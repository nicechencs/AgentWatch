//! `aw attach` and the daemon session API (P1-CLI-02).
//!
//! The production control uses the same authenticated local channel as `aw ui`
//! and `aw daemon stop`. `aw attach --pid` creates an attach session, while
//! launch sessions use [`DaemonSessions::begin_run`] followed by
//! [`DaemonSessions::adopt`]. None of these operations signal a target process.

use std::marker::PhantomData;
use std::thread;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::client::{ApiRequest, Client, ClientError, LoopbackHttp, Transport};
use crate::endpoint::Endpoint;
use crate::exit;

use super::query::{encode_path_segment, encode_query};
use super::Outcome;

/// Parsed `aw attach` flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachArgs<'a> {
    /// `--pid`.
    pub pid: Option<u32>,
    /// `--name` process pattern. The daemon cannot apply this selector.
    pub name: Option<&'a str>,
    /// `--no-follow-children`.
    pub no_follow_children: bool,
    /// `--no-existing-children`.
    pub no_existing_children: bool,
    /// `--move-to-cgroup`.
    pub move_to_cgroup: bool,
    /// `--until-exit`.
    pub until_exit: bool,
    /// `--duration` text, before parsing.
    pub duration: Option<&'a str>,
    /// `--agent`.
    pub agent: Option<&'a str>,
    /// `--pin`.
    pub pin: bool,
    /// `--group`. Groups are not this card; a value is refused.
    pub group: Option<&'a str>,
    /// `--json`.
    pub json: bool,
}

/// What attach asks the daemon to watch. No argv or environment values occur
/// in this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachRequest {
    /// Target pid, when `--pid` was passed.
    pub pid: u32,
    /// Keep watching until the root exits.
    pub until_exit: bool,
    /// Stop monitoring after this long. `None` means no timer.
    pub duration: Option<Duration>,
    /// Agent label.
    pub agent: Option<String>,
}

/// Body for `POST /api/v1/sessions/run`.
///
/// Environment variables deliberately have no representation here. They are
/// only applied by the CLI process spawner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BeginRunRequest {
    /// Target argv, including the program.
    pub argv: Vec<String>,
    /// Working directory, when requested.
    pub cwd: Option<String>,
    /// Optional session label.
    pub name: Option<String>,
    /// Optional agent label.
    pub agent: Option<String>,
}

/// A launch session awaiting adoption by the caller-created child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaunchSession {
    /// Public session id.
    pub public_id: String,
    /// One-time handoff ticket.
    pub ticket: String,
}

/// A session the daemon opened or stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionHandle {
    /// Public id. Not a hostname.
    pub public_id: String,
}

/// Why a session-control call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ControlError {
    /// The daemon did not answer.
    Unreachable { detail: String },
    /// The local channel denied the caller before an HTTP response.
    Forbidden { detail: String },
    /// A process other than LocalSystem or the current user owned the opened
    /// Windows pipe. No request bytes were sent.
    UntrustedServer { detail: String },
    /// The request or response transport failed.
    Transport { detail: String },
    /// The daemon returned a non-success HTTP status.
    Status {
        status: u16,
        code: Option<String>,
        message: String,
    },
    /// A successful daemon response omitted a required field.
    BadReply { detail: String },
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { detail } => write!(
                f,
                "连不上后台，请先运行 `aw daemon start`，或加 --no-daemon（本地轮询采集，证据 S）。详情：{detail}"
            ),
            Self::Forbidden { detail } => write!(
                f,
                "后台在运行，但这个账户没有权限打开它的通道。请让管理员把你加入 agentwatch 组（Windows：AgentWatch Users）。详情：{detail}"
            ),
            Self::UntrustedServer { .. } => {
                f.write_str("连上的不是 AgentWatch 后台（管道被别的程序占用），已停止发送。")
            }
            Self::Transport { detail } => write!(f, "向后台发请求失败：{detail}"),
            Self::Status {
                status,
                code,
                message,
            } => crate::daemon_errors::write_status(f, *status, code.as_deref(), message),
            Self::BadReply { detail } => write!(f, "后台返回的会话数据不完整：{detail}"),
        }
    }
}

impl std::error::Error for ControlError {}

impl From<ClientError> for ControlError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Unreachable { detail } => Self::Unreachable { detail },
            ClientError::Forbidden { detail } => Self::Forbidden { detail },
            ClientError::UntrustedServer { detail } => Self::UntrustedServer { detail },
            ClientError::Transport { detail } => Self::Transport { detail },
            ClientError::Status {
                status,
                code,
                message,
            } => Self::Status {
                status,
                code,
                message,
            },
        }
    }
}

impl ControlError {
    /// Exit code consistent with [`ClientError::exit_code`].
    #[must_use]
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::Unreachable { .. } => exit::UNREACHABLE,
            Self::Forbidden { .. } | Self::UntrustedServer { .. } => exit::PERMISSION,
            Self::Transport { .. } | Self::BadReply { .. } => exit::GENERAL,
            Self::Status { status, .. } => exit::from_http_status(*status),
        }
    }

    /// Stable machine-readable code for this failure.
    ///
    /// A daemon `error.code` is kept as-is (it is already a machine token, and
    /// JSON output must not replace it with a status class). Statuses without
    /// one fall back to the class.
    #[must_use]
    pub(crate) fn machine_code(&self) -> &str {
        match self {
            Self::Unreachable { .. } => "unreachable",
            Self::Forbidden { .. } => "forbidden",
            Self::UntrustedServer { .. } => "daemon_untrusted_server",
            Self::Status { code, status, .. } => code.as_deref().unwrap_or(match *status {
                401 => "unauthorized",
                403 => "forbidden",
                404 => "not_found",
                _ => "status",
            }),
            Self::Transport { .. } => "transport",
            Self::BadReply { .. } => "bad_reply",
        }
    }

    /// Whether the daemon specifically reported that no collector is present.
    #[must_use]
    pub(crate) fn collector_unavailable(&self) -> bool {
        matches!(self, Self::Status { status: 503, code, message }
            if code.as_deref() == Some("collector_unavailable") || message.contains("collector"))
    }

    /// Whether a session is absent or invisible to the caller.
    #[must_use]
    pub(crate) fn not_found(&self) -> bool {
        matches!(self, Self::Status { status: 404, .. })
    }

    /// `@last` when the caller has no sessions. The daemon answers 404 with
    /// `no_sessions`, which is not "that session is missing".
    #[must_use]
    pub(crate) fn no_sessions(&self) -> bool {
        matches!(
            self,
            Self::Status { code: Some(code), .. } if code == "no_sessions"
        )
    }
}

/// Session operations used by run, attach, and stop.
///
/// `stop_monitoring` ends observation only; there is intentionally no target
/// termination method in this trait.
pub(crate) trait DaemonSessions {
    /// Create a launch session and receive its one-time adoption ticket.
    fn begin_run(&mut self, request: &BeginRunRequest) -> Result<LaunchSession, ControlError>;

    /// Give the daemon a caller-created root process.
    fn adopt(&mut self, session: &LaunchSession, pid: u32) -> Result<(), ControlError>;

    /// Report the numeric target exit code after a caller-created child exits.
    /// The daemon preserves a code it already recorded itself.
    fn record_exit(&mut self, session: &LaunchSession, exit_code: i32) -> Result<(), ControlError>;

    /// Create a session for an existing root process.
    fn attach(&mut self, request: &AttachRequest) -> Result<SessionHandle, ControlError>;

    /// Stop observation for a session. This never ends the target process.
    /// Returns the public id that was stopped. `@last` is resolved by the
    /// daemon; a name is resolved among the caller's own sessions.
    fn stop_monitoring(
        &mut self,
        session: &str,
        owner: Option<&str>,
    ) -> Result<String, ControlError>;

    /// Set the session's pinned flag.
    fn pin(&mut self, session: &str) -> Result<(), ControlError>;
}

/// Lends a [`Transport`] to [`Client`], which takes one by value.
#[cfg(test)]
struct Passthrough<'a, T>(&'a mut T);

#[cfg(test)]
impl<T: Transport> Transport for Passthrough<'_, T> {
    fn exchange(&mut self, request: &ApiRequest) -> Result<crate::client::ApiReply, ClientError> {
        self.0.exchange(request)
    }
}

/// Where [`HttpDaemonSessions`] sends a request.
enum SessionTransport<T: Transport> {
    /// Dial a fresh [`LoopbackHttp`] for each call.
    Live(PhantomData<T>),
    /// A transport the caller owns. Tests use this to record requests.
    #[cfg(test)]
    Scripted(T),
}

/// Production session control over one resolved daemon endpoint.
pub(crate) struct HttpDaemonSessions<T: Transport = LoopbackHttp> {
    endpoint: Endpoint,
    transport: SessionTransport<T>,
}

impl HttpDaemonSessions<LoopbackHttp> {
    /// Bind to an endpoint. This does not open a socket.
    #[must_use]
    pub(crate) fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            transport: SessionTransport::Live(PhantomData),
        }
    }
}

impl<T: Transport> HttpDaemonSessions<T> {
    /// Bind to an endpoint and answer every call with `transport`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_transport(endpoint: Endpoint, transport: T) -> Self {
        Self {
            endpoint,
            transport: SessionTransport::Scripted(transport),
        }
    }

    fn call(&mut self, request: &ApiRequest) -> Result<Value, ControlError> {
        let reply = match &mut self.transport {
            #[cfg(test)]
            SessionTransport::Scripted(transport) => {
                let mut client = Client::new(self.endpoint.clone(), Passthrough(transport));
                client.call(request).map_err(ControlError::from)?
            }
            SessionTransport::Live(_) => {
                let transport = LoopbackHttp::new(&self.endpoint).map_err(ControlError::from)?;
                let mut client = Client::new(self.endpoint.clone(), transport);
                client.call(request).map_err(ControlError::from)?
            }
        };
        reply.json().ok_or_else(|| ControlError::BadReply {
            detail: "响应体不是 JSON".to_owned(),
        })
    }
}

impl<T: Transport> HttpDaemonSessions<T> {
    /// The daemon's session routes take public ids and `@last`. `@last` is
    /// resolved on the daemon, against the caller's own sessions, so it is
    /// forwarded unchanged. Any other key that is not an `s-` id is looked up
    /// by exact name among the sessions the daemon returned for this caller.
    /// Not found by name is passed through so the daemon answers 404.
    fn resolve_session(&mut self, key: &str) -> Result<String, ControlError> {
        if key.starts_with("s-") || key == "@last" {
            return Ok(key.to_owned());
        }
        let list = self.call(&ApiRequest::get_query("/api/v1/sessions", "limit=500"))?;
        let rows = list
            .get("sessions")
            .and_then(Value::as_array)
            .ok_or_else(|| ControlError::BadReply {
                detail: "缺少字段 `sessions`".to_owned(),
            })?;
        let ids = |row: &Value| row.get("id").and_then(Value::as_str).map(str::to_owned);
        let matches: Vec<String> = rows
            .iter()
            .filter(|row| row.get("name").and_then(Value::as_str) == Some(key))
            .filter_map(ids)
            .collect();
        match matches.as_slice() {
            [] => Ok(key.to_owned()),
            [one] => Ok(one.clone()),
            many => Err(ControlError::Status {
                status: 400,
                code: Some("ambiguous".to_owned()),
                message: format!(
                    "有 {} 个会话名为 `{key}`；请传入 `aw sessions list` 中的公开 ID",
                    many.len()
                ),
            }),
        }
    }
}

impl<T: Transport> DaemonSessions for HttpDaemonSessions<T> {
    fn begin_run(&mut self, request: &BeginRunRequest) -> Result<LaunchSession, ControlError> {
        let mut body = Map::new();
        body.insert("argv".to_owned(), json!(request.argv));
        insert_optional_text(&mut body, "cwd", request.cwd.as_deref());
        insert_optional_text(&mut body, "name", request.name.as_deref());
        insert_optional_text(&mut body, "agent", request.agent.as_deref());
        let reply = self.call(&ApiRequest::post_json(
            "/api/v1/sessions/run",
            &Value::Object(body),
        ))?;
        Ok(LaunchSession {
            public_id: required_text(&reply, "id")?,
            ticket: required_text(&reply, "ticket")?,
        })
    }

    fn adopt(&mut self, session: &LaunchSession, pid: u32) -> Result<(), ControlError> {
        let path = format!(
            "/api/v1/sessions/{}/adopt",
            encode_path_segment(&session.public_id)
        );
        let _ = self.call(&ApiRequest::post_json(
            &path,
            &json!({ "ticket": session.ticket, "pid": pid }),
        ))?;
        Ok(())
    }

    fn record_exit(&mut self, session: &LaunchSession, exit_code: i32) -> Result<(), ControlError> {
        let path = format!(
            "/api/v1/sessions/{}/exit",
            encode_path_segment(&session.public_id)
        );
        let _ = self.call(&ApiRequest::post_json(
            &path,
            &json!({ "exit_code": exit_code }),
        ))?;
        Ok(())
    }

    fn attach(&mut self, request: &AttachRequest) -> Result<SessionHandle, ControlError> {
        let mut body = Map::new();
        body.insert("mode".to_owned(), json!("attach"));
        body.insert("pid".to_owned(), json!(request.pid));
        insert_optional_text(&mut body, "agent", request.agent.as_deref());
        let reply = self.call(&ApiRequest::post_json(
            "/api/v1/sessions",
            &Value::Object(body),
        ))?;
        Ok(SessionHandle {
            public_id: required_text(&reply, "id")?,
        })
    }

    fn stop_monitoring(
        &mut self,
        session: &str,
        owner: Option<&str>,
    ) -> Result<String, ControlError> {
        let public_id = self.resolve_session(session)?;
        let path = format!("/api/v1/sessions/{}/stop", encode_path_segment(&public_id));
        let request = ApiRequest {
            method: "POST".to_owned(),
            path,
            query: owner
                .map(|value| encode_query(&[("owner", value)]))
                .unwrap_or_default(),
            body: b"{}".to_vec(),
        };
        let reply = self.call(&request)?;
        // `@last` is resolved by the daemon. The id it stopped is the one it
        // names back; a reply that names nothing keeps what was sent.
        Ok(reply
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map_or(public_id, str::to_owned))
    }

    fn pin(&mut self, session: &str) -> Result<(), ControlError> {
        let path = format!("/api/v1/sessions/{}", encode_path_segment(session));
        let _ = self.call(&ApiRequest::json_method_public(
            "PATCH",
            &path,
            &json!({ "pinned": true }),
        ))?;
        Ok(())
    }
}

/// Test-dispatch session control. Production uses [`HttpDaemonSessions`].
///
/// Keeping this small fake lets `execute_args_with` stay socket-free for its
/// existing parser and dispatch tests.
#[derive(Debug, Default)]
pub(crate) struct UnwiredControl;

impl DaemonSessions for UnwiredControl {
    fn begin_run(&mut self, _: &BeginRunRequest) -> Result<LaunchSession, ControlError> {
        Err(unwired())
    }

    fn adopt(&mut self, _: &LaunchSession, _: u32) -> Result<(), ControlError> {
        Err(unwired())
    }

    fn record_exit(&mut self, _: &LaunchSession, _: i32) -> Result<(), ControlError> {
        Err(unwired())
    }

    fn attach(&mut self, _: &AttachRequest) -> Result<SessionHandle, ControlError> {
        Err(unwired())
    }

    fn stop_monitoring(&mut self, _: &str, _: Option<&str>) -> Result<String, ControlError> {
        Err(unwired())
    }

    fn pin(&mut self, _: &str) -> Result<(), ControlError> {
        Err(unwired())
    }
}

fn unwired() -> ControlError {
    ControlError::Unreachable {
        detail: "此测试分发没有接通后台会话 API".to_owned(),
    }
}

fn insert_optional_text(body: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        body.insert(key.to_owned(), json!(value));
    }
}

fn required_text(body: &Value, key: &str) -> Result<String, ControlError> {
    body.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ControlError::BadReply {
            detail: format!("字段 `{key}` 缺失或为空"),
        })
}

/// A clock that can be replaced in tests so `--duration` does not sleep.
pub(crate) trait Sleeper {
    /// Wait for `duration` before the monitoring session is stopped.
    fn sleep(&mut self, duration: Duration);
}

/// Production duration clock.
pub(crate) struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&mut self, duration: Duration) {
        thread::sleep(duration);
    }
}

/// Run `aw attach` with the production clock.
pub(crate) fn run(args: &AttachArgs<'_>, control: &mut dyn DaemonSessions) -> Outcome {
    run_with_sleeper(args, control, &mut ThreadSleeper)
}

/// Run `aw attach` with an injectable duration clock.
pub(crate) fn run_with_sleeper(
    args: &AttachArgs<'_>,
    control: &mut dyn DaemonSessions,
    sleeper: &mut dyn Sleeper,
) -> Outcome {
    let request = match prepare(args) {
        Ok(request) => request,
        Err(outcome) => return outcome,
    };
    let duration = request.duration;
    let until_exit = request.until_exit;
    let handle = match control.attach(&request) {
        Ok(handle) => handle,
        Err(error) => return control_outcome(error, args.json),
    };
    let pin_warning = if args.pin {
        control
            .pin(&handle.public_id)
            .err()
            .map(|error| pin_warning(&error))
    } else {
        None
    };
    if let Some(duration) = duration {
        sleeper.sleep(duration);
        if let Err(error) = control.stop_monitoring(&handle.public_id, None) {
            return control_outcome(error, args.json);
        }
        return attached_outcome(&handle, true, false, args.json, pin_warning.as_deref());
    }
    attached_outcome(
        &handle,
        false,
        until_exit,
        args.json,
        pin_warning.as_deref(),
    )
}

/// Refuse unavailable attach switches before opening a daemon channel.
pub(crate) fn preflight(args: &AttachArgs<'_>) -> Result<(), Outcome> {
    prepare(args).map(|_| ())
}

fn prepare(args: &AttachArgs<'_>) -> Result<AttachRequest, Outcome> {
    if args.name.is_some() {
        return Err(super::error_outcome(
            exit::GENERAL,
            "not_available",
            "此构建的 attach 不支持 --name；请用 `aw ps` 找到进程后传入 --pid",
            args.json,
        ));
    }
    if args.no_follow_children {
        return Err(unavailable_switch("--no-follow-children", args.json));
    }
    if args.no_existing_children {
        return Err(unavailable_switch("--no-existing-children", args.json));
    }
    if args.move_to_cgroup {
        return Err(unavailable_switch("--move-to-cgroup", args.json));
    }
    let Some(pid) = args.pid else {
        return Err(super::error_outcome(
            exit::USAGE,
            "usage",
            "`aw attach` 需要 --pid",
            args.json,
        ));
    };
    if args.group.is_some() {
        return Err(super::error_outcome(
            exit::NOT_IN_BUILD,
            "not_in_build",
            "`--group` 本版本未接入",
            args.json,
        ));
    }
    if args.until_exit && args.duration.is_some() {
        return Err(super::error_outcome(
            exit::USAGE,
            "usage",
            "--until-exit 和 --duration 只能二选一",
            args.json,
        ));
    }
    let duration = match args.duration.map(parse_attach_duration).transpose() {
        Ok(duration) => duration,
        Err(detail) => {
            return Err(super::error_outcome(
                exit::USAGE,
                "usage",
                &detail,
                args.json,
            ))
        }
    };
    Ok(AttachRequest {
        pid,
        until_exit: args.until_exit,
        duration,
        agent: args.agent.map(str::to_owned),
    })
}

fn unavailable_switch(name: &str, json: bool) -> Outcome {
    super::error_outcome(
        exit::GENERAL,
        "not_available",
        &format!("此构建的 attach 不支持 {name}；后台轮询采样器没有这个参数"),
        json,
    )
}

/// `--duration 10s`. A leading `-` or `+` belongs to the query time syntax, not
/// to a watch length, so those are refused rather than treated as zero.
fn parse_attach_duration(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    if text.starts_with('+') || text.starts_with('-') {
        return Err(format!(
            "--duration `{text}` 必须是 10s 这样的时长，不能是相对时间"
        ));
    }
    match crate::output::parse_time(text) {
        Ok(crate::output::TimeArg::BeforeNow(span)) => span_to_duration(span.count, span.unit),
        Ok(_) => Err(format!("--duration `{text}` 必须是 10s 这样的时长")),
        Err(detail) => Err(detail),
    }
}

fn span_to_duration(count: u64, unit: crate::output::TimeUnit) -> Result<Duration, String> {
    use crate::output::TimeUnit;
    let millis = match unit {
        TimeUnit::Millis => count,
        TimeUnit::Seconds => count.saturating_mul(1_000),
        TimeUnit::Minutes => count.saturating_mul(60_000),
        TimeUnit::Hours => count.saturating_mul(3_600_000),
        TimeUnit::Days => count.saturating_mul(86_400_000),
    };
    Ok(Duration::from_millis(millis))
}

/// Render a daemon-session failure with the same exit class as the HTTP client.
pub(crate) fn control_outcome(error: ControlError, json: bool) -> Outcome {
    super::error_outcome(
        error.exit_code(),
        error.machine_code(),
        &error.to_string(),
        json,
    )
}

fn pin_warning(error: &ControlError) -> String {
    format!("[aw] 警告：后台没有保留这个会话：{error}\n")
}

fn attached_outcome(
    handle: &SessionHandle,
    stopped_on_duration: bool,
    until_exit: bool,
    json: bool,
    warning: Option<&str>,
) -> Outcome {
    let note = if stopped_on_duration {
        "监控已按 --duration 结束；目标进程未被结束"
    } else if until_exit {
        "监控已附着；后台会在根进程退出时结束会话；停止监控不会结束目标进程"
    } else {
        "监控已附着；停止监控不会结束目标进程"
    };
    let text = if json {
        let body = json!({
            "session": handle.public_id,
            "monitoring": if stopped_on_duration { "stopped" } else { "attached" },
            "process_terminated": false,
            "message": note,
        });
        format!("{body}\n")
    } else {
        format!("[aw] 会话 {} · {note}\n", handle.public_id)
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: warning.unwrap_or_default().as_bytes().to_vec(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::Duration;

    use super::{
        run_with_sleeper, AttachArgs, AttachRequest, BeginRunRequest, ControlError, DaemonSessions,
        LaunchSession, SessionHandle, Sleeper,
    };
    use crate::exit;

    #[derive(Default)]
    struct FakeControl {
        attached: Vec<AttachRequest>,
        stopped: Vec<String>,
        pinned: Vec<String>,
        attach_error: Option<ControlError>,
        stop_error: Option<ControlError>,
        pin_error: Option<ControlError>,
    }

    impl DaemonSessions for FakeControl {
        fn begin_run(&mut self, _: &BeginRunRequest) -> Result<LaunchSession, ControlError> {
            Err(ControlError::BadReply {
                detail: "attach test must not start a launch".to_owned(),
            })
        }

        fn adopt(&mut self, _: &LaunchSession, _: u32) -> Result<(), ControlError> {
            Err(ControlError::BadReply {
                detail: "attach test must not adopt".to_owned(),
            })
        }

        fn record_exit(&mut self, _: &LaunchSession, _: i32) -> Result<(), ControlError> {
            Err(ControlError::BadReply {
                detail: "attach test must not record an exit".to_owned(),
            })
        }

        fn attach(&mut self, request: &AttachRequest) -> Result<SessionHandle, ControlError> {
            self.attached.push(request.clone());
            match self.attach_error.take() {
                Some(error) => Err(error),
                None => Ok(SessionHandle {
                    public_id: "s-attach".to_owned(),
                }),
            }
        }

        fn stop_monitoring(
            &mut self,
            session: &str,
            _: Option<&str>,
        ) -> Result<String, ControlError> {
            self.stopped.push(session.to_owned());
            match self.stop_error.take() {
                Some(error) => Err(error),
                None => Ok(session.to_owned()),
            }
        }

        fn pin(&mut self, session: &str) -> Result<(), ControlError> {
            self.pinned.push(session.to_owned());
            match self.pin_error.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }

    #[derive(Default)]
    struct FakeSleeper(Vec<Duration>);

    impl Sleeper for FakeSleeper {
        fn sleep(&mut self, duration: Duration) {
            self.0.push(duration);
        }
    }

    fn args() -> AttachArgs<'static> {
        AttachArgs {
            pid: Some(100),
            name: None,
            no_follow_children: false,
            no_existing_children: false,
            move_to_cgroup: false,
            until_exit: false,
            duration: None,
            agent: Some("agent-a"),
            pin: false,
            group: None,
            json: false,
        }
    }

    #[test]
    fn attach_forwards_pid_and_agent() {
        let mut control = FakeControl::default();
        let mut sleeper = FakeSleeper::default();
        let outcome = run_with_sleeper(&args(), &mut control, &mut sleeper);
        assert_eq!(outcome.code, exit::OK);
        assert_eq!(control.attached.len(), 1);
        assert_eq!(control.attached[0].pid, 100);
        assert_eq!(control.attached[0].agent.as_deref(), Some("agent-a"));
        assert!(control.stopped.is_empty());
    }

    #[test]
    fn name_is_refused_without_a_daemon_call() {
        let mut control = FakeControl::default();
        let mut sleeper = FakeSleeper::default();
        let mut parsed = args();
        parsed.pid = None;
        parsed.name = Some("python*");
        let outcome = run_with_sleeper(&parsed, &mut control, &mut sleeper);
        assert_eq!(outcome.code, exit::GENERAL);
        assert!(String::from_utf8(outcome.stderr)
            .expect("utf8")
            .contains("aw ps"));
        assert!(control.attached.is_empty());
    }

    #[test]
    fn duration_sleeps_then_stops_monitoring_without_ending_the_target() {
        let mut control = FakeControl::default();
        let mut sleeper = FakeSleeper::default();
        let mut parsed = args();
        parsed.duration = Some("10s");
        let outcome = run_with_sleeper(&parsed, &mut control, &mut sleeper);
        assert_eq!(outcome.code, exit::OK);
        assert_eq!(sleeper.0, vec![Duration::from_secs(10)]);
        assert_eq!(control.stopped, vec!["s-attach".to_owned()]);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(text.contains("目标进程未被结束"), "{text}");
    }

    #[test]
    fn forbidden_and_unreachable_keep_client_exit_classes() {
        let mut forbidden = FakeControl {
            attach_error: Some(ControlError::Status {
                status: 403,
                code: None,
                message: "forbidden".to_owned(),
            }),
            ..FakeControl::default()
        };
        let mut sleeper = FakeSleeper::default();
        let outcome = run_with_sleeper(&args(), &mut forbidden, &mut sleeper);
        assert_eq!(outcome.code, exit::PERMISSION);
        assert!(String::from_utf8(outcome.stderr)
            .expect("utf8")
            .contains("forbidden"));

        let mut unreachable = FakeControl {
            attach_error: Some(ControlError::Unreachable {
                detail: "down".to_owned(),
            }),
            ..FakeControl::default()
        };
        let outcome = run_with_sleeper(&args(), &mut unreachable, &mut sleeper);
        assert_eq!(outcome.code, exit::UNREACHABLE);
    }

    /// Read one HTTP/1.1 request: headers, then `Content-Length` body bytes,
    /// however many reads that takes.
    #[cfg(unix)]
    fn read_request(stream: &mut std::os::unix::net::UnixStream) -> String {
        use std::io::Read;
        let mut data = Vec::new();
        let mut buf = [0_u8; 4096];
        loop {
            let text = String::from_utf8_lossy(&data).into_owned();
            if let Some(split) = text.find("\r\n\r\n") {
                let length = text[..split]
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if data.len() >= split + 4 + length {
                    return text;
                }
            }
            let n = stream.read(&mut buf).expect("read");
            assert!(n > 0, "client closed before a full request");
            data.extend_from_slice(&buf[..n]);
        }
    }

    /// A one-request-per-connection fake daemon on a Unix socket. Returns the
    /// endpoint, its directory, and the requests it saw.
    #[cfg(unix)]
    fn fake_daemon(
        tag: &str,
        replies: Vec<&'static str>,
    ) -> (
        crate::endpoint::Endpoint,
        std::path::PathBuf,
        std::thread::JoinHandle<Vec<String>>,
    ) {
        use std::io::Write;
        use std::os::unix::net::UnixListener;
        // Short name: macOS caps a socket path at 104 bytes and its temp dir is long.
        let dir = std::env::temp_dir().join(format!("aw{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("s.sock");
        let listener = UnixListener::bind(&path).expect("bind");
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for reply in replies {
                let (mut stream, _) = listener.accept().expect("accept");
                seen.push(read_request(&mut stream));
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    reply.len(),
                    reply
                )
                .expect("reply");
            }
            seen
        });
        (crate::endpoint::Endpoint::Unix { path }, dir, server)
    }

    #[cfg(unix)]
    #[test]
    fn stop_sends_at_last_unchanged_and_resolves_names_first() {
        use super::{DaemonSessions, HttpDaemonSessions};
        let (endpoint, dir, server) = fake_daemon(
            "st",
            vec![
                // `@last` is the daemon's to resolve. It names the session back.
                r#"{"stopped":"@last","id":"s-new"}"#,
                r#"{"sessions":[{"id":"s-new","name":null},{"id":"s-old","name":"x"}]}"#,
                r#"{"stopped":"s-old","id":"s-old"}"#,
                r#"{"stopped":"s-direct","id":"s-direct"}"#,
            ],
        );
        let mut control = HttpDaemonSessions::new(endpoint);
        assert_eq!(
            control.stop_monitoring("@last", None).expect("@last"),
            "s-new"
        );
        assert_eq!(
            control.stop_monitoring("x", None).expect("by name"),
            "s-old"
        );
        assert_eq!(
            control.stop_monitoring("s-direct", None).expect("by id"),
            "s-direct"
        );
        let seen = server.join().expect("join");
        assert!(
            seen[0].starts_with("POST /api/v1/sessions/@last/stop "),
            "{}",
            seen[0]
        );
        assert!(
            seen[1].starts_with("GET /api/v1/sessions?limit=500 "),
            "{}",
            seen[1]
        );
        assert!(
            seen[2].starts_with("POST /api/v1/sessions/s-old/stop "),
            "{}",
            seen[2]
        );
        assert!(
            seen[3].starts_with("POST /api/v1/sessions/s-direct/stop "),
            "{}",
            seen[3]
        );
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn production_control_uses_the_unix_channel_for_all_session_calls() {
        use super::{DaemonSessions, HttpDaemonSessions};

        let (endpoint, dir, server) = fake_daemon(
            "sc",
            vec![
                r#"{"id":"s-run","ticket":"t-run"}"#,
                r#"{"id":"s-run","root_pid":42}"#,
                r#"{"id":"s-attach","session_id":2,"mode":"attach","root_pid":77}"#,
                r#"{"stopped":"s-attach"}"#,
                r#"{"id":"s-attach"}"#,
            ],
        );
        let mut control = HttpDaemonSessions::new(endpoint);
        let launch = control
            .begin_run(&BeginRunRequest {
                argv: vec!["tool".to_owned()],
                cwd: Some("/work".to_owned()),
                name: Some("session".to_owned()),
                agent: Some("agent-a".to_owned()),
            })
            .expect("begin");
        control.adopt(&launch, 42).expect("adopt");
        let attached = control
            .attach(&AttachRequest {
                pid: 77,
                until_exit: false,
                duration: None,
                agent: Some("agent-b".to_owned()),
            })
            .expect("attach");
        control
            .stop_monitoring(&attached.public_id, None)
            .expect("stop");
        control.pin(&attached.public_id).expect("pin");
        let seen = server.join().expect("join");
        assert!(seen[0].starts_with("POST /api/v1/sessions/run HTTP/1.1"));
        assert!(seen[0]
            .contains(r#"{"agent":"agent-a","argv":["tool"],"cwd":"/work","name":"session"}"#));
        assert!(seen[1].starts_with("POST /api/v1/sessions/s-run/adopt HTTP/1.1"));
        assert!(seen[1].contains(r#"{"pid":42,"ticket":"t-run"}"#));
        assert!(seen[2].starts_with("POST /api/v1/sessions HTTP/1.1"));
        assert!(seen[2].contains(r#"{"agent":"agent-b","mode":"attach","pid":77}"#));
        assert!(seen[3].starts_with("POST /api/v1/sessions/s-attach/stop HTTP/1.1"));
        assert!(seen[4].starts_with("PATCH /api/v1/sessions/s-attach HTTP/1.1"));
        assert!(seen[4].contains(r#"{"pinned":true}"#));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
