//! `aw hook <AGENT> [--session <SESSION>]` (P5-AGENT-02, P5-SEC-02).
//!
//! With no policy file, or with `enabled = false`, every path returns exit 0
//! and writes nothing an agent could parse as a decision. That is the
//! audit-only behaviour P5-AGENT-02 shipped, byte for byte.
//!
//! With a policy enabled (P5-SEC-02), the decision is made in this process
//! against the local file. It does not wait for the daemon. Stdout is the
//! agent's decision JSON (Claude Code or Codex). A deny, rewrite, ask, or
//! downgrade also posts one audit record. The post is abandoned at the same
//! 200 ms budget; a miss falls back to a local jsonl file.
//!
//! Budget: 200 ms from the start of [`run`] until the daemon write is abandoned.
//! A slow read, a slow connect, or a missing daemon is a drop of the *report*.
//! The CLI cannot write the daemon's gap table; it sends `dropped: true` when
//! it still has time, and the daemon records `gap_kind = self_report_dropped`
//! (or `intercept_audit_dropped` for an audit the local file also refused).

use std::io::{self, Read};
use std::thread;
use std::time::{Duration, Instant};

use aw_agent_adapters::agents::claude_code::decision::{claude_decision, HookDecision};
use aw_agent_adapters::agents::codex::decision::{codex_decision, CodexDecision};
use aw_agent_adapters::{parse_hook, HookRegistry};
use aw_pipeline::{
    decide, downgrade_codex_ask, Action, DecideError, Decision, Layer, OnError, Phase, Subject,
};
use serde_json::{json, Map, Value};

use crate::client::{ApiRequest, Client, LoopbackHttp};
use crate::endpoint::{self, Endpoint, EndpointInput};
use crate::exit;

use super::intercept_audit::{self, AuditDelivery};
use super::policy_file::{self, PolicyLoad};
use super::Outcome;

/// Hard ceiling. The acceptance measurement is "under 200 ms".
pub(crate) const HOOK_BUDGET: Duration = Duration::from_millis(200);

/// stdin cap. Larger than one bounded tool call, smaller than a transcript.
const MAX_STDIN: usize = 64 * 1024;

/// Environment variable `aw run` injects. Wins over `--session` and over a ProcUid lookup.
pub(crate) const SESSION_ENV: &str = "AW_SESSION";

/// What the hook needs, with I/O behind traits so the budget can be tested
/// without a daemon. Production fills these from stdin and the platform.
pub(crate) struct HookInput<'a> {
    /// Agent id from the command line. Not validated against a profile.
    pub agent: &'a str,
    /// `--session`, when the operator passed one.
    pub session_flag: Option<&'a str>,
    /// `AW_SESSION`, already read by the caller.
    pub session_env: Option<&'a str>,
    /// Resolved daemon address. A connect failure is a drop, not a non-zero exit.
    pub endpoint: &'a Endpoint,
    /// Bytes already read from stdin. Production reads them under the budget.
    pub payload: &'a [u8],
    /// When [`run`] started. The budget is measured from here.
    pub started: Instant,
}

/// Where a parsed hook is sent. The production sender dials the daemon and
/// gives up at `deadline`.
pub(crate) trait HookTransport {
    /// Deliver `body`. `Ok(false)` means the deadline won and the body was not sent.
    ///
    /// # Errors
    ///
    /// A connect or write failure. The hook command still exits 0.
    fn send(&mut self, endpoint: &Endpoint, body: &[u8], deadline: Instant) -> io::Result<bool>;
}

/// Dial the local socket, named pipe, or loopback HTTP, then write one request.
///
/// The whole call is raced against `deadline` on a worker thread: a connect
/// that would block past 200 ms is abandoned. The worker is detached; it does
/// not keep the hook process alive (`main` exits, and the runtime ends the thread).
#[derive(Debug, Default)]
pub(crate) struct PlatformHookTransport;

impl HookTransport for PlatformHookTransport {
    fn send(&mut self, endpoint: &Endpoint, body: &[u8], deadline: Instant) -> io::Result<bool> {
        let endpoint = endpoint.clone();
        let body = body.to_vec();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::Builder::new()
            .name("aw-hook-send".to_owned())
            .spawn(move || {
                let result = send_blocking(&endpoint, &body);
                let _ = tx.send(result);
            })
            .map_err(|err| io::Error::other(err.to_string()))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(result) => result.map(|()| true),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(false),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(io::Error::other("hook send ended before a result"))
            }
        }
    }
}

fn send_blocking(endpoint: &Endpoint, body: &[u8]) -> io::Result<()> {
    // Socket, pipe, and loopback HTTP all speak HTTP/1.1. The old length-prefixed
    // frame never matched the daemon (design §2). Windows still opens the pipe
    // through aw-channel: `LoopbackHttp` calls `open_pipe_client`, which checks
    // the server before any byte is written.
    let request = ApiRequest::post_json("/api/v1/agent/hook", &json_body(body));
    let mut transport =
        LoopbackHttp::new(endpoint).map_err(|err| io::Error::other(err.to_string()))?;
    // Inside the hook budget. A 12 second client deadline would outlive the process.
    transport.set_timeout(Duration::from_millis(50));
    let mut client = Client::new(endpoint.clone(), transport);
    client
        .call(&request)
        .map(|_| ())
        .map_err(|err| io::Error::other(err.to_string()))
}

/// The hook message is already JSON. A body that is not JSON is posted as
/// `{"raw_dropped": true}` so the daemon still sees a drop rather than a
/// length-prefixed frame it cannot parse. The original bytes are not copied
/// into that object.
fn json_body(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap_or_else(|_| json!({"dropped": true, "reason": "not_json"}))
}

/// Run the hook.
///
/// Policy off: always [`exit::OK`], stdout and stderr empty.
/// Policy on: stdout is the decision JSON when there is one. Exit stays 0.
/// A broken policy denies (the default `on_error`) by printing a deny and
/// recording one audit row. Codex `ask` is printed as deny.
pub(crate) fn run(input: HookInput<'_>, transport: &mut dyn HookTransport) -> Outcome {
    let deadline = input.started + HOOK_BUDGET;
    let _ = (HookRegistry, parse_hook_quiet(input.agent, input.payload));
    let policy = policy_file::load_policy(
        policy_env_path().as_deref(),
        policy_file::user_config_home().as_deref(),
    );
    if Instant::now() >= deadline {
        return silent_ok();
    }
    let session = resolve_session(input.session_env, input.session_flag);
    if Instant::now() >= deadline {
        // No time left to tell the daemon either. Still exit 0.
        return silent_ok();
    }
    let decision_bytes = match &policy {
        PolicyLoad::Off => None,
        PolicyLoad::On(policy) => apply_decision(
            policy,
            input.agent,
            session.as_deref(),
            input.payload,
            input.endpoint,
            deadline,
        ),
        PolicyLoad::Broken => apply_on_error(
            OnError::Deny,
            input.agent,
            session.as_deref(),
            input.payload,
            input.endpoint,
            deadline,
            "规则文件读不了，已按拒绝处理",
        ),
    };
    // The self-report is independent of the decision. Policy off keeps the
    // previous message. Policy on still forwards the payload so the daemon
    // can record the E3 call; the decision itself is not in that body.
    let body = hook_message(input.agent, session.as_deref(), input.payload, false);
    let delivered = transport.send(input.endpoint, &body, deadline);
    if !matches!(delivered, Ok(true)) && Instant::now() < deadline {
        let reason = if matches!(delivered, Ok(false)) {
            "timeout"
        } else {
            "send_failed"
        };
        let notice = drop_notice(input.agent, session.as_deref(), reason);
        let _ = transport.send(input.endpoint, &notice, deadline);
    }
    match decision_bytes {
        Some(stdout) => Outcome {
            code: exit::OK,
            stdout,
            stderr: Vec::new(),
        },
        None => silent_ok(),
    }
}

fn silent_ok() -> Outcome {
    Outcome {
        code: exit::OK,
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

fn policy_env_path() -> Option<std::path::PathBuf> {
    std::env::var_os(policy_file::POLICY_ENV)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
}

/// Decide, audit, and render. `None` means print nothing (an allow).
fn apply_decision(
    policy: &aw_pipeline::Policy,
    agent: &str,
    session: Option<&str>,
    payload: &[u8],
    endpoint: &Endpoint,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let value = serde_json::from_slice::<Value>(payload).ok();
    let Some(value) = value else {
        return apply_on_error(
            policy.on_error(),
            agent,
            session,
            payload,
            endpoint,
            deadline,
            "hook 载荷不是 JSON",
        );
    };
    let subject = subject_from(agent, &value);
    let decided = match decide(policy, &subject) {
        Ok(decision) => decision,
        Err(error) => {
            return on_error_from_decide(
                policy.on_error(),
                agent,
                session,
                &subject,
                endpoint,
                deadline,
                &error,
            );
        }
    };
    let decided = if agent == "codex" {
        downgrade_codex_ask(&decided)
    } else {
        decided
    };
    if decided.effective == Action::Allow && decided.fields.is_empty() {
        return None;
    }
    let (rendered, rewritten_text) = render_decision(agent, &subject, &decided, &value);
    let Some(rendered) = rendered else {
        // Codex Bash / apply_patch rewrites must carry a string `command`.
        // Anything else that produced no JSON is a decision failure, not a
        // silent allow: the rule asked for a rewrite or a deny.
        if decided.effective == Action::Allow {
            return None;
        }
        return apply_on_error(
            policy.on_error(),
            agent,
            session,
            payload,
            endpoint,
            deadline,
            "判定结果无法按这个 agent 的格式输出",
        );
    };
    let audited = audit_decision(
        &subject,
        &decided,
        session,
        &original_text(&subject, &value),
        rewritten_text.as_deref(),
        endpoint,
        deadline,
    );
    // A rewrite that could not be audited is a deny. Re-render that deny.
    if audited.delivered == aw_pipeline::Delivered::Dropped && decided.effective == Action::Rewrite
    {
        let downgraded = audited.downgrade_rewrite(&decided);
        let (again, _) = render_decision(agent, &subject, &downgraded, &value);
        return again.and_then(|body| json_stdout(&body));
    }
    json_stdout(&rendered)
}

fn on_error_from_decide(
    on_error: OnError,
    agent: &str,
    session: Option<&str>,
    subject: &Subject,
    endpoint: &Endpoint,
    deadline: Instant,
    error: &DecideError,
) -> Option<Vec<u8>> {
    let reason = match on_error {
        OnError::Deny => "判定出错，已按拒绝处理",
        OnError::Allow => "判定出错，已按放行处理",
    };
    let _ = error;
    let decision = on_error_decision(on_error, reason);
    if decision.effective == Action::Allow {
        let _ = audit_decision(subject, &decision, session, "", None, endpoint, deadline);
        return None;
    }
    let value = Value::Null;
    let (rendered, _) = render_decision(agent, subject, &decision, &value);
    let _ = audit_decision(subject, &decision, session, "", None, endpoint, deadline);
    rendered.and_then(|body| json_stdout(&body))
}

fn apply_on_error(
    on_error: OnError,
    agent: &str,
    session: Option<&str>,
    payload: &[u8],
    endpoint: &Endpoint,
    deadline: Instant,
    reason: &str,
) -> Option<Vec<u8>> {
    let decision = on_error_decision(on_error, reason);
    let value = serde_json::from_slice::<Value>(payload).unwrap_or(Value::Null);
    let subject = if value.is_null() {
        Subject {
            layer: Layer::Hook,
            agent: Some(agent.to_owned()),
            ..Subject::default()
        }
    } else {
        subject_from(agent, &value)
    };
    if decision.effective == Action::Allow {
        let _ = audit_decision(&subject, &decision, session, "", None, endpoint, deadline);
        return None;
    }
    let (rendered, _) = render_decision(agent, &subject, &decision, &value);
    let _ = audit_decision(&subject, &decision, session, "", None, endpoint, deadline);
    rendered.and_then(|body| json_stdout(&body))
}

fn on_error_decision(on_error: OnError, reason: &str) -> Decision {
    let action = match on_error {
        OnError::Deny => Action::Deny,
        OnError::Allow => Action::Allow,
    };
    Decision {
        rule_id: None,
        action,
        effective: action,
        downgraded: false,
        reason: Some(reason.to_owned()),
        fields: Vec::new(),
    }
}

fn audit_decision(
    subject: &Subject,
    decision: &Decision,
    session: Option<&str>,
    original: &str,
    rewritten: Option<&str>,
    endpoint: &Endpoint,
    deadline: Instant,
) -> AuditDelivery {
    let salt = session.unwrap_or("").as_bytes();
    let mut record =
        intercept_audit::record_for(subject, decision, salt, original, rewritten, session);
    let remaining = deadline.saturating_duration_since(Instant::now());
    let backup = intercept_audit::backup_path(audit_env_path().as_deref(), None);
    intercept_audit::deliver(
        Some(endpoint),
        backup.as_deref(),
        &mut record,
        remaining.min(Duration::from_millis(50)),
    )
}

fn audit_env_path() -> Option<std::path::PathBuf> {
    std::env::var_os(intercept_audit::AUDIT_ENV)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
}

fn json_stdout(value: &Value) -> Option<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).ok()?;
    bytes.push(b'\n');
    Some(bytes)
}

fn render_decision(
    agent: &str,
    subject: &Subject,
    decision: &Decision,
    payload: &Value,
) -> (Option<Value>, Option<String>) {
    // `rewrite` is not a permissionDecision. Both agents express it as
    // `allow` plus the replacement object. A downgraded rewrite is already
    // `deny` and must not also carry updatedInput.
    let permission = match decision.effective {
        Action::Rewrite => "allow",
        Action::Deny => "deny",
        Action::Ask => "ask",
        Action::Allow => "allow",
    };
    let reason = decision.reason.as_deref();
    if agent == "codex" {
        let updated = updated_object(payload, subject, decision);
        let text = rewrite_audit_text(decision);
        let rendered = codex_decision(
            permission,
            reason,
            subject.tool.as_deref(),
            updated.as_ref(),
        )
        .map(|decision: CodexDecision| decision.to_json());
        return (rendered, text);
    }
    // Claude Code, and any other agent id that speaks the same hook JSON.
    // An unknown agent still gets the Claude shape: that is the format
    // `aw hook claude-code` documents. Codex is the only other one.
    let (input, output, text) = if subject.phase == Phase::Post {
        let updated = updated_output(payload, decision);
        (None, updated, rewrite_audit_text(decision))
    } else {
        let updated = updated_object(payload, subject, decision);
        (updated, None, rewrite_audit_text(decision))
    };
    let rendered = claude_decision(permission, reason, input.as_ref(), output.as_ref())
        .and_then(|decision: HookDecision| decision.to_json());
    (rendered, text)
}

/// What the audit stores as "after". Only the fields the rule replaced, not
/// the whole tool_input: that object can hold a sibling the rule did not
/// touch, and hashing it would keep more than the change.
fn rewrite_audit_text(decision: &Decision) -> Option<String> {
    if decision.effective != Action::Rewrite {
        return None;
    }
    let mut parts = Vec::new();
    for (field, value) in &decision.fields {
        parts.push(format!("{field}={value}"));
    }
    Some(parts.join("\n"))
}

/// Whole replacement of `tool_input`. Fields the rule did not name stay,
/// including their original JSON type. A bool must not become the string
/// `"true"`: Claude Code treats `updatedInput` as the whole argument object.
fn updated_object(payload: &Value, subject: &Subject, decision: &Decision) -> Option<Value> {
    if decision.effective != Action::Rewrite {
        return None;
    }
    let mut input = payload
        .get("tool_input")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_else(Map::new);
    for (field, value) in &decision.fields {
        let key = field.strip_prefix("arg.").unwrap_or(field.as_str());
        input.insert(key.to_owned(), Value::String(value.clone()));
    }
    // Codex Bash / apply_patch require a string `command`. If the rule
    // rewrote a different field, keep the original command string.
    if subject
        .tool
        .as_deref()
        .is_some_and(|tool| matches!(tool, "Bash" | "apply_patch" | "shell" | "exec_command"))
        && !input.contains_key("command")
    {
        if let Some(command) = subject.command.clone() {
            input.insert("command".to_owned(), Value::String(command));
        }
    }
    Some(Value::Object(input))
}

fn updated_output(payload: &Value, decision: &Decision) -> Option<Value> {
    if decision.effective != Action::Rewrite {
        return None;
    }
    let mut output = payload
        .get("tool_response")
        .cloned()
        .unwrap_or(Value::Object(Map::new()));
    if let Some(object) = output.as_object_mut() {
        for (field, value) in &decision.fields {
            let key = field.strip_prefix("arg.").unwrap_or(field.as_str());
            object.insert(key.to_owned(), Value::String(value.clone()));
        }
    }
    Some(output)
}

fn original_text(subject: &Subject, payload: &Value) -> String {
    subject
        .command
        .clone()
        .or_else(|| subject.path.clone())
        .or_else(|| subject.url.clone())
        .unwrap_or_else(|| {
            payload
                .get("tool_input")
                .map(|value| value.to_string())
                .unwrap_or_default()
        })
}

fn subject_from(agent: &str, payload: &Value) -> Subject {
    let object = payload.as_object();
    let event = object.and_then(|map| string_at(map, "hook_event_name"));
    let tool = object.and_then(|map| string_at(map, "tool_name"));
    let input = object
        .and_then(|map| map.get("tool_input"))
        .and_then(Value::as_object);
    let command = input
        .and_then(|map| string_at(map, "command"))
        .or_else(|| input.and_then(|map| string_at(map, "cmd")));
    let path = input.and_then(|map| {
        string_at(map, "file_path")
            .or_else(|| string_at(map, "path"))
            .or_else(|| string_at(map, "notebook_path"))
    });
    let url = input.and_then(|map| string_at(map, "url"));
    let phase = if event.as_deref() == Some("PostToolUse") {
        Phase::Post
    } else {
        Phase::Pre
    };
    // Only string arguments are matchable. A bool or a number is not a
    // command, and stringifying it would make `updatedInput` change the type.
    let args = input
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|text| (key.clone(), text.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default();
    Subject {
        layer: Layer::Hook,
        agent: Some(agent.to_owned()),
        tool,
        event,
        command,
        path,
        url,
        args,
        phase,
        ..Subject::default()
    }
}

fn string_at(map: &Map<String, Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// Parse for the side of "is this JSON". The mapped calls are not logged.
/// Unknown agents return an empty list inside [`parse_hook`]; that is success.
fn parse_hook_quiet(agent: &str, payload: &[u8]) -> Vec<aw_core::AgentToolCall> {
    let Ok(value) = serde_json::from_slice::<Value>(payload) else {
        return Vec::new();
    };
    parse_hook(agent, &value)
}

/// A drop the daemon can record without seeing the payload.
fn drop_notice(agent: &str, session: Option<&str>, reason: &str) -> Vec<u8> {
    let value = json!({
        "agent": agent,
        "session": session,
        "dropped": true,
        "reason": reason,
    });
    serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec())
}

fn hook_message(agent: &str, session: Option<&str>, payload: &[u8], dropped: bool) -> Vec<u8> {
    // The raw payload is forwarded so the daemon's registry (the one that will
    // hold the real parsers) does the mapping. It is not written to a log here.
    let payload_json = serde_json::from_slice::<Value>(payload).unwrap_or(Value::Null);
    let value = json!({
        "agent": agent,
        "session": session,
        "dropped": dropped,
        "payload": payload_json,
    });
    serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec())
}

/// `AW_SESSION`, then `--session`, then "unknown" (the daemon may still map the caller ProcUid).
fn resolve_session(env_value: Option<&str>, flag: Option<&str>) -> Option<String> {
    blank(env_value).or_else(|| blank(flag))
}

fn blank(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// Production entry: read stdin under the budget, resolve the endpoint, send.
///
/// `args` is `(agent, session flag)`. `env_session` is `AW_SESSION`. Endpoint
/// flags come from the same `Cli` the dispatcher already parsed; passing them
/// again keeps this function from reading the process environment for the token.
pub(crate) fn run_from_stdio(
    agent: &str,
    session_flag: Option<&str>,
    env_session: Option<&str>,
    endpoint_input: &EndpointInput,
) -> Outcome {
    let started = Instant::now();
    let endpoint = match endpoint::resolve(endpoint_input) {
        Ok(endpoint) => endpoint,
        // A bad `--http` is still a hook invocation. Exit 0, send nothing.
        Err(_) => return silent_ok(),
    };
    let payload = match read_stdin_bounded(started + HOOK_BUDGET) {
        Ok(bytes) => bytes,
        Err(_) => return silent_ok(),
    };
    let input = HookInput {
        agent,
        session_flag,
        session_env: env_session,
        endpoint: &endpoint,
        payload: &payload,
        started,
    };
    run(input, &mut PlatformHookTransport)
}

fn read_stdin_bounded(deadline: Instant) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 8 * 1024];
    let mut stdin = io::stdin();
    loop {
        if Instant::now() >= deadline || out.len() >= MAX_STDIN {
            break;
        }
        // A hook's stdin is a pipe that closes after one JSON value. A read
        // that would block is bounded by the caller's deadline only if the
        // platform returns. On a terminal this can wait; `aw hook` is not
        // meant to be typed at. The outer budget still abandons the send.
        let n = stdin.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let room = MAX_STDIN.saturating_sub(out.len());
        let take = n.min(room);
        out.extend_from_slice(&buf[..take]);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    /// `AW_POLICY` is process-global. Tests that set it take this lock.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        match LOCK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    struct Scripted {
        sent: Vec<Vec<u8>>,
        ok: bool,
    }

    impl HookTransport for Scripted {
        fn send(&mut self, _: &Endpoint, body: &[u8], _: Instant) -> io::Result<bool> {
            self.sent.push(body.to_vec());
            Ok(self.ok)
        }
    }

    fn endpoint() -> Endpoint {
        Endpoint::Unix {
            path: std::path::PathBuf::from("/tmp/aw-hook-test.sock"),
        }
    }

    fn input<'a>(agent: &'a str, payload: &'a [u8], endpoint: &'a Endpoint) -> HookInput<'a> {
        HookInput {
            agent,
            session_flag: None,
            session_env: None,
            endpoint,
            payload,
            started: Instant::now(),
        }
    }

    #[test]
    fn policy_off_stdout_is_empty_and_exit_is_zero() {
        let _guard = env_lock();
        std::env::remove_var(policy_file::POLICY_ENV);
        let endpoint = endpoint();
        let payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}"#;
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: true,
        };
        let outcome = run(input("claude-code", payload, &endpoint), &mut transport);
        assert_eq!(outcome.code, exit::OK);
        assert!(outcome.stdout.is_empty());
        assert!(outcome.stderr.is_empty());
    }

    #[test]
    fn claude_deny_rewrite_and_ask_match_the_documented_json() {
        let _guard = env_lock();
        let dir = std::env::temp_dir().join(format!("aw-hook-policy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.toml");
        fs::write(
            &path,
            r#"
enabled = true
[[rule]]
id = "no-rm-rf"
layer = ["hook"]
agent = ["claude-code", "codex"]
tool = ["Bash"]
match.command = { regex = '\brm\s+-rf\b' }
action = "deny"
reason = "不允许递归删除"

[[rule]]
id = "force-dry-run"
layer = ["hook"]
tool = ["Bash"]
match.command = { prefix = "terraform apply" }
action = "rewrite"
rewrite.command = { replace = ["terraform apply", "terraform plan"] }
reason = "只允许 plan"

[[rule]]
id = "ask-before-push"
layer = ["hook"]
tool = ["Bash"]
match.command = { prefix = "git push" }
action = "ask"
"#,
        )
        .unwrap();
        std::env::set_var(policy_file::POLICY_ENV, &path);
        let endpoint = endpoint();
        let audit = dir.join("audit.jsonl");
        std::env::set_var(intercept_audit::AUDIT_ENV, &audit);

        let deny_payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x","extra":1}}"#;
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: false,
        };
        let outcome = run(
            input("claude-code", deny_payload, &endpoint),
            &mut transport,
        );
        let deny: Value = serde_json::from_slice(&outcome.stdout).unwrap();
        assert_eq!(
            deny["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );
        assert_eq!(
            deny["hookSpecificOutput"]["permissionDecisionReason"],
            json!("不允许递归删除")
        );

        let rewrite_payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"terraform apply -auto-approve","extra":true}}"#;
        let outcome = run(
            input("claude-code", rewrite_payload, &endpoint),
            &mut transport,
        );
        let rewrite: Value = serde_json::from_slice(&outcome.stdout).unwrap_or_else(|_| {
            panic!(
                "stdout {} audit {}",
                String::from_utf8_lossy(&outcome.stdout),
                fs::read_to_string(&audit).unwrap_or_default()
            )
        });
        assert_eq!(
            rewrite["hookSpecificOutput"]["permissionDecision"],
            json!("allow"),
            "{rewrite} audit {}",
            fs::read_to_string(&audit).unwrap_or_default()
        );
        assert_eq!(
            rewrite["hookSpecificOutput"]["updatedInput"]["command"],
            json!("terraform plan -auto-approve")
        );
        assert_eq!(
            rewrite["hookSpecificOutput"]["updatedInput"]["extra"],
            json!(true)
        );

        let ask_payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin"}}"#;
        let outcome = run(input("claude-code", ask_payload, &endpoint), &mut transport);
        let ask: Value = serde_json::from_slice(&outcome.stdout).unwrap();
        assert_eq!(
            ask["hookSpecificOutput"]["permissionDecision"],
            json!("ask")
        );

        let codex_ask = run(input("codex", ask_payload, &endpoint), &mut transport);
        let codex: Value = serde_json::from_slice(&codex_ask.stdout).unwrap();
        assert_eq!(
            codex["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );

        let codex_rewrite = run(input("codex", rewrite_payload, &endpoint), &mut transport);
        let codex: Value = serde_json::from_slice(&codex_rewrite.stdout).unwrap();
        assert_eq!(
            codex["hookSpecificOutput"]["permissionDecision"],
            json!("allow")
        );
        assert!(codex["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap()
            .starts_with("terraform plan"));

        let audit_text = fs::read_to_string(&audit).unwrap_or_default();
        assert!(audit_text.contains("\"downgraded\":true") || audit_text.contains("downgraded"));
        assert!(!audit_text.contains("sk-abcdefghijklmnopqrstuvwxyz"));
        std::env::remove_var(policy_file::POLICY_ENV);
        std::env::remove_var(intercept_audit::AUDIT_ENV);
        let _ = fs::remove_dir_all(&dir);
    }
}
