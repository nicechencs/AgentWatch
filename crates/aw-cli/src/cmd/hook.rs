//! `aw hook <AGENT> [--session <SESSION>]` (P5-AGENT-02, P5-SEC-02).
//!
//! With no policy file, or with `enabled = false`, every path returns exit 0
//! and writes nothing an agent could parse as a decision. That is the
//! audit-only behaviour P5-AGENT-02 shipped, byte for byte.
//!
//! With a policy enabled (P5-SEC-02), the decision is made in this process
//! against the local file. It does not wait for the daemon. Stdout is the
//! agent's decision JSON (Claude Code or Codex). A deny, rewrite, ask, or
//! downgrade also posts one audit record. The post is abandoned at the
//! 200 ms budget; a miss falls back to a local jsonl file. The decision itself
//! is not on that clock: a slow stdin or a slow rule file still prints it.
//!
//! Only PreToolUse prints a decision. PostToolUse, SessionStart, and SessionEnd
//! print nothing and write no audit row, even when the policy file is broken
//! (design §5.2).
//!
//! Budget: 200 ms from the start of [`run`] until the daemon write is abandoned.
//! A slow connect or a missing daemon is a drop of the *report*.
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

/// stdin cap. A Write or Edit of a source file rides in one JSON object, and
/// 64 KiB turned every larger one into "not JSON", which a policy that is on
/// denies. 8 MiB covers a source file an editor would hand to a tool call
/// (Claude Code's own per-file ceiling is far above 64 KiB) without holding a
/// transcript. Past this the read stops and the payload is reported as too
/// big, which `on_error` decides — it is not treated as a complete payload.
const MAX_STDIN: usize = 8 * 1024 * 1024;

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
    /// Bytes already read from stdin. Production reads them to EOF, up to
    /// [`MAX_STDIN`]. The 200 ms budget does not cut this read short.
    pub payload: &'a [u8],
    /// The read stopped because the payload passed [`MAX_STDIN`]. The bytes are
    /// a prefix, not a payload, and must not be parsed as one.
    pub payload_truncated: bool,
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
///
/// The 200 ms budget bounds the audit post and the self-report, nothing else.
/// A slow rule file, a slow stdin, or a clock already past the budget still
/// produces the decision. Only an event that can decide prints one: PreToolUse
/// for Claude Code. PostToolUse, SessionStart, and SessionEnd print nothing
/// and write no audit row (design §5.2, step 1; Claude Code hooks page,
/// 2026-10-21: `permissionDecision` belongs to PreToolUse).
pub(crate) fn run(input: HookInput<'_>, transport: &mut dyn HookTransport) -> Outcome {
    let deadline = input.started + HOOK_BUDGET;
    let _ = (HookRegistry, parse_hook_quiet(input.agent, input.payload));
    let policy = policy_file::load_policy(
        policy_env_path().as_deref(),
        policy_file::user_config_home().as_deref(),
    );
    let session = resolve_session(input.session_env, input.session_flag);
    let decision_bytes = match &policy {
        PolicyLoad::Off => None,
        PolicyLoad::On(policy) => apply_decision(
            policy,
            input.agent,
            session.as_deref(),
            input.payload,
            input.payload_truncated,
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

/// Decide, audit, and render. `None` means print nothing (an allow, or an
/// event this step does not decide).
fn apply_decision(
    policy: &aw_pipeline::Policy,
    agent: &str,
    session: Option<&str>,
    payload: &[u8],
    payload_truncated: bool,
    endpoint: &Endpoint,
    deadline: Instant,
) -> Option<Vec<u8>> {
    if payload_truncated {
        // The bytes are a prefix. Parsing them would decide on a command the
        // operator never sent. Say why, and let `on_error` choose.
        return apply_on_error(
            policy.on_error(),
            agent,
            session,
            b"",
            endpoint,
            deadline,
            "hook 载荷过大，已按出错处理",
        );
    }
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
    if !decides(&subject) {
        return None;
    }
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
    let original = original_text(&subject, &value);
    let (audited, posted) = audit_decision(
        &subject,
        &decided,
        session,
        &original,
        rewritten_text.as_deref(),
        endpoint,
        deadline,
    );
    // A rewrite the client cannot confirm was stored is a deny. A local backup
    // counts as stored, so that path still rewrites. `stored: false`, a missed
    // deadline, and a daemon that never answered do not.
    //
    // The daemon may have the row anyway: its write can finish after this
    // client gave up, and that row says `rewrite`. Append the refusal so the
    // last line matches what ran.
    let rewrite_unconfirmed = decided.effective == Action::Rewrite && audited.client_unconfirmed;
    if rewrite_unconfirmed {
        let downgraded = audited.downgrade_rewrite(&decided);
        let _ = intercept_audit::correct_delivered(
            intercept_audit::backup_path(
                audit_env_path().as_deref(),
                intercept_audit::current_session_dir(session).as_deref(),
            )
            .as_deref(),
            Some(endpoint),
            &posted,
            &downgraded,
        );
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
        let _ = audit_decision(
            subject,
            &decision,
            session,
            &on_error_original(subject),
            None,
            endpoint,
            deadline,
        )
        .0;
        return None;
    }
    let value = Value::Null;
    let (rendered, _) = render_decision(agent, subject, &decision, &value);
    let _ = audit_decision(
        subject,
        &decision,
        session,
        &on_error_original(subject),
        None,
        endpoint,
        deadline,
    )
    .0;
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
    // A broken file or a bad payload on SessionStart / PostToolUse must not
    // print a deny: those events have no permissionDecision, and a printed one
    // is a non-blocking error (the tool already ran, or the session proceeds).
    if !decides(&subject) {
        return None;
    }
    let original = on_error_original(&subject);
    if decision.effective == Action::Allow {
        let _ = audit_decision(
            &subject, &decision, session, &original, None, endpoint, deadline,
        )
        .0;
        return None;
    }
    let (rendered, _) = render_decision(agent, &subject, &decision, &value);
    let _ = audit_decision(
        &subject, &decision, session, &original, None, endpoint, deadline,
    )
    .0;
    rendered.and_then(|body| json_stdout(&body))
}

/// Text stored as `before` when the decision is `on_error`, not a rule hit.
///
/// The observed command, path, or URL when the payload still parsed. Otherwise
/// the reason itself: an empty string becomes an empty `before_summary`, and
/// `POST /api/v1/agent/intercept` answers 400, so the deny never lands in
/// `intercept_events`. The policy file's bytes are not part of this string.
fn on_error_original(subject: &Subject) -> String {
    subject
        .command
        .clone()
        .or_else(|| subject.path.clone())
        .or_else(|| subject.url.clone())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "（未能取得原文）".to_owned())
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
) -> (AuditDelivery, aw_pipeline::AuditRecord) {
    // A session id is the salt when one exists. Without one, the salt is
    // process-local and `'static`, so the two paths cannot share one binding.
    let mut record = if let Some(id) = session.filter(|text| !text.is_empty()) {
        intercept_audit::record_for(
            subject,
            decision,
            id.as_bytes(),
            original,
            rewritten,
            session,
        )
    } else {
        intercept_audit::record_for(
            subject,
            decision,
            intercept_audit::process_salt(),
            original,
            rewritten,
            session,
        )
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let backup = intercept_audit::backup_path(
        audit_env_path().as_deref(),
        intercept_audit::current_session_dir(session).as_deref(),
    );
    let delivery = intercept_audit::deliver(
        Some(endpoint),
        backup.as_deref(),
        &mut record,
        remaining.min(Duration::from_millis(50)),
    );
    (delivery, record)
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

/// Whether this event is one the hook may decide.
///
/// Claude Code (hooks page, 2026-10-21): `permissionDecision` belongs to
/// PreToolUse. PostToolUse can only replace the model's view of a result
/// (`updatedToolOutput`) and cannot undo the call. SessionStart and SessionEnd
/// add context; they cannot allow or deny. Step 1 does not rewrite tool
/// results, so those events print nothing and record nothing — a deny printed
/// for them would be a row for a call that was not refused.
///
/// A payload that names no event is treated as PreToolUse. That is the event
/// a hook is injected for, and dropping it would let a tool run.
fn decides(subject: &Subject) -> bool {
    !matches!(
        subject.event.as_deref(),
        Some("PostToolUse" | "SessionStart" | "SessionEnd")
    )
}

fn render_decision(
    agent: &str,
    subject: &Subject,
    decision: &Decision,
    payload: &Value,
) -> (Option<Value>, Option<String>) {
    // `rewrite` is not a permissionDecision. Both agents express it as
    // `allow` plus the replacement object. That `allow` does skip Claude
    // Code's own permission prompt (hooks page: `permissionDecision: "allow"`
    // skips the prompt). Step 1 still prints it: `ask` plus `updatedInput` has
    // nobody to answer under `claude -p`, so the rewritten command would stall.
    // A later switch can put this behind `auto_approve`. A downgraded rewrite
    // is already `deny` and must not also carry updatedInput.
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
            hook_event_name(subject),
        )
        .map(|decision: CodexDecision| decision.to_json());
        return (rendered, text);
    }
    // Claude Code, and any other agent id that speaks the same hook JSON.
    // An unknown agent still gets the Claude shape: that is the format
    // `aw hook claude-code` documents. Codex is the only other one.
    // PostToolUse is not rendered here. [`decides`] returns first, so a
    // rewrite rule never becomes `updatedToolOutput` on a call that already
    // ran. `updated_output` stays available for a later step that opts in.
    let updated = updated_object(payload, subject, decision);
    let text = rewrite_audit_text(decision);
    let rendered = claude_decision(
        permission,
        reason,
        updated.as_ref(),
        None,
        hook_event_name(subject),
    )
    .and_then(|decision: HookDecision| decision.to_json());
    (rendered, text)
}

/// Name written into `hookSpecificOutput.hookEventName`. The input's
/// `hook_event_name` when it had one. A payload that omitted it still has to
/// name an event, or Claude Code treats the object as a non-blocking error
/// and runs the tool. `PreToolUse` is that fallback: it is the event that
/// can still deny.
fn hook_event_name(subject: &Subject) -> &str {
    subject.event.as_deref().unwrap_or("PreToolUse")
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

/// Production entry: read stdin to EOF, resolve the endpoint, decide, send.
///
/// `args` is `(agent, session flag)`. `env_session` is `AW_SESSION`. Endpoint
/// flags come from the same `Cli` the dispatcher already parsed; passing them
/// again keeps this function from reading the process environment for the token.
///
/// The endpoint is only where the audit goes. A bad `--http` still decides:
/// the audit has nowhere to go, so a rewrite is printed as a deny. A stdin
/// that errors is the same kind of failure as a payload that is not JSON.
pub(crate) fn run_from_stdio(
    agent: &str,
    session_flag: Option<&str>,
    env_session: Option<&str>,
    endpoint_input: &EndpointInput,
) -> Outcome {
    let started = Instant::now();
    let endpoint = endpoint::resolve(endpoint_input);
    let read = read_stdin_capped(MAX_STDIN);
    let (payload, truncated, failed) = match read {
        Ok(read) => (read.bytes, read.truncated, false),
        Err(_) => (Vec::new(), false, true),
    };
    // A bad endpoint still has to reach `run`, which is what loads the policy.
    // `run` only uses the endpoint for the audit post and the self-report, and
    // a post to nowhere is the documented "daemon not there" path.
    let fallback = Endpoint::Unix {
        path: std::path::PathBuf::from(if cfg!(windows) {
            r"\\.\pipe\aw-hook-no-endpoint"
        } else {
            "/aw-hook-no-endpoint"
        }),
    };
    let endpoint_ref = endpoint.as_ref().unwrap_or(&fallback);
    if failed {
        return decide_without_payload(
            agent,
            session_flag,
            env_session,
            endpoint_ref,
            started,
            "hook 载荷读不了，已按出错处理",
        );
    }
    let input = HookInput {
        agent,
        session_flag,
        session_env: env_session,
        endpoint: endpoint_ref,
        payload: &payload,
        payload_truncated: truncated,
        started,
    };
    run(input, &mut PlatformHookTransport)
}

/// Policy on, but there is no payload to judge. Same answer as a payload that
/// is not JSON: `on_error`, which defaults to deny. Policy off stays silent.
fn decide_without_payload(
    agent: &str,
    session_flag: Option<&str>,
    env_session: Option<&str>,
    endpoint: &Endpoint,
    started: Instant,
    reason: &str,
) -> Outcome {
    let deadline = started + HOOK_BUDGET;
    let policy = policy_file::load_policy(
        policy_env_path().as_deref(),
        policy_file::user_config_home().as_deref(),
    );
    let session = resolve_session(env_session, session_flag);
    let on_error = match &policy {
        PolicyLoad::Off => return silent_ok(),
        PolicyLoad::On(policy) => policy.on_error(),
        PolicyLoad::Broken => OnError::Deny,
    };
    let stdout = apply_on_error(
        on_error,
        agent,
        session.as_deref(),
        b"",
        endpoint,
        deadline,
        reason,
    );
    match stdout {
        Some(stdout) => Outcome {
            code: exit::OK,
            stdout,
            stderr: Vec::new(),
        },
        None => silent_ok(),
    }
}

struct StdinRead {
    bytes: Vec<u8>,
    /// Stopped at `cap` with more bytes still waiting. `bytes` is a prefix.
    truncated: bool,
}

/// Read stdin until EOF or `cap`.
///
/// Claude Code gives a command hook 600 s, and the JSON arrives as one write
/// followed by a close. The 200 ms budget is for the audit post; cutting the
/// read off there dropped the decision. `cap` is [`MAX_STDIN`]: past it the
/// caller reports "too big" instead of parsing a prefix.
fn read_stdin_capped(cap: usize) -> io::Result<StdinRead> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 8 * 1024];
    let mut stdin = io::stdin();
    loop {
        if out.len() >= cap {
            return Ok(StdinRead {
                bytes: out,
                truncated: true,
            });
        }
        // A hook's stdin is a pipe that closes after one JSON value. On a
        // terminal this waits for the operator; `aw hook` is not meant to be
        // typed at.
        let n = stdin.read(&mut buf)?;
        if n == 0 {
            return Ok(StdinRead {
                bytes: out,
                truncated: false,
            });
        }
        let room = cap.saturating_sub(out.len());
        let take = n.min(room);
        out.extend_from_slice(&buf[..take]);
        if take < n {
            return Ok(StdinRead {
                bytes: out,
                truncated: true,
            });
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;

    // `AW_POLICY` is process-global. The lock lives in `policy_file` so `aw run`
    // tests that set the same variable cannot run beside these.
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
            payload_truncated: false,
            started: Instant::now(),
        }
    }

    #[test]
    fn policy_off_stdout_is_empty_and_exit_is_zero() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let _policy_env = policy_file::EnvVarGuard::unset(policy_file::POLICY_ENV);
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
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = scratch("hook-policy");
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
        let policy_env = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &path);
        let endpoint = endpoint();
        let audit = dir.join("audit.jsonl");
        let _audit_env = policy_file::EnvVarGuard::set(intercept_audit::AUDIT_ENV, &audit);

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
            deny["hookSpecificOutput"]["hookEventName"],
            json!("PreToolUse")
        );
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
            rewrite["hookSpecificOutput"]["hookEventName"],
            json!("PreToolUse")
        );
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
            ask["hookSpecificOutput"]["hookEventName"],
            json!("PreToolUse")
        );
        assert_eq!(
            ask["hookSpecificOutput"]["permissionDecision"],
            json!("ask")
        );

        let codex_ask = run(input("codex", ask_payload, &endpoint), &mut transport);
        let codex: Value = serde_json::from_slice(&codex_ask.stdout).unwrap();
        assert_eq!(
            codex["hookSpecificOutput"]["hookEventName"],
            json!("PreToolUse")
        );
        assert_eq!(
            codex["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );

        let codex_rewrite = run(input("codex", rewrite_payload, &endpoint), &mut transport);
        let codex: Value = serde_json::from_slice(&codex_rewrite.stdout).unwrap();
        assert_eq!(
            codex["hookSpecificOutput"]["hookEventName"],
            json!("PreToolUse")
        );
        assert_eq!(
            codex["hookSpecificOutput"]["permissionDecision"],
            json!("allow")
        );
        assert!(codex["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap()
            .starts_with("terraform plan"));

        // PostToolUse cannot carry permissionDecision (Claude Code hooks page,
        // 2026-10-21). Step 1 does not rewrite tool results either, so the whole
        // stdout stays empty and the audit file does not gain a row.
        let audit_before_post = fs::read_to_string(&audit).unwrap_or_default();
        let post_payload = br#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"terraform apply"},"tool_response":{"ok":true}}"#;
        let post = run(
            input("claude-code", post_payload, &endpoint),
            &mut transport,
        );
        assert_eq!(post.code, exit::OK);
        assert!(
            post.stdout.is_empty(),
            "PostToolUse printed {}",
            String::from_utf8_lossy(&post.stdout)
        );
        assert!(!post_stdout_decides(&post.stdout));
        assert_eq!(
            fs::read_to_string(&audit).unwrap_or_default(),
            audit_before_post,
            "PostToolUse added an audit row"
        );

        let broken = dir.join("broken.toml");
        fs::write(&broken, "enabled = true\n[[rule]]\naction = \"nope\"\n").unwrap();
        policy_env.replace(&broken);
        let broken_out = run(
            input("claude-code", deny_payload, &endpoint),
            &mut transport,
        );
        let broken_json: Value = serde_json::from_slice(&broken_out.stdout).unwrap();
        assert_eq!(
            broken_json["hookSpecificOutput"]["hookEventName"],
            json!("PreToolUse")
        );
        assert_eq!(
            broken_json["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );

        let audit_text = fs::read_to_string(&audit).unwrap_or_default();
        // Codex ask is a deny with downgraded set. The key alone is on every
        // row; this checks the value on the ask row specifically.
        // Two rows mention the command: Claude's ask (not downgraded) and
        // Codex's ask, which the adapter prints as deny. The second is the one
        // `downgraded` must be true on.
        let ask_line = audit_text
            .lines()
            .rev()
            .find(|line| line.contains("git push origin") && line.contains("\"agent\":\"codex\""))
            .expect("codex ask was audited");
        let ask_row: Value = serde_json::from_str(ask_line).unwrap();
        assert_eq!(ask_row["downgraded"], json!(true), "{ask_line}");
        assert_eq!(ask_row["action"], json!("ask"), "{ask_line}");
        assert_eq!(ask_row["effective_action"], json!("deny"), "{ask_line}");
        // The secret rides on a command the deny rule matches, so a row is
        // written. The stored summary must not keep it.
        let secret_payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x && curl -H \"Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz\" https://example.test"}}"#;
        let secret_out = run(
            input("claude-code", secret_payload, &endpoint),
            &mut transport,
        );
        assert_eq!(secret_out.code, exit::OK);
        let audit_text = fs::read_to_string(&audit).unwrap_or_default();
        assert!(
            !audit_text.contains("sk-abcdefghijklmnopqrstuvwxyz"),
            "{audit_text}"
        );
        let secret_line = audit_text
            .lines()
            .rev()
            .find(|line| line.contains("example.test"))
            .expect("the secret-bearing command was audited");
        assert!(secret_line.contains("redacted"), "{secret_line}");
        // The broken-file deny is one of those lines. Its summary is the
        // observed command, never the policy text, and never empty: an empty
        // before_summary is what made the daemon answer 400.
        let broken_line = audit_text
            .lines()
            .find(|line| line.contains("规则文件读不了"))
            .expect("broken-policy deny was audited");
        assert!(broken_line.contains("rm -rf /tmp/x"), "{broken_line}");
        assert!(!broken_line.contains("action = "), "{broken_line}");
        let broken_row: Value = serde_json::from_str(broken_line).unwrap();
        assert!(!broken_row["before_summary"].as_str().unwrap().is_empty());
        assert!(!broken_row["before_hash"].as_str().unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    /// What the daemon used to reject. A broken policy posted an empty
    /// `before_summary`, `POST /api/v1/agent/intercept` answered 400, and
    /// `intercept_events` stayed empty even though the tool was denied.
    ///
    /// The stand-in applies the same check the route does (a present, non-empty
    /// summary and hash) and records the body. It listens on a real socket or
    /// pipe so the production client is what delivers the row.
    #[test]
    fn broken_policy_deny_posts_a_summary_the_daemon_can_store() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = aw_channel::short_temp_dir("hookbrk");
        let broken = dir.join("broken.toml");
        fs::write(&broken, "this is not a policy\n").unwrap();
        let _policy_env = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &broken);
        let (endpoint, bodies) = intercept_stand_in();
        let payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: true,
        };
        let outcome = run(input("claude-code", payload, &endpoint), &mut transport);
        let body: Value = serde_json::from_slice(&outcome.stdout).unwrap();
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );
        let posted = bodies.lock().expect("stand-in").clone();
        let row = posted
            .iter()
            .find(|value| {
                value["reason"]
                    .as_str()
                    .unwrap_or("")
                    .contains("规则文件读不了")
            })
            .expect("broken-policy deny was posted");
        let summary = row["before_summary"].as_str().unwrap_or("");
        let hash = row["before_hash"].as_str().unwrap_or("");
        assert!(summary.contains("echo hello"), "{summary}");
        assert!(!summary.is_empty() && !hash.is_empty(), "{row}");
        assert!(!summary.contains("this is not a policy"), "{summary}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Accepts one loopback HTTP request and keeps the JSON body when it would
    /// pass the daemon's field check: a present, non-empty summary and hash.
    /// Loopback TCP is the channel that exists on all three systems without a
    /// named pipe, so the production client is what delivers the row.
    fn intercept_stand_in() -> (Endpoint, std::sync::Arc<std::sync::Mutex<Vec<Value>>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let saved = std::sync::Arc::clone(&bodies);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0_u8; 16 * 1024];
            let Ok(n) = stream.read(&mut buf) else {
                return;
            };
            let text = String::from_utf8_lossy(&buf[..n]);
            let json_at = text.find("\r\n\r\n").map(|pos| pos + 4).unwrap_or(0);
            let value = serde_json::from_str::<Value>(&text[json_at..]).unwrap_or(Value::Null);
            let ok = value["before_summary"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
                && value["before_hash"]
                    .as_str()
                    .is_some_and(|text| !text.is_empty());
            if ok {
                saved.lock().expect("bodies").push(value);
            }
            // `{}` is a 200 the old client treated as stored. The route's
            // success body is `{"stored": true}`; anything else is not a row.
            let (status, reply_body) = if ok {
                ("200 OK", "{\"stored\":true}")
            } else {
                ("400 Bad Request", "{}")
            };
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{reply_body}",
                reply_body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        });
        let endpoint = endpoint::resolve(&EndpointInput {
            socket: None,
            http: Some(format!("http://127.0.0.1:{port}")),
            token: Some("hook-broken-test".to_owned()),
            token_env: None,
        })
        .expect("loopback endpoint");
        (endpoint, bodies)
    }

    /// Point `XDG_CONFIG_HOME`, `HOME`, and `APPDATA` at an empty directory
    /// under this crate, so a developer's real `policy.toml` cannot decide a
    /// test. Restored on drop, including after a panic.
    fn home_guard() -> HomeGuard {
        HomeGuard::new()
    }

    struct HomeGuard {
        dir: std::path::PathBuf,
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl HomeGuard {
        fn new() -> Self {
            let dir = scratch("hook-home");
            let saved = ["XDG_CONFIG_HOME", "HOME", "APPDATA"]
                .into_iter()
                .map(|key| {
                    let previous = std::env::var_os(key);
                    std::env::set_var(key, &dir);
                    (key, previous)
                })
                .collect();
            Self { dir, saved }
        }
    }

    impl Drop for HomeGuard {
        fn drop(&mut self) {
            for (key, previous) in self.saved.drain(..) {
                match previous {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// Scratch directory inside the crate, never `/tmp`. Windows path limits
    /// do not apply: nothing here is a socket name.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("hook-tests")
            .join(format!(
                "{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `true` when stdout carries a decision or a rewrite. Observational
    /// events must not.
    fn post_stdout_decides(stdout: &[u8]) -> bool {
        let text = String::from_utf8_lossy(stdout);
        text.contains("permissionDecision")
            || text.contains("updatedInput")
            || text.contains("updatedToolOutput")
            || text.contains("\"decision\"")
    }

    /// The 200 ms budget used to return before the decision, so a slow rule
    /// file (or a deadline already behind) printed nothing and exited 0.
    /// The decision is not on that clock: a deny still prints.
    #[test]
    fn past_deadline_still_denies_when_policy_is_on() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = scratch("deadline");
        let path = dir.join("policy.toml");
        fs::write(
            &path,
            "enabled = true\n[[rule]]\nid = \"no-rm\"\nlayer = [\"hook\"]\n\
             match.command = { prefix = \"rm \" }\naction = \"deny\"\n\
             reason = \"no rm\"\n",
        )
        .unwrap();
        let _policy = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &path);
        let _audit =
            policy_file::EnvVarGuard::set(intercept_audit::AUDIT_ENV, &dir.join("audit.jsonl"));
        let endpoint = endpoint();
        let payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf x"}}"#;
        let mut started = input("claude-code", payload, &endpoint);
        // Well past the budget, not 50 ms past it: the audit post is allowed
        // one 50 ms attempt, and a deadline that close still has that attempt
        // left. The bug was returning before the decision at all.
        started.started = Instant::now() - Duration::from_secs(5);
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: true,
        };
        let outcome = run(started, &mut transport);
        assert_eq!(outcome.code, exit::OK);
        let body: Value = serde_json::from_slice(&outcome.stdout).unwrap_or_else(|_| {
            panic!(
                "expected a deny, got {}",
                String::from_utf8_lossy(&outcome.stdout)
            )
        });
        assert_eq!(
            body["hookSpecificOutput"]["hookEventName"],
            json!("PreToolUse")
        );
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecisionReason"],
            json!("no rm")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// `on_error = "allow"` still decides: the miss is reported, not hidden
    /// behind an empty stdout that looks like "policy off".
    #[test]
    fn past_deadline_with_on_error_allow_prints_nothing() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = scratch("deadline-allow");
        let path = dir.join("policy.toml");
        fs::write(
            &path,
            "enabled = true\non_error = \"allow\"\n[[rule]]\nid = \"slow\"\n\
             layer = [\"hook\"]\naction = \"deny\"\nmatch.command = { exact = \"never\" }\n",
        )
        .unwrap();
        let _policy = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &path);
        let endpoint = endpoint();
        let payload =
            br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let mut started = input("claude-code", payload, &endpoint);
        started.started = Instant::now() - HOOK_BUDGET - Duration::from_millis(50);
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: true,
        };
        let outcome = run(started, &mut transport);
        assert_eq!(outcome.code, exit::OK);
        assert!(
            outcome.stdout.is_empty(),
            "{}",
            String::from_utf8_lossy(&outcome.stdout)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A truncated stdin is a decision failure, not a silent allow, once the
    /// operator has turned intercept on.
    #[test]
    fn truncated_payload_denies_when_policy_is_on() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = scratch("truncated");
        let path = dir.join("policy.toml");
        fs::write(
            &path,
            "enabled = true\n[[rule]]\nid = \"a\"\naction = \"allow\"\n",
        )
        .unwrap();
        let _policy = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &path);
        let endpoint = endpoint();
        let payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"#;
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: true,
        };
        let outcome = run(input("claude-code", payload, &endpoint), &mut transport);
        let body: Value = serde_json::from_slice(&outcome.stdout).unwrap_or_else(|_| {
            panic!(
                "truncated stdin was allowed: {}",
                String::from_utf8_lossy(&outcome.stdout)
            )
        });
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecisionReason"],
            json!("hook 载荷不是 JSON")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A 70 KiB Write is a normal tool call. The old 64 KiB cap turned it into
    /// "not JSON" and denied it.
    #[test]
    fn seventy_kilobyte_write_is_decided_not_truncated() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = scratch("big-write");
        let path = dir.join("policy.toml");
        fs::write(
            &path,
            "enabled = true\n[[rule]]\nid = \"no-secret\"\nlayer = [\"hook\"]\n\
             tool = [\"Write\"]\nmatch.path = { exact = \"/tmp/secret.txt\" }\n\
             action = \"deny\"\nreason = \"不写这个文件\"\n",
        )
        .unwrap();
        let _policy = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &path);
        let endpoint = endpoint();
        let content = "a".repeat(70 * 1024);
        let payload = serde_json::to_vec(&json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": { "file_path": "/tmp/notes.txt", "content": content }
        }))
        .unwrap();
        assert!(payload.len() > 70 * 1024, "{}", payload.len());
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: true,
        };
        let outcome = run(input("claude-code", &payload, &endpoint), &mut transport);
        assert_eq!(outcome.code, exit::OK);
        assert!(
            outcome.stdout.is_empty(),
            "a non-matching Write was refused: {}",
            String::from_utf8_lossy(&outcome.stdout)
        );

        let matching = serde_json::to_vec(&json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": { "file_path": "/tmp/secret.txt", "content": content }
        }))
        .unwrap();
        let denied = run(input("claude-code", &matching, &endpoint), &mut transport);
        let body: Value = serde_json::from_slice(&denied.stdout).unwrap_or_else(|_| {
            panic!(
                "matching Write was not denied: {}",
                String::from_utf8_lossy(&denied.stdout)
            )
        });
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecisionReason"],
            json!("不写这个文件")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Over the cap the payload cannot be judged, so `on_error` applies and
    /// the reason says the payload was too big.
    #[test]
    fn payload_over_the_cap_denies_with_a_size_reason() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = scratch("over-cap");
        let path = dir.join("policy.toml");
        fs::write(
            &path,
            "enabled = true\n[[rule]]\nid = \"a\"\naction = \"allow\"\n",
        )
        .unwrap();
        let _policy = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &path);
        let endpoint = endpoint();
        let content = "b".repeat(MAX_STDIN);
        let payload = serde_json::to_vec(&json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": { "file_path": "/tmp/huge.txt", "content": content }
        }))
        .unwrap();
        assert!(payload.len() > MAX_STDIN);
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: true,
        };
        let mut over = input("claude-code", &payload, &endpoint);
        over.payload_truncated = true;
        let outcome = run(over, &mut transport);
        let body: Value = serde_json::from_slice(&outcome.stdout).unwrap_or_else(|_| {
            panic!(
                "oversized payload was allowed: {}",
                String::from_utf8_lossy(&outcome.stdout)
            )
        });
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );
        let reason = body["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or("");
        assert!(reason.contains("过大"), "{reason}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// SessionStart and SessionEnd have no decision fields. A broken policy
    /// used to print `permissionDecision: deny` for them too.
    #[test]
    fn session_events_and_broken_policy_print_nothing() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = scratch("session-events");
        let broken = dir.join("broken.toml");
        fs::write(&broken, "enabled = true\n[[rule]\n").unwrap();
        let _policy = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &broken);
        let audit = dir.join("audit.jsonl");
        let _audit = policy_file::EnvVarGuard::set(intercept_audit::AUDIT_ENV, &audit);
        let endpoint = endpoint();
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: false,
        };
        for event in ["SessionStart", "SessionEnd", "PostToolUse"] {
            let payload = format!(
                "{{\"hook_event_name\":\"{event}\",\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"rm -rf x\"}}}}"
            );
            let outcome = run(
                input("claude-code", payload.as_bytes(), &endpoint),
                &mut transport,
            );
            assert_eq!(outcome.code, exit::OK, "{event}");
            assert!(
                outcome.stdout.is_empty(),
                "{event} printed {}",
                String::from_utf8_lossy(&outcome.stdout)
            );
            assert!(!post_stdout_decides(&outcome.stdout), "{event}");
        }
        assert!(
            !fs::read_to_string(&audit)
                .unwrap_or_default()
                .contains("deny"),
            "an observational event wrote an audit row"
        );
        // The same broken file still denies a real PreToolUse.
        let pre = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf x"}}"#;
        let outcome = run(input("claude-code", pre, &endpoint), &mut transport);
        let body: Value = serde_json::from_slice(&outcome.stdout).unwrap();
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A rewrite whose audit cannot be stored becomes a deny. The transport
    /// refuses the post and no backup path is set, so both copies fail.
    #[test]
    fn rewrite_with_nowhere_to_audit_is_printed_as_deny() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = scratch("rewrite-drop");
        let path = dir.join("policy.toml");
        fs::write(
            &path,
            "enabled = true\n[[rule]]\nid = \"force-dry-run\"\nlayer = [\"hook\"]\n\
             tool = [\"Bash\"]\nmatch.command = { prefix = \"terraform apply\" }\n\
             action = \"rewrite\"\n\
             rewrite.command = { replace = [\"terraform apply\", \"terraform plan\"] }\n\
             reason = \"只允许 plan\"\n",
        )
        .unwrap();
        let _policy = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &path);
        let _audit = policy_file::EnvVarGuard::unset(intercept_audit::AUDIT_ENV);
        let endpoint = endpoint();
        let payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"terraform apply -auto-approve","extra":true}}"#;
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: false,
        };
        let outcome = run(input("claude-code", payload, &endpoint), &mut transport);
        let body: Value = serde_json::from_slice(&outcome.stdout).unwrap_or_else(|_| {
            panic!(
                "rewrite was not downgraded: {}",
                String::from_utf8_lossy(&outcome.stdout)
            )
        });
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );
        assert!(
            body["hookSpecificOutput"].get("updatedInput").is_none(),
            "{body}"
        );
        let reason = body["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or("");
        assert!(reason.contains("审计写不进去"), "{reason}");
        assert!(reason.contains("只允许 plan"), "{reason}");
        let _ = fs::remove_dir_all(&dir);
    }

    fn input_session<'a>(
        agent: &'a str,
        payload: &'a [u8],
        endpoint: &'a Endpoint,
        session: &'a str,
    ) -> HookInput<'a> {
        let mut hooked = input(agent, payload, endpoint);
        hooked.session_env = Some(session);
        hooked
    }

    /// No `AW_INTERCEPT_AUDIT`. The deny line is
    /// `<XDG_STATE_HOME>/agentwatch/sessions/<id>/intercept-audit.jsonl`.
    #[test]
    fn hook_without_audit_env_writes_the_session_directory() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = scratch("hook-session-dir");
        let state = dir.join("state");
        fs::create_dir_all(&state).unwrap();
        let policy = dir.join("policy.toml");
        fs::write(
            &policy,
            "enabled = true\n[[rule]]\nid = \"no-rm\"\nlayer = [\"hook\"]\n\
             tool = [\"Bash\"]\naction = \"deny\"\nreason = \"不允许\"\n",
        )
        .unwrap();
        let _policy = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &policy);
        let _audit = policy_file::EnvVarGuard::unset(intercept_audit::AUDIT_ENV);
        let _state = policy_file::EnvVarGuard::set_text("XDG_STATE_HOME", &state);
        let endpoint = endpoint();
        let payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}"#;
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: false,
        };
        let outcome = run(
            input_session("claude-code", payload, &endpoint, "s-hook"),
            &mut transport,
        );
        let body: Value = serde_json::from_slice(&outcome.stdout).unwrap_or_else(|_| {
            panic!(
                "deny produced no json: {}",
                String::from_utf8_lossy(&outcome.stdout)
            )
        });
        assert_eq!(
            body["hookSpecificOutput"]["hookEventName"],
            json!("PreToolUse"),
            "{body}"
        );
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("deny"),
            "{body}"
        );
        let audit = state
            .join("agentwatch")
            .join("sessions")
            .join("s-hook")
            .join("intercept-audit.jsonl");
        let text = fs::read_to_string(&audit)
            .unwrap_or_else(|_| panic!("no session backup at {}", audit.display()));
        let row: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(row["session"], json!("s-hook"), "{row}");
        assert_eq!(row["effective_action"], json!("deny"), "{row}");
        assert_eq!(row["delivered"], json!("local_backup"), "{row}");
        assert_eq!(row["layer"], json!("hook"), "{row}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A local session backup is stored (design §5.3), so a rewrite still runs
    /// when the daemon is not there.
    #[test]
    fn rewrite_with_a_session_backup_still_rewrites() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = scratch("hook-session-rewrite");
        let state = dir.join("state");
        fs::create_dir_all(&state).unwrap();
        let policy = dir.join("policy.toml");
        fs::write(
            &policy,
            "enabled = true\n[[rule]]\nid = \"force-dry-run\"\nlayer = [\"hook\"]\n\
             tool = [\"Bash\"]\nmatch.command = { prefix = \"terraform apply\" }\n\
             action = \"rewrite\"\n\
             rewrite.command = { replace = [\"terraform apply\", \"terraform plan\"] }\n\
             reason = \"只允许 plan\"\n",
        )
        .unwrap();
        let _policy = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &policy);
        let _audit = policy_file::EnvVarGuard::unset(intercept_audit::AUDIT_ENV);
        let _state = policy_file::EnvVarGuard::set_text("XDG_STATE_HOME", &state);
        let endpoint = endpoint();
        let payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"terraform apply -auto-approve","extra":true}}"#;
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: false,
        };
        let outcome = run(
            input_session("claude-code", payload, &endpoint, "s-hook"),
            &mut transport,
        );
        let body: Value = serde_json::from_slice(&outcome.stdout).unwrap_or_else(|_| {
            panic!(
                "rewrite was downgraded: {}",
                String::from_utf8_lossy(&outcome.stdout)
            )
        });
        assert_eq!(
            body["hookSpecificOutput"]["hookEventName"],
            json!("PreToolUse"),
            "{body}"
        );
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("allow"),
            "{body}"
        );
        assert_eq!(
            body["hookSpecificOutput"]["updatedInput"]["command"],
            json!("terraform plan -auto-approve"),
            "{body}"
        );
        let audit = state
            .join("agentwatch")
            .join("sessions")
            .join("s-hook")
            .join("intercept-audit.jsonl");
        let text = fs::read_to_string(&audit)
            .unwrap_or_else(|_| panic!("no session backup at {}", audit.display()));
        let row: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(row["session"], json!("s-hook"), "{row}");
        assert_eq!(row["effective_action"], json!("rewrite"), "{row}");
        assert_eq!(row["delivered"], json!("local_backup"), "{row}");
        assert_eq!(row["downgraded"], json!(false), "{row}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// 200 with `{"stored": false}` used to count as delivered, so the rewrite
    /// ran and nothing was in the database. It is a deny.
    #[test]
    fn stored_false_downgrades_a_rewrite() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = scratch("stored-false");
        let path = dir.join("policy.toml");
        fs::write(
            &path,
            "enabled = true\n[[rule]]\nid = \"force-dry-run\"\nlayer = [\"hook\"]\n\
             tool = [\"Bash\"]\nmatch.command = { prefix = \"terraform apply\" }\n\
             action = \"rewrite\"\n\
             rewrite.command = { replace = [\"terraform apply\", \"terraform plan\"] }\n",
        )
        .unwrap();
        let _policy = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &path);
        let _audit = policy_file::EnvVarGuard::unset(intercept_audit::AUDIT_ENV);
        let (endpoint, _bodies) = stored_false_stand_in();
        let payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"terraform apply"}}"#;
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: true,
        };
        let outcome = run(input("claude-code", payload, &endpoint), &mut transport);
        let body: Value = serde_json::from_slice(&outcome.stdout).unwrap_or_else(|_| {
            panic!(
                "stored:false still rewrote: {}",
                String::from_utf8_lossy(&outcome.stdout)
            )
        });
        assert_eq!(
            body["hookSpecificOutput"]["hookEventName"],
            json!("PreToolUse"),
            "{body}"
        );
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("deny"),
            "{body}"
        );
        assert!(body["hookSpecificOutput"].get("updatedInput").is_none());
        let reason = body["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or("");
        assert!(reason.contains("审计写不进去"), "{reason}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Answers 200 and `{"stored": false}`, the body the daemon sends when no
    /// database is open.
    fn stored_false_stand_in() -> (Endpoint, std::sync::Arc<std::sync::Mutex<Vec<Value>>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0_u8; 8 * 1024];
            let _ = stream.read(&mut buf);
            let reply_body = "{\"stored\":false,\"storage\":\"not_ready\"}";
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{reply_body}",
                reply_body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        });
        let endpoint = endpoint::resolve(&EndpointInput {
            socket: None,
            http: Some(format!("http://127.0.0.1:{port}")),
            token: Some("hook-stored-false".to_owned()),
            token_env: None,
        })
        .expect("loopback endpoint");
        (endpoint, bodies)
    }

    /// The daemon stored the rewrite, then answered slower than the post
    /// budget. The client downgrades to a deny. The stored row must not be the
    /// last word: the correction line says `deny`.
    #[test]
    fn slow_daemon_rewrite_is_corrected_to_deny() {
        let _guard = policy_file::env_lock();
        let _home = home_guard();
        let dir = scratch("slow-daemon");
        let path = dir.join("policy.toml");
        fs::write(
            &path,
            "enabled = true\n[[rule]]\nid = \"force-dry-run\"\nlayer = [\"hook\"]\n\
             tool = [\"Bash\"]\nmatch.command = { prefix = \"terraform apply\" }\n\
             action = \"rewrite\"\n\
             rewrite.command = { replace = [\"terraform apply\", \"terraform plan\"] }\n\
             reason = \"只允许 plan\"\n",
        )
        .unwrap();
        let _policy = policy_file::EnvVarGuard::set(policy_file::POLICY_ENV, &path);
        // No local backup. The daemon's row is the only copy, and it says
        // rewrite until the correction arrives.
        let _audit = policy_file::EnvVarGuard::unset(intercept_audit::AUDIT_ENV);
        let (endpoint, bodies) = slow_intercept_stand_in();
        let payload = br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"terraform apply"}}"#;
        let mut started = input("claude-code", payload, &endpoint);
        // Inside the 200 ms hook budget, past the 50 ms the audit post is
        // allowed. The post times out after the daemon has the row.
        started.started = Instant::now() - Duration::from_millis(160);
        let mut transport = Scripted {
            sent: Vec::new(),
            ok: true,
        };
        let outcome = run(started, &mut transport);
        let body: Value = serde_json::from_slice(&outcome.stdout).unwrap_or_else(|_| {
            panic!(
                "slow daemon still rewrote: {}",
                String::from_utf8_lossy(&outcome.stdout)
            )
        });
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("deny"),
            "{body}"
        );
        assert!(body["hookSpecificOutput"].get("updatedInput").is_none());
        // The correction is posted after the first answer is given up. The
        // stand-in is still in its slow reply then, so it accepts the second
        // post only after that. Wait for it.
        thread::sleep(Duration::from_millis(500));
        let posted = bodies.lock().expect("stand-in").clone();
        assert_eq!(posted.len(), 2, "daemon saw {posted:?}");
        assert_eq!(
            posted[0]["effective_action"],
            json!("rewrite"),
            "{posted:?}"
        );
        assert_eq!(posted[1]["effective_action"], json!("deny"), "{posted:?}");
        assert_eq!(posted[1]["action"], json!("rewrite"), "{posted:?}");
        assert_eq!(posted[1]["downgraded"], json!(true), "{posted:?}");
        assert!(posted[1]["after_summary"].is_null(), "{posted:?}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Answers `{"stored": true}` after the client's post budget, and keeps the
    /// body. The row is in the database; the client has timed out.
    fn slow_intercept_stand_in() -> (Endpoint, std::sync::Arc<std::sync::Mutex<Vec<Value>>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let saved = std::sync::Arc::clone(&bodies);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            for attempt in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut buf = [0_u8; 16 * 1024];
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                let text = String::from_utf8_lossy(&buf[..n]);
                let json_at = text.find("\r\n\r\n").map(|pos| pos + 4).unwrap_or(0);
                saved
                    .lock()
                    .expect("bodies")
                    .push(serde_json::from_str::<Value>(&text[json_at..]).unwrap_or(Value::Null));
                // The first answer lands after the client gave up. The
                // correction is the second post, and that one is answered.
                if attempt == 0 {
                    thread::sleep(Duration::from_millis(400));
                }
                let reply_body = "{\"stored\":true}";
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{reply_body}",
                    reply_body.len()
                );
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        let endpoint = endpoint::resolve(&EndpointInput {
            socket: None,
            http: Some(format!("http://127.0.0.1:{port}")),
            token: Some("hook-slow-test".to_owned()),
            token_env: None,
        })
        .expect("loopback endpoint");
        (endpoint, bodies)
    }
}
