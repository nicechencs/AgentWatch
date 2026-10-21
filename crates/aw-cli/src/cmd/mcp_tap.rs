//! `aw mcp-tap -- <cmd> [args]` (P6-AGENT-01).
//!
//! Spawns the real server with piped stdin, stdout, and stderr, and copies
//! bytes both ways. Each completed line is parsed by [`aw_agent_adapters::extract`].
//! A parse failure is one fixed line on this process's stderr and does not
//! stop the copy. The original bytes are always forwarded.
//!
//! Daemon ingest is not wired. `POST /api/v1/agent/hook` expects a tool-call
//! payload, not an [`aw_core::AgentRpc`], and this card cannot add a route.
//! Extracts are printed to stderr as one JSON object of labels only. They are
//! not posted. Argument values, result content, argv, and the environment are
//! not printed.
//!
//! Content hashes of argument values are not computed. Holding the value to
//! hash it would keep the thing this wrapper is required not to store.

use std::io::{self, Read, Write};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use aw_agent_adapters::{
    apply_request, apply_response, extract, subject_from_frame, ExtractGap, FieldChange,
    FrameAction, FrameDecision, FrameOutcome, FrameVerdict, RpcExtract, Splitter, DIR_C2S, DIR_S2C,
};
use aw_pipeline::{decide, Action, Decision, Layer, OnError, Phase, Subject};
use serde_json::{json, Value};

use crate::exit;

use super::Outcome;

/// How long a notice may wait for the stderr printer before the copy loop
/// drops that notice and keeps forwarding. The copy itself is never blocked
/// on a daemon (there is no daemon write).
const NOTICE_WAIT: Duration = Duration::from_millis(50);

/// What a copy thread reports. Payload bytes are never in here.
enum CopyNote {
    /// A parsed line. Labels only.
    Extract(RpcExtract),
    /// A line that was not parsed. The reason is a fixed token.
    Gap { reason: ExtractGap },
    /// The copy thread finished. `Err` is an I/O failure on the pipe.
    Done(io::Result<()>),
}

/// Spawn `cmd` and copy stdio both ways.
///
/// `cmd` is the program plus arguments, already split by clap. An empty slice
/// is a usage error and does not spawn. The child's exit code is this
/// process's exit code. A signal death with no code is exit 1, not 0.
///
/// # Panics
///
/// Never. Spawn and copy failures become [`Outcome`] with exit 1.
pub(crate) fn run(cmd: &[String]) -> Outcome {
    let Some((program, args)) = cmd.split_first() else {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "`aw mcp-tap` 需要提供要包装的命令",
            false,
        );
    };
    match spawn_and_copy(program, args) {
        Ok(outcome) => outcome,
        Err(err) => super::error_outcome(
            exit::GENERAL,
            "spawn",
            &format!("mcp-tap：启动失败：{err}"),
            false,
        ),
    }
}

fn spawn_and_copy(program: &str, args: &[String]) -> io::Result<Outcome> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| io::Error::other(err.to_string()))?;

    let policy = Arc::new(load_mcp_policy());
    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("子进程 stdin 未设为管道"))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("子进程 stdout 未设为管道"))?;
    let child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("子进程 stderr 未设为管道"))?;

    // Bounded so a slow printer cannot pin every forwarded byte as a notice.
    // `Done` still fits: the copy thread waits only for that one message.
    let (tx, rx) = mpsc::sync_channel::<CopyNote>(64);

    let stdin_tx = tx.clone();
    let stdin_policy = Arc::clone(&policy);
    let stdin_thread = thread::Builder::new()
        .name("aw-mcp-tap-stdin".to_owned())
        .spawn(move || {
            let result =
                copy_parent_to_child(io::stdin(), child_stdin, DIR_C2S, &stdin_tx, &stdin_policy);
            let _ = stdin_tx.send(CopyNote::Done(result));
        })
        .map_err(|err| io::Error::other(err.to_string()))?;

    let stdout_tx = tx.clone();
    let stdout_policy = policy;
    let stdout_thread = thread::Builder::new()
        .name("aw-mcp-tap-stdout".to_owned())
        .spawn(move || {
            let result = copy_child_to_parent(
                child_stdout,
                io::stdout(),
                DIR_S2C,
                &stdout_tx,
                &stdout_policy,
            );
            let _ = stdout_tx.send(CopyNote::Done(result));
        })
        .map_err(|err| io::Error::other(err.to_string()))?;

    let stderr_thread = thread::Builder::new()
        .name("aw-mcp-tap-stderr".to_owned())
        .spawn(move || {
            // Child stderr is not MCP frames. Copy it through and do not parse it.
            let _ = io::copy(&mut { child_stderr }, &mut io::stderr());
        })
        .map_err(|err| io::Error::other(err.to_string()))?;

    // Drop our sender so the channel closes after the two copy threads finish.
    drop(tx);

    let mut stderr_notes: Vec<u8> = Vec::new();
    let mut copy_error = false;
    let mut finished = 0_u8;
    while finished < 2 {
        let note = match recv_note(&rx) {
            Recv::Note(note) => note,
            Recv::Timeout => continue,
            // Both senders dropped before `Done`. Stop; the joins reap the threads.
            Recv::Disconnected => {
                copy_error = true;
                break;
            }
        };
        match note {
            CopyNote::Extract(extracted) => {
                if !write_extract(&mut stderr_notes, &extracted) {
                    // Encoding failed. There is no daemon route to retry against.
                    let _ = writeln!(stderr_notes, "mcp-tap：未解析帧（daemon_unreachable）");
                }
            }
            CopyNote::Gap { reason } => {
                let _ = writeln!(stderr_notes, "mcp-tap：未解析帧（{reason}）");
            }
            CopyNote::Done(result) => {
                finished = finished.saturating_add(1);
                if result.is_err() {
                    copy_error = true;
                }
            }
        }
    }

    let _ = stdin_thread.join();
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();

    let status = child.wait()?;
    let code = exit_code_from(status, copy_error);
    Ok(Outcome {
        code,
        stdout: Vec::new(),
        stderr: stderr_notes,
    })
}

fn exit_code_from(status: ExitStatus, copy_error: bool) -> i32 {
    if copy_error {
        return exit::GENERAL;
    }
    match status.code() {
        Some(code) => code,
        // Signal death has no code. That is not success.
        None => exit::GENERAL,
    }
}

/// Copy parent stdin onto the child, and note each completed line.
///
/// Policy off: every byte is forwarded before it is parsed. Policy on: a
/// completed line is decided first. A deny is not written to the child; the
/// JSON-RPC error is written to this process's stdout (the MCP client).
fn copy_parent_to_child<R: Read, W: Write>(
    mut from: R,
    mut to: W,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
    policy: &McpPolicy,
) -> io::Result<()> {
    copy_with_policy(&mut from, &mut to, direction, tx, policy, true)
}

/// Copy child stdout onto the parent, and note each completed line.
///
/// Policy off: every byte is forwarded before it is parsed. Policy on: a
/// completed line may be rewritten. A deny on the way back is still forwarded;
/// the tool already ran.
fn copy_child_to_parent<R: Read, W: Write>(
    mut from: R,
    mut to: W,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
    policy: &McpPolicy,
) -> io::Result<()> {
    copy_with_policy(&mut from, &mut to, direction, tx, policy, false)
}

fn copy_with_policy<R: Read, W: Write>(
    from: &mut R,
    to: &mut W,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
    policy: &McpPolicy,
    to_client: bool,
) -> io::Result<()> {
    match policy {
        McpPolicy::Off => copy_parsed(from, to, direction, tx),
        McpPolicy::On(policy) => copy_gated(from, to, direction, tx, policy, to_client),
    }
}

/// Policy on. Complete lines are decided before they are written.
///
/// `to_client` is true on the parent-to-child copy: a deny's JSON-RPC error
/// is written to this process's stdout (the MCP client), not to the child.
/// The child-to-parent copy never denies; a rewrite of a result is written
/// to `to` (the client).
fn copy_gated<R: Read, W: Write>(
    from: &mut R,
    to: &mut W,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
    policy: &aw_pipeline::Policy,
    to_client: bool,
) -> io::Result<()> {
    if to_client {
        copy_gated_client(from, to, &mut io::stdout(), direction, tx, policy)
    } else {
        copy_gated_client(from, to, io::sink(), direction, tx, policy)
    }
}

fn copy_gated_client<R: Read, W: Write, C: Write>(
    from: &mut R,
    to: &mut W,
    mut client: C,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
    policy: &aw_pipeline::Policy,
) -> io::Result<()> {
    let mut splitter = Splitter::new();
    let mut buf = [0_u8; 8 * 1024];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            if let Some(outcome) = splitter.finish() {
                gate_one(&outcome, to, &mut client, direction, tx, policy, true)?;
            }
            to.flush()?;
            return Ok(());
        }
        for outcome in splitter.push(&buf[..n]) {
            gate_one(&outcome, to, &mut client, direction, tx, policy, false)?;
        }
    }
}

fn gate_one<W: Write, C: Write>(
    outcome: &FrameOutcome,
    to: &mut W,
    client: &mut C,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
    policy: &aw_pipeline::Policy,
    eof: bool,
) -> io::Result<()> {
    match outcome {
        FrameOutcome::Gap(_) => {
            // The splitter dropped an oversize line's bytes. There is nothing
            // left to forward. The notice is the only record.
            note_frame(outcome, direction, tx);
            Ok(())
        }
        FrameOutcome::Frame(frame) => {
            let text = String::from_utf8_lossy(frame);
            let line = text.trim_end_matches('\r');
            let decision = decide_line(policy, line, direction);
            let changes = field_changes(&decision);
            let frame_decision = FrameDecision {
                verdict: verdict_of(&decision),
                reason: decision.reason.as_deref(),
                fields: &changes,
            };
            let action = if direction == DIR_C2S {
                apply_request(line, &frame_decision)
            } else {
                apply_response(line, &frame_decision)
            };
            write_action(&action, frame, to, Some(client), eof)?;
            if decision.effective != Action::Allow || decision.action != Action::Allow {
                audit_mcp(&decision, line, action_after(&action));
            }
            note_frame(outcome, direction, tx);
            Ok(())
        }
    }
}

fn action_after(action: &FrameAction) -> Option<&str> {
    match action {
        FrameAction::Rewrite { bytes } => Some(bytes.as_str()),
        FrameAction::Forward | FrameAction::Reject { .. } => None,
    }
}

fn write_action<W: Write>(
    action: &FrameAction,
    original: &[u8],
    to: &mut W,
    client: Option<&mut dyn Write>,
    eof: bool,
) -> io::Result<()> {
    let newline: &[u8] = if eof { b"" } else { b"\n" };
    match action {
        FrameAction::Forward => {
            to.write_all(original)?;
            to.write_all(newline)?;
            to.flush()?;
        }
        FrameAction::Rewrite { bytes } => {
            to.write_all(bytes.as_bytes())?;
            to.write_all(newline)?;
            to.flush()?;
        }
        FrameAction::Reject { response } => {
            // Not written to the child. A request deny answers the MCP client.
            // The production caller passes stdout. A response deny is not
            // produced (`apply_response` forwards those bytes).
            if let Some(client) = client {
                if !response.is_empty() {
                    client.write_all(response.as_bytes())?;
                    client.write_all(b"\n")?;
                    client.flush()?;
                }
            }
        }
    }
    Ok(())
}

fn decide_line(policy: &aw_pipeline::Policy, frame: &str, direction: &str) -> Decision {
    let Some(labels) = subject_from_frame(frame) else {
        return match policy.on_error() {
            OnError::Allow => allow_decision(),
            // Non-JSON is not a call a rule named. Forwarding it keeps a
            // session intact. `on_error` applies when a rewrite cannot be
            // applied, not when the line has no labels.
            OnError::Deny => allow_decision(),
        };
    };
    let subject = Subject {
        layer: Layer::Mcp,
        tool: labels.tool.clone(),
        method: labels.method.clone(),
        mcp_method: labels.method,
        mcp_tool: labels.tool,
        command: labels.command,
        args: labels.args,
        event: Some(direction.to_owned()),
        phase: Phase::Pre,
        ..Subject::default()
    };
    match decide(policy, &subject) {
        Ok(decision) => decision,
        Err(_) => match policy.on_error() {
            OnError::Allow => allow_decision(),
            OnError::Deny => deny_decision("判定出错，已按拒绝处理"),
        },
    }
}

fn verdict_of(decision: &Decision) -> FrameVerdict {
    match decision.effective {
        Action::Deny | Action::Ask => FrameVerdict::Deny,
        Action::Rewrite => FrameVerdict::Rewrite,
        Action::Allow => FrameVerdict::Allow,
    }
}

fn field_changes(decision: &Decision) -> Vec<FieldChange> {
    decision
        .fields
        .iter()
        .map(|(field, value)| FieldChange {
            field: field.clone(),
            value: value.clone(),
        })
        .collect()
}

fn allow_decision() -> Decision {
    Decision {
        rule_id: None,
        action: Action::Allow,
        effective: Action::Allow,
        downgraded: false,
        reason: None,
        fields: Vec::new(),
    }
}

fn deny_decision(reason: &str) -> Decision {
    Decision {
        rule_id: None,
        action: Action::Deny,
        effective: Action::Deny,
        downgraded: false,
        reason: Some(reason.to_owned()),
        fields: Vec::new(),
    }
}

fn audit_mcp(decision: &Decision, before: &str, after: Option<&str>) {
    let subject = subject_from_frame(before)
        .map(|labels| Subject {
            layer: Layer::Mcp,
            tool: labels.tool.clone(),
            method: labels.method.clone(),
            mcp_method: labels.method,
            mcp_tool: labels.tool,
            command: labels.command,
            args: labels.args,
            ..Subject::default()
        })
        .unwrap_or(Subject {
            layer: Layer::Mcp,
            ..Subject::default()
        });
    let backup = super::intercept_audit::backup_path(
        std::env::var_os(super::intercept_audit::AUDIT_ENV)
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .as_deref(),
        None,
    );
    let mut record =
        super::intercept_audit::record_for(&subject, decision, b"", before, after, None);
    let _ = super::intercept_audit::deliver(
        None,
        backup.as_deref(),
        &mut record,
        std::time::Duration::from_millis(20),
    );
}

enum McpPolicy {
    Off,
    On(aw_pipeline::Policy),
}

fn load_mcp_policy() -> McpPolicy {
    let env = std::env::var_os(super::policy_file::POLICY_ENV)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from);
    match super::policy_file::load_policy(
        env.as_deref(),
        super::policy_file::user_config_home().as_deref(),
    ) {
        super::policy_file::PolicyLoad::On(policy) => McpPolicy::On(policy),
        super::policy_file::PolicyLoad::Off | super::policy_file::PolicyLoad::Broken => {
            // Broken: the file did not name which calls to stop. Non-JSON and
            // unnamed frames stay forwarded, same as off. A later card can
            // deny the whole tap; step 1 does not invent that.
            McpPolicy::Off
        }
    }
}

fn copy_parsed<R: Read, W: Write>(
    from: &mut R,
    to: &mut W,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
) -> io::Result<()> {
    let mut splitter = Splitter::new();
    let mut buf = [0_u8; 8 * 1024];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            if let Some(outcome) = splitter.finish() {
                note_frame(&outcome, direction, tx);
            }
            to.flush()?;
            return Ok(());
        }
        let chunk = &buf[..n];
        // Forward first. A parse failure must not drop these bytes.
        to.write_all(chunk)?;
        to.flush()?;
        for outcome in splitter.push(chunk) {
            note_frame(&outcome, direction, tx);
        }
    }
}

fn note_frame(outcome: &FrameOutcome, direction: &'static str, tx: &SyncSender<CopyNote>) {
    let note = match outcome {
        FrameOutcome::Gap(err) => CopyNote::Gap {
            reason: err.reason(),
        },
        FrameOutcome::Frame(bytes) => match std::str::from_utf8(bytes) {
            Err(_) => CopyNote::Gap {
                reason: ExtractGap::NotJson,
            },
            Ok(text) => {
                let req_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                match extract(text, direction, req_bytes) {
                    Ok(extracted) => CopyNote::Extract(extracted),
                    Err(reason) => CopyNote::Gap { reason },
                }
            }
        },
    };
    // Bytes were already forwarded. A full notice queue means the printer is
    // behind; give it 50 ms, then drop this notice and keep copying.
    offer_notice(tx, note);
}

fn offer_notice(tx: &SyncSender<CopyNote>, note: CopyNote) {
    match tx.try_send(note) {
        Ok(()) => {}
        Err(TrySendError::Full(note)) => {
            thread::sleep(NOTICE_WAIT);
            let _ = tx.try_send(note);
        }
        Err(TrySendError::Disconnected(_)) => {}
    }
}

/// Write one JSON object of [`RpcExtract`] fields.
///
/// Returns false when the JSON cannot be encoded. The caller reports that as
/// `daemon_unreachable` without attaching the frame. There is no daemon route
/// for [`aw_core::AgentRpc`], so this line is the only record.
fn write_extract(out: &mut Vec<u8>, extracted: &RpcExtract) -> bool {
    let body = extract_json(extracted);
    let Ok(mut bytes) = serde_json::to_vec(&body) else {
        return false;
    };
    bytes.push(b'\n');
    out.extend_from_slice(&bytes);
    true
}

/// One notice, or why the wait ended.
enum Recv {
    Note(CopyNote),
    /// The child is quiet. Keep waiting.
    Timeout,
    /// Both senders are gone.
    Disconnected,
}

fn recv_note(rx: &Receiver<CopyNote>) -> Recv {
    match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(note) => Recv::Note(note),
        Err(RecvTimeoutError::Timeout) => Recv::Timeout,
        Err(RecvTimeoutError::Disconnected) => Recv::Disconnected,
    }
}

fn extract_json(extracted: &RpcExtract) -> Value {
    json!({
        "method": extracted.method,
        "tool_name": extracted.tool_name,
        "id": extracted.id,
        "req_bytes": extracted.req_bytes,
        "direction": extracted.direction,
        "error_present": extracted.error_present,
        "arg_keys": extracted.arg_keys,
        "arg_types": extracted.arg_types.iter().map(|kind| kind.to_string()).collect::<Vec<_>>(),
        "arg_lengths": extracted.arg_lengths,
    })
}

/// Gate one direction without spawning. Tests use this so a deny never has to
/// touch a real child. `client` receives a request deny's JSON-RPC error.
#[cfg(test)]
fn copy_gated_for_test(
    input: &[u8],
    direction: &'static str,
    policy_text: &str,
    to_client: bool,
) -> io::Result<GatedCopy> {
    let policy = match aw_pipeline::load_str(policy_text) {
        Ok(aw_pipeline::PolicyState::On(policy)) => policy,
        _ => {
            return Err(io::Error::other("test policy is not enabled"));
        }
    };
    let (tx, _rx) = mpsc::sync_channel(8);
    let mut child = Vec::new();
    let mut client = Vec::new();
    let mut splitter_input = io::Cursor::new(input);
    if to_client {
        copy_gated_client(
            &mut splitter_input,
            &mut child,
            &mut client,
            direction,
            &tx,
            &policy,
        )?;
    } else {
        copy_gated_client(
            &mut splitter_input,
            &mut child,
            io::sink(),
            direction,
            &tx,
            &policy,
        )?;
    }
    Ok(GatedCopy { child, client })
}

/// Bytes a gated copy would write. `child` is what the server sees. `client`
/// is a JSON-RPC error for a denied request, empty otherwise.
#[cfg(test)]
struct GatedCopy {
    /// Forwarded or rewritten lines, including their newlines.
    pub child: Vec<u8>,
    /// JSON-RPC errors for denied requests. Not written to `child`.
    pub client: Vec<u8>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const DENY_RM: &str = r#"
version = 1
enabled = true
on_error = "deny"

[[rule]]
id = "no-rm"
layer = ["mcp"]
match.mcp_method = { exact = "tools/call" }
match.command = { prefix = "rm " }
action = "deny"
reason = "不允许删除"
"#;

    const REWRITE: &str = r#"
version = 1
enabled = true

[[rule]]
id = "plan-only"
layer = ["mcp"]
match.command = { prefix = "terraform apply" }
action = "rewrite"
rewrite.command = { replace = ["terraform apply", "terraform plan"] }
"#;

    #[test]
    fn deny_is_not_forwarded_and_the_error_keeps_the_id() {
        let frame = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"run\",\"arguments\":{\"command\":\"rm -rf /tmp\"}}}\n";
        let copy = copy_gated_for_test(frame, DIR_C2S, DENY_RM, true).unwrap();
        assert!(copy.child.is_empty(), "denied frame reached the child");
        let text = String::from_utf8(copy.client).unwrap();
        assert!(text.contains("\"id\":7"));
        assert!(!text.contains("rm -rf"));
        assert!(text.contains("不允许删除"));
    }

    #[test]
    fn rewrite_reaches_the_child_and_a_miss_is_unchanged() {
        let apply = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"run\",\"arguments\":{\"command\":\"terraform apply\",\"dry\":false}}}\n";
        let copy = copy_gated_for_test(apply, DIR_C2S, REWRITE, true).unwrap();
        let child = String::from_utf8(copy.child).unwrap();
        assert!(child.contains("terraform plan"));
        assert!(child.contains("\"dry\":false"));
        assert!(copy.client.is_empty());

        let ping = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n";
        let copy = copy_gated_for_test(ping, DIR_C2S, REWRITE, true).unwrap();
        assert_eq!(copy.child, ping);
    }

    #[test]
    fn policy_off_forwards_before_parsing() {
        let (tx, _rx) = mpsc::sync_channel(4);
        let mut child = Vec::new();
        let input = b"not json\n{\"a\":1}\n";
        copy_with_policy(
            &mut io::Cursor::new(&input[..]),
            &mut child,
            DIR_C2S,
            &tx,
            &McpPolicy::Off,
            true,
        )
        .unwrap();
        assert_eq!(child, input);
    }
}
