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

use crate::endpoint::Endpoint;
use crate::exit;

use super::Outcome;

/// How long one audit post may wait on a daemon. The copy loop is the MCP
/// session, so a daemon that is not listening must fail fast: the same bound
/// `aw hook` uses inside its 200 ms budget. A rewrite that cannot be recorded
/// is a deny (design §5.3).
const AUDIT_POST_BUDGET: Duration = Duration::from_millis(50);

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
/// `endpoint` is where an intercept audit is posted. `None` is a daemon this
/// process could not resolve; the post is skipped and a rewrite with no local
/// backup becomes a deny.
///
/// # Panics
///
/// Never. Spawn and copy failures become [`Outcome`] with exit 1.
pub(crate) fn run(cmd: &[String], endpoint: Option<&Endpoint>) -> Outcome {
    let Some((program, args)) = cmd.split_first() else {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "`aw mcp-tap` 需要提供要包装的命令",
            false,
        );
    };
    match spawn_and_copy(program, args, endpoint) {
        Ok(outcome) => outcome,
        Err(err) => super::error_outcome(
            exit::GENERAL,
            "spawn",
            &format!("mcp-tap：启动失败：{err}"),
            false,
        ),
    }
}

fn spawn_and_copy(
    program: &str,
    args: &[String],
    endpoint: Option<&Endpoint>,
) -> io::Result<Outcome> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| io::Error::other(err.to_string()))?;

    let policy = Arc::new(load_mcp_policy());
    // Resolved once. A connect that fails is still one attempt per audit,
    // bounded by [`AUDIT_POST_BUDGET`], not a reason to skip the post.
    let audit_endpoint = endpoint.cloned();
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
    let stdin_endpoint = audit_endpoint.clone();
    let stdin_thread = thread::Builder::new()
        .name("aw-mcp-tap-stdin".to_owned())
        .spawn(move || {
            let result = copy_parent_to_child(
                io::stdin(),
                child_stdin,
                DIR_C2S,
                &stdin_tx,
                &stdin_policy,
                stdin_endpoint.as_ref(),
            );
            let _ = stdin_tx.send(CopyNote::Done(result));
        })
        .map_err(|err| io::Error::other(err.to_string()))?;

    let stdout_tx = tx.clone();
    let stdout_policy = policy;
    let stdout_endpoint = audit_endpoint;
    let stdout_thread = thread::Builder::new()
        .name("aw-mcp-tap-stdout".to_owned())
        .spawn(move || {
            let result = copy_child_to_parent(
                child_stdout,
                io::stdout(),
                DIR_S2C,
                &stdout_tx,
                &stdout_policy,
                stdout_endpoint.as_ref(),
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
    endpoint: Option<&Endpoint>,
) -> io::Result<()> {
    copy_with_policy(&mut from, &mut to, direction, tx, policy, endpoint, true)
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
    endpoint: Option<&Endpoint>,
) -> io::Result<()> {
    copy_with_policy(&mut from, &mut to, direction, tx, policy, endpoint, false)
}

fn copy_with_policy<R: Read, W: Write>(
    from: &mut R,
    to: &mut W,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
    policy: &McpPolicy,
    endpoint: Option<&Endpoint>,
    to_client: bool,
) -> io::Result<()> {
    match policy {
        McpPolicy::Off => copy_parsed(from, to, direction, tx),
        McpPolicy::On(policy) => copy_gated(from, to, direction, tx, policy, endpoint, to_client),
        McpPolicy::Broken => copy_broken(from, to, direction, tx, endpoint, to_client),
    }
}

/// A broken policy file. `tools/call` requests are denied. Everything else,
/// including responses and notifications, is forwarded unchanged.
fn copy_broken<R: Read, W: Write>(
    from: &mut R,
    to: &mut W,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
    endpoint: Option<&Endpoint>,
    to_client: bool,
) -> io::Result<()> {
    let mut client: Box<dyn Write> = if to_client {
        Box::new(io::stdout())
    } else {
        Box::new(io::sink())
    };
    let mut splitter = Splitter::new();
    let mut buf = [0_u8; 8 * 1024];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            if let Some(outcome) = splitter.finish() {
                gate_broken(&outcome, to, client.as_mut(), direction, tx, endpoint, true)?;
            }
            to.flush()?;
            return Ok(());
        }
        for outcome in splitter.push(&buf[..n]) {
            gate_broken(
                &outcome,
                to,
                client.as_mut(),
                direction,
                tx,
                endpoint,
                false,
            )?;
        }
    }
}

fn gate_broken<W: Write>(
    outcome: &FrameOutcome,
    to: &mut W,
    client: &mut dyn Write,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
    endpoint: Option<&Endpoint>,
    eof: bool,
) -> io::Result<()> {
    let FrameOutcome::Frame(frame) = outcome else {
        note_frame(outcome, direction, tx);
        return Ok(());
    };
    let text = String::from_utf8_lossy(frame);
    let line = text.trim_end_matches('\r');
    if let Some(elements) = batch_elements(line) {
        let mut side = BrokenSide {
            client,
            direction,
            tx,
            endpoint,
            eof,
        };
        return gate_broken_batch(&elements, to, &mut side, outcome);
    }
    let tool_call = direction == DIR_C2S && is_tools_call(line);
    if !tool_call {
        let newline: &[u8] = if eof { b"" } else { b"\n" };
        write_frame(to, frame, newline)?;
        note_frame(outcome, direction, tx);
        return Ok(());
    }
    let decision = deny_decision("规则文件读不了，已按拒绝处理");
    let changes = field_changes(&decision);
    let frame_decision = FrameDecision {
        verdict: FrameVerdict::Deny,
        reason: decision.reason.as_deref(),
        fields: &changes,
    };
    let action = apply_request(line, &frame_decision);
    write_action(&action, frame, to, Some(client), eof)?;
    // A deny still happens when the audit cannot be stored. The notice is the
    // only record of that drop; the policy file's text is not in it. The
    // summary is the command the call carried, not the whole frame.
    let _ = audit_mcp(
        &decision,
        &audit_before(line, &decision),
        None,
        endpoint,
        Some(line),
        direction,
    );
    note_frame(outcome, direction, tx);
    Ok(())
}

/// What one broken-policy line needs besides the bytes it is deciding.
struct BrokenSide<'a> {
    client: &'a mut dyn Write,
    direction: &'static str,
    tx: &'a SyncSender<CopyNote>,
    endpoint: Option<&'a Endpoint>,
    eof: bool,
}

/// One element of a batch under a broken policy. A `tools/call` is denied;
/// anything else is kept and forwarded as one array.
fn gate_broken_batch<W: Write>(
    elements: &[Value],
    to: &mut W,
    side: &mut BrokenSide<'_>,
    outcome: &FrameOutcome,
) -> io::Result<()> {
    let mut forwarded: Vec<Value> = Vec::new();
    for element in elements {
        let line = serde_json::to_string(element).unwrap_or_default();
        if side.direction == DIR_C2S && is_tools_call(&line) {
            let decision = deny_decision("规则文件读不了，已按拒绝处理");
            let changes = field_changes(&decision);
            let frame_decision = FrameDecision {
                verdict: FrameVerdict::Deny,
                reason: decision.reason.as_deref(),
                fields: &changes,
            };
            if let FrameAction::Reject { response } = apply_request(&line, &frame_decision) {
                if !response.is_empty() {
                    write_frame(side.client, response.as_bytes(), b"\n")?;
                }
            }
            let _ = audit_mcp(
                &decision,
                &audit_before(&line, &decision),
                None,
                side.endpoint,
                Some(&line),
                side.direction,
            );
        } else {
            forwarded.push(element.clone());
        }
    }
    if !forwarded.is_empty() {
        if let Ok(bytes) = serde_json::to_vec(&Value::Array(forwarded)) {
            let newline: &[u8] = if side.eof { b"" } else { b"\n" };
            write_frame(to, &bytes, newline)?;
        }
    }
    note_frame(outcome, side.direction, side.tx);
    Ok(())
}

fn is_tools_call(line: &str) -> bool {
    subject_from_frame(line).is_some_and(|labels| labels.method.as_deref() == Some("tools/call"))
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
    endpoint: Option<&Endpoint>,
    to_client: bool,
) -> io::Result<()> {
    if to_client {
        copy_gated_client(from, to, &mut io::stdout(), direction, tx, policy, endpoint)
    } else {
        copy_gated_client(from, to, io::sink(), direction, tx, policy, endpoint)
    }
}

fn copy_gated_client<R: Read, W: Write, C: Write>(
    from: &mut R,
    to: &mut W,
    mut client: C,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
    policy: &aw_pipeline::Policy,
    endpoint: Option<&Endpoint>,
) -> io::Result<()> {
    let mut splitter = Splitter::new();
    let mut buf = [0_u8; 8 * 1024];
    let mut gate = Gate {
        client: &mut client,
        direction,
        tx,
        policy,
        endpoint,
        eof: false,
    };
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            if let Some(outcome) = splitter.finish() {
                gate.eof = true;
                gate_one(&outcome, to, &mut gate)?;
            }
            to.flush()?;
            return Ok(());
        }
        for outcome in splitter.push(&buf[..n]) {
            gate.eof = false;
            gate_one(&outcome, to, &mut gate)?;
        }
    }
}

/// What one gated line needs besides the bytes it is deciding.
struct Gate<'a, C> {
    /// Where a denied request's JSON-RPC error is written.
    client: &'a mut C,
    direction: &'static str,
    tx: &'a SyncSender<CopyNote>,
    policy: &'a aw_pipeline::Policy,
    /// Audit post. `None` skips it.
    endpoint: Option<&'a Endpoint>,
    /// The frame had no trailing newline of its own.
    eof: bool,
}

fn gate_one<W: Write, C: Write>(
    outcome: &FrameOutcome,
    to: &mut W,
    gate: &mut Gate<'_, C>,
) -> io::Result<()> {
    match outcome {
        FrameOutcome::Gap(_) => {
            // The splitter dropped an oversize line's bytes. There is nothing
            // left to forward. The notice is the only record.
            note_frame(outcome, gate.direction, gate.tx);
            Ok(())
        }
        FrameOutcome::Frame(frame) => {
            let text = String::from_utf8_lossy(frame);
            let line = text.trim_end_matches('\r');
            if let Some(elements) = batch_elements(line) {
                gate_batch(&elements, to, gate)?;
                note_frame(outcome, gate.direction, gate.tx);
                return Ok(());
            }
            let action = decide_and_apply(line, gate);
            write_action(&action, frame, to, Some(gate.client), gate.eof)?;
            note_frame(outcome, gate.direction, gate.tx);
            Ok(())
        }
    }
}

/// Decide one line, record it, and turn the decision into bytes.
///
/// The audit is written before the bytes move. A rewrite the daemon and the
/// local file both refused is a deny (design §5.3): the replacement must not
/// leave with no record of the change. A line that is not one JSON object has
/// no call to record; its deny drops the bytes, and posting it would dial the
/// default socket for every blank or binary line. A rewrite the frame cannot
/// hold is recorded again as the deny that actually happens.
fn decide_and_apply(line: &str, gate: &mut Gate<'_, impl Write>) -> FrameAction {
    let decision = decide_line(gate.policy, line, gate.direction);
    let labeled = subject_from_frame(line).is_some();
    let audited =
        if labeled && (decision.effective != Action::Allow || decision.action != Action::Allow) {
            Some(audit_mcp(
                &decision,
                &audit_before(line, &decision),
                planned_after(&decision).as_deref(),
                gate.endpoint,
                Some(line),
                gate.direction,
            ))
        } else {
            None
        };
    // A rewrite the client cannot confirm was stored is a deny. The daemon can
    // still have written the `rewrite` row after this side gave up; the
    // correction line is what a later reader sees last.
    let decision = match audited {
        Some((delivery, posted))
            if delivery.client_unconfirmed && decision.effective == Action::Rewrite =>
        {
            let downgraded = unconfirmed_rewrite(&decision);
            let _ = super::intercept_audit::correct_delivered(
                audit_backup().as_deref(),
                gate.endpoint,
                &posted,
                &downgraded,
            );
            downgraded
        }
        _ => decision,
    };
    let changes = field_changes(&decision);
    let frame_decision = FrameDecision {
        verdict: verdict_of(&decision),
        reason: decision.reason.as_deref(),
        fields: &changes,
    };
    let action = if gate.direction == DIR_C2S {
        apply_request(line, &frame_decision)
    } else {
        apply_response(line, &frame_decision)
    };
    realized_action(&action, &decision, line, gate)
}

/// A JSON-RPC batch is a top-level array. `None` when the line is one object,
/// not JSON, empty, or an array whose elements are not all objects. A response
/// batch is split the same way as a request batch.
///
/// MCP 2025-03-26 required servers to accept a batch; 2025-06-18 removed that.
/// A client can still send one. Each element is decided on its own: a deny
/// answers that element's id, a rewrite rewrites that element, an allow is
/// forwarded. Elements the tap cannot label follow `on_error`.
fn batch_elements(line: &str) -> Option<Vec<Value>> {
    let value: Value = serde_json::from_str(line).ok()?;
    let items = value.as_array()?;
    if items.is_empty() {
        return None;
    }
    if items.iter().all(Value::is_object) {
        Some(items.clone())
    } else {
        None
    }
}

/// Decide every element of one batch, then write the forwarded ones as one
/// array and each deny as its own JSON-RPC error.
///
/// The forwarded array keeps the elements that were allowed or rewritten, in
/// their original order. A batch whose every element was denied writes
/// nothing to the server. A response batch is decided the same way; a deny on
/// the way back cannot un-run the tool, so a denied response element is
/// dropped rather than answered (there is no second client to answer).
fn gate_batch<W: Write>(
    elements: &[Value],
    to: &mut W,
    gate: &mut Gate<'_, impl Write>,
) -> io::Result<()> {
    let mut forwarded: Vec<Value> = Vec::new();
    for element in elements {
        let line = serde_json::to_string(element).unwrap_or_default();
        let action = decide_and_apply(&line, gate);
        match action {
            FrameAction::Forward => forwarded.push(element.clone()),
            FrameAction::Rewrite { bytes } => {
                if let Ok(value) = serde_json::from_str(&bytes) {
                    forwarded.push(value);
                }
            }
            FrameAction::Reject { response } => {
                if gate.direction == DIR_C2S && !response.is_empty() {
                    write_frame(gate.client, response.as_bytes(), b"\n")?;
                }
            }
        }
    }
    if !forwarded.is_empty() {
        if let Ok(bytes) = serde_json::to_vec(&Value::Array(forwarded)) {
            let newline: &[u8] = if gate.eof { b"" } else { b"\n" };
            write_frame(to, &bytes, newline)?;
        }
    }
    Ok(())
}

/// What the audit stores as "before".
///
/// A rewrite names the fields it replaced, so those original values are the
/// change. Anything else (a deny, an ask) keeps the command, path, or URL the
/// rule matched, and falls back to the frame only when the line had none of
/// those. The policy file's own text is never one of these.
fn audit_before(line: &str, decision: &Decision) -> String {
    if decision.action == Action::Rewrite && !decision.fields.is_empty() {
        let Some(labels) = subject_from_frame(line) else {
            return String::new();
        };
        let mut parts = Vec::new();
        for (field, _) in &decision.fields {
            let key = field.strip_prefix("arg.").unwrap_or(field.as_str());
            let value = if key == "command" {
                labels.command.clone()
            } else if key == "mcp_tool" || key == "tool" {
                labels.tool.clone()
            } else if key == "mcp_method" || key == "method" {
                labels.method.clone()
            } else {
                labels
                    .args
                    .iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value.clone())
            };
            if let Some(value) = value {
                parts.push(format!("{field}={value}"));
            }
        }
        if !parts.is_empty() {
            return parts.join("\n");
        }
    }
    subject_from_frame(line)
        .and_then(|labels| labels.command)
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| line.to_owned())
}

/// What a rewrite would store as "after", before the frame is changed.
///
/// Only the fields the rule replaced. The rest of the JSON-RPC line can carry
/// a sibling the rule did not touch.
fn planned_after(decision: &Decision) -> Option<String> {
    if decision.effective != Action::Rewrite {
        return None;
    }
    let mut parts = Vec::new();
    for (field, value) in &decision.fields {
        parts.push(format!("{field}={value}"));
    }
    Some(parts.join("\n"))
}

/// A rewrite that [`apply_request`] / [`apply_response`] could not write back
/// arrives as a drop. The audit row already says rewrite. Append what was
/// actually done: the bytes were not forwarded, and the client gets a JSON-RPC
/// error when the frame has an id.
fn realized_action(
    action: &FrameAction,
    decision: &Decision,
    line: &str,
    gate: &Gate<'_, impl Write>,
) -> FrameAction {
    let FrameAction::Reject { response } = action else {
        return action.clone();
    };
    if decision.effective != Action::Rewrite || !response.is_empty() {
        return action.clone();
    }
    let mut downgraded = decision.clone();
    downgraded.effective = Action::Deny;
    downgraded.downgraded = true;
    downgraded.fields.clear();
    downgraded.reason = Some("改写写不回这一帧，已改为拒绝".to_owned());
    let _ = audit_mcp(
        &downgraded,
        &audit_before(line, &downgraded),
        None,
        gate.endpoint,
        Some(line),
        gate.direction,
    );
    let frame_decision = FrameDecision {
        verdict: FrameVerdict::Deny,
        reason: downgraded.reason.as_deref(),
        fields: &[],
    };
    if gate.direction == DIR_C2S {
        apply_request(line, &frame_decision)
    } else {
        apply_response(line, &frame_decision)
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
        FrameAction::Forward => write_frame(to, original, newline)?,
        FrameAction::Rewrite { bytes } => write_frame(to, bytes.as_bytes(), newline)?,
        FrameAction::Reject { response } => {
            // Not written to the child. A request deny answers the MCP client.
            // The production caller passes stdout. An empty response is a drop
            // (a notification, or a line that is not one JSON object).
            if let Some(client) = client {
                if !response.is_empty() {
                    write_frame(client, response.as_bytes(), b"\n")?;
                }
            }
        }
    }
    Ok(())
}

/// One frame plus its delimiter, in a single `write_all`.
///
/// The request thread and the response thread both write this process's
/// stdout (a deny's JSON-RPC error, and a rewritten result). Two `write_all`
/// calls each take the stdout lock separately, so the two threads can
/// interleave a frame with the other thread's newline. One buffer, one write,
/// keeps each line intact.
fn write_frame<W: Write + ?Sized>(to: &mut W, bytes: &[u8], newline: &[u8]) -> io::Result<()> {
    let mut line = Vec::with_capacity(bytes.len() + newline.len());
    line.extend_from_slice(bytes);
    line.extend_from_slice(newline);
    to.write_all(&line)?;
    to.flush()?;
    Ok(())
}

fn decide_line(policy: &aw_pipeline::Policy, frame: &str, direction: &str) -> Decision {
    let Some(labels) = subject_from_frame(frame) else {
        // A line the tap cannot label is not a call it can prove is safe.
        // Rules are on, so an unreadable `tools/call` (not JSON, or a batch
        // the caller did not split) follows `on_error`. Default is deny.
        return match policy.on_error() {
            OnError::Allow => allow_decision(),
            OnError::Deny => deny_decision("这一行读不了，已按拒绝处理"),
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

/// A rewrite whose audit this process could not confirm, as a deny.
///
/// The rule's action stays `rewrite`. The sentence keeps the rule's reason and
/// says why the bytes did not change.
fn unconfirmed_rewrite(decision: &Decision) -> Decision {
    let extra = "审计写不进去，改写已改为拒绝";
    Decision {
        rule_id: decision.rule_id.clone(),
        action: decision.action,
        effective: Action::Deny,
        downgraded: true,
        reason: Some(match decision.reason.as_deref() {
            Some(text) if !text.is_empty() => format!("{text}（{extra}）"),
            _ => extra.to_owned(),
        }),
        fields: Vec::new(),
    }
}

/// `AW_INTERCEPT_AUDIT`, else nothing. mcp-tap has no session directory of its
/// own; `aw run` passes one through the environment when it has one.
fn audit_backup() -> Option<std::path::PathBuf> {
    super::intercept_audit::backup_path(
        std::env::var_os(super::intercept_audit::AUDIT_ENV)
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .as_deref(),
        None,
    )
}

/// Record one deny, rewrite, ask, or downgrade, then post it.
///
/// The local backup is written first. The daemon post uses `endpoint` (the
/// address `aw` already resolved: `--socket`, `--http`, `AW_SOCKET`, or the
/// platform default) and gives up after [`AUDIT_POST_BUDGET`]. `None` skips
/// the post. A dropped rewrite is the caller's signal to deny instead.
fn audit_mcp(
    decision: &Decision,
    before: &str,
    after: Option<&str>,
    endpoint: Option<&Endpoint>,
    frame: Option<&str>,
    direction: &str,
) -> (
    super::intercept_audit::AuditDelivery,
    aw_pipeline::AuditRecord,
) {
    // `before` is the field summary the audit stores. It is not a JSON-RPC
    // frame: parsing it again leaves tool, method, and event empty. Labels
    // come from the original line (`frame`); the direction is the copy that
    // already knows which way the bytes moved.
    let subject = frame
        .and_then(subject_from_frame)
        .map(|labels| Subject {
            layer: Layer::Mcp,
            tool: labels.tool.clone(),
            method: labels.method.clone(),
            mcp_method: labels.method,
            mcp_tool: labels.tool,
            command: labels.command,
            args: labels.args,
            event: Some(direction.to_owned()),
            ..Subject::default()
        })
        .unwrap_or(Subject {
            layer: Layer::Mcp,
            event: Some(direction.to_owned()),
            ..Subject::default()
        });
    let backup = super::intercept_audit::backup_path(
        std::env::var_os(super::intercept_audit::AUDIT_ENV)
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .as_deref(),
        None,
    );
    // Same salt rule as the hook: a session id is the salt, so two processes
    // auditing one session hash one command the same way. No session means the
    // process-local salt, which is not comparable across restarts.
    let session = std::env::var(super::hook::SESSION_ENV)
        .ok()
        .filter(|id| !id.is_empty());
    let salt: &[u8] = match session.as_deref() {
        Some(id) => id.as_bytes(),
        None => super::intercept_audit::process_salt(),
    };
    let mut record = super::intercept_audit::record_for(
        &subject,
        decision,
        salt,
        before,
        after,
        session.as_deref(),
    );
    let delivery = super::intercept_audit::deliver(
        endpoint,
        backup.as_deref(),
        &mut record,
        AUDIT_POST_BUDGET,
    );
    // Both the local line and the daemon post failed. The notice is the Gap
    // the design asks for. It carries no command text. A rewrite is not
    // forwarded: the caller turns it into a deny.
    if delivery.delivered == aw_pipeline::Delivered::Dropped {
        let _ = writeln!(
            io::stderr(),
            "mcp-tap：拦截审计写不进去（intercept_audit_dropped）"
        );
    }
    (delivery, record)
}

enum McpPolicy {
    Off,
    On(aw_pipeline::Policy),
    /// The file exists and is not a policy. `tools/call` is denied. Other
    /// methods stay forwarded so `initialize` and `tools/list` still work.
    Broken,
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
        super::policy_file::PolicyLoad::Off => McpPolicy::Off,
        // Default `on_error` is deny (design §5.3). Only `tools/call` is
        // refused: denying `initialize` would end the session.
        super::policy_file::PolicyLoad::Broken => McpPolicy::Broken,
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
    copy_gated_for_test_at(input, direction, policy_text, to_client, None)
}

/// Same as [`copy_gated_for_test`], but the audit is posted to `endpoint`.
#[cfg(test)]
fn copy_gated_for_test_at(
    input: &[u8],
    direction: &'static str,
    policy_text: &str,
    to_client: bool,
    endpoint: Option<&Endpoint>,
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
            endpoint,
        )?;
    } else {
        copy_gated_client(
            &mut splitter_input,
            &mut child,
            io::sink(),
            direction,
            &tx,
            &policy,
            endpoint,
        )?;
    }
    Ok(GatedCopy { child, client })
}

#[cfg(test)]
fn copy_broken_for_test(
    input: &[u8],
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
    child: &mut Vec<u8>,
    client: &mut Vec<u8>,
) -> io::Result<()> {
    copy_broken_for_test_at(input, direction, tx, child, client, None)
}

#[cfg(test)]
fn copy_broken_for_test_at(
    input: &[u8],
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
    child: &mut Vec<u8>,
    client: &mut Vec<u8>,
    endpoint: Option<&Endpoint>,
) -> io::Result<()> {
    let mut splitter = Splitter::new();
    let mut frames = splitter.push(input);
    if let Some(tail) = splitter.finish() {
        frames.push(tail);
    }
    let eof_at = frames.len().saturating_sub(1);
    for (index, outcome) in frames.iter().enumerate() {
        gate_broken(
            outcome,
            child,
            client,
            direction,
            tx,
            endpoint,
            index == eof_at && !input.ends_with(b"\n"),
        )?;
    }
    Ok(())
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

    /// `AW_SESSION` is how `aw run` names the daemon session. The audit line
    /// stores that id, not an empty session.
    #[test]
    fn audit_line_carries_aw_session() {
        let _guard = crate::cmd::policy_file::env_lock();
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!(
                "aw-mcp-session-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let audit = dir.join("audit.jsonl");
        let _audit = crate::cmd::policy_file::EnvVarGuard::set(
            crate::cmd::intercept_audit::AUDIT_ENV,
            &audit,
        );
        let _session =
            crate::cmd::policy_file::EnvVarGuard::set_text(crate::cmd::hook::SESSION_ENV, "s-mcp");
        let frame = b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"run\",\"arguments\":{\"command\":\"rm -rf /tmp\"}}}\n";
        let copy = copy_gated_for_test(frame, DIR_C2S, DENY_RM, true).unwrap();
        assert!(copy.child.is_empty(), "denied frame reached the child");
        let text = std::fs::read_to_string(&audit).unwrap();
        let lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
        assert_eq!(lines.len(), 1, "{text}");
        let row: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(row["session"], serde_json::json!("s-mcp"), "{row}");
        assert_eq!(row["effective_action"], serde_json::json!("deny"), "{row}");
        assert_eq!(row["layer"], serde_json::json!("mcp"), "{row}");
        assert_eq!(row["tool"], serde_json::json!("run"), "{row}");
        assert_eq!(row["mcp_method"], serde_json::json!("tools/call"), "{row}");
        assert_eq!(row["before_summary"], serde_json::json!("rm -rf /tmp"), "{row}");
        assert_eq!(row["delivered"], serde_json::json!("local_backup"), "{row}");
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        // A rewrite with nowhere to record it is a deny. This test is about
        // the rewrite itself, so it gets a local audit file.
        let _guard = crate::cmd::policy_file::env_lock();
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("aw-mcp-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let _audit = crate::cmd::policy_file::EnvVarGuard::set(
            crate::cmd::intercept_audit::AUDIT_ENV,
            &dir.join("audit.jsonl"),
        );
        let apply = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"run\",\"arguments\":{\"command\":\"terraform apply\",\"dry\":false}}}\n";
        let copy = copy_gated_for_test(apply, DIR_C2S, REWRITE, true).unwrap();
        let child = String::from_utf8(copy.child).unwrap();
        assert!(child.contains("terraform plan"));
        assert!(child.contains("\"dry\":false"));
        assert!(copy.client.is_empty());

        let ping = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n";
        let copy = copy_gated_for_test(ping, DIR_C2S, REWRITE, true).unwrap();
        assert_eq!(copy.child, ping);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_policy_denies_tools_call_and_forwards_initialize() {
        let (tx, _rx) = mpsc::sync_channel(8);
        let mut child = Vec::new();
        let mut client = Vec::new();
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"run\",\"arguments\":{\"command\":\"rm -rf /tmp\"}}}\n";
        copy_broken_for_test(input, DIR_C2S, &tx, &mut child, &mut client).unwrap();
        let forwarded = String::from_utf8(child).unwrap();
        assert!(forwarded.contains("initialize"));
        assert!(!forwarded.contains("tools/call"));
        assert!(!forwarded.contains("rm -rf"));
        let error = String::from_utf8(client).unwrap();
        assert!(error.contains("\"id\":9"));
        assert!(error.contains("规则文件读不了"));
    }

    /// One JSON-RPC batch. The denied element answers the client with that
    /// element's id; the allowed element is the only thing the server sees;
    /// the rewritten element's command is the replacement.
    #[test]
    fn batch_decides_each_element() {
        let _guard = crate::cmd::policy_file::env_lock();
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("aw-mcp-batch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let _audit = crate::cmd::policy_file::EnvVarGuard::set(
            crate::cmd::intercept_audit::AUDIT_ENV,
            &dir.join("audit.jsonl"),
        );
        let policy = r#"
version = 1
enabled = true
on_error = "deny"

[[rule]]
id = "no-rm"
layer = ["mcp"]
match.command = { prefix = "rm " }
action = "deny"
reason = "不允许删除"

[[rule]]
id = "plan-only"
layer = ["mcp"]
match.command = { prefix = "terraform apply" }
action = "rewrite"
rewrite.command = { replace = ["terraform apply", "terraform plan"] }
"#;
        let frame = concat!(
            r#"[{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run","arguments":{"command":"rm -rf /"}}},"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run","arguments":{"command":"echo ok"}}},"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run","arguments":{"command":"terraform apply"}}}]"#,
            "\n"
        );
        let copy = copy_gated_for_test(frame.as_bytes(), DIR_C2S, policy, true).unwrap();
        let child = String::from_utf8(copy.child).unwrap();
        let client = String::from_utf8(copy.client).unwrap();
        assert!(
            !child.contains("rm -rf"),
            "denied element reached the server: {child}"
        );
        assert!(
            child.contains("echo ok"),
            "allowed element was not forwarded: {child}"
        );
        assert!(
            child.contains("terraform plan"),
            "rewritten element kept the original command: {child}"
        );
        assert!(
            !child.contains("terraform apply"),
            "original command reached the server: {child}"
        );
        assert!(
            client.contains("\"id\":2"),
            "denied element did not answer with its id: {client}"
        );
        assert!(
            client.contains("不允许删除"),
            "deny reason missing: {client}"
        );
        assert!(!client.contains("rm -rf"), "denied text echoed: {client}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A line that is not JSON, while rules are on, is not a call this tap can
    /// label. Forwarding it would let an unreadable `tools/call` through.
    #[test]
    fn non_json_line_is_not_forwarded_when_rules_are_on() {
        let policy = r#"
version = 1
enabled = true
on_error = "deny"

[[rule]]
id = "no-rm"
layer = ["mcp"]
match.command = { prefix = "rm " }
action = "deny"
reason = "不允许删除"
"#;
        let copy = copy_gated_for_test(b"not json at all\n", DIR_C2S, policy, true).unwrap();
        assert!(
            copy.child.is_empty(),
            "non-json line was forwarded: {}",
            String::from_utf8_lossy(&copy.child)
        );
    }

    /// `rewrite.mcp_tool` changes `params.name`. The server must see the new
    /// name, and the audit must say rewrite, not the original tool.
    #[test]
    fn rewrite_mcp_tool_is_what_the_server_receives() {
        let _guard = crate::cmd::policy_file::env_lock();
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("aw-mcp-tool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let audit_path = dir.join("audit.jsonl");
        let _audit = crate::cmd::policy_file::EnvVarGuard::set(
            crate::cmd::intercept_audit::AUDIT_ENV,
            &audit_path,
        );
        let policy = r#"
version = 1
enabled = true

[[rule]]
id = "rename-tool"
layer = ["mcp"]
match.mcp_tool = { exact = "oldtool" }
action = "rewrite"
rewrite.mcp_tool = { replace = ["oldtool", "newtool"] }
"#;
        let frame = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"oldtool\",\"arguments\":{\"command\":\"echo\"}}}\n";
        let copy = copy_gated_for_test(frame, DIR_C2S, policy, true).unwrap();
        let child = String::from_utf8(copy.child).unwrap();
        assert!(
            child.contains("newtool"),
            "server did not see the rewritten tool: {child}"
        );
        assert!(
            !child.contains("oldtool"),
            "original tool name reached the server: {child}"
        );
        let audit = std::fs::read_to_string(&audit_path).unwrap_or_default();
        assert!(
            audit.contains("\"effective_action\":\"rewrite\""),
            "audit did not record the rewrite that was forwarded: {audit}"
        );
        assert!(
            audit.contains("\"tool\":\"oldtool\""),
            "audit lost the tool the frame named: {audit}"
        );
        assert!(
            audit.contains("mcp_tool=oldtool"),
            "audit before-summary is not the tool that was rewritten: {audit}"
        );
        assert!(
            audit.contains("\"mcp_method\":\"tools/call\""),
            "audit lost the method: {audit}"
        );
        assert!(
            audit.contains("\"event\":\"c2s\""),
            "audit lost the direction: {audit}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A response rewrite of `result.text` is what the client receives.
    #[test]
    fn response_rewrite_replaces_result_text() {
        let _guard = crate::cmd::policy_file::env_lock();
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("aw-mcp-resp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let _audit = crate::cmd::policy_file::EnvVarGuard::set(
            crate::cmd::intercept_audit::AUDIT_ENV,
            &dir.join("audit.jsonl"),
        );
        let policy = r#"
version = 1
enabled = true

[[rule]]
id = "redact-result"
layer = ["mcp"]
match.direction = { exact = "s2c" }
match.arg.text = { regex = "SECRET" }
action = "rewrite"
rewrite.arg.text = { replace = ["SECRET", "XXX"] }
"#;
        let frame = b"{\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"text\":\"SECRET\"}}\n";
        let copy = copy_gated_for_test(frame, DIR_S2C, policy, false).unwrap();
        let child = String::from_utf8(copy.child).unwrap();
        assert!(
            child.contains("XXX"),
            "client did not see the rewritten result: {child}"
        );
        assert!(
            !child.contains("SECRET"),
            "original result reached the client: {child}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A broken policy file still has to see a `tools/call` inside a batch.
    /// Forwarding the array would run the call the single-object path denies.
    #[test]
    fn broken_policy_denies_a_tools_call_inside_a_batch() {
        let (tx, _rx) = mpsc::sync_channel(8);
        let mut child = Vec::new();
        let mut client = Vec::new();
        let input = concat!(
            r#"[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}},"#,
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"run","arguments":{"command":"echo hello"}}}]"#,
            "\n"
        );
        copy_broken_for_test(input.as_bytes(), DIR_C2S, &tx, &mut child, &mut client).unwrap();
        let forwarded = String::from_utf8(child).unwrap();
        assert!(
            forwarded.contains("initialize"),
            "initialize was not forwarded: {forwarded}"
        );
        assert!(
            !forwarded.contains("tools/call"),
            "tools/call inside a batch was forwarded: {forwarded}"
        );
        assert!(
            !forwarded.contains("echo hello"),
            "the call's argument reached the server: {forwarded}"
        );
        let error = String::from_utf8(client).unwrap();
        assert!(error.contains("\"id\":9"), "missing id: {error}");
        assert!(error.contains("规则文件读不了"), "reason missing: {error}");
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
            None,
            true,
        )
        .unwrap();
        assert_eq!(child, input);
    }
}
