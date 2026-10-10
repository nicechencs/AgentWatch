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
use std::thread;
use std::time::Duration;

use aw_agent_adapters::{
    extract, ExtractGap, FrameOutcome, RpcExtract, Splitter, DIR_C2S, DIR_S2C,
};
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
            "`aw mcp-tap` needs a command to wrap",
            false,
        );
    };
    match spawn_and_copy(program, args) {
        Ok(outcome) => outcome,
        Err(err) => super::error_outcome(
            exit::GENERAL,
            "spawn",
            &format!("mcp-tap: spawn failed: {err}"),
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

    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("child stdin was not piped"))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("child stdout was not piped"))?;
    let child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("child stderr was not piped"))?;

    // Bounded so a slow printer cannot pin every forwarded byte as a notice.
    // `Done` still fits: the copy thread waits only for that one message.
    let (tx, rx) = mpsc::sync_channel::<CopyNote>(64);

    let stdin_tx = tx.clone();
    let stdin_thread = thread::Builder::new()
        .name("aw-mcp-tap-stdin".to_owned())
        .spawn(move || {
            let result = copy_parent_to_child(io::stdin(), child_stdin, DIR_C2S, &stdin_tx);
            let _ = stdin_tx.send(CopyNote::Done(result));
        })
        .map_err(|err| io::Error::other(err.to_string()))?;

    let stdout_tx = tx.clone();
    let stdout_thread = thread::Builder::new()
        .name("aw-mcp-tap-stdout".to_owned())
        .spawn(move || {
            let result = copy_child_to_parent(child_stdout, io::stdout(), DIR_S2C, &stdout_tx);
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
                    let _ = writeln!(
                        stderr_notes,
                        "mcp-tap: frame not parsed (daemon_unreachable)"
                    );
                }
            }
            CopyNote::Gap { reason } => {
                let _ = writeln!(stderr_notes, "mcp-tap: frame not parsed ({reason})");
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
fn copy_parent_to_child<R: Read, W: Write>(
    mut from: R,
    mut to: W,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
) -> io::Result<()> {
    copy_parsed(&mut from, &mut to, direction, tx)
}

/// Copy child stdout onto the parent, and note each completed line.
fn copy_child_to_parent<R: Read, W: Write>(
    mut from: R,
    mut to: W,
    direction: &'static str,
    tx: &SyncSender<CopyNote>,
) -> io::Result<()> {
    copy_parsed(&mut from, &mut to, direction, tx)
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
