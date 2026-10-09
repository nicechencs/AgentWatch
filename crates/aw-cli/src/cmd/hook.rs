//! `aw hook <AGENT> [--session <SESSION>]` (P5-AGENT-02).
//!
//! The process is a hook script. Agents treat a non-zero exit, or a JSON body
//! that says `deny`, as a decision. This command never does either. Every path
//! returns exit 0 and writes nothing that an agent could parse as a policy.
//!
//! Budget: 200 ms from the start of [`run`] until the daemon write is abandoned.
//! A slow read, a slow connect, or a missing daemon is a drop. The CLI cannot
//! write the daemon's gap table; it sends `dropped: true` when it still has
//! time, and the daemon records `gap_kind = self_report_dropped`.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use aw_agent_adapters::{parse_hook, HookRegistry};
use serde_json::{json, Value};

use crate::endpoint::{self, Endpoint, EndpointInput};
use crate::exit;

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
    match endpoint {
        Endpoint::Http { base, token } => {
            let addr = SocketAddr::from(([127, 0, 0, 1], base.port));
            let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(50))?;
            let _ = stream.set_write_timeout(Some(Duration::from_millis(50)));
            let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
            let head = format!(
                "POST /api/v1/agent/hook HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                base.host_header(),
                token,
                body.len(),
            );
            stream.write_all(head.as_bytes())?;
            stream.write_all(body)?;
            // One byte is enough to know the daemon accepted the TCP connection.
            // The body is not parsed: a daemon error must not change this exit code.
            let mut ack = [0_u8; 1];
            let _ = stream.read(&mut ack);
            Ok(())
        }
        Endpoint::Unix { path } => write_frame(path, body),
        Endpoint::Pipe { path } => write_frame(path, body),
    }
}

/// Length-prefixed frame: 4 byte big-endian length, then the JSON body.
///
/// Unix sockets and Windows named pipes are both opened through `File`. On
/// Windows a pipe path (`\\.\pipe\...`) opens that way; on Unix a socket path
/// does not, and the write fails. That failure is a drop. This card does not
/// add `uds` or a Win32 pipe client — neither is in the lockfile.
fn write_frame(path: &Path, body: &[u8]) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    let len = u32::try_from(body.len()).unwrap_or(u32::MAX);
    file.write_all(&len.to_be_bytes())?;
    file.write_all(body)?;
    Ok(())
}

/// Run the hook. Always [`exit::OK`]. Stdout and stderr stay empty: a hook
/// consumer reads them, and any text here can be mistaken for a decision.
pub(crate) fn run(input: HookInput<'_>, transport: &mut dyn HookTransport) -> Outcome {
    let deadline = input.started + HOOK_BUDGET;
    let _ = (HookRegistry, parse_hook_quiet(input.agent, input.payload));
    if Instant::now() >= deadline {
        return silent_ok();
    }
    let session = resolve_session(input.session_env, input.session_flag);
    if Instant::now() >= deadline {
        // No time left to tell the daemon either. Still exit 0.
        return silent_ok();
    }
    let body = hook_message(input.agent, session.as_deref(), input.payload, false);
    // A `false` (abandoned at the deadline) or any error means the report was
    // not delivered. Say so with one `dropped: true` post, using only the time
    // still inside the budget. If that also fails, stop. Nothing is printed.
    let delivered = transport.send(input.endpoint, &body, deadline);
    if !matches!(delivered, Ok(true)) && Instant::now() < deadline {
        // `Ok(false)` is the deadline. Anything else is a connect or write
        // failure, including a Unix socket that `File::open` cannot write.
        // The notice names the agent and the session only. The payload that
        // failed to send is not attached a second time.
        let reason = if matches!(delivered, Ok(false)) {
            "timeout"
        } else {
            "send_failed"
        };
        let notice = drop_notice(input.agent, session.as_deref(), reason);
        let _ = transport.send(input.endpoint, &notice, deadline);
    }
    silent_ok()
}

fn silent_ok() -> Outcome {
    Outcome {
        code: exit::OK,
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
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
