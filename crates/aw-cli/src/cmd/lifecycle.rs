//! `aw daemon stop`, `restart`, `logs` over the internal channel.
//!
//! - `stop` sends `POST /api/v1/daemon/stop` (accepted only from an
//!   administrator or the daemon's own account, see the daemon's
//!   `api/control.rs`), then polls `/health` until nothing answers. A daemon
//!   that is not running is already stopped: exit 0.
//! - `restart` is `stop` then `start`.
//! - `logs` reads `GET /api/v1/daemon/logs`: the last `--lines` lines, and with
//!   `-f/--follow` keeps asking for what was appended after the returned
//!   offset until interrupted.
//!
//! The daemon owns the log path (its data dir), so `aw` never guesses a file
//! location and never needs read access to it.

#[cfg(unix)]
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use super::ui::{client_error, daemon_start, health, Starter};
use super::{error_outcome, Outcome};
use crate::client::{ApiRequest, Client, Transport};
use crate::endpoint::Endpoint;
use crate::exit;

#[cfg(unix)]
use nix::fcntl::{Flock, FlockArg};

/// How long `stop` waits for `/health` to go away.
pub(crate) const STOP_WAIT: Duration = Duration::from_secs(20);
const STOP_POLL: Duration = Duration::from_millis(200);
/// How often `logs -f` asks for more.
pub(crate) const FOLLOW_POLL: Duration = Duration::from_millis(500);

type Open<'a> = dyn FnMut() -> Box<dyn Transport> + 'a;

fn ok(text: String) -> Outcome {
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn state_line(state: &str, detail: &str, endpoint: &Endpoint, json: bool) -> String {
    if json {
        format!(
            "{}\n",
            json!({ "state": state, "detail": detail, "channel": endpoint.to_string() })
        )
    } else {
        format!("{state}: {detail} · {endpoint}\n")
    }
}

/// `aw daemon stop`.
pub(crate) fn daemon_stop(
    endpoint: &Endpoint,
    open: &mut Open<'_>,
    wait: Duration,
    json: bool,
) -> Outcome {
    match health(endpoint, open()) {
        Ok(_) => {}
        Err(crate::client::ClientError::Unreachable { .. }) => {
            return ok(state_line("stopped", "没有运行", endpoint, json));
        }
        Err(err) => return client_error(&err, endpoint, json),
    }
    let mut client = Client::new(endpoint.clone(), open());
    if let Err(err) = client.call(&ApiRequest::post_json("/api/v1/daemon/stop", &json!({}))) {
        if err.identity_failure_code().is_some() {
            return client_error(&err, endpoint, json);
        }
        if is_permission_error(&err) {
            return error_outcome(
                exit::PERMISSION,
                "permission",
                "需要管理员权限才能停止后台",
                json,
            );
        }
        return client_error(&err, endpoint, json);
    }
    let mut waited = Duration::ZERO;
    loop {
        match health(endpoint, open()) {
            Err(crate::client::ClientError::Unreachable { .. }) => {
                return ok(state_line("stopped", "后台已停止", endpoint, json));
            }
            Ok(_) => {}
            // An identity refusal is an answer, not a stop in progress.
            Err(err) if err.identity_failure_code().is_some() => {
                return client_error(&err, endpoint, json);
            }
            // A reset or half-closed connection while the old daemon tears
            // down is still "stopping": keep polling until it is unreachable
            // or the wait runs out (which is reported, never claimed stopped).
            Err(_) => {}
        }
        if waited >= wait {
            return error_outcome(
                exit::GENERAL,
                "still_running",
                &format!(
                    "agentwatchd 已接受停止请求，但 {} 秒后仍在响应 [{endpoint}]",
                    wait.as_secs()
                ),
                json,
            );
        }
        thread::sleep(STOP_POLL);
        waited += STOP_POLL;
    }
}

/// `aw daemon restart`: stop, then start.
pub(crate) fn daemon_restart(
    endpoint: &Endpoint,
    open: &mut Open<'_>,
    starter: &mut dyn Starter,
    stop_wait: Duration,
    start_wait: Duration,
    json: bool,
) -> Outcome {
    let stopped = daemon_stop(endpoint, open, stop_wait, json);
    if stopped.code != exit::OK {
        if stopped.code == exit::PERMISSION {
            return error_outcome(
                exit::PERMISSION,
                "permission",
                "需要管理员权限才能重启后台",
                json,
            );
        }
        return stopped;
    }
    if let Err(detail) = wait_for_shutdown_release(endpoint, stop_wait) {
        return error_outcome(exit::GENERAL, "restart_timeout", &detail, json);
    }
    let started = daemon_start(endpoint, open, starter, start_wait, json);
    if json || started.code != exit::OK {
        return started;
    }
    let mut stdout = stopped.stdout;
    stdout.extend_from_slice(&started.stdout);
    Outcome { stdout, ..started }
}

/// Wait until the old daemon has released its internal-channel start lock.
///
/// `POST /daemon/stop` is deliberately acknowledged before the foreground
/// loop has flushed collectors and closed its store.  The health endpoint goes
/// away when IPC starts shutting down, which is earlier than releasing this
/// lock.  Starting at that point races the old daemon's data-dir lock.
///
/// Unix sockets have an adjacent flock specifically for serialising startup.
/// Named pipes and HTTP have no equivalent lock file, so their daemon-side
/// bounded instance-lock retry is the fallback.
fn wait_for_shutdown_release(endpoint: &Endpoint, wait: Duration) -> Result<(), String> {
    #[cfg(unix)]
    let lock = match endpoint {
        Endpoint::Unix { path } => {
            let mut name = path.as_os_str().to_owned();
            name.push(".lock");
            Some(std::path::PathBuf::from(name))
        }
        _ => None,
    };
    #[cfg(not(unix))]
    let lock: Option<std::path::PathBuf> = None;

    let Some(lock) = lock else {
        return Ok(());
    };
    let mut waited = Duration::ZERO;
    loop {
        if channel_lock_is_free(&lock)? {
            return Ok(());
        }
        if waited >= wait {
            return Err(format!(
                "agentwatchd 已停止响应，但 {} 秒后仍未释放重启锁；没有启动新实例，以免与旧实例争用数据目录 [{endpoint}]",
                wait.as_secs()
            ));
        }
        thread::sleep(STOP_POLL);
        waited += STOP_POLL;
    }
}

#[cfg(unix)]
fn channel_lock_is_free(path: &std::path::Path) -> Result<bool, String> {
    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(err) => return Err(format!("无法检查重启锁 {}：{}", path.display(), err.kind())),
    };
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => {
            drop(lock);
            Ok(true)
        }
        Err((_, nix::errno::Errno::EWOULDBLOCK)) => Ok(false),
        Err((_, err)) => Err(format!("无法检查重启锁 {}：{err}", path.display())),
    }
}

#[cfg(not(unix))]
fn channel_lock_is_free(_path: &std::path::Path) -> Result<bool, String> {
    Ok(true)
}

/// One logs read: `(text, next offset)`.
fn fetch(
    endpoint: &Endpoint,
    open: &mut Open<'_>,
    query: String,
    json: bool,
) -> Result<(Value, String, u64), Outcome> {
    let mut client = Client::new(endpoint.clone(), open());
    let reply = client
        .call(&ApiRequest::get_query("/api/v1/daemon/logs", query))
        .map_err(|err| {
            if err.identity_failure_code().is_some() {
                client_error(&err, endpoint, json)
            } else if is_permission_error(&err) {
                error_outcome(
                    exit::PERMISSION,
                    "permission",
                    "需要管理员权限才能查看后台日志",
                    json,
                )
            } else {
                client_error(&err, endpoint, json)
            }
        })?;
    let body = reply.json().unwrap_or(Value::Null);
    let text = body
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let offset = body.get("offset").and_then(Value::as_u64).unwrap_or(0);
    Ok((body, text, offset))
}

fn is_permission_error(error: &crate::client::ClientError) -> bool {
    matches!(
        error,
        crate::client::ClientError::Forbidden { .. }
            | crate::client::ClientError::UntrustedServer { .. }
            | crate::client::ClientError::Status {
                status: 401 | 403,
                ..
            }
    )
}

/// `-f` loop settings.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Follow {
    /// Pause between reads.
    pub poll: Duration,
    /// Bound on reads (tests); `None` runs until interrupted or the daemon
    /// goes away.
    pub max_polls: Option<usize>,
}

/// `aw daemon logs [-n N] [-f]`. Output goes to `out` as it arrives so `-f`
/// streams.
pub(crate) fn daemon_logs(
    endpoint: &Endpoint,
    open: &mut Open<'_>,
    lines: usize,
    follow: Option<Follow>,
    json: bool,
    out: &mut dyn Write,
) -> Outcome {
    let (body, text, mut offset) = match fetch(endpoint, open, format!("tail={lines}"), json) {
        Ok(read) => read,
        Err(outcome) => return outcome,
    };
    if write_chunk(out, &body, &text, json).is_err() {
        return Outcome {
            code: exit::OK,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
    }
    let Some(Follow { poll, max_polls }) = follow else {
        return ok(String::new());
    };
    let mut polls = 0_usize;
    while max_polls.is_none_or(|max| polls < max) {
        thread::sleep(poll);
        polls += 1;
        match fetch(endpoint, open, format!("offset={offset}"), json) {
            Ok((body, text, next)) => {
                offset = next;
                if !text.is_empty() && write_chunk(out, &body, &text, json).is_err() {
                    // Reader went away (`| head`): a normal end.
                    break;
                }
            }
            Err(outcome) => return outcome,
        }
    }
    ok(String::new())
}

fn write_chunk(out: &mut dyn Write, body: &Value, text: &str, json: bool) -> std::io::Result<()> {
    if json {
        writeln!(out, "{body}")?;
    } else {
        out.write_all(text.as_bytes())?;
    }
    out.flush()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::time::Duration;

    use super::{daemon_logs, daemon_restart, daemon_stop, Follow};
    use crate::client::{MemoryTransport, Transport};
    use crate::cmd::ui::Starter;
    use crate::endpoint::Endpoint;
    use crate::exit;

    fn sock() -> Endpoint {
        Endpoint::Unix {
            path: PathBuf::from("/tmp/aw-test.sock"),
        }
    }

    fn reply(status: u16, body: &str) -> Box<dyn Transport> {
        Box::new(MemoryTransport::replying(status, body.as_bytes().to_vec()))
    }

    fn down() -> Box<dyn Transport> {
        Box::new(MemoryTransport::failing("down"))
    }

    /// Scripted daemon: answers health until `stop` arrives, then goes away
    /// after `linger` more health checks.
    struct Fake {
        running: bool,
        stop_status: u16,
        linger: usize,
        stops: usize,
    }

    fn opener(fake: Rc<RefCell<Fake>>) -> impl FnMut() -> Box<dyn Transport> {
        // Calls alternate by position: health, stop, health… The closure
        // cannot see the request, so it hands out by the fake's state.
        let mut stop_next = false;
        move || {
            let mut f = fake.borrow_mut();
            if !f.running {
                return down();
            }
            if stop_next {
                stop_next = false;
                f.stops += 1;
                return reply(f.stop_status, r#"{"state":"stopping"}"#);
            }
            if f.stops > 0 {
                if f.linger == 0 {
                    f.running = false;
                    return down();
                }
                f.linger -= 1;
            } else {
                stop_next = true;
            }
            reply(200, r#"{"status":"ok","version":"0.1.0"}"#)
        }
    }

    #[test]
    fn stop_when_not_running_is_ok() {
        let mut open = down;
        let out = daemon_stop(&sock(), &mut open, Duration::ZERO, false);
        assert_eq!(out.code, exit::OK);
        assert!(String::from_utf8(out.stdout).unwrap().contains("没有运行"));
    }

    #[test]
    fn stop_sends_the_request_and_waits_for_health_to_go() {
        let fake = Rc::new(RefCell::new(Fake {
            running: true,
            stop_status: 202,
            linger: 2,
            stops: 0,
        }));
        let mut open = opener(Rc::clone(&fake));
        let out = daemon_stop(&sock(), &mut open, Duration::from_secs(5), false);
        assert_eq!(
            out.code,
            exit::OK,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(fake.borrow().stops, 1);
        assert!(!fake.borrow().running);
    }

    #[test]
    fn stop_refused_is_permission_exit() {
        let fake = Rc::new(RefCell::new(Fake {
            running: true,
            stop_status: 403,
            linger: 0,
            stops: 0,
        }));
        let mut open = opener(fake);
        let out = daemon_stop(&sock(), &mut open, Duration::ZERO, false);
        assert_eq!(out.code, exit::PERMISSION);
    }

    #[test]
    fn stop_that_never_finishes_is_an_error() {
        let mut open = || reply(202, r#"{"status":"ok"}"#);
        let out = daemon_stop(&sock(), &mut open, Duration::ZERO, false);
        assert_eq!(out.code, exit::GENERAL);
    }

    struct CountStarter(Rc<RefCell<Fake>>, usize);
    impl Starter for CountStarter {
        fn start(&mut self) -> Result<u32, String> {
            self.1 += 1;
            let mut f = self.0.borrow_mut();
            f.running = true;
            f.stops = 0;
            Ok(77)
        }
    }

    #[test]
    fn restart_is_stop_then_start() {
        let fake = Rc::new(RefCell::new(Fake {
            running: true,
            stop_status: 202,
            linger: 0,
            stops: 0,
        }));
        let mut open = opener(Rc::clone(&fake));
        let mut starter = CountStarter(Rc::clone(&fake), 0);
        let out = daemon_restart(
            &sock(),
            &mut open,
            &mut starter,
            Duration::from_secs(5),
            Duration::from_secs(5),
            false,
        );
        assert_eq!(
            out.code,
            exit::OK,
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(starter.1, 1);
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(text.contains("stopped"), "{text}");
        assert!(text.contains("已启动 PID 77"), "{text}");
    }

    #[test]
    fn logs_prints_the_tail_and_follows_offsets() {
        let mut calls = 0;
        let mut open = || {
            calls += 1;
            match calls {
                1 => reply(200, r#"{"text":"a\nb\n","offset":4}"#),
                2 => reply(200, r#"{"text":"","offset":4}"#),
                _ => reply(200, r#"{"text":"c\n","offset":6}"#),
            }
        };
        let mut out = Vec::new();
        let outcome = daemon_logs(
            &sock(),
            &mut open,
            50,
            Some(Follow {
                poll: Duration::ZERO,
                max_polls: Some(2),
            }),
            false,
            &mut out,
        );
        assert_eq!(outcome.code, exit::OK);
        assert_eq!(String::from_utf8(out).unwrap(), "a\nb\nc\n");
    }

    #[test]
    fn logs_without_daemon_is_exit_3() {
        let mut open = down;
        let mut out = Vec::new();
        let outcome = daemon_logs(&sock(), &mut open, 50, None, false, &mut out);
        assert_eq!(outcome.code, exit::UNREACHABLE);
        assert!(out.is_empty());
    }
}
