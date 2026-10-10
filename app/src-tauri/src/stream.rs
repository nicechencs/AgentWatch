//! Live stream over the internal channel.
//!
//! The daemon's `GET /api/v1/sessions/{id}/live` answers one SSE snapshot per
//! request (`retry:`, then `id:` / `event:` / `data:` blocks) and closes; a
//! browser `EventSource` reconnects. Here the app does the reconnecting: it
//! asks again with `cursor=<last id>` every `retry` ms and pushes each event to
//! the page through a Tauri channel. Nothing is dropped between polls because
//! the cursor is the last id delivered.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::channel::{self, Failure};

/// Default pause between polls when the daemon sends no `retry:`.
pub const DEFAULT_RETRY: Duration = Duration::from_millis(1000);
/// Pause after a channel error before trying again.
pub const ERROR_BACKOFF: Duration = Duration::from_secs(2);

/// One message to the page.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StreamEvent {
    /// An SSE event: `event` is the SSE event name (`record`, `lagged`, …),
    /// `data` its data text (JSON for `record`).
    Event {
        /// SSE `id:`, when present.
        id: Option<String>,
        /// SSE `event:` (default `message`).
        event: String,
        /// SSE `data:` lines joined with `\n`.
        data: String,
    },
    /// The poll failed; the stream keeps trying after a pause.
    Error {
        /// [`Failure::code`].
        code: String,
        /// [`Failure::message`] (plain Chinese).
        message: String,
        /// [`Failure::detail`]: technical detail for a "details" field.
        detail: String,
        /// HTTP status when the daemon answered with an error.
        status: Option<u16>,
    },
}

/// Parsed SSE body: events and the `retry:` hint.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    /// Events in order.
    pub events: Vec<(Option<String>, String, String)>,
    /// `retry:` in ms.
    pub retry_ms: Option<u64>,
}

/// Parse one SSE body. Comment lines (`:`) are skipped.
#[must_use]
pub fn parse_sse(text: &str) -> Parsed {
    let mut out = Parsed::default();
    for block in text.replace("\r\n", "\n").split("\n\n") {
        let mut id = None;
        let mut event = None;
        let mut data: Vec<&str> = Vec::new();
        for line in block.lines() {
            if line.starts_with(':') {
                continue;
            }
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "id" => id = Some(value.to_owned()),
                "event" => event = Some(value.to_owned()),
                "data" => data.push(value),
                "retry" => out.retry_ms = value.trim().parse().ok(),
                _ => {}
            }
        }
        if !data.is_empty() || event.is_some() {
            out.events.push((
                id,
                event.unwrap_or_else(|| "message".to_owned()),
                data.join("\n"),
            ));
        }
    }
    out
}

/// `target` with `cursor=<last>` set (replacing any cursor already there).
#[must_use]
pub fn with_cursor(target: &str, cursor: Option<&str>) -> String {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut parts: Vec<String> = query
        .split('&')
        .filter(|p| !p.is_empty() && !p.starts_with("cursor="))
        .map(str::to_owned)
        .collect();
    if let Some(cursor) = cursor {
        parts.push(format!("cursor={cursor}"));
    }
    if parts.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", parts.join("&"))
    }
}

/// Only `/api/v1/sessions/{id}/live` may be streamed.
///
/// # Errors
///
/// [`Failure`] `refused` for anything else.
pub fn check_target(target: &str) -> Result<(), Failure> {
    channel::check("GET", target, "")?;
    let path = target.split('?').next().unwrap_or("");
    let ok = path
        .strip_prefix("/api/v1/sessions/")
        .and_then(|rest| rest.strip_suffix("/live"))
        .is_some_and(|sid| !sid.is_empty() && !sid.contains('/'));
    if ok {
        Ok(())
    } else {
        Err(Failure::refused("only /api/v1/sessions/{id}/live streams"))
    }
}

/// One poll of the stream: `GET target` to the daemon. The window passes
/// [`window_get`]; tests pass a fake.
pub type Get<'a> = dyn Fn(&str) -> Result<channel::Reply, Failure> + 'a;

/// The window's poll: every call resolves the path again (the pinned daemon,
/// else the documented order) and goes through the process-wide pin, so a
/// reconnect after the pinned daemon went away walks system socket, then
/// per-user — only not-found / refused moves on, other errors are reported.
///
/// # Errors
///
/// See [`Failure`].
pub fn window_get(resolve: &dyn Fn() -> PathBuf, target: &str) -> Result<channel::Reply, Failure> {
    channel::exchange(&resolve(), "GET", target, "")
}

/// Poll until `closed` is set or `send` reports the page went away. Blocking;
/// run it on its own thread. Each poll (and so each reconnect) is a fresh
/// `get`: nothing about which daemon answered last time is held here.
pub fn run(
    get: &Get<'_>,
    target: &str,
    closed: &Arc<AtomicBool>,
    send: &mut dyn FnMut(StreamEvent) -> bool,
    mut sleep: impl FnMut(Duration),
) {
    let mut cursor: Option<String> = None;
    while !closed.load(Ordering::SeqCst) {
        let wanted = with_cursor(target, cursor.as_deref());
        let pause = match get(&wanted) {
            Ok(reply) if reply.status == 200 => {
                let parsed = parse_sse(&reply.body);
                for (id, event, data) in parsed.events {
                    if id.is_some() {
                        cursor.clone_from(&id);
                    }
                    if !send(StreamEvent::Event { id, event, data }) {
                        return;
                    }
                }
                parsed.retry_ms.map_or(DEFAULT_RETRY, Duration::from_millis)
            }
            Ok(reply) => {
                let gone = reply.status == 404 || reply.status == 403;
                let ok = send(StreamEvent::Error {
                    code: format!("http_{}", reply.status),
                    message: "实时流请求被服务拒绝。".to_owned(),
                    detail: reply.body,
                    status: Some(reply.status),
                });
                if !ok || gone {
                    return;
                }
                ERROR_BACKOFF
            }
            Err(failure) => {
                if !send(StreamEvent::Error {
                    code: failure.code,
                    message: failure.message,
                    detail: failure.detail,
                    status: None,
                }) {
                    return;
                }
                ERROR_BACKOFF
            }
        };
        sleep(pause);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{check_target, parse_sse, with_cursor};

    #[test]
    fn sse_snapshot_parses() {
        let body = "retry: 1000\nevent: lagged\ndata: {\"dropped\":true}\n\nid: 7\nevent: record\ndata: {\"a\":1}\n\n: keepalive\n\n";
        let parsed = parse_sse(body);
        assert_eq!(parsed.retry_ms, Some(1000));
        assert_eq!(parsed.events.len(), 2);
        assert_eq!(parsed.events[0].1, "lagged");
        assert_eq!(
            parsed.events[1],
            (
                Some("7".to_owned()),
                "record".to_owned(),
                "{\"a\":1}".to_owned()
            )
        );
    }

    #[test]
    fn cursor_replaces_and_keeps_other_params() {
        assert_eq!(
            with_cursor("/api/v1/sessions/s-1/live", None),
            "/api/v1/sessions/s-1/live"
        );
        assert_eq!(
            with_cursor("/api/v1/sessions/s-1/live?filter=x&cursor=3", Some("9")),
            "/api/v1/sessions/s-1/live?filter=x&cursor=9"
        );
    }

    #[test]
    fn only_live_routes_stream() {
        assert!(check_target("/api/v1/sessions/s-1/live").is_ok());
        assert!(check_target("/api/v1/sessions/s-1/live?filter=a").is_ok());
        assert!(check_target("/api/v1/sessions").is_err());
        assert!(check_target("/api/v1/sessions/a/b/live").is_err());
        assert!(check_target("/health").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn run_delivers_events_and_advances_the_cursor() {
        use std::io::{Read, Write};
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        let dir = aw_channel::short_temp_dir("live");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("api.sock");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for n in 0..2 {
                let (mut s, _) = listener.accept().expect("accept");
                let mut buf = [0_u8; 2048];
                let k = s.read(&mut buf).expect("read");
                seen.push(
                    String::from_utf8_lossy(&buf[..k])
                        .lines()
                        .next()
                        .unwrap_or("")
                        .to_owned(),
                );
                let body = format!(
                    "retry: 5\nid: {}\nevent: record\ndata: {{\"n\":{n}}}\n\n",
                    n + 1
                );
                let head = format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n", body.len());
                s.write_all(head.as_bytes()).unwrap();
                s.write_all(body.as_bytes()).unwrap();
            }
            seen
        });
        let closed = Arc::new(AtomicBool::new(false));
        let mut got = Vec::new();
        let mut send = |ev: super::StreamEvent| {
            got.push(ev);
            got.len() < 2
        };
        super::run(
            &|t: &str| crate::channel::exchange(&path, "GET", t, ""),
            "/api/v1/sessions/s-1/live",
            &closed,
            &mut send,
            |_| {},
        );
        let seen = server.join().unwrap();
        assert_eq!(got.len(), 2);
        assert!(
            seen[0].starts_with("GET /api/v1/sessions/s-1/live HTTP/1.1"),
            "{seen:?}"
        );
        assert!(
            seen[1].starts_with("GET /api/v1/sessions/s-1/live?cursor=1 HTTP/1.1"),
            "{seen:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The pinned daemon goes away mid-stream: the next poll re-runs the
    /// ordered lookup (system first, then per-user) instead of sticking to
    /// the dead path; a real error on the system socket is reported, not
    /// skipped.
    #[test]
    fn reconnect_re_runs_the_ordered_lookup() {
        use std::cell::RefCell;
        use std::path::{Path, PathBuf};
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        use aw_channel::{DialError, Response};

        use crate::channel::{pinned_exchange, reply_of, Pin};

        let system = PathBuf::from("/sys.sock");
        let user = PathBuf::from("/user.sock");
        let order = vec![system.clone(), user.clone()];
        // Per poll: what each path does. Poll 1: only the user daemon is up.
        // Poll 2: it is gone, a system daemon is up. Poll 3: system denies.
        let script: Vec<[(&Path, &str); 2]> = vec![
            [(&system, "down"), (&user, "up")],
            [(&system, "up"), (&user, "down")],
            [(&system, "denied"), (&user, "down")],
        ];
        let poll = RefCell::new(0_usize);
        let dialled = RefCell::new(Vec::<(usize, PathBuf)>::new());
        let pin = Pin::default();
        let get = |target: &str| {
            let n = *poll.borrow();
            *poll.borrow_mut() += 1;
            let dial = |p: &Path| -> Result<Response, DialError> {
                dialled.borrow_mut().push((n, p.to_path_buf()));
                let what = script[n]
                    .iter()
                    .find(|(q, _)| *q == p)
                    .map_or("down", |(_, w)| *w);
                match what {
                    "up" => Ok(Response {
                        status: 200,
                        headers: vec![],
                        body: format!("id: {n}\nevent: record\ndata: {}\n\n", p.display())
                            .into_bytes(),
                    }),
                    "denied" => Err(DialError::Forbidden(format!("{}: denied", p.display()))),
                    _ => Err(DialError::Unreachable(format!("{}: refused", p.display()))),
                }
            };
            let _ = target;
            pinned_exchange(&pin, &order, &dial)
                .map(reply_of)
                .map_err(Into::into)
        };
        let closed = Arc::new(AtomicBool::new(false));
        let mut got = Vec::new();
        let mut send = |ev: super::StreamEvent| {
            got.push(ev);
            got.len() < 3
        };
        super::run(
            &get,
            "/api/v1/sessions/s-1/live",
            &closed,
            &mut send,
            |_| {},
        );

        let datas: Vec<String> = got
            .iter()
            .map(|ev| match ev {
                super::StreamEvent::Event { data, .. } => data.clone(),
                super::StreamEvent::Error { code, .. } => code.clone(),
            })
            .collect();
        assert_eq!(datas, vec!["/user.sock", "/sys.sock", "daemon_forbidden"]);
        let dialled = dialled.into_inner();
        // Poll 2: the pinned user socket first, refused, then the walk from
        // the top finds the system daemon.
        let second: Vec<_> = dialled
            .iter()
            .filter(|(n, _)| *n == 1)
            .map(|(_, p)| p.clone())
            .collect();
        assert_eq!(second, vec![user.clone(), system.clone()]);
        // Poll 3: the pinned system socket says "denied": reported, the
        // per-user socket is not tried.
        let third: Vec<_> = dialled
            .iter()
            .filter(|(n, _)| *n == 2)
            .map(|(_, p)| p.clone())
            .collect();
        assert_eq!(third, vec![system]);
    }
}
