//! Daemon control over the internal channel only: `aw daemon stop` and
//! `aw daemon logs` (api-and-cli §3).
//!
//! These two routes are not on the loopback HTTP listener. They need a caller
//! identified by the channel itself (socket peer uid, pipe client token): an
//! administrator, or the account the daemon runs as (an unprivileged
//! development daemon). Everyone else gets 403.
//!
//! - `POST /api/v1/daemon/stop` sets the stop flag the runtime loop polls; the
//!   loop then shuts down the way a stop file or Ctrl-C does. 202.
//! - `GET /api/v1/daemon/logs?tail=N` returns the last `N` lines (default 200,
//!   at most 5000) of `agentwatchd.log`. `?offset=B` instead returns what was
//!   appended after byte `B` (at most 64 KiB per call); `aw daemon logs -f`
//!   polls with the returned `offset`. A file shorter than `offset` was
//!   rotated and is read from the start. The log is already sanitized by the
//!   writer, so the text is returned as is.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde_json::json;

use super::auth::Caller;
use super::routes::{error_response, ApiResponse, HttpRequest};

/// Stop route.
pub const STOP_PATH: &str = "/api/v1/daemon/stop";
/// Logs route.
pub const LOGS_PATH: &str = "/api/v1/daemon/logs";
/// UI ticket route (answered by routes.rs, decorated here).
pub const TICKET_PATH: &str = "/api/v1/auth/ui-ticket";

const DEFAULT_TAIL: usize = 200;
const MAX_TAIL: usize = 5000;
const MAX_CHUNK: u64 = 64 * 1024;
/// How far back from the end a `tail` read looks.
const TAIL_WINDOW: u64 = 1024 * 1024;

/// What the internal channel can do to the daemon itself.
#[derive(Debug, Default)]
pub struct Control {
    stop: AtomicBool,
    /// Port the loopback HTTP listener bound; 0 = off. Returned with a UI
    /// ticket so `aw ui` opens the real port.
    http_port: std::sync::atomic::AtomicU32,
    /// Active log file, when the daemon writes one.
    pub log_path: Option<PathBuf>,
    /// User id the daemon runs as, in the channel's `Caller::user_id` form.
    pub owner: Option<String>,
}

impl Control {
    /// Control with the given log file and the current process's user id.
    #[must_use]
    pub fn new(log_path: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            stop: AtomicBool::new(false),
            http_port: std::sync::atomic::AtomicU32::new(0),
            log_path,
            owner: own_user_id(),
        })
    }

    /// A stop was requested over the channel.
    #[must_use]
    pub fn stop_requested(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Record the HTTP port actually bound (0 = listener off).
    pub fn set_http_port(&self, port: u16) {
        self.http_port.store(u32::from(port), Ordering::SeqCst);
    }

    /// HTTP port actually bound; 0 = off.
    #[must_use]
    pub fn http_port(&self) -> u16 {
        u16::try_from(self.http_port.load(Ordering::SeqCst)).unwrap_or(0)
    }

    fn allowed(&self, caller: &Caller) -> bool {
        caller.admin || self.owner.as_deref() == Some(caller.user_id.as_str())
    }
}

/// JSON response. `ApiResponse::json` is private to routes.rs.
fn json_reply(status: u16, value: &serde_json::Value) -> ApiResponse {
    let mut headers = std::collections::BTreeMap::new();
    headers.insert("content-type".to_owned(), "application/json".to_owned());
    ApiResponse {
        status,
        headers,
        body: serde_json::to_vec(value).unwrap_or_default(),
    }
}

#[cfg(unix)]
fn own_user_id() -> Option<String> {
    Some(nix::unistd::geteuid().as_raw().to_string())
}

#[cfg(not(unix))]
fn own_user_id() -> Option<String> {
    None
}

/// `Some(response)` when `req` is a control route, else `None` (normal routes).
#[must_use]
pub fn handle(control: &Control, req: &HttpRequest, caller: &Caller) -> Option<ApiResponse> {
    let path = req.path.as_str();
    if path != STOP_PATH && path != LOGS_PATH {
        return None;
    }
    if !control.allowed(caller) {
        return Some(error_response(
            403,
            "forbidden",
            "daemon control needs an administrator or the daemon's own account",
        ));
    }
    Some(match (req.method.as_str(), path) {
        ("POST", STOP_PATH) => {
            control.stop.store(true, Ordering::SeqCst);
            tracing::info!(target: "aw_daemon::ipc", user = %caller.user_id, "stop requested over the internal channel");
            json_reply(202, &json!({ "state": "stopping" }))
        }
        ("GET", LOGS_PATH) => logs(control, &req.query),
        _ => error_response(405, "method_not_allowed", "method not allowed"),
    })
}

/// Add channel facts to a normal route's reply. Today: a successful
/// `POST /api/v1/auth/ui-ticket` gains `http_port` (the bound port, 0 = off).
#[must_use]
pub fn decorate(control: &Control, req: &HttpRequest, mut reply: ApiResponse) -> ApiResponse {
    if req.method != "POST" || req.path != TICKET_PATH || reply.status != 200 {
        return reply;
    }
    if let Ok(serde_json::Value::Object(mut map)) =
        serde_json::from_slice::<serde_json::Value>(&reply.body)
    {
        map.insert("http_port".to_owned(), json!(control.http_port()));
        if let Ok(body) = serde_json::to_vec(&serde_json::Value::Object(map)) {
            reply.body = body;
        }
    }
    reply
}

fn logs(control: &Control, query: &str) -> ApiResponse {
    let Some(path) = control.log_path.as_ref() else {
        return error_response(404, "no_log_file", "this daemon writes no log file");
    };
    let mut offset = None;
    let mut tail = DEFAULT_TAIL;
    for pair in query.split('&') {
        match pair.split_once('=') {
            Some(("offset", v)) => match v.parse::<u64>() {
                Ok(n) => offset = Some(n),
                Err(_) => return error_response(400, "bad_query", "offset must be a number"),
            },
            Some(("tail", v)) => match v.parse::<usize>() {
                Ok(n) => tail = n.min(MAX_TAIL),
                Err(_) => return error_response(400, "bad_query", "tail must be a number"),
            },
            _ => {}
        }
    }
    let read = match offset {
        Some(from) => read_from(path, from),
        None => read_tail(path, tail),
    };
    match read {
        Ok((text, next)) => json_reply(
            200,
            &json!({ "path": path.display().to_string(), "text": text, "offset": next }),
        ),
        Err(err) if err.kind() == io::ErrorKind::NotFound => json_reply(
            200,
            &json!({ "path": path.display().to_string(), "text": "", "offset": 0 }),
        ),
        Err(err) => error_response(500, "log_unreadable", &err.to_string()),
    }
}

/// Bytes appended after `from`, at most [`MAX_CHUNK`]. Restarts at 0 after rotation.
pub(crate) fn read_from(path: &std::path::Path, from: u64) -> io::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let start = if from > len { 0 } else { from };
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    file.take(MAX_CHUNK).read_to_end(&mut buf)?;
    // Stop at the last newline so a half-written line is sent next time.
    let cut = if start + (buf.len() as u64) < len || !buf.ends_with(b"\n") {
        buf.iter()
            .rposition(|b| *b == b'\n')
            .map_or(buf.len(), |i| i + 1)
    } else {
        buf.len()
    };
    buf.truncate(cut);
    let next = start + buf.len() as u64;
    Ok((String::from_utf8_lossy(&buf).into_owned(), next))
}

/// Last `lines` lines and the file length.
pub(crate) fn read_tail(path: &std::path::Path, lines: usize) -> io::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(TAIL_WINDOW);
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    let all: Vec<&str> = text.lines().collect();
    // A window that starts mid-file starts mid-line: drop that partial line.
    let skip_partial = usize::from(start > 0);
    let usable = &all[skip_partial.min(all.len())..];
    let kept = &usable[usable.len().saturating_sub(lines)..];
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    Ok((out, len))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::io::Write;

    use super::{handle, read_from, read_tail, Control, LOGS_PATH, STOP_PATH};
    use crate::api::auth::Caller;
    use crate::api::routes::HttpRequest;

    fn temp_log(name: &str, text: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aw-ctl-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agentwatchd.log");
        std::fs::write(&path, text).unwrap();
        path
    }

    fn req(method: &str, path: &str, query: &str) -> HttpRequest {
        HttpRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            query: query.to_owned(),
            ..HttpRequest::default()
        }
    }

    fn caller(user: &str, admin: bool) -> Caller {
        Caller {
            user_id: user.to_owned(),
            admin,
            peer: None,
        }
    }

    fn control(log: Option<std::path::PathBuf>) -> Control {
        Control {
            log_path: log,
            owner: Some("1000".to_owned()),
            ..Control::default()
        }
    }

    #[test]
    fn ticket_reply_gains_the_bound_http_port() {
        let ctl = control(None);
        ctl.set_http_port(9123);
        let reply = super::json_reply(200, &serde_json::json!({ "ticket": "t", "ttl_s": 60 }));
        let out = super::decorate(&ctl, &req("POST", super::TICKET_PATH, ""), reply);
        let body: serde_json::Value = serde_json::from_slice(&out.body).unwrap();
        assert_eq!(body["http_port"], 9123);
        assert_eq!(body["ticket"], "t");
        let other = super::json_reply(200, &serde_json::json!({}));
        let out = super::decorate(&ctl, &req("GET", "/health", ""), other);
        assert_eq!(out.body, b"{}");
    }

    #[test]
    fn other_routes_pass_through() {
        assert!(handle(
            &control(None),
            &req("GET", "/health", ""),
            &caller("1", false)
        )
        .is_none());
    }

    #[test]
    fn stop_needs_admin_or_owner_and_sets_the_flag() {
        let ctl = control(None);
        let denied = handle(&ctl, &req("POST", STOP_PATH, ""), &caller("1001", false)).unwrap();
        assert_eq!(denied.status, 403);
        assert!(!ctl.stop_requested());
        let wrong = handle(&ctl, &req("GET", STOP_PATH, ""), &caller("1000", false)).unwrap();
        assert_eq!(wrong.status, 405);
        assert!(!ctl.stop_requested());
        let ok = handle(&ctl, &req("POST", STOP_PATH, ""), &caller("1000", false)).unwrap();
        assert_eq!(ok.status, 202);
        assert!(ctl.stop_requested());
        let admin = control(None);
        let ok = handle(&admin, &req("POST", STOP_PATH, ""), &caller("0", true)).unwrap();
        assert_eq!(ok.status, 202);
    }

    #[test]
    fn logs_tail_and_follow_offsets() {
        let path = temp_log("tail", "one\ntwo\nthree\n");
        let ctl = control(Some(path.clone()));
        let reply = handle(
            &ctl,
            &req("GET", LOGS_PATH, "tail=2"),
            &caller("1000", false),
        )
        .unwrap();
        assert_eq!(reply.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["text"], "two\nthree\n");
        let offset = body["offset"].as_u64().unwrap();
        assert_eq!(offset, 14);

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(b"four\nhalf").unwrap();
        let reply = handle(
            &ctl,
            &req("GET", LOGS_PATH, &format!("offset={offset}")),
            &caller("0", true),
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["text"], "four\n", "half line held back");
        assert_eq!(body["offset"], 19);

        let denied = handle(&ctl, &req("GET", LOGS_PATH, ""), &caller("2", false)).unwrap();
        assert_eq!(denied.status, 403);
        let bad = handle(&ctl, &req("GET", LOGS_PATH, "tail=x"), &caller("0", true)).unwrap();
        assert_eq!(bad.status, 400);
    }

    #[test]
    fn rotation_restarts_and_missing_file_is_empty() {
        let path = temp_log("rot", "a\n");
        let (text, next) = read_from(&path, 500).unwrap();
        assert_eq!((text.as_str(), next), ("a\n", 2));
        let (all, len) = read_tail(&path, 10).unwrap();
        assert_eq!((all.as_str(), len), ("a\n", 2));
        let ctl = control(Some(path.with_file_name("missing.log")));
        let reply = handle(&ctl, &req("GET", LOGS_PATH, ""), &caller("0", true)).unwrap();
        assert_eq!(reply.status, 200);
        let none = control(None);
        let reply = handle(&none, &req("GET", LOGS_PATH, ""), &caller("0", true)).unwrap();
        assert_eq!(reply.status, 404);
    }
}
