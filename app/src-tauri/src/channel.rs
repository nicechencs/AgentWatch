//! Internal channel client for the window (api-and-cli §1, ADR-0005).
//!
//! The app runs unprivileged and talks to `agentwatchd` over the Unix socket
//! (Linux/macOS) or the named pipe (Windows) through `aw-channel`, the same
//! client `aw` uses: same path order (system path, then the per-user path an
//! unprivileged daemon binds), same error classes, pipe-busy retry, timeout.
//! No `Authorization` is sent; the daemon identifies the peer by its OS
//! credential. Nothing here opens a TCP port.
//!
//! Bodies are bytes end to end. [`Reply::body_base64`] carries them unchanged
//! (a CSV zip export); [`Reply::body`] is the same bytes as UTF-8 text for the
//! JSON routes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aw_channel::DialError;

/// Normal request timeout.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// Request body cap, matching the daemon's 64 KiB.
pub const MAX_BODY: usize = 64 * 1024;

/// One reply from the daemon.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// Response headers, names lowercased.
    pub headers: BTreeMap<String, String>,
    /// Body as UTF-8 text (lossy). Use for JSON.
    pub body: String,
    /// Body bytes, standard base64. Use for anything binary.
    pub body_base64: String,
}

/// Error object the page receives when a command fails. `code` is one of
/// `daemon_unreachable`, `daemon_forbidden`, `daemon_busy`, `daemon_timeout`,
/// `channel_broken`, `refused`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Failure {
    /// Stable machine code.
    pub code: String,
    /// One plain Chinese sentence for a person. No paths, no OS error text.
    pub message: String,
    /// Technical detail (paths tried, OS error kinds) for a collapsible
    /// "details" field. Not meant as the main text.
    pub detail: String,
}

impl Failure {
    /// A request this app will not send.
    #[must_use]
    pub fn refused(detail: &str) -> Self {
        Self {
            code: "refused".to_owned(),
            message: "应用拒绝发送这个请求。".to_owned(),
            detail: detail.to_owned(),
        }
    }

    /// The exchange broke inside the app.
    #[must_use]
    pub fn broken(detail: &str) -> Self {
        Self {
            code: "channel_broken".to_owned(),
            message: "与 AgentWatch 服务的连接中断了，请重试。".to_owned(),
            detail: detail.to_owned(),
        }
    }
}

impl From<DialError> for Failure {
    fn from(err: DialError) -> Self {
        Self {
            code: err.code().to_owned(),
            message: err.plain(),
            detail: err.detail().to_owned(),
        }
    }
}

/// Socket or pipe path: `AW_SOCKET` when set, else the first existing
/// candidate in the shared order.
#[must_use]
pub fn channel_path(env: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    aw_channel::resolve(env).unwrap_or_else(|| PathBuf::from(aw_channel::LINUX_SOCKET))
}

/// Only the API and `/health` may be requested. `target` is path plus optional query.
///
/// # Errors
///
/// [`Failure`] `refused` for any other method, path, or an oversize body.
pub fn check(method: &str, target: &str, body: &str) -> Result<(), Failure> {
    let upper = method.to_ascii_uppercase();
    if !matches!(upper.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return Err(Failure::refused(&format!("method {upper}")));
    }
    let path = target.split('?').next().unwrap_or("");
    let allowed = path == "/health" || path.starts_with("/api/v1/");
    if !allowed || target.contains(['\r', '\n', ' ']) || path.contains("..") {
        return Err(Failure::refused("path"));
    }
    if body.len() > MAX_BODY {
        return Err(Failure::refused("body exceeds 64 KiB"));
    }
    Ok(())
}

/// Request bytes. No `Authorization`.
#[must_use]
pub fn encode(method: &str, target: &str, body: &str) -> Vec<u8> {
    aw_channel::encode_request(method, target, "*/*", body.as_bytes())
}

/// Reply from a parsed response.
#[must_use]
pub fn reply_of(response: aw_channel::Response) -> Reply {
    Reply {
        status: response.status,
        headers: response.headers.into_iter().collect(),
        body: String::from_utf8_lossy(&response.body).into_owned(),
        body_base64: base64(&response.body),
    }
}

/// Send one request on the channel and wait for the reply.
///
/// # Errors
///
/// See [`Failure`].
pub fn exchange(path: &Path, method: &str, target: &str, body: &str) -> Result<Reply, Failure> {
    exchange_response(path, method, target, body).map(reply_of)
}

/// [`exchange`], keeping the raw response (bytes, headers): the export save
/// writes these bytes to a file. Goes to the daemon this window is pinned to
/// (see [`Pin`]).
///
/// # Errors
///
/// See [`Failure`].
pub fn exchange_response(
    path: &Path,
    method: &str,
    target: &str,
    body: &str,
) -> Result<aw_channel::Response, Failure> {
    check(method, target, body)?;
    let order = aw_channel::dial_order(path, &|key| std::env::var(key).ok());
    let request = encode(method, target, body);
    let response = pinned_exchange(pin(), &order, &|candidate| {
        aw_channel::exchange(candidate, &request, TIMEOUT)
    })?;
    not_gzip(response)
}

fn not_gzip(response: aw_channel::Response) -> Result<aw_channel::Response, Failure> {
    if response
        .header("content-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("gzip"))
    {
        // The daemon gzips only when asked; this client never asks.
        return Err(Failure::broken("unexpected gzip body"));
    }
    Ok(response)
}

/// The daemon this window talks to, kept for the life of the process.
///
/// The dial order is system socket first, then the per-user one. Walking it on
/// every request let one window talk to two daemons: when another daemon's
/// `/run/agentwatch/api.sock` came up or went away while the user's own daemon
/// was running, each request went to whichever answered first at that moment.
/// That daemon does not have the user's sessions, so a page got "session not
/// found" (Markdown export, timeline) and the user's daemon logged nothing.
/// The first path that answers is kept. Only when it stops answering
/// (not found / refused) is the whole order walked again, so Retry still finds
/// a daemon that came up meanwhile.
#[derive(Debug, Default)]
pub struct Pin {
    path: std::sync::Mutex<Option<PathBuf>>,
}

impl Pin {
    fn current(&self) -> Option<PathBuf> {
        self.path.lock().ok().and_then(|slot| slot.clone())
    }

    fn set(&self, path: Option<PathBuf>) {
        if let Ok(mut slot) = self.path.lock() {
            *slot = path;
        }
    }
}

fn pin() -> &'static Pin {
    static PIN: std::sync::OnceLock<Pin> = std::sync::OnceLock::new();
    PIN.get_or_init(Pin::default)
}

/// The path requests go to now: the pinned daemon, else `fallback`.
#[must_use]
pub fn pinned_path(fallback: PathBuf) -> PathBuf {
    pin().current().unwrap_or(fallback)
}

/// One exchange through `pin`.
///
/// - Pinned: dial only the pinned path. Not found / refused unpins and falls
///   through to the walk below; any other result (including permission
///   denied, busy, timeout) is returned and the pin is kept.
/// - Not pinned: walk `order` (system socket, then per-user) one candidate at
///   a time, never in parallel. Only not found / refused moves on; the first
///   other error is returned and nothing is pinned. The first candidate that
///   answers becomes the pin.
fn pinned_exchange(
    pin: &Pin,
    order: &[PathBuf],
    dial: &dyn Fn(&Path) -> Result<aw_channel::Response, DialError>,
) -> Result<aw_channel::Response, DialError> {
    if let Some(pinned) = pin.current() {
        match dial(&pinned) {
            Err(DialError::Unreachable(_)) => pin.set(None),
            other => return other,
        }
    }
    let mut tried = Vec::new();
    for candidate in order {
        match dial(candidate) {
            Ok(response) => {
                pin.set(Some(candidate.clone()));
                return Ok(response);
            }
            Err(DialError::Unreachable(detail)) => tried.push(detail),
            Err(other) => return Err(other),
        }
    }
    if tried.is_empty() {
        tried.push("no channel path on this OS".to_owned());
    }
    Err(DialError::Unreachable(tried.join("; ")))
}

/// [`exchange`] with an explicit environment and a fresh [`Pin`]: the dial
/// order (system socket, then per-user) with a stale system socket falling
/// through. Tests only; the window goes through the process-wide pin.
///
/// # Errors
///
/// See [`Failure`].
#[cfg(test)]
pub fn exchange_in(
    path: &Path,
    method: &str,
    target: &str,
    body: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Reply, Failure> {
    check(method, target, body)?;
    let order = aw_channel::dial_order(path, env);
    let request = encode(method, target, body);
    let response = pinned_exchange(&Pin::default(), &order, &|candidate| {
        aw_channel::exchange(candidate, &request, TIMEOUT)
    })?;
    not_gzip(response).map(reply_of)
}

/// Standard base64 with padding. std only.
#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let take = |shift: u32| char::from(ALPHABET[((n >> shift) & 63) as usize]);
        out.push(take(18));
        out.push(take(12));
        out.push(if chunk.len() > 1 { take(6) } else { '=' });
        out.push(if chunk.len() > 2 { take(0) } else { '=' });
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{base64, channel_path, check, encode};
    use super::{pinned_exchange, Pin};
    use aw_channel::{DialError, Response};
    use std::cell::RefCell;
    use std::collections::HashSet;
    use std::path::{Path, PathBuf};

    /// A fake channel: each path answers with a fixed outcome; every dial is
    /// recorded in order.
    struct Fake {
        outcomes: RefCell<Vec<(PathBuf, &'static str)>>,
        dialed: RefCell<Vec<PathBuf>>,
    }

    impl Fake {
        fn new(outcomes: &[(&PathBuf, &'static str)]) -> Self {
            Self {
                outcomes: RefCell::new(outcomes.iter().map(|(p, o)| ((*p).clone(), *o)).collect()),
                dialed: RefCell::new(Vec::new()),
            }
        }

        fn set(&self, path: &PathBuf, outcome: &'static str) {
            let mut all = self.outcomes.borrow_mut();
            all.retain(|(p, _)| p != path);
            all.push((path.clone(), outcome));
        }

        fn dial(&self, path: &Path) -> Result<Response, DialError> {
            self.dialed.borrow_mut().push(path.to_path_buf());
            let outcome = self
                .outcomes
                .borrow()
                .iter()
                .find(|(p, _)| p == path)
                .map_or("down", |(_, o)| *o);
            let detail = path.display().to_string();
            match outcome {
                "up" => Ok(Response {
                    status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                }),
                "forbidden" => Err(DialError::Forbidden(detail)),
                "busy" => Err(DialError::Busy(detail)),
                "timeout" => Err(DialError::Timeout(detail)),
                _ => Err(DialError::Unreachable(detail)),
            }
        }

        fn take(&self) -> Vec<PathBuf> {
            std::mem::take(&mut *self.dialed.borrow_mut())
        }
    }

    fn paths() -> (PathBuf, PathBuf) {
        (
            PathBuf::from("/run/agentwatch/api.sock"),
            PathBuf::from("/run/user/1000/agentwatch/api.sock"),
        )
    }

    /// (a) The pin is chosen by the documented order, walked one candidate at
    /// a time: with both daemons up the system one is pinned, and the per-user
    /// one is never dialled.
    #[test]
    fn pin_follows_the_dial_order_system_first() {
        let (system, user) = paths();
        let order = vec![system.clone(), user.clone()];
        let fake = Fake::new(&[(&system, "up"), (&user, "up")]);
        let pin = Pin::default();
        assert!(pinned_exchange(&pin, &order, &|p| fake.dial(p)).is_ok());
        assert_eq!(fake.take(), vec![system.clone()]);
        assert_eq!(pin.current(), Some(system.clone()));
        // System not running: the per-user daemon, only after system was tried.
        let fake = Fake::new(&[(&user, "up")]);
        let pin = Pin::default();
        assert!(pinned_exchange(&pin, &order, &|p| fake.dial(p)).is_ok());
        assert_eq!(fake.take(), vec![system, user.clone()]);
        assert_eq!(pin.current(), Some(user));
    }

    /// (b) When the pinned daemon stops answering (not found / refused), the
    /// order is walked again from its start, system socket first.
    #[test]
    fn a_pinned_daemon_that_stops_answering_re_resolves_from_the_start() {
        let (system, user) = paths();
        let order = vec![system.clone(), user.clone()];
        let fake = Fake::new(&[(&user, "up")]);
        let pin = Pin::default();
        assert!(pinned_exchange(&pin, &order, &|p| fake.dial(p)).is_ok());
        assert_eq!(pin.current(), Some(user.clone()));
        fake.take();
        // The per-user daemon goes away; a system daemon is up now.
        fake.set(&user, "down");
        fake.set(&system, "up");
        assert!(pinned_exchange(&pin, &order, &|p| fake.dial(p)).is_ok());
        assert_eq!(fake.take(), vec![user.clone(), system.clone()]);
        assert_eq!(pin.current(), Some(system.clone()));
        // Pinned system goes away, per-user is back: walk again from system.
        fake.set(&system, "down");
        fake.set(&user, "up");
        assert!(pinned_exchange(&pin, &order, &|p| fake.dial(p)).is_ok());
        assert_eq!(fake.take(), vec![system.clone(), system, user.clone()]);
        assert_eq!(pin.current(), Some(user));
    }

    /// (c) Permission denied, busy, or timeout on an earlier candidate is the
    /// answer: reported as is, the later candidate is not dialled, nothing is
    /// pinned. The same errors on the pinned daemon are reported and keep the
    /// pin (a daemon is there).
    #[test]
    fn real_errors_on_an_earlier_candidate_are_reported_not_skipped() {
        let (system, user) = paths();
        let order = vec![system.clone(), user.clone()];
        for (outcome, code) in [
            ("forbidden", "daemon_forbidden"),
            ("busy", "daemon_busy"),
            ("timeout", "daemon_timeout"),
        ] {
            let fake = Fake::new(&[(&system, outcome), (&user, "up")]);
            let pin = Pin::default();
            let err = pinned_exchange(&pin, &order, &|p| fake.dial(p)).err();
            assert_eq!(err.as_ref().map(DialError::code), Some(code), "{outcome}");
            assert_eq!(fake.take(), vec![system.clone()], "{outcome}");
            assert_eq!(pin.current(), None, "{outcome}");

            let fake = Fake::new(&[(&user, "up")]);
            let pin = Pin::default();
            assert!(pinned_exchange(&pin, &order, &|p| fake.dial(p)).is_ok());
            fake.take();
            fake.set(&user, outcome);
            fake.set(&system, "up");
            let err = pinned_exchange(&pin, &order, &|p| fake.dial(p)).err();
            assert_eq!(
                err.as_ref().map(DialError::code),
                Some(code),
                "pinned {outcome}"
            );
            assert_eq!(fake.take(), vec![user.clone()], "pinned {outcome}");
            assert_eq!(pin.current(), Some(user.clone()), "pinned {outcome}");
        }
    }

    /// Test-bot #144: Markdown export and the timeline said "session not found"
    /// with nothing in the user's daemon log. A window keeps talking to the
    /// daemon that first answered when another daemon's socket comes up.
    #[test]
    fn the_answering_daemon_stays_pinned_until_it_stops_answering() {
        let system = PathBuf::from("/run/agentwatch/api.sock");
        let user = PathBuf::from("/run/user/1000/agentwatch/api.sock");
        let order = vec![system.clone(), user.clone()];
        let up: RefCell<HashSet<PathBuf>> = RefCell::new(HashSet::from([user.clone()]));
        let hits: RefCell<Vec<PathBuf>> = RefCell::new(Vec::new());
        let dial = |path: &Path| -> Result<Response, DialError> {
            if up.borrow().contains(path) {
                hits.borrow_mut().push(path.to_path_buf());
                Ok(Response {
                    status: 200,
                    headers: Vec::new(),
                    body: Vec::new(),
                })
            } else {
                Err(DialError::Unreachable(path.display().to_string()))
            }
        };
        let pin = Pin::default();
        assert!(pinned_exchange(&pin, &order, &dial).is_ok());
        assert_eq!(pin.current(), Some(user.clone()));
        // Another daemon's system socket comes up: still the user's daemon.
        up.borrow_mut().insert(system.clone());
        assert!(pinned_exchange(&pin, &order, &dial).is_ok());
        assert!(pinned_exchange(&pin, &order, &dial).is_ok());
        assert_eq!(
            hits.borrow().as_slice(),
            [user.clone(), user.clone(), user.clone()]
        );
        // The user's daemon stops: the order is walked again.
        up.borrow_mut().remove(&user);
        assert!(pinned_exchange(&pin, &order, &dial).is_ok());
        assert_eq!(pin.current(), Some(system.clone()));
        // Nothing answers: unreachable, nothing pinned.
        up.borrow_mut().clear();
        assert!(matches!(
            pinned_exchange(&pin, &order, &dial),
            Err(DialError::Unreachable(_))
        ));
        assert_eq!(pin.current(), None);
    }

    #[test]
    fn only_api_and_health_pass() {
        assert!(check("GET", "/health", "").is_ok());
        assert!(check("get", "/api/v1/sessions?limit=5", "").is_ok());
        assert!(check("GET", "/", "").is_err());
        assert!(check("GET", "/index.html", "").is_err());
        assert!(check("GET", "/api/v1/../x", "").is_err());
        assert!(check("GET", "/api/v1/x\r\nEvil: 1", "").is_err());
        assert!(check("CONNECT", "/api/v1/x", "").is_err());
        assert!(check("POST", "/api/v1/x", &"a".repeat(64 * 1024 + 1)).is_err());
        assert_eq!(check("GET", "/", "").unwrap_err().code, "refused");
    }

    #[test]
    fn request_has_no_authorization() {
        let text = String::from_utf8(encode("post", "/api/v1/sessions", "{}")).expect("utf8");
        assert!(
            text.starts_with("POST /api/v1/sessions HTTP/1.1\r\n"),
            "{text}"
        );
        assert!(text.contains("Content-Length: 2\r\n"), "{text}");
        assert!(
            !text.to_ascii_lowercase().contains("authorization"),
            "{text}"
        );
        assert!(text.ends_with("\r\n\r\n{}"), "{text}");
    }

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(&[0x50, 0x4b, 0x03, 0x04, 0xff, 0x00]), "UEsDBP8A");
    }

    #[test]
    fn env_override_and_default() {
        let env = |key: &str| (key == aw_channel::AW_SOCKET).then(|| "/tmp/a.sock".to_owned());
        assert_eq!(channel_path(&env), std::path::PathBuf::from("/tmp/a.sock"));
        assert!(!channel_path(&|_| None).as_os_str().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn binary_body_survives_a_real_socket_and_missing_is_unreachable() {
        use std::io::{Read, Write};
        let dir = aw_channel::short_temp_dir("desktop");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("api.sock");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).expect("read");
            let mut out =
                b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: 4\r\n\r\n"
                    .to_vec();
            out.extend_from_slice(&[0x50, 0x4b, 0xff, 0x00]);
            stream.write_all(&out).expect("write");
        });
        let reply = super::exchange(&path, "GET", "/api/v1/export", "").expect("exchange");
        server.join().expect("join");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body_base64, base64(&[0x50, 0x4b, 0xff, 0x00]));
        assert_eq!(
            reply.headers.get("content-type").map(String::as_str),
            Some("application/zip")
        );
        let missing = super::exchange(&dir.join("nope.sock"), "GET", "/health", "").unwrap_err();
        assert_eq!(missing.code, "daemon_unreachable");
        assert_eq!(missing.message, "AgentWatch 服务没有运行。");
        assert!(missing.detail.contains("nope.sock"), "{missing:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The window's Retry: one request with the system socket stale, then
    /// the same request again after a daemon came up on the per-user path.
    #[cfg(unix)]
    #[test]
    fn retry_falls_back_from_a_stale_system_socket_to_the_user_socket() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        let dir = aw_channel::short_temp_dir("retry");
        let system = dir.join("system.sock");
        drop(UnixListener::bind(&system).unwrap()); // stale socket file
        let (sys, run) = (system.display().to_string(), dir.display().to_string());
        let env = move |key: &str| match key {
            "AW_SYSTEM_SOCKET" => Some(sys.clone()),
            "XDG_RUNTIME_DIR" | "HOME" => Some(run.clone()),
            _ => None,
        };
        let path = channel_path(&env);
        assert_eq!(
            path, system,
            "the stale system socket exists, so it is resolved first"
        );
        let first = super::exchange_in(&path, "GET", "/health", "", &env).unwrap_err();
        assert_eq!(first.code, "daemon_unreachable");

        // The per-user path for this OS (XDG on Linux, Application Support on macOS).
        let user = aw_channel::user_path(&env).expect("per-user path");
        std::fs::create_dir_all(user.parent().unwrap()).unwrap();
        let listener = UnixListener::bind(&user).unwrap();
        let server = std::thread::spawn(move || loop {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 512];
            if s.read(&mut buf).unwrap_or(0) == 0 {
                continue; // the resolve probe
            }
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap();
            return;
        });
        let path = channel_path(&env);
        assert_eq!(path, user, "Retry re-resolves to the live per-user socket");
        let reply = super::exchange_in(&path, "GET", "/health", "", &env).unwrap();
        server.join().unwrap();
        assert_eq!(reply.status, 200);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
