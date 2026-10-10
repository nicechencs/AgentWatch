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
    exchange_in(path, method, target, body, &|key| std::env::var(key).ok())
}

/// [`exchange`] with an explicit environment. A default `path` is dialled in
/// the documented order (system socket, then per-user); a stale system socket
/// falls through. Each call re-runs the lookup, so the page's Retry finds a
/// daemon that came up meanwhile.
///
/// # Errors
///
/// See [`Failure`].
pub fn exchange_in(
    path: &Path,
    method: &str,
    target: &str,
    body: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Reply, Failure> {
    check(method, target, body)?;
    let order = aw_channel::dial_order(path, env);
    let (_, response) = aw_channel::exchange_first(&order, &encode(method, target, body), TIMEOUT)?;
    if response
        .header("content-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("gzip"))
    {
        // The daemon gzips only when asked; this client never asks.
        return Err(Failure::broken("unexpected gzip body"));
    }
    Ok(reply_of(response))
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
        let dir = std::env::temp_dir().join(format!("aw-desktop-{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!("aw-desktop-retry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
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

        let user = dir.join("agentwatch").join("api.sock");
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
