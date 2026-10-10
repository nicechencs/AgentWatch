//! Internal channel client (api-and-cli §1, ADR-0005).
//!
//! The app runs unprivileged and talks to `agentwatchd` over the Unix socket
//! (Linux/macOS) or the named pipe (Windows). The bytes are one HTTP/1.1
//! request and one response, the same shape the loopback listener speaks. No
//! `Authorization` is sent: the daemon identifies the peer by its OS
//! credential. Nothing here opens a TCP port.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

/// Same override the daemon and `aw` read.
pub const AW_SOCKET: &str = "AW_SOCKET";

const LINUX_SOCKET: &str = "/run/agentwatch/api.sock";
const MACOS_SOCKET: &str = "/var/run/agentwatch/api.sock";
const WINDOWS_PIPE: &str = r"\\.\pipe\agentwatch-api";

const TIMEOUT: Duration = Duration::from_secs(10);

/// Request body cap, matching the daemon's 64 KiB.
pub const MAX_BODY: usize = 64 * 1024;

/// One reply from the daemon.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// Body text (JSON for the API).
    pub body: String,
}

/// Why a request did not get a reply. Shown to the UI as the error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// The path is not `/health` or under `/api/v1/`, or the method is odd.
    Refused(String),
    /// Nothing answers on the socket or pipe: the service is not running.
    Unreachable(String),
    /// The exchange broke after connecting.
    Broken(String),
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(detail) => write!(f, "refused: {detail}"),
            Self::Unreachable(detail) => write!(f, "daemon_unreachable: {detail}"),
            Self::Broken(detail) => write!(f, "channel_broken: {detail}"),
        }
    }
}

/// Socket or pipe path: [`AW_SOCKET`] when set, else the platform default.
#[must_use]
pub fn channel_path(env: Option<String>) -> PathBuf {
    if let Some(value) = env.filter(|value| !value.trim().is_empty()) {
        return PathBuf::from(value.trim());
    }
    if cfg!(windows) {
        PathBuf::from(WINDOWS_PIPE)
    } else if cfg!(target_os = "macos") {
        PathBuf::from(MACOS_SOCKET)
    } else {
        PathBuf::from(LINUX_SOCKET)
    }
}

/// Only the API and `/health` may be requested. `target` is path plus optional query.
///
/// # Errors
///
/// [`ChannelError::Refused`] for any other method, path, or an oversize body.
pub fn check(method: &str, target: &str, body: &str) -> Result<(), ChannelError> {
    let upper = method.to_ascii_uppercase();
    if !matches!(upper.as_str(), "GET" | "POST" | "PUT" | "PATCH" | "DELETE") {
        return Err(ChannelError::Refused(format!("method {upper}")));
    }
    let path = target.split('?').next().unwrap_or("");
    let allowed = path == "/health" || path.starts_with("/api/v1/");
    if !allowed || target.contains(['\r', '\n', ' ']) || path.contains("..") {
        return Err(ChannelError::Refused("path".to_owned()));
    }
    if body.len() > MAX_BODY {
        return Err(ChannelError::Refused("body exceeds 64 KiB".to_owned()));
    }
    Ok(())
}

/// Request bytes. No `Authorization`.
#[must_use]
pub fn encode(method: &str, target: &str, body: &str) -> Vec<u8> {
    let mut head = format!(
        "{} {target} HTTP/1.1\r\nHost: agentwatch.local\r\nConnection: close\r\nAccept: application/json\r\nContent-Length: {}\r\n",
        method.to_ascii_uppercase(),
        body.len()
    );
    if !body.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

/// Parse one HTTP/1.1 response (the daemon closes after it).
///
/// # Errors
///
/// [`ChannelError::Broken`] when there is no status line or header terminator.
pub fn parse(bytes: &[u8]) -> Result<Reply, ChannelError> {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| ChannelError::Broken("no header terminator".to_owned()))?;
    let head = String::from_utf8_lossy(&bytes[..split]);
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| ChannelError::Broken("no status".to_owned()))?;
    let gzipped = head.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("content-encoding:") && lower.contains("gzip")
    });
    if gzipped {
        // The daemon gzips only when asked; this client never asks.
        return Err(ChannelError::Broken("unexpected gzip body".to_owned()));
    }
    Ok(Reply {
        status,
        body: String::from_utf8_lossy(&bytes[split + 4..]).into_owned(),
    })
}

/// Send one request on the channel and wait for the reply.
///
/// # Errors
///
/// See [`ChannelError`].
pub fn exchange(
    path: &std::path::Path,
    method: &str,
    target: &str,
    body: &str,
) -> Result<Reply, ChannelError> {
    check(method, target, body)?;
    let bytes = encode(method, target, body);
    let raw = dial_and_send(path, &bytes)?;
    parse(&raw)
}

fn roundtrip<S: Read + Write>(stream: &mut S, bytes: &[u8]) -> Result<Vec<u8>, ChannelError> {
    stream
        .write_all(bytes)
        .map_err(|err| ChannelError::Broken(format!("write: {}", err.kind())))?;
    let mut out = Vec::new();
    stream
        .read_to_end(&mut out)
        .map_err(|err| ChannelError::Broken(format!("read: {}", err.kind())))?;
    Ok(out)
}

#[cfg(unix)]
fn dial_and_send(path: &std::path::Path, bytes: &[u8]) -> Result<Vec<u8>, ChannelError> {
    let mut stream = std::os::unix::net::UnixStream::connect(path)
        .map_err(|err| ChannelError::Unreachable(format!("{}: {}", path.display(), err.kind())))?;
    let _ = stream.set_read_timeout(Some(TIMEOUT));
    let _ = stream.set_write_timeout(Some(TIMEOUT));
    roundtrip(&mut stream, bytes)
}

#[cfg(not(unix))]
fn dial_and_send(path: &std::path::Path, bytes: &[u8]) -> Result<Vec<u8>, ChannelError> {
    // A named pipe opens like a file.
    let _ = TIMEOUT;
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|err| ChannelError::Unreachable(format!("{}: {}", path.display(), err.kind())))?;
    roundtrip(&mut pipe, bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{channel_path, check, encode, parse, ChannelError};

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
    fn parse_status_and_body() {
        let reply = parse(b"HTTP/1.1 501 Not Implemented\r\nx: y\r\n\r\n{\"a\":1}").expect("parse");
        assert_eq!(reply.status, 501);
        assert_eq!(reply.body, "{\"a\":1}");
        assert!(matches!(parse(b"garbage"), Err(ChannelError::Broken(_))));
    }

    #[test]
    fn env_override_and_default() {
        assert_eq!(
            channel_path(Some("/tmp/a.sock".to_owned())),
            std::path::PathBuf::from("/tmp/a.sock")
        );
        assert!(!channel_path(None).as_os_str().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn exchange_over_a_real_socket() {
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
            stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n{\"status\":\"ok\"}")
                .expect("write");
        });
        let reply = super::exchange(&path, "GET", "/health", "").expect("exchange");
        server.join().expect("join");
        assert_eq!(reply.status, 200);
        let missing = super::exchange(&dir.join("nope.sock"), "GET", "/health", "");
        assert!(matches!(missing, Err(ChannelError::Unreachable(_))));
    }
}
