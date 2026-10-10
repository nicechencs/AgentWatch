//! Internal channel client shared by `aw` and the desktop app (api-and-cli §1).
//!
//! One place decides three things both clients and the daemon must agree on:
//!
//! 1. **Where the channel is.** [`AW_SOCKET`] when set; otherwise the system
//!    path (root daemon) and then the per-user path (unprivileged daemon).
//!    The daemon binds the system path and falls back to the per-user path
//!    when it may not create the system one; clients pick the first candidate
//!    that exists, in the same order ([`resolve`]).
//!    - Linux: `/run/agentwatch/api.sock`, then
//!      `$XDG_RUNTIME_DIR/agentwatch/api.sock`, else
//!      `$HOME/.local/state/agentwatch/api.sock`.
//!    - macOS: `/var/run/agentwatch/api.sock`, then
//!      `$HOME/Library/Application Support/AgentWatch/api.sock`.
//!    - Windows: `\\.\pipe\agentwatch-api` only (the pipe namespace is not
//!      per-user; the pipe DACL admits ordinary users).
//! 2. **What a failure means** ([`DialError`]). Only "no such socket/pipe" and
//!    "connection refused" mean the daemon is not running. Permission denied
//!    is its own class. A busy pipe (all instances in use) is retried briefly.
//! 3. **The bytes.** One HTTP/1.1 request without `Authorization` (the OS
//!    credential is the identity), one response, connection closed. Bodies
//!    are bytes, never re-decoded, so a zip export survives.
//!
//! std only, no `unsafe`.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Override for tests and development runs. Same name in daemon, `aw`, app.
pub const AW_SOCKET: &str = "AW_SOCKET";
/// Linux system socket.
pub const LINUX_SOCKET: &str = "/run/agentwatch/api.sock";
/// macOS system socket.
pub const MACOS_SOCKET: &str = "/var/run/agentwatch/api.sock";
/// Windows pipe.
pub const WINDOWS_PIPE: &str = r"\\.\pipe\agentwatch-api";
/// Socket file name inside the per-user directory.
pub const SOCKET_FILE: &str = "api.sock";

/// Default exchange timeout.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// How long a busy pipe is retried.
pub const BUSY_RETRY: Duration = Duration::from_secs(2);

/// `ERROR_PIPE_BUSY`: every pipe instance is connected.
const ERROR_PIPE_BUSY: i32 = 231;

/// System path for this OS, or `None` where there is no channel.
#[must_use]
pub fn system_path() -> Option<PathBuf> {
    if cfg!(windows) {
        Some(PathBuf::from(WINDOWS_PIPE))
    } else if cfg!(target_os = "macos") {
        Some(PathBuf::from(MACOS_SOCKET))
    } else if cfg!(unix) {
        Some(PathBuf::from(LINUX_SOCKET))
    } else {
        None
    }
}

/// Per-user socket path from the environment (`env("HOME")` …). `None` on
/// Windows and when neither variable is set.
#[must_use]
pub fn user_path(env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let get = |key: &str| env(key).filter(|v| !v.trim().is_empty());
    if cfg!(windows) {
        return None;
    }
    if cfg!(target_os = "macos") {
        return get("HOME").map(|home| {
            PathBuf::from(home)
                .join("Library/Application Support/AgentWatch")
                .join(SOCKET_FILE)
        });
    }
    if let Some(runtime) = get("XDG_RUNTIME_DIR") {
        return Some(PathBuf::from(runtime).join("agentwatch").join(SOCKET_FILE));
    }
    get("HOME").map(|home| {
        PathBuf::from(home)
            .join(".local/state/agentwatch")
            .join(SOCKET_FILE)
    })
}

/// Candidate paths in order. With [`AW_SOCKET`] set, only that path.
#[must_use]
pub fn candidates(env: &dyn Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    if let Some(value) = env(AW_SOCKET).filter(|v| !v.trim().is_empty()) {
        return vec![PathBuf::from(value.trim())];
    }
    system_path().into_iter().chain(user_path(env)).collect()
}

/// The path a client should dial: the first candidate that exists, else the
/// first candidate (so "not running" names the system path). On Windows the
/// pipe is always the answer.
#[must_use]
pub fn resolve(env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let all = candidates(env);
    if cfg!(windows) {
        return all.into_iter().next();
    }
    all.iter()
        .find(|path| path.exists())
        .cloned()
        .or_else(|| all.into_iter().next())
}

/// [`resolve`] over the process environment.
#[must_use]
pub fn resolve_from_env() -> Option<PathBuf> {
    resolve(&|key| std::env::var(key).ok())
}

/// Why an exchange did not produce a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialError {
    /// No socket/pipe, or connection refused: the daemon is not running.
    Unreachable(String),
    /// The socket or pipe exists but this user may not open it.
    Forbidden(String),
    /// Every pipe instance stayed busy for [`BUSY_RETRY`].
    Busy(String),
    /// No complete response within the timeout.
    Timeout(String),
    /// The exchange broke after connecting, or the response did not parse.
    Broken(String),
}

impl DialError {
    /// Stable machine code. The desktop app returns these to the page.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unreachable(_) => "daemon_unreachable",
            Self::Forbidden(_) => "daemon_forbidden",
            Self::Busy(_) => "daemon_busy",
            Self::Timeout(_) => "daemon_timeout",
            Self::Broken(_) => "channel_broken",
        }
    }

    /// Detail text. Never a credential (there is none on this channel).
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Unreachable(d)
            | Self::Forbidden(d)
            | Self::Busy(d)
            | Self::Timeout(d)
            | Self::Broken(d) => d,
        }
    }

    /// One plain sentence for a person.
    #[must_use]
    pub fn plain(&self) -> String {
        match self {
            Self::Unreachable(d) => format!("AgentWatch service is not running ({d})"),
            Self::Forbidden(d) => format!(
                "AgentWatch service is running, but this account may not connect to it ({d}). Ask an administrator to add you to the agentwatch / AgentWatch Users group"
            ),
            Self::Busy(d) => format!("AgentWatch service is busy, try again ({d})"),
            Self::Timeout(d) => format!("AgentWatch service did not answer in time ({d})"),
            Self::Broken(d) => format!("AgentWatch channel error ({d})"),
        }
    }
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.detail())
    }
}

impl std::error::Error for DialError {}

/// Classify an open/connect error. Pure.
#[must_use]
pub fn classify(err: &io::Error, path: &Path) -> DialError {
    let what = format!("{}: {}", path.display(), err.kind());
    if err.raw_os_error() == Some(ERROR_PIPE_BUSY) && cfg!(windows) {
        return DialError::Busy(what);
    }
    match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => DialError::Unreachable(what),
        io::ErrorKind::PermissionDenied => DialError::Forbidden(what),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => DialError::Timeout(what),
        _ => DialError::Broken(what),
    }
}

/// One parsed response. Header names are lowercased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status.
    pub status: u16,
    /// Headers in order, names lowercased.
    pub headers: Vec<(String, String)>,
    /// Body bytes, unchanged.
    pub body: Vec<u8>,
}

impl Response {
    /// First header named `name` (lowercase).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Request bytes: `target` is path plus optional `?query`. No `Authorization`.
#[must_use]
pub fn encode_request(method: &str, target: &str, accept: &str, body: &[u8]) -> Vec<u8> {
    let mut head = format!(
        "{} {target} HTTP/1.1\r\nHost: agentwatch.local\r\nConnection: close\r\nAccept: {accept}\r\nContent-Length: {}\r\n",
        method.to_ascii_uppercase(),
        body.len()
    );
    if !body.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Parse one HTTP/1.1 response. A `Content-Length` shorter than the bytes read
/// trims the body; a chunked body is decoded.
///
/// # Errors
///
/// [`DialError::Broken`] without a status line or header terminator.
pub fn parse_response(bytes: &[u8]) -> Result<Response, DialError> {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| DialError::Broken("no header terminator".to_owned()))?;
    let head = String::from_utf8_lossy(&bytes[..split]);
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| DialError::Broken("no status".to_owned()))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let mut body = bytes[split + 4..].to_vec();
    let mut response = Response {
        status,
        headers,
        body: Vec::new(),
    };
    if response
        .header("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        body = dechunk(&body)?;
    } else if let Some(len) = response
        .header("content-length")
        .and_then(|v| v.parse::<usize>().ok())
    {
        body.truncate(len);
    }
    response.body = body;
    Ok(response)
}

fn dechunk(mut raw: &[u8]) -> Result<Vec<u8>, DialError> {
    let mut out = Vec::new();
    loop {
        let end = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| DialError::Broken("chunk size".to_owned()))?;
        let size_text = String::from_utf8_lossy(&raw[..end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| DialError::Broken("chunk size".to_owned()))?;
        raw = &raw[end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if raw.len() < size {
            return Err(DialError::Broken("short chunk".to_owned()));
        }
        out.extend_from_slice(&raw[..size]);
        raw = raw.get(size + 2..).unwrap_or(&[]);
    }
}

/// Send `request` on the channel at `path` and read the whole response.
///
/// # Errors
///
/// See [`DialError`].
pub fn exchange(path: &Path, request: &[u8], timeout: Duration) -> Result<Response, DialError> {
    let raw = exchange_raw(path, request, timeout)?;
    parse_response(&raw)
}

/// [`exchange`] without parsing.
///
/// # Errors
///
/// See [`DialError`].
pub fn exchange_raw(path: &Path, request: &[u8], timeout: Duration) -> Result<Vec<u8>, DialError> {
    platform::exchange_raw(path, request, timeout)
}

fn roundtrip<S: Read + Write>(stream: &mut S, bytes: &[u8]) -> Result<Vec<u8>, DialError> {
    stream
        .write_all(bytes)
        .map_err(|err| io_broken("write", &err))?;
    let mut out = Vec::new();
    stream
        .read_to_end(&mut out)
        .map_err(|err| io_broken("read", &err))?;
    Ok(out)
}

fn io_broken(what: &str, err: &io::Error) -> DialError {
    if matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        DialError::Timeout(format!("{what}: {}", err.kind()))
    } else {
        DialError::Broken(format!("{what}: {}", err.kind()))
    }
}

#[cfg(unix)]
mod platform {
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::Duration;

    use super::{classify, roundtrip, DialError};

    pub(super) fn exchange_raw(
        path: &Path,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, DialError> {
        let mut stream = UnixStream::connect(path).map_err(|err| classify(&err, path))?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        roundtrip(&mut stream, request)
    }
}

#[cfg(windows)]
mod platform {
    use std::path::Path;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{classify, roundtrip, DialError, BUSY_RETRY};

    pub(super) fn exchange_raw(
        path: &Path,
        request: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, DialError> {
        let started = Instant::now();
        // A named pipe opens like a file. All instances busy is a short wait,
        // not "not running".
        let mut pipe = loop {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
            {
                Ok(pipe) => break pipe,
                Err(err) => {
                    let class = classify(&err, path);
                    if matches!(class, DialError::Busy(_)) && started.elapsed() < BUSY_RETRY {
                        thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    return Err(class);
                }
            }
        };
        // std pipe handles have no read timeout: run the exchange on a helper
        // thread and stop waiting at the deadline. The daemon also times out
        // its side, so the helper does not outlive the connection for long.
        let bytes = request.to_vec();
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("aw-channel-pipe".to_owned())
            .spawn(move || {
                let _ = tx.send(roundtrip(&mut pipe, &bytes));
            })
            .map_err(|err| DialError::Broken(format!("helper thread: {err}")))?;
        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(_) => Err(DialError::Timeout(format!(
                "{}: no response in {} s",
                path.display(),
                timeout.as_secs()
            ))),
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::path::Path;
    use std::time::Duration;

    use super::DialError;

    pub(super) fn exchange_raw(
        path: &Path,
        _request: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, DialError> {
        Err(DialError::Unreachable(format!(
            "{}: no internal channel on this OS",
            path.display()
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::io;
    use std::path::{Path, PathBuf};

    use super::{candidates, classify, encode_request, parse_response, DialError, AW_SOCKET};
    #[cfg(unix)]
    use super::{resolve, user_path};

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |key| owned.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    }

    #[test]
    fn override_is_the_only_candidate() {
        let env = env_of(&[(AW_SOCKET, " /tmp/x.sock "), ("HOME", "/home/a")]);
        assert_eq!(candidates(&env), vec![PathBuf::from("/tmp/x.sock")]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_order_is_system_then_runtime_dir_then_home() {
        let env = env_of(&[("XDG_RUNTIME_DIR", "/run/user/1000"), ("HOME", "/home/a")]);
        assert_eq!(
            candidates(&env),
            vec![
                PathBuf::from("/run/agentwatch/api.sock"),
                PathBuf::from("/run/user/1000/agentwatch/api.sock"),
            ]
        );
        let env = env_of(&[("HOME", "/home/a")]);
        assert_eq!(
            user_path(&env),
            Some(PathBuf::from("/home/a/.local/state/agentwatch/api.sock"))
        );
        assert_eq!(user_path(&env_of(&[])), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_user_path_is_application_support() {
        let env = env_of(&[("HOME", "/Users/a")]);
        assert_eq!(
            user_path(&env),
            Some(PathBuf::from(
                "/Users/a/Library/Application Support/AgentWatch/api.sock"
            ))
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_prefers_an_existing_user_socket_over_a_missing_system_one() {
        let dir = std::env::temp_dir().join(format!("aw-chan-{}", std::process::id()));
        let sock = dir.join("agentwatch").join("api.sock");
        std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
        std::fs::write(&sock, b"").unwrap();
        let runtime = dir.display().to_string();
        let env = env_of(&[
            ("XDG_RUNTIME_DIR", runtime.as_str()),
            ("HOME", runtime.as_str()),
        ]);
        if !Path::new(super::LINUX_SOCKET).exists() && !Path::new(super::MACOS_SOCKET).exists() {
            let expected = if cfg!(target_os = "macos") {
                user_path(&env).unwrap()
            } else {
                sock.clone()
            };
            if expected.exists() {
                assert_eq!(resolve(&env), Some(expected));
            }
        }
        let empty = env_of(&[]);
        assert!(resolve(&empty).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn errors_are_classified() {
        let p = Path::new("/x");
        let class = |kind| classify(&io::Error::from(kind), p);
        assert!(matches!(
            class(io::ErrorKind::NotFound),
            DialError::Unreachable(_)
        ));
        assert!(matches!(
            class(io::ErrorKind::ConnectionRefused),
            DialError::Unreachable(_)
        ));
        assert!(matches!(
            class(io::ErrorKind::PermissionDenied),
            DialError::Forbidden(_)
        ));
        assert_eq!(
            class(io::ErrorKind::PermissionDenied).code(),
            "daemon_forbidden"
        );
        assert_eq!(class(io::ErrorKind::NotFound).code(), "daemon_unreachable");
        let busy = classify(&io::Error::from_raw_os_error(231), p);
        if cfg!(windows) {
            assert_eq!(busy.code(), "daemon_busy");
        }
    }

    #[test]
    fn body_bytes_survive_and_length_and_chunks_are_honoured() {
        let mut raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\nContent-Length: 4\r\n\r\n"
                .to_vec();
        raw.extend_from_slice(&[0x50, 0x4b, 0xff, 0x00, 0x99]);
        let reply = parse_response(&raw).unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, vec![0x50, 0x4b, 0xff, 0x00]);
        assert_eq!(reply.header("content-type"), Some("application/zip"));
        let chunked =
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
                .unwrap();
        assert_eq!(chunked.body, b"abcde");
        assert!(parse_response(b"nope").is_err());
    }

    #[test]
    fn request_has_no_authorization() {
        let text =
            String::from_utf8(encode_request("post", "/api/v1/x?a=1", "*/*", b"{}")).unwrap();
        assert!(text.starts_with("POST /api/v1/x?a=1 HTTP/1.1\r\n"));
        assert!(!text.to_ascii_lowercase().contains("authorization"));
        assert!(text.ends_with("\r\n\r\n{}"));
    }

    #[cfg(unix)]
    #[test]
    fn exchange_over_a_socket_and_missing_is_unreachable() {
        use std::io::{Read, Write};
        let dir = std::env::temp_dir().join(format!("aw-chan-x-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("api.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 512];
            let _ = s.read(&mut buf).unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\nok").unwrap();
        });
        let reply =
            super::exchange(&path, b"GET /health HTTP/1.1\r\n\r\n", super::TIMEOUT).unwrap();
        server.join().unwrap();
        assert_eq!(reply.body, b"ok");
        let missing = super::exchange(&dir.join("nope"), b"", super::TIMEOUT);
        assert!(matches!(missing, Err(DialError::Unreachable(_))));
        // A socket file nobody listens on: refused, also "not running".
        drop(std::os::unix::net::UnixListener::bind(dir.join("dead")).unwrap());
        let dead = super::exchange(&dir.join("dead"), b"", super::TIMEOUT);
        assert!(matches!(dead, Err(DialError::Unreachable(_))), "{dead:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn permission_denied_is_forbidden_not_unreachable() {
        use std::os::unix::fs::PermissionsExt;
        if nix_like_is_root() {
            return; // root ignores the mode bits
        }
        let dir = std::env::temp_dir().join(format!("aw-chan-p-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("api.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let denied = super::exchange(&path, b"", super::TIMEOUT);
        assert!(matches!(denied, Err(DialError::Forbidden(_))), "{denied:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn nix_like_is_root() -> bool {
        use std::os::unix::fs::MetadataExt;
        // The owner of a fresh temp file is the effective uid.
        let probe = std::env::temp_dir().join(format!("aw-chan-uid-{}", std::process::id()));
        let _ = std::fs::write(&probe, b"");
        let root = std::fs::metadata(&probe)
            .map(|m| m.uid() == 0)
            .unwrap_or(true);
        let _ = std::fs::remove_file(&probe);
        root
    }
}
