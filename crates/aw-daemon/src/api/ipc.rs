//! Internal channel: the CLI and desktop-app transport (api-and-cli §1, ADR-0005).
//!
//! Linux and macOS listen on a Unix domain socket. The bytes on the socket are
//! the same HTTP/1.1 request and response the loopback listener speaks, and
//! they reach the same routes through [`super::routes::dispatch_peer`]. The
//! difference is the credential: here the caller is the socket peer, not a
//! bearer token, and there is no `Host` check because nothing on the network
//! can reach a filesystem socket.
//!
//! Peer identity:
//! - Linux: `SO_PEERCRED` through `rustix` (no `unsafe` in this crate). uid 0
//!   is an administrator.
//! - macOS: `LOCAL_PEERCRED` is not exposed by a safe API this crate links.
//!   The socket mode (0660) is the only gate, and the caller is recorded as
//!   [`UNVERIFIED_PEER`], never as an administrator.
//! - Windows: named pipe `\\.\pipe\agentwatch-api` (tokio). The pipe keeps the
//!   default DACL, so only LocalSystem, Administrators, and the daemon's own
//!   account can open it for writing; a client is recorded as an
//!   administrator. The `AgentWatch Users` DACL and the client SID
//!   (`GetNamedPipeClientProcessId`) are not applied yet, so an ordinary
//!   Windows user cannot open the pipe.
//!
//! The socket path comes from [`AW_SOCKET`] when set (tests and unprivileged
//! development runs), otherwise the documented platform path. A stale socket
//! file left by a crashed daemon is removed; a live one is `AddrInUse`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::routes::ApiState;

/// Environment variable that overrides the socket path for both `agentwatchd`
/// and `aw`. Empty is the same as unset.
pub const AW_SOCKET: &str = "AW_SOCKET";

/// Linux socket (api-and-cli §1).
pub const LINUX_SOCKET: &str = "/run/agentwatch/api.sock";

/// macOS socket (api-and-cli §1).
pub const MACOS_SOCKET: &str = "/var/run/agentwatch/api.sock";

/// Windows named pipe (api-and-cli §1).
pub const WINDOWS_PIPE: &str = r"\\.\pipe\agentwatch-api";

/// `user_id` given to a peer whose uid could not be read. Not an administrator.
pub const UNVERIFIED_PEER: &str = "unverified-peer";

/// Socket mode. Owner and the `agentwatch` group may connect.
pub const SOCKET_MODE: u32 = 0o660;

/// Where the daemon listens: [`AW_SOCKET`] when set, else the platform path.
/// `None` on a platform with no Unix socket channel.
#[must_use]
pub fn socket_path() -> Option<PathBuf> {
    socket_path_from(std::env::var(AW_SOCKET).ok())
}

fn socket_path_from(env: Option<String>) -> Option<PathBuf> {
    if let Some(value) = env.filter(|value| !value.trim().is_empty()) {
        return Some(PathBuf::from(value.trim()));
    }
    if cfg!(target_os = "linux") {
        Some(PathBuf::from(LINUX_SOCKET))
    } else if cfg!(target_os = "macos") {
        Some(PathBuf::from(MACOS_SOCKET))
    } else if cfg!(windows) {
        Some(PathBuf::from(WINDOWS_PIPE))
    } else {
        None
    }
}

/// Shared API state. The loopback HTTP listener holds the same handle, so a
/// ticket issued here can be redeemed there.
pub type SharedState = Arc<Mutex<ApiState>>;

#[cfg(unix)]
pub use unix::IpcServer;

#[cfg(unix)]
mod unix {
    use std::fs;
    use std::io::{self, Read};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use super::super::auth::Caller;
    use super::super::http::{parse_request, write_response};
    use super::super::routes::{dispatch_peer, error_response};
    use super::{SharedState, SOCKET_MODE, UNVERIFIED_PEER};

    const IO_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_REQUEST: usize = 80 * 1024;

    /// A running socket listener. Dropping it stops the loop and removes the file.
    pub struct IpcServer {
        /// Socket path actually bound.
        pub path: PathBuf,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl IpcServer {
        /// Bind `path`, set mode 0660, and serve `state` until shutdown.
        ///
        /// # Errors
        ///
        /// Parent directory creation, a live daemon already on `path`
        /// (`AddrInUse`), bind, or chmod failure.
        pub fn bind(path: &Path, state: SharedState) -> io::Result<Self> {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            if path.exists() {
                if UnixStream::connect(path).is_ok() {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "another daemon is answering on the socket",
                    ));
                }
                fs::remove_file(path)?;
            }
            let listener = UnixListener::bind(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(SOCKET_MODE))?;
            listener.set_nonblocking(true)?;
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            let thread = thread::Builder::new()
                .name("aw-ipc".to_owned())
                .spawn(move || accept_loop(&listener, &state, &flag))?;
            Ok(Self {
                path: path.to_path_buf(),
                stop,
                thread: Some(thread),
            })
        }

        /// Stop the accept loop, join it, and remove the socket file.
        pub fn shutdown(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    impl Drop for IpcServer {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    fn accept_loop(listener: &UnixListener, state: &SharedState, stop: &AtomicBool) {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let state = Arc::clone(state);
                    let spawned = thread::Builder::new()
                        .name("aw-ipc-conn".to_owned())
                        .spawn(move || {
                            if let Err(err) = serve(stream, &state) {
                                tracing::debug!(target: "aw_daemon::ipc", error = %err, "connection closed");
                            }
                        });
                    if spawned.is_err() {
                        tracing::warn!(target: "aw_daemon::ipc", "connection thread not started");
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(err) => {
                    tracing::warn!(target: "aw_daemon::ipc", error = %err, "accept failed");
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    /// The peer as an API caller. uid 0 is an administrator.
    pub(super) fn peer_caller(stream: &UnixStream) -> Caller {
        match peer_uid(stream) {
            Some(uid) => Caller {
                user_id: uid.to_string(),
                admin: uid == 0,
            },
            None => Caller {
                user_id: UNVERIFIED_PEER.to_owned(),
                admin: false,
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn peer_uid(stream: &UnixStream) -> Option<u32> {
        rustix::net::sockopt::socket_peercred(stream)
            .ok()
            .map(|cred| cred.uid.as_raw())
    }

    #[cfg(not(target_os = "linux"))]
    fn peer_uid(_stream: &UnixStream) -> Option<u32> {
        None
    }

    fn serve(mut stream: UnixStream, state: &SharedState) -> io::Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let caller = peer_caller(&stream);
        let mut buf = vec![0_u8; 8 * 1024];
        let mut collected = Vec::new();
        // listen_port 0: the peer path never checks `Host`.
        let request = loop {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                match parse_request(&collected, 0) {
                    Some(req) => break req,
                    None => return Ok(()),
                }
            }
            collected.extend_from_slice(&buf[..n]);
            if collected.len() > MAX_REQUEST {
                let response =
                    error_response(413, "payload_too_large", "request body exceeds 64 KiB");
                return write_response(&mut stream, &response);
            }
            if let Some(req) = parse_request(&collected, 0) {
                break req;
            }
        };
        let response = {
            let mut guard = match state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            dispatch_peer(&mut guard, &request, &caller)
        };
        let route = super::super::http::log_route(&request.path);
        tracing::debug!(
            target: "aw_daemon::ipc",
            method = %request.method,
            route = %route,
            status = response.status,
            admin = caller.admin,
            "request"
        );
        write_response(&mut stream, &response)
    }
}

#[cfg(windows)]
mod pipe {
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    use super::super::auth::Caller;
    use super::super::http::{parse_request, response_bytes};
    use super::super::routes::{dispatch_peer, error_response};
    use super::SharedState;

    const MAX_REQUEST: usize = 80 * 1024;

    /// `user_id` for a pipe client. The pipe keeps the default DACL, which
    /// lets only LocalSystem, Administrators, and the daemon's own account
    /// open it for writing, so a connected client is an administrator. The
    /// client SID is not read yet.
    pub const PIPE_ADMIN: &str = "pipe-admin";

    /// A running named-pipe listener.
    pub struct IpcServer {
        /// Pipe path actually created.
        pub path: PathBuf,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl IpcServer {
        /// Create the first pipe instance on `path` and serve `state`.
        ///
        /// # Errors
        ///
        /// Runtime creation or pipe creation failure (another daemon holding
        /// the first instance is `PermissionDenied` / `AccessDenied`).
        pub fn bind(path: &Path, state: SharedState) -> io::Result<Self> {
            let name = path.as_os_str().to_owned();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let first = runtime
                .block_on(async { ServerOptions::new().first_pipe_instance(true).create(&name) })?;
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            let thread = thread::Builder::new()
                .name("aw-ipc".to_owned())
                .spawn(move || runtime.block_on(accept_loop(name, first, state, flag)))?;
            Ok(Self {
                path: path.to_path_buf(),
                stop,
                thread: Some(thread),
            })
        }

        /// Stop the accept loop and join it.
        pub fn shutdown(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    impl Drop for IpcServer {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    async fn accept_loop(
        name: std::ffi::OsString,
        mut server: NamedPipeServer,
        state: SharedState,
        stop: Arc<AtomicBool>,
    ) {
        while !stop.load(Ordering::Relaxed) {
            let connected = tokio::select! {
                result = server.connect() => result,
                () = tokio::time::sleep(Duration::from_millis(100)) => continue,
            };
            if let Err(err) = connected {
                tracing::warn!(target: "aw_daemon::ipc", error = %err, "pipe connect failed");
                continue;
            }
            let next = match ServerOptions::new().create(&name) {
                Ok(next) => next,
                Err(err) => {
                    tracing::warn!(target: "aw_daemon::ipc", error = %err, "next pipe instance not created");
                    return;
                }
            };
            let client = std::mem::replace(&mut server, next);
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                if let Err(err) = serve(client, &state).await {
                    tracing::debug!(target: "aw_daemon::ipc", error = %err, "pipe connection closed");
                }
            });
        }
    }

    async fn serve(pipe: NamedPipeServer, state: &SharedState) -> io::Result<()> {
        let caller = Caller {
            user_id: PIPE_ADMIN.to_owned(),
            admin: true,
        };
        let mut collected = Vec::new();
        let mut buf = vec![0_u8; 8 * 1024];
        let request = loop {
            pipe.readable().await?;
            match pipe.try_read(&mut buf) {
                Ok(0) => match parse_request(&collected, 0) {
                    Some(req) => break req,
                    None => return Ok(()),
                },
                Ok(n) => {
                    collected.extend_from_slice(&buf[..n]);
                    if collected.len() > MAX_REQUEST {
                        let response =
                            error_response(413, "payload_too_large", "request body exceeds 64 KiB");
                        return write_all(&pipe, &response_bytes(&response)).await;
                    }
                    if let Some(req) = parse_request(&collected, 0) {
                        break req;
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Err(err),
            }
        };
        let response = {
            let mut guard = match state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            dispatch_peer(&mut guard, &request, &caller)
        };
        write_all(&pipe, &response_bytes(&response)).await?;
        pipe.disconnect()
    }

    async fn write_all(pipe: &NamedPipeServer, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            pipe.writable().await?;
            match pipe.try_write(bytes) {
                Ok(n) => bytes = &bytes[n..],
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use pipe::IpcServer;

#[cfg(not(any(unix, windows)))]
pub use other::IpcServer;

#[cfg(not(any(unix, windows)))]
mod other {
    use std::io;
    use std::path::{Path, PathBuf};

    use super::SharedState;

    /// No internal channel on this platform. Never constructed.
    pub struct IpcServer {
        /// Never set.
        pub path: PathBuf,
    }

    impl IpcServer {
        /// Always `Unsupported` on this platform.
        ///
        /// # Errors
        ///
        /// Always.
        pub fn bind(_path: &Path, _state: SharedState) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no internal channel on this platform",
            ))
        }

        /// No-op.
        pub fn shutdown(&mut self) {}
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use super::super::routes::{dispatch, ApiState, HttpRequest};
    use super::{socket_path_from, IpcServer, SOCKET_MODE};

    fn temp_socket(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aw-ipc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("api.sock")
    }

    fn exchange(path: &PathBuf, raw: &str) -> (u16, serde_json::Value) {
        let mut stream = UnixStream::connect(path).expect("connect");
        stream.write_all(raw.as_bytes()).expect("write");
        let mut out = Vec::new();
        stream.read_to_end(&mut out).expect("read");
        let text = String::from_utf8(out).expect("utf8");
        let (head, body) = text.split_once("\r\n\r\n").expect("head");
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .expect("status")
            .parse()
            .expect("number");
        let json = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[test]
    fn env_override_wins_and_blank_is_unset() {
        assert_eq!(
            socket_path_from(Some("/tmp/x.sock".to_owned())),
            Some(PathBuf::from("/tmp/x.sock"))
        );
        let default = socket_path_from(Some("  ".to_owned()));
        if cfg!(target_os = "linux") {
            assert_eq!(default, Some(PathBuf::from(super::LINUX_SOCKET)));
        }
    }

    #[test]
    fn socket_serves_health_and_mode_is_0660() {
        let path = temp_socket("health");
        let state = Arc::new(Mutex::new(ApiState::default()));
        let mut server = IpcServer::bind(&path, state).expect("bind");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, SOCKET_MODE);
        let (status, body) = exchange(&path, "GET /health HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(status, 200);
        assert_eq!(body["status"], "ok");
        server.shutdown();
        assert!(!path.exists(), "socket file removed on shutdown");
    }

    /// The bug this channel fixes: `aw ui` had no way to get a ticket, because
    /// HTTP refuses to mint one and no socket existed. A ticket from the socket
    /// must be redeemable on the loopback HTTP routes of the same state.
    #[test]
    fn ticket_from_socket_redeems_over_http_state() {
        let path = temp_socket("ticket");
        let state = Arc::new(Mutex::new(ApiState::default()));
        let _server = IpcServer::bind(&path, Arc::clone(&state)).expect("bind");
        let (status, body) = exchange(
            &path,
            "POST /api/v1/auth/ui-ticket HTTP/1.1\r\nAuthorization: Bearer forged\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(status, 200, "{body}");
        let ticket = body["ticket"].as_str().expect("ticket").to_owned();
        assert!(!ticket.is_empty());

        let mut guard = state.lock().expect("lock");
        let mut req = HttpRequest {
            method: "POST".to_owned(),
            path: "/api/v1/auth/ui-token".to_owned(),
            body: serde_json::to_vec(&serde_json::json!({ "ticket": ticket })).expect("json"),
            ..HttpRequest::default()
        };
        req.headers
            .insert("host".to_owned(), format!("127.0.0.1:{}", req.listen_port));
        req.headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        let reply = dispatch(&mut guard, &req);
        assert_eq!(reply.status, 200);
    }

    #[test]
    fn peer_is_the_current_uid_on_linux() {
        let path = temp_socket("peer");
        let state = Arc::new(Mutex::new(ApiState::default()));
        let _server = IpcServer::bind(&path, state).expect("bind");
        let (status, body) = exchange(&path, "GET /api/v1/me HTTP/1.1\r\n\r\n");
        assert_eq!(status, 200, "{body}");
        if cfg!(target_os = "linux") {
            let uid = std::fs::metadata("/proc/self")
                .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
                .expect("uid");
            assert_eq!(body["user_id"], uid.to_string());
            assert_eq!(body["admin"], uid == 0);
        } else {
            assert_eq!(body["user_id"], super::UNVERIFIED_PEER);
            assert_eq!(body["admin"], false);
        }
    }

    #[test]
    fn live_socket_is_not_stolen_and_assets_are_not_served() {
        let path = temp_socket("busy");
        let state = Arc::new(Mutex::new(ApiState::default()));
        let _server = IpcServer::bind(&path, Arc::clone(&state)).expect("bind");
        let second = IpcServer::bind(&path, state);
        assert!(second.is_err());
        let (status, _) = exchange(&path, "GET / HTTP/1.1\r\n\r\n");
        assert_eq!(status, 404);
    }
}
