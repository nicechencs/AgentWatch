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
//! - Unix peer credentials are read only by `aw-platform`. uid 0 is an
//!   administrator; an unidentified peer is refused with 403 and never given
//!   a placeholder identity.
//! - When a group named [`SOCKET_GROUP`] exists, the socket is
//!   `root:agentwatch 0660`: members connect without root. Without the group
//!   it is 0666: any local account may connect and is identified by uid (an
//!   ordinary user sees only their own sessions; control needs root or the
//!   daemon's uid). A root daemon is therefore always reachable by the
//!   unprivileged desktop app.
//! - A daemon that may not create the system socket (not root) binds the
//!   per-user socket instead (`aw_channel::user_path`); `aw` and the app look
//!   there second.
//! - Windows: named pipe `\\.\pipe\agentwatch-api` (tokio). The pipe carries an
//!   explicit DACL (`aw_collector_windows::pipe`): LocalSystem and
//!   Administrators full control; `AgentWatch Users` when that group exists,
//!   otherwise interactive users, read/write without create-instance. The
//!   client is identified from its process token (SID; elevated or
//!   LocalSystem = administrator). A client that cannot be identified is
//!   refused with 403.
//!
//! Daemon control (`stop`, `logs`) is answered here before the normal routes,
//! see [`super::control`].
//!
//! The socket path comes from [`AW_SOCKET`] when set (tests and unprivileged
//! development runs), otherwise the documented platform path. A stale socket
//! file left by a crashed daemon is removed; a live one is `AddrInUse`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::control::Control;
use super::routes::ApiState;

/// Environment variable that overrides the socket path for `agentwatchd`,
/// `aw`, and the desktop app. Empty is the same as unset.
pub const AW_SOCKET: &str = aw_channel::AW_SOCKET;

/// Linux socket (api-and-cli §1).
pub const LINUX_SOCKET: &str = aw_channel::LINUX_SOCKET;

/// macOS socket (api-and-cli §1).
pub const MACOS_SOCKET: &str = aw_channel::MACOS_SOCKET;

/// Windows named pipe (api-and-cli §1).
pub const WINDOWS_PIPE: &str = aw_channel::WINDOWS_PIPE;

/// Socket mode when the [`SOCKET_GROUP`] group exists: owner and members.
pub const SOCKET_MODE: u32 = 0o660;

/// Socket mode without that group. Any local account may connect; the peer
/// uid is still read on every request, an ordinary user sees only their own
/// sessions, and daemon control needs root or the daemon's own uid. Without
/// this a root daemon's socket (root:root 0660) would shut out the
/// unprivileged desktop app entirely.
pub const OPEN_SOCKET_MODE: u32 = 0o666;

/// Mode for the socket given whether the group was applied. Pure.
#[must_use]
pub fn socket_mode(grouped: bool) -> u32 {
    if grouped {
        SOCKET_MODE
    } else {
        OPEN_SOCKET_MODE
    }
}

/// Where the daemon listens: [`AW_SOCKET`] when set, else the platform path.
/// `None` on a platform with no channel.
#[must_use]
pub fn socket_path() -> Option<PathBuf> {
    socket_path_from(std::env::var(AW_SOCKET).ok(), &|key| {
        std::env::var(key).ok()
    })
}

fn socket_path_from(
    env: Option<String>,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    if let Some(value) = env.filter(|value| !value.trim().is_empty()) {
        return Some(PathBuf::from(value.trim()));
    }
    // `AW_SYSTEM_SOCKET` stands in for the system path in tests only.
    aw_channel::system_path_from(lookup)
}

/// Per-user socket an unprivileged daemon binds when it may not create the
/// system one. `None` with [`AW_SOCKET`] set (that path is final), on
/// Windows, and without `HOME` / `XDG_RUNTIME_DIR`. Clients look here second
/// (aw-channel), so `aw` and the app find it without configuration.
#[must_use]
pub fn fallback_socket_path() -> Option<PathBuf> {
    if std::env::var(AW_SOCKET).is_ok_and(|v| !v.trim().is_empty()) {
        return None;
    }
    aw_channel::user_path(&|key| std::env::var(key).ok())
}

/// Whether a bind error on the system path should fall back to the per-user
/// path: the daemon may not create the directory or file. A live daemon
/// (`AddrInUse`) is not a reason to fall back.
#[must_use]
pub fn should_fall_back(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::NotFound
            | std::io::ErrorKind::ReadOnlyFilesystem
    )
}

/// Shared API state. The loopback HTTP listener holds the same handle, so a
/// ticket issued here can be redeemed there.
pub type SharedState = Arc<Mutex<ApiState>>;

/// Group that owns the socket when it exists (Linux and macOS).
pub const SOCKET_GROUP: &str = "agentwatch";

/// Control routes first, then the normal routes as `caller`.
fn answer(
    state: &SharedState,
    control: &Control,
    request: &super::routes::HttpRequest,
    caller: &super::auth::Caller,
) -> super::routes::ApiResponse {
    if let Some(reply) = super::control::handle(control, request, caller) {
        return reply;
    }
    let (reply, slow) = {
        let mut guard = match state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match super::routes::take_slow(&mut guard, request, Some(caller)) {
            Some(job) => (None, Some(job)),
            None => (
                Some(super::routes::dispatch_peer(&mut guard, request, caller)),
                None,
            ),
        }
    };
    // An export is built after the lock is released (see `take_slow`).
    let reply = match (reply, slow) {
        (Some(reply), _) => reply,
        (None, Some(job)) => job(),
        (None, None) => super::routes::error_response(500, "internal", "no response"),
    };
    super::control::decorate(control, request, reply)
}

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
    use nix::fcntl::{Flock, FlockArg};

    use super::super::routes::error_response;
    use super::{answer, socket_mode, Control, SharedState, SOCKET_GROUP};

    const IO_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_REQUEST: usize = 80 * 1024;

    /// A running socket listener. Dropping it stops the loop and removes the file.
    pub struct IpcServer {
        /// Socket path actually bound.
        pub path: PathBuf,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
        /// `flock` on `<socket>.lock`, held for the server's life. Declared
        /// last: released only after `Drop` has removed the socket file.
        _lock: Flock<fs::File>,
    }

    /// `<socket>.lock` next to the socket.
    #[must_use]
    pub fn lock_path(path: &Path) -> PathBuf {
        let mut name = path.as_os_str().to_owned();
        name.push(".lock");
        PathBuf::from(name)
    }

    /// Take the exclusive start lock for `path`. Contention means another
    /// daemon is starting or running on this socket: `AddrInUse`.
    fn take_lock(path: &Path) -> io::Result<Flock<fs::File>> {
        let lock = lock_path(path);
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock)?;
        Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, errno)| {
            if errno == nix::errno::Errno::EWOULDBLOCK {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("another agentwatchd holds {}", lock.display()),
                )
            } else {
                io::Error::from(errno)
            }
        })
    }

    /// Remove a stale socket at `path`, under the start lock. Removes only
    /// when all hold: it is a socket (lstat, so not a symlink), connecting
    /// is refused (nobody listens), and it belongs to this daemon's uid.
    /// A live socket is `AddrInUse`; anything else is left alone and is an
    /// error.
    pub(super) fn clear_stale(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        };
        if !meta.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} exists and is not a socket; not removing it",
                    path.display()
                ),
            ));
        }
        match UnixStream::connect(path) {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "another daemon is answering on the socket",
            )),
            Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
                let me = nix::unistd::geteuid().as_raw();
                if meta.uid() != me {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "stale socket {} belongs to uid {}, not {me}; not removing it",
                            path.display(),
                            meta.uid()
                        ),
                    ));
                }
                tracing::info!(target: "aw_daemon::ipc", socket = %path.display(), "removing stale socket (connection refused)");
                fs::remove_file(path)
            }
            Err(err) => Err(err),
        }
    }

    impl IpcServer {
        /// Bind `path`, set mode 0660 (group [`SOCKET_GROUP`] when it
        /// exists), and serve `state` until shutdown.
        ///
        /// # Errors
        ///
        /// Parent directory creation, a live daemon already on `path`
        /// (`AddrInUse`), bind, or chmod failure.
        pub fn bind(path: &Path, state: SharedState, control: Arc<Control>) -> io::Result<Self> {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    fs::create_dir_all(parent)?;
                    // A directory this daemon created is its own and not
                    // writable by others, so nobody can swap the socket.
                    // 0750 with the `agentwatch` group, else 0755.
                    let grouped = set_group(parent);
                    let dir_mode = if grouped { 0o750 } else { 0o755 };
                    let _ = fs::set_permissions(parent, fs::Permissions::from_mode(dir_mode));
                }
            }
            // Lock first, so two daemons starting at once cannot each see
            // the other's fresh socket as stale and delete it.
            let lock = take_lock(path)?;
            clear_stale(path)?;
            if let Some(reason) = aw_channel::socket_path_too_long(path) {
                // `reason` is the Chinese sentence. The English token is only
                // for logs; the bind error shown to the user is the sentence.
                tracing::warn!(target: "aw_daemon::ipc", path = %path.display(), "unusable socket path");
                return Err(io::Error::new(io::ErrorKind::InvalidInput, reason));
            }
            let listener = UnixListener::bind(path)?;
            let grouped = set_group(path);
            fs::set_permissions(path, fs::Permissions::from_mode(socket_mode(grouped)))?;
            listener.set_nonblocking(true)?;
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            let thread = thread::Builder::new()
                .name("aw-ipc".to_owned())
                .spawn(move || accept_loop(&listener, &state, &control, &flag))?;
            Ok(Self {
                path: path.to_path_buf(),
                stop,
                thread: Some(thread),
                _lock: lock,
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

    /// Give the socket to [`SOCKET_GROUP`] when that group exists. Failure
    /// (an unprivileged daemon cannot chown to a group it is not in) is logged;
    /// the socket is then opened to every local account instead (see
    /// [`super::OPEN_SOCKET_MODE`]). `true` when the group was applied.
    fn set_group(path: &Path) -> bool {
        let gid = match nix::unistd::Group::from_name(SOCKET_GROUP) {
            Ok(Some(group)) => group.gid.as_raw(),
            Ok(None) => return false,
            Err(err) => {
                tracing::debug!(target: "aw_daemon::ipc", error = %err, "group lookup failed");
                return false;
            }
        };
        match std::os::unix::fs::chown(path, None, Some(gid)) {
            Ok(()) => true,
            Err(err) => {
                tracing::warn!(target: "aw_daemon::ipc", error = %err, gid, "socket group not set");
                false
            }
        }
    }

    fn accept_loop(
        listener: &UnixListener,
        state: &SharedState,
        control: &Arc<Control>,
        stop: &AtomicBool,
    ) {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let state = Arc::clone(state);
                    let control = Arc::clone(control);
                    let spawned = thread::Builder::new()
                        .name("aw-ipc-conn".to_owned())
                        .spawn(move || {
                            if let Err(err) = serve(stream, &state, &control) {
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

    /// The peer as an API caller. The platform layer is the only code that
    /// reads peer credentials, so an unverified socket can never become a
    /// low-privilege placeholder identity.
    pub(super) fn peer_caller(stream: &UnixStream) -> Result<Caller, aw_platform::PlatformError> {
        let peer = aw_platform::identify_unix_peer(stream)?;
        match peer.owner() {
            aw_platform::Owner::Unix { euid, .. } => {
                let admin = *euid == 0;
                Ok(Caller {
                    user_id: euid.to_string(),
                    admin,
                    peer: Some(peer),
                })
            }
            aw_platform::Owner::Windows { .. } => {
                Err(aw_platform::PlatformError::PeerNotIdentified {
                    reason: "Unix socket peer did not have a Unix owner",
                })
            }
        }
    }

    fn serve(mut stream: UnixStream, state: &SharedState, control: &Control) -> io::Result<()> {
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let caller = match peer_caller(&stream) {
            Ok(caller) => caller,
            Err(_) => {
                let response = error_response(
                    403,
                    "unidentified_peer",
                    "socket peer could not be identified",
                );
                return write_response(&mut stream, &response);
            }
        };
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
        let response = answer(state, control, &request, &caller);
        // `aw daemon logs -f` polls twice a second; logging those reads
        // would feed the log it is following.
        if request.path != super::super::control::LOGS_PATH {
            let route = super::super::http::log_route(&request.path);
            tracing::debug!(
                target: "aw_daemon::ipc",
                method = %request.method,
                route = %route,
                status = response.status,
                admin = caller.admin,
                "request"
            );
        }
        write_response(&mut stream, &response)
    }
}

#[cfg(windows)]
mod pipe {
    use std::ffi::OsString;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use aw_collector_windows::pipe::{create_server, is_admin, pipe_sddl};
    use aw_platform::{identify_pipe_peer, Owner};
    use tokio::net::windows::named_pipe::NamedPipeServer;

    use super::super::auth::Caller;
    use super::super::http::{parse_request, response_bytes};
    use super::super::routes::error_response;
    use super::{answer, Control, SharedState};

    const MAX_REQUEST: usize = 80 * 1024;
    /// A client that has not finished its exchange in this time is dropped.
    const IO_TIMEOUT: Duration = Duration::from_secs(30);

    /// A running named-pipe listener.
    pub struct IpcServer {
        /// Pipe path actually created.
        pub path: PathBuf,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl IpcServer {
        /// Create the first pipe instance on `path` with the AgentWatch DACL
        /// and serve `state`.
        ///
        /// # Errors
        ///
        /// Runtime creation or pipe creation failure (another daemon holding
        /// the first instance is `PermissionDenied` / `AccessDenied`).
        pub fn bind(path: &Path, state: SharedState, control: Arc<Control>) -> io::Result<Self> {
            let name = path.as_os_str().to_owned();
            let sddl = pipe_sddl();
            tracing::info!(target: "aw_daemon::ipc", sddl = %sddl, "pipe DACL");
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let first = runtime.block_on(async { create_server(&name, true, &sddl) })?;
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            let thread = thread::Builder::new()
                .name("aw-ipc".to_owned())
                .spawn(move || {
                    runtime.block_on(accept_loop(name, sddl, first, state, control, flag));
                })?;
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
        name: OsString,
        sddl: String,
        mut server: NamedPipeServer,
        state: SharedState,
        control: Arc<Control>,
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
            // A failed instance create is retried, never the end of the
            // listener: the connected client is still served below.
            let next = loop {
                match create_server(&name, false, &sddl) {
                    Ok(next) => break next,
                    Err(err) => {
                        tracing::warn!(target: "aw_daemon::ipc", error = %err, "next pipe instance not created; retrying");
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            };
            let client = std::mem::replace(&mut server, next);
            let state = Arc::clone(&state);
            let control = Arc::clone(&control);
            tokio::spawn(async move {
                let served = tokio::time::timeout(IO_TIMEOUT, serve(client, state, control)).await;
                if let Ok(Err(err)) = served {
                    tracing::debug!(target: "aw_daemon::ipc", error = %err, "pipe connection closed");
                }
            });
        }
    }

    async fn serve(
        pipe: NamedPipeServer,
        state: SharedState,
        control: Arc<Control>,
    ) -> io::Result<()> {
        let caller = match identify_pipe_peer(pipe.as_raw_handle()) {
            Ok(peer) => match peer.owner() {
                Owner::Windows { sid, elevated, .. } => {
                    let admin = is_admin(sid, *elevated);
                    Caller {
                        user_id: sid.clone(),
                        admin,
                        peer: Some(peer),
                    }
                }
                Owner::Unix { .. } => unreachable!("Windows pipe peer has a Windows owner"),
            },
            Err(err) => {
                tracing::warn!(target: "aw_daemon::ipc", error = %err, "pipe client not identified");
                let response = error_response(
                    403,
                    "unidentified_peer",
                    "pipe client could not be identified",
                );
                write_all(&pipe, &response_bytes(&response)).await?;
                // Dropped, not disconnected: see the end of `serve`.
                return Ok(());
            }
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
        // Routes are synchronous (SQLite); off the runtime thread so one slow
        // request (a large export) does not stall every other pipe client.
        let response =
            tokio::task::spawn_blocking(move || answer(&state, &control, &request, &caller))
                .await
                .unwrap_or_else(|_| error_response(500, "internal", "request handler failed"));
        write_all(&pipe, &response_bytes(&response)).await?;
        // Do not call `disconnect` (DisconnectNamedPipe) here: it throws away
        // whatever the client has not read yet, and the client's read then
        // fails with ERROR_PIPE_NOT_CONNECTED ("uncategorized error"), which
        // made the pipe test fail on Windows CI. Dropping the instance closes
        // the server handle; the client reads the buffered reply and then sees
        // ERROR_BROKEN_PIPE, which std reports as end of file. Each instance
        // serves one connection, so nothing reuses it.
        drop(pipe);
        Ok(())
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
        pub fn bind(
            _path: &Path,
            _state: SharedState,
            _control: std::sync::Arc<super::Control>,
        ) -> io::Result<Self> {
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
    use super::{socket_path_from, Control, IpcServer, OPEN_SOCKET_MODE, SOCKET_MODE};

    /// `<short dir>/api.sock`; the directory is removed when this drops.
    struct TempSocket(PathBuf);

    impl std::ops::Deref for TempSocket {
        type Target = PathBuf;
        fn deref(&self) -> &PathBuf {
            &self.0
        }
    }

    impl AsRef<std::path::Path> for TempSocket {
        fn as_ref(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempSocket {
        fn drop(&mut self) {
            if let Some(dir) = self.0.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    fn temp_socket(name: &str) -> TempSocket {
        TempSocket(aw_channel::short_temp_dir(name).join("api.sock"))
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
        assert!(super::should_fall_back(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
        assert!(!super::should_fall_back(&std::io::Error::from(
            std::io::ErrorKind::AddrInUse
        )));
        // Empty lookup: ignore `AW_SYSTEM_SOCKET` and friends from the shell.
        let none = |_: &str| None;
        assert_eq!(
            socket_path_from(Some("/tmp/x.sock".to_owned()), &none),
            Some(PathBuf::from("/tmp/x.sock"))
        );
        let default = socket_path_from(Some("  ".to_owned()), &none);
        if cfg!(target_os = "linux") {
            assert_eq!(default, Some(PathBuf::from(super::LINUX_SOCKET)));
        }
        // Blank override falls through to `AW_SYSTEM_SOCKET` (not on Windows).
        let lookup = |key: &str| (key == "AW_SYSTEM_SOCKET").then(|| "/tmp/sys.sock".to_owned());
        assert_eq!(
            socket_path_from(Some("  ".to_owned()), &lookup),
            Some(PathBuf::from("/tmp/sys.sock"))
        );
    }

    #[test]
    fn socket_serves_health_and_mode_follows_the_group() {
        let path = temp_socket("health");
        let state = Arc::new(Mutex::new(ApiState::default()));
        let mut server = IpcServer::bind(&path, state, Control::new(None)).expect("bind");
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode() & 0o777;
        // No `agentwatch` group on a test machine: open to local accounts.
        // With the group it is 0660 and the group is `agentwatch`.
        let grouped = nix::unistd::Group::from_name(super::SOCKET_GROUP)
            .ok()
            .flatten()
            .is_some_and(|g| {
                std::os::unix::fs::MetadataExt::gid(&std::fs::metadata(&path).expect("meta"))
                    == g.gid.as_raw()
            });
        assert_eq!(
            mode,
            if grouped {
                SOCKET_MODE
            } else {
                OPEN_SOCKET_MODE
            }
        );
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
        let _server = IpcServer::bind(&path, Arc::clone(&state), Control::new(None)).expect("bind");
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
    fn peer_is_the_current_uid() {
        let path = temp_socket("peer");
        let state = Arc::new(Mutex::new(ApiState::default()));
        let _server = IpcServer::bind(&path, state, Control::new(None)).expect("bind");
        let (status, body) = exchange(&path, "GET /api/v1/me HTTP/1.1\r\n\r\n");
        assert_eq!(status, 200, "{body}");
        // Linux (SO_PEERCRED) and macOS (getpeereid) both report the uid.
        let uid = nix::unistd::geteuid().as_raw();
        assert_eq!(body["user_id"], uid.to_string());
        assert_eq!(body["admin"], uid == 0);
    }

    /// Real-window #144 blocker 3: over the real socket, a non-admin peer
    /// (identified by its uid, not a header) sees a `sleep` it started.
    #[test]
    fn process_table_over_the_socket_lists_a_live_sleep() {
        let path = temp_socket("procs");
        let state = Arc::new(Mutex::new(ApiState::default()));
        let _server = IpcServer::bind(&path, state, Control::new(None)).expect("bind");
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = u64::from(child.id());
        let mut seen = serde_json::Value::Null;
        for _ in 0..40 {
            let (status, body) = exchange(&path, "GET /api/v1/processes?q=sleep HTTP/1.1\r\n\r\n");
            assert_eq!(status, 200, "{body}");
            let hit = body["processes"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["pid"] == pid));
            seen = body;
            if hit {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
        let uid = nix::unistd::geteuid().as_raw();
        assert_eq!(seen["available"], true, "{seen}");
        assert_eq!(seen["scope"], if uid == 0 { "all" } else { "own" });
        let row = seen["processes"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["pid"] == pid))
            .unwrap_or_else(|| panic!("sleep {pid} listed: {seen}"));
        assert_eq!(row["name"], "sleep");
        assert_eq!(row["user_id"], uid.to_string());
    }

    /// Wait until nothing listens on `path` any more. Another test thread
    /// may `fork` while the listener is open; the child holds a copy of the
    /// listening fd until its `exec`, and a connect in that window succeeds,
    /// so the socket is not yet stale. Bounded; panics with the last result.
    fn wait_refused(path: &std::path::Path) {
        let started = std::time::Instant::now();
        loop {
            match UnixStream::connect(path) {
                Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => return,
                other => assert!(
                    started.elapsed() < std::time::Duration::from_secs(10),
                    "{} never became stale: {other:?}",
                    path.display()
                ),
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn stale_socket_is_replaced() {
        let path = temp_socket("stale");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap()); // crashed daemon
        assert!(path.exists());
        wait_refused(path.as_ref());
        let state = Arc::new(Mutex::new(ApiState::default()));
        let _server = IpcServer::bind(&path, state, Control::new(None))
            .unwrap_or_else(|err| panic!("bind over stale {}: {err:?}", path.0.display()));
        let (status, _) = exchange(&path, "GET /health HTTP/1.1\r\n\r\n");
        assert_eq!(status, 200);
    }

    #[test]
    fn a_non_socket_or_symlink_at_the_path_is_not_removed() {
        let path = temp_socket("notsock");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"keep me").unwrap();
        let state = Arc::new(Mutex::new(ApiState::default()));
        assert!(IpcServer::bind(&path, Arc::clone(&state), Control::new(None)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep me");

        // A symlink to a stale socket elsewhere: lstat sees a link, not a socket.
        let target = path.with_file_name("elsewhere.sock");
        drop(std::os::unix::net::UnixListener::bind(&target).unwrap());
        let link = path.with_file_name("link.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(IpcServer::bind(&link, state, Control::new(None)).is_err());
        assert!(std::fs::symlink_metadata(&link).is_ok(), "link kept");
        assert!(target.exists(), "target kept");
    }

    /// Two daemons on one path: the later one fails and the first one's
    /// socket keeps answering — whether the second arrives while the first
    /// runs, or both race to start.
    #[test]
    fn racing_daemons_never_delete_the_live_socket() {
        let path = temp_socket("race");
        let state = Arc::new(Mutex::new(ApiState::default()));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (path, state, barrier) =
                    (path.clone(), Arc::clone(&state), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    IpcServer::bind(&path, state, Control::new(None))
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let winners: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
        assert_eq!(winners.len(), 1, "exactly one daemon binds");
        for err in results.iter().filter_map(|r| r.as_ref().err()) {
            assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse, "{err}");
        }
        let (status, _) = exchange(&path, "GET /health HTTP/1.1\r\n\r\n");
        assert_eq!(status, 200, "the winner's socket survives");
        let late = IpcServer::bind(&path, state, Control::new(None));
        assert_eq!(
            late.err().map(|e| e.kind()),
            Some(std::io::ErrorKind::AddrInUse)
        );
        let (status, _) = exchange(&path, "GET /health HTTP/1.1\r\n\r\n");
        assert_eq!(status, 200);
        drop(results);
    }

    #[test]
    fn live_socket_is_not_stolen_and_assets_are_not_served() {
        let path = temp_socket("busy");
        let state = Arc::new(Mutex::new(ApiState::default()));
        let _server = IpcServer::bind(&path, Arc::clone(&state), Control::new(None)).expect("bind");
        let second = IpcServer::bind(&path, state, Control::new(None));
        assert!(second.is_err());
        let (status, _) = exchange(&path, "GET / HTTP/1.1\r\n\r\n");
        assert_eq!(status, 404);
    }

    /// `aw daemon stop` path: the daemon's own uid may stop it over the
    /// socket; the control flag is what the runtime loop polls.
    #[test]
    fn owner_can_stop_and_read_logs_over_the_socket() {
        let path = temp_socket("stop");
        let log = path.with_file_name("agentwatchd.log");
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();
        std::fs::write(&log, "line one\nline two\n").unwrap();
        let state = Arc::new(Mutex::new(ApiState::default()));
        let control = Control::new(Some(log));
        let _server = IpcServer::bind(&path, state, Arc::clone(&control)).expect("bind");
        let (status, body) = exchange(&path, "GET /api/v1/daemon/logs?tail=1 HTTP/1.1\r\n\r\n");
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["text"], "line two\n");
        assert!(!control.stop_requested());
        let (status, body) = exchange(
            &path,
            "POST /api/v1/daemon/stop HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(status, 202, "{body}");
        assert!(control.stop_requested());
    }
}

/// Real named-pipe runs (R1). They create a private pipe name, start the
/// listener with the AgentWatch DACL, and dial it with `aw_channel` — the
/// client `aw` (cmd → client.rs → aw_channel) and the desktop app
/// (app/src-tauri → aw_channel) both use.
#[cfg(all(test, windows))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod pipe_tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use super::super::routes::ApiState;
    use super::{Control, IpcServer};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn pipe_name() -> PathBuf {
        PathBuf::from(format!(
            r"\\.\pipe\agentwatch-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::SeqCst)
        ))
    }

    fn call(path: &std::path::Path, method: &str, target: &str) -> (u16, serde_json::Value) {
        let body: &[u8] = if method == "POST" { b"{}" } else { b"" };
        let request = aw_channel::encode_request(method, target, "application/json", body);
        let reply = aw_channel::exchange(path, &request, aw_channel::TIMEOUT).expect("exchange");
        let json = serde_json::from_slice(&reply.body).unwrap_or(serde_json::Value::Null);
        (reply.status, json)
    }

    #[test]
    fn pipe_serves_health_and_a_ticket_to_the_shared_client() {
        let path = pipe_name();
        let state = Arc::new(Mutex::new(ApiState::default()));
        let control = Control::new(None);
        control.set_http_port(7456);
        let mut server = IpcServer::bind(&path, state, Arc::clone(&control)).expect("bind pipe");

        let (status, body) = call(&path, "GET", "/health");
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["status"], "ok");

        // Several in a row: each connection needs a fresh instance.
        for _ in 0..3 {
            let (status, body) = call(&path, "POST", "/api/v1/auth/ui-ticket");
            assert_eq!(status, 200, "{body}");
            assert!(!body["ticket"].as_str().unwrap_or("").is_empty(), "{body}");
            assert_eq!(body["http_port"], 7456);
        }

        // The caller is identified from its token, not assumed.
        let (status, me) = call(&path, "GET", "/api/v1/me");
        assert_eq!(status, 200, "{me}");
        let sid = me["user_id"].as_str().unwrap_or("");
        assert!(sid.starts_with("S-1-"), "{me}");
        assert_eq!(
            me["admin"].as_bool(),
            Some(aw_collector_windows::privilege::is_privileged().unwrap_or(false)),
            "admin follows the caller's elevation: {me}"
        );
        server.shutdown();
    }

    #[test]
    fn missing_pipe_is_unreachable() {
        let request = aw_channel::encode_request("GET", "/health", "*/*", b"");
        let err = aw_channel::exchange(&pipe_name(), &request, aw_channel::TIMEOUT).unwrap_err();
        assert_eq!(err.code(), "daemon_unreachable", "{err}");
    }

    #[test]
    fn second_daemon_cannot_take_the_pipe() {
        let path = pipe_name();
        let state = Arc::new(Mutex::new(ApiState::default()));
        let _first = IpcServer::bind(&path, Arc::clone(&state), Control::new(None)).expect("bind");
        assert!(IpcServer::bind(&path, state, Control::new(None)).is_err());
    }
}
