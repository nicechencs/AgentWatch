//! One loopback listener per session (P3-PROXY-02).
//!
//! [`ProxyServer`] binds `127.0.0.1:0`, so the port is chosen by the OS and dies
//! with the listener. The port is the attribution key P3-PIPE-01 will use.
//!
//! This is not a MITM proxy. The handshake and the HTTP parser live behind
//! [`ProxyBackend`]. The default, [`MetadataBackend`], records the first request
//! line of one connection and closes it. A hudsucker backend replaces that
//! trait once `hudsucker`, `hyper`, and `tokio` are in the lock file. Until
//! then an upstream certificate is never accepted or rejected by this process,
//! because no upstream connection is opened — the client is told `501` and the
//! gap is the absence of a response event, not a forged success.

mod backend;

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aw_core::{RawEvent, SessionId};

pub use backend::{Accepted, BackendError, BackendOutput, MetadataBackend, ProxyBackend};

use crate::inject::ProxyOnReject;

/// A session's proxy. Drop closes the listener (the socket is owned here).
pub struct ProxyServer<B: ProxyBackend> {
    listener: TcpListener,
    backend: B,
    session_id: Option<SessionId>,
    next_req: AtomicU64,
    on_reject: ProxyOnReject,
    /// Set by [`ProxyServer::close`]. `accept_one` returns [`AcceptError::Closed`].
    closed: Arc<AtomicBool>,
}

impl<B: ProxyBackend> fmt::Debug for ProxyServer<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyServer")
            .field("local", &self.local_addr().ok())
            .field("session_id", &self.session_id)
            .field("on_reject", &self.on_reject)
            .finish_non_exhaustive()
    }
}

impl ProxyServer<MetadataBackend> {
    /// Bind `127.0.0.1:0` with the metadata backend.
    ///
    /// # Errors
    ///
    /// The bind failed. The message is the I/O kind, not a path.
    pub fn bind_ephemeral(session_id: Option<SessionId>) -> Result<Self, AcceptError> {
        Self::bind_with(session_id, MetadataBackend::new())
    }
}

impl<B: ProxyBackend> ProxyServer<B> {
    /// Bind `127.0.0.1:0` with `backend`.
    ///
    /// # Errors
    ///
    /// The bind failed.
    pub fn bind_with(session_id: Option<SessionId>, backend: B) -> Result<Self, AcceptError> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|err| AcceptError::Bind(io_label(&err)))?;
        listener
            .set_nonblocking(true)
            .map_err(|err| AcceptError::Bind(io_label(&err)))?;
        Ok(Self {
            listener,
            backend,
            session_id,
            next_req: AtomicU64::new(1),
            on_reject: ProxyOnReject::Fail,
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The bound address. The port is the session's proxy port.
    ///
    /// # Errors
    ///
    /// The socket has no local address.
    pub fn local_addr(&self) -> Result<SocketAddr, AcceptError> {
        self.listener
            .local_addr()
            .map_err(|err| AcceptError::Bind(io_label(&err)))
    }

    /// `proxy.on_tls_reject`. Default is [`ProxyOnReject::Fail`].
    pub fn set_on_reject(&mut self, policy: ProxyOnReject) {
        self.on_reject = policy;
    }

    /// Accept at most one connection, or time out. Does not loop.
    ///
    /// A timeout is [`AcceptError::Timeout`], not an empty success: the caller
    /// decides whether that is a gap. Nothing is discarded on the success path.
    ///
    /// # Errors
    ///
    /// Bind-time failures are not repeated. Accept, the backend, or a timeout.
    pub fn accept_one(&mut self, timeout: Duration) -> Result<BackendOutput, AcceptError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(AcceptError::Closed);
        }
        let _ = self.listener.set_nonblocking(false);
        // `TcpListener` has no read timeout. Apply it to the accepted stream.
        let (stream, peer) = match self.listener.accept() {
            Ok(pair) => pair,
            Err(err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                return Err(AcceptError::Timeout);
            }
            Err(err) => return Err(AcceptError::Io(io_label(&err))),
        };
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|err| AcceptError::Io(io_label(&err)))?;
        self.drive(stream, peer)
    }

    /// Accept without blocking. `Ok(None)` means no client is waiting.
    ///
    /// # Errors
    ///
    /// The listener failed, or the backend failed after a client connected.
    pub fn accept_nonblocking(&mut self) -> Result<Option<BackendOutput>, AcceptError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(AcceptError::Closed);
        }
        self.listener
            .set_nonblocking(true)
            .map_err(|err| AcceptError::Io(io_label(&err)))?;
        match self.listener.accept() {
            Ok((stream, peer)) => self.drive(stream, peer).map(Some),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(err) => Err(AcceptError::Io(io_label(&err))),
        }
    }

    /// Stop accepting. The listener is closed by drop; this only flips the flag
    /// so an in-flight `accept_one` can be distinguished from a timeout.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    fn drive(&mut self, stream: TcpStream, peer: SocketAddr) -> Result<BackendOutput, AcceptError> {
        let req_id = self.next_req.fetch_add(1, Ordering::Relaxed);
        let accepted = Accepted {
            stream,
            peer: Some(peer),
            req_id,
            session_id: self.session_id,
            ts_mono_ns: 0,
            ts_wall_ns: 0,
            on_reject: self.on_reject,
        };
        self.backend.handle(accepted).map_err(AcceptError::Backend)
    }
}

/// Why accept failed. No request bytes.
#[derive(Debug)]
pub enum AcceptError {
    /// `bind` failed.
    Bind(&'static str),
    /// No client arrived before the timeout.
    Timeout,
    /// [`ProxyServer::close`] was called.
    Closed,
    /// The listener failed.
    Io(&'static str),
    /// The backend failed after accept.
    Backend(BackendError),
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(kind) => write!(f, "proxy bind: {kind}"),
            Self::Timeout => write!(f, "proxy accept timed out"),
            Self::Closed => write!(f, "proxy listener is closed"),
            Self::Io(kind) => write!(f, "proxy accept: {kind}"),
            Self::Backend(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for AcceptError {}

fn io_label(err: &io::Error) -> &'static str {
    match err.kind() {
        io::ErrorKind::AddrInUse => "addr_in_use",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::WouldBlock => "would_block",
        _ => "other",
    }
}

/// Events from one [`BackendOutput`], for a caller that does not want the rest.
#[must_use]
pub fn events_of(output: BackendOutput) -> Vec<RawEvent> {
    output.events
}
