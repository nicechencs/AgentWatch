//! Replaceable proxy core.
//!
//! `hudsucker` (hyper + tokio + rustls handshake) is the design in
//! network-attribution §5.6. Those crates are not in `Cargo.lock`, and this
//! task must not add them. [`ProxyBackend`] is the seam: a later unlock swaps
//! in a hudsucker backend without changing [`super::ProxyServer`] or the
//! session port map.
//!
//! [`MetadataBackend`] accepts one TCP connection, reads the first line, and
//! emits metadata. It does not complete a TLS handshake, does not parse HTTP/2
//! frames, and does not open an upstream socket. That is a deliberate gap, not
//! a MITM.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;

use crate::record::{
    record_exchange, to_events, RecordedExchange, RequestMeta, ResponseMeta, UrlGap, WsCounts,
};
use aw_core::{RawEvent, SessionId, SocketAddr};

/// What the listener asks the backend to do with one accepted socket.
pub struct Accepted {
    /// The accepted stream. The backend owns it until it returns.
    pub stream: TcpStream,
    /// Peer address. `None` when the platform did not provide one.
    pub peer: Option<std::net::SocketAddr>,
    /// Next request id. The server assigns it so two backends cannot collide.
    pub req_id: u64,
    /// Session this listener belongs to.
    pub session_id: Option<SessionId>,
    /// Monotonic timestamp supplied by the caller. Not read from a clock here.
    pub ts_mono_ns: u64,
    /// Wall timestamp, Unix nanoseconds.
    pub ts_wall_ns: i64,
    /// `fail` or `tunnel` once a handshake would have been rejected.
    pub on_reject: crate::inject::ProxyOnReject,
}

impl fmt::Debug for Accepted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Accepted")
            .field("peer", &self.peer)
            .field("req_id", &self.req_id)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

/// One connection's outcome. Events are already redacted.
#[derive(Debug)]
pub struct BackendOutput {
    /// Zero, one, or two events (`http_request`, then `http_response`).
    pub events: Vec<RawEvent>,
    /// The redacted exchange, when a request line was parsed.
    pub recorded: Option<RecordedExchange>,
    /// Bytes read from the client. `None` when the read failed before a count.
    pub client_bytes: Option<u64>,
}

/// Pluggable core. The default is [`MetadataBackend`].
pub trait ProxyBackend {
    /// Handle one accepted connection.
    ///
    /// # Errors
    ///
    /// I/O failed. The message must not contain a URL or a header value.
    fn handle(&mut self, accepted: Accepted) -> Result<BackendOutput, BackendError>;
}

/// Why a backend stopped. Display text has no request contents.
#[derive(Debug)]
pub enum BackendError {
    /// The socket read or write failed. `kind` is the I/O kind, not the payload.
    Io(&'static str),
    /// The request line was not HTTP. No event is a success path; this is a
    /// parse failure the caller records as a gap if it wants one.
    NotHttp,
    /// The event builder rejected the record.
    Event(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(kind) => write!(f, "proxy connection io: {kind}"),
            Self::NotHttp => write!(f, "first line was not an HTTP request"),
            Self::Event(detail) => write!(f, "proxy event: {detail}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// Reads one HTTP/1 request line and the following header block, then records
/// metadata. Does not forward, does not speak TLS.
///
/// [`Self::upstream_roots`] is a rustls client config built from the bundled
/// Mozilla roots. It is held so a later hudsucker backend can reuse the same
/// "do not accept an untrusted upstream" rule. This backend never calls it:
/// no upstream socket is opened, so an invalid upstream certificate cannot be
/// accepted here either.
///
/// Overload: [`Self::handle`] does not drop the request. It reads what the
/// client already sent (the kernel buffer is the backpressure) and returns.
/// A full MITM would stop reading to stall the client; this backend has no
/// upstream to be overloaded by.
#[derive(Debug, Default)]
pub struct MetadataBackend {
    /// When set, a `CONNECT` under [`crate::inject::ProxyOnReject::Tunnel`] is
    /// recorded with `NA(cert_pinned)`. This backend cannot see a TLS alert, so
    /// the flag is how a caller asks for that record shape. Production leaves
    /// it `false`: a pin is a failed handshake, and no handshake runs here.
    pub treat_connect_as_pinned: bool,
    /// Roots a future upstream dial would trust. `None` when rustls refused to
    /// build a client config. Not used to dial. Absence is not "trust everyone".
    upstream_roots: Option<Arc<rustls::ClientConfig>>,
}

impl MetadataBackend {
    /// Backend that records request lines and nothing else.
    #[must_use]
    pub fn new() -> Self {
        Self {
            treat_connect_as_pinned: false,
            upstream_roots: upstream_client_config().map(Arc::new),
        }
    }

    /// The unused upstream config. `None` means no config was built, so an
    /// upstream dial (which this backend does not do) would have nothing to trust.
    #[must_use]
    pub fn upstream_roots(&self) -> Option<&rustls::ClientConfig> {
        self.upstream_roots.as_deref()
    }
}

fn upstream_client_config() -> Option<rustls::ClientConfig> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    if let Ok(builder) = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
    {
        return Some(builder.with_root_certificates(roots).with_no_client_auth());
    }
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .ok()
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

impl ProxyBackend for MetadataBackend {
    fn handle(&mut self, mut accepted: Accepted) -> Result<BackendOutput, BackendError> {
        let mut buf = [0u8; 8192];
        let n = match accepted.stream.read(&mut buf) {
            Ok(0) => {
                return Ok(BackendOutput {
                    events: Vec::new(),
                    recorded: None,
                    client_bytes: Some(0),
                });
            }
            Ok(n) => n,
            Err(err) => return Err(BackendError::Io(io_kind(&err))),
        };
        let text = String::from_utf8_lossy(&buf[..n]);
        let parsed = parse_request(&text).ok_or(BackendError::NotHttp)?;
        let peer = accepted
            .peer
            .map(SocketAddr::socket)
            .unwrap_or_else(|| SocketAddr::ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
        let mut request = parsed;
        request.client = peer;
        let pinned = self.treat_connect_as_pinned
            && request.method.eq_ignore_ascii_case("CONNECT")
            && accepted.on_reject == crate::inject::ProxyOnReject::Tunnel;
        let url_gap = if pinned {
            Some(UrlGap::CertPinned)
        } else {
            None
        };
        // No response was observed. Status, response body, and duration stay
        // absent. A websocket upgrade is noted only when the request asked for it.
        let websocket = if request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("upgrade") && value.eq_ignore_ascii_case("websocket")
        }) {
            Some(WsCounts {
                frames_up: None,
                frames_down: None,
                bytes_up: None,
                bytes_down: None,
            })
        } else {
            None
        };
        let response = None::<ResponseMeta>;
        let recorded = record_exchange(accepted.req_id, request, response, websocket, url_gap);
        let events = to_events(
            &recorded,
            accepted.req_id,
            accepted.ts_mono_ns,
            accepted.ts_wall_ns,
            accepted.session_id,
        )
        .map_err(|err| BackendError::Event(err.to_string()))?;
        // Tell the client this build does not proxy. Closing is not a silent drop:
        // the caller still has the event.
        let _ = accepted.stream.write_all(
            b"HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let _ = accepted.stream.shutdown(Shutdown::Both);
        Ok(BackendOutput {
            events,
            recorded: Some(recorded),
            client_bytes: u64::try_from(n).ok(),
        })
    }
}

fn io_kind(err: &io::Error) -> &'static str {
    use io::ErrorKind::{
        AddrInUse, AddrNotAvailable, BrokenPipe, ConnectionAborted, ConnectionRefused,
        ConnectionReset, Interrupted, NotFound, PermissionDenied, TimedOut, UnexpectedEof,
        WouldBlock,
    };
    match err.kind() {
        NotFound => "not_found",
        PermissionDenied => "permission_denied",
        ConnectionRefused => "connection_refused",
        ConnectionReset => "connection_reset",
        ConnectionAborted => "connection_aborted",
        BrokenPipe => "broken_pipe",
        TimedOut => "timed_out",
        Interrupted => "interrupted",
        WouldBlock => "would_block",
        UnexpectedEof => "unexpected_eof",
        AddrInUse => "addr_in_use",
        AddrNotAvailable => "addr_not_available",
        _ => "other",
    }
}

fn parse_request(text: &str) -> Option<RequestMeta> {
    let mut lines = text.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let version = parts.next()?.to_owned();
    if !version.starts_with("HTTP/") {
        return None;
    }
    let mut headers = Vec::new();
    let mut content_length: Option<u64> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        let name = name.trim().to_owned();
        let value = value.trim().to_owned();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok();
        }
        headers.push((name, value));
    }
    let url = if method.eq_ignore_ascii_case("CONNECT") {
        format!("https://{target}")
    } else if target.starts_with("http://") || target.starts_with("https://") {
        target
    } else {
        let host = headers
            .iter()
            .find_map(|(name, value)| name.eq_ignore_ascii_case("host").then_some(value.as_str()));
        match host {
            Some(host) => format!("http://{host}{target}"),
            None => target,
        }
    };
    let kind = method_kind(&method);
    Some(RequestMeta {
        method,
        url,
        http_version: version,
        headers,
        // A missing Content-Length on a request that has no body is "not observed"
        // rather than zero. GET/HEAD/CONNECT with no length are treated as no body
        // only when the method is one of those three: the length is then a real zero.
        body_bytes: match content_length {
            Some(n) => Some(n),
            None if matches!(kind, MethodKind::NoBody) => Some(0),
            None => None,
        },
        client: SocketAddr::ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    })
}

enum MethodKind {
    NoBody,
    MaybeBody,
}

fn method_kind(method: &str) -> MethodKind {
    if method.eq_ignore_ascii_case("GET")
        || method.eq_ignore_ascii_case("HEAD")
        || method.eq_ignore_ascii_case("CONNECT")
        || method.eq_ignore_ascii_case("DELETE")
        || method.eq_ignore_ascii_case("TRACE")
    {
        MethodKind::NoBody
    } else {
        MethodKind::MaybeBody
    }
}
