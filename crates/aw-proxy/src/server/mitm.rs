//! hudsucker MITM backend (P3-PROXY-02).
//!
//! One [`MitmProxy`] binds `127.0.0.1:0` and terminates TLS with the session CA
//! from [`crate::ca`]. It records method, redacted URL, status, header whitelist,
//! and body byte counts. The body itself is counted and dropped; it is never
//! logged and never written anywhere.
//!
//! `hudsucker` is built with `default-features = false`, so its `rcgen-ca`
//! feature (and the MPL-2.0 `webpki-roots` crate that feature pulls in) is not
//! linked. Leaves are signed by [`CaStore`] and wrapped in a rustls
//! [`ServerConfig`] here.
//!
//! The synchronous [`super::MetadataBackend`] stays. It answers `501` and is what
//! [`super::ProxyServer`] uses when no runtime is wanted. This module is the one
//! that actually proxies.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::ca::KeyProtector;
use std::time::Instant;

use aw_core::{RawEvent, SessionId};
use http::{Request, Response, Uri, Version};
use http_body_util::BodyExt;
use hudsucker::certificate_authority::CertificateAuthority;
use hudsucker::{
    HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::ClientHello;
use rustls::ServerConfig;
use tokio::sync::{mpsc, oneshot};

use crate::ca::{CaError, CaStore, LeafCert};
use crate::inject::ProxyOnReject;
use crate::record::{
    record_exchange, to_events, RecordedExchange, RequestMeta, ResponseMeta, UrlGap, WsCounts,
};

/// What one accepted exchange produced. Events are already redacted.
#[derive(Debug)]
pub struct MitmOutput {
    /// `http_request`, then `http_response` when a response was seen.
    pub events: Vec<RawEvent>,
    /// The redacted exchange.
    pub recorded: RecordedExchange,
}

/// Why the MITM listener stopped.
#[derive(Debug)]
pub enum MitmError {
    /// The socket could not bind, or the proxy task ended on its own.
    Bind(String),
    /// No CA is loaded, or leaf signing failed. The text has no key material.
    Ca(String),
    /// rustls refused the leaf certificate or its key.
    Tls(String),
}

impl fmt::Display for MitmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(detail) => write!(f, "mitm bind: {detail}"),
            Self::Ca(detail) => write!(f, "mitm ca: {detail}"),
            Self::Tls(detail) => write!(f, "mitm tls: {detail}"),
        }
    }
}

impl std::error::Error for MitmError {}

/// A session's MITM proxy. Drop sends the shutdown signal; the port dies with it.
pub struct MitmProxy {
    local: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    events: mpsc::UnboundedReceiver<MitmOutput>,
}

impl fmt::Debug for MitmProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmProxy")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl MitmProxy {
    /// Bind `127.0.0.1:0` and serve until dropped.
    ///
    /// `ca` is shared. [`CaStore`] is not `Sync` internally, so callers pass the
    /// `Mutex` they already keep it behind. The guard is held only while a leaf
    /// is signed.
    ///
    /// # Errors
    ///
    /// The bind failed, or no CA is loaded. A missing CA is reported before the
    /// listener starts, so a client never connects to a proxy that cannot sign.
    pub async fn bind<P: KeyProtector + Send + 'static>(
        session_id: Option<SessionId>,
        ca: Arc<Mutex<CaStore<P>>>,
        on_reject: ProxyOnReject,
    ) -> Result<Self, MitmError> {
        if ca.lock().map(|store| store.info().is_err()).unwrap_or(true) {
            return Err(MitmError::Ca("no session CA is loaded".to_owned()));
        }
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|err| MitmError::Bind(err.kind().to_string()))?;
        let local = listener
            .local_addr()
            .map_err(|err| MitmError::Bind(err.kind().to_string()))?;

        let (event_tx, events) = mpsc::unbounded_channel();
        let (stop_tx, stop_rx) = oneshot::channel();
        // Built once, up front. If ring cannot make a config at all, bind fails
        // here instead of panicking inside a handshake.
        let refuse = refusing_server_config()?;
        let authority = SessionAuthority { ca, refuse };
        let handler = RecordingHandler {
            session_id,
            on_reject,
            events: event_tx,
            pending: HashMap::new(),
            next_req: 0,
        };

        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(authority)
            .with_rustls_connector(rustls::crypto::ring::default_provider())
            .with_http_handler(handler)
            .with_graceful_shutdown(async move {
                let _ = stop_rx.await;
            })
            .build()
            .map_err(|err| MitmError::Tls(err.to_string()))?;

        tokio::spawn(async move {
            // The error text from hudsucker can include the target URL, so it is
            // not logged. The listener stopping is observable: `recv` returns
            // `None` once the channel closes.
            let _ = proxy.start().await;
        });

        Ok(Self {
            local,
            shutdown: Some(stop_tx),
            events,
        })
    }

    /// The address the operating system chose. The port is the attribution key.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Next recorded exchange, if one has completed.
    pub async fn recv(&mut self) -> Option<MitmOutput> {
        self.events.recv().await
    }
}

impl Drop for MitmProxy {
    fn drop(&mut self) {
        if let Some(stop) = self.shutdown.take() {
            let _ = stop.send(());
        }
    }
}

/// Signs leaves with the session CA. The private key never leaves [`CaStore`]'s
/// memory: this type only borrows it long enough to build a [`ServerConfig`].
struct SessionAuthority<P: KeyProtector> {
    ca: Arc<Mutex<CaStore<P>>>,
    /// Served when a leaf cannot be signed. Fails the handshake closed.
    refuse: Arc<ServerConfig>,
}

impl<P: KeyProtector + Send + 'static> CertificateAuthority for SessionAuthority<P> {
    async fn gen_server_config(&self, authority: &http::uri::Authority) -> Arc<ServerConfig> {
        let host = authority.host();
        // No clock means no expiry can be checked, so no leaf is signed. Falling
        // through to `empty_server_config` makes the handshake fail rather than
        // presenting a certificate dated at the Unix epoch.
        let signed = crate::ca::unix_now().and_then(|now| {
            self.ca
                .lock()
                .ok()
                .and_then(|mut store| store.leaf_for(host, now).ok())
        });
        signed
            .and_then(|leaf| server_config(&leaf).ok())
            .unwrap_or_else(|| Arc::clone(&self.refuse))
    }
}

fn server_config(leaf: &LeafCert) -> Result<Arc<ServerConfig>, MitmError> {
    let der = cert_der(&leaf.cert_pem)?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key_pkcs8.to_vec()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| MitmError::Tls(err.to_string()))?
        .with_no_client_auth()
        .with_single_cert(vec![der], key)
        .map_err(|err| MitmError::Tls(err.to_string()))?;
    Ok(Arc::new(config))
}

fn refusing_server_config() -> Result<Arc<ServerConfig>, MitmError> {
    // The handshake must fail closed. An empty chain is not a valid rustls
    // config, and a config that accepts any client is worse than no proxy, so
    // this instead presents a certificate the session CA never signed. A client
    // that trusts only the session CA rejects it; nothing here disables
    // verification or falls back to plaintext.
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::NoCa;
    let key = rcgen::KeyPair::generate().ok();
    let cert = key.as_ref().and_then(|key| params.self_signed(key).ok());
    match (cert, key) {
        (Some(cert), Some(key)) => {
            let der = CertificateDer::from(cert.der().to_vec());
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
            server_config_from(vec![der], key)
        }
        _ => Err(MitmError::Tls(
            "could not build a refusing certificate".to_owned(),
        )),
    }
}

fn server_config_from(
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, MitmError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| MitmError::Tls(err.to_string()))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|err| MitmError::Tls(err.to_string()))?;
    Ok(Arc::new(config))
}

fn cert_der(pem_text: &str) -> Result<CertificateDer<'static>, MitmError> {
    let parsed = pem::parse(pem_text).map_err(|err| MitmError::Ca(err.to_string()))?;
    if parsed.tag() != "CERTIFICATE" {
        return Err(MitmError::Ca("leaf pem was not a certificate".to_owned()));
    }
    Ok(CertificateDer::from(parsed.into_contents()))
}

/// Counts bytes and records metadata. Holds no body.
#[derive(Clone)]
struct RecordingHandler {
    session_id: Option<SessionId>,
    on_reject: ProxyOnReject,
    events: mpsc::UnboundedSender<MitmOutput>,
    /// Per client address: the request half, kept until its response arrives.
    /// Only one request is in flight per connection, which is what hudsucker
    /// guarantees by handing the pair to the same handler instance.
    pending: HashMap<SocketAddr, PendingRequest>,
    next_req: u64,
}

/// Request metadata held between `handle_request` and `handle_response`.
#[derive(Clone)]
struct PendingRequest {
    id: u64,
    started: Instant,
    meta: RequestMeta,
}

impl HttpHandler for RecordingHandler {
    async fn handle_request(
        &mut self,
        ctx: &HttpContext,
        req: Request<hudsucker::Body>,
    ) -> RequestOrResponse {
        let id = self.next_req;
        self.next_req = self.next_req.saturating_add(1);

        let (parts, body) = req.into_parts();
        let collected = body.collect().await.ok();
        let body_bytes = collected.as_ref().map(c_size);
        let request = RequestMeta {
            method: parts.method.to_string(),
            url: absolute_url(&parts),
            http_version: version_label(parts.version),
            headers: header_pairs(&parts.headers),
            body_bytes,
            client: aw_core::SocketAddr::socket(ctx.client_addr),
        };
        self.pending.insert(
            ctx.client_addr,
            PendingRequest {
                id,
                started: Instant::now(),
                meta: request,
            },
        );

        // The body has been counted and is forwarded. Only its length is kept.
        let rebuilt = collected.map(|c| c.to_bytes()).unwrap_or_default();
        Request::from_parts(parts, hudsucker::Body::from(rebuilt)).into()
    }

    async fn handle_response(
        &mut self,
        ctx: &HttpContext,
        res: Response<hudsucker::Body>,
    ) -> Response<hudsucker::Body> {
        let pending = self.pending.remove(&ctx.client_addr);
        let req_id = pending.as_ref().map(|p| p.id).unwrap_or(0);
        let duration_ms = pending
            .as_ref()
            .and_then(|p| u32::try_from(p.started.elapsed().as_millis()).ok());

        let (parts, body) = res.into_parts();
        let collected = body.collect().await.ok();
        let body_bytes = collected.as_ref().map(c_size);
        let response = ResponseMeta {
            status: Some(parts.status.as_u16()),
            headers: header_pairs(&parts.headers),
            body_bytes,
            duration_ms,
        };

        // No matching request means the response arrived without one. The URL is
        // then unknown, which `record_exchange` records as absent rather than empty.
        let request = pending.map(|p| p.meta).unwrap_or(RequestMeta {
            method: String::new(),
            url: String::new(),
            http_version: String::new(),
            headers: Vec::new(),
            body_bytes: None,
            client: aw_core::SocketAddr::socket(ctx.client_addr),
        });
        let recorded = record_exchange(req_id, request, Some(response), None, None);
        if let Ok(events) = to_events(&recorded, req_id, 0, 0, self.session_id) {
            let _ = self.events.send(MitmOutput { events, recorded });
        }

        let rebuilt = collected.map(|c| c.to_bytes()).unwrap_or_default();
        Response::from_parts(parts, hudsucker::Body::from(rebuilt))
    }

    async fn should_intercept_tls(&mut self, ctx: &HttpContext, _hello: ClientHello<'_>) -> bool {
        // `tunnel` means the client pinned a certificate and we let the bytes
        // through without recording a URL. The decision is per session, not per
        // handshake: this build cannot tell a pin from any other TLS failure
        // until the handshake runs, and by then the choice is already made.
        let _ = ctx;
        self.on_reject != ProxyOnReject::Tunnel
    }
}

impl WebSocketHandler for RecordingHandler {
    async fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        message: hudsucker::tokio_tungstenite::tungstenite::Message,
    ) -> Option<hudsucker::tokio_tungstenite::tungstenite::Message> {
        // Frame payload is not recorded. Only its length, and only when the
        // recorder is asked. This handler forwards unchanged.
        let _ = (ctx, message.len_for_count());
        Some(message)
    }
}

trait MessageLen {
    fn len_for_count(&self) -> usize;
}

impl MessageLen for hudsucker::tokio_tungstenite::tungstenite::Message {
    fn len_for_count(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Binary(bytes) => bytes.len(),
            Self::Ping(bytes) | Self::Pong(bytes) => bytes.len(),
            Self::Close(_) | Self::Frame(_) => 0,
        }
    }
}

fn c_size(collected: &http_body_util::Collected<hyper::body::Bytes>) -> u64 {
    use hyper::body::Body;
    collected.size_hint().lower()
}

fn header_pairs(headers: &http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_owned(), v.to_owned()))
        })
        .collect()
}

fn version_label(version: Version) -> String {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2",
        Version::HTTP_3 => "HTTP/3",
        _ => "HTTP",
    }
    .to_owned()
}

fn absolute_url(parts: &http::request::Parts) -> String {
    if parts.method == http::Method::CONNECT {
        return format!("https://{}", parts.uri);
    }
    if parts.uri.scheme().is_some() {
        return parts.uri.to_string();
    }
    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if host.is_empty() {
        parts.uri.to_string()
    } else {
        format!("http://{host}{}", parts.uri)
    }
}

/// Silence the unused import warning for types the recorder grows into.
#[allow(dead_code)]
fn _uses(uri: Uri, gap: UrlGap, ws: WsCounts, err: CaError) {
    let _ = (uri, gap, ws, err);
}
