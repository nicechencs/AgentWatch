//! Daemon client.
//!
//! The transport is a trait so tests can answer HTTP without a socket. The
//! production transport ([`LoopbackHttp`]) speaks the loopback stub in
//! `aw-daemon`'s `api/routes.rs`: `GET`/`POST`, a `Host` of `127.0.0.1:<port>`
//! or `localhost:<port>`, and `Authorization: Bearer <token>`. Unix sockets and
//! named pipes are the CLI's real channel (api-and-cli §1) but this daemon
//! build does not listen on them, so those endpoints return
//! [`ClientError::Unreachable`] instead of pretending a connection succeeded.
//!
//! No request is sent unless [`Client::call`] is used. The binary's `--help`
//! path never constructs a client.

use std::fmt;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use serde_json::Value;

use crate::endpoint::{token_hint, Endpoint, HttpBase};
use crate::exit::{self, from_http_status};

/// One HTTP request, already decided by a command. Header values are not logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRequest {
    /// `GET`, `POST`, …
    pub method: String,
    /// Path beginning with `/`, no query string.
    pub path: String,
    /// Raw query without `?`. Empty when absent.
    pub query: String,
    /// JSON body. Empty for GET.
    pub body: Vec<u8>,
}

impl ApiRequest {
    /// `GET <path>` with no query and no body.
    #[must_use]
    pub fn get(path: &str) -> Self {
        Self {
            method: "GET".to_owned(),
            path: path.to_owned(),
            query: String::new(),
            body: Vec::new(),
        }
    }

    /// `POST <path>` with a JSON body.
    #[must_use]
    #[allow(dead_code)]
    pub fn post_json(path: &str, body: &Value) -> Self {
        Self::json_method("POST", path, body)
    }

    /// `PUT <path>` with a JSON body. Used by `aw config set` (`PUT /config`).
    #[must_use]
    pub fn put_json(path: &str, body: &Value) -> Self {
        Self::json_method("PUT", path, body)
    }

    /// `GET <path>?<query>`. `query` is the raw string without `?`.
    #[must_use]
    pub fn get_query(path: &str, query: impl Into<String>) -> Self {
        Self {
            method: "GET".to_owned(),
            path: path.to_owned(),
            query: query.into(),
            body: Vec::new(),
        }
    }

    fn json_method(method: &str, path: &str, body: &Value) -> Self {
        let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            query: String::new(),
            body: bytes,
        }
    }
}

/// Status and body from one exchange. Response headers are not kept: this card
/// only needs the status and the JSON the stub returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiReply {
    /// HTTP status.
    pub status: u16,
    /// Body bytes. JSON for the daemon stub.
    pub body: Vec<u8>,
}

impl ApiReply {
    /// Parse the body as JSON. Invalid JSON is a transport-level decode error
    /// expressed as `None`, not a panic.
    #[must_use]
    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

/// Something that can exchange one request. Implementations must not log tokens.
pub trait Transport {
    /// Send `request` and return the status and body.
    ///
    /// # Errors
    ///
    /// [`ClientError::Unreachable`] when nothing is listening.
    /// [`ClientError::Transport`] for a broken exchange.
    fn exchange(&mut self, request: &ApiRequest) -> Result<ApiReply, ClientError>;
}

impl Transport for Box<dyn Transport> {
    fn exchange(&mut self, request: &ApiRequest) -> Result<ApiReply, ClientError> {
        self.as_mut().exchange(request)
    }
}

/// Why a call did not produce a successful reply.
///
/// `Display` never includes a token. HTTP failures include [`token_hint`] only.
#[derive(Debug)]
pub enum ClientError {
    /// The daemon did not answer. Exit 3.
    Unreachable { detail: String },
    /// The exchange failed after connect. Exit 1.
    Transport { detail: String },
    /// The daemon answered with a non-success status.
    Status {
        /// HTTP status.
        status: u16,
        /// Short message taken from the JSON body, or a fallback. No token.
        message: String,
    },
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable { detail } => write!(
                f,
                "daemon unreachable ({detail}). Start it with `aw daemon start`, or pass --no-daemon (polling collectors, all evidence S)"
            ),
            Self::Transport { detail } => write!(f, "daemon request failed: {detail}"),
            Self::Status { status, message } => {
                write!(f, "daemon returned HTTP {status}: {message}")
            }
        }
    }
}

impl std::error::Error for ClientError {}

impl ClientError {
    /// Exit code for this failure.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Unreachable { .. } => exit::UNREACHABLE,
            Self::Transport { .. } => exit::GENERAL,
            Self::Status { status, .. } => from_http_status(*status),
        }
    }
}

/// Client bound to one endpoint and one transport.
pub struct Client<T: Transport> {
    endpoint: Endpoint,
    transport: T,
}

impl<T: Transport> Client<T> {
    /// Bind `transport` to `endpoint`. Does not connect.
    #[must_use]
    pub fn new(endpoint: Endpoint, transport: T) -> Self {
        Self {
            endpoint,
            transport,
        }
    }

    /// The resolved endpoint. Display it; do not debug-print it (HTTP carries a token).
    #[must_use]
    #[allow(dead_code)]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Exchange `request`. A 2xx reply is returned. Anything else is an error
    /// whose exit code matches the status.
    ///
    /// # Errors
    ///
    /// [`ClientError::Unreachable`] for socket and pipe endpoints in this card
    /// (the daemon stub does not listen there) and for a refused HTTP connect.
    /// [`ClientError::Status`] when the daemon answers with a non-2xx status.
    pub fn call(&mut self, request: &ApiRequest) -> Result<ApiReply, ClientError> {
        match &self.endpoint {
            Endpoint::Unix { path } => Err(ClientError::Unreachable {
                detail: format!(
                    "unix socket {} is the CLI channel, but this daemon build has no socket listener",
                    path.display()
                ),
            }),
            Endpoint::Pipe { path } => Err(ClientError::Unreachable {
                detail: format!(
                    "named pipe {} is the CLI channel, but this daemon build has no pipe listener",
                    path.display()
                ),
            }),
            Endpoint::Http { .. } => {
                let reply = self.transport.exchange(request)?;
                if (200..300).contains(&reply.status) {
                    Ok(reply)
                } else {
                    Err(ClientError::Status {
                        status: reply.status,
                        message: status_message(&reply),
                    })
                }
            }
        }
    }
}

fn status_message(reply: &ApiReply) -> String {
    let Some(value) = reply.json() else {
        return format!("non-JSON body, {} bytes", reply.body.len());
    };
    if let Some(message) = value
        .get("error")
        .and_then(|err| err.get("message"))
        .and_then(Value::as_str)
    {
        return message.to_owned();
    }
    if let Some(code) = value.get("error").and_then(Value::as_str) {
        let op = value.get("op").and_then(Value::as_str).unwrap_or("");
        if op.is_empty() {
            return code.to_owned();
        }
        return format!("{code} ({op})");
    }
    format!("HTTP {}", reply.status)
}

/// Production HTTP transport. Dials `127.0.0.1` only, writes one HTTP/1.1
/// request, reads one response, and drops the socket.
///
/// The bearer token is written to the socket and nowhere else. Connect failures
/// name the host and port, never the token.
#[derive(Clone)]
pub struct LoopbackHttp {
    base: HttpBase,
    token: String,
    timeout: Duration,
}

impl LoopbackHttp {
    /// Transport for `endpoint`. Non-HTTP endpoints still construct, and fail at
    /// [`Transport::exchange`] time: the caller should have used [`Client::call`],
    /// which refuses them first.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] when `endpoint` is not HTTP. That is a programming
    /// error, not a missing daemon.
    pub fn new(endpoint: &Endpoint) -> Result<Self, ClientError> {
        match endpoint {
            Endpoint::Http { base, token } => Ok(Self {
                base: base.clone(),
                token: token.clone(),
                timeout: Duration::from_secs(2),
            }),
            Endpoint::Unix { .. } | Endpoint::Pipe { .. } => Err(ClientError::Transport {
                detail: "LoopbackHttp only dials an http endpoint".to_owned(),
            }),
        }
    }
}

impl Transport for LoopbackHttp {
    fn exchange(&mut self, request: &ApiRequest) -> Result<ApiReply, ClientError> {
        if self.base.host.eq_ignore_ascii_case("localhost") {
            // The stub accepts a Host of `localhost:<port>`, but the TCP dial
            // stays numeric so a DNS answer cannot redirect it.
        }
        let addr = SocketAddr::from(([127, 0, 0, 1], self.base.port));
        let mut stream = TcpStream::connect_timeout(&addr, self.timeout).map_err(|_| {
            ClientError::Unreachable {
                detail: format!(
                    "tcp connect to {} timed out or was refused (token {})",
                    self.base.origin(),
                    token_hint(&self.token)
                ),
            }
        })?;
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|err| ClientError::Transport {
                detail: format!("set read timeout: {err}"),
            })?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|err| ClientError::Transport {
                detail: format!("set write timeout: {err}"),
            })?;
        let bytes = encode_request(&self.base, &self.token, request);
        stream
            .write_all(&bytes)
            .map_err(|err| ClientError::Transport {
                detail: format!("write request: {err}"),
            })?;
        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .map_err(|err| ClientError::Transport {
                detail: format!("read response: {err}"),
            })?;
        parse_response(&buf).map_err(|detail| ClientError::Transport { detail })
    }
}

/// HTTP/1.1 request bytes. `Authorization` is included. Callers must not log `bytes`.
fn encode_request(base: &HttpBase, token: &str, request: &ApiRequest) -> Vec<u8> {
    let path = if request.query.is_empty() {
        request.path.clone()
    } else {
        format!("{}?{}", request.path, request.query)
    };
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\nAccept: application/json\r\n",
        method = request.method,
        path = path,
        host = base.host_header(),
        token = token,
    );
    if !request.body.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(&format!("Content-Length: {}\r\n", request.body.len()));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(&request.body);
    out
}

fn parse_response(bytes: &[u8]) -> Result<ApiReply, String> {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "HTTP response has no header terminator".to_owned())?;
    let head = std::str::from_utf8(&bytes[..split])
        .map_err(|_| "HTTP response headers are not UTF-8".to_owned())?;
    let body = bytes[split + 4..].to_vec();
    let status_line = head.lines().next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(format!("not an HTTP status line: `{status_line}`"));
    }
    let code = parts
        .next()
        .unwrap_or("")
        .parse::<u16>()
        .map_err(|_| format!("HTTP status is not a number in `{status_line}`"))?;
    Ok(ApiReply { status: code, body })
}

/// In-memory transport. Records the request it was given (no token: tokens are
/// not part of [`ApiRequest`]) and returns a scripted reply or error.
#[derive(Debug, Default)]
pub struct MemoryTransport {
    /// Requests in call order.
    pub seen: Vec<ApiRequest>,
    next: MemoryScript,
}

/// What the next [`MemoryTransport::exchange`] does.
#[derive(Debug, Default)]
#[allow(dead_code)]
enum MemoryScript {
    Reply(ApiReply),
    Err(String),
    #[default]
    Empty,
}

impl MemoryTransport {
    /// Answer every exchange with `status` and `body`.
    #[must_use]
    #[allow(dead_code)]
    pub fn replying(status: u16, body: Vec<u8>) -> Self {
        Self {
            seen: Vec::new(),
            next: MemoryScript::Reply(ApiReply { status, body }),
        }
    }

    /// Fail every exchange as unreachable, with `detail` (no token text).
    #[must_use]
    #[allow(dead_code)]
    pub fn failing(detail: impl Into<String>) -> Self {
        Self {
            seen: Vec::new(),
            next: MemoryScript::Err(detail.into()),
        }
    }
}

impl Transport for MemoryTransport {
    fn exchange(&mut self, request: &ApiRequest) -> Result<ApiReply, ClientError> {
        self.seen.push(request.clone());
        match &self.next {
            MemoryScript::Reply(reply) => Ok(reply.clone()),
            MemoryScript::Err(detail) => Err(ClientError::Unreachable {
                detail: detail.clone(),
            }),
            MemoryScript::Empty => Err(ClientError::Transport {
                detail: "memory transport has no scripted reply".to_owned(),
            }),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{encode_request, parse_response, token_hint, ApiRequest, Client, MemoryTransport};
    use crate::endpoint::{resolve, EndpointInput};
    use crate::exit;

    fn http_endpoint() -> crate::endpoint::Endpoint {
        resolve(&EndpointInput {
            socket: None,
            http: Some("http://127.0.0.1:7456".to_owned()),
            token: Some("unit-test-token-ABCD".to_owned()),
            token_env: None,
        })
        .expect("endpoint")
    }

    #[test]
    fn memory_success_records_the_request_and_not_the_token() {
        let body = br#"{"status":"ok"}"#.to_vec();
        let transport = MemoryTransport::replying(200, body.clone());
        let mut client = Client::new(http_endpoint(), transport);
        let reply = client.call(&ApiRequest::get("/health")).expect("call");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, body);
        let seen = &client.transport.seen;
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, "/health");
        let dumped = format!("{seen:?}");
        assert!(!dumped.contains("unit-test-token"), "{dumped}");
    }

    #[test]
    fn memory_401_is_permission_and_hides_the_token() {
        let body =
            br#"{"error":{"code":"unauthorized","message":"bearer token required"}}"#.to_vec();
        let transport = MemoryTransport::replying(401, body);
        let mut client = Client::new(http_endpoint(), transport);
        let err = client
            .call(&ApiRequest::get("/api/v1/sessions"))
            .expect_err("401");
        assert_eq!(err.exit_code(), exit::PERMISSION);
        let text = err.to_string();
        assert!(text.contains("401"), "{text}");
        assert!(text.contains("bearer token required"), "{text}");
        assert!(!text.contains("unit-test-token"), "{text}");
        assert!(!text.contains("ABCD") || text.contains("len="), "{text}");
        let _ = token_hint("unit-test-token-ABCD");
    }

    #[test]
    fn socket_endpoint_is_unreachable_without_dialing() {
        let endpoint = resolve(&EndpointInput {
            socket: Some("/tmp/does-not-exist.sock".to_owned()),
            http: None,
            token: None,
            token_env: None,
        })
        .expect("socket");
        let mut client = Client::new(endpoint, MemoryTransport::replying(200, Vec::new()));
        let err = client
            .call(&ApiRequest::get("/health"))
            .expect_err("socket");
        assert_eq!(err.exit_code(), exit::UNREACHABLE);
        let text = err.to_string();
        assert!(text.contains("aw daemon start"), "{text}");
        assert!(text.contains("--no-daemon"), "{text}");
        assert!(
            client.transport.seen.is_empty(),
            "socket path must not hit the transport"
        );
    }

    #[test]
    fn encode_request_carries_host_and_bearer_and_parse_roundtrips() {
        let endpoint = http_endpoint();
        let (base, token) = match &endpoint {
            crate::endpoint::Endpoint::Http { base, token } => (base, token.as_str()),
            _ => panic!("http"),
        };
        let bytes = encode_request(base, token, &ApiRequest::get("/health"));
        let text = String::from_utf8(bytes.clone()).expect("utf8");
        assert!(text.starts_with("GET /health HTTP/1.1\r\n"), "{text}");
        assert!(text.contains("Host: 127.0.0.1:7456\r\n"), "{text}");
        assert!(
            text.contains("Authorization: Bearer unit-test-token-ABCD\r\n"),
            "{text}"
        );
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}";
        let reply = parse_response(raw).expect("parse");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, br#"{"status":"ok"}"#);
    }
}
