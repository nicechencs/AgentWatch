//! Daemon client.
//!
//! The transport is a trait so tests can answer HTTP without a socket. The
//! production transport ([`LoopbackHttp`]) writes one HTTP/1.1 request to the
//! daemon and reads one response. On the internal channel (Unix socket or
//! named pipe, api-and-cli §1) no `Authorization` is sent: the daemon
//! identifies the peer by its OS credential. On loopback HTTP the request
//! carries a `Host` of `127.0.0.1:<port>` or `localhost:<port>` and
//! `Authorization: Bearer <token>`. A socket or pipe nobody listens on is
//! [`ClientError::Unreachable`] (exit 3), not a pretend success.
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

    /// `PATCH` or another JSON method. Used by session rename and pin.
    #[must_use]
    pub fn json_method_public(method: &str, path: &str, body: &Value) -> Self {
        Self::json_method(method, path, body)
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
    /// The socket or pipe exists but this account may not open it. Exit 4.
    Forbidden { detail: String },
    /// The exchange failed after connect. Exit 1.
    Transport { detail: String },
    /// The daemon answered with a non-success status.
    Status {
        /// HTTP status.
        status: u16,
        /// Daemon machine error code, when the JSON error object provided one.
        code: Option<String>,
        /// Short message taken from the JSON body, or a fallback. No token.
        message: String,
    },
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable { detail } => write!(
                f,
                "连不上后台，请先运行 `aw daemon start`，或加 --no-daemon（本地轮询采集，证据 S）。详情：{detail}"
            ),
            Self::Forbidden { detail } => write!(
                f,
                "后台在运行，但这个账户没有权限打开它的通道。请让管理员把你加入 agentwatch 组（Windows：AgentWatch Users）。详情：{detail}"
            ),
            Self::Transport { detail } => write!(f, "向后台发请求失败：{detail}"),
            Self::Status {
                status,
                code,
                message,
            } => crate::daemon_errors::write_status(f, *status, code.as_deref(), message),
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
            Self::Forbidden { .. } => exit::PERMISSION,
            Self::Transport { .. } => exit::GENERAL,
            Self::Status { status, .. } => from_http_status(*status),
        }
    }
}

/// Client bound to one endpoint and one transport.
pub struct Client<T: Transport> {
    endpoint: Endpoint,
    /// The transport. Public so a caller that lends one can take it back
    /// after [`Self::call`].
    pub transport: T,
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
    /// [`ClientError::Unreachable`] when nothing answers on the socket, pipe,
    /// or loopback port.
    /// [`ClientError::Status`] when the daemon answers with a non-2xx status.
    pub fn call(&mut self, request: &ApiRequest) -> Result<ApiReply, ClientError> {
        let reply = self.transport.exchange(request)?;
        if (200..300).contains(&reply.status) {
            Ok(reply)
        } else {
            Err(ClientError::Status {
                status: reply.status,
                code: status_code(&reply),
                message: status_message(&reply),
            })
        }
    }
}

fn status_message(reply: &ApiReply) -> String {
    let Some(value) = reply.json() else {
        return format!("非 JSON 响应体，{} 字节", reply.body.len());
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

fn status_code(reply: &ApiReply) -> Option<String> {
    reply
        .json()
        .and_then(|value| value.get("error")?.get("code")?.as_str().map(str::to_owned))
}

/// Production HTTP transport. Dials `127.0.0.1` only, writes one HTTP/1.1
/// request, reads one response, and drops the socket.
///
/// The bearer token is written to the socket and nowhere else. Connect failures
/// name the host and port, never the token.
#[derive(Clone)]
pub struct LoopbackHttp {
    target: Target,
    timeout: Duration,
}

/// Where [`LoopbackHttp`] dials.
#[derive(Clone)]
enum Target {
    Http { base: HttpBase, token: String },
    Socket { path: std::path::PathBuf },
    Pipe { path: std::path::PathBuf },
}

impl LoopbackHttp {
    /// Transport for `endpoint`. Does not dial.
    ///
    /// # Errors
    ///
    /// Never today. Kept fallible so callers do not change when a transport
    /// needs setup.
    pub fn new(endpoint: &Endpoint) -> Result<Self, ClientError> {
        let target = match endpoint {
            Endpoint::Http { base, token } => Target::Http {
                base: base.clone(),
                token: token.clone(),
            },
            Endpoint::Unix { path } => Target::Socket { path: path.clone() },
            Endpoint::Pipe { path } => Target::Pipe { path: path.clone() },
        };
        Ok(Self {
            target,
            timeout: Duration::from_secs(5),
        })
    }
}

impl Transport for LoopbackHttp {
    fn exchange(&mut self, request: &ApiRequest) -> Result<ApiReply, ClientError> {
        match &self.target {
            Target::Http { base, token } => http_exchange(base, token, self.timeout, request),
            Target::Socket { path } => socket_exchange(path, self.timeout, request),
            Target::Pipe { path } => pipe_exchange(path, request),
        }
    }
}

fn http_exchange(
    base: &HttpBase,
    token: &str,
    timeout: Duration,
    request: &ApiRequest,
) -> Result<ApiReply, ClientError> {
    // The dial stays numeric even for `localhost`, so a DNS answer cannot redirect it.
    let addr = SocketAddr::from(([127, 0, 0, 1], base.port));
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|_| ClientError::Unreachable {
            detail: format!(
                "连接 {} 超时或被拒绝（token {}）",
                base.origin(),
                token_hint(token)
            ),
        })?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| ClientError::Transport {
            detail: format!("设置读取超时失败：{err}"),
        })?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| ClientError::Transport {
            detail: format!("设置写入超时失败：{err}"),
        })?;
    let bytes = encode_request(base, token, request);
    roundtrip(&mut stream, &bytes)
}

fn socket_exchange(
    path: &std::path::Path,
    timeout: Duration,
    request: &ApiRequest,
) -> Result<ApiReply, ClientError> {
    local_exchange(path, timeout, request)
}

/// Socket and pipe both go through aw-channel, the client the desktop app
/// uses too: same error classes, pipe-busy retry, and timeout.
fn pipe_exchange(path: &std::path::Path, request: &ApiRequest) -> Result<ApiReply, ClientError> {
    local_exchange(path, aw_channel::TIMEOUT, request)
}

fn local_exchange(
    path: &std::path::Path,
    timeout: Duration,
    request: &ApiRequest,
) -> Result<ApiReply, ClientError> {
    use aw_channel::DialError;
    // A default path expands to the documented order (system, then per-user):
    // a stale system socket must not hide a live per-user daemon.
    let order = aw_channel::dial_order(path, &|key| std::env::var(key).ok());
    let (_, reply) = aw_channel::exchange_first(&order, &encode_local_request(request), timeout)
        .map_err(|err| match err {
            DialError::Unreachable(detail) => ClientError::Unreachable { detail },
            DialError::Forbidden(detail) => ClientError::Forbidden { detail },
            other => ClientError::Transport {
                detail: other.to_string(),
            },
        })?;
    Ok(ApiReply {
        status: reply.status,
        body: reply.body,
    })
}

fn roundtrip<S: Read + Write>(stream: &mut S, bytes: &[u8]) -> Result<ApiReply, ClientError> {
    stream
        .write_all(bytes)
        .map_err(|err| ClientError::Transport {
            detail: format!("写入请求失败：{err}"),
        })?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .map_err(|err| ClientError::Transport {
            detail: format!("读取响应失败：{err}"),
        })?;
    parse_response(&buf).map_err(|detail| ClientError::Transport { detail })
}

/// Request bytes for the socket or pipe: no `Authorization`, the peer
/// credential is the identity.
fn encode_local_request(request: &ApiRequest) -> Vec<u8> {
    let path = if request.query.is_empty() {
        request.path.clone()
    } else {
        format!("{}?{}", request.path, request.query)
    };
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: agentwatch.local\r\nConnection: close\r\nAccept: application/json\r\nContent-Length: {len}\r\n",
        method = request.method,
        len = request.body.len(),
    );
    if !request.body.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(&request.body);
    out
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
        .ok_or_else(|| "HTTP 响应没有头部结束符".to_owned())?;
    let head =
        std::str::from_utf8(&bytes[..split]).map_err(|_| "HTTP 响应头不是 UTF-8".to_owned())?;
    let body = bytes[split + 4..].to_vec();
    let status_line = head.lines().next().unwrap_or("");
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(format!("不是 HTTP 状态行：`{status_line}`"));
    }
    let code = parts
        .next()
        .unwrap_or("")
        .parse::<u16>()
        .map_err(|_| format!("HTTP 状态行中的状态码不是数字：`{status_line}`"))?;
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
    use super::{
        encode_request, parse_response, token_hint, ApiRequest, Client, ClientError,
        MemoryTransport,
    };
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
        assert!(text.contains("没有通过后台的身份验证"), "{text}");
        assert!(text.contains("bearer token required"), "{text}");
        assert!(!text.contains("unit-test-token"), "{text}");
        assert!(!text.contains("ABCD") || text.contains("len="), "{text}");
        let _ = token_hint("unit-test-token-ABCD");
    }

    #[test]
    fn missing_socket_is_unreachable_exit_3() {
        let endpoint = resolve(&EndpointInput {
            socket: Some("/tmp/aw-does-not-exist.sock".to_owned()),
            http: None,
            token: None,
            token_env: None,
        })
        .expect("socket");
        let transport = super::LoopbackHttp::new(&endpoint).expect("transport");
        let mut client = Client::new(endpoint, transport);
        let err = client
            .call(&ApiRequest::get("/health"))
            .expect_err("socket");
        assert_eq!(err.exit_code(), exit::UNREACHABLE);
        let text = err.to_string();
        assert!(text.contains("aw daemon start"), "{text}");
        assert!(text.contains("--no-daemon"), "{text}");
    }

    #[test]
    fn unreachable_message_starts_with_the_daemon_instruction_and_keeps_detail() {
        let detail = "x.sock: connection refused";
        let text = ClientError::Unreachable {
            detail: detail.to_owned(),
        }
        .to_string();
        assert!(
            text.starts_with("连不上后台，请先运行 `aw daemon start`"),
            "{text}"
        );
        assert!(text.contains(detail), "{text}");
    }

    /// The bug: socket endpoints were refused before any dial, so `aw` could
    /// never reach a daemon on its documented channel.
    #[cfg(unix)]
    #[test]
    fn socket_endpoint_dials_and_sends_no_bearer() {
        use std::io::{Read, Write};
        let dir = aw_channel::short_temp_dir("cli");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("api.sock");
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0_u8; 4096];
            let n = stream.read(&mut buf).expect("read");
            let seen = String::from_utf8_lossy(&buf[..n]).into_owned();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"status\":\"ok\"}",
                )
                .expect("write");
            seen
        });
        let endpoint = resolve(&EndpointInput {
            socket: Some(path.display().to_string()),
            http: None,
            token: Some("unit-test-token-ABCD".to_owned()),
            token_env: None,
        })
        .expect("socket");
        let transport = super::LoopbackHttp::new(&endpoint).expect("transport");
        let mut client = Client::new(endpoint, transport);
        let reply = client.call(&ApiRequest::get("/health")).expect("call");
        assert_eq!(reply.status, 200);
        let seen = server.join().expect("join");
        assert!(seen.starts_with("GET /health HTTP/1.1\r\n"), "{seen}");
        assert!(
            !seen.to_ascii_lowercase().contains("authorization"),
            "{seen}"
        );
        let _ = std::fs::remove_dir_all(&dir);
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
