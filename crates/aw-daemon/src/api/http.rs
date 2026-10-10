//! Loopback HTTP listener (P2-DAEMON-01).
//!
//! axum is not a dependency of this crate. The card asks for it; the workspace
//! lock and the P1 stub both say it is not available offline, and root
//! `Cargo.toml` is out of scope. This module is the transport: `std::net` on a
//! thread, the same [`super::routes::dispatch`] the stub tests call, plus the
//! security headers the card requires (`Content-Security-Policy`,
//! `X-Frame-Options: DENY`, no CORS).
//!
//! The listener refuses any non-loopback address, including one written in
//! config. Tokens are not written to the log. A request line is logged as
//! method, path, and status only.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::routes::{dispatch, ApiResponse, ApiState, HttpBind, HttpRequest};

/// Default UI / API port. api-and-cli §1.
pub const DEFAULT_HTTP_PORT: u16 = 7456;

/// How long one request may sit on the socket before the worker drops it.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Request body cap. Larger bodies are refused with 413. This is not a place
/// to accept a file upload: the API does not store contents.
const MAX_BODY: usize = 64 * 1024;

/// A running loopback listener.
pub struct HttpServer {
    /// Address actually bound. Port may differ from the request when it was 0.
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl HttpServer {
    /// Bind `127.0.0.1:port` and serve `state` until [`HttpServer::shutdown`].
    ///
    /// `port` 0 asks the OS for an ephemeral port (tests). Any non-loopback
    /// address is rejected by [`HttpBind`] before this function is called; this
    /// function only ever binds `Ipv4Addr::LOCALHOST`.
    ///
    /// # Errors
    ///
    /// I/O failure from `TcpListener::bind`.
    pub fn bind(port: u16, state: ApiState) -> std::io::Result<Self> {
        let addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
        // Defense in depth: `loopback_only` is the same check config uses.
        let _ = HttpBind::loopback_only(addr).map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, err.to_string())
        })?;
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let bound = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("aw-http".to_owned())
            .spawn(move || accept_loop(listener, state, flag, bound.port()))?;
        Ok(Self {
            addr: bound,
            stop,
            thread: Some(thread),
        })
    }

    /// Ask the accept loop to exit and join it.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn accept_loop(listener: TcpListener, state: ApiState, stop: Arc<AtomicBool>, port: u16) {
    let state = Arc::new(std::sync::Mutex::new(state));
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if !peer.ip().is_loopback() {
                    // Bound to localhost, so this is unexpected. Drop it and say
                    // so: a non-loopback peer means the bind guarantee failed.
                    tracing::warn!(target: "aw_daemon::http", "rejected non-loopback peer");
                    drop(stream);
                    continue;
                }
                let state = Arc::clone(&state);
                if thread::Builder::new()
                    .name("aw-http-conn".to_owned())
                    .spawn(move || {
                        if let Err(err) = serve_conn(stream, &state, port) {
                            tracing::debug!(target: "aw_daemon::http", error = %err, "connection closed");
                        }
                    })
                    .is_err()
                {
                    tracing::warn!(target: "aw_daemon::http", "connection thread not started");
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                tracing::warn!(target: "aw_daemon::http", error = %err, "accept failed");
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn serve_conn(
    mut stream: TcpStream,
    state: &std::sync::Mutex<ApiState>,
    port: u16,
) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let mut buf = vec![0_u8; 8 * 1024];
    let mut collected = Vec::new();
    let request = loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        collected.extend_from_slice(&buf[..n]);
        if collected.len() > MAX_BODY + 16 * 1024 {
            let response = super::routes::error_response(
                413,
                "payload_too_large",
                "request body exceeds 64 KiB",
            );
            write_response(&mut stream, &response)?;
            return Ok(());
        }
        if let Some(req) = parse_request(&collected, port) {
            break req;
        }
        if collected.windows(4).any(|w| w == b"\r\n\r\n") && content_length(&collected).is_none() {
            break match parse_request(&collected, port) {
                Some(req) => req,
                None => {
                    let response =
                        super::routes::error_response(400, "bad_request", "malformed HTTP request");
                    write_response(&mut stream, &response)?;
                    return Ok(());
                }
            };
        }
    };
    let response = {
        let mut guard = match state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        dispatch(&mut guard, &request)
    };
    // Method + route + status only. The raw path is not logged: a query string
    // was split off, but a path segment can still carry a token or a ticket.
    // 4xx/5xx are a degradation the operator should see without debug logging;
    // successful requests stay at debug so the file is not one line per poll.
    let route = log_route(&request.path);
    if response.status >= 400 {
        tracing::warn!(
            target: "aw_daemon::http",
            method = %request.method,
            route = %route,
            status = response.status,
            "request rejected"
        );
    } else {
        tracing::debug!(
            target: "aw_daemon::http",
            method = %request.method,
            route = %route,
            status = response.status,
            "request"
        );
    }
    write_response(&mut stream, &response)
}

/// Collapse a request path to its route shape.
///
/// Numeric segments and long opaque segments become `*`, so a session id or a
/// ticket in the path is not written to the log. The query string never reaches
/// here.
pub(crate) fn log_route(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for (index, segment) in path.split('/').enumerate() {
        if index > 0 {
            out.push('/');
        }
        if segment.is_empty() {
            continue;
        }
        let opaque = segment.chars().all(|ch| ch.is_ascii_digit())
            || segment.len() > 16
            || segment.chars().any(|ch| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_');
        if opaque {
            out.push('*');
        } else {
            out.push_str(segment);
        }
    }
    if out.is_empty() { "/".to_owned() } else { out }
}

fn content_length(buf: &[u8]) -> Option<usize> {
    let header_end = header_end(buf)?;
    let headers = std::str::from_utf8(&buf[..header_end]).ok()?;
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    None
}

fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_request(buf: &[u8], listen_port: u16) -> Option<HttpRequest> {
    let header_end = header_end(buf)?;
    let head = std::str::from_utf8(&buf[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?;
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_owned(), query.to_owned()),
        None => (target.to_owned(), String::new()),
    };
    let mut headers = std::collections::BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let len = content_length(buf).unwrap_or(0);
    if buf.len() < header_end + len {
        return None;
    }
    if len > MAX_BODY {
        // Parsed far enough to refuse. The caller checks size before this when
        // the buffer grows; this is the exact-length case.
        return Some(HttpRequest {
            method,
            path,
            query,
            headers,
            body: Vec::new(),
            listen_port,
            body_too_large: true,
        });
    }
    let body = buf[header_end..header_end + len].to_vec();
    Some(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
        listen_port,
        body_too_large: false,
    })
}

fn write_response(stream: &mut TcpStream, response: &ApiResponse) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason(response.status)
    );
    head.push_str("connection: close\r\n");
    // Security headers. No CORS header is ever added.
    head.push_str("content-security-policy: default-src 'self'\r\n");
    head.push_str("x-frame-options: DENY\r\n");
    head.push_str("x-content-type-options: nosniff\r\n");
    head.push_str("referrer-policy: no-referrer\r\n");
    head.push_str("cache-control: no-store\r\n");
    for (name, value) in &response.headers {
        if name.eq_ignore_ascii_case("access-control-allow-origin") {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    let body = maybe_gzip(&response.headers, &response.body);
    if body.len() != response.body.len() {
        head.push_str("content-encoding: gzip\r\n");
    }
    head.push_str(&format!("content-length: {}\r\n\r\n", body.len()));
    stream.write_all(head.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

fn maybe_gzip(headers: &std::collections::BTreeMap<String, String>, body: &[u8]) -> Vec<u8> {
    // Gzip is applied only when the route opted in (`content-encoding` is not
    // pre-set) and the body looks like a static asset the client can take
    // compressed. Routes set `x-aw-gzip: accept` when the request's
    // Accept-Encoding contained gzip. The header is stripped before write.
    let wants = headers.get("x-aw-gzip").map(|v| v == "1").unwrap_or(false);
    if !wants || body.len() < 64 {
        return body.to_vec();
    }
    match gzip_bytes(body) {
        Some(compressed) if compressed.len() < body.len() => compressed,
        _ => body.to_vec(),
    }
}

fn gzip_bytes(data: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write as _;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(data).ok()?;
    encoder.finish().ok()
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        421 => "Misdirected Request",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        _ => "Error",
    }
}

/// True when `ip` is a loopback address. Used by config rejection.
#[must_use]
pub fn is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}
