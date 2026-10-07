//! One HTTP/1.1 exchange on an already-connected byte stream.
//!
//! Headers are parsed with `httparse`. The request target is used only to
//! choose a route and a length; it is not written to the truth log.

use std::io::{self, Read, Write};

use super::truth_log::Direction;
use super::{DOWNLOAD_PATTERN, MAX_DOWNLOAD_BYTES};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const READ_CHUNK: usize = 64 * 1024;

pub struct Exchange {
    pub direction: Direction,
    pub app_bytes: u64,
    pub ok: bool,
    pub error: Option<String>,
}

/// Read one request, record the exchange (the closure must sync the truth line),
/// then write the response. The closure runs before the response so a client
/// that stops after reading the response still finds the line on disk.
pub fn serve_one<S, F>(stream: &mut S, mut record: F) -> Result<(), String>
where
    S: Read + Write,
    F: FnMut(Exchange) -> Result<(), String>,
{
    let mut preface = Preface::read(stream)?;
    let exchange = match (preface.method.as_str(), route(&preface.target)) {
        ("POST", Route::Upload) => upload(&mut preface, stream),
        ("GET", Route::Download(len)) => download(len),
        ("GET", Route::DownloadRejected) => Exchange {
            direction: Direction::Download,
            app_bytes: 0,
            ok: false,
            error: Some(format!(
                "download length exceeds the {MAX_DOWNLOAD_BYTES} byte cap"
            )),
        },
        _ => Exchange {
            direction: Direction::Download,
            app_bytes: 0,
            ok: false,
            error: Some("no such route".to_string()),
        },
    };
    let response = response_for(&exchange);
    record(exchange)?;
    stream
        .write_all(&response)
        .and_then(|_| stream.flush())
        .map_err(|err| format!("write response: {err}"))
}

/// Bytes already pulled off the socket while searching for the header block.
struct Preface {
    method: String,
    target: String,
    content_length: Option<u64>,
    rest: Vec<u8>,
    rest_at: usize,
}

impl Preface {
    fn read<S: Read>(stream: &mut S) -> Result<Self, String> {
        let mut buf = Vec::with_capacity(1024);
        let mut tmp = [0u8; 1024];
        loop {
            if buf.len() > MAX_HEADER_BYTES {
                return Err("request headers exceed 16 KiB".to_string());
            }
            let n = stream
                .read(&mut tmp)
                .map_err(|err| format!("read headers: {err}"))?;
            if n == 0 {
                return Err("connection closed before HTTP headers".to_string());
            }
            buf.extend_from_slice(&tmp[..n]);
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut request = httparse::Request::new(&mut headers);
            match request.parse(&buf) {
                Ok(httparse::Status::Complete(end)) => {
                    let method = request
                        .method
                        .ok_or_else(|| "missing method".to_string())?
                        .to_string();
                    let target = request
                        .path
                        .ok_or_else(|| "missing path".to_string())?
                        .to_string();
                    let content_length = content_length(request.headers)?;
                    let rest = buf.split_off(end);
                    return Ok(Self {
                        method,
                        target,
                        content_length,
                        rest,
                        rest_at: 0,
                    });
                }
                Ok(httparse::Status::Partial) => continue,
                Err(err) => return Err(format!("HTTP headers: {err}")),
            }
        }
    }
}

impl Read for Preface {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let available = &self.rest[self.rest_at..];
        if available.is_empty() {
            return Ok(0);
        }
        let n = available.len().min(buf.len());
        buf[..n].copy_from_slice(&available[..n]);
        self.rest_at += n;
        Ok(n)
    }
}

/// Body reader: leftover header-buffer bytes first, then the live stream,
/// stopping at `Content-Length` when one was declared.
struct Body<'a, S> {
    preface: &'a mut Preface,
    stream: &'a mut S,
    remaining: Option<u64>,
}

impl<S: Read> Read for Body<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == Some(0) {
            return Ok(0);
        }
        let limit = self
            .remaining
            .map(|left| left.min(buf.len() as u64) as usize)
            .unwrap_or(buf.len());
        let n = if self.preface.rest_at < self.preface.rest.len() {
            self.preface.read(&mut buf[..limit])?
        } else {
            self.stream.read(&mut buf[..limit])?
        };
        if let Some(left) = self.remaining.as_mut() {
            *left = left.saturating_sub(n as u64);
        }
        Ok(n)
    }
}

enum Route {
    Upload,
    Download(u64),
    DownloadRejected,
    Other,
}

fn route(target: &str) -> Route {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match path {
        "/upload" => Route::Upload,
        "/download" => match bytes_query(query) {
            Ok(n) if n > MAX_DOWNLOAD_BYTES => Route::DownloadRejected,
            Ok(n) => Route::Download(n),
            Err(()) => Route::Other,
        },
        _ => Route::Other,
    }
}

fn bytes_query(query: &str) -> Result<u64, ()> {
    for pair in query.split('&') {
        if let Some(raw) = pair.strip_prefix("bytes=") {
            return raw.parse::<u64>().map_err(|_| ());
        }
    }
    Err(())
}

fn upload<S: Read>(preface: &mut Preface, stream: &mut S) -> Exchange {
    // Copy first: `Body` mutably borrows `preface`, so the field cannot be
    // read again while the reader is alive.
    let limit = preface.content_length;
    let mut got = 0u64;
    {
        let mut body = Body {
            preface,
            stream,
            remaining: limit,
        };
        let mut buf = vec![0u8; READ_CHUNK];
        loop {
            match body.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    got = got.saturating_add(n as u64);
                    // Counted and dropped. `buf` is reused and never stored.
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    return Exchange {
                        direction: Direction::Upload,
                        app_bytes: got,
                        ok: false,
                        error: Some(format!("read body: {err}")),
                    };
                }
            }
        }
    }
    if let Some(limit) = limit {
        if got != limit {
            return Exchange {
                direction: Direction::Upload,
                app_bytes: got,
                ok: false,
                error: Some(format!(
                    "body ended after {got} bytes, Content-Length was {limit}"
                )),
            };
        }
    }
    Exchange {
        direction: Direction::Upload,
        app_bytes: got,
        ok: true,
        error: None,
    }
}

fn download(len: u64) -> Exchange {
    Exchange {
        direction: Direction::Download,
        app_bytes: len,
        ok: true,
        error: None,
    }
}

fn response_for(exchange: &Exchange) -> Vec<u8> {
    if !exchange.ok {
        let reason = exchange.error.as_deref().unwrap_or("request rejected");
        // Our own short status text, never a body or a header the client sent.
        let body = reason.as_bytes();
        return format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect();
    }
    match exchange.direction {
        Direction::Upload => {
            let body = format!("{{\"count\":{}}}", exchange.app_bytes);
            let mut out = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n",
                body.len()
            )
            .into_bytes();
            out.extend_from_slice(body.as_bytes());
            out
        }
        Direction::Download => {
            let len = exchange.app_bytes;
            let mut out = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .into_bytes();
            out.reserve(len as usize);
            let pattern = DOWNLOAD_PATTERN;
            let mut left = len as usize;
            while left > 0 {
                let n = left.min(pattern.len());
                out.extend_from_slice(&pattern[..n]);
                left -= n;
            }
            out
        }
    }
}

fn content_length(headers: &[httparse::Header<'_>]) -> Result<Option<u64>, String> {
    let mut found: Option<u64> = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("content-length") {
            let text = std::str::from_utf8(header.value)
                .map_err(|_| "Content-Length is not utf-8".to_string())?;
            let value = text
                .trim()
                .parse::<u64>()
                .map_err(|_| "Content-Length is not an integer".to_string())?;
            if found.is_some() {
                return Err("repeated Content-Length".to_string());
            }
            found = Some(value);
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("Transfer-Encoding is not accepted; send Content-Length".to_string());
        }
    }
    Ok(found)
}
