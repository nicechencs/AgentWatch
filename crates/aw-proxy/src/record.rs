//! HTTP metadata → `HttpRequest` / `HttpResponse` (P3-PROXY-02).
//!
//! What is kept matches network-attribution §5.4 and security-privacy §3.2 E:
//! method, redacted URL, HTTP version, status, whitelisted headers, body byte
//! counts, duration, `Content-Type`. Body bytes are a count. The body itself is
//! not a field and is not formatted.
//!
//! `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, and
//! `X-Api-Key` are dropped. Other secret-shaped names are dropped the same way.
//! A header that is neither secret nor on the whitelist contributes its name
//! and an empty value, so "the header was present" is not confused with "the
//! value was empty on the wire" — the empty stand-in is the fixed marker
//! `"«redacted:header»"` only for names that are kept without a value. Secret
//! names are absent.
//!
//! Query names `token`, `key`, `secret`, `password`, and the longer list in
//! security-privacy §3.2 C are replaced with `"«redacted:query»"`.
//!
//! Nothing here implements `Debug` by deriving it on a type that holds a URL.
//! [`RecordedExchange`] prints counts.

use std::fmt;

use aw_core::{
    EventKind, Evidence, HeaderList, HttpRequest, HttpResponse, NaReason, RawEvent, RawEventParts,
    Redacted, SessionId, SocketAddr, Source,
};

/// `source` for every event this module builds.
pub const SOURCE_MITM: &str = "proxy/mitm";

/// Fixed replacement for a query value this module will not keep.
pub const REDACTED_QUERY: &str = "«redacted:query»";

/// Fixed replacement for a header value that is recorded as present-only.
pub const REDACTED_HEADER: &str = "«redacted:header»";

/// Headers whose values are stored (security-privacy §3.2 E, whitelist).
const VALUE_HEADERS: &[&str] = &[
    "host",
    "user-agent",
    "content-type",
    "content-length",
    "content-encoding",
    "accept",
    "accept-encoding",
    "referer",
    "origin",
    "x-request-id",
    "server",
    "location",
];

/// Headers that are removed entirely. A present-only record would still leak
/// that a credential header existed with a particular length if we kept the
/// value's length; the task says to drop them.
const DROP_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-amz-security-token",
];

/// One request the proxy observed, already split. Strings are owned because the
/// socket buffer is reused. `Debug` prints lengths.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestMeta {
    /// `GET`, `CONNECT`, … Empty is rejected by [`record_exchange`].
    pub method: String,
    /// Absolute URL, or `host:port` for CONNECT. Redacted before it is stored.
    pub url: String,
    /// `HTTP/1.1`, `HTTP/2`, …
    pub http_version: String,
    /// Header pairs as received. Names are matched case-insensitively.
    pub headers: Vec<(String, String)>,
    /// Body length. `None` when the proxy did not see a body (not zero).
    pub body_bytes: Option<u64>,
    /// Client source address. Exposed for P3-PIPE-01.
    pub client: SocketAddr,
}

impl fmt::Debug for RequestMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestMeta")
            .field("method", &self.method)
            .field("url_len", &self.url.len())
            .field("http_version", &self.http_version)
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body_bytes)
            .field("client", &self.client)
            .finish()
    }
}

/// The matching response. `status` is `None` when no status line was observed
/// (a tunnel, or a failed handshake). That is not status `0`.
#[derive(Clone, PartialEq, Eq)]
pub struct ResponseMeta {
    /// HTTP status. `None` when there was no status line.
    pub status: Option<u16>,
    /// Response headers.
    pub headers: Vec<(String, String)>,
    /// Body length. `None` when the body was not observed.
    pub body_bytes: Option<u64>,
    /// Milliseconds from request headers to response end. `None` when the clock
    /// did not yield a duration.
    pub duration_ms: Option<u32>,
}

impl fmt::Debug for ResponseMeta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseMeta")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body_bytes)
            .field("duration_ms", &self.duration_ms)
            .finish()
    }
}

/// WebSocket counters. Frame contents are not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsCounts {
    /// Frames client → server. `None` when the direction was not counted.
    pub frames_up: Option<u64>,
    /// Frames server → client.
    pub frames_down: Option<u64>,
    /// Payload bytes client → server, excluding the body of the upgrade request.
    pub bytes_up: Option<u64>,
    /// Payload bytes server → client.
    pub bytes_down: Option<u64>,
}

/// Why a URL field is `NA` rather than a redacted string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlGap {
    /// `proxy.on_tls_reject = tunnel`. Domain and byte counts only.
    CertPinned,
    /// The client connected without using the proxy. Not a URL.
    Direct,
}

/// One exchange after redaction, ready to become events.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordedExchange {
    /// Correlates the request event with the response event.
    pub req_id: u64,
    /// Redacted URL. `None` when [`UrlGap`] applies; the event then carries `NA`.
    pub url: Option<String>,
    /// Set when `url` is `None`.
    pub url_gap: Option<UrlGap>,
    /// Request half. `body_bytes` is `None` when unknown — the event field is
    /// `u64` and cannot say "unknown", so a missing count is not emitted as `0`.
    /// The event is skipped and [`Self::request_skipped`] explains why.
    pub request: RequestMeta,
    /// Response half. `None` for a request that never got a response.
    pub response: Option<ResponseMeta>,
    /// WebSocket counters. `None` when the exchange was not a websocket.
    pub websocket: Option<WsCounts>,
    /// `Content-Type` of the response, when it was on the whitelist (it is).
    pub content_type: Option<String>,
    /// Why the request event was not built. `None` when it was.
    pub request_skipped: Option<&'static str>,
}

impl fmt::Debug for RecordedExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordedExchange")
            .field("req_id", &self.req_id)
            .field("url_len", &self.url.as_ref().map(String::len))
            .field("url_gap", &self.url_gap)
            .field("method", &self.request.method)
            .field("status", &self.response.as_ref().and_then(|r| r.status))
            .field(
                "body_bytes",
                &self.response.as_ref().and_then(|r| r.body_bytes),
            )
            .field("websocket", &self.websocket)
            .field("request_skipped", &self.request_skipped)
            .finish()
    }
}

/// Redact `url` in place (owned). Fragment is removed. Secret query values become
/// [`REDACTED_QUERY`]. The scheme, host, and path stay.
#[must_use]
pub fn redact_url(url: &str) -> String {
    let without_fragment = match url.split_once('#') {
        Some((head, _)) => head,
        None => url,
    };
    let Some((path, query)) = without_fragment.split_once('?') else {
        return without_fragment.to_owned();
    };
    if query.is_empty() {
        return format!("{path}?");
    }
    let mut out = String::with_capacity(without_fragment.len());
    out.push_str(path);
    out.push('?');
    let mut first = true;
    for pair in query.split('&') {
        if !first {
            out.push('&');
        }
        first = false;
        match pair.split_once('=') {
            Some((name, _)) if query_name_is_secret(name) => {
                out.push_str(name);
                out.push('=');
                out.push_str(REDACTED_QUERY);
            }
            _ => out.push_str(pair),
        }
    }
    out
}

fn query_name_is_secret(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let stem = lower.rsplit(['-', '_']).next().unwrap_or(lower.as_str());
    matches!(
        stem,
        "token"
            | "key"
            | "apikey"
            | "secret"
            | "password"
            | "passwd"
            | "pwd"
            | "sig"
            | "signature"
            | "auth"
            | "code"
            | "session"
            | "sid"
    ) || lower == "api_key"
        || lower == "access_token"
        || lower == "refresh_token"
        || lower == "client_secret"
        || lower.starts_with("x-amz-")
}

/// Filter headers. Dropped names disappear. Whitelisted names keep their value,
/// except `Referer` and `Location`, which pass through [`redact_url`].
/// Every other name is kept with [`REDACTED_HEADER`] as the value.
#[must_use]
pub fn filter_headers(headers: &[(String, String)]) -> HeaderList {
    let mut kept = Vec::new();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if drop_header(&lower) {
            continue;
        }
        if value_header(&lower) {
            let stored = if lower == "referer" || lower == "location" {
                redact_url(value)
            } else {
                value.clone()
            };
            kept.push((name.clone(), stored));
        } else {
            kept.push((name.clone(), REDACTED_HEADER.to_owned()));
        }
    }
    HeaderList(kept)
}

fn drop_header(lower: &str) -> bool {
    if DROP_HEADERS.contains(&lower) {
        return true;
    }
    // security-privacy §3.2 D keywords, applied to header names.
    let padded = format!("-{lower}-");
    [
        "token",
        "secret",
        "key",
        "password",
        "passwd",
        "credential",
        "auth",
        "cookie",
        "session",
    ]
    .iter()
    .any(|word| padded.contains(&format!("-{word}-")) || lower == *word)
}

fn value_header(lower: &str) -> bool {
    VALUE_HEADERS.contains(&lower)
}

/// Build the redacted exchange. Does not allocate an event.
///
/// `body_bytes` of `None` does not become `0`. The request event is omitted in
/// that case because [`HttpRequest::body_bytes`] is a `u64`.
#[must_use]
pub fn record_exchange(
    req_id: u64,
    request: RequestMeta,
    response: Option<ResponseMeta>,
    websocket: Option<WsCounts>,
    url_gap: Option<UrlGap>,
) -> RecordedExchange {
    let url = if url_gap.is_some() || request.url.is_empty() {
        None
    } else {
        Some(redact_url(&request.url))
    };
    let content_type = response.as_ref().and_then(|resp| {
        resp.headers.iter().find_map(|(name, value)| {
            if name.eq_ignore_ascii_case("content-type") {
                Some(value.clone())
            } else {
                None
            }
        })
    });
    let request_skipped = if request.method.is_empty() {
        Some("method missing")
    } else if request.body_bytes.is_none() && url_gap.is_none() {
        Some("request body length was not observed")
    } else if url.is_none() && url_gap.is_none() {
        Some("url missing")
    } else {
        None
    };
    RecordedExchange {
        req_id,
        url,
        url_gap,
        request,
        response,
        websocket,
        content_type,
        request_skipped,
    }
}

/// Events for one exchange. Empty when the request could not be recorded.
/// A response with no status is not emitted (status `0` is not a status).
///
/// Evidence is [`Evidence::E2`]. Source is [`SOURCE_MITM`].
/// When `url_gap` is set, the request URL is a one-character placeholder inside
/// [`Redacted`] (the schema field is not `Option`) and `field_evidence["url"]`
/// is `NA(cert_pinned)` or `NA(direct_bypass_proxy)`. The placeholder is `"-"`
/// and is not a URL.
pub fn to_events(
    recorded: &RecordedExchange,
    seq: u64,
    ts_mono_ns: u64,
    ts_wall_ns: i64,
    session_id: Option<SessionId>,
) -> Result<Vec<RawEvent>, aw_core::EventError> {
    let mut out = Vec::new();
    if recorded.request_skipped.is_none() {
        if let Some(event) = request_event(recorded, seq, ts_mono_ns, ts_wall_ns, session_id)? {
            out.push(event);
        }
    }
    if let Some(response) = &recorded.response {
        let (Some(status), Some(body_bytes), Some(duration_ms)) =
            (response.status, response.body_bytes, response.duration_ms)
        else {
            return Ok(out);
        };
        let http = HttpResponse::new(
            recorded.req_id,
            status,
            filter_headers(&response.headers),
            body_bytes,
            duration_ms,
        );
        let event = RawEvent::try_new(RawEventParts {
            seq: seq.saturating_add(1),
            ts_mono_ns,
            ts_wall_ns,
            session_id,
            proc: None,
            source: Source::new(SOURCE_MITM),
            evidence: Evidence::E2,
            kind: EventKind::HttpResponse(http),
        })?;
        out.push(event);
    }
    Ok(out)
}

fn request_event(
    recorded: &RecordedExchange,
    seq: u64,
    ts_mono_ns: u64,
    ts_wall_ns: i64,
    session_id: Option<SessionId>,
) -> Result<Option<RawEvent>, aw_core::EventError> {
    let body_bytes = match recorded.url_gap {
        Some(_) => recorded.request.body_bytes,
        None => recorded.request.body_bytes,
    };
    let Some(body_bytes) = body_bytes else {
        return Ok(None);
    };
    let (url_text, na) = match (&recorded.url, recorded.url_gap) {
        (Some(url), _) => (url.clone(), None),
        (None, Some(UrlGap::CertPinned)) => ("-".to_owned(), Some(NaReason::CertPinned)),
        (None, Some(UrlGap::Direct)) => ("-".to_owned(), Some(NaReason::DirectBypassProxy)),
        (None, None) => return Ok(None),
    };
    let http = HttpRequest::new(
        recorded.req_id,
        recorded.request.client,
        None,
        recorded.request.method.clone(),
        Redacted::new(url_text),
        recorded.request.http_version.clone(),
        filter_headers(&recorded.request.headers),
        body_bytes,
        None,
    );
    let mut event = RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns,
        ts_wall_ns,
        session_id,
        proc: None,
        source: Source::new(SOURCE_MITM),
        evidence: Evidence::E2,
        kind: EventKind::HttpRequest(http),
    })?;
    if let Some(reason) = na {
        event.mark_na("url", reason);
    }
    Ok(Some(event))
}

/// True when `blob` still contains `secret`. Used by callers that want to check
/// a redacted URL or header list without this module printing either.
#[must_use]
pub fn contains_secret(blob: &str, secret: &str) -> bool {
    !secret.is_empty() && blob.contains(secret)
}
