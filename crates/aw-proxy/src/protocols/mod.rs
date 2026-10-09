//! Protocol identification for MCP over HTTP and A2A (P6-PROXY-01).
//!
//! This module parses a copy of bytes the caller already buffered. It does not
//! sit on the forward path. A parse error ([`ParseGap`]) is a fact about that
//! copy. It is not a reason to drop, delay, or rewrite the response the proxy
//! is forwarding. Fail-open means: return the gap, keep the bytes the caller
//! still holds, and let the caller record the gap.
//!
//! What is not implemented here, because `server/` and the CLI are outside this
//! card:
//!
//! - The live reverse proxy. [`plan_loopback`] only describes which loopback
//!   port a later caller would target. It does not bind, connect, or listen.
//! - `--mcp-tap` injection into an Agent's temporary MCP config. The port is
//!   expected to come from that config; this module does not read it.
//! - An SSE byte pump. [`count_sse`] counts `data:` frames in a buffer the
//!   caller already has. It does not read a socket.
//!
//! Nothing in the extract stores a body, an argument value, a result, a
//! prompt, a file, an `Authorization` / `Cookie` header, or a URL query.
//! [`ProtocolExtract::arg_shape`] is key names mapped to `{type, len}` only.

mod parse;

use std::collections::BTreeMap;
use std::fmt;

use aw_core::{AgentRpc, Evidence, NaReason};
use serde_json::Value;

pub use parse::{arg_shape_of, count_sse, SseCount};

/// `source` when the body is MCP JSON-RPC observed by the proxy.
pub const SOURCE_MCP: &str = "proxy/mcp";

/// `source` when the body matches an explicit A2A method string.
pub const SOURCE_A2A: &str = "proxy/a2a";

/// Bytes of a body prefix this parser will look at. The caller may hold a
/// longer body; [`HttpInput::req_bytes`] is that full length, which can be
/// larger than the prefix. Bytes past the cap are not parsed and are not
/// returned.
pub const PREFIX_CAP: usize = 64 * 1024;

/// Key names longer than this many Unicode scalars are truncated.
pub const MAX_KEY_SCALARS: usize = 64;

/// A2A methods that are an explicit match (A2A Protocol v1.0, 2026-03-23).
///
/// The v1.0 spec uses JSON-RPC 2.0. These method strings are the ones that
/// identify an A2A call without guessing from a payload shape:
///
/// - `message/send` and `message/stream` (v1.0 §7.1, §7.2).
/// - `tasks/get`, `tasks/cancel`, `tasks/resubscribe` (v1.0 §7.3–§7.5).
/// - `tasks/pushNotificationConfig/set`, `tasks/pushNotificationConfig/get`,
///   `tasks/pushNotificationConfig/list`, `tasks/pushNotificationConfig/delete`
///   (v1.0 §7.6–§7.9).
/// - `agent/getAuthenticatedExtendedCard` (v1.0 §7.10).
///
/// A2A 0.3 (2025) used the same JSON-RPC method strings. A body that only has
/// a top-level `message` object and no such method is **not** classified as
/// A2A here: that shape is not specific, and claiming E2 for it would invent
/// a protocol. Agent Card discovery (`/.well-known/agent-card.json` in v1.0,
/// previously `/.well-known/agent.json`) is a path match, not a body match;
/// this parser does not see the URL path and does not infer A2A from a header.
pub const A2A_METHODS: &[&str] = &[
    "message/send",
    "message/stream",
    "tasks/get",
    "tasks/cancel",
    "tasks/resubscribe",
    "tasks/pushNotificationConfig/set",
    "tasks/pushNotificationConfig/get",
    "tasks/pushNotificationConfig/list",
    "tasks/pushNotificationConfig/delete",
    "agent/getAuthenticatedExtendedCard",
];

/// One HTTP observation the caller already buffered.
///
/// `body_prefix` is borrowed. This function does not take ownership of a body
/// and does not keep the prefix after it returns. `req_bytes` is the length
/// the caller measured for the whole request body. `None` means the caller
/// did not measure it — that is not `0`. `0` is a real empty body.
#[derive(Debug, Clone, Copy)]
pub struct HttpInput<'a> {
    /// Header pairs as the proxy saw them. Names are matched case-insensitively.
    /// Values of `Authorization`, `Cookie`, and other secret-shaped names are
    /// never copied into the extract.
    pub headers: &'a [(String, String)],
    /// At most the first [`PREFIX_CAP`] bytes are parsed. A longer slice is
    /// treated as truncated: parsing stops at the cap and the extract says so.
    pub body_prefix: &'a [u8],
    /// Caller-measured request body length. `None` when the caller did not
    /// pass one. Never invented as `0`.
    pub req_bytes: Option<u64>,
    /// Caller-measured response body length. `None` when unknown.
    pub resp_bytes: Option<u64>,
    /// Duration the caller measured. `None` when the clock did not yield one.
    pub duration_ns: Option<u64>,
}

/// What the prefix was, without the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    /// JSON-RPC whose `method` is not an A2A method. Source [`SOURCE_MCP`].
    Mcp,
    /// JSON-RPC whose `method` is one of [`A2A_METHODS`]. Source [`SOURCE_A2A`].
    A2a,
    /// `Accept: text/event-stream` or `Content-Type: text/event-stream`, and
    /// the body did not yield a JSON-RPC method. No method is invented.
    SseHint,
    /// Headers did not name a protocol and the body did not yield a method.
    Unknown,
}

/// Why the body did not yield a method. The gap does not contain the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseGap {
    /// `body_prefix` was empty. No method, and no SSE count of zero.
    Empty,
    /// The prefix was not JSON.
    NotJson,
    /// The prefix was JSON but not an object.
    NotObject,
    /// The prefix was an object, but `method` was absent or not a string.
    /// A header hint may still have classified the exchange as SSE.
    NoMethod,
    /// The caller passed more than [`PREFIX_CAP`] bytes, or `req_bytes` is
    /// larger than the prefix. Parsing stopped at the cap. The method is set
    /// only when the capped prefix was itself a complete JSON object.
    Truncated,
}

impl ParseGap {
    /// Stable token. Display and Debug use this and nothing from the body.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::NotJson => "not_json",
            Self::NotObject => "not_object",
            Self::NoMethod => "no_method",
            Self::Truncated => "truncated",
        }
    }
}

impl fmt::Display for ParseGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Metadata extracted from one HTTP observation. No body, no argument values.
///
/// `Debug` prints method, target, source, lengths, and the gap. It does not
/// print header values or the body, because this struct does not store them.
#[derive(Clone, PartialEq)]
pub struct ProtocolExtract {
    /// [`SOURCE_MCP`] or [`SOURCE_A2A`] when a method was extracted.
    /// [`SOURCE_MCP`] also for an SSE hint that had no method: the hint is an
    /// MCP transport signal, not an A2A method match. `None` when nothing
    /// identified a protocol — the caller should not emit `AgentRpc` then.
    pub source: Option<&'static str>,
    /// How the classification was reached.
    pub kind: ProtocolKind,
    /// Record-level evidence. [`Evidence::E2`] when a JSON-RPC `method` was
    /// read from a body the caller says the proxy terminated. [`Evidence::I`]
    /// is not used: a non-explicit shape is not classified as A2A.
    /// [`Evidence::NA`] when no method was observed.
    pub evidence: Evidence,
    /// JSON-RPC `method`. `None` when the body did not contain one. A header
    /// hint never fills this.
    pub method: Option<String>,
    /// `params.name` when that field is a string (the MCP tool name).
    /// Truncated to [`MAX_KEY_SCALARS`]. Not `params` itself.
    pub target: Option<String>,
    /// Keys of `params.arguments` mapped to `{"type": ..., "len": ...}`.
    /// `None` when `params.arguments` is not an object. Never argument values.
    pub arg_shape: Option<Value>,
    /// Caller-supplied request length. May be larger than [`PREFIX_CAP`].
    /// `None` when the caller did not pass one.
    pub req_bytes: Option<u64>,
    /// Caller-supplied response length.
    pub resp_bytes: Option<u64>,
    /// `true` when the object has an `error` key. `error.message` is not copied.
    /// `None` when the body was not a JSON object.
    pub is_error: Option<bool>,
    /// Caller-supplied duration.
    pub duration_ns: Option<u64>,
    /// Why a method is missing, or [`ParseGap::Truncated`] when the method
    /// came from a capped prefix. `None` when the prefix parsed cleanly.
    pub gap: Option<ParseGap>,
    /// `true` when parsing stopped at [`PREFIX_CAP`] or `req_bytes` exceeds
    /// the prefix length. The method, if any, is from the capped prefix only.
    pub truncated: bool,
    /// SSE `data:` frames in the prefix. `None` when the body was not
    /// classified as an event stream, or the prefix was empty. `Some(0)` only
    /// when a non-empty complete buffer contained zero `data:` frames.
    /// See [`count_sse`].
    pub sse_frames: Option<u64>,
    /// `true` when the SSE buffer did not end on a frame boundary.
    pub sse_truncated: bool,
}

impl fmt::Debug for ProtocolExtract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtocolExtract")
            .field("source", &self.source)
            .field("kind", &self.kind)
            .field("evidence", &self.evidence)
            .field("method", &self.method)
            .field("target", &self.target)
            .field("arg_shape_present", &self.arg_shape.is_some())
            .field("req_bytes", &self.req_bytes)
            .field("resp_bytes", &self.resp_bytes)
            .field("is_error", &self.is_error)
            .field("duration_ns", &self.duration_ns)
            .field("gap", &self.gap)
            .field("truncated", &self.truncated)
            .field("sse_frames", &self.sse_frames)
            .field("sse_truncated", &self.sse_truncated)
            .finish()
    }
}

impl ProtocolExtract {
    /// `AgentRpc` for a caller that already has a method. `None` when no
    /// method was extracted — this does not invent one, and does not emit an
    /// event whose method is empty.
    ///
    /// `target` stays `None` when `params.name` was absent. The caller must
    /// mark that field `NA(protocol_not_observed)` on the [`aw_core::RawEvent`]
    /// (event-schema: a missing tool name is "not observed", not "no tool").
    /// This function does not build the envelope, because it has no session,
    /// sequence, or clock.
    #[must_use]
    pub fn agent_rpc(&self) -> Option<AgentRpc> {
        let method = self.method.clone()?;
        Some(AgentRpc::new(
            method,
            self.target.clone(),
            self.arg_shape.clone(),
            self.req_bytes,
            self.resp_bytes,
            self.is_error,
            self.duration_ns,
        ))
    }

    /// Field-level evidence the caller should copy onto the event.
    ///
    /// `target` is [`NaReason::ProtocolNotObserved`] when the method was seen
    /// but `params.name` was not. `method` is the same reason when a transport
    /// hint was seen and the body had no method. No entry is emitted for a
    /// field this extract does not claim to know about.
    #[must_use]
    pub fn field_evidence(&self) -> BTreeMap<String, Evidence> {
        let mut map = BTreeMap::new();
        if self.method.is_some() && self.target.is_none() {
            map.insert(
                "target".to_owned(),
                Evidence::NA(NaReason::ProtocolNotObserved),
            );
        }
        if self.method.is_none() && self.source.is_some() {
            map.insert(
                "method".to_owned(),
                Evidence::NA(NaReason::ProtocolNotObserved),
            );
        }
        map
    }
}

/// Identify MCP JSON-RPC or A2A in one buffered HTTP observation.
///
/// Reads `method` and `params.name` from `body_prefix`. Counts SSE `data:`
/// frames when the body or a header says the payload is `text/event-stream`.
/// Does not copy argument values. Does not panic on malformed JSON: that is
/// [`ParseGap::NotJson`] or [`ParseGap::NotObject`].
///
/// Evidence is [`Evidence::E2`] only when a `method` string was read from the
/// prefix (proxy observation of cleartext). A header (`Accept` or
/// `Content-Type`) without a method does not fill `method`.
#[must_use]
pub fn identify_http(input: HttpInput<'_>) -> ProtocolExtract {
    let truncated_by_len = prefix_was_capped(input.body_prefix, input.req_bytes);
    let prefix = cap_prefix(input.body_prefix);
    let sse_header = header_is_event_stream(input.headers);
    let sse = if sse_header || looks_like_sse(prefix) {
        count_sse(prefix)
    } else {
        None
    };

    if prefix.is_empty() {
        return ProtocolExtract {
            source: if sse_header { Some(SOURCE_MCP) } else { None },
            kind: if sse_header {
                ProtocolKind::SseHint
            } else {
                ProtocolKind::Unknown
            },
            evidence: Evidence::NA(NaReason::ProtocolNotObserved),
            method: None,
            target: None,
            arg_shape: None,
            req_bytes: input.req_bytes,
            resp_bytes: input.resp_bytes,
            is_error: None,
            duration_ns: input.duration_ns,
            gap: Some(ParseGap::Empty),
            truncated: truncated_by_len,
            sse_frames: None,
            sse_truncated: false,
        };
    }

    match parse::parse_object(prefix) {
        Ok(parsed) => from_object(input, parsed, sse, truncated_by_len),
        Err(gap) => from_failure(input, gap, sse, sse_header, truncated_by_len),
    }
}

fn from_object(
    input: HttpInput<'_>,
    parsed: parse::ParsedObject,
    sse: Option<SseCount>,
    truncated_by_len: bool,
) -> ProtocolExtract {
    let method = parsed.method;
    let a2a = method.as_deref().is_some_and(is_a2a_method);
    let (source, kind) = if a2a {
        (Some(SOURCE_A2A), ProtocolKind::A2a)
    } else if method.is_some() {
        (Some(SOURCE_MCP), ProtocolKind::Mcp)
    } else if sse.is_some() {
        (Some(SOURCE_MCP), ProtocolKind::SseHint)
    } else {
        (None, ProtocolKind::Unknown)
    };
    let evidence = if method.is_some() {
        Evidence::E2
    } else {
        Evidence::NA(NaReason::ProtocolNotObserved)
    };
    let gap = if method.is_none() {
        Some(ParseGap::NoMethod)
    } else if truncated_by_len {
        Some(ParseGap::Truncated)
    } else {
        None
    };
    let (sse_frames, sse_truncated) = match sse {
        Some(count) => (Some(count.frames), count.truncated),
        None => (None, false),
    };
    ProtocolExtract {
        source,
        kind,
        evidence,
        method,
        target: parsed.target,
        arg_shape: parsed.arg_shape,
        req_bytes: input.req_bytes,
        resp_bytes: input.resp_bytes,
        is_error: Some(parsed.is_error),
        duration_ns: input.duration_ns,
        gap,
        truncated: truncated_by_len,
        sse_frames,
        sse_truncated,
    }
}

fn from_failure(
    input: HttpInput<'_>,
    gap: ParseGap,
    sse: Option<SseCount>,
    sse_header: bool,
    truncated_by_len: bool,
) -> ProtocolExtract {
    let (sse_frames, sse_truncated) = match sse {
        Some(count) => (Some(count.frames), count.truncated),
        None => (None, false),
    };
    let sse_kind = sse_header || sse.is_some();
    ProtocolExtract {
        source: if sse_kind { Some(SOURCE_MCP) } else { None },
        kind: if sse_kind {
            ProtocolKind::SseHint
        } else {
            ProtocolKind::Unknown
        },
        evidence: Evidence::NA(NaReason::ProtocolNotObserved),
        method: None,
        target: None,
        arg_shape: None,
        req_bytes: input.req_bytes,
        resp_bytes: input.resp_bytes,
        is_error: None,
        duration_ns: input.duration_ns,
        gap: Some(if truncated_by_len && gap == ParseGap::NotJson {
            // The capped prefix was not a complete value. Say truncated, not
            // "this was not JSON" — the unread tail might have closed it.
            ParseGap::Truncated
        } else {
            gap
        }),
        truncated: truncated_by_len || sse_truncated,
        sse_frames,
        sse_truncated,
    }
}

fn cap_prefix(body: &[u8]) -> &[u8] {
    if body.len() > PREFIX_CAP {
        &body[..PREFIX_CAP]
    } else {
        body
    }
}

fn prefix_was_capped(prefix: &[u8], req_bytes: Option<u64>) -> bool {
    if prefix.len() > PREFIX_CAP {
        return true;
    }
    match req_bytes {
        Some(len) => u64::try_from(prefix.len()).is_ok_and(|have| len > have),
        None => false,
    }
}

fn header_is_event_stream(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        let name = name.to_ascii_lowercase();
        if name != "accept" && name != "content-type" {
            return false;
        }
        value
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case("text/event-stream"))
    })
}

/// A buffer that starts a Server-Sent Event, not a JSON object.
fn looks_like_sse(prefix: &[u8]) -> bool {
    let trimmed = trim_ascii_start(prefix);
    trimmed.starts_with(b"data:")
        || trimmed.starts_with(b"event:")
        || trimmed.starts_with(b"id:")
        || trimmed.starts_with(b":")
}

fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn is_a2a_method(method: &str) -> bool {
    A2A_METHODS.contains(&method)
}

/// Why [`plan_loopback`] refused a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    /// The caller passed `None`. No port was configured. This is not port 0.
    Missing,
    /// Port 0 is not a real port. Rejected so a later caller cannot bind
    /// "any port" by accident.
    PortZero,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("missing"),
            Self::PortZero => f.write_str("port_zero"),
        }
    }
}

impl std::error::Error for PlanError {}

/// A description of a reverse proxy a later caller might open.
///
/// Constructed only by [`plan_loopback`]. This struct does not listen, does
/// not connect, and does not read the temporary MCP config. `--mcp-tap`
/// injection (rewriting an Agent's MCP server command or URL) and the actual
/// reverse proxy both live outside this card: the CLI and `server/` are out
/// of scope, and this module must not open a socket to look complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopbackTapPlan {
    /// Loopback TCP port the caller named. Never 0.
    pub port: u16,
    /// [`SOURCE_MCP`]. The plan is for the MCP HTTP transport. A2A is
    /// classified per request by [`identify_http`], not by the port.
    pub source: &'static str,
}

/// Describe a loopback reverse-proxy target.
///
/// `port` is the value a caller read from the temporary MCP config. This
/// function checks it and returns. It does not bind the port.
///
/// # Errors
///
/// [`PlanError::Missing`] when `port` is `None`. [`PlanError::PortZero`] when
/// the port is 0.
pub fn plan_loopback(port: Option<u16>) -> Result<LoopbackTapPlan, PlanError> {
    match port {
        None => Err(PlanError::Missing),
        Some(0) => Err(PlanError::PortZero),
        Some(port) => Ok(LoopbackTapPlan {
            port,
            source: SOURCE_MCP,
        }),
    }
}
