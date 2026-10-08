//! E3 ingress: hook reports and a per-session loopback OTLP/HTTP receiver (P5-AGENT-02).
//!
//! `agent_events` has no migration yet. This module defines the row and the
//! write trait, then keeps accepted calls in memory and returns
//! [`StoreAgentEvent::StorageNotReady`]. It does not open SQLite and does not
//! pretend a row was inserted.
//!
//! The OTLP listener is `std::net::TcpListener` plus a small HTTP/1.1 parser,
//! the same style as [`super::http`]. It binds `127.0.0.1:0` only, accepts
//! `/v1/logs`, `/v1/traces`, and `/v1/metrics`, and never dials an upstream.
//! JSON is the only encoding that is parsed. A protobuf body is 415.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aw_agent_adapters::{bound_tool_call, parse_hook};
use aw_core::{AgentToolCall, Evidence, Gap, GapKind, ToolPhase};
use serde_json::{json, Map, Value};

/// `summary` plus the rest of one call, matching the task card.
pub use aw_agent_adapters::MAX_CALL_BYTES as MAX_AGENT_EVENT_BYTES;

/// Request body cap for one OTLP post. The acceptance case is ">1 MB → 413".
pub const OTLP_MAX_BODY: usize = 1024 * 1024;

/// How long one OTLP connection may block on a read or a write.
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Where an accepted call would have been written, once a migration exists.
pub const AGENT_EVENTS_TABLE: &str = "agent_events";

/// `source` column prefix. The channel is appended: `agent.<id>/hook` or `agent.<id>/otel`.
pub fn event_source(agent: &str, channel: &str) -> String {
    let agent = sanitize_id(agent);
    let channel = sanitize_id(channel);
    format!("agent.{agent}/{channel}")
}

fn sanitize_id(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars().take(64) {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        }
    }
    if out.is_empty() {
        "unknown".to_owned()
    } else {
        out
    }
}

/// One `agent_events` row. Evidence is always E3; this type cannot say otherwise.
///
/// `summary_json` is the already-bounded structured summary. It is not a prompt,
/// a model completion, or a file body. `Debug` prints lengths, not the JSON.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentEventRow {
    /// Session the hook or the OTLP endpoint was bound to. `None` when unknown.
    pub session_id: Option<String>,
    /// `agent.<id>/hook` or `agent.<id>/otel`.
    pub source: String,
    /// Always [`Evidence::E3`].
    pub evidence: Evidence,
    /// Agent id from the hook argument or the OTLP resource, not a display name.
    pub agent: String,
    /// Tool name. Empty when the payload named none.
    pub tool: String,
    /// `pre` / `post` / `unknown`.
    pub phase: ToolPhase,
    /// Structured summary, already passed through [`bound_tool_call`].
    pub summary_json: String,
    /// Adapter call id, when the payload had one.
    pub call_id: Option<String>,
}

impl std::fmt::Debug for AgentEventRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentEventRow")
            .field("session_id", &self.session_id.as_ref().map(String::len))
            .field("source", &self.source)
            .field("evidence", &"E3")
            .field("agent", &self.agent)
            .field("tool", &self.tool)
            .field("phase", &self.phase)
            .field("summary_bytes", &self.summary_json.len())
            .field("call_id", &self.call_id.as_ref().map(String::len))
            .finish()
    }
}

impl AgentEventRow {
    /// Build a row from a call that has already been bounded.
    ///
    /// # Errors
    ///
    /// [`IngestError::Oversize`] when the encoded call is still over 4 KB.
    /// [`IngestError::Encode`] when the summary cannot be serialized.
    pub fn from_bounded(session_id: Option<String>, channel: &str, call: &AgentToolCall) -> Result<Self, IngestError> {
        let summary_json = serde_json::to_string(&call.summary).map_err(|_| IngestError::Encode)?;
        let row = Self {
            session_id,
            source: event_source(&call.agent, channel),
            evidence: Evidence::E3,
            agent: call.agent.clone(),
            tool: call.tool.clone(),
            phase: call.phase,
            summary_json,
            call_id: call.call_id.clone(),
        };
        let encoded = serde_json::to_vec(call).map_err(|_| IngestError::Encode)?;
        if encoded.len() > MAX_AGENT_EVENT_BYTES {
            return Err(IngestError::Oversize);
        }
        Ok(row)
    }
}

/// Why a self-report did not become a retained row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestError {
    /// The JSON was not an object. The hook still exits 0; the daemon drops it.
    NotJson,
    /// The bounded call is over 4 KB.
    Oversize,
    /// `serde_json` refused the value. The message is a category, not the payload.
    Encode,
}

/// What the store boundary did with one row.
///
/// `Stored` is reserved for the migration that creates `agent_events`. Nothing
/// in this card returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreAgentEvent {
    /// Accepted into the in-memory buffer. The database was not written.
    ///
    /// `table` is [`AGENT_EVENTS_TABLE`]. `reason` says the migration is absent.
    StorageNotReady { table: &'static str, reason: &'static str },
    /// A future migration inserted the row. Not constructed today.
    Stored { table: &'static str },
}

/// Sink the OTLP listener and the hook route share.
///
/// The memory implementation never opens a database. A later card can replace
/// it once `agent_events` exists, and must still refuse an unbounded summary.
pub trait AgentEventStore: Send {
    /// Retain `row`. Must not log `row`'s summary.
    fn insert(&mut self, row: AgentEventRow) -> StoreAgentEvent;

    /// Record that a self-report was discarded. `detail` is a reason code, not a payload.
    fn record_gap(&mut self, session_id: Option<&str>, detail: &str);
}

/// In-memory stand-in. Rows stay in the process. Nothing is written to SQLite.
#[derive(Debug, Default)]
pub struct MemoryAgentEvents {
    rows: Vec<AgentEventRow>,
    gaps: Vec<Gap>,
}

impl MemoryAgentEvents {
    /// Empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rows accepted since construction. Tests and the hook route read this.
    /// Not a database query.
    #[must_use]
    pub fn rows(&self) -> &[AgentEventRow] {
        &self.rows
    }

    /// Gaps recorded for dropped self-reports.
    #[must_use]
    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }
}

impl AgentEventStore for MemoryAgentEvents {
    fn insert(&mut self, row: AgentEventRow) -> StoreAgentEvent {
        self.rows.push(row);
        StoreAgentEvent::StorageNotReady {
            table: AGENT_EVENTS_TABLE,
            reason: "agent_events has no migration; the row is held in memory only",
        }
    }

    fn record_gap(&mut self, session_id: Option<&str>, detail: &str) {
        let now = mono_now();
        // `detail` is a short reason (`timeout`, `oversize`, `unknown_session`).
        // Session id length is included so a log of this gap cannot grow a payload.
        let note = match session_id {
            Some(id) => format!("{detail} (session_len={})", id.len()),
            None => detail.to_owned(),
        };
        self.gaps.push(Gap::new(
            "agent.self_report",
            GapKind::SelfReportDropped,
            vec!["agent".to_owned()],
            now,
            now,
            Some(1),
            Some(note),
        ));
    }
}

fn mono_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// Parse a hook body, bound each call, and hand it to `store`.
///
/// An unknown agent yields no rows and no error. A call that cannot be bounded
/// becomes a `self_report_dropped` gap. The returned value is what the store
/// said; today that is always [`StoreAgentEvent::StorageNotReady`] when at
/// least one call was accepted, or `None` when nothing was accepted.
pub fn ingest_hook(
    store: &mut dyn AgentEventStore,
    agent: &str,
    session_id: Option<&str>,
    payload: &Value,
) -> Vec<StoreAgentEvent> {
    let calls = parse_hook(agent, payload);
    let mut outcomes = Vec::new();
    if calls.is_empty() {
        return outcomes;
    }
    for call in calls {
        let Some(bounded) = bound_tool_call(call) else {
            store.record_gap(session_id, "oversize");
            continue;
        };
        match AgentEventRow::from_bounded(session_id.map(str::to_owned), "hook", &bounded) {
            Ok(row) => outcomes.push(store.insert(row)),
            Err(IngestError::Oversize) => store.record_gap(session_id, "oversize"),
            Err(IngestError::NotJson | IngestError::Encode) => store.record_gap(session_id, "encode"),
        }
    }
    outcomes
}

/// One session's OTLP/HTTP endpoint. Drop joins the accept thread.
pub struct OtlpEndpoint {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    shared: Arc<Mutex<OtlpShared>>,
}

struct OtlpShared {
    store: MemoryAgentEvents,
    agent: String,
    session_id: Option<String>,
}

impl OtlpEndpoint {
    /// Bind `127.0.0.1:0` and serve until drop or [`OtlpEndpoint::shutdown`].
    ///
    /// The port is chosen by the operating system. The returned address is what
    /// `aw run` would put in the agent's OTLP environment variable.
    ///
    /// # Errors
    ///
    /// `TcpListener::bind` failed. No other address family is tried.
    pub fn bind(agent: impl Into<String>, session_id: Option<String>) -> std::io::Result<Self> {
        let addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0));
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let bound = listener.local_addr()?;
        if !bound.ip().is_loopback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "OTLP listener is not loopback",
            ));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let shared = Arc::new(Mutex::new(OtlpShared {
            store: MemoryAgentEvents::new(),
            agent: sanitize_id(&agent.into()),
            session_id,
        }));
        let shared_thread = Arc::clone(&shared);
        let thread = thread::Builder::new()
            .name("aw-otlp".to_owned())
            .spawn(move || accept_loop(listener, shared_thread, flag))?;
        Ok(Self {
            addr: bound,
            stop,
            thread: Some(thread),
            shared,
        })
    }

    /// Address actually bound. Always `127.0.0.1` with an OS-assigned port.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port>` with no path. The agent appends `/v1/logs`.
    #[must_use]
    pub fn endpoint_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Copy of the in-memory rows. Still not a database read.
    #[must_use]
    pub fn rows(&self) -> Vec<AgentEventRow> {
        let guard = match self.shared.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.store.rows().to_vec()
    }

    /// Stop accepting and join the thread.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for OtlpEndpoint {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn accept_loop(listener: TcpListener, shared: Arc<Mutex<OtlpShared>>, stop: Arc<AtomicBool>) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if !peer.ip().is_loopback() {
                    drop(stream);
                    continue;
                }
                let shared = Arc::clone(&shared);
                let _ = thread::Builder::new().name("aw-otlp-conn".to_owned()).spawn(move || {
                    if let Err(err) = serve_conn(stream, &shared) {
                        // Status only. The error is an I/O kind, not a body.
                        tracing::debug!(target: "aw_daemon::otlp", error = %err, "connection closed");
                    }
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                tracing::warn!(target: "aw_daemon::otlp", error = %err, "accept failed");
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn serve_conn(mut stream: TcpStream, shared: &Mutex<OtlpShared>) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(ReadFail::TooLarge) => {
            write_status(&mut stream, 413, "payload exceeds 1 MiB")?;
            return Ok(());
        }
        Err(ReadFail::Io(err)) => return Err(err),
        Err(ReadFail::Bad) => {
            write_status(&mut stream, 400, "malformed HTTP request")?;
            return Ok(());
        }
    };
    let status = handle(&request, shared);
    // Method, path, status. Never the body: an OTLP log can carry a prompt.
    tracing::debug!(
        target: "aw_daemon::otlp",
        method = %request.method,
        path = %request.path,
        status = status,
        "otlp"
    );
    write_status(&mut stream, status, reason(status))
}

struct OtlpRequest {
    method: String,
    path: String,
    content_type: String,
    body: Vec<u8>,
}

enum ReadFail {
    TooLarge,
    Bad,
    Io(std::io::Error),
}

fn read_request(stream: &mut TcpStream) -> Result<OtlpRequest, ReadFail> {
    let mut buf = vec![0_u8; 8 * 1024];
    let mut collected = Vec::new();
    loop {
        let n = stream.read(&mut buf).map_err(ReadFail::Io)?;
        if n == 0 && collected.is_empty() {
            return Err(ReadFail::Bad);
        }
        collected.extend_from_slice(&buf[..n]);
        // Headers plus one extra MiB is the hard ceiling, even before Content-Length.
        if collected.len() > OTLP_MAX_BODY + 16 * 1024 {
            return Err(ReadFail::TooLarge);
        }
        let Some(header_end) = header_end(&collected) else {
            if n == 0 {
                return Err(ReadFail::Bad);
            }
            continue;
        };
        let length = content_length(&collected).ok_or(ReadFail::Bad)?;
        if length > OTLP_MAX_BODY {
            return Err(ReadFail::TooLarge);
        }
        if collected.len() < header_end + length {
            if n == 0 {
                return Err(ReadFail::Bad);
            }
            continue;
        }
        return parse_head(&collected, header_end, length);
    }
}

fn parse_head(buf: &[u8], header_end: usize, length: usize) -> Result<OtlpRequest, ReadFail> {
    let head = std::str::from_utf8(&buf[..header_end]).map_err(|_| ReadFail::Bad)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(ReadFail::Bad)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(ReadFail::Bad)?.to_owned();
    let target = parts.next().ok_or(ReadFail::Bad)?;
    let path = target.split('?').next().unwrap_or(target).to_owned();
    let mut content_type = String::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-type") {
                content_type = value.trim().to_owned();
            }
        }
    }
    let body = buf[header_end..header_end + length].to_vec();
    Ok(OtlpRequest {
        method,
        path,
        content_type,
        body,
    })
}

fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n").map(|i| i + 4)
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

fn handle(request: &OtlpRequest, shared: &Mutex<OtlpShared>) -> u16 {
    if !request.method.eq_ignore_ascii_case("POST") {
        return 405;
    }
    if !matches!(request.path.as_str(), "/v1/logs" | "/v1/traces" | "/v1/metrics") {
        return 404;
    }
    if is_protobuf(&request.content_type) {
        return 415;
    }
    if !is_json(&request.content_type) && !request.content_type.is_empty() {
        return 415;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&request.body) else {
        return 400;
    };
    let mut guard = match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let agent = guard.agent.clone();
    let session = guard.session_id.clone();
    // Metrics are session metadata in a later card. Accept and retain nothing.
    if request.path == "/v1/metrics" {
        return 200;
    }
    let calls = otel_tool_calls(&agent, &value);
    for call in calls {
        let Some(bounded) = bound_tool_call(call) else {
            guard.store.record_gap(session.as_deref(), "oversize");
            continue;
        };
        match AgentEventRow::from_bounded(session.clone(), "otel", &bounded) {
            Ok(row) => {
                let _ = guard.store.insert(row);
            }
            Err(_) => guard.store.record_gap(session.as_deref(), "encode"),
        }
    }
    200
}

fn is_protobuf(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    lower.contains("application/x-protobuf") || lower.contains("application/protobuf")
}

fn is_json(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    lower.contains("application/json") || lower.contains("+json")
}

/// Pull tool-shaped log records out of an OTLP/JSON document.
///
/// Only `event.name` (or an attribute literally named `tool`) becomes `tool`.
/// Attribute values that are not a short string under the structured-key allow
/// list are dropped inside [`bound_tool_call`]. Prompt-shaped attributes are
/// not copied.
fn otel_tool_calls(agent: &str, value: &Value) -> Vec<AgentToolCall> {
    let mut out = Vec::new();
    let Some(records) = value
        .get("resourceLogs")
        .and_then(Value::as_array)
        .or_else(|| value.get("resource_logs").and_then(Value::as_array))
    else {
        return out;
    };
    for resource in records {
        let Some(scopes) = resource.get("scopeLogs").and_then(Value::as_array).or_else(|| {
            resource.get("scope_logs").and_then(Value::as_array)
        }) else {
            continue;
        };
        for scope in scopes {
            let Some(logs) = scope.get("logRecords").and_then(Value::as_array).or_else(|| {
                scope.get("log_records").and_then(Value::as_array)
            }) else {
                continue;
            };
            for log in logs {
                if let Some(call) = log_to_call(agent, log) {
                    out.push(call);
                }
            }
        }
    }
    out
}

fn log_to_call(agent: &str, log: &Value) -> Option<AgentToolCall> {
    let attributes = log.get("attributes").and_then(Value::as_array)?;
    let mut tool = None;
    let mut summary = Map::new();
    let mut call_id = None;
    let mut phase = ToolPhase::Unknown;
    for attribute in attributes {
        let key = attribute.get("key").and_then(Value::as_str)?;
        let text = attr_string(attribute.get("value")?)?;
        match key {
            "tool" | "event.name" | "gen_ai.tool.name" => tool = Some(text),
            "aw.phase" => {
                phase = match text.as_str() {
                    "pre" => ToolPhase::Pre,
                    "post" => ToolPhase::Post,
                    _ => ToolPhase::Unknown,
                };
            }
            "aw.call_id" | "gen_ai.tool.call.id" => call_id = Some(text),
            "command" | "path" | "url" | "query" => {
                summary.insert(key.to_owned(), Value::String(text));
            }
            _ => {}
        }
    }
    let tool = tool?;
    Some(AgentToolCall::new(
        agent,
        None,
        tool,
        phase,
        Value::Object(summary),
        call_id,
    ))
}

fn attr_string(value: &Value) -> Option<String> {
    value
        .get("stringValue")
        .or_else(|| value.get("string_value"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn write_status(stream: &mut TcpStream, status: u16, message: &str) -> std::io::Result<()> {
    let body = if status == 415 {
        json!({
            "error": "unsupported_media_type",
            "message": "protobuf OTLP is not accepted in this build; send JSON (Content-Type: application/json)",
        })
    } else if status == 413 {
        json!({ "error": "payload_too_large", "message": message })
    } else if (200..300).contains(&status) {
        json!({ "partialSuccess": {} })
    } else {
        json!({ "error": reason(status), "message": message })
    };
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(status),
        bytes.len(),
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&bytes)?;
    Ok(())
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        _ => "Error",
    }
}

/// Registry of OTLP endpoints keyed by session id. The daemon opens one per session.
#[derive(Default)]
pub struct OtlpRegistry {
    endpoints: BTreeMap<String, OtlpEndpoint>,
}

impl OtlpRegistry {
    /// Empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a listener for `session_id` if one is not already open.
    ///
    /// # Errors
    ///
    /// Bind failed. An existing listener is returned as `Ok` of its URL.
    pub fn open(&mut self, agent: &str, session_id: &str) -> std::io::Result<String> {
        if let Some(existing) = self.endpoints.get(session_id) {
            return Ok(existing.endpoint_url());
        }
        let endpoint = OtlpEndpoint::bind(agent, Some(session_id.to_owned()))?;
        let url = endpoint.endpoint_url();
        self.endpoints.insert(session_id.to_owned(), endpoint);
        Ok(url)
    }

    /// Stop and drop the listener for `session_id`, if any.
    pub fn close(&mut self, session_id: &str) {
        self.endpoints.remove(session_id);
    }
}
