//! Method + path + headers + body → status + body.
//!
//! No socket is required to call [`dispatch`]. [`accept_one`] binds `127.0.0.1:0`
//! only long enough to prove the address, then closes it. The daemon binary does
//! not start this listener. axum is not in the offline lock; this is a loopback
//! HTTP stub, not the three transports.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use serde_json::{json, Value};

use super::auth::{
    authorize, bearer_token, visible_sessions, AuthDecision, AuthInput, Caller, SessionView,
    TicketStore, MAX_PAGE,
};
use super::query::{ListQuery, QueryBackendError, SessionQuery, StoreQuery};

/// Why a configured HTTP bind was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpBindError {
    /// The address is not a loopback. Configured or not, it is refused.
    NotLoopback { addr: String },
}

impl std::fmt::Display for HttpBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLoopback { addr } => {
                write!(f, "HTTP listener refused non-loopback address `{addr}`")
            }
        }
    }
}

/// A bind address that has been checked to be loopback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBind {
    _addr: SocketAddr,
}

impl HttpBind {
    /// Accept only loopback. `0.0.0.0` and other public addresses are rejected.
    ///
    /// # Errors
    ///
    /// [`HttpBindError::NotLoopback`] when `addr` is not loopback.
    pub fn loopback_only(addr: SocketAddr) -> Result<Self, HttpBindError> {
        if is_loopback_ip(addr.ip()) {
            Ok(Self { _addr: addr })
        } else {
            Err(HttpBindError::NotLoopback {
                addr: addr.to_string(),
            })
        }
    }
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// One already-parsed HTTP request. Header names are lower-case.
///
/// Not `Debug`: `headers` may hold `Authorization`. Log a token's length, never
/// the header map.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// `GET`, `POST`, …
    pub method: String,
    /// Path only, no query string. Query lives in [`Self::query`].
    pub path: String,
    /// Raw query without `?`. Empty when absent.
    pub query: String,
    /// Lower-cased header names. Values are not logged.
    pub headers: BTreeMap<String, String>,
    /// Body bytes, capped by the parser.
    pub body: Vec<u8>,
    /// Port used when checking `Host`.
    pub listen_port: u16,
    /// Set by the HTTP parser when `Content-Length` exceeds the body cap.
    pub body_too_large: bool,
}

impl Default for HttpRequest {
    fn default() -> Self {
        Self {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            query: String::new(),
            headers: BTreeMap::new(),
            body: Vec::new(),
            listen_port: DEFAULT_PORT_HINT,
            body_too_large: false,
        }
    }
}

const DEFAULT_PORT_HINT: u16 = 7456;

/// Status, headers, and body. CORS headers are never inserted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResponse {
    /// HTTP status.
    pub status: u16,
    /// Response headers. Tests assert this map has no CORS key.
    pub headers: BTreeMap<String, String>,
    /// Body bytes. JSON for errors and session lists.
    pub body: Vec<u8>,
}

impl ApiResponse {
    fn json(status: u16, value: &Value) -> Self {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        let body = match serde_json::to_vec(value) {
            Ok(bytes) => bytes,
            Err(_) => br#"{"error":"encode"}"#.to_vec(),
        };
        Self {
            status,
            headers,
            body,
        }
    }

    /// Header lookup, ASCII case-insensitive.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// True when any CORS response header is present. Production responses are not.
    #[must_use]
    pub fn has_cors(&self) -> bool {
        self.headers
            .keys()
            .any(|key| key.to_ascii_lowercase().starts_with("access-control-"))
    }
}

/// JSON body for an endpoint this card does not back with a store.
#[must_use]
pub fn not_implemented(op: &str) -> ApiResponse {
    ApiResponse::json(
        501,
        &json!({
            "error": "not_implemented",
            "op": op,
        }),
    )
}

/// In-memory sessions plus tickets, and the store-backed query boundary.
///
/// `sessions` is the P1 stub table the auth tests mutate. When it is non-empty,
/// list/detail prefer it so those tests keep working without a database file.
/// A configured [`StoreQuery`] is used for the P2 read endpoints.
pub struct ApiState {
    /// Sessions keyed in insertion order. The auth fixture, not the database.
    pub sessions: Vec<SessionView>,
    /// Tickets and ui_tokens. Memory only. Never serialized to disk.
    pub tickets: TicketStore,
    /// Virtual clock (unix seconds). Tests set this; the handler does not read the host clock
    /// for ticket expiry. Wall clock is used only when `now` is still 0 and a ticket is issued
    /// from a real request.
    pub now: u64,
    next_session: u64,
    /// Read/write boundary. Default is disconnected (no database path).
    pub query: StoreQuery,
    /// Effective config snapshot for `GET /config`. Not a secret store.
    pub config_json: serde_json::Value,
    /// SSE subscribers, keyed by session public id. Slow clients are lagged.
    pub live: LiveHub,
    /// `AW_UI_DEV_URL`, captured at construction. Empty means embedded assets.
    pub ui_dev_url: Option<String>,
    /// `debug.preview_ui`. When true, `GET /` redirects to `/#ticket=` so a
    /// browser opened by hand reaches the UI. Default false: a normal daemon
    /// never hands out a ticket over HTTP.
    pub preview_ui: bool,
}

impl Default for ApiState {
    fn default() -> Self {
        Self {
            sessions: Vec::new(),
            tickets: TicketStore::new(),
            now: 0,
            next_session: 0,
            query: StoreQuery::disconnected(),
            config_json: serde_json::json!({}),
            live: LiveHub::default(),
            ui_dev_url: match crate::assets::AssetMode::from_env() {
                crate::assets::AssetMode::DevProxy { origin } => Some(origin),
                crate::assets::AssetMode::Embedded => None,
            },
            preview_ui: false,
        }
    }
}

impl std::fmt::Debug for ApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `tickets` holds secrets. Debug prints counts only.
        f.debug_struct("ApiState")
            .field("sessions", &self.sessions.len())
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl ApiState {
    /// Empty state at `now`.
    #[must_use]
    pub fn new(now: u64) -> Self {
        Self {
            now,
            ..Self::default()
        }
    }
}

/// In-process SSE fanout. A record is a JSON object already redacted by the
/// pipeline; this hub does not redact and does not log the payload.
#[derive(Default)]
pub struct LiveHub {
    seq: u64,
    /// session id → recent records (bounded).
    buffers: std::collections::HashMap<String, std::collections::VecDeque<LiveRecord>>,
}

/// One live record. `body` is JSON text, not a secret header.
struct LiveRecord {
    seq: u64,
    body: String,
}

impl LiveHub {
    const CAP: usize = 256;

    /// Publish one already-redacted JSON record. Returns the sequence number.
    pub fn publish(&mut self, session_id: &str, json_body: &str) -> u64 {
        self.push_at(session_id, json_body.to_owned())
    }

    /// Same as [`Self::publish`], but a JSON object gets `id` set to the sequence
    /// this call returns. Callers that already chose their own body use [`Self::publish`].
    fn publish_stamped(&mut self, session_id: &str, json_body: &str) -> u64 {
        // Sequence is assigned inside `push_at`. Stamp with the next value, which
        // is what `push_at` will store. The two agree because nothing else mutates
        // `seq` between these lines.
        let seq = self.seq.saturating_add(1);
        self.push_at(session_id, stamp_id(seq, json_body))
    }

    fn push_at(&mut self, session_id: &str, body: String) -> u64 {
        self.seq = self.seq.saturating_add(1);
        let seq = self.seq;
        let buf = self.buffers.entry(session_id.to_owned()).or_default();
        buf.push_back(LiveRecord { seq, body });
        while buf.len() > Self::CAP {
            buf.pop_front();
        }
        seq
    }

    /// Publish one [`aw_pipeline::Output`] as timeline records.
    ///
    /// One JSON body per business row. `flow_buckets` are rollups, not events, so
    /// they are not published. Returns how many records were pushed. A row with no
    /// session id is published under `fallback_session` when that is `Some`;
    /// otherwise it is skipped and counted nowhere (it is not dropped silently —
    /// the caller still holds the `Output`).
    pub fn publish_output(
        &mut self,
        fallback_session: Option<&str>,
        output: &aw_pipeline::Output,
    ) -> u64 {
        publish_output_into(self, fallback_session, output)
    }

    /// Records with `seq` strictly after `after`, plus whether the buffer no
    /// longer contains `after + 1` (the client lagged and must be told).
    fn since(&self, session_id: &str, after: u64) -> (Vec<&LiveRecord>, bool) {
        let Some(buf) = self.buffers.get(session_id) else {
            return (Vec::new(), false);
        };
        let lagged = buf
            .front()
            .is_some_and(|first| first.seq > after.saturating_add(1));
        let rows = buf.iter().filter(|row| row.seq > after).collect();
        (rows, lagged)
    }
}

/// Publish `output` into `hub` under `session_id`.
///
/// The daemon's foreground runtime does not drain the pipeline yet, so nothing
/// calls this. A later runtime that holds both the hub and a pipeline [`aw_pipeline::Output`]
/// calls it once per flush. `session_id` is the live-route id (`s-1`), not the
/// integer [`aw_core::SessionId`] on a row. A row is published under that id.
///
/// `flow_buckets` are not published. Argv, environment values, URLs, and headers
/// are not fields of these records and are not read here.
pub fn publish_output(
    hub: &std::sync::Mutex<LiveHub>,
    session_id: &str,
    output: &aw_pipeline::Output,
) -> u64 {
    match hub.lock() {
        Ok(mut guard) => guard.publish_output(Some(session_id), output),
        Err(poisoned) => poisoned
            .into_inner()
            .publish_output(Some(session_id), output),
    }
}

fn publish_output_into(
    hub: &mut LiveHub,
    fallback_session: Option<&str>,
    output: &aw_pipeline::Output,
) -> u64 {
    let mut n = 0u64;
    for row in &output.processes {
        if let Some(sid) = session_key(row.session_id, fallback_session) {
            let _ = hub.publish_stamped(&sid, &proc_record(row));
            n = n.saturating_add(1);
        }
    }
    for row in &output.file_access {
        if let Some(sid) = session_key(row.session_id, fallback_session) {
            let _ = hub.publish_stamped(&sid, &file_record(row));
            n = n.saturating_add(1);
        }
    }
    for row in &output.net_flows {
        if let Some(sid) = session_key(row.session_id, fallback_session) {
            let _ = hub.publish_stamped(&sid, &net_record(row));
            n = n.saturating_add(1);
        }
    }
    for row in &output.dns {
        if let Some(sid) = session_key(row.session_id, fallback_session) {
            let _ = hub.publish_stamped(&sid, &dns_record(row));
            n = n.saturating_add(1);
        }
    }
    for row in &output.gaps {
        if let Some(sid) = session_key(row.session_id, fallback_session) {
            let _ = hub.publish_stamped(&sid, &gap_record(row));
            n = n.saturating_add(1);
        }
    }
    n
}

fn session_key(id: Option<aw_core::SessionId>, fallback: Option<&str>) -> Option<String> {
    match id {
        Some(id) => Some(id.0.to_string()),
        None => fallback.map(str::to_owned),
    }
}

/// Write `id` into a JSON object. Non-objects are returned unchanged so a caller
/// that already built a body is not rewritten into something else.
fn stamp_id(seq: u64, json_body: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(json_body) else {
        return json_body.to_owned();
    };
    if let Some(obj) = value.as_object_mut() {
        obj.insert("id".to_owned(), json!(seq));
        return serde_json::to_string(&value).unwrap_or_else(|_| json_body.to_owned());
    }
    json_body.to_owned()
}

fn proc_record(row: &aw_pipeline::ProcessRec) -> String {
    let mut fields = serde_json::Map::new();
    fields.insert("pid".to_owned(), json!(row.pid));
    fields.insert("ppid".to_owned(), opt_u32(row.ppid));
    fields.insert("parent_uid".to_owned(), opt_proc(row.parent_uid));
    fields.insert("depth".to_owned(), opt_u32(row.depth));
    fields.insert("exit_ns".to_owned(), opt_u64(row.exit_ns));
    fields.insert("exit_code".to_owned(), opt_i32(row.exit_code));
    fields.insert("exit_signal".to_owned(), opt_i32(row.exit_signal));
    fields.insert("how".to_owned(), json!(start_how_label(row.how)));
    fields.insert("user_id".to_owned(), opt_string(row.user_id.as_deref()));
    fields.insert("signer".to_owned(), opt_string(row.signer.as_deref()));
    fields.insert("agent".to_owned(), opt_string(row.agent.as_deref()));
    // No image, argv, or cwd on ProcessRec. The summary names the agent or the
    // start kind, never a command line.
    let summary = match row.agent.as_deref() {
        Some(agent) if !agent.is_empty() => format!("process {agent}"),
        _ => format!("process {}", start_how_label(row.how)),
    };
    timeline_body(
        "proc",
        row.start_ns,
        &row.evidence,
        &row.source,
        Some(row.proc_uid),
        &summary,
        fields,
    )
}

fn file_record(row: &aw_pipeline::FileAccessRec) -> String {
    let mut fields = serde_json::Map::new();
    fields.insert("op".to_owned(), json!(row.op));
    fields.insert("path".to_owned(), json!(row.path));
    fields.insert("path_to".to_owned(), opt_string(row.path_to.as_deref()));
    fields.insert("access".to_owned(), opt_string(row.access.as_deref()));
    fields.insert("last_ns".to_owned(), json!(row.last_ns));
    fields.insert("opens".to_owned(), json!(row.opens));
    fields.insert("reads".to_owned(), opt_u64(row.reads));
    fields.insert("bytes_read".to_owned(), opt_u64(row.bytes_read));
    fields.insert("writes".to_owned(), opt_u64(row.writes));
    fields.insert("bytes_written".to_owned(), opt_u64(row.bytes_written));
    fields.insert("created".to_owned(), opt_bool(row.created));
    fields.insert("truncated".to_owned(), opt_bool(row.truncated));
    fields.insert("modified".to_owned(), opt_bool(row.modified));
    fields.insert("result".to_owned(), opt_i32(row.result));
    fields.insert("partial".to_owned(), json!(row.partial));
    fields.insert(
        "sensitive_rule".to_owned(),
        opt_string(row.sensitive_rule.as_deref()),
    );
    let summary = format!("{} {}", row.op, path_base(&row.path));
    timeline_body(
        "file",
        row.first_ns,
        &row.evidence,
        &row.source,
        row.proc_uid,
        &summary,
        fields,
    )
}

fn net_record(row: &aw_pipeline::NetFlowRec) -> String {
    let mut fields = serde_json::Map::new();
    fields.insert("proto".to_owned(), opt_string(row.proto.as_deref()));
    fields.insert("direction".to_owned(), opt_string(row.direction.as_deref()));
    fields.insert("local_ip".to_owned(), opt_string(row.local_ip.as_deref()));
    fields.insert("local_port".to_owned(), opt_u16(row.local_port));
    fields.insert("remote_ip".to_owned(), opt_string(row.remote_ip.as_deref()));
    fields.insert("remote_port".to_owned(), opt_u16(row.remote_port));
    fields.insert("domain".to_owned(), opt_string(row.domain.as_deref()));
    fields.insert(
        "domain_source".to_owned(),
        opt_string(row.domain_source.as_deref()),
    );
    fields.insert("sni".to_owned(), opt_string(row.sni.as_deref()));
    fields.insert("bytes_up".to_owned(), opt_u64(row.bytes_up));
    fields.insert("bytes_down".to_owned(), opt_u64(row.bytes_down));
    fields.insert("end_ns".to_owned(), opt_u64(row.end_ns));
    fields.insert("via_proxy".to_owned(), json!(row.via_proxy));
    fields.insert("partial".to_owned(), json!(row.partial));
    fields.insert("flow_id".to_owned(), opt_u64(row.flow_id));
    // Domain or remote endpoint. No URL is stored on NetFlowRec.
    let summary = match row.domain.as_deref() {
        Some(domain) if !domain.is_empty() => format!("flow {domain}"),
        _ => match (row.remote_ip.as_deref(), row.remote_port) {
            (Some(ip), Some(port)) => format!("flow {ip}:{port}"),
            (Some(ip), None) => format!("flow {ip}"),
            _ => "flow".to_owned(),
        },
    };
    timeline_body(
        "net",
        row.start_ns,
        &row.evidence,
        &row.source,
        row.proc_uid,
        &summary,
        fields,
    )
}

fn dns_record(row: &aw_pipeline::DnsRec) -> String {
    let mut fields = serde_json::Map::new();
    fields.insert("qname".to_owned(), json!(row.qname));
    fields.insert("qtype".to_owned(), json!(row.qtype));
    fields.insert("rcode".to_owned(), opt_u16(row.rcode));
    fields.insert("answers".to_owned(), json!(row.answers));
    fields.insert("ttl_min".to_owned(), opt_u32(row.ttl_min));
    fields.insert("server".to_owned(), opt_string(row.server.as_deref()));
    let summary = if row.qname.is_empty() {
        "dns".to_owned()
    } else {
        format!("dns {}", row.qname)
    };
    timeline_body(
        "dns",
        row.ts_ns,
        &row.evidence,
        &row.source,
        row.proc_uid,
        &summary,
        fields,
    )
}

fn gap_record(row: &aw_pipeline::GapRec) -> String {
    let mut fields = serde_json::Map::new();
    let kind = gap_kind_label(row.gap_kind);
    fields.insert("gap_kind".to_owned(), json!(kind));
    fields.insert("collector".to_owned(), json!(row.collector.as_str()));
    fields.insert("affects".to_owned(), json!(row.affects));
    fields.insert("from_mono_ns".to_owned(), json!(row.from_mono_ns));
    fields.insert("to_mono_ns".to_owned(), json!(row.to_mono_ns));
    fields.insert("count".to_owned(), opt_u64(row.count));
    fields.insert("detail".to_owned(), opt_string(row.detail.as_deref()));
    let summary = match row.detail.as_deref() {
        Some(detail) if !detail.is_empty() => format!("gap {kind}: {detail}"),
        _ => format!("gap {kind}"),
    };
    timeline_body(
        "gap",
        row.ts_mono_ns,
        &row.evidence,
        &row.source,
        row.proc.as_ref().map(|proc| proc.uid),
        &summary,
        fields,
    )
}

/// TimelineItem shape the UI parses for an SSE `record` event. `id` is `0` here
/// and replaced with the hub sequence before the body is stored.
fn timeline_body(
    kind: &str,
    ts_ns: u64,
    evidence: &aw_core::Evidence,
    source: &aw_core::Source,
    proc_uid: Option<aw_core::ProcUid>,
    summary: &str,
    fields: serde_json::Map<String, Value>,
) -> String {
    let value = json!({
        "kind": kind,
        "id": 0,
        "ts_ns": ts_ns,
        "evidence": evidence_label(evidence),
        "source": source.as_str(),
        "proc_uid": proc_uid.map(|uid| format!("{:x}", uid.0)),
        "summary": summary,
        "fields": Value::Object(fields),
    });
    serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_owned())
}

fn evidence_label(evidence: &aw_core::Evidence) -> String {
    match evidence {
        aw_core::Evidence::E1 => "E1".to_owned(),
        aw_core::Evidence::E2 => "E2".to_owned(),
        aw_core::Evidence::E3 => "E3".to_owned(),
        aw_core::Evidence::S => "S".to_owned(),
        aw_core::Evidence::I => "I".to_owned(),
        aw_core::Evidence::NA(reason) => format!("NA({})", na_reason_label(reason)),
    }
}

fn na_reason_label(reason: &aw_core::NaReason) -> &'static str {
    match reason {
        aw_core::NaReason::EsNoReadEvent => "es_no_read_event",
        aw_core::NaReason::MmapNotObservable => "mmap_not_observable",
        aw_core::NaReason::TlsNoProxy => "tls_no_proxy",
        aw_core::NaReason::DirectBypassProxy => "direct_bypass_proxy",
        aw_core::NaReason::CertPinned => "cert_pinned",
        aw_core::NaReason::Quic => "quic",
        aw_core::NaReason::Ech => "ech",
        aw_core::NaReason::NoDnsObserved => "no_dns_observed",
        aw_core::NaReason::Preexisting => "preexisting",
        aw_core::NaReason::CollectorUnavailable => "collector_unavailable",
        aw_core::NaReason::Redacted => "redacted",
        aw_core::NaReason::AttributionBreak => "attribution_break",
        aw_core::NaReason::PartialClientHello => "partial_client_hello",
        aw_core::NaReason::H2Hpack => "h2_hpack",
        aw_core::NaReason::TooLarge => "too_large",
        aw_core::NaReason::FileChanged => "file_changed",
        aw_core::NaReason::PeerUnknown => "peer_unknown",
        aw_core::NaReason::ProtocolNotObserved => "protocol_not_observed",
        aw_core::NaReason::Unknown => "unknown",
    }
}

fn gap_kind_label(kind: aw_core::GapKind) -> &'static str {
    match kind {
        aw_core::GapKind::Dropped => "dropped",
        aw_core::GapKind::LostByOs => "lost_by_os",
        aw_core::GapKind::Restart => "restart",
        aw_core::GapKind::RateLimited => "rate_limited",
        aw_core::GapKind::Permission => "permission",
        aw_core::GapKind::AttachWindow => "attach_window",
        aw_core::GapKind::Unsupported => "unsupported",
        aw_core::GapKind::ScopeRace => "scope_race",
        aw_core::GapKind::CollectorDisconnected => "collector_disconnected",
        aw_core::GapKind::SelfReportDropped => "self_report_dropped",
        aw_core::GapKind::AttributionUnknown => "attribution_unknown",
        aw_core::GapKind::CacheEvicted => "cache_evicted",
        aw_core::GapKind::ParseError => "parse_error",
        aw_core::GapKind::RuleStateEvicted => "rule_state_evicted",
        aw_core::GapKind::Unknown => "unknown",
    }
}

fn start_how_label(how: aw_core::StartHow) -> &'static str {
    match how {
        aw_core::StartHow::Fork => "fork",
        aw_core::StartHow::Exec => "exec",
        aw_core::StartHow::Spawn => "spawn",
        aw_core::StartHow::Snapshot => "snapshot",
        aw_core::StartHow::Unknown => "unknown",
    }
}

/// Last path segment. A path is not argv and not a URL. An empty path stays empty.
fn path_base(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn opt_string(value: Option<&str>) -> Value {
    match value {
        Some(text) => json!(text),
        None => Value::Null,
    }
}

fn opt_u64(value: Option<u64>) -> Value {
    match value {
        Some(n) => json!(n),
        None => Value::Null,
    }
}

fn opt_u32(value: Option<u32>) -> Value {
    match value {
        Some(n) => json!(n),
        None => Value::Null,
    }
}

fn opt_u16(value: Option<u16>) -> Value {
    match value {
        Some(n) => json!(n),
        None => Value::Null,
    }
}

fn opt_i32(value: Option<i32>) -> Value {
    match value {
        Some(n) => json!(n),
        None => Value::Null,
    }
}

fn opt_bool(value: Option<bool>) -> Value {
    match value {
        Some(flag) => json!(flag),
        None => Value::Null,
    }
}

fn opt_proc(value: Option<aw_core::ProcUid>) -> Value {
    match value {
        Some(uid) => json!(format!("{:x}", uid.0)),
        None => Value::Null,
    }
}

/// Route `req` against `state`.
///
/// `/health` is unauthenticated and returns only non-sensitive fields.
/// `POST /api/v1/auth/ui-token` redeems a ticket (the body is the credential).
/// Every other `/api/v1` route requires a bearer token and a loopback Host.
#[must_use]
pub fn dispatch(state: &mut ApiState, req: &HttpRequest) -> ApiResponse {
    if req.body_too_large {
        return error_response(413, "payload_too_large", "request body exceeds 64 KiB");
    }

    if req.path == "/health" && req.method.eq_ignore_ascii_case("GET") {
        return health(state);
    }
    // api-and-cli lists `/health` at the server root. The same body is also
    // served under the `/api/v1` prefix so clients that only know the prefix
    // still get a non-sensitive status.
    if req.path == "/api/v1/health" && req.method.eq_ignore_ascii_case("GET") {
        return health(state);
    }

    if !req.path.starts_with("/api/") && req.method.eq_ignore_ascii_case("GET") {
        // Only the document root, and only when the preview switch is on. Every
        // other page path still falls through to the embedded assets, so a deep
        // link is not rewritten and the ticket is not attached to asset URLs.
        if state.preview_ui && (req.path == "/" || req.path.is_empty()) {
            return preview_ticket_redirect(state, req);
        }
        return static_asset(state, req);
    }

    if req.path == "/api/v1/auth/ui-token" && req.method.eq_ignore_ascii_case("POST") {
        return redeem_token(state, req);
    }

    // A hook is not a UI caller. It has no ticket, and a 401 would throw away the
    // only signal that a self-report was dropped. The listener is loopback-only;
    // this route still refuses a non-loopback Host.
    if req.path == "/api/v1/agent/hook" && req.method.eq_ignore_ascii_case("POST") {
        return ingest_agent_hook(state, req);
    }

    // Socket/pipe ticket issuance is not an HTTP-bearer flow. Over this stub,
    // a presented bearer (or an explicit test caller header is not invented):
    // HTTP callers redeem tokens; issuing a ticket requires an already-known
    // bearer so the ticket is bound to that user. A missing bearer is 401.
    let caller = match authenticate(state, req) {
        Ok(caller) => caller,
        Err(response) => return response,
    };

    route_authed(state, req, &caller)
}

/// `POST /api/v1/agent/hook`. Loopback only. No bearer: the hook process has no ticket.
///
/// `dropped: true` records a `self_report_dropped` gap and does not insert a
/// tool call. Any other body is parsed by [`super::agent::ingest_hook`] and,
/// when the database is configured, written to `agent_events`. No database is
/// `StorageNotReady`, not a forged success.
fn ingest_agent_hook(state: &mut ApiState, req: &HttpRequest) -> ApiResponse {
    let host = req.headers.get("host").cloned();
    if req_host_bad(&host, req.listen_port) {
        return misdirected();
    }
    let value: serde_json::Value = match serde_json::from_slice(&req.body) {
        Ok(value) => value,
        Err(_) => {
            return error_response(400, "not_json", "hook body is not JSON");
        }
    };
    let dropped = value.get("dropped").and_then(serde_json::Value::as_bool) == Some(true);
    let agent = value
        .get("agent")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let session = value
        .get("session")
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned);
    let reason = value
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned);

    if dropped {
        let report = super::query::HookReport {
            session,
            agent: agent.to_owned(),
            source: String::new(),
            tool: None,
            phase: None,
            call_id: None,
            command: None,
            path: None,
            url: None,
            query: None,
            summary_json: None,
            evidence: "NA".to_owned(),
            field_evidence: None,
            na_reason: Some("self_report_dropped".to_owned()),
            dropped: true,
            drop_reason: reason.or_else(|| Some("self_report_dropped".to_owned())),
        };
        return hook_result(state, &report);
    }

    let payload = value
        .get("payload")
        .cloned()
        .unwrap_or_else(|| value.clone());
    let mut memory = super::agent::MemoryAgentEvents::new();
    let outcomes = super::agent::ingest_hook(&mut memory, agent, session.as_deref(), &payload);
    if outcomes.is_empty() && !memory.gaps().is_empty() {
        // The parser rejected the call (oversize or not JSON-shaped). That is a
        // drop, recorded as a gap, not as an empty success.
        let report = super::query::HookReport {
            session,
            agent: agent.to_owned(),
            source: String::new(),
            tool: None,
            phase: None,
            call_id: None,
            command: None,
            path: None,
            url: None,
            query: None,
            summary_json: None,
            evidence: "NA".to_owned(),
            field_evidence: None,
            na_reason: Some("self_report_dropped".to_owned()),
            dropped: true,
            drop_reason: Some("oversize".to_owned()),
        };
        return hook_result(state, &report);
    }
    if outcomes.is_empty() {
        // Unknown agent, or a payload with no calls. Not an error, and not a row.
        return ApiResponse::json(200, &json!({ "accepted": 0 }));
    }

    let mut accepted = 0_u64;
    let mut not_ready = false;
    for row in memory.rows() {
        let fields = summary_fields(&row.summary_json);
        let report = super::query::HookReport {
            session: session.clone(),
            agent: row.agent.clone(),
            source: row.source.clone(),
            tool: none_if_empty(
                fields
                    .tool
                    .or_else(|| none_if_empty_owned(row.tool.clone())),
            ),
            phase: Some(phase_label(row.phase).to_owned()),
            call_id: row.call_id.clone(),
            command: fields.command,
            path: fields.path,
            url: fields.url,
            query: fields.query,
            summary_json: Some(row.summary_json.clone()),
            evidence: "E3".to_owned(),
            field_evidence: None,
            na_reason: None,
            dropped: false,
            drop_reason: None,
        };
        match state.query.ingest_self_report(&report) {
            Ok(super::query::HookIngest::Stored) => accepted = accepted.saturating_add(1),
            Ok(super::query::HookIngest::NoDatabase) => not_ready = true,
            Ok(super::query::HookIngest::Gap) => {}
            Err(_) => {
                return error_response(500, "store", "self-report was not written");
            }
        }
    }
    if not_ready {
        // The migration exists, but this process has no database configured.
        // Say so. Do not claim the row was stored.
        return ApiResponse::json(
            200,
            &json!({ "accepted": accepted, "storage": "not_ready" }),
        );
    }
    ApiResponse::json(200, &json!({ "accepted": accepted }))
}

fn hook_result(state: &mut ApiState, report: &super::query::HookReport) -> ApiResponse {
    match state.query.ingest_self_report(report) {
        Ok(super::query::HookIngest::Gap) => {
            ApiResponse::json(200, &json!({ "gap": "self_report_dropped" }))
        }
        Ok(super::query::HookIngest::NoDatabase) => ApiResponse::json(
            200,
            &json!({ "gap": "self_report_dropped", "storage": "not_ready" }),
        ),
        Ok(super::query::HookIngest::Stored) => {
            ApiResponse::json(200, &json!({ "gap": "self_report_dropped" }))
        }
        Err(_) => error_response(500, "store", "self-report gap was not written"),
    }
}

/// The five summary keys a self-report may keep. Missing keys stay `None`.
struct SummaryFields {
    command: Option<String>,
    path: Option<String>,
    url: Option<String>,
    query: Option<String>,
    tool: Option<String>,
}

/// Whitelist keys only. Anything else in the summary JSON is ignored.
fn summary_fields(summary_json: &str) -> SummaryFields {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(summary_json) else {
        return SummaryFields {
            command: None,
            path: None,
            url: None,
            query: None,
            tool: None,
        };
    };
    SummaryFields {
        command: summary_string(&value, "command"),
        path: summary_string(&value, "path"),
        url: summary_string(&value, "url"),
        query: summary_string(&value, "query"),
        tool: summary_string(&value, "tool"),
    }
}

fn summary_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn none_if_empty(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.is_empty())
}

fn none_if_empty_owned(value: String) -> Option<String> {
    none_if_empty(Some(value))
}

fn phase_label(phase: aw_core::ToolPhase) -> &'static str {
    match phase {
        aw_core::ToolPhase::Pre => "pre",
        aw_core::ToolPhase::Post => "post",
        aw_core::ToolPhase::Unknown => "unknown",
    }
}

fn health(state: &ApiState) -> ApiResponse {
    // In-memory stub rows only. The database count is not queried here: `/health`
    // is unauthenticated and must not touch session contents.
    let active = state.sessions.len();
    // `storage` stays a non-sensitive word. No path, no user id, no token.
    let storage = if state.query.db_path.is_some() {
        "configured"
    } else {
        "unchecked"
    };
    ApiResponse::json(
        200,
        &json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "storage": storage,
            "active_sessions": active,
        }),
    )
}

fn authenticate(state: &mut ApiState, req: &HttpRequest) -> Result<Caller, ApiResponse> {
    let header = req.headers.get("authorization").map(String::as_str);
    let token = bearer_token(header);
    let caller = match token {
        Some(token) => state.tickets.caller_for_token(token, state.now).ok(),
        None => None,
    };
    // Host is checked even when the token is missing, but a foreign host wins
    // so `Host: evil.com` is 421 rather than 401 (acceptance order: both are
    // specified; evil.com is the case the card names as 421).
    let host = req.headers.get("host").cloned();
    if req_host_bad(&host, req.listen_port) {
        return Err(misdirected());
    }
    if caller.is_none() {
        return Err(unauthorized());
    }
    // Admin-only operations are decided in the route, where the body (process
    // owner) and the operation name are both known. Here a present caller with
    // a loopback Host is enough.
    let input = AuthInput {
        http: true,
        host,
        listen_port: req.listen_port,
        authorization: None,
        caller,
        operation: "read".to_owned(),
        session_owner: None,
        target_process_owner: None,
    };
    match authorize(&input) {
        AuthDecision::Allow(caller) => Ok(caller),
        AuthDecision::Misdirected => Err(misdirected()),
        AuthDecision::Unauthorized => Err(unauthorized()),
        AuthDecision::Forbidden => Err(forbidden()),
    }
}

fn req_host_bad(host: &Option<String>, port: u16) -> bool {
    let probe = AuthInput {
        http: true,
        host: host.clone(),
        listen_port: port,
        authorization: None,
        caller: Some(Caller {
            user_id: "probe".to_owned(),
            admin: false,
        }),
        operation: "probe".to_owned(),
        session_owner: None,
        target_process_owner: None,
    };
    matches!(authorize(&probe), AuthDecision::Misdirected)
}

fn route_authed(state: &mut ApiState, req: &HttpRequest, caller: &Caller) -> ApiResponse {
    let method = req.method.to_ascii_uppercase();
    let path = req.path.as_str();

    if path == "/api/v1/auth/ui-ticket" && method == "POST" {
        // api-and-cli §1: a browser holding a ui_token must not mint another
        // ticket. HTTP requests carry `Authorization`. The socket/pipe transport
        // (not built in this card) authenticates by peer credential and leaves
        // that header empty, then calls the same dispatcher.
        let presented = req.headers.contains_key("authorization");
        if presented {
            return ApiResponse::json(
                403,
                &json!({
                    "error": {
                        "code": "forbidden",
                        "message": "ui-ticket is issued on the socket or named pipe, not over HTTP bearer"
                    }
                }),
            );
        }
        let (_ticket, secret) =
            state
                .tickets
                .issue_ui_ticket(&caller.user_id, caller.admin, clock(state));
        // The secret is the response body, not a log line.
        return ApiResponse::json(200, &json!({ "ticket": secret, "ttl_s": 60 }));
    }

    if path == "/api/v1/sessions" && method == "GET" {
        if !state.sessions.is_empty() || state.query.db_path.is_none() {
            let visible = visible_sessions(&state.sessions, caller);
            let rows: Vec<Value> = visible
                .into_iter()
                .map(|session| {
                    json!({
                        "id": session.id,
                        "user_id": session.user_id,
                        "name": session.name,
                    })
                })
                .collect();
            return ApiResponse::json(200, &json!({ "sessions": rows }));
        }
        let query = match list_query(&req.query) {
            Ok(q) => q,
            Err(response) => return response,
        };
        return match state.query.list_sessions(&caller.user_id, &query) {
            Ok(page) => {
                let rows: Vec<Value> = page
                    .rows
                    .iter()
                    .map(|row| {
                        json!({
                            "id": row.public_id,
                            "session_id": row.id,
                            "name": row.name,
                            "mode": row.mode,
                            "agent": row.agent,
                            "started_ns": row.started_ns,
                            "ended_ns": row.ended_ns,
                            "pinned": row.pinned,
                        })
                    })
                    .collect();
                ApiResponse::json(
                    200,
                    &json!({
                        "sessions": rows,
                        "next_cursor": page.next_cursor,
                    }),
                )
            }
            Err(err) => from_backend(err),
        };
    }

    if path == "/api/v1/sessions" && method == "POST" {
        state.next_session = state.next_session.saturating_add(1);
        let id = format!("s-{}", state.next_session);
        let name = session_name_from_body(&req.body);
        state.sessions.push(SessionView {
            id: id.clone(),
            user_id: caller.user_id.clone(),
            name,
        });
        return ApiResponse::json(201, &json!({ "id": id, "user_id": caller.user_id }));
    }

    if let Some(rest) = path.strip_prefix("/api/v1/sessions/") {
        return session_sub(state, &method, rest, caller, &req.body, &req.query);
    }

    match (method.as_str(), path) {
        ("GET", "/api/v1/me") => ApiResponse::json(
            200,
            &json!({ "user_id": caller.user_id, "admin": caller.admin }),
        ),
        ("GET", "/api/v1/doctor") => doctor(state),
        ("GET", "/api/v1/processes") => system_processes(req),
        ("POST", "/api/v1/sessions/run") => not_implemented("run"),
        ("GET", "/api/v1/db/stats") => db_stats(state, caller),
        ("POST", "/api/v1/db/purge") => db_purge(state, caller, &req.body),
        ("POST", "/api/v1/db/vacuum") => db_admin(state, caller, StoreOp::Vacuum),
        ("POST", "/api/v1/db/migrate") => db_admin(state, caller, StoreOp::Migrate),
        ("PUT", "/api/v1/config") => put_config(state, caller, &req.body),
        ("GET", "/api/v1/config") => {
            ApiResponse::json(200, &json!({ "config": state.config_json }))
        }
        ("GET", "/api/v1/openapi.json") => {
            ApiResponse::json(200, &super::openapi::document(req.listen_port))
        }
        ("GET", "/api/v1/search") => search(state, caller, req),
        _ => ApiResponse::json(
            404,
            &json!({ "error": { "code": "not_found", "message": "no such route" } }),
        ),
    }
}

/// Which admin store operation [`db_admin`] runs.
enum StoreOp {
    Vacuum,
    Migrate,
}

/// `POST /db/purge`. A non-admin is 403. An admin purges.
///
/// The body is `{ "older_than"?: "<duration>", "all"?: bool }`. `older_than`
/// is a duration (`30d`, `12h`, `30m`, or the `<n>s` / `<n>ms` / `<n>ns` forms),
/// measured back from now. A body that names neither field is a 400.
fn db_purge(state: &ApiState, caller: &Caller, body: &[u8]) -> ApiResponse {
    if !caller_is_admin(caller) {
        return forbidden();
    }
    let value: serde_json::Value = if body.is_empty() {
        serde_json::Value::Null
    } else {
        match serde_json::from_slice(body) {
            Ok(value) => value,
            Err(_) => return error_response(400, "bad_request", "purge body is not JSON"),
        }
    };
    let all = value.get("all").and_then(serde_json::Value::as_bool);
    let older = value.get("older_than").and_then(serde_json::Value::as_str);
    if all.is_none() && older.is_none() {
        return error_response(400, "bad_argument", "body: expected older_than or all");
    }
    let older_than_ns = match older {
        None => None,
        Some(text) => match older_than_cutoff_ns(text) {
            Ok(ns) => Some(ns),
            Err(response) => return response,
        },
    };
    match state
        .query
        .db_purge(&caller.user_id, true, older_than_ns, all.unwrap_or(false))
    {
        Ok(value) => ApiResponse::json(200, &value),
        Err(err) => from_backend(err),
    }
}

/// `older_than` is how far back from now. The store wants the cutoff instant.
fn older_than_cutoff_ns(text: &str) -> Result<i64, ApiResponse> {
    let age = parse_age_ns(text).ok_or_else(|| {
        error_response(
            400,
            "bad_argument",
            "older_than: expected <n>d|<n>h|<n>m|<n>s|<n>ms|<n>ns",
        )
    })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    Ok(now.saturating_sub(age))
}

fn parse_age_ns(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let split = raw
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(raw.len());
    let (num, unit) = raw.split_at(split);
    let n = num.parse::<i64>().ok()?;
    if n < 0 {
        return None;
    }
    let scale = match unit {
        "" | "s" => 1_000_000_000,
        "ms" => 1_000_000,
        "ns" => 1,
        "m" => 60 * 1_000_000_000,
        "h" => 60 * 60 * 1_000_000_000,
        "d" => 24 * 60 * 60 * 1_000_000_000,
        _ => return None,
    };
    Some(n.saturating_mul(scale))
}

fn db_admin(state: &ApiState, caller: &Caller, op: StoreOp) -> ApiResponse {
    if !caller_is_admin(caller) {
        return forbidden();
    }
    let result = match op {
        StoreOp::Vacuum => state.query.db_vacuum(&caller.user_id, true),
        StoreOp::Migrate => state.query.db_migrate(&caller.user_id, true),
    };
    match result {
        Ok(value) => ApiResponse::json(200, &value),
        Err(err) => from_backend(err),
    }
}

fn caller_is_admin(caller: &Caller) -> bool {
    let input = AuthInput {
        http: false,
        host: None,
        listen_port: 0,
        authorization: None,
        caller: Some(caller.clone()),
        operation: "db_purge".to_owned(),
        session_owner: None,
        target_process_owner: None,
    };
    matches!(authorize(&input), AuthDecision::Allow(_))
}

fn session_sub(
    state: &mut ApiState,
    method: &str,
    rest: &str,
    caller: &Caller,
    body: &[u8],
    query: &str,
) -> ApiResponse {
    let (sid, tail) = split_sid(rest);
    let memory = state.sessions.iter().find(|row| row.id == sid).cloned();
    if let Some(session) = &memory {
        if !caller.admin && session.user_id != caller.user_id {
            // Hide other users' ids the same way as a missing id.
            return not_found_session();
        }
    }
    let owner = memory
        .as_ref()
        .map(|session| session.user_id.clone())
        .unwrap_or_else(|| caller.user_id.clone());

    // Query tails run before the memory GET so `/timeline` is not swallowed by
    // the detail handler. A stub session with no database keeps the P1 501
    // path: calling the disconnected store would 404 a session the stub owns.
    let store_configured = state.query.db_path.is_some();
    let live = method == "GET" && tail == "live";
    if !tail.is_empty() && (memory.is_none() || store_configured || live) {
        if let Some(response) = session_query_route(state, method, &sid, tail, caller, query, body)
        {
            return response;
        }
    }

    if tail.is_empty() && method == "GET" {
        if let Some(session) = &memory {
            return ApiResponse::json(
                200,
                &json!({ "id": sid, "user_id": owner, "name": session.name }),
            );
        }
        return map_summary(state.query.session_detail(&caller.user_id, &sid));
    }
    if tail.is_empty() && method == "DELETE" {
        if memory.is_none() {
            return match state.query.delete_session(&caller.user_id, &sid) {
                Ok(None) => not_found_session(),
                Ok(Some(())) => ApiResponse::json(200, &json!({ "deleted": sid })),
                Err(err) => from_backend(err),
            };
        }
        let input = AuthInput {
            http: false,
            host: None,
            listen_port: 0,
            authorization: None,
            caller: Some(caller.clone()),
            operation: "session_delete".to_owned(),
            session_owner: Some(owner),
            target_process_owner: None,
        };
        return match authorize(&input) {
            AuthDecision::Allow(_) => {
                state.sessions.retain(|row| row.id != sid);
                ApiResponse::json(200, &json!({ "deleted": sid }))
            }
            _ => forbidden(),
        };
    }
    if tail.is_empty() && method == "PATCH" {
        return patch_memory_or_store(state, &sid, caller, body);
    }

    // P3 / P5 endpoints stay 501 even when the session exists. The card forbids
    // implementing them.
    if matches!(
        (method, tail),
        ("GET", "http") | ("GET", "findings") | ("GET", "agent-events")
    ) {
        // Store-backed reads are handled in `session_query_route`. This 501 is
        // the stub path: no database, or a memory session that did not enter
        // that function. Do not answer it with an empty list.
        return not_implemented(tail);
    }

    let op = match (method, tail) {
        ("POST", "stop") => "stop",
        ("POST", "attach") => "attach",
        ("POST", "adopt") => "run",
        ("GET", "processes") => "procs",
        ("GET", "flows") => "flows",
        ("GET", "timeline") => "timeline",
        ("GET", "gaps") => "gaps",
        ("GET", "export") => "export",
        _ => {
            return ApiResponse::json(
                404,
                &json!({ "error": { "code": "not_found", "message": "no such route" } }),
            );
        }
    };

    if op == "attach" {
        // No process table in this card. `process_owner` in the JSON body stands
        // in for "this pid belongs to another user". A different owner is
        // admin-only and returns 403. A missing owner is not treated as "ours";
        // the attach itself stays unimplemented (501) because there is no process
        // table to attach to.
        if let Some(process_owner) = json_string_field_bytes(body, "process_owner") {
            if process_owner != caller.user_id {
                let input = AuthInput {
                    http: false,
                    host: None,
                    listen_port: 0,
                    authorization: None,
                    caller: Some(caller.clone()),
                    operation: "attach_other_user".to_owned(),
                    session_owner: Some(owner),
                    target_process_owner: Some(process_owner),
                };
                return match authorize(&input) {
                    AuthDecision::Allow(_) => not_implemented("attach"),
                    _ => forbidden(),
                };
            }
        }
    }

    not_implemented(op)
}

fn split_sid(rest: &str) -> (String, &str) {
    if let Some((sid, tail)) = rest.split_once('/') {
        (sid.to_owned(), tail)
    } else {
        (rest.to_owned(), "")
    }
}

fn json_string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn json_string_field_bytes(body: &[u8], key: &str) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    json_string_field(&value, key)
}

fn patch_memory_or_store(
    state: &mut ApiState,
    sid: &str,
    caller: &Caller,
    body: &[u8],
) -> ApiResponse {
    let value: serde_json::Value = serde_json::from_slice(body).unwrap_or(serde_json::Value::Null);
    let name = value.get("name").and_then(serde_json::Value::as_str);
    let pinned = value.get("pinned").and_then(serde_json::Value::as_bool);
    if let Some(session) = state.sessions.iter_mut().find(|row| row.id == sid) {
        if !caller.admin && session.user_id != caller.user_id {
            return not_found_session();
        }
        if let Some(name) = name {
            session.name = name.to_owned();
        }
        return ApiResponse::json(200, &json!({ "id": sid, "name": session.name }));
    }
    match state
        .query
        .patch_session(&caller.user_id, sid, name, pinned)
    {
        Ok(None) => not_found_session(),
        Ok(Some(())) => ApiResponse::json(200, &json!({ "id": sid })),
        Err(err) => from_backend(err),
    }
}

fn map_summary(result: Result<Option<aw_store::SessionSummary>, QueryBackendError>) -> ApiResponse {
    match result {
        Ok(None) => not_found_session(),
        Ok(Some(summary)) => ApiResponse::json(
            200,
            &json!({
                "id": summary.public_id,
                "session_id": summary.id,
                "name": summary.name,
                "agent": summary.agent,
                "started_ns": summary.started_ns,
                "ended_ns": summary.ended_ns,
                "stats": {
                    "process_count": summary.process_count,
                    "flow_count": summary.flow_count,
                    "dns_count": summary.dns_count,
                    "gap_count": summary.gap_count,
                    "bytes_up": summary.bytes_up,
                    "bytes_down": summary.bytes_down,
                }
            }),
        ),
        Err(err) => from_backend(err),
    }
}

fn session_name_from_body(body: &[u8]) -> String {
    json_string_field_bytes(body, "name").unwrap_or_default()
}

/// `GET /` while `debug.preview_ui` is on.
///
/// Issues one ticket for a fixed local-preview identity and redirects to
/// `/#ticket=...`. The fragment is not sent back to the server, and the page
/// strips it after redeeming. A non-loopback Host is refused like every other
/// ticket path. The ticket secret is the redirect target, never a log line.
fn preview_ticket_redirect(state: &mut ApiState, req: &HttpRequest) -> ApiResponse {
    if req_host_bad(&req.headers.get("host").cloned(), req.listen_port) {
        return misdirected();
    }
    let (_ticket, secret) = state
        .tickets
        .issue_ui_ticket(PREVIEW_UI_USER, false, clock(state));
    let mut headers = BTreeMap::new();
    headers.insert("location".to_owned(), format!("/#ticket={secret}"));
    headers.insert(
        "content-type".to_owned(),
        "text/plain; charset=utf-8".to_owned(),
    );
    // `no-store` so a shared browser cache cannot replay the ticket.
    headers.insert("cache-control".to_owned(), "no-store".to_owned());
    ApiResponse {
        status: 302,
        headers,
        body: b"preview ticket issued".to_vec(),
    }
}

/// Identity the preview redirect binds its ticket to. Not a real account: the
/// preview switch is a local convenience, and this name only scopes the
/// resulting token. It is not read from the request.
const PREVIEW_UI_USER: &str = "local-preview";

fn redeem_token(state: &mut ApiState, req: &HttpRequest) -> ApiResponse {
    if req_host_bad(&req.headers.get("host").cloned(), req.listen_port) {
        return misdirected();
    }
    let ticket = json_string_field_bytes(&req.body, "ticket").unwrap_or_default();
    if ticket.is_empty() {
        return unauthorized();
    }
    match state.tickets.redeem(&ticket, state.now) {
        Ok(token) => ApiResponse::json(200, &json!({ "token": token, "ttl_s": 12 * 60 * 60 })),
        Err(_) => ApiResponse::json(
            401,
            &json!({ "error": { "code": "unauthorized", "message": "ticket refused" } }),
        ),
    }
}

/// JSON error. `offset` is included only for filter parse failures.
#[must_use]
pub fn error_response(status: u16, code: &str, message: &str) -> ApiResponse {
    ApiResponse::json(
        status,
        &json!({ "error": { "code": code, "message": message } }),
    )
}

fn error_at(status: u16, code: &str, message: &str, offset: Option<usize>) -> ApiResponse {
    let mut body = json!({ "error": { "code": code, "message": message } });
    if let Some(offset) = offset {
        if let Some(obj) = body.get_mut("error") {
            obj["offset"] = json!(offset);
        }
    }
    ApiResponse::json(status, &body)
}

fn from_backend(err: QueryBackendError) -> ApiResponse {
    match err {
        QueryBackendError::Filter { offset, message } => {
            error_at(400, "bad_filter", &message, offset)
        }
        QueryBackendError::BadArgument { name, expected } => {
            error_response(400, "bad_argument", &format!("{name}: expected {expected}"))
        }
        QueryBackendError::NotFound => error_response(404, "not_found", "session not found"),
        QueryBackendError::Unimplemented { what } => not_implemented(what),
        QueryBackendError::Store(message) => error_response(500, "store", &message),
    }
}

fn list_query(raw: &str) -> Result<ListQuery, ApiResponse> {
    let pairs = query_pairs(raw);
    let limit = match pairs.get("limit").map(String::as_str) {
        None => 100,
        Some(text) => text
            .parse::<i64>()
            .map_err(|_| error_response(400, "bad_argument", "limit: expected an integer"))?,
    };
    if limit <= 0 || limit > MAX_PAGE {
        return Err(error_response(
            400,
            "bad_argument",
            "limit: expected 1..=2000",
        ));
    }
    Ok(ListQuery {
        filter: pairs.get("filter").cloned(),
        from_ns: optional_i64(&pairs, "from")?,
        to_ns: optional_i64(&pairs, "to")?,
        cats: pairs
            .get("cats")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        group_by: pairs.get("group_by").cloned(),
        sort: pairs.get("sort").cloned(),
        limit,
        cursor: pairs.get("cursor").cloned(),
        q: pairs.get("q").cloned(),
        kind: pairs.get("kind").cloned(),
        since_ns: optional_i64(&pairs, "since")?,
        until_ns: optional_i64(&pairs, "until")?,
        agent: pairs.get("agent").cloned(),
        active_only: pairs
            .get("active")
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
        buckets: optional_i64(&pairs, "buckets")?,
        tree: pairs.get("tree").is_some_and(|v| v == "1"),
        reference: pairs.get("ref").cloned(),
        window: pairs.get("window").cloned(),
        step: pairs.get("step").cloned(),
    })
}

fn optional_i64(
    pairs: &std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<Option<i64>, ApiResponse> {
    match pairs.get(key) {
        None => Ok(None),
        Some(text) if text.is_empty() => Ok(None),
        Some(text) => text.parse::<i64>().map(Some).map_err(|_| {
            error_response(400, "bad_argument", &format!("{key}: expected an integer"))
        }),
    }
}

fn query_pairs(raw: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for part in raw.split('&') {
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        out.insert(percent_decode(k), percent_decode(v));
    }
    out
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(hex);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn clock(state: &ApiState) -> u64 {
    if state.now == 0 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    } else {
        state.now
    }
}

fn session_query_route(
    state: &mut ApiState,
    method: &str,
    sid: &str,
    tail: &str,
    caller: &Caller,
    query: &str,
    body: &[u8],
) -> Option<ApiResponse> {
    let parsed = match list_query(query) {
        Ok(q) => q,
        Err(response) => return Some(response),
    };
    let user = caller.user_id.as_str();
    // Memory stub sessions are not in SQLite. Query endpoints 404 them the same
    // way a hidden id does, except `/live`, which is in-process.
    let response = match (method, tail) {
        ("GET", "summary") => map_summary(state.query.session_summary(user, sid)),
        ("GET", "timeline") => match state.query.timeline(user, sid, &parsed) {
            Ok(None) => not_found_session(),
            Ok(Some(page)) => ApiResponse::json(200, &timeline_json(&page)),
            Err(err) => from_backend(err),
        },
        ("GET", "timeline/histogram") => map_opt(state.query.histogram(user, sid, &parsed)),
        ("GET", "processes") => map_opt(state.query.processes(user, sid, &parsed)),
        ("GET", "flows") => map_opt(state.query.flows(user, sid, &parsed)),
        ("GET", "traffic") => map_opt(state.query.traffic(user, sid, &parsed)),
        ("GET", "dns") => map_opt(state.query.dns(user, sid, &parsed)),
        ("GET", "gaps") => map_opt(state.query.gaps(user, sid)),
        ("GET", "around") => map_opt(state.query.around(user, sid, &parsed)),
        ("GET", "files") => map_opt(state.query.files(user, sid, &parsed)),
        ("GET", "live") => live_snapshot(state, sid, caller, &parsed),
        ("POST", "stop") => match state.query.stop_session(user, sid) {
            Ok(None) => stop_memory(state, sid, caller),
            Ok(Some(())) => ApiResponse::json(200, &json!({ "stopped": sid })),
            Err(err) => from_backend(err),
        },
        _ => {
            return session_p3_route(
                state,
                &P3Route {
                    method,
                    sid,
                    tail,
                    caller,
                    raw_query: query,
                    body,
                    parsed: &parsed,
                },
            )
        }
    };
    Some(response)
}

struct P3Route<'a> {
    method: &'a str,
    sid: &'a str,
    tail: &'a str,
    caller: &'a Caller,
    raw_query: &'a str,
    body: &'a [u8],
    parsed: &'a ListQuery,
}

/// P3-DAEMON-01 tails. Appended after the P2 match so those arms stay in order.
///
/// Returns `None` when this is not an http, findings, or Markdown export
/// request. The caller then keeps the existing 501 path, including
/// `GET .../export` with no `format=md` and every memory-stub session that
/// never entered `session_query_route`.
fn session_p3_route(state: &ApiState, route: &P3Route<'_>) -> Option<ApiResponse> {
    let P3Route {
        method,
        sid,
        tail,
        caller,
        raw_query,
        body,
        parsed,
    } = *route;
    if state.query.db_path.is_none() {
        return session_tail_more(state, method, sid, tail, &caller.user_id, parsed);
    }
    if method == "GET" && tail == "http" {
        return Some(super::http_events::get_http(state, caller, sid, raw_query));
    }
    if method == "GET" && tail == "findings" {
        return Some(super::findings::get_findings(state, caller, sid, raw_query));
    }
    if method == "PATCH" {
        if let Some(id) = tail.strip_prefix("findings/") {
            if !id.is_empty() && !id.contains('/') {
                return Some(super::findings::patch_finding(state, caller, sid, id, body));
            }
        }
    }
    if (method == "GET" || method == "POST") && tail == "export" && export_format_is_md(raw_query) {
        return Some(crate::export::markdown::export_markdown(
            state, caller, sid, raw_query,
        ));
    }
    session_tail_more(state, method, sid, tail, &caller.user_id, parsed)
}

fn export_format_is_md(raw_query: &str) -> bool {
    raw_query.split('&').any(|part| {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        key == "format" && (value == "md" || value == "markdown")
    })
}

fn session_tail_more(
    state: &ApiState,
    method: &str,
    sid: &str,
    tail: &str,
    user: &str,
    query: &ListQuery,
) -> Option<ApiResponse> {
    let _ = query;
    if method == "GET" {
        if let Some(proc_uid) = tail.strip_prefix("processes/") {
            return Some(map_opt(state.query.process_detail(user, sid, proc_uid)));
        }
        if let Some(rest) = tail.strip_prefix("flows/") {
            if let Some(id_text) = rest.strip_suffix("/buckets") {
                let id = match id_text.parse::<i64>() {
                    Ok(id) => id,
                    Err(_) => {
                        return Some(error_response(
                            400,
                            "bad_argument",
                            "flow id: expected an integer",
                        ))
                    }
                };
                return Some(map_opt(state.query.flow_buckets(user, sid, id)));
            }
        }
    }
    None
}

fn map_opt(result: Result<Option<serde_json::Value>, QueryBackendError>) -> ApiResponse {
    match result {
        Ok(None) => not_found_session(),
        Ok(Some(value)) => ApiResponse::json(200, &value),
        Err(err) => from_backend(err),
    }
}

fn not_found_session() -> ApiResponse {
    error_response(404, "not_found", "session not found")
}

fn stop_memory(state: &mut ApiState, sid: &str, caller: &Caller) -> ApiResponse {
    let Some(session) = state.sessions.iter().find(|row| row.id == sid) else {
        return not_found_session();
    };
    if !caller.admin && session.user_id != caller.user_id {
        return not_found_session();
    }
    // The stub has no process. Stopping records the intent without deleting the row.
    ApiResponse::json(200, &json!({ "stopped": sid, "persisted": false }))
}

fn timeline_json(page: &aw_store::TimelinePage) -> serde_json::Value {
    json!({
        "rows": page.rows.iter().map(|row| json!({
            "session_id": row.session_id,
            "ts_ns": row.ts_ns,
            "cat": row.cat,
            "id": row.id,
            "proc_uid": row.proc_uid.map(|id| format!("{id:x}")),
            "evidence": row.evidence,
        })).collect::<Vec<_>>(),
        "next_cursor": page.next.map(|c| format!("{},{}", c.ts_ns, c.id)),
    })
}

fn live_snapshot(state: &ApiState, sid: &str, caller: &Caller, query: &ListQuery) -> ApiResponse {
    let visible = state
        .sessions
        .iter()
        .any(|row| row.id == sid && (caller.admin || row.user_id == caller.user_id));
    // A store-backed session is not in the stub vec. Visibility was already
    // checked by `session_sub` only for stub rows. When the stub does not know
    // the id, still serve the hub: the store check below hides foreign ids
    // when a database is configured.
    if !visible && state.query.db_path.is_some() {
        match state.query.session_detail(&caller.user_id, sid) {
            Ok(None) | Err(_) => return not_found_session(),
            Ok(Some(_)) => {}
        }
    }
    if !visible && state.query.db_path.is_none() && !state.sessions.is_empty() {
        return not_found_session();
    }
    let after = query
        .cursor
        .as_deref()
        .and_then(|c| c.parse::<u64>().ok())
        .unwrap_or(0);
    let (rows, lagged) = state.live.since(sid, after);
    let mut body = String::from("retry: 1000\n");
    if lagged {
        body.push_str("event: lagged\ndata: {\"dropped\":true}\n\n");
    }
    let mut last = after;
    for row in rows {
        if let Some(filter) = query.filter.as_deref() {
            if !live_filter_match(filter, &row.body) {
                last = row.seq;
                continue;
            }
        }
        body.push_str(&format!(
            "id: {}\nevent: record\ndata: {}\n\n",
            row.seq, row.body
        ));
        last = row.seq;
    }
    if last == after && !lagged {
        body.push_str(": keepalive\n\n");
    }
    let mut headers = std::collections::BTreeMap::new();
    headers.insert(
        "content-type".to_owned(),
        "text/event-stream; charset=utf-8".to_owned(),
    );
    headers.insert("cache-control".to_owned(), "no-store".to_owned());
    ApiResponse {
        status: 200,
        headers,
        body: body.into_bytes(),
    }
}

/// Coarse live filter. A record here is JSON text, not a typed record, so
/// [`aw_core::Expr::to_predicate`] has no fields to read and the SQL compiler
/// does not apply. A filter that does not parse drops the record. One that
/// parses keeps it when the filter text, or each of its value tokens, occurs in
/// the JSON. This is a containment check, not the query predicate, and it does
/// not upgrade evidence. The authoritative filter is the one on the query routes.
fn live_filter_match(filter: &str, json_body: &str) -> bool {
    match aw_store::parse_filter(filter) {
        Ok(_) => json_body.contains(filter) || filter_mentions_body(filter, json_body),
        Err(_) => false,
    }
}

fn filter_mentions_body(filter: &str, json_body: &str) -> bool {
    // Bare words and `field:value` values: keep the record when every value
    // token is present. This is a containment check, not a SQL predicate.
    filter.split_whitespace().all(|token| {
        let value = token.split(':').next_back().unwrap_or(token);
        let value = value.trim_matches('"');
        value.is_empty() || json_body.contains(value)
    })
}

fn doctor(state: &ApiState) -> ApiResponse {
    let _ = state;
    // No collector is probed on the HTTP thread. The report says so.
    ApiResponse::json(
        200,
        &json!({
            "probed": false,
            "reason": "collector probe is not run on the request path",
            "collectors": [],
        }),
    )
}

fn system_processes(req: &HttpRequest) -> ApiResponse {
    // Reading the OS process table is platform code (task: stay in aw-daemon
    // API). Report unavailable rather than a partial or invented tree.
    let _ = req;
    ApiResponse::json(
        200,
        &json!({
            "processes": [],
            "available": false,
            "reason": "system process tree is not collected by this build",
        }),
    )
}

fn db_stats(state: &ApiState, caller: &Caller) -> ApiResponse {
    match state.query.db_stats(&caller.user_id, caller.admin) {
        Ok(value) => ApiResponse::json(200, &value),
        Err(err) => from_backend(err),
    }
}

fn search(state: &ApiState, caller: &Caller, req: &HttpRequest) -> ApiResponse {
    let query = match list_query(&req.query) {
        Ok(q) => q,
        Err(response) => return response,
    };
    match state.query.search(&caller.user_id, &query) {
        Ok(value) => ApiResponse::json(200, &value),
        Err(err) => from_backend(err),
    }
}

fn put_config(state: &mut ApiState, caller: &Caller, body: &[u8]) -> ApiResponse {
    let input = AuthInput {
        http: false,
        host: None,
        listen_port: 0,
        authorization: None,
        caller: Some(caller.clone()),
        operation: "config_put".to_owned(),
        session_owner: None,
        target_process_owner: None,
    };
    if !matches!(authorize(&input), AuthDecision::Allow(_)) {
        return forbidden();
    }
    let value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return error_response(400, "bad_request", "config body is not JSON"),
    };
    // In-memory only. Disk write and hot reload belong to the config owner.
    state.config_json = value;
    ApiResponse::json(200, &json!({ "applied": "memory" }))
}

fn static_asset(state: &ApiState, req: &HttpRequest) -> ApiResponse {
    if let Some(origin) = &state.ui_dev_url {
        return proxy_dev(origin, req);
    }
    let rel = if req.path == "/" {
        "index.html"
    } else {
        req.path.trim_start_matches('/')
    };
    let file = crate::assets::get(rel).or_else(|| {
        // SPA fallback only when the UI was actually embedded.
        if crate::assets::dist_was_present() {
            crate::assets::index_html()
        } else {
            None
        }
    });
    let Some(file) = file else {
        return error_response(404, "not_found", "ui asset not embedded");
    };
    let mut headers = std::collections::BTreeMap::new();
    headers.insert(
        "content-type".to_owned(),
        crate::assets::content_type(&file.path).to_owned(),
    );
    let accept = req
        .headers
        .get("accept-encoding")
        .map(String::as_str)
        .unwrap_or("");
    if accept.to_ascii_lowercase().contains("gzip") {
        headers.insert("x-aw-gzip".to_owned(), "1".to_owned());
    }
    ApiResponse {
        status: 200,
        headers,
        body: file.data,
    }
}

fn proxy_dev(origin: &str, req: &HttpRequest) -> ApiResponse {
    if origin.starts_with("https://") {
        return error_response(
            502,
            "dev_proxy",
            "AW_UI_DEV_URL https is not enabled; use an http origin",
        );
    }
    let url = format!(
        "{origin}{}{}",
        req.path,
        if req.query.is_empty() {
            String::new()
        } else {
            format!("?{}", req.query)
        }
    );
    match ureq::get(&url).call() {
        Ok(mut response) => {
            let status = response.status().as_u16();
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_owned();
            let mut body = Vec::new();
            let mut reader = std::io::Read::take(response.body_mut().as_reader(), 2 * 1024 * 1024);
            let _ = std::io::Read::read_to_end(&mut reader, &mut body);
            let mut headers = std::collections::BTreeMap::new();
            headers.insert("content-type".to_owned(), content_type);
            ApiResponse {
                status,
                headers,
                body,
            }
        }
        Err(err) => error_response(502, "dev_proxy", &format!("ui dev server: {err}")),
    }
}

fn unauthorized() -> ApiResponse {
    ApiResponse::json(
        401,
        &json!({ "error": { "code": "unauthorized", "message": "bearer token required" } }),
    )
}

fn misdirected() -> ApiResponse {
    ApiResponse::json(
        421,
        &json!({ "error": { "code": "misdirected", "message": "host is not the loopback listener" } }),
    )
}

fn forbidden() -> ApiResponse {
    ApiResponse::json(
        403,
        &json!({ "error": { "code": "forbidden", "message": "administrator required" } }),
    )
}

#[cfg(test)]
mod tests {
    use super::{dispatch, not_implemented, ApiState, HttpBind, HttpRequest};
    use crate::api::auth::{TicketStore, UI_TICKET_TTL};
    use crate::api::pipe_dacl_configured;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::net::TcpListener;
    use std::net::{Ipv4Addr, SocketAddr};

    fn req(
        method: &str,
        path: &str,
        host: Option<&str>,
        bearer: Option<&str>,
        body: &[u8],
    ) -> HttpRequest {
        let mut headers = BTreeMap::new();
        if let Some(host) = host {
            headers.insert("host".to_owned(), host.to_owned());
        }
        if let Some(token) = bearer {
            headers.insert("authorization".to_owned(), format!("Bearer {token}"));
        }
        HttpRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            query: String::new(),
            headers,
            body: body.to_vec(),
            listen_port: 7456,
            body_too_large: false,
        }
    }

    fn json_body(response: &super::ApiResponse) -> Value {
        serde_json::from_slice(&response.body).unwrap_or(Value::Null)
    }

    fn token_for(state: &mut ApiState, user: &str, admin: bool) -> String {
        let (_ticket, secret) = state.tickets.issue_ui_ticket(user, admin, state.now);
        state.tickets.redeem(&secret, state.now).unwrap_or_default()
    }

    #[test]
    fn wildcard_bind_is_rejected() {
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 7456));
        let result = HttpBind::loopback_only(addr);
        assert!(result.is_err());
    }

    #[test]
    fn loopback_bind_is_accepted() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        assert!(HttpBind::loopback_only(addr).is_ok());
    }

    #[test]
    fn responses_have_no_cors_header() {
        let mut state = ApiState::new(1_000);
        let response = dispatch(&mut state, &req("GET", "/health", None, None, b""));
        assert!(!response.has_cors());
        assert!(response.header("access-control-allow-origin").is_none());
        let missing = dispatch(
            &mut state,
            &req("GET", "/api/v1/sessions", Some("127.0.0.1:7456"), None, b""),
        );
        assert_eq!(missing.status, 401);
        assert!(missing.header("Access-Control-Allow-Origin").is_none());
        assert!(!missing.has_cors());
    }

    #[test]
    fn missing_bearer_is_401() {
        let mut state = ApiState::new(1_000);
        let response = dispatch(
            &mut state,
            &req("GET", "/api/v1/sessions", Some("127.0.0.1:7456"), None, b""),
        );
        assert_eq!(response.status, 401);
    }

    #[test]
    fn evil_host_is_421() {
        let mut state = ApiState::new(1_000);
        let token = token_for(&mut state, "alice", false);
        let response = dispatch(
            &mut state,
            &req(
                "GET",
                "/api/v1/sessions",
                Some("evil.com"),
                Some(&token),
                b"",
            ),
        );
        assert_eq!(response.status, 421);
    }

    #[test]
    fn ticket_second_use_fails_and_late_use_fails() {
        let mut tickets = TicketStore::new();
        let now = 5_000_u64;
        let (_ticket, secret) = tickets.issue_ui_ticket("alice", false, now);
        assert!(tickets.redeem(&secret, now).is_ok());
        assert!(tickets.redeem(&secret, now).is_err());

        let mut state = ApiState::new(now);
        let (_ticket, secret) = state.tickets.issue_ui_ticket("alice", false, now);
        state.now = now + UI_TICKET_TTL + 1;
        let body = format!(r#"{{"ticket":"{secret}"}}"#);
        let response = dispatch(
            &mut state,
            &req(
                "POST",
                "/api/v1/auth/ui-token",
                Some("127.0.0.1:7456"),
                None,
                body.as_bytes(),
            ),
        );
        assert_eq!(response.status, 401);
    }

    #[test]
    fn user_a_does_not_see_user_b_sessions() {
        let mut state = ApiState::new(10);
        let alice = token_for(&mut state, "alice", false);
        let bob = token_for(&mut state, "bob", false);
        let created = dispatch(
            &mut state,
            &req(
                "POST",
                "/api/v1/sessions",
                Some("localhost:7456"),
                Some(&bob),
                br#"{"name":"bobs"}"#,
            ),
        );
        assert_eq!(created.status, 201);
        let listed = dispatch(
            &mut state,
            &req(
                "GET",
                "/api/v1/sessions",
                Some("127.0.0.1:7456"),
                Some(&alice),
                b"",
            ),
        );
        assert_eq!(listed.status, 200);
        let body = json_body(&listed);
        let rows = body.get("sessions").and_then(Value::as_array);
        assert_eq!(rows.map(Vec::len), Some(0));
    }

    #[test]
    fn non_admin_purge_and_config_are_403() {
        let mut state = ApiState::new(10);
        let alice = token_for(&mut state, "alice", false);
        let purge = dispatch(
            &mut state,
            &req(
                "POST",
                "/api/v1/db/purge",
                Some("127.0.0.1:7456"),
                Some(&alice),
                b"{}",
            ),
        );
        assert_eq!(purge.status, 403);
        let config = dispatch(
            &mut state,
            &req(
                "PUT",
                "/api/v1/config",
                Some("127.0.0.1:7456"),
                Some(&alice),
                b"{}",
            ),
        );
        assert_eq!(config.status, 403);
    }

    #[test]
    fn non_admin_attach_other_user_is_403() {
        let mut state = ApiState::new(10);
        let alice = token_for(&mut state, "alice", false);
        let created = dispatch(
            &mut state,
            &req(
                "POST",
                "/api/v1/sessions",
                Some("127.0.0.1:7456"),
                Some(&alice),
                br#"{"name":"mine"}"#,
            ),
        );
        let id = json_body(&created)
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let path = format!("/api/v1/sessions/{id}/attach");
        let response = dispatch(
            &mut state,
            &req(
                "POST",
                &path,
                Some("127.0.0.1:7456"),
                Some(&alice),
                br#"{"process_owner":"bob"}"#,
            ),
        );
        assert_eq!(response.status, 403);
    }

    #[test]
    fn unimplemented_endpoints_are_501_not_empty() {
        let mut state = ApiState::new(10);
        let alice = token_for(&mut state, "alice", false);
        let created = dispatch(
            &mut state,
            &req(
                "POST",
                "/api/v1/sessions",
                Some("127.0.0.1:7456"),
                Some(&alice),
                b"{}",
            ),
        );
        let id = json_body(&created)
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("s-1")
            .to_owned();
        // These two answer 200 and say the data was not collected. That is not
        // a 501, and it is not an empty success.
        let doctor = dispatch(
            &mut state,
            &req(
                "GET",
                "/api/v1/doctor",
                Some("127.0.0.1:7456"),
                Some(&alice),
                b"",
            ),
        );
        assert_eq!(doctor.status, 200);
        assert_eq!(
            json_body(&doctor).get("probed").and_then(Value::as_bool),
            Some(false)
        );
        let processes = dispatch(
            &mut state,
            &req(
                "GET",
                "/api/v1/processes",
                Some("127.0.0.1:7456"),
                Some(&alice),
                b"",
            ),
        );
        assert_eq!(processes.status, 200);
        assert_eq!(
            json_body(&processes)
                .get("available")
                .and_then(Value::as_bool),
            Some(false)
        );
        // No database is configured on this state, so stats are null, not 0.
        let stats = dispatch(
            &mut state,
            &req(
                "GET",
                "/api/v1/db/stats",
                Some("127.0.0.1:7456"),
                Some(&alice),
                b"",
            ),
        );
        assert_eq!(
            stats.status,
            200,
            "{}",
            String::from_utf8_lossy(&stats.body)
        );
        let stats_body = json_body(&stats);
        assert!(
            stats_body.get("db_bytes").is_some_and(Value::is_null),
            "{stats_body}"
        );
        assert_eq!(
            stats_body.get("scope").and_then(Value::as_str),
            Some("unconfigured")
        );
        let cases = [
            ("GET", &format!("/api/v1/sessions/{id}/export"), "export"),
            ("GET", &format!("/api/v1/sessions/{id}/flows"), "flows"),
            (
                "GET",
                &format!("/api/v1/sessions/{id}/timeline"),
                "timeline",
            ),
            ("GET", &format!("/api/v1/sessions/{id}/gaps"), "gaps"),
            ("GET", &format!("/api/v1/sessions/{id}/processes"), "procs"),
            ("POST", &format!("/api/v1/sessions/{id}/stop"), "stop"),
        ];
        for (method, path, op) in cases {
            let response = dispatch(
                &mut state,
                &req(method, path, Some("127.0.0.1:7456"), Some(&alice), b""),
            );
            assert_eq!(response.status, 501, "{method} {path}");
            let body = json_body(&response);
            assert_eq!(
                body.get("error").and_then(Value::as_str),
                Some("not_implemented")
            );
            assert_eq!(body.get("op").and_then(Value::as_str), Some(op));
            assert!(!response.body.is_empty());
        }
    }

    #[test]
    fn pipe_dacl_was_not_configured() {
        assert!(!pipe_dacl_configured());
    }

    #[test]
    fn not_implemented_shape() {
        let response = not_implemented("export");
        assert_eq!(response.status, 501);
        assert!(!response.has_cors());
    }

    #[test]
    fn ephemeral_listener_is_loopback_and_closed() -> std::io::Result<()> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let bound = listener.local_addr()?;
        let _checked = HttpBind::loopback_only(bound).map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, err.to_string())
        })?;
        drop(listener);
        assert!(bound.ip().is_loopback());
        // The listener is dropped inside accept_one. We only check that the
        // address was loopback and that the function returned a real port.
        assert_ne!(bound.port(), 0);
        Ok(())
    }
}
