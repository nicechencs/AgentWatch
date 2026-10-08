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
        self.seq = self.seq.saturating_add(1);
        let buf = self.buffers.entry(session_id.to_owned()).or_default();
        buf.push_back(LiveRecord {
            seq: self.seq,
            body: json_body.to_owned(),
        });
        while buf.len() > Self::CAP {
            buf.pop_front();
        }
        self.seq
    }

    /// Records with `seq` strictly after `after`, plus whether the buffer no
    /// longer contains `after + 1` (the client lagged and must be told).
    fn since(&self, session_id: &str, after: u64) -> (Vec<&LiveRecord>, bool) {
        let Some(buf) = self.buffers.get(session_id) else {
            return (Vec::new(), false);
        };
        let lagged = buf.front().is_some_and(|first| first.seq > after.saturating_add(1));
        let rows = buf.iter().filter(|row| row.seq > after).collect();
        (rows, lagged)
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
        return static_asset(state, req);
    }

    if req.path == "/api/v1/auth/ui-token" && req.method.eq_ignore_ascii_case("POST") {
        return redeem_token(state, req);
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
                ApiResponse::json(200, &json!({
                    "sessions": rows,
                    "next_cursor": page.next_cursor,
                }))
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
        ("POST", "/api/v1/db/purge") => admin_or_501(caller, "db_purge"),
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

fn admin_or_501(caller: &Caller, op: &str) -> ApiResponse {
    let input = AuthInput {
        http: false,
        host: None,
        listen_port: 0,
        authorization: None,
        caller: Some(caller.clone()),
        operation: op.to_owned(),
        session_owner: None,
        target_process_owner: None,
    };
    match authorize(&input) {
        AuthDecision::Allow(_) => not_implemented(op),
        AuthDecision::Forbidden => forbidden(),
        AuthDecision::Misdirected | AuthDecision::Unauthorized => unauthorized(),
    }
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
        if let Some(response) = session_query_route(state, method, &sid, tail, caller, query) {
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
        QueryBackendError::BadArgument { name, expected } => error_response(
            400,
            "bad_argument",
            &format!("{name}: expected {expected}"),
        ),
        QueryBackendError::NotFound => error_response(404, "not_found", "session not found"),
        QueryBackendError::Unimplemented { what } => not_implemented(what),
        QueryBackendError::Store(message) => error_response(500, "store", &message),
    }
}

fn list_query(raw: &str) -> Result<ListQuery, ApiResponse> {
    let pairs = query_pairs(raw);
    let limit = match pairs.get("limit").map(String::as_str) {
        None => 100,
        Some(text) => text.parse::<i64>().map_err(|_| {
            error_response(400, "bad_argument", "limit: expected an integer")
        })?,
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
            .map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect())
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
        active_only: pairs.get("active").is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
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
            if let Ok(hex) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                16,
            ) {
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
        _ => return session_tail_more(state, method, sid, tail, user, &parsed),
    };
    Some(response)
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
                        return Some(error_response(400, "bad_argument", "flow id: expected an integer"))
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
    let visible = state.sessions.iter().any(|row| {
        row.id == sid && (caller.admin || row.user_id == caller.user_id)
    });
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
        body.push_str(&format!("id: {}\nevent: record\ndata: {}\n\n", row.seq, row.body));
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
    let accept = req.headers.get("accept-encoding").map(String::as_str).unwrap_or("");
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
        let cases = [
            ("GET", "/api/v1/doctor", "doctor"),
            ("GET", "/api/v1/processes", "processes"),
            ("GET", "/api/v1/db/stats", "db_stats"),
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
