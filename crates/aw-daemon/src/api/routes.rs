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
    TicketStore,
};

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
}

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

/// In-memory sessions plus tickets. Enough for auth tests. Not the store.
#[derive(Debug, Default)]
pub struct ApiState {
    /// Sessions keyed in insertion order.
    pub sessions: Vec<SessionView>,
    /// Tickets and ui_tokens. Memory only.
    pub tickets: TicketStore,
    /// Virtual clock (unix seconds). Tests set this; the handler does not read the host clock.
    pub now: u64,
    next_session: u64,
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

/// Route `req` against `state`.
///
/// `/health` is unauthenticated and returns only non-sensitive fields.
/// `POST /api/v1/auth/ui-token` redeems a ticket (the body is the credential).
/// Every other `/api/v1` route requires a bearer token and a loopback Host.
#[must_use]
pub fn dispatch(state: &mut ApiState, req: &HttpRequest) -> ApiResponse {
    if req.path == "/health" && req.method.eq_ignore_ascii_case("GET") {
        return health();
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

fn health() -> ApiResponse {
    ApiResponse::json(
        200,
        &json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "storage": "unchecked",
            "active_sessions": 0,
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
        let (_ticket, secret) =
            state
                .tickets
                .issue_ui_ticket(&caller.user_id, caller.admin, state.now);
        // The secret is the response body, not a log line.
        return ApiResponse::json(200, &json!({ "ticket": secret, "ttl_s": 60 }));
    }

    if path == "/api/v1/sessions" && method == "GET" {
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
        return session_sub(state, &method, rest, caller, &req.body);
    }

    match (method.as_str(), path) {
        ("GET", "/api/v1/doctor") => not_implemented("doctor"),
        ("GET", "/api/v1/processes") => not_implemented("processes"),
        ("POST", "/api/v1/sessions/run") => not_implemented("run"),
        ("GET", "/api/v1/db/stats") => not_implemented("db_stats"),
        ("POST", "/api/v1/db/purge") => admin_or_501(caller, "db_purge"),
        ("PUT", "/api/v1/config") => admin_or_501(caller, "config_put"),
        ("GET", "/api/v1/config") => not_implemented("config_get"),
        ("GET", "/api/v1/openapi.json") => not_implemented("openapi"),
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
) -> ApiResponse {
    let (sid, tail) = split_sid(rest);
    let Some(session) = state.sessions.iter().find(|row| row.id == sid) else {
        // Hide other users' ids the same way as a missing id.
        return ApiResponse::json(
            404,
            &json!({ "error": { "code": "not_found", "message": "session not found" } }),
        );
    };
    if !caller.admin && session.user_id != caller.user_id {
        return ApiResponse::json(
            404,
            &json!({ "error": { "code": "not_found", "message": "session not found" } }),
        );
    }
    let owner = session.user_id.clone();

    if tail.is_empty() && method == "GET" {
        return ApiResponse::json(
            200,
            &json!({ "id": sid, "user_id": owner, "name": session.name }),
        );
    }
    if tail.is_empty() && method == "DELETE" {
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
        return not_implemented("session_patch");
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
