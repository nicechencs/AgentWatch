//! Pure authorization decisions. No clock, no socket, no token logging.
//!
//! Time is a caller-supplied `now` (unix seconds). Host clock reads do not
//! belong in these functions so tests can expire a ticket without sleeping.

use std::collections::HashMap;

/// One-time UI ticket lifetime. api-and-cli §1: 60 seconds.
pub const UI_TICKET_TTL: u64 = 60;

/// In-memory UI token lifetime. api-and-cli §1: 12 hours.
pub const UI_TOKEN_TTL: u64 = 12 * 60 * 60;

/// Operations that require an administrator.
///
/// Ordinary users may list and mutate only their own sessions. Attaching to
/// another user's process, purging the database, and changing config are admin.
pub const ADMIN_OPS: &[&str] = &[
    "attach_other_user",
    "db_purge",
    "config_put",
    "delete_other_session",
];

/// Who is calling, already resolved by the transport.
///
/// HTTP fills this only after a bearer token maps to a user. Socket and pipe
/// transports are expected to fill `user_id` from peer credentials later; this
/// card does not query the operating system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// Stable user id. Sessions are keyed by this, not by a display name.
    pub user_id: String,
    /// `true` for root / Administrators. Ordinary users are `false`.
    pub admin: bool,
}

/// What the transport observed, before any allow/deny.
///
/// Not `Debug`: `authorization` is a bearer token. Do not print this struct.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthInput {
    /// `true` when the socket is a loopback HTTP listener.
    pub http: bool,
    /// `Host` header value, if the transport is HTTP. Absent means missing.
    pub host: Option<String>,
    /// Port the listener was bound to. Used only to check the Host header.
    pub listen_port: u16,
    /// Raw `Authorization` value. Never logged. Length-only if a caller logs.
    pub authorization: Option<String>,
    /// Resolved caller. `None` when HTTP has not presented a known token.
    pub caller: Option<Caller>,
    /// Operation name. Admin-only names are listed in [`ADMIN_OPS`].
    pub operation: String,
    /// Session owner, when the operation targets one session.
    pub session_owner: Option<String>,
    /// Process owner, when the operation attaches to a process.
    pub target_process_owner: Option<String>,
}

/// Allow, or why the request stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    /// The caller may proceed. Carries the resolved caller.
    Allow(Caller),
    /// HTTP `Host` is not the loopback listener. Respond 421.
    Misdirected,
    /// HTTP bearer token is missing or unknown. Respond 401.
    Unauthorized,
    /// The caller is authenticated but not allowed. Respond 403.
    Forbidden,
}

/// Why a ui_token was refused. The token text is not included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// The token is not in memory (unknown, expired, or never issued).
    UnknownToken,
}

/// Why [`TicketStore::redeem`] failed. The ticket text is not included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketError {
    /// No such ticket, or it was already redeemed.
    UnknownOrUsed,
    /// `now` is at or after `issued_at + UI_TICKET_TTL`.
    Expired,
}

/// A one-time ticket. The secret is the map key, not a field we display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiTicket {
    /// User the ticket is bound to.
    pub user_id: String,
    /// Whether that user is an administrator.
    pub admin: bool,
    /// Unix seconds when the ticket was issued.
    pub issued_at: u64,
}

/// In-memory tickets and the tokens they redeem into.
///
/// Nothing here is written to disk. Dropping the store drops every token.
#[derive(Debug, Default)]
pub struct TicketStore {
    tickets: HashMap<String, UiTicket>,
    /// token → (user_id, admin, expires_at_unix).
    tokens: HashMap<String, (String, bool, u64)>,
    next_id: u64,
}

impl TicketStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a one-time ticket for `user_id` at `now` (unix seconds).
    ///
    /// Returns `(ticket, secret)`. The secret is the only copy of the ticket
    /// id. Callers must not log it.
    pub fn issue_ui_ticket(&mut self, user_id: &str, admin: bool, now: u64) -> (UiTicket, String) {
        self.next_id = self.next_id.saturating_add(1);
        let secret = format!("t-{}-{now}", self.next_id);
        let ticket = UiTicket {
            user_id: user_id.to_owned(),
            admin,
            issued_at: now,
        };
        self.tickets.insert(secret.clone(), ticket.clone());
        (ticket, secret)
    }

    /// Redeem `ticket` at `now`. Second use fails. `now + 61` after issue fails.
    ///
    /// On success the ticket is removed and a ui_token (12 h from `now`) is stored.
    ///
    /// # Errors
    ///
    /// [`TicketError::UnknownOrUsed`] or [`TicketError::Expired`].
    pub fn redeem(&mut self, ticket: &str, now: u64) -> Result<String, TicketError> {
        let Some(issued) = self.tickets.get(ticket) else {
            return Err(TicketError::UnknownOrUsed);
        };
        if now >= issued.issued_at.saturating_add(UI_TICKET_TTL) {
            self.tickets.remove(ticket);
            return Err(TicketError::Expired);
        }
        let issued = match self.tickets.remove(ticket) {
            Some(issued) => issued,
            None => return Err(TicketError::UnknownOrUsed),
        };
        self.next_id = self.next_id.saturating_add(1);
        let token = format!("k-{}-{now}", self.next_id);
        let expires_at = now.saturating_add(UI_TOKEN_TTL);
        self.tokens
            .insert(token.clone(), (issued.user_id, issued.admin, expires_at));
        Ok(token)
    }

    /// Resolve a ui_token at `now`. Expired tokens are dropped.
    ///
    /// # Errors
    ///
    /// [`AuthError::UnknownToken`] when missing or expired.
    pub fn caller_for_token(&mut self, token: &str, now: u64) -> Result<Caller, AuthError> {
        let Some((user_id, admin, expires_at)) = self.tokens.get(token).cloned() else {
            return Err(AuthError::UnknownToken);
        };
        if now >= expires_at {
            self.tokens.remove(token);
            return Err(AuthError::UnknownToken);
        }
        Ok(Caller { user_id, admin })
    }
}

/// Decide whether this request may proceed.
///
/// Order: non-loopback listeners are refused by [`crate::routes::HttpBind`], not
/// here. HTTP with a foreign `Host` is [`AuthDecision::Misdirected`] (421).
/// Missing or unknown bearer is [`AuthDecision::Unauthorized`] (401). Admin-only
/// operations and cross-user attach / delete are [`AuthDecision::Forbidden`] (403).
#[must_use]
pub fn authorize(req: &AuthInput) -> AuthDecision {
    if req.http {
        if !host_matches_loopback(req.host.as_deref(), req.listen_port) {
            return AuthDecision::Misdirected;
        }
        if req.caller.is_none() {
            return AuthDecision::Unauthorized;
        }
    }
    let Some(caller) = req.caller.clone() else {
        return AuthDecision::Unauthorized;
    };
    if !caller.admin && is_forbidden(&caller, req) {
        return AuthDecision::Forbidden;
    }
    AuthDecision::Allow(caller)
}

fn is_forbidden(caller: &Caller, req: &AuthInput) -> bool {
    if ADMIN_OPS.contains(&req.operation.as_str()) {
        return true;
    }
    if req.operation == "attach" {
        if let Some(owner) = req.target_process_owner.as_deref() {
            if owner != caller.user_id {
                return true;
            }
        }
    }
    if req.operation == "session_delete" {
        if let Some(owner) = req.session_owner.as_deref() {
            if owner != caller.user_id {
                return true;
            }
        }
    }
    false
}

/// `Host` must be `127.0.0.1:<port>` or `localhost:<port>`.
fn host_matches_loopback(host: Option<&str>, port: u16) -> bool {
    let Some(host) = host else {
        return false;
    };
    let host = host.trim();
    let expected_ip = format!("127.0.0.1:{port}");
    let expected_name = format!("localhost:{port}");
    host.eq_ignore_ascii_case(&expected_ip) || host.eq_ignore_ascii_case(&expected_name)
}

/// One session row visible to the API. In memory only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionView {
    /// Public id.
    pub id: String,
    /// Owning user. Ordinary callers only see rows with their own id.
    pub user_id: String,
    /// Optional label. Not a secret.
    pub name: String,
}

/// Ordinary users see only their own sessions. Admins see all of them.
#[must_use]
pub fn visible_sessions<'a>(sessions: &'a [SessionView], caller: &Caller) -> Vec<&'a SessionView> {
    if caller.admin {
        return sessions.iter().collect();
    }
    sessions
        .iter()
        .filter(|session| session.user_id == caller.user_id)
        .collect()
}

/// Extract a bearer token from an `Authorization` header.
///
/// Returns `None` when the header is missing or is not `Bearer <token>`.
/// The token text is returned to the caller; this function does not log it.
#[must_use]
pub fn bearer_token(authorization: Option<&str>) -> Option<&str> {
    let header = authorization?;
    let mut parts = header.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let token = parts.next()?.trim();
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
        Some(token)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{
        authorize, bearer_token, visible_sessions, AuthDecision, AuthInput, Caller, SessionView,
        TicketError, TicketStore, UI_TICKET_TTL,
    };

    fn http_input(host: Option<&str>, caller: Option<Caller>, operation: &str) -> AuthInput {
        AuthInput {
            http: true,
            host: host.map(str::to_owned),
            listen_port: 7456,
            authorization: None,
            caller,
            operation: operation.to_owned(),
            session_owner: None,
            target_process_owner: None,
        }
    }

    #[test]
    fn missing_bearer_is_unauthorized() {
        let decision = authorize(&http_input(Some("127.0.0.1:7456"), None, "sessions_list"));
        assert_eq!(decision, AuthDecision::Unauthorized);
    }

    #[test]
    fn evil_host_is_misdirected() {
        let user = Caller {
            user_id: "a".to_owned(),
            admin: false,
        };
        let decision = authorize(&http_input(Some("evil.com"), Some(user), "sessions_list"));
        assert_eq!(decision, AuthDecision::Misdirected);
    }

    #[test]
    fn ticket_second_use_and_late_use_fail() {
        let mut store = TicketStore::new();
        let now = 1_000_u64;
        let (_ticket, secret) = store.issue_ui_ticket("alice", false, now);
        let first = store.redeem(&secret, now);
        assert!(first.is_ok());
        let second = store.redeem(&secret, now);
        assert_eq!(second, Err(TicketError::UnknownOrUsed));

        let (_again, secret_late) = store.issue_ui_ticket("alice", false, now);
        let late = store.redeem(&secret_late, now + UI_TICKET_TTL + 1);
        assert_eq!(late, Err(TicketError::Expired));
    }

    #[test]
    fn token_expires_after_twelve_hours() {
        let mut store = TicketStore::new();
        let now = 50_u64;
        let (_ticket, secret) = store.issue_ui_ticket("alice", false, now);
        let token = store.redeem(&secret, now);
        assert!(token.is_ok());
        let token = match token {
            Ok(token) => token,
            Err(_) => return,
        };
        assert!(store.caller_for_token(&token, now).is_ok());
        let twelve_hours = now + super::UI_TOKEN_TTL;
        assert!(store.caller_for_token(&token, twelve_hours).is_err());
    }

    #[test]
    fn user_a_does_not_see_user_b() {
        let sessions = vec![
            SessionView {
                id: "s-a".to_owned(),
                user_id: "alice".to_owned(),
                name: "a".to_owned(),
            },
            SessionView {
                id: "s-b".to_owned(),
                user_id: "bob".to_owned(),
                name: "b".to_owned(),
            },
        ];
        let alice = Caller {
            user_id: "alice".to_owned(),
            admin: false,
        };
        let visible = visible_sessions(&sessions, &alice);
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].id, "s-a");
    }

    #[test]
    fn admin_sees_both_sessions() {
        let sessions = vec![
            SessionView {
                id: "s-a".to_owned(),
                user_id: "alice".to_owned(),
                name: "a".to_owned(),
            },
            SessionView {
                id: "s-b".to_owned(),
                user_id: "bob".to_owned(),
                name: "b".to_owned(),
            },
        ];
        let root = Caller {
            user_id: "root".to_owned(),
            admin: true,
        };
        assert_eq!(visible_sessions(&sessions, &root).len(), 2);
    }

    #[test]
    fn non_admin_admin_ops_are_forbidden() {
        let user = Caller {
            user_id: "alice".to_owned(),
            admin: false,
        };
        for op in ["attach_other_user", "db_purge", "config_put"] {
            let decision = authorize(&http_input(Some("localhost:7456"), Some(user.clone()), op));
            assert_eq!(decision, AuthDecision::Forbidden, "{op}");
        }
    }

    #[test]
    fn admin_admin_ops_are_allowed() {
        let admin = Caller {
            user_id: "root".to_owned(),
            admin: true,
        };
        let decision = authorize(&http_input(Some("127.0.0.1:7456"), Some(admin), "db_purge"));
        assert!(matches!(decision, AuthDecision::Allow(_)));
    }

    #[test]
    fn bearer_parse_rejects_empty_and_basic() {
        assert_eq!(bearer_token(None), None);
        assert_eq!(bearer_token(Some("Basic abc")), None);
        assert_eq!(bearer_token(Some("Bearer ")), None);
        assert_eq!(bearer_token(Some("Bearer secret")), Some("secret"));
    }
}
