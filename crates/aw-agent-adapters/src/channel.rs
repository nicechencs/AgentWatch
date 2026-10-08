//! E3 source trait. Adapters implement this later. This module has no I/O.

use std::fmt;

/// Session the daemon hands to a self-report source.
///
/// Only the session id. No process environment, no paths, no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHandle {
    session_id: String,
}

impl SessionHandle {
    /// `session_id` is the daemon's session id string, not a pid.
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
        }
    }

    /// Session id passed to [`SessionHandle::new`].
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

/// Failure while starting or stopping a self-report source.
///
/// There is no concrete source in this crate yet, so nothing constructs this
/// except callers of a future adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelError {
    message: String,
}

impl ChannelError {
    /// `message` is a reason, not a payload. Do not put argv, URLs, or headers in it.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The reason given to [`ChannelError::new`].
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ChannelError {}

/// One E3 channel (hooks, OTEL, …). Implementors live in later tasks.
///
/// `start` / `stop` must not change the agent's own configuration on disk.
pub trait SelfReportSource {
    /// Stable channel id, for example `claude-code/hooks`. Not a display name.
    fn id(&self) -> &str;

    /// Begin receiving self-reports for `session`.
    fn start(&mut self, session: &SessionHandle) -> Result<(), ChannelError>;

    /// Stop receiving. Must be safe to call after a failed `start`.
    fn stop(&mut self) -> Result<(), ChannelError>;
}
