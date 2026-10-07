//! Local API auth and routing (P1-DAEMON-03).
//!
//! axum is not in the offline lock; this is a loopback HTTP stub, not the three
//! transports. Unix-socket peer credentials (`SO_PEERCRED` / `LOCAL_PEERCRED`)
//! and the Windows named-pipe DACL (`GetNamedPipeClientProcessId`) are not
//! implemented here. [`pipe_dacl_configured`] stays `false` until a later card
//! runs that check. A later card can swap in axum without rewriting the decision
//! functions: [`auth::authorize`] and [`routes::dispatch`].
//!
//! The daemon binary does not call this module yet. A later card wires the
//! listener. `dead_code` is allowed on the public surface so the routing table
//! can exist before that wiring without failing `-D warnings`.

#![allow(dead_code)]

mod auth;
mod routes;

/// Whether a Windows named-pipe DACL was actually applied and verified.
///
/// This card does not create a named pipe, does not modify an ACL, and does not
/// install a service. The non-admin open test was not run, so this stays false
/// rather than reporting a check that never happened.
#[must_use]
pub fn pipe_dacl_configured() -> bool {
    false
}
