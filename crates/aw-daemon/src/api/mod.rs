//! Local API: auth, loopback HTTP, and session queries (P1-DAEMON-03, P2-DAEMON-01/02).
//!
//! axum is not a dependency. P2-DAEMON-01 asks for it; the P1 stub and this
//! crate's `Cargo.toml` keep a `std::net` listener in [`http`] that calls the
//! same [`routes::dispatch`]. Unix-socket peer credentials and the Windows
//! named-pipe DACL are still not implemented. [`pipe_dacl_configured`] stays
//! `false` until a later card runs that check.
//!
//! `dead_code` is allowed on the public surface so the listener can exist
//! before `main` starts it.

#![allow(dead_code)]

mod agent;
mod auth;
mod findings;
mod http;
mod http_events;
mod ipc;
mod openapi;
mod proxy;
mod query;
mod routes;

pub(crate) use agent::OtlpRegistry;
pub(crate) use findings::share;

pub(crate) use http::HttpServer;
pub(crate) use ipc::{socket_path, IpcServer};
pub(crate) use query::StoreQuery;
pub(crate) use routes::ApiState;

/// Whether a Windows named-pipe DACL was actually applied and verified.
///
/// This card does not create a named pipe, does not modify an ACL, and does not
/// install a service. The non-admin open test was not run, so this stays false
/// rather than reporting a check that never happened.
#[must_use]
pub fn pipe_dacl_configured() -> bool {
    false
}
