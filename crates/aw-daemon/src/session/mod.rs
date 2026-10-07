//! Platform-independent session orchestration (P1-DAEMON-04).
//!
//! A session is the unit of an audit. This module owns the run / attach / stop
//! sequence. Platform differences (cgroup, Job Object, Endpoint Security) stay
//! behind [`ScopeProvider`]. Later cards implement that trait; this one only
//! ships [`MockScope`].
//!
//! There is no tokio and no process-spawning code. The clock is a `u64` the
//! caller advances, the same way [`crate::supervisor`] does. The daemon binary
//! does not call this module yet, so `dead_code` is allowed on the public
//! surface until a later card wires the API. The re-exports below are that
//! surface: nothing in this crate calls them yet, so the unused-import lint
//! is silenced here rather than by deleting the names a later card needs.
//!
//! # Identity
//!
//! The daemon runs as root or SYSTEM. A [`ScopeProvider`] must not launch the
//! target as that identity. Launch mode is "the CLI creates the process
//! suspended, under the calling user; the daemon only adopts it" (SPIKE-05).
//! `stop` ends observation. It does not end the target process.

#![allow(dead_code, unused_imports)]

mod orch;
mod provider;
mod sink;

pub use orch::{
    process_exit, process_file_placeholder, AdoptRequest, AttachOptions, EndReason, LaunchRequest,
    SessionError, SessionMode, SessionOrchestrator, SessionRecord, SessionStatus, SessionSummary,
    StartedRun, ADOPT_TIMEOUT_NS,
};
pub use provider::{
    Adopted, Attached, LaunchTicket, MockScope, PreparedLaunch, ProviderError, ScopeAction,
    ScopeProvider, SnapshotProc,
};
pub use sink::{FanoutSink, Flushed, SessionSink};

#[cfg(test)]
mod tests;
