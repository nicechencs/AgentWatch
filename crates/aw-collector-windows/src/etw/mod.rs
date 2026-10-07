//! ETW session layer (P1-WIN-01).
//!
//! [`session`] is pure: names, buffer defaults, the scope filter, loss deltas,
//! and the QPC / FILETIME conversion. It does not open a session.
//! [`trace`] opens one, through ferrisetw, and only on Windows.
//! [`ffi`] is the only module that calls `ControlTraceW` directly.

mod ffi;
pub mod session;
pub mod trace;

#[cfg(all(test, feature = "e2e"))]
mod session_e2e;

pub use session::{
    classify_provider, filetime_to_unix_ns, gap_for_loss, is_agentwatch_session, loss_delta,
    poll_loss, raw_gap_for_loss, session_name, ConfigError, EtwClockMode, EtwStamp, LossDelta,
    LossPoll, LossReading, ProbeReport, ProviderClass, ProviderSpec, QpcClock, ScopeFilter,
    SessionConfig, SessionError, BUFFER_SIZE_KB, DNS_CLIENT_GUID, KERNEL_FILE_GUID,
    KERNEL_NETWORK_GUID, KERNEL_PROCESS_GUID, LOSS_POLL_INTERVAL, MAXIMUM_BUFFERS, MINIMUM_BUFFERS,
    NT_KERNEL_LOGGER, SESSION_PREFIX, SESSION_SOURCE,
};
pub use trace::{
    gap_from_delta, probe, stop_leftover, CallbackAction, HeaderEvent, ProviderId, Session,
    SessionMessage,
};
