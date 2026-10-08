//! ETW session layer (P1-WIN-01).
//!
//! [`session`] is pure: names, buffer defaults, the scope filter, loss deltas,
//! and the QPC / FILETIME conversion. It does not open a session.
//! [`trace`] opens one, through ferrisetw, and only on Windows.
//! [`ffi`] is the only module that calls `ControlTraceW` directly.
//! [`process`] decodes Kernel-Process events. It does not open a session.
//! Process back-fill (`NtQueryInformationProcess`, PEB) lives in [`crate::peb`].
//! [`network`] decodes Kernel-Network events and pre-aggregates send/recv for 1 s.
//! [`dns`] decodes DNS-Client 3006/3008. Neither opens a session.

pub mod dns;
mod ffi;
pub mod network;
pub mod process;
pub mod session;
pub mod trace;

#[cfg(all(test, feature = "e2e"))]
mod session_e2e;

pub use dns::{
    decode_dns, parse_query_results, DecodedDns, DnsAnswerCache, DnsCacheRow, DnsProperties,
    EVENT_DNS_QUERY, EVENT_DNS_QUERY_COMPLETED, PID_ATTRIBUTION_NOTE, PID_FIELD, SOURCE_DNS_CLIENT,
};
pub use network::{
    decode_network, flush_due, normalize_ip, ConnectionKey, DecodedNetwork, FlowPreAgg,
    NetworkProperties, AGGREGATE_WINDOW_NS, DNS_PORT, SOURCE_KERNEL_NETWORK,
};
pub use process::{
    apply_backfill, apply_report, decode_process, resolve_parent, split_command_line, BackfillJob,
    BackfillMiss, BackfillPool, BackfillReport, CachedProcess, DecodeClock, DecodedProcess,
    DecodedStart, DecodedStop, ParentLink, ProcessCache, ProcessProperties, Undecodable,
    EVENT_PROCESS_START, EVENT_PROCESS_STOP, SOURCE_PROCESS_START, SOURCE_PROCESS_STOP,
};
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
