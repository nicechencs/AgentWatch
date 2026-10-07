//! Polling fallback collector.
//!
//! `ProcessStart`, `ProcessExit`, `NetConnect`, and `NetClose` are evidence
//! [`aw_core::Evidence::S`]. A [`aw_core::Gap`] is [`aw_core::Evidence::E1`]: the
//! gap itself was observed, matching [`aw_core::MockCollector`]. A field the
//! snapshot cannot see is `None` plus `field_evidence` `NA(reason)`. It is never
//! `0` or an empty string. A gap is not an upgrade of a sampled observation.
//!
//! Enumeration is behind [`ProcessSource`] and [`ConnectionSource`]. Tests inject
//! snapshots. The live `sysinfo` adapter and the Windows `netstat -ano` parser are
//! not called from tests, and they are not called unless a [`PollCollector`] is
//! constructed with [`PollCollector::with_host`].
//!
//! [`Placeholder`] stays public so `aw-daemon` can name this crate. It is not a
//! collector.

#![forbid(unsafe_code)]

mod bytes;
mod diff;
mod host;
mod netstat;
mod poll;
mod source;

pub use bytes::connection_byte_counts;
pub use diff::{diff_connections, diff_processes, ConnectionDelta, ProcessDelta};
pub use netstat::parse_netstat_ano;
pub use poll::{
    PollCollector, PollConfig, PollError, DEFAULT_CONN_INTERVAL, DEFAULT_PROC_INTERVAL,
};
pub use source::{
    ConnectionRow, ConnectionSnapshot, ConnectionSource, ProcessRow, ProcessSnapshot,
    ProcessSource, ProcessStartTime, StaticConnectionSource, StaticProcessSource,
};

/// Empty marker so the daemon can name this crate before it hosts the collector.
pub struct Placeholder;
