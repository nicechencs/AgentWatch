//! macOS collector.
//!
//! The crate root is not wrapped in `#![cfg(target_os = "macos")]`. That
//! attribute would compile the JSON decoder out on Windows and Linux, and
//! P1-MAC-01's decode tests have to run there. `endpoint_security` is gated
//! with `cfg(target_os = "macos")` as a whole. That is the module that will
//! spawn `/usr/bin/eslogger`. The gate is not removed to make tests compile.
//!
//! JSON decoding, sequence-gap detection, and the pre-parse PID filter live in
//! [`eslogger`] and have no macOS API.

#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

mod eslogger;
mod nettop;
mod pktap;
mod scope;

#[cfg(target_os = "macos")]
mod endpoint_security;

#[cfg(target_os = "macos")]
pub use endpoint_security::MacosCollector;

pub use eslogger::{
    apply_subscribe_open, decode_line, pid_in_scope, AuditToken, BudgetDecision, EsEvent,
    FileSubscription, LineAction, LineDecoder, LossDetector, OpenBudget, OpenIntent, PidFilter,
    ProbeError, ResponsibleToken, SequenceKind, SequenceLoss, SubscribeOpen, BYTES_NA,
    DEFAULT_CPU_PERCENT, DEFAULT_SUSTAIN, FILE_EVENTS,
};

pub use nettop::{
    parse_nettop, sampling_note, NetSample, NettopDecoder, NettopEvent, NettopRow, ProcessScope,
    SAMPLING_NOTE, SOURCE_NETTOP_FLOW,
};
pub use pktap::{
    decode_dns, DecodedPktap, DnsPacket, GlobalDnsCache, PktapClock, PktapEvent, SOURCE_PKTAP_DNS,
};
pub use scope::{
    attach_snapshot, on_attribution, on_fork, on_unknown_pid, ChildList, ForkParent, ScopeAction,
    ScopeSet, SnapshotError, LAUNCHD_PID, LINK_BROKEN_NOTE, PENDING_HOLD,
};
