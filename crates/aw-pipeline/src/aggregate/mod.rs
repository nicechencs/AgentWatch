//! Aggregate stage pieces.
//!
//! Network flows (P1-PIPE-04) and file handles (P2-PIPE-01). Neither reads a
//! clock, and neither stores file content, URLs, or headers.

mod file;
pub mod ipc;
mod net;

pub use file::{FileAggregator, BYTES_READ_FIELD, BYTES_WRITTEN_FIELD, DEFAULT_STATE_CAP};
pub use net::{
    summarize, FlowAcc, FlowGroupBy, FlowGroupKey, FlowSummary, NetAggregator, BYTES_DOWN_FIELD,
    BYTES_UP_FIELD, PARTIAL_FLUSH_NS, UDP_IDLE_NS,
};
