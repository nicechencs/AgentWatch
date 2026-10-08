//! Aggregate stage pieces.
//!
//! P1-PIPE-04 implements network flows only. File-handle aggregation stays a
//! later card. This module does not read a clock and does not store content,
//! URLs, or headers.

mod net;

pub use net::{
    summarize, FlowAcc, FlowGroupBy, FlowGroupKey, FlowSummary, NetAggregator, BYTES_DOWN_FIELD,
    BYTES_UP_FIELD, PARTIAL_FLUSH_NS, UDP_IDLE_NS,
};
