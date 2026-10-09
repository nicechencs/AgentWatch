//! IPC aggregation as seen from the aggregate stage (P6-PIPE-02).
//!
//! The implementation lives in [`crate::ipc`]. This module is the name next
//! to [`super::net`] and [`super::file`]. It does not write store rows, does
//! not read a clock, and does not emit `shared_artifact` links.
//!
//! An internal pipe (both ends the same instance) is still a channel. It is
//! not an agent link.

pub use crate::ipc::{
    bucket_index, is_self_reported_tool, strongest_evidence, AgentLink, ChannelKey, DecodedEvent,
    EndpointId, ExternalPeer, InstanceId, IpcAggregator, IpcBucket, IpcChannel, LinkKind, LinkRef,
    PairedOpen, ProcInstance, SpawnEdge, WatchFinding, BUCKET_NS, WATCH_GROUP_KIND,
    WATCH_GROUP_TEXT,
};
