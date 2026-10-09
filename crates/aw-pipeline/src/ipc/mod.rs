//! Channel aggregation and agent-link generation (P6-PIPE-02).
//!
//! This module consumes events the caller has already decoded. It does not
//! collect IPC, does not read a clock, and does not write a database. The
//! caller supplies `ts_mono_ns` on each event and an instance map that was
//! resolved before the call. P6-PIPE-01 is not imported.
//!
//! A pipe whose two ends map to the same [`InstanceId`] is still recorded as
//! a channel. It does not become an `ipc` [`AgentLink`]: that edge is only
//! for two different instances.
//!
//! `shared_artifact` is not produced here.

mod types;

pub use types::{
    bucket_index, is_self_reported_tool, strongest_evidence, AgentLink, ChannelKey, DecodedEvent,
    EndpointId, ExternalPeer, InstanceId, IpcAggregator, IpcBucket, IpcChannel, LinkKind, LinkRef,
    PairedOpen, ProcInstance, SpawnEdge, WatchFinding, BUCKET_NS, WATCH_GROUP_KIND,
    WATCH_GROUP_TEXT,
};
