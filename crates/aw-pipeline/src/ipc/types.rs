//! In-memory IPC buckets and agent links (P6-PIPE-02).
//!
//! Evidence on a link is the strongest grade among its refs.
//! Order, strongest first: E1 > E2 > S > E3 > I. [`Evidence::NA`] is not a grade
//! and never wins. A link whose only refs are E3 stays E3.
//!
//! [`IpcOpen`] has no collector channel id. The caller passes [`PairedOpen`]
//! when it has already joined an open to the id used by [`IpcTransfer`] and
//! [`IpcClose`]. A transfer with no prior open is kept, with unknown ends:
//! this module does not invent a peer.
//!
//! Call [`IpcAggregator::set_instances`] and [`IpcAggregator::note_outside_agent`]
//! before [`IpcAggregator::observe`]. The map is not re-applied to events that
//! were already consumed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use aw_core::{
    AgentRpc, AgentToolCall, Evidence, IpcClose, IpcDirection, IpcKind, IpcOpen, IpcTransfer,
    NaReason, ProcRef, ProcUid, SessionId, Source,
};

/// Five-second bucket width. ADR-0011. Not read from a clock.
pub const BUCKET_NS: u64 = 5_000_000_000;

/// Finding kind when a peer looks like an agent outside this session.
pub const WATCH_GROUP_KIND: &str = "watch_group_suggestion";

/// Fixed template. Does not claim the process did anything.
pub const WATCH_GROUP_TEXT: &str = "建议把该进程加入监控组";

/// Shortest id accepted for a `subagent` summary marker. Empty is not an id.
const SUBAGENT_ID_MIN: usize = 1;
/// Longest id accepted. Longer text is treated as argument content and ignored.
const SUBAGENT_ID_MAX: usize = 64;

/// Caller-assigned agent instance. Not a store row id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstanceId(pub i64);

/// One endpoint of a channel.
///
/// Socket paths and pipe names are not part of the identity. Only their
/// lengths are kept, on [`IpcChannel::name_len`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EndpointId {
    pub proc_uid: Option<ProcUid>,
    pub pid: Option<u32>,
}

impl EndpointId {
    pub fn from_proc(proc: &ProcRef) -> Self {
        Self {
            proc_uid: Some(proc.uid),
            pid: Some(proc.pid),
        }
    }

    pub const fn unknown() -> Self {
        Self {
            proc_uid: None,
            pid: None,
        }
    }

    pub const fn is_unknown(self) -> bool {
        self.proc_uid.is_none() && self.pid.is_none()
    }
}

/// Bucket key: session, kind, the two endpoints, and the 5 s index.
///
/// The collector channel id is not part of the key. Two channels with the
/// same ends in the same window share one bucket. Per-channel totals still
/// live on [`IpcChannel`] when the open was paired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelKey {
    pub session_id: Option<SessionId>,
    pub kind: IpcKind,
    pub endpoint_a: EndpointId,
    pub endpoint_b: EndpointId,
    pub bucket_index: u64,
}

/// Process the caller already mapped onto an instance inside the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcInstance {
    pub instance: InstanceId,
}

/// Parent/child edge the caller already resolved. This module does not match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnEdge {
    pub parent_instance_id: InstanceId,
    pub child_instance_id: InstanceId,
    pub evidence: Evidence,
    pub ts_mono_ns: u64,
    pub session_id: Option<SessionId>,
    pub source: Source,
}

/// Peer that is not an in-session instance.
///
/// `pid` is `None` when the process itself was not observed. No executable
/// path is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalPeer {
    pub pid: Option<u32>,
}

/// An [`IpcOpen`] the caller already joined to a collector channel id.
#[derive(Clone)]
pub struct PairedOpen {
    pub channel: u64,
    pub open: IpcOpen,
    pub evidence: Evidence,
    pub source: Source,
    pub ts_mono_ns: u64,
    pub session_id: Option<SessionId>,
    /// Local end. `None` when the opener process was not observed.
    pub local: Option<ProcRef>,
}

impl fmt::Debug for PairedOpen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairedOpen")
            .field("channel", &self.channel)
            .field("kind", &self.open.kind)
            .field("peer", &self.open.peer)
            .field("name_len", &self.open.name.as_ref().map(String::len))
            .field("evidence", &self.evidence)
            .field("ts_mono_ns", &self.ts_mono_ns)
            .field("session_id", &self.session_id)
            .field("local_pid", &self.local.as_ref().map(|proc| proc.pid))
            .finish()
    }
}

/// One already-decoded event. `evidence` is the record-level grade.
#[derive(Clone)]
pub enum DecodedEvent {
    Open(PairedOpen),
    Transfer {
        transfer: IpcTransfer,
        evidence: Evidence,
        source: Source,
        ts_mono_ns: u64,
        session_id: Option<SessionId>,
    },
    Close {
        close: IpcClose,
        evidence: Evidence,
        source: Source,
        ts_mono_ns: u64,
        session_id: Option<SessionId>,
    },
    Rpc {
        rpc: AgentRpc,
        evidence: Evidence,
        source: Source,
        ts_mono_ns: u64,
        session_id: Option<SessionId>,
        /// Instance that emitted the RPC, when the caller mapped it.
        from: Option<InstanceId>,
        /// Peer instance, when the caller mapped it. Not invented here.
        to: Option<InstanceId>,
        /// Collector channel id, when the caller already paired one.
        channel: Option<u64>,
    },
    ToolCall {
        call: AgentToolCall,
        evidence: Evidence,
        source: Source,
        ts_mono_ns: u64,
        session_id: Option<SessionId>,
        from: Option<InstanceId>,
        /// Peer instance named by the caller. Summary text is not copied.
        to: Option<InstanceId>,
    },
}

impl fmt::Debug for DecodedEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(open) => f.debug_tuple("Open").field(open).finish(),
            Self::Transfer {
                transfer,
                evidence,
                ts_mono_ns,
                session_id,
                ..
            } => f
                .debug_struct("Transfer")
                .field("channel", &transfer.channel)
                .field("direction", &transfer.direction)
                .field("bytes", &transfer.bytes)
                .field("evidence", evidence)
                .field("ts_mono_ns", ts_mono_ns)
                .field("session_id", session_id)
                .finish(),
            Self::Close {
                close,
                evidence,
                ts_mono_ns,
                session_id,
                ..
            } => f
                .debug_struct("Close")
                .field("channel", &close.channel)
                .field("total_a_to_b", &close.total_a_to_b)
                .field("total_b_to_a", &close.total_b_to_a)
                .field("evidence", evidence)
                .field("ts_mono_ns", ts_mono_ns)
                .field("session_id", session_id)
                .finish(),
            Self::Rpc {
                rpc,
                evidence,
                ts_mono_ns,
                session_id,
                from,
                to,
                channel,
                ..
            } => f
                .debug_struct("Rpc")
                .field("method_len", &rpc.method.len())
                .field("target_len", &rpc.target.as_ref().map(String::len))
                .field("evidence", evidence)
                .field("ts_mono_ns", ts_mono_ns)
                .field("session_id", session_id)
                .field("from", from)
                .field("to", to)
                .field("channel", channel)
                .finish(),
            Self::ToolCall {
                call,
                evidence,
                ts_mono_ns,
                session_id,
                from,
                to,
                ..
            } => f
                .debug_struct("ToolCall")
                .field("tool_len", &call.tool.len())
                .field("summary", &"<redacted>")
                .field("evidence", evidence)
                .field("ts_mono_ns", ts_mono_ns)
                .field("session_id", session_id)
                .field("from", from)
                .field("to", to)
                .finish(),
        }
    }
}

/// One 5 s bucket. A byte side stays `None` until that direction is observed.
///
/// Close totals are not written here. A close total is a cumulative for the
/// whole channel, not a claim that those bytes fell inside this window.
/// [`IpcChannel`] prefers the close total for a side when one was observed.
#[derive(Clone, PartialEq, Eq)]
pub struct IpcBucket {
    pub key: ChannelKey,
    /// Collector channel id from the event that created the bucket.
    ///
    /// A second channel with the same key does not replace this. Its bytes
    /// are still added. The per-channel row is [`IpcChannel`].
    pub collector_channel: Option<u64>,
    pub bytes_a_to_b: Option<u64>,
    pub bytes_b_to_a: Option<u64>,
    /// Bytes whose direction was [`IpcDirection::Unknown`]. Not assigned to a side.
    pub bytes_undirected: Option<u64>,
    /// Strongest record evidence seen on this bucket. `NA` does not count.
    pub evidence: Option<Evidence>,
    pub source: Source,
    pub first_ns: u64,
    pub last_ns: u64,
    /// Both ends resolved to the same instance. The bucket is still kept.
    pub internal: bool,
    pub name_len: Option<usize>,
}

impl fmt::Debug for IpcBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpcBucket")
            .field("key", &self.key)
            .field("collector_channel", &self.collector_channel)
            .field("bytes_a_to_b", &self.bytes_a_to_b)
            .field("bytes_b_to_a", &self.bytes_b_to_a)
            .field("bytes_undirected", &self.bytes_undirected)
            .field("evidence", &self.evidence)
            .field("first_ns", &self.first_ns)
            .field("last_ns", &self.last_ns)
            .field("internal", &self.internal)
            .field("name_len", &self.name_len)
            .finish()
    }
}

/// Rolled-up channel. Convertible later to `IpcChannelInsert`. Not written here.
///
/// `bytes_a_to_b` / `bytes_b_to_a` are the close total for that side when the
/// close observed it, otherwise the sum of transfers. `None` means that side
/// was never observed. It is not `0`.
#[derive(Clone, PartialEq, Eq)]
pub struct IpcChannel {
    pub session_id: Option<SessionId>,
    pub kind: IpcKind,
    pub endpoint_a: EndpointId,
    pub endpoint_b: EndpointId,
    pub collector_channel: Option<u64>,
    pub bytes_a_to_b: Option<u64>,
    pub bytes_b_to_a: Option<u64>,
    pub bytes_undirected: Option<u64>,
    pub evidence: Option<Evidence>,
    pub source: Source,
    pub first_ns: u64,
    pub last_ns: u64,
    /// Same instance on both ends. No `ipc` link is emitted for this row.
    pub internal: bool,
    pub name_len: Option<usize>,
    /// Set when endpoint B was not observed. Not a stand-in peer.
    pub peer_na: Option<NaReason>,
}

impl fmt::Debug for IpcChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpcChannel")
            .field("session_id", &self.session_id)
            .field("kind", &self.kind)
            .field("endpoint_a", &self.endpoint_a)
            .field("endpoint_b", &self.endpoint_b)
            .field("collector_channel", &self.collector_channel)
            .field("bytes_a_to_b", &self.bytes_a_to_b)
            .field("bytes_b_to_a", &self.bytes_b_to_a)
            .field("bytes_undirected", &self.bytes_undirected)
            .field("evidence", &self.evidence)
            .field("internal", &self.internal)
            .field("name_len", &self.name_len)
            .field("peer_na", &self.peer_na)
            .finish()
    }
}

/// Why an [`AgentLink`] exists. `shared_artifact` is intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkKind {
    Spawned,
    Ipc,
    Rpc,
    SelfReported,
}

impl LinkKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spawned => "spawned",
            Self::Ipc => "ipc",
            Self::Rpc => "rpc",
            Self::SelfReported => "self_reported",
        }
    }
}

/// One piece of evidence kept on a link. The link grade is the strongest of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRef {
    pub evidence: Evidence,
    pub kind: LinkKind,
    /// Collector channel id. Spawn and self-report have none.
    pub channel: Option<u64>,
    pub ts_mono_ns: u64,
    pub source: Source,
}

/// One agent-to-agent or agent-to-outside edge.
#[derive(Clone, PartialEq, Eq)]
pub struct AgentLink {
    pub session_id: Option<SessionId>,
    pub from_instance: InstanceId,
    /// Set when the peer is an instance in the caller map.
    pub to_instance: Option<InstanceId>,
    /// Set when the peer is outside the session, or was not observed.
    pub to_external: Option<ExternalPeer>,
    pub kind: LinkKind,
    /// Strongest grade among [`Self::refs`]. E3 when every ref is E3.
    pub evidence: Evidence,
    pub refs: Vec<LinkRef>,
    /// Observed byte total. `None` when no side was observed.
    ///
    /// For `ipc`, a close total replaces the transfer sum of that side only.
    /// The other side stays `None` if it was never observed, and is not filled
    /// with `0`. Undirected bytes are included when that is all that was seen.
    pub bytes: Option<u64>,
    pub first_ns: u64,
    pub last_ns: u64,
    /// Method name for `rpc`. Not argument content. `Debug` prints the length.
    pub method: Option<String>,
    /// Tool name for `rpc`. Not argument content. `Debug` prints the length.
    pub target: Option<String>,
    pub source: Source,
}

impl fmt::Debug for AgentLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentLink")
            .field("session_id", &self.session_id)
            .field("from_instance", &self.from_instance)
            .field("to_instance", &self.to_instance)
            .field("to_external", &self.to_external)
            .field("kind", &self.kind)
            .field("evidence", &self.evidence)
            .field("refs", &self.refs)
            .field("bytes", &self.bytes)
            .field("first_ns", &self.first_ns)
            .field("last_ns", &self.last_ns)
            .field("method_len", &self.method.as_ref().map(String::len))
            .field("target_len", &self.target.as_ref().map(String::len))
            .finish()
    }
}

/// Info-level note. Evidence is [`Evidence::I`], not E1.
#[derive(Clone, PartialEq, Eq)]
pub struct WatchFinding {
    pub kind: &'static str,
    pub text: &'static str,
    pub evidence: Evidence,
    pub peer_pid: Option<u32>,
    pub ts_mono_ns: u64,
    pub session_id: Option<SessionId>,
}

impl fmt::Debug for WatchFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchFinding")
            .field("kind", &self.kind)
            .field("text", &self.text)
            .field("evidence", &self.evidence)
            .field("peer_pid", &self.peer_pid)
            .field("ts_mono_ns", &self.ts_mono_ns)
            .field("session_id", &self.session_id)
            .finish()
    }
}

/// 5 s bucket index for a monotonic timestamp the caller already has.
pub const fn bucket_index(ts_mono_ns: u64) -> u64 {
    ts_mono_ns / BUCKET_NS
}

/// Strongest grade in `grades`. `NA` is skipped. Empty or all-`NA` is `None`.
pub fn strongest_evidence<'a>(grades: impl IntoIterator<Item = &'a Evidence>) -> Option<Evidence> {
    let mut best: Option<&Evidence> = None;
    for grade in grades {
        if rank(grade).is_none() {
            continue;
        }
        best = Some(match best {
            None => grade,
            Some(current) if rank(grade) < rank(current) => grade,
            Some(current) => current,
        });
    }
    best.cloned()
}

/// `mcp__*` tool name, or a summary object with a `subagent` bool or short id.
///
/// The summary value is not copied onto a link. A long string is not a marker.
pub fn is_self_reported_tool(call: &AgentToolCall) -> bool {
    if call.tool.starts_with("mcp__") {
        return true;
    }
    match call.summary.get("subagent") {
        Some(serde_json::Value::Bool(flag)) => *flag,
        Some(serde_json::Value::String(id)) => is_short_id(id),
        _ => false,
    }
}

/// Running aggregation. Time comes from the caller. Nothing is written to disk.
#[derive(Debug, Default)]
pub struct IpcAggregator {
    /// `pid -> instance` for processes inside the session.
    instances: BTreeMap<u32, ProcInstance>,
    /// Pids the caller identified as agents that are not in [`Self::instances`].
    outside_agents: BTreeSet<u32>,
    open: BTreeMap<u64, OpenState>,
    buckets: BTreeMap<OrdBucket, IpcBucket>,
    links: Vec<AgentLink>,
    findings: Vec<WatchFinding>,
}

#[derive(Clone, Debug)]
struct OpenState {
    parts: KeyParts,
    evidence: Option<Evidence>,
    source: Source,
    first_ns: u64,
    last_ns: u64,
    /// Sum of observed transfers. `None` until that direction is seen.
    bytes_a_to_b: Option<u64>,
    bytes_b_to_a: Option<u64>,
    bytes_undirected: Option<u64>,
    /// Platform cumulative from [`IpcClose`]. `None` is not a measured zero.
    close_a_to_b: Option<u64>,
    close_b_to_a: Option<u64>,
    name_len: Option<usize>,
    peer_na: Option<NaReason>,
}

#[derive(Clone, Copy, Debug)]
struct KeyParts {
    session_id: Option<SessionId>,
    kind: IpcKind,
    endpoint_a: EndpointId,
    endpoint_b: EndpointId,
    from: Option<InstanceId>,
    to: Option<InstanceId>,
    to_external: Option<ExternalPeer>,
    internal: bool,
    outside_agent: bool,
    peer_pid: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct OrdBucket {
    session: Option<u64>,
    kind: u8,
    a_uid: Option<u64>,
    a_pid: Option<u32>,
    b_uid: Option<u64>,
    b_pid: Option<u32>,
    bucket_index: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct OrdChannel {
    session: Option<u64>,
    kind: u8,
    a_uid: Option<u64>,
    a_pid: Option<u32>,
    b_uid: Option<u64>,
    b_pid: Option<u32>,
    collector_channel: Option<u64>,
}

struct BucketTouch<'a> {
    channel: u64,
    parts: &'a KeyParts,
    ts_mono_ns: u64,
    evidence: Evidence,
    source: &'a Source,
    name_len: Option<usize>,
    add: ByteAdd,
}

struct ByteAdd {
    a_to_b: Option<u64>,
    b_to_a: Option<u64>,
    undirected: Option<u64>,
}

impl IpcAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the in-session instance map. A pid absent from this map is outside.
    ///
    /// Does not revisit events already observed.
    pub fn set_instances(&mut self, instances: impl IntoIterator<Item = (u32, ProcInstance)>) {
        self.instances = instances.into_iter().collect();
    }

    /// Mark `pid` as an agent that is not in the session map.
    ///
    /// A later IPC open whose peer has this pid emits one info finding.
    /// This module does not decide that a process is an agent. A pid that is
    /// also in the session map does not get a finding. Already-consumed opens
    /// are not backfilled.
    pub fn note_outside_agent(&mut self, pid: u32) {
        self.outside_agents.insert(pid);
    }

    /// Record a spawn edge the caller already resolved to two instances.
    ///
    /// The same instance on both ends is not an edge. `NA` is not a grade.
    pub fn observe_spawn(&mut self, edge: SpawnEdge) {
        if edge.parent_instance_id == edge.child_instance_id || edge.evidence.is_na() {
            return;
        }
        let evidence = edge.evidence;
        let source = edge.source;
        self.push_link(AgentLink {
            session_id: edge.session_id,
            from_instance: edge.parent_instance_id,
            to_instance: Some(edge.child_instance_id),
            to_external: None,
            kind: LinkKind::Spawned,
            evidence: evidence.clone(),
            refs: vec![LinkRef {
                evidence,
                kind: LinkKind::Spawned,
                channel: None,
                ts_mono_ns: edge.ts_mono_ns,
                source: source.clone(),
            }],
            bytes: None,
            first_ns: edge.ts_mono_ns,
            last_ns: edge.ts_mono_ns,
            method: None,
            target: None,
            source,
        });
    }

    /// Apply one decoded event.
    pub fn observe(&mut self, event: DecodedEvent) {
        match event {
            DecodedEvent::Open(open) => self.observe_open(open),
            DecodedEvent::Transfer {
                transfer,
                evidence,
                source,
                ts_mono_ns,
                session_id,
            } => self.observe_transfer(transfer, evidence, source, ts_mono_ns, session_id),
            DecodedEvent::Close {
                close,
                evidence,
                source,
                ts_mono_ns,
                session_id,
            } => self.observe_close(close, evidence, source, ts_mono_ns, session_id),
            DecodedEvent::Rpc {
                rpc,
                evidence,
                source,
                ts_mono_ns,
                session_id,
                from,
                to,
                channel,
            } => self.observe_rpc(RpcInput {
                rpc,
                evidence,
                source,
                ts_mono_ns,
                session_id,
                from,
                to,
                channel,
            }),
            DecodedEvent::ToolCall {
                call,
                evidence,
                source,
                ts_mono_ns,
                session_id,
                from,
                to,
            } => self.observe_tool(ToolInput {
                call,
                evidence,
                source,
                ts_mono_ns,
                session_id,
                from,
                to,
            }),
        }
    }

    /// Buckets, in key order. An internal pipe is included. Its link is not.
    pub fn buckets(&self) -> impl Iterator<Item = &IpcBucket> {
        self.buckets.values()
    }

    /// One row per paired channel, plus transfers that never had an open.
    ///
    /// Internal pipes are included. `shared_artifact` is not produced.
    pub fn channels(&self) -> Vec<IpcChannel> {
        let mut rows: BTreeMap<OrdChannel, IpcChannel> = BTreeMap::new();
        for (channel, state) in &self.open {
            let row = channel_from_open(*channel, state);
            rows.insert(ord_channel(&row), row);
        }
        for bucket in self.buckets.values() {
            if bucket
                .collector_channel
                .is_some_and(|id| self.open.contains_key(&id))
            {
                continue;
            }
            let row = channel_from_bucket(bucket);
            let id = ord_channel(&row);
            rows.entry(id)
                .and_modify(|existing| merge_channel(existing, &row))
                .or_insert(row);
        }
        rows.into_values().collect()
    }

    pub fn links(&self) -> &[AgentLink] {
        &self.links
    }

    pub fn findings(&self) -> &[WatchFinding] {
        &self.findings
    }

    fn observe_open(&mut self, open: PairedOpen) {
        let evidence = open.evidence;
        let source = open.source;
        let ts_mono_ns = open.ts_mono_ns;
        let channel = open.channel;
        let name_len = open.open.name.as_ref().map(String::len);
        let peer_missing = open.open.peer.is_none();
        let parts = self.classify(
            open.session_id,
            open.open.kind,
            open.local.as_ref(),
            open.open.peer.as_ref(),
        );
        let already = self.open.contains_key(&channel);
        if already {
            self.adopt_open(
                channel,
                &parts,
                ts_mono_ns,
                &evidence,
                name_len,
                peer_missing,
            );
        } else if let std::collections::btree_map::Entry::Vacant(slot) = self.open.entry(channel) {
            slot.insert(fresh_open(
                &parts,
                &evidence,
                &source,
                ts_mono_ns,
                name_len,
                if peer_missing {
                    Some(NaReason::PeerUnknown)
                } else {
                    None
                },
            ));
        }
        self.touch_bucket(BucketTouch {
            channel,
            parts: &parts,
            ts_mono_ns,
            evidence: evidence.clone(),
            source: &source,
            name_len,
            add: ByteAdd::none(),
        });
        self.maybe_ipc_link(channel, &parts, ts_mono_ns, evidence, &source);
        self.maybe_finding(&parts, ts_mono_ns);
    }

    fn adopt_open(
        &mut self,
        channel: u64,
        parts: &KeyParts,
        ts_mono_ns: u64,
        evidence: &Evidence,
        name_len: Option<usize>,
        peer_missing: bool,
    ) {
        // A transfer or close may have arrived first, with unknown ends.
        // Keep its byte totals. Replace the ends now that the open names them.
        let had_unknown_ends = self.open.get(&channel).is_some_and(|slot| {
            slot.parts.endpoint_a.is_unknown() && slot.parts.endpoint_b.is_unknown()
        });
        if let Some(slot) = self.open.get_mut(&channel) {
            slot.parts = *parts;
            slot.last_ns = ts_mono_ns.max(slot.last_ns);
            slot.first_ns = ts_mono_ns.min(slot.first_ns);
            slot.evidence = stronger_opt(slot.evidence.clone(), grade_or_none(evidence.clone()));
            if slot.name_len.is_none() {
                slot.name_len = name_len;
            }
            if !peer_missing {
                slot.peer_na = None;
            }
        }
        if had_unknown_ends {
            self.rehome_unknown_buckets(channel, parts);
        }
    }

    fn observe_transfer(
        &mut self,
        transfer: IpcTransfer,
        evidence: Evidence,
        source: Source,
        ts_mono_ns: u64,
        session_id: Option<SessionId>,
    ) {
        let add = ByteAdd::from_transfer(transfer.direction, transfer.bytes);
        let channel = transfer.channel;
        if !self.open.contains_key(&channel) {
            // Ends are not known yet. Keep the bytes on a stub so a later open
            // does not start from zero and drop them. The peer is not invented.
            let parts = self.classify(session_id, IpcKind::Unknown, None, None);
            self.open.insert(
                channel,
                fresh_open(
                    &parts,
                    &evidence,
                    &source,
                    ts_mono_ns,
                    None,
                    Some(NaReason::PeerUnknown),
                ),
            );
        }
        let Some(state) = self.open.get(&channel).cloned() else {
            return;
        };
        if let Some(slot) = self.open.get_mut(&channel) {
            add_bytes(slot, &add);
            slot.last_ns = ts_mono_ns.max(slot.last_ns);
            slot.evidence = stronger_opt(slot.evidence.clone(), grade_or_none(evidence.clone()));
        }
        self.touch_bucket(BucketTouch {
            channel,
            parts: &state.parts,
            ts_mono_ns,
            evidence: evidence.clone(),
            source: &source,
            name_len: state.name_len,
            add,
        });
        self.note_on_link(channel, ts_mono_ns, evidence, source);
    }

    fn observe_close(
        &mut self,
        close: IpcClose,
        evidence: Evidence,
        source: Source,
        ts_mono_ns: u64,
        session_id: Option<SessionId>,
    ) {
        let channel = close.channel;
        let known = self.open.get(&channel).cloned();
        let parts = known.as_ref().map_or_else(
            || self.classify(session_id, IpcKind::Unknown, None, None),
            |state| state.parts,
        );
        let name_len = known.as_ref().and_then(|state| state.name_len);
        match self.open.entry(channel) {
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let slot = entry.get_mut();
                // `None` does not replace a transfer sum and is not stored as 0.
                if close.total_a_to_b.is_some() {
                    slot.close_a_to_b = close.total_a_to_b;
                }
                if close.total_b_to_a.is_some() {
                    slot.close_b_to_a = close.total_b_to_a;
                }
                slot.last_ns = ts_mono_ns.max(slot.last_ns);
                slot.evidence =
                    stronger_opt(slot.evidence.clone(), grade_or_none(evidence.clone()));
            }
            std::collections::btree_map::Entry::Vacant(entry) => {
                // Close without a paired open. Ends stay unknown; the totals are kept.
                let mut state = fresh_open(
                    &parts,
                    &evidence,
                    &source,
                    ts_mono_ns,
                    name_len,
                    Some(NaReason::PeerUnknown),
                );
                state.close_a_to_b = close.total_a_to_b;
                state.close_b_to_a = close.total_b_to_a;
                entry.insert(state);
            }
        }
        self.touch_bucket(BucketTouch {
            channel,
            parts: &parts,
            ts_mono_ns,
            evidence: evidence.clone(),
            source: &source,
            name_len,
            add: ByteAdd::none(),
        });
        self.note_on_link(channel, ts_mono_ns, evidence, source);
    }

    fn observe_rpc(&mut self, input: RpcInput) {
        let Some(from) = input.from else {
            return;
        };
        if input.evidence.is_na() {
            return;
        }
        let (to_instance, to_external) = match input.to {
            Some(id) if id == from => return,
            Some(id) => (Some(id), None),
            None => (None, Some(ExternalPeer { pid: None })),
        };
        let method = if input.rpc.method.is_empty() {
            None
        } else {
            Some(input.rpc.method)
        };
        let evidence = input.evidence;
        let source = input.source;
        self.push_link(AgentLink {
            session_id: input.session_id,
            from_instance: from,
            to_instance,
            to_external,
            kind: LinkKind::Rpc,
            evidence: evidence.clone(),
            refs: vec![LinkRef {
                evidence,
                kind: LinkKind::Rpc,
                channel: input.channel,
                ts_mono_ns: input.ts_mono_ns,
                source: source.clone(),
            }],
            bytes: add_pair(input.rpc.req_bytes, input.rpc.resp_bytes),
            first_ns: input.ts_mono_ns,
            last_ns: input.ts_mono_ns,
            method,
            target: input.rpc.target,
            source,
        });
    }

    fn observe_tool(&mut self, input: ToolInput) {
        if input.evidence.is_na() || !is_self_reported_tool(&input.call) {
            return;
        }
        let Some(from) = input.from else {
            return;
        };
        // A self-report is E3 even when the caller stamped a stronger grade.
        let evidence = Evidence::E3;
        let (to_instance, to_external) = match input.to {
            Some(id) if id == from => return,
            Some(id) => (Some(id), None),
            None => (None, Some(ExternalPeer { pid: None })),
        };
        let source = input.source;
        self.push_link(AgentLink {
            session_id: input.session_id,
            from_instance: from,
            to_instance,
            to_external,
            kind: LinkKind::SelfReported,
            evidence: evidence.clone(),
            refs: vec![LinkRef {
                evidence,
                kind: LinkKind::SelfReported,
                channel: None,
                ts_mono_ns: input.ts_mono_ns,
                source: source.clone(),
            }],
            bytes: None,
            first_ns: input.ts_mono_ns,
            last_ns: input.ts_mono_ns,
            method: None,
            target: None,
            source,
        });
    }

    fn classify(
        &self,
        session_id: Option<SessionId>,
        kind: IpcKind,
        local: Option<&ProcRef>,
        peer: Option<&ProcRef>,
    ) -> KeyParts {
        let endpoint_a = local.map_or_else(EndpointId::unknown, EndpointId::from_proc);
        let endpoint_b = peer.map_or_else(EndpointId::unknown, EndpointId::from_proc);
        let from = local.and_then(|proc| self.instances.get(&proc.pid).map(|row| row.instance));
        let to = peer.and_then(|proc| self.instances.get(&proc.pid).map(|row| row.instance));
        let internal = matches!((from, to), (Some(left), Some(right)) if left == right);
        let peer_outside = peer.is_some() && to.is_none();
        let outside_agent =
            peer.is_some_and(|proc| peer_outside && self.outside_agents.contains(&proc.pid));
        let to_external = if internal {
            None
        } else if peer.is_none() || peer_outside {
            Some(ExternalPeer {
                pid: peer.map(|proc| proc.pid),
            })
        } else {
            None
        };
        KeyParts {
            session_id,
            kind,
            endpoint_a,
            endpoint_b,
            from,
            to: if internal { None } else { to },
            to_external,
            internal,
            outside_agent,
            peer_pid: peer.map(|proc| proc.pid),
        }
    }

    fn touch_bucket(&mut self, touch: BucketTouch<'_>) {
        let BucketTouch {
            channel,
            parts,
            ts_mono_ns,
            evidence,
            source,
            name_len,
            add,
        } = touch;
        let key = ChannelKey {
            session_id: parts.session_id,
            kind: parts.kind,
            endpoint_a: parts.endpoint_a,
            endpoint_b: parts.endpoint_b,
            bucket_index: bucket_index(ts_mono_ns),
        };
        let ord = ord_bucket(&key);
        let bucket = self.buckets.entry(ord).or_insert_with(|| IpcBucket {
            key,
            collector_channel: Some(channel),
            bytes_a_to_b: None,
            bytes_b_to_a: None,
            bytes_undirected: None,
            evidence: None,
            source: source.clone(),
            first_ns: ts_mono_ns,
            last_ns: ts_mono_ns,
            internal: parts.internal,
            name_len,
        });
        add_opt(&mut bucket.bytes_a_to_b, add.a_to_b);
        add_opt(&mut bucket.bytes_b_to_a, add.b_to_a);
        add_opt(&mut bucket.bytes_undirected, add.undirected);
        bucket.evidence = stronger_opt(bucket.evidence.clone(), grade_or_none(evidence));
        bucket.last_ns = ts_mono_ns.max(bucket.last_ns);
        bucket.first_ns = ts_mono_ns.min(bucket.first_ns);
        if bucket.name_len.is_none() {
            bucket.name_len = name_len;
        }
    }

    /// Move bytes recorded before the open (unknown ends) onto the real key.
    fn rehome_unknown_buckets(&mut self, channel: u64, parts: &KeyParts) {
        let stale: Vec<OrdBucket> = self
            .buckets
            .iter()
            .filter(|(_, bucket)| {
                bucket.collector_channel == Some(channel)
                    && bucket.key.endpoint_a.is_unknown()
                    && bucket.key.endpoint_b.is_unknown()
                    && bucket.key.kind == IpcKind::Unknown
            })
            .map(|(ord, _)| *ord)
            .collect();
        for ord in stale {
            let Some(old) = self.buckets.remove(&ord) else {
                continue;
            };
            let key = ChannelKey {
                session_id: parts.session_id,
                kind: parts.kind,
                endpoint_a: parts.endpoint_a,
                endpoint_b: parts.endpoint_b,
                bucket_index: old.key.bucket_index,
            };
            let dest = ord_bucket(&key);
            if let Some(bucket) = self.buckets.get_mut(&dest) {
                add_opt(&mut bucket.bytes_a_to_b, old.bytes_a_to_b);
                add_opt(&mut bucket.bytes_b_to_a, old.bytes_b_to_a);
                add_opt(&mut bucket.bytes_undirected, old.bytes_undirected);
                bucket.evidence = stronger_opt(bucket.evidence.clone(), old.evidence);
                bucket.first_ns = bucket.first_ns.min(old.first_ns);
                bucket.last_ns = bucket.last_ns.max(old.last_ns);
            } else {
                self.buckets.insert(
                    dest,
                    IpcBucket {
                        key,
                        collector_channel: Some(channel),
                        bytes_a_to_b: old.bytes_a_to_b,
                        bytes_b_to_a: old.bytes_b_to_a,
                        bytes_undirected: old.bytes_undirected,
                        evidence: old.evidence,
                        source: old.source,
                        first_ns: old.first_ns,
                        last_ns: old.last_ns,
                        internal: parts.internal,
                        name_len: old.name_len,
                    },
                );
            }
        }
    }

    fn maybe_ipc_link(
        &mut self,
        channel: u64,
        parts: &KeyParts,
        ts_mono_ns: u64,
        evidence: Evidence,
        source: &Source,
    ) {
        // Same instance on both ends: the channel stays, the edge does not.
        if parts.internal || evidence.is_na() {
            return;
        }
        let Some(from) = parts.from else {
            return;
        };
        if parts.to.is_none() && parts.to_external.is_none() {
            return;
        }
        self.push_link(AgentLink {
            session_id: parts.session_id,
            from_instance: from,
            to_instance: parts.to,
            to_external: parts.to_external,
            kind: LinkKind::Ipc,
            evidence: evidence.clone(),
            refs: vec![LinkRef {
                evidence,
                kind: LinkKind::Ipc,
                channel: Some(channel),
                ts_mono_ns,
                source: source.clone(),
            }],
            bytes: None,
            first_ns: ts_mono_ns,
            last_ns: ts_mono_ns,
            method: None,
            target: None,
            source: source.clone(),
        });
    }

    fn note_on_link(&mut self, channel: u64, ts_mono_ns: u64, evidence: Evidence, source: Source) {
        let Some(index) = ipc_link_index(&self.links, channel) else {
            return;
        };
        let link = &mut self.links[index];
        link.last_ns = ts_mono_ns.max(link.last_ns);
        if !evidence.is_na() {
            link.refs.push(LinkRef {
                evidence,
                kind: LinkKind::Ipc,
                channel: Some(channel),
                ts_mono_ns,
                source,
            });
            if let Some(best) = strongest_evidence(link.refs.iter().map(|item| &item.evidence)) {
                link.evidence = best;
            }
        }
        self.refresh_ipc_bytes(index);
    }

    fn refresh_ipc_bytes(&mut self, index: usize) {
        let channels: Vec<u64> = self.links[index]
            .refs
            .iter()
            .filter_map(|item| item.channel)
            .collect();
        let mut total = None;
        let mut seen = BTreeSet::new();
        for id in channels {
            if !seen.insert(id) {
                continue;
            }
            let Some(state) = self.open.get(&id) else {
                continue;
            };
            add_opt(&mut total, state.close_a_to_b.or(state.bytes_a_to_b));
            add_opt(&mut total, state.close_b_to_a.or(state.bytes_b_to_a));
            add_opt(&mut total, state.bytes_undirected);
        }
        self.links[index].bytes = total;
    }

    fn maybe_finding(&mut self, parts: &KeyParts, ts_mono_ns: u64) {
        if !parts.outside_agent {
            return;
        }
        if self
            .findings
            .iter()
            .any(|row| row.peer_pid == parts.peer_pid)
        {
            return;
        }
        self.findings.push(WatchFinding {
            kind: WATCH_GROUP_KIND,
            text: WATCH_GROUP_TEXT,
            evidence: Evidence::I,
            peer_pid: parts.peer_pid,
            ts_mono_ns,
            session_id: parts.session_id,
        });
    }

    fn push_link(&mut self, link: AgentLink) {
        if let Some(index) = self.links.iter().position(|row| same_edge(row, &link)) {
            let ipc = self.links[index].kind == LinkKind::Ipc;
            {
                let existing = &mut self.links[index];
                existing.refs.extend(link.refs);
                existing.evidence =
                    strongest_evidence(existing.refs.iter().map(|item| &item.evidence))
                        .unwrap_or(existing.evidence.clone());
                existing.first_ns = existing.first_ns.min(link.first_ns);
                existing.last_ns = existing.last_ns.max(link.last_ns);
                if !ipc {
                    add_opt(&mut existing.bytes, link.bytes);
                }
                if existing.method.is_none() {
                    existing.method = link.method;
                }
                if existing.target.is_none() {
                    existing.target = link.target;
                }
            }
            if ipc {
                self.refresh_ipc_bytes(index);
            }
            return;
        }
        let ipc = link.kind == LinkKind::Ipc;
        self.links.push(link);
        if ipc {
            let index = self.links.len() - 1;
            self.refresh_ipc_bytes(index);
        }
    }
}

struct RpcInput {
    rpc: AgentRpc,
    evidence: Evidence,
    source: Source,
    ts_mono_ns: u64,
    session_id: Option<SessionId>,
    from: Option<InstanceId>,
    to: Option<InstanceId>,
    channel: Option<u64>,
}

struct ToolInput {
    call: AgentToolCall,
    evidence: Evidence,
    source: Source,
    ts_mono_ns: u64,
    session_id: Option<SessionId>,
    from: Option<InstanceId>,
    to: Option<InstanceId>,
}

fn fresh_open(
    parts: &KeyParts,
    evidence: &Evidence,
    source: &Source,
    ts_mono_ns: u64,
    name_len: Option<usize>,
    peer_na: Option<NaReason>,
) -> OpenState {
    OpenState {
        parts: *parts,
        evidence: grade_or_none(evidence.clone()),
        source: source.clone(),
        first_ns: ts_mono_ns,
        last_ns: ts_mono_ns,
        bytes_a_to_b: None,
        bytes_b_to_a: None,
        bytes_undirected: None,
        close_a_to_b: None,
        close_b_to_a: None,
        name_len,
        peer_na,
    }
}

fn channel_from_open(channel: u64, state: &OpenState) -> IpcChannel {
    IpcChannel {
        session_id: state.parts.session_id,
        kind: state.parts.kind,
        endpoint_a: state.parts.endpoint_a,
        endpoint_b: state.parts.endpoint_b,
        collector_channel: Some(channel),
        bytes_a_to_b: state.close_a_to_b.or(state.bytes_a_to_b),
        bytes_b_to_a: state.close_b_to_a.or(state.bytes_b_to_a),
        bytes_undirected: state.bytes_undirected,
        evidence: state.evidence.clone(),
        source: state.source.clone(),
        first_ns: state.first_ns,
        last_ns: state.last_ns,
        internal: state.parts.internal,
        name_len: state.name_len,
        peer_na: state.peer_na.clone(),
    }
}

fn channel_from_bucket(bucket: &IpcBucket) -> IpcChannel {
    IpcChannel {
        session_id: bucket.key.session_id,
        kind: bucket.key.kind,
        endpoint_a: bucket.key.endpoint_a,
        endpoint_b: bucket.key.endpoint_b,
        collector_channel: bucket.collector_channel,
        bytes_a_to_b: bucket.bytes_a_to_b,
        bytes_b_to_a: bucket.bytes_b_to_a,
        bytes_undirected: bucket.bytes_undirected,
        evidence: bucket.evidence.clone(),
        source: bucket.source.clone(),
        first_ns: bucket.first_ns,
        last_ns: bucket.last_ns,
        internal: bucket.internal,
        name_len: bucket.name_len,
        peer_na: if bucket.key.endpoint_b.is_unknown() {
            Some(NaReason::PeerUnknown)
        } else {
            None
        },
    }
}

fn merge_channel(row: &mut IpcChannel, extra: &IpcChannel) {
    add_opt(&mut row.bytes_a_to_b, extra.bytes_a_to_b);
    add_opt(&mut row.bytes_b_to_a, extra.bytes_b_to_a);
    add_opt(&mut row.bytes_undirected, extra.bytes_undirected);
    row.evidence = stronger_opt(row.evidence.clone(), extra.evidence.clone());
    row.first_ns = row.first_ns.min(extra.first_ns);
    row.last_ns = row.last_ns.max(extra.last_ns);
    if row.name_len.is_none() {
        row.name_len = extra.name_len;
    }
    if row.peer_na.is_none() {
        row.peer_na = extra.peer_na.clone();
    }
}

fn same_edge(left: &AgentLink, right: &AgentLink) -> bool {
    left.kind == right.kind
        && left.from_instance == right.from_instance
        && left.to_instance == right.to_instance
        && left.to_external == right.to_external
        && left.session_id == right.session_id
}

fn ipc_link_index(links: &[AgentLink], channel: u64) -> Option<usize> {
    links.iter().position(|link| {
        link.kind == LinkKind::Ipc && link.refs.iter().any(|item| item.channel == Some(channel))
    })
}

fn is_short_id(id: &str) -> bool {
    (SUBAGENT_ID_MIN..=SUBAGENT_ID_MAX).contains(&id.len())
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn kind_ord(kind: IpcKind) -> u8 {
    match kind {
        IpcKind::Pipe => 0,
        IpcKind::UnixStream => 1,
        IpcKind::UnixDgram => 2,
        IpcKind::NamedPipe => 3,
        IpcKind::LoopbackTcp => 4,
        IpcKind::LoopbackUdp => 5,
        IpcKind::Unknown => 6,
    }
}

fn ord_bucket(key: &ChannelKey) -> OrdBucket {
    OrdBucket {
        session: key.session_id.map(|id| id.0),
        kind: kind_ord(key.kind),
        a_uid: key.endpoint_a.proc_uid.map(|uid| uid.0),
        a_pid: key.endpoint_a.pid,
        b_uid: key.endpoint_b.proc_uid.map(|uid| uid.0),
        b_pid: key.endpoint_b.pid,
        bucket_index: key.bucket_index,
    }
}

fn ord_channel(row: &IpcChannel) -> OrdChannel {
    OrdChannel {
        session: row.session_id.map(|id| id.0),
        kind: kind_ord(row.kind),
        a_uid: row.endpoint_a.proc_uid.map(|uid| uid.0),
        a_pid: row.endpoint_a.pid,
        b_uid: row.endpoint_b.proc_uid.map(|uid| uid.0),
        b_pid: row.endpoint_b.pid,
        collector_channel: row.collector_channel,
    }
}

impl ByteAdd {
    const fn none() -> Self {
        Self {
            a_to_b: None,
            b_to_a: None,
            undirected: None,
        }
    }

    fn from_transfer(direction: IpcDirection, bytes: u64) -> Self {
        match direction {
            IpcDirection::AToB => Self {
                a_to_b: Some(bytes),
                b_to_a: None,
                undirected: None,
            },
            IpcDirection::BToA => Self {
                a_to_b: None,
                b_to_a: Some(bytes),
                undirected: None,
            },
            IpcDirection::Unknown => Self {
                a_to_b: None,
                b_to_a: None,
                undirected: Some(bytes),
            },
        }
    }
}

fn add_bytes(slot: &mut OpenState, add: &ByteAdd) {
    add_opt(&mut slot.bytes_a_to_b, add.a_to_b);
    add_opt(&mut slot.bytes_b_to_a, add.b_to_a);
    add_opt(&mut slot.bytes_undirected, add.undirected);
}

/// First observation of a side becomes `Some`, including a measured `0`.
/// A side that is never passed stays `None`.
fn add_opt(slot: &mut Option<u64>, add: Option<u64>) {
    if let Some(add) = add {
        *slot = Some(match *slot {
            Some(current) => current.saturating_add(add),
            None => add,
        });
    }
}

fn add_pair(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (None, None) => None,
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (Some(left), Some(right)) => Some(left.saturating_add(right)),
    }
}

fn grade_or_none(evidence: Evidence) -> Option<Evidence> {
    if evidence.is_na() {
        None
    } else {
        Some(evidence)
    }
}

/// Rank, strongest first. `NA` has no rank.
fn rank(evidence: &Evidence) -> Option<u8> {
    match evidence {
        Evidence::E1 => Some(0),
        Evidence::E2 => Some(1),
        Evidence::S => Some(2),
        Evidence::E3 => Some(3),
        Evidence::I => Some(4),
        Evidence::NA(_) => None,
    }
}

fn stronger(left: &Evidence, right: &Evidence) -> Evidence {
    match (rank(left), rank(right)) {
        (Some(left_rank), Some(right_rank)) if left_rank <= right_rank => left.clone(),
        (Some(_), Some(_)) => right.clone(),
        (Some(_), None) => left.clone(),
        (None, Some(_)) => right.clone(),
        (None, None) => left.clone(),
    }
}

fn stronger_opt(left: Option<Evidence>, right: Option<Evidence>) -> Option<Evidence> {
    match (left, right) {
        (Some(left), Some(right)) => Some(stronger(&left, &right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}
