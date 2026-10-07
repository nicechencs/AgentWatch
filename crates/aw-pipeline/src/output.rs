//! In-memory records produced by [`crate::Pipeline::replay`].
//!
//! Shapes follow storage.md (`processes`, `net_flows`, `net_flow_buckets`, `dns`,
//! `gaps`). This card's passthrough stages leave the business vecs empty. Unknown
//! fields on a record a later stage might build are `Option` and stay `None`; this
//! module does not invent `0` or `""` for a value that was not observed.
//!
//! [`GapRec`] copies the gap payload and the event envelope that does not hold argv,
//! environment values, URLs, or headers. It does not store the [`aw_core::RawEvent`].

use std::collections::BTreeMap;

use aw_core::{Evidence, Gap, GapKind, ProcRef, ProcUid, SessionId, Source, StartHow};

/// Everything a replay produced. Business vecs are empty until a later card fills them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Events the aggregate placeholder observed. Not a business record.
    pub events_seen: u64,
    /// `processes` rows. Empty in this card.
    pub processes: Vec<ProcessRec>,
    /// `net_flows` rows. Empty in this card.
    pub net_flows: Vec<NetFlowRec>,
    /// `net_flow_buckets` rows. Empty in this card.
    pub flow_buckets: Vec<FlowBucketRec>,
    /// `dns` rows. Empty in this card.
    pub dns: Vec<DnsRec>,
    /// Gaps that arrived as events, copied unchanged.
    pub gaps: Vec<GapRec>,
}

impl Output {
    /// No events, no records.
    pub fn empty() -> Self {
        Self {
            events_seen: 0,
            processes: Vec::new(),
            net_flows: Vec::new(),
            flow_buckets: Vec::new(),
            dns: Vec::new(),
            gaps: Vec::new(),
        }
    }
}

impl Default for Output {
    fn default() -> Self {
        Self::empty()
    }
}

/// One `processes` row. Not produced by the passthrough aggregate.
///
/// `depth` is `Option` because this card does not compute a tree. storage.md's
/// `DEFAULT 0` is a later writer's schema default, not an observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRec {
    /// Owning session, when scope has assigned one.
    pub session_id: Option<SessionId>,
    /// Stable process id.
    pub proc_uid: ProcUid,
    /// OS pid at the observation.
    pub pid: u32,
    /// Parent [`ProcUid`], when known.
    pub parent_uid: Option<ProcUid>,
    /// Parent pid, when known.
    pub ppid: Option<u32>,
    /// Distance from the session root. `None` until a stage computes it.
    pub depth: Option<u32>,
    /// Process start, monotonic nanoseconds.
    pub start_ns: u64,
    /// Exit time. `None` if the process has not exited in this replay.
    pub exit_ns: Option<u64>,
    /// Exit code. `None` if not observed.
    pub exit_code: Option<i32>,
    /// Exit signal. `None` if not observed.
    pub exit_signal: Option<i32>,
    /// How the process started.
    pub how: StartHow,
    /// User id string. `None` if not observed. Not an empty string.
    pub user_id: Option<String>,
    /// Signer, when the platform reported one.
    pub signer: Option<String>,
    /// Record evidence. Not raised by this crate's placeholders.
    pub evidence: Evidence,
    /// Field-level evidence copied from the source event.
    pub field_evidence: BTreeMap<String, Evidence>,
    /// Collector source string.
    pub source: Source,
    /// Recognized agent name. `None` until an adapter says so.
    pub agent: Option<String>,
}

/// One `net_flows` row. Not produced by the passthrough aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetFlowRec {
    /// Owning session, when known.
    pub session_id: Option<SessionId>,
    /// Subject process, when known.
    pub proc_uid: Option<ProcUid>,
    /// `tcp` or `udp`, as storage.md stores it. `None` if the event did not say.
    pub proto: Option<String>,
    /// `outbound`, `inbound`, or `unknown`. `None` if not observed.
    pub direction: Option<String>,
    /// Local address text. `None` if not observed.
    pub local_ip: Option<String>,
    /// Local port. `None` if not observed.
    pub local_port: Option<u16>,
    /// Remote address text. `None` if not observed.
    pub remote_ip: Option<String>,
    /// Remote port. `None` if not observed.
    pub remote_port: Option<u16>,
    /// Best domain. `None` if no DNS or SNI was observed.
    pub domain: Option<String>,
    /// How `domain` was chosen. `None` when there is no domain.
    pub domain_source: Option<String>,
    /// TLS SNI, when observed.
    pub sni: Option<String>,
    /// Bytes sent. `None` means not observed, not zero.
    pub bytes_up: Option<u64>,
    /// Bytes received. `None` means not observed, not zero.
    pub bytes_down: Option<u64>,
    /// Flow start, monotonic nanoseconds.
    pub start_ns: u64,
    /// Flow end. `None` if still open in this replay.
    pub end_ns: Option<u64>,
    /// Record evidence.
    pub evidence: Evidence,
    /// Collector source.
    pub source: Source,
}

/// One `net_flow_buckets` row. Not produced by the passthrough aggregate.
///
/// Byte counters here are measurements a later stage would add. This card emits none,
/// so the fields stay `Option` rather than a default of zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowBucketRec {
    /// Flow this bucket belongs to, once a writer assigns an id. `None` in memory before that.
    pub flow_id: Option<u64>,
    /// Owning session, when known.
    pub session_id: Option<SessionId>,
    /// Bucket start, aligned to `aggregate.bucket_secs` by a later stage.
    pub bucket_ns: u64,
    /// Bytes sent in the bucket. `None` if not measured.
    pub bytes_up: Option<u64>,
    /// Bytes received in the bucket. `None` if not measured.
    pub bytes_down: Option<u64>,
    /// Record evidence.
    pub evidence: Evidence,
}

/// One `dns` row. Not produced by the passthrough aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRec {
    /// Owning session, when known.
    pub session_id: Option<SessionId>,
    /// Process that sent the query. `None` for an unattributed resolver.
    pub proc_uid: Option<ProcUid>,
    /// Observation time, monotonic nanoseconds.
    pub ts_ns: u64,
    /// Query name.
    pub qname: String,
    /// Query type.
    pub qtype: u16,
    /// Response code. `None` on a query that has no answer yet.
    pub rcode: Option<u16>,
    /// Answer records as already-structured text. Empty when there are none, which is
    /// an observation of "no answers", not a stand-in for unknown.
    pub answers: Vec<String>,
    /// Smallest TTL in the answer. `None` when no TTL was observed.
    pub ttl_min: Option<u32>,
    /// Resolver address. `None` when not observed.
    pub server: Option<String>,
    /// Record evidence.
    pub evidence: Evidence,
    /// Collector source.
    pub source: Source,
}

/// One gap copied from an input [`aw_core::EventKind::Gap`].
///
/// Fields match the event. Evidence is the event's evidence, not a higher level.
/// `count` stays [`None`] when the event's count was unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapRec {
    /// Event sequence.
    pub seq: u64,
    /// Event monotonic time.
    pub ts_mono_ns: u64,
    /// Event wall time, as carried on the event (schema field, not invented here).
    pub ts_wall_ns: i64,
    /// Session on the event. `None` when the event had none.
    pub session_id: Option<SessionId>,
    /// Subject process on the event. `None` for a collector-wide gap.
    pub proc: Option<ProcRef>,
    /// Record evidence, copied. Not raised.
    pub evidence: Evidence,
    /// Field-level evidence, copied. Empty when the event had none.
    pub field_evidence: BTreeMap<String, Evidence>,
    /// Event source, copied. Not the same field as [`Self::collector`].
    pub source: Source,
    /// Collector that reported the gap.
    pub collector: Source,
    /// Why the stretch is missing.
    pub gap_kind: GapKind,
    /// Event classes affected.
    pub affects: Vec<String>,
    /// Gap window start.
    pub from_mono_ns: u64,
    /// Gap window end.
    pub to_mono_ns: u64,
    /// Known loss count. `None` when the count itself is unknown.
    pub count: Option<u64>,
    /// Optional short detail. Not a place for argv or URLs.
    pub detail: Option<String>,
}

impl GapRec {
    /// Copy `gap` and the envelope fields that do not carry secrets.
    pub fn from_event(event: &aw_core::RawEvent, gap: &Gap) -> Self {
        Self {
            seq: event.seq,
            ts_mono_ns: event.ts_mono_ns,
            ts_wall_ns: event.ts_wall_ns,
            session_id: event.session_id,
            proc: event.proc.clone(),
            evidence: event.evidence.clone(),
            field_evidence: event.field_evidence.clone(),
            source: event.source.clone(),
            collector: gap.collector.clone(),
            gap_kind: gap.gap_kind,
            affects: gap.affects.clone(),
            from_mono_ns: gap.from_mono_ns,
            to_mono_ns: gap.to_mono_ns,
            count: gap.count,
            detail: gap.detail.clone(),
        }
    }
}
