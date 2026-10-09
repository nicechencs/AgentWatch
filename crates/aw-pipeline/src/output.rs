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
    /// `file_access` rows. Empty until the file aggregator emits one.
    pub file_access: Vec<FileAccessRec>,
    /// Gaps that arrived as events, copied unchanged.
    pub gaps: Vec<GapRec>,
    /// Session flags. `unsafe_no_redact` is the only value this crate writes,
    /// and only when the caller switched the built-in rules off for the run.
    pub flags: Vec<String>,
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
            file_access: Vec::new(),
            gaps: Vec::new(),
            flags: Vec::new(),
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
    /// `true` only after a proxy rewrite says this flow went through the explicit
    /// proxy. Aggregate leaves it `false`: there is no proxy session on that path,
    /// which is "not rewritten", not "unknown".
    pub via_proxy: bool,
    /// `true` when a proxy session was on and this flow is a non-loopback TCP/UDP
    /// connect that did not use the proxy (network-attribution §5.3).
    ///
    /// Aggregate and a batcher with no [`crate::enrich::ProxySession`] leave this
    /// `false`. That is "no proxy session judged this flow", not "unknown whether
    /// it bypassed". A judged bypass is `true`; a judged via-proxy or unchanged
    /// flow stays `false`. There is no `quic` column on `net_flows`; UDP/443 is
    /// recorded as `NA(quic)` on [`Self::field_evidence`] under `url`.
    pub direct: bool,
    /// `true` while the flow is still open and this row is a 30 s partial flush.
    /// A closed flow is `false`.
    pub partial: bool,
    /// Platform cumulative bytes sent, from `NetClose.total_sent`. `None` when
    /// the close did not carry a platform total.
    pub platform_total_up: Option<u64>,
    /// Platform cumulative bytes received, from `NetClose.total_recv`.
    pub platform_total_down: Option<u64>,
    /// Signed difference `platform_total_up - bytes_up` when the close carried a
    /// total and the two disagreed by more than 5%. `None` otherwise. Not a
    /// stand-in for "no bytes".
    pub bytes_up_delta: Option<i64>,
    /// Signed difference `platform_total_down - bytes_down` under the same rule.
    pub bytes_down_delta: Option<i64>,
    /// Record evidence.
    pub evidence: Evidence,
    /// Field-level evidence. Empty when every field matches the record level.
    pub field_evidence: BTreeMap<String, Evidence>,
    /// Collector source.
    pub source: Source,
    /// In-memory flow id assigned by aggregate. `None` on a record this stage
    /// did not build.
    pub flow_id: Option<u64>,
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
    /// Record evidence. `S` when every byte in the bucket came from a snapshot.
    pub evidence: Evidence,
    /// Field-level evidence. A sampled bucket marks `bytes_up` and `bytes_down`.
    pub field_evidence: BTreeMap<String, Evidence>,
}

/// One `file_access` row. Produced by the file aggregator (P2-PIPE-01).
///
/// Byte counters stay [`None`] until a read or write event actually reported a
/// count. A platform that has no read event (macOS ES) keeps the field `None`
/// and records `NA` in [`Self::field_evidence`]. This struct does not invent `0`.
///
/// `path` is a filesystem path, not argv or a URL. `Debug` is derived because
/// the aggregator never puts a secret into these fields; redaction of argv and
/// URLs happens in an earlier stage and is not stored here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAccessRec {
    /// Owning session, when known.
    pub session_id: Option<SessionId>,
    /// Subject process. `None` only when the source event had no process.
    pub proc_uid: Option<ProcUid>,
    /// `access`, `create`, `delete`, `rename`, or `exec`.
    pub op: String,
    /// Path as the event reported it. Not resolved and not read from disk.
    pub path: String,
    /// Rename target. `None` for every op other than `rename`.
    pub path_to: Option<String>,
    /// `read` / `write` / `read_write` / `exec` / `unknown`. `None` when `op` is
    /// not `access` or `exec`.
    pub access: Option<String>,
    /// First observation, monotonic nanoseconds.
    pub first_ns: u64,
    /// Latest observation, monotonic nanoseconds.
    pub last_ns: u64,
    /// How many opens this row covers. A single open is `1`, not `None`.
    pub opens: u64,
    /// Read syscalls observed. `None` when no read event was seen.
    pub reads: Option<u64>,
    /// Bytes reported by read events. `None` when no byte count was observed.
    pub bytes_read: Option<u64>,
    /// Write syscalls observed. `None` when no write event was seen.
    pub writes: Option<u64>,
    /// Bytes reported by write events. `None` when no byte count was observed.
    pub bytes_written: Option<u64>,
    /// `Some(true)` when an open reported the file was created.
    pub created: Option<bool>,
    /// `Some(true)` when an open reported truncation.
    pub truncated: Option<bool>,
    /// `Some(true)` when a close reported the file was modified.
    pub modified: Option<bool>,
    /// Platform error from a failed open. `None` when the open succeeded or no
    /// result was reported. `0` is not written here.
    pub result: Option<i32>,
    /// `true` for a flush of a handle that is still open.
    pub partial: bool,
    /// Sensitive-path rule id, when a later stage labelled this path.
    pub sensitive_rule: Option<String>,
    /// `sensitive.<rule>` or `sensitive.<rule>.info`. Empty when unlabelled.
    pub tags: Vec<String>,
    /// Directory-fold marker. `None` on an ordinary per-path row.
    pub folded_dir: Option<String>,
    /// Paths kept as samples of a folded directory. Empty on an ordinary row.
    pub sample_paths: Vec<String>,
    /// Record evidence. The weakest level among the events that built the row.
    pub evidence: Evidence,
    /// Field-level evidence, copied from the source events. Not raised.
    pub field_evidence: BTreeMap<String, Evidence>,
    /// Collector source of the first event.
    pub source: Source,
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
