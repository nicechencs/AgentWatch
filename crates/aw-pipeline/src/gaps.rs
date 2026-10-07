//! Gap merge. Same collector and same [`GapKind`] inside 5 s become one gap.
//!
//! pipeline.md §4.1: consecutive gaps from one collector of one kind collapse so
//! the gap records themselves do not become a storm. `count` is summed.
//! Evidence is never raised. When the inputs disagree, the merged gap keeps the
//! weaker level (E1 > E2 > S > E3 > I). `NA` is weaker than every observed level.
//!
//! Time is the caller's monotonic nanoseconds. This module does not read a clock.

use std::collections::BTreeMap;

use aw_core::{Evidence, GapKind, NaReason, ProcRef, SessionId, Source};

use crate::output::GapRec;

/// Window in which the same collector and kind collapse. pipeline.md §4.1.
pub const MERGE_WINDOW_NS: u64 = 5_000_000_000;

/// Collector name written on gaps this crate creates (ingress drops, rate limits,
/// store failures, skipped rows). Not a hostname.
pub const PIPELINE_COLLECTOR: &str = "pipeline/batcher";

/// How many failed batches stay in memory before the oldest is dropped.
/// pipeline.md §3.7 says "the last N batches"; N is not specified. 4 is small
/// enough that a stuck disk does not grow without bound.
pub const DEFAULT_RETRY_BATCHES: usize = 4;

/// Detail string for a write that was dropped after the retry cap.
///
/// `aw_core::GapKind` has no `store_failure` variant (pipeline.md §3.7 names one).
/// The gap uses [`GapKind::Unknown`] and this exact detail so a reader can still
/// tell a store failure from every other unknown gap. Do not add a variant here.
pub const STORE_FAILURE_DETAIL: &str = "store_failure";

/// Detail on a process row that was not written because `depth` was not observed.
///
/// `processes.depth` is `NOT NULL`. Passing `0` would claim "session root". The
/// row is skipped instead, and this gap counts it.
pub const DEPTH_UNOBSERVED_DETAIL: &str = "depth_unobserved";

/// Open merge buckets, keyed by collector, kind, and process.
///
/// pipeline.md §4.1 names collector and kind. A per-process rate-limit gap also
/// carries a [`ProcRef`]. Folding two processes into one bucket would hide which
/// process was limited, so the process id is part of the key. A collector-wide
/// gap (no process) still merges with other collector-wide gaps of the same kind.
#[derive(Debug, Default)]
pub struct GapMerger {
    open: BTreeMap<MergeKey, GapRec>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MergeKey {
    collector: String,
    /// Discriminant only. [`GapKind`] is not [`Ord`].
    kind: u8,
    /// `None` for a collector-wide gap.
    proc_uid: Option<u64>,
}

impl GapMerger {
    /// No open buckets.
    pub fn new() -> Self {
        Self {
            open: BTreeMap::new(),
        }
    }

    /// Fold `gap` into the open bucket, or start a new one.
    ///
    /// A bucket closes when this gap's `from_mono_ns` is more than
    /// [`MERGE_WINDOW_NS`] after the bucket's `to_mono_ns`. The closed gap is
    /// returned; `gap` itself stays open. `None` means it merged into the open
    /// bucket (or replaced an empty one).
    pub fn observe(&mut self, gap: GapRec) -> Option<GapRec> {
        let key = MergeKey {
            collector: gap.collector.as_str().to_owned(),
            kind: gap_kind_ord(gap.gap_kind),
            proc_uid: gap.proc.as_ref().map(|proc| proc.uid.0),
        };
        match self.open.get(&key) {
            Some(open) if gap.from_mono_ns.saturating_sub(open.to_mono_ns) <= MERGE_WINDOW_NS => {
                let merged = merge_pair(open, &gap);
                self.open.insert(key, merged);
                None
            }
            Some(_) => self.open.insert(key, gap),
            None => {
                self.open.insert(key, gap);
                None
            }
        }
    }

    /// Close every open bucket. Order is collector, then kind.
    pub fn flush(&mut self) -> Vec<GapRec> {
        std::mem::take(&mut self.open).into_values().collect()
    }

    /// How many buckets are still open.
    pub fn open_len(&self) -> usize {
        self.open.len()
    }
}

/// Collapse `failures` ingress `try_send` misses into one dropped gap.
///
/// The ingress already counts each failure ([`crate::ingress::Ingress::failures`]).
/// This function does not touch that queue. `failures == 0` returns nothing:
/// there is no gap to report. The window is a single point at `now_ns` because
/// the counter has no per-failure timestamp.
pub fn dropped_from_failures(failures: u64, now_ns: u64) -> Option<GapRec> {
    if failures == 0 {
        return None;
    }
    let gap = make_gap(
        PIPELINE_COLLECTOR,
        GapKind::Dropped,
        vec!["ingress".to_owned()],
        now_ns,
        now_ns,
        Some(failures),
        None,
        Evidence::E1,
    );
    Some(gap)
}

/// Record `n` drop counts (each count is one failed `try_send`) and merge them.
///
/// Acceptance: 1000 calls collapse to one [`GapKind::Dropped`] gap whose `count`
/// is 1000. `now_ns` is the monotonic time of the whole burst; every count shares
/// it, so they sit inside the 5 s window.
pub fn record_drops(n: u64, now_ns: u64) -> Vec<GapRec> {
    let mut merger = GapMerger::new();
    let mut closed = Vec::new();
    for _ in 0..n {
        if let Some(gap) = dropped_from_failures(1, now_ns) {
            if let Some(done) = merger.observe(gap) {
                closed.push(done);
            }
        }
    }
    closed.extend(merger.flush());
    closed
}

/// Build a gap this crate owns. Evidence is the level the caller already has.
/// This function does not raise it.
#[allow(clippy::too_many_arguments)]
pub fn make_gap(
    collector: &str,
    kind: GapKind,
    affects: Vec<String>,
    from_mono_ns: u64,
    to_mono_ns: u64,
    count: Option<u64>,
    detail: Option<String>,
    evidence: Evidence,
) -> GapRec {
    GapRec {
        seq: 0,
        ts_mono_ns: to_mono_ns,
        ts_wall_ns: 0,
        session_id: None,
        proc: None,
        evidence,
        field_evidence: BTreeMap::new(),
        source: Source::new(collector),
        collector: Source::new(collector),
        gap_kind: kind,
        affects,
        from_mono_ns,
        to_mono_ns,
        count,
        detail,
    }
}

/// A rate-limit gap for one process. `count` is how many events were not forwarded.
pub fn rate_limited_gap(
    proc: &ProcRef,
    session_id: Option<SessionId>,
    kind_name: &str,
    from_mono_ns: u64,
    to_mono_ns: u64,
    count: u64,
    evidence: Evidence,
) -> GapRec {
    let mut gap = make_gap(
        PIPELINE_COLLECTOR,
        GapKind::RateLimited,
        vec![kind_name.to_owned()],
        from_mono_ns,
        to_mono_ns,
        Some(count),
        None,
        evidence,
    );
    gap.proc = Some(proc.clone());
    gap.session_id = session_id;
    gap
}

fn merge_pair(open: &GapRec, incoming: &GapRec) -> GapRec {
    let mut merged = open.clone();
    merged.from_mono_ns = open.from_mono_ns.min(incoming.from_mono_ns);
    merged.to_mono_ns = open.to_mono_ns.max(incoming.to_mono_ns);
    merged.ts_mono_ns = merged.to_mono_ns;
    merged.count = add_counts(open.count, incoming.count);
    merged.evidence = weaker(&open.evidence, &incoming.evidence);
    merged.affects = union_affects(&open.affects, &incoming.affects);
    merged.detail = merge_detail(open.detail.as_deref(), incoming.detail.as_deref());
    if open.session_id != incoming.session_id {
        merged.session_id = None;
    }
    // The merge key already requires the same process. A mismatch is a bug in
    // the key, not a reason to drop the attribution. Keep the open gap's proc.
    // seq stays the first gap's seq. A merged record is not a new observation.
    merged
}

fn add_counts(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (None, None) => None,
        (Some(a), None) | (None, Some(a)) => Some(a),
        (Some(a), Some(b)) => Some(a.saturating_add(b)),
    }
}

fn union_affects(left: &[String], right: &[String]) -> Vec<String> {
    let mut out = left.to_vec();
    for item in right {
        if !out.iter().any(|have| have == item) {
            out.push(item.clone());
        }
    }
    out
}

fn merge_detail(left: Option<&str>, right: Option<&str>) -> Option<String> {
    match (left, right) {
        (None, None) => None,
        (Some(a), None) | (None, Some(a)) => Some(a.to_owned()),
        (Some(a), Some(b)) if a == b => Some(a.to_owned()),
        (Some(a), Some(_)) => {
            // The two details disagreed. Keep the first and note that, without
            // copying the second string (it may be caller-supplied text).
            Some(format!("{a}; detail_disagreed"))
        }
    }
}

/// Rank: E1 > E2 > S > E3 > I. `NA` is weaker than every observed level.
/// Equal levels return `left`.
pub fn weaker(left: &Evidence, right: &Evidence) -> Evidence {
    if rank(left) <= rank(right) {
        left.clone()
    } else {
        right.clone()
    }
}

fn rank(evidence: &Evidence) -> u8 {
    match evidence {
        Evidence::E1 => 5,
        Evidence::E2 => 4,
        Evidence::S => 3,
        Evidence::E3 => 2,
        Evidence::I => 1,
        Evidence::NA(_) => 0,
    }
}

fn gap_kind_ord(kind: GapKind) -> u8 {
    match kind {
        GapKind::Dropped => 0,
        GapKind::LostByOs => 1,
        GapKind::Restart => 2,
        GapKind::RateLimited => 3,
        GapKind::Permission => 4,
        GapKind::AttachWindow => 5,
        GapKind::Unsupported => 6,
        GapKind::ScopeRace => 7,
        GapKind::CollectorDisconnected => 8,
        GapKind::SelfReportDropped => 9,
        GapKind::AttributionUnknown => 10,
        GapKind::CacheEvicted => 11,
        GapKind::ParseError => 12,
        GapKind::RuleStateEvicted => 13,
        GapKind::Unknown => 14,
    }
}

/// Wire name of a gap kind. Matches the serde snake_case, including `Unknown`.
pub fn gap_kind_name(kind: GapKind) -> &'static str {
    match kind {
        GapKind::Dropped => "dropped",
        GapKind::LostByOs => "lost_by_os",
        GapKind::Restart => "restart",
        GapKind::RateLimited => "rate_limited",
        GapKind::Permission => "permission",
        GapKind::AttachWindow => "attach_window",
        GapKind::Unsupported => "unsupported",
        GapKind::ScopeRace => "scope_race",
        GapKind::CollectorDisconnected => "collector_disconnected",
        GapKind::SelfReportDropped => "self_report_dropped",
        GapKind::AttributionUnknown => "attribution_unknown",
        GapKind::CacheEvicted => "cache_evicted",
        GapKind::ParseError => "parse_error",
        GapKind::RuleStateEvicted => "rule_state_evicted",
        GapKind::Unknown => "unknown",
    }
}

/// `Evidence` as the one-letter store column. `NA` stays `NA`; the reason is
/// not folded into a stronger level.
pub fn evidence_code(evidence: &Evidence) -> &'static str {
    match evidence {
        Evidence::E1 => "E1",
        Evidence::E2 => "E2",
        Evidence::E3 => "E3",
        Evidence::S => "S",
        Evidence::I => "I",
        Evidence::NA(_) => "NA",
    }
}

/// `NA` reason code, when the evidence is `NA`.
pub fn na_reason_code(evidence: &Evidence) -> Option<&'static str> {
    match evidence {
        Evidence::NA(reason) => Some(na_name(reason)),
        _ => None,
    }
}

fn na_name(reason: &NaReason) -> &'static str {
    match reason {
        NaReason::EsNoReadEvent => "es_no_read_event",
        NaReason::MmapNotObservable => "mmap_not_observable",
        NaReason::TlsNoProxy => "tls_no_proxy",
        NaReason::DirectBypassProxy => "direct_bypass_proxy",
        NaReason::CertPinned => "cert_pinned",
        NaReason::Quic => "quic",
        NaReason::Ech => "ech",
        NaReason::NoDnsObserved => "no_dns_observed",
        NaReason::Preexisting => "preexisting",
        NaReason::CollectorUnavailable => "collector_unavailable",
        NaReason::Redacted => "redacted",
        NaReason::AttributionBreak => "attribution_break",
        NaReason::PartialClientHello => "partial_client_hello",
        NaReason::H2Hpack => "h2_hpack",
        NaReason::TooLarge => "too_large",
        NaReason::FileChanged => "file_changed",
        NaReason::PeerUnknown => "peer_unknown",
        NaReason::ProtocolNotObserved => "protocol_not_observed",
        NaReason::Unknown => "unknown",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn thousand_drops_collapse_to_one_gap() {
        let gaps = record_drops(1000, 50);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].gap_kind, GapKind::Dropped);
        assert_eq!(gaps[0].count, Some(1000));
        assert_eq!(gaps[0].evidence, Evidence::E1);
        assert_eq!(gaps[0].collector.as_str(), PIPELINE_COLLECTOR);
    }

    #[test]
    fn zero_drops_emit_nothing() {
        assert!(record_drops(0, 1).is_empty());
        assert!(dropped_from_failures(0, 1).is_none());
    }

    #[test]
    fn different_kinds_do_not_merge() {
        let mut merger = GapMerger::new();
        let dropped = make_gap(
            "ebpf/ring",
            GapKind::Dropped,
            vec!["net".to_owned()],
            0,
            0,
            Some(1),
            None,
            Evidence::E1,
        );
        let lost = make_gap(
            "ebpf/ring",
            GapKind::LostByOs,
            vec!["net".to_owned()],
            0,
            0,
            Some(2),
            None,
            Evidence::E1,
        );
        assert!(merger.observe(dropped).is_none());
        assert!(merger.observe(lost).is_none());
        let closed = merger.flush();
        assert_eq!(closed.len(), 2);
    }

    #[test]
    fn outside_the_window_closes_the_open_bucket() {
        let mut merger = GapMerger::new();
        let first = make_gap(
            "etw/proc",
            GapKind::Dropped,
            vec!["process".to_owned()],
            0,
            1_000,
            Some(3),
            None,
            Evidence::E1,
        );
        let later = make_gap(
            "etw/proc",
            GapKind::Dropped,
            vec!["process".to_owned()],
            1_000 + MERGE_WINDOW_NS + 1,
            1_000 + MERGE_WINDOW_NS + 1,
            Some(4),
            None,
            Evidence::E1,
        );
        assert!(merger.observe(first).is_none());
        let closed = merger.observe(later).expect("first bucket closes");
        assert_eq!(closed.count, Some(3));
        let rest = merger.flush();
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].count, Some(4));
    }

    #[test]
    fn disagreeing_evidence_keeps_the_weaker_level() {
        let strong = make_gap(
            "poll/net",
            GapKind::RateLimited,
            vec!["process_start".to_owned()],
            0,
            10,
            Some(1),
            None,
            Evidence::E1,
        );
        let weak = make_gap(
            "poll/net",
            GapKind::RateLimited,
            vec!["process_start".to_owned()],
            20,
            30,
            Some(2),
            None,
            Evidence::I,
        );
        let mut merger = GapMerger::new();
        merger.observe(strong);
        merger.observe(weak);
        let closed = merger.flush();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].evidence, Evidence::I);
        assert_eq!(closed[0].count, Some(3));
        assert_eq!(closed[0].from_mono_ns, 0);
        assert_eq!(closed[0].to_mono_ns, 30);
    }

    #[test]
    fn e3_is_not_upgraded_when_merged_with_e1() {
        let self_report = make_gap(
            "agent/hook",
            GapKind::SelfReportDropped,
            vec!["agent_rpc".to_owned()],
            0,
            1,
            Some(1),
            None,
            Evidence::E3,
        );
        let kernel = make_gap(
            "agent/hook",
            GapKind::SelfReportDropped,
            vec!["agent_rpc".to_owned()],
            2,
            3,
            Some(1),
            None,
            Evidence::E1,
        );
        assert_eq!(
            weaker(&kernel.evidence, &self_report.evidence),
            Evidence::E3
        );
        let mut merger = GapMerger::new();
        merger.observe(kernel);
        merger.observe(self_report);
        let closed = merger.flush();
        assert_eq!(closed[0].evidence, Evidence::E3);
    }

    #[test]
    fn unknown_counts_stay_unknown_until_one_side_has_a_number() {
        let unknown = make_gap(
            "es/client",
            GapKind::LostByOs,
            vec!["file".to_owned()],
            0,
            1,
            None,
            None,
            Evidence::E1,
        );
        let known = make_gap(
            "es/client",
            GapKind::LostByOs,
            vec!["file".to_owned()],
            2,
            3,
            Some(5),
            None,
            Evidence::E1,
        );
        let mut merger = GapMerger::new();
        merger.observe(unknown);
        merger.observe(known);
        assert_eq!(merger.flush()[0].count, Some(5));
    }
}
