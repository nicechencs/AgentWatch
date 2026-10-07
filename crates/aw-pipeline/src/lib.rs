//! Pipeline skeleton: ordered stages, a bounded ingress, and in-memory replay.
//!
//! Collectors push [`aw_core::RawEvent`]s. This crate turns them into records. The
//! bodies of Scope, Dedup, Enrich, Redact, Aggregate, Correlate, and Batcher are
//! passthrough placeholders (P1-PIPE-01). Later cards replace one stage at a time.
//!
//! The task card names a `tokio::mpsc` ingress. This workspace has no tokio, and
//! replay does not need a runtime, so [`ingress::Ingress`] uses
//! `std::sync::mpsc::sync_channel`. The default capacity is still 65536, the send
//! side still uses only `try_send`, and a failure still increments a counter instead
//! of dropping the event. `Gap { dropped }` from that counter is P1-PIPE-05.
//!
//! Replay ([`Pipeline::replay`]) drives [`clock::ReplayClock`] from each event's
//! `ts_mono_ns`. That path does not read the host clock. Production code that needs
//! a live monotonic reading uses [`clock::InstantClock`], which reads
//! [`std::time::Instant`] and reports no wall time.
//!
//! Placeholders do not raise evidence, do not invent `0` for an unknown field, and
//! do not store file contents, HTTP bodies, `Authorization`, or `Cookie`.

#![forbid(unsafe_code)]

pub mod clock;
pub mod config;
pub mod enrich;
pub mod ingress;
pub mod output;
pub mod pipeline;
pub mod scope;
pub mod stage;

pub use clock::{InstantClock, PipelineClock, ReplayClock};
pub use config::{
    AggregateConfig, CorrelationConfig, LimitsConfig, PipelineConfig, RateLimit, StoreConfig,
};
pub use enrich::{
    ProcCache, ProcCacheConfig, ProcInfo, DEFAULT_CAPACITY as PROC_CACHE_CAPACITY,
    DEFAULT_LINGER_SECS,
};
pub use ingress::{Ingress, IngressRx, DEFAULT_CAPACITY};
pub use output::{DnsRec, FlowBucketRec, GapRec, NetFlowRec, Output, ProcessRec};
pub use pipeline::Pipeline;
pub use scope::{ScopeConfig, ScopeFilter, ScopeSet, ScopeUpdate, DEFAULT_PENDING_MS};
pub use stage::{
    AggregateStage, BatcherStage, CorrelateStage, DedupStage, EnrichStage, Forward, RedactStage,
    ScopeStage, Stage, Tail,
};

/// Empty marker so the daemon can name this crate before every stage is real.
pub struct Placeholder;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::PathBuf;

    use aw_core::time::Clock;
    use aw_core::{
        EventKind, EventSink, Evidence, FixtureReader, Gap, GapKind, ProcRef, ProcUid,
        ProcessStart, RawEvent, RawEventParts, SessionId, SinkError, Source, StartHow,
    };

    use super::*;

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/common/placeholder-process/events.jsonl")
    }

    fn load_fixture() -> Vec<RawEvent> {
        let (_header, events) = FixtureReader::open(&fixture_path())
            .expect("open placeholder fixture")
            .read_all()
            .expect("read placeholder fixture");
        events
    }

    fn gap_event(evidence: Evidence, count: Option<u64>) -> RawEvent {
        RawEvent::try_new(RawEventParts {
            seq: 7,
            ts_mono_ns: 5_000,
            ts_wall_ns: 1_759_795_200_000_000_000,
            session_id: Some(SessionId(1)),
            proc: None,
            source: Source::new("placeholder/test"),
            evidence,
            kind: EventKind::Gap(Gap::new(
                "placeholder/test",
                GapKind::Dropped,
                vec!["file".to_owned()],
                1_000,
                5_000,
                count,
                None,
            )),
        })
        .expect("gap event")
    }

    #[test]
    fn placeholder_type_still_exists() {
        let _marker = Placeholder;
        assert_eq!(std::mem::size_of_val(&_marker), 0);
    }

    #[test]
    fn replay_placeholder_fixture_counts_and_is_deterministic() {
        // insta is not used. fixtures/README.md stores plain-text snaps, and this
        // card must not add that dependency. Two ordinary replays are compared with
        // `PartialEq` instead of a snapshot file.
        let events = load_fixture();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind.kind_name(), "process_start");

        let cfg = PipelineConfig::default();
        let first = Pipeline::replay(events.clone(), cfg.clone());
        let second = Pipeline::replay(events, cfg);

        assert_eq!(first.events_seen, 1);
        assert!(first.processes.is_empty());
        assert!(first.net_flows.is_empty());
        assert!(first.flow_buckets.is_empty());
        assert!(first.dns.is_empty());
        assert!(first.gaps.is_empty());
        assert_eq!(first, second);
    }

    #[test]
    fn aggregate_copies_gap_without_raising_evidence() {
        let event = gap_event(Evidence::E1, None);
        let out = Pipeline::replay([event], PipelineConfig::default());
        assert_eq!(out.events_seen, 1);
        assert_eq!(out.gaps.len(), 1);
        let gap = &out.gaps[0];
        assert_eq!(gap.evidence, Evidence::E1);
        assert_eq!(gap.gap_kind, GapKind::Dropped);
        assert_eq!(gap.count, None);
        assert_eq!(gap.affects, vec!["file".to_owned()]);
        assert_eq!(gap.seq, 7);
        assert!(out.processes.is_empty());
    }

    #[test]
    fn inference_gap_stays_inference() {
        let event = gap_event(Evidence::I, Some(3));
        let out = Pipeline::replay([event], PipelineConfig::default());
        assert_eq!(out.gaps.len(), 1);
        assert_eq!(out.gaps[0].evidence, Evidence::I);
        assert_eq!(out.gaps[0].count, Some(3));
    }

    #[test]
    fn config_defaults_match_pipeline_doc() {
        let cfg = PipelineConfig::default();
        assert_eq!(cfg.aggregate.bucket_secs, 5);
        assert_eq!(cfg.aggregate.file_flush_secs, 30);
        assert_eq!(cfg.aggregate.coalesce_window_ms, 1000);
        assert_eq!(cfg.store.batch_max_rows, 1000);
        assert_eq!(cfg.store.batch_max_ms, 100);
        assert_eq!(cfg.correlation.max_window_secs, 300);
        assert_eq!(cfg.limits.file_open.per_sec, 2000);
        assert_eq!(cfg.limits.file_open.burst, 10_000);
        assert!(cfg.limits.file_rw.is_none());
        assert!(cfg.limits.ipc_transfer.is_none());
        assert_eq!(cfg.limits.process_start.per_sec, 200);
        assert_eq!(cfg.limits.net_connect.burst, 2000);
        assert_eq!(cfg.limits.dns.per_sec, 500);
        assert_eq!(cfg.limits.agent_rpc.burst, 1000);
    }

    #[test]
    fn ingress_full_counts_and_returns_the_event() {
        let (mut ingress, _rx) = Ingress::with_capacity(1);
        let first = process_event(1);
        let second = process_event(2);
        ingress.emit(first).expect("one slot");
        let err = ingress.emit(second).expect_err("second does not fit");
        match err {
            SinkError::Full { event } => {
                assert_eq!(event.seq, 2);
                assert_eq!(event.kind.kind_name(), "process_start");
            }
            other => panic!("expected Full, got {other}"),
        }
        assert_eq!(ingress.failures(), 1);
    }

    #[test]
    fn ingress_disconnect_counts_and_does_not_drop_silently() {
        let (mut ingress, rx) = Ingress::with_capacity(1);
        drop(rx);
        let err = ingress.emit(process_event(9)).expect_err("disconnected");
        match err {
            SinkError::Full { event } => assert_eq!(event.seq, 9),
            other => panic!("expected the event back, got {other}"),
        }
        assert_eq!(ingress.failures(), 1);
    }

    #[test]
    fn default_capacity_is_65536() {
        assert_eq!(DEFAULT_CAPACITY, 65_536);
    }

    #[test]
    fn replay_clock_follows_event_timestamps_only() {
        let mut clock = ReplayClock::new();
        assert_eq!(clock.now_ns(), 0);
        clock.advance_to(4_000);
        assert_eq!(PipelineClock::now_ns(&clock), 4_000);
        clock.advance_to(1_000);
        assert_eq!(clock.now_ns(), 1_000);
        assert!(clock.mono_to_wall(4_000).is_none());
    }

    #[test]
    fn a_stage_can_be_replaced_without_the_others() {
        // CountingStage stands in for Scope. The other six stay the stock placeholders.
        let mut scope = CountingStage::default();
        let mut dedup = DedupStage::default();
        let mut out = Output::empty();
        let event = process_event(1);
        scope.process(event, &mut out, &mut dedup);
        assert_eq!(scope.seen, 1);
        assert_eq!(
            out.events_seen, 0,
            "replaced scope, stock dedup does not count"
        );
    }

    #[derive(Default)]
    struct CountingStage {
        seen: u64,
    }

    impl Stage for CountingStage {
        fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
            self.seen = self.seen.saturating_add(1);
            next.process(event, out, &mut Tail);
        }

        fn tick(&mut self, _now_ns: u64) {}
    }

    fn process_event(seq: u64) -> RawEvent {
        RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns: seq.saturating_mul(1_000),
            ts_wall_ns: 1_759_795_200_000_000_000,
            session_id: None,
            proc: Some(ProcRef {
                uid: ProcUid(1),
                pid: 100,
                tid: None,
            }),
            source: Source::new("placeholder/test"),
            evidence: Evidence::E1,
            kind: EventKind::ProcessStart(ProcessStart::new(
                1,
                None,
                1_759_795_200_000_000_000,
                Some("/tmp/placeholder".to_owned()),
                None,
                None,
                None,
                StartHow::Exec,
                None,
                None,
            )),
        })
        .expect("process_start")
    }
}
