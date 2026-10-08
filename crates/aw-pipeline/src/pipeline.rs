//! Replay driver. Runs the seven stages in order on a virtual clock.
//!
//! [`Pipeline::replay`] does not read [`std::time::Instant`] or the wall clock. The
//! virtual position is each event's `ts_mono_ns`. Passthrough stages emit no business
//! records; see [`crate::output::Output`].

use aw_core::RawEvent;

use crate::clock::{PipelineClock, ReplayClock};
use crate::config::PipelineConfig;
use crate::output::Output;
use crate::stage::{
    AggregateStage, BatcherStage, CorrelateStage, DedupStage, EnrichStage, RedactStage, ScopeStage,
    Stage, Tail,
};

/// The seven stages, in pipeline.md order, with the config they will eventually read.
///
/// [`Pipeline::replay`] runs the stock passthrough chain. Each stage is its own type
/// that implements [`Stage`], so a test can put a different impl in front of the
/// remaining stock stages without editing this crate.
pub struct Pipeline {
    cfg: PipelineConfig,
    scope: ScopeStage,
    dedup: DedupStage,
    enrich: EnrichStage,
    redact: RedactStage,
    aggregate: AggregateStage,
    correlate: CorrelateStage,
    batcher: BatcherStage,
}

impl Pipeline {
    /// Pipeline with the stages that read `cfg`: redact, aggregate, and the
    /// degrade ladder. Scope, dedup, enrich, and correlate stay passthrough.
    pub fn new(cfg: PipelineConfig) -> Self {
        let redact = RedactStage::new(&cfg.redaction);
        let aggregate = AggregateStage::with_degrade(
            cfg.aggregate.clone(),
            cfg.sensitive.clone(),
            cfg.degrade.clone(),
        );
        let batcher = BatcherStage::new(cfg.clone());
        Self {
            cfg,
            scope: ScopeStage::default(),
            dedup: DedupStage::default(),
            enrich: EnrichStage::default(),
            redact,
            aggregate,
            correlate: CorrelateStage::default(),
            batcher,
        }
    }

    /// Config this pipeline was built with.
    pub fn config(&self) -> &PipelineConfig {
        &self.cfg
    }

    /// Current degrade level, 0 through 4. Replay stays at 0 because it feeds no
    /// resource samples.
    pub fn degrade_level(&self) -> u8 {
        self.aggregate.degrade_level()
    }

    /// `true` after a sample put RSS over `hard_rss_bytes`, until a later sample
    /// is under it. The daemon reads this and stops the collectors; this crate
    /// does not.
    pub fn emergency_stop(&self) -> bool {
        self.aggregate.emergency_stop()
    }

    /// Apply one resource sample and, if the level changes, widen the file
    /// coalesce window and the network bucket. The step's gap lands on `out`.
    pub fn observe_degrade(&mut self, sample: crate::degrade::DegradeSample, out: &mut Output) {
        self.aggregate.observe_degrade(sample, out);
    }

    /// Run `events` through Scope → Dedup → Enrich → Redact → Aggregate → Correlate → Batcher.
    ///
    /// The virtual clock jumps to each event's `ts_mono_ns` before `tick` and `process`.
    /// Order of events is the iterator order. The same input and config produce the same
    /// [`Output`].
    pub fn replay(events: impl IntoIterator<Item = RawEvent>, cfg: PipelineConfig) -> Output {
        let mut pipeline = Self::new(cfg);
        let mut clock = ReplayClock::new();
        let mut out = Output::empty();
        for event in events {
            clock.advance_to(event.ts_mono_ns);
            let now = clock.now_ns();
            pipeline.tick(now, &mut out);
            pipeline.process(event, &mut out);
        }
        pipeline.finish(&mut out);
        out
    }

    fn finish(&mut self, out: &mut Output) {
        self.aggregate.finish(out);
    }

    fn tick(&mut self, now_ns: u64, out: &mut Output) {
        self.scope.tick(now_ns, out);
        self.dedup.tick(now_ns, out);
        self.enrich.tick(now_ns, out);
        self.redact.tick(now_ns, out);
        self.aggregate.tick(now_ns, out);
        self.correlate.tick(now_ns, out);
        self.batcher.tick(now_ns, out);
    }

    fn process(&mut self, event: RawEvent, out: &mut Output) {
        // Nested so each stage's `next` is the following one. The chain ends at Tail
        // inside the last stage. This is the fixed order; a test that needs a different
        // middle stage calls the `Stage` impls directly.
        self.scope.process(
            event,
            out,
            &mut Chain {
                stage: &mut self.dedup,
                next: &mut Chain {
                    stage: &mut self.enrich,
                    next: &mut Chain {
                        stage: &mut self.redact,
                        next: &mut Chain {
                            stage: &mut self.aggregate,
                            next: &mut Chain {
                                stage: &mut self.correlate,
                                next: &mut Chain {
                                    stage: &mut self.batcher,
                                    next: &mut Tail,
                                },
                            },
                        },
                    },
                },
            },
        );
    }
}

/// Links `stage` to `next` so `Forward` can call straight through.
struct Chain<'a> {
    stage: &'a mut dyn Stage,
    next: &'a mut dyn Stage,
}

impl Stage for Chain<'_> {
    fn process(&mut self, event: RawEvent, out: &mut Output, _next: &mut dyn Stage) {
        self.stage.process(event, out, self.next);
    }

    fn tick(&mut self, now_ns: u64, out: &mut Output) {
        self.stage.tick(now_ns, out);
    }
}
