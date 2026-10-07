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
    /// Passthrough pipeline with explicit defaults.
    pub fn new(cfg: PipelineConfig) -> Self {
        Self {
            cfg,
            scope: ScopeStage::default(),
            dedup: DedupStage::default(),
            enrich: EnrichStage::default(),
            redact: RedactStage::default(),
            aggregate: AggregateStage,
            correlate: CorrelateStage::default(),
            batcher: BatcherStage::default(),
        }
    }

    /// Config this pipeline was built with. Stages in this card do not read it.
    pub fn config(&self) -> &PipelineConfig {
        &self.cfg
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
            pipeline.tick(now);
            pipeline.process(event, &mut out);
        }
        out
    }

    fn tick(&mut self, now_ns: u64) {
        self.scope.tick(now_ns);
        self.dedup.tick(now_ns);
        self.enrich.tick(now_ns);
        self.redact.tick(now_ns);
        self.aggregate.tick(now_ns);
        self.correlate.tick(now_ns);
        self.batcher.tick(now_ns);
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

    fn tick(&mut self, now_ns: u64) {
        self.stage.tick(now_ns);
    }
}
