//! Stage trait and the seven passthrough placeholders.
//!
//! Order is fixed: Scope → Dedup → Enrich → Redact → Aggregate → Correlate → Batcher.
//! P1-PIPE-02, P1-PIPE-03, P1-PIPE-04, and P1-PIPE-05 replace the bodies. This card
//! only forwards events. It does not filter, deduplicate, redact, aggregate, correlate,
//! or write. Evidence on an accepted event is not changed.
//!
//! Each stage is its own type so a test can swap one impl without touching the others.

use aw_core::RawEvent;

use crate::output::Output;

/// One step in the fixed pipeline order.
///
/// `process` may push records into `out` and must forward the event to the next stage
/// unless a later card's real impl is allowed to drop it. The placeholders here always
/// forward. `tick` is called with the pipeline clock's monotonic position so a later
/// windowed impl can replace the no-op without changing the driver.
pub trait Stage {
    /// Handle one event. `next` is the following stage, or the end of the chain.
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage);

    /// Advance time-based state to `now_ns`. Placeholders do nothing.
    fn tick(&mut self, now_ns: u64);
}

/// End of the chain. Does not forward and does not record.
#[derive(Debug, Default)]
pub struct Tail;

impl Stage for Tail {
    fn process(&mut self, _event: RawEvent, _out: &mut Output, _next: &mut dyn Stage) {}

    fn tick(&mut self, _now_ns: u64) {}
}

/// Forwards every event. Used by Scope, Dedup, Enrich, Redact, Correlate, and Batcher.
#[derive(Debug, Default)]
pub struct Forward;

impl Stage for Forward {
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        next.process(event, out, &mut Tail);
    }

    fn tick(&mut self, _now_ns: u64) {}
}

/// Scope placeholder. Real filtering is P1-PIPE-02.
#[derive(Debug, Default)]
pub struct ScopeStage {
    inner: Forward,
}

impl Stage for ScopeStage {
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        self.inner.process(event, out, next);
    }

    fn tick(&mut self, now_ns: u64) {
        self.inner.tick(now_ns);
    }
}

/// Dedup placeholder. Passthrough in P1.
#[derive(Debug, Default)]
pub struct DedupStage {
    inner: Forward,
}

impl Stage for DedupStage {
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        self.inner.process(event, out, next);
    }

    fn tick(&mut self, now_ns: u64) {
        self.inner.tick(now_ns);
    }
}

/// Enrich placeholder. Real lookups are P1-PIPE-03.
#[derive(Debug, Default)]
pub struct EnrichStage {
    inner: Forward,
}

impl Stage for EnrichStage {
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        self.inner.process(event, out, next);
    }

    fn tick(&mut self, now_ns: u64) {
        self.inner.tick(now_ns);
    }
}

/// Redact placeholder. Passthrough in P1. Does not rewrite evidence.
#[derive(Debug, Default)]
pub struct RedactStage {
    inner: Forward,
}

impl Stage for RedactStage {
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        self.inner.process(event, out, next);
    }

    fn tick(&mut self, now_ns: u64) {
        self.inner.tick(now_ns);
    }
}

/// Aggregate placeholder.
///
/// Counts every input event into [`Output::events_seen`]. An event that is already a
/// [`aw_core::EventKind::Gap`] is copied into [`Output::gaps`] with the same evidence
/// and the same gap fields. Nothing else is emitted: no process, flow, bucket, or DNS
/// record. Evidence is not raised. The event is still forwarded.
#[derive(Debug, Default)]
pub struct AggregateStage;

impl Stage for AggregateStage {
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        out.events_seen = out.events_seen.saturating_add(1);
        if let aw_core::EventKind::Gap(gap) = &event.kind {
            out.gaps
                .push(crate::output::GapRec::from_event(&event, gap));
        }
        next.process(event, out, &mut Tail);
    }

    fn tick(&mut self, _now_ns: u64) {}
}

/// Correlate placeholder. Passthrough in P1. Does not emit findings.
#[derive(Debug, Default)]
pub struct CorrelateStage {
    inner: Forward,
}

impl Stage for CorrelateStage {
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        self.inner.process(event, out, next);
    }

    fn tick(&mut self, now_ns: u64) {
        self.inner.tick(now_ns);
    }
}

/// Batcher placeholder. Does not write. Real batching is a later card.
#[derive(Debug, Default)]
pub struct BatcherStage {
    inner: Forward,
}

impl Stage for BatcherStage {
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        self.inner.process(event, out, next);
    }

    fn tick(&mut self, now_ns: u64) {
        self.inner.tick(now_ns);
    }
}
