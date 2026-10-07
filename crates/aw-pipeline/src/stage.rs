//! Stage trait and the seven passthrough placeholders.
//!
//! Order is fixed: Scope → Dedup → Enrich → Redact → Aggregate → Correlate → Batcher.
//! P1-PIPE-02, P1-PIPE-03, P1-PIPE-04, and P1-PIPE-05 replace the bodies. This card
//! only forwards events. It does not filter, deduplicate, redact, aggregate, correlate,
//! or write. Evidence on an accepted event is not changed.
//!
//! Each stage is its own type so a test can swap one impl without touching the others.

use std::collections::VecDeque;

use aw_core::RawEvent;

use crate::output::Output;
use crate::scope::{ScopeConfig, ScopeFilter};

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

/// Scope filter (P1-PIPE-02).
///
/// With no session injected, every event is forwarded. That keeps
/// [`crate::Pipeline::replay`] on an unscoped fixture identical to the
/// passthrough skeleton. After [`ScopeStage::apply`] adds a root, events
/// outside the session are not forwarded.
///
/// [`Stage::tick`] only expires a hold that is still unknown. A hold that has
/// become in-scope is released at the start of the next [`Stage::process`],
/// where `out` exists, or by [`ScopeStage::drain_ready`] when the chain is idle.
pub struct ScopeStage {
    filter: ScopeFilter,
    /// Events `tick` released. Forwarded on the next `process`.
    ready: VecDeque<RawEvent>,
}

impl Default for ScopeStage {
    fn default() -> Self {
        Self::new(ScopeConfig::default())
    }
}

impl ScopeStage {
    /// Filter with explicit pending window, cache limits, and daemon-exe list.
    pub fn new(cfg: ScopeConfig) -> Self {
        Self {
            filter: ScopeFilter::new(cfg),
            ready: VecDeque::new(),
        }
    }

    /// Inject a root or a snapshot. Does not read the host clock.
    pub fn apply(&mut self, update: crate::scope::ScopeUpdate) {
        self.filter.apply(update);
    }

    /// Events dropped because the pending window closed with no matching start.
    pub fn pending_drops(&self) -> u64 {
        self.filter.pending_drops()
    }

    /// Events dropped because their process is outside every watched session.
    pub fn out_of_scope_drops(&self) -> u64 {
        self.filter.out_of_scope_drops()
    }

    /// Child starts refused because the parent is a system daemon outside scope.
    pub fn attribution_breaks(&self) -> u64 {
        self.filter.attribution_breaks()
    }

    /// Process cache, including exited rows still inside the linger window.
    pub fn cache(&self) -> &crate::enrich::ProcCache {
        self.filter.cache()
    }

    /// Membership.
    pub fn scope(&self) -> &crate::scope::ScopeSet {
        self.filter.scope()
    }

    /// Forward events whose hold has already been decided. No-op when nothing is waiting.
    ///
    /// [`Stage::tick`] only expires timeouts. This is what releases a hold that
    /// became in-scope, which needs `out` to update a [`crate::ProcessRec`].
    pub fn drain_ready(&mut self, out: &mut Output, next: &mut dyn Stage) {
        self.ready.extend(self.filter.take_ready(out));
        self.forward_ready(out, next);
    }

    fn forward_ready(&mut self, out: &mut Output, next: &mut dyn Stage) {
        while let Some(event) = self.ready.pop_front() {
            next.process(event, out, &mut Tail);
        }
    }
}

impl Stage for ScopeStage {
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        self.ready.extend(self.filter.take_ready(out));
        self.forward_ready(out, next);
        for event in self.filter.push(event, out) {
            next.process(event, out, &mut Tail);
        }
    }

    fn tick(&mut self, now_ns: u64) {
        // Counting a timeout does not need `Output`. Releasing an in-scope hold
        // does, and that happens in `process` via [`ScopeFilter::take_ready`].
        self.filter.tick(now_ns);
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
