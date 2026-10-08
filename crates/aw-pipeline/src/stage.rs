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

    /// Advance time-based state to `now_ns`.
    ///
    /// `out` is where a windowed stage emits records a clock advance produced
    /// (a UDP flow that went quiet, a bucket that closed). Placeholders ignore
    /// both arguments. The clock is the caller's monotonic nanoseconds; this
    /// method does not read the host clock.
    fn tick(&mut self, now_ns: u64, out: &mut Output);
}

/// End of the chain. Does not forward and does not record.
#[derive(Debug, Default)]
pub struct Tail;

impl Stage for Tail {
    fn process(&mut self, _event: RawEvent, _out: &mut Output, _next: &mut dyn Stage) {}

    fn tick(&mut self, _now_ns: u64, _out: &mut Output) {}
}

/// Forwards every event. Used by Scope, Dedup, Enrich, Redact, Correlate, and Batcher.
#[derive(Debug, Default)]
pub struct Forward;

impl Stage for Forward {
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        next.process(event, out, &mut Tail);
    }

    fn tick(&mut self, _now_ns: u64, _out: &mut Output) {}
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

    fn tick(&mut self, now_ns: u64, _out: &mut Output) {
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

    fn tick(&mut self, now_ns: u64, out: &mut Output) {
        self.inner.tick(now_ns, out);
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

    fn tick(&mut self, now_ns: u64, out: &mut Output) {
        self.inner.tick(now_ns, out);
    }
}

/// Redaction (P2-PIPE-03). Rewrites argv, env, URLs, and headers before aggregate.
///
/// Evidence is not touched: a redacted value is still the value the collector
/// saw, with the sensitive part replaced. The text before replacement is not
/// logged and not put on `out`. With `--unsafe-no-redact` the stage forwards
/// unchanged and records [`crate::redact::UNSAFE_NO_REDACT_FLAG`] once.
pub struct RedactStage {
    redactor: crate::redact::Redactor,
    noted: bool,
}

impl Default for RedactStage {
    fn default() -> Self {
        Self::new(&crate::config::RedactionConfig::default())
    }
}

impl RedactStage {
    /// One redactor for the session, from `[redaction]`.
    pub fn new(cfg: &crate::config::RedactionConfig) -> Self {
        Self {
            redactor: crate::redact::Redactor::new(cfg),
            noted: false,
        }
    }

    /// Whether this session runs with the built-in rules switched off.
    pub fn disabled(&self) -> bool {
        self.redactor.disabled()
    }
}

impl Stage for RedactStage {
    fn process(&mut self, mut event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        if self.redactor.disabled() {
            if !self.noted {
                out.flags
                    .push(crate::redact::UNSAFE_NO_REDACT_FLAG.to_owned());
                self.noted = true;
            }
        } else {
            let exe = event.kind.exe_base();
            self.redactor.apply(&mut event, exe.as_deref());
        }
        next.process(event, out, &mut Tail);
    }

    fn tick(&mut self, _now_ns: u64, _out: &mut Output) {}
}

/// Network aggregate (P1-PIPE-04).
///
/// Counts every input event into [`Output::events_seen`]. An event that is already a
/// [`aw_core::EventKind::Gap`] is copied into [`Output::gaps`] with the same evidence
/// and the same gap fields. `NetConnect` / `NetSend` / `NetRecv` / `NetClose` /
/// `TlsSni` update [`crate::aggregate::NetAggregator`] and may emit
/// [`crate::output::NetFlowRec`] and [`crate::output::FlowBucketRec`]. Evidence is
/// not raised. The event is still forwarded. File aggregation is not this card.
pub struct AggregateStage {
    net: crate::aggregate::NetAggregator,
    /// File open→close rows (P2-PIPE-01). Independent of the network table.
    file: crate::aggregate::FileAggregator,
    /// Sensitive-path labels (P2-PIPE-02). Applied to rows as they are emitted.
    sensitive: crate::sensitive::Rules,
    /// Agent profile id for the `agent-config` info exception. `None` until a
    /// `ProcessStart` or a caller sets one.
    agent: Option<String>,
    /// L0–L4 (P2-PIPE-04). Replay feeds it no samples, so it stays at L0 and
    /// keeps every row.
    degrade: crate::degrade::DegradeLadder,
}

impl Default for AggregateStage {
    fn default() -> Self {
        Self::new(crate::config::AggregateConfig::default())
    }
}

impl AggregateStage {
    /// Bucket width from `cfg`. A zero width is treated as the documented 5 s.
    pub fn new(cfg: crate::config::AggregateConfig) -> Self {
        Self::with_sensitive(cfg, crate::config::SensitiveConfig::default())
    }

    /// Aggregate plus the sensitive-path table. Built-in rules stay on; `sensitive`
    /// only supplies the session home, case folding, and extra rules.
    pub fn with_sensitive(
        cfg: crate::config::AggregateConfig,
        sensitive: crate::config::SensitiveConfig,
    ) -> Self {
        Self {
            net: crate::aggregate::NetAggregator::new(cfg.bucket_secs),
            file: crate::aggregate::FileAggregator::new(&cfg),
            sensitive: crate::sensitive::Rules::load(&sensitive),
            agent: None,
            degrade: crate::degrade::DegradeLadder::default(),
        }
    }

    /// Aggregate plus the degrade ladder's thresholds. Replay uses the defaults
    /// and never calls [`Self::observe_degrade`], so the level stays 0.
    pub fn with_degrade(
        cfg: crate::config::AggregateConfig,
        sensitive: crate::config::SensitiveConfig,
        degrade: crate::config::DegradeConfig,
    ) -> Self {
        let mut stage = Self::with_sensitive(cfg, sensitive);
        stage.degrade = crate::degrade::DegradeLadder::new(degrade);
        stage
    }

    /// Accessor profile for the `agent-config` info exception.
    pub fn set_agent(&mut self, agent: Option<String>) {
        self.agent = agent;
    }

    /// Current degrade level, 0 through 4.
    pub fn degrade_level(&self) -> u8 {
        self.degrade.level()
    }

    /// `true` after RSS crossed the hard limit, until a later sample is under it.
    pub fn emergency_stop(&self) -> bool {
        self.degrade.emergency()
    }

    /// Apply one resource sample. At most one ladder step. A level change widens
    /// the file coalesce window and the network bucket; the gaps for the step are
    /// appended to `out`.
    pub fn observe_degrade(&mut self, sample: crate::degrade::DegradeSample, out: &mut Output) {
        if self.degrade.observe(sample, out) {
            self.file.set_coalesce_ms(self.degrade.coalesce_ms());
            self.net.set_bucket_secs(self.degrade.bucket_secs());
        }
    }

    /// Emit file rows a close finished but the coalesce window was still holding.
    pub fn finish(&mut self, out: &mut Output) {
        let before = out.file_access.len();
        self.file.finish(out);
        self.label_and_thin(before, out);
    }

    /// In-memory group of the flows still open plus the ones already emitted.
    ///
    /// CLI live views call this. It does not read a clock and does not write.
    pub fn summarize(
        &self,
        by: crate::aggregate::FlowGroupBy,
    ) -> Vec<crate::aggregate::FlowSummary> {
        self.net.summarize(by)
    }
}

impl Stage for AggregateStage {
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        out.events_seen = out.events_seen.saturating_add(1);
        if let aw_core::EventKind::Gap(gap) = &event.kind {
            out.gaps
                .push(crate::output::GapRec::from_event(&event, gap));
        }
        self.net.observe(&event, out);
        let before = out.file_access.len();
        self.file.observe(&event, out);
        self.label_and_thin(before, out);
        next.process(event, out, &mut Tail);
    }

    fn tick(&mut self, now_ns: u64, out: &mut Output) {
        self.net.tick(now_ns, out);
        let before = out.file_access.len();
        self.file.tick(now_ns, out);
        self.label_and_thin(before, out);
    }
}

impl AggregateStage {
    /// Label the rows emitted since `before`, then drop the ones the current
    /// degrade level does not keep. Labelling runs first so a protected row is
    /// recognized by its `sensitive_rule`.
    fn label_and_thin(&mut self, before: usize, out: &mut Output) {
        let agent = self.agent.as_deref();
        for row in &mut out.file_access[before..] {
            self.sensitive.label(row, agent);
        }
        self.degrade.retain_new_files(&mut out.file_access, before);
    }
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

    fn tick(&mut self, now_ns: u64, out: &mut Output) {
        self.inner.tick(now_ns, out);
    }
}

/// Batcher (P1-PIPE-05). Rate-limits, and writes when a sink is attached.
///
/// [`crate::Pipeline::replay`] builds this with [`Self::default`], which has no
/// sink and does not open a database. Events that pass the per-process limiter
/// are forwarded. A `process_start` over the bucket is not forwarded; the
/// limiter records [`aw_core::GapKind::RateLimited`] on `out`.
///
/// [`Self::set_degrade`] turns on L1: individual `NetSend` / `NetRecv` events
/// are not forwarded and are counted. Other kinds still go through.
///
/// [`Self::set_sink`] attaches an [`aw_store::RecordSink`]. Gap events are
/// handed to the batcher so they merge. Flush timing uses `event.ts_mono_ns`
/// and [`Stage::tick`]'s `now_ns`, not the host clock.
pub struct BatcherStage {
    limiter: crate::limits::Limiter,
    batch: Option<crate::batcher::Batcher<crate::batcher::DynSink>>,
    store: crate::config::StoreConfig,
    /// L1. Replay leaves this false: it has no queue to measure.
    degrade: bool,
    now_ns: u64,
}

impl Default for BatcherStage {
    fn default() -> Self {
        Self::new(crate::config::PipelineConfig::default())
    }
}

impl BatcherStage {
    /// Limiter from `cfg.limits`. No sink until [`Self::set_sink`].
    pub fn new(cfg: crate::config::PipelineConfig) -> Self {
        Self {
            limiter: crate::limits::Limiter::new(cfg.limits),
            batch: None,
            store: cfg.store,
            degrade: false,
            now_ns: 0,
        }
    }

    /// Attach a sink. Call this before records arrive; an open batch is not kept.
    pub fn set_sink(&mut self, sink: Box<dyn aw_store::RecordSink + Send>) {
        self.batch = Some(crate::batcher::Batcher::with_defaults(
            crate::batcher::DynSink::new(sink),
            self.store.clone(),
        ));
    }

    /// L1 switch. `true` drops individual `NetSend` / `NetRecv` events.
    pub fn set_degrade(&mut self, degrade: bool) {
        self.degrade = degrade;
    }

    /// `NetSend` events L1 did not forward. Not a byte count.
    pub fn net_send_dropped(&self) -> u64 {
        self.limiter.net_send_dropped()
    }

    /// `NetRecv` events L1 did not forward. Not a byte count.
    pub fn net_recv_dropped(&self) -> u64 {
        self.limiter.net_recv_dropped()
    }
}

impl Stage for BatcherStage {
    fn process(&mut self, event: RawEvent, out: &mut Output, next: &mut dyn Stage) {
        self.now_ns = event.ts_mono_ns;
        match self.limiter.admit(&event, self.degrade) {
            Err(crate::limits::Hold::RateLimited) => {
                // Not forwarded. `take_gaps` closes the merge bucket so the
                // count is visible on `out` without waiting out the 5 s window.
                // Tests that want the window kept open call `Limiter` directly.
                out.gaps.extend(self.limiter.take_gaps());
            }
            Err(crate::limits::Hold::Degraded) => {
                // Counted on the limiter. Not forwarded. No gap per event:
                // L1 is a counter, and a per-event gap would be the storm §4
                // tells us to avoid.
            }
            Ok(()) => {
                if let Some(batch) = self.batch.as_mut() {
                    if let aw_core::EventKind::Gap(gap) = &event.kind {
                        let mut only = Output::empty();
                        only.gaps
                            .push(crate::output::GapRec::from_event(&event, gap));
                        out.gaps.extend(batch.push_output(&only, self.now_ns));
                    }
                }
                next.process(event, out, &mut Tail);
            }
        }
    }

    fn tick(&mut self, now_ns: u64, out: &mut Output) {
        self.now_ns = now_ns;
        if let Some(batch) = self.batch.as_mut() {
            let emitted = batch.tick(now_ns);
            if !emitted.is_empty() {
                // Keep the gaps on `out` as well as feeding them back, so a
                // replay that ends on a time flush still shows them.
                out.gaps.extend(emitted.iter().cloned());
                let mut only = Output::empty();
                only.gaps = emitted;
                batch.ingest(&only, now_ns);
            }
        }
    }
}
