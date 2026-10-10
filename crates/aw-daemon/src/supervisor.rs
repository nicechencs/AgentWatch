//! Collector supervisor: probe, independent steps, restart, demotion.
//!
//! There is no tokio and no thread in this module. [`Supervisor::step`] takes
//! `now_ms` so tests drive a virtual clock. [`next_delay_ms`] is a pure function
//! of the attempt number (1 s, 2 s, 4 s, … capped at 60 s). Nothing here sleeps.
//!
//! `aw_core::Collector` has `start`, `update_scope`, `stop`, `health`, and
//! `capabilities`. It does not have `probe()`, and `start` drains a replay
//! rather than "one tick". [`Supervised`] is the adapter this card needs.
//! Platform collectors implement it later; this file only implements it for the
//! test double. `aw-core` is not modified.
//!
//! A collector error or panic becomes one [`GapKind::Restart`] description and
//! arms the backoff. The gap's own evidence is [`Evidence::E1`]: [`GapKind`]'s
//! docs say the gap itself is an observed fact. It is not evidence S, and it
//! does not raise any other record. Five consecutive failures demote that
//! collector's classes to the next tier and emit one [`GapKind::Unsupported`].
//!
//! Panic does not leave [`Supervisor::step`]. The call is wrapped in
//! [`std::panic::catch_unwind`] with [`std::panic::AssertUnwindSafe`].

// The bin has no session yet, so most of this module is only reached from its
// tests. Dead-code is checked per target and does not count `#[cfg(test)]`.
#![allow(dead_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use aw_core::{Evidence, GapKind, NaReason, Scope};

use crate::capabilities::{
    CapabilityChoice, CapabilityClass, CapabilityReport, ClassProbe, ReportError, SourceTier,
};

/// First restart wait. Attempt 1.
pub const BACKOFF_BASE_MS: u64 = 1_000;

/// Longest restart wait.
pub const BACKOFF_CAP_MS: u64 = 60_000;

/// Consecutive failures before the collector's classes move to the next tier.
pub const DEMOTE_AFTER: u32 = 5;

/// Delay before the next start after `attempt` consecutive failures.
///
/// `attempt` is 1-based. `0` has no delay. The sequence is 1 s, 2 s, 4 s, …
/// and never exceeds 60 s. Shift is capped so the multiplication cannot overflow.
pub fn next_delay_ms(attempt: u32) -> u64 {
    if attempt == 0 {
        return 0;
    }
    let shift = attempt.saturating_sub(1).min(16);
    let scaled = BACKOFF_BASE_MS.saturating_mul(1_u64 << shift);
    scaled.min(BACKOFF_CAP_MS)
}

/// One collector the supervisor can probe, tick, and scope.
///
/// This is not [`aw_core::Collector`]. That trait has no `probe()` and its
/// `start` takes a sink for a whole replay. [`tick`](Self::tick) is one step
/// the supervisor can isolate. A later card can wrap a real `Collector`.
pub trait Supervised {
    /// Stable collector name. Not a display sentence. No secrets.
    fn name(&self) -> &str;

    /// Tier this collector belongs to. Probe order is native, legacy, poll.
    fn tier(&self) -> SourceTier;

    /// Per-class answer. A missing class is treated as unavailable.
    fn probe(&self, class: CapabilityClass) -> ClassProbe;

    /// One unit of work. `Err` is a failure the supervisor restarts from.
    /// A panic is caught by the supervisor and treated the same way.
    ///
    /// # Errors
    ///
    /// [`TickError`] when this step failed. The message must not contain argv,
    /// environment values, URLs, or headers.
    fn tick(&mut self) -> Result<(), TickError>;

    /// Record `scope` and apply it if the collector has a scope hook.
    fn update_scope(&mut self, scope: &Scope);
}

/// Failure returned by [`Supervised::tick`]. The text must not carry secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickError {
    message: String,
}

impl TickError {
    /// `message` is a redacted diagnostic. This type does not scan it.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Borrow the diagnostic.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for TickError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TickError {}

/// A gap the supervisor observed. Not written to SQLite here.
///
/// `evidence` is [`Evidence::E1`] for both restart and demotion: the gap was
/// observed by this process. [`GapKind`] documents that the gap itself is a
/// fact. The evidence is not [`Evidence::S`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupervisorGap {
    /// Collector that failed or was demoted.
    pub collector: String,
    /// [`GapKind::Restart`] or [`GapKind::Unsupported`].
    pub kind: GapKind,
    /// Evidence of the gap record. Always [`Evidence::E1`].
    pub evidence: Evidence,
    /// Classes this gap affects (`"proc"`, `"net"`, `"dns"`).
    pub affects: Vec<String>,
    /// Virtual time of the observation, milliseconds.
    pub at_ms: u64,
    /// Redacted detail. No argv, environment values, URLs, or headers.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotPhase {
    /// Registered, but it won no class. Not ticked. Still probed on demotion.
    Idle,
    /// Ready to tick.
    Running,
    /// Waiting until `ready_at_ms` before the next tick.
    BackingOff { ready_at_ms: u64 },
    /// Five failures consumed this tier. Not ticked again.
    Demoted,
}

struct Slot<C> {
    collector: C,
    phase: SlotPhase,
    /// Consecutive tick failures since the last success. Not probe failures.
    consecutive_failures: u32,
    /// Classes this collector was chosen for. Demotion rewrites these rows.
    classes: Vec<CapabilityClass>,
}

/// Outcome of probing an empty tier list, or of a report that rejected a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorError {
    /// [`CapabilityReport`] refused a row.
    Report(ReportError),
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Report(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for SupervisorError {}

impl From<ReportError> for SupervisorError {
    fn from(err: ReportError) -> Self {
        Self::Report(err)
    }
}

/// Owns one collector per chosen tier and the [`CapabilityReport`] for the caller.
pub struct Supervisor<C> {
    slots: Vec<Slot<C>>,
    report: CapabilityReport,
    gaps: Vec<SupervisorGap>,
    scope: Option<Scope>,
}

impl<C: Supervised> Supervisor<C> {
    /// Probe `collectors` in native → legacy → poll order.
    ///
    /// Each class picks the first tier that offers it. A class nobody offers is
    /// [`Evidence::NA`] with [`NaReason::CollectorUnavailable`]. Collectors that
    /// win no class are not supervised. Order inside a tier follows `collectors`.
    ///
    /// # Errors
    ///
    /// [`SupervisorError::Report`] if a constructed row is inconsistent. With the
    /// constructors used here that does not happen; the error is still surfaced.
    pub fn start(collectors: Vec<C>) -> Result<Self, SupervisorError> {
        // Stable partition: native, then legacy, then poll. Input order inside a tier.
        let mut by_tier: [Vec<C>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for collector in collectors {
            let index = collector.tier() as usize;
            if index < by_tier.len() {
                by_tier[index].push(collector);
            }
        }
        let mut ordered: Vec<C> = Vec::new();
        for tier_slots in by_tier {
            ordered.extend(tier_slots);
        }

        let mut chosen: [Option<CapabilityChoice>; 3] = [None, None, None];
        let mut assigned: Vec<(usize, CapabilityClass)> = Vec::new();

        for class in CapabilityClass::ALL {
            let mut found = false;
            for (index, collector) in ordered.iter().enumerate() {
                let answer = collector.probe(class);
                if answer.class != class || !answer.is_available() {
                    continue;
                }
                chosen[class_index(class)] = Some(CapabilityChoice::from_tier(
                    class,
                    collector.tier(),
                    answer.evidence,
                ));
                assigned.push((index, class));
                found = true;
                break;
            }
            if !found {
                chosen[class_index(class)] = Some(CapabilityChoice::unavailable(
                    class,
                    NaReason::CollectorUnavailable,
                ));
            }
        }

        let proc = chosen[0].clone().ok_or_else(missing_row)?;
        let net = chosen[1].clone().ok_or_else(missing_row)?;
        let dns = chosen[2].clone().ok_or_else(missing_row)?;
        let report = CapabilityReport::new(proc, net, dns)?;

        let mut slots = Vec::new();
        for (index, collector) in ordered.into_iter().enumerate() {
            let classes: Vec<CapabilityClass> = assigned
                .iter()
                .filter(|(slot, _)| *slot == index)
                .map(|(_, class)| *class)
                .collect();
            // A collector that won nothing stays registered so a later demotion
            // can probe it. It is not ticked until it owns a class.
            let phase = if classes.is_empty() {
                SlotPhase::Idle
            } else {
                SlotPhase::Running
            };
            slots.push(Slot {
                collector,
                phase,
                consecutive_failures: 0,
                classes,
            });
        }

        let supervisor = Self {
            slots,
            report,
            gaps: Vec::new(),
            scope: None,
        };
        supervisor.log_selection();
        Ok(supervisor)
    }

    /// One line per class: which tier won, or that nobody offered it.
    ///
    /// The collector name and the evidence level only. A probe answer can carry
    /// an `NA` reason string; that string is not logged, because a collector is
    /// free to put anything in it.
    fn log_selection(&self) {
        for class in CapabilityClass::ALL {
            let choice = self.report.get(class);
            match choice.source_name() {
                Some(source) => tracing::info!(
                    class = class.as_str(),
                    source,
                    evidence = evidence_label(&choice.evidence),
                    "collector selected"
                ),
                None => tracing::warn!(
                    class = class.as_str(),
                    "no collector offered this class"
                ),
            }
        }
    }

    /// Report the caller stores on the session. Not written by this module.
    pub fn report(&self) -> &CapabilityReport {
        &self.report
    }

    /// Gaps observed so far, in order. Restart and demotion only.
    pub fn gaps(&self) -> &[SupervisorGap] {
        &self.gaps
    }

    /// Scope from the last [`update_scope`](Self::update_scope), if any.
    pub fn scope(&self) -> Option<&Scope> {
        self.scope.as_ref()
    }

    /// Borrow a supervised collector by name.
    pub fn collector(&self, name: &str) -> Option<&C> {
        self.slots
            .iter()
            .find(|slot| slot.collector.name() == name)
            .map(|slot| &slot.collector)
    }

    /// Remember `scope` and pass it to every active collector's scope hook.
    pub fn update_scope(&mut self, scope: &Scope) {
        self.scope = Some(scope.clone());
        for slot in &mut self.slots {
            slot.collector.update_scope(scope);
        }
    }

    /// Advance every collector that is due at `now_ms`.
    ///
    /// A collector in backoff is skipped until its deadline. A demoted collector
    /// is not ticked. One collector's error or panic does not stop the others.
    /// The panic payload is discarded; only the collector name is recorded.
    pub fn step(&mut self, now_ms: u64) {
        for index in 0..self.slots.len() {
            if !self.due(index, now_ms) {
                continue;
            }
            let name = self.slots[index].collector.name().to_owned();
            let tick_result = catch_unwind(AssertUnwindSafe(|| self.slots[index].collector.tick()));
            match tick_result {
                Ok(Ok(())) => {
                    self.slots[index].consecutive_failures = 0;
                    self.slots[index].phase = SlotPhase::Running;
                }
                Ok(Err(err)) => self.on_failure(index, now_ms, err.message()),
                Err(_) => {
                    // Panic payload is not formatted: it may contain anything the
                    // collector pushed, including values we must not log.
                    let _ = name;
                    self.on_failure(index, now_ms, "collector panicked");
                }
            }
        }
    }

    fn due(&self, index: usize, now_ms: u64) -> bool {
        match self.slots[index].phase {
            SlotPhase::Running => true,
            SlotPhase::BackingOff { ready_at_ms } => now_ms >= ready_at_ms,
            SlotPhase::Idle | SlotPhase::Demoted => false,
        }
    }

    fn on_failure(&mut self, index: usize, now_ms: u64, detail: &str) {
        let failures = self.slots[index].consecutive_failures.saturating_add(1);
        self.slots[index].consecutive_failures = failures;
        let name = self.slots[index].collector.name().to_owned();
        let affects = class_names(&self.slots[index].classes);

        // The gap is evidence E1 because this supervisor observed the failure.
        // GapKind's own doc: the gap itself is a fact. Not S.
        self.gaps.push(SupervisorGap {
            collector: name.clone(),
            kind: GapKind::Restart,
            evidence: Evidence::E1,
            affects: affects.clone(),
            at_ms: now_ms,
            detail: format!("{name}: {detail}"),
        });
        // `detail` is the collector's own message. `TickError` documents it as a
        // redacted diagnostic, so it is safe to log; the panic path passes a
        // fixed string instead of the panic payload.
        tracing::warn!(
            collector = %name,
            failures,
            detail,
            "collector failed; restart gap recorded"
        );

        if failures >= DEMOTE_AFTER {
            self.demote(index, now_ms);
            return;
        }

        let delay = next_delay_ms(failures);
        self.slots[index].phase = SlotPhase::BackingOff {
            ready_at_ms: now_ms.saturating_add(delay),
        };
    }

    /// Move this collector's classes to the next tier, or to NA if none remains.
    ///
    /// One [`GapKind::Unsupported`] is recorded for the demotion. The collector
    /// is not ticked again. A panic inside the replacement is not possible here:
    /// demotion only rewrites the report.
    fn demote(&mut self, index: usize, now_ms: u64) {
        let from = self.slots[index].collector.tier();
        let name = self.slots[index].collector.name().to_owned();
        let classes = self.slots[index].classes.clone();
        self.slots[index].phase = SlotPhase::Demoted;

        // Poll stamps S (fallback-poll §1). A higher fallback keeps the evidence
        // its own probe declared. A class the fallback cannot see becomes NA
        // with CollectorUnavailable — never a named source at a guessed level.
        let mut landed: Vec<String> = Vec::new();
        for class in &classes {
            let choice = match self.fallback_choice(*class, from) {
                Some(choice) => choice,
                None => CapabilityChoice::unavailable(*class, NaReason::CollectorUnavailable),
            };
            if let Some(source) = choice.source_name() {
                if !landed.iter().any(|seen| seen == source) {
                    landed.push(source.to_owned());
                }
            }
            // The row's class matches the slot we just built it for.
            let _ = self.report.set(*class, choice);
        }
        let detail = if landed.is_empty() {
            "no further tier".to_owned()
        } else {
            format!("demoted to {}", landed.join(","))
        };
        self.push_unsupported(name.clone(), classes, now_ms, &detail);
        tracing::warn!(
            collector = %name,
            failures = DEMOTE_AFTER,
            detail = %detail,
            "collector demoted after repeated failures"
        );
    }

    /// First supervised tier after `from` whose probe offers `class`.
    fn fallback_choice(
        &mut self,
        class: CapabilityClass,
        from: SourceTier,
    ) -> Option<CapabilityChoice> {
        let mut tier = from.next()?;
        loop {
            let found = self
                .slots
                .iter()
                .position(|slot| slot.collector.tier() == tier && slot.phase != SlotPhase::Demoted);
            if let Some(slot_index) = found {
                let answer = self.slots[slot_index].collector.probe(class);
                if answer.class == class && answer.is_available() {
                    let evidence = answer.evidence.clone();
                    let slot = &mut self.slots[slot_index];
                    if !slot.classes.contains(&class) {
                        slot.classes.push(class);
                    }
                    // An idle fallback starts being ticked now that it owns a class.
                    if slot.phase == SlotPhase::Idle {
                        slot.phase = SlotPhase::Running;
                    }
                    return Some(CapabilityChoice::from_tier(class, tier, evidence));
                }
            }
            tier = tier.next()?;
        }
    }

    fn push_unsupported(
        &mut self,
        name: String,
        classes: Vec<CapabilityClass>,
        now_ms: u64,
        detail: &str,
    ) {
        self.gaps.push(SupervisorGap {
            collector: name.clone(),
            kind: GapKind::Unsupported,
            evidence: Evidence::E1,
            affects: class_names(&classes),
            at_ms: now_ms,
            detail: format!("{name}: {detail}"),
        });
    }
}

fn class_index(class: CapabilityClass) -> usize {
    match class {
        CapabilityClass::Proc => 0,
        CapabilityClass::Net => 1,
        CapabilityClass::Dns => 2,
    }
}

fn class_names(classes: &[CapabilityClass]) -> Vec<String> {
    classes
        .iter()
        .map(|class| class.as_str().to_owned())
        .collect()
}

fn missing_row() -> SupervisorError {
    SupervisorError::Report(ReportError::SourceWithoutEvidence)
}

/// Short evidence label for a log line. `NA` is not given its reason: the reason
/// enum's `Debug` form is stable, but logging only the level keeps the line short.
fn evidence_label(evidence: &Evidence) -> &'static str {
    match evidence {
        Evidence::E1 => "E1",
        Evidence::E2 => "E2",
        Evidence::E3 => "E3",
        Evidence::S => "S",
        Evidence::I => "I",
        Evidence::NA(_) => "NA",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[derive(Debug)]
    struct Scripted {
        name: &'static str,
        tier: SourceTier,
        offers: Vec<CapabilityClass>,
        evidence: Evidence,
        /// `Some(n)` panics when `calls` reaches `n` (1-based).
        panic_on: Option<u32>,
        /// When true, every tick returns an error.
        fail: bool,
        calls: Cell<u32>,
        scope_updates: Cell<u32>,
        last_scope: Cell<bool>,
    }

    impl Scripted {
        fn native(name: &'static str, offers: Vec<CapabilityClass>) -> Self {
            Self::at(name, SourceTier::Native, offers, Evidence::E1)
        }

        fn poll(name: &'static str, offers: Vec<CapabilityClass>) -> Self {
            Self::at(name, SourceTier::Poll, offers, Evidence::S)
        }

        fn at(
            name: &'static str,
            tier: SourceTier,
            offers: Vec<CapabilityClass>,
            evidence: Evidence,
        ) -> Self {
            Self {
                name,
                tier,
                offers,
                evidence,
                panic_on: None,
                fail: false,
                calls: Cell::new(0),
                scope_updates: Cell::new(0),
                last_scope: Cell::new(false),
            }
        }

        fn failing(mut self) -> Self {
            self.fail = true;
            self
        }

        fn panic_on_call(mut self, n: u32) -> Self {
            self.panic_on = Some(n);
            self
        }
    }

    impl Supervised for Scripted {
        fn name(&self) -> &str {
            self.name
        }

        fn tier(&self) -> SourceTier {
            self.tier
        }

        fn probe(&self, class: CapabilityClass) -> ClassProbe {
            if self.offers.contains(&class) {
                ClassProbe::available(class, self.evidence.clone()).expect("test evidence")
            } else {
                ClassProbe::unavailable(class, NaReason::CollectorUnavailable)
            }
        }

        fn tick(&mut self) -> Result<(), TickError> {
            let n = self.calls.get().saturating_add(1);
            self.calls.set(n);
            if self.panic_on == Some(n) {
                panic!("scripted panic");
            }
            if self.fail {
                return Err(TickError::new("scripted failure"));
            }
            Ok(())
        }

        fn update_scope(&mut self, _scope: &Scope) {
            self.scope_updates
                .set(self.scope_updates.get().saturating_add(1));
            self.last_scope.set(true);
        }
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(next_delay_ms(0), 0);
        assert_eq!(next_delay_ms(1), 1_000);
        assert_eq!(next_delay_ms(2), 2_000);
        assert_eq!(next_delay_ms(3), 4_000);
        assert_eq!(next_delay_ms(4), 8_000);
        assert_eq!(next_delay_ms(5), 16_000);
        assert_eq!(next_delay_ms(6), 32_000);
        assert_eq!(next_delay_ms(7), 60_000);
        assert_eq!(next_delay_ms(30), 60_000);
    }

    #[test]
    fn probe_mixes_tiers_per_class() {
        let supervisor = Supervisor::start(vec![
            Scripted::poll("poll", vec![CapabilityClass::Proc, CapabilityClass::Net]),
            Scripted::native("native", vec![CapabilityClass::Proc, CapabilityClass::Dns]),
        ])
        .expect("start");

        let report = supervisor.report();
        assert_eq!(
            report.get(CapabilityClass::Proc).source_name(),
            Some("native")
        );
        assert_eq!(report.get(CapabilityClass::Proc).evidence, Evidence::E1);
        assert_eq!(
            report.get(CapabilityClass::Dns).source_name(),
            Some("native")
        );
        assert_eq!(report.get(CapabilityClass::Net).source_name(), Some("poll"));
        assert_eq!(report.get(CapabilityClass::Net).evidence, Evidence::S);
        // poll won NET only, so it is supervised. native won PROC and DNS.
        assert!(supervisor.collector("native").is_some());
        assert!(supervisor.collector("poll").is_some());
    }

    #[test]
    fn unavailable_class_uses_na_reason() {
        let supervisor = Supervisor::start(vec![Scripted::native(
            "native",
            vec![CapabilityClass::Proc],
        )])
        .expect("start");
        let net = supervisor.report().get(CapabilityClass::Net);
        assert!(net.source_name().is_none());
        assert_eq!(net.evidence, Evidence::NA(NaReason::CollectorUnavailable));
    }

    #[test]
    fn panic_on_third_call_records_one_restart_and_spares_the_other() {
        let mut supervisor = Supervisor::start(vec![
            Scripted::native("native", vec![CapabilityClass::Proc]).panic_on_call(3),
            Scripted::poll("poll", vec![CapabilityClass::Net, CapabilityClass::Dns]),
        ])
        .expect("start");

        // Calls 1 and 2 succeed. No sleep: the clock only moves when we say so.
        supervisor.step(0);
        supervisor.step(1);
        assert!(supervisor.gaps().is_empty());
        assert_eq!(supervisor.collector("poll").expect("poll").calls.get(), 2);

        // Third call panics. Exactly one Restart gap. poll still advanced.
        supervisor.step(2);
        let restarts: Vec<_> = supervisor
            .gaps()
            .iter()
            .filter(|gap| gap.kind == GapKind::Restart)
            .collect();
        assert_eq!(restarts.len(), 1);
        assert_eq!(restarts[0].collector, "native");
        assert_eq!(restarts[0].evidence, Evidence::E1);
        assert_eq!(restarts[0].affects, vec!["proc".to_owned()]);
        assert!(supervisor
            .gaps()
            .iter()
            .all(|gap| gap.kind != GapKind::Unsupported));
        assert_eq!(supervisor.collector("poll").expect("poll").calls.get(), 3);
        assert_eq!(
            supervisor.collector("native").expect("native").calls.get(),
            3
        );

        // Backoff for attempt 1 is 1000 ms. A step before that must not tick native.
        supervisor.step(2 + 999);
        assert_eq!(
            supervisor.collector("native").expect("native").calls.get(),
            3
        );
        assert_eq!(supervisor.collector("poll").expect("poll").calls.get(), 4);

        supervisor.step(2 + 1_000);
        assert_eq!(
            supervisor.collector("native").expect("native").calls.get(),
            4
        );
        assert_eq!(supervisor.gaps().len(), 1);
    }

    #[test]
    fn five_failures_demote_net_to_poll_at_s() {
        let mut supervisor = Supervisor::start(vec![
            Scripted::native("native", vec![CapabilityClass::Net]).failing(),
            Scripted::native(
                "proc-native",
                vec![CapabilityClass::Proc, CapabilityClass::Dns],
            ),
            // Not chosen at start: native already covers NET. Demotion must
            // find this probe and take its evidence (S), not invent a level.
            Scripted::poll("poll", vec![CapabilityClass::Net]),
        ])
        .expect("start");

        assert_eq!(
            supervisor.report().get(CapabilityClass::Net).source_name(),
            Some("native")
        );
        assert_eq!(
            supervisor.report().get(CapabilityClass::Net).evidence,
            Evidence::E1
        );

        // Each failure arms a longer backoff. Drive the virtual clock to each deadline.
        let mut now = 0_u64;
        for _ in 0..DEMOTE_AFTER {
            supervisor.step(now);
            // After a non-demoting failure the next tick is `next_delay_ms` later.
            // After the fifth, the slot is demoted and the delay no longer matters.
            let restarts = supervisor
                .gaps()
                .iter()
                .filter(|gap| gap.kind == GapKind::Restart && gap.collector == "native")
                .count();
            if restarts < DEMOTE_AFTER as usize {
                now = now.saturating_add(next_delay_ms(restarts as u32));
            }
        }

        let restarts = supervisor
            .gaps()
            .iter()
            .filter(|gap| gap.kind == GapKind::Restart && gap.collector == "native")
            .count();
        assert_eq!(restarts, DEMOTE_AFTER as usize);
        let unsupported: Vec<_> = supervisor
            .gaps()
            .iter()
            .filter(|gap| gap.kind == GapKind::Unsupported)
            .collect();
        assert_eq!(unsupported.len(), 1);
        assert_eq!(unsupported[0].collector, "native");
        assert_eq!(unsupported[0].evidence, Evidence::E1);
        assert_eq!(unsupported[0].affects, vec!["net".to_owned()]);

        let net = supervisor.report().get(CapabilityClass::Net);
        assert_eq!(net.source_name(), Some("poll"));
        assert_eq!(net.evidence, Evidence::S);

        // The other collector never failed and was not demoted.
        assert_eq!(
            supervisor.report().get(CapabilityClass::Proc).source_name(),
            Some("native")
        );
        assert_eq!(
            supervisor.report().get(CapabilityClass::Proc).evidence,
            Evidence::E1
        );
        assert!(supervisor
            .gaps()
            .iter()
            .all(|gap| gap.collector != "proc-native"));

        // Further time does not tick the demoted collector or add another gap.
        let gaps_before = supervisor.gaps().len();
        let calls_before = supervisor.collector("native").expect("native").calls.get();
        supervisor.step(now.saturating_add(1_000_000));
        assert_eq!(
            supervisor.collector("native").expect("native").calls.get(),
            calls_before
        );
        assert_eq!(supervisor.gaps().len(), gaps_before);
    }

    #[test]
    fn update_scope_reaches_each_collector() {
        let mut supervisor = Supervisor::start(vec![
            Scripted::native("native", vec![CapabilityClass::Proc, CapabilityClass::Dns]),
            Scripted::poll("poll", vec![CapabilityClass::Net]),
        ])
        .expect("start");
        let scope = Scope::launch("job-1").expect("token");
        supervisor.update_scope(&scope);
        assert_eq!(
            supervisor
                .collector("native")
                .expect("native")
                .scope_updates
                .get(),
            1
        );
        assert_eq!(
            supervisor
                .collector("poll")
                .expect("poll")
                .scope_updates
                .get(),
            1
        );
        assert!(supervisor.scope().is_some());
    }

    #[test]
    fn error_and_panic_use_the_same_backoff() {
        let mut supervisor = Supervisor::start(vec![Scripted::native(
            "native",
            vec![
                CapabilityClass::Proc,
                CapabilityClass::Net,
                CapabilityClass::Dns,
            ],
        )
        .failing()])
        .expect("start");
        supervisor.step(0);
        supervisor.step(500);
        assert_eq!(
            supervisor.collector("native").expect("native").calls.get(),
            1
        );
        supervisor.step(1_000);
        assert_eq!(
            supervisor.collector("native").expect("native").calls.get(),
            2
        );
        assert_eq!(
            supervisor
                .gaps()
                .iter()
                .filter(|gap| gap.kind == GapKind::Restart)
                .count(),
            2
        );
    }
}
