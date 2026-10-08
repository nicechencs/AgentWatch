//! CPU budget for the eslogger `open` subscription.
//!
//! macos.md §1.1: a full-system `open` stream can pass the CPU budget. When the
//! eslogger child and the parse thread together stay over the threshold, the
//! collector drops `open` and keeps `close`, `create`, `unlink`, `rename`.
//! The drop is a `Gap { rate_limited }`, not a silent change of subscription.
//!
//! This module does not read a process table and does not spawn anything. The
//! caller supplies a usage sample (percent of one core, 0–100) and a monotonic
//! timestamp. A missing sample is not treated as zero: the caller simply does
//! not call [`OpenBudget::observe`].

use aw_core::{
    Capability, EventKind, Evidence, Gap, GapKind, NaReason, RawEvent, RawEventParts, Source,
};

use super::decode::{EsEvent, LineDecoder};
use super::file::FileSubscription;

/// Default ceiling, in percent of one core, for the eslogger child plus the
/// parse thread. P2-MAC-02 names 5%.
pub const DEFAULT_CPU_PERCENT: u8 = 5;

/// How long usage must stay over the ceiling before `open` is dropped.
/// P2-MAC-02 names 30 seconds.
pub const DEFAULT_SUSTAIN: std::time::Duration = std::time::Duration::from_secs(30);

/// `collectors.macos.subscribe_open`.
///
/// `Auto` is the default: subscribe, then drop `open` if the budget trips.
/// `On` never drops it. `Off` never subscribes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubscribeOpen {
    /// Subscribe, and unsubscribe when [`OpenBudget`] trips.
    #[default]
    Auto,
    /// Always subscribe. High CPU is reported and does not change the set.
    On,
    /// Never subscribe. `close` / `create` / `unlink` / `rename` still run.
    Off,
}

impl SubscribeOpen {
    /// Parse `auto`, `on`, or `off`. Anything else is `None` — not `Auto`.
    /// A typo must not silently enable the expensive subscription.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "auto" => Some(Self::Auto),
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
            _ => None,
        }
    }

    /// Wire name. Matches the configuration values.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

/// What one usage sample did to the subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetDecision {
    /// Still inside the budget, or the overage has not lasted `sustain` yet.
    Hold,
    /// `open` was just removed. The caller emits the gap from
    /// [`OpenBudget::take_gap`].
    Unsubscribed,
    /// This sample does not change the subscription. Mode is `On` or `Off`,
    /// or `open` was already removed. No second gap.
    Unchanged,
}

/// Tracks whether `open` stays subscribed.
///
/// The clock is the caller's monotonic nanoseconds, the same domain as
/// `RawEvent::ts_mono_ns`. This type has no `Instant` of its own, so a test
/// can step the clock without sleeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenBudget {
    mode: SubscribeOpen,
    /// Ceiling in percent of one core.
    cpu_percent: u8,
    /// Overage must last at least this long.
    sustain_ns: u64,
    /// When the current over-budget run started. `None` while usage is at or
    /// under the ceiling, and while no sample has arrived.
    over_since_ns: Option<u64>,
    /// Live subscription. `open` starts set unless the mode is `Off`.
    subscription: FileSubscription,
    /// One pending unsubscribe gap. Set on the transition, cleared by
    /// [`Self::take_gap`], so a second call does not emit a second gap.
    gap_pending: bool,
}

impl OpenBudget {
    /// Budget for `mode` at the default ceiling (5% for 30 s) and the default
    /// file subscription.
    pub fn new(mode: SubscribeOpen) -> Self {
        Self::with_threshold(mode, DEFAULT_CPU_PERCENT, DEFAULT_SUSTAIN)
    }

    /// Budget with an explicit ceiling.
    ///
    /// `cpu_percent` above 100 is clamped to 100. A threshold of 0 means
    /// "any non-zero sample is over", which is a real configuration a test
    /// can ask for; it is not used as "unknown".
    pub fn with_threshold(
        mode: SubscribeOpen,
        cpu_percent: u8,
        sustain: std::time::Duration,
    ) -> Self {
        let mut subscription = FileSubscription::macos_default();
        if mode == SubscribeOpen::Off {
            subscription.open = false;
        }
        Self {
            mode,
            cpu_percent: cpu_percent.min(100),
            sustain_ns: u64::try_from(sustain.as_nanos()).unwrap_or(u64::MAX),
            over_since_ns: None,
            subscription,
            gap_pending: false,
        }
    }

    /// Configuration mode. Does not change after construction.
    pub const fn mode(&self) -> SubscribeOpen {
        self.mode
    }

    /// Subscription eslogger should be running with right now.
    pub const fn subscription(&self) -> FileSubscription {
        self.subscription
    }

    /// `true` once `open` has been turned off, either by config or by a trip.
    pub const fn open_unsubscribed(&self) -> bool {
        !self.subscription.open
    }

    /// Note one CPU sample.
    ///
    /// `cpu_percent` is the combined usage of the eslogger child and the parse
    /// thread, in percent of one core. `now_mono_ns` must come from the same
    /// clock as the previous call. A clock that goes backwards clears the
    /// over-budget run instead of inventing a duration.
    ///
    /// `On` never unsubscribes. `Off` is already unsubscribed. `Auto` drops
    /// `open` on the first sample that is still over the ceiling `sustain`
    /// after the run started.
    pub fn observe(&mut self, cpu_percent: u8, now_mono_ns: u64) -> BudgetDecision {
        if self.mode != SubscribeOpen::Auto || !self.subscription.open {
            return BudgetDecision::Unchanged;
        }
        if cpu_percent <= self.cpu_percent {
            self.over_since_ns = None;
            return BudgetDecision::Hold;
        }
        let started = match self.over_since_ns {
            Some(started) if now_mono_ns >= started => started,
            _ => {
                // First sample of this run, or the clock moved backwards.
                // The duration is not yet known, so this sample does not trip.
                self.over_since_ns = Some(now_mono_ns);
                return BudgetDecision::Hold;
            }
        };
        let elapsed = now_mono_ns.saturating_sub(started);
        if elapsed < self.sustain_ns {
            return BudgetDecision::Hold;
        }
        self.subscription.open = false;
        self.gap_pending = true;
        self.over_since_ns = None;
        BudgetDecision::Unsubscribed
    }

    /// The gap for a trip, built on `decoder` so its sequence stays in line
    /// with file events.
    ///
    /// Returns `Some` once, on the call after [`BudgetDecision::Unsubscribed`].
    /// A later call returns `None`. Calling it without a trip also returns
    /// `None`: `Off` never subscribed, and `On` never trips, so neither invents
    /// a rate-limit gap.
    pub fn take_gap(
        &mut self,
        decoder: &mut LineDecoder,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
    ) -> Option<EsEvent> {
        if !self.gap_pending {
            return None;
        }
        self.gap_pending = false;
        Some(unsubscribe_gap(decoder, ts_mono_ns, ts_wall_ns))
    }

    /// File capability for `aw doctor` and the gap page.
    ///
    /// The category stays [`Evidence::E1`]: open, close, create, unlink, rename,
    /// and truncate are real events. CAP-FILE-02 (read counts and byte counts)
    /// is `NA(es_no_read_event)`, carried in the note rather than as the
    /// category evidence. Marking the whole category `NA` would hide the events
    /// that were actually observed. `CapabilitySet` has no per-CAP slot, and
    /// this crate cannot change `aw-core` to add one.
    pub fn capabilities(&self) -> Capability {
        let cap = Capability::available(Evidence::E1)
            .unwrap_or_else(|_| Capability::unavailable(NaReason::EsNoReadEvent));
        cap.with_note(self.capability_note())
    }

    fn capability_note(&self) -> String {
        let mut note = String::from(
            "CAP-FILE-02 is NA(es_no_read_event): Endpoint Security has no per-read event, so bytes_read and reads are unavailable",
        );
        if self.open_unsubscribed() {
            note.push_str("; open is not subscribed");
        }
        note
    }
}

/// `Gap { kind: rate_limited, detail: "eslogger open unsubscribed" }`.
///
/// Detail text is fixed by P2-MAC-02. It names the subscription change and
/// carries no path, pid, or user name.
pub fn unsubscribe_gap(decoder: &mut LineDecoder, ts_mono_ns: u64, ts_wall_ns: i64) -> EsEvent {
    let seq = decoder.alloc_seq();
    let source = Source::new("macos.eslogger/open");
    let gap = Gap::new(
        source.clone(),
        GapKind::RateLimited,
        vec!["file".to_owned()],
        ts_mono_ns,
        ts_mono_ns,
        None,
        Some("eslogger open unsubscribed".to_owned()),
    );
    let event = match RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns,
        ts_wall_ns,
        session_id: None,
        proc: None,
        source,
        evidence: Evidence::E1,
        kind: EventKind::Gap(gap),
    }) {
        Ok(event) => event,
        Err(_) => RawEvent {
            v: aw_core::SCHEMA_VERSION,
            seq,
            ts_mono_ns,
            ts_wall_ns,
            session_id: None,
            proc: None,
            source: Source::new("macos.eslogger/open"),
            evidence: Evidence::E1,
            field_evidence: std::collections::BTreeMap::new(),
            kind: EventKind::Gap(Gap::new(
                Source::new("macos.eslogger/open"),
                GapKind::RateLimited,
                vec!["file".to_owned()],
                ts_mono_ns,
                ts_mono_ns,
                None,
                Some("eslogger open unsubscribed".to_owned()),
            )),
        },
    };
    EsEvent {
        event: Some(event),
        exe: None,
        argv: None,
        cwd: None,
        how: None,
        ppid: None,
        start_time_ns: None,
        es_version: None,
        responsible: None,
        subject_pid: None,
        exit_stat: None,
    }
}

/// Apply `mode` to a subscription that was built some other way.
///
/// `Off` clears `open`. `On` and `Auto` leave it as the caller set it; `Auto`
/// then moves under an [`OpenBudget`].
pub fn apply_subscribe_open(
    mut subscription: FileSubscription,
    mode: SubscribeOpen,
) -> FileSubscription {
    if mode == SubscribeOpen::Off {
        subscription.open = false;
    }
    subscription
}
