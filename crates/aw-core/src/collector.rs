//! Collector contract: how a daemon starts, scopes, and stops a source of [`RawEvent`]s.
//!
//! This module declares the trait and the capability report. It does not talk to
//! ETW, eBPF, Endpoint Security, or any other platform API, and it does not depend
//! on a runtime. A concrete collector lives in its own crate and only implements
//! [`Collector`].
//!
//! [`MockCollector`] replays events the caller already built. It does not open
//! fixture files. Evidence already stamped on each [`RawEvent`] is forwarded
//! unchanged; this module never promotes a level.

#![deny(missing_docs)]

use std::fmt;

use crate::{
    EventKind, Evidence, Gap, GapKind, NaReason, ProcUid, RawEvent, RawEventParts, Source,
    SCHEMA_VERSION,
};

/// One observation category a collector may or may not be able to produce.
///
/// The set is the rows `aw doctor` and the UI need before a session starts.
/// It is not a second event taxonomy: each category still maps onto existing
/// [`EventKind`] variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapabilityCategory {
    /// Process start and exit, including parent identity when the platform has it.
    Proc,
    /// File open, read, write, close, create, delete, and rename.
    File,
    /// Connect, send, recv, and close. Not URLs.
    Net,
    /// DNS questions and answers.
    Dns,
    /// URL or HTTP metadata. Usually [`Evidence::NA`] unless a proxy is in scope.
    Url,
    /// Whether the collector can restrict observation to a [`Scope`] at the source.
    Scope,
}

impl CapabilityCategory {
    /// Stable snake_case name used in diagnostics. Not a JSON schema tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proc => "proc",
            Self::File => "file",
            Self::Net => "net",
            Self::Dns => "dns",
            Self::Url => "url",
            Self::Scope => "scope",
        }
    }
}

impl fmt::Display for CapabilityCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one category can contribute, expressed with the shared [`Evidence`] enum.
///
/// [`Evidence::NA`] is the only way to say "not available", and it already carries
/// a [`NaReason`]. A collector must not substitute `0`, an empty string, or a
/// higher evidence level for a category it cannot observe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// Highest evidence this collector will stamp on events of the category.
    pub evidence: Evidence,
    /// Short note for `aw doctor`. Must not contain argv, environment values,
    /// URLs, or headers. `None` when [`evidence`](Self::evidence) already says enough.
    pub note: Option<String>,
}

impl Capability {
    /// Category is observable at `evidence`. `evidence` must not be [`Evidence::NA`].
    ///
    /// Returns [`ScopeError::NaWithoutReason`] when the caller passes `NA`, because
    /// availability and unavailability are different constructors.
    pub fn available(evidence: Evidence) -> Result<Self, ScopeError> {
        if evidence.is_na() {
            return Err(ScopeError::NaWithoutReason);
        }
        Ok(Self {
            evidence,
            note: None,
        })
    }

    /// Category cannot be observed. `reason` is stored inside [`Evidence::NA`].
    pub fn unavailable(reason: NaReason) -> Self {
        Self {
            evidence: Evidence::NA(reason),
            note: None,
        }
    }

    /// Attach a doctor-facing note. The note must not carry secrets; this type
    /// does not scan it.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// Declared evidence for every [`CapabilityCategory`].
///
/// A set is complete: every category is present. Categories the collector cannot
/// see are [`Evidence::NA`], never omitted. [`CapabilitySet::ALL`] lists the
/// categories in display order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySet {
    proc: Capability,
    file: Capability,
    net: Capability,
    dns: Capability,
    url: Capability,
    scope: Capability,
}

impl CapabilitySet {
    /// Every category, in the order `aw doctor` prints them.
    pub const ALL: [CapabilityCategory; 6] = [
        CapabilityCategory::Proc,
        CapabilityCategory::File,
        CapabilityCategory::Net,
        CapabilityCategory::Dns,
        CapabilityCategory::Url,
        CapabilityCategory::Scope,
    ];

    /// Build a set. Every category is required so a caller cannot forget `NA`.
    pub fn new(
        proc: Capability,
        file: Capability,
        net: Capability,
        dns: Capability,
        url: Capability,
        scope: Capability,
    ) -> Self {
        Self {
            proc,
            file,
            net,
            dns,
            url,
            scope,
        }
    }

    /// Same evidence for every category. Use this only when that is actually true.
    /// Passing [`Evidence::NA`] fails: an unavailable set still needs a [`NaReason`] per call.
    pub fn uniform(evidence: Evidence) -> Result<Self, ScopeError> {
        Ok(Self {
            proc: Capability::available(evidence.clone())?,
            file: Capability::available(evidence.clone())?,
            net: Capability::available(evidence.clone())?,
            dns: Capability::available(evidence.clone())?,
            url: Capability::available(evidence.clone())?,
            scope: Capability::available(evidence)?,
        })
    }

    /// Every category is [`Evidence::NA`] with the same reason.
    pub fn all_unavailable(reason: NaReason) -> Self {
        Self {
            proc: Capability::unavailable(reason.clone()),
            file: Capability::unavailable(reason.clone()),
            net: Capability::unavailable(reason.clone()),
            dns: Capability::unavailable(reason.clone()),
            url: Capability::unavailable(reason.clone()),
            scope: Capability::unavailable(reason),
        }
    }

    /// Evidence declared for `category`.
    pub fn get(&self, category: CapabilityCategory) -> &Capability {
        match category {
            CapabilityCategory::Proc => &self.proc,
            CapabilityCategory::File => &self.file,
            CapabilityCategory::Net => &self.net,
            CapabilityCategory::Dns => &self.dns,
            CapabilityCategory::Url => &self.url,
            CapabilityCategory::Scope => &self.scope,
        }
    }
}

/// Opaque token a collector interprets as "processes I launched".
///
/// This is not an OS handle. The daemon stores whatever the platform collector
/// asked it to remember (a job name, a cgroup path, an endpoint-security client
/// id) as text. `aw-core` does not open it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LaunchToken(String);

impl LaunchToken {
    /// Wrap a non-empty token.
    ///
    /// Empty is rejected. An empty string must not stand in for "no token".
    pub fn new(token: impl Into<String>) -> Result<Self, ScopeError> {
        let token = token.into();
        if token.is_empty() {
            return Err(ScopeError::EmptyLaunchToken);
        }
        Ok(Self(token))
    }

    /// Borrow the token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LaunchToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Who the collector should watch.
///
/// Launch mode hands the collector a [`LaunchToken`] it already understands.
/// Attach mode names the root processes by [`ProcUid`]. Both modes live in one
/// enum so a collector cannot be started with neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Watch the tree the collector itself started. The token is opaque here.
    Launch {
        /// Platform-specific identity of the launched tree. Not an OS handle.
        token: LaunchToken,
    },
    /// Watch trees rooted at these already-running processes.
    Attach {
        /// Root process identities. Duplicate [`ProcUid`]s are collapsed; order is kept.
        roots: Vec<ProcUid>,
    },
}

impl Scope {
    /// Launch scope. `token` must be non-empty.
    pub fn launch(token: impl Into<String>) -> Result<Self, ScopeError> {
        Ok(Self::Launch {
            token: LaunchToken::new(token)?,
        })
    }

    /// Attach scope. An empty root set is rejected: "attach to nobody" is not a scope.
    ///
    /// Duplicate [`ProcUid`]s are kept once, in first-seen order. [`ProcUid`] is not
    /// ordered, so this is a linear dedupe rather than a sorted set.
    pub fn attach(roots: impl IntoIterator<Item = ProcUid>) -> Result<Self, ScopeError> {
        let mut unique = Vec::new();
        for uid in roots {
            if !unique.contains(&uid) {
                unique.push(uid);
            }
        }
        if unique.is_empty() {
            return Err(ScopeError::EmptyAttach);
        }
        Ok(Self::Attach { roots: unique })
    }

    /// Roots in attach mode. Launch mode has no roots and returns an empty slice.
    ///
    /// An empty slice here means "this is a launch scope", not "the roots are unknown".
    pub fn roots(&self) -> &[ProcUid] {
        match self {
            Self::Launch { .. } => &[],
            Self::Attach { roots } => roots,
        }
    }
}

/// Why a [`Scope`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// [`LaunchToken::new`] was given an empty string.
    EmptyLaunchToken,
    /// [`Scope::attach`] was given no root [`ProcUid`].
    EmptyAttach,
    /// [`Capability::available`] was given [`Evidence::NA`]. Use [`Capability::unavailable`].
    NaWithoutReason,
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLaunchToken => {
                f.write_str("launch token is empty; an empty string is not a handle")
            }
            Self::EmptyAttach => f.write_str("attach scope has no root ProcUid"),
            Self::NaWithoutReason => f.write_str(
                "Evidence::NA is not an available capability; use Capability::unavailable",
            ),
        }
    }
}

impl std::error::Error for ScopeError {}

/// Failure to accept one [`RawEvent`].
///
/// A full buffer is [`SinkError::Full`]. The event is returned to the caller so
/// it can be counted or turned into a [`Gap`]. Dropping it inside the sink is
/// not an option this error allows: the event is still in the `Full` variant.
#[derive(Debug)]
pub enum SinkError {
    /// The sink refused the event because its buffer is at capacity.
    ///
    /// `event` is the value that was not stored. The collector must not discard
    /// it. The usual response is to surface a [`GapKind::Dropped`] gap (or return
    /// this error and let the caller record the gap). Capacity is the sink's
    /// own bound; this crate does not pick a number.
    Full {
        /// The event the sink did not accept.
        ///
        /// Boxed so [`SinkError`] stays small enough to return from [`EventSink::emit`].
        /// The event is still owned by the caller; boxing is not a drop.
        event: Box<RawEvent>,
    },
    /// The sink is closed and will not take further events.
    Closed,
    /// A collector-defined failure. `message` must not contain argv, environment
    /// values, URLs, or header values.
    Other {
        /// Redacted diagnostic. No secrets.
        message: String,
    },
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full { event } => write!(
                f,
                "event sink is full (seq {}, kind {}); event was not dropped, it was returned",
                event.seq,
                event.kind.kind_name()
            ),
            Self::Closed => f.write_str("event sink is closed"),
            Self::Other { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for SinkError {}

/// Consumer of [`RawEvent`]s.
///
/// The collector pushes; it does not own a channel. A bounded queue implements
/// this trait and returns [`SinkError::Full`] when it cannot accept another
/// event. That return is the opposite of a silent drop: the event comes back
/// inside the error, and a later stage records a [`Gap`].
///
/// Implementations must not raise the evidence on an event they accept.
pub trait EventSink {
    /// Accept `event`, or return it inside [`SinkError::Full`] when the buffer is full.
    ///
    /// # Errors
    ///
    /// [`SinkError::Full`] when the bounded buffer cannot take another event.
    /// [`SinkError::Closed`] when the consumer has stopped. [`SinkError::Other`]
    /// for a collector-defined failure whose message contains no secrets.
    fn emit(&mut self, event: RawEvent) -> Result<(), SinkError>;
}

impl<T: EventSink + ?Sized> EventSink for &mut T {
    fn emit(&mut self, event: RawEvent) -> Result<(), SinkError> {
        (*self).emit(event)
    }
}

/// In-memory sink that stores every accepted event and fails when `capacity` is hit.
///
/// `capacity` is a bound, not a drop policy. The event that does not fit is
/// returned in [`SinkError::Full`].
#[derive(Debug, Clone, PartialEq)]
pub struct VecSink {
    capacity: usize,
    events: Vec<RawEvent>,
    /// How many non-gap events may be stored. `None` means the whole capacity.
    /// A gap may still use a slot this limit left free.
    ordinary_limit: Option<usize>,
}

impl VecSink {
    /// Sink that holds at most `capacity` events. Zero is a valid bound: the first
    /// `emit` returns [`SinkError::Full`] and stores nothing.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity,
            events: Vec::new(),
            ordinary_limit: None,
        }
    }

    /// Cap non-gap events at `limit`, leaving any remaining capacity for a gap.
    ///
    /// `limit` greater than `capacity` is clamped. This does not drop events:
    /// a non-gap event past the cap is returned as [`SinkError::Full`].
    pub fn hold_ordinary(&mut self, limit: usize) {
        self.ordinary_limit = Some(limit.min(self.capacity));
    }

    /// Events accepted so far, in emit order.
    pub fn events(&self) -> &[RawEvent] {
        &self.events
    }

    /// How many more events fit before [`SinkError::Full`].
    pub fn remaining(&self) -> usize {
        self.capacity.saturating_sub(self.events.len())
    }
}

impl EventSink for VecSink {
    fn emit(&mut self, event: RawEvent) -> Result<(), SinkError> {
        let is_gap = matches!(event.kind, EventKind::Gap(_));
        let ordinary = match self.ordinary_limit {
            Some(limit) => limit.min(self.capacity),
            None => self.capacity,
        };
        let limit = if is_gap { self.capacity } else { ordinary };
        if self.events.len() >= limit {
            return Err(SinkError::Full {
                event: Box::new(event),
            });
        }
        self.events.push(event);
        Ok(())
    }
}

/// Failure while starting, updating, or stopping a collector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectorError {
    /// [`Collector::start`] was called while the collector was already running.
    AlreadyRunning,
    /// [`Collector::update_scope`] or [`Collector::stop`] was called while it was stopped.
    NotRunning,
    /// The sink rejected an event and the collector could not turn the rejection
    /// into a delivered [`Gap`]. `undelivered` is how many events (including a
    /// gap the sink also refused) did not reach the sink. Nothing in that count
    /// was discarded without being reported here.
    Sink {
        /// Sink failure, without the raw event payload (that payload may hold secrets).
        kind: SinkFailureKind,
        /// Events that did not reach the sink, including a gap the sink also refused.
        undelivered: u64,
    },
}

/// Sink failure classified without copying event payloads into a `Result`.
///
/// [`SinkError::Full`] carries the [`RawEvent`] so a caller can retry it. Once a
/// collector gives up on that retry it records only this kind plus a count, so
/// argv and URLs inside the event do not land in an error string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkFailureKind {
    /// The sink's bounded buffer was full.
    Full,
    /// The sink was closed.
    Closed,
    /// [`SinkError::Other`]. The message is intentionally not stored.
    Other,
}

impl SinkFailureKind {
    fn from_sink(err: &SinkError) -> Self {
        match err {
            SinkError::Full { .. } => Self::Full,
            SinkError::Closed => Self::Closed,
            SinkError::Other { .. } => Self::Other,
        }
    }
}

impl fmt::Display for CollectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning => f.write_str("collector is already running"),
            Self::NotRunning => f.write_str("collector is not running"),
            Self::Sink {
                kind,
                undelivered,
            } => write!(
                f,
                "sink rejected events ({kind:?}); {undelivered} were not delivered and were not silently dropped"
            ),
        }
    }
}

impl std::error::Error for CollectorError {}

/// Point-in-time status for `aw doctor` and the daemon supervisor.
///
/// `last_error` is a short diagnostic. It must not contain argv, environment
/// values, URLs, or header values. Collectors copy from [`CollectorError`]'s
/// `Display` (which omits event payloads) rather than from [`RawEvent`]'s `Debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    /// `true` after a successful `start` until `stop`.
    pub running: bool,
    /// Last start, scope, or stop failure. `None` if the last operation succeeded.
    ///
    /// The string must not contain argv, environment values, URLs, or headers.
    pub last_error: Option<String>,
    /// Events the collector knows it did not deliver, plus gaps it emitted for
    /// those losses. A silent drop is not representable: every increment here
    /// corresponds to a [`Gap`] the sink accepted, or to a [`CollectorError::Sink`]
    /// when even the gap could not be delivered.
    pub undelivered: u64,
}

impl Health {
    /// Stopped, no error, nothing undelivered.
    pub const fn idle() -> Self {
        Self {
            running: false,
            last_error: None,
            undelivered: 0,
        }
    }
}

/// Platform-independent source of [`RawEvent`]s.
///
/// `start` borrows the sink for the call. A live collector that pushes from
/// another thread is a platform concern: it owns its own queue and still ends
/// at some [`EventSink`]. This trait does not take a tokio channel.
///
/// `update_scope` replaces the filter. A collector that cannot filter at the
/// source still accepts the scope and reports the limitation through
/// [`CapabilityCategory::Scope`] (typically [`Evidence::NA`]), rather than
/// pretending the filter was applied.
pub trait Collector {
    /// Stable name, for example `"mock.replay"`. Used as the collector half of
    /// [`crate::Source`] (`"<name>/<probe>"`). Not a display sentence.
    fn name(&self) -> &str;

    /// Evidence this collector will actually produce. Not a claim that every
    /// category is visible.
    fn capabilities(&self) -> &CapabilitySet;

    /// Begin emitting into `sink` for `scope`.
    ///
    /// # Errors
    ///
    /// [`CollectorError::AlreadyRunning`] if a previous start was not stopped.
    /// [`CollectorError::Sink`] if the sink refuses an event and the collector
    /// cannot deliver a replacement [`Gap`] either. The refused event is not dropped.
    fn start(&mut self, scope: &Scope, sink: &mut dyn EventSink) -> Result<(), CollectorError>;

    /// Replace the active scope. Events already emitted stay emitted.
    ///
    /// # Errors
    ///
    /// [`CollectorError::NotRunning`] if `start` has not succeeded.
    fn update_scope(&mut self, scope: &Scope) -> Result<(), CollectorError>;

    /// Stop emitting. A second `stop` is [`CollectorError::NotRunning`].
    ///
    /// # Errors
    ///
    /// [`CollectorError::NotRunning`] if the collector is already stopped.
    fn stop(&mut self) -> Result<(), CollectorError>;

    /// Supervisor view. See [`Health`] for the secret-handling rule on `last_error`.
    fn health(&self) -> Health;
}

/// Replays a fixed list of [`RawEvent`]s into an [`EventSink`].
///
/// The caller supplies the events. This type does not read fixtures. Each event
/// is forwarded with the evidence it already carries.
///
/// If the sink returns [`SinkError::Full`] or another error, the mock does not
/// drop the remainder. It tries once to emit a [`GapKind::Dropped`] gap for the
/// events still held (the rejected one plus everything not yet sent). If that
/// gap is itself refused, `start` returns [`CollectorError::Sink`] and
/// [`Health::undelivered`] counts them. Either way the loss is visible.
#[derive(Debug, Clone)]
pub struct MockCollector {
    name: String,
    capabilities: CapabilitySet,
    pending: Vec<RawEvent>,
    scope: Option<Scope>,
    running: bool,
    last_error: Option<String>,
    undelivered: u64,
}

impl MockCollector {
    /// Collector named `name` that will emit `events` on the next successful [`Collector::start`].
    ///
    /// `capabilities` is whatever the test declared. The mock does not invent a
    /// "sees everything" set.
    pub fn new(
        name: impl Into<String>,
        capabilities: CapabilitySet,
        events: impl IntoIterator<Item = RawEvent>,
    ) -> Self {
        Self {
            name: name.into(),
            capabilities,
            pending: events.into_iter().collect(),
            scope: None,
            running: false,
            last_error: None,
            undelivered: 0,
        }
    }

    /// Scope from the last successful `start` or `update_scope`.
    pub fn scope(&self) -> Option<&Scope> {
        self.scope.as_ref()
    }

    /// Events not yet delivered. After a clean `start` this is empty.
    pub fn pending(&self) -> &[RawEvent] {
        &self.pending
    }
}

impl Collector for MockCollector {
    fn name(&self) -> &str {
        &self.name
    }

    fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    fn start(&mut self, scope: &Scope, sink: &mut dyn EventSink) -> Result<(), CollectorError> {
        if self.running {
            let err = CollectorError::AlreadyRunning;
            self.last_error = Some(err.to_string());
            return Err(err);
        }
        self.scope = Some(scope.clone());
        self.running = true;
        self.last_error = None;

        let mut rest = std::mem::take(&mut self.pending);
        while !rest.is_empty() {
            let event = rest.remove(0);
            if let Err(err) = sink.emit(event) {
                let lost = (rest.len() as u64).saturating_add(1);
                return self.report_undelivered(sink, lost, &err);
            }
        }
        Ok(())
    }

    fn update_scope(&mut self, scope: &Scope) -> Result<(), CollectorError> {
        if !self.running {
            let err = CollectorError::NotRunning;
            self.last_error = Some(err.to_string());
            return Err(err);
        }
        self.scope = Some(scope.clone());
        self.last_error = None;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), CollectorError> {
        if !self.running {
            let err = CollectorError::NotRunning;
            self.last_error = Some(err.to_string());
            return Err(err);
        }
        self.running = false;
        self.last_error = None;
        Ok(())
    }

    fn health(&self) -> Health {
        Health {
            running: self.running,
            last_error: self.last_error.clone(),
            undelivered: self.undelivered,
        }
    }
}

impl MockCollector {
    /// Surface `lost` replayed events the sink did not accept.
    ///
    /// One [`GapKind::Dropped`] gap is tried. If the sink accepts it, `start`
    /// succeeds and [`Health::undelivered`] is `lost`. If it refuses the gap too,
    /// `start` returns [`CollectorError::Sink`] and the count includes the gap.
    /// Either path accounts for every event `emit` already consumed.
    fn report_undelivered(
        &mut self,
        sink: &mut dyn EventSink,
        lost: u64,
        cause: &SinkError,
    ) -> Result<(), CollectorError> {
        let kind = SinkFailureKind::from_sink(cause);
        let gap = gap_for_undelivered(&self.name, lost);
        match sink.emit(gap) {
            Ok(()) => {
                self.undelivered = self.undelivered.saturating_add(lost);
                self.pending.clear();
                Ok(())
            }
            Err(_) => {
                // The gap itself did not land. Count it with the lost events.
                let undelivered = lost.saturating_add(1);
                self.undelivered = self.undelivered.saturating_add(undelivered);
                self.pending.clear();
                let err = CollectorError::Sink { kind, undelivered };
                self.last_error = Some(err.to_string());
                Err(err)
            }
        }
    }
}

/// A [`GapKind::Dropped`] event for `count` replayed events the sink refused.
///
/// `seq` and both timestamps are `0` because this gap is synthesized by the mock,
/// which has no clock of its own. That is a real zero, not a stand-in for unknown:
/// the loss count is [`Gap::count`], and "when" is "during this `start` call".
/// [`RawEvent::try_new`] cannot fail for [`EventKind::Gap`] (no required `None`),
/// so a construction error is itself reported as a second gap rather than a panic
/// or a dropped count.
fn gap_for_undelivered(collector_name: &str, count: u64) -> RawEvent {
    let source = Source::new(format!("{collector_name}/replay"));
    let gap = Gap::new(
        source.clone(),
        GapKind::Dropped,
        vec!["collector".to_owned()],
        0,
        0,
        Some(count),
        Some("sink rejected events; they were not delivered".to_owned()),
    );
    match RawEvent::try_new(RawEventParts {
        seq: 0,
        ts_mono_ns: 0,
        ts_wall_ns: 0,
        session_id: None,
        proc: None,
        source,
        evidence: Evidence::E1,
        kind: EventKind::Gap(gap),
    }) {
        Ok(event) => event,
        // try_new only rejects a required None without NA. Gap has none, so this
        // arm does not run. If a later schema change makes it fail, still emit a
        // gap: building the struct directly keeps the loss visible.
        Err(_) => gap_for_undelivered_direct(collector_name, count),
    }
}

fn gap_for_undelivered_direct(collector_name: &str, count: u64) -> RawEvent {
    let source = Source::new(format!("{collector_name}/replay"));
    RawEvent {
        v: SCHEMA_VERSION,
        seq: 0,
        ts_mono_ns: 0,
        ts_wall_ns: 0,
        session_id: None,
        proc: None,
        source: source.clone(),
        evidence: Evidence::E1,
        field_evidence: std::collections::BTreeMap::new(),
        kind: EventKind::Gap(Gap::new(
            source,
            GapKind::Dropped,
            vec!["collector".to_owned()],
            0,
            0,
            Some(count),
            Some("sink rejected events; they were not delivered".to_owned()),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{ProcRef, ProcessExit};

    fn exit_event(seq: u64, evidence: Evidence) -> RawEvent {
        RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns: seq.saturating_mul(1_000),
            ts_wall_ns: 1_700_000_000_000_000_000,
            session_id: None,
            proc: Some(ProcRef {
                uid: ProcUid(0xabc),
                pid: 42,
                tid: None,
            }),
            source: Source::new("mock.replay/test"),
            evidence,
            kind: EventKind::ProcessExit(ProcessExit::new(Some(0), None)),
        })
        .unwrap_or_else(|err| panic!("process_exit fixture rejected: {err}"))
    }

    fn declared_caps() -> CapabilitySet {
        CapabilitySet::new(
            Capability::available(Evidence::E1).expect("E1 is available"),
            Capability::unavailable(NaReason::CollectorUnavailable),
            Capability::unavailable(NaReason::CollectorUnavailable),
            Capability::unavailable(NaReason::CollectorUnavailable),
            Capability::unavailable(NaReason::TlsNoProxy),
            Capability::available(Evidence::S).expect("S is available"),
        )
    }

    #[test]
    fn replay_preserves_count_kind_and_evidence() {
        let events = vec![
            exit_event(1, Evidence::E1),
            exit_event(2, Evidence::S),
            exit_event(3, Evidence::I),
        ];
        let mut collector = MockCollector::new("mock.replay", declared_caps(), events);
        let mut sink = VecSink::with_capacity(8);
        let scope = Scope::launch("job-1").expect("token");

        collector.start(&scope, &mut sink).expect("start");

        assert_eq!(sink.events().len(), 3);
        assert!(sink
            .events()
            .iter()
            .all(|event| event.kind.kind_name() == "process_exit"));
        assert_eq!(sink.events()[0].evidence, Evidence::E1);
        assert_eq!(sink.events()[1].evidence, Evidence::S);
        assert_eq!(sink.events()[2].evidence, Evidence::I);
        assert!(collector.pending().is_empty());
        assert!(collector.health().running);
        assert_eq!(collector.health().undelivered, 0);
        assert!(collector.health().last_error.is_none());
    }

    #[test]
    fn update_scope_stop_and_declared_capabilities() {
        let mut collector = MockCollector::new(
            "mock.replay",
            declared_caps(),
            [exit_event(1, Evidence::E3)],
        );
        let caps = collector.capabilities().clone();
        assert_eq!(caps.get(CapabilityCategory::Proc).evidence, Evidence::E1);
        assert_eq!(
            caps.get(CapabilityCategory::File).evidence,
            Evidence::NA(NaReason::CollectorUnavailable)
        );
        assert_eq!(
            caps.get(CapabilityCategory::Url).evidence,
            Evidence::NA(NaReason::TlsNoProxy)
        );
        assert_eq!(caps.get(CapabilityCategory::Scope).evidence, Evidence::S);
        // The mock reports exactly the set it was built with, not "everything".
        assert!(caps.get(CapabilityCategory::Net).evidence.is_na());

        let mut sink = VecSink::with_capacity(4);
        let launch = Scope::launch("job-1").expect("token");
        collector.start(&launch, &mut sink).expect("start");
        assert_eq!(sink.events().len(), 1);
        assert_eq!(sink.events()[0].evidence, Evidence::E3);

        let attach = Scope::attach([ProcUid(7), ProcUid(7), ProcUid(9)]).expect("roots");
        collector.update_scope(&attach).expect("update");
        match collector.scope() {
            Some(Scope::Attach { roots }) => {
                assert_eq!(roots.as_slice(), &[ProcUid(7), ProcUid(9)]);
            }
            other => panic!("expected attach scope, got {other:?}"),
        }

        collector.stop().expect("stop");
        assert!(!collector.health().running);
        assert!(collector.update_scope(&launch).is_err());
        assert!(collector.stop().is_err());
        assert!(collector.health().last_error.is_some());
    }

    #[test]
    fn full_sink_surfaces_a_gap_instead_of_dropping() {
        // The first event fills the only ordinary slot. The second is refused,
        // and the gap uses the slot that is still free. `undelivered` counts
        // the refused event, not the gap. A sink with no free slot is next.
        let mut collector = MockCollector::new(
            "mock.replay",
            declared_caps(),
            [exit_event(1, Evidence::E1), exit_event(2, Evidence::S)],
        );
        let mut sink = VecSink::with_capacity(2);
        sink.hold_ordinary(1);
        let scope = Scope::attach([ProcUid(1)]).expect("root");
        collector.start(&scope, &mut sink).expect("gap fits");

        assert_eq!(sink.events().len(), 2);
        assert_eq!(sink.events()[0].kind.kind_name(), "process_exit");
        assert_eq!(sink.events()[0].evidence, Evidence::E1);
        assert_eq!(sink.events()[1].kind.kind_name(), "gap");
        assert_eq!(collector.health().undelivered, 1);
        assert!(collector.pending().is_empty());
        assert!(collector.health().last_error.is_none());
    }

    #[test]
    fn full_sink_that_also_rejects_the_gap_returns_an_error() {
        let mut collector = MockCollector::new(
            "mock.replay",
            declared_caps(),
            [exit_event(1, Evidence::E1)],
        );
        let mut sink = VecSink::with_capacity(0);
        let scope = Scope::launch("job").expect("token");
        let err = collector.start(&scope, &mut sink).expect_err("no room");
        match err {
            CollectorError::Sink {
                kind: SinkFailureKind::Full,
                undelivered,
            } => assert_eq!(undelivered, 2),
            other => panic!("expected sink full, got {other:?}"),
        }
        assert!(sink.events().is_empty());
        assert_eq!(collector.health().undelivered, 2);
        let message = collector.health().last_error.expect("recorded");
        assert!(!message.contains("argv"));
        assert!(message.contains("not silently dropped"));
    }

    #[test]
    fn empty_scope_is_not_a_silent_default() {
        assert!(Scope::launch("").is_err());
        assert!(Scope::attach([]).is_err());
        assert!(Capability::available(Evidence::NA(NaReason::CollectorUnavailable)).is_err());
    }
}
