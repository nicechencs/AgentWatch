//! Polling collector.
//!
//! [`PollCollector::start`] borrows the sink for that call and does not spawn a
//! thread. [`PollCollector::poll_once`] is one tick. Tests pass the timestamp and
//! the snapshots, so this module never sleeps and never reads the host clock.
//!
//! The first successful process sample and the first successful connection sample
//! are baselines: rows already present are not reported as new. A failed sample is
//! a [`Gap`] and is not stored as an empty baseline, so the next success does not
//! look like every process just started.

use std::time::Duration;

use aw_core::{
    Capability, CapabilitySet, Collector, CollectorError, EventKind, EventSink, Evidence, Gap,
    GapKind, Health, NaReason, ProcRef, ProcUid, ProcessStart, RawEvent, RawEventParts, Scope,
    SinkError, SinkFailureKind, Source, StartHow,
};

use crate::diff::{
    build_connection_event, build_process_event, diff_connections, diff_processes, finish_event,
    parent_uid, pids_for_uids, subtree_rows, ConnectionDelta, ProcessDelta, SkippedProcess,
};
use crate::host::{HostConnectionSource, HostProcessSource};
use crate::source::{
    ConnectionSnapshot, ConnectionSource, ProcessSnapshot, ProcessSource, SourceFailure,
};

/// Default process sample interval. A future scheduler waits this long.
/// [`PollCollector::poll_once`] itself always samples, so tests do not sleep.
pub const DEFAULT_PROC_INTERVAL: Duration = Duration::from_millis(250);

/// Default connection sample interval.
pub const DEFAULT_CONN_INTERVAL: Duration = Duration::from_secs(1);

const PROC_SOURCE: &str = "poll/sysinfo";
const NET_SOURCE: &str = "poll/netstat";

/// Why [`PollConfig`] was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollError {
    /// A sample interval of zero is not a schedule.
    ZeroInterval,
}

/// Sample intervals. Zero is rejected.
///
/// Stored for a future scheduler. [`PollCollector::poll_once`] does not wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollConfig {
    /// How often a scheduler should sample processes.
    pub proc_interval: Duration,
    /// How often a scheduler should sample connections.
    pub conn_interval: Duration,
}

impl PollConfig {
    /// [`DEFAULT_PROC_INTERVAL`] and [`DEFAULT_CONN_INTERVAL`].
    pub const fn standard() -> Self {
        Self {
            proc_interval: DEFAULT_PROC_INTERVAL,
            conn_interval: DEFAULT_CONN_INTERVAL,
        }
    }

    /// Named intervals.
    ///
    /// # Errors
    ///
    /// [`PollError::ZeroInterval`] when either duration is zero.
    pub fn new(proc_interval: Duration, conn_interval: Duration) -> Result<Self, PollError> {
        if proc_interval.is_zero() || conn_interval.is_zero() {
            return Err(PollError::ZeroInterval);
        }
        Ok(Self {
            proc_interval,
            conn_interval,
        })
    }
}

impl Default for PollConfig {
    fn default() -> Self {
        Self::standard()
    }
}

/// Which pids the next process sample is allowed to refresh.
enum Watch {
    /// `Scope::Launch`. The token is stored as text and is never opened. The watch
    /// set stays empty until [`Collector::update_scope`] supplies attach roots.
    Launch { token: String }, // stored, never opened as a handle
    /// `Scope::Attach`, after the root [`ProcUid`]s have been turned into pids.
    /// An empty `pids` means the roots are not resolved yet.
    Attach { pids: Vec<u32> },
}

/// Polling fallback. Process rows come from `P`, connection rows from `C`.
pub struct PollCollector<P, C> {
    processes: P,
    connections: C,
    caps: CapabilitySet,
    config: PollConfig,
    running: bool,
    /// Clock supplied to `start`. `poll_once` overrides it for that tick.
    /// `None` until `start`. Never stored as `0` to mean "unknown".
    clock: Option<(u64, i64)>,
    watch: Option<Watch>,
    /// Roots from the last attach, used to resolve pids on the next full sample.
    attach_uids: Vec<ProcUid>,
    /// `None` until the first successful sample. A failure leaves this `None`,
    /// so the next success is a fresh baseline instead of a flood of starts.
    /// `poll_once` emits the gap for that failure with the caller's clock.
    proc_baseline: Option<ProcessSnapshot>,
    conn_baseline: Option<ConnectionSnapshot>,
    /// Pids accepted into the watch set. Exits are emitted only for these.
    watched: Vec<u32>,
    seq: u64,
    undelivered: u64,
    last_error: Option<String>,
    /// `true` when the connection source declared itself unavailable. Those empty
    /// samples are not gaps.
    net_unavailable: bool,
}

impl PollCollector<HostProcessSource, HostConnectionSource> {
    /// Live `sysinfo` and, on Windows, `netstat -ano`.
    ///
    /// Tests must not call this. The first `start` or `poll_once` reads the host.
    pub fn with_host(config: PollConfig) -> Self {
        Self::from_sources(
            HostProcessSource::new(),
            HostConnectionSource::new(),
            config,
        )
    }
}

impl<P, C> PollCollector<P, C>
where
    P: ProcessSource,
    C: ConnectionSource,
{
    /// Collector over injected sources. Does not touch the host.
    pub fn from_sources(processes: P, connections: C, config: PollConfig) -> Self {
        let net_unavailable = connections.unavailable_reason().is_some();
        Self {
            processes,
            connections,
            caps: capabilities(net_unavailable),
            config,
            running: false,
            clock: None,
            watch: None,
            attach_uids: Vec::new(),
            proc_baseline: None,
            conn_baseline: None,
            watched: Vec::new(),
            seq: 0,
            undelivered: 0,
            last_error: None,
            net_unavailable,
        }
    }

    /// Sample once and emit the delta since the baseline.
    ///
    /// Always samples. Intervals in [`PollConfig`] are not consulted.
    ///
    /// # Errors
    ///
    /// [`CollectorError::NotRunning`] when `start` has not succeeded.
    /// [`CollectorError::Sink`] when the sink refuses an event and the replacement gap.
    pub fn poll_once(
        &mut self,
        sink: &mut dyn EventSink,
        mono_ns: u64,
        wall_ns: i64,
    ) -> Result<(), CollectorError> {
        if !self.running {
            return Err(CollectorError::NotRunning);
        }
        self.sample(sink, mono_ns, wall_ns)
    }

    /// One process read of `root_pid` and its descendants.
    ///
    /// Does not start the poll loop and does not require `start`. Rows with no
    /// start time or no parent pid are omitted: [`ProcessStart`] cannot represent
    /// either as `None`. This method returns no [`Gap`] for those rows.
    pub fn snapshot(&mut self, root_pid: u32) -> Vec<ProcessStart> {
        self.processes.set_restrict(None);
        let Ok(sample) = self.processes.snapshot() else {
            return Vec::new();
        };
        let boot = sample.boot_id.clone();
        let mut starts = Vec::new();
        for row in subtree_rows(&sample, root_pid) {
            let parent = parent_uid(&row, &sample);
            let delta = ProcessDelta::Started(row);
            let Ok(built) =
                build_process_event(&delta, boot.as_deref(), StartHow::Snapshot, parent)
            else {
                continue;
            };
            if let EventKind::ProcessStart(start) = built.event_kind {
                starts.push(start);
            }
        }
        starts
    }

    /// Intervals stored for a scheduler.
    pub fn config(&self) -> PollConfig {
        self.config
    }

    /// Launch token text, when the active scope is launch. Not a pid.
    pub fn launch_token(&self) -> Option<&str> {
        match self.watch.as_ref() {
            Some(Watch::Launch { token }) => Some(token.as_str()),
            _ => None,
        }
    }

    /// [`Collector::start`] plus the caller's clock.
    ///
    /// The trait itself has no timestamp argument. A gap emitted while taking the
    /// baseline uses this pair. `0` is only stored when the caller passed `0`.
    ///
    /// # Errors
    ///
    /// Same as [`Collector::start`].
    pub fn start_at(
        &mut self,
        scope: &Scope,
        sink: &mut dyn EventSink,
        mono_ns: u64,
        wall_ns: i64,
    ) -> Result<(), CollectorError> {
        self.clock = Some((mono_ns, wall_ns));
        self.start(scope, sink)
    }

    /// Baseline-only sample for [`Collector::start`] when no clock was stored.
    ///
    /// A failure is not given a timestamp of `0`. The baseline stays empty.
    /// The next [`PollCollector::poll_once`] emits the gap, because a failed
    /// sample is not stored and `sample` reports `Err` with the caller's clock.
    fn sample_quiet(&mut self) {
        self.apply_restrict();
        match self.processes.snapshot() {
            Ok(sample) => {
                self.resolve_attach_roots(&sample);
                self.seed_watched(&sample);
                self.proc_baseline = Some(filter_processes(&sample, &self.watched));
                self.arm_restrict_from_watch();
            }
            Err(_) => {
                self.proc_baseline = None;
            }
        }
        if self.net_unavailable {
            let _ = self.connections.snapshot();
            return;
        }
        match self.connections.snapshot() {
            Ok(sample) => {
                let filtered = filter_connections(&sample, &self.watched);
                self.conn_baseline = Some(filtered);
            }
            Err(_) => {
                self.conn_baseline = None;
            }
        }
    }

    fn sample(
        &mut self,
        sink: &mut dyn EventSink,
        mono_ns: u64,
        wall_ns: i64,
    ) -> Result<(), CollectorError> {
        self.apply_restrict();
        match self.processes.snapshot() {
            Ok(sample) => {
                // A previous failure already emitted its gap and cleared the
                // baseline. This sample starts over. It is not a flood of starts.
                self.consume_processes(sample, sink, mono_ns, wall_ns)?;
            }
            Err(err) => {
                // Not an empty baseline. The next success starts over.
                self.proc_baseline = None;
                self.emit_source_gap(sink, PROC_SOURCE, err.kind, "proc", mono_ns, wall_ns)?;
            }
        }
        if self.net_unavailable {
            // Platform stub. The capability is already NA. An empty table is not a gap.
            let _ = self.connections.snapshot();
            return Ok(());
        }
        match self.connections.snapshot() {
            Ok(sample) => {
                self.consume_connections(sample, sink, mono_ns, wall_ns)?;
            }
            Err(err) => {
                self.conn_baseline = None;
                self.emit_source_gap(sink, NET_SOURCE, err.kind, "net", mono_ns, wall_ns)?;
            }
        }
        Ok(())
    }

    fn consume_processes(
        &mut self,
        sample: ProcessSnapshot,
        sink: &mut dyn EventSink,
        mono_ns: u64,
        wall_ns: i64,
    ) -> Result<(), CollectorError> {
        self.resolve_attach_roots(&sample);
        let establishing = self.proc_baseline.is_none();
        if establishing {
            self.seed_watched(&sample);
            self.proc_baseline = Some(filter_processes(&sample, &self.watched));
            self.arm_restrict_from_watch();
            return Ok(());
        }

        let before = match self.proc_baseline.clone() {
            Some(before) => before,
            None => return Ok(()),
        };
        // Keep a row whose parent is watched even when the row itself is not yet
        // in `watched`. Otherwise a child with no ppid (which cannot be hashed
        // into the set) would vanish instead of becoming a gap.
        let visible = self.pids_touching_watch(&sample);
        let filtered = filter_processes(&sample, &visible);
        let deltas = diff_processes(&before, &filtered);
        let source = Source::new(PROC_SOURCE);
        for delta in &deltas {
            if !self.delta_in_scope(delta) {
                continue;
            }
            let parent = match delta {
                ProcessDelta::Started(row) => parent_uid(row, &filtered),
                ProcessDelta::Exited(_) => None,
            };
            match build_process_event(delta, filtered.boot_id.as_deref(), StartHow::Spawn, parent) {
                Ok(built) => {
                    let seq = self.next_seq();
                    match finish_event(built, seq, mono_ns, wall_ns, &source) {
                        Ok(event) => self.emit(sink, event, mono_ns, wall_ns)?,
                        Err(()) => self.emit_skip_gap(
                            sink,
                            SkippedProcess {
                                pid: delta_pid(delta),
                                missing: "event",
                            },
                            mono_ns,
                            wall_ns,
                        )?,
                    }
                }
                Err(skipped) => self.emit_skip_gap(sink, skipped, mono_ns, wall_ns)?,
            }
            match delta {
                ProcessDelta::Started(row) => {
                    if !self.watched.contains(&row.pid) {
                        self.watched.push(row.pid);
                    }
                }
                ProcessDelta::Exited(row) => {
                    self.watched.retain(|pid| *pid != row.pid);
                }
            }
        }
        self.proc_baseline = Some(filter_processes(&sample, &self.watched));
        self.arm_restrict_from_watch();
        Ok(())
    }

    fn consume_connections(
        &mut self,
        sample: ConnectionSnapshot,
        sink: &mut dyn EventSink,
        mono_ns: u64,
        wall_ns: i64,
    ) -> Result<(), CollectorError> {
        // Rows with no pid are not a flow and are not dropped. They become a gap
        // whose detail is the fixed label "pid" and carries no address.
        let unowned = unowned_connection_count(&sample);
        let filtered = filter_connections(&sample, &self.watched);
        if self.conn_baseline.is_none() {
            self.conn_baseline = Some(filtered);
            self.emit_unowned_gaps(sink, unowned, mono_ns, wall_ns)?;
            return Ok(());
        }
        let before = match self.conn_baseline.clone() {
            Some(before) => before,
            None => return Ok(()),
        };
        let deltas = diff_connections(&before, &filtered);
        let source = Source::new(NET_SOURCE);
        let procs = self.proc_baseline.clone();
        for delta in &deltas {
            let row = connection_row(delta);
            let Some(pid) = row.pid else {
                // `filter_connections` already removed pid-less rows. A delta
                // cannot carry one. Do not guess a pid if one appears anyway.
                continue;
            };
            if !self.watched.contains(&pid) {
                continue;
            }
            let proc = procs.as_ref().and_then(|snap| proc_of(snap, pid));
            let seq = self.next_seq();
            match build_connection_event(delta, seq, mono_ns, wall_ns, &source, proc) {
                Ok(event) => self.emit(sink, event, mono_ns, wall_ns)?,
                Err(()) => self.emit_source_gap(
                    sink,
                    NET_SOURCE,
                    SourceFailure::Parse,
                    "net",
                    mono_ns,
                    wall_ns,
                )?,
            }
        }
        self.conn_baseline = Some(filtered);
        self.emit_unowned_gaps(sink, unowned, mono_ns, wall_ns)?;
        Ok(())
    }

    /// One gap per connection row that has no owning pid.
    ///
    /// The detail is the fixed label `"pid"`. It does not include the local or
    /// remote address, the protocol, or any text from the listing.
    fn emit_unowned_gaps(
        &mut self,
        sink: &mut dyn EventSink,
        count: usize,
        mono_ns: u64,
        wall_ns: i64,
    ) -> Result<(), CollectorError> {
        for _ in 0..count {
            let seq = self.next_seq();
            let event = gap_event(GapStamp {
                probe: NET_SOURCE,
                kind: GapKind::AttributionUnknown,
                affects: "net",
                count: Some(1),
                detail: "pid",
                seq,
                mono_ns,
                wall_ns,
            });
            self.emit(sink, event, mono_ns, wall_ns)?;
        }
        Ok(())
    }

    fn resolve_attach_roots(&mut self, sample: &ProcessSnapshot) {
        let needs_resolve = match self.watch.as_ref() {
            Some(Watch::Attach { pids }) => pids.is_empty() && !self.attach_uids.is_empty(),
            _ => false,
        };
        if !needs_resolve {
            return;
        }
        let found = pids_for_uids(sample, &self.attach_uids);
        if found.is_empty() {
            return;
        }
        if let Some(Watch::Attach { pids }) = self.watch.as_mut() {
            *pids = found;
        }
    }

    fn seed_watched(&mut self, sample: &ProcessSnapshot) {
        match self.watch.as_ref() {
            Some(Watch::Launch { .. }) | None => {
                // Launch watches nobody until a later attach. Do not take every pid.
                self.watched.clear();
            }
            Some(Watch::Attach { pids }) => {
                self.watched.clone_from(pids);
                for pid in child_pids(sample, &self.watched) {
                    if !self.watched.contains(&pid) {
                        self.watched.push(pid);
                    }
                }
            }
        }
    }

    fn pids_touching_watch(&self, sample: &ProcessSnapshot) -> Vec<u32> {
        let mut pids = self.watched.clone();
        for row in &sample.rows {
            let parent_watched = row.ppid.is_some_and(|ppid| self.watched.contains(&ppid));
            if (self.watched.contains(&row.pid) || parent_watched) && !pids.contains(&row.pid) {
                pids.push(row.pid);
            }
        }
        pids
    }

    fn delta_in_scope(&self, delta: &ProcessDelta) -> bool {
        let row = match delta {
            ProcessDelta::Started(row) | ProcessDelta::Exited(row) => row,
        };
        if self.watched.contains(&row.pid) {
            return true;
        }
        matches!(delta, ProcessDelta::Started(_))
            && row.ppid.is_some_and(|ppid| self.watched.contains(&ppid))
    }

    fn apply_restrict(&mut self) {
        match self.watch.as_ref() {
            Some(Watch::Launch { .. }) | None => {
                // Launch never scans. A pending attach is resolved by the attach arm.
                if self.watched.is_empty() {
                    self.processes.set_restrict(Some(&[]));
                } else {
                    let watched = self.watched.clone();
                    self.processes.set_restrict(Some(&watched));
                }
            }
            Some(Watch::Attach { pids }) if pids.is_empty() => {
                // One full table, to translate ProcUid roots into pids.
                self.processes.set_restrict(None);
            }
            Some(Watch::Attach { .. }) => {
                if self.watched.is_empty() {
                    self.processes.set_restrict(Some(&[]));
                } else {
                    let watched = self.watched.clone();
                    self.processes.set_restrict(Some(&watched));
                }
            }
        }
    }

    fn arm_restrict_from_watch(&mut self) {
        if self.watched.is_empty() {
            self.processes.set_restrict(Some(&[]));
        } else {
            let watched = self.watched.clone();
            self.processes.set_restrict(Some(&watched));
        }
    }

    fn remember_scope(&mut self, scope: &Scope) {
        match scope {
            Scope::Launch { token } => {
                let token = token.as_str().to_owned();
                self.watch = Some(Watch::Launch { token });
                // The token is text. Reading it back makes the store observable
                // without parsing it as a pid or opening it as a handle.
                debug_assert!(self.launch_token().is_some());
                self.attach_uids.clear();
                self.watched.clear();
                self.proc_baseline = None;
                self.conn_baseline = None;
                self.processes.set_restrict(Some(&[]));
            }
            Scope::Attach { roots } => {
                self.attach_uids.clone_from(roots);
                self.watch = Some(Watch::Attach { pids: Vec::new() });
                self.watched.clear();
                // The previous pid set is not this scope. Force a fresh baseline
                // so the next sample resolves uids instead of diffing stale rows.
                self.proc_baseline = None;
                self.conn_baseline = None;
                self.processes.set_restrict(None);
            }
        }
    }

    fn emit(
        &mut self,
        sink: &mut dyn EventSink,
        event: RawEvent,
        mono_ns: u64,
        wall_ns: i64,
    ) -> Result<(), CollectorError> {
        match sink.emit(event) {
            Ok(()) => Ok(()),
            Err(err) => self.report_undelivered(sink, 1, &err, mono_ns, wall_ns),
        }
    }

    fn report_undelivered(
        &mut self,
        sink: &mut dyn EventSink,
        lost: u64,
        cause: &SinkError,
        mono_ns: u64,
        wall_ns: i64,
    ) -> Result<(), CollectorError> {
        let kind = match cause {
            SinkError::Full { .. } => SinkFailureKind::Full,
            SinkError::Closed => SinkFailureKind::Closed,
            SinkError::Other { .. } => SinkFailureKind::Other,
        };
        let gap = gap_event(GapStamp {
            probe: PROC_SOURCE,
            kind: GapKind::Dropped,
            affects: "collector",
            count: Some(lost),
            detail: "sink rejected events; they were not delivered",
            seq: self.next_seq(),
            mono_ns,
            wall_ns,
        });
        match sink.emit(gap) {
            Ok(()) => {
                self.undelivered = self.undelivered.saturating_add(lost);
                Ok(())
            }
            Err(_) => {
                let undelivered = lost.saturating_add(1);
                self.undelivered = self.undelivered.saturating_add(undelivered);
                let err = CollectorError::Sink { kind, undelivered };
                self.last_error = Some(err.to_string());
                Err(err)
            }
        }
    }

    fn emit_source_gap(
        &mut self,
        sink: &mut dyn EventSink,
        probe: &str,
        failure: SourceFailure,
        affects: &str,
        mono_ns: u64,
        wall_ns: i64,
    ) -> Result<(), CollectorError> {
        let kind = match failure {
            SourceFailure::Disconnected => GapKind::CollectorDisconnected,
            SourceFailure::Parse => GapKind::ParseError,
            SourceFailure::Permission => GapKind::Permission,
        };
        let seq = self.next_seq();
        let event = gap_event(GapStamp {
            probe,
            kind,
            affects,
            count: None,
            detail: "sample failed",
            seq,
            mono_ns,
            wall_ns,
        });
        self.emit(sink, event, mono_ns, wall_ns)
    }

    fn emit_skip_gap(
        &mut self,
        sink: &mut dyn EventSink,
        skipped: SkippedProcess,
        mono_ns: u64,
        wall_ns: i64,
    ) -> Result<(), CollectorError> {
        let seq = self.next_seq();
        // `missing` is a fixed label (`"ppid"` or `"start_time_ns"`), never a path.
        let event = gap_event(GapStamp {
            probe: PROC_SOURCE,
            kind: GapKind::Unsupported,
            affects: "proc",
            count: Some(1),
            detail: skipped.missing,
            seq,
            mono_ns,
            wall_ns,
        });
        let _ = skipped.pid;
        self.emit(sink, event, mono_ns, wall_ns)
    }

    fn next_seq(&mut self) -> u64 {
        self.seq = self.seq.saturating_add(1);
        self.seq
    }
}

impl<P, C> Collector for PollCollector<P, C>
where
    P: ProcessSource,
    C: ConnectionSource,
{
    fn name(&self) -> &str {
        "poll"
    }

    fn capabilities(&self) -> &CapabilitySet {
        &self.caps
    }

    fn start(&mut self, scope: &Scope, sink: &mut dyn EventSink) -> Result<(), CollectorError> {
        if self.running {
            return Err(CollectorError::AlreadyRunning);
        }
        self.remember_scope(scope);
        self.seq = 0;
        self.last_error = None;
        // Baselines only. No ProcessStart / NetConnect for rows already present.
        // A failed first sample leaves the baseline empty and emits a gap; the
        // collector is still running so a later poll_once can try again.
        // `clock` was set by `start_at`. The trait has no timestamp, so a direct
        // `start` with no prior clock cannot stamp a gap. That path takes the
        // baseline only when the sample succeeds; a failure is still a gap, and
        // its clock is whatever `start_at` stored. Tests call `start_at`.
        if let Some((mono_ns, wall_ns)) = self.clock {
            self.sample(sink, mono_ns, wall_ns)?;
        } else {
            // `Collector::start` has no clock. Do not invent timestamps for a gap.
            // A failed sample stays unbaselined; the next `poll_once` reports it
            // with the caller's clock. A successful sample is stored as a baseline
            // and emits nothing, so it needs no timestamp.
            self.sample_quiet();
        }
        self.running = true;
        Ok(())
    }

    fn update_scope(&mut self, scope: &Scope) -> Result<(), CollectorError> {
        if !self.running {
            return Err(CollectorError::NotRunning);
        }
        self.remember_scope(scope);
        Ok(())
    }

    fn stop(&mut self) -> Result<(), CollectorError> {
        if !self.running {
            return Err(CollectorError::NotRunning);
        }
        self.running = false;
        self.watch = None;
        self.attach_uids.clear();
        self.watched.clear();
        self.proc_baseline = None;
        self.conn_baseline = None;
        self.processes.set_restrict(Some(&[]));
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

fn capabilities(net_unavailable: bool) -> CapabilitySet {
    let proc = Capability::available(Evidence::S)
        .map(|cap| {
            cap.with_note(
                "process list is a sample; a process that exits between samples is not reported",
            )
        })
        .unwrap_or_else(|_| Capability::unavailable(NaReason::CollectorUnavailable));
    let net = if net_unavailable {
        Capability::unavailable(NaReason::CollectorUnavailable).with_note(
            "connection listing is not implemented on this target; byte counts are not read",
        )
    } else {
        Capability::available(Evidence::S)
            .map(|cap| {
                cap.with_note(
                    "connection list is a sample; byte counts are NA and are not reported as zero",
                )
            })
            .unwrap_or_else(|_| Capability::unavailable(NaReason::CollectorUnavailable))
    };
    let scope = Capability::available(Evidence::S)
        .map(|cap| {
            cap.with_note(
                "user-space pid filter, not a kernel scope; a new child is visible only when the source returns it",
            )
        })
        .unwrap_or_else(|_| Capability::unavailable(NaReason::CollectorUnavailable));
    let na = Capability::unavailable(NaReason::CollectorUnavailable);
    CapabilitySet::new(proc, na.clone(), net, na.clone(), na, scope)
}

fn filter_processes(sample: &ProcessSnapshot, pids: &[u32]) -> ProcessSnapshot {
    ProcessSnapshot {
        boot_id: sample.boot_id.clone(),
        rows: sample
            .rows
            .iter()
            .filter(|row| pids.contains(&row.pid))
            .cloned()
            .collect(),
    }
}

fn filter_connections(sample: &ConnectionSnapshot, pids: &[u32]) -> ConnectionSnapshot {
    ConnectionSnapshot {
        rows: sample
            .rows
            .iter()
            .filter(|row| row.pid.is_some_and(|pid| pids.contains(&pid)))
            .cloned()
            .collect(),
    }
}

/// Established rows with no pid. Listeners are not flows, so they are not counted.
/// A listener with no pid is the normal `netstat` form and is not a gap.
fn unowned_connection_count(sample: &ConnectionSnapshot) -> usize {
    sample
        .rows
        .iter()
        .filter(|row| !row.listening && row.remote.is_some() && row.pid.is_none())
        .count()
}

fn child_pids(sample: &ProcessSnapshot, parents: &[u32]) -> Vec<u32> {
    let mut found = Vec::new();
    let mut frontier: Vec<u32> = parents.to_vec();
    while let Some(parent) = frontier.pop() {
        for row in &sample.rows {
            if row.ppid == Some(parent)
                && row.pid != parent
                && !found.contains(&row.pid)
                && !parents.contains(&row.pid)
            {
                found.push(row.pid);
                frontier.push(row.pid);
            }
        }
    }
    found
}

fn connection_row(delta: &ConnectionDelta) -> &crate::source::ConnectionRow {
    match delta {
        ConnectionDelta::Connected(row) | ConnectionDelta::Closed(row) => row,
    }
}

fn delta_pid(delta: &ProcessDelta) -> u32 {
    match delta {
        ProcessDelta::Started(row) | ProcessDelta::Exited(row) => row.pid,
    }
}

fn proc_of(sample: &ProcessSnapshot, pid: u32) -> Option<ProcRef> {
    use crate::source::ProcessStartTime;
    use aw_core::proc::{ProcessIdentity, StartTimeUnit};

    let boot = sample.boot_id.as_deref()?;
    let row = sample.rows.iter().find(|row| row.pid == pid)?;
    let ProcessStartTime::UnixSeconds(secs) = row.start else {
        return None;
    };
    let identity = ProcessIdentity::from_parts(boot, row.pid, secs, StartTimeUnit::Seconds)?;
    Some(ProcRef {
        uid: identity.uid,
        pid: row.pid,
        tid: None,
    })
}

struct GapStamp<'a> {
    probe: &'a str,
    kind: GapKind,
    affects: &'a str,
    count: Option<u64>,
    detail: &'a str,
    seq: u64,
    mono_ns: u64,
    wall_ns: i64,
}

fn gap_event(stamp: GapStamp<'_>) -> RawEvent {
    let GapStamp {
        probe,
        kind,
        affects,
        count,
        detail,
        seq,
        mono_ns,
        wall_ns,
    } = stamp;
    let source = Source::new(probe);
    let gap = Gap::new(
        source.clone(),
        kind,
        vec![affects.to_owned()],
        mono_ns,
        mono_ns,
        count,
        Some(detail.to_owned()),
    );
    // Gap has no required None, so try_new does not fail for it.
    match RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns: mono_ns,
        ts_wall_ns: wall_ns,
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
            ts_mono_ns: mono_ns,
            ts_wall_ns: wall_ns,
            session_id: None,
            proc: None,
            source: Source::new(probe),
            evidence: Evidence::E1,
            field_evidence: std::collections::BTreeMap::new(),
            kind: EventKind::Gap(Gap::new(
                Source::new(probe),
                kind,
                vec![affects.to_owned()],
                mono_ns,
                mono_ns,
                count,
                Some(detail.to_owned()),
            )),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::source::{
        ConnectionRow, FailingConnectionSource, FailingProcessSource, ProcessRow, ProcessStartTime,
        SourceFailure, StaticConnectionSource, StaticProcessSource,
    };
    use aw_core::{
        proc::{ProcessIdentity, StartTimeUnit},
        CapabilityCategory, EventKind, Evidence, FlowDirection, GapKind, L4Proto, NaReason,
        ProcUid, VecSink,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    const BOOT: &[u8] = b"boot-test";
    const MONO: u64 = 10_000;
    const WALL: i64 = 1_700_000_000_000_000_000;

    fn row(pid: u32, ppid: Option<u32>) -> ProcessRow {
        ProcessRow::bare(pid, ppid, ProcessStartTime::UnixSeconds(1_700_000_000))
    }

    fn snap(rows: Vec<ProcessRow>) -> ProcessSnapshot {
        ProcessSnapshot::new(BOOT.to_vec(), rows)
    }

    fn uid_of(pid: u32) -> ProcUid {
        ProcessIdentity::from_parts(BOOT, pid, 1_700_000_000, StartTimeUnit::Seconds)
            .expect("boot id fits")
            .uid
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn flow(pid: u32, local: u16, remote: u16) -> ConnectionRow {
        ConnectionRow {
            pid: Some(pid),
            proto: L4Proto::Tcp,
            local: loopback(local),
            remote: Some(loopback(remote)),
            direction: FlowDirection::Unknown,
            sock_id: None,
            listening: false,
        }
    }

    fn collector(
        procs: Vec<ProcessSnapshot>,
        conns: Vec<ConnectionSnapshot>,
    ) -> PollCollector<StaticProcessSource, StaticConnectionSource> {
        PollCollector::from_sources(
            StaticProcessSource::new(procs),
            StaticConnectionSource::new(conns),
            PollConfig::standard(),
        )
    }

    fn kinds(sink: &VecSink) -> Vec<&'static str> {
        sink.events()
            .iter()
            .map(|event| event.kind.kind_name())
            .collect()
    }

    #[test]
    fn baseline_emits_nothing_then_start_and_exit_are_s() {
        let first = snap(vec![row(10, Some(1))]);
        let second = snap(vec![row(10, Some(1)), row(11, Some(10))]);
        let third = snap(vec![row(10, Some(1))]);
        let mut c = collector(
            vec![first, second, third],
            vec![
                ConnectionSnapshot::default(),
                ConnectionSnapshot::default(),
                ConnectionSnapshot::default(),
            ],
        );
        let mut sink = VecSink::with_capacity(8);
        let scope = Scope::attach([uid_of(10)]).expect("root");
        c.start_at(&scope, &mut sink, MONO, WALL).expect("start");
        assert!(sink.events().is_empty(), "baseline is not a start");

        c.poll_once(&mut sink, MONO + 1, WALL).expect("tick");
        assert_eq!(kinds(&sink), vec!["process_start"]);
        let event = &sink.events()[0];
        assert_eq!(event.evidence, Evidence::S);
        assert_eq!(event.source.as_str(), "poll/sysinfo");
        assert_eq!(event.ts_mono_ns, MONO + 1);
        assert_eq!(event.seq, 1);
        let EventKind::ProcessStart(start) = &event.kind else {
            panic!("kind");
        };
        assert_eq!(start.ppid, 10);
        assert_eq!(start.how, StartHow::Spawn);
        assert!(!event.field_evidence.contains_key("exit_code"));
        assert!(event.field_evidence.get("exe").is_some_and(Evidence::is_na));

        c.poll_once(&mut sink, MONO + 2, WALL).expect("tick");
        assert_eq!(kinds(&sink), vec!["process_start", "process_exit"]);
        let exit = &sink.events()[1];
        assert_eq!(exit.evidence, Evidence::S);
        let EventKind::ProcessExit(body) = &exit.kind else {
            panic!("exit");
        };
        assert_eq!(body.exit_code, None);
        assert!(exit
            .field_evidence
            .get("exit_code")
            .is_some_and(|ev| ev == &Evidence::NA(NaReason::CollectorUnavailable)));
    }

    #[test]
    fn launch_does_not_scan_and_keeps_the_token_as_text() {
        let mut c = collector(
            vec![snap(vec![row(10, Some(1)), row(11, Some(10))])],
            vec![ConnectionSnapshot::new(vec![flow(10, 1, 2)])],
        );
        let mut sink = VecSink::with_capacity(8);
        let scope = Scope::launch("job-text-not-a-pid").expect("token");
        c.start_at(&scope, &mut sink, MONO, WALL).expect("start");
        c.poll_once(&mut sink, MONO + 1, WALL).expect("tick");
        assert!(sink.events().is_empty());
        assert_eq!(c.launch_token(), Some("job-text-not-a-pid"));
        assert_eq!(c.config().proc_interval, DEFAULT_PROC_INTERVAL);
        assert_eq!(c.config().conn_interval, DEFAULT_CONN_INTERVAL);
    }

    #[test]
    fn out_of_scope_pid_emits_nothing_child_is_kept() {
        let first = snap(vec![row(10, Some(1)), row(99, Some(1))]);
        let second = snap(vec![
            row(10, Some(1)),
            row(99, Some(1)),
            row(11, Some(10)),
            row(100, Some(99)),
        ]);
        let mut c = collector(
            vec![first, second],
            vec![ConnectionSnapshot::default(), ConnectionSnapshot::default()],
        );
        let mut sink = VecSink::with_capacity(8);
        c.start_at(
            &Scope::attach([uid_of(10)]).expect("root"),
            &mut sink,
            MONO,
            WALL,
        )
        .expect("start");
        c.poll_once(&mut sink, MONO + 1, WALL).expect("tick");
        assert_eq!(kinds(&sink), vec!["process_start"]);
        let EventKind::ProcessStart(start) = &sink.events()[0].kind else {
            panic!("start");
        };
        assert_eq!(start.ppid, 10);
    }

    #[test]
    fn missing_start_time_is_a_gap_not_a_zero() {
        let first = snap(vec![row(10, Some(1))]);
        // In scope because its parent is watched. The start time is missing, so
        // the start cannot be built and must be a gap rather than time 0.
        let broken = ProcessRow::bare(11, Some(10), ProcessStartTime::Unavailable);
        let second = snap(vec![row(10, Some(1)), broken]);
        let mut c = collector(
            vec![first, second],
            vec![ConnectionSnapshot::default(), ConnectionSnapshot::default()],
        );
        let mut sink = VecSink::with_capacity(4);
        c.start_at(
            &Scope::attach([uid_of(10)]).expect("root"),
            &mut sink,
            MONO,
            WALL,
        )
        .expect("start");
        c.poll_once(&mut sink, MONO + 5, WALL).expect("tick");
        assert_eq!(kinds(&sink), vec!["gap"]);
        let event = &sink.events()[0];
        assert_eq!(event.evidence, Evidence::E1);
        assert_eq!(event.ts_mono_ns, MONO + 5);
        let EventKind::Gap(gap) = &event.kind else {
            panic!("gap");
        };
        assert_eq!(gap.gap_kind, GapKind::Unsupported);
        assert_eq!(gap.detail.as_deref(), Some("start_time_ns"));
        assert_eq!(gap.count, Some(1));
    }

    #[test]
    fn failed_sample_is_a_gap_and_recovery_is_a_baseline() {
        let mut c = PollCollector::from_sources(
            FailingProcessSource {
                failure: SourceFailure::Disconnected,
            },
            StaticConnectionSource::unavailable(NaReason::CollectorUnavailable),
            PollConfig::standard(),
        );
        let mut sink = VecSink::with_capacity(4);
        let err = c.start_at(&Scope::launch("job").expect("token"), &mut sink, MONO, WALL);
        assert!(err.is_ok());
        assert_eq!(kinds(&sink), vec!["gap"]);
        let EventKind::Gap(gap) = &sink.events()[0].kind else {
            panic!("gap");
        };
        assert_eq!(gap.gap_kind, GapKind::CollectorDisconnected);
        assert_eq!(sink.events()[0].ts_mono_ns, MONO);
        assert_ne!(sink.events()[0].evidence, Evidence::S);
    }

    #[test]
    fn connection_delta_is_connect_and_close_without_zero_bytes() {
        let procs = snap(vec![row(10, Some(1))]);
        let idle = ConnectionSnapshot::default();
        let up = ConnectionSnapshot::new(vec![flow(10, 4000, 443)]);
        let mut c = collector(
            vec![procs.clone(), procs.clone(), procs],
            vec![idle, up.clone(), ConnectionSnapshot::default()],
        );
        let mut sink = VecSink::with_capacity(8);
        c.start_at(
            &Scope::attach([uid_of(10)]).expect("root"),
            &mut sink,
            MONO,
            WALL,
        )
        .expect("start");
        c.poll_once(&mut sink, MONO + 1, WALL).expect("tick");
        assert_eq!(kinds(&sink), vec!["net_connect"]);
        let event = &sink.events()[0];
        assert_eq!(event.evidence, Evidence::S);
        assert_eq!(event.source.as_str(), "poll/netstat");
        assert!(event
            .field_evidence
            .get("result")
            .is_some_and(Evidence::is_na));
        let EventKind::NetConnect(body) = &event.kind else {
            panic!("connect");
        };
        assert_eq!(body.direction, FlowDirection::Unknown);
        assert!(body.result.is_none());

        c.poll_once(&mut sink, MONO + 2, WALL).expect("tick");
        assert_eq!(kinds(&sink), vec!["net_connect", "net_close"]);
        let close = &sink.events()[1];
        let EventKind::NetClose(body) = &close.kind else {
            panic!("close");
        };
        assert_eq!(body.total_sent, None);
        assert_eq!(body.total_recv, None);
        assert!(close
            .field_evidence
            .get("total_sent")
            .is_some_and(Evidence::is_na));
        assert!(close
            .field_evidence
            .get("total_recv")
            .is_some_and(Evidence::is_na));
    }

    #[test]
    fn unavailable_net_source_is_a_capability_not_a_gap() {
        let mut c = PollCollector::from_sources(
            StaticProcessSource::new([snap(vec![row(10, Some(1))])]),
            StaticConnectionSource::unavailable(NaReason::CollectorUnavailable),
            PollConfig::standard(),
        );
        let net = c.capabilities().get(CapabilityCategory::Net);
        assert!(net.evidence.is_na());
        let mut sink = VecSink::with_capacity(4);
        c.start_at(
            &Scope::attach([uid_of(10)]).expect("root"),
            &mut sink,
            MONO,
            WALL,
        )
        .expect("start");
        c.poll_once(&mut sink, MONO + 1, WALL).expect("tick");
        assert!(sink.events().is_empty());
        assert!(c.capabilities().get(CapabilityCategory::Proc).evidence == Evidence::S);
        assert!(c
            .capabilities()
            .get(CapabilityCategory::File)
            .evidence
            .is_na());
        assert!(c
            .capabilities()
            .get(CapabilityCategory::Dns)
            .evidence
            .is_na());
        assert!(c
            .capabilities()
            .get(CapabilityCategory::Url)
            .evidence
            .is_na());
    }

    #[test]
    fn connection_without_pid_is_a_gap_not_a_flow() {
        let procs = snap(vec![row(10, Some(1))]);
        let mut orphan = flow(10, 1, 2);
        orphan.pid = None;
        let mut c = collector(
            vec![procs.clone(), procs],
            vec![
                ConnectionSnapshot::default(),
                ConnectionSnapshot::new(vec![orphan]),
            ],
        );
        let mut sink = VecSink::with_capacity(4);
        c.start_at(
            &Scope::attach([uid_of(10)]).expect("root"),
            &mut sink,
            MONO,
            WALL,
        )
        .expect("start");
        c.poll_once(&mut sink, MONO + 1, WALL).expect("tick");
        assert_eq!(kinds(&sink), vec!["gap"]);
        let gap_event = &sink.events()[0];
        assert_eq!(gap_event.evidence, Evidence::E1);
        assert_eq!(gap_event.source.as_str(), "poll/netstat");
        let EventKind::Gap(gap) = &gap_event.kind else {
            panic!("gap");
        };
        assert_eq!(gap.gap_kind, GapKind::AttributionUnknown);
        assert_eq!(gap.affects, vec!["net".to_owned()]);
        assert_eq!(gap.count, Some(1));
        assert_eq!(gap.detail.as_deref(), Some("pid"));
        assert!(!sink
            .events()
            .iter()
            .any(|event| event.kind.kind_name() == "net_connect"));
    }

    #[test]
    fn snapshot_returns_the_subtree_and_skips_rows_without_a_parent() {
        let mut c = collector(
            vec![snap(vec![
                row(10, Some(1)),
                row(11, Some(10)),
                ProcessRow::bare(12, None, ProcessStartTime::UnixSeconds(1_700_000_000)),
                row(20, Some(2)),
            ])],
            vec![ConnectionSnapshot::default()],
        );
        let starts = c.snapshot(10);
        assert_eq!(starts.len(), 2);
        assert!(starts.iter().all(|start| start.how == StartHow::Snapshot));
        assert!(starts.iter().any(|start| start.ppid == 1));
        assert!(starts.iter().any(|start| start.ppid == 10));
    }

    #[test]
    fn full_sink_returns_the_event_as_a_counted_gap() {
        let first = snap(vec![row(10, Some(1))]);
        let second = snap(vec![row(10, Some(1)), row(11, Some(10))]);
        let mut c = collector(
            vec![first, second],
            vec![ConnectionSnapshot::default(), ConnectionSnapshot::default()],
        );
        let mut sink = VecSink::with_capacity(1);
        sink.hold_ordinary(0);
        c.start_at(
            &Scope::attach([uid_of(10)]).expect("root"),
            &mut sink,
            MONO,
            WALL,
        )
        .expect("start");
        c.poll_once(&mut sink, MONO + 1, WALL).expect("gap fits");
        assert_eq!(kinds(&sink), vec!["gap"]);
        let EventKind::Gap(gap) = &sink.events()[0].kind else {
            panic!("gap");
        };
        assert_eq!(gap.gap_kind, GapKind::Dropped);
        assert_eq!(c.health().undelivered, 1);
    }

    #[test]
    fn zero_interval_is_rejected() {
        let err = PollConfig::new(Duration::from_millis(0), DEFAULT_CONN_INTERVAL);
        assert_eq!(err, Err(PollError::ZeroInterval));
    }

    #[test]
    fn permission_failure_is_a_permission_gap() {
        let mut c = PollCollector::from_sources(
            StaticProcessSource::new([snap(vec![row(10, Some(1))])]),
            FailingConnectionSource {
                failure: SourceFailure::Permission,
            },
            PollConfig::standard(),
        );
        let mut sink = VecSink::with_capacity(4);
        c.start_at(
            &Scope::attach([uid_of(10)]).expect("root"),
            &mut sink,
            MONO,
            WALL,
        )
        .expect("start");
        assert_eq!(kinds(&sink), vec!["gap"]);
        let EventKind::Gap(gap) = &sink.events()[0].kind else {
            panic!("gap");
        };
        assert_eq!(gap.gap_kind, GapKind::Permission);
        assert_eq!(gap.affects, vec!["net".to_owned()]);
    }

    #[test]
    fn diff_ignores_a_process_that_lived_between_samples() {
        let before = snap(vec![row(10, Some(1))]);
        let after = snap(vec![row(10, Some(1))]);
        let deltas = crate::diff::diff_processes(&before, &after);
        assert!(deltas.is_empty());
    }
}
