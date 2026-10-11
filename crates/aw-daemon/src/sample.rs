//! Foreground poll sampler.
//!
//! One [`PollCollector::with_host`] samples the host. Each tick's events go
//! through [`Pipeline::replay`]. Records are written to `data_dir/agentwatch.db`,
//! the file [`crate::api::StoreQuery`] already opens.
//!
//! Scope. [`Scope`] has no "every process" variant. [`Scope::Launch`] keeps the
//! token as text and sets `restrict` to an empty pid list, which refreshes
//! nothing (`host.rs`: `Some([])` does not scan). [`Scope::attach`] of an
//! unresolved root does one full-table refresh (`set_restrict(None)`), turns
//! the [`ProcUid`] into a pid, then keeps that pid and its children. This
//! sampler attaches to pid 1. Pid 1 is init; the children are the processes
//! the host source returns. The [`ProcUid`] is `ProcessIdentity::from_parts`
//! over the boot id, pid, and the `/proc` start time rounded down to seconds.
//! Stored process start times remain precise (`btime_ns + starttime * 1e9 / clk_tck`).
//!
//! The first `start_at` is a baseline and emits nothing for processes already
//! running. Later `poll_once` calls emit starts and exits that appeared between
//! samples, at evidence S. A failed sample is the collector's own gap (E1).
//!
//! [`PollCollector::snapshot`] is not the live path. It returns [`ProcessStart`]
//! without the pid or the [`ProcUid`], and it omits rows that have no parent
//! or no start time without a gap. `start_at` plus `poll_once` keep both.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aw_collector_poll::{PollCollector, PollConfig};
use aw_core::proc::{ProcessIdentity, StartTimeUnit};
use aw_core::{
    Collector, EventKind, Evidence, Gap, GapKind, NaReason, ProcRef, ProcUid, ProcessStart,
    RawEvent, RawEventParts, Scope, SessionId, Source, StartHow, VecSink,
};
use aw_pipeline::gaps::{self, DEPTH_UNOBSERVED_DETAIL, STORE_FAILURE_DETAIL};
use aw_pipeline::{GapRec, NetFlowRec, Output, Pipeline, PipelineConfig, ProcessRec};
use aw_store::{
    DnsRow, GapRow, NetFlowBucketRow, NetFlowRow, ProcessImageRow, ProcessRow, RecordSink,
    SessionRow, SqliteSink, Store, WriteBatch,
};

/// Public id of the one daemon-wide sample session. Stable for the process.
const SESSION_PUBLIC_ID: &str = "daemon-sample";

/// `sessions.id` for that session. Not a pid.
const SESSION_DB_ID: i64 = 1;

/// How often a sample is due. The stop-file loop sleeps less than this.
const SAMPLE_EVERY: Duration = Duration::from_millis(250);

/// Bound on events kept from one tick. A full sink becomes a gap inside the
/// collector; this process does not drop the rest quietly.
const SINK_CAPACITY: usize = 8_192;

/// `snapshot` walks this pid and its descendants. Pid 1 is init.
const SAMPLE_ROOT_PID: u32 = 1;

const PROC_SOURCE: &str = "poll/sysinfo";

/// One process read from `/proc`, enough to pair with a `ProcessStart`.
struct ProcFact {
    pid: u32,
    ppid: u32,
    /// Unix start time in nanoseconds, as reported by `/proc`.
    start_ns: u64,
    uid: ProcUid,
}

/// Root identity captured by `/adopt` while the Unix pipe gate still holds the
/// child before its real program can exec. It is only a sampling-level hint:
/// executable path, argv, cwd, and OS user were not sampled and remain NA.
#[derive(Debug, Clone)]
pub(crate) struct RootHint {
    /// Process id supplied to `/adopt`.
    pub(crate) pid: u32,
    /// Parent pid read from `/proc/<pid>/stat`.
    pub(crate) ppid: u32,
    /// Unix start time in nanoseconds, captured together with the adopted pid.
    pub(crate) start_ns: u64,
    /// Stable process identity for this boot / pid / start time.
    pub(crate) uid: ProcUid,
    /// Basename of the session argv[0], not a sampled executable path.
    pub(crate) name: Option<String>,
}

/// Which session a sampler writes and which process subtree it watches.
///
/// The daemon-wide sample is [`SampleTarget::daemon`]: session 1, rooted at
/// pid 1. `POST /sessions` (attach) and `/sessions/{sid}/adopt` (run) build
/// one per watched root ([`crate::watch`]).
#[derive(Debug, Clone)]
pub struct SampleTarget {
    /// `sessions.id`.
    pub db_id: i64,
    /// `sessions.public_id`.
    pub public_id: String,
    /// `sessions.name`.
    pub name: Option<String>,
    /// `attach` or `launch`.
    pub mode: &'static str,
    /// Root of the watched subtree.
    pub root_pid: u32,
    /// `sessions.user_id`.
    pub user_id: String,
    /// `sessions.argv` as a JSON array, already redacted. `None` when not given.
    pub argv_json: Option<String>,
    /// `sessions.agent`.
    pub agent: Option<String>,
    /// Write the `sessions` row on the first batch. `false` when the route
    /// already inserted it.
    pub write_session_row: bool,
    /// Identity captured at adoption. It makes a root that exits before the
    /// first poll recordable without pretending the missing fields were seen.
    pub root_hint: Option<RootHint>,
}

impl SampleTarget {
    /// The daemon-wide attach sample (pid 1, session 1).
    pub fn daemon() -> Self {
        Self {
            db_id: SESSION_DB_ID,
            public_id: SESSION_PUBLIC_ID.to_owned(),
            name: Some("daemon-wide attach sample".to_owned()),
            mode: "attach",
            root_pid: SAMPLE_ROOT_PID,
            user_id: current_user_id(),
            argv_json: None,
            agent: None,
            write_session_row: true,
            root_hint: None,
        }
    }

    /// The `sessions` row for this target.
    pub fn session_row(&self, started_ns: i64) -> SessionRow {
        let mut row = session_row(started_ns);
        row.id = self.db_id;
        row.public_id.clone_from(&self.public_id);
        row.name.clone_from(&self.name);
        row.mode = self.mode.to_owned();
        row.user_id.clone_from(&self.user_id);
        row.root_proc_uid = self
            .root_hint
            .as_ref()
            .map(|hint| i64::from_ne_bytes(hint.uid.0.to_ne_bytes()));
        row.argv.clone_from(&self.argv_json);
        row.agent.clone_from(&self.agent);
        row
    }
}

/// Host poll collector and the session it writes.
///
/// `HostProcessSource` and `HostConnectionSource` are named only so this
/// struct can hold the value [`PollCollector::with_host`] returns. The
/// foreground loop calls [`HostSampler::tick`]; there is no sampler thread.
pub struct HostSampler {
    target: SampleTarget,
    collector: PollCollector<
        aw_collector_poll::HostProcessSource,
        aw_collector_poll::HostConnectionSource,
    >,
    db_path: std::path::PathBuf,
    session_written: bool,
    started: bool,
    /// Pids returned by the last `snapshot`. A pid that disappears between
    /// snapshots has no exit event on that path, so the next tick counts it
    /// as a gap instead of inventing an exit code.
    seen_pids: BTreeSet<u32>,
    seq: u64,
    /// The previous write failed. The next batch carries one store_failure gap.
    pending_store_failure: bool,
    /// Monotonic nanoseconds handed to the collector. Not a wall clock.
    mono_ns: u64,
    /// Processes whose executable path is already in `process_images`. One
    /// image row per process per run; the store also ignores a repeat.
    imaged: BTreeSet<u64>,
    /// Identity of the root at `start`, for [`Self::root_alive`].
    root_uid: Option<ProcUid>,
    /// Wall time of the last sample that was taken and stored.
    last_sample_ns: Option<i64>,
}

impl HostSampler {
    /// Build the collector for the daemon-wide sample. Does not read the
    /// process table.
    pub fn new(db_path: impl Into<std::path::PathBuf>) -> Self {
        Self::for_target(db_path, SampleTarget::daemon())
    }

    /// Build the collector for `target`. Does not read the process table.
    pub fn for_target(db_path: impl Into<std::path::PathBuf>, target: SampleTarget) -> Self {
        Self {
            session_written: !target.write_session_row,
            target,
            collector: PollCollector::with_host(PollConfig::standard()),
            db_path: db_path.into(),
            started: false,
            seen_pids: BTreeSet::new(),
            seq: 0,
            pending_store_failure: false,
            mono_ns: 1,
            imaged: BTreeSet::new(),
            root_uid: None,
            last_sample_ns: None,
        }
    }

    /// Attach to the target's root pid and take the baseline.
    ///
    /// A missing boot id or a missing start time does not start the collector.
    /// Inventing either would attach to a different process. Returns whether
    /// the collector started.
    pub fn start(&mut self) -> bool {
        // A database from an earlier run already holds the session row.
        // Inserting it again hit the primary key and failed every batch. A
        // session the user stopped stays stopped: sampling it again would make
        // the UI's 「已停止」 untrue.
        match sample_session_state(&self.db_path, self.target.db_id) {
            SampleSessionState::Ended => {
                tracing::info!("poll sampler not started: the session was stopped");
                return false;
            }
            SampleSessionState::Active => self.session_written = true,
            SampleSessionState::Absent => {}
        }
        let Some(uid) = proc_uid_of(self.target.root_pid) else {
            if process_is_gone(self.target.root_pid) {
                tracing::debug!(
                    pid = self.target.root_pid,
                    "program already exited, skipping sampling"
                );
            } else {
                tracing::warn!(
                    pid = self.target.root_pid,
                    "poll sampler not started: root process identity unavailable"
                );
            }
            return false;
        };
        if self
            .target
            .root_hint
            .as_ref()
            .is_some_and(|hint| hint.uid != uid)
        {
            tracing::warn!(
                pid = self.target.root_pid,
                "poll sampler not started: root process identity changed"
            );
            return false;
        }
        self.root_uid = Some(uid);
        let Ok(scope) = Scope::attach([uid]) else {
            tracing::warn!("poll sampler not started: attach scope rejected");
            return false;
        };
        let mut sink = VecSink::with_capacity(SINK_CAPACITY);
        let wall_ns = wall_now_ns();
        // `start_at` is the baseline. It does not emit the processes already
        // running. `snapshot` does: it clears the restrict list, refreshes
        // every process, and returns pid 1 plus its descendants as
        // `StartHow::Snapshot` at evidence S. `ProcessStart` has no pid and
        // no `ProcUid`, so the rows are paired with `/proc` below.
        let starts = self.collector.snapshot(self.target.root_pid);
        match self
            .collector
            .start_at(&scope, &mut sink, self.mono_ns, wall_ns)
        {
            Ok(()) => {
                self.started = true;
                let mut events = self.events_from_snapshot(&starts, wall_ns);
                events.extend(sink.events().iter().cloned());
                if let Err(err) = self.persist(&events, wall_ns) {
                    tracing::warn!(error = %err, "poll baseline write failed");
                    self.pending_store_failure = true;
                } else {
                    self.last_sample_ns = Some(wall_ns);
                }
            }
            Err(err) => {
                // Display omits event payloads. It does not include argv.
                tracing::warn!(error = %err, "poll collector start failed");
            }
        }
        self.started
    }

    /// Persist the adopted root from the synchronous hint if it disappeared
    /// before this sampler could start. The process row goes through the same
    /// event-to-batch path as an ordinary snapshot, so its evidence and NA
    /// fields remain honest.
    pub fn persist_gone_root_hint(&mut self) -> bool {
        // A live process with this identity failed for some other reason;
        // do not replace a real sampler with a synthetic snapshot in that
        // case. A reused pid is also not the adopted root.
        if self
            .target
            .root_hint
            .as_ref()
            .is_some_and(|hint| proc_uid_of(hint.pid) == Some(hint.uid))
        {
            return false;
        }
        self.persist_root_hint()
    }

    /// Write the adopted root's row from the identity `/adopt` captured,
    /// before the first poll: a root that exits before (or between) polls is
    /// still one process with its exit code, never zero processes. The
    /// sampler's own row for the same process is the same id (same pid and
    /// start), so a later poll updates it rather than adding a second.
    pub fn persist_root_hint(&mut self) -> bool {
        let Some(hint) = self.target.root_hint.clone() else {
            return false;
        };
        if sample_session_state(&self.db_path, self.target.db_id) == SampleSessionState::Ended {
            return false;
        }
        let Some(start_ns) = i64::try_from(hint.start_ns).ok() else {
            return false;
        };
        let wall_ns = wall_now_ns();
        let start = ProcessStart::new(
            hint.ppid,
            None,
            start_ns,
            hint.name,
            None,
            None,
            None,
            StartHow::Snapshot,
            None,
            None,
        );
        let fact = ProcFact {
            pid: hint.pid,
            ppid: hint.ppid,
            start_ns: hint.start_ns,
            uid: hint.uid,
        };
        let Some(event) = self.start_event(&start, &fact, wall_ns) else {
            return false;
        };
        match self.persist(&[event], wall_ns) {
            Ok(()) => {
                self.last_sample_ns = Some(wall_ns);
                true
            }
            Err(err) => {
                tracing::warn!(error = %err, "poll root hint write failed");
                self.pending_store_failure = true;
                false
            }
        }
    }

    /// Whether the root process is still the one this sampler attached to:
    /// same pid and same start time. A reused pid is not the same process.
    pub fn root_alive(&self) -> bool {
        proc_uid_of(self.target.root_pid).is_some_and(|uid| Some(uid) == self.root_uid)
    }

    /// Whether the collector is started (sampling on each tick).
    pub fn running(&self) -> bool {
        self.started
    }

    /// Wall time of the last stored sample, Unix nanoseconds.
    pub fn last_sample_ns(&self) -> Option<i64> {
        self.last_sample_ns
    }

    /// The session this sampler writes.
    pub fn target(&self) -> &SampleTarget {
        &self.target
    }

    /// Take one sample. The foreground loop decides when this is due.
    pub fn tick(&mut self) {
        if !self.started {
            return;
        }
        self.sample_now();
    }

    /// One more sample. Called once during shutdown, before [`stop`](Self::stop).
    pub fn flush(&mut self) {
        if self.started {
            self.sample_now();
        }
    }

    /// Stop emitting. The collector has no thread of its own.
    pub fn stop(&mut self) {
        if self.started {
            let _ = Collector::stop(&mut self.collector);
            self.started = false;
        }
    }

    fn sample_now(&mut self) {
        // `POST /sessions/daemon-sample/stop` only writes `ended_ns`. The
        // sampler kept polling into the stopped session, so the page said
        // 「已停止」 while the process count kept rising. Stop here instead.
        if self.session_written
            && sample_session_state(&self.db_path, self.target.db_id) == SampleSessionState::Ended
        {
            tracing::info!("poll sampler stopped: the sample session was stopped");
            self.stop();
            return;
        }
        self.mono_ns = self.mono_ns.saturating_add(sample_period_ns());
        let wall_ns = wall_now_ns();
        let mut sink = VecSink::with_capacity(SINK_CAPACITY);
        if let Err(err) = self.collector.poll_once(&mut sink, self.mono_ns, wall_ns) {
            tracing::warn!(error = %err, "poll sample failed");
            self.pending_store_failure = true;
            return;
        }
        if let Err(err) = self.persist(sink.events(), wall_ns) {
            tracing::warn!(error = %err, "poll sample write failed");
            self.pending_store_failure = true;
        } else {
            self.last_sample_ns = Some(wall_ns);
        }
    }

    /// Turn `snapshot`'s starts into events the pipeline can replay.
    ///
    /// `ProcessStart` does not carry the pid or the [`ProcUid`]. Both are
    /// required to write a `processes` row. They are read from `/proc` for
    /// pid 1 and its descendants and paired by `(ppid, start_time_ns)`,
    /// which is what `snapshot` kept. A start that matches no `/proc` row
    /// is not given a pid of 0; it is counted in one gap.
    fn events_from_snapshot(&mut self, starts: &[ProcessStart], wall_ns: i64) -> Vec<RawEvent> {
        // Only rows inside the watched subtree may pair. Two processes with the
        // same parent that started in the same second are otherwise
        // indistinguishable by `(ppid, start)`, and a sibling outside the
        // subtree would be recorded under this session.
        let table = subtree_of(proc_table(), self.target.root_pid);
        let mut used = BTreeSet::new();
        let mut events = Vec::new();
        let mut unmatched = 0_u64;
        // `snapshot` drops a row whose ppid sysinfo reported as absent. Pid 1's
        // parent is 0, and sysinfo stores that as `None`, so init never comes
        // back. The row is still in `table`. It is added here, evidence S,
        // with no parent uid (not observed as a ProcUid) and ppid 0, which is
        // the ppid `/proc/1/stat` reported.
        let root_is_init = self.target.root_pid == SAMPLE_ROOT_PID;
        if let Some(init) = table
            .iter()
            .find(|row| root_is_init && row.pid == SAMPLE_ROOT_PID)
        {
            if let Some(event) = self.init_event(init, wall_ns) {
                used.insert(init.pid);
                events.push(event);
            }
        }
        for start in starts {
            let Some(row) = find_proc(&table, start, &used) else {
                unmatched = unmatched.saturating_add(1);
                continue;
            };
            used.insert(row.pid);
            let Some(event) = self.start_event(start, row, wall_ns) else {
                unmatched = unmatched.saturating_add(1);
                continue;
            };
            events.push(event);
        }
        if unmatched > 0 {
            events.push(self.gap_event(
                GapKind::Unsupported,
                "proc",
                Some(unmatched),
                "snapshot row had no pid",
                wall_ns,
            ));
        }
        // First snapshot establishes who was present. A later snapshot that
        // no longer contains a pid is a disappearance, not an exit code.
        self.seen_pids = used;
        events
    }

    /// Pid 1, which `snapshot` cannot return. Fields that were not read stay
    /// `None` and are marked NA. Argv is not read.
    fn init_event(&mut self, row: &ProcFact, wall_ns: i64) -> Option<RawEvent> {
        let start_ns = i64::try_from(row.start_ns).ok()?;
        let start = ProcessStart::new(
            row.ppid,
            None,
            start_ns,
            None,
            None,
            None,
            None,
            StartHow::Snapshot,
            None,
            None,
        );
        self.start_event(&start, row, wall_ns)
    }

    fn start_event(
        &mut self,
        start: &ProcessStart,
        row: &ProcFact,
        wall_ns: i64,
    ) -> Option<RawEvent> {
        let seq = self.next_seq();
        let mut start = start.clone();
        start.start_time_ns = i64::try_from(row.start_ns).ok()?;
        let mut event = RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns: self.mono_ns,
            ts_wall_ns: wall_ns,
            session_id: Some(SessionId(u64::try_from(self.target.db_id).unwrap_or(1))),
            proc: Some(ProcRef {
                uid: row.uid,
                pid: row.pid,
                tid: None,
            }),
            source: Source::new(PROC_SOURCE),
            // The snapshot is a sample. Not raised to E1.
            evidence: Evidence::S,
            kind: EventKind::ProcessStart(start.clone()),
        })
        .ok()?;
        if start.exe.is_none() {
            event.mark_na("exe", NaReason::CollectorUnavailable);
        }
        if start.argv.is_none() {
            event.mark_na("argv", NaReason::CollectorUnavailable);
        }
        if start.cwd.is_none() {
            event.mark_na("cwd", NaReason::CollectorUnavailable);
        }
        if start.user.is_none() {
            event.mark_na("user", NaReason::CollectorUnavailable);
        }
        if start.parent_uid.is_none() {
            event.mark_na("parent_uid", NaReason::CollectorUnavailable);
        }
        event.mark_na("env", NaReason::CollectorUnavailable);
        event.mark_na("signer", NaReason::CollectorUnavailable);
        Some(event)
    }

    fn gap_event(
        &mut self,
        kind: GapKind,
        affects: &str,
        count: Option<u64>,
        detail: &str,
        wall_ns: i64,
    ) -> RawEvent {
        let source = Source::new(PROC_SOURCE);
        let seq = self.next_seq();
        let gap = Gap::new(
            source.clone(),
            kind,
            vec![affects.to_owned()],
            self.mono_ns,
            self.mono_ns,
            count,
            Some(detail.to_owned()),
        );
        RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns: self.mono_ns,
            ts_wall_ns: wall_ns,
            session_id: Some(SessionId(u64::try_from(self.target.db_id).unwrap_or(1))),
            proc: None,
            source,
            evidence: Evidence::E1,
            kind: EventKind::Gap(gap),
        })
        .unwrap_or_else(|_| RawEvent {
            v: aw_core::SCHEMA_VERSION,
            seq,
            ts_mono_ns: self.mono_ns,
            ts_wall_ns: wall_ns,
            session_id: Some(SessionId(u64::try_from(self.target.db_id).unwrap_or(1))),
            proc: None,
            source: Source::new(PROC_SOURCE),
            evidence: Evidence::E1,
            field_evidence: BTreeMap::new(),
            kind: EventKind::Gap(Gap::new(
                Source::new(PROC_SOURCE),
                kind,
                vec![affects.to_owned()],
                self.mono_ns,
                self.mono_ns,
                count,
                Some(detail.to_owned()),
            )),
        })
    }

    fn next_seq(&mut self) -> u64 {
        self.seq = self.seq.saturating_add(1);
        self.seq
    }

    fn persist(&mut self, events: &[aw_core::RawEvent], wall_ns: i64) -> io::Result<()> {
        let output = Pipeline::replay(events.iter().cloned(), PipelineConfig::default());
        // `Pipeline::replay` does not inject a scope root, so an open scope
        // remembers the process and emits no `ProcessRec` (scope.rs
        // `remember_open`). The events were still redacted and counted.
        // Rows are built from the events, not from a second reading of argv.
        let clock = Clock {
            mono_ns: self.mono_ns,
            wall_ns,
        };
        let mut batch = map_events(events, wall_ns);
        batch.process_images = image_rows(events, &self.imaged, wall_ns);
        let from_output = map_output(&output, clock);
        batch.processes.extend(from_output.processes);
        batch.net_flows.extend(from_output.net_flows);
        batch.net_flow_buckets.extend(from_output.net_flow_buckets);
        batch.dns.extend(from_output.dns);
        batch.gaps.extend(from_output.gaps);
        if !self.session_written {
            batch.sessions.insert(0, self.target.session_row(wall_ns));
        }
        if self.pending_store_failure {
            batch.gaps.push(store_failure_gap(wall_ns));
            self.pending_store_failure = false;
        }
        // Rows mapped without a session id fall back to the daemon sample's
        // id; this sampler's rows belong to its own session.
        let own = self.target.db_id;
        if own != SESSION_DB_ID {
            for row in &mut batch.processes {
                row.session_id = own;
            }
            for row in &mut batch.gaps {
                row.session_id = Some(own);
            }
            for row in &mut batch.process_images {
                row.session_id = own;
            }
        }
        if batch_is_empty(&batch) {
            return Ok(());
        }
        let mut store = Store::open(&self.db_path).map_err(|err| store_io(&err))?;
        let mut writer = SqliteSink::new(&mut store).map_err(|err| store_io(&err))?;
        match writer.write_batch(&batch) {
            Ok(()) => {
                if !batch.sessions.is_empty() {
                    self.session_written = true;
                }
                for image in &batch.process_images {
                    self.imaged
                        .insert(u64::from_ne_bytes(image.proc_uid.to_ne_bytes()));
                }
                Ok(())
            }
            Err(err) => {
                // The SQLite reason is what tells a constraint failure from a
                // locked or full disk. It used to be swallowed into a fixed
                // string (BUGS B4). `store_reason` keeps the reason and drops
                // any filesystem path.
                self.pending_store_failure = true;
                Err(store_io(&err))
            }
        }
    }
}

/// Wall-clock nanoseconds of an event, for columns read as unix time
/// (`processes.start_ns` / `exit_ns`). `ts_mono_ns` counts from the sampler's
/// start and is only used when the wall clock was not read (before the epoch).
fn event_wall_ns(event: &aw_core::RawEvent) -> u64 {
    u64::try_from(event.ts_wall_ns)
        .ok()
        .filter(|ns| *ns > 0)
        .unwrap_or(event.ts_mono_ns)
}

fn sample_period_ns() -> u64 {
    u64::try_from(SAMPLE_EVERY.as_nanos()).unwrap_or(250_000_000)
}

fn wall_now_ns() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX),
        // Before the epoch. Not an observed unix time, so it is not 0.
        Err(_) => i64::MIN,
    }
}

/// Whether the sample session row exists and whether it was stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SampleSessionState {
    /// No database or no row yet.
    Absent,
    /// Row present, `ended_ns` NULL.
    Active,
    /// Row present with `ended_ns` set (the user pressed stop).
    Ended,
}

/// Read-only look at the sample session row. A database that cannot be read
/// is `Absent`; the next write reports its own failure.
fn sample_session_state(db_path: &std::path::Path, db_id: i64) -> SampleSessionState {
    if !db_path.is_file() {
        return SampleSessionState::Absent;
    }
    let Ok(conn) =
        rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
    else {
        return SampleSessionState::Absent;
    };
    let row: Result<Option<i64>, rusqlite::Error> = conn.query_row(
        "SELECT ended_ns FROM sessions WHERE id = ?1",
        rusqlite::params![db_id],
        |row| row.get(0),
    );
    match row {
        Ok(Some(_)) => SampleSessionState::Ended,
        Ok(None) => SampleSessionState::Active,
        Err(_) => SampleSessionState::Absent,
    }
}

/// One `process_images` row per started process whose executable path was
/// read. The process page and timeline take the name from this table; without
/// it every process showed as 「?」. Only the path is stored: argv and cwd come
/// from raw events that did not pass the redactor, so they stay NULL (NA).
fn image_rows(events: &[RawEvent], imaged: &BTreeSet<u64>, wall_ns: i64) -> Vec<ProcessImageRow> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for event in events {
        let EventKind::ProcessStart(start) = &event.kind else {
            continue;
        };
        let (Some(proc), Some(exe)) = (event.proc.as_ref(), start.exe.as_ref()) else {
            continue;
        };
        if imaged.contains(&proc.uid.0) || !seen.insert(proc.uid.0) {
            continue;
        }
        let session_id = event
            .session_id
            .and_then(|SessionId(id)| i64::try_from(id).ok())
            .unwrap_or(SESSION_DB_ID);
        rows.push(ProcessImageRow {
            id: None,
            session_id,
            proc_uid: uid_bits(proc.uid),
            seq: 0,
            ts_ns: wall_ns,
            exe: Some(exe.clone()),
            argv: None,
            cwd: None,
            env: None,
            evidence: gaps::evidence_code(&event.evidence).to_owned(),
            field_evidence: Some(
                r#"{"argv":{"level":"NA","reason":"collector_unavailable"},"cwd":{"level":"NA","reason":"collector_unavailable"}}"#
                    .to_owned(),
            ),
            source: event.source.as_str().to_owned(),
        });
    }
    rows
}

fn batch_is_empty(batch: &WriteBatch) -> bool {
    batch.sessions.is_empty()
        && batch.process_images.is_empty()
        && batch.processes.is_empty()
        && batch.net_flows.is_empty()
        && batch.net_flow_buckets.is_empty()
        && batch.dns.is_empty()
        && batch.gaps.is_empty()
}

fn store_io(err: &aw_store::StoreError) -> io::Error {
    io::Error::other(format!("store_failure: {}", store_reason(err)))
}

/// Why a store call failed, for the log. The operation and the SQLite or OS
/// message only. An `Io` error's path is left out; row values are never part of
/// a `StoreError`.
fn store_reason(err: &aw_store::StoreError) -> String {
    match err {
        aw_store::StoreError::Io { op, source, .. } => format!("{op}: {}", source.kind()),
        other => other.to_string(),
    }
}

/// [`ProcUid`] of pid 1, hashed the way the poll collector hashes a row.
///
/// `None` when the boot id or the start time cannot be read. Not a zero hash.
/// Live processes under pid 1, keyed the same way the poll collector keys them.
fn proc_table() -> Vec<ProcFact> {
    aw_platform::platform()
        .sampling_process_table()
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|process| {
            let start_secs = process.start_ns / 1_000_000_000;
            let identity = ProcessIdentity::from_parts(
                &process.boot_id,
                process.key.pid,
                start_secs,
                StartTimeUnit::Seconds,
            )?;
            Some(ProcFact {
                pid: process.key.pid,
                ppid: process.ppid,
                start_ns: process.start_ns,
                uid: identity.uid,
            })
        })
        .collect()
}

/// `table` rows that are `root` or descend from it.
fn subtree_of(table: Vec<ProcFact>, root: u32) -> Vec<ProcFact> {
    let mut keep: BTreeSet<u32> = BTreeSet::from([root]);
    loop {
        let before = keep.len();
        for row in &table {
            if keep.contains(&row.ppid) {
                keep.insert(row.pid);
            }
        }
        if keep.len() == before {
            break;
        }
    }
    table
        .into_iter()
        .filter(|row| keep.contains(&row.pid))
        .collect()
}

/// Pair `start` with the unused `/proc` row that has the same parent and start.
fn find_proc<'a>(
    table: &'a [ProcFact],
    start: &ProcessStart,
    used: &BTreeSet<u32>,
) -> Option<&'a ProcFact> {
    let start_secs = u64::try_from(start.start_time_ns).ok()? / 1_000_000_000;
    table.iter().find(|row| {
        !used.contains(&row.pid)
            && row.ppid == start.ppid
            && row.start_ns / 1_000_000_000 == start_secs
    })
}

/// [`ProcUid`] of `pid`, hashed the way the poll collector hashes a row.
/// `None` when the process is gone or its identity cannot be read.
pub(crate) fn proc_uid_of(pid: u32) -> Option<ProcUid> {
    let process = aw_platform::platform().sampling_process(pid).ok()??;
    proc_uid_from_sampling(&process)
}

/// Whether the platform can confirm that `pid` is no longer present.
///
/// This is deliberately separate from [`proc_uid_of`]: a missing sampling
/// identity can also mean that a still-running process was unreadable. That
/// case remains a warning rather than being mistaken for a normal exit.
fn process_is_gone(pid: u32) -> bool {
    matches!(aw_platform::platform().process_identity(pid), Ok(None))
}

/// Build the poll collector's identity from a precise platform start time.
///
/// The value retained in the row stays precise, but the uid uses seconds:
/// that is the only start-time granularity the poll collector exposes.
fn proc_uid_from_sampling(process: &aw_platform::SamplingProcess) -> Option<ProcUid> {
    let start_secs = process.start_ns / 1_000_000_000;
    ProcessIdentity::from_parts(
        &process.boot_id,
        process.key.pid,
        start_secs,
        StartTimeUnit::Seconds,
    )
    .map(|id| id.uid)
}

/// Capture the adopted root while the caller still holds it behind the pipe
/// gate. `None` means one required `/proc` fact was unavailable; callers keep
/// the adoption valid, but cannot later claim a root snapshot they lack.
pub(crate) fn root_hint(pid: u32, name: Option<String>) -> Option<RootHint> {
    let process = aw_platform::platform().sampling_process(pid).ok()??;
    Some(RootHint {
        pid,
        ppid: process.ppid,
        start_ns: process.start_ns,
        uid: proc_uid_from_sampling(&process)?,
        name,
    })
}

fn session_row(started_ns: i64) -> SessionRow {
    SessionRow {
        id: SESSION_DB_ID,
        public_id: SESSION_PUBLIC_ID.to_owned(),
        name: Some("daemon-wide attach sample".to_owned()),
        mode: "attach".to_owned(),
        agent: None,
        root_proc_uid: None,
        // The daemon was not given a command line to record. Empty is not "none".
        argv: None,
        cwd: None,
        user_id: current_user_id(),
        started_ns,
        ended_ns: None,
        end_reason: None,
        exit_code: None,
        proxy_enabled: 0,
        proxy_port: None,
        platform: std::env::consts::OS.to_owned(),
        os_version: None,
        collectors: r#"["poll"]"#.to_owned(),
        collector_profile: None,
        config_digest: None,
        pinned: 0,
        stats: None,
    }
}

/// User id the daemon-wide sample session is recorded under. The preview UI
/// ticket binds to the same id so a preview browser can see that session.
pub(crate) fn current_user_id() -> String {
    aw_platform::platform()
        .current_user_id()
        // The column is NOT NULL. This is a daemon label, never a guessed
        // caller identity used for launch-as.
        .unwrap_or_else(|| "daemon".to_owned())
}

// Kept for the existing formula-level sampler tests. Production process
// identity reads live exclusively behind `aw_platform::Platform` above.
#[cfg(all(test, target_os = "linux"))]
const LINUX_CLK_TCK: u64 = 100;

#[cfg(all(test, target_os = "linux"))]
fn start_ns_from_ticks(btime_secs: u64, ticks: u64) -> Option<u64> {
    let btime_ns = btime_secs.checked_mul(1_000_000_000)?;
    let elapsed_ns = ticks.checked_mul(1_000_000_000)? / LINUX_CLK_TCK;
    btime_ns.checked_add(elapsed_ns)
}

#[cfg(all(test, target_os = "linux"))]
fn read_boot_id() -> Option<Vec<u8>> {
    Some(
        aw_platform::platform()
            .sampling_process(std::process::id())
            .ok()??
            .boot_id,
    )
}

/// One `processes` row per `ProcessStart` / `ProcessExit` that carried a [`ProcRef`].
///
/// Depth is the parent walk. A start whose parent uid is set but not in this
/// batch is skipped and counted, not stored at depth 0. Evidence stays the
/// event's evidence.
fn map_events(events: &[aw_core::RawEvent], now_ns: i64) -> WriteBatch {
    let mut drafts: Vec<ProcessRec> = Vec::new();
    let mut gaps = Vec::new();
    let mut skipped_pid = 0_u64;
    for event in events {
        match &event.kind {
            EventKind::ProcessStart(start) => {
                let Some(proc) = event.proc.as_ref() else {
                    skipped_pid = skipped_pid.saturating_add(1);
                    continue;
                };
                drafts.push(ProcessRec {
                    session_id: event.session_id,
                    proc_uid: proc.uid,
                    pid: proc.pid,
                    parent_uid: start.parent_uid,
                    // ppid 0 is a real reading (pid 1's parent). It is not
                    // "unknown". Unknown stays None, which this path does not
                    // produce: a start that reached here had a ppid.
                    ppid: Some(start.ppid),
                    depth: None,
                    start_ns: u64::try_from(start.start_time_ns)
                        .unwrap_or_else(|_| event_wall_ns(event)),
                    exit_ns: None,
                    exit_code: None,
                    exit_signal: None,
                    how: start.how,
                    user_id: start.user.as_ref().map(|user| user.id.clone()),
                    signer: start.signer.clone(),
                    evidence: event.evidence.clone(),
                    field_evidence: event.field_evidence.clone(),
                    source: event.source.clone(),
                    agent: None,
                });
            }
            EventKind::ProcessExit(exit) => {
                let Some(proc) = event.proc.as_ref() else {
                    skipped_pid = skipped_pid.saturating_add(1);
                    continue;
                };
                if let Some(existing) = drafts.iter_mut().find(|row| row.proc_uid == proc.uid) {
                    existing.exit_ns = Some(event_wall_ns(event));
                    existing.exit_code = exit.exit_code;
                    existing.exit_signal = exit.signal;
                } else {
                    drafts.push(ProcessRec {
                        session_id: event.session_id,
                        proc_uid: proc.uid,
                        pid: proc.pid,
                        parent_uid: None,
                        ppid: None,
                        depth: None,
                        // Start unknown: the exit instant is the only time
                        // there is. It must be wall time; the monotonic tick
                        // was stored here and showed as 1970-01-01.
                        start_ns: event_wall_ns(event),
                        exit_ns: Some(event_wall_ns(event)),
                        exit_code: exit.exit_code,
                        exit_signal: exit.signal,
                        how: StartHow::Unknown,
                        user_id: None,
                        signer: None,
                        evidence: event.evidence.clone(),
                        field_evidence: event.field_evidence.clone(),
                        source: event.source.clone(),
                        agent: None,
                    });
                }
            }
            EventKind::Gap(_) => {}
            _ => {}
        }
    }
    // Depth is hops of `ppid` inside this batch. `parent_uid` is often missing
    // on a poll snapshot (the parent was not hashed), and treating that as
    // "no parent" would mark every such row as a root. A ppid that is not in
    // the batch is a root of the observed tree: the parent was not returned.
    // A cycle is skipped, not stored as 0.
    let depths = depths_by_pid(&drafts);
    let mut batch = WriteBatch::default();
    let mut skipped_depth = 0_u64;
    for rec in &drafts {
        let depth = depths.get(&rec.pid).copied();
        match process_row(rec, depth) {
            Some(row) => batch.processes.push(row),
            None => skipped_depth = skipped_depth.saturating_add(1),
        }
    }
    if skipped_pid.saturating_add(skipped_depth) > 0 {
        gaps.push(depth_gap(now_ns, skipped_pid.saturating_add(skipped_depth)));
    }
    batch.gaps = gaps;
    batch
}

/// Hops from a row whose `ppid` is not another row's pid.
fn depths_by_pid(rows: &[ProcessRec]) -> BTreeMap<u32, i64> {
    let mut parent: BTreeMap<u32, Option<u32>> = BTreeMap::new();
    for row in rows {
        parent.insert(row.pid, row.ppid);
    }
    let mut out = BTreeMap::new();
    for row in rows {
        if let Some(depth) = walk_pid(&parent, row.pid) {
            out.insert(row.pid, depth);
        }
    }
    out
}

fn walk_pid(parent: &BTreeMap<u32, Option<u32>>, pid: u32) -> Option<i64> {
    let mut depth = 0_i64;
    let mut cursor = pid;
    let mut seen = Vec::new();
    loop {
        if seen.contains(&cursor) {
            return None;
        }
        seen.push(cursor);
        match parent.get(&cursor).copied().flatten() {
            // No ppid, or the parent is not in this batch. This row is a root
            // of what was observed. Depth 0 is that distance, not a stand-in
            // for "unknown".
            None => return Some(depth),
            Some(next) if !parent.contains_key(&next) => return Some(depth),
            Some(next) => {
                depth = depth.saturating_add(1);
                cursor = next;
                if depth > 64 {
                    return None;
                }
            }
        }
    }
}

fn map_output(output: &Output, clock: Clock) -> WriteBatch {
    let now_ns = clock.wall_ns;
    let mut batch = WriteBatch::default();
    let depths = depths_of(&output.processes);
    let mut skipped = 0_u64;
    for rec in &output.processes {
        let depth = rec
            .depth
            .map(i64::from)
            .or_else(|| depths.get(&rec.proc_uid.0).copied());
        match process_row(rec, depth) {
            Some(row) => batch.processes.push(row),
            None => skipped = skipped.saturating_add(1),
        }
    }
    if skipped > 0 {
        batch.gaps.push(depth_gap(now_ns, skipped));
    }
    for rec in &output.net_flows {
        if let Some(row) = flow_row(rec) {
            batch.net_flows.push(row);
        }
    }
    for rec in &output.flow_buckets {
        if let Some(row) = bucket_row(rec) {
            batch.net_flow_buckets.push(row);
        }
    }
    for rec in &output.dns {
        if let Some(row) = dns_row(rec) {
            batch.dns.push(row);
        }
    }
    for gap in &output.gaps {
        batch.gaps.push(gap_row(gap, clock));
    }
    batch
}

/// Hops from a row whose parent is not in this batch.
///
/// A parent uid that is set but missing from the batch is not depth 0. The
/// row is absent from the map and the caller skips it.
fn depths_of(rows: &[ProcessRec]) -> BTreeMap<u64, i64> {
    let mut parent: BTreeMap<u64, Option<u64>> = BTreeMap::new();
    for row in rows {
        parent.insert(row.proc_uid.0, row.parent_uid.map(|uid| uid.0));
    }
    let mut out = BTreeMap::new();
    for row in rows {
        if let Some(depth) = walk_depth(&parent, row.proc_uid.0) {
            out.insert(row.proc_uid.0, depth);
        }
    }
    out
}

fn walk_depth(parent: &BTreeMap<u64, Option<u64>>, uid: u64) -> Option<i64> {
    let mut depth = 0_i64;
    let mut cursor = uid;
    let mut seen = Vec::new();
    loop {
        if seen.contains(&cursor) {
            return None;
        }
        seen.push(cursor);
        match parent.get(&cursor).copied().flatten() {
            None => return Some(depth),
            Some(next) if parent.contains_key(&next) => {
                depth = depth.saturating_add(1);
                cursor = next;
                if depth > 64 {
                    return None;
                }
            }
            Some(_) => return None,
        }
    }
}

fn process_row(proc: &ProcessRec, depth: Option<i64>) -> Option<ProcessRow> {
    let depth = depth?;
    let session_id = match proc.session_id {
        Some(SessionId(id)) => i64::try_from(id).unwrap_or(SESSION_DB_ID),
        // Replay does not assign a session. The row still belongs to the
        // daemon sample session this process opened.
        None => SESSION_DB_ID,
    };
    Some(ProcessRow {
        session_id,
        proc_uid: uid_bits(proc.proc_uid),
        pid: i64::from(proc.pid),
        parent_uid: proc.parent_uid.map(uid_bits),
        ppid: proc.ppid.map(i64::from),
        depth,
        start_ns: i64::try_from(proc.start_ns).unwrap_or(i64::MAX),
        exit_ns: proc.exit_ns.and_then(|ns| i64::try_from(ns).ok()),
        exit_code: proc.exit_code.map(i64::from),
        exit_signal: proc.exit_signal.map(i64::from),
        how: start_how_name(proc.how).to_owned(),
        user_id: proc.user_id.clone(),
        signer: proc.signer.clone(),
        evidence: gaps::evidence_code(&proc.evidence).to_owned(),
        field_evidence: field_evidence_json(&proc.field_evidence),
        source: proc.source.as_str().to_owned(),
        agent: proc.agent.clone(),
    })
}

fn flow_row(flow: &NetFlowRec) -> Option<NetFlowRow> {
    // Required columns. Unknown stays out of the table rather than becoming "".
    let proto = flow.proto.clone()?;
    let direction = flow.direction.clone()?;
    let local_ip = flow.local_ip.clone()?;
    let local_port = flow.local_port?;
    let remote_ip = flow.remote_ip.clone()?;
    let remote_port = flow.remote_port?;
    let proc_uid = flow.proc_uid.map(uid_bits)?;
    let session_id = flow
        .session_id
        .and_then(|SessionId(id)| i64::try_from(id).ok())
        .unwrap_or(SESSION_DB_ID);
    Some(NetFlowRow {
        id: flow
            .flow_id
            .and_then(|id| i64::try_from(id).ok())
            .unwrap_or_else(|| flow_key(flow)),
        session_id,
        proc_uid,
        proto,
        direction,
        local_ip: local_ip.clone(),
        local_port: i64::from(local_port),
        remote_ip: remote_ip.clone(),
        remote_port: i64::from(remote_port),
        domain: flow.domain.clone(),
        domain_source: flow.domain_source.clone(),
        domain_alts: None,
        sni: flow.sni.clone(),
        alpn: None,
        start_ns: i64::try_from(flow.start_ns).unwrap_or(i64::MAX),
        end_ns: flow.end_ns.and_then(|ns| i64::try_from(ns).ok()),
        bytes_up: flow.bytes_up.and_then(|n| i64::try_from(n).ok()),
        bytes_down: flow.bytes_down.and_then(|n| i64::try_from(n).ok()),
        via_proxy: i64::from(flow.via_proxy),
        direct: i64::from(flow.direct),
        // Not observed by the poll collector. The column is `NOT NULL` and the
        // schema default is "not marked", which is what 0 means here. It is
        // not an observation that the flow was absent at attach.
        preexisting: 0,
        is_loopback: i64::from(ip_is_loopback(&local_ip) || ip_is_loopback(&remote_ip)),
        result: None,
        platform_total_up: flow.platform_total_up.and_then(|n| i64::try_from(n).ok()),
        platform_total_down: flow.platform_total_down.and_then(|n| i64::try_from(n).ok()),
        evidence: gaps::evidence_code(&flow.evidence).to_owned(),
        na_reason: gaps::na_reason_code(&flow.evidence).map(str::to_owned),
        field_evidence: field_evidence_json(&flow.field_evidence),
        source: flow.source.as_str().to_owned(),
    })
}

/// Stable upsert key when the pipeline did not assign a flow id.
///
/// The mix is of the tuple text, not a claim about bytes transferred.
fn flow_key(flow: &NetFlowRec) -> i64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let bytes = flow
        .proto
        .as_deref()
        .unwrap_or("")
        .bytes()
        .chain(flow.local_ip.as_deref().unwrap_or("").bytes())
        .chain(flow.remote_ip.as_deref().unwrap_or("").bytes());
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash ^= u64::from(flow.local_port.unwrap_or(0));
    hash ^= u64::from(flow.remote_port.unwrap_or(0)).wrapping_shl(16);
    i64::try_from(hash & 0x7fff_ffff_ffff_ffff).unwrap_or(1)
}

fn ip_is_loopback(ip: &str) -> bool {
    matches!(ip.parse::<IpAddr>(), Ok(addr) if addr.is_loopback())
}

fn bucket_row(bucket: &aw_pipeline::FlowBucketRec) -> Option<NetFlowBucketRow> {
    let (bytes_up, bytes_down) = match (bucket.bytes_up, bucket.bytes_down) {
        (None, None) => return None,
        (Some(up), Some(down)) => (up, down),
        (Some(up), None) => (up, 0),
        (None, Some(down)) => (0, down),
    };
    Some(NetFlowBucketRow {
        flow_id: bucket.flow_id.and_then(|id| i64::try_from(id).ok())?,
        session_id: bucket
            .session_id
            .and_then(|SessionId(id)| i64::try_from(id).ok())
            .unwrap_or(SESSION_DB_ID),
        bucket_ns: i64::try_from(bucket.bucket_ns).unwrap_or(i64::MAX),
        bytes_up: i64::try_from(bytes_up).unwrap_or(i64::MAX),
        bytes_down: i64::try_from(bytes_down).unwrap_or(i64::MAX),
        evidence: gaps::evidence_code(&bucket.evidence).to_owned(),
    })
}

fn dns_row(dns: &aw_pipeline::DnsRec) -> Option<DnsRow> {
    let answers = if dns.answers.is_empty() {
        Some("[]".to_owned())
    } else {
        Some(json_string_array(&dns.answers))
    };
    Some(DnsRow {
        id: None,
        session_id: dns
            .session_id
            .and_then(|SessionId(id)| i64::try_from(id).ok())
            .unwrap_or(SESSION_DB_ID),
        proc_uid: dns.proc_uid.map(uid_bits),
        ts_ns: i64::try_from(dns.ts_ns).unwrap_or(i64::MAX),
        qname: dns.qname.clone(),
        qtype: i64::from(dns.qtype),
        rcode: dns.rcode.map(i64::from),
        answers,
        ttl_min: dns.ttl_min.map(i64::from),
        server: dns.server.clone(),
        evidence: gaps::evidence_code(&dns.evidence).to_owned(),
        source: dns.source.as_str().to_owned(),
    })
}

/// The sampler's two clocks read at the same instant. Collectors stamp gaps
/// with the monotonic tick; the `gaps` table is read as unix time.
#[derive(Debug, Clone, Copy)]
struct Clock {
    mono_ns: u64,
    wall_ns: i64,
}

impl Clock {
    /// Wall time of an earlier (or equal) monotonic tick. Stored as-is, the
    /// tick read as a few seconds after 1970-01-01 on the gaps page.
    fn wall_of(self, mono_ns: u64) -> i64 {
        let back = i64::try_from(self.mono_ns.saturating_sub(mono_ns)).unwrap_or(i64::MAX);
        let ahead = i64::try_from(mono_ns.saturating_sub(self.mono_ns)).unwrap_or(i64::MAX);
        self.wall_ns.saturating_sub(back).saturating_add(ahead)
    }
}

fn gap_row(gap: &GapRec, clock: Clock) -> GapRow {
    // Anchor on the gap event's own pair of clocks when it carries a wall
    // time; otherwise on the sampler's reading for this batch.
    let clock = if gap.ts_wall_ns > 0 {
        Clock {
            mono_ns: gap.ts_mono_ns,
            wall_ns: gap.ts_wall_ns,
        }
    } else {
        clock
    };
    GapRow {
        id: None,
        session_id: gap
            .session_id
            .and_then(|SessionId(id)| i64::try_from(id).ok())
            .or(Some(SESSION_DB_ID)),
        collector: gap.collector.as_str().to_owned(),
        kind: gaps::gap_kind_name(gap.gap_kind).to_owned(),
        affects: json_string_array(&gap.affects),
        from_ns: clock.wall_of(gap.from_mono_ns),
        to_ns: clock.wall_of(gap.to_mono_ns),
        count: gap.count.and_then(|n| i64::try_from(n).ok()),
        detail: gap.detail.clone(),
    }
}

fn store_failure_gap(now_ns: i64) -> GapRow {
    GapRow {
        id: None,
        session_id: Some(SESSION_DB_ID),
        collector: "daemon/poll".to_owned(),
        kind: gaps::gap_kind_name(GapKind::Unknown).to_owned(),
        affects: "[\"store\"]".to_owned(),
        from_ns: now_ns,
        to_ns: now_ns,
        count: None,
        detail: Some(STORE_FAILURE_DETAIL.to_owned()),
    }
}

fn depth_gap(now_ns: i64, count: u64) -> GapRow {
    let ns = now_ns;
    GapRow {
        id: None,
        session_id: Some(SESSION_DB_ID),
        collector: "daemon/poll".to_owned(),
        kind: gaps::gap_kind_name(GapKind::Unknown).to_owned(),
        affects: "[\"process\"]".to_owned(),
        from_ns: ns,
        to_ns: ns,
        count: i64::try_from(count).ok(),
        detail: Some(DEPTH_UNOBSERVED_DETAIL.to_owned()),
    }
}

fn uid_bits(uid: ProcUid) -> i64 {
    i64::from_ne_bytes(uid.0.to_ne_bytes())
}

fn start_how_name(how: StartHow) -> &'static str {
    match how {
        StartHow::Fork => "fork",
        StartHow::Exec => "exec",
        StartHow::Spawn => "spawn",
        StartHow::Snapshot => "snapshot",
        StartHow::Unknown => "unknown",
    }
}

fn field_evidence_json(fields: &BTreeMap<String, Evidence>) -> Option<String> {
    if fields.is_empty() {
        return None;
    }
    let mut parts = Vec::with_capacity(fields.len());
    for (key, evidence) in fields {
        let code = gaps::evidence_code(evidence);
        let value = match gaps::na_reason_code(evidence) {
            Some(reason) => format!("{{\"level\":\"{code}\",\"reason\":\"{reason}\"}}"),
            None => format!("{{\"level\":\"{code}\"}}"),
        };
        parts.push(format!("{}:{value}", json_string(key)));
    }
    Some(format!("{{{}}}", parts.join(",")))
}

fn json_string_array(items: &[String]) -> String {
    let body = items
        .iter()
        .map(|item| json_string(item))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

fn json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod depth_tests {
    use super::depths_by_pid;
    use aw_core::{Evidence, ProcUid, Source, StartHow};
    use aw_pipeline::ProcessRec;

    fn rec(pid: u32, ppid: Option<u32>) -> ProcessRec {
        ProcessRec {
            session_id: None,
            proc_uid: ProcUid(u64::from(pid)),
            pid,
            parent_uid: None,
            ppid,
            depth: None,
            start_ns: 1,
            exit_ns: None,
            exit_code: None,
            exit_signal: None,
            how: StartHow::Snapshot,
            user_id: None,
            signer: None,
            evidence: Evidence::S,
            field_evidence: std::collections::BTreeMap::new(),
            source: Source::new("poll/test"),
            agent: None,
        }
    }

    fn proc_event(seq: u64, pid: u32, kind: aw_core::EventKind) -> aw_core::RawEvent {
        aw_core::RawEvent::try_new(aw_core::RawEventParts {
            seq,
            ts_mono_ns: seq * 1_000,
            ts_wall_ns: 1_700_000_000_000_000_000,
            session_id: Some(aw_core::SessionId(1)),
            proc: Some(aw_core::ProcRef {
                uid: ProcUid(u64::from(pid) + 0x5000),
                pid,
                tid: None,
            }),
            source: Source::new("poll/sysinfo"),
            evidence: Evidence::S,
            kind,
        })
        .expect("event")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_start_time_keeps_tick_precision() {
        let btime = 1_700_000_000;
        let first = super::start_ns_from_ticks(btime, 42_000).expect("first tick");
        let second = super::start_ns_from_ticks(btime, 42_001).expect("second tick");
        assert_eq!(second - first, 1_000_000_000 / super::LINUX_CLK_TCK);
        assert_ne!(first, second);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_hint_and_sampler_share_the_poll_identity_and_precise_start_time() {
        let pid = std::process::id();
        let hint = super::root_hint(pid, None).expect("root hint for this test process");
        let row = super::proc_table()
            .into_iter()
            .find(|row| row.pid == pid)
            .expect("this test process in sampler table");
        let boot = super::read_boot_id().expect("boot id");
        let expected = aw_core::proc::ProcessIdentity::from_parts(
            &boot,
            pid,
            hint.start_ns / 1_000_000_000,
            aw_core::proc::StartTimeUnit::Seconds,
        )
        .expect("poll identity")
        .uid;

        assert_eq!(hint.uid, expected);
        assert_eq!(row.uid, expected);
        assert_eq!(hint.start_ns, row.start_ns);
    }

    /// Gap rows were stored with the collector's monotonic tick, which the
    /// gaps page read as unix time (a few seconds after 1970-01-01).
    #[test]
    fn gap_rows_are_stored_at_wall_time() {
        let wall = 1_700_000_000_000_000_000_i64;
        let gap = aw_pipeline::GapRec {
            seq: 1,
            ts_mono_ns: 10_000_000_000,
            ts_wall_ns: wall,
            session_id: Some(aw_core::SessionId(1)),
            proc: None,
            evidence: Evidence::S,
            field_evidence: std::collections::BTreeMap::new(),
            source: Source::new("poll/sysinfo"),
            collector: Source::new("poll/sysinfo"),
            gap_kind: aw_core::GapKind::Unknown,
            affects: vec!["process".to_owned()],
            from_mono_ns: 8_000_000_000,
            to_mono_ns: 10_000_000_000,
            count: None,
            detail: None,
        };
        let clock = super::Clock {
            mono_ns: 12_000_000_000,
            wall_ns: wall + 2_000_000_000,
        };
        let row = super::gap_row(&gap, clock);
        assert_eq!(row.from_ns, wall - 2_000_000_000);
        assert_eq!(row.to_ns, wall);
        // A gap event without a wall time falls back to the batch's clocks.
        let unstamped = aw_pipeline::GapRec {
            ts_wall_ns: 0,
            ..gap
        };
        let row = super::gap_row(&unstamped, clock);
        assert_eq!(row.from_ns, wall - 2_000_000_000);
        assert_eq!(row.to_ns, wall);
        assert_eq!(clock.wall_of(13_000_000_000), wall + 3_000_000_000);
    }

    /// UI review of #143: an exit whose start was never seen was stored with
    /// the monotonic tick as `start_ns` / `exit_ns`, so the timeline showed
    /// it at 1970-01-01 08:00.
    #[test]
    fn exit_without_a_seen_start_is_stored_at_wall_time() {
        let (dir, db) = temp_db("exit-wall");
        let mut sampler = super::HostSampler::new(&db);
        let exit = proc_event(
            5,
            77,
            aw_core::EventKind::ProcessExit(aw_core::ProcessExit::new(None, None)),
        );
        sampler.persist(&[exit], 1).expect("batch");
        let store = aw_store::Store::open(&db).expect("open");
        let (start_ns, exit_ns): (i64, Option<i64>) = store
            .connection()
            .query_row(
                "SELECT start_ns, exit_ns FROM processes WHERE pid = 77",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("row 77");
        assert_eq!(start_ns, 1_700_000_000_000_000_000);
        assert_eq!(exit_ns, Some(1_700_000_000_000_000_000));
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// BUGS B4: a baseline process's exit arrived in a later tick as a second
    /// `processes` row with the same key. The insert hit the primary key, the
    /// whole batch rolled back, and the log only said `store_failure`.
    #[test]
    fn exit_of_a_baseline_process_is_stored_on_its_row() {
        let dir = std::env::temp_dir().join(format!("aw-sample-exit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let db = dir.join("agentwatch.db");
        let mut sampler = super::HostSampler::new(&db);
        let start = aw_core::ProcessStart::new(
            1,
            None,
            1_700_000_000_000_000_000,
            None,
            None,
            None,
            None,
            StartHow::Snapshot,
            None,
            None,
        );
        let baseline = proc_event(1, 42, aw_core::EventKind::ProcessStart(start));
        sampler.persist(&[baseline], 1).expect("baseline batch");
        // A later tick: the exit, plus an unrelated new process.
        let exit = proc_event(
            2,
            42,
            aw_core::EventKind::ProcessExit(aw_core::ProcessExit::new(Some(0), None)),
        );
        let child = aw_core::ProcessStart::new(
            1,
            None,
            1_700_000_001_000_000_000,
            None,
            None,
            None,
            None,
            StartHow::Spawn,
            None,
            None,
        );
        let newcomer = proc_event(3, 43, aw_core::EventKind::ProcessStart(child));
        sampler
            .persist(&[exit, newcomer], 2)
            .expect("the exit must not fail the batch");
        assert!(!sampler.pending_store_failure);

        let store = aw_store::Store::open(&db).expect("open");
        let exit_ns: Option<i64> = store
            .connection()
            .query_row("SELECT exit_ns FROM processes WHERE pid = 42", [], |row| {
                row.get(0)
            })
            .expect("row 42");
        // Wall time, not the sampler's monotonic tick (UI review: exits and
        // start-unknown processes showed as 01/01 08:00, i.e. 1970).
        assert_eq!(exit_ns, Some(1_700_000_000_000_000_000));
        let count: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM processes", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 2, "the new process in the same batch is stored");
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn store_reason_keeps_the_cause_and_drops_the_path() {
        let err = aw_store::StoreError::Io {
            op: "backup",
            path: Some(std::path::PathBuf::from(
                "/home/someone/secret-dir/agentwatch.db",
            )),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        };
        let reason = super::store_reason(&err);
        assert!(!reason.contains("secret-dir"), "path must not be logged");
        assert!(reason.starts_with("backup: "), "{reason}");
    }

    #[test]
    fn parent_outside_the_batch_is_a_root_and_a_cycle_is_skipped() {
        let rows = vec![
            rec(1, Some(0)),
            rec(20, Some(1)),
            rec(7, Some(8)),
            rec(8, Some(7)),
        ];
        let depths = depths_by_pid(&rows);
        assert_eq!(depths.get(&1).copied(), Some(0));
        assert_eq!(depths.get(&20).copied(), Some(1));
        assert!(!depths.contains_key(&7));
        assert!(!depths.contains_key(&8));
    }

    fn temp_db(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("aw-sample-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let db = dir.join("agentwatch.db");
        (dir, db)
    }

    fn start_with_exe(exe: Option<&str>) -> aw_core::EventKind {
        aw_core::EventKind::ProcessStart(aw_core::ProcessStart::new(
            1,
            None,
            1_700_000_000_000_000_000,
            exe.map(str::to_owned),
            None,
            None,
            None,
            StartHow::Snapshot,
            None,
            None,
        ))
    }

    /// UI review P1-6: every process showed as 「?」 because the sampler wrote
    /// `processes` rows and never a `process_images` row, which is where the
    /// process page and the timeline read the executable name from.
    #[test]
    fn sampler_stores_the_executable_name_once_per_process() {
        let (dir, db) = temp_db("images");
        let mut sampler = super::HostSampler::new(&db);
        let first = proc_event(1, 42, start_with_exe(Some("/usr/bin/bash")));
        let nameless = proc_event(2, 43, start_with_exe(None));
        sampler
            .persist(&[first.clone(), nameless], 1)
            .expect("batch");
        // Same process again in a later batch, and again after a restart on
        // the same database: neither may duplicate nor fail the batch.
        sampler
            .persist(std::slice::from_ref(&first), 2)
            .expect("repeat");
        let mut restarted = super::HostSampler::new(&db);
        restarted.session_written = true;
        restarted.persist(&[first], 3).expect("restart repeat");

        let store = aw_store::Store::open(&db).expect("open");
        let rows: Vec<(i64, Option<String>, Option<String>)> = {
            let mut stmt = store
                .connection()
                .prepare("SELECT seq, exe, argv FROM process_images ORDER BY id")
                .expect("prepare");
            stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .expect("query")
                .collect::<Result<_, _>>()
                .expect("rows")
        };
        assert_eq!(rows, vec![(0, Some("/usr/bin/bash".to_owned()), None)]);
        let tree = aw_store::process_tree(store.connection(), &super::current_user_id(), 1)
            .expect("tree")
            .expect("visible");
        let names: Vec<Option<String>> = flatten(&tree).into_iter().map(|n| n.exe_name).collect();
        assert!(names.contains(&Some("bash".to_owned())), "{names:?}");
        // UI review #6: the name must also be searchable across sessions,
        // with the FTS index and with the instr fallback.
        let fts_on = aw_store::read_fts_mode(store.connection())
            .expect("fts mode")
            .enabled();
        for fts in [fts_on, false] {
            let hits = aw_store::search(
                store.connection(),
                &super::current_user_id(),
                "bash",
                fts,
                None,
                None,
            )
            .expect("search");
            assert_eq!(hits.len(), 1, "fts={fts}: {hits:?}");
            assert_eq!(hits[0].src, "process_images");
            // The hit says what it is and when, not just a row id.
            assert_eq!(hits[0].text.as_deref(), Some("/usr/bin/bash"));
            assert!(hits[0].ts_ns.is_some_and(|ns| ns > 0), "{hits:?}");
            assert_eq!(hits[0].evidence.as_deref(), Some("S"));
        }
        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn flatten(nodes: &[aw_store::ProcessNode]) -> Vec<aw_store::ProcessNode> {
        let mut out = Vec::new();
        for node in nodes {
            out.push(node.clone());
            out.extend(flatten(&node.children));
        }
        out
    }

    /// UI review P1-7: stop wrote `ended_ns` but the sampler kept polling into
    /// the session, so the page said 「已停止」 while the counts kept rising.
    #[test]
    fn a_stopped_sample_session_is_not_sampled_again() {
        let (dir, db) = temp_db("stop");
        let mut sampler = super::HostSampler::new(&db);
        let first = proc_event(1, 42, start_with_exe(Some("/usr/bin/bash")));
        sampler.persist(&[first], 1).expect("baseline");
        assert_eq!(
            super::sample_session_state(&db, 1),
            super::SampleSessionState::Active
        );
        {
            let store = aw_store::Store::open(&db).expect("open");
            aw_store::stop_session(store.connection(), &super::current_user_id(), 1, 5)
                .expect("stop")
                .expect("visible");
        }
        assert_eq!(
            super::sample_session_state(&db, 1),
            super::SampleSessionState::Ended
        );
        // Pretend the collector is running: the next sample must stop it
        // before polling, and a later tick does nothing.
        sampler.started = true;
        sampler.sample_now();
        assert!(!sampler.started, "sampler must stop once the session ended");
        sampler.tick();
        assert!(!sampler.started);

        // A daemon restarted on this database leaves the session stopped.
        let mut restarted = super::HostSampler::new(&db);
        restarted.start();
        assert!(!restarted.started);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
