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
//! over the same boot id and the same start-time seconds `sysinfo` reports
//! (`btime + starttime/clk_tck`), so the collector's own lookup matches.
//!
//! The first `start_at` is a baseline and emits nothing for processes already
//! running. Later `poll_once` calls emit starts and exits that appeared between
//! samples, at evidence S. A failed sample is the collector's own gap (E1).
//!
//! [`PollCollector::snapshot`] is not the live path. It returns [`ProcessStart`]
//! without the pid or the [`ProcUid`], and it omits rows that have no parent
//! or no start time without a gap. `start_at` plus `poll_once` keep both.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
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
    DnsRow, GapRow, NetFlowBucketRow, NetFlowRow, ProcessRow, RecordSink, SessionRow, SqliteSink,
    Store, WriteBatch,
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

/// Linux `CLK_TCK`. `sysconf(_SC_CLK_TCK)` needs `unsafe`, which this crate
/// forbids. 100 is the value `sysinfo` uses when `sysconf` fails, and it is
/// the value Linux ships. A kernel built with a different tick rate would
/// hash a different uid; the attach would then not resolve and the collector
/// would not keep scanning. That failure is visible (no process rows), not a
/// guessed pid.
const LINUX_CLK_TCK: u64 = 100;

/// `snapshot` walks this pid and its descendants. Pid 1 is init.
const SAMPLE_ROOT_PID: u32 = 1;

const PROC_SOURCE: &str = "poll/sysinfo";

/// One process read from `/proc`, enough to pair with a `ProcessStart`.
struct ProcFact {
    pid: u32,
    ppid: u32,
    /// Unix start seconds, the same unit `ProcessStart.start_time_ns` is built from.
    start_secs: u64,
    uid: ProcUid,
}

/// Host poll collector and the session it writes.
///
/// `HostProcessSource` and `HostConnectionSource` are named only so this
/// struct can hold the value [`PollCollector::with_host`] returns. The
/// foreground loop calls [`HostSampler::tick`]; there is no sampler thread.
pub struct HostSampler {
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
}

impl HostSampler {
    /// Build the collector. Does not read the process table.
    pub fn new(db_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            collector: PollCollector::with_host(PollConfig::standard()),
            db_path: db_path.into(),
            session_written: false,
            started: false,
            seen_pids: BTreeSet::new(),
            seq: 0,
            pending_store_failure: false,
            mono_ns: 1,
        }
    }

    /// Attach to pid 1 and take the baseline.
    ///
    /// A missing boot id or a missing start time does not start the collector.
    /// Inventing either would attach to a process that is not pid 1.
    pub fn start(&mut self) {
        let Some(uid) = init_proc_uid() else {
            tracing::warn!("poll sampler not started: pid 1 identity unavailable");
            return;
        };
        let Ok(scope) = Scope::attach([uid]) else {
            tracing::warn!("poll sampler not started: attach scope rejected");
            return;
        };
        let mut sink = VecSink::with_capacity(SINK_CAPACITY);
        let wall_ns = wall_now_ns();
        // `start_at` is the baseline. It does not emit the processes already
        // running. `snapshot` does: it clears the restrict list, refreshes
        // every process, and returns pid 1 plus its descendants as
        // `StartHow::Snapshot` at evidence S. `ProcessStart` has no pid and
        // no `ProcUid`, so the rows are paired with `/proc` below.
        let starts = self.collector.snapshot(SAMPLE_ROOT_PID);
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
                }
            }
            Err(err) => {
                // Display omits event payloads. It does not include argv.
                tracing::warn!(error = %err, "poll collector start failed");
            }
        }
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
        let table = proc_table();
        let mut used = BTreeSet::new();
        let mut events = Vec::new();
        let mut unmatched = 0_u64;
        // `snapshot` drops a row whose ppid sysinfo reported as absent. Pid 1's
        // parent is 0, and sysinfo stores that as `None`, so init never comes
        // back. The row is still in `table`. It is added here, evidence S,
        // with no parent uid (not observed as a ProcUid) and ppid 0, which is
        // the ppid `/proc/1/stat` reported.
        if let Some(init) = table.iter().find(|row| row.pid == SAMPLE_ROOT_PID) {
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
        let start_ns = i64::try_from(row.start_secs.saturating_mul(1_000_000_000)).ok()?;
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
        let mut event = RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns: self.mono_ns,
            ts_wall_ns: wall_ns,
            session_id: Some(SessionId(u64::try_from(SESSION_DB_ID).unwrap_or(1))),
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
            session_id: Some(SessionId(u64::try_from(SESSION_DB_ID).unwrap_or(1))),
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
            session_id: Some(SessionId(1)),
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
        let mut batch = map_events(events, self.mono_ns);
        let from_output = map_output(&output, self.mono_ns);
        batch.processes.extend(from_output.processes);
        batch.net_flows.extend(from_output.net_flows);
        batch.net_flow_buckets.extend(from_output.net_flow_buckets);
        batch.dns.extend(from_output.dns);
        batch.gaps.extend(from_output.gaps);
        if !self.session_written {
            batch.sessions.insert(0, session_row(wall_ns));
        }
        if self.pending_store_failure {
            batch.gaps.push(store_failure_gap(wall_ns));
            self.pending_store_failure = false;
        }
        if batch_is_empty(&batch) {
            return Ok(());
        }
        let mut store = Store::open(&self.db_path).map_err(store_io)?;
        let mut writer = SqliteSink::new(&mut store).map_err(store_io)?;
        match writer.write_batch(&batch) {
            Ok(()) => {
                if !batch.sessions.is_empty() {
                    self.session_written = true;
                }
                Ok(())
            }
            Err(_err) => {
                // `_err` can name a filesystem path. The log line stays fixed.
                self.pending_store_failure = true;
                Err(io::Error::other("store_failure"))
            }
        }
    }
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

fn batch_is_empty(batch: &WriteBatch) -> bool {
    batch.sessions.is_empty()
        && batch.processes.is_empty()
        && batch.net_flows.is_empty()
        && batch.net_flow_buckets.is_empty()
        && batch.dns.is_empty()
        && batch.gaps.is_empty()
}

fn store_io(_err: aw_store::StoreError) -> io::Error {
    io::Error::other("store_failure")
}

/// [`ProcUid`] of pid 1, hashed the way the poll collector hashes a row.
///
/// `None` when the boot id or the start time cannot be read. Not a zero hash.
/// Live processes under pid 1, keyed the same way the poll collector keys them.
fn proc_table() -> Vec<ProcFact> {
    #[cfg(target_os = "linux")]
    {
        let Some(boot) = read_boot_id() else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        let Ok(entries) = fs::read_dir("/proc") else {
            return Vec::new();
        };
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Some(start_secs) = read_pid_start_secs(pid) else {
                continue;
            };
            let Some(ppid) = read_ppid(pid) else {
                continue;
            };
            let Some(identity) =
                ProcessIdentity::from_parts(&boot, pid, start_secs, StartTimeUnit::Seconds)
            else {
                continue;
            };
            rows.push(ProcFact {
                pid,
                ppid,
                start_secs,
                uid: identity.uid,
            });
        }
        rows
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// Pair `start` with the unused `/proc` row that has the same parent and start.
fn find_proc<'a>(
    table: &'a [ProcFact],
    start: &ProcessStart,
    used: &BTreeSet<u32>,
) -> Option<&'a ProcFact> {
    let start_secs = u64::try_from(start.start_time_ns).ok()? / 1_000_000_000;
    table.iter().find(|row| {
        !used.contains(&row.pid) && row.ppid == start.ppid && row.start_secs == start_secs
    })
}

#[cfg(target_os = "linux")]
fn read_ppid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1.trim_start();
    // Field 4 is ppid, the second token after `)`.
    rest.split_whitespace().nth(1)?.parse().ok()
}

fn init_proc_uid() -> Option<ProcUid> {
    let boot = read_boot_id()?;
    let start_secs = read_pid_start_secs(1)?;
    ProcessIdentity::from_parts(&boot, 1, start_secs, StartTimeUnit::Seconds).map(|id| id.uid)
}

fn read_boot_id() -> Option<Vec<u8>> {
    // Same file the poll collector reads on Linux (`host.rs`). Other targets
    // take the boot id from `sysinfo`, which this crate does not link. A
    // made-up boot id would not match the collector's hash, so the attach
    // would never resolve. Refuse instead.
    #[cfg(target_os = "linux")]
    {
        let text = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.as_bytes().to_vec())
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Unix start seconds of `pid`, matching `sysinfo`'s Linux process start:
/// `/proc/stat` `btime` plus `/proc/<pid>/stat` field 22 divided by the tick.
fn read_pid_start_secs(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let ticks = stat_start_ticks(&stat)?;
        let btime = read_btime()?;
        if LINUX_CLK_TCK == 0 {
            return None;
        }
        Some(btime.saturating_add(ticks / LINUX_CLK_TCK))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Field 22 (`starttime`) of `/proc/pid/stat`.
///
/// The command is wrapped in parentheses and may contain spaces and
/// parentheses, so the fields after it begin at the last `)`.
#[cfg(target_os = "linux")]
fn stat_start_ticks(stat: &str) -> Option<u64> {
    let rest = stat.rsplit_once(')')?.1.trim_start();
    // Field 3 is the state, the first token after `)`. starttime is field 22,
    // which is index 19 of what remains.
    let field = rest.split_whitespace().nth(19)?;
    field.parse().ok()
}

#[cfg(target_os = "linux")]
fn read_btime() -> Option<u64> {
    let text = fs::read_to_string("/proc/stat").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("btime ") {
            return rest.trim().parse().ok();
        }
    }
    None
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

fn current_user_id() -> String {
    #[cfg(unix)]
    {
        unix_uid_string()
    }
    #[cfg(not(unix))]
    {
        // Not a user name. The column is `NOT NULL`.
        "daemon".to_owned()
    }
}

#[cfg(unix)]
fn unix_uid_string() -> String {
    // Numeric uid of this process, from the owner of `/proc/self`. Not a name.
    #[cfg(target_os = "linux")]
    {
        if let Ok(meta) = fs::metadata("/proc/self") {
            use std::os::unix::fs::MetadataExt;
            return meta.uid().to_string();
        }
    }
    "daemon".to_owned()
}

/// One `processes` row per `ProcessStart` / `ProcessExit` that carried a [`ProcRef`].
///
/// Depth is the parent walk. A start whose parent uid is set but not in this
/// batch is skipped and counted, not stored at depth 0. Evidence stays the
/// event's evidence.
fn map_events(events: &[aw_core::RawEvent], now_ns: u64) -> WriteBatch {
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
                    start_ns: u64::try_from(start.start_time_ns).unwrap_or(event.ts_mono_ns),
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
                    existing.exit_ns = Some(event.ts_mono_ns);
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
                        start_ns: event.ts_mono_ns,
                        exit_ns: Some(event.ts_mono_ns),
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

fn map_output(output: &Output, now_ns: u64) -> WriteBatch {
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
        batch.gaps.push(gap_row(gap));
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

fn gap_row(gap: &GapRec) -> GapRow {
    GapRow {
        id: None,
        session_id: gap
            .session_id
            .and_then(|SessionId(id)| i64::try_from(id).ok())
            .or(Some(SESSION_DB_ID)),
        collector: gap.collector.as_str().to_owned(),
        kind: gaps::gap_kind_name(gap.gap_kind).to_owned(),
        affects: json_string_array(&gap.affects),
        from_ns: i64::try_from(gap.from_mono_ns).unwrap_or(i64::MAX),
        to_ns: i64::try_from(gap.to_mono_ns).unwrap_or(i64::MAX),
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

fn depth_gap(now_ns: u64, count: u64) -> GapRow {
    let ns = i64::try_from(now_ns).unwrap_or(i64::MAX);
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
}
