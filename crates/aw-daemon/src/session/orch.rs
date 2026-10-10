//! Session state machine.
//!
//! Launch (SPIKE-05): `begin_run` prepares a ticket and does not create a
//! process. The CLI creates it suspended, then `adopt` moves it into scope.
//! If `adopt` has not arrived [`ADOPT_TIMEOUT_NS`] after the ticket, `tick`
//! tells the provider to terminate that process and the session fails.
//!
//! Attach: `begin_collect`, then the process-tree snapshot, then a rescan.
//! Snapshot rows are injected as `ProcessStart` with [`StartHow::Snapshot`]
//! and evidence [`Evidence::S`]. A reported start time is copied. A missing
//! one is marked `NA(preexisting)`: the schema field is `i64` and cannot be
//! `None`, and `0` without that mark would mean the epoch.
//!
//! `stop` flushes and releases. It does not terminate the target.
//!
//! [`recover`](SessionOrchestrator::recover) marks every session that had not
//! ended as [`SessionStatus::Interrupted`] and emits one [`GapKind::Restart`]
//! covering the downtime.

use std::collections::BTreeMap;

use aw_core::{
    EventKind, Evidence, Gap, GapKind, ProcRef, ProcUid, ProcessExit, ProcessStart, RawEvent,
    RawEventParts, SessionId, Source, StartHow,
};

use super::provider::{Adopted, LaunchTicket, ProviderError, ScopeProvider, SnapshotProc};
use super::sink::{FanoutSink, SessionSink};

/// How long the CLI has to call `adopt` after `begin_run`. Five seconds.
pub const ADOPT_TIMEOUT_NS: u64 = 5_000_000_000;

const SOURCE: &str = "daemon.session/orchestrator";

/// Why observation stopped. `stop` is a user request; it is not a kill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    /// The root process exited.
    RootExited,
    /// `POST /sessions/{id}/stop`. The target keeps running.
    Stopped,
    /// `--duration` elapsed.
    Duration,
    /// `--until-exit`: the caller's own process exited.
    UntilExit,
    /// The daemon process restarted while this session was still open.
    Interrupted,
    /// Adopt did not arrive within [`ADOPT_TIMEOUT_NS`]. The target was terminated.
    AdoptTimeout,
}

impl EndReason {
    /// Storage `end_reason` text. Not a sentence.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RootExited => "exited",
            Self::Stopped => "stopped",
            Self::Duration => "duration",
            Self::UntilExit => "until_exit",
            Self::Interrupted => "daemon_shutdown",
            Self::AdoptTimeout => "adopt_timeout",
        }
    }
}

/// Lifecycle. `Running` is the only state that accepts events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// Ticket issued; waiting for the CLI to send a pid.
    AwaitingAdopt,
    /// Scope is live.
    Running,
    /// Ended cleanly. `ended_ns` is set.
    Ended,
    /// Ended because the daemon restarted. `ended_ns` is set.
    Interrupted,
    /// Adopt timed out. The provider was asked to terminate the target.
    Failed,
}

impl SessionStatus {
    /// Storage-style label. Not a sentence.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingAdopt => "awaiting_adopt",
            Self::Running => "running",
            Self::Ended => "ended",
            Self::Interrupted => "interrupted",
            Self::Failed => "failed",
        }
    }
}

/// Counts written when a session ends. Absence is `None`, never `0`-as-unknown:
/// these counters are observations this process made, so zero is a real zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    /// `ProcessStart` events injected or accepted for this session.
    pub process_starts: u64,
    /// Other events accepted for this session.
    pub other_events: u64,
    /// Distinct pids the session was watching at end.
    pub watched_pids: u64,
}

/// Durable view of one session. The store is not written here; a later card copies this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Numeric id.
    pub id: SessionId,
    /// `run` or `attach`.
    pub mode: SessionMode,
    /// Current lifecycle.
    pub status: SessionStatus,
    /// Virtual time the session was created.
    pub started_ns: u64,
    /// Virtual time observation stopped. `None` while the session is open.
    pub ended_ns: Option<u64>,
    /// Why it ended. `None` while open.
    pub end_reason: Option<EndReason>,
    /// Written on flush.
    pub summary: Option<SessionSummary>,
    /// Root process, once known.
    pub root: Option<ProcUid>,
    /// Root pid, once known.
    pub root_pid: Option<u32>,
}

/// How the session was opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    /// CLI creates the process; daemon adopts it.
    Run,
    /// Already-running tree.
    Attach,
}

/// `POST /sessions` with `mode=run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    /// Caller identity. Recorded so a later card can enforce "not root".
    /// This orchestrator does not spawn, so the value is stored and not used
    /// to call `CreateProcess` / `posix_spawn`.
    pub caller: String,
    /// Optional cap. `None` means no duration limit.
    pub duration_ns: Option<u64>,
    /// When `Some`, the session ends once `pid` exits (the CLI process).
    pub until_exit: Option<u32>,
}

/// `POST /sessions/{id}/adopt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptRequest {
    /// Process the CLI created suspended.
    pub pid: u32,
    /// Ticket from [`SessionOrchestrator::begin_run`].
    pub ticket: LaunchTicket,
    /// Identity, when the CLI already computed one. `None` lets the provider assign it.
    pub uid: Option<ProcUid>,
}

/// `POST /sessions` with `mode=attach`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachOptions {
    /// Root pid to walk from.
    pub root_pid: u32,
    /// Follow children. Default in the product is `true`; the caller passes it explicitly.
    pub follow_children: bool,
    /// Optional cap.
    pub duration_ns: Option<u64>,
    /// Optional pid whose exit ends the session.
    pub until_exit: Option<u32>,
}

/// Why an orchestration call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// No session with that id.
    NotFound { session: SessionId },
    /// The call does not apply to the current status.
    BadState {
        /// Session.
        session: SessionId,
        /// Status at the time of the call.
        status: SessionStatus,
    },
    /// The ticket does not belong to this session.
    TicketMismatch { session: SessionId },
    /// Adopt arrived with no pid. Zero is not used as a sentinel; this is a missing field.
    MissingPid,
    /// The provider refused.
    Provider(ProviderError),
    /// Building an injected event failed. The message names the kind, not argv.
    Event(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { session } => write!(f, "session {} was not found", session.0),
            Self::BadState { session, status } => {
                write!(f, "session {} is {status:?}", session.0)
            }
            Self::TicketMismatch { session } => {
                write!(f, "ticket does not belong to session {}", session.0)
            }
            Self::MissingPid => f.write_str("adopt requires a pid; 0 is not a missing pid"),
            Self::Provider(err) => write!(f, "{err}"),
            Self::Event(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<ProviderError> for SessionError {
    fn from(err: ProviderError) -> Self {
        Self::Provider(err)
    }
}

struct LiveSession {
    record: SessionRecord,
    ticket: Option<LaunchTicket>,
    /// Virtual time `begin_run` returned. Adopt must arrive by this plus the timeout.
    adopt_deadline_ns: Option<u64>,
    /// Pid staged for termination if adopt times out. `None` until the caller
    /// tells us which process to kill via [`SessionOrchestrator::note_launch_pid`].
    pending_pid: Option<u32>,
    duration_ns: Option<u64>,
    until_exit: Option<u32>,
    /// Pids whose events belong to this session.
    members: Vec<Watched>,
    process_starts: u64,
    other_events: u64,
}

struct Watched {
    uid: ProcUid,
    pid: u32,
    /// `true` once a `ProcessExit` for this pid was accepted.
    exited: bool,
}

/// What `begin_run` hands back. The CLI keeps the ticket and creates the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedRun {
    /// New session.
    pub session: SessionId,
    /// Ticket to send with `adopt`.
    pub ticket: LaunchTicket,
}

/// Orchestrator. `S` is the provider, `K` is the event sink.
pub struct SessionOrchestrator<S, K> {
    provider: S,
    sink: K,
    next_id: u64,
    next_seq: u64,
    now_ns: u64,
    sessions: BTreeMap<u64, LiveSession>,
}

impl<S: ScopeProvider> SessionOrchestrator<S, FanoutSink> {
    /// Orchestrator with an in-memory fan-out sink.
    pub fn new(provider: S) -> Self {
        Self::with_sink(provider, FanoutSink::new())
    }
}

impl<S: ScopeProvider, K: SessionSink> SessionOrchestrator<S, K> {
    /// Orchestrator with a caller-supplied sink.
    pub fn with_sink(provider: S, sink: K) -> Self {
        Self {
            provider,
            sink,
            next_id: 1,
            next_seq: 1,
            now_ns: 0,
            sessions: BTreeMap::new(),
        }
    }

    /// Virtual clock. Tests set this; production would pass `Instant` elapsed.
    pub fn set_now_ns(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
    }

    /// Current virtual time.
    pub fn now_ns(&self) -> u64 {
        self.now_ns
    }

    /// Borrow the provider (call log, terminated pids).
    pub fn provider(&self) -> &S {
        &self.provider
    }

    /// Borrow the sink.
    pub fn sink(&self) -> &K {
        &self.sink
    }

    /// Mutable sink, so a test can inspect fan-out that happened inside a call.
    pub fn sink_mut(&mut self) -> &mut K {
        &mut self.sink
    }

    /// Mutable provider, so a test can install a process table between calls.
    pub fn provider_mut(&mut self) -> &mut S {
        &mut self.provider
    }

    /// One session, if it exists.
    pub fn session(&self, id: SessionId) -> Option<&SessionRecord> {
        self.sessions.get(&id.0).map(|live| &live.record)
    }

    /// Every session, in id order.
    pub fn sessions(&self) -> Vec<&SessionRecord> {
        self.sessions.values().map(|live| &live.record).collect()
    }

    /// `POST /sessions` mode=run. Returns the session and the ticket.
    ///
    /// Does not create a process. The provider only reserves a container.
    ///
    /// # Errors
    ///
    /// [`SessionError::Provider`] when the container cannot be reserved.
    pub fn begin_run(&mut self, req: LaunchRequest) -> Result<StartedRun, SessionError> {
        let _ = req.caller;
        let id = SessionId(self.alloc_id());
        let prepared = self.provider.prepare_launch(id)?;
        let live = LiveSession {
            record: SessionRecord {
                id,
                mode: SessionMode::Run,
                status: SessionStatus::AwaitingAdopt,
                started_ns: self.now_ns,
                ended_ns: None,
                end_reason: None,
                summary: None,
                root: None,
                root_pid: None,
            },
            ticket: Some(prepared.ticket.clone()),
            adopt_deadline_ns: Some(self.now_ns.saturating_add(ADOPT_TIMEOUT_NS)),
            pending_pid: None,
            duration_ns: req.duration_ns,
            until_exit: req.until_exit,
            members: Vec::new(),
            process_starts: 0,
            other_events: 0,
        };
        self.sessions.insert(id.0, live);
        // The ticket is the credential the CLI uses to adopt. It is not logged.
        tracing::info!(session = id.0, mode = "run", "session prepared");
        Ok(StartedRun {
            session: id,
            ticket: prepared.ticket,
        })
    }

    /// Tell the orchestrator which pid to terminate if adopt times out.
    ///
    /// The CLI calls this in the same breath as process creation, before
    /// `adopt`. Without it, a timeout still fails the session but cannot name
    /// a process, and [`SessionError::MissingPid`] is returned from `tick`
    /// rather than killing pid 0.
    ///
    /// # Errors
    ///
    /// [`SessionError::NotFound`], [`SessionError::BadState`] when the session
    /// is not waiting for adopt, [`SessionError::MissingPid`] when `pid` is 0
    /// — zero is not a stand-in for "no process".
    pub fn note_launch_pid(&mut self, id: SessionId, pid: u32) -> Result<(), SessionError> {
        if pid == 0 {
            return Err(SessionError::MissingPid);
        }
        let live = self.live_mut(id)?;
        if live.record.status != SessionStatus::AwaitingAdopt {
            return Err(SessionError::BadState {
                session: id,
                status: live.record.status,
            });
        }
        live.pending_pid = Some(pid);
        Ok(())
    }

    /// `POST /sessions/{id}/adopt`. Moves `pid` into scope and updates the filter.
    ///
    /// # Errors
    ///
    /// [`SessionError::NotFound`], [`SessionError::BadState`], [`SessionError::TicketMismatch`],
    /// [`SessionError::Provider`].
    pub fn adopt(&mut self, id: SessionId, req: AdoptRequest) -> Result<Adopted, SessionError> {
        let status = self.live(id)?.record.status;
        if status != SessionStatus::AwaitingAdopt {
            return Err(SessionError::BadState {
                session: id,
                status,
            });
        }
        let expected = self
            .live(id)?
            .ticket
            .clone()
            .ok_or(SessionError::TicketMismatch { session: id })?;
        if expected.as_str() != req.ticket.as_str() {
            return Err(SessionError::TicketMismatch { session: id });
        }
        let adopted = self.provider.adopt(id, req.pid, &req.ticket)?;
        let uid = req.uid.unwrap_or(adopted.uid);
        {
            let live = self.live_mut(id)?;
            live.record.status = SessionStatus::Running;
            live.record.root = Some(uid);
            live.record.root_pid = Some(req.pid);
            live.ticket = None;
            live.adopt_deadline_ns = None;
            live.pending_pid = None;
            live.members.push(Watched {
                uid,
                pid: req.pid,
                exited: false,
            });
        }
        self.watch(id, req.pid);
        tracing::info!(session = id.0, pid = req.pid, "session adopted");
        Ok(Adopted {
            uid,
            pid: adopted.pid,
        })
    }

    /// Attach. Order is fixed: begin collection, snapshot, inject, rescan, inject the rest.
    ///
    /// # Errors
    ///
    /// [`SessionError::Provider`] when the root is missing or collection cannot start.
    /// [`SessionError::Event`] when an injected event cannot be built.
    pub fn begin_attach(&mut self, opts: AttachOptions) -> Result<SessionRecord, SessionError> {
        let id = SessionId(self.alloc_id());
        self.provider.begin_collect(id, &opts)?;
        let attached = self.provider.attach(id, opts.root_pid, &opts)?;
        let follow = opts.follow_children;
        let duration_ns = opts.duration_ns;
        let until_exit = opts.until_exit;
        let root_pid = opts.root_pid;
        {
            let live = LiveSession {
                record: SessionRecord {
                    id,
                    mode: SessionMode::Attach,
                    status: SessionStatus::Running,
                    started_ns: self.now_ns,
                    ended_ns: None,
                    end_reason: None,
                    summary: None,
                    root: Some(attached.root),
                    root_pid: Some(root_pid),
                },
                ticket: None,
                adopt_deadline_ns: None,
                pending_pid: None,
                duration_ns,
                until_exit,
                members: Vec::new(),
                process_starts: 0,
                other_events: 0,
            };
            self.sessions.insert(id.0, live);
        }
        self.ingest_snapshot(id, &attached.members, follow)?;
        let again = self.provider.rescan(id, root_pid)?;
        self.ingest_snapshot(id, &again, follow)?;
        tracing::info!(
            session = id.0,
            pid = root_pid,
            mode = "attach",
            "session attached"
        );
        Ok(self.live(id)?.record.clone())
    }

    /// Advance the virtual clock and apply end conditions.
    ///
    /// Ends a session when adopt times out, `--duration` elapses, or a
    /// previously noted root exit is already recorded. Root-exit itself is
    /// applied in [`ingest`](Self::ingest) when the exit event arrives; this
    /// method catches the timeout and duration clocks.
    ///
    /// # Errors
    ///
    /// [`SessionError::Provider`] when the timeout path cannot terminate the pid.
    /// [`SessionError::MissingPid`] when adopt timed out and no pid was noted —
    /// the session still fails, and the error says the process was not killed
    /// because none was named. The session status is [`SessionStatus::Failed`]
    /// either way; the error is the "could not terminate" signal.
    pub fn tick(&mut self, now_ns: u64) -> Result<(), SessionError> {
        self.now_ns = now_ns;
        let ids: Vec<SessionId> = self.sessions.values().map(|live| live.record.id).collect();
        for id in ids {
            self.apply_clock(id, now_ns)?;
        }
        Ok(())
    }

    /// `POST /sessions/{id}/stop`. Flushes and releases. Does not terminate.
    ///
    /// # Errors
    ///
    /// [`SessionError::NotFound`], [`SessionError::BadState`] when already ended.
    pub fn stop(&mut self, id: SessionId) -> Result<SessionRecord, SessionError> {
        self.finish(id, EndReason::Stopped, SessionStatus::Ended)
    }

    /// Push one collector event. Fan-out is by pid membership: a process in two
    /// sessions is delivered to both. A `ProcessExit` of the root ends that session.
    ///
    /// # Errors
    ///
    /// [`SessionError::Provider`] if ending the session fails to release.
    pub fn ingest(&mut self, event: RawEvent) -> Result<(), SessionError> {
        let pid = event.proc.as_ref().map(|proc| proc.pid);
        let is_exit = matches!(event.kind, EventKind::ProcessExit(_));
        let is_start = matches!(event.kind, EventKind::ProcessStart(_));
        self.sink.push(event);
        if let Some(pid) = pid {
            self.note_event(pid, is_start);
            if is_exit {
                self.on_exit(pid)?;
            }
        }
        Ok(())
    }

    /// Daemon came back. Every session that had not ended becomes
    /// [`SessionStatus::Interrupted`], and one [`GapKind::Restart`] covers
    /// `[started_ns, recovered_at_ns]` — the stretch this process was not observing.
    ///
    /// `recovered_at_ns` is the virtual time of the new process. It may be less
    /// than a session's `started_ns` only if the caller passes a clock that went
    /// backwards; the gap then uses `started_ns` as both ends rather than inventing
    /// a span.
    ///
    /// # Errors
    ///
    /// [`SessionError::Event`] when the gap event cannot be built.
    /// [`SessionError::Provider`] when release fails.
    pub fn recover(&mut self, recovered_at_ns: u64) -> Result<Vec<SessionRecord>, SessionError> {
        self.now_ns = recovered_at_ns;
        let open: Vec<SessionId> = self
            .sessions
            .values()
            .filter(|live| {
                matches!(
                    live.record.status,
                    SessionStatus::AwaitingAdopt | SessionStatus::Running
                )
            })
            .map(|live| live.record.id)
            .collect();
        let mut out = Vec::new();
        for id in open {
            let from_ns = self.live(id)?.record.started_ns;
            let to_ns = recovered_at_ns.max(from_ns);
            let gap = self.restart_gap(id, from_ns, to_ns)?;
            self.sink.push(gap);
            let record = self.finish(id, EndReason::Interrupted, SessionStatus::Interrupted)?;
            out.push(record);
        }
        Ok(out)
    }

    fn apply_clock(&mut self, id: SessionId, now_ns: u64) -> Result<(), SessionError> {
        let status = self.live(id)?.record.status;
        if status == SessionStatus::AwaitingAdopt {
            let deadline = self.live(id)?.adopt_deadline_ns;
            if deadline.is_some_and(|deadline| now_ns >= deadline) {
                return self.fail_adopt(id);
            }
            return Ok(());
        }
        if status != SessionStatus::Running {
            return Ok(());
        }
        let started = self.live(id)?.record.started_ns;
        let duration = self.live(id)?.duration_ns;
        if duration.is_some_and(|limit| now_ns.saturating_sub(started) >= limit) {
            self.finish(id, EndReason::Duration, SessionStatus::Ended)?;
            return Ok(());
        }
        let until = self.live(id)?.until_exit;
        if let Some(pid) = until {
            let exited = self
                .live(id)?
                .members
                .iter()
                .any(|member| member.pid == pid && member.exited);
            if exited {
                self.finish(id, EndReason::UntilExit, SessionStatus::Ended)?;
            }
        }
        Ok(())
    }

    fn fail_adopt(&mut self, id: SessionId) -> Result<(), SessionError> {
        let pid = self.live(id)?.pending_pid;
        if let Some(pid) = pid {
            self.provider.terminate(pid)?;
        }
        self.finish(id, EndReason::AdoptTimeout, SessionStatus::Failed)?;
        if pid.is_none() {
            return Err(SessionError::MissingPid);
        }
        Ok(())
    }

    fn on_exit(&mut self, pid: u32) -> Result<(), SessionError> {
        let ids: Vec<SessionId> = self.sessions.values().map(|live| live.record.id).collect();
        for id in ids {
            let running = self.live(id)?.record.status == SessionStatus::Running;
            if !running {
                continue;
            }
            let is_member = self
                .live_mut(id)?
                .members
                .iter_mut()
                .find(|member| member.pid == pid)
                .map(|member| {
                    member.exited = true;
                    true
                })
                .unwrap_or(false);
            let root_pid = self.live(id)?.record.root_pid;
            let until = self.live(id)?.until_exit;
            // `--until-exit` names a pid that may sit outside the scope (the
            // CLI itself). Its exit still ends observation, and still does not
            // kill anyone else.
            if until == Some(pid) && root_pid != Some(pid) {
                self.finish(id, EndReason::UntilExit, SessionStatus::Ended)?;
                continue;
            }
            if !is_member {
                continue;
            }
            if root_pid == Some(pid) {
                self.finish(id, EndReason::RootExited, SessionStatus::Ended)?;
            }
        }
        Ok(())
    }

    fn finish(
        &mut self,
        id: SessionId,
        reason: EndReason,
        status: SessionStatus,
    ) -> Result<SessionRecord, SessionError> {
        let current = self.live(id)?.record.status;
        if matches!(
            current,
            SessionStatus::Ended | SessionStatus::Interrupted | SessionStatus::Failed
        ) {
            return Err(SessionError::BadState {
                session: id,
                status: current,
            });
        }
        let summary = SessionSummary {
            process_starts: self.live(id)?.process_starts,
            other_events: self.live(id)?.other_events,
            watched_pids: self.live(id)?.members.len() as u64,
        };
        // Release only if the provider was actually engaged. AwaitingAdopt still
        // has a container from prepare_launch, so it is released too.
        self.provider.release(id)?;
        let _ = self.sink.flush(id, &summary);
        let ended_ns = self.now_ns;
        let live = self.live_mut(id)?;
        live.record.status = status;
        live.record.ended_ns = Some(ended_ns);
        live.record.end_reason = Some(reason);
        // Counts only. The summary has no paths, argv, or event content.
        tracing::info!(
            session = id.0,
            reason = reason.as_str(),
            status = status.as_str(),
            process_starts = summary.process_starts,
            other_events = summary.other_events,
            "session ended"
        );
        live.record.summary = Some(summary);
        Ok(live.record.clone())
    }

    fn ingest_snapshot(
        &mut self,
        id: SessionId,
        rows: &[SnapshotProc],
        follow_children: bool,
    ) -> Result<(), SessionError> {
        let root_pid = self.live(id)?.record.root_pid;
        for row in rows {
            if !follow_children && Some(row.pid) != root_pid {
                continue;
            }
            let already = self
                .live(id)?
                .members
                .iter()
                .any(|member| member.uid == row.uid);
            if already {
                continue;
            }
            self.live_mut(id)?.members.push(Watched {
                uid: row.uid,
                pid: row.pid,
                exited: false,
            });
            self.watch(id, row.pid);
            let event = self.snapshot_event(id, row)?;
            self.live_mut(id)?.process_starts = self.live(id)?.process_starts.saturating_add(1);
            self.sink.push(event);
        }
        Ok(())
    }

    fn snapshot_event(
        &mut self,
        id: SessionId,
        row: &SnapshotProc,
    ) -> Result<RawEvent, SessionError> {
        // `start_time_ns` is i64 in the schema, so a missing observation cannot
        // be `None`. `None` from the snapshot becomes `NA(preexisting)` below.
        // The payload holds 0 only together with the NA mark below. Readers
        // must not treat that 0 as the epoch.
        let start_known = row.start_ns.is_some();
        let start_time_ns = row
            .start_ns
            .and_then(|ns| i64::try_from(ns).ok())
            .unwrap_or(0);
        let seq = self.alloc_seq();
        let mut event = RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns: self.now_ns,
            ts_wall_ns: 0,
            session_id: Some(id),
            proc: Some(ProcRef {
                uid: row.uid,
                pid: row.pid,
                tid: None,
            }),
            source: Source::new(SOURCE),
            evidence: Evidence::S,
            kind: EventKind::ProcessStart(ProcessStart::new(
                row.ppid.unwrap_or(0),
                row.parent_uid,
                start_time_ns,
                row.exe.clone(),
                None,
                None,
                None,
                StartHow::Snapshot,
                None,
                None,
            )),
        })
        .map_err(|err| SessionError::Event(err.to_string()))?;
        if !start_known {
            event.mark_na("start_time_ns", aw_core::NaReason::Preexisting);
        }
        if row.ppid.is_none() && row.parent_uid.is_none() {
            event.mark_na("ppid", aw_core::NaReason::Preexisting);
        }
        Ok(event)
    }

    fn restart_gap(
        &mut self,
        id: SessionId,
        from_ns: u64,
        to_ns: u64,
    ) -> Result<RawEvent, SessionError> {
        let seq = self.alloc_seq();
        RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns: to_ns,
            ts_wall_ns: 0,
            session_id: Some(id),
            proc: None,
            source: Source::new(SOURCE),
            evidence: Evidence::E1,
            kind: EventKind::Gap(Gap::new(
                SOURCE,
                GapKind::Restart,
                vec!["proc".to_owned(), "file".to_owned(), "net".to_owned()],
                from_ns,
                to_ns,
                None,
                Some(
                    "daemon restarted; the session was not observed during this stretch".to_owned(),
                ),
            )),
        })
        .map_err(|err| SessionError::Event(err.to_string()))
    }

    fn note_event(&mut self, pid: u32, is_start: bool) {
        let ids: Vec<u64> = self.sessions.keys().copied().collect();
        for id in ids {
            let Some(live) = self.sessions.get_mut(&id) else {
                continue;
            };
            if live.record.status != SessionStatus::Running {
                continue;
            }
            if !live.members.iter().any(|member| member.pid == pid) {
                continue;
            }
            if is_start {
                live.process_starts = live.process_starts.saturating_add(1);
            } else {
                live.other_events = live.other_events.saturating_add(1);
            }
        }
    }

    fn watch(&mut self, id: SessionId, pid: u32) {
        self.sink.watch(id, pid);
    }

    fn live(&self, id: SessionId) -> Result<&LiveSession, SessionError> {
        self.sessions
            .get(&id.0)
            .ok_or(SessionError::NotFound { session: id })
    }

    fn live_mut(&mut self, id: SessionId) -> Result<&mut LiveSession, SessionError> {
        self.sessions
            .get_mut(&id.0)
            .ok_or(SessionError::NotFound { session: id })
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    fn alloc_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }
}

/// Exit event a test (or a mock collector) feeds back in.
pub fn process_exit(
    pid: u32,
    uid: ProcUid,
    ts_mono_ns: u64,
    seq: u64,
) -> Result<RawEvent, SessionError> {
    RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns,
        ts_wall_ns: 0,
        session_id: None,
        proc: Some(ProcRef {
            uid,
            pid,
            tid: None,
        }),
        source: Source::new("mock.collector/test"),
        evidence: Evidence::E1,
        kind: EventKind::ProcessExit(ProcessExit::new(Some(0), None)),
    })
    .map_err(|err| SessionError::Event(err.to_string()))
}

/// A non-exit event, so two sessions can both observe the same process.
pub fn process_file_placeholder(
    pid: u32,
    uid: ProcUid,
    ts_mono_ns: u64,
    seq: u64,
) -> Result<RawEvent, SessionError> {
    // Use ProcessExit's sibling only when we need a second kind. A second
    // ProcessStart is a real observation of exec; tests that just need "an
    // event" use a gap-free ProcessExit with a distinct seq. This function
    // builds a ProcessStart so it counts as activity without ending the session.
    RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns,
        ts_wall_ns: 0,
        session_id: None,
        proc: Some(ProcRef {
            uid,
            pid,
            tid: None,
        }),
        source: Source::new("mock.collector/test"),
        evidence: Evidence::E1,
        kind: EventKind::ProcessStart(ProcessStart::new(
            0,
            None,
            i64::try_from(ts_mono_ns).unwrap_or(0),
            Some("mock".to_owned()),
            None,
            None,
            None,
            StartHow::Exec,
            None,
            None,
        )),
    })
    .map_err(|err| SessionError::Event(err.to_string()))
}
