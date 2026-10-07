//! Scope filter: keep events whose process belongs to a watched session.
//!
//! This is the user-space fallback. Collectors do their own kernel filtering.
//! An event whose process is not yet known is held for [`ScopeConfig::pending_ms`]
//! and decided when the matching `ProcessStart` arrives, or dropped and counted
//! when the hold expires. Time comes from the pipeline clock via [`ScopeFilter::tick`],
//! never from the host clock.
//!
//! An empty [`ScopeSet`] (no session has been injected) forwards every event.
//! That is the state of [`crate::Pipeline::replay`] until a daemon calls
//! [`ScopeFilter::apply`]. Once any session exists, events outside it are not
//! forwarded.
//!
//! Evidence on a forwarded event is copied, not raised. Unknown fields stay `None`.

use std::collections::{HashMap, HashSet, VecDeque};

use aw_core::{EventKind, Evidence, ProcRef, ProcUid, RawEvent, SessionId, Source, StartHow};

use crate::enrich::{ProcCache, ProcCacheConfig, ProcInfo};
use crate::output::{Output, ProcessRec};

/// Default hold for an event whose process is not in the set yet.
pub const DEFAULT_PENDING_MS: u64 = 200;

/// How long to hold an unknown process, and which executables break attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeConfig {
    /// Hold window. Default [`DEFAULT_PENDING_MS`].
    pub pending_ms: u64,
    /// Process-cache limits. Linger default is 60 seconds.
    pub proc_cache: ProcCacheConfig,
    /// Basenames of system daemons that do not pull their children into scope
    /// when the daemon itself is outside the session.
    pub attribution_break_exes: Vec<String>,
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            pending_ms: DEFAULT_PENDING_MS,
            proc_cache: ProcCacheConfig::default(),
            attribution_break_exes: default_break_exes(),
        }
    }
}

fn default_break_exes() -> Vec<String> {
    ["launchd", "systemd", "services.exe", "init"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

/// One session's roots and the descendants included so far.
///
/// Exited members stay until the session is removed, so a late event can still
/// match. That matches process-tracking §3.
#[derive(Debug, Clone)]
pub struct ScopeSet {
    sessions: HashMap<SessionId, SessionScope>,
}

#[derive(Debug, Clone)]
struct SessionScope {
    roots: HashSet<ProcUid>,
    members: HashSet<ProcUid>,
}

impl ScopeSet {
    /// No sessions. The filter forwards everything until the first update.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// `true` when a daemon has not injected a session yet.
    pub fn is_open(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Watch `root` as a member of `session`. Idempotent.
    pub fn add_root(&mut self, session: SessionId, root: ProcUid) {
        let scope = self
            .sessions
            .entry(session)
            .or_insert_with(|| SessionScope {
                roots: HashSet::new(),
                members: HashSet::new(),
            });
        scope.roots.insert(root);
        scope.members.insert(root);
    }

    /// Sessions that currently contain `uid`, in id order.
    pub fn sessions_of(&self, uid: ProcUid) -> Vec<SessionId> {
        let mut found: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, scope)| scope.members.contains(&uid))
            .map(|(id, _)| *id)
            .collect();
        found.sort_by_key(|id| id.0);
        found
    }

    /// `true` when `uid` is already inside some watched session.
    pub fn contains(&self, uid: ProcUid) -> bool {
        self.sessions
            .values()
            .any(|scope| scope.members.contains(&uid))
    }

    /// Add `child` to every session that already contains `parent`.
    fn include_child(&mut self, parent: ProcUid, child: ProcUid) -> Vec<SessionId> {
        let mut joined = Vec::new();
        for (id, scope) in &mut self.sessions {
            if scope.members.contains(&parent) && scope.members.insert(child) {
                joined.push(*id);
            }
        }
        joined.sort_by_key(|id| id.0);
        joined
    }
}

impl Default for ScopeSet {
    fn default() -> Self {
        Self::new()
    }
}

/// What a daemon injects. No `/proc` read and no platform API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeUpdate {
    /// Add a root process to `session`.
    AddRoot {
        /// Session that owns the root.
        session: SessionId,
        /// Root [`ProcUid`].
        root: ProcUid,
    },
    /// A process the daemon already observed (attach snapshot or a start).
    NoteSnapshot {
        /// Identity. Same pid with a different uid is a different process.
        uid: ProcUid,
        /// OS pid.
        pid: u32,
        /// Parent pid, when the snapshot had one.
        ppid: Option<u32>,
        /// Parent [`ProcUid`], when the snapshot had one.
        parent_uid: Option<ProcUid>,
        /// Executable path, when the snapshot had one.
        exe: Option<String>,
        /// Start time, monotonic nanoseconds, when known.
        start_ns: Option<u64>,
        /// How the process was observed. Snapshots use [`StartHow::Snapshot`].
        how: StartHow,
        /// Evidence of the snapshot. Stored on the row; not raised.
        evidence: Evidence,
        /// Collector source string.
        source: Source,
    },
}

struct Held {
    event: RawEvent,
    /// `ts_mono_ns` of the event plus the pending window.
    deadline_ns: u64,
}

/// Scope stage state: membership, the process cache, and the pending buffer.
pub struct ScopeFilter {
    cfg: ScopeConfig,
    scope: ScopeSet,
    cache: ProcCache,
    /// Evidence and source from the event that created each cached process.
    origin: HashMap<ProcUid, Origin>,
    pending: VecDeque<Held>,
    /// Events dropped because the pending window closed with no matching start.
    pending_drops: u64,
    /// Events dropped because the process was outside every watched session.
    out_of_scope_drops: u64,
    /// Child starts refused because the parent is a known system daemon.
    attribution_breaks: u64,
    /// Monotonic position last reported by [`Self::tick`] or an event.
    now_ns: u64,
    /// `(uid, session)` pairs that already emitted a [`ProcessRec`].
    emitted: HashSet<(ProcUid, SessionId)>,
}

struct Origin {
    evidence: Evidence,
    source: Source,
    how: StartHow,
    user_id: Option<String>,
    signer: Option<String>,
}

impl ScopeFilter {
    /// Filter with explicit limits.
    pub fn new(cfg: ScopeConfig) -> Self {
        let cache = ProcCache::new(cfg.proc_cache);
        Self {
            cfg,
            scope: ScopeSet::new(),
            cache,
            origin: HashMap::new(),
            pending: VecDeque::new(),
            pending_drops: 0,
            out_of_scope_drops: 0,
            attribution_breaks: 0,
            now_ns: 0,
            emitted: HashSet::new(),
        }
    }

    /// Events dropped after [`ScopeConfig::pending_ms`] with no matching start.
    pub fn pending_drops(&self) -> u64 {
        self.pending_drops
    }

    /// Events dropped because their process is outside every watched session.
    pub fn out_of_scope_drops(&self) -> u64 {
        self.out_of_scope_drops
    }

    /// Child starts not pulled in because the parent is a configured system daemon
    /// and that parent is not itself in scope.
    pub fn attribution_breaks(&self) -> u64 {
        self.attribution_breaks
    }

    /// Live process cache.
    pub fn cache(&self) -> &ProcCache {
        &self.cache
    }

    /// Mutable process cache, for a daemon that already built a [`ProcInfo`].
    pub fn cache_mut(&mut self) -> &mut ProcCache {
        &mut self.cache
    }

    /// Membership. Empty until [`Self::apply`] adds a root.
    pub fn scope(&self) -> &ScopeSet {
        &self.scope
    }

    /// Apply one daemon update. Does not read the host clock.
    pub fn apply(&mut self, update: ScopeUpdate) {
        match update {
            ScopeUpdate::AddRoot { session, root } => {
                self.scope.add_root(session, root);
            }
            ScopeUpdate::NoteSnapshot {
                uid,
                pid,
                ppid,
                parent_uid,
                exe,
                start_ns,
                how,
                evidence,
                source,
            } => {
                let mut info = ProcInfo::live(pid, start_ns.unwrap_or(self.now_ns));
                info.ppid = ppid;
                info.parent_uid = parent_uid;
                info.exe = exe;
                info.start_ns = start_ns;
                if self.cache.insert(uid, info) {
                    self.origin.entry(uid).or_insert(Origin {
                        evidence,
                        source,
                        how,
                        user_id: None,
                        signer: None,
                    });
                }
            }
        }
    }

    /// Move the virtual clock to `now_ns` and drop holds whose window has closed.
    ///
    /// Does not emit records. A held event that is now in scope stays pending
    /// until [`Self::push`] or [`Self::take_ready`], which have an [`Output`].
    /// A timestamp behind the current position is kept as-is, matching
    /// [`crate::ReplayClock`].
    pub fn tick(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
        self.cache.tick(now_ns);
        self.expire(now_ns);
    }

    /// Forward held events that are now in scope, and return them.
    ///
    /// [`Stage::tick`](crate::Stage::tick) cannot see `out`, so the stage calls
    /// this on the next `process`. Safe to call when nothing is waiting.
    pub fn take_ready(&mut self, out: &mut Output) -> Vec<RawEvent> {
        let mut ready = Vec::new();
        self.sweep_pending(out, &mut ready);
        ready
    }

    /// Decide `event`.
    ///
    /// Returned events are in scope (or no session exists yet) and must be
    /// forwarded, including any previously held event this call just released.
    /// Evidence on each returned event is the evidence it arrived with.
    pub fn push(&mut self, event: RawEvent, out: &mut Output) -> Vec<RawEvent> {
        self.now_ns = event.ts_mono_ns;
        let mut ready = Vec::new();
        if self.scope.is_open() {
            self.remember_open(&event);
            ready.push(event);
            return ready;
        }
        self.decide(event, out, &mut ready);
        self.sweep_pending(out, &mut ready);
        ready
    }

    fn decide(&mut self, event: RawEvent, out: &mut Output, ready: &mut Vec<RawEvent>) {
        let Some(uid) = event_uid(&event) else {
            // No process: a collector-wide gap. It is not "out of scope".
            ready.push(event);
            return;
        };

        if let EventKind::ProcessStart(start) = &event.kind {
            self.observe_start(uid, &event, start, out);
        } else if let EventKind::ProcessExit(exit) = &event.kind {
            let code = exit.exit_code;
            let signal = exit.signal;
            self.observe_exit(uid, &event, code, signal, out);
        }

        self.enqueue_or_forward(uid, event, ready);
    }

    fn enqueue_or_forward(&mut self, uid: ProcUid, mut event: RawEvent, ready: &mut Vec<RawEvent>) {
        let sessions = self.scope.sessions_of(uid);
        if sessions.is_empty() {
            if matches!(event.kind, EventKind::ProcessStart(_)) {
                // The parent was already known (or absent) and was not a member.
                // Waiting will not change that.
                self.out_of_scope_drops = self.out_of_scope_drops.saturating_add(1);
            } else {
                let deadline = event.ts_mono_ns.saturating_add(self.pending_ns());
                self.pending.push_back(Held {
                    event,
                    deadline_ns: deadline,
                });
            }
            return;
        }
        // pipeline §3.1: one process in several sessions is copied to each.
        // P1 drives a single session; the first match is the forwarded copy.
        if let Some(session) = sessions.first().copied() {
            event.session_id = Some(session);
        }
        ready.push(event);
    }

    fn observe_start(
        &mut self,
        uid: ProcUid,
        event: &RawEvent,
        start: &aw_core::ProcessStart,
        out: &mut Output,
    ) {
        let pid = event.proc.as_ref().map(|proc| proc.pid);
        let mut info = ProcInfo::live(pid.unwrap_or(0), event.ts_mono_ns);
        // ppid 0 is a real pid (the kernel swapper on some platforms) only when
        // the event named a parent uid. Without a parent uid, 0 means "not set"
        // on the required schema field, so it stays None.
        info.ppid = if start.ppid != 0 || start.parent_uid.is_some() {
            Some(start.ppid)
        } else {
            None
        };
        info.parent_uid = start.parent_uid;
        info.exe = start.exe.clone();
        info.argv = start.argv.clone();
        info.cwd = start.cwd.clone();
        info.start_ns = u64::try_from(start.start_time_ns).ok();
        if self.cache.insert(uid, info) {
            self.origin.insert(
                uid,
                Origin {
                    evidence: event.evidence.clone(),
                    source: event.source.clone(),
                    how: start.how,
                    user_id: start.user.as_ref().map(|user| user.id.clone()),
                    signer: start.signer.clone(),
                },
            );
        }

        if self.parent_breaks(start.parent_uid) {
            self.attribution_breaks = self.attribution_breaks.saturating_add(1);
            return;
        }
        if let Some(parent) = start.parent_uid {
            let joined = self.scope.include_child(parent, uid);
            for session in joined {
                self.emit_process(uid, session, out);
            }
        }
        // A root added before its start event still needs a record.
        for session in self.scope.sessions_of(uid) {
            self.emit_process(uid, session, out);
        }
    }

    fn observe_exit(
        &mut self,
        uid: ProcUid,
        event: &RawEvent,
        exit_code: Option<i32>,
        exit_signal: Option<i32>,
        out: &mut Output,
    ) {
        if !self
            .cache
            .note_exit(uid, event.ts_mono_ns, exit_code, exit_signal)
        {
            let pid = event.proc.as_ref().map(|proc| proc.pid).unwrap_or(0);
            let mut info = ProcInfo::live(pid, event.ts_mono_ns);
            info.exit_ns = Some(event.ts_mono_ns);
            info.exit_code = exit_code;
            info.exit_signal = exit_signal;
            if self.cache.insert(uid, info) {
                self.origin.entry(uid).or_insert(Origin {
                    evidence: event.evidence.clone(),
                    source: event.source.clone(),
                    how: StartHow::Snapshot,
                    user_id: None,
                    signer: None,
                });
            }
        }
        for session in self.scope.sessions_of(uid) {
            self.emit_exit(uid, session, event, exit_code, exit_signal, out);
        }
    }

    fn remember_open(&mut self, event: &RawEvent) {
        // No session yet. Remember the process so a later root can see it.
        // Do not emit ProcessRec: nothing is in a session.
        let Some(uid) = event_uid(event) else {
            return;
        };
        let EventKind::ProcessStart(start) = &event.kind else {
            return;
        };
        let pid = event.proc.as_ref().map(|proc| proc.pid).unwrap_or(0);
        let mut info = ProcInfo::live(pid, event.ts_mono_ns);
        info.ppid = (start.ppid != 0).then_some(start.ppid);
        info.parent_uid = start.parent_uid;
        info.exe = start.exe.clone();
        info.argv = start.argv.clone();
        info.cwd = start.cwd.clone();
        info.start_ns = u64::try_from(start.start_time_ns).ok();
        if self.cache.insert(uid, info) {
            self.origin.insert(
                uid,
                Origin {
                    evidence: event.evidence.clone(),
                    source: event.source.clone(),
                    how: start.how,
                    user_id: start.user.as_ref().map(|user| user.id.clone()),
                    signer: start.signer.clone(),
                },
            );
        }
    }

    /// Parent is a configured system daemon and is not in any watched session.
    fn parent_breaks(&self, parent_uid: Option<ProcUid>) -> bool {
        let Some(parent_uid) = parent_uid else {
            return false;
        };
        if self.scope.contains(parent_uid) {
            return false;
        }
        let Some(parent) = self.cache.get(parent_uid) else {
            return false;
        };
        exe_is_break(parent.exe.as_deref(), &self.cfg.attribution_break_exes)
    }

    fn sweep_pending(&mut self, out: &mut Output, ready: &mut Vec<RawEvent>) {
        let mut kept = VecDeque::new();
        while let Some(held) = self.pending.pop_front() {
            let Some(uid) = event_uid(&held.event) else {
                ready.push(held.event);
                continue;
            };
            if !self.scope.contains(uid) {
                if self.now_ns >= held.deadline_ns {
                    self.pending_drops = self.pending_drops.saturating_add(1);
                } else {
                    kept.push_back(held);
                }
                continue;
            }
            self.release_held(held.event, out, ready);
        }
        self.pending = kept;
    }

    fn expire(&mut self, now_ns: u64) {
        // Only rows that were already held. `push` of the event that *sets*
        // `now_ns` runs after `tick` in [`crate::Pipeline::replay`], and that
        // event's own deadline must not be judged before it is inserted.
        let mut kept = VecDeque::new();
        while let Some(held) = self.pending.pop_front() {
            let in_scope = event_uid(&held.event).is_some_and(|uid| self.scope.contains(uid));
            if now_ns >= held.deadline_ns && !in_scope {
                self.pending_drops = self.pending_drops.saturating_add(1);
            } else {
                kept.push_back(held);
            }
        }
        self.pending = kept;
    }

    fn release_held(&mut self, mut event: RawEvent, out: &mut Output, ready: &mut Vec<RawEvent>) {
        let Some(uid) = event_uid(&event) else {
            ready.push(event);
            return;
        };
        let sessions = self.scope.sessions_of(uid);
        if let EventKind::ProcessExit(exit) = &event.kind {
            let code = exit.exit_code;
            let signal = exit.signal;
            for session in &sessions {
                self.emit_exit(uid, *session, &event, code, signal, out);
            }
        }
        if let Some(session) = sessions.first().copied() {
            event.session_id = Some(session);
        }
        ready.push(event);
    }

    fn emit_process(&mut self, uid: ProcUid, session: SessionId, out: &mut Output) {
        if !self.emitted.insert((uid, session)) {
            return;
        }
        let Some(info) = self.cache.get(uid) else {
            self.emitted.remove(&(uid, session));
            return;
        };
        // A root injected before any observation has no pid. Do not write 0.
        if info.pid == 0 && info.start_ns.is_none() {
            self.emitted.remove(&(uid, session));
            return;
        }
        let pid = info.pid;
        let parent_uid = info.parent_uid;
        let ppid = info.ppid;
        let start_ns = info.start_ns.unwrap_or(self.now_ns);
        let agent = info.agent_hint.clone();
        let origin = self.origin.get(&uid);
        out.processes.push(ProcessRec {
            session_id: Some(session),
            proc_uid: uid,
            pid,
            parent_uid,
            ppid,
            depth: None,
            start_ns,
            exit_ns: None,
            exit_code: None,
            exit_signal: None,
            how: origin.map(|row| row.how).unwrap_or(StartHow::Snapshot),
            user_id: origin.and_then(|row| row.user_id.clone()),
            signer: origin.and_then(|row| row.signer.clone()),
            evidence: origin
                .map(|row| row.evidence.clone())
                .unwrap_or(Evidence::S),
            field_evidence: std::collections::BTreeMap::new(),
            source: origin
                .map(|row| row.source.clone())
                .unwrap_or_else(|| Source::new("pipeline/scope")),
            agent,
        });
    }

    fn emit_exit(
        &mut self,
        uid: ProcUid,
        session: SessionId,
        event: &RawEvent,
        exit_code: Option<i32>,
        exit_signal: Option<i32>,
        out: &mut Output,
    ) {
        if let Some(existing) = out
            .processes
            .iter_mut()
            .find(|rec| rec.proc_uid == uid && rec.session_id == Some(session))
        {
            existing.exit_ns = Some(event.ts_mono_ns);
            existing.exit_code = exit_code;
            existing.exit_signal = exit_signal;
            // Exit evidence is not allowed to raise the start evidence.
            // A lower observation does not lower it either: the row keeps the
            // start's evidence. The exit event itself still carries its own.
            return;
        }
        let info = self.cache.get(uid);
        let pid = info.map(|row| row.pid).unwrap_or(0);
        if pid == 0 {
            return;
        }
        let parent_uid = info.and_then(|row| row.parent_uid);
        let ppid = info.and_then(|row| row.ppid);
        let start_ns = info
            .and_then(|row| row.start_ns)
            .unwrap_or(event.ts_mono_ns);
        out.processes.push(ProcessRec {
            session_id: Some(session),
            proc_uid: uid,
            pid,
            parent_uid,
            ppid,
            depth: None,
            start_ns,
            exit_ns: Some(event.ts_mono_ns),
            exit_code,
            exit_signal,
            how: self
                .origin
                .get(&uid)
                .map(|row| row.how)
                .unwrap_or(StartHow::Snapshot),
            user_id: None,
            signer: None,
            evidence: event.evidence.clone(),
            field_evidence: event.field_evidence.clone(),
            source: event.source.clone(),
            agent: None,
        });
        self.emitted.insert((uid, session));
    }

    fn pending_ns(&self) -> u64 {
        self.cfg.pending_ms.saturating_mul(1_000_000)
    }
}

impl Default for ScopeFilter {
    fn default() -> Self {
        Self::new(ScopeConfig::default())
    }
}

fn event_uid(event: &RawEvent) -> Option<ProcUid> {
    event.proc.as_ref().map(|proc: &ProcRef| proc.uid)
}

fn exe_is_break(exe: Option<&str>, names: &[String]) -> bool {
    let Some(exe) = exe else {
        return false;
    };
    let base = exe_basename(exe);
    names.iter().any(|name| base.eq_ignore_ascii_case(name))
}

fn exe_basename(exe: &str) -> &str {
    let trimmed = exe.trim_end_matches(['/', '\\']);
    trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aw_core::{ProcessExit, ProcessStart, RawEventParts};

    const SESSION: SessionId = SessionId(7);
    const WALL: i64 = 1_759_795_200_000_000_000;

    fn start_event(
        seq: u64,
        ts_ms: u64,
        uid: u64,
        pid: u32,
        ppid: u32,
        parent: Option<u64>,
        exe: &str,
    ) -> RawEvent {
        RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns: ts_ms.saturating_mul(1_000_000),
            ts_wall_ns: WALL,
            session_id: None,
            proc: Some(ProcRef {
                uid: ProcUid(uid),
                pid,
                tid: None,
            }),
            source: Source::new("scope/test"),
            evidence: Evidence::E1,
            kind: EventKind::ProcessStart(ProcessStart::new(
                ppid,
                parent.map(ProcUid),
                i64::try_from(ts_ms.saturating_mul(1_000_000)).unwrap_or(0),
                Some(exe.to_owned()),
                Some(vec![aw_core::Redacted::new("secret-arg")]),
                None,
                None,
                StartHow::Fork,
                None,
                None,
            )),
        })
        .expect("process_start")
    }

    fn exit_event(seq: u64, ts_ms: u64, uid: u64, pid: u32, evidence: Evidence) -> RawEvent {
        RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns: ts_ms.saturating_mul(1_000_000),
            ts_wall_ns: WALL,
            session_id: None,
            proc: Some(ProcRef {
                uid: ProcUid(uid),
                pid,
                tid: None,
            }),
            source: Source::new("scope/test"),
            evidence,
            kind: EventKind::ProcessExit(ProcessExit::new(Some(1), None)),
        })
        .expect("exit")
    }

    fn feed(filter: &mut ScopeFilter, event: RawEvent, out: &mut Output) -> Vec<RawEvent> {
        let ts = event.ts_mono_ns;
        filter.tick(ts);
        let mut ready = filter.take_ready(out);
        ready.extend(filter.push(event, out));
        ready
    }

    #[test]
    fn three_levels_include_a_grandchild_event_150ms_early() {
        let mut filter = ScopeFilter::default();
        let mut out = Output::empty();
        filter.apply(ScopeUpdate::AddRoot {
            session: SESSION,
            root: ProcUid(1),
        });

        let root = start_event(1, 0, 1, 10, 1, None, "/usr/bin/agent");
        let ready = feed(&mut filter, root, &mut out);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].session_id, Some(SESSION));
        assert_eq!(ready[0].evidence, Evidence::E1);

        let child = start_event(2, 1_000, 2, 20, 10, Some(1), "/usr/bin/child");
        let ready = feed(&mut filter, child, &mut out);
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].evidence, Evidence::E1);

        // Grandchild event at t=1850 ms, 150 ms before its start at t=2000.
        let early = exit_event(3, 1_850, 3, 30, Evidence::S);
        let ready = feed(&mut filter, early, &mut out);
        assert!(
            ready.is_empty(),
            "grandchild is unknown, so the event is held"
        );
        assert_eq!(filter.pending_drops(), 0);

        let grand = start_event(4, 2_000, 3, 30, 20, Some(2), "/usr/bin/grand");
        let ready = feed(&mut filter, grand, &mut out);
        assert!(
            ready
                .iter()
                .any(|ev| ev.seq == 4 && ev.evidence == Evidence::E1),
            "grandchild start is in scope at its own evidence"
        );
        assert!(
            ready
                .iter()
                .any(|ev| ev.seq == 3 && ev.evidence == Evidence::S),
            "event that arrived 150 ms early is released, still at S"
        );

        let uids: Vec<u64> = out.processes.iter().map(|rec| rec.proc_uid.0).collect();
        assert!(uids.contains(&1), "root recorded");
        assert!(uids.contains(&2), "child recorded");
        assert!(uids.contains(&3), "grandchild recorded");
        assert!(out.processes.iter().all(|rec| rec.depth.is_none()));
        let grand_rec = out
            .processes
            .iter()
            .find(|rec| rec.proc_uid == ProcUid(3))
            .expect("grandchild row");
        assert_eq!(grand_rec.evidence, Evidence::E1);
        assert_eq!(grand_rec.exit_code, Some(1));
        assert_eq!(filter.pending_drops(), 0);
    }

    #[test]
    fn unknown_pid_past_200ms_is_dropped_and_counted() {
        let mut filter = ScopeFilter::default();
        let mut out = Output::empty();
        filter.apply(ScopeUpdate::AddRoot {
            session: SESSION,
            root: ProcUid(1),
        });
        let root = start_event(1, 0, 1, 10, 1, None, "/usr/bin/agent");
        let _ = feed(&mut filter, root, &mut out);

        let stray = exit_event(2, 100, 99, 99, Evidence::E1);
        let ready = feed(&mut filter, stray, &mut out);
        assert!(ready.is_empty());
        assert_eq!(filter.pending_drops(), 0);

        // Event time 100 ms + 200 ms hold = 300 ms. No matching start arrives.
        filter.tick(300 * 1_000_000);
        let released = filter.take_ready(&mut out);
        assert!(released.is_empty());
        assert_eq!(filter.pending_drops(), 1);
        assert!(out.processes.iter().all(|rec| rec.proc_uid != ProcUid(99)));
    }

    #[test]
    fn pid_reuse_does_not_cross_wire() {
        let mut filter = ScopeFilter::default();
        let mut out = Output::empty();
        filter.apply(ScopeUpdate::AddRoot {
            session: SESSION,
            root: ProcUid(1),
        });
        let root = start_event(1, 0, 1, 10, 1, None, "/usr/bin/agent");
        let _ = feed(&mut filter, root, &mut out);

        let first = start_event(2, 100, 2, 50, 10, Some(1), "/usr/bin/first");
        let ready = feed(&mut filter, first, &mut out);
        assert_eq!(ready.len(), 1);

        // init is outside the session. The reused pid's parent is init, not uid 1.
        filter.apply(ScopeUpdate::NoteSnapshot {
            uid: ProcUid(8),
            pid: 1,
            ppid: None,
            parent_uid: None,
            exe: Some("/sbin/init".to_owned()),
            start_ns: Some(0),
            how: StartHow::Snapshot,
            evidence: Evidence::S,
            source: Source::new("scope/test"),
        });
        let reused = start_event(3, 500, 3, 50, 1, Some(8), "/usr/bin/other");
        let ready = feed(&mut filter, reused, &mut out);
        assert!(
            ready.is_empty(),
            "same pid, different ProcUid, parent outside scope"
        );
        assert!(!filter.scope().contains(ProcUid(3)));
        assert!(filter.scope().contains(ProcUid(2)));

        let cached_first = filter.cache().get(ProcUid(2)).expect("first still cached");
        let cached_reuse = filter.cache().get(ProcUid(3)).expect("reuse cached");
        assert_eq!(cached_first.pid, 50);
        assert_eq!(cached_reuse.pid, 50);
        assert_eq!(cached_first.exe.as_deref(), Some("/usr/bin/first"));
        assert_eq!(cached_reuse.exe.as_deref(), Some("/usr/bin/other"));
        assert_ne!(cached_first.start_ns, cached_reuse.start_ns);
        // resolve_pid prefers the live row. Both are live, so the later insert wins
        // only as "a" live row — it must not be uid 2 once we exit uid 2.
        let _ = filter
            .cache_mut()
            .note_exit(ProcUid(2), 600 * 1_000_000, Some(0), None);
        let resolved = filter
            .cache_mut()
            .resolve_pid(50, 700 * 1_000_000)
            .expect("live reuse");
        assert_eq!(resolved, ProcUid(3));
    }

    #[test]
    fn ten_thousand_out_of_scope_events_leave_only_in_scope_processes() {
        let mut filter = ScopeFilter::default();
        let mut out = Output::empty();
        filter.apply(ScopeUpdate::AddRoot {
            session: SESSION,
            root: ProcUid(1),
        });
        let root = start_event(1, 0, 1, 10, 1, None, "/usr/bin/agent");
        let mut forwarded = feed(&mut filter, root, &mut out);

        let child = start_event(2, 10, 2, 20, 10, Some(1), "/usr/bin/child");
        forwarded.extend(feed(&mut filter, child, &mut out));

        for n in 0..10_000u64 {
            let noise = start_event(
                100 + n,
                20 + n,
                1_000 + n,
                5_000,
                1,
                Some(8),
                "/usr/bin/noise",
            );
            forwarded.extend(feed(&mut filter, noise, &mut out));
        }

        assert_eq!(forwarded.len(), 2, "only root and child are forwarded");
        assert!(forwarded.iter().all(|ev| {
            ev.proc
                .as_ref()
                .is_some_and(|proc| proc.uid.0 == 1 || proc.uid.0 == 2)
        }));
        let uids: HashSet<u64> = out.processes.iter().map(|rec| rec.proc_uid.0).collect();
        assert_eq!(uids, HashSet::from([1, 2]));
        assert_eq!(filter.out_of_scope_drops(), 10_000);
    }

    #[test]
    fn system_daemon_parent_outside_scope_does_not_include_the_child() {
        let mut filter = ScopeFilter::default();
        let mut out = Output::empty();
        filter.apply(ScopeUpdate::AddRoot {
            session: SESSION,
            root: ProcUid(1),
        });
        filter.apply(ScopeUpdate::NoteSnapshot {
            uid: ProcUid(4),
            pid: 1,
            ppid: None,
            parent_uid: None,
            exe: Some("/sbin/launchd".to_owned()),
            start_ns: Some(0),
            how: StartHow::Snapshot,
            evidence: Evidence::S,
            source: Source::new("scope/test"),
        });
        let child = start_event(5, 50, 9, 90, 1, Some(4), "/usr/bin/orphaned");
        let ready = feed(&mut filter, child, &mut out);
        assert!(ready.is_empty());
        assert_eq!(filter.attribution_breaks(), 1);
        assert!(!filter.scope().contains(ProcUid(9)));
        assert!(out.processes.iter().all(|rec| rec.proc_uid != ProcUid(9)));
    }

    #[test]
    fn daemon_parent_inside_scope_still_includes_the_child() {
        let mut filter = ScopeFilter::default();
        let mut out = Output::empty();
        filter.apply(ScopeUpdate::AddRoot {
            session: SESSION,
            root: ProcUid(4),
        });
        let daemon = start_event(1, 0, 4, 1, 0, None, "/sbin/systemd");
        let ready = feed(&mut filter, daemon, &mut out);
        assert_eq!(ready.len(), 1);
        let child = start_event(2, 10, 5, 40, 1, Some(4), "/usr/bin/unit");
        let ready = feed(&mut filter, child, &mut out);
        assert_eq!(ready.len(), 1);
        assert_eq!(filter.attribution_breaks(), 0);
        assert!(filter.scope().contains(ProcUid(5)));
    }
}
