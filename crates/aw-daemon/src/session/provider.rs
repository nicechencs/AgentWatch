//! [`ScopeProvider`]: the four platform actions a session needs.
//!
//! Each action returns [`Result`]. Failure is never `0`, an empty string, or a
//! default pid. [`MockScope`] records the call order so tests can lock the
//! attach sequence (collect, then snapshot, then rescan) without a platform.
//!
//! # Launch identity
//!
//! Implementors must not start the target as root or SYSTEM. The calling user
//! creates the process (suspended) and this trait only moves it into the scope
//! container. `stop` on a session must not kill that process; the only kill
//! path is [`ScopeProvider::terminate`], and the orchestrator calls it only
//! when adopt times out.

use std::collections::BTreeMap;

use aw_core::{ProcUid, SessionId};

use super::orch::AttachOptions;

/// Opaque handle the CLI holds between `prepare_launch` and `adopt`.
///
/// Not an OS handle. Empty text is rejected: an empty string is not a ticket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LaunchTicket {
    text: String,
}

impl LaunchTicket {
    /// Wrap non-empty ticket text.
    ///
    /// # Errors
    ///
    /// [`ProviderError::EmptyTicket`] when `text` is empty.
    pub fn new(text: impl Into<String>) -> Result<Self, ProviderError> {
        let text = text.into();
        if text.is_empty() {
            return Err(ProviderError::EmptyTicket);
        }
        Ok(Self { text })
    }

    /// Borrow the ticket text.
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl std::fmt::Display for LaunchTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// What `prepare_launch` returns to the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedLaunch {
    /// Ticket the CLI sends back with the pid.
    pub ticket: LaunchTicket,
}

/// What `adopt` reports after the process is inside the scope container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adopted {
    /// Identity of the adopted process.
    pub uid: ProcUid,
    /// OS pid. The same value the CLI sent; kept so a test can see it.
    pub pid: u32,
}

/// One process a snapshot observed. Not a [`aw_core::RawEvent`] yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotProc {
    /// Stable identity. A reused pid with a different uid is a different process.
    pub uid: ProcUid,
    /// OS pid.
    pub pid: u32,
    /// Parent pid, when the snapshot had one. `None` is "not observed".
    pub ppid: Option<u32>,
    /// Parent identity, when the snapshot had one.
    pub parent_uid: Option<ProcUid>,
    /// Executable path at snapshot time, not at the real start. `None` if unread.
    pub exe: Option<String>,
    /// Start time, monotonic nanoseconds. `None` if the platform did not say.
    pub start_ns: Option<u64>,
}

/// What `attach` reports: the tree that was already running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attached {
    /// Root the caller named.
    pub root: ProcUid,
    /// Root plus descendants, in the order the provider enumerated them.
    pub members: Vec<SnapshotProc>,
}

/// Why a scope action failed. No variant is "empty means unknown".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// [`LaunchTicket::new`] was given an empty string.
    EmptyTicket,
    /// The ticket does not match a launch this provider prepared.
    UnknownTicket,
    /// `adopt` was asked for a pid this provider was not told about.
    UnknownPid { pid: u32 },
    /// The root was not in the process table.
    RootNotFound { pid: u32 },
    /// A previous action already released this session.
    AlreadyReleased { session: SessionId },
    /// The provider was asked to terminate a process it does not hold.
    NotHeld { pid: u32 },
    /// Scripted failure. `message` must not contain argv, environment values, URLs, or headers.
    Failed { message: String },
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTicket => f.write_str("launch ticket is empty"),
            Self::UnknownTicket => f.write_str("launch ticket is not one this provider prepared"),
            Self::UnknownPid { pid } => write!(f, "pid {pid} is not waiting to be adopted"),
            Self::RootNotFound { pid } => write!(f, "pid {pid} is not in the process table"),
            Self::AlreadyReleased { session } => {
                write!(f, "session {} was already released", session.0)
            }
            Self::NotHeld { pid } => write!(f, "pid {pid} is not held by this provider"),
            Self::Failed { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for ProviderError {}

/// One recorded call, in the order the orchestrator made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeAction {
    /// `prepare_launch`.
    PrepareLaunch { session: SessionId },
    /// `adopt`.
    Adopt { session: SessionId, pid: u32 },
    /// Start collecting and tracking, before any snapshot.
    BeginCollect { session: SessionId },
    /// First process-tree snapshot.
    Snapshot { session: SessionId, root_pid: u32 },
    /// Second scan, after the snapshot, to fill the race window.
    Rescan { session: SessionId, root_pid: u32 },
    /// Replace the collector filter.
    UpdateFilter { session: SessionId },
    /// Flush the pipeline for this session.
    Flush { session: SessionId },
    /// Release the scope container. Does not kill the target.
    Release { session: SessionId },
    /// Kill a process the CLI created and this daemon failed to adopt in time.
    Terminate { pid: u32 },
}

/// Platform hook for launch, attach, and release.
///
/// Four actions from the task card, plus the two the orchestration needs and
/// the platform must still own: [`begin_collect`](Self::begin_collect) (attach
/// starts collection before the snapshot) and [`terminate`](Self::terminate)
/// (adopt timeout kills the target). Every method returns [`Result`].
///
/// # Identity
///
/// Do not launch the target as root or SYSTEM. This trait has no "spawn"
/// method on purpose: the CLI creates the process under the calling user.
pub trait ScopeProvider {
    /// Reserve a scope container and return a ticket. Does not create a process.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] when the container cannot be reserved.
    fn prepare_launch(&mut self, session: SessionId) -> Result<PreparedLaunch, ProviderError>;

    /// Move `pid` into the container named by `ticket`, then update the collector filter.
    ///
    /// # Errors
    ///
    /// [`ProviderError::UnknownTicket`] or [`ProviderError::UnknownPid`] when the
    /// pair does not match a prepared launch.
    fn adopt(
        &mut self,
        session: SessionId,
        pid: u32,
        ticket: &LaunchTicket,
    ) -> Result<Adopted, ProviderError>;

    /// Start collection and scope tracking for an attach. Called before any snapshot.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] when collection cannot start.
    fn begin_collect(
        &mut self,
        session: SessionId,
        opts: &AttachOptions,
    ) -> Result<(), ProviderError>;

    /// Enumerate the live tree under `root_pid`.
    ///
    /// # Errors
    ///
    /// [`ProviderError::RootNotFound`] when `root_pid` is not in the table.
    fn attach(
        &mut self,
        session: SessionId,
        root_pid: u32,
        opts: &AttachOptions,
    ) -> Result<Attached, ProviderError>;

    /// Scan the tree again. Processes that appeared during the snapshot come back here.
    ///
    /// # Errors
    ///
    /// [`ProviderError::RootNotFound`] when the root disappeared and the scan cannot run.
    fn rescan(
        &mut self,
        session: SessionId,
        root_pid: u32,
    ) -> Result<Vec<SnapshotProc>, ProviderError>;

    /// Drop the scope container. Must not kill the target.
    ///
    /// # Errors
    ///
    /// [`ProviderError::AlreadyReleased`] when `session` was already released.
    fn release(&mut self, session: SessionId) -> Result<(), ProviderError>;

    /// End a process the CLI created because adopt did not arrive in time.
    ///
    /// The orchestrator calls this only on the adopt-timeout path. `stop` does not.
    ///
    /// # Errors
    ///
    /// [`ProviderError::NotHeld`] when `pid` is not a process this provider is tracking.
    fn terminate(&mut self, pid: u32) -> Result<(), ProviderError>;
}

#[derive(Debug, Clone)]
struct MockProc {
    uid: ProcUid,
    pid: u32,
    ppid: Option<u32>,
    parent_uid: Option<ProcUid>,
    exe: Option<String>,
    start_ns: Option<u64>,
    /// When `Some`, the process appears only on the rescan, not the first snapshot.
    appears_on_rescan: bool,
}

/// In-memory [`ScopeProvider`]. Records every call. Holds no OS handle.
#[derive(Debug)]
pub struct MockScope {
    next_ticket: u64,
    /// Ticket text → session that prepared it.
    open_tickets: BTreeMap<String, u64>,
    /// Consumed tickets, so a second adopt fails instead of looking like success.
    used_tickets: BTreeMap<String, u64>,
    /// Pid the test says the CLI created, mapped to the process identity.
    waiting: BTreeMap<u32, ProcUid>,
    /// Processes currently inside a scope container, keyed by [`SessionId`]'s integer.
    /// `SessionId` is not `Ord`; the integer is the same value.
    held: BTreeMap<u64, Vec<u32>>,
    /// Process table the attach tests install.
    table: Vec<MockProc>,
    /// Sessions whose container was released.
    released: Vec<SessionId>,
    /// Pids [`terminate`](ScopeProvider::terminate) was asked to kill.
    terminated: Vec<u32>,
    /// Call order.
    log: Vec<ScopeAction>,
    /// Next `prepare_launch` fails with this message, then the slot clears.
    fail_prepare: Option<String>,
}

impl MockScope {
    /// Empty table, no tickets.
    pub fn new() -> Self {
        Self {
            next_ticket: 1,
            open_tickets: BTreeMap::new(),
            used_tickets: BTreeMap::new(),
            waiting: BTreeMap::new(),
            held: BTreeMap::new(),
            table: Vec::new(),
            released: Vec::new(),
            terminated: Vec::new(),
            log: Vec::new(),
            fail_prepare: None,
        }
    }

    /// The next `prepare_launch` returns [`ProviderError::Failed`].
    pub fn fail_next_prepare(&mut self, message: impl Into<String>) {
        self.fail_prepare = Some(message.into());
    }

    /// Register a process the CLI will ask the daemon to adopt.
    pub fn stage_waiting(&mut self, pid: u32, uid: ProcUid) {
        self.waiting.insert(pid, uid);
    }

    /// Install one row of the process table used by attach.
    pub fn add_proc(&mut self, proc: SnapshotProc) {
        self.table.push(MockProc {
            uid: proc.uid,
            pid: proc.pid,
            ppid: proc.ppid,
            parent_uid: proc.parent_uid,
            exe: proc.exe,
            start_ns: proc.start_ns,
            appears_on_rescan: false,
        });
    }

    /// Same as [`add_proc`](Self::add_proc), but the row is invisible until `rescan`.
    pub fn add_proc_on_rescan(&mut self, proc: SnapshotProc) {
        self.table.push(MockProc {
            uid: proc.uid,
            pid: proc.pid,
            ppid: proc.ppid,
            parent_uid: proc.parent_uid,
            exe: proc.exe,
            start_ns: proc.start_ns,
            appears_on_rescan: true,
        });
    }

    /// Call order so far.
    pub fn log(&self) -> &[ScopeAction] {
        &self.log
    }

    /// Pids `terminate` was called with, in order.
    pub fn terminated(&self) -> &[u32] {
        &self.terminated
    }

    /// Sessions `release` was called with, in order.
    pub fn released(&self) -> &[SessionId] {
        &self.released
    }

    /// `true` when `pid` is currently inside `session`'s container.
    pub fn holds(&self, session: SessionId, pid: u32) -> bool {
        self.held
            .get(&session.0)
            .is_some_and(|pids| pids.contains(&pid))
    }

    fn descendants(&self, root_pid: u32, include_late: bool) -> Result<Vec<SnapshotProc>, ProviderError> {
        let root_known = self.table.iter().any(|row| row.pid == root_pid);
        if !root_known {
            return Err(ProviderError::RootNotFound { pid: root_pid });
        }
        let mut out = Vec::new();
        let mut frontier = vec![root_pid];
        while let Some(pid) = frontier.pop() {
            for row in &self.table {
                let is_root = row.pid == root_pid && pid == root_pid;
                let is_child = row.ppid == Some(pid) && row.pid != pid;
                if !is_root && !is_child {
                    continue;
                }
                if row.appears_on_rescan && !include_late {
                    continue;
                }
                if out.iter().any(|seen: &SnapshotProc| seen.uid == row.uid) {
                    continue;
                }
                if is_child {
                    frontier.push(row.pid);
                }
                out.push(SnapshotProc {
                    uid: row.uid,
                    pid: row.pid,
                    ppid: row.ppid,
                    parent_uid: row.parent_uid,
                    exe: row.exe.clone(),
                    start_ns: row.start_ns,
                });
            }
        }
        Ok(out)
    }
}

impl Default for MockScope {
    fn default() -> Self {
        Self::new()
    }
}

impl ScopeProvider for MockScope {
    fn prepare_launch(&mut self, session: SessionId) -> Result<PreparedLaunch, ProviderError> {
        self.log.push(ScopeAction::PrepareLaunch { session });
        if let Some(message) = self.fail_prepare.take() {
            return Err(ProviderError::Failed { message });
        }
        let text = format!("ticket-{session}-{n}", session = session.0, n = self.next_ticket);
        self.next_ticket = self.next_ticket.saturating_add(1);
        let ticket = LaunchTicket::new(text)?;
        self.open_tickets.insert(ticket.as_str().to_owned(), session.0);
        Ok(PreparedLaunch { ticket })
    }

    fn adopt(
        &mut self,
        session: SessionId,
        pid: u32,
        ticket: &LaunchTicket,
    ) -> Result<Adopted, ProviderError> {
        self.log.push(ScopeAction::Adopt { session, pid });
        let Some(owner) = self.open_tickets.remove(ticket.as_str()) else {
            if self.used_tickets.contains_key(ticket.as_str()) {
                return Err(ProviderError::UnknownTicket);
            }
            return Err(ProviderError::UnknownTicket);
        };
        self.used_tickets.insert(ticket.as_str().to_owned(), owner);
        if owner != session.0 {
            return Err(ProviderError::UnknownTicket);
        }
        let Some(uid) = self.waiting.remove(&pid) else {
            return Err(ProviderError::UnknownPid { pid });
        };
        self.held.entry(session.0).or_default().push(pid);
        self.log.push(ScopeAction::UpdateFilter { session });
        Ok(Adopted { uid, pid })
    }

    fn begin_collect(
        &mut self,
        session: SessionId,
        _opts: &AttachOptions,
    ) -> Result<(), ProviderError> {
        self.log.push(ScopeAction::BeginCollect { session });
        Ok(())
    }

    fn attach(
        &mut self,
        session: SessionId,
        root_pid: u32,
        _opts: &AttachOptions,
    ) -> Result<Attached, ProviderError> {
        self.log.push(ScopeAction::Snapshot { session, root_pid });
        let members = self.descendants(root_pid, false)?;
        let root = members
            .iter()
            .find(|row| row.pid == root_pid)
            .map(|row| row.uid)
            .ok_or(ProviderError::RootNotFound { pid: root_pid })?;
        let pids: Vec<u32> = members.iter().map(|row| row.pid).collect();
        self.held.insert(session.0, pids);
        Ok(Attached { root, members })
    }

    fn rescan(
        &mut self,
        session: SessionId,
        root_pid: u32,
    ) -> Result<Vec<SnapshotProc>, ProviderError> {
        self.log
            .push(ScopeAction::Rescan { session, root_pid });
        let members = self.descendants(root_pid, true)?;
        let pids: Vec<u32> = members.iter().map(|row| row.pid).collect();
        self.held.insert(session.0, pids);
        self.log.push(ScopeAction::UpdateFilter { session });
        Ok(members)
    }

    fn release(&mut self, session: SessionId) -> Result<(), ProviderError> {
        self.log.push(ScopeAction::Release { session });
        if self.released.contains(&session) {
            return Err(ProviderError::AlreadyReleased { session });
        }
        self.held.remove(&session.0);
        self.released.push(session);
        Ok(())
    }

    fn terminate(&mut self, pid: u32) -> Result<(), ProviderError> {
        self.log.push(ScopeAction::Terminate { pid });
        // Only a pid the CLI staged, or one already inside a container. A stranger
        // is an error, not a silent no-op.
        let staged = self.waiting.contains_key(&pid);
        let held = self.held.values().any(|pids| pids.contains(&pid));
        if !staged && !held {
            return Err(ProviderError::NotHeld { pid });
        }
        self.waiting.remove(&pid);
        for pids in self.held.values_mut() {
            pids.retain(|held_pid| *held_pid != pid);
        }
        self.terminated.push(pid);
        Ok(())
    }
}
