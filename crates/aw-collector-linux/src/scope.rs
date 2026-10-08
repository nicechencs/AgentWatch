//! Linux cgroup v2 scope and `scope_pids` attach (P1-LNX-04, linux.md §4).
//!
//! This module does not talk to the kernel. It does not fork, it does not write
//! `/sys/fs/cgroup`, and it does not open a BPF map. The CLI launch state machine
//! lives in `aw-cli` (`launch/unix_linux.rs`) and talks to the OS only through a
//! trait the default tests replace with a fake. The attach walk here is the same
//! shape: [`ProcScan`] returns rows, [`run_attach`] records the order.
//!
//! # What was measured
//!
//! SPIKE-05 did not run on Linux. cgroup v2, `StartTransientUnit`, the pipe-then-exec
//! handshake, and the `/proc` race window are all 【待验证】. [`UnverifiedCgroupHost`]
//! refuses every step with [`ScopeError::NotVerified`] instead of pretending a
//! directory was created.
//!
//! # Launch
//!
//! [`run_launch`] is the daemon half of linux.md §4.1. The CLI has already forked
//! and the child is blocked on a pipe ([`LaunchPhase::WaitingOnPipe`]). The steps,
//! in order:
//!
//! 1. Create `agentwatch.slice/session-<sid>`. On systemd, try D-Bus
//!    `StartTransientUnit` first. A failure is not silent: the result says the
//!    scope was not created and names the mkdir fallback, which is itself 【待验证】.
//! 2. Write the child pid into `cgroup.procs`.
//! 3. Write the cgroup id into `scope_cgroups`.
//! 4. `adopt`. Only then may the caller let the child exec.
//!
//! On adopt failure or timeout the child is terminated and [`LaunchStep::Exec`] is
//! absent. cgroup v1 has no launch mode: [`run_launch`] returns
//! [`ScopeError::CgroupV1NoLaunch`] and creates no session directory. Tracking
//! falls back to [`run_attach`] (`scope_pids`). [`v1_doctor_hint`] is the sentence
//! `aw doctor` should print; this module does not run that command.
//!
//! # Attach
//!
//! [`run_attach`] is linux.md §4.2:
//!
//! 1. The probes are already attached (the caller says so; this module does not
//!    load them). Write the root tgid into `scope_pids`. The kernel adds children
//!    on `sched_process_fork`. That hook is not implemented here.
//! 2. Scan `/proc` and write the descendants that already exist.
//! 3. Scan again and write anyone the first pass missed.
//!
//! `--move-to-cgroup` is optional ([`AttachRequest::move_to_cgroup`]). It is off
//! unless the caller sets it. Moving a live tree changes its resource controls
//! (process-tracking §5), so the default path never asks for it.
//!
//! # Cleanup
//!
//! [`cleanup_cgroup`] removes the session directory only when `cgroup.procs` is
//! empty. A directory that still holds a pid is left in place and the result
//! carries [`CGROUP_NONEMPTY_NOTE`].
//!
//! # Escape
//!
//! [`escape_gap`] turns one observation — a pid that was in the session cgroup
//! and is now in another — into a [`Gap`]. The source is
//! [`SOURCE_CGROUP_ESCAPE`] (`linux.ebpf/cgroup_attach_task`), matching the
//! `cgroup:cgroup_attach_task` tracepoint in linux.md §2.1. The kernel probe
//! itself is not attached by this module.

use aw_core::{Gap, GapKind, Source};

use crate::maps::SCOPE_CGROUPS;
use crate::maps::SCOPE_PIDS;

/// Session note when cleanup finds the cgroup still occupied.
///
/// Same register as `aw_collector_windows::BREAKAWAY_INCOMPLETE_NOTE`: a fixed
/// sentence, not a claim about what the leftover process did.
pub const CGROUP_NONEMPTY_NOTE: &str = "会话 cgroup 仍有进程，未删除";

/// `aw doctor` text when the host is cgroup v1.
///
/// Launch mode is not implemented on v1 (linux.md §4, P1-LNX-04). The process
/// tree is tracked through `scope_pids` instead. This function only returns the
/// sentence; it does not invoke `aw doctor`.
pub const V1_DOCTOR_HINT: &str = "检测到 cgroup v1：启动模式不可用，已退化为 scope_pids 进程树跟踪。cgroup v2 才能把进程关在会话目录里。";

/// Source stamped on an escape gap. The probe name is the tracepoint, not a guess.
pub const SOURCE_CGROUP_ESCAPE: &str = "linux.ebpf/cgroup_attach_task";

/// Slice path the daemon creates under the cgroup v2 mount.
///
/// linux.md §4.1 writes `/sys/fs/cgroup/agentwatch.slice/session-<sid>/`. The
/// mount point itself is a host concern ([`CgroupHost::mount_point`]); this
/// constant is the slice directory name.
pub const SLICE_NAME: &str = "agentwatch.slice";

/// How long `adopt` may take before the child is terminated. Five seconds, the
/// same bound the Windows launcher uses. Not measured on Linux (【待验证】).
pub const ADOPT_TIMEOUT_SECS: u64 = 5;

/// Which cgroup hierarchy the host reported.
///
/// SPIKE-05 did not probe this. The enum exists so a caller can pass a scripted
/// answer. [`CgroupVersion::Unknown`] is not treated as v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupVersion {
    /// Unified hierarchy. Launch mode is allowed.
    V2,
    /// Legacy hierarchy. Launch mode is refused; attach still tracks `scope_pids`.
    V1,
    /// The probe could not tell. Not a license to create a session directory.
    Unknown,
}

/// Whether systemd is managing the host's cgroups.
///
/// SPIKE-05 did not compare `StartTransientUnit` with a raw mkdir. Both paths
/// stay behind [`CgroupHost`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdPresence {
    /// A system bus is available. Try `StartTransientUnit` first.
    System,
    /// No systemd, or only a user instance this card does not call.
    Absent,
}

/// Who the launched process runs as. There is no root variant.
///
/// linux.md §4.1: the target runs as the user who invoked `aw`, not as the
/// daemon. Inheritance of the TTY, the environment, and the cwd is requested
/// and recorded as such. The values are not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchIdentity {
    /// The user who invoked `aw`. TTY, environment, and cwd are inherited.
    CallingUser,
}

/// Where the child is in the fork/exec handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchPhase {
    /// CLI has forked. The child has not reached the wait yet.
    Forked,
    /// Child is blocked on the pipe. exec has not happened.
    WaitingOnPipe,
    /// `adopt` returned. The child may exec.
    ReadyToExec,
    /// Adopt failed or timed out. The child was asked to die and must not exec.
    Terminated,
}

/// What one launch asks the daemon half to do.
///
/// `command_len` is the only trace of argv this module keeps. The strings
/// themselves stay in the CLI process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    /// Session id used in `session-<sid>`. `None` is not a valid id; callers
    /// pass [`ScopeError::MissingSession`] rather than inventing `0`.
    pub session_id: u64,
    /// Number of argv elements. Not the elements.
    pub command_len: usize,
    /// Always [`LaunchIdentity::CallingUser`].
    pub identity: LaunchIdentity,
    /// Always starts at [`LaunchPhase::WaitingOnPipe`]: the CLI has already forked.
    pub phase: LaunchPhase,
    /// Host hierarchy. [`CgroupVersion::V1`] refuses the launch.
    pub cgroup: CgroupVersion,
    /// Whether to try `StartTransientUnit` before mkdir.
    pub systemd: SystemdPresence,
}

impl LaunchRequest {
    /// A v2 launch for `session_id`, as the calling user, child already waiting.
    ///
    /// # Errors
    ///
    /// [`ScopeError::EmptyCommand`] when `command_len` is zero. An empty command
    /// is not a stand-in for "launch nothing".
    pub fn new(session_id: u64, command_len: usize) -> Result<Self, ScopeError> {
        if command_len == 0 {
            return Err(ScopeError::EmptyCommand);
        }
        Ok(Self {
            session_id,
            command_len,
            identity: LaunchIdentity::CallingUser,
            phase: LaunchPhase::WaitingOnPipe,
            cgroup: CgroupVersion::V2,
            systemd: SystemdPresence::System,
        })
    }

    /// Record the hierarchy the host probe reported.
    #[must_use]
    pub fn with_cgroup(mut self, cgroup: CgroupVersion) -> Self {
        self.cgroup = cgroup;
        self
    }

    /// Record whether systemd is present.
    #[must_use]
    pub fn with_systemd(mut self, systemd: SystemdPresence) -> Self {
        self.systemd = systemd;
        self
    }
}

/// One step [`run_launch`] took, in order. Tests assert on this list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchStep {
    /// Child was already forked and is waiting. Recorded, not performed here.
    Forked,
    /// Child is blocked on the pipe. Recorded, not performed here.
    WaitingOnPipe,
    /// D-Bus `StartTransientUnit` was attempted.
    StartTransientUnit,
    /// `StartTransientUnit` failed and the mkdir fallback was used.
    ///
    /// The failure is also on [`LaunchOutcome::transient_unit_error`]. This step
    /// existing means the fallback ran; it does not mean the D-Bus call succeeded.
    TransientUnitFellBack,
    /// `agentwatch.slice/session-<sid>` was created (by systemd or by mkdir).
    CreateSessionCgroup,
    /// The child pid was written to `cgroup.procs`.
    WriteCgroupProcs,
    /// The cgroup id was written to `scope_cgroups`.
    WriteScopeCgroups,
    /// Daemon `adopt`.
    Adopt,
    /// The child was told it may exec. Absent when adopt did not succeed.
    Exec,
    /// The child was terminated. Used on the adopt-failure path.
    Terminate,
}

/// How the session cgroup was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupCreatePath {
    /// `StartTransientUnit` returned success. SPIKE-05 did not measure this.
    TransientUnit,
    /// No systemd, so the host mkdir'd the directory directly.
    Mkdir,
    /// `StartTransientUnit` failed. The error is kept and mkdir was used.
    ///
    /// linux.md §4.1 marks the systemd-versus-mkdir choice 【待验证】. Falling
    /// back is the documented escape, and it is labeled rather than hidden.
    MkdirAfterTransientUnitFailed,
}

/// Why `adopt` did not return success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptWait {
    /// Daemon accepted the child.
    Adopted,
    /// [`ADOPT_TIMEOUT_SECS`] elapsed with no accept.
    TimedOut,
    /// The daemon refused, or the wait itself failed.
    Failed { detail: String },
}

/// What a finished launch reports.
///
/// `exec_allowed` is `true` only when [`LaunchStep::Exec`] is in `steps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchOutcome {
    /// Steps taken, in order.
    pub steps: Vec<LaunchStep>,
    /// Relative path `agentwatch.slice/session-<sid>`.
    pub session_dir: String,
    /// cgroup id written to `scope_cgroups`, when the host returned one.
    pub cgroup_id: Option<u64>,
    /// Which create path ran.
    pub created_via: CgroupCreatePath,
    /// `StartTransientUnit` error, when the fallback ran. `None` on a clean path.
    pub transient_unit_error: Option<String>,
    /// Child pid the host was given.
    pub pid: u32,
    /// `true` only after a successful adopt.
    pub exec_allowed: bool,
    /// Last phase. [`LaunchPhase::ReadyToExec`] or [`LaunchPhase::Terminated`].
    pub phase: LaunchPhase,
}

/// OS calls [`run_launch`] and [`cleanup_cgroup`] need. One method per step.
///
/// A test fake records calls and returns scripted answers. It must not fork and
/// must not write a cgroup file. [`UnverifiedCgroupHost`] is the stub and also
/// touches nothing.
pub trait CgroupHost {
    /// Hierarchy the host would report. Scripted in tests.
    fn cgroup_version(&mut self) -> CgroupVersion;

    /// Whether a system bus is available for `StartTransientUnit`.
    fn systemd(&mut self) -> SystemdPresence;

    /// Create a transient scope unit for `session_dir`.
    ///
    /// # Errors
    ///
    /// [`ScopeError::TransientUnitFailed`] when D-Bus refused. The caller falls
    /// back to [`Self::mkdir_session`] and keeps the message.
    fn start_transient_unit(&mut self, session_dir: &str) -> Result<(), ScopeError>;

    /// Create `session_dir` by mkdir. Used when systemd is absent, and as the
    /// labeled fallback when [`Self::start_transient_unit`] fails.
    ///
    /// # Errors
    ///
    /// [`ScopeError::CreateFailed`] when the directory was not created.
    fn mkdir_session(&mut self, session_dir: &str) -> Result<(), ScopeError>;

    /// Write `pid` into `<session_dir>/cgroup.procs`.
    ///
    /// # Errors
    ///
    /// [`ScopeError::WriteProcsFailed`] when the write did not land.
    fn write_cgroup_procs(&mut self, session_dir: &str, pid: u32) -> Result<(), ScopeError>;

    /// Look up the cgroup id of `session_dir`.
    ///
    /// `None` is not returned for "unknown": the host returns
    /// [`ScopeError::CgroupIdUnavailable`] with a reason, and the caller does not
    /// invent `0`.
    ///
    /// # Errors
    ///
    /// [`ScopeError::CgroupIdUnavailable`] when the id cannot be read.
    fn cgroup_id(&mut self, session_dir: &str) -> Result<u64, ScopeError>;

    /// Insert `cgroup_id` into the `scope_cgroups` map.
    ///
    /// # Errors
    ///
    /// [`ScopeError::MapUpdateFailed`] when the map refused the key.
    fn write_scope_cgroups(&mut self, cgroup_id: u64) -> Result<(), ScopeError>;

    /// Ask the daemon to adopt `pid` and wait up to [`ADOPT_TIMEOUT_SECS`].
    ///
    /// Failures are returned inside [`AdoptWait`], not as `Err`, so the machine
    /// can terminate without exec. `Err` is treated as [`AdoptWait::Failed`].
    fn adopt(&mut self, pid: u32) -> Result<AdoptWait, ScopeError>;

    /// Tell the waiting child it may exec. Called only after [`AdoptWait::Adopted`].
    ///
    /// # Errors
    ///
    /// [`ScopeError::ExecFailed`] when the pipe write failed. The caller terminates.
    fn release_exec(&mut self, pid: u32) -> Result<(), ScopeError>;

    /// End `pid`. Used when adopt did not succeed, and when exec itself failed.
    ///
    /// # Errors
    ///
    /// [`ScopeError::TerminateFailed`] when the process could not be ended. The
    /// machine still returns the original adopt error.
    fn terminate(&mut self, pid: u32) -> Result<(), ScopeError>;

    /// Pids currently in `<session_dir>/cgroup.procs`.
    ///
    /// An empty vec means the directory has no members. It does not mean the
    /// read failed — that is [`ScopeError::ReadProcsFailed`].
    ///
    /// # Errors
    ///
    /// [`ScopeError::ReadProcsFailed`] when the file could not be read. The caller
    /// must not delete a directory it could not inspect.
    fn cgroup_procs(&mut self, session_dir: &str) -> Result<Vec<u32>, ScopeError>;

    /// Remove `session_dir`. Called only when [`Self::cgroup_procs`] returned empty.
    ///
    /// # Errors
    ///
    /// [`ScopeError::RemoveFailed`] when the directory stayed.
    fn remove_session(&mut self, session_dir: &str) -> Result<(), ScopeError>;
}

/// Run the daemon half of a launch.
///
/// The child is already [`LaunchPhase::WaitingOnPipe`]. On adopt timeout or
/// adopt failure, [`LaunchStep::Exec`] is not recorded and the child is
/// terminated.
///
/// # Errors
///
/// [`ScopeError::CgroupV1NoLaunch`] on v1, before any directory is created.
/// [`ScopeError::NotWaiting`] when the child is not blocked on the pipe.
/// Other variants as listed on [`ScopeError`].
pub fn run_launch<H: CgroupHost>(
    host: &mut H,
    request: &LaunchRequest,
    pid: u32,
) -> Result<LaunchOutcome, ScopeError> {
    if request.identity != LaunchIdentity::CallingUser {
        return Err(ScopeError::NotCallingUser);
    }
    if request.phase != LaunchPhase::WaitingOnPipe {
        return Err(ScopeError::NotWaiting);
    }
    if request.command_len == 0 {
        return Err(ScopeError::EmptyCommand);
    }

    // The host's own probe wins over the request when they disagree, so a scripted
    // v1 host cannot be talked into creating a directory.
    let version = host.cgroup_version();
    if version != CgroupVersion::V2 || request.cgroup != CgroupVersion::V2 {
        return Err(ScopeError::CgroupV1NoLaunch);
    }

    let mut steps = vec![LaunchStep::Forked, LaunchStep::WaitingOnPipe];
    let session_dir = session_dir(request.session_id);

    let systemd = host.systemd();
    let (created_via, transient_unit_error) = if systemd == SystemdPresence::System {
        steps.push(LaunchStep::StartTransientUnit);
        match host.start_transient_unit(&session_dir) {
            Ok(()) => (CgroupCreatePath::TransientUnit, None),
            Err(err) => {
                let detail = err.to_string();
                steps.push(LaunchStep::TransientUnitFellBack);
                host.mkdir_session(&session_dir).map_err(|mkdir_err| {
                    ScopeError::CreateFailed {
                        detail: format!(
                            "StartTransientUnit failed ({detail}); mkdir fallback failed: {mkdir_err}"
                        ),
                    }
                })?;
                (
                    CgroupCreatePath::MkdirAfterTransientUnitFailed,
                    Some(detail),
                )
            }
        }
    } else {
        host.mkdir_session(&session_dir)?;
        (CgroupCreatePath::Mkdir, None)
    };
    steps.push(LaunchStep::CreateSessionCgroup);

    steps.push(LaunchStep::WriteCgroupProcs);
    if let Err(err) = host.write_cgroup_procs(&session_dir, pid) {
        steps.push(LaunchStep::Terminate);
        let _ = host.terminate(pid);
        return Err(err);
    }

    let cgroup_id = match host.cgroup_id(&session_dir) {
        Ok(id) => id,
        Err(err) => {
            steps.push(LaunchStep::Terminate);
            let _ = host.terminate(pid);
            return Err(err);
        }
    };
    steps.push(LaunchStep::WriteScopeCgroups);
    if let Err(err) = host.write_scope_cgroups(cgroup_id) {
        steps.push(LaunchStep::Terminate);
        let _ = host.terminate(pid);
        return Err(err);
    }

    steps.push(LaunchStep::Adopt);
    let waited = match host.adopt(pid) {
        Ok(waited) => waited,
        Err(err) => AdoptWait::Failed {
            detail: err.to_string(),
        },
    };
    match waited {
        AdoptWait::Adopted => {}
        AdoptWait::TimedOut => {
            steps.push(LaunchStep::Terminate);
            let _ = host.terminate(pid);
            return Err(ScopeError::AdoptTimeout);
        }
        AdoptWait::Failed { detail } => {
            steps.push(LaunchStep::Terminate);
            let _ = host.terminate(pid);
            return Err(ScopeError::AdoptFailed { detail });
        }
    }

    steps.push(LaunchStep::Exec);
    if let Err(err) = host.release_exec(pid) {
        steps.push(LaunchStep::Terminate);
        let _ = host.terminate(pid);
        return Err(err);
    }

    Ok(LaunchOutcome {
        steps,
        session_dir,
        cgroup_id: Some(cgroup_id),
        created_via,
        transient_unit_error,
        pid,
        exec_allowed: true,
        phase: LaunchPhase::ReadyToExec,
    })
}

/// `agentwatch.slice/session-<sid>`, relative to the cgroup v2 mount.
#[must_use]
pub fn session_dir(session_id: u64) -> String {
    format!("{SLICE_NAME}/session-{session_id}")
}

/// Doctor sentence for a v1 host. Does not run `aw doctor`.
#[must_use]
pub fn v1_doctor_hint() -> &'static str {
    V1_DOCTOR_HINT
}

/// Result of trying to remove a session cgroup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupOutcome {
    /// Directory the caller asked about.
    pub session_dir: String,
    /// `true` only when the directory was removed.
    pub removed: bool,
    /// Pids still inside, when it was kept. Empty when it was removed.
    pub remaining_pids: Vec<u32>,
    /// [`CGROUP_NONEMPTY_NOTE`] when the directory was kept because it was occupied.
    pub note: Option<&'static str>,
}

/// Remove `session_dir` when `cgroup.procs` is empty.
///
/// A non-empty directory is kept and [`CleanupOutcome::note`] is
/// [`CGROUP_NONEMPTY_NOTE`]. A failed read does not delete.
///
/// # Errors
///
/// [`ScopeError::ReadProcsFailed`] when membership could not be read.
/// [`ScopeError::RemoveFailed`] when an empty directory could not be removed.
pub fn cleanup_cgroup<H: CgroupHost>(
    host: &mut H,
    session_dir: &str,
) -> Result<CleanupOutcome, ScopeError> {
    let remaining = host.cgroup_procs(session_dir)?;
    if !remaining.is_empty() {
        return Ok(CleanupOutcome {
            session_dir: session_dir.to_owned(),
            removed: false,
            remaining_pids: remaining,
            note: Some(CGROUP_NONEMPTY_NOTE),
        });
    }
    host.remove_session(session_dir)?;
    Ok(CleanupOutcome {
        session_dir: session_dir.to_owned(),
        removed: true,
        remaining_pids: Vec::new(),
        note: None,
    })
}

/// One `/proc` row a scan returned.
///
/// `ppid` is `None` when the row had no parent. `0` is not used for that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcRow {
    /// Thread-group id.
    pub tgid: u32,
    /// Parent tgid, when the scan had one.
    pub ppid: Option<u32>,
}

/// Reads the process table. Tests pass a fake table. A live `/proc` walk is
/// 【待验证】 and is not implemented here.
pub trait ProcScan {
    /// Rows visible at this moment. Order is the order the scan observed them.
    fn scan(&mut self) -> Result<Vec<ProcRow>, ScopeError>;
}

/// Writes the `scope_pids` map and, optionally, moves a pid into the session cgroup.
pub trait ScopeMap {
    /// Insert `tgid` into `scope_pids`.
    ///
    /// # Errors
    ///
    /// [`ScopeError::MapUpdateFailed`] when the map refused the key.
    fn insert_scope_pid(&mut self, tgid: u32) -> Result<(), ScopeError>;

    /// Move `tgid` into `session_dir` (`cgroup.procs`). Only called when
    /// [`AttachRequest::move_to_cgroup`] is set.
    ///
    /// # Errors
    ///
    /// [`ScopeError::WriteProcsFailed`] when the write did not land.
    fn move_into_cgroup(&mut self, session_dir: &str, tgid: u32) -> Result<(), ScopeError>;
}

/// What one `aw attach` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachRequest {
    /// Root tgid the operator named (`--pid`).
    pub root_tgid: u32,
    /// Session directory, required only when `move_to_cgroup` is set.
    ///
    /// `None` with `move_to_cgroup == true` is [`ScopeError::MissingSession`],
    /// not an empty path.
    pub session_dir: Option<String>,
    /// `--move-to-cgroup`. Default is off.
    pub move_to_cgroup: bool,
}

impl AttachRequest {
    /// Attach to `root_tgid` without moving it into a cgroup.
    #[must_use]
    pub fn new(root_tgid: u32) -> Self {
        Self {
            root_tgid,
            session_dir: None,
            move_to_cgroup: false,
        }
    }

    /// Set `--move-to-cgroup` and the directory the tree should move into.
    #[must_use]
    pub fn with_move(mut self, session_dir: impl Into<String>) -> Self {
        self.move_to_cgroup = true;
        self.session_dir = Some(session_dir.into());
        self
    }
}

/// One step [`run_attach`] took, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachStep {
    /// Probes are already attached. Recorded, not performed here.
    ProbesAttached,
    /// Root tgid written to `scope_pids`.
    WriteRootPid,
    /// First `/proc` scan, writing descendants that already exist.
    FirstScan,
    /// Second scan, writing anyone the first pass missed.
    Rescan,
    /// Optional: a pid was written to the session `cgroup.procs`.
    MoveToCgroup,
}

/// What a finished attach reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachOutcome {
    /// Steps taken, in order.
    pub steps: Vec<AttachStep>,
    /// Tgids written to `scope_pids`, root first, then first-scan, then rescan.
    pub scope_pids: Vec<u32>,
    /// Tgids moved into the session cgroup. Empty when the flag was off.
    pub moved: Vec<u32>,
    /// `true` when `--move-to-cgroup` was set.
    pub move_to_cgroup: bool,
}

/// Attach to a running tree.
///
/// Order is fixed: root tgid into `scope_pids`, then a scan, then a second scan.
/// The kernel's fork hook is what closes the race for children born after the
/// probes attach; this function only writes the maps. See the module note.
///
/// # Errors
///
/// [`ScopeError::MissingSession`] when the move flag is set and no directory was
/// given. [`ScopeError::RootNotFound`] when neither scan contains the root.
/// Map errors as listed on [`ScopeError`].
pub fn run_attach<S: ProcScan, M: ScopeMap>(
    scan: &mut S,
    map: &mut M,
    request: &AttachRequest,
) -> Result<AttachOutcome, ScopeError> {
    if request.move_to_cgroup && request.session_dir.is_none() {
        return Err(ScopeError::MissingSession);
    }
    let mut steps = vec![AttachStep::ProbesAttached, AttachStep::WriteRootPid];
    let mut scope_pids = Vec::new();
    let mut moved = Vec::new();

    // The root goes in before either scan, so a child forked while we walk
    // `/proc` is caught by the kernel hook rather than by this scan. The hook
    // itself is not in this crate.
    map.insert_scope_pid(request.root_tgid)?;
    scope_pids.push(request.root_tgid);
    if request.move_to_cgroup {
        let dir = request
            .session_dir
            .as_deref()
            .ok_or(ScopeError::MissingSession)?;
        steps.push(AttachStep::MoveToCgroup);
        map.move_into_cgroup(dir, request.root_tgid)?;
        moved.push(request.root_tgid);
    }

    steps.push(AttachStep::FirstScan);
    let first = scan.scan()?;
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(request.root_tgid);
    write_descendants(
        map,
        &first,
        request,
        &mut seen,
        &mut scope_pids,
        &mut moved,
        &mut steps,
    )?;

    steps.push(AttachStep::Rescan);
    let second = scan.scan()?;
    write_descendants(
        map,
        &second,
        request,
        &mut seen,
        &mut scope_pids,
        &mut moved,
        &mut steps,
    )?;

    if !seen.contains(&request.root_tgid)
        || !first
            .iter()
            .chain(second.iter())
            .any(|row| row.tgid == request.root_tgid)
    {
        // The root was written before the scans. If neither scan saw it, the
        // operator named a pid that is not in the table. The map insert already
        // happened; the caller still hears about it instead of a silent success.
        return Err(ScopeError::RootNotFound {
            tgid: request.root_tgid,
        });
    }

    Ok(AttachOutcome {
        steps,
        scope_pids,
        moved,
        move_to_cgroup: request.move_to_cgroup,
    })
}

/// Walk `rows` and write descendants of the root that are not in `seen` yet.
fn write_descendants<M: ScopeMap>(
    map: &mut M,
    rows: &[ProcRow],
    request: &AttachRequest,
    seen: &mut std::collections::BTreeSet<u32>,
    scope_pids: &mut Vec<u32>,
    moved: &mut Vec<u32>,
    steps: &mut Vec<AttachStep>,
) -> Result<(), ScopeError> {
    // Parent-before-child, so a grandchild whose parent is also new this pass
    // is included. Bound the walk by the row count; a cycle would otherwise spin.
    let mut progressed = true;
    let mut guard = 0;
    let limit = rows.len().saturating_add(1);
    while progressed && guard < limit {
        progressed = false;
        guard = guard.saturating_add(1);
        for row in rows {
            if seen.contains(&row.tgid) {
                continue;
            }
            let Some(ppid) = row.ppid else {
                continue;
            };
            if !seen.contains(&ppid) {
                continue;
            }
            map.insert_scope_pid(row.tgid)?;
            seen.insert(row.tgid);
            scope_pids.push(row.tgid);
            if request.move_to_cgroup {
                let dir = request
                    .session_dir
                    .as_deref()
                    .ok_or(ScopeError::MissingSession)?;
                steps.push(AttachStep::MoveToCgroup);
                map.move_into_cgroup(dir, row.tgid)?;
                moved.push(row.tgid);
            }
            progressed = true;
        }
    }
    Ok(())
}

/// One observation that a pid left the session cgroup.
///
/// `from_cgroup_id` / `to_cgroup_id` come from the `cgroup:cgroup_attach_task`
/// tracepoint (linux.md §2.1). `None` means that side was not in the record.
/// `0` is not used as "unknown".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscapeObservation {
    /// tgid that moved.
    pub tgid: u32,
    /// Session cgroup id the process was in.
    pub session_cgroup_id: u64,
    /// Destination cgroup id, when the record had one.
    pub destination_cgroup_id: Option<u64>,
    /// Monotonic time the move was observed, in nanoseconds.
    pub mono_ns: u64,
}

/// A [`Gap`] for a process that left the session cgroup.
///
/// `source` is [`SOURCE_CGROUP_ESCAPE`]. `gap_kind` is [`GapKind::ScopeRace`]:
/// the process is no longer inside the watched scope. `count` is `Some(1)`
/// because this is one observed move, not an unknown loss. The detail names the
/// tgid and the two cgroup ids; it does not name a command line.
#[must_use]
pub fn escape_gap(obs: &EscapeObservation) -> Gap {
    let destination = match obs.destination_cgroup_id {
        Some(id) => format!("{id}"),
        None => "unavailable".to_owned(),
    };
    Gap::new(
        Source::new(SOURCE_CGROUP_ESCAPE),
        GapKind::ScopeRace,
        vec!["proc".to_owned(), "file".to_owned(), "net".to_owned()],
        obs.mono_ns,
        obs.mono_ns,
        Some(1),
        Some(format!(
            "pid {} left session cgroup {} for cgroup {destination}",
            obs.tgid, obs.session_cgroup_id
        )),
    )
}

/// Why a scope operation stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    /// [`LaunchRequest::new`] was given no command.
    EmptyCommand,
    /// The request's identity was not [`LaunchIdentity::CallingUser`].
    ///
    /// The enum has one variant today. The guard stays so a future variant
    /// cannot silently become a root launch.
    NotCallingUser,
    /// The child was not in [`LaunchPhase::WaitingOnPipe`].
    NotWaiting,
    /// Host is cgroup v1 (or the version is unknown). No session directory was
    /// created. [`v1_doctor_hint`] is the sentence for `aw doctor`.
    CgroupV1NoLaunch,
    /// `StartTransientUnit` failed. Carried into the mkdir fallback; also
    /// returned directly when the caller asked not to fall back.
    TransientUnitFailed { detail: String },
    /// The session directory was not created.
    CreateFailed { detail: String },
    /// `cgroup.procs` was not written.
    WriteProcsFailed { detail: String },
    /// The cgroup id could not be read. Not substituted with `0`.
    CgroupIdUnavailable { detail: String },
    /// `scope_cgroups` or `scope_pids` refused the update.
    MapUpdateFailed { detail: String },
    /// `adopt` did not succeed within [`ADOPT_TIMEOUT_SECS`]. The child was
    /// terminated and was not told to exec.
    AdoptTimeout,
    /// `adopt` failed for a reason other than the timeout. The child was
    /// terminated and was not told to exec.
    AdoptFailed { detail: String },
    /// The pipe write that releases exec failed. The child was terminated.
    ExecFailed { detail: String },
    /// The child could not be ended.
    TerminateFailed { detail: String },
    /// `cgroup.procs` could not be read, so the directory was not removed.
    ReadProcsFailed { detail: String },
    /// An empty session directory could not be removed.
    RemoveFailed { detail: String },
    /// `--move-to-cgroup` was set and no session directory was given.
    MissingSession,
    /// The root tgid was in neither scan.
    RootNotFound { tgid: u32 },
    /// [`UnverifiedCgroupHost`] was used. No cgroup call was made.
    NotVerified { step: &'static str },
}

impl std::fmt::Display for ScopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCommand => f.write_str("launch command is empty"),
            Self::NotCallingUser => {
                f.write_str("only the calling user may launch; root is not a path")
            }
            Self::NotWaiting => f.write_str("child is not waiting on the pipe"),
            Self::CgroupV1NoLaunch => f.write_str(V1_DOCTOR_HINT),
            Self::TransientUnitFailed { detail } => {
                write!(f, "StartTransientUnit failed: {detail}")
            }
            Self::CreateFailed { detail } => write!(f, "session cgroup was not created: {detail}"),
            Self::WriteProcsFailed { detail } => {
                write!(f, "writing cgroup.procs failed: {detail}")
            }
            Self::CgroupIdUnavailable { detail } => {
                write!(f, "cgroup id is unavailable: {detail}")
            }
            Self::MapUpdateFailed { detail } => write!(f, "scope map update failed: {detail}"),
            Self::AdoptTimeout => {
                f.write_str("adopt timed out; the child was terminated and did not exec")
            }
            Self::AdoptFailed { detail } => write!(f, "adopt failed: {detail}"),
            Self::ExecFailed { detail } => write!(f, "releasing exec failed: {detail}"),
            Self::TerminateFailed { detail } => write!(f, "terminating the child failed: {detail}"),
            Self::ReadProcsFailed { detail } => {
                write!(f, "reading cgroup.procs failed: {detail}")
            }
            Self::RemoveFailed { detail } => {
                write!(f, "removing the session cgroup failed: {detail}")
            }
            Self::MissingSession => {
                f.write_str("move-to-cgroup was set but no session directory was given")
            }
            Self::RootNotFound { tgid } => {
                write!(f, "tgid {tgid} is not in the process table")
            }
            Self::NotVerified { step } => write!(
                f,
                "{step} is not verified in this environment; no cgroup was touched"
            ),
        }
    }
}

impl std::error::Error for ScopeError {}

/// Linux stub. Compiles only on Linux. Touches nothing.
///
/// SPIKE-05 did not run on Linux, so this type refuses every step with
/// [`ScopeError::NotVerified`] instead of writing `/sys/fs/cgroup` from a
/// default test or from an unwired command.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct UnverifiedCgroupHost;

#[cfg(target_os = "linux")]
impl CgroupHost for UnverifiedCgroupHost {
    fn cgroup_version(&mut self) -> CgroupVersion {
        CgroupVersion::Unknown
    }

    fn systemd(&mut self) -> SystemdPresence {
        SystemdPresence::Absent
    }

    fn start_transient_unit(&mut self, _session_dir: &str) -> Result<(), ScopeError> {
        Err(ScopeError::NotVerified {
            step: "StartTransientUnit",
        })
    }

    fn mkdir_session(&mut self, _session_dir: &str) -> Result<(), ScopeError> {
        Err(ScopeError::NotVerified {
            step: "mkdir agentwatch.slice/session-<sid>",
        })
    }

    fn write_cgroup_procs(&mut self, _session_dir: &str, _pid: u32) -> Result<(), ScopeError> {
        Err(ScopeError::NotVerified {
            step: "write cgroup.procs",
        })
    }

    fn cgroup_id(&mut self, _session_dir: &str) -> Result<u64, ScopeError> {
        Err(ScopeError::NotVerified {
            step: "read cgroup id",
        })
    }

    fn write_scope_cgroups(&mut self, _cgroup_id: u64) -> Result<(), ScopeError> {
        Err(ScopeError::NotVerified {
            step: "update scope_cgroups",
        })
    }

    fn adopt(&mut self, _pid: u32) -> Result<AdoptWait, ScopeError> {
        Err(ScopeError::NotVerified { step: "adopt" })
    }

    fn release_exec(&mut self, _pid: u32) -> Result<(), ScopeError> {
        Err(ScopeError::NotVerified {
            step: "release exec",
        })
    }

    fn terminate(&mut self, _pid: u32) -> Result<(), ScopeError> {
        Err(ScopeError::NotVerified {
            step: "terminate child",
        })
    }

    fn cgroup_procs(&mut self, _session_dir: &str) -> Result<Vec<u32>, ScopeError> {
        Err(ScopeError::NotVerified {
            step: "read cgroup.procs",
        })
    }

    fn remove_session(&mut self, _session_dir: &str) -> Result<(), ScopeError> {
        Err(ScopeError::NotVerified {
            step: "rmdir session cgroup",
        })
    }
}

/// Map name a caller should update. Re-exported so tests can name it without
/// reaching into [`crate::maps`] twice. The kernel side is not updated here.
#[must_use]
pub fn scope_cgroups_map() -> &'static str {
    SCOPE_CGROUPS
}

/// Map name attach mode writes. The kernel fork hook that auto-includes a child
/// is not implemented in this crate.
#[must_use]
pub fn scope_pids_map() -> &'static str {
    SCOPE_PIDS
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FakeHost {
        version: CgroupVersion,
        systemd: SystemdPresence,
        transient_fails: bool,
        adopt: AdoptWait,
        cgroup_id: u64,
        procs: Vec<u32>,
        steps: Vec<LaunchStep>,
        terminated: bool,
        exec_released: bool,
        removed: bool,
        created_dirs: Vec<String>,
        wrote_pid: Option<u32>,
        wrote_cgroup: Option<u64>,
    }

    impl FakeHost {
        fn v2(adopt: AdoptWait) -> Self {
            Self {
                version: CgroupVersion::V2,
                systemd: SystemdPresence::System,
                transient_fails: false,
                adopt,
                cgroup_id: 0xC0_u64,
                procs: Vec::new(),
                steps: Vec::new(),
                terminated: false,
                exec_released: false,
                removed: false,
                created_dirs: Vec::new(),
                wrote_pid: None,
                wrote_cgroup: None,
            }
        }
    }

    impl CgroupHost for FakeHost {
        fn cgroup_version(&mut self) -> CgroupVersion {
            self.version
        }

        fn systemd(&mut self) -> SystemdPresence {
            self.systemd
        }

        fn start_transient_unit(&mut self, session_dir: &str) -> Result<(), ScopeError> {
            self.steps.push(LaunchStep::StartTransientUnit);
            if self.transient_fails {
                return Err(ScopeError::TransientUnitFailed {
                    detail: "scripted dbus refusal".to_owned(),
                });
            }
            self.created_dirs.push(session_dir.to_owned());
            Ok(())
        }

        fn mkdir_session(&mut self, session_dir: &str) -> Result<(), ScopeError> {
            self.created_dirs.push(session_dir.to_owned());
            Ok(())
        }

        fn write_cgroup_procs(&mut self, _session_dir: &str, pid: u32) -> Result<(), ScopeError> {
            self.steps.push(LaunchStep::WriteCgroupProcs);
            self.wrote_pid = Some(pid);
            self.procs.push(pid);
            Ok(())
        }

        fn cgroup_id(&mut self, _session_dir: &str) -> Result<u64, ScopeError> {
            Ok(self.cgroup_id)
        }

        fn write_scope_cgroups(&mut self, cgroup_id: u64) -> Result<(), ScopeError> {
            self.steps.push(LaunchStep::WriteScopeCgroups);
            self.wrote_cgroup = Some(cgroup_id);
            Ok(())
        }

        fn adopt(&mut self, _pid: u32) -> Result<AdoptWait, ScopeError> {
            self.steps.push(LaunchStep::Adopt);
            Ok(self.adopt.clone())
        }

        fn release_exec(&mut self, _pid: u32) -> Result<(), ScopeError> {
            self.steps.push(LaunchStep::Exec);
            self.exec_released = true;
            Ok(())
        }

        fn terminate(&mut self, pid: u32) -> Result<(), ScopeError> {
            self.steps.push(LaunchStep::Terminate);
            self.terminated = true;
            self.procs.retain(|existing| *existing != pid);
            Ok(())
        }

        fn cgroup_procs(&mut self, _session_dir: &str) -> Result<Vec<u32>, ScopeError> {
            Ok(self.procs.clone())
        }

        fn remove_session(&mut self, _session_dir: &str) -> Result<(), ScopeError> {
            self.removed = true;
            Ok(())
        }
    }

    fn request() -> LaunchRequest {
        LaunchRequest::new(7, 2).expect("command")
    }

    #[test]
    fn launch_steps_run_fork_cgroup_procs_map_adopt_exec() {
        let mut host = FakeHost::v2(AdoptWait::Adopted);
        let done = run_launch(&mut host, &request(), 4242).expect("launch");
        assert_eq!(
            done.steps,
            vec![
                LaunchStep::Forked,
                LaunchStep::WaitingOnPipe,
                LaunchStep::StartTransientUnit,
                LaunchStep::CreateSessionCgroup,
                LaunchStep::WriteCgroupProcs,
                LaunchStep::WriteScopeCgroups,
                LaunchStep::Adopt,
                LaunchStep::Exec,
            ]
        );
        let adopt_at = done
            .steps
            .iter()
            .position(|step| *step == LaunchStep::Adopt)
            .expect("adopt");
        let exec_at = done
            .steps
            .iter()
            .position(|step| *step == LaunchStep::Exec)
            .expect("exec");
        assert!(adopt_at < exec_at);
        assert!(done.exec_allowed);
        assert_eq!(done.phase, LaunchPhase::ReadyToExec);
        assert!(host.exec_released);
        assert!(!host.terminated);
        assert_eq!(host.wrote_pid, Some(4242));
        assert_eq!(host.wrote_cgroup, Some(0xC0));
        assert_eq!(done.created_via, CgroupCreatePath::TransientUnit);
        assert_eq!(done.transient_unit_error, None);
        assert_eq!(done.session_dir, "agentwatch.slice/session-7");
        assert_eq!(scope_cgroups_map(), "scope_cgroups");
    }

    #[test]
    fn adopt_failure_does_not_exec_and_terminates() {
        let mut host = FakeHost::v2(AdoptWait::Failed {
            detail: "daemon refused".to_owned(),
        });
        let err = run_launch(&mut host, &request(), 4242).expect_err("adopt");
        assert_eq!(
            err,
            ScopeError::AdoptFailed {
                detail: "daemon refused".to_owned(),
            }
        );
        assert!(host.terminated);
        assert!(!host.exec_released);
        assert!(!host.steps.contains(&LaunchStep::Exec));
        assert_eq!(*host.steps.last().expect("last"), LaunchStep::Terminate);
    }

    #[test]
    fn adopt_timeout_does_not_exec_and_terminates() {
        let mut host = FakeHost::v2(AdoptWait::TimedOut);
        let err = run_launch(&mut host, &request(), 4242).expect_err("timeout");
        assert_eq!(err, ScopeError::AdoptTimeout);
        assert!(host.terminated);
        assert!(!host.exec_released);
        assert!(!host.steps.contains(&LaunchStep::Exec));
        assert_eq!(ADOPT_TIMEOUT_SECS, 5);
    }

    #[test]
    fn transient_unit_failure_is_labeled_and_falls_back() {
        let mut host = FakeHost::v2(AdoptWait::Adopted);
        host.transient_fails = true;
        let done = run_launch(&mut host, &request(), 4242).expect("fallback");
        assert_eq!(
            done.created_via,
            CgroupCreatePath::MkdirAfterTransientUnitFailed
        );
        assert_eq!(
            done.transient_unit_error.as_deref(),
            Some("StartTransientUnit failed: scripted dbus refusal")
        );
        assert!(done.steps.contains(&LaunchStep::TransientUnitFellBack));
        assert!(done.exec_allowed);
    }

    #[test]
    fn nonempty_cgroup_is_kept_with_a_note() {
        let mut host = FakeHost::v2(AdoptWait::Adopted);
        host.procs = vec![9, 10];
        let outcome = cleanup_cgroup(&mut host, "agentwatch.slice/session-7").expect("cleanup");
        assert!(!outcome.removed);
        assert!(!host.removed);
        assert_eq!(outcome.remaining_pids, vec![9, 10]);
        assert_eq!(outcome.note, Some(CGROUP_NONEMPTY_NOTE));
        assert_eq!(outcome.note, Some("会话 cgroup 仍有进程，未删除"));
    }

    #[test]
    fn empty_cgroup_is_removed_without_a_note() {
        let mut host = FakeHost::v2(AdoptWait::Adopted);
        let outcome = cleanup_cgroup(&mut host, "agentwatch.slice/session-7").expect("cleanup");
        assert!(outcome.removed);
        assert!(host.removed);
        assert!(outcome.remaining_pids.is_empty());
        assert_eq!(outcome.note, None);
    }

    #[derive(Debug)]
    struct FakeScan {
        passes: Vec<Vec<ProcRow>>,
        calls: usize,
    }

    impl ProcScan for FakeScan {
        fn scan(&mut self) -> Result<Vec<ProcRow>, ScopeError> {
            let rows = self.passes.get(self.calls).cloned().unwrap_or_default();
            self.calls = self.calls.saturating_add(1);
            Ok(rows)
        }
    }

    #[derive(Debug, Default)]
    struct FakeMap {
        pids: Vec<u32>,
        moved: Vec<u32>,
    }

    impl ScopeMap for FakeMap {
        fn insert_scope_pid(&mut self, tgid: u32) -> Result<(), ScopeError> {
            self.pids.push(tgid);
            Ok(())
        }

        fn move_into_cgroup(&mut self, _session_dir: &str, tgid: u32) -> Result<(), ScopeError> {
            self.moved.push(tgid);
            Ok(())
        }
    }

    fn row(tgid: u32, ppid: Option<u32>) -> ProcRow {
        ProcRow { tgid, ppid }
    }

    #[test]
    fn attach_order_is_root_then_scan_then_rescan() {
        // First pass sees the root and one child. The second pass adds a grandchild
        // that appeared between the two scans.
        let mut scan = FakeScan {
            passes: vec![
                vec![row(1, None), row(2, Some(1))],
                vec![row(1, None), row(2, Some(1)), row(3, Some(2))],
            ],
            calls: 0,
        };
        let mut map = FakeMap::default();
        let done = run_attach(&mut scan, &mut map, &AttachRequest::new(1)).expect("attach");
        assert_eq!(
            done.steps,
            vec![
                AttachStep::ProbesAttached,
                AttachStep::WriteRootPid,
                AttachStep::FirstScan,
                AttachStep::Rescan,
            ]
        );
        assert_eq!(done.scope_pids, vec![1, 2, 3]);
        assert!(done.moved.is_empty());
        assert!(!done.move_to_cgroup);
        assert_eq!(scan.calls, 2);
        assert_eq!(scope_pids_map(), "scope_pids");
        let root_at = done
            .steps
            .iter()
            .position(|step| *step == AttachStep::WriteRootPid)
            .expect("root");
        let first_at = done
            .steps
            .iter()
            .position(|step| *step == AttachStep::FirstScan)
            .expect("first");
        let rescan_at = done
            .steps
            .iter()
            .position(|step| *step == AttachStep::Rescan)
            .expect("rescan");
        assert!(root_at < first_at && first_at < rescan_at);
    }

    #[test]
    fn move_to_cgroup_writes_every_member() {
        let mut scan = FakeScan {
            passes: vec![
                vec![row(10, Some(0)), row(11, Some(10))],
                vec![row(10, Some(0)), row(11, Some(10))],
            ],
            calls: 0,
        };
        let mut map = FakeMap::default();
        let request = AttachRequest::new(10).with_move("agentwatch.slice/session-7");
        let done = run_attach(&mut scan, &mut map, &request).expect("attach");
        assert!(done.move_to_cgroup);
        assert_eq!(done.moved, vec![10, 11]);
        assert_eq!(done.scope_pids, vec![10, 11]);
        assert!(done.steps.contains(&AttachStep::MoveToCgroup));
    }

    #[test]
    fn move_flag_off_does_not_move() {
        let mut scan = FakeScan {
            passes: vec![vec![row(10, None)], vec![row(10, None)]],
            calls: 0,
        };
        let mut map = FakeMap::default();
        let done = run_attach(&mut scan, &mut map, &AttachRequest::new(10)).expect("attach");
        assert!(!done.move_to_cgroup);
        assert!(done.moved.is_empty());
        assert!(map.moved.is_empty());
        assert!(!done.steps.contains(&AttachStep::MoveToCgroup));
    }

    #[test]
    fn cgroup_v1_refuses_launch_and_names_the_doctor_hint() {
        let mut host = FakeHost::v2(AdoptWait::Adopted);
        host.version = CgroupVersion::V1;
        let err =
            run_launch(&mut host, &request().with_cgroup(CgroupVersion::V1), 4242).expect_err("v1");
        assert_eq!(err, ScopeError::CgroupV1NoLaunch);
        assert_eq!(err.to_string(), v1_doctor_hint());
        assert!(host.created_dirs.is_empty());
        assert!(!host.exec_released);
        assert!(!host.terminated);
        assert!(host.steps.is_empty());
        assert!(v1_doctor_hint().contains("scope_pids"));
    }

    #[test]
    fn escape_observation_is_a_scope_race_gap() {
        let gap = escape_gap(&EscapeObservation {
            tgid: 42,
            session_cgroup_id: 100,
            destination_cgroup_id: Some(200),
            mono_ns: 5_000,
        });
        assert_eq!(gap.collector.as_str(), SOURCE_CGROUP_ESCAPE);
        assert_eq!(gap.collector.as_str(), "linux.ebpf/cgroup_attach_task");
        assert_eq!(gap.gap_kind, GapKind::ScopeRace);
        assert_eq!(gap.count, Some(1));
        assert_eq!(gap.from_mono_ns, 5_000);
        assert_eq!(gap.to_mono_ns, 5_000);
        assert!(gap.affects.iter().any(|item| item == "proc"));
        let detail = gap.detail.expect("detail");
        assert!(detail.contains("42"));
        assert!(detail.contains("100"));
        assert!(detail.contains("200"));
        assert!(detail.contains("left session cgroup"));
    }

    #[test]
    fn escape_without_a_destination_does_not_invent_zero() {
        let gap = escape_gap(&EscapeObservation {
            tgid: 7,
            session_cgroup_id: 9,
            destination_cgroup_id: None,
            mono_ns: 1,
        });
        let detail = gap.detail.expect("detail");
        assert!(detail.contains("unavailable"));
        assert!(!detail.contains("cgroup 0"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unverified_stub_does_not_create_a_cgroup() {
        let mut host = UnverifiedCgroupHost;
        let err = run_launch(&mut host, &request(), 1).expect_err("stub");
        assert_eq!(err, ScopeError::CgroupV1NoLaunch);
    }
}
