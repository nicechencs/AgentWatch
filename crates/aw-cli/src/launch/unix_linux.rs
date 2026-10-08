//! Linux cgroup v2 launch state machine (P1-LNX-04, linux.md §4.1).
//!
//! Wired by P1-CLI-02's `launch/mod.rs` under `cfg(target_os = "linux")`. The
//! `mod unix_linux;` line in `launch/mod.rs` is unconditional for now, so the
//! state machine compiles and its tests run on Windows. P1-CLI-02 should gate
//! that line with `cfg(target_os = "linux")` when it dispatches `aw run`.
//!
//! The steps, in order:
//!
//! 1. CLI forks. The child blocks on a pipe before exec
//!    ([`LaunchPhase::Forked`], then [`LaunchPhase::WaitingOnPipe`]).
//! 2. The daemon creates `agentwatch.slice/session-<sid>`. On a systemd system
//!    it tries D-Bus `StartTransientUnit` first. A failure is not silent: the
//!    result records it and the mkdir fallback runs.
//! 3. The daemon writes the child into `cgroup.procs` and the cgroup id into
//!    `scope_cgroups`.
//! 4. `adopt` returns.
//! 5. Only then does the child exec.
//!
//! [`CgroupLaunch`] is the only place those calls exist. [`run_launch`] is pure:
//! it records the calls and stops. The default tests pass a fake. They do not
//! fork and they do not write `/sys/fs/cgroup`.
//!
//! # Identity
//!
//! The target runs as the user who invoked `aw`. [`LaunchIdentity::CallingUser`]
//! is the only identity this module accepts. There is no root path: the daemon
//! does not exec the target. TTY, environment, and cwd are recorded as
//! "inheritance requested". The environment values are not stored.
//!
//! # What is not verified
//!
//! SPIKE-05 did not run on Linux. cgroup v2, `StartTransientUnit`, and the
//! pipe-then-exec handshake are 【待验证】. [`UnverifiedCgroupLaunch`] is the
//! Linux stub. Every method returns [`LaunchError::NotVerified`]. It does not
//! fork. Default tests do not construct it.
//!
//! # Adopt timeout
//!
//! [`ADOPT_TIMEOUT`] is five seconds. On timeout, and on adopt failure, the
//! machine terminates the child and does not exec. The step list has no
//! [`LaunchStep::Exec`].
//!
//! # cgroup v1
//!
//! Launch mode is not implemented on v1. [`run_launch`] returns
//! [`LaunchError::CgroupV1NoLaunch`] and creates no session directory. The
//! doctor sentence is [`V1_DOCTOR_HINT`]; this module does not run `aw doctor`.
//! Tracking then falls back to `scope_pids` in `aw-collector-linux`.

use std::time::Duration;

/// How long `adopt` may take before the child is terminated. Five seconds.
pub const ADOPT_TIMEOUT: Duration = Duration::from_secs(5);

/// `aw doctor` text when the host is cgroup v1.
///
/// Launch mode is refused. The process tree is tracked through `scope_pids`
/// instead. This module returns the sentence; it does not invoke `aw doctor`.
pub const V1_DOCTOR_HINT: &str = "检测到 cgroup v1：启动模式不可用，已退化为 scope_pids 进程树跟踪。cgroup v2 才能把进程关在会话目录里。";

/// Slice directory under the cgroup v2 mount (linux.md §4.1).
pub const SLICE_NAME: &str = "agentwatch.slice";

/// Who the target process runs as. There is no root variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchIdentity {
    /// The user who invoked `aw`. TTY, environment, and cwd are inherited.
    CallingUser,
}

/// Where the child is in the fork/exec handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchPhase {
    /// `fork` returned. The child has not reached the pipe yet.
    Forked,
    /// Child is blocked on the pipe. exec has not happened.
    WaitingOnPipe,
    /// `adopt` returned. The child may exec.
    ReadyToExec,
    /// Adopt failed or timed out. The child was asked to die and must not exec.
    Terminated,
}

/// Which cgroup hierarchy the host reported.
///
/// [`CgroupVersion::Unknown`] is not treated as v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CgroupVersion {
    /// Unified hierarchy. Launch mode is allowed.
    V2,
    /// Legacy hierarchy. Launch mode is refused.
    V1,
    /// The probe could not tell. Not a license to create a session directory.
    Unknown,
}

/// Whether systemd is managing the host's cgroups.
///
/// SPIKE-05 did not compare `StartTransientUnit` with a raw mkdir. Both stay
/// behind [`CgroupLaunch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdPresence {
    /// A system bus is available. Try `StartTransientUnit` first.
    System,
    /// No systemd. The session directory is created with mkdir.
    Absent,
}

/// What one `aw run` asks the state machine to do.
///
/// `command` is the argv the child will exec. It is not logged. [`Debug`] prints
/// the length only, so a `{:?}` on this struct does not leak the arguments.
#[derive(Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    command: Vec<String>,
    /// Always [`LaunchIdentity::CallingUser`].
    pub identity: LaunchIdentity,
    /// Host hierarchy. [`CgroupVersion::V1`] refuses the launch.
    pub cgroup: CgroupVersion,
    /// Whether to try `StartTransientUnit` before mkdir.
    pub systemd: SystemdPresence,
    /// Session id used in `session-<sid>`.
    pub session_id: u64,
}

impl std::fmt::Debug for LaunchRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchRequest")
            .field("command_len", &self.command.len())
            .field("identity", &self.identity)
            .field("cgroup", &self.cgroup)
            .field("systemd", &self.systemd)
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl LaunchRequest {
    /// A v2 launch of `command` as the calling user, on a systemd host.
    ///
    /// # Errors
    ///
    /// [`LaunchError::EmptyCommand`] when `command` is empty. An empty command
    /// is not a stand-in for "launch nothing".
    pub fn new(session_id: u64, command: Vec<String>) -> Result<Self, LaunchError> {
        if command.is_empty() {
            return Err(LaunchError::EmptyCommand);
        }
        Ok(Self {
            command,
            identity: LaunchIdentity::CallingUser,
            cgroup: CgroupVersion::V2,
            systemd: SystemdPresence::System,
            session_id,
        })
    }

    /// Number of argv elements. The elements themselves are not returned to logs.
    #[must_use]
    pub fn command_len(&self) -> usize {
        self.command.len()
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

/// One step the machine took, in order. Tests assert on this list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchStep {
    /// CLI `fork`. The child does not exec yet.
    Fork,
    /// Child is blocked on the pipe.
    WaitOnPipe,
    /// D-Bus `StartTransientUnit` was attempted.
    StartTransientUnit,
    /// `StartTransientUnit` failed and the mkdir fallback ran.
    ///
    /// The failure is also on [`LaunchOutcome::transient_unit_error`].
    TransientUnitFellBack,
    /// `agentwatch.slice/session-<sid>` was created.
    CreateSessionCgroup,
    /// The child pid was written to `cgroup.procs`.
    WriteCgroupProcs,
    /// The cgroup id was written to `scope_cgroups`.
    WriteScopeCgroups,
    /// Daemon `adopt`.
    Adopt,
    /// Child was told it may exec. Absent when adopt did not succeed.
    Exec,
    /// Child was terminated. Used on the adopt-failure path.
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

/// What a finished launch reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchOutcome {
    /// The target's exit code. Not remapped. Present only after exec.
    pub code: i32,
    /// Steps the machine took, in order.
    pub steps: Vec<LaunchStep>,
    /// `agentwatch.slice/session-<sid>`.
    pub session_dir: String,
    /// cgroup id written to `scope_cgroups`.
    pub cgroup_id: Option<u64>,
    /// Which create path ran.
    pub created_via: CgroupCreatePath,
    /// `StartTransientUnit` error, when the fallback ran.
    pub transient_unit_error: Option<String>,
    /// Pid the fake (or the OS) assigned.
    pub pid: u32,
    /// Last phase. [`LaunchPhase::ReadyToExec`] on the success path.
    pub phase: LaunchPhase,
    /// Inheritance the caller asked for. The values are not stored.
    pub inheritance: Inheritance,
}

/// What the child was asked to inherit. Presence means "requested", not a copy
/// of the environment block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Inheritance {
    /// The CLI's controlling terminal.
    pub tty: bool,
    /// The CLI's environment. The values are not recorded.
    pub environment: bool,
    /// The CLI's working directory.
    pub cwd: bool,
}

impl Inheritance {
    /// The launch path always requests all three. There is no partial mode.
    #[must_use]
    pub const fn requested() -> Self {
        Self {
            tty: true,
            environment: true,
            cwd: true,
        }
    }
}

/// Outcome of waiting for `adopt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptWait {
    /// Daemon accepted the child.
    Adopted,
    /// [`ADOPT_TIMEOUT`] elapsed with no accept.
    TimedOut,
    /// The daemon refused. The machine must not exec.
    Failed { detail: String },
}

/// Why a launch stopped before the target ran to completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchError {
    /// [`LaunchRequest::new`] was given no command.
    EmptyCommand,
    /// `fork` failed. No child exists; nothing else ran.
    ForkFailed { detail: String },
    /// The host is cgroup v1, or the version is unknown. No session directory
    /// was created. [`V1_DOCTOR_HINT`] is the doctor sentence.
    CgroupV1NoLaunch,
    /// `StartTransientUnit` failed and the mkdir fallback also failed.
    CreateFailed { detail: String },
    /// `cgroup.procs` was not written. The child was terminated.
    WriteProcsFailed { detail: String },
    /// The cgroup id could not be read. Not substituted with `0`.
    /// The child was terminated.
    CgroupIdUnavailable { detail: String },
    /// `scope_cgroups` refused the update. The child was terminated.
    MapUpdateFailed { detail: String },
    /// `adopt` did not succeed within [`ADOPT_TIMEOUT`]. The child was terminated
    /// and did not exec.
    AdoptTimeout,
    /// `adopt` failed for a reason other than the timeout. The child was
    /// terminated and did not exec.
    AdoptFailed { detail: String },
    /// The pipe write that releases exec failed. The child was terminated.
    ExecFailed { detail: String },
    /// Waiting for the child after exec failed.
    WaitFailed { detail: String },
    /// [`UnverifiedCgroupLaunch`] was used. No process was created.
    NotVerified { step: &'static str },
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCommand => f.write_str("launch command is empty"),
            Self::ForkFailed { detail } => write!(f, "fork failed: {detail}"),
            Self::CgroupV1NoLaunch => f.write_str(V1_DOCTOR_HINT),
            Self::CreateFailed { detail } => write!(f, "session cgroup was not created: {detail}"),
            Self::WriteProcsFailed { detail } => {
                write!(f, "writing cgroup.procs failed: {detail}")
            }
            Self::CgroupIdUnavailable { detail } => {
                write!(f, "cgroup id is unavailable: {detail}")
            }
            Self::MapUpdateFailed { detail } => write!(f, "scope_cgroups update failed: {detail}"),
            Self::AdoptTimeout => {
                f.write_str("adopt timed out; the child was terminated and did not exec")
            }
            Self::AdoptFailed { detail } => write!(f, "adopt failed: {detail}"),
            Self::ExecFailed { detail } => write!(f, "exec was not released: {detail}"),
            Self::WaitFailed { detail } => write!(f, "waiting for the child failed: {detail}"),
            Self::NotVerified { step } => write!(
                f,
                "{step} is not verified in this environment; no process was created"
            ),
        }
    }
}

impl std::error::Error for LaunchError {}

/// OS calls the state machine needs. One method per step.
///
/// A test fake records calls and returns scripted answers. It must not fork.
/// [`UnverifiedCgroupLaunch`] is the Linux stub and also starts nothing.
pub trait CgroupLaunch {
    /// `fork`. Returns the child pid. The child does not exec.
    ///
    /// The implementation records that TTY, environment, and cwd inheritance was
    /// requested. It does not copy the environment into the trace.
    ///
    /// # Errors
    ///
    /// [`LaunchError::ForkFailed`] when no child was created.
    fn fork_child(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError>;

    /// Block the child on the pipe. After this, [`LaunchPhase::WaitingOnPipe`].
    ///
    /// # Errors
    ///
    /// [`LaunchError::ForkFailed`] when the pipe could not be set up. The child
    /// is then terminated by the caller.
    fn wait_on_pipe(&mut self, pid: u32) -> Result<(), LaunchError>;

    /// Hierarchy the host would report.
    fn cgroup_version(&mut self) -> CgroupVersion;

    /// Whether a system bus is available for `StartTransientUnit`.
    fn systemd(&mut self) -> SystemdPresence;

    /// Create a transient scope unit for `session_dir`.
    ///
    /// # Errors
    ///
    /// [`LaunchError::CreateFailed`] when D-Bus refused. The caller falls back
    /// to [`Self::mkdir_session`] and keeps the message.
    fn start_transient_unit(&mut self, session_dir: &str) -> Result<(), LaunchError>;

    /// Create `session_dir` by mkdir.
    ///
    /// # Errors
    ///
    /// [`LaunchError::CreateFailed`] when the directory was not created.
    fn mkdir_session(&mut self, session_dir: &str) -> Result<(), LaunchError>;

    /// Write `pid` into `<session_dir>/cgroup.procs`.
    ///
    /// # Errors
    ///
    /// [`LaunchError::WriteProcsFailed`] when the write did not land.
    fn write_cgroup_procs(&mut self, session_dir: &str, pid: u32) -> Result<(), LaunchError>;

    /// Look up the cgroup id. `Err` — never `0` — when it cannot be read.
    ///
    /// # Errors
    ///
    /// [`LaunchError::CgroupIdUnavailable`] when the id is unknown.
    fn cgroup_id(&mut self, session_dir: &str) -> Result<u64, LaunchError>;

    /// Insert `cgroup_id` into `scope_cgroups`.
    ///
    /// # Errors
    ///
    /// [`LaunchError::MapUpdateFailed`] when the map refused the key.
    fn write_scope_cgroups(&mut self, cgroup_id: u64) -> Result<(), LaunchError>;

    /// Wait up to [`ADOPT_TIMEOUT`] for the daemon to adopt `pid`.
    ///
    /// Failures come back inside [`AdoptWait`], not as `Err`, so the machine can
    /// terminate without exec. `Err` is treated as [`AdoptWait::Failed`].
    fn adopt(&mut self, pid: u32) -> Result<AdoptWait, LaunchError>;

    /// Release the pipe so the child execs. Called only after [`AdoptWait::Adopted`].
    ///
    /// # Errors
    ///
    /// [`LaunchError::ExecFailed`] when the pipe write failed.
    fn release_exec(&mut self, pid: u32) -> Result<(), LaunchError>;

    /// End `pid`. Used when adopt did not succeed, and when exec itself failed.
    ///
    /// # Errors
    ///
    /// [`LaunchError::WaitFailed`] when the process could not be ended. The
    /// machine still returns the original adopt error.
    fn terminate(&mut self, pid: u32) -> Result<(), LaunchError>;

    /// Block until `pid` exits. Returns its exit code unchanged.
    ///
    /// # Errors
    ///
    /// [`LaunchError::WaitFailed`] when the wait itself failed.
    fn wait_exit(&mut self, pid: u32) -> Result<i32, LaunchError>;
}

/// Run the launch. See the module note for the step order.
///
/// On adopt timeout and adopt failure, [`LaunchStep::Exec`] is not recorded.
/// The child is terminated first.
///
/// # Errors
///
/// [`LaunchError`] as listed on that type. The success path is [`LaunchOutcome`].
pub fn run_launch<L: CgroupLaunch>(
    launch: &mut L,
    request: &LaunchRequest,
) -> Result<LaunchOutcome, LaunchError> {
    if request.identity != LaunchIdentity::CallingUser {
        // The enum has one variant today. This guard stays so a future variant
        // cannot silently become a root launch.
        return Err(LaunchError::ForkFailed {
            detail: "only the calling user may launch; root is not a path".to_owned(),
        });
    }
    if request.command.is_empty() {
        return Err(LaunchError::EmptyCommand);
    }

    let mut steps = Vec::new();

    steps.push(LaunchStep::Fork);
    let pid = launch.fork_child(request)?;

    steps.push(LaunchStep::WaitOnPipe);
    if let Err(err) = launch.wait_on_pipe(pid) {
        steps.push(LaunchStep::Terminate);
        let _ = launch.terminate(pid);
        return Err(err);
    }

    // The host's own probe wins, so a scripted v1 host cannot be talked into
    // creating a directory. The child already exists and is still blocked; it
    // is terminated rather than exec'd.
    let version = launch.cgroup_version();
    if version != CgroupVersion::V2 || request.cgroup != CgroupVersion::V2 {
        steps.push(LaunchStep::Terminate);
        let _ = launch.terminate(pid);
        return Err(LaunchError::CgroupV1NoLaunch);
    }

    let session_dir = format!("{SLICE_NAME}/session-{}", request.session_id);
    let systemd = launch.systemd();
    let (created_via, transient_unit_error) = if systemd == SystemdPresence::System
        || request.systemd == SystemdPresence::System
    {
        steps.push(LaunchStep::StartTransientUnit);
        match launch.start_transient_unit(&session_dir) {
            Ok(()) => (CgroupCreatePath::TransientUnit, None),
            Err(err) => {
                let detail = err.to_string();
                steps.push(LaunchStep::TransientUnitFellBack);
                if let Err(mkdir_err) = launch.mkdir_session(&session_dir) {
                    steps.push(LaunchStep::Terminate);
                    let _ = launch.terminate(pid);
                    return Err(LaunchError::CreateFailed {
                        detail: format!(
                            "StartTransientUnit failed ({detail}); mkdir fallback failed: {mkdir_err}"
                        ),
                    });
                }
                (
                    CgroupCreatePath::MkdirAfterTransientUnitFailed,
                    Some(detail),
                )
            }
        }
    } else {
        if let Err(err) = launch.mkdir_session(&session_dir) {
            steps.push(LaunchStep::Terminate);
            let _ = launch.terminate(pid);
            return Err(err);
        }
        (CgroupCreatePath::Mkdir, None)
    };
    steps.push(LaunchStep::CreateSessionCgroup);

    steps.push(LaunchStep::WriteCgroupProcs);
    if let Err(err) = launch.write_cgroup_procs(&session_dir, pid) {
        steps.push(LaunchStep::Terminate);
        let _ = launch.terminate(pid);
        return Err(err);
    }

    let cgroup_id = match launch.cgroup_id(&session_dir) {
        Ok(id) => id,
        Err(err) => {
            steps.push(LaunchStep::Terminate);
            let _ = launch.terminate(pid);
            return Err(err);
        }
    };
    steps.push(LaunchStep::WriteScopeCgroups);
    if let Err(err) = launch.write_scope_cgroups(cgroup_id) {
        steps.push(LaunchStep::Terminate);
        let _ = launch.terminate(pid);
        return Err(err);
    }

    steps.push(LaunchStep::Adopt);
    let waited = match launch.adopt(pid) {
        Ok(waited) => waited,
        Err(err) => AdoptWait::Failed {
            detail: err.to_string(),
        },
    };
    match waited {
        AdoptWait::Adopted => {}
        AdoptWait::TimedOut => {
            steps.push(LaunchStep::Terminate);
            let _ = launch.terminate(pid);
            return Err(LaunchError::AdoptTimeout);
        }
        AdoptWait::Failed { detail } => {
            steps.push(LaunchStep::Terminate);
            let _ = launch.terminate(pid);
            return Err(LaunchError::AdoptFailed { detail });
        }
    }

    steps.push(LaunchStep::Exec);
    if let Err(err) = launch.release_exec(pid) {
        steps.push(LaunchStep::Terminate);
        let _ = launch.terminate(pid);
        return Err(err);
    }

    let code = launch.wait_exit(pid)?;
    Ok(LaunchOutcome {
        code,
        steps,
        session_dir,
        cgroup_id: Some(cgroup_id),
        created_via,
        transient_unit_error,
        pid,
        phase: LaunchPhase::ReadyToExec,
        inheritance: Inheritance::requested(),
    })
}

/// Linux stub. Compiles only on Linux. Starts nothing.
///
/// SPIKE-05 did not run on Linux. Until cgroup v2 and `StartTransientUnit` are
/// measured, this type refuses every step with [`LaunchError::NotVerified`]
/// instead of forking from a default test or from an unwired command.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct UnverifiedCgroupLaunch;

#[cfg(target_os = "linux")]
impl CgroupLaunch for UnverifiedCgroupLaunch {
    fn fork_child(&mut self, _request: &LaunchRequest) -> Result<u32, LaunchError> {
        Err(LaunchError::NotVerified { step: "fork" })
    }

    fn wait_on_pipe(&mut self, _pid: u32) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified {
            step: "wait on pipe",
        })
    }

    fn cgroup_version(&mut self) -> CgroupVersion {
        CgroupVersion::Unknown
    }

    fn systemd(&mut self) -> SystemdPresence {
        SystemdPresence::Absent
    }

    fn start_transient_unit(&mut self, _session_dir: &str) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified {
            step: "StartTransientUnit",
        })
    }

    fn mkdir_session(&mut self, _session_dir: &str) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified {
            step: "mkdir agentwatch.slice/session-<sid>",
        })
    }

    fn write_cgroup_procs(&mut self, _session_dir: &str, _pid: u32) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified {
            step: "write cgroup.procs",
        })
    }

    fn cgroup_id(&mut self, _session_dir: &str) -> Result<u64, LaunchError> {
        Err(LaunchError::NotVerified {
            step: "read cgroup id",
        })
    }

    fn write_scope_cgroups(&mut self, _cgroup_id: u64) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified {
            step: "update scope_cgroups",
        })
    }

    fn adopt(&mut self, _pid: u32) -> Result<AdoptWait, LaunchError> {
        Err(LaunchError::NotVerified { step: "adopt" })
    }

    fn release_exec(&mut self, _pid: u32) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified { step: "exec" })
    }

    fn terminate(&mut self, _pid: u32) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified {
            step: "terminate child",
        })
    }

    fn wait_exit(&mut self, _pid: u32) -> Result<i32, LaunchError> {
        Err(LaunchError::NotVerified {
            step: "wait for child",
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod launch_tests {
    use super::*;

    #[derive(Debug)]
    struct FakeLaunch {
        pid: u32,
        exit_code: i32,
        adopt: AdoptWait,
        version: CgroupVersion,
        systemd: SystemdPresence,
        transient_fails: bool,
        mkdir_fails: bool,
        steps: Vec<LaunchStep>,
        terminated: bool,
        exec_released: bool,
        created_dirs: Vec<String>,
        wrote_pid: Option<u32>,
        wrote_cgroup: Option<u64>,
        cgroup_id: u64,
        saw_identity: Option<LaunchIdentity>,
        inheritance_requested: bool,
        command_len_seen: Option<usize>,
    }

    impl FakeLaunch {
        fn v2(adopt: AdoptWait) -> Self {
            Self {
                pid: 4242,
                exit_code: 0,
                adopt,
                version: CgroupVersion::V2,
                systemd: SystemdPresence::System,
                transient_fails: false,
                mkdir_fails: false,
                steps: Vec::new(),
                terminated: false,
                exec_released: false,
                created_dirs: Vec::new(),
                wrote_pid: None,
                wrote_cgroup: None,
                cgroup_id: 0xC0,
                saw_identity: None,
                inheritance_requested: false,
                command_len_seen: None,
            }
        }
    }

    impl CgroupLaunch for FakeLaunch {
        fn fork_child(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError> {
            self.steps.push(LaunchStep::Fork);
            self.saw_identity = Some(request.identity);
            self.command_len_seen = Some(request.command_len());
            self.inheritance_requested = true;
            Ok(self.pid)
        }

        fn wait_on_pipe(&mut self, pid: u32) -> Result<(), LaunchError> {
            self.steps.push(LaunchStep::WaitOnPipe);
            if pid != self.pid {
                return Err(LaunchError::ForkFailed {
                    detail: "pid mismatch".to_owned(),
                });
            }
            Ok(())
        }

        fn cgroup_version(&mut self) -> CgroupVersion {
            self.version
        }

        fn systemd(&mut self) -> SystemdPresence {
            self.systemd
        }

        fn start_transient_unit(&mut self, session_dir: &str) -> Result<(), LaunchError> {
            self.steps.push(LaunchStep::StartTransientUnit);
            if self.transient_fails {
                return Err(LaunchError::CreateFailed {
                    detail: "scripted dbus refusal".to_owned(),
                });
            }
            self.created_dirs.push(session_dir.to_owned());
            Ok(())
        }

        fn mkdir_session(&mut self, session_dir: &str) -> Result<(), LaunchError> {
            if self.mkdir_fails {
                return Err(LaunchError::CreateFailed {
                    detail: "scripted mkdir".to_owned(),
                });
            }
            self.created_dirs.push(session_dir.to_owned());
            Ok(())
        }

        fn write_cgroup_procs(&mut self, _session_dir: &str, pid: u32) -> Result<(), LaunchError> {
            self.steps.push(LaunchStep::WriteCgroupProcs);
            self.wrote_pid = Some(pid);
            Ok(())
        }

        fn cgroup_id(&mut self, _session_dir: &str) -> Result<u64, LaunchError> {
            Ok(self.cgroup_id)
        }

        fn write_scope_cgroups(&mut self, cgroup_id: u64) -> Result<(), LaunchError> {
            self.steps.push(LaunchStep::WriteScopeCgroups);
            self.wrote_cgroup = Some(cgroup_id);
            Ok(())
        }

        fn adopt(&mut self, pid: u32) -> Result<AdoptWait, LaunchError> {
            self.steps.push(LaunchStep::Adopt);
            if pid != self.pid {
                return Ok(AdoptWait::Failed {
                    detail: "pid mismatch".to_owned(),
                });
            }
            Ok(self.adopt.clone())
        }

        fn release_exec(&mut self, pid: u32) -> Result<(), LaunchError> {
            self.steps.push(LaunchStep::Exec);
            if pid != self.pid {
                return Err(LaunchError::ExecFailed {
                    detail: "pid mismatch".to_owned(),
                });
            }
            self.exec_released = true;
            Ok(())
        }

        fn terminate(&mut self, pid: u32) -> Result<(), LaunchError> {
            self.steps.push(LaunchStep::Terminate);
            if pid != self.pid {
                return Err(LaunchError::WaitFailed {
                    detail: "pid mismatch".to_owned(),
                });
            }
            self.terminated = true;
            self.exec_released = false;
            Ok(())
        }

        fn wait_exit(&mut self, pid: u32) -> Result<i32, LaunchError> {
            if pid != self.pid {
                return Err(LaunchError::WaitFailed {
                    detail: "pid mismatch".to_owned(),
                });
            }
            Ok(self.exit_code)
        }
    }

    fn request() -> LaunchRequest {
        LaunchRequest::new(
            7,
            vec!["bash".to_owned(), "-c".to_owned(), "true".to_owned()],
        )
        .expect("command")
    }

    #[test]
    fn steps_are_fork_then_cgroup_then_adopt_then_exec() {
        let mut launch = FakeLaunch::v2(AdoptWait::Adopted);
        launch.exit_code = 0;
        let done = run_launch(&mut launch, &request()).expect("launch");
        assert_eq!(
            done.steps,
            vec![
                LaunchStep::Fork,
                LaunchStep::WaitOnPipe,
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
        assert!(launch.exec_released);
        assert!(!launch.terminated);
        assert_eq!(launch.saw_identity, Some(LaunchIdentity::CallingUser));
        assert_eq!(launch.wrote_pid, Some(4242));
        assert_eq!(launch.wrote_cgroup, Some(0xC0));
        assert_eq!(done.created_via, CgroupCreatePath::TransientUnit);
        assert_eq!(done.transient_unit_error, None);
        assert_eq!(done.session_dir, "agentwatch.slice/session-7");
        assert_eq!(done.phase, LaunchPhase::ReadyToExec);
        assert_eq!(done.inheritance, Inheritance::requested());
        assert!(done.inheritance.tty && done.inheritance.environment && done.inheritance.cwd);
        assert_eq!(launch.command_len_seen, Some(3));
        // Debug must not print the command strings.
        let rendered = format!("{:?}", request());
        assert!(!rendered.contains("bash"));
        assert!(rendered.contains("command_len"));
    }

    #[test]
    fn adopt_failure_has_no_exec_and_terminates() {
        let mut launch = FakeLaunch::v2(AdoptWait::Failed {
            detail: "daemon refused".to_owned(),
        });
        let err = run_launch(&mut launch, &request()).expect_err("adopt");
        assert_eq!(
            err,
            LaunchError::AdoptFailed {
                detail: "daemon refused".to_owned(),
            }
        );
        assert!(launch.terminated);
        assert!(!launch.exec_released);
        assert!(!launch.steps.contains(&LaunchStep::Exec));
        assert_eq!(*launch.steps.last().expect("last"), LaunchStep::Terminate);
    }

    #[test]
    fn adopt_timeout_has_no_exec_and_terminates() {
        let mut launch = FakeLaunch::v2(AdoptWait::TimedOut);
        let err = run_launch(&mut launch, &request()).expect_err("timeout");
        assert_eq!(err, LaunchError::AdoptTimeout);
        assert!(launch.terminated);
        assert!(!launch.exec_released);
        assert!(!launch.steps.contains(&LaunchStep::Exec));
        assert_eq!(ADOPT_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn transient_unit_failure_is_labeled_and_falls_back() {
        let mut launch = FakeLaunch::v2(AdoptWait::Adopted);
        launch.transient_fails = true;
        let done = run_launch(&mut launch, &request()).expect("fallback");
        assert_eq!(
            done.created_via,
            CgroupCreatePath::MkdirAfterTransientUnitFailed
        );
        assert_eq!(
            done.transient_unit_error.as_deref(),
            Some("session cgroup was not created: scripted dbus refusal")
        );
        assert!(done.steps.contains(&LaunchStep::TransientUnitFellBack));
        assert!(done.steps.contains(&LaunchStep::Exec));
        assert!(!launch.terminated);
    }

    #[test]
    fn cgroup_v1_does_not_create_a_session_and_names_the_doctor_hint() {
        let mut launch = FakeLaunch::v2(AdoptWait::Adopted);
        launch.version = CgroupVersion::V1;
        let err =
            run_launch(&mut launch, &request().with_cgroup(CgroupVersion::V1)).expect_err("v1");
        assert_eq!(err, LaunchError::CgroupV1NoLaunch);
        assert_eq!(err.to_string(), V1_DOCTOR_HINT);
        assert!(V1_DOCTOR_HINT.contains("scope_pids"));
        assert!(launch.created_dirs.is_empty());
        assert!(!launch.exec_released);
        assert!(launch.terminated);
        assert!(!launch.steps.contains(&LaunchStep::Exec));
        assert!(!launch.steps.contains(&LaunchStep::CreateSessionCgroup));
        assert!(!launch.steps.contains(&LaunchStep::StartTransientUnit));
    }

    #[test]
    fn empty_command_is_rejected() {
        let err = LaunchRequest::new(1, Vec::new()).expect_err("empty");
        assert_eq!(err, LaunchError::EmptyCommand);
    }

    #[test]
    fn absent_systemd_uses_mkdir_without_a_transient_unit_error() {
        let mut launch = FakeLaunch::v2(AdoptWait::Adopted);
        launch.systemd = SystemdPresence::Absent;
        let done = run_launch(
            &mut launch,
            &request().with_systemd(SystemdPresence::Absent),
        )
        .expect("mkdir");
        assert_eq!(done.created_via, CgroupCreatePath::Mkdir);
        assert_eq!(done.transient_unit_error, None);
        assert!(!done.steps.contains(&LaunchStep::StartTransientUnit));
        assert!(done.steps.contains(&LaunchStep::CreateSessionCgroup));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unverified_stub_does_not_fork() {
        let mut launch = UnverifiedCgroupLaunch;
        let err = run_launch(&mut launch, &request()).expect_err("stub");
        assert_eq!(err, LaunchError::NotVerified { step: "fork" });
    }
}
