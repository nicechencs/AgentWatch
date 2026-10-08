//! Windows launch state machine (P1-WIN-04, windows.md §4.1).
//!
//! The steps, in order:
//!
//! 1. `CREATE_SUSPENDED` — create the target, still frozen.
//! 2. Create a Job and `AssignProcessToJobObject`.
//! 3. Hand the Job handle to the daemon (`DuplicateHandle`, or a named Job).
//! 4. `adopt`.
//! 5. `ResumeThread` — only after adopt succeeds.
//!
//! [`JobApi`] is the only place those Win32 calls exist. [`run_launch`] is pure:
//! it records the calls and stops. The default tests pass a fake. They do not
//! start a process.
//!
//! # Identity
//!
//! The target runs as the user who invoked `aw`, with that user's token.
//! [`LaunchIdentity::CallingUser`] is the only identity this module accepts.
//! There is no SYSTEM path: the daemon (LocalSystem) does not call
//! `CreateProcess`. SPIKE-05 measured the ordinary-user half (create suspended,
//! assign, resume) and it succeeded. `DuplicateHandle` into the service and the
//! IOCP were not measured (【待验证】).
//!
//! # What is not verified
//!
//! [`UnverifiedJobApi`] is the Windows stub. Every method returns
//! [`LaunchError::NotVerified`]. It does not call Win32. Default tests do not
//! construct it. SPIKE-05 did not measure handle passing or the completion port,
//! so this card does not ship a live implementation of those calls.
//!
//! # Adopt timeout
//!
//! [`ADOPT_TIMEOUT`] is five seconds, the same bound as the daemon's
//! `ADOPT_TIMEOUT_NS`. On timeout the machine terminates the target and does
//! not call `ResumeThread`. A failed handle handoff also skips `ResumeThread`:
//! the target stays suspended and is then terminated, so it never runs outside
//! the scope.
//!
//! # Breakaway
//!
//! Breakaway stays off unless [`LaunchRequest::allow_breakaway`] is set. When
//! it is set, the result carries the session note from
//! [`BREAKAWAY_INCOMPLETE_NOTE`] ("范围可能不完整").
//! SPIKE-05 did not find a program that fails without breakaway; the flag is
//! the escape hatch windows.md §4.1 asks for, not a measured fix.
//!
//! # Exit code
//!
//! [`TargetExit::code`] is the target's code. `aw run -- cmd /c exit 7` is
//! covered by the fake: the machine returns 7 and does not map it onto the
//! CLI's own error codes.

use std::time::Duration;

/// Session note when breakaway is allowed. Same text as
/// `aw_collector_windows::BREAKAWAY_INCOMPLETE_NOTE`. Copied here so `aw-cli`
/// does not take a platform-collector dependency.
pub const BREAKAWAY_INCOMPLETE_NOTE: &str = "范围可能不完整";

/// How long `adopt` may take before the target is terminated. Five seconds.
pub const ADOPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Who the target process runs as. There is no SYSTEM variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchIdentity {
    /// The user who invoked `aw`. Token, desktop, and console are inherited.
    CallingUser,
}

/// What one `aw run` asks the state machine to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    /// Executable plus arguments. Not logged. The fake stores only the length.
    pub command: Vec<String>,
    /// `--allow-breakaway`. Default is off.
    pub allow_breakaway: bool,
    /// Always [`LaunchIdentity::CallingUser`].
    pub identity: LaunchIdentity,
}

impl LaunchRequest {
    /// A request for `command`, as the calling user, breakaway forbidden.
    ///
    /// # Errors
    ///
    /// [`LaunchError::EmptyCommand`] when `command` is empty. An empty command
    /// is not a stand-in for "launch nothing".
    pub fn new(command: Vec<String>) -> Result<Self, LaunchError> {
        if command.is_empty() {
            return Err(LaunchError::EmptyCommand);
        }
        Ok(Self {
            command,
            allow_breakaway: false,
            identity: LaunchIdentity::CallingUser,
        })
    }

    /// Set `--allow-breakaway`.
    #[must_use]
    pub fn with_breakaway(mut self, allow: bool) -> Self {
        self.allow_breakaway = allow;
        self
    }
}

/// One step the machine took, in order. Tests assert on this list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchStep {
    /// `CreateProcess` with `CREATE_SUSPENDED`, as the calling user.
    CreateSuspended,
    /// `CreateJobObject`.
    CreateJob,
    /// `AssignProcessToJobObject`.
    AssignToJob,
    /// Hand the Job handle to the daemon.
    HandOffHandle,
    /// Daemon `adopt`.
    Adopt,
    /// `ResumeThread`. Absent when adopt did not succeed.
    ResumeThread,
    /// Target was terminated. Used on the timeout and handoff-failure paths.
    Terminate,
}

/// Annotation written onto the session when breakaway is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionAnnotation {
    /// [`BREAKAWAY_INCOMPLETE_NOTE`].
    pub note: &'static str,
}

/// What a finished launch reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetExit {
    /// The target's exit code. Not remapped.
    pub code: i32,
    /// Steps the machine took, in order.
    pub steps: Vec<LaunchStep>,
    /// Set only when `--allow-breakaway` was on.
    pub annotation: Option<SessionAnnotation>,
    /// Pid the fake (or the OS) assigned. `None` is not used on the success path.
    pub pid: u32,
}

/// Why a launch stopped before the target ran to completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchError {
    /// [`LaunchRequest::new`] was given no command.
    EmptyCommand,
    /// `CREATE_SUSPENDED` failed. The target does not exist; nothing else ran.
    CreateFailed { detail: String },
    /// The Job could not be created, or the process could not be assigned.
    /// The suspended process was terminated.
    JobFailed { detail: String },
    /// The handle did not reach the daemon. `ResumeThread` was not called.
    /// The suspended process was terminated.
    HandleHandoffFailed { detail: String },
    /// `adopt` did not succeed within [`ADOPT_TIMEOUT`]. The target was terminated
    /// and was not resumed.
    AdoptTimeout,
    /// `adopt` failed for a reason other than the timeout. The target was
    /// terminated and was not resumed.
    AdoptFailed { detail: String },
    /// The target was resumed, then waiting for it failed.
    WaitFailed { detail: String },
    /// [`UnverifiedJobApi`] was used. No Win32 call was made.
    NotVerified { step: &'static str },
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCommand => f.write_str("launch command is empty"),
            Self::CreateFailed { detail } => write!(f, "create suspended failed: {detail}"),
            Self::JobFailed { detail } => write!(f, "job assignment failed: {detail}"),
            Self::HandleHandoffFailed { detail } => {
                write!(f, "job handle handoff failed: {detail}")
            }
            Self::AdoptTimeout => f.write_str("adopt timed out; the target was terminated"),
            Self::AdoptFailed { detail } => write!(f, "adopt failed: {detail}"),
            Self::WaitFailed { detail } => write!(f, "waiting for the target failed: {detail}"),
            Self::NotVerified { step } => write!(
                f,
                "{step} is not verified in this environment; no process was created"
            ),
        }
    }
}

impl std::error::Error for LaunchError {}

/// Outcome of handing the Job to the daemon and waiting for `adopt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptWait {
    /// Daemon accepted the process.
    Adopted,
    /// [`ADOPT_TIMEOUT`] elapsed with no accept.
    TimedOut,
    /// The handoff itself failed. The machine must not resume.
    HandoffFailed { detail: String },
    /// The daemon refused. The machine must not resume.
    Failed { detail: String },
}

/// OS calls the state machine needs. One method per step.
///
/// A test fake records calls and returns scripted answers. It must not start
/// a process. [`UnverifiedJobApi`] is the Windows stub and also starts nothing.
pub trait JobApi {
    /// `CreateProcess` with `CREATE_SUSPENDED`, as [`LaunchIdentity::CallingUser`].
    ///
    /// Returns the pid. Does not resume.
    ///
    /// # Errors
    ///
    /// [`LaunchError::CreateFailed`] when the process was not created.
    fn create_suspended(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError>;

    /// `CreateJobObject` and `AssignProcessToJobObject` for `pid`.
    ///
    /// `allow_breakaway` sets `JOB_OBJECT_LIMIT_BREAKAWAY_OK` when `true`.
    /// The default is `false`: a child that asks to leave the Job fails.
    ///
    /// # Errors
    ///
    /// [`LaunchError::JobFailed`] when the Job or the assignment failed.
    fn create_job_and_assign(&mut self, pid: u32, allow_breakaway: bool)
        -> Result<(), LaunchError>;

    /// Duplicate the Job handle into the daemon (or publish a named Job) and
    /// wait up to [`ADOPT_TIMEOUT`] for `adopt`.
    ///
    /// # Errors
    ///
    /// Implementations return the failure inside [`AdoptWait`], not as `Err`,
    /// so the machine can choose terminate-without-resume. `Err` is reserved
    /// for a failure of the trait object itself, which the machine treats as
    /// [`AdoptWait::Failed`].
    fn handoff_and_adopt(&mut self, pid: u32) -> Result<AdoptWait, LaunchError>;

    /// `ResumeThread` for `pid`. Called only after [`AdoptWait::Adopted`].
    ///
    /// # Errors
    ///
    /// [`LaunchError::WaitFailed`] when the thread could not be resumed. The
    /// process already exists and is inside the Job; the caller terminates it.
    fn resume(&mut self, pid: u32) -> Result<(), LaunchError>;

    /// End `pid`. Used when adopt did not succeed, and when resume itself failed.
    ///
    /// # Errors
    ///
    /// [`LaunchError::WaitFailed`] when the process could not be ended. The
    /// machine still returns the original adopt or handoff error.
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
/// On adopt timeout, handle-handoff failure, and adopt failure, `ResumeThread`
/// is not called. The target is terminated first.
///
/// # Errors
///
/// [`LaunchError`] as listed on that type. The success path is [`TargetExit`].
pub fn run_launch<A: JobApi>(
    api: &mut A,
    request: &LaunchRequest,
) -> Result<TargetExit, LaunchError> {
    if request.identity != LaunchIdentity::CallingUser {
        // The enum has one variant today. This guard stays so a future variant
        // cannot silently become a SYSTEM launch.
        return Err(LaunchError::CreateFailed {
            detail: "only the calling user may launch; SYSTEM is not a path".to_owned(),
        });
    }

    let mut steps = Vec::new();
    let allow_breakaway = request.allow_breakaway;
    let annotation = allow_breakaway.then_some(SessionAnnotation {
        note: BREAKAWAY_INCOMPLETE_NOTE,
    });

    steps.push(LaunchStep::CreateSuspended);
    let pid = api.create_suspended(request)?;

    steps.push(LaunchStep::CreateJob);
    steps.push(LaunchStep::AssignToJob);
    if let Err(err) = api.create_job_and_assign(pid, allow_breakaway) {
        steps.push(LaunchStep::Terminate);
        let _ = api.terminate(pid);
        return Err(err);
    }

    steps.push(LaunchStep::HandOffHandle);
    steps.push(LaunchStep::Adopt);
    let waited = match api.handoff_and_adopt(pid) {
        Ok(waited) => waited,
        Err(err) => AdoptWait::Failed {
            detail: err.to_string(),
        },
    };

    match waited {
        AdoptWait::Adopted => {}
        AdoptWait::TimedOut => {
            steps.push(LaunchStep::Terminate);
            let _ = api.terminate(pid);
            return Err(LaunchError::AdoptTimeout);
        }
        AdoptWait::HandoffFailed { detail } => {
            steps.push(LaunchStep::Terminate);
            let _ = api.terminate(pid);
            return Err(LaunchError::HandleHandoffFailed { detail });
        }
        AdoptWait::Failed { detail } => {
            steps.push(LaunchStep::Terminate);
            let _ = api.terminate(pid);
            return Err(LaunchError::AdoptFailed { detail });
        }
    }

    steps.push(LaunchStep::ResumeThread);
    if let Err(err) = api.resume(pid) {
        steps.push(LaunchStep::Terminate);
        let _ = api.terminate(pid);
        return Err(err);
    }

    let code = api.wait_exit(pid)?;
    Ok(TargetExit {
        code,
        steps,
        annotation,
        pid,
    })
}

/// Windows stub. Compiles only on Windows. Starts nothing.
///
/// SPIKE-05 measured create-suspended / assign / resume inside one process. It
/// did not measure `DuplicateHandle` into the service or the Job IOCP. Until
/// that is measured, this type refuses every step with
/// [`LaunchError::NotVerified`] instead of calling Win32 from a default test
/// or from an unwired command.
#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
pub struct UnverifiedJobApi;

#[cfg(target_os = "windows")]
impl JobApi for UnverifiedJobApi {
    fn create_suspended(&mut self, _request: &LaunchRequest) -> Result<u32, LaunchError> {
        Err(LaunchError::NotVerified {
            step: "CreateProcessW(CREATE_SUSPENDED)",
        })
    }

    fn create_job_and_assign(
        &mut self,
        _pid: u32,
        _allow_breakaway: bool,
    ) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified {
            step: "CreateJobObject + AssignProcessToJobObject",
        })
    }

    fn handoff_and_adopt(&mut self, _pid: u32) -> Result<AdoptWait, LaunchError> {
        Err(LaunchError::NotVerified {
            step: "DuplicateHandle + adopt",
        })
    }

    fn resume(&mut self, _pid: u32) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified {
            step: "ResumeThread",
        })
    }

    fn terminate(&mut self, _pid: u32) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified {
            step: "TerminateProcess",
        })
    }

    fn wait_exit(&mut self, _pid: u32) -> Result<i32, LaunchError> {
        Err(LaunchError::NotVerified {
            step: "WaitForSingleObject",
        })
    }
}

/// Scripted [`JobApi`] for tests. Holds no handle and starts no process.
#[cfg(test)]
#[derive(Debug)]
struct FakeJob {
    pid: u32,
    exit_code: i32,
    adopt: AdoptWait,
    fail_create: bool,
    fail_job: bool,
    fail_resume: bool,
    steps: Vec<LaunchStep>,
    resumed: bool,
    terminated: bool,
    /// Whether breakaway was requested at assign time.
    assigned_breakaway: Option<bool>,
    /// Identity observed at create time.
    saw_identity: Option<LaunchIdentity>,
}

#[cfg(test)]
impl FakeJob {
    fn new(adopt: AdoptWait) -> Self {
        Self {
            pid: 4242,
            exit_code: 0,
            adopt,
            fail_create: false,
            fail_job: false,
            fail_resume: false,
            steps: Vec::new(),
            resumed: false,
            terminated: false,
            assigned_breakaway: None,
            saw_identity: None,
        }
    }
}

#[cfg(test)]
impl JobApi for FakeJob {
    fn create_suspended(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError> {
        self.steps.push(LaunchStep::CreateSuspended);
        self.saw_identity = Some(request.identity);
        if self.fail_create {
            return Err(LaunchError::CreateFailed {
                detail: "scripted".to_owned(),
            });
        }
        Ok(self.pid)
    }

    fn create_job_and_assign(
        &mut self,
        pid: u32,
        allow_breakaway: bool,
    ) -> Result<(), LaunchError> {
        self.steps.push(LaunchStep::CreateJob);
        self.steps.push(LaunchStep::AssignToJob);
        self.assigned_breakaway = Some(allow_breakaway);
        if pid != self.pid {
            return Err(LaunchError::JobFailed {
                detail: "pid mismatch".to_owned(),
            });
        }
        if self.fail_job {
            return Err(LaunchError::JobFailed {
                detail: "scripted".to_owned(),
            });
        }
        Ok(())
    }

    fn handoff_and_adopt(&mut self, pid: u32) -> Result<AdoptWait, LaunchError> {
        self.steps.push(LaunchStep::HandOffHandle);
        self.steps.push(LaunchStep::Adopt);
        if pid != self.pid {
            return Ok(AdoptWait::Failed {
                detail: "pid mismatch".to_owned(),
            });
        }
        Ok(self.adopt.clone())
    }

    fn resume(&mut self, pid: u32) -> Result<(), LaunchError> {
        self.steps.push(LaunchStep::ResumeThread);
        if pid != self.pid {
            return Err(LaunchError::WaitFailed {
                detail: "pid mismatch".to_owned(),
            });
        }
        if self.fail_resume {
            return Err(LaunchError::WaitFailed {
                detail: "scripted resume".to_owned(),
            });
        }
        self.resumed = true;
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn request(breakaway: bool) -> LaunchRequest {
        LaunchRequest::new(vec![
            "cmd".to_owned(),
            "/c".to_owned(),
            "exit".to_owned(),
            "7".to_owned(),
        ])
        .expect("command")
        .with_breakaway(breakaway)
    }

    #[test]
    fn resume_happens_only_after_adopt() {
        let mut api = FakeJob::new(AdoptWait::Adopted);
        api.exit_code = 7;
        let done = run_launch(&mut api, &request(false)).expect("launch");
        assert_eq!(
            done.steps,
            vec![
                LaunchStep::CreateSuspended,
                LaunchStep::CreateJob,
                LaunchStep::AssignToJob,
                LaunchStep::HandOffHandle,
                LaunchStep::Adopt,
                LaunchStep::ResumeThread,
            ]
        );
        let adopt_at = done
            .steps
            .iter()
            .position(|step| *step == LaunchStep::Adopt)
            .expect("adopt");
        let resume_at = done
            .steps
            .iter()
            .position(|step| *step == LaunchStep::ResumeThread)
            .expect("resume");
        assert!(adopt_at < resume_at);
        assert!(api.resumed);
        assert!(!api.terminated);
        assert_eq!(api.saw_identity, Some(LaunchIdentity::CallingUser));
        assert_eq!(done.annotation, None);
        assert_eq!(api.assigned_breakaway, Some(false));
    }

    #[test]
    fn adopt_timeout_terminates_and_does_not_resume() {
        let mut api = FakeJob::new(AdoptWait::TimedOut);
        let err = run_launch(&mut api, &request(false)).expect_err("timeout");
        assert_eq!(err, LaunchError::AdoptTimeout);
        assert!(api.terminated);
        assert!(!api.resumed);
        assert!(!api.steps.contains(&LaunchStep::ResumeThread));
        assert_eq!(*api.steps.last().expect("last"), LaunchStep::Terminate);
        assert_eq!(ADOPT_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn handle_handoff_failure_does_not_resume() {
        let mut api = FakeJob::new(AdoptWait::HandoffFailed {
            detail: "duplicate failed".to_owned(),
        });
        let err = run_launch(&mut api, &request(false)).expect_err("handoff");
        assert_eq!(
            err,
            LaunchError::HandleHandoffFailed {
                detail: "duplicate failed".to_owned(),
            }
        );
        assert!(api.terminated);
        assert!(!api.resumed);
        assert!(!api.steps.contains(&LaunchStep::ResumeThread));
    }

    #[test]
    fn exit_code_is_forwarded_unchanged() {
        let mut api = FakeJob::new(AdoptWait::Adopted);
        api.exit_code = 7;
        let done = run_launch(&mut api, &request(false)).expect("launch");
        assert_eq!(done.code, 7);
    }

    #[test]
    fn allow_breakaway_annotates_the_session() {
        let mut api = FakeJob::new(AdoptWait::Adopted);
        api.exit_code = 0;
        let done = run_launch(&mut api, &request(true)).expect("launch");
        assert_eq!(
            done.annotation.map(|note| note.note),
            Some(BREAKAWAY_INCOMPLETE_NOTE)
        );
        assert_eq!(api.assigned_breakaway, Some(true));
        assert_eq!(
            done.annotation.map(|note| note.note),
            Some("范围可能不完整")
        );
    }

    #[test]
    fn empty_command_is_rejected() {
        let err = LaunchRequest::new(Vec::new()).expect_err("empty");
        assert_eq!(err, LaunchError::EmptyCommand);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn unverified_stub_does_not_create_a_process() {
        let mut api = UnverifiedJobApi;
        let err = run_launch(&mut api, &request(false)).expect_err("stub");
        assert_eq!(
            err,
            LaunchError::NotVerified {
                step: "CreateProcessW(CREATE_SUSPENDED)",
            }
        );
    }
}
