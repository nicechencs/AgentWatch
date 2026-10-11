//! OS-independent state machine for the Windows held-process launch path.
//!
//! Win32 calls remain in the Windows platform implementation.  This module
//! only describes their required ordering, so its fake-driven tests run on
//! Linux, macOS, and Windows.

use std::time::Duration;

pub const BREAKAWAY_INCOMPLETE_NOTE: &str = "范围可能不完整";
pub const ADOPT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchIdentity {
    CallingUser,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    pub command: Vec<String>,
    pub allow_breakaway: bool,
    pub identity: LaunchIdentity,
}

impl LaunchRequest {
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

    #[must_use]
    pub fn with_breakaway(mut self, allow: bool) -> Self {
        self.allow_breakaway = allow;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchStep {
    CreateSuspended,
    CreateJob,
    AssignToJob,
    HandOffHandle,
    Adopt,
    ResumeThread,
    Terminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionAnnotation {
    pub note: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetExit {
    pub code: i32,
    pub steps: Vec<LaunchStep>,
    pub annotation: Option<SessionAnnotation>,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchError {
    EmptyCommand,
    CreateFailed { detail: String },
    JobFailed { detail: String },
    HandleHandoffFailed { detail: String },
    AdoptTimeout,
    AdoptFailed { detail: String },
    WaitFailed { detail: String },
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCommand => f.write_str("启动命令为空"),
            Self::CreateFailed { detail } => write!(f, "创建挂起进程失败：{detail}"),
            Self::JobFailed { detail } => write!(f, "分配 Job 失败：{detail}"),
            Self::HandleHandoffFailed { detail } => write!(f, "移交 Job 句柄失败：{detail}"),
            Self::AdoptTimeout => f.write_str("adopt 超时；目标进程已结束"),
            Self::AdoptFailed { detail } => write!(f, "adopt 失败：{detail}"),
            Self::WaitFailed { detail } => write!(f, "等待目标进程失败：{detail}"),
        }
    }
}

impl std::error::Error for LaunchError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptWait {
    Adopted,
    TimedOut,
    HandoffFailed { detail: String },
    Failed { detail: String },
}

/// Platform operations needed by the Windows Job launch protocol.
///
/// This trait intentionally contains no FFI types, allowing its ordering and
/// error behavior to be verified on every OS.
pub trait JobApi {
    fn create_suspended(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError>;
    fn create_job_and_assign(&mut self, pid: u32, allow_breakaway: bool)
        -> Result<(), LaunchError>;
    fn handoff_and_adopt(&mut self, pid: u32) -> Result<AdoptWait, LaunchError>;
    fn resume(&mut self, pid: u32) -> Result<(), LaunchError>;
    fn terminate(&mut self, pid: u32) -> Result<(), LaunchError>;
    fn wait_exit(&mut self, pid: u32) -> Result<i32, LaunchError>;
}

/// Run the launch protocol.  A target is resumed only after daemon adoption.
pub fn run_launch<A: JobApi>(
    api: &mut A,
    request: &LaunchRequest,
) -> Result<TargetExit, LaunchError> {
    if request.identity != LaunchIdentity::CallingUser {
        return Err(LaunchError::CreateFailed {
            detail: "只能以调用用户身份启动；SYSTEM 不是路径".to_owned(),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_command_is_rejected() {
        let err = LaunchRequest::new(Vec::new()).expect_err("empty");
        assert_eq!(err, LaunchError::EmptyCommand);
    }

    #[derive(Debug)]
    struct FakeJob {
        pid: u32,
        exit_code: i32,
        adopt: AdoptWait,
        steps: Vec<LaunchStep>,
        resumed: bool,
        terminated: bool,
        assigned_breakaway: Option<bool>,
        saw_identity: Option<LaunchIdentity>,
    }

    impl FakeJob {
        fn new(adopt: AdoptWait) -> Self {
            Self {
                pid: 4242,
                exit_code: 0,
                adopt,
                steps: Vec::new(),
                resumed: false,
                terminated: false,
                assigned_breakaway: None,
                saw_identity: None,
            }
        }
    }

    impl JobApi for FakeJob {
        fn create_suspended(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError> {
            self.steps.push(LaunchStep::CreateSuspended);
            self.saw_identity = Some(request.identity);
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
}
