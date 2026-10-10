//! macOS launch state machine (P1-MAC-03, macos.md §4, process-tracking §4).
//!
//! Wired in by P1-CLI-02's `launch/mod.rs` under `cfg(target_os = "macos")`.
//! This file is not registered there yet: another card owns `launch/mod.rs`.
//! It compiles on every host because every OS call sits behind [`SpawnApi`].
//!
//! # Steps
//!
//! Preferred path, when [`SpawnApi::spawn_suspended`] succeeds:
//!
//! 1. `posix_spawn` with `POSIX_SPAWN_START_SUSPENDED`.
//! 2. `adopt` — the daemon confirms the pid is in scope.
//! 3. `SIGCONT` — only after that confirmation.
//!
//! Fallback, when `spawn_suspended` returns [`LaunchError::Unsupported`]:
//!
//! 1. `fork`, then the child blocks on a pipe before `exec`.
//! 2. `adopt`.
//! 3. Release the pipe — only after that confirmation.
//!
//! `POSIX_SPAWN_START_SUSPENDED` is 【待验证】 (SPIKE-05 §5.2, SPIKE-03 question 6).
//! Availability is a runtime answer from the trait, not a constant this module
//! claims to have measured. Both paths are tested with a fake. Neither test
//! calls `posix_spawn` or `fork`.
//!
//! # Failure
//!
//! If adopt fails or times out, the machine does not send `SIGCONT` and does
//! not release the pipe. It terminates the child. The child never runs user
//! code outside the scope.
//!
//! # Identity
//!
//! [`LaunchIdentity`] has one variant, [`LaunchIdentity::CallingUser`]. There
//! is no root variant. The target runs as the user who invoked `aw`.
//! process-tracking §4's `setuid` path is the daemon's job and is not here.
//!
//! # Waiting
//!
//! On macOS the preferred wait is `waitpid` after `SIGCONT`. The pipe fallback
//! waits the same way after the release byte. Linux (a different card, not
//! this file) waits on a cgroup-aware exec instead of `SIGCONT`. The cfg split
//! belongs in `launch/mod.rs` when that card lands. This file does not cfg
//! out its own tests.
//!
//! # What is not verified
//!
//! [`UnverifiedSpawnApi`] is the production stub. Every method returns
//! [`LaunchError::NotVerified`]. It does not call libc. SPIKE-05 did not run
//! the macOS half, so this card does not ship a live `posix_spawn`.

use std::time::Duration;

/// How long `adopt` may take before the child is terminated. Five seconds,
/// the same bound the Windows launcher uses.
pub const ADOPT_TIMEOUT: Duration = Duration::from_secs(5);

/// Who the target process runs as. There is no root variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchIdentity {
    /// The user who invoked `aw`. uid, gid, env, and cwd stay that user's.
    CallingUser,
}

/// What one `aw run` asks the state machine to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    /// Executable plus arguments. Not logged. Callers must not `Debug` this
    /// into a log line. The fake records only the argument count.
    pub command: Vec<String>,
    /// Always [`LaunchIdentity::CallingUser`].
    pub identity: LaunchIdentity,
}

impl LaunchRequest {
    /// A request for `command`, as the calling user.
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
            identity: LaunchIdentity::CallingUser,
        })
    }
}

/// Which create path the machine took.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnPath {
    /// `posix_spawn` with `POSIX_SPAWN_START_SUSPENDED`.
    Suspended,
    /// `spawn_suspended` returned [`LaunchError::Unsupported`]. Fork plus pipe.
    ForkPipe,
}

/// One step the machine took, in order. Tests assert on this list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchStep {
    /// Preferred create. Absent on the fallback path.
    SpawnSuspended,
    /// Fallback create. Absent on the preferred path.
    ForkAndWaitPipe,
    /// Daemon `adopt`.
    Adopt,
    /// `SIGCONT`. Only after adopt, and only on [`SpawnPath::Suspended`].
    SigCont,
    /// Release the pipe so the child may `exec`. Only after adopt, and only
    /// on [`SpawnPath::ForkPipe`].
    ReleasePipe,
    /// Child was terminated. Adopt did not succeed, or continue itself failed.
    Terminate,
}

/// What a finished launch reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetExit {
    /// The target's exit code. Not remapped onto the CLI's own codes.
    pub code: i32,
    /// Steps the machine took, in order.
    pub steps: Vec<LaunchStep>,
    /// Which create path ran.
    pub path: SpawnPath,
    /// Pid the fake (or the OS) assigned.
    pub pid: u32,
}

/// Why a launch stopped before the target ran to completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchError {
    /// [`LaunchRequest::new`] was given no command.
    EmptyCommand,
    /// `POSIX_SPAWN_START_SUSPENDED` is not available on this OS. The machine
    /// switches to the fork-and-pipe path. Not a failure by itself.
    Unsupported,
    /// `posix_spawn` failed for a reason other than the missing flag.
    SpawnFailed { detail: String },
    /// `fork` or the pipe setup failed. No child is left running.
    ForkFailed { detail: String },
    /// `adopt` did not succeed within [`ADOPT_TIMEOUT`]. The child was
    /// terminated and was not continued.
    AdoptTimeout,
    /// `adopt` failed for a reason other than the timeout. The child was
    /// terminated and was not continued.
    AdoptFailed { detail: String },
    /// Continuing (`SIGCONT` or the pipe) or waiting for the child failed.
    ContinueFailed { detail: String },
    /// [`UnverifiedSpawnApi`] was used. No libc call was made.
    NotVerified { step: &'static str },
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCommand => f.write_str("启动命令为空"),
            Self::Unsupported => {
                f.write_str("POSIX_SPAWN_START_SUSPENDED 不可用；改用 fork-and-pipe")
            }
            Self::SpawnFailed { detail } => write!(f, "posix_spawn 失败：{detail}"),
            Self::ForkFailed { detail } => write!(f, "fork-and-pipe 失败：{detail}"),
            Self::AdoptTimeout => f.write_str("adopt 超时；子进程已结束"),
            Self::AdoptFailed { detail } => write!(f, "adopt 失败：{detail}"),
            Self::ContinueFailed { detail } => {
                write!(f, "继续子进程失败：{detail}")
            }
            Self::NotVerified { step } => write!(f, "步骤 {step} 未在此环境验证；没有创建进程"),
        }
    }
}

impl std::error::Error for LaunchError {}

/// Outcome of waiting for the daemon to adopt `pid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdoptWait {
    /// Daemon accepted the process.
    Adopted,
    /// [`ADOPT_TIMEOUT`] elapsed with no accept.
    TimedOut,
    /// The daemon refused. The machine must not continue the child.
    Failed { detail: String },
}

/// OS calls the state machine needs. One method per step.
///
/// A test fake records calls and returns scripted answers. It must not start
/// a process. [`UnverifiedSpawnApi`] is the production stub and also starts
/// nothing.
pub trait SpawnApi {
    /// `posix_spawn` with `POSIX_SPAWN_START_SUSPENDED`, as the calling user.
    ///
    /// Returns the pid. Does not send `SIGCONT`.
    ///
    /// # Errors
    ///
    /// [`LaunchError::Unsupported`] when the flag cannot be set. The machine
    /// then calls [`SpawnApi::fork_and_wait_pipe`]. [`LaunchError::SpawnFailed`]
    /// when spawn failed for another reason. The machine does not fall back
    /// on that error.
    fn spawn_suspended(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError>;

    /// `fork`, then leave the child blocked on a pipe until
    /// [`SpawnApi::release_pipe`].
    ///
    /// # Errors
    ///
    /// [`LaunchError::ForkFailed`] when no child was created.
    fn fork_and_wait_pipe(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError>;

    /// Ask the daemon to adopt `pid` and wait up to [`ADOPT_TIMEOUT`].
    ///
    /// Failures are returned inside [`AdoptWait`], not as `Err`, so the
    /// machine can terminate without continuing. `Err` is treated as
    /// [`AdoptWait::Failed`].
    ///
    /// # Errors
    ///
    /// [`LaunchError`] only when the trait object itself failed.
    fn adopt(&mut self, pid: u32) -> Result<AdoptWait, LaunchError>;

    /// `SIGCONT` for `pid`. Called only after [`AdoptWait::Adopted`] on the
    /// suspended path.
    ///
    /// # Errors
    ///
    /// [`LaunchError::ContinueFailed`] when the signal was not delivered.
    fn sigcont(&mut self, pid: u32) -> Result<(), LaunchError>;

    /// Write the release byte. Called only after [`AdoptWait::Adopted`] on
    /// the fork path.
    ///
    /// # Errors
    ///
    /// [`LaunchError::ContinueFailed`] when the pipe could not be released.
    fn release_pipe(&mut self, pid: u32) -> Result<(), LaunchError>;

    /// End `pid`. Used when adopt did not succeed, and when continue failed.
    ///
    /// # Errors
    ///
    /// [`LaunchError::ContinueFailed`] when the child could not be ended. The
    /// machine still returns the original adopt error.
    fn terminate(&mut self, pid: u32) -> Result<(), LaunchError>;

    /// Block until `pid` exits. Returns its exit code unchanged.
    ///
    /// # Errors
    ///
    /// [`LaunchError::ContinueFailed`] when the wait itself failed.
    fn wait_exit(&mut self, pid: u32) -> Result<i32, LaunchError>;
}

/// Run the launch. See the module note for the two step orders.
///
/// On adopt timeout and adopt failure the child is terminated. `SIGCONT` is
/// not sent and the pipe is not released.
///
/// # Errors
///
/// [`LaunchError`] as listed on that type. The success path is [`TargetExit`].
pub fn run_launch<A: SpawnApi>(
    api: &mut A,
    request: &LaunchRequest,
) -> Result<TargetExit, LaunchError> {
    if request.identity != LaunchIdentity::CallingUser {
        // The enum has one variant today. This guard stays so a future variant
        // cannot silently become a root launch.
        return Err(LaunchError::SpawnFailed {
            detail: "只能以调用用户身份启动；root 不是路径".to_owned(),
        });
    }

    let mut steps = Vec::new();
    let (pid, path) = match api.spawn_suspended(request) {
        Ok(pid) => {
            steps.push(LaunchStep::SpawnSuspended);
            (pid, SpawnPath::Suspended)
        }
        Err(LaunchError::Unsupported) => {
            steps.push(LaunchStep::ForkAndWaitPipe);
            let pid = api.fork_and_wait_pipe(request)?;
            (pid, SpawnPath::ForkPipe)
        }
        Err(err) => return Err(err),
    };

    steps.push(LaunchStep::Adopt);
    let waited = match api.adopt(pid) {
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
        AdoptWait::Failed { detail } => {
            steps.push(LaunchStep::Terminate);
            let _ = api.terminate(pid);
            return Err(LaunchError::AdoptFailed { detail });
        }
    }

    let continued = match path {
        SpawnPath::Suspended => {
            steps.push(LaunchStep::SigCont);
            api.sigcont(pid)
        }
        SpawnPath::ForkPipe => {
            steps.push(LaunchStep::ReleasePipe);
            api.release_pipe(pid)
        }
    };
    if let Err(err) = continued {
        steps.push(LaunchStep::Terminate);
        let _ = api.terminate(pid);
        return Err(err);
    }

    let code = api.wait_exit(pid)?;
    Ok(TargetExit {
        code,
        steps,
        path,
        pid,
    })
}

/// Production stub. Compiles on every host. Starts nothing.
///
/// `POSIX_SPAWN_START_SUSPENDED` is 【待验证】. Until a macOS host measures it,
/// this type refuses every step with [`LaunchError::NotVerified`] instead of
/// calling libc from a default test or from an unwired command.
///
/// This type is the test stub. Production on macOS uses [`PosixSpawnApi`] via
/// [`production`]. Do not replace this impl with a live spawn: the
/// "does not create a process" test depends on the refusal.
#[derive(Debug, Default)]
pub struct UnverifiedSpawnApi;

impl SpawnApi for UnverifiedSpawnApi {
    fn spawn_suspended(&mut self, _request: &LaunchRequest) -> Result<u32, LaunchError> {
        Err(LaunchError::NotVerified {
            step: "posix_spawn(POSIX_SPAWN_START_SUSPENDED)",
        })
    }

    fn fork_and_wait_pipe(&mut self, _request: &LaunchRequest) -> Result<u32, LaunchError> {
        Err(LaunchError::NotVerified {
            step: "fork + pipe wait",
        })
    }

    fn adopt(&mut self, _pid: u32) -> Result<AdoptWait, LaunchError> {
        Err(LaunchError::NotVerified { step: "adopt" })
    }

    fn sigcont(&mut self, _pid: u32) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified { step: "SIGCONT" })
    }

    fn release_pipe(&mut self, _pid: u32) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified {
            step: "pipe release",
        })
    }

    fn terminate(&mut self, _pid: u32) -> Result<(), LaunchError> {
        Err(LaunchError::NotVerified {
            step: "terminate child",
        })
    }

    fn wait_exit(&mut self, _pid: u32) -> Result<i32, LaunchError> {
        Err(LaunchError::NotVerified { step: "waitpid" })
    }
}

/// Honest limit of [`PosixSpawnApi`].
///
/// `POSIX_SPAWN_START_SUSPENDED` needs an Apple-specific attribute
/// (`posix_spawnattr_setflags` with a flag that is not in a crate this binary
/// already depends on). `aw-cli` has no `libc` dependency and the workspace
/// forbids `unsafe`. This build therefore does not set the flag and does not
/// call `fork` plus a wait pipe either (that is also `unsafe`).
///
/// The child is spawned with [`std::process::Command`] and starts running.
/// Grandchild scope is a collector concern and is not claimed here. This is
/// not E1 scope.
#[cfg(target_os = "macos")]
const NO_SUSPEND_NOTE: &str =
    "未应用挂起；此构建没有 Job 或挂起机制，未设置 POSIX_SPAWN_START_SUSPENDED；不保证孙进程范围";

/// Production [`SpawnApi`] for macOS.
///
/// `spawn_suspended` starts the child with [`std::process::Command`] and
/// returns [`LaunchError::SpawnFailed`] whose detail is [`NO_SUSPEND_NOTE`]
/// only when spawn itself fails to be the honest path — see the method. On
/// success the pid is returned and [`Self::detail`] carries the note so a
/// caller can print it. The method does **not** return [`LaunchError::Unsupported`]:
/// that would fall through to `fork_and_wait_pipe`, and this build cannot
/// fork-and-wait without `unsafe`. A plain spawn whose detail says suspension
/// was not applied is the honest result.
///
/// `adopt` returns [`AdoptWait::Adopted`] with no daemon round-trip. That is
/// not a scope claim. The collector does not learn the pid from this type.
///
/// argv is the `Command` program and its arguments. It is not written to a
/// log or to an error `Display`.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct PosixSpawnApi {
    child: Option<std::process::Child>,
    /// Set after a successful spawn. Says suspension was not applied.
    detail: Option<&'static str>,
}

/// Production macOS launcher. Only compiled on macOS.
///
/// On any other OS this function does not exist, so a non-macOS binary cannot
/// construct the API and cannot spawn through it.
#[cfg(target_os = "macos")]
#[must_use]
pub fn production() -> PosixSpawnApi {
    PosixSpawnApi {
        child: None,
        detail: None,
    }
}

#[cfg(target_os = "macos")]
impl PosixSpawnApi {
    /// Note from the last successful spawn.
    ///
    /// `Some` means the child is running and suspension was **not** applied.
    /// `None` means no child has been spawned yet.
    #[must_use]
    pub fn detail(&self) -> Option<&'static str> {
        self.detail
    }

    fn child_mut(&mut self) -> Result<&mut std::process::Child, LaunchError> {
        self.child
            .as_mut()
            .ok_or_else(|| LaunchError::ContinueFailed {
                detail: "此步骤没有子进程".to_owned(),
            })
    }

    fn spawn_command(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError> {
        if request.identity != LaunchIdentity::CallingUser {
            return Err(LaunchError::SpawnFailed {
                detail: "只能以调用用户身份启动；root 不是路径".to_owned(),
            });
        }
        let Some((program, args)) = request.command.split_first() else {
            return Err(LaunchError::EmptyCommand);
        };
        let mut cmd = std::process::Command::new(program);
        cmd.args(args);
        cmd.stdin(std::process::Stdio::inherit());
        cmd.stdout(std::process::Stdio::inherit());
        cmd.stderr(std::process::Stdio::inherit());
        match cmd.spawn() {
            Ok(child) => {
                let pid = child.id();
                self.child = Some(child);
                self.detail = Some(NO_SUSPEND_NOTE);
                Ok(pid)
            }
            Err(err) => Err(LaunchError::SpawnFailed {
                // `err` is an io::Error. Its Display is the OS message, not argv.
                detail: format!("通过 Command 调用 posix_spawn 失败：{err}；{NO_SUSPEND_NOTE}"),
            }),
        }
    }
}

#[cfg(target_os = "macos")]
impl SpawnApi for PosixSpawnApi {
    fn spawn_suspended(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError> {
        // Not POSIX_SPAWN_START_SUSPENDED. The child runs immediately.
        // Returning Unsupported would ask `run_launch` to fork-and-wait, which
        // this build also cannot do. The spawn detail records the missing flag.
        self.spawn_command(request)
    }

    fn fork_and_wait_pipe(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError> {
        // Same Command spawn. There is no pipe and no pre-exec wait. Callers
        // that land here (only if `spawn_suspended` returned Unsupported, which
        // this type does not) still must not claim the child is blocked.
        self.spawn_command(request)
    }

    fn adopt(&mut self, pid: u32) -> Result<AdoptWait, LaunchError> {
        let child_pid = self.child_mut()?.id();
        if child_pid != pid {
            return Ok(AdoptWait::Failed {
                detail: "PID 与已启动的子进程不匹配".to_owned(),
            });
        }
        // No daemon. Accepting locally lets `run_launch` wait for the exit
        // code. It does not put the pid in a scope and is not E1.
        Ok(AdoptWait::Adopted)
    }

    fn sigcont(&mut self, pid: u32) -> Result<(), LaunchError> {
        let child_pid = self.child_mut()?.id();
        if child_pid != pid {
            return Err(LaunchError::ContinueFailed {
                detail: "PID 与已启动的子进程不匹配".to_owned(),
            });
        }
        // The child was not suspended, so SIGCONT is not sent. `Ok` here means
        // "nothing to continue", not "the process was suspended and then
        // continued". [`Self::detail`] is `Some(NO_SUSPEND_NOTE)` after spawn
        // and is the only place that fact is recorded. Killing the child here
        // would hide its real exit code.
        Ok(())
    }

    fn release_pipe(&mut self, pid: u32) -> Result<(), LaunchError> {
        let child_pid = self.child_mut()?.id();
        if child_pid != pid {
            return Err(LaunchError::ContinueFailed {
                detail: "PID 与已启动的子进程不匹配".to_owned(),
            });
        }
        Err(LaunchError::ContinueFailed {
            detail: "没有持有管道；未挂起进程".to_owned(),
        })
    }

    fn terminate(&mut self, pid: u32) -> Result<(), LaunchError> {
        let child = self.child_mut()?;
        if child.id() != pid {
            return Err(LaunchError::ContinueFailed {
                detail: "PID 与已启动的子进程不匹配".to_owned(),
            });
        }
        child.kill().map_err(|err| LaunchError::ContinueFailed {
            detail: format!("结束进程失败：{err}"),
        })?;
        let _ = child.wait();
        Ok(())
    }

    fn wait_exit(&mut self, pid: u32) -> Result<i32, LaunchError> {
        let child = self.child_mut()?;
        if child.id() != pid {
            return Err(LaunchError::ContinueFailed {
                detail: "PID 与已启动的子进程不匹配".to_owned(),
            });
        }
        match child.wait() {
            Ok(status) => Ok(status.code().unwrap_or(-1)),
            Err(err) => Err(LaunchError::ContinueFailed {
                detail: format!("通过 Child::wait 调用 waitpid 失败：{err}"),
            }),
        }
    }
}

/// Run `command` and wait. Suspension is not applied.
///
/// Returns the child's exit code, its pid, and [`NO_SUSPEND_NOTE`]. The note
/// is not an E1 scope claim. Grandchild tracking is the collector's job.
///
/// This is a plain method, not [`crate`]'s `UnixLauncher`, so the test-only
/// include of this file (parent is the crate root, not `launch`) still
/// compiles. `aw run` calls it from `cmd/run.rs` on macOS.
///
/// # Errors
///
/// [`LaunchError`] from the state machine. A spawn failure happens before a
/// pid exists. Adopt failure terminates the child inside [`run_launch`].
#[cfg(target_os = "macos")]
pub fn launch_command(
    api: &mut PosixSpawnApi,
    command: Vec<String>,
    no_daemon: bool,
) -> Result<(i32, u32, Option<&'static str>, bool), LaunchError> {
    let request = LaunchRequest::new(command)?;
    let finished = run_launch(api, &request)?;
    Ok((finished.code, finished.pid, api.detail, no_daemon))
}

/// Scripted [`SpawnApi`] for tests. Holds no pid and starts no process.
#[cfg(test)]
#[derive(Debug)]
struct FakeSpawn {
    pid: u32,
    exit_code: i32,
    adopt: AdoptWait,
    /// When true, `spawn_suspended` returns [`LaunchError::Unsupported`].
    suspended_unsupported: bool,
    fail_spawn: bool,
    fail_fork: bool,
    steps: Vec<LaunchStep>,
    continued: bool,
    terminated: bool,
    saw_identity: Option<LaunchIdentity>,
    /// Argument count only. The command text is not stored.
    arg_count: Option<usize>,
}

#[cfg(test)]
impl FakeSpawn {
    fn new(adopt: AdoptWait) -> Self {
        Self {
            pid: 4242,
            exit_code: 0,
            adopt,
            suspended_unsupported: false,
            fail_spawn: false,
            fail_fork: false,
            steps: Vec::new(),
            continued: false,
            terminated: false,
            saw_identity: None,
            arg_count: None,
        }
    }
}

#[cfg(test)]
impl SpawnApi for FakeSpawn {
    fn spawn_suspended(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError> {
        self.steps.push(LaunchStep::SpawnSuspended);
        self.saw_identity = Some(request.identity);
        self.arg_count = Some(request.command.len());
        if self.suspended_unsupported {
            return Err(LaunchError::Unsupported);
        }
        if self.fail_spawn {
            return Err(LaunchError::SpawnFailed {
                detail: "scripted".to_owned(),
            });
        }
        Ok(self.pid)
    }

    fn fork_and_wait_pipe(&mut self, request: &LaunchRequest) -> Result<u32, LaunchError> {
        self.steps.push(LaunchStep::ForkAndWaitPipe);
        self.saw_identity = Some(request.identity);
        self.arg_count = Some(request.command.len());
        if self.fail_fork {
            return Err(LaunchError::ForkFailed {
                detail: "scripted".to_owned(),
            });
        }
        Ok(self.pid)
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

    fn sigcont(&mut self, pid: u32) -> Result<(), LaunchError> {
        self.steps.push(LaunchStep::SigCont);
        if pid != self.pid {
            return Err(LaunchError::ContinueFailed {
                detail: "pid mismatch".to_owned(),
            });
        }
        self.continued = true;
        Ok(())
    }

    fn release_pipe(&mut self, pid: u32) -> Result<(), LaunchError> {
        self.steps.push(LaunchStep::ReleasePipe);
        if pid != self.pid {
            return Err(LaunchError::ContinueFailed {
                detail: "pid mismatch".to_owned(),
            });
        }
        self.continued = true;
        Ok(())
    }

    fn terminate(&mut self, pid: u32) -> Result<(), LaunchError> {
        self.steps.push(LaunchStep::Terminate);
        if pid != self.pid {
            return Err(LaunchError::ContinueFailed {
                detail: "pid mismatch".to_owned(),
            });
        }
        self.terminated = true;
        Ok(())
    }

    fn wait_exit(&mut self, pid: u32) -> Result<i32, LaunchError> {
        if pid != self.pid {
            return Err(LaunchError::ContinueFailed {
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

    fn request() -> LaunchRequest {
        LaunchRequest::new(vec!["zsh".to_owned(), "-c".to_owned(), "exit 7".to_owned()])
            .expect("command")
    }

    #[test]
    fn suspended_path_is_spawn_then_adopt_then_sigcont() {
        let mut api = FakeSpawn::new(AdoptWait::Adopted);
        api.exit_code = 7;
        let done = run_launch(&mut api, &request()).expect("launch");
        assert_eq!(done.path, SpawnPath::Suspended);
        assert_eq!(
            done.steps,
            vec![
                LaunchStep::SpawnSuspended,
                LaunchStep::Adopt,
                LaunchStep::SigCont,
            ]
        );
        let adopt_at = done
            .steps
            .iter()
            .position(|step| *step == LaunchStep::Adopt)
            .expect("adopt");
        let cont_at = done
            .steps
            .iter()
            .position(|step| *step == LaunchStep::SigCont)
            .expect("sigcont");
        assert!(adopt_at < cont_at);
        assert!(api.continued);
        assert!(!api.terminated);
        assert!(!done.steps.contains(&LaunchStep::ReleasePipe));
        assert_eq!(api.saw_identity, Some(LaunchIdentity::CallingUser));
        assert_eq!(done.code, 7);
        assert_eq!(done.pid, 4242);
    }

    #[test]
    fn adopt_failure_does_not_sigcont_and_terminates() {
        let mut api = FakeSpawn::new(AdoptWait::Failed {
            detail: "daemon refused".to_owned(),
        });
        let err = run_launch(&mut api, &request()).expect_err("adopt");
        assert_eq!(
            err,
            LaunchError::AdoptFailed {
                detail: "daemon refused".to_owned(),
            }
        );
        assert!(api.terminated);
        assert!(!api.continued);
        assert!(!api.steps.contains(&LaunchStep::SigCont));
        assert!(!api.steps.contains(&LaunchStep::ReleasePipe));
        assert_eq!(*api.steps.last().expect("last"), LaunchStep::Terminate);
    }

    #[test]
    fn adopt_timeout_does_not_sigcont_and_terminates() {
        let mut api = FakeSpawn::new(AdoptWait::TimedOut);
        let err = run_launch(&mut api, &request()).expect_err("timeout");
        assert_eq!(err, LaunchError::AdoptTimeout);
        assert!(api.terminated);
        assert!(!api.continued);
        assert!(!api.steps.contains(&LaunchStep::SigCont));
        assert_eq!(ADOPT_TIMEOUT, Duration::from_secs(5));
    }

    #[test]
    fn unsupported_suspended_uses_fork_pipe_in_order() {
        let mut api = FakeSpawn::new(AdoptWait::Adopted);
        api.suspended_unsupported = true;
        api.exit_code = 0;
        let done = run_launch(&mut api, &request()).expect("fallback");
        assert_eq!(done.path, SpawnPath::ForkPipe);
        assert_eq!(
            done.steps,
            vec![
                LaunchStep::ForkAndWaitPipe,
                LaunchStep::Adopt,
                LaunchStep::ReleasePipe,
            ]
        );
        let adopt_at = done
            .steps
            .iter()
            .position(|step| *step == LaunchStep::Adopt)
            .expect("adopt");
        let release_at = done
            .steps
            .iter()
            .position(|step| *step == LaunchStep::ReleasePipe)
            .expect("release");
        assert!(adopt_at < release_at);
        assert!(api.continued);
        assert!(!api.terminated);
        assert!(!done.steps.contains(&LaunchStep::SigCont));
        assert_eq!(api.saw_identity, Some(LaunchIdentity::CallingUser));
    }

    #[test]
    fn fork_path_adopt_failure_does_not_release_the_pipe() {
        let mut api = FakeSpawn::new(AdoptWait::TimedOut);
        api.suspended_unsupported = true;
        let err = run_launch(&mut api, &request()).expect_err("timeout");
        assert_eq!(err, LaunchError::AdoptTimeout);
        assert!(api.terminated);
        assert!(!api.continued);
        assert!(!api.steps.contains(&LaunchStep::ReleasePipe));
        assert!(!api.steps.contains(&LaunchStep::SigCont));
    }

    #[test]
    fn empty_command_is_rejected() {
        let err = LaunchRequest::new(Vec::new()).expect_err("empty");
        assert_eq!(err, LaunchError::EmptyCommand);
    }

    #[test]
    fn spawn_failure_does_not_fall_back_to_fork() {
        let mut api = FakeSpawn::new(AdoptWait::Adopted);
        api.fail_spawn = true;
        let err = run_launch(&mut api, &request()).expect_err("spawn");
        assert_eq!(
            err,
            LaunchError::SpawnFailed {
                detail: "scripted".to_owned(),
            }
        );
        assert!(!api.steps.contains(&LaunchStep::ForkAndWaitPipe));
        assert!(!api.continued);
        assert!(!api.terminated);
    }

    #[test]
    fn unverified_stub_does_not_create_a_process() {
        let mut api = UnverifiedSpawnApi;
        let err = run_launch(&mut api, &request()).expect_err("stub");
        assert_eq!(
            err,
            LaunchError::NotVerified {
                step: "posix_spawn(POSIX_SPAWN_START_SUSPENDED)",
            }
        );
    }
}
