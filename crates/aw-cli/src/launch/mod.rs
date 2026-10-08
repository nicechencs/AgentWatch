//! Platform launchers for `aw run` (P1-WIN-04, P1-CLI-02).
//!
//! Windows calls [`windows::run_launch`]. Other targets have no launcher in this
//! crate yet: P1-LNX-04 and P1-MAC-03 own `launch/unix_linux.rs` and
//! `launch/unix_macos.rs`. Those files are not referenced here. The non-Windows
//! path is the [`UnixLauncher`] trait. Its production value returns
//! [`LaunchDispatchError::NotImplemented`] and starts nothing.
//!
//! Ctrl-C forwarding lives on the launcher trait (`forward_interrupt`). Tests
//! pass a fake and never send a real signal.

// The state machine's public items are the contract for later cards. Not every
// variant is constructed by this binary yet; that is not a dead-code defect.
#[allow(dead_code)]
mod windows;

// P1-LNX-04 (`unix_linux.rs`) and P1-MAC-03 (`unix_macos.rs`) are not declared
// here. Those files are owned by the other cards. Non-Windows `aw run` goes
// through [`UnixLauncher`]; [`UnsupportedUnixLauncher`] is the production value
// until those cards replace it.

#[allow(unused_imports)]
pub use windows::{
    run_launch, JobApi, LaunchError, LaunchRequest, LaunchStep, SessionAnnotation, TargetExit,
    ADOPT_TIMEOUT, BREAKAWAY_INCOMPLETE_NOTE,
};

/// Present only on Windows. The stub refuses every step; it does not call Win32.
#[cfg(target_os = "windows")]
pub use windows::UnverifiedJobApi;

/// What `aw run` asks a platform launcher to do.
///
/// `command`, `cwd`, and `env` are inputs, not log fields. A launcher must not
/// print them. The length of `env` is the only fact a summary may mention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSpec {
    /// Executable plus arguments. Not logged.
    pub command: Vec<String>,
    /// Working directory override. `None` means the caller's directory.
    pub cwd: Option<String>,
    /// Extra environment pairs, already split as `KEY=VALUE`. Not logged.
    pub env: Vec<(String, String)>,
    /// `--no-follow-children`: the scope is the root process only.
    pub no_follow_children: bool,
    /// `--allow-breakaway` is not a `Run` flag today. Always `false` from `aw run`.
    pub allow_breakaway: bool,
    /// `--no-daemon`: poll collector inside the CLI, evidence S. The launcher
    /// still starts the target as the calling user; it does not raise privilege.
    pub no_daemon: bool,
}

impl RunSpec {
    /// A spec for `command`, as the calling user.
    ///
    /// # Errors
    ///
    /// [`LaunchError::EmptyCommand`] when `command` is empty.
    pub fn new(command: Vec<String>) -> Result<Self, LaunchError> {
        if command.is_empty() {
            return Err(LaunchError::EmptyCommand);
        }
        Ok(Self {
            command,
            cwd: None,
            env: Vec::new(),
            no_follow_children: false,
            allow_breakaway: false,
            no_daemon: false,
        })
    }
}

/// Why the dispatch could not hand the spec to a platform launcher.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum LaunchDispatchError {
    /// The Windows state machine stopped before the target finished.
    Windows(LaunchError),
    /// This target has no launcher yet. Named so the message can say which card.
    NotImplemented { detail: String },
}

impl std::fmt::Display for LaunchDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Windows(err) => write!(f, "{err}"),
            Self::NotImplemented { detail } => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for LaunchDispatchError {}

/// One launched target. `code` is the target's exit code, not a CLI error code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launched {
    /// Target exit code, unchanged.
    pub code: i32,
    /// Pid the launcher assigned.
    pub pid: u32,
    /// Session note, when the launcher wrote one (breakaway).
    pub note: Option<&'static str>,
    /// `true` when `--no-daemon` was set. The summary then says the mode is sampling.
    pub sampling: bool,
}

/// Platform launcher `aw run` calls.
///
/// P1-LNX-04 and P1-MAC-03 implement this for their targets. The method set is
/// deliberately small: start as the calling user, forward one interrupt, and
/// report the exit. There is no method that changes the user token.
#[allow(dead_code)]
pub trait UnixLauncher {
    /// Create the target as the calling user and wait until it exits.
    ///
    /// Must not start the target as another user. Must not print `spec.command`
    /// or `spec.env`.
    ///
    /// # Errors
    ///
    /// [`LaunchDispatchError::NotImplemented`] until the platform card lands, or
    /// a launcher-specific failure that did not produce an exit code.
    fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError>;

    /// Forward one interrupt (Ctrl-C) to the target. Tests call this on a fake;
    /// they do not send a real signal.
    ///
    /// # Errors
    ///
    /// The launcher could not forward. The target is left running.
    fn forward_interrupt(&mut self, pid: u32) -> Result<(), LaunchDispatchError>;
}

impl<T: UnixLauncher + ?Sized> UnixLauncher for &mut T {
    fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
        (**self).launch(spec)
    }

    fn forward_interrupt(&mut self, pid: u32) -> Result<(), LaunchDispatchError> {
        (**self).forward_interrupt(pid)
    }
}

/// Production launcher for non-Windows targets. Starts nothing.
///
/// The real process launcher is P1-LNX-04 (`launch/unix_linux.rs`) and
/// P1-MAC-03 (`launch/unix_macos.rs`). Those modules are not compiled here.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct UnsupportedUnixLauncher;

impl UnixLauncher for UnsupportedUnixLauncher {
    fn launch(&mut self, _spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
        Err(LaunchDispatchError::NotImplemented {
            detail: "no Unix launcher is built into this binary; process start is provided by P1-LNX-04 and P1-MAC-03".to_owned(),
        })
    }

    fn forward_interrupt(&mut self, _pid: u32) -> Result<(), LaunchDispatchError> {
        Err(LaunchDispatchError::NotImplemented {
            detail: "no Unix launcher is built into this binary; interrupt forwarding is provided by P1-LNX-04 and P1-MAC-03".to_owned(),
        })
    }
}

/// Run `spec` on Windows through [`run_launch`].
///
/// Uses `api` for every Win32 step. The production caller passes
/// [`UnverifiedJobApi`], which refuses the first step and creates no process.
/// The target identity is always [`windows::LaunchIdentity::CallingUser`].
///
/// # Errors
///
/// [`LaunchDispatchError::Windows`] when the state machine stops.
#[cfg(target_os = "windows")]
pub fn dispatch_windows<A: JobApi>(
    api: &mut A,
    spec: &RunSpec,
) -> Result<Launched, LaunchDispatchError> {
    let mut request =
        LaunchRequest::new(spec.command.clone()).map_err(LaunchDispatchError::Windows)?;
    request.allow_breakaway = spec.allow_breakaway;
    let finished = run_launch(api, &request).map_err(LaunchDispatchError::Windows)?;
    Ok(Launched {
        code: finished.code,
        pid: finished.pid,
        note: finished.annotation.map(|item| item.note),
        sampling: spec.no_daemon,
    })
}

/// Hand `spec` to a [`UnixLauncher`].
///
/// On Windows `aw run` does not call this: it calls [`dispatch_windows`]. The
/// function stays available on every target so the trait contract can be tested
/// without a Unix host. P1-LNX-04 and P1-MAC-03 supply the production impl.
///
/// # Errors
///
/// Whatever `launcher` returns. [`UnsupportedUnixLauncher`] returns
/// [`LaunchDispatchError::NotImplemented`].
#[allow(dead_code)]
pub fn dispatch_unix(
    launcher: &mut dyn UnixLauncher,
    spec: &RunSpec,
) -> Result<Launched, LaunchDispatchError> {
    launcher.launch(spec)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod dispatch_tests {
    use super::{
        dispatch_unix, LaunchDispatchError, Launched, RunSpec, UnixLauncher,
        UnsupportedUnixLauncher,
    };

    #[cfg(target_os = "windows")]
    use super::dispatch_windows;

    struct FakeUnix {
        code: i32,
        forwarded: Vec<u32>,
        saw_breakaway: Option<bool>,
        saw_env_len: Option<usize>,
    }

    impl UnixLauncher for FakeUnix {
        fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
            self.saw_breakaway = Some(spec.allow_breakaway);
            self.saw_env_len = Some(spec.env.len());
            Ok(Launched {
                code: self.code,
                pid: 7,
                note: None,
                sampling: spec.no_daemon,
            })
        }

        fn forward_interrupt(&mut self, pid: u32) -> Result<(), LaunchDispatchError> {
            self.forwarded.push(pid);
            Ok(())
        }
    }

    #[test]
    fn unsupported_unix_names_the_cards_and_starts_nothing() {
        let spec = RunSpec::new(vec!["cmd".to_owned()]).expect("spec");
        let err = UnsupportedUnixLauncher.launch(&spec).expect_err("stub");
        let text = err.to_string();
        assert!(text.contains("P1-LNX-04"), "{text}");
        assert!(text.contains("P1-MAC-03"), "{text}");
        assert!(
            !text.contains("cmd") || text.contains("no Unix launcher"),
            "{text}"
        );
    }

    #[test]
    fn fake_unix_returns_the_target_code_and_records_an_interrupt() {
        let spec = RunSpec::new(vec!["tool".to_owned()]).expect("spec");
        let mut fake = FakeUnix {
            code: 7,
            forwarded: Vec::new(),
            saw_breakaway: None,
            saw_env_len: None,
        };
        let launched = dispatch_unix(&mut fake, &spec).expect("launch");
        assert_eq!(launched.code, 7);
        fake.forward_interrupt(launched.pid).expect("forward");
        assert_eq!(fake.forwarded, vec![7]);
        assert_eq!(fake.saw_breakaway, Some(false));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_dispatch_uses_the_calling_user_and_keeps_exit_7() {
        use super::windows::{AdoptWait, JobApi, LaunchIdentity, LaunchStep};

        struct FakeJob {
            steps: Vec<LaunchStep>,
        }

        impl JobApi for FakeJob {
            fn create_suspended(
                &mut self,
                request: &super::LaunchRequest,
            ) -> Result<u32, super::LaunchError> {
                assert_eq!(request.identity, LaunchIdentity::CallingUser);
                self.steps.push(LaunchStep::CreateSuspended);
                Ok(11)
            }

            fn create_job_and_assign(
                &mut self,
                _pid: u32,
                allow_breakaway: bool,
            ) -> Result<(), super::LaunchError> {
                assert!(!allow_breakaway);
                self.steps.push(LaunchStep::CreateJob);
                self.steps.push(LaunchStep::AssignToJob);
                Ok(())
            }

            fn handoff_and_adopt(&mut self, _pid: u32) -> Result<AdoptWait, super::LaunchError> {
                self.steps.push(LaunchStep::HandOffHandle);
                self.steps.push(LaunchStep::Adopt);
                Ok(AdoptWait::Adopted)
            }

            fn resume(&mut self, _pid: u32) -> Result<(), super::LaunchError> {
                self.steps.push(LaunchStep::ResumeThread);
                Ok(())
            }

            fn terminate(&mut self, _pid: u32) -> Result<(), super::LaunchError> {
                self.steps.push(LaunchStep::Terminate);
                Ok(())
            }

            fn wait_exit(&mut self, _pid: u32) -> Result<i32, super::LaunchError> {
                Ok(7)
            }
        }

        let spec =
            RunSpec::new(vec!["cmd".to_owned(), "/c".to_owned(), "exit".to_owned()]).expect("spec");
        let mut api = FakeJob { steps: Vec::new() };
        let launched = dispatch_windows(&mut api, &spec).expect("windows");
        assert_eq!(launched.code, 7);
        assert!(!api.steps.contains(&LaunchStep::Terminate));
    }
}
