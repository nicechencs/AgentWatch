//! Platform launchers for `aw run` (P1-WIN-04, P1-CLI-02).
//!
//! Windows launch lives in `aw-platform`, so this crate has no Win32 FFI.
//! macOS `aw run` starts through `aw-platform` (`POSIX_SPAWN_START_SUSPENDED`),
//! not through this module. Linux production uses
//! [`unix_linux::LocalCgroupHost`] (cfg-gated): a delegated cgroup v2 directory,
//! or a structured error and no child. [`UnsupportedUnixLauncher`] remains the
//! production value on every other non-Windows target.
//!
//! Ctrl-C forwarding lives on the launcher trait (`forward_interrupt`). Tests
//! pass a fake and never send a real signal.

// Linux production `aw run` uses [`unix_linux::LocalCgroupHost`]. The module is
// cfg-gated so non-Linux builds do not compile the host. [`UnverifiedCgroupLaunch`]
// stays the test double inside that file; this module does not construct it.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "unix_linux.rs"]
mod unix_linux;

/// Present only on Linux. [`unix_linux::LocalCgroupHost`] creates a cgroup v2
/// session directory when the caller is delegated, and refuses otherwise.
#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub use unix_linux::LocalCgroupHost;

/// Linux launch errors, so `aw run` can decide when to fall back from a
/// cgroup scope to process-tree tracking.
#[cfg(target_os = "linux")]
#[allow(unused_imports)]
pub use unix_linux::{LaunchError as LinuxLaunchError, LaunchResult as LinuxLaunchResult};

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
    /// [`LaunchDispatchError::Invalid`] when `command` is empty.
    pub fn new(command: Vec<String>) -> Result<Self, LaunchDispatchError> {
        if command.is_empty() {
            return Err(LaunchDispatchError::Invalid {
                detail: "启动命令为空".to_owned(),
            });
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
    /// The platform launcher stopped before the target finished.
    Platform { detail: String },
    /// The supplied run request is invalid before a launcher is called.
    Invalid { detail: String },
    /// This target has no launcher yet. Named so the message can say which card.
    NotImplemented { detail: String },
}

impl std::fmt::Display for LaunchDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Platform { detail } | Self::Invalid { detail } => write!(f, "{detail}"),
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
/// P1-MAC-03 (`aw-platform` on macOS). The macOS module is not compiled here.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct UnsupportedUnixLauncher;

impl UnixLauncher for UnsupportedUnixLauncher {
    fn launch(&mut self, _spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
        Err(LaunchDispatchError::NotImplemented {
            detail: "此二进制没有内置 Unix 启动器；进程启动由 P1-LNX-04 和 P1-MAC-03 提供"
                .to_owned(),
        })
    }

    fn forward_interrupt(&mut self, _pid: u32) -> Result<(), LaunchDispatchError> {
        Err(LaunchDispatchError::NotImplemented {
            detail: "此二进制没有内置 Unix 启动器；中断转发由 P1-LNX-04 和 P1-MAC-03 提供"
                .to_owned(),
        })
    }
}

/// Hand `spec` to a [`UnixLauncher`].
///
/// The function stays available on every target so the trait contract can be tested
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
}
