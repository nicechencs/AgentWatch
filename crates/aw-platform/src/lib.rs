//! Explicit operating-system boundary for AgentWatch shared code.
//!
//! `unsafe_code` is `deny`, not the workspace `forbid`: a `forbid` cannot be
//! relaxed, and the Windows and macOS modules need FFI. Those modules are the
//! only places that opt back in (`#[allow(unsafe_code)]`), and every call
//! there has a `SAFETY` comment. Shared code in this file stays safe.
#![deny(unsafe_code)]

/// OS-independent Windows Job launch state machine.
///
/// The Windows platform module supplies the FFI primitives; this module keeps
/// the ordering and failure rules testable on every supported target.
pub mod held_launch;

use std::fmt;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
// The hold stage is a forked child, not a re-exec. It is Unix-generic: macOS
// and Linux both call it. The gate pipe stays CLOEXEC in the parent, so a
// sibling spawn cannot inherit it.
#[cfg(unix)]
pub(crate) mod unix;

/// The fixed `PATH` a from-scratch target environment starts with. See
/// `unix/hold.rs`. Unix only: Windows does not build that environment here.
#[cfg(unix)]
pub const fn unix_default_path() -> &'static str {
    unix::hold::DEFAULT_TARGET_PATH
}

/// Candidate paths for a program name, built as strings. No filesystem access.
/// See [`unix::hold::program_candidates`]. Unix only: Windows does not search a
/// `:`-separated PATH.
#[cfg(unix)]
#[must_use]
pub fn unix_program_candidates(program: &str, search_path: Option<&str>) -> Vec<String> {
    unix::hold::program_candidates(program, search_path)
}
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
use linux::CurrentPlatform;
#[cfg(target_os = "macos")]
use macos::CurrentPlatform;
#[cfg(target_os = "windows")]
use windows::CurrentPlatform;

/// Operating system version for `aw doctor`. `None` when this build cannot read
/// it; the caller prints 「不可得」 and never an empty string.
#[must_use]
pub fn os_version() -> Option<String> {
    os_version_of()
}

/// Stable Windows boot discriminator used by every Windows process identity.
/// It is the System process (pid 4) creation time, not wall clock minus
/// uptime, so time synchronization and sampling at different moments cannot
/// produce different generations for the same boot.
#[cfg(windows)]
pub fn windows_system_boot_id() -> Option<Vec<u8>> {
    windows::system_boot_id()
}
#[cfg(target_os = "linux")]
fn os_version_of() -> Option<String> {
    linux::os_version()
}
#[cfg(target_os = "macos")]
fn os_version_of() -> Option<String> {
    macos::os_version()
}
#[cfg(target_os = "windows")]
fn os_version_of() -> Option<String> {
    windows::os_version()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedKind {
    NotInThisBuild,
    NotSupportedOnThisOs,
}
impl UnsupportedKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInThisBuild => "not_in_this_build",
            Self::NotSupportedOnThisOs => "not_supported_on_this_os",
        }
    }
    pub const fn zh(self) -> &'static str {
        match self {
            Self::NotInThisBuild => "本版本未接入",
            Self::NotSupportedOnThisOs => "这个系统不支持",
        }
    }
    pub const fn en(self) -> &'static str {
        match self {
            Self::NotInThisBuild => "Not in this build",
            Self::NotSupportedOnThisOs => "Not supported on this OS",
        }
    }
}
impl fmt::Display for UnsupportedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.en())
    }
}

/// A target failed after the launch gate was released.  These categories are
/// deliberately independent of `std::io::ErrorKind`: callers must preserve
/// whether the target program or its working directory caused the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnFailure {
    ProgramNotFound,
    ProgramNotPermitted,
    CwdNotFound,
    CwdNotPermitted,
}

impl SpawnFailure {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProgramNotFound => "program_not_found",
            Self::ProgramNotPermitted => "program_not_permitted",
            Self::CwdNotFound => "cwd_not_found",
            Self::CwdNotPermitted => "cwd_not_permitted",
        }
    }
}

#[derive(Debug)]
pub enum PlatformError {
    Unsupported {
        capability: &'static str,
        os: &'static str,
        kind: UnsupportedKind,
    },
    /// Never convert a missing OS credential into a daemon/default identity.
    PeerNotIdentified {
        reason: &'static str,
    },
    /// Windows named-pipe peer authentication failed at a Win32 call. Keep
    /// the operation and exact code so the daemon can diagnose a 403 without
    /// exposing it in a human-facing error message.
    PipePeerNotIdentified {
        operation: &'static str,
        win32_error: i32,
    },
    /// The held child reached `chdir` or `execve` after the caller released
    /// its gate.  This is not a generic gate failure: it is a user-correctable
    /// program or directory failure and must reach the API/CLI unchanged.
    Spawn(SpawnFailure),
    Io(std::io::Error),
    Invalid {
        capability: &'static str,
        detail: &'static str,
    },
}
impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported {
                capability,
                os,
                kind,
            } => write!(
                f,
                "{capability} is unsupported on {os}: {} ({})",
                kind.en(),
                kind.as_str()
            ),
            Self::PeerNotIdentified { reason } => write!(f, "peer was not identified: {reason}"),
            Self::PipePeerNotIdentified {
                operation,
                win32_error,
            } => write!(
                f,
                "named-pipe peer was not identified: {operation} failed (Win32 error {win32_error})"
            ),
            Self::Spawn(kind) => write!(f, "held target could not start: {}", kind.code()),
            Self::Io(error) => write!(f, "platform I/O error: {error}"),
            Self::Invalid { capability, detail } => write!(f, "{capability}: {detail}"),
        }
    }
}
impl std::error::Error for PlatformError {}

impl PlatformError {
    /// The exact Win32 error from a named-pipe peer-authentication primitive.
    /// Other platform errors deliberately do not claim to carry one.
    #[must_use]
    pub const fn pipe_peer_win32_error(&self) -> Option<i32> {
        match self {
            Self::PipePeerNotIdentified { win32_error, .. } => Some(*win32_error),
            _ => None,
        }
    }
}

/// Why a client could not establish that a connected Windows named pipe is an
/// AgentWatch daemon pipe. The client must send no request bytes on either
/// outcome, but the stable categories intentionally differ for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeServerVerificationError {
    /// The pipe object's owner SID could not be queried.
    CannotQuery {
        operation: &'static str,
        win32_error: u32,
        /// Diagnostic detail for logs and JSON output only. Human-facing
        /// wording stays with the channel error category.
        detail: Option<String>,
    },
    /// The owner SID was read successfully but is not trusted as a daemon.
    NotDaemon {
        /// Diagnostic detail for logs and JSON output only. This may name a
        /// local image path, never a request or credential.
        detail: Option<String>,
    },
}

impl fmt::Display for PipeServerVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CannotQuery {
                operation,
                win32_error,
                detail,
            } => {
                write!(
                    f,
                    "named-pipe server owner query failed: {operation} (Win32 error {win32_error})"
                )?;
                if let Some(detail) = detail {
                    write!(f, "; {detail}")?;
                }
                Ok(())
            }
            Self::NotDaemon { detail } => {
                f.write_str("named-pipe server owner is not trusted")?;
                if let Some(detail) = detail {
                    write!(f, ": {detail}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for PipeServerVerificationError {}

/// The observed installation state for the Windows `AgentWatch` SCM service.
///
/// An SCM query failure is intentionally distinct from no service: callers
/// must fail closed and require a LocalSystem-owned pipe in that case.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeServiceStatus {
    /// The SCM reports that the service does not exist. A foreground,
    /// same-user development daemon is allowed in this mode.
    NotInstalled,
    /// The service exists, whether or not it is currently running.
    Installed {
        /// The executable parsed from `QueryServiceConfigW`, when available.
        binary_path: Option<PathBuf>,
    },
    /// SCM could not determine whether the service exists. Treat this exactly
    /// like an installed service and retain the detail for diagnostics.
    QueryFailed {
        operation: &'static str,
        win32_error: u32,
    },
}
impl From<std::io::Error> for PlatformError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessKey {
    pub pid: u32,
    pub start_time: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityLevel {
    Low,
    Medium,
    High,
    System,
    Other(u32),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    Unix {
        ruid: u32,
        euid: u32,
        suid: u32,
        rgid: u32,
        egid: u32,
        sgid: u32,
        /// Supplementary groups when the platform can authenticate them.
        /// `None` means the platform peer API does not expose them.
        groups: Option<Vec<u32>>,
    },
    Windows {
        sid: String,
        elevated: bool,
        integrity: Option<IntegrityLevel>,
    },
}
#[derive(Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub key: ProcessKey,
    pub ppid: Option<u32>,
    pub exe: Option<PathBuf>,
    pub argv: Option<Vec<String>>,
    pub owner: Option<Owner>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamplingProcess {
    pub key: ProcessKey,
    pub ppid: u32,
    pub start_ns: u64,
    pub boot_id: Vec<u8>,
}
impl fmt::Debug for ProcessEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessEntry")
            .field("key", &self.key)
            .field("ppid", &self.ppid)
            .field("exe", &self.exe)
            .field("argv_len", &self.argv.as_ref().map(Vec::len))
            .field("owner", &self.owner)
            .finish()
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct SpawnRequest {
    pub command: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    /// Where the target's environment comes from.
    ///
    /// The privileged daemon path passes [`EnvSource::Exact`]: the child gets
    /// exactly `env` and nothing of this process. `aw run` and `--no-daemon`
    /// pass [`EnvSource::Inherit`]: they already run as the user, and the child
    /// keeps this process's environment with `env` applied on top. There is no
    /// default that inherits. A caller that forgets the field does not compile.
    pub env_source: EnvSource,
}

/// Which environment `execve` hands the target. Built in the parent, before `fork`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvSource {
    /// This process's environment, then `SpawnRequest::env` overrides. A name
    /// that is not UTF-8 is skipped and logged in the parent; it is never a panic.
    /// Loader names (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`) are dropped unless the
    /// request names them. This is the `aw run` / `--no-daemon` path only.
    Inherit,
    /// Exactly `SpawnRequest::env`, built from scratch. The process environment
    /// is not read. The privileged daemon path uses this so a root daemon cannot
    /// hand its own variables to the target.
    Exact,
}
impl fmt::Debug for SpawnRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnRequest")
            .field("command_len", &self.command.len())
            .field("has_cwd", &self.cwd.is_some())
            .field("env_len", &self.env.len())
            .field("env_source", &self.env_source)
            .finish()
    }
}

/// Owns a process only until release. Dropping/aborting it terminates and reaps it.
pub trait HeldChild: Send {
    fn pid(&self) -> u32;
    fn release(self: Box<Self>) -> Result<Box<dyn ReleasedChild>, PlatformError>;
    fn abort(&mut self) -> Result<(), PlatformError>;
}
/// The sole owner of a released OS child handle. It cannot reap an arbitrary PID.
pub trait ReleasedChild: Send {
    fn pid(&self) -> u32;
    fn try_reap(&mut self) -> Result<ReapOutcome, PlatformError>;
    fn wait(self: Box<Self>) -> Result<ReapOutcome, PlatformError>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapOutcome {
    Exited(i32),
    Signaled(i32),
    StillRunning,
}

/// An OS-authenticated peer. Private fields prevent request data from forging it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    owner: Owner,
    pid: Option<u32>,
}
impl PeerIdentity {
    #[allow(dead_code)] // constructed by OS modules that identify peers in this build
    pub(crate) fn new(owner: Owner, pid: Option<u32>) -> Self {
        Self { owner, pid }
    }
    pub fn owner(&self) -> &Owner {
        &self.owner
    }
    pub const fn pid(&self) -> Option<u32> {
        self.pid
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifiedCaller {
    owner: Owner,
}
impl IdentifiedCaller {
    /// The only way to name a caller who connected. `PeerIdentity` is built
    /// inside this crate from an OS credential, so a uid and gid from a
    /// request cannot become a caller.
    pub fn from_peer(peer: PeerIdentity) -> Self {
        Self { owner: peer.owner }
    }

    pub fn current_user() -> Result<Self, PlatformError> {
        Ok(Self {
            owner: platform().current_owner()?,
        })
    }
    pub fn owner(&self) -> &Owner {
        &self.owner
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    SpawnSuspended,
    SpawnAsCaller,
    ProcessIdentity,
    ProcessTable,
    PeerIdentity,
    SecureDataDir,
    ExitCode,
}
impl Capability {
    /// Stable machine-readable capability name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpawnSuspended => "spawn_suspended",
            Self::SpawnAsCaller => "spawn_as_caller",
            Self::ProcessIdentity => "process_identity",
            Self::ProcessTable => "process_table",
            Self::PeerIdentity => "peer_identity",
            Self::SecureDataDir => "secure_data_dir",
            Self::ExitCode => "exit_code",
        }
    }

    /// Chinese display name used by human-facing `aw doctor` output.
    pub const fn zh(self) -> &'static str {
        match self {
            Self::SpawnSuspended => "挂起启动",
            Self::SpawnAsCaller => "以连接方身份启动",
            Self::ProcessIdentity => "进程身份",
            Self::ProcessTable => "进程表",
            Self::PeerIdentity => "认出连接方",
            Self::SecureDataDir => "数据目录权限",
            Self::ExitCode => "退出码",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityStatus {
    Available,
    /// The primitive is compiled in, but its required runtime check has not
    /// succeeded in this daemon yet.
    Unavailable,
    NotInThisBuild,
    NotSupportedOnThisOs,
}

pub trait Platform: Send + Sync {
    fn os(&self) -> &'static str;
    /// Existing root of the OS process tree used by the daemon-wide sampler.
    /// This is not a universal numeric constant: Windows has no pid 1.
    fn host_anchor_pid(&self) -> u32;
    fn capability(&self, capability: Capability) -> CapabilityStatus;
    fn spawn_suspended(
        &self,
        caller: &IdentifiedCaller,
        request: &SpawnRequest,
    ) -> Result<Box<dyn HeldChild>, PlatformError>;
    fn process_identity(&self, pid: u32) -> Result<Option<ProcessEntry>, PlatformError>;
    fn process_table(&self) -> Result<Vec<ProcessEntry>, PlatformError>;
    fn sampling_process(&self, pid: u32) -> Result<Option<SamplingProcess>, PlatformError>;
    fn sampling_process_table(&self) -> Result<Vec<SamplingProcess>, PlatformError>;
    /// Create and secure the daemon data directory before the daemon opens
    /// any file below it. Implementations reject a pre-existing directory
    /// owned by somebody other than the account allowed for that location,
    /// and reject links/reparse points rather than following them.
    /// Returns the canonical, securely opened-and-checked directory path. The
    /// daemon must use this path for subsequent opens so a benign system alias
    /// such as macOS `/tmp` is never resolved again after hardening.
    fn secure_data_dir(&self, path: &Path) -> Result<PathBuf, PlatformError>;
    fn default_data_dir(&self) -> Result<PathBuf, PlatformError>;
    fn default_config_path(&self) -> Result<PathBuf, PlatformError>;
    fn is_privileged(&self) -> Option<bool>;
    fn current_user_id(&self) -> Option<String>;
    fn current_owner(&self) -> Result<Owner, PlatformError>;
}
#[must_use]
pub fn platform() -> &'static dyn Platform {
    static CURRENT: CurrentPlatform = CurrentPlatform;
    &CURRENT
}

#[cfg(unix)]
pub fn identify_unix_peer(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerIdentity, PlatformError> {
    identify_peer(stream)
}
#[cfg(target_os = "linux")]
fn identify_peer(stream: &std::os::unix::net::UnixStream) -> Result<PeerIdentity, PlatformError> {
    linux::identify_unix_peer(stream)
}
#[cfg(target_os = "macos")]
fn identify_peer(stream: &std::os::unix::net::UnixStream) -> Result<PeerIdentity, PlatformError> {
    macos::identify_unix_peer(stream)
}
#[cfg(windows)]
pub fn identify_pipe_peer(
    handle: std::os::windows::io::RawHandle,
) -> Result<PeerIdentity, PlatformError> {
    windows::identify_pipe_peer(handle)
}

/// Refuse a Windows named-pipe server unless its pipe-object owner follows
/// the installed-service rule. When `AgentWatch` is installed, only
/// LocalSystem is accepted; without that service, a same-user development
/// daemon is also accepted.
#[cfg(windows)]
pub fn verify_pipe_server(
    handle: std::os::windows::io::RawHandle,
) -> Result<(), PipeServerVerificationError> {
    windows::verify_pipe_server(handle)
}

/// Testable form of [`verify_pipe_server`] with an injected SCM observation.
/// Product callers use [`verify_pipe_server`], whose observation comes from
/// the local SCM. This hook keeps the same production decision path testable
/// without installing a service.
#[cfg(windows)]
#[doc(hidden)]
pub fn verify_pipe_server_with_service_status(
    handle: std::os::windows::io::RawHandle,
    service_status: &PipeServiceStatus,
) -> Result<(), PipeServerVerificationError> {
    windows::verify_pipe_server_with_service_status(handle, service_status)
}

/// Testable owner-allowlist form retained for the existing reverse tests.
/// Product callers must use [`verify_pipe_server`] or the service-status hook.
#[cfg(windows)]
#[doc(hidden)]
pub fn verify_pipe_server_for_owners(
    handle: std::os::windows::io::RawHandle,
    trusted_owners: &[&str],
) -> Result<(), PipeServerVerificationError> {
    windows::verify_pipe_server_for_owners(handle, trusted_owners)
}

/// Record that a complete Windows named-pipe request made the round trip after
/// the peer checks. `aw doctor` uses this runtime fact rather than advertising
/// peer identification merely because this build contains the API.
#[cfg(windows)]
pub fn note_pipe_peer_identification() {
    windows::note_pipe_peer_identification();
}

/// Build the minimal environment for a program launched by the Windows daemon.
///
/// On Windows this is built from the current account's profile, not from the
/// daemon process environment. Other systems have their own account-environment
/// builders, so asking for the Windows form is explicit unsupported there.
#[cfg(windows)]
pub fn account_base_env() -> Result<Vec<(String, String)>, PlatformError> {
    windows::account_base_env()
}

/// Windows account-profile environments are not available on this OS.
#[cfg(not(windows))]
pub fn account_base_env() -> Result<Vec<(String, String)>, PlatformError> {
    Err(PlatformError::Unsupported {
        capability: "account_base_env",
        os: std::env::consts::OS,
        kind: UnsupportedKind::NotSupportedOnThisOs,
    })
}

/// Whether a caller may replace a base environment variable.
///
/// Unix names are case-sensitive, while Windows names are not. Keeping that
/// choice with the platform avoids a target-OS branch in shared launch code.
#[must_use]
pub fn is_reserved_env_name(name: &str, case_insensitive: bool) -> bool {
    const RESERVED: [&str; 5] = ["HOME", "USER", "LOGNAME", "SHELL", "PATH"];

    RESERVED.iter().any(|reserved| {
        if case_insensitive {
            name.eq_ignore_ascii_case(reserved)
        } else {
            name == *reserved
        }
    })
}

/// Windows environment names are case-insensitive, including the reserved
/// names that requests may not replace.
#[cfg(windows)]
#[must_use]
pub fn windows_reserved_env_name(name: &str) -> bool {
    windows::windows_reserved_env_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsupported_words() {
        assert_eq!(
            UnsupportedKind::NotInThisBuild.as_str(),
            "not_in_this_build"
        );
        assert_eq!(UnsupportedKind::NotSupportedOnThisOs.zh(), "这个系统不支持");
    }

    #[test]
    fn capability_names_are_stable() {
        assert_eq!(Capability::SpawnSuspended.as_str(), "spawn_suspended");
        assert_eq!(Capability::SpawnAsCaller.as_str(), "spawn_as_caller");
        assert_eq!(Capability::SpawnAsCaller.zh(), "以连接方身份启动");
        assert_eq!(Capability::ExitCode.zh(), "退出码");
    }

    #[test]
    fn reserved_environment_names_follow_the_platform_case_rule() {
        for name in ["Path", "path", "PATH", "Home"] {
            assert!(is_reserved_env_name(name, true), "{name} must be reserved");
        }
        for name in ["LANG", "TZ", "LC_ALL"] {
            assert!(!is_reserved_env_name(name, true), "{name} is not reserved");
        }
        assert!(is_reserved_env_name("PATH", false));
        assert!(!is_reserved_env_name("Path", false));
    }

    #[cfg(not(windows))]
    #[test]
    fn windows_account_environment_is_explicitly_unsupported_off_windows() {
        assert!(matches!(
            account_base_env(),
            Err(PlatformError::Unsupported {
                capability: "account_base_env",
                kind: UnsupportedKind::NotSupportedOnThisOs,
                ..
            })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reports_spawn_as_caller_available() {
        assert_eq!(
            platform().capability(Capability::SpawnAsCaller),
            CapabilityStatus::Available
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_peer_identity_reports_current_uid() -> Result<(), PlatformError> {
        use std::os::unix::net::UnixStream;

        let (server, _client) = UnixStream::pair()?;
        let peer = identify_unix_peer(&server)?;
        let Owner::Unix { euid, .. } = peer.owner() else {
            return Err(PlatformError::PeerNotIdentified {
                reason: "Unix stream peer did not have a Unix owner",
            });
        };
        assert_eq!(*euid, nix::unistd::geteuid().as_raw());
        Ok(())
    }
}
