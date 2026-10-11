//! Explicit operating-system boundary for AgentWatch shared code.
#![forbid(unsafe_code)]
use std::fmt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "linux")]
use linux::CurrentPlatform;
#[cfg(target_os = "macos")]
use macos::CurrentPlatform;
#[cfg(target_os = "windows")]
use windows::CurrentPlatform;

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
#[derive(Debug)]
pub enum PlatformError {
    Unsupported {
        capability: &'static str,
        os: &'static str,
        kind: UnsupportedKind,
    },
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
            Self::Io(e) => write!(f, "platform I/O error: {e}"),
            Self::Invalid { capability, detail } => write!(f, "{capability}: {detail}"),
        }
    }
}
impl std::error::Error for PlatformError {}
impl From<std::io::Error> for PlatformError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
/// PID and start time prevent PID reuse. Linux: `/proc/<pid>/stat` field 22 ticks; macOS: `proc_pidinfo(PROC_PIDTBSDINFO)` / `sysctl(KERN_PROC)`; Windows: `GetProcessTimes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessKey {
    pub pid: u32,
    pub start_time: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    Unix {
        ruid: u32,
        euid: u32,
        suid: u32,
        groups: Vec<u32>,
    },
    Windows {
        sid: String,
        elevated: bool,
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
/// Process facts needed to form the poll collector's stable identity.
///
/// `start_ns` is a wall-clock timestamp when the OS can provide one.  It is
/// deliberately separate from [`ProcessKey::start_time`], whose unit is
/// native to the OS (Linux clock ticks, Windows FILETIME, and so on).
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
}
impl fmt::Debug for SpawnRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpawnRequest")
            .field("command_len", &self.command.len())
            .field("has_cwd", &self.cwd.is_some())
            .field("env_len", &self.env.len())
            .finish()
    }
}
/// HELD: daemon death also kills the target (Linux gate EOF/PDEATHSIG; Windows suspended Job `KILL_ON_JOB_CLOSE`; macOS `POSIX_SPAWN_START_SUSPENDED` watchdog). RELEASED: target survives daemon restart. `abort`/Drop before release kill and reap.
pub trait HeldChild: Send {
    fn pid(&self) -> u32;
    fn release(&mut self) -> Result<(), PlatformError>;
    fn abort(&mut self) -> Result<(), PlatformError>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapOutcome {
    Exited(i32),
    Signaled(i32),
    StillRunning,
    NotOurChild,
}
/// Transport identity comes from Linux `SO_PEERCRED`, macOS `getpeereid` plus `LOCAL_PEERPID`, or Windows `GetNamedPipeClientProcessId` plus client token. Windows pipes require `PIPE_REJECT_REMOTE_CLIENTS` and an explicit DACL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdentity {
    Identified { owner: Owner, pid: Option<u32> },
    NotIdentified { reason: &'static str },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifiedCaller {
    owner: Owner,
}
impl IdentifiedCaller {
    pub fn from_peer(peer: PeerIdentity) -> Result<Self, PlatformError> {
        match peer {
            PeerIdentity::Identified { owner, .. } => Ok(Self { owner }),
            PeerIdentity::NotIdentified { .. } => Err(PlatformError::Invalid {
                capability: "caller_identity",
                detail: "caller was not identified",
            }),
        }
    }
    #[allow(dead_code)]
    pub(crate) fn owner(&self) -> &Owner {
        &self.owner
    }
}
pub trait Platform: Send + Sync {
    fn os(&self) -> &'static str;
    fn spawn_suspended(
        &self,
        caller: &IdentifiedCaller,
        request: &SpawnRequest,
    ) -> Result<Box<dyn HeldChild>, PlatformError>;
    fn process_identity(&self, pid: u32) -> Result<Option<ProcessEntry>, PlatformError>;
    fn process_table(&self) -> Result<Vec<ProcessEntry>, PlatformError>;
    /// Facts used by the platform-independent poll sampler to make a stable
    /// process identity.  Unsupported systems return an explicit error rather
    /// than an empty table.
    fn sampling_process(&self, pid: u32) -> Result<Option<SamplingProcess>, PlatformError>;
    fn sampling_process_table(&self) -> Result<Vec<SamplingProcess>, PlatformError>;
    /// Used by stop-recording and sampler disappearance handling; Windows waits, uses `GetExitCodeProcess`, and closes its handle.
    fn reap_child(&self, key: ProcessKey) -> Result<ReapOutcome, PlatformError>;
    fn secure_data_dir(&self, path: &Path) -> Result<(), PlatformError>;
    fn default_data_dir(&self) -> Result<PathBuf, PlatformError>;
    fn default_config_path(&self) -> Result<PathBuf, PlatformError>;
    fn is_privileged(&self) -> Option<bool>;
    /// Stable textual identifier for the daemon's own account, if the OS has
    /// one that can be represented without guessing.
    fn current_user_id(&self) -> Option<String>;
}
#[must_use]
pub fn platform() -> &'static dyn Platform {
    static CURRENT: CurrentPlatform = CurrentPlatform;
    &CURRENT
}
#[cfg(feature = "test-hold-delay")]
pub fn test_hold_delay() -> Option<std::time::Duration> {
    let ms = std::env::var("AW_TEST_HOLD_DELAY_MS")
        .ok()?
        .parse::<u64>()
        .ok()?;
    Some(std::time::Duration::from_millis(ms.min(10_000)))
}
#[cfg(not(feature = "test-hold-delay"))]
pub const fn test_hold_delay() -> Option<std::time::Duration> {
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_required() {
        assert!(
            IdentifiedCaller::from_peer(PeerIdentity::NotIdentified { reason: "test" }).is_err()
        )
    }
    #[test]
    fn unsupported_words() {
        assert_eq!(
            UnsupportedKind::NotInThisBuild.as_str(),
            "not_in_this_build"
        );
        assert_eq!(UnsupportedKind::NotSupportedOnThisOs.zh(), "这个系统不支持")
    }
    #[cfg(not(feature = "test-hold-delay"))]
    #[test]
    fn delay_off() {
        std::env::set_var("AW_TEST_HOLD_DELAY_MS", "1");
        assert_eq!(test_hold_delay(), None);
        std::env::remove_var("AW_TEST_HOLD_DELAY_MS");
    }
    #[cfg(feature = "test-hold-delay")]
    #[test]
    fn delay_capped() {
        std::env::set_var("AW_TEST_HOLD_DELAY_MS", "10001");
        assert_eq!(test_hold_delay(), Some(std::time::Duration::from_secs(10)));
        std::env::remove_var("AW_TEST_HOLD_DELAY_MS");
    }
}
