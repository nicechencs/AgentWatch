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
    /// Never convert a missing OS credential into a daemon/default identity.
    PeerNotIdentified {
        reason: &'static str,
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
            Self::PeerNotIdentified { reason } => write!(f, "peer was not identified: {reason}"),
            Self::Io(error) => write!(f, "platform I/O error: {error}"),
            Self::Invalid { capability, detail } => write!(f, "{capability}: {detail}"),
        }
    }
}
impl std::error::Error for PlatformError {}
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
        groups: Vec<u32>,
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
    ProcessIdentity,
    ProcessTable,
    PeerIdentity,
    SecureDataDir,
    ExitCode,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityStatus {
    Available,
    NotInThisBuild,
    NotSupportedOnThisOs,
}

pub trait Platform: Send + Sync {
    fn os(&self) -> &'static str;
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
    fn secure_data_dir(&self, path: &Path) -> Result<(), PlatformError>;
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
}
