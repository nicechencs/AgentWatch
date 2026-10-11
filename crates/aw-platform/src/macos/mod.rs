use crate::{
    Capability, CapabilityStatus, IdentifiedCaller, Owner, PeerIdentity, Platform, PlatformError,
    ProcessEntry, SamplingProcess, SpawnRequest, UnsupportedKind,
};
use std::path::{Path, PathBuf};
pub(crate) struct CurrentPlatform;
fn no(capability: &'static str) -> PlatformError {
    PlatformError::Unsupported {
        capability,
        os: "macos",
        kind: UnsupportedKind::NotInThisBuild,
    }
}
pub fn identify_unix_peer(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerIdentity, PlatformError> {
    let (uid, gid) =
        nix::unistd::getpeereid(stream).map_err(|_| PlatformError::PeerNotIdentified {
            reason: "getpeereid unavailable",
        })?;
    // LOCAL_PEERPID is not available on every socket configuration. The uid
    // and gid above are enough to authenticate the caller, so preserve that
    // identity when the optional pid cannot be obtained. Darwin's peer API
    // does not provide supplementary groups; represent that absence as none.
    let pid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerPid)
        .ok()
        .and_then(|pid| u32::try_from(pid).ok());
    let uid = uid.as_raw();
    let gid = gid.as_raw();
    Ok(PeerIdentity::new(
        Owner::Unix {
            ruid: uid,
            euid: uid,
            suid: uid,
            rgid: gid,
            egid: gid,
            sgid: gid,
            // getpeereid/LOCAL_PEERPID cannot report supplementary groups.
            groups: None,
        },
        pid,
    ))
}
impl Platform for CurrentPlatform {
    fn os(&self) -> &'static str {
        "macos"
    }
    fn capability(&self, capability: Capability) -> CapabilityStatus {
        match capability {
            Capability::SpawnSuspended
            | Capability::SpawnAsCaller
            | Capability::ProcessIdentity
            | Capability::ProcessTable
            | Capability::PeerIdentity
            | Capability::ExitCode
            | Capability::SecureDataDir => CapabilityStatus::NotInThisBuild,
        }
    }
    fn spawn_suspended(
        &self,
        _: &IdentifiedCaller,
        _: &SpawnRequest,
    ) -> Result<Box<dyn crate::HeldChild>, PlatformError> {
        Err(no("spawn_suspended"))
    }
    fn process_identity(&self, _: u32) -> Result<Option<ProcessEntry>, PlatformError> {
        Err(no("process_identity"))
    }
    fn process_table(&self) -> Result<Vec<ProcessEntry>, PlatformError> {
        Err(no("process_table"))
    }
    fn sampling_process(&self, _: u32) -> Result<Option<SamplingProcess>, PlatformError> {
        Err(no("sampling_process"))
    }
    fn sampling_process_table(&self) -> Result<Vec<SamplingProcess>, PlatformError> {
        Err(no("sampling_process_table"))
    }
    fn secure_data_dir(&self, _: &Path) -> Result<(), PlatformError> {
        Err(no("secure_data_dir"))
    }
    fn default_data_dir(&self) -> Result<PathBuf, PlatformError> {
        Ok(PathBuf::from("/Library/Application Support/AgentWatch"))
    }
    fn default_config_path(&self) -> Result<PathBuf, PlatformError> {
        Ok(PathBuf::from(
            "/Library/Application Support/AgentWatch/config.toml",
        ))
    }
    fn is_privileged(&self) -> Option<bool> {
        aw_collector_macos::privilege::is_privileged()
    }
    fn current_user_id(&self) -> Option<String> {
        None
    }
    fn current_owner(&self) -> Result<Owner, PlatformError> {
        Err(no("current_owner"))
    }
}
