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
    _: &std::os::unix::net::UnixStream,
) -> Result<PeerIdentity, PlatformError> {
    Err(no("peer_identity"))
}
impl Platform for CurrentPlatform {
    fn os(&self) -> &'static str {
        "macos"
    }
    fn capability(&self, capability: Capability) -> CapabilityStatus {
        match capability {
            Capability::SpawnSuspended
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
