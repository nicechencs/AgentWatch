use crate::{
    IdentifiedCaller, Platform, PlatformError, ProcessEntry, ProcessKey, ReapOutcome, SpawnRequest,
    UnsupportedKind,
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
impl Platform for CurrentPlatform {
    fn os(&self) -> &'static str {
        "macos"
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
    fn reap_child(&self, _: ProcessKey) -> Result<ReapOutcome, PlatformError> {
        Err(no("reap_child"))
    }
    fn secure_data_dir(&self, p: &Path) -> Result<(), PlatformError> {
        std::fs::create_dir_all(p).map_err(Into::into)
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
}
