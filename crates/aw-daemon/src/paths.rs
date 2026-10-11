//! Platform data and config paths.
//!
//! `cfg(target_os)` is allowed only in this module. Business logic must call
//! [`default_data_dir`] / [`default_config_path`] and must not branch on the OS.
//!
//! The task card names these data directories (no extra `data/` segment):
//! Linux `/var/lib/agentwatch`, macOS `/Library/Application Support/AgentWatch`,
//! Windows `%ProgramData%\AgentWatch`. architecture.md §7 puts Windows and macOS
//! data under a `data` subdirectory of the same root. This card follows the
//! task card. Config files still live where §7 says they do.
//!
//! Creating a directory that fails is an error. There is no fallback to the
//! user home directory. This module never creates the three system directories
//! by itself; callers pass a configured path (tests and `--foreground` use a
//! temp directory via `storage.data_dir`).

use std::io;
use std::path::{Path, PathBuf};

/// Default daemon data directory for this platform.
///
/// # Errors
///
/// On Windows, returns an error when `ProgramData` is unset. It does not invent
/// a path under the user profile.
pub fn default_data_dir() -> io::Result<PathBuf> {
    aw_platform::platform()
        .default_data_dir()
        .map_err(platform_error)
}

/// Default daemon config file for this platform (§7 locations).
///
/// # Errors
///
/// On Windows, returns an error when `ProgramData` is unset.
pub fn default_config_path() -> io::Result<PathBuf> {
    aw_platform::platform()
        .default_config_path()
        .map_err(platform_error)
}

/// Create `dir` (and parents). Failure is returned as-is; nothing is written elsewhere.
///
/// # Errors
///
/// Returns the `create_dir_all` error. Does not fall back to another directory.
pub fn ensure_data_dir(dir: &Path) -> io::Result<()> {
    aw_platform::platform()
        .secure_data_dir(dir)
        .map_err(platform_error)
}

fn platform_error(error: aw_platform::PlatformError) -> io::Error {
    match error {
        aw_platform::PlatformError::Io(error) => error,
        aw_platform::PlatformError::Unsupported { .. } => {
            io::Error::new(io::ErrorKind::Unsupported, error)
        }
        aw_platform::PlatformError::Invalid { .. } => {
            io::Error::new(io::ErrorKind::InvalidInput, error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ensure_data_dir;

    #[test]
    fn ensure_data_dir_creates_a_temp_tree() -> std::io::Result<()> {
        let nanos = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_nanos(),
            Err(_) => 0,
        };
        let dir =
            std::env::temp_dir().join(format!("agentwatchd-paths-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let nested = dir.join("nested");
        ensure_data_dir(&nested)?;
        let created = nested.is_dir();
        let _ = std::fs::remove_dir_all(&dir);
        if created {
            Ok(())
        } else {
            Err(std::io::Error::other("temp data dir was not created"))
        }
    }
}
