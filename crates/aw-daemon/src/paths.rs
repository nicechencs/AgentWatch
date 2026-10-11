//! Platform data and config paths.
//!
//! `cfg(target_os)` is allowed only in this module. Business logic must call
//! [`default_data_dir`] / [`default_config_path`] and must not branch on the OS.
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

/// Create and secure `dir` (and parents) before anything is written below it.
///
/// # Errors
///
/// Returns the platform permission/ownership error. Does not fall back to
/// another directory and never follows a symlink/reparse point.
pub fn ensure_data_dir(dir: &Path) -> io::Result<()> {
    aw_platform::platform()
        .secure_data_dir(dir)
        .map_err(|error| secure_data_dir_error(dir, error))
}

fn secure_data_dir_error(dir: &Path, error: aw_platform::PlatformError) -> io::Error {
    if matches!(
        error,
        aw_platform::PlatformError::Invalid {
            capability: "secure_data_dir",
            detail: "data directory owner is not trusted"
                | "data directory owner is not the daemon user"
                | "data directory owner changed while it was being secured",
        }
    ) {
        let message = format!(
            "数据目录「{}」不归管理员所有，可能被别人改过。为防万一，后台没有启动。请删掉这个目录后再启动后台。",
            dir.display()
        );
        return io::Error::new(io::ErrorKind::PermissionDenied, message);
    }
    platform_error(error)
}

fn platform_error(error: aw_platform::PlatformError) -> io::Error {
    match error {
        aw_platform::PlatformError::Io(error) => error,
        aw_platform::PlatformError::Unsupported { .. } => {
            io::Error::new(io::ErrorKind::Unsupported, error)
        }
        aw_platform::PlatformError::Invalid { .. }
        | aw_platform::PlatformError::PeerNotIdentified { .. }
        | aw_platform::PlatformError::PipePeerNotIdentified { .. } => {
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

    #[cfg(unix)]
    #[test]
    fn ensure_data_dir_rejects_a_symlink() -> std::io::Result<()> {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "agentwatchd-paths-link-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let target = root.join("target");
        let link = root.join("link");
        std::fs::create_dir_all(&target)?;
        symlink(&target, &link)?;
        let Err(error) = ensure_data_dir(&link) else {
            return Err(std::io::Error::other("a data-dir symlink must be refused"));
        };
        let _ = std::fs::remove_dir_all(&root);
        if error.kind() == std::io::ErrorKind::InvalidInput {
            Ok(())
        } else {
            Err(error)
        }
    }
}
