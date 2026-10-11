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
/// On Windows, returns an error when the ProgramData known folder cannot be
/// read. It does not read the `ProgramData` environment variable and does not
/// invent a path under the user profile.
pub fn default_data_dir() -> io::Result<PathBuf> {
    aw_platform::platform()
        .default_data_dir()
        .map_err(platform_error)
}

/// Default daemon config file for this platform (§7 locations).
///
/// # Errors
///
/// On Windows, returns an error when the ProgramData known folder cannot be read.
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
pub fn ensure_data_dir(dir: &Path) -> io::Result<PathBuf> {
    aw_platform::platform()
        .secure_data_dir(dir)
        .map_err(|error| secure_data_dir_error(dir, error))
}

fn secure_data_dir_error(dir: &Path, error: aw_platform::PlatformError) -> io::Error {
    // The platform error preserves diagnostic detail, but a daemon's terminal
    // must only show one of the reviewed Chinese explanations. In particular,
    // do not print errno text here: it is platform-dependent and often English.
    let message = match error {
        aw_platform::PlatformError::Invalid { detail, .. }
            if detail.contains("symlink") || detail.contains("reparse point") =>
        {
            format!(
                "数据目录「{}」是一个链接，后台不会顺着链接写数据，所以没有启动。请换成普通目录后再启动后台。",
                dir.display()
            )
        }
        aw_platform::PlatformError::Invalid {
            detail: "official data directory requires a privileged daemon",
            ..
        } => format!(
            "正式数据目录「{}」只能由管理员运行的后台使用。请用管理员运行后台，或者换一个自己的目录。",
            dir.display()
        ),
        aw_platform::PlatformError::Invalid { detail, .. }
            if detail.contains("writable by other users") || detail.contains("owner-only") =>
        {
            format!(
                "数据目录「{}」别的用户也能写，后台没有启动。请把权限改成只有你自己能写，或者换一个目录。",
                dir.display()
            )
        }
        aw_platform::PlatformError::Io(_) => format!(
            "数据目录「{}」的权限改不过来，后台没有启动。原因：系统拒绝了这次操作。请删掉这个目录后再启动后台。",
            dir.display()
        ),
        _ => format!(
            "数据目录「{}」不归管理员所有，可能被别人改过。为防万一，后台没有启动。请删掉这个目录后再启动后台。",
            dir.display()
        ),
    };
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn platform_error(error: aw_platform::PlatformError) -> io::Error {
    match error {
        aw_platform::PlatformError::Io(error) => error,
        aw_platform::PlatformError::Unsupported { .. } => {
            io::Error::new(io::ErrorKind::Unsupported, error)
        }
        aw_platform::PlatformError::Invalid { .. }
        | aw_platform::PlatformError::PeerNotIdentified { .. }
        | aw_platform::PlatformError::PipePeerNotIdentified { .. }
        | aw_platform::PlatformError::UnsafeBatchArgument { .. }
        | aw_platform::PlatformError::Spawn(_) => {
            io::Error::new(io::ErrorKind::InvalidInput, error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ensure_data_dir, secure_data_dir_error};
    use std::path::Path;

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
        let expected = format!(
            "数据目录「{}」是一个链接，后台不会顺着链接写数据，所以没有启动。请换成普通目录后再启动后台。",
            link.display()
        );
        let _ = std::fs::remove_dir_all(&root);
        if error.kind() == std::io::ErrorKind::PermissionDenied && error.to_string() == expected {
            Ok(())
        } else {
            Err(error)
        }
    }

    #[test]
    fn secure_data_dir_errors_use_the_reviewed_templates() {
        let path = Path::new("/example/data");
        let cases = [
            (
                aw_platform::PlatformError::Invalid {
                    capability: "secure_data_dir",
                    detail: "data directory path contains a symlink",
                },
                "数据目录「/example/data」是一个链接，后台不会顺着链接写数据，所以没有启动。请换成普通目录后再启动后台。",
            ),
            (
                aw_platform::PlatformError::Invalid {
                    capability: "secure_data_dir",
                    detail: "official data directory requires a privileged daemon",
                },
                "正式数据目录「/example/data」只能由管理员运行的后台使用。请用管理员运行后台，或者换一个自己的目录。",
            ),
            (
                aw_platform::PlatformError::Invalid {
                    capability: "secure_data_dir",
                    detail: "data directory ancestor is writable by other users",
                },
                "数据目录「/example/data」别的用户也能写，后台没有启动。请把权限改成只有你自己能写，或者换一个目录。",
            ),
            (
                aw_platform::PlatformError::Io(std::io::Error::from_raw_os_error(13)),
                "数据目录「/example/data」的权限改不过来，后台没有启动。原因：系统拒绝了这次操作。请删掉这个目录后再启动后台。",
            ),
            (
                aw_platform::PlatformError::Invalid {
                    capability: "secure_data_dir",
                    detail: "data directory owner is not the daemon user",
                },
                "数据目录「/example/data」不归管理员所有，可能被别人改过。为防万一，后台没有启动。请删掉这个目录后再启动后台。",
            ),
        ];
        for (platform_error, expected) in cases {
            assert_eq!(
                secure_data_dir_error(path, platform_error).to_string(),
                expected
            );
        }
    }
}
