//! Resolve scenario paths strictly inside the temp root.
//!
//! A step that says `home/.ssh/id_rsa` is a bait file under `$SIM_ROOT`, never
//! the real user home. Absolute paths and `..` escapes are rejected.

use std::path::{Component, Path, PathBuf};

#[derive(Debug)]
pub struct PathError {
    pub path: String,
    pub reason: &'static str,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refusing path `{}`: {} (only relative paths under the sim temp root are allowed)",
            self.path, self.reason
        )
    }
}

impl std::error::Error for PathError {}

/// Join `rel` onto `root` after rejecting absolute paths and parent escapes.
pub fn under_root(root: &Path, rel: &str) -> Result<PathBuf, PathError> {
    let raw = Path::new(rel);
    if raw.is_absolute() {
        return Err(PathError {
            path: rel.to_string(),
            reason: "absolute path",
        });
    }
    if rel.contains('~') {
        return Err(PathError {
            path: rel.to_string(),
            reason: "tilde is not expanded; bait files stay under the temp root",
        });
    }
    let mut out = root.to_path_buf();
    for comp in raw.components() {
        match comp {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(PathError {
                    path: rel.to_string(),
                    reason: "`..` would leave the temp root",
                });
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(PathError {
                    path: rel.to_string(),
                    reason: "absolute path",
                });
            }
        }
    }
    if !out.starts_with(root) {
        return Err(PathError {
            path: rel.to_string(),
            reason: "resolved path is outside the temp root",
        });
    }
    Ok(out)
}

/// Fill `size` bytes with a recognizable, non-secret pattern.
pub fn bait_bytes(size: u64) -> Vec<u8> {
    const MARK: &[u8] = b"SIMBAIT-not-a-secret-";
    let size = usize::try_from(size).unwrap_or(usize::MAX);
    let mut buf = Vec::with_capacity(size);
    while buf.len() < size {
        let n = (size - buf.len()).min(MARK.len());
        buf.extend_from_slice(&MARK[..n]);
    }
    buf
}
