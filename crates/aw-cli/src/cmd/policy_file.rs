//! Where an intercept policy is read from (P5-SEC-01).
//!
//! Order:
//!
//! 1. `AW_POLICY`, when set to a non-empty path. A missing file is "off",
//!    not an error: the operator can point at a file they have not written yet.
//! 2. Otherwise the per-user file, never the daemon's system config
//!    (`/etc/agentwatch/config.toml` is not a policy, and a project file would
//!    be writable by the agent). The path is:
//!    - `$XDG_CONFIG_HOME/agentwatch/policy.toml` on Unix, or
//!      `~/.config/agentwatch/policy.toml` when `XDG_CONFIG_HOME` is unset;
//!    - `%APPDATA%\agentwatch\policy.toml` on Windows.
//!
//! A file that exists but is not a policy is [`PolicyLoad::Broken`]. Callers
//! apply `on_error` only when they already know the operator turned intercept
//! on; a broken file has no readable `on_error`, so the default is deny
//! (design §5.3). [`PolicyLoad::Off`] keeps today's behaviour.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use aw_pipeline::{load_str, Policy, PolicyState};

/// `AW_POLICY`. A path, not the document.
pub const POLICY_ENV: &str = "AW_POLICY";

/// Process-wide lock for tests that set or clear [`POLICY_ENV`].
///
/// The variable is process-global. `aw hook` and `aw run` tests run in the same
/// binary, so each module's own mutex still lets them overwrite each other.
#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    match LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Restores one environment variable when dropped, including on panic.
#[cfg(test)]
pub(crate) struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

#[cfg(test)]
impl EnvVarGuard {
    /// Remember the current value, then set `key` to `value`.
    pub(crate) fn set(key: &'static str, value: &std::path::Path) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }

    /// Replace the live value. Drop still restores what [`Self::set`] saved.
    pub(crate) fn replace(&self, value: &std::path::Path) {
        std::env::set_var(self.key, value);
    }

    /// Remember the current value, then set `key` to a string.
    pub(crate) fn set_text(key: &'static str, value: &std::path::Path) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }

    /// Remember the current value, then remove `key`.
    pub(crate) fn unset(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, previous }
    }
}

/// Point `XDG_CONFIG_HOME`, `HOME`, and `APPDATA` at an empty directory for the
/// guard's lifetime, then put them back.
///
/// `AW_POLICY` unset makes [`load_policy`] read the per-user file. A developer
/// machine that already has one would decide the test. The directory is created
/// under the crate, not in `/tmp`.
#[cfg(test)]
pub(crate) struct HomeEnvGuard {
    dir: PathBuf,
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

#[cfg(test)]
impl HomeEnvGuard {
    /// Isolate the three homes. Drop restores each one, including after a panic.
    pub(crate) fn isolate() -> Self {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("policy-home")
            .join(format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("policy home");
        let saved = ["XDG_CONFIG_HOME", "HOME", "APPDATA"]
            .into_iter()
            .map(|key| {
                let previous = std::env::var_os(key);
                std::env::set_var(key, &dir);
                (key, previous)
            })
            .collect();
        Self { dir, saved }
    }
}

#[cfg(test)]
impl Drop for HomeEnvGuard {
    fn drop(&mut self) {
        for (key, previous) in self.saved.drain(..) {
            match previous {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

/// What the hook, mcp-tap, and the proxy should do with the file.
#[derive(Debug)]
pub(crate) enum PolicyLoad {
    /// No file, or `enabled` is false / absent. Do not intercept.
    Off,
    /// Rules are in force.
    On(Policy),
    /// The file exists and is not a policy. Default `on_error` is deny.
    /// The parse error is not kept: displaying it can quote a command the
    /// operator put in the file.
    Broken,
}

/// Read the policy. `env` is `AW_POLICY` already fetched by the caller, so
/// tests do not touch the process environment. `home` is the user home, used
/// only when `XDG_CONFIG_HOME` / `APPDATA` are absent.
pub(crate) fn load_policy(env_path: Option<&Path>, config_home: Option<&Path>) -> PolicyLoad {
    let path = match env_path {
        Some(path) => path.to_path_buf(),
        None => match default_policy_path(config_home) {
            Some(path) => path,
            None => return PolicyLoad::Off,
        },
    };
    match fs::read_to_string(&path) {
        Ok(text) => match load_str(&text) {
            Ok(PolicyState::Off) => PolicyLoad::Off,
            Ok(PolicyState::On(policy)) => PolicyLoad::On(policy),
            Err(_) => PolicyLoad::Broken,
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound => PolicyLoad::Off,
        // Unreadable is not "off": the operator pointed at a file and we
        // could not see whether it enables intercept. Treat it as broken so
        // an enabled-looking failure denies rather than silently allowing.
        Err(_) => PolicyLoad::Broken,
    }
}

/// Per-user policy path. `None` when this process has no config home and no
/// home directory to fall back on.
pub(crate) fn default_policy_path(config_home: Option<&Path>) -> Option<PathBuf> {
    let home = config_home?;
    Some(home.join("agentwatch").join("policy.toml"))
}

/// `XDG_CONFIG_HOME`, else `$HOME/.config`. Windows uses `APPDATA`.
///
/// An empty variable is treated as unset. This does not create the directory.
pub(crate) fn user_config_home() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return Some(PathBuf::from(xdg));
            }
        }
        std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(|home| PathBuf::from(home).join(".config"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aw-policy-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_is_off_and_enabled_file_is_on() {
        let dir = scratch("missing");
        let path = dir.join("nope.toml");
        assert!(matches!(load_policy(Some(&path), None), PolicyLoad::Off));
        let policy = dir.join("policy.toml");
        let mut file = fs::File::create(&policy).unwrap();
        writeln!(
            file,
            "enabled = true\n[[rule]]\nid = \"a\"\naction = \"deny\"\nlayer = [\"hook\"]\n"
        )
        .unwrap();
        assert!(matches!(
            load_policy(Some(&policy), None),
            PolicyLoad::On(_)
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_file_is_off_and_garbage_is_broken() {
        let dir = scratch("off");
        let policy = dir.join("policy.toml");
        fs::write(&policy, "enabled = false\n").unwrap();
        assert!(matches!(load_policy(Some(&policy), None), PolicyLoad::Off));
        fs::write(&policy, "enabled = true\n[[rule]]\naction = \"nope\"\n").unwrap();
        assert!(matches!(
            load_policy(Some(&policy), None),
            PolicyLoad::Broken
        ));
        let _ = fs::remove_dir_all(&dir);
    }
}
