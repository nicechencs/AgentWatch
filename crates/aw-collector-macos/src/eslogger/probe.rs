//! Why a capability probe refused to start eslogger.
//!
//! The task's `probe()` checks three facts: macOS ≥ 13, the process is root,
//! and Full Disk Access is granted. This host cannot run eslogger, so the
//! checks that need a live system stay as error variants. Callers on macOS
//! construct them; tests construct them without launching anything.
//!
//! TCC detection itself (start eslogger and see if it exits at once with a
//! TCC error) is a macOS-only step and is not implemented in this module.

use std::fmt;

/// Probe failed before any event was read.
///
/// Display text names the check and a next step. It must not contain argv,
/// a user name, a host name, or a path under a home directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// Darwin major version is below 13. eslogger is not on this OS.
    UnsupportedOs {
        /// `None` when the version could not be read. That is not "version 0".
        major: Option<u32>,
    },
    /// The collector is not running as root. eslogger requires it.
    NotRoot,
    /// eslogger exited immediately with a TCC / Full Disk Access refusal.
    ///
    /// `hint` is a fixed sentence pointing at System Settings. It is not the
    /// raw stderr: eslogger's text can echo paths.
    FullDiskAccessDenied {
        /// Operator-facing hint. No secrets.
        hint: String,
    },
    /// The `eslogger` binary is not at `/usr/bin/eslogger`.
    BinaryMissing,
    /// eslogger was started and then left. The collector must emit `Gap{restart}`
    /// and back off; this error is the reason, not a dropped event.
    Exited {
        /// Process status if the platform reported one. `None` if it did not.
        status: Option<i32>,
    },
}

impl ProbeError {
    /// Fixed hint for a TCC refusal. Kept here so every caller says the same thing.
    pub const FULL_DISK_HINT: &'static str =
        "grant Full Disk Access to the agentwatch daemon in System Settings, then retry";

    /// TCC refusal with the fixed hint.
    pub fn full_disk_access_denied() -> Self {
        Self::FullDiskAccessDenied {
            hint: Self::FULL_DISK_HINT.to_owned(),
        }
    }
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedOs { major: Some(major) } => {
                write!(
                    f,
                    "eslogger needs macOS 13 or newer; this system reports {major}"
                )
            }
            Self::UnsupportedOs { major: None } => {
                f.write_str("eslogger needs macOS 13 or newer; the OS version could not be read")
            }
            Self::NotRoot => f.write_str("eslogger requires root; the collector is not root"),
            Self::FullDiskAccessDenied { hint } => {
                write!(f, "eslogger was refused by TCC (Full Disk Access): {hint}")
            }
            Self::BinaryMissing => f.write_str("eslogger was not found at /usr/bin/eslogger"),
            Self::Exited {
                status: Some(status),
            } => {
                write!(
                    f,
                    "eslogger exited (status {status}); a restart gap is required"
                )
            }
            Self::Exited { status: None } => {
                f.write_str("eslogger exited (status unavailable); a restart gap is required")
            }
        }
    }
}

impl std::error::Error for ProbeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcc_hint_does_not_carry_a_path_or_a_user() {
        let err = ProbeError::full_disk_access_denied();
        let text = err.to_string();
        assert!(text.contains("Full Disk Access"));
        assert!(!text.contains('/'));
        assert!(!text.contains("home"));
    }

    #[test]
    fn unknown_os_version_is_not_reported_as_zero() {
        let text = ProbeError::UnsupportedOs { major: None }.to_string();
        assert!(text.contains("could not be read"));
        assert!(!text.contains("reports 0"));
    }
}
