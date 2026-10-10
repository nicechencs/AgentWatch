//! Whether this process holds an elevated (administrator) token.
//!
//! An administrator account without UAC elevation runs at Medium integrity and
//! is not privileged here. An elevated token runs at High integrity
//! (`S-1-16-12288`); a service as LocalSystem runs at System integrity
//! (`S-1-16-16384`). Both count.
//!
//! The integrity SID is read from `whoami /groups`, so this module needs no
//! `unsafe`. SID strings are not localized, unlike the group names around them.
//! The parser is pure and is tested on every target.

/// Mandatory label SIDs that mean an elevated or system token.
const ELEVATED_LABELS: [&str; 3] = ["S-1-16-12288", "S-1-16-16384", "S-1-16-20480"];

/// Any mandatory label at all. Without one the output is not a group listing.
const LABEL_PREFIX: &str = "S-1-16-";

/// `Some(true)` when the listing carries a High, System, or Protected Process
/// label. `Some(false)` for another label (Medium, Low). `None` when no
/// mandatory label is present: the output was not understood.
pub fn privileged_from_whoami_groups(stdout: &str) -> Option<bool> {
    if !stdout.contains(LABEL_PREFIX) {
        return None;
    }
    Some(
        ELEVATED_LABELS
            .iter()
            .any(|label| contains_sid(stdout, label)),
    )
}

/// `label` as a whole SID, not a prefix of a longer one.
fn contains_sid(text: &str, label: &str) -> bool {
    text.match_indices(label).any(|(at, _)| {
        let next = text[at + label.len()..].chars().next();
        !next.is_some_and(|ch| ch.is_ascii_digit() || ch == '-')
    })
}

/// Privilege of the current process. `None` when `whoami` cannot be run.
#[cfg(target_os = "windows")]
pub fn is_privileged() -> Option<bool> {
    // Absolute path under the system root: a PATH entry must not answer this.
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let whoami = std::path::Path::new(&root)
        .join("System32")
        .join("whoami.exe");
    let output = std::process::Command::new(whoami)
        .args(["/groups", "/fo", "csv", "/nh"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    // Group names can be in the console code page. The SIDs are ASCII either way.
    privileged_from_whoami_groups(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(test)]
mod tests {
    use super::privileged_from_whoami_groups;

    const MEDIUM: &str = "\"Everyone\",\"Well-known group\",\"S-1-1-0\",\"Mandatory group\"\r\n\
\"Mandatory Label\\Medium Mandatory Level\",\"Label\",\"S-1-16-8192\",\"\"\r\n";
    const HIGH: &str = "\"BUILTIN\\Administrators\",\"Alias\",\"S-1-5-32-544\",\"Group owner\"\r\n\
\"Mandatory Label\\High Mandatory Level\",\"Label\",\"S-1-16-12288\",\"\"\r\n";
    const SYSTEM: &str =
        "\"Mandatory Label\\System Mandatory Level\",\"Label\",\"S-1-16-16384\",\"\"\r\n";

    #[test]
    fn elevated_and_system_tokens_are_privileged() {
        assert_eq!(privileged_from_whoami_groups(HIGH), Some(true));
        assert_eq!(privileged_from_whoami_groups(SYSTEM), Some(true));
    }

    #[test]
    fn unelevated_admin_is_not_privileged() {
        // Administrators group present but filtered by UAC: Medium label.
        let filtered = format!(
            "\"BUILTIN\\Administrators\",\"Alias\",\"S-1-5-32-544\",\"Deny only\"\r\n{MEDIUM}"
        );
        assert_eq!(privileged_from_whoami_groups(&filtered), Some(false));
    }

    #[test]
    fn a_longer_sid_is_not_a_match() {
        let text = "\"x\",\"Label\",\"S-1-16-122880\",\"\"\r\n\"y\",\"Label\",\"S-1-16-8192\",\"\"";
        assert_eq!(privileged_from_whoami_groups(text), Some(false));
    }

    #[test]
    fn output_without_a_label_is_unknown() {
        assert_eq!(privileged_from_whoami_groups("ERROR: access denied"), None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn live_answer_is_known() {
        assert!(super::is_privileged().is_some());
    }
}
