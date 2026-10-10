//! Whether this process runs as root.
//!
//! This crate forbids `unsafe`, so `geteuid` is not called through FFI. The
//! answer is `/usr/bin/id -u`, which prints the effective uid. The parser is
//! pure and is tested on every target.

/// `Some(true)` when `id -u` printed `0`. `None` for anything that is not a uid.
pub fn privileged_from_id_output(stdout: &str) -> Option<bool> {
    let uid: u32 = stdout.trim().parse().ok()?;
    Some(uid == 0)
}

/// Privilege of the current process. `None` when `id` cannot be run.
#[cfg(target_os = "macos")]
pub fn is_privileged() -> Option<bool> {
    // Absolute path: a PATH entry must not answer this question.
    let output = std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    privileged_from_id_output(std::str::from_utf8(&output.stdout).ok()?)
}

#[cfg(test)]
mod tests {
    use super::privileged_from_id_output;

    #[test]
    fn uid_zero_is_privileged() {
        assert_eq!(privileged_from_id_output("0\n"), Some(true));
        assert_eq!(privileged_from_id_output("501\n"), Some(false));
    }

    #[test]
    fn garbage_is_unknown_not_false() {
        assert_eq!(privileged_from_id_output(""), None);
        assert_eq!(privileged_from_id_output("id: illegal option"), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn live_answer_is_known() {
        assert!(super::is_privileged().is_some());
    }
}
