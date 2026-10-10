//! Whether this process runs with root-level privilege.
//!
//! `std` has no `geteuid` and this crate forbids `unsafe`, so the answer comes
//! from `/proc/self/status`: the effective uid (second `Uid:` field) and the
//! effective capability mask. The parser is pure and is tested on every target.

/// `CAP_SYS_ADMIN`. A non-root process holding it can still load eBPF and read
/// other processes, so it counts as privileged for the daemon.
const CAP_SYS_ADMIN: u32 = 21;

/// `Some(true)` for effective uid 0 or `CAP_SYS_ADMIN` in `CapEff`.
/// `None` when the text has no readable `Uid:` line. Not a guessed `false`.
pub fn privileged_from_status(status: &str) -> Option<bool> {
    let euid: u32 = status
        .lines()
        .find(|line| line.starts_with("Uid:"))?
        .split_whitespace()
        .nth(2)?
        .parse()
        .ok()?;
    if euid == 0 {
        return Some(true);
    }
    let cap_admin = status
        .lines()
        .find(|line| line.starts_with("CapEff:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .is_some_and(|mask| mask & (1_u64 << CAP_SYS_ADMIN) != 0);
    Some(cap_admin)
}

/// Privilege of the current process. `None` when `/proc/self/status` cannot be read.
#[cfg(target_os = "linux")]
pub fn is_privileged() -> Option<bool> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    privileged_from_status(&text)
}

#[cfg(test)]
mod tests {
    use super::privileged_from_status;

    #[test]
    fn root_effective_uid_is_privileged_even_when_real_uid_is_not() {
        // `sudo` style: real 1000, effective 0.
        let text = "Name:\taw\nUid:\t1000\t0\t0\t0\nCapEff:\t0000000000000000\n";
        assert_eq!(privileged_from_status(text), Some(true));
    }

    #[test]
    fn plain_user_is_not_privileged() {
        let text = "Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n";
        assert_eq!(privileged_from_status(text), Some(false));
    }

    #[test]
    fn cap_sys_admin_without_root_is_privileged() {
        let text = "Uid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000200000\n";
        assert_eq!(privileged_from_status(text), Some(true));
    }

    #[test]
    fn missing_uid_line_is_unknown_not_false() {
        assert_eq!(privileged_from_status("Name:\taw\n"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_answer_matches_the_effective_uid() {
        let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        assert_eq!(super::is_privileged(), privileged_from_status(&text));
        assert!(super::is_privileged().is_some());
    }
}
