//! Whether this daemon process runs with administrator or root privilege.
//!
//! `aw-daemon` is the one crate that assembles platform code with `cfg`
//! (AGENTS.md §6). Each platform crate owns its own check and its parser tests:
//!
//! * Linux: effective uid 0 or `CAP_SYS_ADMIN`, from `/proc/self/status`.
//! * macOS: effective uid 0, from `/usr/bin/id -u`.
//! * Windows: an elevated (High) or System integrity label, from `whoami /groups`.
//!
//! `None` means the check itself failed. It is reported as unknown, not as
//! "not privileged".

/// Privilege of the current process, or `None` when it could not be read.
pub(crate) fn current() -> Option<bool> {
    aw_platform::platform().is_privileged()
}

#[cfg(test)]
mod tests {
    /// BUGS B5: the answer used to be a hard-coded "not admin". On the three
    /// supported targets the check must produce an answer, whatever it is.
    #[test]
    fn privilege_is_known_on_supported_targets() {
        if cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        )) {
            assert!(super::current().is_some());
        }
    }
}
