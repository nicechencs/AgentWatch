//! Unix pieces shared by more than one platform module.
//!
//! [`hold`] is the macOS suspended launch: a forked child that switches
//! account, then blocks on a pipe before exec. It lives here, not under
//! `macos/`, because the same code has to be tested on Linux. Linux's own
//! launch does not call it.

// Linux compiles this so the hold can be tested here; only the macOS
// `Platform` calls it, so production code on Linux never references it.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
pub(crate) mod hold;
