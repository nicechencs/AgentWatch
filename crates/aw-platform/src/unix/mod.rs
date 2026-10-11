//! Unix pieces shared by more than one platform module.
//!
//! [`hold`] is the suspended launch: a forked child that switches account,
//! then blocks on a pipe before exec. It lives here, not under `macos/`,
//! because Linux uses the same stage. A shell gate that cleared `FD_CLOEXEC`
//! in the parent was inherited by every sibling spawn running at the same time.

// Linux and macOS both call this. Other Unix targets compile it for the tests.
#[cfg_attr(
    not(any(test, target_os = "macos", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) mod hold;

#[allow(unsafe_code)]
pub(crate) mod signals;
