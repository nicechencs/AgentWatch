//! Library surface for the Linux launch state machine (P1-LNX-04).
//!
//! `aw` itself is the `aw` bin and does not link this crate. This lib exists so
//! `crates/aw-cli/src/launch/unix_linux.rs` compiles and its tests run before
//! P1-CLI-02 registers it from `launch/mod.rs` under `cfg(target_os = "linux")`.
//! Nothing here is called by `main`.

#![forbid(unsafe_code)]

#[path = "launch/unix_linux.rs"]
mod unix_linux;

pub use unix_linux::{
    run_launch, AdoptWait, CgroupCreatePath, CgroupLaunch, CgroupVersion, Inheritance, LaunchError,
    LaunchIdentity, LaunchOutcome, LaunchPhase, LaunchRequest, LaunchStep, SystemdPresence,
    ADOPT_TIMEOUT, SLICE_NAME, V1_DOCTOR_HINT,
};

/// Present only on Linux. The stub refuses every step; it does not fork.
#[cfg(target_os = "linux")]
pub use unix_linux::UnverifiedCgroupLaunch;
