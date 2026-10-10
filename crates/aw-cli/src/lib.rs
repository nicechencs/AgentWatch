//! Library surface for the Linux launch state machine (P1-LNX-04).
//!
//! `aw` itself is the `aw` bin and does not link this crate. This lib exposes the
//! Linux launch state machine so its tests run outside the bin.
//! [`UnverifiedCgroupLaunch`] is the test double; it refuses every step and does
//! not fork. Production `aw run` uses `LocalCgroupHost` from the bin.

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
