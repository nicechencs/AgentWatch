//! Platform launchers for `aw run` (P1-WIN-04, and later the Unix cards).
//!
//! The command tree in `cmd/` does not call this yet. Wiring `aw run` to it is
//! a later card; this module is the state machine those flags will drive.
//!
//! Windows is [`windows`]. Other targets have no launcher here.

mod windows;

// Re-exported for the later card that wires `aw run`. This binary does not
// call them yet.
#[allow(unused_imports)]
pub use windows::{
    run_launch, JobApi, LaunchError, LaunchRequest, LaunchStep, SessionAnnotation, TargetExit,
    ADOPT_TIMEOUT, BREAKAWAY_INCOMPLETE_NOTE,
};

/// Present only on Windows. The stub refuses every step; it does not call Win32.
#[cfg(target_os = "windows")]
#[allow(unused_imports)]
pub use windows::UnverifiedJobApi;
