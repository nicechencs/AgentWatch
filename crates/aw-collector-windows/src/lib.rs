//! Windows collector. Non-Windows targets compile this crate as an empty shell.
//!
//! The `#![cfg(target_os = "windows")]` gate is per item rather than on the
//! crate, because a crate-level `cfg` would also drop the module-level docs
//! and the empty-shell test on other targets. `etw` is the only thing in the
//! crate, and it is Windows-only. `scope` is the exception: the attach-tree walk
//! and the breakaway note are pure and compile on every target. They do not
//! call Win32.
//!
//! `unsafe_code` is `deny` here, not `forbid`. A `forbid` cannot be relaxed in
//! a child module. Two modules opt in with `allow`: `etw::ffi` (`ControlTraceW`,
//! which ferrisetw does not expose) and `peb` (`NtQueryInformationProcess` and
//! `ReadProcessMemory`). Every `unsafe` block in both carries a `SAFETY`
//! comment. The workspace lint stays `forbid`; this crate overrides it for itself.

#![deny(unsafe_code)]
#![cfg_attr(not(target_os = "windows"), allow(unused))]

#[cfg(target_os = "windows")]
pub mod etw;
#[cfg(target_os = "windows")]
pub mod peb;
pub mod scope;

#[cfg(target_os = "windows")]
pub use etw::trace::Session as WindowsCollector;
pub use scope::{
    build_attach_tree, AttachError, AttachMember, AttachPlan, BreakawayPolicy, ExcludedProcess,
    ExcludedReason, SnapshotProcess, BREAKAWAY_INCOMPLETE_NOTE,
};

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
