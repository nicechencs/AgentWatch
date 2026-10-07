//! Windows collector. Non-Windows targets compile this crate as an empty shell.
//!
//! The `#![cfg(target_os = "windows")]` gate is per item rather than on the
//! crate, because a crate-level `cfg` would also drop the module-level docs
//! and the empty-shell test on other targets. `etw` is the only thing in the
//! crate, and it is Windows-only.
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

#[cfg(target_os = "windows")]
pub use etw::trace::Session as WindowsCollector;

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
