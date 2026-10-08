//! Linux collector.
//!
//! Non-Linux targets compile the platform body out. The tier probe, the map
//! layout, and the loss counter are pure and stay compiled everywhere, so
//! `cargo test -p aw-collector-linux` covers them on Windows.
//!
//! Aya is intentionally not a dependency. SPIKE-01 has not started, and this
//! tree must keep `cargo check --workspace` and `cargo deny` green on Windows
//! without a BPF toolchain. [`loader::BpfLoader`] is the seam a later task fills
//! in behind `cfg(target_os = "linux")`. The Linux stub refuses every attach
//! and says why, instead of pretending a program was loaded.

#![forbid(unsafe_code)]

mod decode;
mod loader;
mod lost;
mod maps;
mod probe;

#[cfg(target_os = "linux")]
mod collector;

#[cfg(target_os = "linux")]
pub use collector::LinuxCollector;

pub use decode::proc::{
    argv_bytes as ebpf_argv_bytes, decode_proc as decode_ebpf_proc,
    encode_proc as encode_ebpf_proc, CwdRead, DecodeContext as ProcDecodeContext, ProcDecodeError,
    ProcDecoded, ProcRecord, SessionCgroups, ARGV_CAP, FILENAME_CAP, HEADER_LEN as PROC_HEADER_LEN,
    KIND_CGROUP, KIND_EXEC, KIND_EXIT, KIND_FORK, SOURCE_CGROUP, SOURCE_EXEC as SOURCE_EBPF_EXEC,
    SOURCE_EXIT as SOURCE_EBPF_EXIT, SOURCE_FORK,
};
pub use loader::{classify_attach_error, BpfLoader, EmbeddedProgram, LoaderConfig};
pub use lost::{lost_gap, LostSample, LOST_SOURCE};
pub use maps::{
    shared_maps, MapKind, MapSpec, EVENTS, EVENTS_RINGBUF_BYTES, LOST, SCOPE_CGROUPS, SCOPE_PIDS,
};
pub use probe::{
    all_probes, parse_collector_arg, select_tier, MountFailure, MountResult, PermissionError,
    Privilege, ProbeHost, ProbeId, ScriptedHost, Tier, TierDecision, TierRequest,
};

/// `1` once `build.rs` embeds an object. Today it is always `0`.
pub const EMBEDDED_OBJECT_BYTES: &str = env!("AW_EBPF_EMBEDDED");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_script_reports_no_embedded_object() {
        assert_eq!(EMBEDDED_OBJECT_BYTES, "0");
    }
}
