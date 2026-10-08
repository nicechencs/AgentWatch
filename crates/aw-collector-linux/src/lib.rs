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
mod dns_parse;
mod file;
mod legacy;
mod loader;
mod lost;
mod maps;
mod netdecode;
mod probe;
mod scope;
mod sni;

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
pub use dns_parse::{parse_dns, DnsParse, DnsParseInput, ParsedAnswer, ParsedDns};
pub use file::{
    decode_file, encode_flush, encode_open, encode_pending, encode_transfer, join_cwd, pending_gap,
    pre_existing_fd, CwdLookup as FileCwdLookup, DecodeOutcome as FileDecodeOutcome, FdPath,
    FdPathRead, FileDecode, FileDecodeError, FlushIn, OpenIn, PathJoin as FilePathJoin, PendingIn,
    ProcIdentity as FileProcIdentity, ScopeView as FileScopeView, TransferFlow, TransferIn,
    FIELD_BYTES as FILE_FIELD_BYTES, SOURCE_FEXIT_OPEN, SOURCE_LSM_FILE_OPEN, SOURCE_TP_CLOSE,
    SOURCE_TP_OPENAT, SOURCE_TP_UNLINKAT,
};
pub use legacy::fanotify::{
    decode_fanotify, flush_count, in_scope as fanotify_in_scope, init_flags as fanotify_init_flags,
    FanCount, FanEvent, FanKernel, FanotifyConfig, FanotifyError, INIT_FLAGS, MARK_ALWAYS,
    SOURCE_FANOTIFY,
};
pub use legacy::{
    attribute_dns, counter_evidence, decode_proc, decode_sock_delta, diff_sock, inode_na,
    lookup_inode, open_legacy, pid_for_inode, CounterStep, DnsPacket, InodeLookup, InodeOwner,
    KnownSocket, LegacyError, LegacySource, ProcConnectorEvent, ProcSkip, ProcWhat, SockDelta,
    SockSample, UnavailableLegacy, FIELD_ARGV, FIELD_PROC, SOURCE_AF_PACKET, SOURCE_PROC_CONNECTOR,
    SOURCE_SOCK_DIAG,
};
pub use loader::{classify_attach_error, BpfLoader, EmbeddedProgram, LoaderConfig};
pub use lost::{lost_gap, LostSample, LOST_SOURCE};
pub use maps::{
    shared_maps, MapKind, MapSpec, EVENTS, EVENTS_RINGBUF_BYTES, LOST, SCOPE_CGROUPS, SCOPE_PIDS,
};
pub use netdecode::{
    connect_from_bytes, decode_net, dns_from_bytes, normalize_ip, proc_uid_ready, state_from_bytes,
    stats_from_bytes, ConnectRecord, DecodedNet, DnsRecordIn, Endpoint, NetRecord, ProcIdentity,
    SkipReason, StateRecord, StatsDelta, DNS_PAYLOAD_CAP, RESOLVED_STUB, SOURCE_PREFIX,
};
pub use probe::{
    all_probes, parse_collector_arg, select_tier, MountFailure, MountResult, PermissionError,
    Privilege, ProbeHost, ProbeId, ScriptedHost, Tier, TierDecision, TierRequest,
};
pub use scope::{
    cleanup_cgroup, escape_gap, run_attach, run_launch as run_scope_launch, scope_cgroups_map,
    scope_pids_map, session_dir, v1_doctor_hint, AdoptWait as ScopeAdoptWait, AttachOutcome,
    AttachRequest, AttachStep, CgroupCreatePath as ScopeCgroupCreatePath, CgroupHost,
    CgroupVersion, CleanupOutcome, EscapeObservation, LaunchIdentity as ScopeLaunchIdentity,
    LaunchOutcome as ScopeLaunchOutcome, LaunchPhase, LaunchRequest as ScopeLaunchRequest,
    LaunchStep as ScopeLaunchStep, ProcRow, ProcScan, ScopeError, ScopeMap, SystemdPresence,
    ADOPT_TIMEOUT_SECS, CGROUP_NONEMPTY_NOTE, SLICE_NAME as SCOPE_SLICE_NAME, SOURCE_CGROUP_ESCAPE,
    V1_DOCTOR_HINT,
};
pub use sni::{
    sni_enabled, FirstWrite, SniAttach, SniError, SniExtractor, SniSource, SNI_PREFIX_CAP,
    SOURCE_AFPACKET_SNI, SOURCE_EBPF_SNI,
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
