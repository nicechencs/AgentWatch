//! Shared eBPF map layout.
//!
//! These constants describe the maps the kernel programs and the loader agree
//! on (linux §1, P1-LNX-01). Nothing here opens a map or talks to the kernel.
//! The programs themselves are still the empty probe in `aw-ebpf`; later tasks
//! must keep these names and sizes.

/// `scope_cgroups`: cgroup ids that belong to the session.
pub const SCOPE_CGROUPS: &str = "scope_cgroups";

/// `scope_pids`: tgids that belong to the session (attach mode).
pub const SCOPE_PIDS: &str = "scope_pids";

/// `events`: BPF ring buffer the probes write into.
pub const EVENTS: &str = "events";

/// `lost`: per-CPU counter of records the ring buffer refused.
pub const LOST: &str = "lost";

/// Default ring buffer size: 16 MiB (linux §6).
pub const EVENTS_RINGBUF_BYTES: u32 = 16 * 1024 * 1024;

/// One map the loader and the (future) programs both name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapSpec {
    /// Map name. Must match the kernel program.
    pub name: &'static str,
    /// Kind. The loader uses this when it eventually creates the map.
    pub kind: MapKind,
    /// Value width in bytes. `None` for a ring buffer, which has no value type.
    pub value_size: Option<u32>,
    /// Ring buffer capacity in bytes. `None` unless [`MapKind::RingBuf`].
    pub ringbuf_bytes: Option<u32>,
}

/// Map kinds this collector uses. Not a full BPF map-type enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    /// Hash set of ids (`scope_cgroups`, `scope_pids`). Key and value are `u64` / `u32`.
    Hash,
    /// BPF ring buffer (`events`).
    RingBuf,
    /// Per-CPU array of counters (`lost`).
    PerCpuArray,
}

/// The four maps P1-LNX-01 fixes. Order is the order a loader should create them.
///
/// A static slice, so [`crate::loader::EmbeddedProgram::empty`] can borrow it for `'static`.
pub fn shared_maps() -> &'static [MapSpec] {
    &SHARED_MAPS
}

const SHARED_MAPS: [MapSpec; 4] = {
    [
        MapSpec {
            name: SCOPE_CGROUPS,
            kind: MapKind::Hash,
            value_size: Some(4),
            ringbuf_bytes: None,
        },
        MapSpec {
            name: SCOPE_PIDS,
            kind: MapKind::Hash,
            value_size: Some(4),
            ringbuf_bytes: None,
        },
        MapSpec {
            name: EVENTS,
            kind: MapKind::RingBuf,
            value_size: None,
            ringbuf_bytes: Some(EVENTS_RINGBUF_BYTES),
        },
        MapSpec {
            name: LOST,
            kind: MapKind::PerCpuArray,
            value_size: Some(8),
            ringbuf_bytes: None,
        },
    ]
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_maps_match_the_task_card() {
        let maps = shared_maps();
        assert_eq!(maps.len(), 4);
        assert_eq!(maps[0].name, "scope_cgroups");
        assert_eq!(maps[0].kind, MapKind::Hash);
        assert_eq!(maps[1].name, "scope_pids");
        assert_eq!(maps[1].kind, MapKind::Hash);
        assert_eq!(maps[2].name, "events");
        assert_eq!(maps[2].kind, MapKind::RingBuf);
        assert_eq!(maps[2].ringbuf_bytes, Some(16 * 1024 * 1024));
        assert_eq!(maps[3].name, "lost");
        assert_eq!(maps[3].kind, MapKind::PerCpuArray);
        assert_eq!(maps[3].value_size, Some(8));
    }

    #[test]
    fn names_are_unique() {
        let maps = shared_maps();
        for (i, left) in maps.iter().enumerate() {
            for right in maps.iter().skip(i + 1) {
                assert_ne!(left.name, right.name);
            }
        }
    }
}
