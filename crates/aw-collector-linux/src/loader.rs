//! Loader boundary.
//!
//! [`BpfLoader`] is what a Linux build will implement with Aya. This crate does
//! not depend on Aya: SPIKE-01 has not started, and an unconditional (or even
//! target-gated) aya dependency would be resolved by cargo-deny on Windows.
//! The Linux stub below compiles on Linux and reports that no program is embedded
//! yet, which the tier probe records as `Unsupported` rather than as success.

use crate::maps::{MapSpec, EVENTS_RINGBUF_BYTES};
use crate::probe::{MountFailure, MountResult, ProbeId};

/// What a loader needs before it can attach anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoaderConfig {
    /// Ring buffer size in bytes. Defaults to 16 MiB.
    pub ringbuf_bytes: u32,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            ringbuf_bytes: EVENTS_RINGBUF_BYTES,
        }
    }
}

/// Bytes of one embedded program, plus the maps it expects.
///
/// P1-LNX-01 has no bytecode. [`EmbeddedProgram::empty`] is the only constructor
/// until `build.rs` starts emitting an object file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmbeddedProgram {
    /// ELF bytes. Empty until a later task embeds the object.
    pub bytes: &'static [u8],
    /// Maps the program and the loader agree on.
    pub maps: &'static [MapSpec],
}

impl EmbeddedProgram {
    /// No bytecode. Loading this fails with [`MountFailure::Unsupported`].
    pub const fn empty(maps: &'static [MapSpec]) -> Self {
        Self { bytes: &[], maps }
    }

    /// `true` when there is an object to hand to a loader.
    pub const fn has_bytecode(&self) -> bool {
        !self.bytes.is_empty()
    }
}

/// Attaches one probe and reads the `lost` counter.
///
/// Implementors live behind `cfg(target_os = "linux")`. They must not be called
/// from a unit test: tests drive [`crate::probe::ProbeHost`] directly.
pub trait BpfLoader {
    /// Error from the platform. Display must not include argv, environment, or paths
    /// from the target process.
    type Error: core::fmt::Display;

    /// Load `program` and attach `probe`. Does not retry another probe.
    fn attach(&mut self, program: &EmbeddedProgram, probe: ProbeId) -> Result<(), Self::Error>;

    /// Sum of the per-CPU `lost` map. `None` if the map is not loaded.
    fn read_lost(&self) -> Result<Option<u64>, Self::Error>;
}

/// Classifies a loader error into a mount result.
///
/// Permission is separated so the tier probe can say why. Everything else is
/// `Unsupported`: this card has no richer taxonomy, and inventing one would
/// hide the real failure inside a success tier.
pub fn classify_attach_error(permission_denied: bool) -> MountResult {
    if permission_denied {
        MountResult::Failed(MountFailure::Permission)
    } else {
        MountResult::Failed(MountFailure::Unsupported)
    }
}

/// Linux loader stub.
///
/// It does not link Aya and does not call the `bpf` syscall. Every attach fails
/// with [`MountFailure::Unsupported`] until P1-LNX-02 embeds a real program and
/// SPIKE-01 has shown that Aya loads it. See the crate-level note in `lib.rs`.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct AyaLoader {
    config: LoaderConfig,
}

#[cfg(target_os = "linux")]
impl AyaLoader {
    /// Build a loader that will refuse to attach until bytecode exists.
    pub fn new(config: LoaderConfig) -> Self {
        Self { config }
    }

    /// Ring buffer size this loader would request. Exposed so a test on Linux
    /// can see the stub was constructed with the shared layout.
    pub fn ringbuf_bytes(&self) -> u32 {
        self.config.ringbuf_bytes
    }
}

/// Why the stub refused. One variant, so callers cannot mistake it for success.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AyaUnavailable;

#[cfg(target_os = "linux")]
impl core::fmt::Display for AyaUnavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(
            "Aya loader is not linked (P1-LNX-01); no eBPF program is embedded yet",
        )
    }
}

#[cfg(target_os = "linux")]
impl BpfLoader for AyaLoader {
    type Error = AyaUnavailable;

    fn attach(&mut self, program: &EmbeddedProgram, _probe: ProbeId) -> Result<(), Self::Error> {
        let _ = program;
        Err(AyaUnavailable)
    }

    fn read_lost(&self) -> Result<Option<u64>, Self::Error> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::{shared_maps, EVENTS, EVENTS_RINGBUF_BYTES};

    #[test]
    fn empty_program_has_no_bytecode_and_names_the_ringbuf() {
        let program = EmbeddedProgram::empty(shared_maps());
        assert!(!program.has_bytecode());
        assert!(program.bytes.is_empty());
        let Some(events) = program.maps.iter().find(|m| m.name == EVENTS) else {
            panic!("events map");
        };
        assert_eq!(events.ringbuf_bytes, Some(EVENTS_RINGBUF_BYTES));
    }

    #[test]
    fn classify_separates_permission_from_unsupported() {
        assert_eq!(
            classify_attach_error(true),
            MountResult::Failed(MountFailure::Permission)
        );
        assert_eq!(
            classify_attach_error(false),
            MountResult::Failed(MountFailure::Unsupported)
        );
    }

    #[test]
    fn default_config_is_sixteen_mib() {
        assert_eq!(LoaderConfig::default().ringbuf_bytes, 16 * 1024 * 1024);
    }
}
