//! Process identity. Pure function of caller-supplied numbers (ADR-0007).
//!
//! `proc_uid = xxh3_64(boot_id ‖ pid ‖ start_time_truncated)`.
//!
//! The hash input is this byte string, and nothing else (no host entropy, no
//! time of day):
//!
//! ```text
//! boot_id                         raw bytes, caller order, no terminator
//! pid                             u32 little-endian
//! start_time / 10 ms              u64 little-endian
//! ```
//!
//! `start_time` is truncated to 10 ms **before** hashing. In nanoseconds that
//! bucket is `10_000_000` ns; the caller names the unit so a jiffy count cannot
//! be mixed with a nanosecond count by accident. The value stored for display
//! is the original, untruncated start time.
//!
//! This module does not build a process tree. "Parent started after child" is
//! a pipeline rule, not an identity rule.

use crate::event::ProcUid;
use crate::xxh3::xxh3_64;

/// 10 ms expressed in nanoseconds. One truncation bucket when the caller passes
/// [`StartTimeUnit::Nanoseconds`].
pub const TRUNCATION_NANOS: u64 = 10_000_000;

/// How many of the caller's start-time ticks make one 10 ms bucket.
///
/// The identity function never converts between units itself. Passing the unit
/// keeps a Linux jiffy count from being hashed as if it were nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StartTimeUnit {
    /// Caller already divided by 10 ms. Each tick is one bucket.
    Already10ms,
    /// Nanoseconds since an arbitrary epoch. Bucket = `10_000_000` ns.
    Nanoseconds,
    /// 100-nanosecond ticks (Windows FILETIME). Bucket = `100_000` ticks.
    HundredNanoseconds,
    /// Microseconds. Bucket = `10_000` µs.
    Microseconds,
    /// Milliseconds. Bucket = `10` ms.
    Milliseconds,
    /// Whole seconds. Coarser than 10 ms, so each tick is its own bucket and
    /// no further truncation is applied.
    Seconds,
    /// Linux `USER_HZ` clock ticks (jiffies), 100 Hz on every architecture
    /// Linux currently ships. One jiffy is 10 ms, so each tick is one bucket.
    Jiffies100Hz,
}

impl StartTimeUnit {
    /// Ticks of this unit that fill exactly one 10 ms bucket.
    ///
    /// `1` means the caller is already at (or coarser than) the 10 ms grid, so
    /// truncation is integer division by one.
    pub const fn ticks_per_bucket(self) -> u64 {
        match self {
            Self::Already10ms | Self::Jiffies100Hz | Self::Seconds => 1,
            Self::Milliseconds => 10,
            Self::Microseconds => 10_000,
            Self::HundredNanoseconds => 100_000,
            Self::Nanoseconds => TRUNCATION_NANOS,
        }
    }
}

/// Identity of one process, plus the raw fields a UI needs to show it.
///
/// `uid` is the hash. `pid` and `start_time` are the inputs **before**
/// truncation, so a display can show the start time the platform actually
/// reported. Two readings inside the same 10 ms bucket share a `uid` and still
/// keep their own original start time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    /// `xxh3_64` of boot id, pid, and the truncated start time.
    pub uid: ProcUid,
    /// Raw pid. Not derived from the hash.
    pub pid: u32,
    /// Start time in [`StartTimeUnit`] ticks, before the 10 ms truncation.
    pub start_time: u64,
    /// Unit of `start_time`. Recorded so a later reader does not guess.
    pub start_time_unit: StartTimeUnit,
}

impl ProcessIdentity {
    /// Hash `(boot_id, pid, start_time)` into a [`ProcUid`], keeping the raw fields.
    ///
    /// `boot_id` is taken as opaque bytes. An empty boot id is a real value
    /// (it still mixes into the hash); it does not mean "unknown". Callers that
    /// do not have a boot id must not invent one — pass the absence up with
    /// `Option` at their own layer instead of calling this.
    ///
    /// Returns `None` only when the encoded input would exceed what the in-tree
    /// XXH3 can hash (boot id longer than 228 bytes). A boot id from any
    /// supported platform is a UUID string and does not hit this.
    pub fn from_parts(
        boot_id: &[u8],
        pid: u32,
        start_time: u64,
        unit: StartTimeUnit,
    ) -> Option<Self> {
        let truncated = truncate_start_time(start_time, unit);
        let uid = proc_uid(boot_id, pid, truncated)?;
        Some(Self {
            uid,
            pid,
            start_time,
            start_time_unit: unit,
        })
    }
}

/// `start_time` divided into 10 ms buckets. The remainder is discarded.
pub fn truncate_start_time(start_time: u64, unit: StartTimeUnit) -> u64 {
    start_time / unit.ticks_per_bucket()
}

/// `xxh3_64` over the layout documented at the top of this module.
///
/// `truncated_start` must already be in 10 ms buckets ([`truncate_start_time`]).
/// Returns `None` when `boot_id` is too long for the in-tree hasher.
pub fn proc_uid(boot_id: &[u8], pid: u32, truncated_start: u64) -> Option<ProcUid> {
    // boot_id || pid(u32 LE) || start(u64 LE). 12 bytes plus the boot id.
    let mut buf = [0_u8; 12 + 228];
    let n = boot_id.len();
    if n > 228 {
        return None;
    }
    buf[..n].copy_from_slice(boot_id);
    buf[n..n + 4].copy_from_slice(&pid.to_le_bytes());
    buf[n + 4..n + 12].copy_from_slice(&truncated_start.to_le_bytes());
    xxh3_64(&buf[..n + 12]).map(ProcUid)
}

#[cfg(test)]
mod proc_uid {
    use super::{truncate_start_time, ProcessIdentity, StartTimeUnit};

    const BOOT_A: &[u8] = b"11111111-1111-1111-1111-111111111111";
    const BOOT_B: &[u8] = b"22222222-2222-2222-2222-222222222222";

    fn ident(boot: &[u8], pid: u32, start: u64) -> ProcessIdentity {
        match ProcessIdentity::from_parts(boot, pid, start, StartTimeUnit::Nanoseconds) {
            Some(identity) => identity,
            // A UUID boot id is 36 bytes. `None` here means the hasher refused it,
            // which these cases are not exercising.
            None => panic!("boot id is a short UUID"),
        }
    }

    #[test]
    fn same_pid_different_start_time_differs() {
        let a = ident(BOOT_A, 4242, 1_000_000_000);
        let b = ident(BOOT_A, 4242, 1_000_000_000 + 50_000_000);
        assert_ne!(a.uid, b.uid);
        assert_eq!(a.pid, b.pid);
        assert_eq!(a.start_time, 1_000_000_000);
        assert_eq!(b.start_time, 1_050_000_000);
    }

    #[test]
    fn identical_inputs_are_stable_across_calls() {
        let first = ident(BOOT_A, 7, 5_000_000_000);
        let second = ident(BOOT_A, 7, 5_000_000_000);
        assert_eq!(first.uid, second.uid);
        assert_eq!(first, second);
    }

    #[test]
    fn truncation_collapses_one_10ms_bucket_and_splits_on_the_boundary() {
        // 10 ms = 10_000_000 ns. 1_000_000_000 is on a bucket edge.
        let base = 1_000_000_000_u64;
        let at_edge = ident(BOOT_A, 9, base);
        let inside = ident(BOOT_A, 9, base + 9_999_999);
        let next_bucket = ident(BOOT_A, 9, base + 10_000_000);

        assert_eq!(at_edge.uid, inside.uid, "same 10 ms bucket must hash equal");
        assert_ne!(
            inside.uid, next_bucket.uid,
            "crossing a 10 ms boundary must hash different"
        );
        // Display keeps the raw reading even when the hash collapsed.
        assert_eq!(inside.start_time, base + 9_999_999);
        assert_eq!(
            truncate_start_time(base + 9_999_999, StartTimeUnit::Nanoseconds),
            truncate_start_time(base, StartTimeUnit::Nanoseconds),
        );
        assert_ne!(
            truncate_start_time(base + 10_000_000, StartTimeUnit::Nanoseconds),
            truncate_start_time(base, StartTimeUnit::Nanoseconds),
        );
    }

    #[test]
    fn boot_id_changes_the_hash() {
        let a = ident(BOOT_A, 9, 1_000_000_000);
        let b = ident(BOOT_B, 9, 1_000_000_000);
        assert_ne!(a.uid, b.uid);
        assert_eq!(a.pid, b.pid);
        assert_eq!(a.start_time, b.start_time);
    }

    #[test]
    fn unit_is_part_of_the_contract_not_silently_converted() {
        // The same integer in two units is a different bucket, on purpose.
        let Some(ns) =
            ProcessIdentity::from_parts(BOOT_A, 1, 10_000_000, StartTimeUnit::Nanoseconds)
        else {
            panic!("short boot id");
        };
        let Some(ms) =
            ProcessIdentity::from_parts(BOOT_A, 1, 10_000_000, StartTimeUnit::Milliseconds)
        else {
            panic!("short boot id");
        };
        assert_ne!(ns.uid, ms.uid);
        assert_eq!(
            truncate_start_time(10_000_000, StartTimeUnit::Nanoseconds),
            1
        );
        assert_eq!(
            truncate_start_time(10_000_000, StartTimeUnit::Milliseconds),
            1_000_000
        );
    }
}
