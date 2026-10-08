//! Ring-buffer loss accounting.
//!
//! The kernel program increments a per-CPU counter when the ring buffer refuses
//! a record. Userspace reads the sum once a second. The difference is a fact
//! about the collector (`GapKind::LostByOs`), not a guess about the target.
//! This module only subtracts two readings.

use aw_core::{Gap, GapKind, Source};

/// Source stamped on a loss gap. The probe name matches the map, not a hook.
pub const LOST_SOURCE: &str = "linux.ebpf/lost";

/// Two readings of the summed per-CPU `lost` counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LostSample {
    /// Monotonic time of the reading, in nanoseconds.
    pub mono_ns: u64,
    /// Sum across CPUs. The kernel value is monotonic for the life of the map.
    pub total: u64,
}

/// A gap when `current.total` is ahead of `previous.total`, otherwise nothing.
///
/// A counter that went backwards is not treated as zero loss and is not wrapped
/// into a huge delta: the caller gets `None` and should open a separate gap for
/// a restarted map. This function does not invent that gap.
pub fn lost_gap(previous: LostSample, current: LostSample) -> Option<Gap> {
    let delta = current.total.checked_sub(previous.total)?;
    if delta == 0 {
        return None;
    }
    Some(Gap::new(
        Source::new(LOST_SOURCE),
        GapKind::LostByOs,
        vec!["proc".to_string(), "file".to_string(), "net".to_string()],
        previous.mono_ns,
        current.mono_ns,
        Some(delta),
        Some(format!(
            "{delta} event(s) lost by the ring buffer since the previous read"
        )),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(mono_ns: u64, total: u64) -> LostSample {
        LostSample { mono_ns, total }
    }

    #[test]
    fn no_delta_is_not_a_gap() {
        assert!(lost_gap(sample(0, 5), sample(1_000_000_000, 5)).is_none());
    }

    #[test]
    fn an_increase_is_a_lost_by_os_gap_with_the_delta() {
        let gap = must_gap(lost_gap(sample(1_000, 5), sample(1_001_000, 8)));
        assert_eq!(gap.gap_kind, GapKind::LostByOs);
        assert_eq!(gap.count, Some(3));
        assert_eq!(gap.from_mono_ns, 1_000);
        assert_eq!(gap.to_mono_ns, 1_001_000);
        assert_eq!(gap.collector.as_str(), LOST_SOURCE);
        assert!(gap.affects.iter().any(|a| a == "file"));
    }

    #[test]
    fn a_backwards_counter_is_not_reported_as_loss() {
        assert!(lost_gap(sample(0, 10), sample(1, 4)).is_none());
    }

    #[test]
    fn first_reading_against_zero_reports_the_whole_total() {
        let gap = must_gap(lost_gap(sample(0, 0), sample(1_000_000_000, 2)));
        assert_eq!(gap.count, Some(2));
    }

    fn must_gap(gap: Option<Gap>) -> Gap {
        match gap {
            Some(gap) => gap,
            None => panic!("expected a loss gap"),
        }
    }
}
