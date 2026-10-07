//! Sequence holes in eslogger output become loss records.
//!
//! macos.md §1.1: `seq_num` counts per event type and `global_seq_num` counts
//! across types. A jump forward is a loss. The first observed value only
//! establishes the baseline; we do not invent a loss for messages that arrived
//! before the collector was watching.
//!
//! SPIKE-03 has not confirmed that either field is present. A missing counter
//! is not a gap: the detector records nothing for that stream and leaves the
//! absence to the decoder's `NA` mark.

use std::collections::BTreeMap;

/// Which counter jumped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SequenceKind {
    /// `seq_num` for one eslogger event name (`exec`, `fork`, `exit`, …).
    PerEvent,
    /// `global_seq_num`, shared by every event type.
    Global,
}

/// One hole: `previous + 1 .. observed` (exclusive of `observed`) was not seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceLoss {
    /// Which counter.
    pub kind: SequenceKind,
    /// Event name for [`SequenceKind::PerEvent`]. `None` for the global counter.
    pub event: Option<String>,
    /// Last value that was present.
    pub previous: u64,
    /// Value that arrived after the hole.
    pub observed: u64,
    /// How many numbers are missing (`observed - previous - 1`).
    pub missing: u64,
}

/// Tracks the last `seq_num` per event name and the last `global_seq_num`.
#[derive(Debug, Clone, Default)]
pub struct LossDetector {
    per_event: BTreeMap<String, u64>,
    global: Option<u64>,
}

impl LossDetector {
    /// Empty detector. The first sample of each stream is a baseline.
    pub fn new() -> Self {
        Self::default()
    }

    /// Note `seq_num` for `event`.
    ///
    /// Returns a loss when `seq` is more than one past the last value for this
    /// event name. Equal or backwards is not a loss: eslogger's per-type counter
    /// is not documented to reset, and SPIKE-03 has not said what a repeat means.
    /// Inventing a gap there would claim a loss we did not observe.
    pub fn observe_seq(&mut self, event: &str, seq: u64) -> Option<SequenceLoss> {
        note(&mut self.per_event, event, seq).map(|(previous, missing)| SequenceLoss {
            kind: SequenceKind::PerEvent,
            event: Some(event.to_owned()),
            previous,
            observed: seq,
            missing,
        })
    }

    /// Note `global_seq_num`. Same jump rule as [`Self::observe_seq`].
    pub fn observe_global(&mut self, seq: u64) -> Option<SequenceLoss> {
        let mut slot = BTreeMap::new();
        if let Some(prev) = self.global {
            slot.insert(String::new(), prev);
        }
        let loss = note(&mut slot, "", seq).map(|(previous, missing)| SequenceLoss {
            kind: SequenceKind::Global,
            event: None,
            previous,
            observed: seq,
            missing,
        });
        self.global = slot.get("").copied();
        loss
    }
}

fn note(map: &mut BTreeMap<String, u64>, key: &str, seq: u64) -> Option<(u64, u64)> {
    match map.get(key).copied() {
        None => {
            map.insert(key.to_owned(), seq);
            None
        }
        Some(previous) => {
            map.insert(key.to_owned(), seq);
            let gap = seq.saturating_sub(previous);
            if gap > 1 {
                Some((previous, gap - 1))
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_hole_in_seq_num_reports_the_missing_count() {
        let mut det = LossDetector::new();
        assert!(det.observe_seq("exec", 1).is_none());
        assert!(det.observe_seq("exec", 2).is_none());
        let loss = det.observe_seq("exec", 5).expect("hole");
        assert_eq!(loss.kind, SequenceKind::PerEvent);
        assert_eq!(loss.event.as_deref(), Some("exec"));
        assert_eq!(loss.previous, 2);
        assert_eq!(loss.observed, 5);
        assert_eq!(loss.missing, 2);
    }

    #[test]
    fn first_value_is_a_baseline_not_a_loss() {
        let mut det = LossDetector::new();
        assert!(det.observe_seq("exit", 40).is_none());
        assert!(det.observe_global(100).is_none());
    }

    #[test]
    fn per_event_counters_do_not_share_a_stream() {
        let mut det = LossDetector::new();
        assert!(det.observe_seq("exec", 1).is_none());
        assert!(det.observe_seq("exit", 1).is_none());
        assert!(det.observe_seq("exec", 2).is_none());
    }

    #[test]
    fn global_hole_is_separate_from_per_event() {
        let mut det = LossDetector::new();
        assert!(det.observe_global(7).is_none());
        let loss = det.observe_global(9).expect("hole");
        assert_eq!(loss.kind, SequenceKind::Global);
        assert!(loss.event.is_none());
        assert_eq!(loss.missing, 1);
    }
}
