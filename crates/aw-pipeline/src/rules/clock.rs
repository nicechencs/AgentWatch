//! The clock the matcher reads.
//!
//! [`RuleClock`] is the only time source the engine uses, so a replay advances a
//! [`VirtualClock`] instead of reading the host. Two runs of the same input
//! produce the same findings because nothing else can move.

/// Monotonic nanoseconds, supplied by the caller.
pub trait RuleClock {
    /// The current position, in nanoseconds.
    fn now_ns(&self) -> u64;
}

/// A clock the caller moves by hand.
///
/// Replay and tests set the position from each record's own timestamp. The
/// clock never reads [`std::time::Instant`] or the wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualClock {
    now_ns: u64,
}

impl VirtualClock {
    /// Position `0`.
    pub const fn new() -> Self {
        Self { now_ns: 0 }
    }

    /// Move to `ts_ns`. A value behind the current position is kept as given:
    /// the engine does not clamp, and it does not consult the host clock.
    pub fn advance_to(&mut self, ts_ns: u64) {
        self.now_ns = ts_ns;
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleClock for VirtualClock {
    fn now_ns(&self) -> u64 {
        self.now_ns
    }
}

impl RuleClock for crate::clock::ReplayClock {
    fn now_ns(&self) -> u64 {
        crate::clock::PipelineClock::now_ns(self)
    }
}

impl RuleClock for crate::clock::InstantClock {
    fn now_ns(&self) -> u64 {
        crate::clock::PipelineClock::now_ns(self)
    }
}
