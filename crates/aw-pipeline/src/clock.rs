//! Clocks the pipeline uses for time windows.
//!
//! [`aw_core::time::Clock`] only converts monotonic nanoseconds to wall time. It has
//! no `now()`. This module adds a monotonic position on top of that trait and does
//! not change `aw-core`.
//!
//! Production reads [`std::time::Instant`] and nothing else. Wall time stays
//! [`None`]: this card does not call `SystemTime`, and an unknown wall time is not
//! the unix epoch.
//!
//! Replay advances only from each event's `ts_mono_ns`. That path must not read
//! [`Instant`] or the wall clock, so a replay result does not depend on when it ran.

use std::time::Instant;

use aw_core::time::{Clock, WallTime};

/// Monotonic position plus [`Clock`] conversion.
///
/// Stages call [`PipelineClock::now_ns`] for windows. They do not read the host clock.
pub trait PipelineClock: Clock {
    /// Current monotonic nanoseconds in this clock's domain.
    fn now_ns(&self) -> u64;
}

/// Production clock. Origin is one [`Instant`]; wall time is unknown.
///
/// `mono_to_wall` is always [`None`]. A wall reading was not observed.
pub struct InstantClock {
    origin: Instant,
}

impl InstantClock {
    /// Start at this instant. Later `now_ns` values are elapsed nanoseconds.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for InstantClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for InstantClock {
    fn mono_to_wall(&self, _mono_ns: u64) -> Option<WallTime> {
        None
    }

    fn wall_to_mono(&self, _wall: WallTime) -> Option<u64> {
        None
    }
}

impl PipelineClock for InstantClock {
    fn now_ns(&self) -> u64 {
        let elapsed = self.origin.elapsed();
        u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
    }
}

/// Replay clock. The position moves only when the caller sets it from an event.
///
/// No [`Instant`] and no wall clock. `mono_to_wall` is [`None`] because the event's
/// `ts_wall_ns` is a field on the event, not a conversion this clock invents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayClock {
    now_ns: u64,
}

impl ReplayClock {
    /// Position `0` until the first event moves it.
    pub const fn new() -> Self {
        Self { now_ns: 0 }
    }

    /// Move the virtual clock to `ts_mono_ns`.
    ///
    /// A timestamp behind the current position is kept as-is. Replay walks events in
    /// input order; it does not clamp, and it does not read the host clock to "fix" it.
    pub fn advance_to(&mut self, ts_mono_ns: u64) {
        self.now_ns = ts_mono_ns;
    }
}

impl Default for ReplayClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ReplayClock {
    fn mono_to_wall(&self, _mono_ns: u64) -> Option<WallTime> {
        None
    }

    fn wall_to_mono(&self, _wall: WallTime) -> Option<u64> {
        None
    }
}

impl PipelineClock for ReplayClock {
    fn now_ns(&self) -> u64 {
        self.now_ns
    }
}
