//! Timestamps and the clock trait collectors implement.
//!
//! A timestamp has two readings:
//!
//! * `mono_ns` — nanoseconds on a monotonic clock. This is the ordering key.
//! * `wall` — civil time, **if the collector has one**. Unknown wall time is
//!   [`None`]. It is never `0`, the unix epoch, or any other sentinel.
//!
//! Converting between the two is a method on [`Clock`], not a constant offset.
//! Linux boot time, Windows FILETIME and macOS `clock_gettime` do not share an
//! epoch, so a hardcoded offset would be a lie on every platform but one.
//!
//! Nothing in this module reads the host clock. [`ManualClock`] only plays back
//! numbers the test handed it.

/// Nanoseconds since 1970-01-01T00:00:00Z.
///
/// Distinct from [`Timestamp::mono_ns`], which is not on the unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WallTime {
    /// Whole seconds since the unix epoch. May be before 1970 (`i64` negative).
    pub secs: i64,
    /// Sub-second nanoseconds, in `0..1_000_000_000`.
    pub nanos: u32,
}

impl WallTime {
    /// Build a wall time, or `None` when `nanos` is not a fraction of a second.
    ///
    /// A bad fraction is a caller bug, not "unknown time". Unknown time stays
    /// `Option<WallTime>::None` and never reaches this constructor.
    pub const fn new(secs: i64, nanos: u32) -> Option<Self> {
        if nanos >= 1_000_000_000 {
            return None;
        }
        Some(Self { secs, nanos })
    }
}

/// One instant, as far as a collector could read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Timestamp {
    /// Monotonic nanoseconds. The epoch is the collector's clock, not 1970.
    pub mono_ns: u64,
    /// Wall clock at the same instant, or `None` when the collector has no
    /// wall reading. Absence is not encoded as zero.
    pub wall: Option<WallTime>,
}

impl Timestamp {
    /// Monotonic reading only. Wall time is explicitly unknown.
    pub const fn mono(mono_ns: u64) -> Self {
        Self {
            mono_ns,
            wall: None,
        }
    }

    /// Both readings. `wall` must already be a validated [`WallTime`].
    pub const fn with_wall(mono_ns: u64, wall: WallTime) -> Self {
        Self {
            mono_ns,
            wall: Some(wall),
        }
    }
}

/// Platform clock, as the collector sees it.
///
/// Implementors live in the platform crates. This crate only defines the
/// conversion. `mono_to_wall` returns `None` when that monotonic reading has no
/// paired wall time (clock stepped, reading not taken, offset not known yet).
/// It must not substitute the unix epoch.
pub trait Clock {
    /// Wall time corresponding to `mono_ns`, if this clock can name one.
    fn mono_to_wall(&self, mono_ns: u64) -> Option<WallTime>;

    /// Monotonic nanoseconds corresponding to `wall`, if this clock can name one.
    fn wall_to_mono(&self, wall: WallTime) -> Option<u64>;
}

/// Test double. Replays a fixed offset and nothing else.
///
/// `offset_ns` is "wall nanoseconds minus `mono_ns`" for this fake only. A
/// production collector must not assume its own epoch works that way; that is
/// why the conversion stays on the trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManualClock {
    /// Added to `mono_ns` to reach unix-epoch nanoseconds. May be negative.
    offset_ns: i128,
    /// When false, both conversions report "not available" instead of guessing.
    wall_known: bool,
}

impl ManualClock {
    /// A clock whose wall time is `mono_ns + offset_ns` on the unix epoch.
    pub const fn with_offset(offset_ns: i128) -> Self {
        Self {
            offset_ns,
            wall_known: true,
        }
    }

    /// A clock that has monotonic time and no wall time.
    pub const fn without_wall() -> Self {
        Self {
            offset_ns: 0,
            wall_known: false,
        }
    }

    /// Read a timestamp the way a collector would: mono always, wall only when
    /// this clock has one.
    pub fn timestamp(&self, mono_ns: u64) -> Timestamp {
        Timestamp {
            mono_ns,
            wall: self.mono_to_wall(mono_ns),
        }
    }
}

impl Clock for ManualClock {
    fn mono_to_wall(&self, mono_ns: u64) -> Option<WallTime> {
        if !self.wall_known {
            return None;
        }
        let wall_ns = self.offset_ns.checked_add(i128::from(mono_ns))?;
        let secs = wall_ns.div_euclid(1_000_000_000);
        let nanos = wall_ns.rem_euclid(1_000_000_000);
        let secs = i64::try_from(secs).ok()?;
        let nanos = u32::try_from(nanos).ok()?;
        WallTime::new(secs, nanos)
    }

    fn wall_to_mono(&self, wall: WallTime) -> Option<u64> {
        if !self.wall_known {
            return None;
        }
        let wall_ns = i128::from(wall.secs)
            .checked_mul(1_000_000_000)?
            .checked_add(i128::from(wall.nanos))?;
        let mono = wall_ns.checked_sub(self.offset_ns)?;
        u64::try_from(mono).ok()
    }
}

#[cfg(test)]
mod timestamp {
    use super::{Clock, ManualClock, Timestamp, WallTime};

    #[test]
    fn unknown_wall_is_none_not_epoch() {
        let clock = ManualClock::without_wall();
        let stamp = clock.timestamp(50);
        assert_eq!(stamp.mono_ns, 50);
        assert_eq!(stamp.wall, None);
        assert_eq!(clock.mono_to_wall(50), None);
        assert_eq!(
            clock.wall_to_mono(WallTime { secs: 0, nanos: 0 }),
            None,
            "no wall clock does not treat the unix epoch as a real reading"
        );
    }

    #[test]
    fn conversion_uses_the_trait_offset_not_a_fixed_epoch() {
        // Two collectors, two epochs. The same mono reading is not the same wall.
        let early = ManualClock::with_offset(1_700_000_000_000_000_000);
        let late = ManualClock::with_offset(1_800_000_000_000_000_000);
        let mono = 25_000_000_u64;
        let wall_early = early.mono_to_wall(mono);
        let wall_late = late.mono_to_wall(mono);
        assert_ne!(wall_early, wall_late);

        let Some(wall) = wall_early else {
            panic!("this fake has a wall clock");
        };
        assert_eq!(early.wall_to_mono(wall), Some(mono));
        assert_ne!(late.wall_to_mono(wall), Some(mono));
    }

    #[test]
    fn trait_object_dispatches_without_reading_the_host_clock() {
        let clock = ManualClock::with_offset(5_000_000_000);
        let as_trait: &dyn Clock = &clock;
        let wall = as_trait.mono_to_wall(1_500_000_000);
        assert_eq!(wall, WallTime::new(6, 500_000_000));
        let Some(wall) = wall else {
            panic!("offset clock returned a wall time above");
        };
        let stamp = Timestamp::with_wall(1_500_000_000, wall);
        assert_eq!(stamp.wall.map(|w| w.secs), Some(6));
    }

    #[test]
    fn nanos_that_are_not_a_fraction_are_rejected() {
        assert!(WallTime::new(1, 1_000_000_000).is_none());
        assert_eq!(WallTime::new(-1, 0).map(|w| w.secs), Some(-1));
    }
}
