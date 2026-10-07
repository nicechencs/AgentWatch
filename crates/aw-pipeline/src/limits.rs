//! Per-process token buckets and the L1 degrade step.
//!
//! pipeline.md §5: each process has its own bucket per event class. Events over
//! the limit are counted and become [`aw_core::GapKind::RateLimited`]. They are
//! not forwarded. Other processes are not affected.
//!
//! Byte aggregation is not this stage. A dropped `NetSend` / `NetRecv` is an
//! event this stage did not forward; the byte counter on the event is not
//! rewritten and is not replaced with zero.
//!
//! Queue occupancy over 80% (pipeline.md §2) enters L1. P1 drops individual
//! `NetSend` and `NetRecv` events and keeps a counter. `ProcessStart`,
//! `FileOpen`, `NetConnect`, and `Dns*` are not dropped by L1.
//!
//! Time is the event's `ts_mono_ns` (or [`crate::stage::Stage::tick`]). The
//! buckets do not read the host clock.

use std::collections::HashMap;

use aw_core::{EventKind, ProcUid, RawEvent};

use crate::config::{LimitsConfig, RateLimit};
use crate::gaps::{self, GapMerger};
use crate::output::{GapRec, Output};

/// Ingress occupancy at or above this fraction of capacity is L1.
/// pipeline.md §2 says "over 80%". The boundary is included: 80% is already
/// the degrade line the budget describes as exceeded-or-at.
pub const DEGRADE_FILL_NUM: u64 = 8;
pub const DEGRADE_FILL_DEN: u64 = 10;

/// One class the limit table names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitClass {
    /// `process_start`.
    ProcessStart,
    /// `file_open`.
    FileOpen,
    /// `net_connect`.
    NetConnect,
    /// `dns_query` and `dns_answer`.
    Dns,
    /// `agent_rpc`.
    AgentRpc,
    /// `ipc_transfer`. Unlimited unless a rate was configured.
    IpcTransfer,
    /// `file_read` and `file_write`. Unlimited unless a rate was configured.
    FileRw,
}

/// Why an event was not forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hold {
    /// The process's bucket for this class was empty.
    RateLimited,
    /// L1 is on and this event is a `NetSend` or `NetRecv`.
    Degraded,
}

/// Per-process limiters plus the L1 counter.
#[derive(Debug)]
pub struct Limiter {
    limits: LimitsConfig,
    buckets: HashMap<(ProcUid, LimitClass), Bucket>,
    /// `NetSend` events not forwarded while L1 is active.
    net_send_dropped: u64,
    /// `NetRecv` events not forwarded while L1 is active.
    net_recv_dropped: u64,
    pending: GapMerger,
    /// Rate-limit gaps whose 5 s window already closed. The merger holds only
    /// the newest bucket per collector and kind, so a closed one waits here
    /// until [`Self::take_gaps`].
    retained: Vec<GapRec>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: u64,
    /// Last refill, monotonic nanoseconds.
    updated_ns: u64,
    per_sec: u64,
    burst: u64,
}

impl Limiter {
    /// Buckets start empty of state. The first event for a process fills the
    /// burst, then spends one token, using that event's timestamp.
    pub fn new(limits: LimitsConfig) -> Self {
        Self {
            limits,
            buckets: HashMap::new(),
            net_send_dropped: 0,
            net_recv_dropped: 0,
            pending: GapMerger::new(),
            retained: Vec::new(),
        }
    }

    /// `NetSend` events held back by L1. Not a byte count.
    pub fn net_send_dropped(&self) -> u64 {
        self.net_send_dropped
    }

    /// `NetRecv` events held back by L1. Not a byte count.
    pub fn net_recv_dropped(&self) -> u64 {
        self.net_recv_dropped
    }

    /// `true` when `queued / capacity` is at least 80%.
    ///
    /// A zero capacity is treated as full: there is no room. The check uses
    /// integer math (`queued * 10 >= capacity * 8`) so it does not depend on
    /// floating point.
    pub fn queue_over_threshold(queued: u64, capacity: u64) -> bool {
        if capacity == 0 {
            return true;
        }
        queued.saturating_mul(DEGRADE_FILL_DEN) >= capacity.saturating_mul(DEGRADE_FILL_NUM)
    }

    /// Decide whether `event` is forwarded.
    ///
    /// `degrade` is the L1 flag from the queue-occupancy check. A held event is
    /// not forwarded. Its rate-limit gap is merged into the pending merger;
    /// call [`Self::take_gaps`] to drain closed gaps. L1 drops are only counted.
    pub fn admit(&mut self, event: &RawEvent, degrade: bool) -> Result<(), Hold> {
        if degrade && is_l1_drop(&event.kind) {
            match &event.kind {
                EventKind::NetSend(_) => {
                    self.net_send_dropped = self.net_send_dropped.saturating_add(1);
                }
                EventKind::NetRecv(_) => {
                    self.net_recv_dropped = self.net_recv_dropped.saturating_add(1);
                }
                _ => {}
            }
            return Err(Hold::Degraded);
        }
        let Some(class) = class_of(&event.kind) else {
            return Ok(());
        };
        let Some(limit) = self.limit_for(class) else {
            // Unlimited class (`file_rw`, `ipc_transfer` by default).
            return Ok(());
        };
        let Some(proc) = event.proc.as_ref() else {
            // No process to key the bucket. Do not invent a shared bucket, and
            // do not drop the event: the limit is per process.
            return Ok(());
        };
        let now = event.ts_mono_ns;
        let key = (proc.uid, class);
        let bucket = self.buckets.entry(key).or_insert_with(|| Bucket {
            tokens: limit.burst,
            updated_ns: now,
            per_sec: limit.per_sec,
            burst: limit.burst,
        });
        bucket.refill(now);
        if bucket.tokens == 0 {
            let evidence = event.evidence.clone();
            let session = event.session_id;
            let gap = gaps::rate_limited_gap(
                proc,
                session,
                event.kind.kind_name(),
                now,
                now,
                1,
                evidence,
            );
            // Same process, same kind, inside 5 s: one gap, summed count.
            // A closed bucket (the window elapsed) is left for `take_gaps`.
            // Storing it here would need a side channel; `observe` returns it.
            if let Some(closed) = self.pending.observe(gap) {
                self.retained.push(closed);
            }
            return Err(Hold::RateLimited);
        }
        bucket.tokens -= 1;
        Ok(())
    }

    /// Gaps whose merge window has closed, plus any still open.
    pub fn take_gaps(&mut self) -> Vec<GapRec> {
        let mut out = std::mem::take(&mut self.retained);
        out.extend(self.pending.flush());
        out
    }

    /// Push closed rate-limit gaps onto `out`, merged.
    pub fn drain_into(&mut self, out: &mut Output) {
        out.gaps.extend(self.take_gaps());
    }

    fn limit_for(&self, class: LimitClass) -> Option<RateLimit> {
        match class {
            LimitClass::ProcessStart => Some(self.limits.process_start),
            LimitClass::FileOpen => Some(self.limits.file_open),
            LimitClass::NetConnect => Some(self.limits.net_connect),
            LimitClass::Dns => Some(self.limits.dns),
            LimitClass::AgentRpc => Some(self.limits.agent_rpc),
            LimitClass::IpcTransfer => self.limits.ipc_transfer,
            LimitClass::FileRw => self.limits.file_rw,
        }
    }
}

impl Bucket {
    fn refill(&mut self, now_ns: u64) {
        if now_ns <= self.updated_ns {
            // Time did not move forward. Tokens stay where they are.
            // A rewind does not grant a fresh burst.
            return;
        }
        let elapsed = now_ns - self.updated_ns;
        self.updated_ns = now_ns;
        if self.per_sec == 0 || self.burst == 0 {
            return;
        }
        // tokens += elapsed_ns * per_sec / 1e9, capped at burst.
        // Split so the multiply cannot overflow a u64 at large elapsed.
        let whole_secs = elapsed / 1_000_000_000;
        let rem_ns = elapsed % 1_000_000_000;
        let from_secs = whole_secs.saturating_mul(self.per_sec);
        let from_rem = rem_ns.saturating_mul(self.per_sec) / 1_000_000_000;
        let add = from_secs.saturating_add(from_rem);
        self.tokens = self.tokens.saturating_add(add).min(self.burst);
    }
}

fn class_of(kind: &EventKind) -> Option<LimitClass> {
    match kind {
        EventKind::ProcessStart(_) => Some(LimitClass::ProcessStart),
        EventKind::FileOpen(_) => Some(LimitClass::FileOpen),
        EventKind::FileRead(_) | EventKind::FileWrite(_) => Some(LimitClass::FileRw),
        EventKind::NetConnect(_) => Some(LimitClass::NetConnect),
        EventKind::DnsQuery(_) | EventKind::DnsAnswer(_) => Some(LimitClass::Dns),
        EventKind::IpcTransfer(_) => Some(LimitClass::IpcTransfer),
        EventKind::AgentRpc(_) => Some(LimitClass::AgentRpc),
        _ => None,
    }
}

/// L1 drops only the high-frequency byte events the budget names.
/// `NetSend` and `NetRecv` exist on [`EventKind`]. File read/write are not
/// dropped here: the card's P1 step is the net pair, and byte aggregation is
/// another stage.
fn is_l1_drop(kind: &EventKind) -> bool {
    matches!(kind, EventKind::NetSend(_) | EventKind::NetRecv(_))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::PipelineConfig;
    use aw_core::{
        Evidence, ProcRef, ProcUid, ProcessStart, RawEvent, RawEventParts, Source, StartHow,
    };

    fn start(seq: u64, pid: u32, uid: u64, ts: u64) -> RawEvent {
        RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns: ts,
            ts_wall_ns: 1,
            session_id: None,
            proc: Some(ProcRef {
                uid: ProcUid(uid),
                pid,
                tid: None,
            }),
            source: Source::new("test/limit"),
            evidence: Evidence::E1,
            kind: EventKind::ProcessStart(ProcessStart::new(
                1,
                None,
                1,
                None,
                None,
                None,
                None,
                StartHow::Spawn,
                None,
                None,
            )),
        })
        .expect("process_start")
    }

    #[test]
    fn one_process_at_5000_per_second_is_limited_the_other_is_not() {
        let mut limiter = Limiter::new(PipelineConfig::default().limits);
        let mut held = 0u64;
        let mut passed = 0u64;
        // Burst is 1000 and the rate is 200/s. All 5000 share one timestamp,
        // so nothing refills. 1000 pass, 4000 are counted as rate_limited.
        for i in 0..5000 {
            match limiter.admit(&start(i, 10, 1, 1_000), false) {
                Ok(()) => passed += 1,
                Err(Hold::RateLimited) => held += 1,
                Err(Hold::Degraded) => panic!("L1 is off"),
            }
        }
        assert_eq!(passed, 1000);
        assert_eq!(held, 4000);
        let mut other_passed = 0u64;
        for i in 0..500 {
            if limiter
                .admit(&start(10_000 + i, 11, 2, 1_000), false)
                .is_ok()
            {
                other_passed += 1;
            }
        }
        assert_eq!(other_passed, 500, "a second process has its own burst");
        let gaps = limiter.take_gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].gap_kind, aw_core::GapKind::RateLimited);
        assert_eq!(gaps[0].count, Some(4000));
        assert_eq!(gaps[0].proc.as_ref().map(|p| p.uid), Some(ProcUid(1)));
    }

    #[test]
    fn refill_uses_event_time_not_the_host_clock() {
        let mut limiter = Limiter::new(PipelineConfig::default().limits);
        // Spend the burst of 1000 at t = 0.
        for i in 0..1000 {
            assert!(limiter.admit(&start(i, 10, 1, 0), false).is_ok());
        }
        assert!(limiter.admit(&start(1000, 10, 1, 0), false).is_err());
        // One second later on the event clock: 200 tokens come back.
        let mut passed = 0u64;
        for i in 0..200 {
            if limiter
                .admit(&start(2000 + i, 10, 1, 1_000_000_000), false)
                .is_ok()
            {
                passed += 1;
            }
        }
        assert_eq!(passed, 200);
        assert!(limiter
            .admit(&start(3000, 10, 1, 1_000_000_000), false)
            .is_err());
    }

    #[test]
    fn eighty_percent_is_the_degrade_line() {
        assert!(!Limiter::queue_over_threshold(79, 100));
        assert!(Limiter::queue_over_threshold(80, 100));
        assert!(Limiter::queue_over_threshold(81, 100));
        assert!(Limiter::queue_over_threshold(0, 0));
    }
}
