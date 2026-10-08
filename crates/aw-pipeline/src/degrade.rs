//! Degrade ladder L0–L4 (P2-PIPE-04).
//!
//! Samples come from the caller. This module does not read the host clock, the
//! process table, or the disk. A `None` reading is "not observed" and does not
//! by itself raise a level. Replay never feeds a sample, so it stays at L0.
//!
//! Entering and leaving a level each emit one `Gap { kind: rate_limited,
//! detail: "degrade L<n>" }`. RSS over `hard_rss_bytes` emits `Gap { kind:
//! restart }` once and sets [`DegradeLadder::emergency`]. Collectors are not
//! frozen here: the daemon is outside this crate, and it reads the flag.

use std::collections::HashMap;

use aw_core::{Evidence, GapKind, ProcUid};

use crate::config::DegradeConfig;
use crate::gaps::make_gap;
use crate::output::{FileAccessRec, GapRec, Output};

/// How long CPU must stay over twice the budget before that signal counts.
const CPU_HOLD_NS: u64 = 10_000_000_000;

/// One resource reading, taken at `now_ns` on the pipeline clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DegradeSample {
    /// Monotonic nanoseconds. Not wall time.
    pub now_ns: u64,
    /// Ingress queued events. `None` when the queue was not observed.
    pub queue_fill_num: Option<u64>,
    /// Ingress capacity. Together with `queue_fill_num`, 80% full enters a level.
    pub queue_fill_den: Option<u64>,
    /// Pipeline CPU in millicores (1000 = one core). `None` when not sampled.
    pub cpu_millicores: Option<u64>,
    /// Bytes this session has stored. `None` when not observed.
    pub session_bytes: Option<u64>,
    /// Caller already decided free disk is short. This crate has no byte cutoff:
    /// performance-budget §4 does not name one.
    pub low_disk: bool,
    /// Daemon RSS. `None` when not observed. Over the hard limit is an emergency
    /// stop, not another ladder step.
    pub rss_bytes: Option<u64>,
}

/// L0–L4 plus the emergency-stop flag.
pub struct DegradeLadder {
    level: u8,
    emergency: bool,
    cpu_budget: u64,
    max_session_bytes: Option<u64>,
    hard_rss: Option<u64>,
    l3_keep: u64,
    recover_ns: u64,
    cpu_over_since: Option<u64>,
    clear_since: Option<u64>,
    l3_kept: HashMap<ProcUid, u64>,
    l3_anon: u64,
    suppressed: u64,
}

impl Default for DegradeLadder {
    fn default() -> Self {
        Self::new(DegradeConfig::default())
    }
}

impl DegradeLadder {
    /// Thresholds from `[degrade]`. A zero CPU budget or recover interval becomes
    /// the documented default rather than "never" or "immediately".
    pub fn new(cfg: DegradeConfig) -> Self {
        let recover_secs = if cfg.recover_secs == 0 {
            30
        } else {
            cfg.recover_secs
        };
        let cpu_budget = if cfg.cpu_budget_millicores == 0 {
            150
        } else {
            cfg.cpu_budget_millicores
        };
        Self {
            level: 0,
            emergency: false,
            cpu_budget,
            max_session_bytes: cfg.max_session_bytes,
            hard_rss: cfg.hard_rss_bytes,
            l3_keep: cfg.l3_keep_per_proc,
            recover_ns: recover_secs.saturating_mul(1_000_000_000),
            cpu_over_since: None,
            clear_since: None,
            l3_kept: HashMap::new(),
            l3_anon: 0,
            suppressed: 0,
        }
    }

    /// Current level, 0 through 4. `/health` and `aw doctor` read this.
    pub fn level(&self) -> u8 {
        self.level
    }

    /// `true` after RSS crossed the hard limit, until a later sample is under it.
    pub fn emergency(&self) -> bool {
        self.emergency
    }

    /// Detail rows not kept. Not a byte count.
    pub fn suppressed(&self) -> u64 {
        self.suppressed
    }

    /// Read-only coalesce window. L0 is 1 s. L1 and above are 10 s.
    pub fn coalesce_ms(&self) -> u64 {
        if self.level == 0 {
            1_000
        } else {
            10_000
        }
    }

    /// Network bucket width. L0 is 5 s. L1 and above are 30 s.
    pub fn bucket_secs(&self) -> u64 {
        if self.level == 0 {
            5
        } else {
            30
        }
    }

    /// Apply one sample. At most one step up or one step down.
    ///
    /// Returns whether the level changed, so the caller can widen buckets.
    /// Gaps are appended to `out`.
    pub fn observe(&mut self, sample: DegradeSample, out: &mut Output) -> bool {
        self.note_rss(sample.rss_bytes, out, sample.now_ns);
        let trigger = self.triggered(&sample);
        let before = self.level;
        if trigger {
            self.clear_since = None;
            if self.level < 4 {
                self.level += 1;
                self.reset_keep();
                out.gaps.push(level_gap(self.level, sample.now_ns));
            }
        } else if self.level > 0 {
            let since = *self.clear_since.get_or_insert(sample.now_ns);
            if sample.now_ns.saturating_sub(since) >= self.recover_ns {
                self.level -= 1;
                self.clear_since = Some(sample.now_ns);
                self.reset_keep();
                out.gaps.push(level_gap(self.level, sample.now_ns));
            }
        }
        self.level != before
    }

    /// Drop detail rows the current level does not keep.
    ///
    /// Only the suffix that starts at `before` is considered, so rows already
    /// emitted at a milder level stay. Protected rows are never removed.
    pub fn retain_new_files(&mut self, rows: &mut Vec<FileAccessRec>, before: usize) {
        if self.level < 2 || before >= rows.len() {
            return;
        }
        let mut index = before;
        while index < rows.len() {
            if self.keep_row(&rows[index]) {
                index += 1;
            } else {
                rows.remove(index);
                self.suppressed = self.suppressed.saturating_add(1);
            }
        }
    }

    fn reset_keep(&mut self) {
        self.l3_kept.clear();
        self.l3_anon = 0;
    }

    fn keep_row(&mut self, row: &FileAccessRec) -> bool {
        if crate::limit::file_row_protected(row) {
            return true;
        }
        if self.level >= 2 && crate::limit::is_ordinary_read(row) {
            return false;
        }
        if self.level >= 4 {
            return false;
        }
        if self.level == 3 {
            return self.within_cap(row);
        }
        true
    }

    fn within_cap(&mut self, row: &FileAccessRec) -> bool {
        let cap = self.l3_keep;
        match row.proc_uid {
            Some(uid) => {
                let count = self.l3_kept.entry(uid).or_insert(0);
                if *count >= cap {
                    return false;
                }
                *count = count.saturating_add(1);
                true
            }
            None => {
                if self.l3_anon >= cap {
                    return false;
                }
                self.l3_anon = self.l3_anon.saturating_add(1);
                true
            }
        }
    }

    fn triggered(&mut self, sample: &DegradeSample) -> bool {
        let cpu = self.cpu_sustained(sample);
        let queue = queue_high(sample);
        let volume = self.volume_high(sample.session_bytes);
        queue || volume || sample.low_disk || cpu
    }

    fn cpu_sustained(&mut self, sample: &DegradeSample) -> bool {
        let Some(cpu) = sample.cpu_millicores else {
            self.cpu_over_since = None;
            return false;
        };
        if cpu <= self.cpu_budget.saturating_mul(2) {
            self.cpu_over_since = None;
            return false;
        }
        let since = *self.cpu_over_since.get_or_insert(sample.now_ns);
        sample.now_ns.saturating_sub(since) >= CPU_HOLD_NS
    }

    fn volume_high(&self, bytes: Option<u64>) -> bool {
        match (bytes, self.max_session_bytes) {
            (Some(have), Some(max)) => have > max,
            _ => false,
        }
    }

    fn note_rss(&mut self, rss: Option<u64>, out: &mut Output, now_ns: u64) {
        let Some(limit) = self.hard_rss else {
            return;
        };
        let Some(rss) = rss else {
            return;
        };
        if rss > limit {
            if !self.emergency {
                self.emergency = true;
                out.gaps.push(restart_gap(now_ns));
            }
        } else if self.emergency {
            self.emergency = false;
        }
    }
}

fn queue_high(sample: &DegradeSample) -> bool {
    let (Some(num), Some(den)) = (sample.queue_fill_num, sample.queue_fill_den) else {
        return false;
    };
    if den == 0 {
        return false;
    }
    u128::from(num).saturating_mul(100) >= u128::from(den).saturating_mul(80)
}

fn level_gap(level: u8, now_ns: u64) -> GapRec {
    make_gap(
        "pipeline",
        GapKind::RateLimited,
        vec!["degrade".to_owned()],
        now_ns,
        now_ns,
        Some(1),
        Some(format!("degrade L{level}")),
        Evidence::E1,
    )
}

fn restart_gap(now_ns: u64) -> GapRec {
    make_gap(
        "pipeline",
        GapKind::Restart,
        vec!["collector".to_owned()],
        now_ns,
        now_ns,
        Some(1),
        Some("hard_rss_bytes".to_owned()),
        Evidence::E1,
    )
}
