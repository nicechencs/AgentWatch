//! `ProcUid → ProcInfo` cache used by scope and later enrich stages.
//!
//! The cache does not read `/proc` or any platform API. A daemon inserts snapshots
//! through [`ProcCache::insert`] / [`ProcCache::note_exit`]. After exit an entry
//! stays for [`ProcCacheConfig::linger_secs`] so a late event can still resolve.
//! At capacity only exited entries are evicted, least-recently used first. A live
//! process is never removed to make room; that refusal is counted.

use std::collections::{HashMap, VecDeque};

use aw_core::{ProcUid, Redacted};

/// Default retention after exit. process-tracking §8 says five minutes for
/// inactive sessions; this card's default is 60 seconds.
pub const DEFAULT_LINGER_SECS: u64 = 60;

/// Default entry cap. process-tracking §8 names 65536.
pub const DEFAULT_CAPACITY: usize = 65_536;

/// How long exited rows stay, and how many rows fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcCacheConfig {
    /// Seconds to keep an exited process. Default [`DEFAULT_LINGER_SECS`].
    pub linger_secs: u64,
    /// Maximum entries. Default [`DEFAULT_CAPACITY`].
    pub capacity: usize,
}

impl Default for ProcCacheConfig {
    fn default() -> Self {
        Self {
            linger_secs: DEFAULT_LINGER_SECS,
            capacity: DEFAULT_CAPACITY,
        }
    }
}

/// One cached process.
///
/// `argv` is kept so a later enrich step can read it. This struct does not
/// derive `Debug`: a derived impl would print argv. [`ProcInfo::summary`] is the
/// log form and omits argv, cwd, and exe text.
pub struct ProcInfo {
    /// OS pid at the observation.
    pub pid: u32,
    /// Parent pid, when known. `None` is unknown, not `0`.
    pub ppid: Option<u32>,
    /// Parent [`ProcUid`], when known.
    pub parent_uid: Option<ProcUid>,
    /// Executable path, when known. Not logged from this struct.
    pub exe: Option<String>,
    /// Argv, when known. Not logged and not written into [`crate::ProcessRec`].
    pub argv: Option<Vec<Redacted>>,
    /// Working directory, when known.
    pub cwd: Option<String>,
    /// Process start, monotonic nanoseconds, when known.
    pub start_ns: Option<u64>,
    /// Exit time, monotonic nanoseconds. `None` while the process is live.
    pub exit_ns: Option<u64>,
    /// Exit code, when a `ProcessExit` reported one.
    pub exit_code: Option<i32>,
    /// Exit signal, when a `ProcessExit` reported one.
    pub exit_signal: Option<i32>,
    /// Agent name from a later adapter. `None` until then.
    pub agent_hint: Option<String>,
    /// Monotonic time of the last lookup or update. Used for LRU among exited rows.
    last_used_ns: u64,
}

impl ProcInfo {
    /// A live process with only the fields the caller actually has.
    pub fn live(pid: u32, seen_ns: u64) -> Self {
        Self {
            pid,
            ppid: None,
            parent_uid: None,
            exe: None,
            argv: None,
            cwd: None,
            start_ns: None,
            exit_ns: None,
            exit_code: None,
            exit_signal: None,
            agent_hint: None,
            last_used_ns: seen_ns,
        }
    }

    /// `true` after [`ProcCache::note_exit`].
    pub fn has_exited(&self) -> bool {
        self.exit_ns.is_some()
    }
}

/// Process table keyed by [`ProcUid`].
///
/// Same pid with a different [`ProcUid`] is a different process. Lookups by pid
/// return the newest live entry, then the newest exited one, and never cross
/// those identities.
pub struct ProcCache {
    cfg: ProcCacheConfig,
    by_uid: HashMap<ProcUid, ProcInfo>,
    /// Newest uid for a pid is at the back. Dead uids are skipped on lookup.
    by_pid: HashMap<u32, VecDeque<ProcUid>>,
    /// Times an insert was refused because every resident entry was still live.
    refused_live: u64,
}

impl ProcCache {
    /// Cache with explicit limits.
    pub fn new(cfg: ProcCacheConfig) -> Self {
        Self {
            cfg,
            by_uid: HashMap::new(),
            by_pid: HashMap::new(),
            refused_live: 0,
        }
    }

    /// Inserts refused because evicting a live process is not allowed.
    pub fn refused_live(&self) -> u64 {
        self.refused_live
    }

    /// Entries currently stored, including ones waiting out their linger window.
    pub fn len(&self) -> usize {
        self.by_uid.len()
    }

    /// No entries.
    pub fn is_empty(&self) -> bool {
        self.by_uid.is_empty()
    }

    /// Configured linger, in monotonic nanoseconds.
    pub fn linger_ns(&self) -> u64 {
        self.cfg.linger_secs.saturating_mul(1_000_000_000)
    }

    /// Borrow the row for `uid`, and mark it used at `now_ns`.
    pub fn get_mut(&mut self, uid: ProcUid, now_ns: u64) -> Option<&mut ProcInfo> {
        let info = self.by_uid.get_mut(&uid)?;
        info.last_used_ns = now_ns;
        Some(info)
    }

    /// Borrow the row for `uid` without changing LRU order.
    pub fn get(&self, uid: ProcUid) -> Option<&ProcInfo> {
        self.by_uid.get(&uid)
    }

    /// Resolve `pid` to the current [`ProcUid`].
    ///
    /// A live row wins over an exited one. Two exited rows keep the one with the
    /// later `last_used_ns`. A pid whose only rows have different start times
    /// still returns just one uid: the live one, or the most recently used exit.
    pub fn resolve_pid(&mut self, pid: u32, now_ns: u64) -> Option<ProcUid> {
        let chain = self.by_pid.get(&pid)?;
        let mut best_live: Option<ProcUid> = None;
        let mut best_exited: Option<(ProcUid, u64)> = None;
        for uid in chain {
            let Some(info) = self.by_uid.get(uid) else {
                continue;
            };
            if info.exit_ns.is_none() {
                best_live = Some(*uid);
            } else if best_exited.is_none_or(|(_, used)| info.last_used_ns >= used) {
                best_exited = Some((*uid, info.last_used_ns));
            }
        }
        let chosen = best_live.or_else(|| best_exited.map(|(uid, _)| uid))?;
        if let Some(info) = self.by_uid.get_mut(&chosen) {
            info.last_used_ns = now_ns;
        }
        Some(chosen)
    }

    /// Insert or replace `uid`.
    ///
    /// Returns `false` when the cache is full of live processes and `uid` is new.
    /// The refusal is counted. An update of an existing uid always succeeds.
    pub fn insert(&mut self, uid: ProcUid, mut info: ProcInfo) -> bool {
        if self.by_uid.contains_key(&uid) {
            if let Some(prev) = self.by_uid.get(&uid) {
                if prev.pid != info.pid {
                    self.unlink_pid(prev.pid, uid);
                    self.link_pid(info.pid, uid);
                }
            }
            self.by_uid.insert(uid, info);
            return true;
        }
        if self.by_uid.len() >= self.cfg.capacity && !self.evict_one_exited() {
            self.refused_live = self.refused_live.saturating_add(1);
            return false;
        }
        info.last_used_ns = info.last_used_ns.max(info.start_ns.unwrap_or(0));
        self.link_pid(info.pid, uid);
        self.by_uid.insert(uid, info);
        true
    }

    /// Mark `uid` exited at `exit_ns`. Missing fields stay `None`.
    ///
    /// Returns `false` when `uid` was not cached.
    pub fn note_exit(
        &mut self,
        uid: ProcUid,
        exit_ns: u64,
        exit_code: Option<i32>,
        exit_signal: Option<i32>,
    ) -> bool {
        let Some(info) = self.by_uid.get_mut(&uid) else {
            return false;
        };
        info.exit_ns = Some(exit_ns);
        info.exit_code = exit_code;
        info.exit_signal = exit_signal;
        info.last_used_ns = exit_ns;
        true
    }

    /// Drop exited rows whose linger window has closed at `now_ns`.
    pub fn tick(&mut self, now_ns: u64) {
        let linger = self.linger_ns();
        let expired: Vec<ProcUid> = self
            .by_uid
            .iter()
            .filter_map(|(uid, info)| {
                let exit_ns = info.exit_ns?;
                let due = exit_ns.saturating_add(linger);
                (now_ns >= due).then_some(*uid)
            })
            .collect();
        for uid in expired {
            self.remove(uid);
        }
    }

    fn evict_one_exited(&mut self) -> bool {
        let victim = self
            .by_uid
            .iter()
            .filter(|(_, info)| info.exit_ns.is_some())
            .min_by_key(|(_, info)| info.last_used_ns)
            .map(|(uid, _)| *uid);
        let Some(uid) = victim else {
            return false;
        };
        self.remove(uid);
        true
    }

    fn remove(&mut self, uid: ProcUid) {
        if let Some(info) = self.by_uid.remove(&uid) {
            self.unlink_pid(info.pid, uid);
        }
    }

    fn link_pid(&mut self, pid: u32, uid: ProcUid) {
        let chain = self.by_pid.entry(pid).or_default();
        if !chain.contains(&uid) {
            chain.push_back(uid);
        }
    }

    fn unlink_pid(&mut self, pid: u32, uid: ProcUid) {
        let Some(chain) = self.by_pid.get_mut(&pid) else {
            return;
        };
        chain.retain(|existing| *existing != uid);
        if chain.is_empty() {
            self.by_pid.remove(&pid);
        }
    }
}

impl Default for ProcCache {
    fn default() -> Self {
        Self::new(ProcCacheConfig::default())
    }
}
