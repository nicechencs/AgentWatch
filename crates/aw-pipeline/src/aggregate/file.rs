//! File-access aggregation (P2-PIPE-01).
//!
//! One open handle becomes one [`FileAccessAcc`], keyed by `(ProcUid, handle)`.
//! A platform with no handle (macOS ES) is keyed by `(ProcUid, path)` instead.
//! The row is emitted on `FileClose`, on process exit, or when the handle has
//! been open for `aggregate.file_flush_secs` (`partial = true`, then it keeps
//! accumulating).
//!
//! Read-only opens of the same path inside `aggregate.coalesce_window_ms` merge
//! into the open row and increment `opens`. `FileCreate`, `FileDelete`,
//! `FileRename`, and an exec open are not aggregated: each becomes its own row.
//!
//! This module does not open files, does not stat them, and does not fill a
//! missing byte count with `0`. A read event whose `bytes` is `None` (macOS ES)
//! leaves `bytes_read` as `None` and copies the event's `field_evidence`.
//! Record evidence is the weakest level among the events that built the row.
//!
//! Sensitive labels and rate limits are not applied here.

use std::collections::{BTreeMap, HashMap, VecDeque};

use aw_core::{
    EventKind, Evidence, FileAccessMode, IoVia, ProcUid, RawEvent, SessionId, Source,
};

use crate::config::AggregateConfig;
use crate::gaps::weaker;
use crate::output::{FileAccessRec, Output};

/// Default open-row cap per session. The task card says 100_000.
pub const DEFAULT_STATE_CAP: u64 = 100_000;

/// `field_evidence` key for bytes read. Matches storage.md's column name.
pub const BYTES_READ_FIELD: &str = "bytes_read";

/// `field_evidence` key for bytes written.
pub const BYTES_WRITTEN_FIELD: &str = "bytes_written";

const NS_PER_MS: u64 = 1_000_000;
const NS_PER_SEC: u64 = 1_000_000_000;

/// Built-in directory prefixes folded into one counted row.
const DEFAULT_NOISE_PREFIXES: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/usr/lib",
    "/lib",
    "/lib64",
    "/usr/share/locale",
    "/usr/lib/locale",
];

/// Built-in suffixes folded even when the directory is not a noise prefix.
const DEFAULT_NOISE_SUFFIXES: &[&str] = &[
    ".so",
    ".dylib",
    ".dll",
    ".mo",
    ".pyc",
];

/// Open file-access rows and the handle → path table.
///
/// Rows are ordered by first-seen time so a full table can emit the oldest.
/// Closed rows are not kept: the caller already has them on [`Output`].
pub struct FileAggregator {
    flush_ns: u64,
    coalesce_ns: u64,
    cap: u64,
    sample_cap: u64,
    noise_prefixes: Vec<String>,
    noise_suffixes: Vec<String>,
    /// Open rows, oldest first.
    order: VecDeque<AccKey>,
    open: HashMap<AccKey, FileAccessAcc>,
    /// `(proc, handle)` of an open that has not closed. A later read/write/close
    /// that carries only the handle finds its path here.
    handles: HashMap<(ProcUid, u64), AccKey>,
    /// Monotonic time of the last `observe` or `tick`. `None` before either.
    now_ns: Option<u64>,
    /// Rows emitted because the table was over [`Self::cap`].
    evicted: u64,
}

/// One create, delete, or rename, which becomes a row immediately.
struct Immediate<'a> {
    op: &'static str,
    path: &'a str,
    path_to: Option<String>,
    access: Option<String>,
    created: Option<bool>,
    truncated: Option<bool>,
}

impl<'a> Immediate<'a> {
    /// The fields a create or delete leaves unset. Callers override `op` and `path`.
    fn empty() -> Self {
        Self {
            op: "access",
            path: "",
            path_to: None,
            access: None,
            created: None,
            truncated: None,
        }
    }
}

/// Why a row is still open.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum AccKey {
    /// Linux / Windows: the platform gave a handle.
    Handle { proc: ProcUid, handle: u64 },
    /// macOS, or any event with a path and no handle.
    Path { proc: ProcUid, path: String },
    /// A noise directory, counted instead of stored per file.
    Noise { proc: ProcUid, dir: String },
}

/// Running totals for one open file, or one folded directory.
struct FileAccessAcc {
    session_id: Option<SessionId>,
    proc_uid: Option<ProcUid>,
    op: &'static str,
    path: String,
    path_to: Option<String>,
    access: Option<String>,
    first_ns: u64,
    last_ns: u64,
    opens: u64,
    reads: Option<u64>,
    bytes_read: Option<u64>,
    writes: Option<u64>,
    bytes_written: Option<u64>,
    created: Option<bool>,
    truncated: Option<bool>,
    modified: Option<bool>,
    result: Option<i32>,
    /// `true` once any read or write was observed, so a later read-only open
    /// of the same path does not merge into a row that already wrote.
    wrote: bool,
    read_only: bool,
    evidence: Evidence,
    field_evidence: BTreeMap<String, Evidence>,
    source: Source,
    /// Last monotonic time a partial row was emitted. `None` until the first.
    last_partial_ns: Option<u64>,
    folded_dir: Option<String>,
    sample_paths: Vec<String>,
    /// `true` when a read event arrived with `bytes: None`. The byte field
    /// stays `None`; the reason is whatever `field_evidence` already copied.
    bytes_read_unknown: bool,
    bytes_written_unknown: bool,
    /// Opens not yet closed. A coalesced read-only row stays up until this
    /// hits zero.
    live: u64,
    /// Closed, but still inside the coalesce window so a repeat open can merge.
    pending_close: bool,
}

impl FileAggregator {
    /// Widths from `cfg`. A zero flush or coalesce window becomes the documented
    /// default rather than a window that never fires.
    pub fn new(cfg: &AggregateConfig) -> Self {
        let flush_secs = if cfg.file_flush_secs == 0 {
            30
        } else {
            cfg.file_flush_secs
        };
        let coalesce_ms = if cfg.coalesce_window_ms == 0 {
            1000
        } else {
            cfg.coalesce_window_ms
        };
        let cap = if cfg.file_state_cap == 0 {
            DEFAULT_STATE_CAP
        } else {
            cfg.file_state_cap
        };
        let prefixes = if cfg.noise_prefixes.is_empty() {
            DEFAULT_NOISE_PREFIXES
                .iter()
                .map(|s| (*s).to_owned())
                .collect()
        } else {
            cfg.noise_prefixes.clone()
        };
        let suffixes = if cfg.noise_suffixes.is_empty() {
            DEFAULT_NOISE_SUFFIXES
                .iter()
                .map(|s| (*s).to_owned())
                .collect()
        } else {
            cfg.noise_suffixes.clone()
        };
        Self {
            flush_ns: flush_secs.saturating_mul(NS_PER_SEC),
            coalesce_ns: coalesce_ms.saturating_mul(NS_PER_MS),
            cap,
            sample_cap: cfg.noise_sample_cap,
            noise_prefixes: prefixes,
            noise_suffixes: suffixes,
            order: VecDeque::new(),
            open: HashMap::new(),
            handles: HashMap::new(),
            now_ns: None,
            evicted: 0,
        }
    }

    /// Rows emitted early because the open table was over its cap.
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Widen or narrow the read-only coalesce window. The degrade ladder calls
    /// this when it changes level (1 s at L0, 10 s above). Already-open rows keep
    /// their own timestamps; only the window they are compared against changes.
    pub fn set_coalesce_ms(&mut self, coalesce_ms: u64) {
        let ms = if coalesce_ms == 0 { 1000 } else { coalesce_ms };
        self.coalesce_ns = ms.saturating_mul(NS_PER_MS);
    }

    /// How many rows are still open.
    pub fn open_len(&self) -> usize {
        self.open.len()
    }

    /// Apply one event. Non-file events are ignored, except `ProcessExit`,
    /// which flushes every row of that process. The event is not stored.
    pub fn observe(&mut self, event: &RawEvent, out: &mut Output) {
        self.advance(event.ts_mono_ns, out);
        match &event.kind {
            EventKind::FileOpen(open) => self.on_open(event, open, out),
            EventKind::FileRead(read) => self.on_read(event, read, out),
            EventKind::FileWrite(write) => self.on_write(event, write, out),
            EventKind::FileClose(close) => self.on_close(event, close, out),
            EventKind::FileCreate(create) => self.emit_immediate(
                event,
                Immediate {
                    op: "create",
                    path: &create.path,
                    created: Some(true),
                    ..Immediate::empty()
                },
                out,
            ),
            EventKind::FileDelete(delete) => self.emit_immediate(
                event,
                Immediate {
                    op: "delete",
                    path: &delete.path,
                    ..Immediate::empty()
                },
                out,
            ),
            EventKind::FileRename(rename) => self.emit_immediate(
                event,
                Immediate {
                    op: "rename",
                    path: &rename.from,
                    path_to: Some(rename.to.clone()),
                    ..Immediate::empty()
                },
                out,
            ),
            EventKind::ProcessExit(_) => self.flush_proc(event, out),
            _ => {}
        }
    }

    /// Emit partials whose flush interval has elapsed.
    ///
    /// Does not read a clock. A time that does not move forward emits nothing.
    pub fn tick(&mut self, now_ns: u64, out: &mut Output) {
        self.advance(now_ns, out);
    }

    fn advance(&mut self, now_ns: u64, out: &mut Output) {
        self.now_ns = Some(now_ns);
        self.expire_due(now_ns, out);
        let due: Vec<AccKey> = self
            .open
            .iter()
            .filter(|(_, acc)| !acc.pending_close && partial_due(acc, now_ns, self.flush_ns))
            .map(|(key, _)| key.clone())
            .collect();
        for key in due {
            if let Some(acc) = self.open.get_mut(&key) {
                out.file_access.push(acc.snapshot(true));
                acc.last_partial_ns = Some(now_ns);
            }
        }
    }

    fn on_open(&mut self, event: &RawEvent, open: &aw_core::FileOpen, out: &mut Output) {
        if open.access == FileAccessMode::Exec {
            // Exec is its own op. It is not folded into the read/write row and
            // does not occupy a slot: nothing later aggregates onto it.
            let mut acc = FileAccessAcc::from_open(event, open);
            acc.op = "exec";
            acc.access = Some("exec".to_owned());
            out.file_access.push(acc.snapshot(false));
            return;
        }
        if let Some(dir) = self.noise_dir(&open.path) {
            self.note_noise(event, &dir, &open.path, open, out);
            return;
        }
        let read_only = is_read_only(open.access);
        if read_only {
            if let Some(proc) = event.proc.as_ref() {
                self.expire_path(proc.uid, &open.path, event.ts_mono_ns, out);
            }
            if let Some(existing) = self.coalesce_target(event, &open.path) {
                if let Some(acc) = self.open.get_mut(&existing) {
                    acc.opens = acc.opens.saturating_add(1);
                    acc.live = acc.live.saturating_add(1);
                    acc.pending_close = false;
                    acc.touch(event);
                    note_open_flags(acc, open);
                }
                if let Some(handle) = open.handle {
                    if let Some(proc) = event.proc.as_ref() {
                        self.handles.insert((proc.uid, handle), existing);
                    }
                }
                return;
            }
            let Some(proc) = event.proc.as_ref() else {
                return;
            };
            let key = AccKey::Path {
                proc: proc.uid,
                path: open.path.clone(),
            };
            if let Some(old) = self.take(&key) {
                // A row that is still here and refused to merge (it already
                // wrote, for example) is closed out so this open starts clean.
                out.file_access.push(old.snapshot(false));
            }
            let acc = FileAccessAcc::from_open(event, open);
            self.insert(key.clone(), acc, out);
            if let Some(handle) = open.handle {
                self.handles.insert((proc.uid, handle), key);
            }
            return;
        }
        let key = self.key_for(event, open.handle, &open.path);
        let Some(key) = key else {
            return;
        };
        if self.open.get(&key).is_some_and(|acc| acc.read_only) {
            if let Some(old) = self.take(&key) {
                out.file_access.push(old.snapshot(false));
            }
        }
        if self.open.contains_key(&key) {
            if let Some(acc) = self.open.get_mut(&key) {
                acc.opens = acc.opens.saturating_add(1);
                acc.touch(event);
                note_open_flags(acc, open);
            }
            return;
        }
        let acc = FileAccessAcc::from_open(event, open);
        self.insert(key.clone(), acc, out);
        if let (Some(proc), Some(handle)) = (event.proc.as_ref(), open.handle) {
            self.handles.insert((proc.uid, handle), key);
        }
    }

    fn on_read(&mut self, event: &RawEvent, read: &aw_core::FileRead, out: &mut Output) {
        let key = self.resolve(event, read.handle, read.path.as_deref());
        let Some(key) = key else {
            // A read with no open and no path cannot be attributed. It is not
            // invented as a row with an empty path.
            return;
        };
        let mmap = read.via == Some(IoVia::Mmap);
        if let Some(acc) = self.open.get_mut(&key) {
            acc.add_read(event, read.bytes, mmap);
            return;
        }
        // No `FileOpen` was seen. `opens` stays 0: claiming 1 would invent an
        // open. The DDL default of 1 is a schema default, not an observation.
        let mut acc = FileAccessAcc::bare(event, key_path(&key, read.path.as_deref()));
        acc.opens = 0;
        acc.add_read(event, read.bytes, mmap);
        self.insert(key, acc, out);
    }

    fn on_write(&mut self, event: &RawEvent, write: &aw_core::FileWrite, out: &mut Output) {
        let key = self.resolve(event, write.handle, write.path.as_deref());
        let Some(key) = key else {
            return;
        };
        if let Some(acc) = self.open.get_mut(&key) {
            acc.add_write(event, write.bytes);
            return;
        }
        let mut acc = FileAccessAcc::bare(event, key_path(&key, write.path.as_deref()));
        acc.opens = 0;
        acc.add_write(event, write.bytes);
        self.insert(key, acc, out);
    }

    fn on_close(
        &mut self,
        event: &RawEvent,
        close: &aw_core::FileClose,
        out: &mut Output,
    ) {
        let key = self.resolve(event, close.handle, close.path.as_deref());
        let Some(key) = key else {
            return;
        };
        if matches!(key, AccKey::Noise { .. }) {
            // A noise row counts the directory. One file closing does not end it.
            if let Some(acc) = self.open.get_mut(&key) {
                acc.touch(event);
            }
            return;
        }
        if let (Some(proc), Some(handle)) = (event.proc.as_ref(), close.handle) {
            self.handles.remove(&(proc.uid, handle));
        }
        if !self.open.contains_key(&key) {
            // A close with no open is not a file we can describe, unless it
            // carried a path. Then it is one observation of a close.
            let Some(path) = close.path.clone() else {
                return;
            };
            let mut acc = FileAccessAcc::bare(event, path);
            acc.modified = close.modified;
            acc.touch(event);
            out.file_access.push(acc.snapshot(false));
            return;
        }
        let emit_now = if let Some(acc) = self.open.get_mut(&key) {
            acc.touch(event);
            if close.modified == Some(true) {
                acc.modified = Some(true);
            } else if acc.modified.is_none() {
                acc.modified = close.modified;
            }
            if acc.path.is_empty() {
                if let Some(path) = close.path.clone() {
                    acc.path = path;
                }
            }
            if close.handle.is_none() {
                // No handle identity: one close ends the path accumulation.
                acc.live = 0;
            } else if acc.live > 0 {
                acc.live -= 1;
            }
            if acc.live > 0 {
                false
            } else if acc.read_only && !acc.wrote {
                acc.pending_close = true;
                false
            } else {
                true
            }
        } else {
            false
        };
        if emit_now {
            if let Some(acc) = self.take(&key) {
                out.file_access.push(acc.snapshot(false));
            }
        }
    }

    fn flush_proc(&mut self, event: &RawEvent, out: &mut Output) {
        let Some(proc) = event.proc.as_ref() else {
            return;
        };
        let uid = proc.uid;
        let keys: Vec<AccKey> = self
            .open
            .keys()
            .filter(|key| key.proc() == Some(uid))
            .cloned()
            .collect();
        for key in keys {
            if let Some(mut acc) = self.take(&key) {
                acc.touch(event);
                out.file_access.push(acc.snapshot(false));
            }
        }
        self.handles.retain(|(proc_uid, _), _| *proc_uid != uid);
    }

    fn emit_immediate(&mut self, event: &RawEvent, row: Immediate<'_>, out: &mut Output) {
        let mut acc = FileAccessAcc::bare(event, row.path.to_owned());
        acc.op = row.op;
        acc.path_to = row.path_to;
        acc.access = row.access;
        acc.created = row.created;
        acc.truncated = row.truncated;
        acc.opens = 1;
        out.file_access.push(acc.snapshot(false));
    }

    fn note_noise(
        &mut self,
        event: &RawEvent,
        dir: &str,
        path: &str,
        open: &aw_core::FileOpen,
        out: &mut Output,
    ) {
        let Some(proc) = event.proc.as_ref() else {
            return;
        };
        let key = AccKey::Noise {
            proc: proc.uid,
            dir: dir.to_owned(),
        };
        if let Some(acc) = self.open.get_mut(&key) {
            if coalesce_open(acc, event.ts_mono_ns, self.coalesce_ns) || acc.read_only {
                acc.opens = acc.opens.saturating_add(1);
                acc.touch(event);
                if acc.sample_paths.len() < self.sample_cap as usize
                    && !acc.sample_paths.iter().any(|have| have == path)
                {
                    acc.sample_paths.push(path.to_owned());
                }
                return;
            }
        }
        let mut acc = FileAccessAcc::from_open(event, open);
        acc.path = dir.to_owned();
        acc.folded_dir = Some(dir.to_owned());
        acc.sample_paths.push(path.to_owned());
        self.insert(key, acc, out);
    }

    fn coalesce_target(&self, event: &RawEvent, path: &str) -> Option<AccKey> {
        let proc = event.proc.as_ref()?;
        let key = AccKey::Path {
            proc: proc.uid,
            path: path.to_owned(),
        };
        let acc = self.open.get(&key)?;
        if acc.read_only && !acc.wrote && coalesce_open(acc, event.ts_mono_ns, self.coalesce_ns) {
            Some(key)
        } else {
            None
        }
    }

    fn key_for(&self, event: &RawEvent, handle: Option<u64>, path: &str) -> Option<AccKey> {
        let proc = event.proc.as_ref()?;
        Some(match handle {
            Some(handle) => AccKey::Handle {
                proc: proc.uid,
                handle,
            },
            None => AccKey::Path {
                proc: proc.uid,
                path: path.to_owned(),
            },
        })
    }

    fn resolve(
        &self,
        event: &RawEvent,
        handle: Option<u64>,
        path: Option<&str>,
    ) -> Option<AccKey> {
        let proc = event.proc.as_ref()?;
        if let Some(handle) = handle {
            if let Some(key) = self.handles.get(&(proc.uid, handle)) {
                return Some(key.clone());
            }
            return Some(AccKey::Handle {
                proc: proc.uid,
                handle,
            });
        }
        let path = path?;
        if let Some(dir) = self.noise_dir(path) {
            return Some(AccKey::Noise {
                proc: proc.uid,
                dir,
            });
        }
        Some(AccKey::Path {
            proc: proc.uid,
            path: path.to_owned(),
        })
    }

    fn noise_dir(&self, path: &str) -> Option<String> {
        let normalized = path.replace('\\', "/");
        for prefix in &self.noise_prefixes {
            if normalized == *prefix || normalized.starts_with(&format!("{prefix}/")) {
                return Some(prefix.clone());
            }
        }
        if self.noise_suffixes.iter().any(|suffix| {
            normalized.ends_with(suffix.as_str())
                || normalized.contains(&format!("{suffix}."))
        }) {
            return Some(parent_dir(&normalized));
        }
        None
    }

    fn insert(&mut self, key: AccKey, acc: FileAccessAcc, out: &mut Output) {
        while self.open.len() as u64 >= self.cap {
            let Some(old_key) = self.order.pop_front() else {
                break;
            };
            if let Some(old) = self.open.remove(&old_key) {
                // The row is not dropped. It is emitted early, the same way a
                // flush emits a partial, and the eviction is counted.
                self.evicted = self.evicted.saturating_add(1);
                out.file_access.push(old.snapshot(true));
            }
        }
        self.order.push_back(key.clone());
        self.open.insert(key, acc);
    }

    fn take(&mut self, key: &AccKey) -> Option<FileAccessAcc> {
        let acc = self.open.remove(key)?;
        self.order.retain(|have| have != key);
        Some(acc)
    }

    /// Emit read-only rows whose coalesce window has elapsed.
    fn expire_due(&mut self, now_ns: u64, out: &mut Output) {
        let keys: Vec<AccKey> = self
            .open
            .iter()
            .filter(|(_, acc)| {
                acc.pending_close && now_ns.saturating_sub(acc.last_ns) > self.coalesce_ns
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            if let Some(acc) = self.take(&key) {
                out.file_access.push(acc.snapshot(false));
            }
        }
    }

    /// Emit one path row when a new open falls outside its coalesce window.
    fn expire_path(&mut self, proc: ProcUid, path: &str, now_ns: u64, out: &mut Output) {
        let key = AccKey::Path {
            proc,
            path: path.to_owned(),
        };
        let expired = self.open.get(&key).is_some_and(|acc| {
            acc.pending_close && now_ns.saturating_sub(acc.last_ns) > self.coalesce_ns
        });
        if expired {
            if let Some(acc) = self.take(&key) {
                out.file_access.push(acc.snapshot(false));
            }
        }
    }

    /// Emit rows a close already finished but the coalesce window was still holding.
    ///
    /// Does not emit handles that are still open. Those wait for process exit
    /// or the flush interval. Does not move the clock.
    pub fn finish(&mut self, out: &mut Output) {
        let keys: Vec<AccKey> = self
            .open
            .iter()
            .filter(|(_, acc)| acc.pending_close)
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            if let Some(acc) = self.take(&key) {
                out.file_access.push(acc.snapshot(false));
            }
        }
    }
}

impl FileAccessAcc {
    fn from_open(event: &RawEvent, open: &aw_core::FileOpen) -> Self {
        let mut acc = Self::bare(event, open.path.clone());
        acc.access = Some(access_name(open.access).to_owned());
        acc.read_only = is_read_only(open.access);
        acc.created = open.created;
        acc.truncated = open.truncated;
        acc.result = open.result.filter(|code| *code != 0);
        acc.field_evidence = event.field_evidence.clone();
        acc.live = 1;
        acc
    }

    fn bare(event: &RawEvent, path: String) -> Self {
        Self {
            session_id: event.session_id,
            proc_uid: event.proc.as_ref().map(|proc| proc.uid),
            op: "access",
            path,
            path_to: None,
            access: None,
            first_ns: event.ts_mono_ns,
            last_ns: event.ts_mono_ns,
            opens: 1,
            reads: None,
            bytes_read: None,
            writes: None,
            bytes_written: None,
            created: None,
            truncated: None,
            modified: None,
            result: None,
            wrote: false,
            read_only: true,
            evidence: event.evidence.clone(),
            field_evidence: event.field_evidence.clone(),
            source: event.source.clone(),
            last_partial_ns: None,
            folded_dir: None,
            sample_paths: Vec::new(),
            bytes_read_unknown: false,
            bytes_written_unknown: false,
            live: 0,
            pending_close: false,
        }
    }

    fn touch(&mut self, event: &RawEvent) {
        if event.ts_mono_ns < self.first_ns {
            self.first_ns = event.ts_mono_ns;
        }
        if event.ts_mono_ns > self.last_ns {
            self.last_ns = event.ts_mono_ns;
        }
        self.evidence = weaker(&self.evidence, &event.evidence);
        merge_fields(&mut self.field_evidence, &event.field_evidence);
        if self.session_id.is_none() {
            self.session_id = event.session_id;
        }
        if self.proc_uid.is_none() {
            self.proc_uid = event.proc.as_ref().map(|proc| proc.uid);
        }
    }

    fn add_read(&mut self, event: &RawEvent, bytes: Option<u64>, mmap: bool) {
        self.touch(event);
        self.reads = Some(self.reads.unwrap_or(0).saturating_add(1));
        match bytes {
            Some(n) => {
                self.bytes_read = Some(self.bytes_read.unwrap_or(0).saturating_add(n));
            }
            None => {
                self.bytes_read_unknown = true;
                if mmap && !self.field_evidence.contains_key(BYTES_READ_FIELD) {
                    self.field_evidence.insert(
                        BYTES_READ_FIELD.to_owned(),
                        Evidence::NA(aw_core::NaReason::MmapNotObservable),
                    );
                }
            }
        }
    }

    fn add_write(&mut self, event: &RawEvent, bytes: Option<u64>) {
        self.touch(event);
        self.wrote = true;
        self.read_only = false;
        if self.access.as_deref() == Some("read") || self.access.is_none() {
            self.access = Some(
                if self.reads.is_some() {
                    "read_write"
                } else {
                    "write"
                }
                .to_owned(),
            );
        } else if self.access.as_deref() == Some("read") {
            self.access = Some("read_write".to_owned());
        }
        self.writes = Some(self.writes.unwrap_or(0).saturating_add(1));
        match bytes {
            Some(n) => {
                self.bytes_written = Some(self.bytes_written.unwrap_or(0).saturating_add(n));
            }
            None => self.bytes_written_unknown = true,
        }
    }

    fn snapshot(&self, partial: bool) -> FileAccessRec {
        let mut field_evidence = self.field_evidence.clone();
        if self.bytes_read_unknown && self.bytes_read.is_none() {
            field_evidence
                .entry(BYTES_READ_FIELD.to_owned())
                .or_insert_with(|| Evidence::NA(aw_core::NaReason::EsNoReadEvent));
        }
        if self.bytes_written_unknown && self.bytes_written.is_none() {
            field_evidence
                .entry(BYTES_WRITTEN_FIELD.to_owned())
                .or_insert_with(|| Evidence::NA(aw_core::NaReason::EsNoReadEvent));
        }
        FileAccessRec {
            session_id: self.session_id,
            proc_uid: self.proc_uid,
            op: self.op.to_owned(),
            path: self.path.clone(),
            path_to: self.path_to.clone(),
            access: self.access.clone(),
            first_ns: self.first_ns,
            last_ns: self.last_ns,
            opens: self.opens,
            reads: self.reads,
            bytes_read: self.bytes_read,
            writes: self.writes,
            bytes_written: self.bytes_written,
            created: self.created,
            truncated: self.truncated,
            modified: self.modified,
            result: self.result,
            partial,
            sensitive_rule: None,
            tags: Vec::new(),
            folded_dir: self.folded_dir.clone(),
            sample_paths: self.sample_paths.clone(),
            evidence: self.evidence.clone(),
            field_evidence,
            source: self.source.clone(),
        }
    }
}

impl AccKey {
    fn proc(&self) -> Option<ProcUid> {
        match self {
            Self::Handle { proc, .. } | Self::Path { proc, .. } | Self::Noise { proc, .. } => {
                Some(*proc)
            }
        }
    }
}

fn key_path(key: &AccKey, fallback: Option<&str>) -> String {
    match key {
        AccKey::Path { path, .. } => path.clone(),
        AccKey::Noise { dir, .. } => dir.clone(),
        AccKey::Handle { .. } => fallback.unwrap_or("").to_owned(),
    }
}

fn note_open_flags(acc: &mut FileAccessAcc, open: &aw_core::FileOpen) {
    if open.created == Some(true) {
        acc.created = Some(true);
    }
    if open.truncated == Some(true) {
        acc.truncated = Some(true);
    }
    if let Some(code) = open.result {
        if code != 0 {
            acc.result = Some(code);
        }
    }
}

fn is_read_only(access: FileAccessMode) -> bool {
    matches!(access, FileAccessMode::Read | FileAccessMode::Unknown)
}

fn access_name(access: FileAccessMode) -> &'static str {
    match access {
        FileAccessMode::Read => "read",
        FileAccessMode::Write => "write",
        FileAccessMode::ReadWrite => "read_write",
        FileAccessMode::Exec => "exec",
        FileAccessMode::Unknown => "unknown",
    }
}

fn coalesce_open(acc: &FileAccessAcc, now_ns: u64, window_ns: u64) -> bool {
    now_ns.saturating_sub(acc.last_ns) <= window_ns
}

fn partial_due(acc: &FileAccessAcc, now_ns: u64, flush_ns: u64) -> bool {
    let since = acc.last_partial_ns.unwrap_or(acc.first_ns);
    now_ns.saturating_sub(since) >= flush_ns && now_ns > acc.first_ns
}

fn parent_dir(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_owned(),
        Some(idx) => path[..idx].to_owned(),
        None => path.to_owned(),
    }
}

/// Field evidence is kept per field. A field seen at two levels keeps the weaker.
fn merge_fields(into: &mut BTreeMap<String, Evidence>, from: &BTreeMap<String, Evidence>) {
    for (field, evidence) in from {
        into.entry(field.clone())
            .and_modify(|have| *have = weaker(have, evidence))
            .or_insert_with(|| evidence.clone());
    }
}
