//! fanotify decode for the legacy tier (P2-LNX-03, linux.md §3).
//!
//! No syscall lives here. The Linux process that has `CAP_SYS_ADMIN` reads
//! the fanotify fd and hands this module one [`FanEvent`] at a time. This
//! file only maps that record onto `RawEvent` and stamps evidence.
//!
//! | mask | event | bytes |
//! |---|---|---|
//! | `FAN_OPEN` | `FileOpen` | not a byte count |
//! | `FAN_ACCESS` | aggregated `FileRead` | `NA(collector_unavailable)` — fanotify counts the access, not the bytes |
//! | `FAN_MODIFY` | aggregated `FileWrite` | same |
//! | `FAN_CLOSE_WRITE` / `FAN_CLOSE_NOWRITE` | `FileClose` | `modified` is known |
//! | `FAN_CREATE` (5.1+) | `FileCreate` | |
//! | `FAN_DELETE` (5.1+) | `FileDelete` | |
//! | `FAN_RENAME` (5.17+) | `FileRename` | |
//! | `FAN_Q_OVERFLOW` | `Gap { kind: dropped }` | |
//!
//! A pid of 0, or a pid whose process has already exited, is not attributed.
//! That record becomes `Gap { kind: attribution_unknown }` with a count,
//! instead of a `File*` event wearing a guessed pid. `FAN_CLASS_CONTENT` and
//! permission events are not represented: this tier must not block the
//! watched process, and it must not read file contents.

use std::collections::BTreeMap;

use aw_core::{
    Capability, CapabilitySet, EventKind, Evidence, FileAccessMode, FileClose, FileCreate,
    FileDelete, FileOpen, FileRead, FileRename, FileWrite, Gap, GapKind, IoVia, NaReason, ProcRef,
    ProcUid, RawEvent, Source, SCHEMA_VERSION,
};

/// `linux.legacy/fanotify`.
pub const SOURCE_FANOTIFY: &str = "linux.legacy/fanotify";

/// `field_evidence` key for the byte count fanotify cannot see.
pub const FIELD_BYTES: &str = "bytes";

/// `FAN_ACCESS`.
pub const FAN_ACCESS: u64 = 0x0000_0001;
/// `FAN_MODIFY`.
pub const FAN_MODIFY: u64 = 0x0000_0002;
/// `FAN_CLOSE_WRITE`.
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
/// `FAN_CLOSE_NOWRITE`.
pub const FAN_CLOSE_NOWRITE: u64 = 0x0000_0010;
/// `FAN_OPEN`.
pub const FAN_OPEN: u64 = 0x0000_0020;
/// `FAN_Q_OVERFLOW`.
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
/// `FAN_OPEN_PERM`. Not subscribed. Present so a stray event is recognizable
/// and dropped as a gap instead of being treated as an open.
pub const FAN_OPEN_PERM: u64 = 0x0001_0000;
/// `FAN_ACCESS_PERM`. Not subscribed.
pub const FAN_ACCESS_PERM: u64 = 0x0002_0000;
/// `FAN_ONDIR`.
pub const FAN_ONDIR: u64 = 0x4000_0000;
/// `FAN_CREATE` (Linux 5.1).
pub const FAN_CREATE: u64 = 0x0000_0100;
/// `FAN_DELETE` (Linux 5.1).
pub const FAN_DELETE: u64 = 0x0000_0200;
/// `FAN_DELETE_SELF`.
pub const FAN_DELETE_SELF: u64 = 0x0000_0400;
/// `FAN_MOVED_FROM` (the pre-5.17 rename half).
pub const FAN_MOVED_FROM: u64 = 0x0000_0040;
/// `FAN_MOVED_TO`.
pub const FAN_MOVED_TO: u64 = 0x0000_0080;
/// `FAN_RENAME` (Linux 5.17).
pub const FAN_RENAME: u64 = 0x1000_0000;

/// `FAN_REPORT_FID`.
pub const FAN_REPORT_FID: u32 = 0x0000_0200;
/// `FAN_REPORT_DIR_FID`.
pub const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;
/// `FAN_REPORT_NAME`.
pub const FAN_REPORT_NAME: u32 = 0x0000_0800;
/// `FAN_REPORT_DFID_NAME` = dir fid + name.
pub const FAN_REPORT_DFID_NAME: u32 = FAN_REPORT_DIR_FID | FAN_REPORT_NAME;
/// `FAN_CLASS_NOTIF`. Notification class only. Never `FAN_CLASS_CONTENT`.
pub const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
/// `FAN_CLASS_CONTENT`. Refused by [`FanotifyConfig::validate`].
pub const FAN_CLASS_CONTENT: u32 = 0x0000_0004;
/// `FAN_UNLIMITED_QUEUE`.
pub const FAN_UNLIMITED_QUEUE: u32 = 0x0000_0010;
/// `FAN_CLOEXEC`.
pub const FAN_CLOEXEC: u32 = 0x0000_0001;
/// `FAN_NONBLOCK`.
pub const FAN_NONBLOCK: u32 = 0x0000_0002;

/// Init flags this tier asks for.
///
/// `FAN_CLASS_NOTIF` is the zero class bit. Combined with `FAN_REPORT_FID`
/// and `FAN_REPORT_DFID_NAME` so the event carries a file handle and a name
/// instead of a readable fd. `FAN_CLOEXEC` keeps the fd out of children the
/// collector itself spawns.
pub const INIT_FLAGS: u32 =
    FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_REPORT_FID | FAN_REPORT_DFID_NAME | FAN_UNLIMITED_QUEUE;

/// Marks that do not depend on a kernel version.
pub const MARK_ALWAYS: u64 = FAN_OPEN | FAN_ACCESS | FAN_MODIFY | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;

/// Extra marks on Linux 5.1+ (create and delete).
pub const MARK_SINCE_5_1: u64 = FAN_CREATE | FAN_DELETE;

/// Extra marks on Linux 5.17+ (atomic rename).
pub const MARK_SINCE_5_17: u64 = FAN_RENAME;

/// One event the reader already pulled off the fanotify fd.
///
/// Paths are the text the reader built from the file handle and the name
/// (`open_by_handle_at` is the reader's job, and it must not read the file).
/// `None` means the handle did not resolve. That is not an empty path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanEvent {
    /// `event_len` mask bits.
    pub mask: u64,
    /// Pid the kernel put on the event. `0` means the kernel did not
    /// attribute it (linux.md §3, 【待验证】).
    pub pid: u32,
    /// `true` when the caller already knows this pid has exited, so the
    /// event cannot be tied to a live process.
    pub pid_gone: bool,
    /// Path of the file. `None` when the file handle did not resolve.
    pub path: Option<String>,
    /// Second path for `FAN_RENAME` (the new name). `None` when the kernel
    /// did not deliver one.
    pub path_to: Option<String>,
    /// `true` when the path is a normalized absolute path. A bare name from
    /// `FAN_REPORT_DFID_NAME` that the reader could not anchor is `false`.
    pub path_resolved: bool,
    /// Monotonic time the reader observed the event.
    pub ts_mono_ns: u64,
    /// Wall clock. `None` is `NA`, not epoch 0.
    pub ts_wall_ns: Option<i64>,
    /// `ProcUid` when the caller has a start time for `pid`. `None` is not
    /// rewritten to 0.
    pub proc_uid: Option<u64>,
}

/// How many times one pid touched one path via `FAN_ACCESS` or `FAN_MODIFY`.
///
/// fanotify does not report a byte count. The caller adds one per event and
/// flushes the row on close (or on a timer). `bytes` on the resulting event
/// is `NA`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanCount {
    /// `FAN_ACCESS` or `FAN_MODIFY`.
    pub mask: u64,
    /// Pid the accesses were attributed to. Already known non-zero.
    pub pid: u32,
    /// `ProcUid` when the caller has one.
    pub proc_uid: Option<u64>,
    /// Path the count is for.
    pub path: Option<String>,
    /// Whether `path` is absolute.
    pub path_resolved: bool,
    /// Number of events folded into this row. Not a byte count.
    pub times: u64,
    /// Monotonic time of the first event in the row.
    pub from_mono_ns: u64,
    /// Monotonic time of the flush.
    pub to_mono_ns: u64,
    /// Wall clock of the flush. `None` is `NA`.
    pub ts_wall_ns: Option<i64>,
}

/// Kernel features the reader discovered while marking.
///
/// A mark that the kernel rejects is not retried as a different event. It is
/// reported through [`FanotifyConfig::capabilities`] so `aw doctor` can show
/// the event type as unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanKernel {
    /// `FAN_CREATE` and `FAN_DELETE` were accepted (Linux 5.1+).
    pub create_delete: bool,
    /// `FAN_RENAME` was accepted (Linux 5.17+).
    pub rename: bool,
    /// The mount mark itself succeeded.
    pub mark_ok: bool,
}

/// What the reader asked the kernel for. Validated, not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanotifyConfig {
    /// Flags passed to `fanotify_init`.
    pub init_flags: u32,
    /// Event mask passed to `fanotify_mark`.
    pub mark_mask: u64,
    /// What the running kernel accepted.
    pub kernel: FanKernel,
}

impl FanotifyConfig {
    /// The flags this tier uses, plus the marks `kernel` can actually deliver.
    pub fn for_kernel(kernel: FanKernel) -> Self {
        let mut mark_mask = MARK_ALWAYS;
        if kernel.create_delete {
            mark_mask |= MARK_SINCE_5_1;
        }
        if kernel.rename {
            mark_mask |= MARK_SINCE_5_17;
        }
        Self {
            init_flags: INIT_FLAGS,
            mark_mask,
            kernel,
        }
    }

    /// `Err` when the config would block a process or read file content.
    ///
    /// `FAN_CLASS_CONTENT`, `FAN_OPEN_PERM`, and `FAN_ACCESS_PERM` are the
    /// rejection. A notification-class config with no permission bits is ok.
    pub fn validate(self) -> Result<(), FanotifyError> {
        let class = self.init_flags & FAN_CLASS_CONTENT;
        if class == FAN_CLASS_CONTENT {
            return Err(FanotifyError::PermissionClass);
        }
        if self.mark_mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM) != 0 {
            return Err(FanotifyError::PermissionClass);
        }
        Ok(())
    }

    /// Capability report for `aw doctor`.
    ///
    /// File events the kernel accepted are E1. A missing create/delete or
    /// rename mark is `NA(collector_unavailable)` on the file category's note,
    /// not a silent hole. Byte counts are never claimed: the note says they
    /// are NA. URL, DNS, and net stay NA — fanotify does not see them.
    pub fn capabilities(self) -> CapabilitySet {
        let mut notes: Vec<&str> = Vec::new();
        if !self.kernel.mark_ok {
            notes.push("fanotify mark failed");
        }
        if !self.kernel.create_delete {
            notes.push("FAN_CREATE and FAN_DELETE are unavailable on this kernel");
        }
        if !self.kernel.rename {
            notes.push("FAN_RENAME is unavailable on this kernel");
        }
        notes.push("file read and write byte counts are NA under fanotify");
        let note = notes.join("; ");
        let file = if self.kernel.mark_ok {
            Capability::available(Evidence::E1)
                .unwrap_or_else(|_| Capability::unavailable(NaReason::CollectorUnavailable))
                .with_note(note)
        } else {
            Capability::unavailable(NaReason::CollectorUnavailable).with_note(note)
        };
        CapabilitySet::new(
            Capability::unavailable(NaReason::CollectorUnavailable)
                .with_note("fanotify does not report process events"),
            file,
            Capability::unavailable(NaReason::CollectorUnavailable)
                .with_note("fanotify does not report network events"),
            Capability::unavailable(NaReason::CollectorUnavailable)
                .with_note("fanotify does not report dns"),
            Capability::unavailable(NaReason::CollectorUnavailable)
                .with_note("fanotify does not report urls"),
            Capability::available(Evidence::E1)
                .unwrap_or_else(|_| Capability::unavailable(NaReason::CollectorUnavailable))
                .with_note("filtered by pid in userspace"),
        )
    }
}

/// Why a fanotify record was not turned into a file event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FanotifyError {
    /// The config carries a permission class or a permission event bit.
    PermissionClass,
    /// The mask is not one this tier decodes.
    UnknownMask(u64),
}

impl std::fmt::Display for FanotifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PermissionClass => f.write_str(
                "fanotify permission class is refused; the collector must not block the watched process",
            ),
            Self::UnknownMask(mask) => write!(f, "fanotify mask 0x{mask:x} is not decoded"),
        }
    }
}

impl std::error::Error for FanotifyError {}

/// Decode one metadata event.
///
/// A pid of 0 or a pid the caller flagged as gone returns one
/// `Gap { kind: attribution_unknown }` and no file event. `FAN_Q_OVERFLOW`
/// returns one `Gap { kind: dropped }`. `FAN_ACCESS` and `FAN_MODIFY` are not
/// decoded here: the caller counts them and flushes through [`flush_count`].
pub fn decode_fanotify(event: &FanEvent, seq: u64) -> Result<Vec<RawEvent>, FanotifyError> {
    if event.mask & FAN_Q_OVERFLOW != 0 {
        return Ok(vec![overflow_gap(event, seq)]);
    }
    if event.mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM) != 0 {
        return Err(FanotifyError::PermissionClass);
    }
    if event.pid == 0 || event.pid_gone {
        return Ok(vec![attribution_gap(event, seq)]);
    }
    if event.mask & (FAN_ACCESS | FAN_MODIFY) != 0
        && event.mask & (FAN_OPEN | FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE | FAN_CREATE | FAN_DELETE | FAN_RENAME)
            == 0
    {
        // Counted by the caller. One access is not yet a byte event.
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    if event.mask & FAN_OPEN != 0 {
        out.push(open_event(event, seq));
    }
    if event.mask & FAN_CREATE != 0 {
        out.push(create_event(event, seq + out.len() as u64));
    }
    if event.mask & FAN_DELETE != 0 || event.mask & FAN_DELETE_SELF != 0 {
        out.push(delete_event(event, seq + out.len() as u64));
    }
    if event.mask & FAN_RENAME != 0 || event.mask & (FAN_MOVED_FROM | FAN_MOVED_TO) == (FAN_MOVED_FROM | FAN_MOVED_TO)
    {
        out.push(rename_event(event, seq + out.len() as u64));
    }
    if event.mask & (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE) != 0 {
        out.push(close_event(event, seq + out.len() as u64));
    }
    if out.is_empty() {
        return Err(FanotifyError::UnknownMask(event.mask));
    }
    Ok(out)
}

/// Flush one aggregated access/modify row.
///
/// `times == 0` returns `None`. The event's `bytes` is `None` and
/// `field_evidence["bytes"]` is `NA(collector_unavailable)`. The record
/// evidence stays E1: the access happened, the size of it did not.
pub fn flush_count(count: &FanCount, seq: u64) -> Option<RawEvent> {
    if count.times == 0 || count.pid == 0 {
        return None;
    }
    let kind = if count.mask & FAN_MODIFY != 0 {
        EventKind::FileWrite(FileWrite::new(
            None,
            count.path.clone(),
            None,
            None,
        ))
    } else {
        EventKind::FileRead(FileRead::new(
            None,
            count.path.clone(),
            None,
            None,
            Some(IoVia::Syscall),
        ))
    };
    let mut event = base(count.to_mono_ns, count.ts_wall_ns, seq, Some(proc_of(count.pid, count.proc_uid)), kind);
    event.mark_na(FIELD_BYTES, NaReason::CollectorUnavailable);
    event.mark_na("offset", NaReason::CollectorUnavailable);
    event.mark_na("handle", NaReason::CollectorUnavailable);
    if count.path.is_none() {
        event.mark_na("path", NaReason::CollectorUnavailable);
    } else if !count.path_resolved {
        event.field_evidence.insert("path".to_owned(), Evidence::E1);
    }
    if count.proc_uid.is_none() {
        event.mark_na("proc", NaReason::CollectorUnavailable);
    }
    Some(event)
}

fn open_event(event: &FanEvent, seq: u64) -> RawEvent {
    let path = event.path.clone().unwrap_or_default();
    let open = FileOpen::new(
        None,
        path,
        FileAccessMode::Unknown,
        None,
        None,
        Some(0),
        Some(IoVia::Syscall),
        event.path_resolved && event.path.is_some(),
    );
    let mut raw = base(
        event.ts_mono_ns,
        event.ts_wall_ns,
        seq,
        Some(proc_of(event.pid, event.proc_uid)),
        EventKind::FileOpen(open),
    );
    raw.mark_na("handle", NaReason::CollectorUnavailable);
    raw.mark_na("access", NaReason::CollectorUnavailable);
    raw.mark_na("created", NaReason::CollectorUnavailable);
    raw.mark_na("truncated", NaReason::CollectorUnavailable);
    if event.path.is_none() {
        raw.mark_na("path", NaReason::CollectorUnavailable);
    }
    stamp_proc(&mut raw, event.proc_uid);
    raw
}

fn create_event(event: &FanEvent, seq: u64) -> RawEvent {
    let create = FileCreate::new(event.path.clone().unwrap_or_default(), event.mask & FAN_ONDIR != 0);
    let mut raw = base(
        event.ts_mono_ns,
        event.ts_wall_ns,
        seq,
        Some(proc_of(event.pid, event.proc_uid)),
        EventKind::FileCreate(create),
    );
    if event.path.is_none() {
        raw.mark_na("path", NaReason::CollectorUnavailable);
    }
    stamp_proc(&mut raw, event.proc_uid);
    raw
}

fn delete_event(event: &FanEvent, seq: u64) -> RawEvent {
    let is_dir = if event.mask & FAN_ONDIR != 0 {
        Some(true)
    } else {
        None
    };
    let delete = FileDelete::new(event.path.clone().unwrap_or_default(), is_dir);
    let mut raw = base(
        event.ts_mono_ns,
        event.ts_wall_ns,
        seq,
        Some(proc_of(event.pid, event.proc_uid)),
        EventKind::FileDelete(delete),
    );
    if event.path.is_none() {
        raw.mark_na("path", NaReason::CollectorUnavailable);
    }
    if is_dir.is_none() {
        raw.mark_na("is_dir", NaReason::CollectorUnavailable);
    }
    stamp_proc(&mut raw, event.proc_uid);
    raw
}

fn rename_event(event: &FanEvent, seq: u64) -> RawEvent {
    let rename = FileRename::new(
        event.path.clone().unwrap_or_default(),
        event.path_to.clone().unwrap_or_default(),
    );
    let mut raw = base(
        event.ts_mono_ns,
        event.ts_wall_ns,
        seq,
        Some(proc_of(event.pid, event.proc_uid)),
        EventKind::FileRename(rename),
    );
    if event.path.is_none() {
        raw.mark_na("from", NaReason::CollectorUnavailable);
    }
    if event.path_to.is_none() {
        raw.mark_na("to", NaReason::CollectorUnavailable);
    }
    stamp_proc(&mut raw, event.proc_uid);
    raw
}

fn close_event(event: &FanEvent, seq: u64) -> RawEvent {
    let modified = if event.mask & FAN_CLOSE_WRITE != 0 {
        Some(true)
    } else if event.mask & FAN_CLOSE_NOWRITE != 0 {
        Some(false)
    } else {
        None
    };
    let close = FileClose::new(None, event.path.clone(), modified);
    let mut raw = base(
        event.ts_mono_ns,
        event.ts_wall_ns,
        seq,
        Some(proc_of(event.pid, event.proc_uid)),
        EventKind::FileClose(close),
    );
    raw.mark_na("handle", NaReason::CollectorUnavailable);
    if event.path.is_none() {
        raw.mark_na("path", NaReason::CollectorUnavailable);
    }
    if modified.is_none() {
        raw.mark_na("modified", NaReason::CollectorUnavailable);
    }
    stamp_proc(&mut raw, event.proc_uid);
    raw
}

fn overflow_gap(event: &FanEvent, seq: u64) -> RawEvent {
    let gap = Gap::new(
        Source::new(SOURCE_FANOTIFY),
        GapKind::Dropped,
        vec!["file".to_owned()],
        event.ts_mono_ns,
        event.ts_mono_ns,
        None,
        Some("fanotify queue overflowed (FAN_Q_OVERFLOW); the kernel dropped file events".to_owned()),
    );
    let mut raw = base(
        event.ts_mono_ns,
        event.ts_wall_ns,
        seq,
        None,
        EventKind::Gap(gap),
    );
    raw.mark_na("proc", NaReason::CollectorUnavailable);
    raw.mark_na("count", NaReason::CollectorUnavailable);
    raw
}

fn attribution_gap(event: &FanEvent, seq: u64) -> RawEvent {
    let why = if event.pid == 0 {
        "fanotify event pid was 0; the file event is not attributed to a process"
    } else {
        "fanotify event pid had already exited; the file event is not attributed to a process"
    };
    let gap = Gap::new(
        Source::new(SOURCE_FANOTIFY),
        GapKind::AttributionUnknown,
        vec!["file".to_owned()],
        event.ts_mono_ns,
        event.ts_mono_ns,
        Some(1),
        Some(why.to_owned()),
    );
    let mut raw = base(
        event.ts_mono_ns,
        event.ts_wall_ns,
        seq,
        None,
        EventKind::Gap(gap),
    );
    raw.mark_na("proc", NaReason::AttributionBreak);
    raw
}

fn stamp_proc(event: &mut RawEvent, proc_uid: Option<u64>) {
    if proc_uid.is_none() {
        event.mark_na("proc", NaReason::CollectorUnavailable);
    }
}

fn proc_of(pid: u32, proc_uid: Option<u64>) -> ProcRef {
    ProcRef {
        uid: ProcUid(proc_uid.unwrap_or(0)),
        pid,
        tid: None,
    }
}

fn base(
    ts_mono_ns: u64,
    ts_wall_ns: Option<i64>,
    seq: u64,
    proc: Option<ProcRef>,
    kind: EventKind,
) -> RawEvent {
    let wall_known = ts_wall_ns.is_some();
    let mut event = RawEvent {
        v: SCHEMA_VERSION,
        seq,
        ts_mono_ns,
        ts_wall_ns: ts_wall_ns.unwrap_or(0),
        session_id: None,
        proc,
        source: Source::new(SOURCE_FANOTIFY),
        evidence: Evidence::E1,
        field_evidence: BTreeMap::new(),
        kind,
    };
    if !wall_known {
        event.mark_na("ts_wall_ns", NaReason::CollectorUnavailable);
    }
    let _ = event.check();
    event
}

/// Userspace pid filter. The kernel mark is per mount, so every process on
/// that mount is delivered; events whose pid is outside `scoped` are not
/// decoded. A pid of 0 is never in scope: that record is an attribution gap,
/// not a member of an empty filter.
pub fn in_scope(pid: u32, scoped: &[u32]) -> bool {
    pid != 0 && scoped.contains(&pid)
}

/// `fanotify_init` flags. `nonblock` adds [`FAN_NONBLOCK`] so a reader can
/// poll instead of blocking in `read`. The class bit stays notification.
pub fn init_flags(nonblock: bool) -> u32 {
    if nonblock {
        INIT_FLAGS | FAN_NONBLOCK
    } else {
        INIT_FLAGS
    }
}
