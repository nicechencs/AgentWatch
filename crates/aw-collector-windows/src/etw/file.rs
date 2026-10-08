//! Kernel-File subscription, early scope drop, and read/write accumulation.
//!
//! windows.md §2.2. Event ids and field names there are 【待验证 SPIKE-02】.
//! A property this module does not find is `NA(collector_unavailable)`. It is
//! not filled with `0` or `""`.
//!
//! | event id | name | what this module does |
//! |---|---|---|
//! | 10 | NameCreate | cache path only (P2-WIN-02). No `RawEvent`. |
//! | 11 | NameDelete | drop the cache row. No `RawEvent`. |
//! | 12 | Create | `FileOpen`, or `FileCreate` when `CreateDisposition` is a create. |
//! | 14 | Close | flush the accumulated read/write, then `FileClose`. |
//! | 15 | Read | add `IOSize` to `(pid, FileObject)`. Not forwarded one by one. |
//! | 16 | Write | same, for writes. |
//! | 26 | DeletePath | `FileDelete`. |
//! | 27 | RenamePath | `FileRename`. |
//! | 30 | CreateNewFile | `FileCreate`. |
//!
//! The callback path is [`on_file_header`]: it reads the header PID, checks the
//! scope set, and returns. It does not parse a schema. Read and write events
//! that pass the filter are accumulated here and emitted by the map on Close
//! (P2-WIN-02). `source` is `windows.etw/kernel_file`.
//!
//! `EVENT_FILTER_TYPE_PID` is not used. windows.md §2.2 says it cannot grow as
//! child processes appear, and it is capped. The scope set is the filter.
//!
//! This module does not open a session and does not call ferrisetw.

use std::collections::HashMap;

use aw_core::{NaReason, Source};

use std::sync::mpsc::{SyncSender, TrySendError};

use super::session::ScopeFilter;
use super::trace::{CallbackAction, HeaderEvent, SessionMessage};

/// `source` for every Kernel-File event. The task card names this string.
pub const SOURCE_KERNEL_FILE: &str = "windows.etw/kernel_file";

/// NameCreate. windows.md §2.2. Builds the FileKey → path cache. 【待验证 SPIKE-02】.
pub const EVENT_NAME_CREATE: u16 = 10;
/// NameDelete. Drops the cache row. 【待验证 SPIKE-02】.
pub const EVENT_NAME_DELETE: u16 = 11;
/// Create. `FileOpen`, or `FileCreate` when the disposition creates. 【待验证 SPIKE-02】.
pub const EVENT_CREATE: u16 = 12;
/// Close. Flushes the accumulated read/write, then `FileClose`. 【待验证 SPIKE-02】.
pub const EVENT_CLOSE: u16 = 14;
/// Read. Accumulated, not forwarded. 【待验证 SPIKE-02】.
pub const EVENT_READ: u16 = 15;
/// Write. Accumulated, not forwarded. 【待验证 SPIKE-02】.
pub const EVENT_WRITE: u16 = 16;
/// DeletePath. `FileDelete`. 【待验证 SPIKE-02】.
pub const EVENT_DELETE_PATH: u16 = 26;
/// RenamePath. `FileRename`. 【待验证 SPIKE-02】.
pub const EVENT_RENAME_PATH: u16 = 27;
/// CreateNewFile. `FileCreate`. 【待验证 SPIKE-02】.
pub const EVENT_CREATE_NEW_FILE: u16 = 30;

/// System process. Cache-manager delayed writes and readahead are attributed
/// here (windows.md §2.2). 【待验证 SPIKE-02】 whether that is always PID 4.
pub const PID_SYSTEM: u32 = 4;

/// `FILE_SUPERSEDE`. A create disposition. winbase.h. 【待验证 SPIKE-02】
/// that Kernel-File `CreateDisposition` uses these values.
pub const FILE_SUPERSEDE: u32 = 0;
/// `FILE_OPEN`. Not a create.
pub const FILE_OPEN: u32 = 1;
/// `FILE_CREATE`. A create disposition.
pub const FILE_CREATE: u32 = 2;
/// `FILE_OPEN_IF`. A create disposition (creates when the file is absent).
pub const FILE_OPEN_IF: u32 = 3;
/// `FILE_OVERWRITE`. Not a create. Truncates an existing file.
pub const FILE_OVERWRITE: u32 = 4;
/// `FILE_OVERWRITE_IF`. A create disposition. Also truncates.
pub const FILE_OVERWRITE_IF: u32 = 5;

/// `FILE_DIRECTORY_FILE` inside `CreateOptions`.
pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;

/// One property from a decoded Kernel-File event.
///
/// The session layer forwards headers only and does not parse properties. A
/// caller that has a schema (a fixture, or a later consumer) fills one of these
/// and hands it to the map. This module does not call ferrisetw. Absent is
/// `None`, never `0`: a zero `IOSize` is a real read, a missing property is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileProperties {
    /// `EventDescriptor.Id`. Ids outside the §2.2 table are ignored.
    pub event_id: u16,
    /// Event-header `ProcessId`. Absent is not `0` (PID 0 is the Idle process).
    pub pid: Option<u32>,
    /// Event-header thread id, when the caller has one.
    pub tid: Option<u32>,
    /// `FileObject` pointer, as an integer. The cache key, together with the
    /// Create time. Absent is not `0`.
    pub file_object: Option<u64>,
    /// `FileKey`. NameCreate / NameDelete / Read / Write / Close / Delete / Rename.
    pub file_key: Option<u64>,
    /// `FileName` (Create, NameCreate, CreateNewFile) or `FilePath` (Delete, Rename).
    ///
    /// The raw device path (`\Device\HarddiskVolumeN\...`). Not a drive letter.
    /// The map rewrites it. Absent is not `""`.
    pub file_name: Option<String>,
    /// `CreateOptions`. Create only.
    pub create_options: Option<u32>,
    /// `ShareAccess`. Create only. Not a `FileOpen` field; recorded as NA.
    pub share_access: Option<u32>,
    /// `FileAttributes` (`CreateAttributes` in windows.md §2.2). Create only.
    pub file_attributes: Option<u32>,
    /// `CreateDisposition`. Create only. Decides `FileOpen` versus `FileCreate`.
    pub create_disposition: Option<u32>,
    /// `Irp`. Create only. Not a payload field.
    pub irp: Option<u64>,
    /// `IssuingThreadId`. Create only. Used as `tid` when the header has none.
    pub issuing_thread_id: Option<u32>,
    /// `IOSize`. Read / Write. Bytes of this operation.
    pub io_size: Option<u64>,
    /// `ByteOffset`. Read / Write.
    pub byte_offset: Option<u64>,
    /// `IOFlags`. Read / Write. Not a payload field.
    pub io_flags: Option<u32>,
    /// Rename extra info. windows.md §2.2 names one path ("新路径"). When a
    /// second path property is present it is the old path. 【待验证 SPIKE-02】
    /// which property that is; this module does not guess a name for it.
    pub extra_info: Option<u32>,
    /// NTSTATUS of the operation, when the event carries one. §2.2 does not name
    /// it on any row, so a caller that does not have it leaves this `None` and
    /// the decoder marks `result` NA.
    pub status: Option<i32>,
}

impl FileProperties {
    /// An event with an id and nothing else.
    pub fn bare(event_id: u16) -> Self {
        Self {
            event_id,
            pid: None,
            tid: None,
            file_object: None,
            file_key: None,
            file_name: None,
            create_options: None,
            share_access: None,
            file_attributes: None,
            create_disposition: None,
            irp: None,
            issuing_thread_id: None,
            io_size: None,
            byte_offset: None,
            io_flags: None,
            extra_info: None,
            status: None,
        }
    }
}

/// Which §2.2 row an event id is, and whether it is forwarded or accumulated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp {
    /// NameCreate. Cache only.
    NameCreate,
    /// NameDelete. Cache only.
    NameDelete,
    /// Create. `FileOpen` or `FileCreate`.
    Create,
    /// Close. Flush, then `FileClose`.
    Close,
    /// Read. Accumulated until Close.
    Read,
    /// Write. Accumulated until Close.
    Write,
    /// DeletePath. `FileDelete`.
    Delete,
    /// RenamePath. `FileRename`.
    Rename,
    /// CreateNewFile. `FileCreate`.
    CreateNew,
}

/// `true` for the nine ids in windows.md §2.2. Anything else is not a file event.
pub fn classify(event_id: u16) -> Option<FileOp> {
    Some(match event_id {
        EVENT_NAME_CREATE => FileOp::NameCreate,
        EVENT_NAME_DELETE => FileOp::NameDelete,
        EVENT_CREATE => FileOp::Create,
        EVENT_CLOSE => FileOp::Close,
        EVENT_READ => FileOp::Read,
        EVENT_WRITE => FileOp::Write,
        EVENT_DELETE_PATH => FileOp::Delete,
        EVENT_RENAME_PATH => FileOp::Rename,
        EVENT_CREATE_NEW_FILE => FileOp::CreateNew,
        _ => return None,
    })
}

/// `true` when `disposition` is one of the four create dispositions.
///
/// `FILE_OPEN` and `FILE_OVERWRITE` open an existing file and are not creates.
/// An absent disposition is not a create: the caller marks the field NA instead
/// of assuming either answer.
pub fn disposition_creates(disposition: u32) -> bool {
    matches!(
        disposition,
        FILE_SUPERSEDE | FILE_CREATE | FILE_OPEN_IF | FILE_OVERWRITE_IF
    )
}

/// `true` when `disposition` truncates (`FILE_OVERWRITE`, `FILE_OVERWRITE_IF`,
/// `FILE_SUPERSEDE`).
pub fn disposition_truncates(disposition: u32) -> bool {
    matches!(
        disposition,
        FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF
    )
}

/// What the callback does with one Kernel-File header, before any property parse.
///
/// `Read` and `Write` that pass the scope check are counted here and are **not**
/// queued. The task card says they are not forwarded one by one. Every other
/// in-scope file event is queued as a header, the same way process and network
/// events are. An id this module does not know is dropped: parsing it would
/// spend the CPU the filter exists to save.
pub fn on_file_header(
    filter: &ScopeFilter,
    tx: &SyncSender<SessionMessage>,
    tally: &mut IoTally,
    event: HeaderEvent,
) -> FileCallback {
    if !filter.contains(event.pid) {
        return FileCallback::OutOfScope;
    }
    let Some(op) = classify(event.event_id) else {
        return FileCallback::NotFileEvent;
    };
    if matches!(op, FileOp::Read | FileOp::Write) {
        tally.note_header(event.pid);
        return FileCallback::Accumulated;
    }
    match tx.try_send(SessionMessage::Header(event)) {
        Ok(()) => FileCallback::Queued,
        Err(TrySendError::Full(_)) => FileCallback::ChannelFull,
        Err(TrySendError::Disconnected(_)) => FileCallback::ChannelClosed,
    }
}

/// Outcome of [`on_file_header`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCallback {
    /// Header PID was not in the scope set. Properties were not read.
    OutOfScope,
    /// The id is not in the §2.2 table. Not parsed.
    NotFileEvent,
    /// A read or a write. Counted, not queued.
    Accumulated,
    /// Header was queued for the consumer.
    Queued,
    /// The channel was full. Not retried and not parsed.
    ChannelFull,
    /// The receiver is gone.
    ChannelClosed,
}

impl FileCallback {
    /// The shared channel outcome, when this result is one of those.
    ///
    /// `None` for the file-specific outcomes (out of scope, not a file event,
    /// accumulated). Those never touch the channel.
    pub fn as_channel(self) -> Option<CallbackAction> {
        match self {
            Self::OutOfScope => Some(CallbackAction::Dropped),
            Self::Queued => Some(CallbackAction::Queued),
            Self::ChannelFull => Some(CallbackAction::ChannelFull),
            Self::ChannelClosed => Some(CallbackAction::ChannelClosed),
            Self::NotFileEvent | Self::Accumulated => None,
        }
    }
}

/// Running read/write totals for one `(pid, FileObject)`.
///
/// Emitted once, on Close. A `reads` of `Some(0)` never happens: the entry
/// exists only after at least one event. `None` means every event that opened
/// the entry lacked `IOSize`, so the byte count is unknown rather than zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoTotals {
    /// How many Read events were added.
    pub reads: u64,
    /// Sum of `IOSize` on those reads. `None` when none of them carried `IOSize`.
    pub bytes_read: Option<u64>,
    /// How many Write events were added.
    pub writes: u64,
    /// Sum of `IOSize` on those writes. `None` when none of them carried `IOSize`.
    pub bytes_written: Option<u64>,
    /// `ByteOffset` of the first read that had one. Later reads do not move it:
    /// the aggregate is a total, not a position.
    pub read_offset: Option<u64>,
    /// `ByteOffset` of the first write that had one.
    pub write_offset: Option<u64>,
}

/// `(pid, FileObject)` → accumulated read/write.
///
/// The key is the header PID plus the `FileObject`, as the task card says. The
/// map in P2-WIN-02 is what attributes a System (PID 4) write back to the
/// process that created the file. This tally does not do that: it records who
/// the event header named.
///
/// A read or write whose `FileObject` property is absent is counted in
/// [`IoTally::unkeyed`] and marked NA. It is not stored under `FileObject = 0`.
#[derive(Debug, Default)]
pub struct IoTally {
    by_object: HashMap<(u32, u64), IoTotals>,
    /// Read/write events the callback counted before the property parse. The
    /// consumer subtracts as it folds parsed events in, so a gap between the
    /// two is visible instead of silently lost.
    header_reads_writes: u64,
    /// Parsed read/write events that had no `FileObject`.
    unkeyed: u64,
}

impl IoTally {
    /// Empty tally.
    pub fn new() -> Self {
        Self {
            by_object: HashMap::new(),
            header_reads_writes: 0,
            unkeyed: 0,
        }
    }

    /// How many `(pid, FileObject)` rows are open.
    pub fn pending(&self) -> usize {
        self.by_object.len()
    }

    /// Read/write headers noted by the callback and not yet folded in.
    pub fn header_reads_writes(&self) -> u64 {
        self.header_reads_writes
    }

    /// Parsed read/write events dropped for lack of a `FileObject`.
    pub fn unkeyed(&self) -> u64 {
        self.unkeyed
    }

    /// The callback saw one in-scope read or write. No property was read.
    pub fn note_header(&mut self, _pid: u32) {
        self.header_reads_writes = self.header_reads_writes.saturating_add(1);
    }

    /// Add one parsed read or write.
    ///
    /// `pid` is the header PID. `file_object = None` increments [`Self::unkeyed`]
    /// and adds nothing: there is no key to aggregate under. `io_size = None`
    /// still counts the operation, and leaves the byte sum `None` until some
    /// event in the same row carries a size.
    pub fn add(
        &mut self,
        pid: u32,
        file_object: Option<u64>,
        write: bool,
        io_size: Option<u64>,
        offset: Option<u64>,
    ) {
        self.header_reads_writes = self.header_reads_writes.saturating_sub(1);
        let Some(file_object) = file_object else {
            self.unkeyed = self.unkeyed.saturating_add(1);
            return;
        };
        let row = self.by_object.entry((pid, file_object)).or_default();
        if write {
            row.writes = row.writes.saturating_add(1);
            add_bytes(&mut row.bytes_written, io_size);
            if row.write_offset.is_none() {
                row.write_offset = offset;
            }
        } else {
            row.reads = row.reads.saturating_add(1);
            add_bytes(&mut row.bytes_read, io_size);
            if row.read_offset.is_none() {
                row.read_offset = offset;
            }
        }
    }

    /// Take and remove the totals for `(pid, file_object)`.
    ///
    /// `None` when nothing was accumulated. Close uses that to emit a `FileClose`
    /// without a read or a write. The row is removed either way the caller asks:
    /// this function removes it.
    pub fn take(&mut self, pid: u32, file_object: u64) -> Option<IoTotals> {
        self.by_object.remove(&(pid, file_object))
    }

    /// Totals for `(pid, file_object)` without removing them.
    pub fn get(&self, pid: u32, file_object: u64) -> Option<IoTotals> {
        self.by_object.get(&(pid, file_object)).copied()
    }

    /// Drop every row. Returns how many were dropped.
    ///
    /// Session shutdown uses this. The caller writes one `Gap` for the count
    /// instead of emitting a partial read/write with no close, which would look
    /// like a finished operation.
    pub fn clear(&mut self) -> u64 {
        let n = self.by_object.len() as u64;
        self.by_object.clear();
        n
    }
}

fn add_bytes(slot: &mut Option<u64>, io_size: Option<u64>) {
    let Some(n) = io_size else {
        return;
    };
    *slot = Some(slot.unwrap_or(0).saturating_add(n));
}

/// Why a file field is `NA`. Kernel-File simply does not carry it, or the
/// property was absent on this event. Both are [`NaReason::CollectorUnavailable`]:
/// there is no more specific code for "the ETW event has no such column".
pub fn unavailable() -> NaReason {
    NaReason::CollectorUnavailable
}

/// The `source` value, as a [`Source`].
pub fn source() -> Source {
    Source::new(SOURCE_KERNEL_FILE)
}
