//! Bytes to [`aw_core::RawEvent`] for the file probes.
//!
//! One ringbuf record can become more than one event. A close with both read
//! and write totals emits `FileRead`, `FileWrite`, and `FileClose`. A
//! file-to-socket transfer emits `FileRead` and `NetSend`, both with
//! `via = sendfile` (or splice / copy_file_range). An mmap emits `FileOpen`
//! with `via = mmap` and marks `bytes` `NA(mmap_not_observable)` on the
//! companion `FileRead` that carries no count — the open itself has no byte
//! field, so the NA lives on that read record only when the caller asks for
//! the byte view via [`decode_file`]. The mmap path emits the open plus a
//! read whose `bytes` is `None`.

use std::collections::BTreeMap;

use aw_core::{
    EventKind, Evidence, FileAccessMode, FileClose, FileCreate, FileDelete, FileOpen, FileRead,
    FileRename, FileWrite, FlowKey, Gap, GapKind, IoVia, L4Proto, NaReason, NetSend, ProcRef,
    ProcUid, RawEvent, SocketAddr as EventAddr, Source, SCHEMA_VERSION,
};

use super::path::{join_cwd, CwdLookup, PathJoin};
use super::record::{
    OpenIn, PendingIn, ACCESS_EXEC, ACCESS_READ, ACCESS_READ_WRITE, ACCESS_WRITE, CREATED,
    CREATED_UNKNOWN, DST_TRUNCATED, D_PATH_DENIED, END_FILE, END_SOCKET, FD_OTHER, FD_PIPE,
    FD_REGULAR, FD_SOCKET, FLUSH_LEN, HAS_ACCESS, HAS_DIRFD, HAS_DST, HAS_FD, HAS_PATH, HAS_RESULT,
    IS_DIR, IS_DIR_UNKNOWN, KIND_CLOSE, KIND_CREATE, KIND_DELETE, KIND_EXIT_FLUSH, KIND_MMAP,
    KIND_OPEN, KIND_RENAME, KIND_TRANSFER, OPEN_HEADER_LEN, PATH_CAP, PATH_D_PATH, PATH_DENTRY,
    PATH_PROC_FD, PATH_RESOLVED, PATH_TRUNCATED, PATH_USER, PENDING_MAP_FULL, PENDING_RING_FULL,
    RECORD_OPEN, RECORD_RW, TRANSFER_LEN, TRUNCATED, TRUNCATED_UNKNOWN, WHICH_COPY_FILE_RANGE,
    WHICH_MMAP, WHICH_SENDFILE, WHICH_SPLICE, END_NONE, END_PIPE,
};

/// `linux.ebpf/lsm_file_open`.
pub const SOURCE_LSM_FILE_OPEN: &str = "lsm_file_open";
/// `linux.ebpf/fexit_do_filp_open`. The open record does not say fexit apart
/// from lsm; both resolve the path. Callers that attached fexit pass this
/// name themselves. Kept so the two hooks stay distinguishable.
pub const SOURCE_FEXIT_OPEN: &str = "fexit_do_filp_open";
/// `linux.ebpf/tp_openat`. `openat2` uses the same prefix with `tp_openat2`.
pub const SOURCE_TP_OPENAT: &str = "tp_openat";
/// `linux.ebpf/lsm_path_unlink`.
pub const SOURCE_LSM_PATH_UNLINK: &str = "lsm_path_unlink";
/// `linux.ebpf/tp_unlinkat`.
pub const SOURCE_TP_UNLINKAT: &str = "tp_unlinkat";
/// `linux.ebpf/lsm_path_rename`.
pub const SOURCE_LSM_PATH_RENAME: &str = "lsm_path_rename";
/// `linux.ebpf/tp_renameat2`.
pub const SOURCE_TP_RENAMEAT2: &str = "tp_renameat2";
/// `linux.ebpf/tp_mkdirat`.
pub const SOURCE_TP_MKDIRAT: &str = "tp_mkdirat";
/// Aggregated read totals, flushed at close.
pub const SOURCE_READ: &str = "linux.ebpf/tp_read";
/// Aggregated write totals, flushed at close.
pub const SOURCE_WRITE: &str = "linux.ebpf/tp_write";
/// `linux.ebpf/tp_close`.
pub const SOURCE_TP_CLOSE: &str = "linux.ebpf/tp_close";
/// `linux.ebpf/tp_mmap`.
pub const SOURCE_MMAP: &str = "linux.ebpf/tp_mmap";
/// `linux.ebpf/tp_sendfile64`.
pub const SOURCE_SENDFILE: &str = "linux.ebpf/tp_sendfile64";
/// `linux.ebpf/tp_splice`.
pub const SOURCE_SPLICE: &str = "linux.ebpf/tp_splice";
/// `linux.ebpf/tp_copy_file_range`.
pub const SOURCE_COPY_FILE_RANGE: &str = "linux.ebpf/tp_copy_file_range";

/// `field_evidence` key for a byte count the platform cannot see.
pub const FIELD_BYTES: &str = "bytes";
/// `field_evidence` key for an offset the probe did not read.
pub const FIELD_OFFSET: &str = "offset";
/// `field_evidence` key for a path joined from a relative user string.
pub const FIELD_PATH: &str = "path";

/// Why a record was not decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileDecodeError {
    /// Shorter than the header the tag asked for, or the path tail runs past
    /// the buffer.
    TruncatedRecord,
    /// The first `u32` is not an open-family or rw-family tag.
    UnknownTag(u32),
    /// `kind` is not one this family emits.
    UnknownKind(u32),
    /// `path_len` or `dst_len` is above [`PATH_CAP`].
    LengthOverCap,
    /// Path or destination bytes are not UTF-8. The bytes are not replaced.
    PathNotUtf8,
    /// A rename with no destination path.
    RenameWithoutDestination,
}

/// What the caller knows about the process the record names.
///
/// `proc_uid` is `hash(boot_id, tgid, start_time)` computed by the caller
/// (ADR-0007). This module does not hash and does not invent a uid of 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcIdentity {
    /// Host tgid the record must match.
    pub tgid: u32,
    /// `ProcUid` once the caller has a start time. `None` keeps the pid and
    /// marks `proc` `NA`.
    pub proc_uid: Option<u64>,
}

/// Whether the tgid is inside the session.
///
/// The kernel already filtered. This repeats the check for a capture that
/// was not filtered. An empty set rejects every record.
#[derive(Debug, Clone, Copy)]
pub struct ScopeView<'a> {
    /// Tgids currently in the session.
    pub tgids: &'a [u32],
}

impl<'a> ScopeView<'a> {
    /// `true` when `tgid` is one of the session tgids.
    pub fn contains(self, tgid: u32) -> bool {
        self.tgids.contains(&tgid)
    }
}

/// Path of an fd the caller already knows, from the open that created it or
/// from a `/proc/<pid>/fd` read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdPath {
    /// Path text.
    pub path: String,
    /// `E1` for a path captured at open by `bpf_d_path`. `S` for a path read
    /// later from `/proc/<pid>/fd` (the process may have changed it).
    pub evidence: Evidence,
    /// `true` when the path is a normalized absolute path.
    pub path_resolved: bool,
}

/// Where the path of a flushed fd came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdPathRead {
    /// Known. The evidence on the value is copied onto the event.
    Known(FdPath),
    /// Not known. The event's `path` stays `None` and is marked NA.
    Unknown,
}

/// Five-tuple the caller already has for the socket end of a transfer.
///
/// `sendfile` does not carry the socket addresses. The caller looks them up
/// from the net probe's sock table. `None` means that lookup missed: the
/// `NetSend` is still emitted, with the flow marked NA rather than a zero
/// address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferFlow {
    /// Local socket.
    pub local: std::net::SocketAddr,
    /// Remote socket.
    pub remote: std::net::SocketAddr,
    /// `sock` pointer, when the net probe observed this fd.
    pub sock_id: Option<u64>,
}

/// Clock and identity the decoder cannot read off the record.
#[derive(Debug, Clone, Copy)]
pub struct DecodeOutcome<'a> {
    /// Wall clock. `None` is `NA`, not epoch 0.
    pub ts_wall_ns: Option<i64>,
    /// First sequence number. A record that emits several events uses
    /// `seq`, `seq + 1`, …
    pub seq: u64,
    /// Process identity. The tgid must equal the record's tgid.
    pub proc: ProcIdentity,
    /// Cwd for a tracepoint path that is not absolute.
    pub cwd: &'a CwdLookup,
}

/// One decoded file record: zero or more events.
#[derive(Debug, Clone, PartialEq)]
pub struct FileDecode {
    /// Events, in the order they should be forwarded.
    pub events: Vec<RawEvent>,
    /// Sequence number the next record should start at.
    pub next_seq: u64,
}

/// Decode one ringbuf record.
///
/// `scoped` rejects a tgid that is not in the session: the result is an empty
/// event list, not an error. `fd_path` is consulted for close, mmap, and
/// transfer records. `flow` is consulted only for a file-to-socket transfer.
pub fn decode_file(
    bytes: &[u8],
    ctx: DecodeOutcome<'_>,
    scoped: ScopeView<'_>,
    fd_path: &FdPathRead,
    flow: Option<&TransferFlow>,
) -> Result<FileDecode, FileDecodeError> {
    if bytes.len() < 4 {
        return Err(FileDecodeError::TruncatedRecord);
    }
    let tag = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    match tag {
        RECORD_OPEN => decode_open_bytes(bytes, ctx, scoped),
        RECORD_RW => decode_rw_bytes(bytes, ctx, scoped, fd_path, flow),
        other => Err(FileDecodeError::UnknownTag(other)),
    }
}

/// A non-zero `io_pending` delta. `count == 0` returns `None`: nothing was
/// dropped in that interval. The gap kind is [`GapKind::Dropped`].
pub fn pending_gap(pending: &PendingIn) -> Option<RawEvent> {
    if pending.count == 0 {
        return None;
    }
    let detail = match pending.reason {
        Some(PENDING_MAP_FULL) => format!(
            "{} file-probe map insert(s) refused; the record was counted, not dropped silently",
            pending.count
        ),
        Some(PENDING_RING_FULL) => format!(
            "{} file-probe ring buffer reserve(s) refused; the record was counted, not dropped silently",
            pending.count
        ),
        Some(other) => format!(
            "{} file-probe drop(s) with reason byte {other}",
            pending.count
        ),
        None => format!(
            "{} file-probe drop(s); the reason byte was empty",
            pending.count
        ),
    };
    let gap = Gap::new(
        Source::new("linux.ebpf/io_pending"),
        GapKind::Dropped,
        vec!["file".to_owned()],
        pending.from_mono_ns,
        pending.to_mono_ns,
        Some(pending.count),
        Some(detail),
    );
    let mut event = bare_event(
        pending.to_mono_ns,
        None,
        0,
        None,
        Source::new("linux.ebpf/io_pending"),
        EventKind::Gap(gap),
    );
    // A gap has no process: the dropped inserts were not attributed.
    event.proc = None;
    event.mark_na("proc", NaReason::CollectorUnavailable);
    Some(event)
}

/// An fd that was already open when the collector attached.
///
/// The path and the kind come from `/proc/<tgid>/fd`. Both are evidence S
/// (linux.md §2.2). The byte counters are `NA(preexisting)`: the collector
/// did not see the reads and writes that already happened. This is not a
/// zero.
pub fn pre_existing_fd(
    ctx: DecodeOutcome<'_>,
    fd: u32,
    path: &FdPathRead,
    kind: u8,
) -> RawEvent {
    let (path_text, path_ev) = match path {
        FdPathRead::Known(known) => (Some(known.path.clone()), known.evidence.clone()),
        FdPathRead::Unknown => (None, Evidence::NA(NaReason::CollectorUnavailable)),
    };
    let open = FileOpen::new(
        Some(handle(ctx.proc.tgid, fd)),
        path_text.clone().unwrap_or_default(),
        fd_kind_access(kind),
        None,
        None,
        None,
        Some(IoVia::Syscall),
        matches!(path, FdPathRead::Known(k) if k.path_resolved),
    );
    let mut event = bare_event(
        0,
        ctx.ts_wall_ns,
        ctx.seq,
        Some(proc_of(ctx.proc)),
        Source::new("linux.procfs/fd"),
        EventKind::FileOpen(open),
    );
    event.evidence = Evidence::S;
    event.field_evidence.insert(FIELD_PATH.to_owned(), path_ev);
    event.mark_na("created", NaReason::Preexisting);
    event.mark_na("truncated", NaReason::Preexisting);
    event.mark_na("result", NaReason::Preexisting);
    if matches!(path, FdPathRead::Unknown) {
        event.mark_na(FIELD_PATH, NaReason::CollectorUnavailable);
    }
    if ctx.proc.proc_uid.is_none() {
        event.mark_na("proc", NaReason::CollectorUnavailable);
    }
    if ctx.ts_wall_ns.is_none() {
        event.mark_na("ts_wall_ns", NaReason::CollectorUnavailable);
    }
    let _ = event.check();
    event
}

fn decode_open_bytes(
    bytes: &[u8],
    ctx: DecodeOutcome<'_>,
    scoped: ScopeView<'_>,
) -> Result<FileDecode, FileDecodeError> {
    let open = parse_open(bytes)?;
    if !scoped.contains(open.tgid) || open.tgid != ctx.proc.tgid {
        return Ok(empty(ctx.seq));
    }
    let source = Source::new(format!(
        "linux.ebpf/{}",
        probe_of(open.kind, open_flags(&open))
    ));
    let path = resolve_path(&open, ctx.cwd);
    let mut events = Vec::new();
    let mut seq = ctx.seq;
    match open.kind {
        KIND_OPEN => {
            events.push(open_event(&open, &path, ctx, seq, source.clone()));
            seq += 1;
            // An open that created the inode is also a FileCreate. The open
            // still carries `created = Some(true)`.
            if open.created == Some(true) {
                events.push(create_event(&open, &path, ctx, seq, source, false));
                seq += 1;
            }
        }
        KIND_CREATE => {
            events.push(create_event(&open, &path, ctx, seq, source, true));
            seq += 1;
        }
        KIND_DELETE => {
            events.push(delete_event(&open, &path, ctx, seq, source));
            seq += 1;
        }
        KIND_RENAME => {
            events.push(rename_event(&open, &path, ctx, seq, source)?);
            seq += 1;
        }
        other => return Err(FileDecodeError::UnknownKind(other)),
    }
    Ok(FileDecode {
        events,
        next_seq: seq,
    })
}

fn decode_rw_bytes(
    bytes: &[u8],
    ctx: DecodeOutcome<'_>,
    scoped: ScopeView<'_>,
    fd_path: &FdPathRead,
    flow: Option<&TransferFlow>,
) -> Result<FileDecode, FileDecodeError> {
    if bytes.len() < 8 {
        return Err(FileDecodeError::TruncatedRecord);
    }
    let kind = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let tgid = peek_tgid(bytes)?;
    if !scoped.contains(tgid) || tgid != ctx.proc.tgid {
        return Ok(empty(ctx.seq));
    }
    match kind {
        KIND_CLOSE | KIND_EXIT_FLUSH => decode_flush(bytes, ctx, fd_path),
        KIND_MMAP => decode_mmap(bytes, ctx, fd_path),
        KIND_TRANSFER => decode_transfer(bytes, ctx, fd_path, flow),
        other => Err(FileDecodeError::UnknownKind(other)),
    }
}

fn decode_flush(
    bytes: &[u8],
    ctx: DecodeOutcome<'_>,
    fd_path: &FdPathRead,
) -> Result<FileDecode, FileDecodeError> {
    if bytes.len() < FLUSH_LEN {
        return Err(FileDecodeError::TruncatedRecord);
    }
    let kind = get_u32(bytes, 4);
    let ts = get_u64(bytes, 8);
    let tgid = get_u32(bytes, 16);
    let tid = get_u32(bytes, 20);
    let fd = get_u32(bytes, 24);
    let fd_kind = bytes[28];
    let totals_known = bytes[29] == 1;
    let reads = get_u64(bytes, 32);
    let bytes_read = get_u64(bytes, 40);
    let writes = get_u64(bytes, 48);
    let bytes_written = get_u64(bytes, 56);
    // Only a regular file produces FileRead / FileWrite. A socket or a pipe
    // close still emits FileClose so the fd_kind row is visibly retired, but
    // the byte fields stay NA: those bytes belong to the net probe.
    // Socket and pipe bytes belong to the net probe. Closing one is not a
    // file event; emitting FileClose for it would invent a file.
    if fd_kind == FD_SOCKET || fd_kind == FD_PIPE || fd_kind == FD_OTHER {
        return Ok(empty(ctx.seq));
    }
    let regular = fd_kind == FD_REGULAR;
    let (path, path_ev, resolved) = path_of(fd_path);
    let handle = Some(handle(tgid, fd));
    let tid = if kind == KIND_EXIT_FLUSH || tid == 0 {
        None
    } else {
        Some(tid)
    };
    let mut seq = ctx.seq;
    let mut events = Vec::new();
    if regular && totals_known && reads > 0 {
        let read = FileRead::new(handle, path.clone(), Some(bytes_read), None, Some(IoVia::Syscall));
        let mut event = event_at(
            ts,
            ctx,
            seq,
            tid,
            Source::new(SOURCE_READ),
            EventKind::FileRead(read),
        );
        stamp_path(&mut event, &path_ev, resolved);
        event.mark_na(FIELD_OFFSET, NaReason::CollectorUnavailable);
        events.push(event);
        seq += 1;
    }
    if regular && totals_known && writes > 0 {
        let write = FileWrite::new(handle, path.clone(), Some(bytes_written), None);
        let mut event = event_at(
            ts,
            ctx,
            seq,
            tid,
            Source::new(SOURCE_WRITE),
            EventKind::FileWrite(write),
        );
        stamp_path(&mut event, &path_ev, resolved);
        event.mark_na(FIELD_OFFSET, NaReason::CollectorUnavailable);
        events.push(event);
        seq += 1;
    }
    let modified = if totals_known {
        Some(writes > 0)
    } else {
        None
    };
    let close = FileClose::new(handle, path.clone(), modified);
    let mut event = event_at(
        ts,
        ctx,
        seq,
        tid,
        Source::new(SOURCE_TP_CLOSE),
        EventKind::FileClose(close),
    );
    stamp_path(&mut event, &path_ev, resolved);
    if !totals_known {
        event.mark_na("modified", NaReason::CollectorUnavailable);
    }
    if !regular {
        // fd_kind was 0: the probe did not classify the fd. The close is
        // still reported; the byte totals are not, because they were not
        // counted. `FileClose` has no `bytes` field, so the NA names `modified`.
        event.mark_na("modified", NaReason::CollectorUnavailable);
    }
    events.push(event);
    seq += 1;
    Ok(FileDecode {
        events,
        next_seq: seq,
    })
}

fn decode_mmap(
    bytes: &[u8],
    ctx: DecodeOutcome<'_>,
    fd_path: &FdPathRead,
) -> Result<FileDecode, FileDecodeError> {
    let transfer = parse_transfer(bytes)?;
    let (path, path_ev, resolved) = path_of(fd_path);
    let path_text = path.clone().unwrap_or_default();
    // Protection bits are not in the record. `Unknown` is not a guess of
    // read/write, and a mapped file was not created or truncated by mmap.
    let open = FileOpen::new(
        Some(handle(transfer.tgid, transfer.src_fd)),
        path_text,
        FileAccessMode::Unknown,
        None,
        None,
        None,
        Some(IoVia::Mmap),
        resolved,
    );
    let mut open_event = event_at(
        transfer.ts_mono_ns,
        ctx,
        ctx.seq,
        transfer.tid,
        Source::new(SOURCE_MMAP),
        EventKind::FileOpen(open),
    );
    stamp_path(&mut open_event, &path_ev, resolved);
    if path.is_none() {
        open_event.mark_na(FIELD_PATH, NaReason::CollectorUnavailable);
    }
    open_event.mark_na("access", NaReason::CollectorUnavailable);
    open_event.mark_na("created", NaReason::CollectorUnavailable);
    open_event.mark_na("truncated", NaReason::CollectorUnavailable);
    open_event.mark_na("result", NaReason::CollectorUnavailable);
    // CAP-FILE-08: the mapping is visible, the bytes it will touch are not.
    // `FileOpen` has no `bytes` field; the NA is the statement of that fact.
    open_event.mark_na(FIELD_BYTES, NaReason::MmapNotObservable);
    if transfer.which != WHICH_MMAP {
        // The kind said mmap. A different `which` is still this event; the
        // constant is the only legal value the probe writes for KIND_MMAP.
        open_event.mark_na("which", NaReason::CollectorUnavailable);
    }
    Ok(FileDecode {
        events: vec![open_event],
        next_seq: ctx.seq + 1,
    })
}

fn decode_transfer(
    bytes: &[u8],
    ctx: DecodeOutcome<'_>,
    fd_path: &FdPathRead,
    flow: Option<&TransferFlow>,
) -> Result<FileDecode, FileDecodeError> {
    let transfer = parse_transfer(bytes)?;
    // Only a regular-file source is a FileRead. Anything else is not this
    // probe's event: the net probe counts socket bytes on its own.
    if transfer.src_kind != END_FILE {
        return Ok(empty(ctx.seq));
    }
    let via = match transfer.which {
        WHICH_SENDFILE => IoVia::Sendfile,
        WHICH_SPLICE => IoVia::Splice,
        WHICH_COPY_FILE_RANGE => IoVia::CopyFileRange,
        _ => IoVia::Unknown,
    };
    let source = Source::new(match transfer.which {
        WHICH_SENDFILE => SOURCE_SENDFILE,
        WHICH_SPLICE => SOURCE_SPLICE,
        WHICH_COPY_FILE_RANGE => SOURCE_COPY_FILE_RANGE,
        _ => SOURCE_SENDFILE,
    });
    let (path, path_ev, resolved) = path_of(fd_path);
    let mut seq = ctx.seq;
    let mut events = Vec::new();
    let read = FileRead::new(
        Some(handle(transfer.tgid, transfer.src_fd)),
        path.clone(),
        transfer.bytes,
        transfer.offset,
        Some(via),
    );
    let mut read_event = event_at(
        transfer.ts_mono_ns,
        ctx,
        seq,
        transfer.tid,
        source.clone(),
        EventKind::FileRead(read),
    );
    if transfer.bytes.is_none() {
        read_event.mark_na(FIELD_BYTES, NaReason::CollectorUnavailable);
    }
    if transfer.offset.is_none() {
        read_event.mark_na(FIELD_OFFSET, NaReason::CollectorUnavailable);
    }
    stamp_path(&mut read_event, &path_ev, resolved);
    events.push(read_event);
    seq += 1;
    // File → socket is also a NetSend. The via tag is a clue, not a verdict
    // (ADR-0011 / evidence-model: this does not say a file was uploaded).
    // A pipe destination is the file side only. A missing flow or a missing
    // byte count is not filled with 0.0.0.0 or 0 bytes.
    if transfer.dst_kind == END_SOCKET {
        if let (Some(flow), Some(nbytes)) = (flow, transfer.bytes) {
            let net = net_send(flow, nbytes, via);
            events.push(event_at(
                transfer.ts_mono_ns,
                ctx,
                seq,
                transfer.tid,
                source,
                EventKind::NetSend(net),
            ));
            seq += 1;
        } else if let Some(read_event) = events.first_mut() {
            read_event.mark_na("flow", NaReason::CollectorUnavailable);
        }
    } else if transfer.dst_kind == END_PIPE || transfer.dst_kind == END_NONE {
        // Not a socket. No NetSend, and no invented peer.
    }
    Ok(FileDecode {
        events,
        next_seq: seq,
    })
}

fn net_send(flow: &TransferFlow, bytes: u64, via: IoVia) -> NetSend {
    let key = FlowKey {
        proto: L4Proto::Tcp,
        local: EventAddr::socket(flow.local),
        remote: EventAddr::socket(flow.remote),
        sock_id: flow.sock_id,
    };
    NetSend::new(key, bytes, Some(via))
}

fn open_event(
    open: &OpenIn,
    path: &PathJoin,
    ctx: DecodeOutcome<'_>,
    seq: u64,
    source: Source,
) -> RawEvent {
    let access = access_of(open.access);
    let file = FileOpen::new(
        open.fd.map(|fd| handle(open.tgid, fd)),
        path.path.clone(),
        access,
        open.created,
        open.truncated,
        open.result,
        Some(IoVia::Syscall),
        open.path_resolved && !path.cwd_missing,
    );
    // A user-string path is never `path_resolved`, even after the cwd join.
    let file = if open.path_from == Some(PATH_USER) || open.d_path_denied {
        FileOpen {
            path_resolved: false,
            ..file
        }
    } else {
        file
    };
    let mut event = event_at(
        open.ts_mono_ns,
        ctx,
        seq,
        open.tid,
        source,
        EventKind::FileOpen(file),
    );
    if open.fd.is_none() {
        event.mark_na("handle", NaReason::CollectorUnavailable);
    }
    if open.access.is_none() {
        event.mark_na("access", NaReason::CollectorUnavailable);
    }
    if open.created.is_none() {
        event.mark_na("created", NaReason::CollectorUnavailable);
    }
    if open.truncated.is_none() {
        event.mark_na("truncated", NaReason::CollectorUnavailable);
    }
    if open.result.is_none() {
        event.mark_na("result", NaReason::CollectorUnavailable);
    }
    if open.path.is_none() {
        event.mark_na(FIELD_PATH, NaReason::CollectorUnavailable);
    } else if path.cwd_missing {
        event.mark_na(FIELD_PATH, NaReason::CollectorUnavailable);
        event.field_evidence.insert(
            "path.cwd".to_owned(),
            Evidence::NA(NaReason::CollectorUnavailable),
        );
    }
    if open.path_truncated {
        event
            .field_evidence
            .insert("path.truncated".to_owned(), Evidence::E1);
    }
    event
}

fn create_event(
    open: &OpenIn,
    path: &PathJoin,
    ctx: DecodeOutcome<'_>,
    seq: u64,
    source: Source,
    from_create_kind: bool,
) -> RawEvent {
    let is_dir = if from_create_kind {
        open.is_dir.unwrap_or(false)
    } else {
        false
    };
    let create = FileCreate::new(path.path.clone(), is_dir);
    let mut event = event_at(
        open.ts_mono_ns,
        ctx,
        seq,
        open.tid,
        source,
        EventKind::FileCreate(create),
    );
    if open.path.is_none() || path.cwd_missing {
        event.mark_na(FIELD_PATH, NaReason::CollectorUnavailable);
    }
    if from_create_kind && open.is_dir.is_none() {
        event.mark_na("is_dir", NaReason::CollectorUnavailable);
    }
    event
}

fn delete_event(
    open: &OpenIn,
    path: &PathJoin,
    ctx: DecodeOutcome<'_>,
    seq: u64,
    source: Source,
) -> RawEvent {
    let delete = FileDelete::new(path.path.clone(), open.is_dir);
    let mut event = event_at(
        open.ts_mono_ns,
        ctx,
        seq,
        open.tid,
        source,
        EventKind::FileDelete(delete),
    );
    if open.path.is_none() || path.cwd_missing {
        event.mark_na(FIELD_PATH, NaReason::CollectorUnavailable);
    }
    if open.is_dir.is_none() {
        event.mark_na("is_dir", NaReason::CollectorUnavailable);
    }
    event
}

fn rename_event(
    open: &OpenIn,
    path: &PathJoin,
    ctx: DecodeOutcome<'_>,
    seq: u64,
    source: Source,
) -> Result<RawEvent, FileDecodeError> {
    let dst_raw = open
        .dst
        .as_deref()
        .ok_or(FileDecodeError::RenameWithoutDestination)?;
    let dst = join_cwd(dst_raw, ctx.cwd);
    let rename = FileRename::new(path.path.clone(), dst.path);
    let mut event = event_at(
        open.ts_mono_ns,
        ctx,
        seq,
        open.tid,
        source,
        EventKind::FileRename(rename),
    );
    if open.path.is_none() || path.cwd_missing {
        event.mark_na("from", NaReason::CollectorUnavailable);
    }
    if dst.cwd_missing {
        event.mark_na("to", NaReason::CollectorUnavailable);
    }
    if open.path_truncated {
        event
            .field_evidence
            .insert("from.truncated".to_owned(), Evidence::E1);
    }
    if open.dst_truncated {
        event
            .field_evidence
            .insert("to.truncated".to_owned(), Evidence::E1);
    }
    Ok(event)
}

fn resolve_path(open: &OpenIn, cwd: &CwdLookup) -> PathJoin {
    let Some(raw) = open.path.as_deref() else {
        return PathJoin {
            path: String::new(),
            path_resolved: false,
            cwd_missing: false,
        };
    };
    if open.path_resolved && !open.d_path_denied && open.path_from != Some(PATH_USER) {
        return PathJoin {
            path: raw.to_owned(),
            path_resolved: true,
            cwd_missing: false,
        };
    }
    join_cwd(raw, cwd)
}

fn path_of(read: &FdPathRead) -> (Option<String>, Evidence, bool) {
    match read {
        FdPathRead::Known(known) => (
            Some(known.path.clone()),
            known.evidence.clone(),
            known.path_resolved,
        ),
        FdPathRead::Unknown => (None, Evidence::NA(NaReason::CollectorUnavailable), false),
    }
}

fn stamp_path(event: &mut RawEvent, evidence: &Evidence, resolved: bool) {
    if evidence.is_na() {
        event.mark_na(FIELD_PATH, NaReason::CollectorUnavailable);
        return;
    }
    if !resolved || !matches!(evidence, Evidence::E1) {
        event
            .field_evidence
            .insert(FIELD_PATH.to_owned(), evidence.clone());
    }
}

fn access_of(access: Option<u8>) -> FileAccessMode {
    match access {
        Some(ACCESS_READ) => FileAccessMode::Read,
        Some(ACCESS_WRITE) => FileAccessMode::Write,
        Some(ACCESS_READ_WRITE) => FileAccessMode::ReadWrite,
        Some(ACCESS_EXEC) => FileAccessMode::Exec,
        _ => FileAccessMode::Unknown,
    }
}

fn fd_kind_access(kind: u8) -> FileAccessMode {
    match kind {
        FD_REGULAR => FileAccessMode::Unknown,
        _ => FileAccessMode::Unknown,
    }
}

/// `(tgid, fd)` packed so two fds in different processes do not collide.
fn handle(tgid: u32, fd: u32) -> u64 {
    (u64::from(tgid) << 32) | u64::from(fd)
}

fn proc_of(proc: ProcIdentity) -> ProcRef {
    ProcRef {
        uid: ProcUid(proc.proc_uid.unwrap_or(0)),
        pid: proc.tgid,
        tid: None,
    }
}

fn event_at(
    ts_mono_ns: u64,
    ctx: DecodeOutcome<'_>,
    seq: u64,
    tid: Option<u32>,
    source: Source,
    kind: EventKind,
) -> RawEvent {
    let mut proc = proc_of(ctx.proc);
    proc.tid = tid;
    let mut event = bare_event(ts_mono_ns, ctx.ts_wall_ns, seq, Some(proc), source, kind);
    if ctx.proc.proc_uid.is_none() {
        event.mark_na("proc", NaReason::CollectorUnavailable);
    }
    event
}

fn bare_event(
    ts_mono_ns: u64,
    ts_wall_ns: Option<i64>,
    seq: u64,
    proc: Option<ProcRef>,
    source: Source,
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
        source,
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

fn empty(seq: u64) -> FileDecode {
    FileDecode {
        events: Vec::new(),
        next_seq: seq,
    }
}

struct TransferParsed {
    ts_mono_ns: u64,
    tgid: u32,
    tid: Option<u32>,
    src_fd: u32,
    src_kind: u8,
    dst_kind: u8,
    bytes: Option<u64>,
    offset: Option<u64>,
    which: u8,
}

fn parse_transfer(bytes: &[u8]) -> Result<TransferParsed, FileDecodeError> {
    if bytes.len() < TRANSFER_LEN {
        return Err(FileDecodeError::TruncatedRecord);
    }
    let tid_raw = get_u32(bytes, 20);
    let bytes_known = bytes[34] == 1;
    let offset_known = bytes[56] == 1;
    Ok(TransferParsed {
        ts_mono_ns: get_u64(bytes, 8),
        tgid: get_u32(bytes, 16),
        tid: if tid_raw == 0 { None } else { Some(tid_raw) },
        src_fd: get_u32(bytes, 24),
        src_kind: bytes[32],
        dst_kind: bytes[33],
        bytes: if bytes_known {
            Some(get_u64(bytes, 40))
        } else {
            None
        },
        offset: if offset_known {
            Some(get_u64(bytes, 48))
        } else {
            None
        },
        which: bytes[35],
    })
}

fn peek_tgid(bytes: &[u8]) -> Result<u32, FileDecodeError> {
    if bytes.len() < 20 {
        return Err(FileDecodeError::TruncatedRecord);
    }
    Ok(get_u32(bytes, 16))
}

fn parse_open(bytes: &[u8]) -> Result<OpenIn, FileDecodeError> {
    if bytes.len() < OPEN_HEADER_LEN {
        return Err(FileDecodeError::TruncatedRecord);
    }
    let kind = get_u32(bytes, 4);
    let flags = get_u32(bytes, 40);
    let path_len = get_u16(bytes, 44) as usize;
    let dst_len = get_u16(bytes, 46) as usize;
    if path_len > PATH_CAP || dst_len > PATH_CAP {
        return Err(FileDecodeError::LengthOverCap);
    }
    if bytes.len() < OPEN_HEADER_LEN + path_len + dst_len {
        return Err(FileDecodeError::TruncatedRecord);
    }
    let path = if flags & HAS_PATH != 0 {
        Some(utf8(
            &bytes[OPEN_HEADER_LEN..OPEN_HEADER_LEN + path_len],
        )?)
    } else {
        None
    };
    let dst = if flags & HAS_DST != 0 {
        let start = OPEN_HEADER_LEN + path_len;
        Some(utf8(&bytes[start..start + dst_len])?)
    } else {
        None
    };
    let tid_raw = get_u32(bytes, 20);
    Ok(OpenIn {
        kind,
        ts_mono_ns: get_u64(bytes, 8),
        tgid: get_u32(bytes, 16),
        tid: if tid_raw == 0 { None } else { Some(tid_raw) },
        fd: if flags & HAS_FD != 0 {
            Some(get_u32(bytes, 24))
        } else {
            None
        },
        dirfd: if flags & HAS_DIRFD != 0 {
            Some(get_i32(bytes, 28))
        } else {
            None
        },
        result: if flags & HAS_RESULT != 0 {
            Some(get_i32(bytes, 32))
        } else {
            None
        },
        access: if flags & HAS_ACCESS != 0 {
            Some(bytes[36])
        } else {
            None
        },
        created: tri_state(flags, CREATED, CREATED_UNKNOWN),
        truncated: tri_state(flags, TRUNCATED, TRUNCATED_UNKNOWN),
        path_resolved: flags & PATH_RESOLVED != 0,
        path_from: match bytes[37] {
            0 => None,
            PATH_D_PATH | PATH_USER | PATH_DENTRY | PATH_PROC_FD => Some(bytes[37]),
            _ => None,
        },
        d_path_denied: flags & D_PATH_DENIED != 0,
        path,
        path_truncated: flags & PATH_TRUNCATED != 0,
        dst,
        dst_truncated: flags & DST_TRUNCATED != 0,
        is_dir: if flags & IS_DIR_UNKNOWN != 0 {
            None
        } else if flags & IS_DIR != 0 {
            Some(true)
        } else {
            Some(false)
        },
    })
}

/// Flags reconstructed from an [`OpenIn`], so the source name matches the
/// wire flags [`probe_of`] reads.
fn open_flags(open: &OpenIn) -> u32 {
    let mut flags = 0u32;
    if open.path_resolved {
        flags |= PATH_RESOLVED;
    }
    if open.d_path_denied {
        flags |= D_PATH_DENIED;
    }
    flags
}

/// The record does not carry the probe name. The kind plus whether the path
/// was resolved picks the source the task card names. A tracepoint that
/// somehow resolved still stays a tracepoint source: `path_from` decides.
fn probe_of(kind: u32, flags: u32) -> &'static str {
    let resolved = flags & PATH_RESOLVED != 0;
    let user = flags & D_PATH_DENIED != 0 || !resolved;
    match kind {
        KIND_OPEN if !user => SOURCE_LSM_FILE_OPEN,
        KIND_OPEN => SOURCE_TP_OPENAT,
        KIND_CREATE if !user => SOURCE_LSM_FILE_OPEN,
        KIND_CREATE => SOURCE_TP_MKDIRAT,
        KIND_DELETE if !user => SOURCE_LSM_PATH_UNLINK,
        KIND_DELETE => SOURCE_TP_UNLINKAT,
        KIND_RENAME if !user => SOURCE_LSM_PATH_RENAME,
        KIND_RENAME => SOURCE_TP_RENAMEAT2,
        _ => SOURCE_TP_OPENAT,
    }
}

fn tri_state(flags: u32, yes: u32, unknown: u32) -> Option<bool> {
    if flags & unknown != 0 {
        None
    } else {
        Some(flags & yes != 0)
    }
}

fn utf8(bytes: &[u8]) -> Result<String, FileDecodeError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| FileDecodeError::PathNotUtf8)
}

fn get_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn get_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn get_i32(bytes: &[u8], at: usize) -> i32 {
    i32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn get_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
        bytes[at + 4],
        bytes[at + 5],
        bytes[at + 6],
        bytes[at + 7],
    ])
}

