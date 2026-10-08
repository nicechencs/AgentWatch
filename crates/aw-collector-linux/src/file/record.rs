//! Wire constants and the in-memory records a decoder accepts.
//!
//! Integers on the wire are little-endian. [`encode_open`], [`encode_flush`],
//! [`encode_transfer`], and [`encode_pending`] write them explicitly so a test
//! (or a future ring-buffer reader) can round-trip without `memcpy` of a
//! struct that might pick up padding.

/// Open-family ringbuf tag. Matches `aw-ebpf` `file::RECORD_OPEN`.
pub const RECORD_OPEN: u32 = 1;
/// Read/write-family ringbuf tag. Matches `aw-ebpf` `file::RECORD_RW`.
pub const RECORD_RW: u32 = 2;

/// `lsm/file_open`, `fexit/do_filp_open`, `sys_exit_openat(2)`.
pub const KIND_OPEN: u32 = 1;
/// `mkdirat`, or an open that created the inode.
pub const KIND_CREATE: u32 = 2;
/// `unlinkat` / `path_unlink`.
pub const KIND_DELETE: u32 = 3;
/// `renameat2` / `path_rename`.
pub const KIND_RENAME: u32 = 4;

/// Close of one fd.
pub const KIND_CLOSE: u32 = 1;
/// Flush of an fd that was still open when the thread-group leader exited.
pub const KIND_EXIT_FLUSH: u32 = 2;
/// `mmap` of a regular file.
pub const KIND_MMAP: u32 = 3;
/// `sendfile` / `splice` / `copy_file_range`.
pub const KIND_TRANSFER: u32 = 4;

/// Path byte cap. A longer tail is a malformed record.
pub const PATH_CAP: usize = 4096;

/// Bytes before the path tail of an open-family record.
pub const OPEN_HEADER_LEN: usize = 64;
/// [`FlushIn`] width.
pub const FLUSH_LEN: usize = 64;
/// [`TransferIn`] width. Matches `aw-ebpf` `file::rw::TRANSFER_HEADER_LEN`.
pub const TRANSFER_LEN: usize = 64;
/// [`PendingIn`] width.
pub const PENDING_LEN: usize = 16;

/// `fd_kind` / transfer-end coding.
pub const FD_REGULAR: u8 = 1;
pub const FD_SOCKET: u8 = 2;
pub const FD_PIPE: u8 = 3;
pub const FD_OTHER: u8 = 4;

pub const END_NONE: u8 = 0;
pub const END_FILE: u8 = 1;
pub const END_SOCKET: u8 = 2;
pub const END_PIPE: u8 = 3;

pub const PATH_D_PATH: u8 = 1;
pub const PATH_USER: u8 = 2;
pub const PATH_DENTRY: u8 = 3;
pub const PATH_PROC_FD: u8 = 4;

pub const ACCESS_READ: u8 = 1;
pub const ACCESS_WRITE: u8 = 2;
pub const ACCESS_READ_WRITE: u8 = 3;
pub const ACCESS_EXEC: u8 = 4;

pub const WHICH_MMAP: u8 = 0;
pub const WHICH_SENDFILE: u8 = 1;
pub const WHICH_SPLICE: u8 = 2;
pub const WHICH_COPY_FILE_RANGE: u8 = 3;

pub const PENDING_MAP_FULL: u8 = 1;
pub const PENDING_RING_FULL: u8 = 2;

/// `result` was read.
pub const HAS_RESULT: u32 = 1 << 0;
/// `fd` is the new descriptor.
pub const HAS_FD: u32 = 1 << 1;
/// `access` was read.
pub const HAS_ACCESS: u32 = 1 << 2;
/// The open created the inode.
pub const CREATED: u32 = 1 << 3;
/// The probe could not tell whether the inode was new.
pub const CREATED_UNKNOWN: u32 = 1 << 4;
/// The open truncated the file.
pub const TRUNCATED: u32 = 1 << 5;
/// Truncate state was not read.
pub const TRUNCATED_UNKNOWN: u32 = 1 << 6;
/// Path came from `bpf_d_path` or an equivalent absolute walk.
pub const PATH_RESOLVED: u32 = 1 << 7;
/// Path bytes follow the header.
pub const HAS_PATH: u32 = 1 << 8;
/// The kernel path was longer than [`PATH_CAP`].
pub const PATH_TRUNCATED: u32 = 1 << 9;
/// Rename destination bytes follow the source path.
pub const HAS_DST: u32 = 1 << 10;
/// The destination was longer than [`PATH_CAP`].
pub const DST_TRUNCATED: u32 = 1 << 11;
/// The object is a directory.
pub const IS_DIR: u32 = 1 << 12;
/// Directory-ness was not read.
pub const IS_DIR_UNKNOWN: u32 = 1 << 13;
/// `dirfd` was read and is not `AT_FDCWD`.
pub const HAS_DIRFD: u32 = 1 << 14;
/// `bpf_d_path` was not allowed on this hook.
pub const D_PATH_DENIED: u32 = 1 << 15;

/// One open / create / delete / rename, already lifted off the wire.
///
/// `None` means the probe did not read the field. It is not a zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenIn {
    /// [`KIND_OPEN`], [`KIND_CREATE`], [`KIND_DELETE`], or [`KIND_RENAME`].
    pub kind: u32,
    /// `bpf_ktime_get_ns`.
    pub ts_mono_ns: u64,
    /// Host tgid.
    pub tgid: u32,
    /// Host tid. `None` when the probe did not read it.
    pub tid: Option<u32>,
    /// New fd. `None` on delete, rename, mkdir, and on a failed open.
    pub fd: Option<u32>,
    /// Directory fd of an `*at` call that was not `AT_FDCWD`.
    pub dirfd: Option<i32>,
    /// Errno, positive. `Some(0)` is success. `None` was not read.
    pub result: Option<i32>,
    /// [`ACCESS_READ`] and friends. `None` was not read.
    pub access: Option<u8>,
    /// `Some(true)` created, `Some(false)` did not, `None` unknown.
    pub created: Option<bool>,
    /// `Some(true)` truncated, `Some(false)` did not, `None` unknown.
    pub truncated: Option<bool>,
    /// `true` only when the path is a normalized absolute path.
    pub path_resolved: bool,
    /// [`PATH_D_PATH`] and friends. `None` when the probe did not say.
    pub path_from: Option<u8>,
    /// `true` when `bpf_d_path` was refused on this hook.
    pub d_path_denied: bool,
    /// Path bytes. `None` when the probe had no path. A truncated path is
    /// still `Some` — the prefix is real — and [`OpenIn::path_truncated`] says so.
    pub path: Option<String>,
    /// The kernel path was longer than [`PATH_CAP`].
    pub path_truncated: bool,
    /// Rename destination. `None` unless `kind` is [`KIND_RENAME`].
    pub dst: Option<String>,
    /// The destination was longer than [`PATH_CAP`].
    pub dst_truncated: bool,
    /// `Some(true)` directory, `Some(false)` not, `None` unknown.
    pub is_dir: Option<bool>,
}

/// One fd flushed at close or at process exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushIn {
    /// [`KIND_CLOSE`] or [`KIND_EXIT_FLUSH`].
    pub kind: u32,
    /// `bpf_ktime_get_ns`.
    pub ts_mono_ns: u64,
    /// Host tgid.
    pub tgid: u32,
    /// Host tid of the closer. `None` on an exit flush.
    pub tid: Option<u32>,
    /// File descriptor.
    pub fd: u32,
    /// [`FD_REGULAR`] and friends.
    pub fd_kind: u8,
    /// `false` means the `fd_io` lookup failed and the four counters are not
    /// meaningful. They stay `None` in the events.
    pub totals_known: bool,
    /// Successful read calls. A real zero is `Some(0)`.
    pub reads: Option<u64>,
    /// Sum of positive read return values.
    pub bytes_read: Option<u64>,
    /// Successful write calls.
    pub writes: Option<u64>,
    /// Sum of positive write return values.
    pub bytes_written: Option<u64>,
}

/// `mmap`, or one file-to-socket transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferIn {
    /// [`KIND_MMAP`] or [`KIND_TRANSFER`].
    pub kind: u32,
    /// `bpf_ktime_get_ns`.
    pub ts_mono_ns: u64,
    /// Host tgid.
    pub tgid: u32,
    /// Host tid.
    pub tid: Option<u32>,
    /// Source fd (the file, for both mmap and a transfer).
    pub src_fd: u32,
    /// Destination fd. `None` for mmap.
    pub dst_fd: Option<u32>,
    /// [`END_FILE`] and friends.
    pub src_kind: u8,
    /// [`END_SOCKET`] and friends. [`END_NONE`] for mmap.
    pub dst_kind: u8,
    /// Byte count. `None` for mmap: the probe does not know it.
    pub bytes: Option<u64>,
    /// File offset. `None` when the syscall argument was not read.
    pub offset: Option<u64>,
    /// [`WHICH_SENDFILE`] and friends. [`WHICH_MMAP`] for an mmap.
    pub which: u8,
}

/// One per-CPU overflow slot, already summed by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingIn {
    /// How many map inserts or ringbuf reserves failed since the previous read.
    pub count: u64,
    /// [`PENDING_MAP_FULL`] or [`PENDING_RING_FULL`]. `None` when the reason
    /// byte was 0.
    pub reason: Option<u8>,
    /// Monotonic time of the previous reading.
    pub from_mono_ns: u64,
    /// Monotonic time of this reading.
    pub to_mono_ns: u64,
}

/// Write an open-family record. The path and destination are UTF-8; a longer
/// string than [`PATH_CAP`] is refused rather than silently cut, so a test
/// cannot disagree with the decoder about truncation.
pub fn encode_open(record: &OpenIn) -> Result<Vec<u8>, &'static str> {
    let path = record.path.as_deref().unwrap_or("");
    let dst = record.dst.as_deref().unwrap_or("");
    if path.len() > PATH_CAP || dst.len() > PATH_CAP {
        return Err("path longer than PATH_CAP");
    }
    let mut flags = 0u32;
    if record.result.is_some() {
        flags |= HAS_RESULT;
    }
    if record.fd.is_some() {
        flags |= HAS_FD;
    }
    if record.access.is_some() {
        flags |= HAS_ACCESS;
    }
    match record.created {
        Some(true) => flags |= CREATED,
        Some(false) => {}
        None => flags |= CREATED_UNKNOWN,
    }
    match record.truncated {
        Some(true) => flags |= TRUNCATED,
        Some(false) => {}
        None => flags |= TRUNCATED_UNKNOWN,
    }
    if record.path_resolved {
        flags |= PATH_RESOLVED;
    }
    if record.path.is_some() {
        flags |= HAS_PATH;
    }
    if record.path_truncated {
        flags |= PATH_TRUNCATED;
    }
    if record.dst.is_some() {
        flags |= HAS_DST;
    }
    if record.dst_truncated {
        flags |= DST_TRUNCATED;
    }
    match record.is_dir {
        Some(true) => flags |= IS_DIR,
        Some(false) => {}
        None => flags |= IS_DIR_UNKNOWN,
    }
    if record.dirfd.is_some() {
        flags |= HAS_DIRFD;
    }
    if record.d_path_denied {
        flags |= D_PATH_DENIED;
    }
    let mut out = vec![0u8; OPEN_HEADER_LEN + path.len() + dst.len()];
    put_u32(&mut out, 0, RECORD_OPEN);
    put_u32(&mut out, 4, record.kind);
    put_u64(&mut out, 8, record.ts_mono_ns);
    put_u32(&mut out, 16, record.tgid);
    put_u32(&mut out, 20, record.tid.unwrap_or(0));
    put_u32(&mut out, 24, record.fd.unwrap_or(0));
    put_i32(&mut out, 28, record.dirfd.unwrap_or(0));
    put_i32(&mut out, 32, record.result.unwrap_or(0));
    out[36] = record.access.unwrap_or(0);
    out[37] = record.path_from.unwrap_or(0);
    put_u32(&mut out, 40, flags);
    put_u16(&mut out, 44, path.len() as u16);
    put_u16(&mut out, 46, dst.len() as u16);
    out[OPEN_HEADER_LEN..OPEN_HEADER_LEN + path.len()].copy_from_slice(path.as_bytes());
    out[OPEN_HEADER_LEN + path.len()..].copy_from_slice(dst.as_bytes());
    Ok(out)
}

/// Write a flush record.
pub fn encode_flush(record: &FlushIn) -> Vec<u8> {
    let mut out = vec![0u8; FLUSH_LEN];
    put_u32(&mut out, 0, RECORD_RW);
    put_u32(&mut out, 4, record.kind);
    put_u64(&mut out, 8, record.ts_mono_ns);
    put_u32(&mut out, 16, record.tgid);
    put_u32(&mut out, 20, record.tid.unwrap_or(0));
    put_u32(&mut out, 24, record.fd);
    out[28] = record.fd_kind;
    out[29] = u8::from(record.totals_known);
    put_u64(&mut out, 32, record.reads.unwrap_or(0));
    put_u64(&mut out, 40, record.bytes_read.unwrap_or(0));
    put_u64(&mut out, 48, record.writes.unwrap_or(0));
    put_u64(&mut out, 56, record.bytes_written.unwrap_or(0));
    out
}

/// Write a transfer / mmap record.
///
/// Layout matches `aw-ebpf` `TransferRecord` (64 bytes): tag, kind, ts, tgid,
/// tid, src_fd, dst_fd, four `u8`s, 4 bytes of alignment pad, bytes at 40,
/// offset at 48, offset_known at 56, 7 pad bytes.
pub fn encode_transfer(record: &TransferIn) -> Vec<u8> {
    let mut out = vec![0u8; TRANSFER_LEN];
    put_u32(&mut out, 0, RECORD_RW);
    put_u32(&mut out, 4, record.kind);
    put_u64(&mut out, 8, record.ts_mono_ns);
    put_u32(&mut out, 16, record.tgid);
    put_u32(&mut out, 20, record.tid.unwrap_or(0));
    put_u32(&mut out, 24, record.src_fd);
    put_u32(&mut out, 28, record.dst_fd.unwrap_or(0));
    out[32] = record.src_kind;
    out[33] = record.dst_kind;
    out[34] = u8::from(record.bytes.is_some());
    out[35] = record.which;
    // bytes is at 40, not 36: the wire struct pads 4 bytes so the u64 is aligned.
    put_u64(&mut out, 40, record.bytes.unwrap_or(0));
    put_u64(&mut out, 48, record.offset.unwrap_or(0));
    out[56] = u8::from(record.offset.is_some());
    out
}

/// Write one `io_pending` slot. The caller has already summed CPUs.
pub fn encode_pending(count: u64, reason: Option<u8>) -> Vec<u8> {
    let mut out = vec![0u8; PENDING_LEN];
    put_u64(&mut out, 0, count);
    out[8] = reason.unwrap_or(0);
    out
}

fn put_u16(buf: &mut [u8], at: usize, value: u16) {
    buf[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(buf: &mut [u8], at: usize, value: u32) {
    buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_i32(buf: &mut [u8], at: usize, value: i32) {
    buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(buf: &mut [u8], at: usize, value: u64) {
    buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
