//! Read/write aggregation, close flush, mmap, and sendfile (P2-LNX-02).
//!
//! `sys_exit_read` / `pread64` / `readv` / `preadv` and
//! `sys_exit_write` / `pwrite64` / `writev` / `pwritev` do not reserve a
//! ringbuf slot. They look up `(tgid, fd)` in `fd_kind`. A row whose `kind`
//! is [`super::FD_REGULAR`] is the only row that is updated, by adding the
//! syscall's return value (bytes) and one to the call count. A negative
//! return is an error and is not added. A missing row is not treated as a
//! regular file: the bytes are not counted, and the probe writes nothing.
//!
//! `sys_enter_close` reads the [`FdIo`] row, emits one [`FlushRecord`], and
//! deletes both the `fd_io` row and the `fd_kind` row. Process exit
//! (`sched_process_exit` of the thread-group leader) walks `fd_io` for that
//! tgid and emits one flush per fd, then deletes them. Userspace turns a
//! flush with a non-zero read side into one aggregated `FileRead`, a
//! non-zero write side into one aggregated `FileWrite`, and always emits
//! `FileClose` for a real close.
//!
//! `mmap` of a regular file emits [`KIND_MMAP`] immediately. It is an open
//! (`via = mmap`), not a byte count. The byte fields stay absent.
//!
//! `sendfile` / `splice` / `copy_file_range` emit [`KIND_TRANSFER`] when the
//! source fd is a regular file and the destination fd is a socket. Both facts
//! come from `fd_kind`. The record is a clue for userspace, which emits
//! `FileRead { via: sendfile }` and `NetSend { via: sendfile }` together.
//! Evidence stays E1; nothing here decides that a file was uploaded.
//!
//! # Maps
//!
//! | map | key | value | cap |
//! |---|---|---|---|
//! | `fd_kind` | [`FdKindKey`] | [`FdKindValue`] | [`FD_KIND_CAP`] |
//! | `fd_io` | [`FdIoKey`] | [`FdIo`] | [`FD_IO_CAP`] |
//! | `io_pending` | per-CPU index | [`IoPending`] | one row per CPU |
//!
//! When `fd_io` or `fd_kind` refuses an insert, the probe increments
//! [`IoPending`] on the current CPU with [`super::PENDING_MAP_FULL`] and
//! returns. It does not drop the fact. A ringbuf reserve that fails
//! increments [`super::PENDING_RING_FULL`] the same way, and also the shared
//! `lost` map (linux.md §1). Userspace reads `io_pending` and emits
//! `Gap { kind: dropped }`.

use super::{
    END_FILE, END_NONE, END_PIPE, END_SOCKET, FD_OTHER, FD_PIPE, FD_REGULAR, FD_SOCKET,
    PENDING_MAP_FULL, PENDING_RING_FULL, RECORD_RW,
};

/// `fd_kind` map name. Written by the open probe and by `socket` / `accept`
/// (those probes live with the net program; they must use this name).
pub const FD_KIND_MAP: &str = "fd_kind";

/// `fd_io` map name. Read/write totals, keyed by `(tgid, fd)`.
pub const FD_IO_MAP: &str = "fd_io";

/// Per-CPU overflow record. Not a counter of bytes. A non-zero `count` is a
/// `Gap` waiting to be emitted.
pub const IO_PENDING_MAP: &str = "io_pending";

/// Default cap for `fd_kind`. A full map is a gap, not a silent miss.
pub const FD_KIND_CAP: u32 = 262_144;

/// Default cap for `fd_io`. Same rule.
pub const FD_IO_CAP: u32 = 262_144;

/// Close, or the flush of one fd at process exit.
pub const KIND_CLOSE: u32 = 1;
/// Same payload as [`KIND_CLOSE`], but the fd was still open when the
/// thread-group leader exited. Userspace still emits the aggregated totals.
pub const KIND_EXIT_FLUSH: u32 = 2;
/// `mmap` of a regular file. No byte count.
pub const KIND_MMAP: u32 = 3;
/// `sendfile` / `splice` / `copy_file_range`.
pub const KIND_TRANSFER: u32 = 4;

/// Hooks that only update `fd_io`, in linux.md §2.2 order.
pub const RW_PROBES: [&str; 16] = [
    "tp_read",
    "tp_pread64",
    "tp_readv",
    "tp_preadv",
    "tp_write",
    "tp_pwrite64",
    "tp_writev",
    "tp_pwritev",
    "tp_close",
    "tp_mmap",
    "tp_sendfile64",
    "tp_splice",
    "tp_copy_file_range",
    "fd_kind",
    "fd_io",
    "io_pending",
];

/// Header size of a [`FlushRecord`].
pub const FLUSH_HEADER_LEN: usize = 64;

/// Header size of a [`TransferRecord`].
///
/// 4+4+8+4+4+4+4 + 4 (kinds/which) + 8 + 8 + 1 + 7 pad = 64. The pad keeps
/// the next record 8-aligned in a per-CPU scratch buffer.
pub const TRANSFER_HEADER_LEN: usize = 64;

/// Key of `fd_kind` and of `fd_io`. An fd is only meaningful inside one tgid.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdKindKey {
    /// Thread-group id.
    pub tgid: u32,
    /// File descriptor.
    pub fd: u32,
}

/// `fd_io` uses the same key shape. A separate name so a writer does not
/// put a kind into the byte map by accident.
pub type FdIoKey = FdKindKey;

/// Value of `fd_kind`. Eight bytes.
///
/// `kind == 0` is not stored. A missing key means "not observed", which the
/// read/write probe skips.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdKindValue {
    /// [`FD_REGULAR`], [`FD_SOCKET`], [`FD_PIPE`], or [`FD_OTHER`].
    pub kind: u8,
    /// `1` when the open path was stored for this fd. The path itself is not
    /// in this map: it is in the open record, and userspace keeps it. This
    /// flag only says the probe classified the fd at open time rather than
    /// from a later `/proc/<pid>/fd` read.
    pub from_open: u8,
    /// Reserved. Write 0.
    pub _pad0: u16,
    /// Generation. Userspace bumps this only as documentation; the kernel
    /// writes `0`.
    pub _pad1: u32,
}

const _: () = assert!(core::mem::size_of::<FdKindKey>() == 8);
const _: () = assert!(core::mem::size_of::<FdKindValue>() == 8);

/// Value of `fd_io`. Totals since the fd was opened, or since the last flush
/// deleted the row.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdIo {
    /// Successful read calls (`read`, `pread64`, `readv`, `preadv`).
    pub reads: u64,
    /// Sum of the positive return values of those calls.
    pub bytes_read: u64,
    /// Successful write calls.
    pub writes: u64,
    /// Sum of the positive return values of those calls.
    pub bytes_written: u64,
}

const _: () = assert!(core::mem::size_of::<FdIo>() == 32);

/// One fd flushed to the ring buffer.
///
/// 64 bytes. `reads == 0` means no read happened, which is a real zero, not
/// "unknown": the row existed, so the probe was counting. A fd that was never
/// in `fd_io` is not flushed (close of a socket, or an fd opened before
/// attach — that one is filled from `/proc` in userspace, evidence S).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlushRecord {
    /// [`RECORD_RW`].
    pub tag: u32,
    /// [`KIND_CLOSE`] or [`KIND_EXIT_FLUSH`].
    pub kind: u32,
    /// `bpf_ktime_get_ns` at the close or the exit walk.
    pub ts_mono_ns: u64,
    /// Thread-group id.
    pub tgid: u32,
    /// Thread id of the closer. `0` on an exit flush: the exiting leader is
    /// the tgid, and the probe does not invent a tid.
    pub pid: u32,
    /// File descriptor being closed or flushed.
    pub fd: u32,
    /// [`FdKindValue::kind`] at flush time.
    pub fd_kind: u8,
    /// `1` when the totals were read out of `fd_io`. `0` means the map lookup
    /// failed and the four counters below are not meaningful.
    pub totals_known: u8,
    /// Reserved. Write 0.
    pub _pad0: u16,
    /// Copied out of [`FdIo`].
    pub reads: u64,
    /// Copied out of [`FdIo`].
    pub bytes_read: u64,
    /// Copied out of [`FdIo`].
    pub writes: u64,
    /// Copied out of [`FdIo`].
    pub bytes_written: u64,
}

const _: () = assert!(core::mem::size_of::<FlushRecord>() == FLUSH_HEADER_LEN);
const _: () = assert!(RECORD_RW == 2);
const _: () = assert!(PENDING_MAP_FULL != PENDING_RING_FULL);

/// `mmap`, or one `sendfile` / `splice` / `copy_file_range`.
///
/// 64 bytes. For [`KIND_MMAP`], `dst_fd` is `0`, `dst_kind` is [`END_NONE`],
/// and `bytes` is `0` with `bytes_known = 0`: the probe does not know how
/// many bytes the mapping will touch. Userspace marks `bytes` as
/// `NA(mmap_not_observable)`.
///
/// For [`KIND_TRANSFER`], `bytes_known = 1` and `bytes` is the positive
/// return value. `src_kind` / `dst_kind` are [`END_FILE`] / [`END_SOCKET`] /
/// [`END_PIPE`] as classified from `fd_kind`. A transfer whose source is not
/// a regular file is not emitted.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TransferRecord {
    /// [`RECORD_RW`].
    pub tag: u32,
    /// [`KIND_MMAP`] or [`KIND_TRANSFER`].
    pub kind: u32,
    /// `bpf_ktime_get_ns`.
    pub ts_mono_ns: u64,
    /// Thread-group id.
    pub tgid: u32,
    /// Thread id.
    pub pid: u32,
    /// Source fd. For `mmap`, the file being mapped.
    pub src_fd: u32,
    /// Destination fd. `0` for `mmap`.
    pub dst_fd: u32,
    /// [`END_FILE`] / [`END_SOCKET`] / [`END_PIPE`] / [`END_NONE`].
    pub src_kind: u8,
    /// Same coding as `src_kind`.
    pub dst_kind: u8,
    /// `1` when `bytes` is the syscall return value.
    pub bytes_known: u8,
    /// Which call. `1` sendfile64, `2` splice, `3` copy_file_range, `0` mmap.
    pub which: u8,
    /// Pads `bytes` to an 8-byte boundary. Write 0. Without it a `repr(C)`
    /// compiler would insert the same 4 bytes silently and the two sides
    /// could disagree about where `bytes` starts.
    pub _pad_align: u32,
    /// Byte count. Meaningful only when `bytes_known` is `1`.
    pub bytes: u64,
    /// File offset argument, when the syscall has one (`mmap`, `sendfile`,
    /// `copy_file_range`). Meaningful only when [`TransferRecord::offset_known`]
    /// is `1`. A read offset of 0 stays 0.
    pub offset: u64,
    /// `1` when `offset` was read.
    pub offset_known: u8,
    /// Reserved. Write 0.
    pub _pad0: [u8; 7],
}

const _: () = assert!(core::mem::size_of::<TransferRecord>() == TRANSFER_HEADER_LEN);
/// `bytes` must sit at offset 40. A compiler that pads differently would
/// break the userspace decoder, so pin it.
const _: () = assert!(core::mem::offset_of!(TransferRecord, bytes) == 40);
const _: () = assert!(core::mem::offset_of!(TransferRecord, offset) == 48);
const _: () = assert!(core::mem::offset_of!(TransferRecord, offset_known) == 56);

/// One per-CPU slot in `io_pending`.
///
/// The probe adds `count` and does not clear it. Userspace subtracts the
/// previous reading (the same way as the shared `lost` map) and emits one
/// `Gap { kind: dropped }` per non-zero delta. `reason` is
/// [`PENDING_MAP_FULL`] or [`PENDING_RING_FULL`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoPending {
    /// How many map inserts or ringbuf reserves failed on this CPU.
    pub count: u64,
    /// [`PENDING_MAP_FULL`] or [`PENDING_RING_FULL`]. `0` means "no reason
    /// recorded", which userspace still reports as a drop, with the detail
    /// saying the reason byte was empty.
    pub reason: u8,
    /// Reserved. Write 0.
    pub _pad0: [u8; 7],
}

const _: () = assert!(core::mem::size_of::<IoPending>() == 16);

/// `which` values on a [`TransferRecord`].
pub const WHICH_MMAP: u8 = 0;
pub const WHICH_SENDFILE: u8 = 1;
pub const WHICH_SPLICE: u8 = 2;
pub const WHICH_COPY_FILE_RANGE: u8 = 3;

/// Map a `fd_kind` byte onto the transfer-record end coding.
pub fn end_of(kind: u8) -> u8 {
    match kind {
        FD_REGULAR => END_FILE,
        FD_SOCKET => END_SOCKET,
        FD_PIPE => END_PIPE,
        FD_OTHER => END_NONE,
        _ => END_NONE,
    }
}
