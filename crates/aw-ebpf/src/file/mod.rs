//! File-probe record layout. Nothing here attaches a program.
//!
//! P2-LNX-01 and P2-LNX-02 name the hooks in linux.md §2.2. Aya is not a
//! dependency of this crate (see `Cargo.toml`), so this module does not call
//! `bpf_d_path`, open a map, or attach. It is the byte layout those probes
//! must write into the `events` ring buffer, and the map shapes they must use,
//! when they are filled in after SPIKE-01.
//!
//! Userspace decoding lives in `aw-collector-linux` (`file` module), which can
//! be tested on any host. That module owns the reader. The `#[repr(C)]`
//! headers below are the wire prefix, field for field. Wire integers are
//! little-endian. Do not `memcpy` the struct: it describes order and size, and
//! the collector writes each integer explicitly.
//!
//! # Scope
//!
//! Every probe returns immediately when `bpf_get_current_cgroup_id()` is not in
//! `scope_cgroups` and the tgid is not in `scope_pids`. It does not write
//! `fd_kind`, `fd_io`, or `io_pending`, and it does not reserve a ringbuf slot.
//! Userspace repeats the check, because a record can be decoded from a capture
//! that was not filtered.
//!
//! # What is not dropped in the kernel
//!
//! `/proc`, `/sys`, `/dev`, dynamic-library, and locale paths are **not**
//! filtered here. The pipeline folds them and keeps the count (linux.md §2.2).
//! A failed open (`EACCES`, `ENOENT`, and the rest) is still a record: `result`
//! carries the errno and the path is still reported.
//!
//! # Read and write are aggregated
//!
//! `sys_exit_read` / `pread64` / `readv` / `preadv` and the write counterparts
//! do not emit one event per call. They add into [`FdIo`] keyed by
//! `(tgid, fd)`, and only when [`FdKindValue`] says the fd is a regular file.
//! The totals leave the map on `sys_enter_close`, on process exit, or when
//! userspace asks for a flush. That is one aggregated `FileRead` / `FileWrite`
//! plus a `FileClose`, not a stream (ADR-0011).

#![allow(dead_code)]

mod open;
mod rw;

pub use open::{
    flag, OpenHeader, OpenTail, DIR_CAP, HEADER_LEN as OPEN_HEADER_LEN, KIND_CREATE,
    KIND_DELETE, KIND_OPEN, KIND_RENAME, NAME_CAP, OPEN_PROBES, PATH_CAP,
};
pub use rw::{
    FdIo, FdIoKey, FdKindKey, FdKindValue, FlushRecord, IoPending, TransferRecord,
    FD_IO_CAP, FD_IO_MAP, FD_KIND_CAP, FD_KIND_MAP, FLUSH_HEADER_LEN, IO_PENDING_MAP,
    KIND_CLOSE, KIND_EXIT_FLUSH, KIND_MMAP, KIND_TRANSFER, RW_PROBES, TRANSFER_HEADER_LEN,
};

/// `events` ringbuf record tags written by the file probes.
///
/// Process records (`aw-ebpf` `proc`) and network records (`aw-ebpf` `net`)
/// use their own `kind` / `tag` numbers inside their own families. A reader
/// that shares one ringbuf must branch on the probe, not on this number
/// alone. The numbers here are stable for the file family.
pub const RECORD_OPEN: u32 = 1;
pub const RECORD_RW: u32 = 2;

/// `fd_kind` values. `0` is not a kind: an fd with no row is unknown, and
/// read/write accounting skips it rather than guessing "regular".
pub const FD_REGULAR: u8 = 1;
pub const FD_SOCKET: u8 = 2;
pub const FD_PIPE: u8 = 3;
pub const FD_OTHER: u8 = 4;

/// How the path bytes were obtained.
pub const PATH_D_PATH: u8 = 1;
pub const PATH_USER: u8 = 2;
pub const PATH_DENTRY: u8 = 3;
pub const PATH_PROC_FD: u8 = 4;

/// `f_mode` / open-flag intent, packed into one `u8` for the record.
pub const ACCESS_READ: u8 = 1;
pub const ACCESS_WRITE: u8 = 2;
pub const ACCESS_READ_WRITE: u8 = 3;
pub const ACCESS_EXEC: u8 = 4;

/// Which side of a `sendfile` / `splice` / `copy_file_range` the fd is.
pub const END_NONE: u8 = 0;
pub const END_FILE: u8 = 1;
pub const END_SOCKET: u8 = 2;
pub const END_PIPE: u8 = 3;

/// `io_pending` row kinds. Userspace turns a non-empty row into a `Gap`.
pub const PENDING_MAP_FULL: u8 = 1;
pub const PENDING_RING_FULL: u8 = 2;
