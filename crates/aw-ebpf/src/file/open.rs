//! Open / create / delete / rename record (P2-LNX-01, linux.md §2.2).
//!
//! One record, four `kind` values. The tail is the path (and, for a rename,
//! the destination path). A directory create (`mkdirat`) uses `KIND_CREATE`
//! with [`flag::IS_DIR`].
//!
//! # Probe order
//!
//! ebpf-full tries the hooks in [`OPEN_PROBES`] order and keeps the first that
//! attaches. ebpf-lite skips the LSM and fexit rows and uses the tracepoints.
//! A hook that fails to attach is that hook's problem: the loader writes a
//! `Gap` for it and tries the next row. This file does not attach.
//!
//! | kind | preferred hook | fallback |
//! |---|---|---|
//! | [`KIND_OPEN`] | `lsm/file_open` | `fexit/do_filp_open`, then `sys_exit_openat` / `openat2` |
//! | [`KIND_CREATE`] | `lsm/path_mkdir` (directories) or `O_CREAT` on the open path | `sys_exit_mkdirat`, `sys_exit_openat` with `O_CREAT` |
//! | [`KIND_DELETE`] | `lsm/path_unlink` | `sys_enter_unlinkat` |
//! | [`KIND_RENAME`] | `lsm/path_rename` | `sys_enter_renameat2` |
//!
//! `lsm/file_open` and `fexit/do_filp_open` call `bpf_d_path` and set
//! [`flag::PATH_RESOLVED`]. The tracepoint fallback copies the user string
//! (`bpf_probe_read_user`) and leaves that flag clear: the string may be
//! relative, and userspace joins it with the process cwd. That join still
//! reports `path_resolved = false` (linux.md §2.2). A path longer than
//! [`PATH_CAP`] is cut and sets [`flag::PATH_TRUNCATED`]; it is not dropped.
//!
//! # `fd_kind`
//!
//! A successful open of a regular file, socket, or pipe writes one
//! [`super::FdKindValue`] into `fd_kind`, keyed by [`super::FdKindKey`].
//! Failed opens do not, because there is no fd. The map is read by the
//! read/write probes (P2-LNX-02); this record only describes the write.

use super::{
    ACCESS_EXEC, ACCESS_READ, ACCESS_READ_WRITE, ACCESS_WRITE, PATH_D_PATH, PATH_DENTRY,
    PATH_PROC_FD, PATH_USER, RECORD_OPEN,
};

/// `lsm/file_open`, `fexit/do_filp_open`, `sys_exit_openat`, `sys_exit_openat2`.
pub const KIND_OPEN: u32 = 1;
/// `mkdirat`, or an open that created the inode (`O_CREAT` and a new inode).
pub const KIND_CREATE: u32 = 2;
/// `unlinkat` / `path_unlink`.
pub const KIND_DELETE: u32 = 3;
/// `renameat2` / `path_rename`.
pub const KIND_RENAME: u32 = 4;

/// Path byte cap, including the destination of a rename. A longer path is cut.
pub const PATH_CAP: usize = 4096;

/// Directory-fd path cap, used only as a comment for the userspace join.
/// The record does not carry the directory path; userspace reads it from
/// `/proc/<tgid>/fd/<dirfd>` when `dirfd` is not `AT_FDCWD`.
pub const DIR_CAP: usize = 4096;

/// Name byte cap for the last component of a `FAN_REPORT_DFID_NAME`-style
/// dentry walk. The eBPF path does not use this; it is here so the userspace
/// fanotify decoder and this layout share one number.
pub const NAME_CAP: usize = 255;

/// Header size in bytes, before the path tail (and the rename destination).
pub const HEADER_LEN: usize = 64;

/// Hooks, in the order a loader tries them. `source` is `linux.ebpf/<name>`
/// with the slash in the hook replaced: `lsm/file_open` → `lsm_file_open`.
pub const OPEN_PROBES: [&str; 9] = [
    "lsm_file_open",
    "fexit_do_filp_open",
    "tp_openat",
    "tp_openat2",
    "lsm_path_unlink",
    "tp_unlinkat",
    "lsm_path_rename",
    "tp_renameat2",
    "tp_mkdirat",
];

/// Flag bits in [`OpenHeader::flags`].
pub mod flag {
    /// `result` is a real errno (or 0 for success). Unset means the probe did
    /// not read it; userspace must not treat the integer as success.
    pub const HAS_RESULT: u32 = 1 << 0;
    /// `fd` is the new descriptor. Unset on delete, rename, mkdir, and on an
    /// open that failed before an fd existed.
    pub const HAS_FD: u32 = 1 << 1;
    /// `access` was read from `f_mode` or from the open flags.
    pub const HAS_ACCESS: u32 = 1 << 2;
    /// The open created the inode (`O_CREAT` and the inode was new).
    pub const CREATED: u32 = 1 << 3;
    /// The probe could not tell whether the inode was new. `created` stays
    /// unknown in userspace; this bit is **not** "not created".
    pub const CREATED_UNKNOWN: u32 = 1 << 4;
    /// `O_TRUNC` was set, or `f_mode` showed a truncate.
    pub const TRUNCATED: u32 = 1 << 5;
    /// Truncate state was not read.
    pub const TRUNCATED_UNKNOWN: u32 = 1 << 6;
    /// Path bytes came from `bpf_d_path` (or an equivalent absolute walk).
    pub const PATH_RESOLVED: u32 = 1 << 7;
    /// Path bytes are present after the header.
    pub const HAS_PATH: u32 = 1 << 8;
    /// The kernel path was longer than [`super::PATH_CAP`].
    pub const PATH_TRUNCATED: u32 = 1 << 9;
    /// Rename destination bytes follow the source path.
    pub const HAS_DST: u32 = 1 << 10;
    /// The destination was longer than [`super::PATH_CAP`].
    pub const DST_TRUNCATED: u32 = 1 << 11;
    /// The object is a directory (`mkdirat`, or unlink/rename of a directory).
    pub const IS_DIR: u32 = 1 << 12;
    /// Directory-ness was not read. Userspace leaves `is_dir` as `None`.
    pub const IS_DIR_UNKNOWN: u32 = 1 << 13;
    /// `dirfd` was read and is not `AT_FDCWD`.
    pub const HAS_DIRFD: u32 = 1 << 14;
    /// `bpf_d_path` was not allowed on this hook (linux.md §6). The path is
    /// the user string, and [`PATH_RESOLVED`] stays clear.
    pub const D_PATH_DENIED: u32 = 1 << 15;
}

/// How [`OpenHeader::path_from`] should be read.
pub fn path_from_name(path_from: u8) -> &'static str {
    match path_from {
        PATH_D_PATH => "bpf_d_path",
        PATH_USER => "user",
        PATH_DENTRY => "dentry",
        PATH_PROC_FD => "proc_fd",
        _ => "unknown",
    }
}

/// Fixed prefix of one open-family record. The path tail follows it.
///
/// Field order is the wire order. Alignment of these primitive types produces
/// no implicit padding; [`HEADER_LEN`] locks that.
#[repr(C)]
pub struct OpenHeader {
    /// [`RECORD_OPEN`]. Readers of a mixed ringbuf branch on this first.
    pub tag: u32,
    /// [`KIND_OPEN`], [`KIND_CREATE`], [`KIND_DELETE`], or [`KIND_RENAME`].
    pub kind: u32,
    /// `bpf_ktime_get_ns`.
    pub ts_mono_ns: u64,
    /// Thread-group id. The scope check uses this, not `pid`.
    pub tgid: u32,
    /// Thread id. `0` with [`flag::HAS_FD`] still clear is "not read" only when
    /// the probe says so; a real tid of 0 does not occur.
    pub pid: u32,
    /// New fd for an open. Valid when [`flag::HAS_FD`] is set.
    pub fd: u32,
    /// Directory fd for `*at` calls. Valid when [`flag::HAS_DIRFD`] is set.
    /// `AT_FDCWD` (`-100`) is not stored: the probe leaves the flag clear.
    pub dirfd: i32,
    /// Errno, positive, Linux numbering. `0` is success **only** when
    /// [`flag::HAS_RESULT`] is set. A failed open is still emitted.
    pub result: i32,
    /// [`super::ACCESS_READ`] and friends. Valid when [`flag::HAS_ACCESS`] is set.
    pub access: u8,
    /// [`super::PATH_D_PATH`] and friends. `0` means the probe did not say.
    pub path_from: u8,
    /// Reserved. Write 0.
    pub _pad0: u16,
    /// [`flag`] bits.
    pub flags: u32,
    /// Path bytes after the header. Never greater than [`PATH_CAP`].
    pub path_len: u16,
    /// Destination bytes after the path. Never greater than [`PATH_CAP`].
    /// Zero unless [`flag::HAS_DST`] is set (rename).
    pub dst_len: u16,
    /// Must be written as 0. Brings the header to [`HEADER_LEN`] so the path
    /// tail starts at a stable offset. Readers skip it.
    pub reserved: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<OpenHeader>() == HEADER_LEN);
const _: () = assert!(RECORD_OPEN == 1);

/// Tail layout, documented so the userspace decoder and a future writer agree.
///
/// Not a struct the probe allocates. The bytes sit after [`OpenHeader`]:
/// `path_len` bytes, then `dst_len` bytes. Neither is NUL-terminated; the
/// lengths are the only delimiter. A NUL inside the bytes is part of the
/// path and is a malformed record, not a terminator.
#[repr(C)]
pub struct OpenTail {
    /// Present when [`flag::HAS_PATH`] is set.
    pub path: [u8; PATH_CAP],
    /// Present when [`flag::HAS_DST`] is set.
    pub dst: [u8; PATH_CAP],
}

/// Access byte the open probe writes. `0` is "not read", not "no access".
pub fn access_byte(read: bool, write: bool, exec: bool) -> u8 {
    match (read, write, exec) {
        (true, true, _) => ACCESS_READ_WRITE,
        (true, false, _) => ACCESS_READ,
        (false, true, _) => ACCESS_WRITE,
        (false, false, true) => ACCESS_EXEC,
        (false, false, false) => 0,
    }
}
