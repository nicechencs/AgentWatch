//! Process-probe record layout. Nothing here attaches a program.
//!
//! P1-LNX-02 names four tracepoints. Aya is not a dependency of this crate
//! (see `Cargo.toml`), so this file does not call `bpf_probe_read`, open a
//! map, or attach. It is the byte layout those probes must write into the
//! `events` ring buffer when they are filled in after SPIKE-01.
//!
//! Userspace decoding lives in `aw-collector-linux` (`decode::proc`), which
//! can be tested on any host. That module owns the reader. The `#[repr(C)]`
//! header below is the same 64-byte prefix, field for field. Wire integers
//! are little-endian. Do not `memcpy` the struct: it describes order and
//! size, and the collector writes each integer explicitly.
//!
//! | probe | `kind` | what a record carries |
//! |---|---|---|
//! | `sched:sched_process_fork` | 1 | parent tgid, child tgid, child `task->start_time` |
//! | `sched:sched_process_exec` | 2 | filename, tgid, `old_pid`, argv, uid, gid, cgroup id |
//! | `sched:sched_process_exit` | 3 | tgid, `task->exit_code`, leader bit |
//! | `cgroup:cgroup_attach_task` | 4 | tgid, cgroup being left, destination cgroup |
//!
//! `kind` is a `u32` at offset 0. Offsets below match [`ProcRecordHeader`].
//!
//! ```text
//! off  len  field
//!   0    4  kind
//!   4    4  tgid                  child on fork; subject otherwise
//!   8    4  parent_tgid           meaningful when HAS_PARENT is set
//!  12    4  old_pid               sched_process_exec; HAS_OLD_PID
//!  16    8  start_time_ns         task->start_time, monotonic ns since boot
//!  24    4  uid                   HAS_UID
//!  28    4  gid                   HAS_GID
//!  32    8  cgroup_id             cgroup the task is in; HAS_CGROUP
//!  40    8  dst_cgroup_id         cgroup_attach_task destination; HAS_DST_CGROUP
//!  48    4  exit_code_raw         task->exit_code as i32; HAS_EXIT_CODE
//!  52    4  flags                 ProcFlags bits
//!  56    2  argv_len              tail bytes after the filename, ≤ 4096
//!  58    2  filename_len          filename bytes, ≤ 4096
//!  60    4  reserved              write 0; readers ignore it
//!  64       filename bytes, then argv bytes
//! ```
//!
//! Argv is a prefix of `mm->arg_start .. arg_end`, at most [`ARGV_CAP`] bytes,
//! copied through a per-CPU scratch array (not allocated here). A longer
//! region sets [`ProcFlags::ARGV_TRUNCATED`] and still sends only 4096 bytes.
//! The environment is not copied. A `CLONE_THREAD` fork sets
//! [`ProcFlags::IS_THREAD`] and userspace emits no process event. An exit
//! sets [`ProcFlags::IS_LEADER`] only for the thread-group leader; userspace
//! emits `ProcessExit` only then.
//!
//! `start_time_ns` is the input to `proc_uid = hash(boot_id, tgid, start_time)`
//! (ADR-0007). This crate does not hash: it has no `aw-core`, and the boot id
//! is a userspace value (`/proc/sys/kernel/random/boot_id`).

#![allow(dead_code)]

/// `sched_process_fork`.
pub const KIND_FORK: u32 = 1;
/// `sched_process_exec`.
pub const KIND_EXEC: u32 = 2;
/// `sched_process_exit`.
pub const KIND_EXIT: u32 = 3;
/// `cgroup_attach_task`.
pub const KIND_CGROUP: u32 = 4;

/// Argv byte cap. Matches `aw-collector-linux` `decode::proc::ARGV_CAP`.
pub const ARGV_CAP: usize = 4096;

/// Filename byte cap. A longer path is not a valid record.
pub const FILENAME_CAP: usize = 4096;

/// Header size in bytes, before the filename and argv tails.
pub const HEADER_LEN: usize = 64;

/// Flag bits in `ProcRecordHeader::flags`.
pub mod flag {
    /// `parent_tgid` was read. Unset means unknown, not pid 0.
    pub const HAS_PARENT: u32 = 1 << 0;
    /// `uid` was read.
    pub const HAS_UID: u32 = 1 << 1;
    /// `gid` was read.
    pub const HAS_GID: u32 = 1 << 2;
    /// `exit_code_raw` is `task->exit_code`.
    pub const HAS_EXIT_CODE: u32 = 1 << 3;
    /// Subject is the thread-group leader. Exit events without this are dropped.
    pub const IS_LEADER: u32 = 1 << 4;
    /// `mm->arg_end - mm->arg_start` was greater than [`super::ARGV_CAP`].
    pub const ARGV_TRUNCATED: u32 = 1 << 5;
    /// Fork was `CLONE_THREAD`. Userspace does not emit a process event.
    pub const IS_THREAD: u32 = 1 << 6;
    /// `old_pid` was read (`sched_process_exec`).
    pub const HAS_OLD_PID: u32 = 1 << 7;
    /// Filename tail is present.
    pub const HAS_FILENAME: u32 = 1 << 8;
    /// `start_time_ns` was read. Without it, userspace cannot build a `ProcUid`.
    pub const HAS_START_TIME: u32 = 1 << 9;
    /// Argv tail is present (it may be empty). Unset means argv was not copied.
    pub const HAS_ARGV: u32 = 1 << 10;
    /// `cgroup_id` was read.
    pub const HAS_CGROUP: u32 = 1 << 11;
    /// `dst_cgroup_id` was read.
    pub const HAS_DST_CGROUP: u32 = 1 << 12;
}

/// Fixed prefix of one process record. Tails (filename, argv) follow it.
///
/// Field order is the wire order. Alignment of these primitive types produces
/// no implicit padding; [`HEADER_LEN`] locks that.
#[repr(C)]
pub struct ProcRecordHeader {
    /// [`KIND_FORK`], [`KIND_EXEC`], [`KIND_EXIT`], or [`KIND_CGROUP`].
    pub kind: u32,
    /// Child tgid on fork; the subject tgid otherwise.
    pub tgid: u32,
    /// Parent tgid. Valid when [`flag::HAS_PARENT`] is set.
    pub parent_tgid: u32,
    /// `sched_process_exec` old pid. Valid when [`flag::HAS_OLD_PID`] is set.
    pub old_pid: u32,
    /// `task->start_time`, monotonic nanoseconds since boot.
    pub start_time_ns: u64,
    /// Real uid. Valid when [`flag::HAS_UID`] is set.
    pub uid: u32,
    /// Real gid. Valid when [`flag::HAS_GID`] is set.
    pub gid: u32,
    /// Cgroup the task is in (the one being left, on an attach). [`flag::HAS_CGROUP`].
    pub cgroup_id: u64,
    /// Destination cgroup of `cgroup_attach_task`. [`flag::HAS_DST_CGROUP`].
    pub dst_cgroup_id: u64,
    /// Raw `task->exit_code`. [`flag::HAS_EXIT_CODE`].
    pub exit_code_raw: i32,
    /// [`flag`] bits.
    pub flags: u32,
    /// Number of argv bytes after the filename. Never greater than [`ARGV_CAP`].
    pub argv_len: u16,
    /// Number of filename bytes after the header. Never greater than [`FILENAME_CAP`].
    pub filename_len: u16,
    /// Must be written as 0. Readers skip it.
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<ProcRecordHeader>() == HEADER_LEN);
