//! Empty eBPF placeholder.
//!
//! P1-LNX-01 only stands up the crate. Real probes (exec, openat, tcp_sendmsg)
//! land in P1-LNX-02 and P1-LNX-03, after SPIKE-01. This binary does not call
//! Aya and does not attach to anything.
//!
//! Shared map names and sizes live in `aw-collector-linux` (`maps` module) so
//! they can be unit-tested without a BPF toolchain. When the probes are written
//! they must use the same names:
//!
//! - `scope_cgroups` — cgroup ids in the session
//! - `scope_pids` — tgids in the session
//! - `events` — ringbuf, 16 MiB
//! - `lost` — per-CPU counter of events the ringbuf could not accept
//!
//! P1-LNX-02 adds `proc`: the process-probe record layout (fork, exec, exit,
//! cgroup attach). P1-LNX-03 adds `net`: the TCP/UDP record layout. Both are
//! description only. No probe is attached from here.
//!
//! P2-LNX-01 / P2-LNX-02 add `file`: the open/create/delete/rename record, the
//! `fd_kind` and `fd_io` maps, and the close/mmap/sendfile records. Same rule:
//! layout only, nothing is attached from here.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

mod file;
mod net;
mod proc;

/// Names the file-probe layouts so a bpf-target build keeps them. The value
/// is the open-record header size; a reader uses the constants in `file`.
#[no_mangle]
#[allow(dead_code)]
pub static FILE_OPEN_HEADER_LEN: usize = file::OPEN_HEADER_LEN;

/// Flush-record size. See `file::FLUSH_HEADER_LEN`.
#[no_mangle]
#[allow(dead_code)]
pub static FILE_FLUSH_HEADER_LEN: usize = file::FLUSH_HEADER_LEN;

/// Transfer-record size. `bytes` is at offset 40 inside it.
#[no_mangle]
#[allow(dead_code)]
pub static FILE_TRANSFER_HEADER_LEN: usize = file::TRANSFER_HEADER_LEN;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
