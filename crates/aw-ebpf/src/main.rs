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

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
