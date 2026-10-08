//! Ring-buffer record decoders.
//!
//! Each submodule turns one probe family's bytes into [`aw_core::RawEvent`].
//! None of them open `/proc`, load BPF, or call a Linux API, so the tests run
//! on any host.

pub mod proc;

// TCP/UDP records are decoded by `crate::netdecode`, not a submodule here.
// P1-LNX-03 landed while this module was being created for the process probes,
// and moving it would have raced that change. The two decoders do not share types.
