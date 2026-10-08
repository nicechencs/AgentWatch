//! Userspace decode of the file records described in `aw-ebpf`'s `file` module.
//!
//! The kernel probes are not loaded here (this crate runs on Windows, and Aya
//! is not a dependency). [`decode`] turns one already-copied record into
//! `FileOpen`, `FileCreate`, `FileDelete`, `FileRename`, an aggregated
//! `FileRead` / `FileWrite`, `FileClose`, or a `Gap`.
//!
//! `aw-ebpf` is not a workspace member, so the layout is repeated here as plain
//! Rust. The sizes are the ones `aw-ebpf/src/file/` locks with `const _: ()`
//! asserts: open header 64, flush 64, transfer 64.
//!
//! A field the record says was not read stays `None` and is marked
//! `NA(collector_unavailable)`. A zero that *was* read stays zero: a successful
//! open has `result = Some(0)`, and a close that counted nothing has
//! `bytes = Some(0)`.
//!
//! Records whose tgid the caller says is out of scope produce nothing. The
//! kernel filter is supposed to have done this already; the check is repeated
//! so a capture that skipped it does not attribute a bystander.

mod decode;
mod path;
mod record;

pub use decode::{
    decode_file, pending_gap, pre_existing_fd, DecodeOutcome, FdPath, FdPathRead, FileDecode,
    FileDecodeError, ProcIdentity, ScopeView, TransferFlow, FIELD_BYTES, SOURCE_FEXIT_OPEN,
    SOURCE_LSM_FILE_OPEN, SOURCE_TP_CLOSE, SOURCE_TP_OPENAT, SOURCE_TP_UNLINKAT,
};
pub use path::{join_cwd, CwdLookup, PathJoin};
pub use record::{
    encode_flush, encode_open, encode_pending, encode_transfer, FlushIn, OpenIn, PendingIn,
    TransferIn,
};
