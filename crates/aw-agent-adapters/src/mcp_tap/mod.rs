//! MCP stdio frame splitting and JSON-RPC shape extraction (P6-AGENT-01).
//!
//! This module has no I/O. It does not spawn a process, open a socket, or keep
//! argument or result bytes. The wrapper that copies stdin and stdout lives in
//! `aw-cli`.
//!
//! Fail-open is the caller's job. [`extract`] returning [`ExtractGap`] means the
//! frame was not turned into metadata. The original bytes must still be
//! forwarded. Dropping them would change the MCP session, which this parser is
//! not allowed to do.
//!
//! Content hashes of argument values are not computed. A chunk hash would
//! require holding the value, and this module does not keep values.

mod extract;
mod frame;

pub use extract::{extract, ArgType, ExtractGap, RpcExtract, MAX_KEY_SCALARS};
pub use frame::{push_frames, FrameError, FrameOutcome, Splitter, MAX_FRAME_BYTES};

/// Direction the wrapper observed. The parser does not infer it from the JSON.
pub const DIR_C2S: &str = "c2s";
/// Server to client.
pub const DIR_S2C: &str = "s2c";
