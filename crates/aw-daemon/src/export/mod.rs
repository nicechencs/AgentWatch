//! Human-readable export (P3-DAEMON-01).
//!
//! JSONL and CSV rows stay in `aw-store`; [`data`] frames them as a response.
//! [`markdown`] builds the report. Nothing here opens files or writes a
//! session directory.

pub(crate) mod data;
pub(crate) mod markdown;
