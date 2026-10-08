//! Human-readable export (P3-DAEMON-01).
//!
//! JSONL and CSV stay in `aw-store`. This module only builds the Markdown
//! report. It does not open files and does not write a session directory.

pub(crate) mod markdown;
