//! eslogger JSON lines → process events.
//!
//! This module does not spawn a process and does not call a macOS API. It parses
//! one JSON object, drops lines whose subject PID is outside the scope, and
//! notices a hole in `seq_num` or `global_seq_num`.
//!
//! Field paths follow macos.md §1.1. Paths that document marks as awaiting
//! SPIKE-03 are read only when the JSON object actually contains them; a missing
//! path becomes `None` plus `NA(collector_unavailable)`, never a guessed default.
//! SPIKE-03 status is「未开始」, so nothing here treats a path as measured.

mod decode;
mod filter;
mod loss;
mod probe;

pub use decode::{decode_line, AuditToken, EsEvent, LineDecoder, ResponsibleToken};
pub use filter::{pid_in_scope, LineAction, PidFilter};
pub use loss::{LossDetector, SequenceKind, SequenceLoss};
pub use probe::ProbeError;
