//! eslogger JSON lines → process and file events.
//!
//! This module does not spawn a process and does not call a macOS API. It parses
//! one JSON object, drops lines whose subject PID is outside the scope, and
//! notices a hole in `seq_num` or `global_seq_num`.
//!
//! Field paths follow macos.md §1.1. Paths that document marks as awaiting
//! SPIKE-03 are read only when the JSON object actually contains them; a missing
//! path becomes `None` plus `NA(collector_unavailable)`, never a guessed default.
//! SPIKE-03 status is「未开始」, so nothing here treats a path as measured.

mod budget;
mod decode;
mod file;
mod filter;
mod loss;
mod probe;

pub use budget::{
    apply_subscribe_open, BudgetDecision, OpenBudget, SubscribeOpen, DEFAULT_CPU_PERCENT,
    DEFAULT_SUSTAIN,
};
pub use decode::{decode_line, AuditToken, EsEvent, LineDecoder, ResponsibleToken};
pub use file::{FileSubscription, OpenIntent, BYTES_NA, FILE_EVENTS};
pub use filter::{pid_in_scope, LineAction, PidFilter};
pub use loss::{LossDetector, SequenceKind, SequenceLoss};
pub use probe::ProbeError;
