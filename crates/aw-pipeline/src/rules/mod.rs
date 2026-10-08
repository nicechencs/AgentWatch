//! Correlation rule engine (P3-PIPE-04, P3-PIPE-05).
//!
//! A rule is a small TOML file. [`load_builtin`] reads the eight rules compiled
//! into this crate; [`load_with_user`] layers a directory on top of them and
//! records which built-in rule a user file replaced. Loading is where the
//! constraints from pipeline.md §3.6 are enforced, so a rule that loads can be
//! run without a second check.
//!
//! [`Engine`] matches records as they arrive. It reads time from a [`RuleClock`]
//! and never from the host, and it writes [`FindingDraft`]s rather than rows.
//! Wiring it into the pipeline stage chain is a later change: this module does
//! not touch `stage.rs`.
//!
//! Evidence is decided at load time. The engine copies it onto a finding and
//! does not raise it. `sensitive_read_then_send` emits `"I"` on every path.

mod ast;
mod clock;
mod engine;
mod error;
mod load;
mod parse;
mod record;

pub use ast::{
    EvidenceLevel, KeyField, MatchStep, Rule, Same, Severity, UpgradeIf, DEFAULT_STATE_CAP,
    MAX_WITHIN_NS,
};
pub use clock::{RuleClock, VirtualClock};
pub use engine::{Engine, EngineConfig, FindingDraft, ProcNode, RecordRef, RuleGap, StepOutput};
pub use error::RuleError;
pub use load::{load_builtin, load_with_user, Override, RuleSet};
pub use record::{RuleRecord, StepFacts};
