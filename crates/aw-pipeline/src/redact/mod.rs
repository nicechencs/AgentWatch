//! In-memory redaction (P2-PIPE-03).
//!
//! Runs before aggregate. Replacements are written back onto the event. The
//! pre-redaction text is not logged, not put in errors, and not returned.

mod engine;

pub use engine::{builtin_rules, BuiltinRule, Redactor, UNSAFE_NO_REDACT_FLAG};
