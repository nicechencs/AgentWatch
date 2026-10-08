//! Sensitive-path labels (P2-PIPE-02).
//!
//! A match writes `sensitive_rule` and a `sensitive.<rule>` tag. It does not
//! read the file, and it does not emit a finding.

mod glob;
mod rules;

pub use glob::PathGlob;
pub use rules::{expand_home, Hit, Rules};
