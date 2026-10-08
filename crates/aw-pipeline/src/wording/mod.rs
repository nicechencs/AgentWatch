//! Fixed wording templates and the banned-phrase lint (P3-PIPE-03).
//!
//! Every user-facing conclusion comes from [`render`]. The Chinese and English
//! tables are compiled in from `zh.toml` / `en.toml` and parsed once. A missing
//! parameter is an error: render never substitutes an empty string and never
//! returns a half-filled sentence. Path- and host-shaped parameter values have
//! the home-directory user segment replaced before they are interpolated.
//!
//! [`lint`] checks a finished string against evidence-model §7. It does not
//! guess which template produced the text. A caller that rendered
//! `evidence.content_match` passes [`RuleId::ContentMatchPhrase`] to
//! [`lint_allowing`].

mod lint;
mod render;

pub use lint::{lint, lint_allowing, RuleId, Violation};
pub use render::{render, template_key_mismatch, Lang, WordingError};
