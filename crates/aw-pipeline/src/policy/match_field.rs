//! Field matchers: `exact`, `prefix`, `glob`, `regex`.
//!
//! Globs are the same subset as [`crate::sensitive::PathGlob`]: `*` inside one
//! segment, `**` across separators, `?` one non-separator. A regex uses the
//! `regex` crate, so a hostile pattern cannot stall the matcher. Patterns are
//! compiled once, at load.

use regex::Regex;

use crate::sensitive::PathGlob;

/// One compiled comparison.
#[derive(Debug, Clone)]
pub enum Matcher {
    /// Whole string equal.
    Exact(String),
    /// `text` starts with this prefix.
    Prefix(String),
    /// Path-style glob. See [`PathGlob`].
    Glob(PathGlob),
    /// Linear-time regular expression.
    Regex(Regex),
}

impl Matcher {
    /// Compile one matcher object. Exactly one of `exact`, `prefix`, `glob`,
    /// `regex` may be set.
    ///
    /// # Errors
    ///
    /// [`MatchError::Empty`], [`MatchError::Ambiguous`], or
    /// [`MatchError::BadRegex`]. The regex source is not included: a pattern
    /// can be copied from a value the operator did not mean to log.
    pub fn compile(value: &toml::Value) -> Result<Self, MatchError> {
        let Some(table) = value.as_table() else {
            return Err(MatchError::NotTable);
        };
        let mut chosen: Option<Self> = None;
        for (key, raw) in table {
            let text = raw.as_str().ok_or(MatchError::NotString)?;
            let next = match key.as_str() {
                "exact" => Self::Exact(text.to_owned()),
                "prefix" => Self::Prefix(text.to_owned()),
                "glob" => Self::Glob(PathGlob::compile(text, false)),
                "regex" => {
                    let regex = Regex::new(text).map_err(|_| MatchError::BadRegex)?;
                    Self::Regex(regex)
                }
                _ => return Err(MatchError::UnknownKind),
            };
            if chosen.is_some() {
                return Err(MatchError::Ambiguous);
            }
            chosen = Some(next);
        }
        chosen.ok_or(MatchError::Empty)
    }

    /// `true` when `text` satisfies this matcher.
    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        match self {
            Self::Exact(want) => text == want,
            Self::Prefix(prefix) => text.starts_with(prefix.as_str()),
            Self::Glob(glob) => glob.is_match(text),
            Self::Regex(regex) => regex.is_match(text),
        }
    }
}

/// Why a matcher object was refused. Display names the kind, never the pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchError {
    /// The value was not a table.
    NotTable,
    /// A matcher value was not a string.
    NotString,
    /// No `exact` / `prefix` / `glob` / `regex` key.
    Empty,
    /// More than one of those keys was set.
    Ambiguous,
    /// The key is not one of the four kinds.
    UnknownKind,
    /// `regex` did not compile.
    BadRegex,
}

impl std::fmt::Display for MatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::NotTable => "match value is not a table",
            Self::NotString => "match value is not a string",
            Self::Empty => "match has no exact, prefix, glob, or regex",
            Self::Ambiguous => "match has more than one of exact, prefix, glob, regex",
            Self::UnknownKind => "match kind is not exact, prefix, glob, or regex",
            Self::BadRegex => "match regex did not compile",
        };
        f.write_str(text)
    }
}
