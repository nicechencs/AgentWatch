//! Load-time errors. Every one names the file and the 1-based line it came from.
//!
//! A rejected rule is never half-loaded. The caller gets the whole set back or
//! one error. Parameter values, paths, and hosts are not copied into the text:
//! the message names the rule id, the field, and the offending literal.

use std::path::PathBuf;

/// Why a rule file was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    /// The file is not TOML, or not the shape this engine reads.
    Syntax {
        /// Source file. `None` for a compiled-in rule.
        file: Option<PathBuf>,
        /// 1-based line of the failure.
        line: u32,
        /// What was wrong, without any rule body text.
        detail: String,
    },
    /// A load-time constraint failed: evidence, severity, wording, or window.
    Invalid {
        /// Source file. `None` for a compiled-in rule.
        file: Option<PathBuf>,
        /// 1-based line of the field that failed.
        line: u32,
        /// Rule id, when the file got that far.
        rule_id: String,
        /// What the engine refused.
        detail: String,
    },
    /// A `where` expression is not the shared filter grammar.
    Where {
        /// Source file. `None` for a compiled-in rule.
        file: Option<PathBuf>,
        /// 1-based line of the `where` value.
        line: u32,
        /// Rule id.
        rule_id: String,
        /// Step alias the expression belongs to.
        step: String,
        /// The filter parser's own message, which already carries its column.
        detail: String,
    },
    /// A user rule directory could not be read.
    Io {
        /// The path that failed.
        path: PathBuf,
        /// OS error text.
        detail: String,
    },
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syntax { file, line, detail } => {
                write!(f, "{}:{line}: {detail}", file_label(file.as_deref()))
            }
            Self::Invalid {
                file,
                line,
                rule_id,
                detail,
            } => {
                write!(
                    f,
                    "{}:{line}: rule `{rule_id}`: {detail}",
                    file_label(file.as_deref())
                )
            }
            Self::Where {
                file,
                line,
                rule_id,
                step,
                detail,
            } => {
                write!(
                    f,
                    "{}:{line}: rule `{rule_id}` step `{step}`: {detail}",
                    file_label(file.as_deref())
                )
            }
            Self::Io { path, detail } => {
                write!(f, "{}: {detail}", path.display())
            }
        }
    }
}

impl std::error::Error for RuleError {}

impl RuleError {
    /// 1-based line, when the error has one. Directory errors have none.
    pub fn line(&self) -> Option<u32> {
        match self {
            Self::Syntax { line, .. } | Self::Invalid { line, .. } | Self::Where { line, .. } => {
                Some(*line)
            }
            Self::Io { .. } => None,
        }
    }
}

fn file_label(file: Option<&std::path::Path>) -> String {
    match file {
        Some(path) => path.display().to_string(),
        None => "<builtin>".to_owned(),
    }
}

/// 1-based line of the byte `offset` inside `source`.
pub(crate) fn line_of(source: &str, offset: usize) -> u32 {
    let offset = offset.min(source.len());
    let mut line = 1_u32;
    for ch in source[..offset].chars() {
        if ch == '\n' {
            line = line.saturating_add(1);
        }
    }
    line
}
