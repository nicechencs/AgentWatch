//! Parse errors that carry a source position.
//!
//! The column is a byte offset into the original query, not a character index.
//! Messages name the offending text so a caller can say "column 12: unknown
//! field `domian`".

use thiserror::Error;

/// Why [`super::parse`] rejected a query.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FilterError {
    /// A field name is not in the registry.
    #[error("column {offset}: unknown field `{name}`{suggestion}")]
    UnknownField {
        /// Byte offset of the field name.
        offset: usize,
        /// The text that was written.
        name: String,
        /// `, did you mean \`domain\`` when something close exists, else empty.
        suggestion: String,
    },
    /// The operator is not one this field accepts.
    #[error("column {offset}: operator `{op}` is not valid for `{field}`")]
    BadOperator {
        /// Byte offset of the operator.
        offset: usize,
        /// Field name.
        field: String,
        /// Operator text.
        op: String,
    },
    /// A value could not be read as the field's type.
    #[error("column {offset}: `{value}` is not a valid {expected} for `{field}`")]
    BadValue {
        /// Byte offset of the value.
        offset: usize,
        /// Field name.
        field: String,
        /// What the field expected (`number`, `duration`, `bool`, …).
        expected: &'static str,
        /// The text that was written.
        value: String,
    },
    /// The query is not the grammar in api-and-cli §4.2.
    #[error("column {offset}: expected {expected}, found {found}")]
    Syntax {
        /// Byte offset where parsing stopped.
        offset: usize,
        /// What the grammar wanted.
        expected: &'static str,
        /// What was left, truncated.
        found: String,
    },
}

impl FilterError {
    /// Byte offset of the failure, for callers that only need the position.
    pub fn offset(&self) -> usize {
        match self {
            Self::UnknownField { offset, .. }
            | Self::BadOperator { offset, .. }
            | Self::BadValue { offset, .. }
            | Self::Syntax { offset, .. } => *offset,
        }
    }
}
