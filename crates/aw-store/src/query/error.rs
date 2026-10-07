//! Query failures. Display text names the operation. It does not include
//! argv, environment values, URLs, or request headers.

use std::fmt;

/// Why a query or a filter expression was rejected.
#[derive(Debug)]
pub enum QueryError {
    /// The filter string is not a valid expression.
    Parse {
        /// Byte offset into the filter where parsing stopped.
        offset: usize,
        /// What was wrong, without the user's value.
        message: &'static str,
    },
    /// A field this layer does not implement. `path` is reserved for P2.
    UnsupportedField {
        /// The field name, which is an identifier, not a user value.
        field: String,
    },
    /// A field name that is not in the P1 set and not a known later field.
    UnknownField {
        /// The field name.
        field: String,
    },
    /// An operator that field does not accept.
    BadOperator {
        /// Field the operator was applied to.
        field: &'static str,
        /// Operator text.
        op: &'static str,
    },
    /// A value that could not be read as the field's type.
    BadValue {
        /// Field the value was bound to.
        field: &'static str,
        /// Why, without echoing the value.
        message: &'static str,
    },
    /// `group_by` or `sort` is not one of the documented tokens.
    BadArgument {
        /// Which argument.
        name: &'static str,
        /// Allowed tokens, for the caller.
        expected: &'static str,
    },
    /// SQLite returned an error. The message is rusqlite's Display, not Debug.
    Sqlite {
        /// What was being done.
        op: &'static str,
        /// rusqlite error.
        source: rusqlite::Error,
    },
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { offset, message } => {
                write!(f, "filter parse error at {offset}: {message}")
            }
            Self::UnsupportedField { field } => {
                write!(f, "unsupported field: {field}")
            }
            Self::UnknownField { field } => write!(f, "unknown field: {field}"),
            Self::BadOperator { field, op } => {
                write!(f, "operator {op} is not valid for {field}")
            }
            Self::BadValue { field, message } => write!(f, "bad value for {field}: {message}"),
            Self::BadArgument { name, expected } => {
                write!(f, "bad {name}: expected {expected}")
            }
            Self::Sqlite { op, source } => write!(f, "{op}: {source}"),
        }
    }
}

impl std::error::Error for QueryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl QueryError {
    pub(crate) fn sqlite(op: &'static str, source: rusqlite::Error) -> Self {
        Self::Sqlite { op, source }
    }
}
