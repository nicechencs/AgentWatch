//! Failures from opening a database, migrating it, or writing a batch.
//!
//! Display text names the operation and the SQLite or IO message. It does not
//! include argv, environment values, URLs, or request headers.

use std::fmt;
use std::path::PathBuf;

/// Why [`crate::Store::open`] or [`crate::RecordSink::write_batch`] failed.
#[derive(Debug)]
pub enum StoreError {
    /// Creating the parent directory, copying a backup, or setting the file mode failed.
    Io {
        /// What was being done, for example `backup` or `chmod`.
        op: &'static str,
        /// Path involved, when there is one.
        path: Option<PathBuf>,
        /// OS error.
        source: std::io::Error,
    },
    /// SQLite returned an error. The connection is left unusable for a failed migration
    /// or a failed batch: both roll the transaction back before this is returned.
    Sqlite {
        /// What was being done, for example `migrate` or `write_batch`.
        op: &'static str,
        /// rusqlite error. Displayed, not debug-printed.
        source: rusqlite::Error,
    },
    /// `schema_meta.schema_version` is missing or not an integer.
    BadSchemaVersion {
        /// The raw value, when one was present.
        found: Option<String>,
    },
    /// A migration script ran, then the version row did not match the script number.
    VersionMismatch {
        /// Version the script was supposed to install.
        expected: u32,
        /// Version read back afterwards.
        found: Option<u32>,
    },
    /// The caller asked for a write on a database this binary opened read-only.
    ReadOnly,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { op, path, source } => match path {
                Some(path) => write!(f, "{op} failed for {path}: {source}", path = path.display()),
                None => write!(f, "{op} failed: {source}"),
            },
            Self::Sqlite { op, source } => write!(f, "{op}: {source}"),
            Self::BadSchemaVersion { found } => match found {
                Some(found) => write!(f, "schema_version is not an integer: {found}"),
                None => write!(f, "schema_version is missing"),
            },
            Self::VersionMismatch { expected, found } => {
                write!(
                    f,
                    "schema_version after migration is {found:?}, expected {expected}"
                )
            }
            Self::ReadOnly => write!(f, "database was opened read-only"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Sqlite { source, .. } => Some(source),
            Self::BadSchemaVersion { .. } | Self::VersionMismatch { .. } | Self::ReadOnly => None,
        }
    }
}

impl StoreError {
    pub(crate) fn io(
        op: &'static str,
        path: impl Into<Option<PathBuf>>,
        source: std::io::Error,
    ) -> Self {
        Self::Io {
            op,
            path: path.into(),
            source,
        }
    }

    pub(crate) fn sqlite(op: &'static str, source: rusqlite::Error) -> Self {
        Self::Sqlite { op, source }
    }
}
