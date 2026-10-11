//! Failures from opening a database, migrating it, or writing a batch.
//!
//! Display text names the operation and the SQLite or IO message. It does not
//! include argv, environment values, URLs, or request headers.

use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

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
    /// SQLite waited for a writer and still returned `SQLITE_BUSY` or
    /// `SQLITE_LOCKED`. The elapsed time is measured around the public store
    /// operation, never guessed from the configured timeout.
    Busy {
        /// Operation that reached SQLite while the database was busy.
        op: &'static str,
        /// Actual elapsed time before SQLite returned the busy error.
        waited: Duration,
        /// SQLite's English diagnostic. It is for logs and machine detail,
        /// not for a human-facing message.
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
    /// An existing database was not already using WAL. Reopening it must not
    /// change journal mode because that needs a lock shared with live writers.
    UnexpectedJournalMode {
        /// Value returned by `PRAGMA journal_mode`.
        found: String,
    },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { op, path, source } => match path {
                Some(path) => write!(f, "{op} failed for {path}: {source}", path = path.display()),
                None => write!(f, "{op} failed: {source}"),
            },
            Self::Sqlite { op, source } => write!(f, "{op}: {source}"),
            Self::Busy { op, waited, source } => {
                write!(f, "{op}: database remained busy after {waited:?}: {source}")
            }
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
            Self::UnexpectedJournalMode { found } => {
                write!(f, "database journal_mode is {found}, expected wal")
            }
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Sqlite { source, .. } => Some(source),
            Self::Busy { source, .. } => Some(source),
            Self::BadSchemaVersion { .. }
            | Self::VersionMismatch { .. }
            | Self::ReadOnly
            | Self::UnexpectedJournalMode { .. } => None,
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

    /// Turn a SQLite busy/locked failure into a measured busy error.
    #[must_use]
    pub(crate) fn with_busy_elapsed(self, started: Instant) -> Self {
        match self {
            Self::Sqlite { op, source } if sqlite_busy(&source) => Self::Busy {
                op,
                waited: started.elapsed(),
                source,
            },
            other => other,
        }
    }

    /// Seconds to present to a person after a measured busy failure.
    #[must_use]
    pub fn busy_waited_seconds(&self) -> Option<u64> {
        match self {
            Self::Busy { waited, .. } => Some(waited.as_secs().max(1)),
            _ => None,
        }
    }

    /// SQLite's diagnostic for structured JSON/log detail only.
    #[must_use]
    pub fn busy_detail(&self) -> Option<String> {
        match self {
            Self::Busy { op, source, .. } => Some(format!("{op}: {source}")),
            _ => None,
        }
    }
}

fn sqlite_busy(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked,
                ..
            },
            _
        )
    )
}
