//! SQLite connection setup shared by the store and daemon-side readers.
//!
//! Every connection gets the same busy handler before it issues any other
//! statement.  Persistent database settings deliberately do not live here:
//! changing `journal_mode` or `auto_vacuum` while another connection writes
//! needs an exclusive lock.  [`crate::Store`] applies those two settings only
//! while creating an empty database.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

#[cfg(feature = "test-support")]
use crate::test_support;

/// How long SQLite waits for an existing writer before returning `SQLITE_BUSY`.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(8);

/// Configure a newly opened SQLite connection.
///
/// This must remain the first database operation on every connection.  The
/// remaining connection-local settings belong to [`crate::Store`], whose
/// writable connections need them, rather than to read-only inspection opens.
pub fn configure_connection(conn: &mut Connection) -> rusqlite::Result<()> {
    let started = std::time::Instant::now();
    conn.busy_timeout(BUSY_TIMEOUT)?;
    #[cfg(feature = "test-support")]
    test_support::record("sqlite3_busy_timeout", started.elapsed());
    #[cfg(not(feature = "test-support"))]
    let _ = started;
    Ok(())
}

/// Open a connection with the shared busy timeout installed first.
pub fn open_connection(path: impl AsRef<Path>) -> rusqlite::Result<Connection> {
    let started = std::time::Instant::now();
    let mut conn = Connection::open(path)?;
    #[cfg(feature = "test-support")]
    test_support::record("sqlite3_open", started.elapsed());
    #[cfg(not(feature = "test-support"))]
    let _ = started;
    configure_connection(&mut conn)?;
    #[cfg(feature = "test-support")]
    test_support::install_profile(&mut conn);
    Ok(conn)
}

/// Open an in-memory connection with the shared busy timeout installed first.
///
/// Unit tests use this rather than bypassing the production connection setup.
pub fn open_in_memory_connection() -> rusqlite::Result<Connection> {
    let started = std::time::Instant::now();
    let mut conn = Connection::open_in_memory()?;
    #[cfg(feature = "test-support")]
    test_support::record("sqlite3_open_in_memory", started.elapsed());
    #[cfg(not(feature = "test-support"))]
    let _ = started;
    configure_connection(&mut conn)?;
    #[cfg(feature = "test-support")]
    test_support::install_profile(&mut conn);
    Ok(conn)
}

/// Open a connection with `flags` and the shared busy timeout installed first.
pub fn open_connection_with_flags(
    path: impl AsRef<Path>,
    flags: OpenFlags,
) -> rusqlite::Result<Connection> {
    let started = std::time::Instant::now();
    let mut conn = Connection::open_with_flags(path, flags)?;
    #[cfg(feature = "test-support")]
    test_support::record("sqlite3_open_with_flags", started.elapsed());
    #[cfg(not(feature = "test-support"))]
    let _ = started;
    configure_connection(&mut conn)?;
    #[cfg(feature = "test-support")]
    test_support::install_profile(&mut conn);
    Ok(conn)
}
