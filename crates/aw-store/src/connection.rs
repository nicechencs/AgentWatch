//! SQLite connection setup shared by the store and daemon-side readers.
//!
//! Every connection gets the same busy handler before it issues any other
//! statement.  Persistent database settings deliberately do not live here:
//! changing `journal_mode` or `auto_vacuum` while another connection writes
//! needs an exclusive lock.  [`crate::Store`] applies those two settings only
//! while creating an empty database.

use std::cell::Cell;
use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags};

#[cfg(feature = "test-support")]
use crate::test_support;

/// How long SQLite waits for an existing writer before returning `SQLITE_BUSY`.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Copy)]
struct BusyWindow {
    started: Instant,
    deadline: Instant,
}

thread_local! {
    /// A caller may bound several SQLite operations with one deadline.  SQLite
    /// invokes a busy handler on the same thread as the operation that needs a
    /// lock, so this remains local to the request and never affects another
    /// daemon worker.
    static BUSY_DEADLINE: Cell<Option<BusyWindow>> = const { Cell::new(None) };
}

/// One end-to-end budget for a sequence of SQLite operations on this thread.
///
/// Connections opened while this guard lives use a busy handler that stops at
/// the shared deadline.  Without it, [`BUSY_TIMEOUT`] remains a per-statement
/// SQLite timeout, which is appropriate for independent background work.
pub struct BusyDeadline {
    previous: Option<BusyWindow>,
    window: BusyWindow,
}

impl BusyDeadline {
    /// Start an end-to-end SQLite lock budget for the current thread.
    #[must_use]
    pub fn start(timeout: Duration) -> Self {
        let started = Instant::now();
        let candidate = BusyWindow {
            started,
            deadline: started + timeout,
        };
        let previous = BUSY_DEADLINE.with(Cell::get);
        // An inner DB helper must not restart a request's eight-second clock.
        // Preserve the outer start and only shorten its deadline if needed.
        let window = previous.map_or(candidate, |outer| BusyWindow {
            started: outer.started,
            deadline: outer.deadline.min(candidate.deadline),
        });
        BUSY_DEADLINE.with(|current| current.set(Some(window)));
        Self { previous, window }
    }

    /// Elapsed time in the bounded sequence.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.window.started.elapsed()
    }
}

impl Drop for BusyDeadline {
    fn drop(&mut self) {
        BUSY_DEADLINE.with(|current| current.set(self.previous));
    }
}

fn shared_deadline_active() -> bool {
    BUSY_DEADLINE.with(|current| current.get().is_some())
}

/// Elapsed time since the current request-wide SQLite budget started.
///
/// Store errors use this instead of the individual statement timer so their
/// structured wait field describes the whole request when a deadline guard is
/// active.
pub(crate) fn busy_deadline_elapsed() -> Option<Duration> {
    BUSY_DEADLINE.with(|current| current.get().map(|window| window.started.elapsed()))
}

fn deadline_busy_handler(_attempt: i32) -> bool {
    const RETRY_DELAY: Duration = Duration::from_millis(1);
    let Some(window) = BUSY_DEADLINE.with(Cell::get) else {
        return false;
    };
    let Some(remaining) = window.deadline.checked_duration_since(Instant::now()) else {
        return false;
    };
    std::thread::sleep(remaining.min(RETRY_DELAY));
    Instant::now() < window.deadline
}

/// Configure a newly opened SQLite connection.
///
/// This must remain the first database operation on every connection.  The
/// remaining connection-local settings belong to [`crate::Store`], whose
/// writable connections need them, rather than to read-only inspection opens.
pub fn configure_connection(conn: &mut Connection) -> rusqlite::Result<()> {
    let started = std::time::Instant::now();
    let shared_deadline = shared_deadline_active();
    if shared_deadline {
        conn.busy_handler(Some(deadline_busy_handler))?;
    } else {
        conn.busy_timeout(BUSY_TIMEOUT)?;
    }
    #[cfg(feature = "test-support")]
    test_support::record(
        if shared_deadline {
            "sqlite3_busy_handler_deadline"
        } else {
            "sqlite3_busy_timeout"
        },
        started.elapsed(),
    );
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

#[cfg(test)]
mod tests {
    use super::{shared_deadline_active, BusyDeadline};
    use std::time::Duration;

    #[test]
    fn deadline_scope_is_current_thread_only_and_restores_the_previous_value() {
        assert!(!shared_deadline_active());
        let outer = BusyDeadline::start(Duration::from_secs(1));
        assert!(shared_deadline_active());
        {
            let inner = BusyDeadline::start(Duration::from_secs(1));
            assert!(shared_deadline_active());
            drop(inner);
        }
        assert!(shared_deadline_active());
        drop(outer);
        assert!(!shared_deadline_active());
    }
}
