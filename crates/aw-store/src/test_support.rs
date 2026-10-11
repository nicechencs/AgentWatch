//! Test-only SQLite timing diagnostics.
//!
//! A [`TraceCapture`] is local to the current thread.  Connections opened
//! while it is active install SQLite's profile callback and retain a concise,
//! parameter-free statement label with its elapsed time.  This lets a caller
//! diagnose lock waits without putting caller-supplied values in test output.

use std::cell::RefCell;
use std::time::Duration;

use rusqlite::Connection;

/// One SQLite call observed during a [`TraceCapture`].
#[derive(Clone, Debug)]
pub struct TraceEntry {
    /// Fixed API or parameter-free SQL label.
    pub operation: String,
    /// Time SQLite reported for this call.
    pub elapsed: Duration,
}

struct ActiveCapture {
    entries: Vec<TraceEntry>,
}

thread_local! {
    static ACTIVE_CAPTURE: RefCell<Option<ActiveCapture>> = const { RefCell::new(None) };
}

/// Current-thread collection of connection setup and SQLite statement timings.
///
/// The capture is intentionally opt-in and is only compiled through the
/// `test-support` feature.  Dropping it without [`Self::finish`] clears the
/// current-thread state so a failed test cannot affect a later test.
pub struct TraceCapture {
    active: bool,
}

impl TraceCapture {
    /// Begin a fresh current-thread capture.
    #[must_use]
    pub fn start() -> Self {
        ACTIVE_CAPTURE.with(|capture| {
            *capture.borrow_mut() = Some(ActiveCapture {
                entries: Vec::new(),
            });
        });
        Self { active: true }
    }

    /// End this capture and return timings in execution order.
    #[must_use]
    pub fn finish(mut self) -> Vec<TraceEntry> {
        self.active = false;
        ACTIVE_CAPTURE.with(|capture| {
            capture
                .borrow_mut()
                .take()
                .map_or_else(Vec::new, |active| active.entries)
        })
    }
}

impl Drop for TraceCapture {
    fn drop(&mut self) {
        if self.active {
            ACTIVE_CAPTURE.with(|capture| {
                let _ = capture.borrow_mut().take();
            });
        }
    }
}

/// Record a non-SQLite-VM connection operation when a capture is active.
pub fn record(operation: &'static str, elapsed: Duration) {
    ACTIVE_CAPTURE.with(|capture| {
        if let Some(active) = capture.borrow_mut().as_mut() {
            active.entries.push(TraceEntry {
                operation: operation.to_owned(),
                elapsed,
            });
        }
    });
}

/// Install the SQLite profile callback on a freshly configured connection.
pub fn install_profile(conn: &mut Connection) {
    conn.profile(Some(profile));
}

fn profile(sql: &str, elapsed: Duration) {
    ACTIVE_CAPTURE.with(|capture| {
        if let Some(active) = capture.borrow_mut().as_mut() {
            active.entries.push(TraceEntry {
                operation: sql_label(sql),
                elapsed,
            });
        }
    });
}

fn sql_label(sql: &str) -> String {
    let words: Vec<&str> = sql.split_whitespace().collect();
    let Some(first) = words.first() else {
        return "<empty SQL>".to_owned();
    };
    if first.eq_ignore_ascii_case("PRAGMA") {
        return words
            .get(1)
            .map_or_else(|| "PRAGMA".to_owned(), |name| format!("PRAGMA {name}"));
    }
    if first.eq_ignore_ascii_case("BEGIN") {
        return "BEGIN IMMEDIATE".to_owned();
    }
    if first.eq_ignore_ascii_case("COMMIT") || first.eq_ignore_ascii_case("ROLLBACK") {
        return (*first).to_ascii_uppercase();
    }
    if first.eq_ignore_ascii_case("INSERT") {
        return words.get(2).map_or_else(
            || "INSERT".to_owned(),
            |table| format!("INSERT INTO {table}"),
        );
    }
    if first.eq_ignore_ascii_case("UPDATE") || first.eq_ignore_ascii_case("DELETE") {
        return words.get(1).map_or_else(
            || (*first).to_ascii_uppercase(),
            |table| format!("{} {table}", first.to_ascii_uppercase()),
        );
    }
    if first.eq_ignore_ascii_case("CREATE") {
        return words
            .get(1)
            .map_or_else(|| "CREATE".to_owned(), |kind| format!("CREATE {kind}"));
    }
    (*first).to_ascii_uppercase()
}

#[cfg(test)]
mod tests {
    use super::sql_label;

    #[test]
    fn statement_labels_omit_values() {
        assert_eq!(
            sql_label("PRAGMA journal_mode = WAL"),
            "PRAGMA journal_mode"
        );
        assert_eq!(sql_label("BEGIN IMMEDIATE"), "BEGIN IMMEDIATE");
        assert_eq!(
            sql_label("INSERT INTO sessions (public_id) VALUES ('secret')"),
            "INSERT INTO sessions"
        );
    }
}
