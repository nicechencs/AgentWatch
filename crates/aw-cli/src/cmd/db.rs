//! `aw db` (P1-CLI-04).
//!
//! The CLI does not open SQLite. [`DbStore`] is the side-effect boundary:
//! stats, vacuum, migrate, and purge are calls a test can record. The default
//! store is empty and does not delete anything.
//!
//! `purge --all` needs an administrator ([`super::daemon::Privilege`]) and
//! exits 4 otherwise. `purge --older-than` does not. Pinned sessions are never
//! counted as removed.

use serde_json::json;

use crate::exit;
use crate::output::{parse_time, DurationArg, TimeArg, TimeUnit};

use super::daemon::Privilege;
use super::Outcome;

/// `db stats` numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DbStats {
    /// Logical database size. `None` when the store has no file.
    pub db_bytes: Option<u64>,
    /// Sessions that are not pinned.
    pub sessions: u64,
    /// Pinned sessions. Reported separately so a purge can leave them.
    pub pinned_sessions: u64,
}

/// What purge asked the store to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PurgeRequest {
    /// `ended_ns` strictly before this instant. `None` duration is not used:
    /// the caller parses `--older-than` first.
    OlderThan {
        /// Cutoff, Unix nanoseconds.
        ended_before_ns: i64,
    },
    /// Every ended, unpinned session.
    All,
}

/// Result of a purge. Pinned and active sessions stay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PurgeResult {
    /// Public ids that were removed.
    pub removed: Vec<String>,
    /// Public ids that were left because they are pinned or still active.
    pub kept: Vec<String>,
}

/// Store operations. Implementations must not delete on any method other than
/// [`purge`](Self::purge).
pub(crate) trait DbStore {
    /// Current counts.
    fn stats(&self) -> DbStats;

    /// Compact. Returns a one-line note.
    ///
    /// # Errors
    ///
    /// A store failure. No path with a username.
    fn vacuum(&mut self) -> Result<String, String>;

    /// Apply migrations. `dry_run` lists them and writes nothing.
    ///
    /// # Errors
    ///
    /// A store failure.
    fn migrate(&mut self, dry_run: bool) -> Result<String, String>;

    /// Remove sessions selected by `request`. Pinned and active rows stay.
    ///
    /// # Errors
    ///
    /// A store failure.
    fn purge(&mut self, request: &PurgeRequest) -> Result<PurgeResult, String>;
}

/// Empty store. Every mutating call is a no-op note.
#[derive(Debug, Default)]
pub(crate) struct EmptyDb;

impl DbStore for EmptyDb {
    fn stats(&self) -> DbStats {
        DbStats {
            db_bytes: None,
            sessions: 0,
            pinned_sessions: 0,
        }
    }

    fn vacuum(&mut self) -> Result<String, String> {
        Ok("vacuum recorded; no database is open".to_owned())
    }

    fn migrate(&mut self, dry_run: bool) -> Result<String, String> {
        if dry_run {
            Ok("migrate --dry-run: no pending migration".to_owned())
        } else {
            Ok("migrate recorded; no database is open".to_owned())
        }
    }

    fn purge(&mut self, _request: &PurgeRequest) -> Result<PurgeResult, String> {
        Ok(PurgeResult {
            removed: Vec::new(),
            kept: Vec::new(),
        })
    }
}

/// Clock used to turn `--older-than 0s` into a cutoff. Tests pass a fixed value.
pub(crate) trait Clock {
    /// Unix nanoseconds.
    fn now_ns(&self) -> i64;
}

/// A fixed instant. Not the wall clock.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FixedClock(pub i64);

impl Clock for FixedClock {
    fn now_ns(&self) -> i64 {
        self.0
    }
}

/// Which `db` subcommand to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DbOp {
    /// `stats`.
    Stats,
    /// `vacuum`.
    Vacuum,
    /// `migrate`.
    Migrate {
        /// `--dry-run`.
        dry_run: bool,
    },
    /// `purge`.
    Purge {
        /// `--older-than`, raw text. Parsed here.
        older_than: Option<String>,
        /// `--all`.
        all: bool,
        /// `--yes`. Required for a purge that would delete.
        yes: bool,
    },
}

/// Run one `db` subcommand.
pub(crate) fn run(
    op: DbOp,
    json: bool,
    privilege: &dyn Privilege,
    clock: &dyn Clock,
    store: &mut dyn DbStore,
) -> Outcome {
    match op {
        DbOp::Stats => stats_outcome(&store.stats(), json),
        DbOp::Vacuum => match store.vacuum() {
            Ok(detail) => note("vacuum", &detail, json),
            Err(detail) => super::error_outcome(exit::GENERAL, "db", &detail, json),
        },
        DbOp::Migrate { dry_run } => match store.migrate(dry_run) {
            Ok(detail) => note("migrate", &detail, json),
            Err(detail) => super::error_outcome(exit::GENERAL, "db", &detail, json),
        },
        DbOp::Purge {
            older_than,
            all,
            yes,
        } => purge(
            older_than.as_deref(),
            all,
            yes,
            json,
            privilege,
            clock,
            store,
        ),
    }
}

fn purge(
    older_than: Option<&str>,
    all: bool,
    yes: bool,
    json: bool,
    privilege: &dyn Privilege,
    clock: &dyn Clock,
    store: &mut dyn DbStore,
) -> Outcome {
    if all && older_than.is_some() {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "`db purge` takes either --older-than or --all, not both",
            json,
        );
    }
    if !all && older_than.is_none() {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "`db purge` needs --older-than <dur> or --all",
            json,
        );
    }
    if !yes {
        return super::error_outcome(exit::USAGE, "usage", "`db purge` needs --yes", json);
    }
    if all && !privilege.is_admin() {
        return super::error_outcome(
            exit::PERMISSION,
            "permission",
            "administrator required for `db purge --all`; re-run in an administrator terminal or with sudo",
            json,
        );
    }
    let request = if all {
        PurgeRequest::All
    } else {
        let Some(text) = older_than else {
            return super::error_outcome(
                exit::USAGE,
                "usage",
                "`db purge` needs --older-than <dur> or --all",
                json,
            );
        };
        let cutoff = match older_than_cutoff(text, clock.now_ns()) {
            Ok(cutoff) => cutoff,
            Err(detail) => return super::error_outcome(exit::USAGE, "usage", &detail, json),
        };
        PurgeRequest::OlderThan {
            ended_before_ns: cutoff,
        }
    };
    match store.purge(&request) {
        Ok(result) => purge_outcome(&result, json),
        Err(detail) => super::error_outcome(exit::GENERAL, "db", &detail, json),
    }
}

/// Cutoff for `--older-than`. The store drops rows with `ended_ns <= cutoff`.
/// `0s` is `now_ns + 1`, so a session that ended at this instant is included
/// and one that ends later is not. A still-running session has no `ended_ns`
/// and is never selected. A longer duration is subtracted from `now_ns`, then
/// the same one nanosecond is added. An RFC 3339 value is not converted (this
/// crate has no time parser that yields nanoseconds) and is rejected rather
/// than treated as zero.
pub(crate) fn older_than_cutoff(text: &str, now_ns: i64) -> Result<i64, String> {
    let arg = parse_time(text)?;
    match arg {
        TimeArg::BeforeNow(duration) | TimeArg::FromSessionStart(duration) => {
            let delta = duration_ns(duration)?;
            Ok(now_ns.saturating_sub(delta).saturating_add(1))
        }
        TimeArg::Rfc3339(_) => Err(
            "`--older-than` needs a duration such as 0s or 30d, not an absolute time".to_owned(),
        ),
    }
}

fn duration_ns(duration: DurationArg) -> Result<i64, String> {
    let count =
        i64::try_from(duration.count).map_err(|_| "duration does not fit in i64".to_owned())?;
    let unit: i64 = match duration.unit {
        TimeUnit::Millis => 1_000_000,
        TimeUnit::Seconds => 1_000_000_000,
        TimeUnit::Minutes => 60 * 1_000_000_000,
        TimeUnit::Hours => 60 * 60 * 1_000_000_000,
        TimeUnit::Days => 24 * 60 * 60 * 1_000_000_000,
    };
    count
        .checked_mul(unit)
        .ok_or_else(|| "duration overflowed nanoseconds".to_owned())
}

fn stats_outcome(stats: &DbStats, json: bool) -> Outcome {
    let text = if json {
        format!(
            "{}\n",
            json!({
                "db_bytes": stats.db_bytes,
                "sessions": stats.sessions,
                "pinned_sessions": stats.pinned_sessions,
            })
        )
    } else {
        let bytes = match stats.db_bytes {
            Some(bytes) => bytes.to_string(),
            None => "unknown".to_owned(),
        };
        format!(
            "db_bytes {bytes}\nsessions {}\npinned_sessions {}\n",
            stats.sessions, stats.pinned_sessions
        )
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn purge_outcome(result: &PurgeResult, json: bool) -> Outcome {
    let text = if json {
        format!(
            "{}\n",
            json!({
                "removed": result.removed,
                "kept": result.kept,
                "sessions": result.kept.iter().filter(|_| true).count(),
            })
        )
    } else {
        format!(
            "removed {}\nkept {}\n",
            result.removed.len(),
            result.kept.len()
        )
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn note(op: &str, detail: &str, json: bool) -> Outcome {
    let text = if json {
        format!("{}\n", json!({ "op": op, "detail": detail }))
    } else {
        format!("{detail}\n")
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{run, Clock, DbOp, DbStats, DbStore, FixedClock, PurgeRequest, PurgeResult};
    use crate::cmd::daemon::Privilege;
    use crate::exit;

    /// One session the stub store knows about. No username, no hostname.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SessionRow {
        /// Public id.
        public_id: String,
        /// Ended, Unix nanoseconds. `None` means still active.
        ended_ns: Option<i64>,
        /// Pinned sessions are excluded from purge.
        pinned: bool,
    }

    /// Apply a purge to an in-memory session list. Pinned and active rows stay.
    fn purge_rows(rows: &mut Vec<SessionRow>, request: &PurgeRequest) -> PurgeResult {
        let mut removed = Vec::new();
        let mut kept = Vec::new();
        let mut next = Vec::new();
        for row in rows.drain(..) {
            let drop_it = match request {
                PurgeRequest::All => row.ended_ns.is_some() && !row.pinned,
                PurgeRequest::OlderThan { ended_before_ns } => {
                    // Inclusive. `0s` is `now`, and a session that ended at exactly
                    // now is already over. `ended_ns: None` is still running, not
                    // zero, and stays.
                    matches!(row.ended_ns, Some(ended) if ended <= *ended_before_ns) && !row.pinned
                }
            };
            if drop_it {
                removed.push(row.public_id);
            } else {
                kept.push(row.public_id.clone());
                next.push(row);
            }
        }
        *rows = next;
        PurgeResult { removed, kept }
    }

    /// In-memory store. Tests use this to assert purge arguments and the remaining
    /// session count.
    #[derive(Debug, Clone)]
    struct MemoryDb {
        /// Sessions currently stored.
        sessions: Vec<SessionRow>,
        /// Purge requests in call order.
        purges: Vec<PurgeRequest>,
        /// Logical size. `None` means unknown, not zero.
        db_bytes: Option<u64>,
    }

    impl MemoryDb {
        /// Store `sessions` and no size.
        fn with_sessions(sessions: Vec<SessionRow>) -> Self {
            Self {
                sessions,
                purges: Vec::new(),
                db_bytes: None,
            }
        }

        /// Counts after the last purge.
        fn counts(&self) -> DbStats {
            let pinned_sessions = self.sessions.iter().filter(|row| row.pinned).count() as u64;
            let sessions = (self.sessions.len() as u64).saturating_sub(pinned_sessions);
            DbStats {
                db_bytes: self.db_bytes,
                sessions,
                pinned_sessions,
            }
        }
    }

    impl DbStore for MemoryDb {
        fn stats(&self) -> DbStats {
            self.counts()
        }

        fn vacuum(&mut self) -> Result<String, String> {
            Ok("vacuum recorded".to_owned())
        }

        fn migrate(&mut self, dry_run: bool) -> Result<String, String> {
            if dry_run {
                Ok("migrate --dry-run recorded; nothing written".to_owned())
            } else {
                Ok("migrate recorded".to_owned())
            }
        }

        fn purge(&mut self, request: &PurgeRequest) -> Result<PurgeResult, String> {
            self.purges.push(request.clone());
            Ok(purge_rows(&mut self.sessions, request))
        }
    }

    struct Admin(bool);

    impl Privilege for Admin {
        fn is_admin(&self) -> bool {
            self.0
        }
    }

    fn clock() -> FixedClock {
        FixedClock(1_000_000_000_000)
    }

    fn sample() -> MemoryDb {
        MemoryDb::with_sessions(vec![
            SessionRow {
                public_id: "s-old".to_owned(),
                ended_ns: Some(1),
                pinned: false,
            },
            SessionRow {
                public_id: "s-new".to_owned(),
                ended_ns: Some(clock().now_ns().saturating_add(1)),
                pinned: false,
            },
            SessionRow {
                public_id: "s-pin".to_owned(),
                ended_ns: Some(1),
                pinned: true,
            },
            SessionRow {
                public_id: "s-live".to_owned(),
                ended_ns: None,
                pinned: false,
            },
        ])
    }

    #[test]
    fn purge_older_than_zero_drops_ended_and_keeps_pinned() {
        let mut store = sample();
        let outcome = run(
            DbOp::Purge {
                older_than: Some("0s".to_owned()),
                all: false,
                yes: true,
            },
            true,
            &Admin(false),
            &clock(),
            &mut store,
        );
        assert_eq!(
            outcome.code,
            exit::OK,
            "{}",
            String::from_utf8_lossy(&outcome.stderr)
        );
        assert_eq!(
            store.purges,
            vec![PurgeRequest::OlderThan {
                ended_before_ns: clock().now_ns().saturating_add(1),
            }]
        );
        let stats = store.stats();
        assert_eq!(stats.sessions, 1, "only the still-active session remains");
        assert_eq!(stats.pinned_sessions, 1);
        let ids: Vec<_> = store
            .sessions
            .iter()
            .map(|row| row.public_id.as_str())
            .collect();
        assert!(ids.contains(&"s-pin"));
        assert!(ids.contains(&"s-live"));
        assert!(!ids.contains(&"s-old"));
        assert!(!ids.contains(&"s-new"));
    }

    #[test]
    fn purge_all_without_admin_is_exit_4() {
        let mut store = sample();
        let outcome = run(
            DbOp::Purge {
                older_than: None,
                all: true,
                yes: true,
            },
            false,
            &Admin(false),
            &clock(),
            &mut store,
        );
        assert_eq!(outcome.code, exit::PERMISSION);
        let err = String::from_utf8(outcome.stderr).expect("utf8");
        assert!(
            err.contains("sudo") || err.contains("administrator"),
            "{err}"
        );
        assert!(store.purges.is_empty());
        assert_eq!(store.sessions.len(), 4);
    }

    #[test]
    fn purge_all_with_admin_leaves_only_pinned_and_active() {
        let mut store = sample();
        let outcome = run(
            DbOp::Purge {
                older_than: None,
                all: true,
                yes: true,
            },
            false,
            &Admin(true),
            &clock(),
            &mut store,
        );
        assert_eq!(outcome.code, exit::OK);
        assert_eq!(store.purges, vec![PurgeRequest::All]);
        assert_eq!(store.stats().sessions, 1);
        assert_eq!(store.stats().pinned_sessions, 1);
    }

    #[test]
    fn stats_reports_the_stub_counts() {
        let mut store = MemoryDb::with_sessions(vec![SessionRow {
            public_id: "s-pin".to_owned(),
            ended_ns: Some(1),
            pinned: true,
        }]);
        let outcome = run(DbOp::Stats, true, &Admin(false), &clock(), &mut store);
        assert_eq!(outcome.code, exit::OK);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        let value: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert_eq!(value["sessions"], 0);
        assert_eq!(value["pinned_sessions"], 1);
        assert!(value["db_bytes"].is_null());
    }
}
