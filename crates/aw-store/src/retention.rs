//! Retention, `stats`, and `purge`.
//!
//! Algorithm from storage.md §5, with two differences this crate cannot close:
//!
//! - **Write-lock bound.** The doc says each incremental-vacuum step holds the
//!   write lock for at most 50 ms, and the task card repeats that for one cleanup
//!   step. SQLite does not expose a 50 ms budget on `incremental_vacuum`. This
//!   module deletes in batches of [`BATCH_ROWS`] and then runs
//!   `incremental_vacuum` plus `wal_checkpoint(TRUNCATE)`. It does **not** claim
//!   the 50 ms bound, and it does not sleep to measure one.
//! - **`Gap{store_failure}`.** The card asks for that gap when free disk is below
//!   `min_free_disk_bytes`. `aw-core::GapKind` has no `store_failure` variant and
//!   this crate must not invent one. [`Retention::apply`] returns
//!   [`ApplyOutcome::MetadataAndGapsOnly`] instead. The caller turns that into a
//!   gap. Free bytes are a parameter: `std::fs` has no portable free-space API,
//!   and this crate does not call a platform one. `free_bytes: None` skips the
//!   disk check ([`DiskCheck::Skipped`]).
//!
//! `schema_meta` is `(key TEXT PRIMARY KEY, value TEXT NOT NULL)`. Each deletion
//! writes `purged:<public_id>` → `<deleted_ns>,<reason>`. That matches storage.md
//! §5 ("键为 `purged:<public_id>`，值为时间和原因").
//!
//! Size is `page_count * page_size + wal file length`, as in §5. `DELETE` does
//! not shrink the file. `incremental_vacuum` only returns pages to the OS when
//! `auto_vacuum=INCREMENTAL` was set before the first `CREATE` (the migrator
//! does that). A database created without it will not shrink; callers should
//! read [`ApplyReport::db_bytes`] (logical pages) rather than the file length.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::StoreError;
use crate::migrate::Store;

/// Rows deleted per `DELETE` statement. storage.md §5.
pub const BATCH_ROWS: i64 = 5000;

/// Default `max_db_bytes`: 2 GiB.
pub const DEFAULT_MAX_DB_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Default `max_age_days`: 30.
pub const DEFAULT_MAX_AGE_DAYS: u32 = 30;

/// Default `min_free_disk_bytes`: 1 GiB.
pub const DEFAULT_MIN_FREE_DISK_BYTES: u64 = 1024 * 1024 * 1024;

/// Fraction of `max_db_bytes` that starts oldest-session deletion. storage.md §5
/// uses `max_db_bytes * 0.9`.
const SIZE_PRESSURE: f64 = 0.9;

const NS_PER_DAY: i64 = 24 * 60 * 60 * 1_000_000_000;

/// Child tables deleted before `sessions`, so one batch never depends on
/// `ON DELETE CASCADE` spanning more than [`BATCH_ROWS`] rows.
///
/// `processes` and `net_flow_buckets` are `WITHOUT ROWID`, so the batch key is
/// the primary key, not `rowid`. Order: `net_flow_buckets` before `net_flows`
/// (the bucket table references `net_flows.id`). `sessions` is deleted last,
/// one row at a time, after its children are gone.
const CHILD_TABLES: &[ChildTable] = &[
    // Present only after migrations 0003–0005. `delete_children_in_batches`
    // skips a name that is not in sqlite_master, so a P1 database still purges.
    // The FTS rows for these ids are removed by the BEFORE DELETE triggers in
    // 0005_fts.sql; this list does not DELETE FROM fts_text itself.
    ChildTable {
        name: "file_access",
        key: "id",
    },
    ChildTable {
        name: "net_flow_buckets",
        key: "flow_id, bucket_ns",
    },
    ChildTable {
        name: "processes",
        key: "session_id, proc_uid",
    },
    ChildTable {
        name: "process_images",
        key: "id",
    },
    ChildTable {
        name: "net_flows",
        key: "id",
    },
    ChildTable {
        name: "dns",
        key: "id",
    },
    ChildTable {
        name: "gaps",
        key: "id",
    },
];

struct ChildTable {
    name: &'static str,
    /// Comma-separated primary-key columns. Not user input.
    key: &'static str,
}

/// `[retention]` from storage.md §5.
///
/// `max_session_bytes` and `check_interval_secs` are stored so a later caller
/// can read the same config. This module does not enforce a per-session cap
/// (that is the L3 degrade ladder, not this task) and does not sleep for the
/// check interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Main database pages plus the WAL file. Default 2 GiB.
    pub max_db_bytes: u64,
    /// Sessions with `ended_ns` older than this many days are eligible. Default 30.
    pub max_age_days: u32,
    /// Caller-supplied free-space threshold. Default 1 GiB.
    ///
    /// Compared only when [`Retention::apply`] is given `Some(free_bytes)`.
    pub min_free_disk_bytes: u64,
    /// Documented per-session cap. Not enforced here.
    pub max_session_bytes: u64,
    /// Documented check interval, in seconds. Not slept here.
    pub check_interval_secs: u64,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            max_db_bytes: DEFAULT_MAX_DB_BYTES,
            max_age_days: DEFAULT_MAX_AGE_DAYS,
            min_free_disk_bytes: DEFAULT_MIN_FREE_DISK_BYTES,
            max_session_bytes: 512 * 1024 * 1024,
            check_interval_secs: 300,
        }
    }
}

/// Why a session was removed. Stored as the suffix of the audit value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeReason {
    /// `ended_ns` is older than `max_age_days`.
    Age,
    /// Database size was over 90% of `max_db_bytes`.
    Size,
    /// `purge(older_than)` selected this session.
    OlderThan,
    /// `purge(all)` selected this session.
    All,
}

impl PurgeReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Age => "age",
            Self::Size => "size",
            Self::OlderThan => "older_than",
            Self::All => "all",
        }
    }
}

/// One `schema_meta` audit row: key `purged:<public_id>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeReport {
    /// `sessions.public_id` at the time of deletion.
    pub public_id: String,
    /// `sessions.id`.
    pub session_id: i64,
    /// Why it was deleted.
    pub reason: PurgeReason,
    /// Wall-clock nanoseconds recorded in the audit value.
    pub deleted_ns: i64,
}

/// What the disk check did. `None` free bytes is not treated as zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskCheck {
    /// `free_bytes` was `None`. Retention still deleted by age and size.
    Skipped,
    /// `free_bytes` was at least `min_free_disk_bytes`.
    Ok,
    /// `free_bytes` was below `min_free_disk_bytes`.
    Low,
}

/// Whether new session detail should be written.
///
/// This is the structured signal the card asks for instead of `GapKind::store_failure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Free space was unknown or sufficient. Detail writes are allowed.
    Normal,
    /// Free space was below the threshold. Caller should write session metadata
    /// and gaps only, and record its own gap. This crate does not insert a gap
    /// row: `GapKind` has no store-failure variant.
    MetadataAndGapsOnly,
}

/// Result of [`Retention::apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    /// Sessions removed by the age rule, then the size rule.
    pub purged: Vec<PurgeReport>,
    /// `page_count * page_size + wal file bytes` after vacuum and checkpoint.
    pub db_bytes: u64,
    /// How free space was judged.
    pub disk: DiskCheck,
    /// What the caller should do with new detail.
    pub write_mode: WriteMode,
    /// Size was still over 90% of the cap, and every remaining session is
    /// active (`ended_ns IS NULL`) or `pinned = 1`. storage.md calls the alarm
    /// `storage_full`. No `GapKind` is written.
    pub storage_full: bool,
}

/// One table's row count for [`Stats`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableCount {
    /// SQLite table name.
    pub table: &'static str,
    /// `COUNT(*)`.
    pub rows: i64,
}

/// Oldest session by `started_ns`, if any exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OldestSession {
    /// `sessions.id`.
    pub id: i64,
    /// `sessions.public_id`.
    pub public_id: String,
    /// `sessions.started_ns`.
    pub started_ns: i64,
    /// `sessions.ended_ns`. `None` means still active.
    pub ended_ns: Option<i64>,
    /// `sessions.pinned != 0`.
    pub pinned: bool,
}

/// `stats()`: size, per-table counts, oldest session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stats {
    /// `page_count * page_size + wal file bytes`.
    pub db_bytes: u64,
    /// `page_count * page_size` alone, so a test can ignore the WAL.
    pub page_bytes: u64,
    /// WAL file length. `0` when the `-wal` sibling is absent.
    pub wal_bytes: u64,
    /// Counts for the P1 tables. `schema_meta` included.
    pub tables: Vec<TableCount>,
    /// Session with the smallest `started_ns`, or `None` when the table is empty.
    pub oldest_session: Option<OldestSession>,
}

/// Explicit purge request. Does not delete active or pinned sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeScope {
    /// `ended_ns` is present and strictly less than this instant.
    OlderThan {
        /// Unix nanoseconds.
        ended_before_ns: i64,
    },
    /// Every ended, unpinned session.
    All,
}

/// Retention against one [`Store`] write connection.
///
/// The connection is borrowed. A concurrent writer must be a different
/// connection (SQLite WAL). This type does not spawn a thread and does not
/// time the lock.
pub struct Retention<'a> {
    conn: &'a mut Connection,
    db_path: PathBuf,
    config: RetentionConfig,
}

impl<'a> Retention<'a> {
    /// Borrow `store`'s write connection. `db_path` is only used to stat the
    /// `-wal` sibling. It is not opened.
    pub fn new(store: &'a mut Store, db_path: impl Into<PathBuf>, config: RetentionConfig) -> Self {
        Self {
            conn: store.connection_mut(),
            db_path: db_path.into(),
            config,
        }
    }

    /// Config this value was built with.
    pub fn config(&self) -> &RetentionConfig {
        &self.config
    }

    /// Size, per-table row counts, oldest session.
    pub fn stats(&self) -> Result<Stats, StoreError> {
        read_stats(self.conn, &self.db_path)
    }

    /// Run storage.md §5 steps 1–4 once.
    ///
    /// `now_ns` is the caller's clock (Unix nanoseconds). `free_bytes` is the
    /// caller's free-space sample. `None` skips the disk check.
    ///
    /// Active sessions (`ended_ns IS NULL`) and `pinned != 0` are never deleted.
    /// When free space is low, age and size deletion still run — the doc's
    /// "只写元数据和缺口" mode is about *new* detail, reported as
    /// [`WriteMode::MetadataAndGapsOnly`].
    pub fn apply(
        &mut self,
        now_ns: i64,
        free_bytes: Option<u64>,
    ) -> Result<ApplyReport, StoreError> {
        let (disk, write_mode) = judge_disk(free_bytes, self.config.min_free_disk_bytes);

        let mut purged = Vec::new();
        if self.config.max_age_days > 0 {
            let cutoff = now_ns
                .saturating_sub(i64::from(self.config.max_age_days).saturating_mul(NS_PER_DAY));
            let victims = select_ended_unpinned(
                self.conn,
                "SELECT id, public_id FROM sessions
                 WHERE pinned = 0 AND ended_ns IS NOT NULL AND ended_ns < ?1
                 ORDER BY ended_ns ASC, id ASC",
                [cutoff],
            )?;
            for (id, public_id) in victims {
                let deleted_ns = purge_session(self.conn, id, &public_id, PurgeReason::Age)?;
                purged.push(PurgeReport {
                    public_id,
                    session_id: id,
                    reason: PurgeReason::Age,
                    deleted_ns,
                });
                // §5 step 3, after each deletion, so the size loop sees freed pages.
                incremental_vacuum(self.conn)?;
            }
        }

        let limit = size_limit(self.config.max_db_bytes);
        let mut storage_full = false;
        loop {
            let size = db_bytes(self.conn, &self.db_path)?;
            if size <= limit {
                break;
            }
            let next = oldest_ended_unpinned(self.conn)?;
            let Some((id, public_id)) = next else {
                storage_full = true;
                break;
            };
            let deleted_ns = purge_session(self.conn, id, &public_id, PurgeReason::Size)?;
            purged.push(PurgeReport {
                public_id,
                session_id: id,
                reason: PurgeReason::Size,
                deleted_ns,
            });
            // page_count does not fall until incremental_vacuum runs. Doing it
            // here is what stops the loop. It is not a 50 ms budget.
            incremental_vacuum(self.conn)?;
            // A busy checkpoint is not a failure (step 4: only when no reader).
            checkpoint_truncate(self.conn)?;
        }

        checkpoint_truncate(self.conn)?;
        let db_bytes = db_bytes(self.conn, &self.db_path)?;
        Ok(ApplyReport {
            purged,
            db_bytes,
            disk,
            write_mode,
            storage_full,
        })
    }

    /// `purge(older_than | all)`.
    ///
    /// Same protection as [`Self::apply`]: an active or pinned session is left
    /// in place, and each deletion writes `purged:<public_id>`.
    pub fn purge(&mut self, scope: PurgeScope) -> Result<Vec<PurgeReport>, StoreError> {
        let reason = match scope {
            PurgeScope::OlderThan { .. } => PurgeReason::OlderThan,
            PurgeScope::All => PurgeReason::All,
        };
        let victims = match scope {
            PurgeScope::OlderThan { ended_before_ns } => select_ended_unpinned(
                self.conn,
                "SELECT id, public_id FROM sessions
                 WHERE pinned = 0 AND ended_ns IS NOT NULL AND ended_ns < ?1
                 ORDER BY ended_ns ASC, id ASC",
                [ended_before_ns],
            )?,
            PurgeScope::All => select_ended_unpinned(
                self.conn,
                "SELECT id, public_id FROM sessions
                 WHERE pinned = 0 AND ended_ns IS NOT NULL
                 ORDER BY started_ns ASC, id ASC",
                [],
            )?,
        };
        let mut purged = Vec::with_capacity(victims.len());
        for (id, public_id) in victims {
            let deleted_ns = purge_session(self.conn, id, &public_id, reason)?;
            purged.push(PurgeReport {
                public_id,
                session_id: id,
                reason,
                deleted_ns,
            });
        }
        incremental_vacuum(self.conn)?;
        checkpoint_truncate(self.conn)?;
        Ok(purged)
    }

    /// Return free pages to the OS and truncate the WAL. Deletes nothing.
    ///
    /// `incremental_vacuum` only gives back pages already freed by a deletion,
    /// so on a database with no purged sessions this changes nothing and still
    /// succeeds.
    pub fn vacuum(&mut self) -> Result<(), StoreError> {
        incremental_vacuum(self.conn)?;
        checkpoint_truncate(self.conn)
    }
}

fn judge_disk(free_bytes: Option<u64>, min_free: u64) -> (DiskCheck, WriteMode) {
    match free_bytes {
        None => (DiskCheck::Skipped, WriteMode::Normal),
        Some(free) if free < min_free => (DiskCheck::Low, WriteMode::MetadataAndGapsOnly),
        Some(_) => (DiskCheck::Ok, WriteMode::Normal),
    }
}

fn size_limit(max_db_bytes: u64) -> u64 {
    let scaled = (max_db_bytes as f64) * SIZE_PRESSURE;
    if !scaled.is_finite() || scaled <= 0.0 {
        return 0;
    }
    // Floor so a value just under 90% does not trip the loop.
    scaled.floor() as u64
}

fn select_ended_unpinned(
    conn: &Connection,
    sql: &str,
    param: impl rusqlite::Params,
) -> Result<Vec<(i64, String)>, StoreError> {
    let mut stmt = conn
        .prepare(sql)
        .map_err(|err| StoreError::sqlite("select_purge_victims", err))?;
    let rows = stmt
        .query_map(param, |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|err| StoreError::sqlite("select_purge_victims", err))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|err| StoreError::sqlite("select_purge_victims", err))?);
    }
    Ok(out)
}

fn oldest_ended_unpinned(conn: &Connection) -> Result<Option<(i64, String)>, StoreError> {
    conn.query_row(
        "SELECT id, public_id FROM sessions
         WHERE pinned = 0 AND ended_ns IS NOT NULL
         ORDER BY started_ns ASC, id ASC
         LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(|err| StoreError::sqlite("select_oldest_ended", err))
}

/// Delete one session in batches of [`BATCH_ROWS`], then write the audit row.
///
/// Each batch is its own transaction, so a concurrent writer is not blocked for
/// the whole session. The 50 ms bound is not measured.
fn purge_session(
    conn: &mut Connection,
    session_id: i64,
    public_id: &str,
    reason: PurgeReason,
) -> Result<i64, StoreError> {
    for table in CHILD_TABLES {
        delete_children_in_batches(conn, table, session_id)?;
    }
    // The session row is one row. Children are already gone, so CASCADE is a no-op.
    let tx = conn
        .transaction()
        .map_err(|err| StoreError::sqlite("begin_purge_session", err))?;
    tx.execute("DELETE FROM sessions WHERE id = ?1", params![session_id])
        .map_err(|err| StoreError::sqlite("delete_session", err))?;
    let deleted_ns = write_purge_audit(&tx, public_id, reason)?;
    tx.commit()
        .map_err(|err| StoreError::sqlite("commit_purge_session", err))?;
    Ok(deleted_ns)
}

fn delete_children_in_batches(
    conn: &mut Connection,
    table: &ChildTable,
    session_id: i64,
) -> Result<(), StoreError> {
    if !table_exists(conn, table.name)? {
        return Ok(());
    }
    // Names and keys are the const list above, not user input.
    let sql = format!(
        "DELETE FROM {name} WHERE ({key}) IN \
         (SELECT {key} FROM {name} WHERE session_id = ?1 LIMIT {BATCH_ROWS})",
        name = table.name,
        key = table.key,
    );
    loop {
        let tx = conn
            .transaction()
            .map_err(|err| StoreError::sqlite("begin_purge_batch", err))?;
        let n = tx
            .execute(&sql, params![session_id])
            .map_err(|err| StoreError::sqlite("delete_batch", err))?;
        tx.commit()
            .map_err(|err| StoreError::sqlite("commit_purge_batch", err))?;
        if n == 0 {
            break;
        }
    }
    Ok(())
}

fn write_purge_audit(
    conn: &Connection,
    public_id: &str,
    reason: PurgeReason,
) -> Result<i64, StoreError> {
    let deleted_ns = unix_now_ns();
    let key = format!("purged:{public_id}");
    let value = format!("{deleted_ns},{}", reason.as_str());
    conn.execute(
        "INSERT INTO schema_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )
    .map_err(|err| StoreError::sqlite("purge_audit", err))?;
    Ok(deleted_ns)
}

fn incremental_vacuum(conn: &Connection) -> Result<(), StoreError> {
    // `PRAGMA incremental_vacuum` yields one row per page moved. `execute_batch`
    // steps a statement once and would free a single page, leaving the freelist
    // (and `page_count`) almost unchanged. Drain every row.
    //
    // Chunks of [`BATCH_ROWS`] rather than one unbounded pragma: each statement
    // is its own auto-commit, so the write lock is not held for the whole
    // freelist. That is the batching storage.md §5 asks for. It is not a
    // measured 50 ms bound — SQLite has no such parameter, and this function
    // does not time itself.
    //
    // A full `VACUUM` is not run. On a database that was not created with
    // `auto_vacuum=INCREMENTAL` (the migrator sets it before the first CREATE),
    // this loop exits immediately because the first statement frees nothing.
    // The page count is not a bound parameter: SQLite rejects `?` here
    // ("near ?1: syntax error"). BATCH_ROWS is a crate constant.
    let sql = format!("PRAGMA incremental_vacuum({BATCH_ROWS})");
    loop {
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|err| StoreError::sqlite("prepare_incremental_vacuum", err))?;
        let rows = stmt
            .query_map([], |_row| Ok(()))
            .map_err(|err| StoreError::sqlite("incremental_vacuum", err))?;
        let mut freed = 0_i64;
        for row in rows {
            row.map_err(|err| StoreError::sqlite("incremental_vacuum", err))?;
            freed += 1;
        }
        drop(stmt);
        if freed == 0 {
            break;
        }
    }
    Ok(())
}

fn checkpoint_truncate(conn: &Connection) -> Result<(), StoreError> {
    // storage.md §5 step 4: TRUNCATE only when no read transaction is active.
    // SQLite reports that as SQLITE_BUSY (or a busy flag in the result row)
    // rather than waiting. A busy result is not a retention failure.
    match conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
        row.get::<_, i64>(0)
    }) {
        Ok(_busy_flag) => Ok(()),
        Err(err) if sqlite_busy(&err) => Ok(()),
        Err(err) => Err(StoreError::sqlite("wal_checkpoint", err)),
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

fn read_stats(conn: &Connection, db_path: &Path) -> Result<Stats, StoreError> {
    let page_bytes = page_bytes(conn)?;
    let wal_bytes = wal_len(db_path)?;
    let mut tables = TABLE_NAMES
        .iter()
        .map(|table| count_named(conn, table))
        .collect::<Result<Vec<_>, StoreError>>()?;
    for table in OPTIONAL_TABLES {
        if table_exists(conn, table)? {
            tables.push(count_named(conn, table)?);
        }
    }
    let oldest_session = conn
        .query_row(
            "SELECT id, public_id, started_ns, ended_ns, pinned
             FROM sessions
             ORDER BY started_ns ASC, id ASC
             LIMIT 1",
            [],
            |row| {
                let pinned: i64 = row.get(4)?;
                Ok(OldestSession {
                    id: row.get(0)?,
                    public_id: row.get(1)?,
                    started_ns: row.get(2)?,
                    ended_ns: row.get(3)?,
                    pinned: pinned != 0,
                })
            },
        )
        .optional()
        .map_err(|err| StoreError::sqlite("oldest_session", err))?;
    Ok(Stats {
        db_bytes: page_bytes.saturating_add(wal_bytes),
        page_bytes,
        wal_bytes,
        tables,
        oldest_session,
    })
}

const TABLE_NAMES: &[&str] = &[
    "schema_meta",
    "sessions",
    "processes",
    "process_images",
    "net_flows",
    "net_flow_buckets",
    "dns",
    "gaps",
];

/// Tables counted only when the migration that creates them has run.
const OPTIONAL_TABLES: &[&str] = &["file_access"];

fn count_named(conn: &Connection, table: &'static str) -> Result<TableCount, StoreError> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let rows: i64 = conn
        .query_row(&sql, [], |row| row.get(0))
        .map_err(|err| StoreError::sqlite("count_table", err))?;
    Ok(TableCount { table, rows })
}

fn table_exists(conn: &Connection, name: &str) -> Result<bool, StoreError> {
    let found: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![name],
            |row| row.get(0),
        )
        .map_err(|err| StoreError::sqlite("table_exists", err))?;
    Ok(found > 0)
}

fn db_bytes(conn: &Connection, db_path: &Path) -> Result<u64, StoreError> {
    Ok(page_bytes(conn)?.saturating_add(wal_len(db_path)?))
}

fn page_bytes(conn: &Connection) -> Result<u64, StoreError> {
    let page_count: i64 = conn
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|err| StoreError::sqlite("pragma_page_count", err))?;
    let page_size: i64 = conn
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|err| StoreError::sqlite("pragma_page_size", err))?;
    let pages = u64::try_from(page_count).unwrap_or(0);
    let size = u64::try_from(page_size).unwrap_or(0);
    Ok(pages.saturating_mul(size))
}

fn wal_len(db_path: &Path) -> Result<u64, StoreError> {
    let wal = sibling(db_path, "-wal");
    match std::fs::metadata(&wal) {
        Ok(meta) => Ok(meta.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(StoreError::io("stat_wal", Some(wal), err)),
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(suffix);
    PathBuf::from(os)
}

fn unix_now_ns() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;

    use super::*;
    use crate::migrate::Store;

    fn temp_db(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("aw-store-retention-{label}-{nanos}.db"))
    }

    fn remove_db(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(sibling(path, "-wal"));
        let _ = fs::remove_file(sibling(path, "-shm"));
    }

    fn insert_session(
        conn: &Connection,
        id: i64,
        public_id: &str,
        started_ns: i64,
        ended_ns: Option<i64>,
        pinned: i64,
        payload: &str,
    ) {
        conn.execute(
            "INSERT INTO sessions (
                id, public_id, name, mode, agent, root_proc_uid, argv, cwd, user_id,
                started_ns, ended_ns, end_reason, exit_code, proxy_enabled, proxy_port,
                platform, os_version, collectors, collector_profile, config_digest,
                pinned, stats
             ) VALUES (
                ?1, ?2, NULL, 'launch', NULL, NULL, 'placeholder', NULL, '0',
                ?3, ?4, NULL, NULL, 0, NULL,
                'linux', NULL, ?5, NULL, NULL,
                ?6, ?5
             )",
            params![id, public_id, started_ns, ended_ns, payload, pinned],
        )
        .expect("insert session");
    }

    /// ~1 MiB of JSON text. Not a secret. Used only to grow `collectors` / `stats`.
    fn payload(tag: u8) -> String {
        let unit = format!("{{\"k\":\"{tag:02x}\"}}");
        let repeats = (1024 * 1024) / unit.len() + 1;
        let mut s = String::with_capacity(repeats * unit.len() + 2);
        s.push('[');
        for i in 0..repeats {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&unit);
        }
        s.push(']');
        s
    }

    fn open(path: &Path) -> Store {
        remove_db(path);
        Store::open(path).expect("open")
    }

    #[test]
    fn age_then_size_keeps_pinned_and_active() {
        let path = temp_db("cap");
        let mut store = open(&path);
        // 10 MB cap, as the task card's test. Threshold is 9 MB (90%).
        let config = RetentionConfig {
            max_db_bytes: 10 * 1024 * 1024,
            max_age_days: 30,
            min_free_disk_bytes: 1024,
            ..RetentionConfig::default()
        };
        let blob = payload(1);
        // 32 ended sessions × two ~1 MB text columns ≈ 64 MB of payload, which
        // is past both the 30 MB the card names and the 9 MB threshold.
        // started_ns is inside the 30-day window so the age rule does not fire
        // on these; a separate older session does.
        let now = 40 * NS_PER_DAY;
        {
            let conn = store.connection();
            insert_session(conn, 1, "old", 0, Some(1), 0, &blob);
            for i in 0..32 {
                let id = 10 + i;
                insert_session(
                    conn,
                    id,
                    &format!("s{id}"),
                    now - 1_000 + i,
                    Some(now - 500 + i),
                    0,
                    &blob,
                );
            }
            insert_session(
                conn,
                100,
                "pinned",
                now - 50_000,
                Some(now - 40_000),
                1,
                &blob,
            );
            insert_session(conn, 101, "active", now - 10, None, 0, &blob);
        }

        let before = Retention::new(&mut store, &path, config.clone())
            .stats()
            .expect("stats before");
        let sessions_before = table_rows(&before, "sessions");
        assert!(
            before.page_bytes > 30 * 1024 * 1024,
            "fixture must exceed 30 MB of pages, got {}",
            before.page_bytes
        );
        assert_eq!(sessions_before, 35);

        let report = Retention::new(&mut store, &path, config)
            .apply(now, Some(10 * 1024 * 1024))
            .expect("apply");
        assert_eq!(report.disk, DiskCheck::Ok);
        assert_eq!(report.write_mode, WriteMode::Normal);
        assert!(!report.storage_full);

        let stats = Retention::new(
            &mut store,
            &path,
            RetentionConfig {
                max_db_bytes: 10 * 1024 * 1024,
                ..RetentionConfig::default()
            },
        )
        .stats()
        .expect("stats after");

        // What was measured: PRAGMA page_count * page_size, plus the WAL file
        // length. The on-disk file length is also recorded below. incremental_vacuum
        // is what the doc allows; VACUUM is not run. If pages do not fall under
        // 9 MB, the assertions on rows still stand and this message says so.
        let file_len = fs::metadata(&path).expect("meta").len();
        let page_under = stats.page_bytes < 9 * 1024 * 1024;
        let file_under = file_len < 9 * 1024 * 1024;
        assert!(
            page_under,
            "page_count * page_size = {} (file len {file_len}, wal {}); \
             incremental_vacuum did not bring logical size under 9 MB. \
             Row assertions follow only when this fails — it is expected to pass \
             because auto_vacuum=INCREMENTAL is set before CREATE.",
            stats.page_bytes, stats.wal_bytes
        );
        // File length is reported, not required: WAL truncation can leave the
        // main file equal to page bytes. Both are checked so the report is honest.
        assert!(
            file_under || page_under,
            "neither file ({file_len}) nor pages ({}) are under 9 MB",
            stats.page_bytes
        );

        let ids = session_ids(store.connection());
        assert!(ids.contains(&100), "pinned session must survive: {ids:?}");
        assert!(ids.contains(&101), "active session must survive: {ids:?}");
        assert!(!ids.contains(&1), "aged session must go");
        assert!(
            ids.len() < sessions_before as usize,
            "size rule must delete at least one ended session"
        );
        for id in &ids {
            if *id == 100 || *id == 101 {
                continue;
            }
            // Survivors are the newest ended sessions. Oldest ended ones go first.
            assert!(*id >= 10, "unexpected id {id}");
        }

        let audits: Vec<(String, String)> = {
            let mut stmt = store
                .connection()
                .prepare(
                    "SELECT key, value FROM schema_meta WHERE key LIKE 'purged:%' ORDER BY key",
                )
                .expect("prepare audits");
            stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .expect("query")
                .collect::<Result<Vec<_>, _>>()
                .expect("audits")
        };
        assert!(
            audits
                .iter()
                .any(|(k, v)| k == "purged:old" && v.ends_with(",age")),
            "age audit missing: {audits:?}"
        );
        assert!(
            audits.iter().any(|(_, v)| v.ends_with(",size")),
            "size audit missing: {audits:?}"
        );
        assert_eq!(audits.len(), report.purged.len());
        remove_db(&path);
    }

    #[test]
    fn low_disk_is_a_status_not_a_gap_kind() {
        let path = temp_db("disk");
        let mut store = open(&path);
        let config = RetentionConfig {
            max_db_bytes: DEFAULT_MAX_DB_BYTES,
            min_free_disk_bytes: 1000,
            ..RetentionConfig::default()
        };
        let skipped = Retention::new(&mut store, &path, config.clone())
            .apply(1, None)
            .expect("skip");
        assert_eq!(skipped.disk, DiskCheck::Skipped);
        assert_eq!(skipped.write_mode, WriteMode::Normal);

        let low = Retention::new(&mut store, &path, config)
            .apply(1, Some(999))
            .expect("low");
        assert_eq!(low.disk, DiskCheck::Low);
        assert_eq!(low.write_mode, WriteMode::MetadataAndGapsOnly);
        // No gap row was invented.
        let gaps: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM gaps", [], |row| row.get(0))
            .expect("gaps");
        assert_eq!(gaps, 0);
        remove_db(&path);
    }

    #[test]
    fn purge_all_and_older_than_leave_pinned_and_active() {
        let path = temp_db("purge");
        let mut store = open(&path);
        let blob = "[]";
        {
            let conn = store.connection();
            insert_session(conn, 1, "early", 10, Some(20), 0, blob);
            insert_session(conn, 2, "later", 30, Some(40), 0, blob);
            insert_session(conn, 3, "pinned", 5, Some(6), 1, blob);
            insert_session(conn, 4, "active", 50, None, 0, blob);
        }
        let older = Retention::new(&mut store, &path, RetentionConfig::default())
            .purge(PurgeScope::OlderThan {
                ended_before_ns: 30,
            })
            .expect("older_than");
        assert_eq!(older.len(), 1);
        assert_eq!(older[0].public_id, "early");
        assert_eq!(older[0].reason, PurgeReason::OlderThan);
        assert!(session_ids(store.connection()).contains(&2));

        let all = Retention::new(&mut store, &path, RetentionConfig::default())
            .purge(PurgeScope::All)
            .expect("all");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].public_id, "later");
        let ids = session_ids(store.connection());
        assert_eq!(ids, vec![3, 4]);
        let audit: String = store
            .connection()
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'purged:later'",
                [],
                |row| row.get(0),
            )
            .expect("audit");
        assert!(audit.ends_with(",all"), "{audit}");
        remove_db(&path);
    }

    #[test]
    fn stats_names_oldest_and_counts() {
        let path = temp_db("stats");
        let mut store = open(&path);
        {
            let conn = store.connection();
            insert_session(conn, 2, "second", 200, Some(300), 0, "[]");
            insert_session(conn, 1, "first", 100, None, 1, "[]");
        }
        let stats = Retention::new(&mut store, &path, RetentionConfig::default())
            .stats()
            .expect("stats");
        assert!(stats.page_bytes > 0);
        assert_eq!(table_rows(&stats, "sessions"), 2);
        assert_eq!(table_rows(&stats, "schema_meta"), 4);
        let oldest = stats.oldest_session.expect("oldest");
        assert_eq!(oldest.public_id, "first");
        assert_eq!(oldest.started_ns, 100);
        assert!(oldest.ended_ns.is_none());
        assert!(oldest.pinned);
        remove_db(&path);
    }

    #[test]
    fn delete_batch_and_concurrent_insert_both_commit() {
        // Two connections. The retention side deletes in one batch transaction.
        // The writer side inserts one session. Both commits must succeed.
        // The card's "Batcher waits ≤ 100 ms" bound is NOT measured: this test
        // only checks that both transactions commit. busy_timeout is set so
        // SQLite retries SQLITE_BUSY instead of failing the test on a race.
        let path = temp_db("concurrent");
        let mut store = open(&path);
        let blob = "[]";
        {
            let conn = store.connection();
            insert_session(conn, 1, "victim", 10, Some(20), 0, blob);
            conn.execute(
                "INSERT INTO dns (id, session_id, proc_uid, ts_ns, qname, qtype, rcode, answers, ttl_min, server, evidence, source)
                 VALUES (1, 1, NULL, 10, 'example.test', 1, NULL, NULL, NULL, NULL, 'E1', 'test')",
                [],
            )
            .expect("dns");
        }
        // Checkpoint so the second connection sees the schema and the row.
        store
            .connection()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .expect("checkpoint");

        let barrier = Arc::new(Barrier::new(2));
        let path_writer = path.clone();
        let barrier_writer = Arc::clone(&barrier);
        let writer = thread::spawn(move || {
            let conn = Connection::open(&path_writer).expect("writer open");
            conn.busy_timeout(std::time::Duration::from_secs(5))
                .expect("busy");
            conn.execute_batch("PRAGMA foreign_keys = ON").expect("fk");
            barrier_writer.wait();
            conn.execute(
                "INSERT INTO sessions (
                    id, public_id, name, mode, agent, root_proc_uid, argv, cwd, user_id,
                    started_ns, ended_ns, end_reason, exit_code, proxy_enabled, proxy_port,
                    platform, os_version, collectors, collector_profile, config_digest,
                    pinned, stats
                 ) VALUES (
                    9, 'writer', NULL, 'launch', NULL, NULL, 'placeholder', NULL, '0',
                    90, 91, NULL, NULL, 0, NULL,
                    'linux', NULL, '[]', NULL, NULL,
                    0, NULL
                 )",
                [],
            )
            .expect("concurrent insert");
        });

        store
            .connection()
            .busy_timeout(std::time::Duration::from_secs(5))
            .expect("busy");
        barrier.wait();
        let purged = Retention::new(&mut store, &path, RetentionConfig::default())
            .purge(PurgeScope::All)
            .expect("purge during insert");
        assert_eq!(purged.len(), 1);
        writer.join().expect("writer thread");

        let ids = session_ids(store.connection());
        assert!(
            ids.contains(&9),
            "concurrent insert must commit, ids={ids:?}"
        );
        assert!(!ids.contains(&1), "purge must commit, ids={ids:?}");
        remove_db(&path);
    }

    #[test]
    fn batches_cover_more_than_5000_child_rows() {
        let path = temp_db("batch");
        let mut store = open(&path);
        {
            let conn = store.connection();
            insert_session(conn, 1, "wide", 10, Some(20), 0, "[]");
            let tx = conn.unchecked_transaction().expect("tx");
            for i in 0..(BATCH_ROWS + 10) {
                tx.execute(
                    "INSERT INTO dns (id, session_id, proc_uid, ts_ns, qname, qtype, rcode, answers, ttl_min, server, evidence, source)
                     VALUES (?1, 1, NULL, ?1, 'example.test', 1, NULL, NULL, NULL, NULL, 'E1', 'test')",
                    params![i + 1],
                )
                .expect("dns row");
            }
            tx.commit().expect("commit dns");
        }
        let purged = Retention::new(&mut store, &path, RetentionConfig::default())
            .purge(PurgeScope::All)
            .expect("purge");
        assert_eq!(purged.len(), 1);
        let dns: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM dns", [], |row| row.get(0))
            .expect("count");
        assert_eq!(dns, 0);
        let sessions: i64 = store
            .connection()
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
            .expect("sessions");
        assert_eq!(sessions, 0);
        remove_db(&path);
    }

    fn table_rows(stats: &Stats, name: &str) -> i64 {
        stats
            .tables
            .iter()
            .find(|t| t.table == name)
            .expect("table")
            .rows
    }

    fn session_ids(conn: &Connection) -> Vec<i64> {
        let mut stmt = conn
            .prepare("SELECT id FROM sessions ORDER BY id")
            .expect("prepare");
        stmt.query_map([], |row| row.get(0))
            .expect("query")
            .collect::<Result<Vec<_>, _>>()
            .expect("ids")
    }
}
