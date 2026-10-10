//! Embedded SQL migrations.
//!
//! Scripts live in `crates/aw-store/migrations/` and are compiled in with
//! `include_str!`. The runner reads `schema_meta.schema_version` (storage.md §6),
//! which is independent of the event schema version in `aw-core`.
//!
//! A database newer than this binary is reopened read-only. Pending scripts run
//! inside one transaction. A failure rolls that transaction back and
//! [`super::Store::open`] returns [`StoreError`] without leaving a partial schema.
//!
//! Before applying scripts to a file that already exists, the closed database
//! (and its `-wal` / `-shm` siblings, if present) is copied to
//! `{path}.bak-v{old}`. The copy is kept on success and deleted if migration
//! fails. A brand-new file is not backed up.
//!
//! storage.md §6 names the SQLite online backup API. That API is rusqlite's
//! `backup` feature. This crate enables only `bundled`, so the backup is a file
//! copy taken while the connection is closed. The process is the single writer.
//! The copy is not a `VACUUM`.
//!
//! Windows ACLs are not applied. Restricting the file to SYSTEM and Administrators
//! would need platform-specific code and a new dependency, and changing ACLs on
//! this machine is out of scope. Unix sets mode `0o600` after the file is created.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags};

use crate::error::StoreError;

/// Bootstrap version installed by [`MIGRATION_0001`].
///
/// Later scripts are applied on demand by the schema helpers, not by
/// [`Store::open`]. A database with only P1 tables stays at version 1. This
/// number is not the compatibility ceiling: this binary can also reopen the
/// schemas installed by those helpers, up to [`INTER_AGENT_SCHEMA_VERSION`].
/// Versions can be sparse; version 9 or 10 does not imply file or HTTP tables.
/// `0002_timeline_view.sql` is still applied by [`crate::query::ensure_timeline`],
/// not by this runner: it is not a numbered schema change.
pub const SCHEMA_VERSION: u32 = 1;

/// Highest schema version understood by this binary, independently of bootstrap.
const SUPPORTED_SCHEMA_VERSION: u32 = INTER_AGENT_SCHEMA_VERSION;

const MIGRATION_0001: &str = include_str!("../migrations/0001_init.sql");

/// `file_access` table and its four indexes. storage.md §3.
pub const MIGRATION_0003: &str = include_str!("../migrations/0003_file_access.sql");

/// Rebuilds the `timeline` view so the `file` branch is present.
pub const MIGRATION_0004: &str = include_str!("../migrations/0004_timeline_file.sql");

/// FTS5 trigram index over path, argv, and URL. storage.md §3.2.
pub const MIGRATION_0005: &str = include_str!("../migrations/0005_fts.sql");

/// `http` and `findings`, including `user_state*`. storage.md §3.
/// Does not touch the timeline view; that rebuild is [`MIGRATION_0007`] because
/// the view reads `file_access`, which a P1 database does not have.
pub const MIGRATION_0006: &str = include_str!("../migrations/0006_http_findings.sql");

/// Rebuilds the `timeline` view so the `http` and `finding` branches are present.
/// Requires `file_access` (0003) and `http` / `findings` (0006).
pub const MIGRATION_0007: &str = include_str!("../migrations/0007_timeline_http.sql");

/// `http.field_evidence` and `http.na_reason` for a URL that is NA.
///
/// `net_flows.via_proxy` and `net_flows.direct` are not touched: 0001 already
/// created both. [`apply_proxy_schema`] runs each ALTER only when the column
/// is missing, because SQLite has no `ADD COLUMN IF NOT EXISTS`.
pub const MIGRATION_0008: &str = include_str!("../migrations/0008_proxy_flow_marks.sql");

/// Version after [`MIGRATION_0003`], [`MIGRATION_0004`], and [`MIGRATION_0005`].
///
/// [`MIGRATION_0006`] and [`MIGRATION_0007`] are not part of this number.
/// 0007 reads `file_access`, so it cannot run on a database that stopped at
/// version 1. [`apply_http_schema`] runs the pair on its own.
pub const FILE_SCHEMA_VERSION: u32 = 5;

/// Scripts [`Store::open`] does not apply on its own.
///
/// Pass them to [`Store::open_with_scripts`] (see [`apply_file_schema`]) when
/// the caller is about to write or query `file_access`. Versions are strictly
/// increasing and all greater than [`SCHEMA_VERSION`].
pub fn file_schema_scripts() -> [(u32, &'static str); 3] {
    [
        (3, MIGRATION_0003),
        (4, MIGRATION_0004),
        (5, MIGRATION_0005),
    ]
}

/// `http`, `findings`, and the timeline rebuild that reads both.
///
/// [`MIGRATION_0007`] selects from `file_access`, so the caller applies
/// [`file_schema_scripts`] first. [`apply_http_schema`] does that check.
pub fn http_schema_scripts() -> [(u32, &'static str); 2] {
    [(6, MIGRATION_0006), (7, MIGRATION_0007)]
}

/// Version after [`MIGRATION_0006`] and [`MIGRATION_0007`].
pub const HTTP_SCHEMA_VERSION: u32 = 7;

/// Version after [`MIGRATION_0008`].
///
/// Not part of [`HTTP_SCHEMA_VERSION`]. A database that stores `http` but never
/// records a proxy URL reason stays at 7. [`apply_proxy_schema`] advances this.
pub const PROXY_SCHEMA_VERSION: u32 = 8;

/// `agent_events`: one bounded E3 self-report. [`apply_agent_schema`] runs it
/// only when the table is missing. A database that never stores a self-report
/// stays at whatever version it already had.
pub const MIGRATION_0009: &str = include_str!("../migrations/0009_agent_events.sql");

/// Version after [`MIGRATION_0009`].
///
/// Not part of [`SCHEMA_VERSION`], [`FILE_SCHEMA_VERSION`], or
/// [`PROXY_SCHEMA_VERSION`]. [`Store::open`] does not apply this script.
/// [`apply_agent_schema`] does, and only when `agent_events` is absent.
pub const AGENT_SCHEMA_VERSION: u32 = 9;

/// Inter-agent tables and `sessions.group_id` (P6-STORE-01).
///
/// [`apply_inter_agent_schema`] runs it only when `watch_groups` is missing.
/// A database that never stores an inter-agent row stays at whatever version
/// it already had. [`Store::open`] does not apply this script.
pub const MIGRATION_0010: &str = include_str!("../migrations/0010_inter_agent.sql");

/// Version after [`MIGRATION_0010`].
pub const INTER_AGENT_SCHEMA_VERSION: u32 = 10;

/// Apply [`http_schema_scripts`] when `http` is not there yet.
///
/// `file_access` must already exist: 0007's view reads it. A database that has
/// not applied [`file_schema_scripts`] gets [`StoreError::VersionMismatch`]
/// rather than a view that fails to create. Applying the scripts preserves a
/// higher stored version. A database that already has `http` is left alone,
/// including its `schema_version`.
pub fn apply_http_schema(store: &mut Store) -> Result<(), StoreError> {
    if store.is_read_only() {
        return Err(StoreError::ReadOnly);
    }
    let conn = store.connection();
    if table_present(conn, "http", "probe_http")? {
        return Ok(());
    }
    if !table_present(conn, "file_access", "probe_file_access")? {
        return Err(StoreError::VersionMismatch {
            expected: FILE_SCHEMA_VERSION,
            found: Some(store.schema_version()?),
        });
    }
    let tx = conn
        .unchecked_transaction()
        .map_err(|err| StoreError::sqlite("begin_http_schema", err))?;
    let applied = (|| {
        for (version, sql) in http_schema_scripts() {
            tx.execute_batch(sql)
                .map_err(|err| StoreError::sqlite("migrate_http_schema", err))?;
            tx.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET value =
                     MAX(CAST(schema_meta.value AS INTEGER), CAST(excluded.value AS INTEGER))",
                rusqlite::params![version.to_string()],
            )
            .map_err(|err| StoreError::sqlite("migrate_http_schema_version", err))?;
        }
        Ok::<(), StoreError>(())
    })();
    match applied {
        Ok(()) => tx
            .commit()
            .map_err(|err| StoreError::sqlite("commit_http_schema", err)),
        Err(err) => {
            drop(tx);
            Err(err)
        }
    }
}

/// Add `http.field_evidence` and `http.na_reason` when they are not there yet.
///
/// `http` must already exist ([`apply_http_schema`]). A database without it
/// gets [`StoreError::VersionMismatch`] rather than an ALTER against a missing
/// table. A column that is already present is skipped; the other column is
/// still added. `schema_version` advances to at least [`PROXY_SCHEMA_VERSION`]
/// only when this call adds at least one column; a higher stored version is
/// preserved. A database that already has both is
/// left alone, including its version.
///
/// `net_flows.via_proxy` and `net_flows.direct` are not added here. 0001
/// created them. `direct` and `via_proxy` are already filter fields
/// ([`crate::query::compile`]).
pub fn apply_proxy_schema(store: &mut Store) -> Result<(), StoreError> {
    if store.is_read_only() {
        return Err(StoreError::ReadOnly);
    }
    let conn = store.connection();
    if !table_present(conn, "http", "probe_http_proxy")? {
        return Err(StoreError::VersionMismatch {
            expected: HTTP_SCHEMA_VERSION,
            found: Some(store.schema_version()?),
        });
    }
    let need_field = !column_present(conn, "http", "field_evidence", "probe_http_field_evidence")?;
    let need_na = !column_present(conn, "http", "na_reason", "probe_http_na_reason")?;
    if !need_field && !need_na {
        return Ok(());
    }
    let field_sql = alter_statement(MIGRATION_0008, "field_evidence");
    let na_sql = alter_statement(MIGRATION_0008, "na_reason");
    let tx = conn
        .unchecked_transaction()
        .map_err(|err| StoreError::sqlite("begin_proxy_schema", err))?;
    let applied = (|| {
        // Statements are the two ALTERs in MIGRATION_0008, in that order.
        // Running the whole script would fail once either column already exists.
        if need_field {
            let sql = field_sql.ok_or(StoreError::BadSchemaVersion {
                found: Some("field_evidence".to_owned()),
            })?;
            tx.execute_batch(sql)
                .map_err(|err| StoreError::sqlite("migrate_http_field_evidence", err))?;
        }
        if need_na {
            let sql = na_sql.ok_or(StoreError::BadSchemaVersion {
                found: Some("na_reason".to_owned()),
            })?;
            tx.execute_batch(sql)
                .map_err(|err| StoreError::sqlite("migrate_http_na_reason", err))?;
        }
        tx.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value =
                     MAX(CAST(schema_meta.value AS INTEGER), CAST(excluded.value AS INTEGER))",
            rusqlite::params![PROXY_SCHEMA_VERSION.to_string()],
        )
        .map_err(|err| StoreError::sqlite("migrate_proxy_schema_version", err))?;
        Ok::<(), StoreError>(())
    })();
    match applied {
        Ok(()) => tx
            .commit()
            .map_err(|err| StoreError::sqlite("commit_proxy_schema", err)),
        Err(err) => {
            drop(tx);
            Err(err)
        }
    }
}

/// Create `agent_events` when it is not there yet.
///
/// The table does not depend on `http` or `file_access`. A database that
/// already has it is left alone, including its `schema_version`. `schema_version`
/// advances to at least [`AGENT_SCHEMA_VERSION`] only when this call creates
/// the table; a higher stored version is preserved.
///
/// # Errors
///
/// [`StoreError::ReadOnly`] when the store was opened read-only.
/// [`StoreError::Sqlite`] when the script or the version row fails. The
/// transaction is rolled back.
pub fn apply_agent_schema(store: &mut Store) -> Result<(), StoreError> {
    if store.is_read_only() {
        return Err(StoreError::ReadOnly);
    }
    let conn = store.connection();
    if table_present(conn, "agent_events", "probe_agent_events")? {
        return Ok(());
    }
    let tx = conn
        .unchecked_transaction()
        .map_err(|err| StoreError::sqlite("begin_agent_schema", err))?;
    let applied = (|| {
        tx.execute_batch(MIGRATION_0009)
            .map_err(|err| StoreError::sqlite("migrate_agent_events", err))?;
        tx.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value =
                     MAX(CAST(schema_meta.value AS INTEGER), CAST(excluded.value AS INTEGER))",
            rusqlite::params![AGENT_SCHEMA_VERSION.to_string()],
        )
        .map_err(|err| StoreError::sqlite("migrate_agent_schema_version", err))?;
        Ok::<(), StoreError>(())
    })();
    match applied {
        Ok(()) => tx
            .commit()
            .map_err(|err| StoreError::sqlite("commit_agent_schema", err)),
        Err(err) => {
            drop(tx);
            Err(err)
        }
    }
}

/// Create the inter-agent tables and `sessions.group_id` when they are absent.
///
/// The script does not depend on `http`, `file_access`, or `agent_events`.
/// A database that already has `watch_groups` is left alone, including its
/// `schema_version`. `schema_version` advances to at least
/// [`INTER_AGENT_SCHEMA_VERSION`] only when this call creates the tables;
/// a higher stored version is preserved.
///
/// # Errors
///
/// [`StoreError::ReadOnly`] when the store was opened read-only.
/// [`StoreError::Sqlite`] when the script or the version row fails. The
/// transaction is rolled back.
pub fn apply_inter_agent_schema(store: &mut Store) -> Result<(), StoreError> {
    if store.is_read_only() {
        return Err(StoreError::ReadOnly);
    }
    let conn = store.connection();
    if table_present(conn, "watch_groups", "probe_watch_groups")? {
        return Ok(());
    }
    let tx = conn
        .unchecked_transaction()
        .map_err(|err| StoreError::sqlite("begin_inter_agent_schema", err))?;
    let applied = (|| {
        tx.execute_batch(MIGRATION_0010)
            .map_err(|err| StoreError::sqlite("migrate_inter_agent", err))?;
        tx.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO UPDATE SET value =
                     MAX(CAST(schema_meta.value AS INTEGER), CAST(excluded.value AS INTEGER))",
            rusqlite::params![INTER_AGENT_SCHEMA_VERSION.to_string()],
        )
        .map_err(|err| StoreError::sqlite("migrate_inter_agent_schema_version", err))?;
        Ok::<(), StoreError>(())
    })();
    match applied {
        Ok(()) => tx
            .commit()
            .map_err(|err| StoreError::sqlite("commit_inter_agent_schema", err)),
        Err(err) => {
            drop(tx);
            Err(err)
        }
    }
}

/// The single `ALTER TABLE http ADD COLUMN <name> ...;` line inside `script`.
///
/// `name` is a fixed column from this migration, not user input. `None` means
/// the script no longer contains that add, which is a broken build rather than
/// a database that should be altered with a hand-written statement.
fn alter_statement<'a>(script: &'a str, column: &str) -> Option<&'a str> {
    let needle = format!("ADD COLUMN {column} ");
    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.contains(&needle) {
            return Some(trimmed);
        }
    }
    None
}

fn column_present(
    conn: &Connection,
    table: &str,
    column: &str,
    op: &'static str,
) -> Result<bool, StoreError> {
    // `table` is a fixed name from this crate, not user input. PRAGMA does not
    // accept a placeholder for the table, so it is checked against the two
    // names this migration is allowed to look at.
    let pragma = match table {
        "http" => "PRAGMA table_info(http)",
        "net_flows" => "PRAGMA table_info(net_flows)",
        _ => {
            return Err(StoreError::sqlite(
                op,
                rusqlite::Error::InvalidParameterName(table.to_owned()),
            ))
        }
    };
    let mut stmt = conn
        .prepare(pragma)
        .map_err(|err| StoreError::sqlite(op, err))?;
    let mut rows = stmt.query([]).map_err(|err| StoreError::sqlite(op, err))?;
    while let Some(row) = rows.next().map_err(|err| StoreError::sqlite(op, err))? {
        let name: String = row.get(1).map_err(|err| StoreError::sqlite(op, err))?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn table_present(conn: &Connection, name: &str, op: &'static str) -> Result<bool, StoreError> {
    let found: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            rusqlite::params![name],
            |row| row.get(0),
        )
        .map_err(|err| StoreError::sqlite(op, err))?;
    Ok(found > 0)
}

const META_VERSION: &str = "schema_version";
const META_CREATED_NS: &str = "created_ns";
const META_APP_VERSION: &str = "app_version";
const META_HOST_ID: &str = "host_id";

/// What [`super::Store::open`] did to the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenStatus {
    /// The file was missing or empty. Migration 0001 ran. No backup was made.
    Created,
    /// The file has a supported version and no scripts were pending.
    Current,
    /// One or more migrations ran. `backup` is the closed-file copy of the old version.
    Migrated {
        /// Version before this open.
        from: u32,
        /// Version after this open, including any explicitly supplied scripts.
        to: u32,
        /// `{path}.bak-v{from}` kept after a successful upgrade.
        backup: PathBuf,
    },
    /// The file's version is newer than this binary. The connection is read-only.
    ReadOnlyNewer {
        /// Version stored in the file.
        found: u32,
        /// Highest version this binary can write.
        supported: u32,
    },
}

/// A SQLite file opened by the migrator.
pub struct Store {
    conn: Connection,
    status: OpenStatus,
    read_only: bool,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("status", &self.status)
            .field("read_only", &self.read_only)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Open `path`, creating the bootstrap schema when missing.
    ///
    /// Supported schemas through [`INTER_AGENT_SCHEMA_VERSION`] remain writable;
    /// optional tables are only added by their schema helpers. Parent directories
    /// are created. On Unix the new or migrated file is mode `0o600`.
    /// A version higher than the supported ceiling yields [`OpenStatus::ReadOnlyNewer`]
    /// and does not write. A failed migration deletes the backup made for this attempt
    /// and returns [`StoreError`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_scripts(path.as_ref(), &[])
    }

    /// Like [`Store::open`], then run `extra` as additional migration scripts.
    ///
    /// Each entry is `(version, sql)`. Versions must be strictly increasing and
    /// greater than [`SCHEMA_VERSION`] when the built-in script is also pending.
    /// Tests use this to inject a failing statement without editing `0001_init.sql`.
    /// A stored version above this binary's supported ceiling remains read-only,
    /// even when `extra` is supplied. Production callers should use [`Store::open`].
    pub fn open_with_scripts(path: &Path, extra: &[(u32, &str)]) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|err| {
                    StoreError::io("create_parent", Some(parent.to_path_buf()), err)
                })?;
            }
        }

        let existed = file_nonempty(path)?;
        let (found, needs_migration) = if existed {
            let found = read_version_quietly(path)?;
            if found > SUPPORTED_SCHEMA_VERSION {
                let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .map_err(|err| StoreError::sqlite("open_read_only", err))?;
                return Ok(Self {
                    conn,
                    status: OpenStatus::ReadOnlyNewer {
                        found,
                        supported: SUPPORTED_SCHEMA_VERSION,
                    },
                    read_only: true,
                });
            }
            (Some(found), found < SCHEMA_VERSION || !extra.is_empty())
        } else {
            (None, true)
        };

        if !needs_migration {
            let conn = open_writable(path)?;
            apply_pragmas(&conn)?;
            let _ = restrict_unix(path);
            return Ok(Self {
                conn,
                status: OpenStatus::Current,
                read_only: false,
            });
        }

        let backup = if existed {
            let from = found.ok_or(StoreError::BadSchemaVersion { found: None })?;
            Some(backup_closed_file(path, from)?)
        } else {
            None
        };

        let conn = open_writable(path)?;
        // auto_vacuum is set before the first CREATE and is not followed by VACUUM.
        // On an existing database the pragma is a no-op until a vacuum this crate does not run.
        apply_pragmas(&conn)?;

        let from = found.unwrap_or(0);
        let result = apply_pending(&conn, from, extra);
        match result {
            Ok(to) => {
                restrict_unix(path)?;
                let status = if from == 0 && backup.is_none() {
                    OpenStatus::Created
                } else {
                    OpenStatus::Migrated {
                        from,
                        to,
                        backup: backup.unwrap_or_else(|| path.to_path_buf()),
                    }
                };
                Ok(Self {
                    conn,
                    status,
                    read_only: false,
                })
            }
            Err(err) => {
                drop(conn);
                if let Some(backup_path) = backup {
                    let _ = remove_backup_set(&backup_path);
                }
                Err(err)
            }
        }
    }

    /// How the file was opened. See [`OpenStatus`].
    pub fn status(&self) -> &OpenStatus {
        &self.status
    }

    /// `true` when the file is newer than this binary and was opened read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// `schema_meta.schema_version` as an integer.
    pub fn schema_version(&self) -> Result<u32, StoreError> {
        read_version(&self.conn)
    }

    /// Borrow the write connection. Read-only opens still return the connection;
    /// writes fail at SQLite.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Borrow the write connection mutably. [`crate::SqliteSink`] needs this.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

fn open_writable(path: &Path) -> Result<Connection, StoreError> {
    // Touch the file first so a subsequent chmod applies to an existing inode.
    let _file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| StoreError::io("create_db", Some(path.to_path_buf()), err))?;
    Connection::open(path).map_err(|err| StoreError::sqlite("open", err))
}

fn apply_pragmas(conn: &Connection) -> Result<(), StoreError> {
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")
        .map_err(|err| StoreError::sqlite("pragma_auto_vacuum", err))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|err| StoreError::sqlite("pragma_journal_mode", err))?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|err| StoreError::sqlite("pragma_synchronous", err))?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|err| StoreError::sqlite("pragma_foreign_keys", err))?;
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|err| StoreError::sqlite("pragma_temp_store", err))?;
    conn.pragma_update(None, "mmap_size", 268_435_456_i64)
        .map_err(|err| StoreError::sqlite("pragma_mmap_size", err))?;
    Ok(())
}

fn apply_pending(conn: &Connection, from: u32, extra: &[(u32, &str)]) -> Result<u32, StoreError> {
    let mut scripts: Vec<(u32, &str)> = Vec::new();
    if from < SCHEMA_VERSION {
        scripts.push((SCHEMA_VERSION, MIGRATION_0001));
    }
    for (version, sql) in extra {
        if *version > from {
            scripts.push((*version, *sql));
        }
    }
    scripts.sort_by_key(|(version, _)| *version);
    if scripts.is_empty() {
        return Ok(from);
    }

    let tx = conn
        .unchecked_transaction()
        .map_err(|err| StoreError::sqlite("begin_migration", err))?;
    let mut to = from;
    let applied = (|| {
        for (version, sql) in &scripts {
            if *version <= to {
                continue;
            }
            tx.execute_batch(sql)
                .map_err(|err| StoreError::sqlite("migrate", err))?;
            if *version == SCHEMA_VERSION && from < SCHEMA_VERSION {
                seed_meta(&tx)?;
            } else {
                tx.execute(
                    "INSERT INTO schema_meta (key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    rusqlite::params![META_VERSION, version.to_string()],
                )
                .map_err(|err| StoreError::sqlite("migrate_version", err))?;
            }
            to = *version;
        }
        Ok::<(), StoreError>(())
    })();
    match applied {
        Ok(()) => {
            tx.commit()
                .map_err(|err| StoreError::sqlite("commit_migration", err))?;
            let found = read_version(conn)?;
            if found != to {
                return Err(StoreError::VersionMismatch {
                    expected: to,
                    found: Some(found),
                });
            }
            Ok(to)
        }
        Err(err) => {
            // Dropping the transaction rolls it back. DDL in SQLite is transactional.
            drop(tx);
            Err(err)
        }
    }
}

fn seed_meta(conn: &Connection) -> Result<(), StoreError> {
    let created_ns = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos().to_string(),
        // 0 means the clock is before the Unix epoch, not an unknown field.
        Err(_) => "0".to_string(),
    };
    let host_id = random_uuid(conn)?;
    let rows = [
        (META_VERSION, SCHEMA_VERSION.to_string()),
        (META_CREATED_NS, created_ns),
        (META_APP_VERSION, env!("CARGO_PKG_VERSION").to_string()),
        (META_HOST_ID, host_id),
    ];
    for (key, value) in rows {
        conn.execute(
            "INSERT INTO schema_meta (key, value) VALUES (?1, ?2)",
            rusqlite::params![key, value],
        )
        .map_err(|err| StoreError::sqlite("seed_meta", err))?;
    }
    Ok(())
}

fn random_uuid(conn: &Connection) -> Result<String, StoreError> {
    let blob: Vec<u8> = conn
        .query_row("SELECT randomblob(16)", [], |row| row.get(0))
        .map_err(|err| StoreError::sqlite("host_id", err))?;
    if blob.len() != 16 {
        return Err(StoreError::BadSchemaVersion {
            found: Some(format!("randomblob len {}", blob.len())),
        });
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&blob);
    // RFC 4122 version 4 / variant 10. Not a hostname and not derived from the machine.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h = |i: usize| format!("{:02x}", bytes[i]);
    Ok(format!(
        "{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        h(0),
        h(1),
        h(2),
        h(3),
        h(4),
        h(5),
        h(6),
        h(7),
        h(8),
        h(9),
        h(10),
        h(11),
        h(12),
        h(13),
        h(14),
        h(15),
    ))
}

fn read_version(conn: &Connection) -> Result<u32, StoreError> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM schema_meta WHERE key = ?1",
            rusqlite::params![META_VERSION],
            |row| row.get(0),
        )
        .map_err(|err| StoreError::sqlite("read_schema_version", err))?;
    parse_version(value)
}

fn read_version_quietly(path: &Path) -> Result<u32, StoreError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|err| StoreError::sqlite("peek_version", err))?;
    // foreign_keys is irrelevant for a one-row read. Do not set write pragmas.
    let found = read_version(&conn)?;
    drop(conn);
    Ok(found)
}

fn parse_version(value: Option<String>) -> Result<u32, StoreError> {
    let Some(value) = value else {
        return Err(StoreError::BadSchemaVersion { found: None });
    };
    value
        .parse::<u32>()
        .map_err(|_| StoreError::BadSchemaVersion { found: Some(value) })
}

fn file_nonempty(path: &Path) -> Result<bool, StoreError> {
    match fs::metadata(path) {
        Ok(meta) => Ok(meta.len() > 0),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(StoreError::io("stat_db", Some(path.to_path_buf()), err)),
    }
}

fn backup_closed_file(path: &Path, from: u32) -> Result<PathBuf, StoreError> {
    let backup = sibling(path, &format!(".bak-v{from}"));
    copy_if_present(path, &backup)?;
    copy_if_present(&sibling(path, "-wal"), &sibling(&backup, "-wal"))?;
    copy_if_present(&sibling(path, "-shm"), &sibling(&backup, "-shm"))?;
    Ok(backup)
}

fn copy_if_present(from: &Path, to: &Path) -> Result<(), StoreError> {
    match fs::metadata(from) {
        Ok(meta) if meta.len() > 0 || meta.is_file() => {
            fs::copy(from, to)
                .map_err(|err| StoreError::io("backup", Some(to.to_path_buf()), err))?;
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(StoreError::io(
            "stat_backup_src",
            Some(from.to_path_buf()),
            err,
        )),
    }
}

fn remove_backup_set(backup: &Path) -> Result<(), StoreError> {
    for path in [
        backup.to_path_buf(),
        sibling(backup, "-wal"),
        sibling(backup, "-shm"),
    ] {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(StoreError::io("remove_backup", Some(path), err)),
        }
    }
    Ok(())
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(suffix);
    PathBuf::from(os)
}

/// Unix: owner read/write only. Windows: not implemented (see module docs).
fn restrict_unix(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)
            .map_err(|err| StoreError::io("chmod", Some(path.to_path_buf()), err))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn temp_db(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("aw-store-migrate-{label}-{nanos}.db"))
    }

    #[test]
    fn empty_file_migrates_to_v1() {
        let path = temp_db("empty");
        let _ = fs::remove_file(&path);
        let store = Store::open(&path).expect("open empty");
        assert_eq!(store.status(), &OpenStatus::Created);
        assert_eq!(store.schema_version().expect("version"), 1);
        assert!(!store.is_read_only());
        let tables = table_names(store.connection());
        for name in [
            "schema_meta",
            "sessions",
            "processes",
            "process_images",
            "net_flows",
            "net_flow_buckets",
            "dns",
            "gaps",
        ] {
            assert!(tables.contains(&name.to_string()), "missing {name}");
        }
        for absent in [
            "file_access",
            "http",
            "findings",
            "agent_events",
            "raw_events",
            "watch_groups",
        ] {
            assert!(!tables.contains(&absent.to_string()), "unexpected {absent}");
        }
        let host: String = store
            .connection()
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'host_id'",
                [],
                |row| row.get(0),
            )
            .expect("host_id");
        assert_eq!(host.len(), 36);
        assert!(!host.contains('\\') && !host.contains('/'));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reopen_is_idempotent() {
        let path = temp_db("reopen");
        let _ = fs::remove_file(&path);
        {
            let store = Store::open(&path).expect("first");
            assert!(matches!(store.status(), OpenStatus::Created));
        }
        let store = Store::open(&path).expect("second");
        assert_eq!(store.status(), &OpenStatus::Current);
        assert_eq!(store.schema_version().expect("version"), 1);
        let backup = sibling(&path, ".bak-v0");
        assert!(!backup.exists(), "current open must not write a backup");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn injected_failure_rolls_back_and_keeps_schema() {
        let path = temp_db("rollback");
        let _ = fs::remove_file(&path);
        {
            let store = Store::open(&path).expect("base");
            assert_eq!(store.schema_version().expect("v"), 1);
        }
        let before = table_names_at(&path);
        let err = Store::open_with_scripts(
            &path,
            &[(2, "CREATE TABLE should_not_stick (id INTEGER); SELECT * FROM no_such_migration_table;")],
        );
        assert!(err.is_err(), "illegal migration must fail the open");
        let backup = sibling(&path, ".bak-v1");
        assert!(!backup.exists(), "failed attempt must delete its backup");
        let store = Store::open(&path).expect("still opens");
        assert_eq!(store.schema_version().expect("version"), 1);
        assert_eq!(table_names(store.connection()), before);
        let stuck: i64 = store
            .connection()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'should_not_stick'",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(stuck, 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn newer_database_opens_read_only() {
        let path = temp_db("newer");
        let _ = fs::remove_file(&path);
        {
            let store = Store::open(&path).expect("v1");
            assert!(matches!(store.status(), OpenStatus::Created));
        }
        {
            let store = Store::open_with_scripts(
                &path,
                &[(
                    SUPPORTED_SCHEMA_VERSION + 1,
                    "UPDATE schema_meta SET value = value WHERE key = 'schema_version';",
                )],
            )
            .expect("bump");
            let backup = sibling(&path, ".bak-v1");
            assert_eq!(
                store.status(),
                &OpenStatus::Migrated {
                    from: 1,
                    to: SUPPORTED_SCHEMA_VERSION + 1,
                    backup: backup.clone(),
                }
            );
            assert!(backup.exists(), "successful upgrade keeps the backup");
        }
        let store = Store::open(&path).expect("newer");
        assert_eq!(
            store.status(),
            &OpenStatus::ReadOnlyNewer {
                found: SUPPORTED_SCHEMA_VERSION + 1,
                supported: SUPPORTED_SCHEMA_VERSION,
            }
        );
        assert!(store.is_read_only());
        let write = store.connection().execute(
            "INSERT INTO schema_meta (key, value) VALUES ('nope', 'nope')",
            [],
        );
        assert!(write.is_err(), "read-only connection must reject writes");
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(sibling(&path, ".bak-v1"));
    }

    fn table_names(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .expect("prepare");
        let rows = stmt
            .query_map([], |row| row.get(0))
            .expect("query")
            .collect::<Result<Vec<String>, _>>()
            .expect("rows");
        rows
    }

    fn table_names_at(path: &Path) -> Vec<String> {
        let conn = Connection::open(path).expect("open");
        table_names(&conn)
    }
}
