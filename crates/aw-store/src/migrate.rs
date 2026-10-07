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

/// Version installed by [`MIGRATION_0001`].
pub const SCHEMA_VERSION: u32 = 1;

const MIGRATION_0001: &str = include_str!("../migrations/0001_init.sql");

const META_VERSION: &str = "schema_version";
const META_CREATED_NS: &str = "created_ns";
const META_APP_VERSION: &str = "app_version";
const META_HOST_ID: &str = "host_id";

/// What [`super::Store::open`] did to the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenStatus {
    /// The file was missing or empty. Migration 0001 ran. No backup was made.
    Created,
    /// The file was already at [`SCHEMA_VERSION`]. Nothing was written.
    Current,
    /// One or more migrations ran. `backup` is the closed-file copy of the old version.
    Migrated {
        /// Version before this open.
        from: u32,
        /// Version after this open. Equal to [`SCHEMA_VERSION`] unless a test injects a script.
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
    /// Open `path`, creating it when missing, and bring it to [`SCHEMA_VERSION`].
    ///
    /// Parent directories are created. On Unix the new or migrated file is mode `0o600`.
    /// A version higher than [`SCHEMA_VERSION`] yields [`OpenStatus::ReadOnlyNewer`]
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
    /// Production callers should use [`Store::open`].
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
            if found > SCHEMA_VERSION && extra.is_empty() {
                let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .map_err(|err| StoreError::sqlite("open_read_only", err))?;
                return Ok(Self {
                    conn,
                    status: OpenStatus::ReadOnlyNewer {
                        found,
                        supported: SCHEMA_VERSION,
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
                    2,
                    "UPDATE schema_meta SET value = value WHERE key = 'schema_version';",
                )],
            )
            .expect("bump");
            let backup = sibling(&path, ".bak-v1");
            assert_eq!(
                store.status(),
                &OpenStatus::Migrated {
                    from: 1,
                    to: 2,
                    backup: backup.clone(),
                }
            );
            assert!(backup.exists(), "successful upgrade keeps the backup");
        }
        let store = Store::open(&path).expect("newer");
        assert_eq!(
            store.status(),
            &OpenStatus::ReadOnlyNewer {
                found: 2,
                supported: 1,
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
