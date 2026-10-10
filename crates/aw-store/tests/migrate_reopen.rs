#![allow(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use aw_store::{
    apply_agent_schema, apply_file_schema, apply_http_schema, apply_inter_agent_schema,
    apply_proxy_schema, OpenStatus, Store, StoreError,
};
use rusqlite::Connection;

const MIGRATION_0001_OLD: &str = include_str!("../migrations/0001_init.sql");
const MIGRATION_0002: &str = include_str!("../migrations/0002_timeline_view.sql");
const MIGRATION_0003: &str = include_str!("../migrations/0003_file_access.sql");
const MIGRATION_0004: &str = include_str!("../migrations/0004_timeline_file.sql");
const MIGRATION_0005: &str = include_str!("../migrations/0005_fts.sql");
const MIGRATION_0006: &str = include_str!("../migrations/0006_http_findings.sql");
const MIGRATION_0007: &str = include_str!("../migrations/0007_timeline_http.sql");
const MIGRATION_0008: &str = include_str!("../migrations/0008_proxy_flow_marks.sql");
const MIGRATION_0009: &str = include_str!("../migrations/0009_agent_events.sql");

struct TestDb {
    dir: PathBuf,
    path: PathBuf,
}

impl TestDb {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "aw-store-reopen-{}-{nanos}-{id}",
            std::process::id()
        ));
        fs::create_dir(&dir).expect("test directory");
        let path = dir.join("store.db");
        Self { dir, path }
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn present(conn: &Connection, table: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )
    .expect("table presence")
}

fn schema(conn: &Connection) -> Vec<(String, String, Option<String>)> {
    conn.prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
        .expect("schema query")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("schema rows")
        .collect::<Result<_, _>>()
        .expect("schema values")
}

fn insert_data(conn: &Connection) {
    conn.execute_batch(
        "INSERT INTO sessions (id, public_id, mode, user_id, started_ns, platform, collectors)
         VALUES (1, 'reopen-session', 'launch', 'fixture-user', 1, 'fixture', '[]');
         INSERT INTO dns (session_id, ts_ns, qname, qtype, evidence, source)
         VALUES (1, 2, 'before.example.test', 1, 'E1', 'fixture');",
    )
    .expect("base data");
    for (table, sql) in [
        (
            "file_access",
            "INSERT INTO file_access (session_id, proc_uid, op, path, first_ns, last_ns, evidence, source)
             VALUES (1, 1, 'access', '/fixture/reopen', 3, 3, 'E1', 'fixture')",
        ),
        (
            "http",
            "INSERT INTO http (session_id, ts_ns, method, url, host, evidence, source)
             VALUES (1, 4, 'GET', 'https://example.test/reopen', 'example.test', 'E2', 'fixture')",
        ),
        (
            "agent_events",
            "INSERT INTO agent_events (session_id, ts_ns, agent, tool, evidence, source)
             VALUES (1, 5, 'fixture-agent', 'fixture-tool', 'E3', 'fixture')",
        ),
        (
            "watch_groups",
            "INSERT INTO watch_groups (public_id, user_id, name, created_ns)
             VALUES ('reopen-group', 'fixture-user', 'fixture-group', 6)",
        ),
    ] {
        if present(conn, table) {
            conn.execute(sql, []).expect("feature data");
        }
    }
}

fn records(conn: &Connection) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for (table, column) in [
        ("sessions", "public_id"),
        ("dns", "qname"),
        ("file_access", "path"),
        ("http", "url"),
        ("agent_events", "tool"),
        ("watch_groups", "name"),
    ] {
        if present(conn, table) {
            // Both identifiers are fixed test constants.
            let sql = format!("SELECT {column} FROM {table} ORDER BY id");
            let values = conn
                .prepare(&sql)
                .expect("data query")
                .query_map([], |row| row.get::<_, String>(0))
                .expect("data rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("data values");
            result.extend(values.into_iter().map(|value| (table.to_owned(), value)));
        }
    }
    result
}

fn prepare(store: &mut Store, version: u32) {
    match version {
        5 => apply_file_schema(store).expect("file schema"),
        7 | 8 => {
            apply_file_schema(store).expect("file schema");
            apply_http_schema(store).expect("http schema");
            if version == 8 {
                apply_proxy_schema(store).expect("proxy schema");
            }
        }
        9 => apply_agent_schema(store).expect("sparse agent schema"),
        10 => apply_inter_agent_schema(store).expect("sparse inter-agent schema"),
        _ => panic!("unexpected test version"),
    }
    assert_eq!(store.schema_version().expect("prepared version"), version);
}

fn assert_supported_reopen(version: u32) {
    let db = TestDb::new();
    let (before_schema, before_data) = {
        let mut store = Store::open(&db.path).expect("new store");
        assert_eq!(store.status(), &OpenStatus::Created);
        assert_eq!(store.schema_version().expect("bootstrap version"), 1);
        prepare(&mut store, version);
        insert_data(store.connection());
        (schema(store.connection()), records(store.connection()))
    };
    {
        let mut store = Store::open(&db.path).expect("reopen supported store");
        assert_eq!(store.status(), &OpenStatus::Current);
        assert!(!store.is_read_only());
        assert_eq!(store.schema_version().expect("reopened version"), version);
        assert_eq!(schema(store.connection()), before_schema);
        assert_eq!(records(store.connection()), before_data);
        if version == 9 || version == 10 {
            assert!(matches!(
                apply_http_schema(&mut store),
                Err(StoreError::VersionMismatch { expected: 5, found: Some(v) }) if v == version
            ));
            assert_eq!(schema(store.connection()), before_schema);
        }
        // Repeating the actual helper must also remain idempotent after reopen.
        prepare(&mut store, version);
        assert_eq!(schema(store.connection()), before_schema);
        assert_eq!(records(store.connection()), before_data);
        store
            .connection()
            .execute(
                "INSERT INTO dns (session_id, ts_ns, qname, qtype, evidence, source)
                 VALUES (1, 7, 'after.example.test', 1, 'E1', 'fixture')",
                [],
            )
            .expect("write after reopen");
    }
    let store = Store::open(&db.path).expect("reopen written store");
    let count: i64 = store
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM dns WHERE qname = 'after.example.test'",
            [],
            |row| row.get(0),
        )
        .expect("persisted write");
    assert_eq!(count, 1);
    if version == 9 || version == 10 {
        for absent in ["file_access", "fts_text", "http", "findings"] {
            assert!(!present(store.connection(), absent), "unexpected {absent}");
        }
        assert_eq!(present(store.connection(), "agent_events"), version == 9);
        assert_eq!(present(store.connection(), "watch_groups"), version == 10);
    }
    assert_eq!(
        fs::read_dir(&db.dir)
            .expect("test files")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".bak-v"))
            .count(),
        0
    );
}

#[test]
fn file_v5_reopens_writable() {
    assert_supported_reopen(5);
}

#[test]
fn http_v7_reopens_writable() {
    assert_supported_reopen(7);
}

#[test]
fn proxy_v8_reopens_writable() {
    assert_supported_reopen(8);
}

#[test]
fn sparse_agent_v9_reopens_writable_without_extra_ddl() {
    assert_supported_reopen(9);
}

#[test]
fn sparse_inter_agent_v10_reopens_writable_without_extra_ddl() {
    assert_supported_reopen(10);
}

#[test]
fn old_v9_database_opens_with_null_exit_codes() {
    let db = TestDb::new();
    // A v9 database written by a release before exit codes were recorded:
    // the column exists (0001) but no row ever had a value.
    let old_init = MIGRATION_0001_OLD.to_owned();
    let conn = Connection::open(&db.path).expect("legacy database");
    for sql in [
        old_init.as_str(),
        MIGRATION_0002,
        MIGRATION_0003,
        MIGRATION_0004,
        MIGRATION_0005,
        MIGRATION_0006,
        MIGRATION_0007,
        MIGRATION_0008,
        MIGRATION_0009,
    ] {
        conn.execute_batch(sql).expect("legacy migration");
    }
    conn.execute(
        "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '9')",
        [],
    )
    .expect("legacy schema version");
    conn.execute_batch(
        "INSERT INTO sessions (id, public_id, mode, user_id, started_ns, platform, collectors) \
         VALUES (1, 'legacy-exit', 'launch', 'fixture-user', 1, 'fixture', '[]'); \
         INSERT INTO processes (session_id, proc_uid, pid, depth, start_ns, how, evidence, source) \
         VALUES (1, 1, 100, 0, 1, 'spawn', 'S', 'fixture');",
    )
    .expect("legacy process row");
    drop(conn);

    let store = Store::open(&db.path).expect("migrated store");
    let exit_code: Option<i64> = store
        .connection()
        .query_row(
            "SELECT exit_code FROM processes WHERE session_id = 1 AND proc_uid = 1",
            [],
            |row| row.get(0),
        )
        .expect("migrated exit code");
    assert_eq!(exit_code, None);
}

#[test]
fn file_helper_preserves_sparse_higher_versions_and_data() {
    for version in [9, 10] {
        let db = TestDb::new();
        {
            let mut store = Store::open(&db.path).expect("base");
            prepare(&mut store, version);
            insert_data(store.connection());
        }
        let mut store = Store::open(&db.path).expect("reopen sparse store");
        let before_data = records(store.connection());
        apply_file_schema(&mut store).expect("file schema after higher version");
        assert_eq!(
            store.schema_version().expect("monotonic file version"),
            version
        );
        assert!(present(store.connection(), "file_access"));
        assert!(present(store.connection(), "fts_text"));
        assert!(!present(store.connection(), "http"));
        assert!(!present(store.connection(), "findings"));
        assert_eq!(records(store.connection()), before_data);
        let before_schema = schema(store.connection());
        apply_file_schema(&mut store).expect("idempotent file schema");
        assert_eq!(
            store.schema_version().expect("repeated file version"),
            version
        );
        assert_eq!(schema(store.connection()), before_schema);
        drop(store);
        let store = Store::open(&db.path).expect("reopen after file helper");
        assert!(!store.is_read_only());
        assert_eq!(
            store.schema_version().expect("persisted file version"),
            version
        );
        assert_eq!(records(store.connection()), before_data);
    }
}

#[test]
fn helpers_preserve_higher_versions() {
    for version in [9, 10] {
        let db = TestDb::new();
        let mut store = Store::open(&db.path).expect("base");
        apply_file_schema(&mut store).expect("file schema");
        prepare(&mut store, version);
        for helper in [apply_agent_schema, apply_http_schema, apply_proxy_schema] {
            helper(&mut store).expect("add missing feature");
            assert_eq!(store.schema_version().expect("monotonic version"), version);
            helper(&mut store).expect("repeat helper");
            assert_eq!(store.schema_version().expect("idempotent version"), version);
        }
        apply_inter_agent_schema(&mut store).expect("inter-agent schema");
        assert_eq!(store.schema_version().expect("highest version"), 10);
    }
}

#[test]
fn future_v11_is_read_only_and_unchanged_even_with_extra_scripts() {
    let db = TestDb::new();
    {
        let store = Store::open(&db.path).expect("base");
        insert_data(store.connection());
        store
            .connection()
            .execute(
                "UPDATE schema_meta SET value = '11' WHERE key = 'schema_version'",
                [],
            )
            .expect("future version");
    }
    let before = fs::read(&db.path).expect("database bytes");
    for extra in [
        &[][..],
        &[(2, "CREATE TABLE must_not_run (id INTEGER)")][..],
        &[(12, "CREATE TABLE must_not_run (id INTEGER)")][..],
    ] {
        let mut store = Store::open_with_scripts(&db.path, extra).expect("future open");
        assert_eq!(
            store.status(),
            &OpenStatus::ReadOnlyNewer {
                found: 11,
                supported: 10
            }
        );
        assert!(store.is_read_only());
        assert_eq!(store.schema_version().expect("future version"), 11);
        assert!(store.connection().execute("DELETE FROM dns", []).is_err());
        assert!(matches!(
            apply_agent_schema(&mut store),
            Err(StoreError::ReadOnly)
        ));
        assert!(!present(store.connection(), "must_not_run"));
    }
    assert_eq!(
        fs::read(&db.path).expect("unchanged database bytes"),
        before
    );
    for entry in fs::read_dir(&db.dir).expect("test files") {
        let name = entry.expect("test file").file_name();
        // SQLite may create WAL coordination files even for a read-only open.
        assert!(matches!(
            name.to_str(),
            Some("store.db" | "store.db-wal" | "store.db-shm")
        ));
    }
}

#[test]
fn failed_pending_migrations_roll_back_schema_version_and_data() {
    let db = TestDb::new();
    let (before_schema, before_data) = {
        let mut store = Store::open(&db.path).expect("base");
        apply_agent_schema(&mut store).expect("agent schema");
        insert_data(store.connection());
        (schema(store.connection()), records(store.connection()))
    };
    let result = Store::open_with_scripts(&db.path, &[
        (10, "CREATE TABLE must_roll_back (id INTEGER); UPDATE dns SET qname = 'changed.example.test';"),
        (11, "SELECT * FROM missing_migration_table;"),
    ]);
    assert!(result.is_err());
    assert!(!db.dir.join("store.db.bak-v9").exists());
    let store = Store::open(&db.path).expect("reopen rolled-back store");
    assert!(!store.is_read_only());
    assert_eq!(store.schema_version().expect("rolled-back version"), 9);
    assert_eq!(schema(store.connection()), before_schema);
    assert_eq!(records(store.connection()), before_data);
}

#[test]
fn failed_helper_rolls_back_ddl_data_and_version() {
    let db = TestDb::new();
    let mut store = Store::open(&db.path).expect("base");
    apply_inter_agent_schema(&mut store).expect("higher version");
    insert_data(store.connection());
    // The last index in 0009 will conflict after the table and first index exist.
    store
        .connection()
        .execute("CREATE INDEX idx_agent_events_call ON dns(qname)", [])
        .expect("failure injection");
    let before_schema = schema(store.connection());
    let before_data = records(store.connection());
    assert!(apply_agent_schema(&mut store).is_err());
    assert_eq!(store.schema_version().expect("unchanged version"), 10);
    assert_eq!(schema(store.connection()), before_schema);
    assert_eq!(records(store.connection()), before_data);
}
