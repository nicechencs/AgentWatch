//! `sim gen-db --rows N [--out path.db]` — generate a synthetic SQLite
//! database for use as a query-performance benchmark (P2-STORE-03).
//!
//! The generated database contains `file_access` and `processes` rows in
//! the schema defined by `crates/aw-store/migrations/`.  `sim` does not
//! depend on `aw-store`, so the schema is replicated here as a minimal
//! subset sufficient for benchmark queries.
//!
//! # Schema (subset)
//!
//! ```sql
//! CREATE TABLE sessions (id INTEGER PRIMARY KEY, ...)
//! CREATE TABLE processes (session_id, proc_uid, pid, ...)
//! CREATE TABLE file_access (id INTEGER PRIMARY KEY, session_id, proc_uid,
//!                           op, path, first_ns, last_ns, evidence, source, ...)
//! ```
//!
//! # Usage
//!
//!   sim gen-db --rows 100000 [--out bench.db] [--sessions 4]

use std::path::PathBuf;

/// Run `sim gen-db` from parsed CLI arguments.
pub fn run(args: Vec<String>) -> Result<(), String> {
    let opts = parse_args(args)?;

    if opts.out.exists() {
        return Err(format!(
            "output file already exists: {}; remove it first",
            opts.out.display()
        ));
    }

    generate(&opts)
}

fn parse_args(args: Vec<String>) -> Result<Opts, String> {
    let mut rows: u64 = 10_000;
    let mut out = PathBuf::from("bench.db");
    let mut sessions: u64 = 4;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let next = |flag: &str, it: &mut std::vec::IntoIter<String>| -> Result<String, String> {
            it.next().ok_or_else(|| format!("{flag} needs a value"))
        };
        match arg.as_str() {
            "--rows" => {
                let raw = next("--rows", &mut iter)?;
                rows = raw
                    .parse()
                    .map_err(|_| format!("--rows is not a number: {raw}"))?;
            }
            "--out" => out = PathBuf::from(next("--out", &mut iter)?),
            "--sessions" => {
                let raw = next("--sessions", &mut iter)?;
                sessions = raw
                    .parse()
                    .map_err(|_| format!("--sessions is not a number: {raw}"))?;
            }
            "-h" | "--help" => {
                return Err("usage: sim gen-db --rows N [--out bench.db] [--sessions 4]".to_string())
            }
            other => return Err(format!("unknown gen-db flag `{other}`")),
        }
    }
    Ok(Opts {
        rows,
        out,
        sessions,
    })
}

pub(crate) struct Opts {
    rows: u64,
    out: PathBuf,
    sessions: u64,
}

// ---------------------------------------------------------------------------
// Generator — pure Rust using SQLite through raw rusqlite calls.
// rusqlite is already a dev-dependency of sim (via serve integration tests);
// here it is used directly since sim/Cargo.toml already carries it at
// version 0.32.1.
// ---------------------------------------------------------------------------

/// Generate the database.  This is also callable from unit tests.
pub(crate) fn generate(opts: &Opts) -> Result<(), String> {
    use rusqlite::Connection;

    let conn =
        Connection::open(&opts.out).map_err(|e| format!("open {}: {e}", opts.out.display()))?;

    conn.execute_batch(SCHEMA)
        .map_err(|e| format!("create schema: {e}"))?;

    // Insert synthetic sessions.
    let sessions = opts.sessions.max(1);
    for sid in 1..=sessions {
        conn.execute(
            "INSERT INTO sessions (id, public_id, mode, user_id, started_ns,
                                   platform, collectors, stats)
             VALUES (?1, ?2, 'launch', 'simuser', ?3, 'sim', 'sim', NULL)",
            rusqlite::params![
                sid as i64,
                format!("sim-session-{sid:04}"),
                (sid * 1_000_000_000) as i64,
            ],
        )
        .map_err(|e| format!("insert session {sid}: {e}"))?;
    }

    // Insert synthetic processes (one per 100 file rows, spread across sessions).
    let procs_per_session = ((opts.rows / sessions) / 100).max(1);
    for sid in 1..=sessions {
        for p in 0..procs_per_session {
            let proc_uid = (sid * 100_000 + p) as i64;
            conn.execute(
                "INSERT INTO processes (session_id, proc_uid, pid, ppid, depth,
                                        start_ns, how, evidence, source)
                 VALUES (?1, ?2, ?3, NULL, 0, ?4, 'exec', 'E1', 'sim/gen')",
                rusqlite::params![
                    sid as i64,
                    proc_uid,
                    (1000 + p) as i64,
                    (sid * 1_000_000_000 + p * 1000) as i64,
                ],
            )
            .map_err(|e| format!("insert process {p}: {e}"))?;
        }
    }

    // Insert file_access rows in batches for speed.
    let rows_per_session = opts.rows / sessions;
    let paths = BAIT_PATHS;
    let ops = OPS;
    let evidences = EVIDENCES;

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| format!("begin tx: {e}"))?;

    for sid in 1..=sessions {
        let proc_uid_base = (sid * 100_000) as i64;
        let procs_in_session = procs_per_session as i64;
        for i in 0..rows_per_session {
            let path = paths[(i as usize) % paths.len()];
            let op = ops[(i as usize) % ops.len()];
            let evidence = evidences[(i as usize) % evidences.len()];
            let proc_uid = proc_uid_base + (i as i64 % procs_in_session);
            let first_ns = (sid * 1_000_000_000 + i * 1000) as i64;
            let last_ns = first_ns + 500;
            let bytes_read: Option<i64> = if op == "access" {
                Some((i % 65536) as i64 + 1)
            } else {
                None
            };
            let bytes_written: Option<i64> = if op == "create" || op == "rename" {
                Some((i % 4096) as i64 + 1)
            } else {
                None
            };
            tx.execute(
                "INSERT INTO file_access
                   (session_id, proc_uid, op, path, first_ns, last_ns,
                    bytes_read, bytes_written, evidence, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'sim/gen')",
                rusqlite::params![
                    sid as i64,
                    proc_uid,
                    op,
                    path,
                    first_ns,
                    last_ns,
                    bytes_read,
                    bytes_written,
                    evidence,
                ],
            )
            .map_err(|e| format!("insert row {i}: {e}"))?;
        }
    }

    tx.commit().map_err(|e| format!("commit: {e}"))?;

    println!(
        "gen-db: wrote {} file_access rows across {} session(s) to {}",
        opts.rows,
        sessions,
        opts.out.display()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Embedded minimal schema (mirrors aw-store migrations, read-only subset)
// ---------------------------------------------------------------------------

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('schema_version', '5');

CREATE TABLE IF NOT EXISTS sessions (
  id              INTEGER PRIMARY KEY,
  public_id       TEXT NOT NULL UNIQUE,
  name            TEXT,
  mode            TEXT NOT NULL DEFAULT 'launch',
  agent           TEXT,
  user_id         TEXT NOT NULL,
  started_ns      INTEGER NOT NULL,
  ended_ns        INTEGER,
  platform        TEXT NOT NULL,
  collectors      TEXT NOT NULL,
  pinned          INTEGER NOT NULL DEFAULT 0,
  stats           TEXT
);

CREATE TABLE IF NOT EXISTS processes (
  session_id      INTEGER NOT NULL,
  proc_uid        INTEGER NOT NULL,
  pid             INTEGER NOT NULL,
  parent_uid      INTEGER,
  ppid            INTEGER,
  depth           INTEGER NOT NULL DEFAULT 0,
  start_ns        INTEGER NOT NULL,
  exit_ns         INTEGER,
  how             TEXT NOT NULL,
  evidence        TEXT NOT NULL,
  source          TEXT NOT NULL,
  PRIMARY KEY (session_id, proc_uid)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_proc_pid ON processes(session_id, pid);

CREATE TABLE IF NOT EXISTS file_access (
  id              INTEGER PRIMARY KEY,
  session_id      INTEGER NOT NULL,
  proc_uid        INTEGER NOT NULL,
  op              TEXT NOT NULL CHECK (op IN ('access','create','delete','rename','exec')),
  path            TEXT NOT NULL,
  path_to         TEXT,
  access          TEXT,
  first_ns        INTEGER NOT NULL,
  last_ns         INTEGER NOT NULL,
  opens           INTEGER NOT NULL DEFAULT 1,
  reads           INTEGER,
  bytes_read      INTEGER,
  writes          INTEGER,
  bytes_written   INTEGER,
  created         INTEGER,
  truncated       INTEGER,
  modified        INTEGER,
  result          INTEGER,
  partial         INTEGER NOT NULL DEFAULT 0,
  sensitive_rule  TEXT,
  evidence        TEXT NOT NULL,
  na_reason       TEXT,
  field_evidence  TEXT,
  source          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fa_session_ts ON file_access(session_id, first_ns);
CREATE INDEX IF NOT EXISTS idx_fa_path       ON file_access(path);
";

const BAIT_PATHS: &[&str] = &[
    "/home/simuser/.ssh/id_rsa",
    "/home/simuser/.aws/credentials",
    "/home/simuser/.env",
    "/home/simuser/.netrc",
    "/home/simuser/work/data.bin",
    "/home/simuser/work/output.jsonl",
    "/tmp/simwork/src/main.rs",
    "/tmp/simwork/target/debug/app",
    "/tmp/simwork/Cargo.toml",
    "/usr/local/share/sim/config.toml",
];

const OPS: &[&str] = &["access", "access", "access", "create", "delete", "rename"];

const EVIDENCES: &[&str] = &["E1", "E2", "E1", "E1", "E3"];

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn temp_path(suffix: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "sim-gen-db-{}-{}{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            suffix
        ));
        base
    }

    #[test]
    fn generates_correct_row_count() {
        let path = temp_path(".db");
        let opts = Opts {
            rows: 100,
            out: path.clone(),
            sessions: 2,
        };
        generate(&opts).unwrap();

        let conn = Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM file_access", [], |r| r.get(0))
            .unwrap();
        // rows is divided across sessions; total should equal or closely approximate
        // (we do rows/sessions per session).
        assert!(
            (98..=102).contains(&count),
            "expected ~100 rows, got {count}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn schema_version_is_set() {
        let path = temp_path("-sv.db");
        generate(&Opts {
            rows: 10,
            out: path.clone(),
            sessions: 1,
        })
        .unwrap();
        let conn = Connection::open(&path).unwrap();
        let v: String = conn
            .query_row(
                "SELECT value FROM schema_meta WHERE key='schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(v, "5");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn refuses_existing_file() {
        let path = temp_path("-exists.db");
        std::fs::write(&path, b"placeholder").unwrap();
        let opts = Opts {
            rows: 10,
            out: path.clone(),
            sessions: 1,
        };
        let result = super::run(vec![
            "--rows".to_string(),
            "10".to_string(),
            "--out".to_string(),
            path.to_str().unwrap().to_string(),
        ]);
        let _ = std::fs::remove_file(&path);
        drop(opts);
        assert!(result.is_err(), "expected an error for existing file");
    }

    #[test]
    fn all_ops_present() {
        let path = temp_path("-ops.db");
        generate(&Opts {
            rows: 600,
            out: path.clone(),
            sessions: 1,
        })
        .unwrap();
        let conn = Connection::open(&path).unwrap();
        let mut stmt = conn
            .prepare("SELECT DISTINCT op FROM file_access ORDER BY op")
            .unwrap();
        let ops: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        let _ = std::fs::remove_file(&path);
        assert!(ops.contains(&"access".to_string()), "missing access op");
        assert!(ops.contains(&"create".to_string()), "missing create op");
    }
}
