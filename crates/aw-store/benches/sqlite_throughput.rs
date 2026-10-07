//! SPIKE-06: WAL + batched inserts on a minimal events table.
//!
//! Not the product DDL in storage.md. Two shapes only:
//!   inline: events.path TEXT
//!   dict:   events.path_id + path_dict(id, path)
//!
//! Synthetic rows. Paths are `/tmp/placeholder/N`. No argv, env, URL, or body.
//!
//! Caps (also printed):
//!   throughput: stop at 3s or 150_000 rows, whichever first
//!   size + query: 100_000 rows (1e6 figure is `bytes/row * 1_000_000`, labeled)
//!
//! `cargo bench -p aw-store`

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, DatabaseName, TransactionBehavior};

const CAP_SECS: f64 = 3.0;
const CAP_ROWS: u64 = 150_000;
const SIZE_ROWS: u64 = 100_000;
const QUERY_UID: i64 = 7;
const PATH_SLOTS: u64 = 64;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("bench_error={err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let dir = spike_dir()?;
    std::fs::create_dir_all(&dir).map_err(|err| format!("mkdir {dir:?}: {err}"))?;

    println!("machine_note=Windows 10, this dev machine only");
    println!("cap_secs={CAP_SECS}");
    println!("cap_rows={CAP_ROWS}");
    println!("size_rows={SIZE_ROWS}");
    println!("path_slots={PATH_SLOTS}");
    println!("pragma=journal_mode=WAL synchronous=NORMAL foreign_keys=ON temp_store=MEMORY mmap_size=268435456 auto_vacuum=INCREMENTAL");
    println!("begin=IMMEDIATE");

    for layout in [Layout::Inline, Layout::Dict] {
        for &batch in &[1_u64, 100, 1000] {
            let path = dir.join(format!("tp-{}-{batch}.db", layout.name()));
            let sample = measure_throughput(&path, layout, batch)?;
            println!(
                "throughput layout={} batch={batch} rows={} elapsed_ms={:.3} rows_per_s={:.1} commits={} p99_commit_us={}",
                layout.name(),
                sample.rows,
                sample.elapsed.as_secs_f64() * 1000.0,
                sample.rows_per_s,
                sample.commit_us.len(),
                p99(&sample.commit_us),
            );
        }

        let path = dir.join(format!("size-{}.db", layout.name()));
        let size = measure_size_and_query(&path, layout, SIZE_ROWS)?;
        let per_row = size.bytes as f64 / size.rows as f64;
        let extrapolated = per_row * 1_000_000.0;
        println!(
            "size layout={} rows={} file_bytes={} wal_bytes={} total_bytes={} bytes_per_row={per_row:.2} extrapolated_1e6_bytes={extrapolated:.0} extrapolation=yes_from_{SIZE_ROWS}_rows",
            layout.name(),
            size.rows,
            size.file_bytes,
            size.wal_bytes,
            size.bytes,
        );
        println!(
            "query layout={} rows={} proc_uid={QUERY_UID} hits={} elapsed_us={} plan={}",
            layout.name(),
            size.rows,
            size.hits,
            size.query_us,
            size.plan,
        );
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum Layout {
    Inline,
    Dict,
}

impl Layout {
    fn name(self) -> &'static str {
        match self {
            Layout::Inline => "inline",
            Layout::Dict => "dict",
        }
    }
}

struct Throughput {
    rows: u64,
    elapsed: Duration,
    rows_per_s: f64,
    commit_us: Vec<u64>,
}

struct SizeQuery {
    rows: u64,
    file_bytes: u64,
    wal_bytes: u64,
    bytes: u64,
    hits: i64,
    query_us: u128,
    plan: String,
}

fn measure_throughput(
    path: &std::path::Path,
    layout: Layout,
    batch: u64,
) -> Result<Throughput, String> {
    let mut conn = open_fresh(path)?;
    create_schema(&conn, layout)?;
    seed_dict(&mut conn, layout)?;

    let started = Instant::now();
    let mut rows = 0_u64;
    let mut commit_us = Vec::new();
    let mut seq = 0_u64;

    while rows < CAP_ROWS && started.elapsed().as_secs_f64() < CAP_SECS {
        let n = batch.min(CAP_ROWS - rows);
        let commit_at = Instant::now();
        insert_batch(&mut conn, layout, seq, n)?;
        commit_us.push(micros(commit_at.elapsed()));
        seq += n;
        rows += n;
    }

    let elapsed = started.elapsed();
    let rows_per_s = if elapsed.as_secs_f64() > 0.0 {
        rows as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    drop(conn);
    Ok(Throughput {
        rows,
        elapsed,
        rows_per_s,
        commit_us,
    })
}

fn measure_size_and_query(
    path: &std::path::Path,
    layout: Layout,
    rows: u64,
) -> Result<SizeQuery, String> {
    let mut conn = open_fresh(path)?;
    create_schema(&conn, layout)?;
    seed_dict(&mut conn, layout)?;

    let batch = 1000_u64;
    let mut done = 0_u64;
    while done < rows {
        let n = batch.min(rows - done);
        insert_batch(&mut conn, layout, done, n)?;
        done += n;
    }
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|err| format!("checkpoint: {err}"))?;

    let plan_sql = "SELECT id FROM events WHERE proc_uid = ?1";
    let plan = explain(&conn, plan_sql)?;

    let q0 = Instant::now();
    let hits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE proc_uid = ?1",
            params![QUERY_UID],
            |row| row.get(0),
        )
        .map_err(|err| format!("query: {err}"))?;
    let query_us = q0.elapsed().as_micros();

    // Close so the reported size is the file on disk, not an open handle's view.
    drop(conn);
    let file_bytes = file_len(path)?;
    let wal_bytes = file_len_optional(&wal_path(path))?;
    Ok(SizeQuery {
        rows: done,
        file_bytes,
        wal_bytes,
        bytes: file_bytes.saturating_add(wal_bytes),
        hits,
        query_us,
        plan,
    })
}

fn open_fresh(path: &std::path::Path) -> Result<Connection, String> {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(wal_path(path));
    let _ = std::fs::remove_file(shm_path(path));
    let conn = Connection::open(path).map_err(|err| format!("open {path:?}: {err}"))?;
    // auto_vacuum must be set before any table exists.
    conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")
        .map_err(|err| format!("auto_vacuum: {err}"))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|err| format!("journal_mode: {err}"))?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|err| format!("synchronous: {err}"))?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|err| format!("foreign_keys: {err}"))?;
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|err| format!("temp_store: {err}"))?;
    conn.pragma_update(None, "mmap_size", 268_435_456_i64)
        .map_err(|err| format!("mmap_size: {err}"))?;
    let journal: String = conn
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(|err| format!("read journal_mode: {err}"))?;
    if !journal.eq_ignore_ascii_case("wal") {
        return Err(format!("journal_mode stayed {journal}"));
    }
    let _ = DatabaseName::Main;
    Ok(conn)
}

fn create_schema(conn: &Connection, layout: Layout) -> Result<(), String> {
    let events = match layout {
        Layout::Inline => {
            "CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                ts_mono_ns INTEGER NOT NULL,
                proc_uid INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                kind INTEGER NOT NULL,
                path TEXT NOT NULL,
                bytes INTEGER NOT NULL,
                evidence TEXT NOT NULL
            );"
        }
        Layout::Dict => {
            "CREATE TABLE path_dict (
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL
            );
            CREATE TABLE events (
                id INTEGER PRIMARY KEY,
                ts_mono_ns INTEGER NOT NULL,
                proc_uid INTEGER NOT NULL,
                pid INTEGER NOT NULL,
                kind INTEGER NOT NULL,
                path_id INTEGER NOT NULL,
                bytes INTEGER NOT NULL,
                evidence TEXT NOT NULL
            );"
        }
    };
    conn.execute_batch(events)
        .map_err(|err| format!("schema: {err}"))?;
    conn.execute_batch("CREATE INDEX idx_events_proc_uid ON events(proc_uid);")
        .map_err(|err| format!("index: {err}"))?;
    Ok(())
}

fn seed_dict(conn: &mut Connection, layout: Layout) -> Result<(), String> {
    if !matches!(layout, Layout::Dict) {
        return Ok(());
    }
    let tx = conn
        .unchecked_transaction()
        .map_err(|err| format!("dict tx: {err}"))?;
    {
        let mut stmt = tx
            .prepare_cached("INSERT INTO path_dict (id, path) VALUES (?1, ?2)")
            .map_err(|err| format!("dict prepare: {err}"))?;
        for id in 0..PATH_SLOTS {
            let path = placeholder_path(id);
            stmt.execute(params![id as i64, path])
                .map_err(|err| format!("dict insert: {err}"))?;
        }
    }
    tx.commit().map_err(|err| format!("dict commit: {err}"))?;
    Ok(())
}

fn insert_batch(conn: &mut Connection, layout: Layout, seq: u64, n: u64) -> Result<(), String> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| format!("begin: {err}"))?;
    match layout {
        Layout::Inline => {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO events (id, ts_mono_ns, proc_uid, pid, kind, path, bytes, evidence)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )
                .map_err(|err| format!("prepare inline: {err}"))?;
            for i in 0..n {
                let row = seq + i;
                let path = placeholder_path(row % PATH_SLOTS);
                stmt.execute(params![
                    row as i64,
                    row as i64,
                    proc_uid(row),
                    pid(row),
                    (row % 4) as i64,
                    path,
                    (row % 4096) as i64,
                    "E1",
                ])
                .map_err(|err| format!("insert inline: {err}"))?;
            }
        }
        Layout::Dict => {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO events (id, ts_mono_ns, proc_uid, pid, kind, path_id, bytes, evidence)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )
                .map_err(|err| format!("prepare dict: {err}"))?;
            for i in 0..n {
                let row = seq + i;
                stmt.execute(params![
                    row as i64,
                    row as i64,
                    proc_uid(row),
                    pid(row),
                    (row % 4) as i64,
                    (row % PATH_SLOTS) as i64,
                    (row % 4096) as i64,
                    "E1",
                ])
                .map_err(|err| format!("insert dict: {err}"))?;
            }
        }
    }
    tx.commit().map_err(|err| format!("commit: {err}"))?;
    Ok(())
}

fn explain(conn: &Connection, sql: &str) -> Result<String, String> {
    let mut stmt = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .map_err(|err| format!("explain prepare: {err}"))?;
    let mut rows = stmt
        .query(params![QUERY_UID])
        .map_err(|err| format!("explain query: {err}"))?;
    let mut parts = Vec::new();
    while let Some(row) = rows.next().map_err(|err| format!("explain row: {err}"))? {
        let detail: String = row.get(3).map_err(|err| format!("explain col: {err}"))?;
        parts.push(detail);
    }
    Ok(parts.join(" | "))
}

fn proc_uid(row: u64) -> i64 {
    (row % 16) as i64
}

fn pid(row: u64) -> i64 {
    1000 + (row % 32) as i64
}

fn placeholder_path(slot: u64) -> String {
    format!("/tmp/placeholder/{slot}")
}

fn p99(samples: &[u64]) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let idx = ((sorted.len() as u128 * 99) / 100) as usize;
    let idx = idx.min(sorted.len() - 1);
    sorted[idx]
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

fn spike_dir() -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("clock: {err}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("aw-store-spike06-{nanos}")))
}

fn wal_path(db: &std::path::Path) -> PathBuf {
    let mut s = db.as_os_str().to_owned();
    s.push("-wal");
    PathBuf::from(s)
}

fn shm_path(db: &std::path::Path) -> PathBuf {
    let mut s = db.as_os_str().to_owned();
    s.push("-shm");
    PathBuf::from(s)
}

fn file_len(path: &std::path::Path) -> Result<u64, String> {
    let meta = std::fs::metadata(path).map_err(|err| format!("stat {path:?}: {err}"))?;
    Ok(meta.len())
}

fn file_len_optional(path: &std::path::Path) -> Result<u64, String> {
    match std::fs::metadata(path) {
        Ok(meta) => Ok(meta.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(format!("stat {path:?}: {err}")),
    }
}
