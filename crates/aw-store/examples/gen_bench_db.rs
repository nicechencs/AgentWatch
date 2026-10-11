//! Build a synthetic database for the timeline p95 check (P1-STORE-02).
//!
//! ```text
//! cargo run -p aw-store --example gen_bench_db --offline -- <path.db> [rows]
//! ```
//!
//! `rows` defaults to 1_000_000 `net_flows` in one session. One row in 50 has
//! domain `hit.example.com`; the rest have `other.net`. The process does not
//! time the query. The 1e6 p95 was not measured by the unit tests.
//!
//! The view from `0002_timeline_view.sql` is created here. The crate migrator
//! still installs only `0001_init.sql`.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use aw_store::{ensure_timeline, Store};
use rusqlite::{params, TransactionBehavior};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: gen_bench_db <path.db> [rows]");
        return ExitCode::from(2);
    };
    let rows: i64 = match args.next() {
        Some(raw) => match raw.parse() {
            Ok(n) if n > 0 => n,
            _ => {
                eprintln!("rows must be a positive integer");
                return ExitCode::from(2);
            }
        },
        None => 1_000_000,
    };
    if args.next().is_some() {
        eprintln!("usage: gen_bench_db <path.db> [rows]");
        return ExitCode::from(2);
    }

    let started = Instant::now();
    let mut store = match Store::open_runtime(PathBuf::from(&path)) {
        Ok(store) => store,
        Err(err) => {
            eprintln!("open: {err}");
            return ExitCode::from(1);
        }
    };
    let conn = store.connection_mut();
    if let Err(err) = ensure_timeline(conn) {
        eprintln!("timeline view: {err}");
        return ExitCode::from(1);
    }
    let tx = match conn.transaction_with_behavior(TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(err) => {
            eprintln!("begin: {err}");
            return ExitCode::from(1);
        }
    };
    if let Err(err) = seed(&tx, rows) {
        eprintln!("seed: {err}");
        return ExitCode::from(1);
    }
    if let Err(err) = tx.commit() {
        eprintln!("commit: {err}");
        return ExitCode::from(1);
    }
    println!("rows={rows} elapsed_ms={}", started.elapsed().as_millis());
    ExitCode::SUCCESS
}

fn seed(tx: &rusqlite::Transaction<'_>, rows: i64) -> Result<(), rusqlite::Error> {
    tx.execute(
        "INSERT INTO sessions (id, public_id, mode, user_id, started_ns, platform, collectors) \
         VALUES (1, 'bench', 'launch', 'bench-user', 0, 'linux', '[]')",
        [],
    )?;
    tx.execute(
        "INSERT INTO processes (session_id, proc_uid, pid, depth, start_ns, how, evidence, source) \
         VALUES (1, 1, 100, 0, 0, 'spawn', 'E1', 'bench')",
        [],
    )?;
    let mut stmt = tx.prepare(
        "INSERT INTO net_flows (
            id, session_id, proc_uid, proto, direction, local_ip, local_port,
            remote_ip, remote_port, domain, start_ns, evidence, source
         ) VALUES (?1, 1, 1, 'tcp', 'outbound', '127.0.0.1', 1, '9.9.9.9', 443, ?2, ?3, 'E1', 'bench')",
    )?;
    for i in 0..rows {
        let domain = if i % 50 == 0 {
            "hit.example.com"
        } else {
            "other.net"
        };
        stmt.execute(params![i + 1, domain, i])?;
    }
    Ok(())
}
