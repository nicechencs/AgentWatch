//! One batch of 1000 rows against the P1 product DDL.
//!
//! Not SPIKE-06. That bench writes a minimal `events` table and is unchanged.
//! This one migrates `0001_init.sql`, inserts one session, then times a single
//! `BEGIN IMMEDIATE` batch of 1000 `processes` rows. No criterion.
//!
//! `cargo bench -p aw-store --bench product_ddl -- --nocapture`

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aw_store::{ProcessRow, RecordSink, SessionRow, SqliteSink, Store, WriteBatch};

const ROWS: usize = 1000;

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
    let path = bench_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| format!("mkdir: {err}"))?;
    }
    let _ = std::fs::remove_file(&path);

    let mut store = Store::open(&path).map_err(|err| format!("open: {err}"))?;
    let batch = sample_batch();
    let mut sink = SqliteSink::new(&mut store).map_err(|err| format!("sink: {err}"))?;

    let started = Instant::now();
    sink.write_batch(&batch)
        .map_err(|err| format!("write_batch: {err}"))?;
    let elapsed = started.elapsed();
    let rows_per_s = if elapsed.as_secs_f64() > 0.0 {
        ROWS as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };

    println!("bench=product_ddl");
    println!("ddl=0001_init.sql tables=sessions+processes");
    println!("rows={ROWS}");
    println!("batches=1");
    println!("begin=IMMEDIATE");
    println!("elapsed_ms={:.3}", elapsed.as_secs_f64() * 1000.0);
    println!("rows_per_s={rows_per_s:.1}");
    println!("note=single batch, not SPIKE-06 minimal events table");
    Ok(())
}

fn sample_batch() -> WriteBatch {
    let mut batch = WriteBatch {
        sessions: vec![SessionRow {
            id: 1,
            public_id: "bench".to_string(),
            name: None,
            mode: "launch".to_string(),
            agent: None,
            root_proc_uid: None,
            argv: None,
            cwd: None,
            user_id: "0".to_string(),
            started_ns: 1,
            ended_ns: None,
            end_reason: None,
            exit_code: None,
            proxy_enabled: 0,
            proxy_port: None,
            platform: "windows".to_string(),
            os_version: None,
            collectors: "[]".to_string(),
            collector_profile: None,
            config_digest: None,
            pinned: 0,
            stats: None,
        }],
        processes: Vec::with_capacity(ROWS),
        process_images: Vec::new(),
        net_flows: Vec::new(),
        net_flow_buckets: Vec::new(),
        dns: Vec::new(),
        gaps: Vec::new(),
    };
    for i in 0..ROWS {
        batch.processes.push(ProcessRow {
            session_id: 1,
            proc_uid: i as i64,
            pid: 1000 + i as i64,
            parent_uid: None,
            ppid: None,
            depth: 0,
            start_ns: 1 + i as i64,
            exit_ns: None,
            exit_code: None,
            exit_signal: None,
            how: "spawn".to_string(),
            user_id: None,
            signer: None,
            evidence: "E1".to_string(),
            field_evidence: None,
            source: "bench".to_string(),
            agent: None,
        });
    }
    batch
}

fn bench_path() -> Result<PathBuf, String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("clock: {err}"))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("aw-store-product-ddl-{nanos}.db")))
}
