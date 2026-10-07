//! Passthrough throughput. Not a pass/fail gate.
//!
//! Synthetic `process_start` events only. Paths are `/tmp/placeholder/N`.
//! No argv, environment values, URLs, headers, or bodies.
//!
//! Every event goes through all seven stages. None are dropped to raise the number.
//! `cargo bench` builds this in release unless `--profile dev` is passed. The printed
//! `events_per_s` is a measurement on this machine, not a claim that 500k/s was met.
//! [`std::time::Instant`] here only times the harness. [`aw_pipeline::Pipeline::replay`]
//! itself does not read it.

use std::process::ExitCode;
use std::time::Instant;

use aw_core::{
    EventKind, Evidence, ProcRef, ProcUid, ProcessStart, RawEvent, RawEventParts, Source, StartHow,
};
use aw_pipeline::{Pipeline, PipelineConfig};

const EVENTS: u64 = 100_000;

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
    let mut events = Vec::with_capacity(usize_from_u64(EVENTS));
    for seq in 0..EVENTS {
        events.push(synthetic_event(seq)?);
    }
    let started = Instant::now();
    let out = Pipeline::replay(events, PipelineConfig::default());
    let elapsed = started.elapsed();
    if out.events_seen != EVENTS {
        return Err(format!(
            "events_seen {} != {EVENTS}; stages dropped events",
            out.events_seen
        ));
    }
    if !out.processes.is_empty() || !out.net_flows.is_empty() || !out.gaps.is_empty() {
        return Err("passthrough produced business records".to_owned());
    }
    let secs = elapsed.as_secs_f64();
    let events_per_s = if secs > 0.0 {
        EVENTS as f64 / secs
    } else {
        0.0
    };
    println!("events={EVENTS}");
    println!("events_seen={}", out.events_seen);
    println!("elapsed_ms={:.3}", secs * 1000.0);
    println!("events_per_s={events_per_s:.1}");
    println!("stages=scope,dedup,enrich,redact,aggregate,correlate,batcher");
    Ok(())
}

fn synthetic_event(seq: u64) -> Result<RawEvent, String> {
    RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns: seq.saturating_mul(1_000),
        ts_wall_ns: 1_759_795_200_000_000_000,
        session_id: None,
        proc: Some(ProcRef {
            uid: ProcUid(seq),
            pid: 1000,
            tid: None,
        }),
        source: Source::new("placeholder/bench"),
        evidence: Evidence::E1,
        kind: EventKind::ProcessStart(ProcessStart::new(
            1,
            None,
            1_759_795_200_000_000_000,
            Some(format!("/tmp/placeholder/{seq}")),
            None,
            None,
            None,
            StartHow::Exec,
            None,
            None,
        )),
    })
    .map_err(|_| "could not build placeholder process_start".to_owned())
}

fn usize_from_u64(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}
