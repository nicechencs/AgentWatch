//! Linux launch contract: concurrent gated spawns must not leak one child's
//! gate pipe into a sibling. Each round starts `THREADS` held children at the
//! same time (barrier), releases them, and each target lists its own fds
//! (`readlink /proc/$$/fd/*`). Any fd beyond the baseline (what a plain spawn
//! from this test process inherits) is a leak; a `pipe:[...]` leak is a foreign
//! gate read end.
//!
//! CI default: 48 threads x 20 rounds. Stress: AW_GATE_STRESS_ROUNDS=300.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use aw_platform::{platform, IdentifiedCaller, ReapOutcome, SpawnRequest};

const SCRIPT: &str = "for f in /proc/$$/fd/*; do n=${f##*/}; printf '%s %s\\n' \"$n\" \"$(readlink \"$f\")\"; done > \"$1\"";

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn fds(path: &Path) -> Vec<(u32, String)> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (n, t) = l.split_once(' ')?;
            Some((n.parse().ok()?, t.to_owned()))
        })
        .collect()
}

#[test]
fn concurrent_gated_spawns_do_not_leak_gate_pipes_into_siblings() {
    let threads = env_usize("AW_GATE_STRESS_THREADS", 48);
    let rounds = env_usize("AW_GATE_STRESS_ROUNDS", 20);
    let dir = std::env::temp_dir().join(format!("aw-gate-stress-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // Baseline: what a plain spawn from this process inherits.
    let base_path = dir.join("baseline");
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(SCRIPT)
        .arg("aw")
        .arg(&base_path)
        .status()
        .unwrap();
    assert!(status.success());
    let baseline: BTreeSet<u32> = fds(&base_path).into_iter().map(|(n, _)| n).collect();

    let mut spawned = 0_usize;
    let mut leaking_children = 0_usize;
    let mut leaked_fds = 0_usize;
    let mut leaked_pipes = 0_usize;
    let mut rounds_with_leak = 0_usize;
    let mut other_failures = Vec::new();
    let mut samples = Vec::new();
    let started = std::time::Instant::now();
    for round in 0..rounds {
        let barrier = Arc::new(Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|i| {
                let barrier = Arc::clone(&barrier);
                let out: PathBuf = dir.join(format!("r{round}-t{i}"));
                thread::spawn(move || -> Result<PathBuf, String> {
                    let caller = IdentifiedCaller::current_user().map_err(|e| e.to_string())?;
                    let request = SpawnRequest {
                        command: vec![
                            "sh".into(),
                            "-c".into(),
                            SCRIPT.into(),
                            "aw".into(),
                            out.to_string_lossy().into_owned(),
                        ],
                        cwd: None,
                        env: std::env::vars().collect(),
                    };
                    barrier.wait();
                    let held = platform()
                        .spawn_suspended(&caller, &request)
                        .map_err(|e| format!("spawn: {e}"))?;
                    let released = held.release().map_err(|e| format!("release: {e}"))?;
                    match released.wait().map_err(|e| format!("wait: {e}"))? {
                        ReapOutcome::Exited(0) => Ok(out),
                        other => Err(format!("target ended {other:?}")),
                    }
                })
            })
            .collect();
        let mut leak_this_round = false;
        for handle in handles {
            spawned += 1;
            match handle.join().unwrap() {
                Ok(out) => {
                    let extra: Vec<_> = fds(&out)
                        .into_iter()
                        .filter(|(n, _)| !baseline.contains(n))
                        .collect();
                    if !extra.is_empty() {
                        leak_this_round = true;
                        leaking_children += 1;
                        leaked_fds += extra.len();
                        leaked_pipes += extra.iter().filter(|(_, t)| t.starts_with("pipe:")).count();
                        if samples.len() < 5 {
                            samples.push(format!("round {round}: {extra:?}"));
                        }
                    }
                    let _ = std::fs::remove_file(&out);
                }
                Err(err) => other_failures.push(format!("round {round}: {err}")),
            }
        }
        if leak_this_round {
            rounds_with_leak += 1;
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!(
        "GATE-STRESS threads={threads} rounds={rounds} spawned={spawned} \
         leaking_children={leaking_children} ({:.2}%) leaked_fds={leaked_fds} \
         leaked_pipe_fds={leaked_pipes} rounds_with_leak={rounds_with_leak}/{rounds} \
         other_failures={} elapsed_ms={} baseline={baseline:?}",
        100.0 * leaking_children as f64 / spawned.max(1) as f64,
        other_failures.len(),
        started.elapsed().as_millis()
    );
    for s in &samples {
        eprintln!("GATE-STRESS sample {s}");
    }
    for f in other_failures.iter().take(5) {
        eprintln!("GATE-STRESS other {f}");
    }
    assert!(other_failures.is_empty(), "spawn/release/wait failures: {other_failures:?}");
    assert_eq!(leaking_children, 0, "gate pipes leaked into sibling targets: {samples:?}");
}

/// One spawn while this process already holds more than ten descriptors: the
/// gate fd number is then >= 10, which `/bin/sh` = dash rejects
/// (`Syntax error: Bad fd number`, exit 2) when the gate script names it.
#[test]
fn gated_spawn_works_when_the_gate_fd_number_is_ten_or_more() {
    let _hold: Vec<std::fs::File> = (0..16)
        .map(|_| std::fs::File::open("/dev/null").unwrap())
        .collect();
    let caller = IdentifiedCaller::current_user().unwrap();
    let request = SpawnRequest {
        command: vec!["true".into()],
        cwd: None,
        env: std::env::vars().collect(),
    };
    let held = platform().spawn_suspended(&caller, &request).unwrap();
    let outcome = held.release().unwrap().wait().unwrap();
    assert_eq!(outcome, ReapOutcome::Exited(0));
}
