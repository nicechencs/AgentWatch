//! Behavior simulator. Reads a TOML scenario, performs the steps, and writes
//! a ground-truth JSONL log. This package must not depend on any `aw-*` crate.
//!
//! `sim serve` (P0-SIM-03) is a localhost byte sink/source. `sim run` does not
//! start it; HTTP steps still record `ok: false` when nothing is listening.
//!
#![forbid(unsafe_code)]

mod exec;
mod http_step;
mod paths;
mod scenario;
mod server;
mod truth;

use std::env;
use std::path::PathBuf;

fn main() {
    if let Err(err) = run() {
        eprintln!("sim: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let cmd = args.next().ok_or_else(usage)?;
    match cmd.as_str() {
        "run" => cmd_run(args.collect()),
        "spawn" => cmd_spawn(args.collect()),
        // `exec` steps re-enter here. The process exists so the OS sees argv
        // (including spaces and non-ASCII) and then exits. Nothing is printed.
        "argv-echo" => Ok(()),
        "-h" | "--help" | "help" => {
            println!("{}", usage());
            Ok(())
        }
        "serve" => server::serve(args.collect()),
        "eval" | "compare" | "scan-secrets" | "gen-db" => Err(format!(
            "`sim {cmd}` is not part of P0-SIM-02 (see later SIM tasks)"
        )),
        other => Err(format!("unknown command `{other}`\n{}\n", usage())),
    }
}

fn usage() -> String {
    "usage:\n  sim run <scenario.toml> --truth <file> [--root <dir>] [--duration <ms>]\n  sim spawn --payload <file> --truth <file> --ppid <pid>\n  sim serve --http 127.0.0.1:0 --https 127.0.0.1:0 --truth <file> --cert-out <dir>\n    (`sim serve --help` for the byte server)\n\n  --duration <ms> shortens steps that declare duration_ms (and long_conn).\n  SIM_DURATION_MS does the same when --duration is omitted.\n".to_string()
}

fn cmd_run(args: Vec<String>) -> Result<(), String> {
    let mut scenario_path: Option<PathBuf> = None;
    let mut truth: Option<PathBuf> = None;
    let mut sim_root: Option<PathBuf> = None;
    let mut duration_override_ms: Option<u64> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--truth" => {
                truth = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "--truth needs a path".to_string())?,
                ));
            }
            "--root" => {
                sim_root = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "--root needs a path".to_string())?,
                ));
            }
            "--duration" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "--duration needs milliseconds".to_string())?;
                duration_override_ms = Some(
                    raw.parse::<u64>()
                        .map_err(|_| format!("--duration is not an integer: {raw}"))?,
                );
            }
            "-h" | "--help" => {
                println!("{}", usage());
                return Ok(());
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown flag `{other}`"));
            }
            other => {
                if scenario_path.is_some() {
                    return Err("only one scenario path is accepted".to_string());
                }
                scenario_path = Some(PathBuf::from(other));
            }
        }
    }
    let scenario_path = scenario_path.ok_or_else(|| "missing <scenario.toml>".to_string())?;
    let truth = truth.ok_or_else(|| "missing --truth <file>".to_string())?;
    let text = std::fs::read_to_string(&scenario_path)
        .map_err(|err| format!("read {}: {err}", scenario_path.display()))?;
    let scenario =
        scenario::Scenario::parse(&text).map_err(|err| format!("parse scenario: {err}"))?;
    let duration_override_ms = duration_override_ms.or_else(duration_from_env);
    exec::run_scenario(
        &scenario,
        &exec::RunOpts {
            truth,
            sim_root,
            duration_override_ms,
        },
    )
}

fn duration_from_env() -> Option<u64> {
    env::var("SIM_DURATION_MS").ok()?.parse().ok()
}

fn cmd_spawn(args: Vec<String>) -> Result<(), String> {
    let mut payload: Option<PathBuf> = None;
    let mut truth: Option<PathBuf> = None;
    let mut ppid: Option<u32> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--payload" => {
                payload = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "--payload needs a path".to_string())?,
                ));
            }
            "--truth" => {
                truth = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "--truth needs a path".to_string())?,
                ));
            }
            "--ppid" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "--ppid needs a pid".to_string())?;
                ppid = Some(
                    raw.parse::<u32>()
                        .map_err(|_| format!("--ppid is not a u32: {raw}"))?,
                );
            }
            other => return Err(format!("unknown spawn arg `{other}`")),
        }
    }
    let payload = payload.ok_or_else(|| "spawn requires --payload".to_string())?;
    let truth = truth.ok_or_else(|| "spawn requires --truth".to_string())?;
    let ppid = ppid.ok_or_else(|| "spawn requires --ppid".to_string())?;
    exec::run_spawn_child(&payload, &truth, ppid)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::paths;
    use super::scenario::Scenario;

    #[test]
    fn rejects_absolute_and_parent_paths() {
        let root = std::env::temp_dir().join("sim-path-jail");
        assert!(paths::under_root(&root, "home/.ssh/id_rsa").is_ok());
        assert!(paths::under_root(&root, "../outside").is_err());
        assert!(paths::under_root(&root, "/etc/passwd").is_err());
        assert!(paths::under_root(&root, "~/.ssh/id_rsa").is_err());
    }

    #[test]
    fn bait_bytes_are_the_requested_length() {
        assert_eq!(paths::bait_bytes(0).len(), 0);
        assert_eq!(paths::bait_bytes(412).len(), 412);
        assert!(paths::bait_bytes(32).starts_with(b"SIMBAIT-"));
    }

    #[test]
    fn nested_spawn_toml_roundtrips() {
        let text = r#"
name = "mini"
[[step]]
action = "spawn"
id = "child"
steps = [
  { action = "read_file", path = "home/.ssh/id_rsa" },
]
"#;
        let scenario = Scenario::parse(text).unwrap();
        assert_eq!(scenario.step.len(), 1);
        assert_eq!(scenario.step[0].steps[0].action, "read_file");
    }
}
