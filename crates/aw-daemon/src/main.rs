//! agentwatchd entry point.
//!
//! Commands:
//! - `agentwatchd --foreground [--config PATH]` runs until `agentwatchd.stop`
//!   appears in the data directory.
//! - `agentwatchd config schema` prints the hand-written JSON Schema.
//! - `agentwatchd --log-probe --config PATH` writes one sanitized tracing event
//!   and exits. It is a test hook so integration tests can read the log file.
//!
//! Collector assembly stays in `collectors.rs`. This file does not name a platform.

#![forbid(unsafe_code)]
#![deny(clippy::disallowed_methods)]

use std::path::PathBuf;
use std::process::ExitCode;

use config::{config_schema_pretty, load_selected, ConfigError};
use runtime::{emit_sensitive_probe, run_foreground, RuntimeError};

mod api;
// Markdown export (P3-DAEMON-01). Routes call it; it uses `api::share`.
mod export;
// Embedded UI. `main` does not serve it yet; `api` looks assets up. Naming the
// module here keeps `assets.rs` in the binary without a dead_code warning when
// nothing in `main` calls it.
mod assets;
// File-content hashing (P3-PIPE-06). Not called from `main`; named so the
// module is part of the binary and clippy sees it. The session path calls
// `file_hasher::hash_file` once a proxied read is correlated.
mod capabilities;
mod collector_state;
mod collectors;
mod config;
mod file_hasher;
mod paths;
mod privilege;
mod runtime;
mod sample;
mod service;
mod session;
mod supervisor;
mod watch;

fn main() -> ExitCode {
    // Keeps the collector crates linked. No platform collector is started here.
    let _ = collectors::wired();
    // Keeps the file hasher linked. The pointer is never called, so nothing is
    // opened or read at startup. The session correlator will call it for real.
    let _keep: fn(&std::path::Path, &file_hasher::HashFileLimits) -> _ = file_hasher::hash_file;
    // Keeps the UI embed linked. `false` when `ui/dist` was absent at build time.
    let _ = assets::dist_was_present();

    match dispatch(std::env::args().skip(1)) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("agentwatchd: {err}");
            exit_code_for(&err)
        }
    }
}

fn exit_code_for(err: &CliError) -> ExitCode {
    match err {
        CliError::Runtime(RuntimeError::AlreadyRunning { .. }) => ExitCode::from(2),
        _ => ExitCode::from(1),
    }
}

enum CliError {
    Usage(String),
    Config(ConfigError),
    Runtime(RuntimeError),
    Schema(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(msg) => write!(f, "{msg}"),
            Self::Config(err) => write!(f, "{err}"),
            Self::Runtime(err) => write!(f, "{err}"),
            Self::Schema(err) => write!(f, "schema: {err}"),
        }
    }
}

fn dispatch(args: impl IntoIterator<Item = String>) -> Result<ExitCode, CliError> {
    let args: Vec<String> = args.into_iter().collect();
    if args.is_empty() {
        return Err(CliError::Usage(usage().to_owned()));
    }
    if args[0] == "config" {
        return command_config(&args[1..]);
    }
    // Internal: the root daemon's account-switch helper (see `api::launch_as`).
    #[cfg(target_os = "linux")]
    if args[0] == api::LAUNCH_AS_HELPER_ARG {
        return Ok(api::launch_as_helper());
    }
    // Internal: macOS hold stage. Started with a fixed environment; the
    // account, program and environment arrive as data on a pipe. It blocks
    // until release, switches, then execs. A failure exits with the step's
    // code (121–127) and does not exec. See `aw_platform::gate_main`.
    #[cfg(target_os = "macos")]
    if args[0] == aw_platform::GATE_ARG {
        aw_platform::gate_main();
    }

    let mut foreground = false;
    let mut log_probe = false;
    let mut config_path: Option<PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--foreground" => foreground = true,
            "--log-probe" => log_probe = true,
            "--config" => {
                index += 1;
                let path = args
                    .get(index)
                    .ok_or_else(|| CliError::Usage("`--config` requires a path".to_owned()))?;
                config_path = Some(PathBuf::from(path));
            }
            "--help" | "-h" => {
                println!("{}", usage());
                return Ok(ExitCode::SUCCESS);
            }
            other => {
                return Err(CliError::Usage(format!(
                    "unknown argument `{other}`\n{}",
                    usage()
                )));
            }
        }
        index += 1;
    }

    if log_probe {
        return command_log_probe(config_path.as_deref());
    }
    if foreground {
        return command_foreground(config_path.as_deref());
    }
    Err(CliError::Usage(usage().to_owned()))
}

fn command_config(args: &[String]) -> Result<ExitCode, CliError> {
    match args {
        [cmd] if cmd == "schema" => {
            let json = config_schema_pretty().map_err(CliError::Schema)?;
            println!("{json}");
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(CliError::Usage(
            "usage: agentwatchd config schema".to_owned(),
        )),
    }
}

fn command_foreground(config_path: Option<&std::path::Path>) -> Result<ExitCode, CliError> {
    let (config, warnings, loaded_path) = load_selected(config_path).map_err(CliError::Config)?;
    run_foreground(&config, &warnings, loaded_path.as_deref()).map_err(CliError::Runtime)?;
    Ok(ExitCode::SUCCESS)
}

fn command_log_probe(config_path: Option<&std::path::Path>) -> Result<ExitCode, CliError> {
    let (config, warnings, _) = load_selected(config_path).map_err(CliError::Config)?;
    // Probe still takes the single-instance lock so it cannot race a live daemon
    // in the same data directory, then emits one event and shuts down.
    let data_dir = config::resolve_data_dir(&config).map_err(CliError::Config)?;
    paths::ensure_data_dir(&data_dir).map_err(|source| {
        CliError::Runtime(RuntimeError::DataDir {
            path: data_dir.clone(),
            source,
        })
    })?;
    let _lock = runtime::InstanceLock::acquire(&data_dir).map_err(CliError::Runtime)?;
    // install via a one-shot foreground is too heavy; open the subscriber by
    // running the same log setup the foreground path uses, then emit and exit.
    // `run_foreground` deletes a stale stop file and blocks. Write the stop
    // file only after logging is up — the probe does not enter that loop.
    runtime::init_logging(&data_dir).map_err(CliError::Runtime)?;
    for warning in &warnings {
        tracing::warn!("{}", warning.message());
    }
    emit_sensitive_probe();
    Ok(ExitCode::SUCCESS)
}

fn usage() -> &'static str {
    "usage:\n  agentwatchd --foreground [--config PATH]\n  agentwatchd config schema\n  agentwatchd --log-probe --config PATH"
}

#[cfg(test)]
mod tests {
    use super::dispatch;
    use std::process::ExitCode;

    #[test]
    fn schema_command_is_success() -> Result<(), String> {
        let code =
            dispatch(["config".to_owned(), "schema".to_owned()]).map_err(|err| err.to_string())?;
        if code == ExitCode::SUCCESS {
            Ok(())
        } else {
            Err("schema command did not succeed".to_owned())
        }
    }
}
