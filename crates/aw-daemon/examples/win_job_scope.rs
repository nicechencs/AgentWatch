//! Launcher for the Windows Job Object scope PoC (P0-DAEMON-01 / SPIKE-05).
//!
//! The workspace forbids `unsafe_code` in every member, including examples, and
//! that forbid cannot be overridden from `aw-daemon`. The Win32 calls therefore
//! live in `examples/win_job_poc`, which is not a workspace member. This example
//! only builds and runs that binary, then forwards its exit code.
//!
//! No elevation. If the child prints `GetLastError`, this process exits 1.

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(windows)]
    {
        match run() {
            Ok(code) => code,
            Err(err) => {
                eprintln!("win_job_scope: {err}");
                ExitCode::from(1)
            }
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("win_job_scope: this example only runs on Windows");
        ExitCode::SUCCESS
    }
}

#[cfg(windows)]
fn run() -> Result<ExitCode, String> {
    use std::env;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let helper = manifest_dir.join("examples").join("win_job_poc");
    let manifest = helper.join("Cargo.toml");
    let target_dir = helper.join("target");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

    let status = Command::new(cargo)
        .arg("run")
        .arg("--quiet")
        .arg("--offline")
        .arg("--manifest-path")
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&target_dir)
        .stdin(Stdio::null())
        .status()
        .map_err(|err| format!("spawn cargo for win_job_poc: {err}"))?;

    let code = u8::try_from(status.code().unwrap_or(1)).unwrap_or(1);
    Ok(ExitCode::from(code))
}
