//! AgentWatch command-line entry point: parses commands, resolves the daemon endpoint, and dispatches.

// Unsafe code is denied. `cmd::run` has two documented exceptions: the Unix
// `pre_exec` that keeps the pipe gate out of the target, and the Windows FFI
// that resumes a CREATE_SUSPENDED child after daemon adoption.
#![deny(unsafe_code)]

mod client;
mod cmd;
mod daemon_errors;
mod endpoint;
mod exit;
mod launch;
mod output;

// P1-MAC-03. On macOS, `launch/mod.rs` already compiles `unix_macos.rs`, and
// this include is skipped so the file is not compiled twice. Everywhere else
// the test binary still needs the state machine (and `UnverifiedSpawnApi`).
// The `UnixLauncher` impl inside the file is `cfg(target_os = "macos")`, so
// this copy never implements a trait its parent does not define.
#[cfg(all(test, not(target_os = "macos")))]
#[path = "launch/unix_macos.rs"]
mod launch_unix_macos;

use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match cmd::execute_args(&args) {
        Ok(outcome) => {
            let code = outcome.code;
            if let Err(err) = write_outcome(&outcome) {
                let _ = writeln!(io::stderr(), "aw: 写出结果失败：{err}");
                return ExitCode::from(1);
            }
            exit_code(code)
        }
        Err(err) => {
            let _ = writeln!(io::stderr(), "aw: 执行失败：{err}");
            ExitCode::from(1)
        }
    }
}

fn write_outcome(outcome: &cmd::Outcome) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    outcome.write_to(&mut stdout, &mut stderr)?;
    stdout.flush()?;
    stderr.flush()?;
    Ok(())
}

fn exit_code(code: i32) -> ExitCode {
    u8::try_from(code).map_or(ExitCode::from(1), ExitCode::from)
}
