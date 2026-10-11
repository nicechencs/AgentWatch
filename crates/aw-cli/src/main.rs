//! AgentWatch command-line entry point: parses commands, resolves the daemon endpoint, and dispatches.

// Unsafe code is denied. Suspended launch and Win32 FFI live in `aw-platform`,
// so this binary has no `pre_exec` gate and no CREATE_SUSPENDED resume of its own.
#![deny(unsafe_code)]

mod client;
mod cmd;
mod daemon_errors;
mod endpoint;
mod exit;
mod launch;
mod output;

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
