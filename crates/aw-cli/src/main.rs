//! `aw` entry point (P1-CLI-01).
//!
//! Parses the command tree, resolves the daemon endpoint, and dispatches.
//! Business commands are stubs: they probe the daemon and then report that
//! they are not implemented.

#![forbid(unsafe_code)]

mod client;
mod cmd;
mod endpoint;
mod exit;
mod launch;
mod output;

// P1-MAC-03. `launch/mod.rs` does not declare this file (P1-CLI-02 owns that
// module and will add `#[cfg(target_os = "macos")] mod unix_macos;`). The path
// attribute compiles the state machine into the test binary on every host,
// including Windows, without touching `launch/mod.rs`.
#[cfg(test)]
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
                let _ = writeln!(io::stderr(), "aw: write output: {err}");
                return ExitCode::from(1);
            }
            exit_code(code)
        }
        Err(err) => {
            let _ = writeln!(io::stderr(), "aw: {err}");
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
