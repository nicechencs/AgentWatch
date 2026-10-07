//! Repository tasks invoked as `cargo xtask <command>`.
//!
//! `ci` runs fmt, clippy, and the workspace tests.
//! `build-ebpf` is a no-op until the eBPF crate exists.

#![forbid(unsafe_code)]

use std::env;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("ci") => {
            if args.next().is_some() {
                eprintln!("cargo xtask ci takes no arguments");
                return ExitCode::from(2);
            }
            ci()
        }
        Some("build-ebpf") => {
            // aw-ebpf is not a workspace member and needs nightly plus bpf-linker.
            // P0-LNX-01 owns the real build. Exiting 0 keeps CI placeholders green.
            println!("not implemented");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown xtask command: {other}");
            usage();
            ExitCode::from(2)
        }
        None => {
            usage();
            ExitCode::from(2)
        }
    }
}

fn usage() {
    eprintln!("usage: cargo xtask <ci|build-ebpf>");
}

fn ci() -> ExitCode {
    let steps: &[(&str, &[&str])] = &[
        ("fmt", &["fmt", "--all", "--check"]),
        (
            "clippy",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("test", &["test", "--workspace"]),
    ];

    for (name, args) in steps {
        let status = match cargo(args) {
            Ok(status) => status,
            Err(err) => {
                eprintln!("failed to spawn cargo {name}: {err}");
                return ExitCode::from(1);
            }
        };
        if !status.success() {
            let code = status.code().unwrap_or(1);
            let code = u8::try_from(code).unwrap_or(1);
            eprintln!("cargo {name} failed (exit {code})");
            return ExitCode::from(code);
        }
    }

    ExitCode::SUCCESS
}

fn cargo(args: &[&str]) -> std::io::Result<std::process::ExitStatus> {
    // Honor CARGO when cargo itself spawned us, so toolchains stay consistent.
    let program = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    Command::new(program).args(args).status()
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
