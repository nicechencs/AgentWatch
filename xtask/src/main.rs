//! Repository tasks invoked as `cargo xtask <command>`.
//!
//! `ci` runs fmt, clippy, and the workspace tests.
//! `build-ebpf` does not compile anything yet. On every host it prints that the
//! bpf toolchain is not available and exits 0. A real build waits for SPIKE-01.

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
        Some("build-ebpf") => build_ebpf(),
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

fn build_ebpf() -> ExitCode {
    // aw-ebpf is not a workspace member. It needs Linux, nightly, rust-src, and
    // bpf-linker. SPIKE-01 has not started, so this command never invokes that
    // toolchain. Exit 0 on every host, including Linux, so CI does not go red
    // for a build this card cannot run.
    if cfg!(target_os = "linux") {
        println!(
            "跳过，需要 Linux：bpf 工具链（nightly + bpf-linker）尚未接入，SPIKE-01 未开始，本次不编译 aw-ebpf。"
        );
    } else {
        println!(
            "跳过，需要 Linux：当前不是 Linux，不编译 aw-ebpf（nightly + bpf-linker 仅在 Linux 上使用）。"
        );
    }
    ExitCode::SUCCESS
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
