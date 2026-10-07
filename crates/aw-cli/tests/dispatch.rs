//! Process-level checks for the `aw` binary.
//!
//! These tests do not pass `--http` and strip `AW_TOKEN`, so the binary takes
//! the platform socket or pipe and returns unreachable without dialing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn aw() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aw"));
    cmd.env_remove("AW_TOKEN");
    cmd
}

fn output(args: &[&str]) -> std::process::Output {
    aw().args(args).output().expect("spawn aw")
}

#[test]
fn help_exits_0_and_lists_subcommands() {
    let out = output(&["--help"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let help = String::from_utf8(out.stdout).expect("utf8");
    for name in ["run", "ps", "sessions", "daemon", "version", "mcp-tap"] {
        assert!(
            help.lines()
                .any(|line| line.split_whitespace().next() == Some(name)),
            "missing `{name}`"
        );
    }
}

#[test]
fn version_exits_0() {
    let out = output(&["version"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("utf8");
    assert!(text.contains("0.1.0"), "{text}");
}

#[test]
fn version_check_exits_1_and_does_not_claim_a_network_call() {
    let out = output(&["version", "--check"]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8(out.stderr).expect("utf8");
    assert!(err.contains("does not contact the network"), "{err}");
}

#[test]
fn ps_without_a_daemon_exits_3() {
    let out = output(&["ps"]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8(out.stderr).expect("utf8");
    assert!(err.contains("aw daemon start"), "{err}");
    assert!(err.contains("--no-daemon"), "{err}");
}

#[test]
fn unknown_command_exits_2() {
    let out = output(&["not-a-command"]);
    assert_eq!(out.status.code(), Some(2));
}
