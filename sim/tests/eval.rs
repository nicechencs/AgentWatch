//! `sim eval` against hand-built truth and export JSONL.
//!
//! Fixtures live in `tests/fixtures/eval/`. They are not copies of `out/`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sim_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sim"))
}

fn fixture(name: &str) -> PathBuf {
    manifest_dir().join("tests/fixtures/eval").join(name)
}

fn thresholds() -> PathBuf {
    manifest_dir().join("thresholds/p1.toml")
}

fn eval(export: &str, platform: &str) -> std::process::Output {
    Command::new(sim_bin())
        .arg("eval")
        .arg("--truth")
        .arg(fixture("truth.jsonl"))
        .arg("--export")
        .arg(fixture(export))
        .arg("--thresholds")
        .arg(thresholds())
        .arg("--platform")
        .arg(platform)
        .output()
        .expect("run sim eval")
}

#[test]
fn eval_missing_one_process_recall_is_one_half() {
    // Two asserted processes (child + short). The export has only the child.
    // The short-lived one stays in the denominator because the export is E1.
    let output = eval("export_miss_one.jsonl", "linux");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(
        !output.status.success(),
        "50% proc recall must fail the 95% bar\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("| proc | 2 | 1 | 50.0% | 0 |"),
        "proc recall line missing:\n{stdout}"
    );
    assert!(stdout.contains("pid=21"), "missed short process listed:\n{stdout}");
    assert!(stdout.contains("RESULT: FAIL"), "{stdout}");
}

#[test]
fn eval_byte_error_of_six_percent_fails() {
    let output = eval("export_byte_6pct.jsonl", "linux");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(
        !output.status.success(),
        "6% must fail the 5% byte budget\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("| proc | 2 | 2 | 100.0% | 0 |"),
        "both processes match:\n{stdout}"
    );
    assert!(stdout.contains("6.0%"), "byte error should show 6.0%:\n{stdout}");
    assert!(stdout.contains("byte error"), "{stdout}");
    assert!(stdout.contains("RESULT: FAIL"), "{stdout}");
}

#[test]
fn eval_m1_budget_allows_six_percent() {
    let output = eval("export_byte_6pct.jsonl", "macos-m1");
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(
        output.status.success(),
        "6% is inside the 15% M1 budget\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("RESULT: PASS"), "{stdout}");
}

#[test]
fn eval_session_flag_is_refused() {
    let output = Command::new(sim_bin())
        .arg("eval")
        .arg("--session")
        .arg("@last")
        .output()
        .expect("run sim eval");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not implemented") || stderr.contains("daemon"),
        "{stderr}"
    );
}
