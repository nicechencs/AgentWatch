//! P3-PIPE-04: rule files are refused at load time, with a line number.
//! The TOML below is synthetic. Nothing is matched and nothing is stored.

#![allow(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use aw_pipeline::rules::{load_builtin, load_with_user, EvidenceLevel, RuleError};

fn two_step(evidence: &str, within: &str, wording: &str) -> String {
    format!(
        r#"
[rule]
id = "fixture_rule"
version = 1
title = "fixture"
evidence = "{evidence}"
wording = "{wording}"
severity = "notice"

[[rule.match]]
as = "a"
record = "file_access"
where = 'op = "access"'

[[rule.match]]
as = "b"
record = "net_flow"
where = 'bytes_up > 0'
within = "{within}"
same = "session"

[rule.emit]
key = ["a.path"]
params = ["proc_a", "t_a", "path", "ev_a", "delta", "proc_b", "dest", "bytes_up", "ev_b"]
"#
    )
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        // Parallel tests can read the same clock value (macOS timer resolution),
        // so add the pid and a per-process counter.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("aw-rule-load-{}-{nanos}-{seq}", std::process::id()));
        fs::create_dir(&path).expect("temp dir");
        Self { path }
    }

    fn write(&self, body: &str) {
        fs::write(self.path.join("fixture.toml"), body).expect("write rule");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn refused(body: &str) -> RuleError {
    let dir = TempDir::new();
    dir.write(body);
    let err = load_with_user(Some(&dir.path)).expect_err("rule must be refused");
    assert!(err.line().is_some(), "a refused rule names a line: {err}");
    err
}

#[test]
fn builtin_rules_load_and_the_two_step_rule_stays_inference() {
    let set = load_builtin().expect("built-in rules");
    assert!(set.rules().len() >= 8, "the built-in set is short");
    let rule = set
        .get("sensitive_read_then_send")
        .expect("sensitive_read_then_send");
    assert_eq!(rule.evidence, EvidenceLevel::I);
    assert!(rule.steps.len() >= 2);
}

#[test]
fn a_multi_step_rule_cannot_claim_e1() {
    let err = refused(&two_step("E1", "10s", "infer.temporal"));
    let RuleError::Invalid {
        rule_id, detail, ..
    } = err
    else {
        panic!("expected Invalid");
    };
    assert_eq!(rule_id, "fixture_rule");
    assert!(detail.contains("fact_conjunction"), "{detail}");
}

#[test]
fn a_window_over_ten_minutes_is_refused() {
    let err = refused(&two_step("I", "11m", "infer.temporal"));
    let RuleError::Invalid { detail, .. } = err else {
        panic!("expected Invalid");
    };
    assert!(
        detail.contains("within") || detail.contains("10"),
        "{detail}"
    );
}

#[test]
fn an_unknown_template_is_refused() {
    let err = refused(&two_step("I", "10s", "no.such.template"));
    let RuleError::Invalid { detail, .. } = err else {
        panic!("expected Invalid");
    };
    assert!(detail.contains("wording"), "{detail}");
}

#[test]
fn a_broken_where_names_the_step() {
    let source = r#"
[rule]
id = "fixture_rule"
version = 1
title = "fixture"
evidence = "E1"
wording = "fact.file_read"
severity = "info"

[[rule.match]]
as = "a"
record = "file_access"
where = "domian:example"

[rule.emit]
key = ["a.path"]
params = ["proc", "path", "bytes"]
"#;
    let err = refused(source);
    let RuleError::Where { step, detail, .. } = err else {
        panic!("expected Where, got {err}");
    };
    assert_eq!(step, "a");
    assert!(detail.contains("domian"), "{detail}");
}

#[test]
fn the_same_file_loads_to_the_same_evidence() {
    let source = two_step("I", "10s", "infer.temporal");
    let left_dir = TempDir::new();
    let right_dir = TempDir::new();
    left_dir.write(&source);
    right_dir.write(&source);
    let left = load_with_user(Some(&left_dir.path)).expect("load");
    let right = load_with_user(Some(&right_dir.path)).expect("load");
    let left_rule = left.get("fixture_rule").expect("left");
    let right_rule = right.get("fixture_rule").expect("right");
    assert_eq!(left_rule.evidence, right_rule.evidence);
    assert_eq!(left_rule.steps.len(), right_rule.steps.len());
}
