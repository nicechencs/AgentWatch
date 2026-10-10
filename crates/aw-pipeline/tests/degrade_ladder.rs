//! P2-PIPE-04: degrade ladder on a virtual clock. No host metrics are read.

#![allow(clippy::expect_used)]

use aw_core::{Evidence, GapKind, ProcUid, Source};
use aw_pipeline::{DegradeConfig, DegradeLadder, DegradeSample, FileAccessRec, Output};

fn sample(now_ns: u64, queue: Option<(u64, u64)>, low_disk: bool) -> DegradeSample {
    DegradeSample {
        now_ns,
        queue_fill_num: queue.map(|pair| pair.0),
        queue_fill_den: queue.map(|pair| pair.1),
        low_disk,
        ..DegradeSample::default()
    }
}

fn ladder() -> DegradeLadder {
    DegradeLadder::new(DegradeConfig {
        hard_rss_bytes: Some(100),
        cpu_budget_millicores: 150,
        max_session_bytes: Some(1_000),
        l3_keep_per_proc: 1,
        recover_secs: 30,
    })
}

fn row(op: &str, sensitive: bool) -> FileAccessRec {
    FileAccessRec {
        session_id: None,
        proc_uid: Some(ProcUid(1)),
        op: op.to_owned(),
        path: "/fixture/work.txt".to_owned(),
        path_to: None,
        access: Some("read".to_owned()),
        first_ns: 0,
        last_ns: 0,
        opens: 1,
        reads: None,
        bytes_read: None,
        writes: None,
        bytes_written: None,
        created: None,
        truncated: None,
        modified: None,
        result: None,
        partial: false,
        sensitive_rule: sensitive.then(|| "ssh-keys".to_owned()),
        tags: Vec::new(),
        folded_dir: None,
        sample_paths: Vec::new(),
        evidence: Evidence::E1,
        field_evidence: Default::default(),
        source: Source::new("synthetic/file"),
    }
}

#[test]
fn pressure_steps_up_and_a_quiet_interval_steps_back_down() {
    let mut ladder = ladder();
    let mut out = Output::default();
    assert!(ladder.observe(sample(0, Some((90, 100)), false), &mut out));
    assert!(ladder.observe(sample(1, Some((90, 100)), false), &mut out));
    assert_eq!(ladder.level(), 2);
    let armed = sample(1_000_000_000, Some((1, 100)), false);
    assert!(
        !ladder.observe(armed, &mut out),
        "the first quiet sample only starts the recovery timer"
    );
    assert_eq!(ladder.level(), 2);
    let reading = sample(31_000_000_001, Some((1, 100)), false);
    let changed = ladder.observe(reading, &mut out);
    assert_eq!(
        (
            changed,
            ladder.level(),
            reading.queue_fill_num,
            reading.queue_fill_den
        ),
        (true, 1, Some(1), Some(100))
    );
    let details: Vec<_> = out
        .gaps
        .iter()
        .filter(|gap| gap.gap_kind == GapKind::RateLimited)
        .map(|gap| gap.detail.clone())
        .collect();
    assert_eq!(
        details,
        [
            Some("degrade L1".to_owned()),
            Some("degrade L2".to_owned()),
            Some("degrade L1".to_owned())
        ]
    );
}

#[test]
fn a_missing_reading_does_not_raise_the_level() {
    let mut ladder = ladder();
    let mut out = Output::default();
    assert!(!ladder.observe(sample(0, None, false), &mut out));
    assert_eq!(ladder.level(), 0);
    assert!(out.gaps.is_empty());
}

#[test]
fn hard_rss_is_an_emergency_stop_and_not_another_level() {
    let mut ladder = ladder();
    let mut out = Output::default();
    let mut reading = sample(0, None, false);
    reading.rss_bytes = Some(101);
    assert!(!ladder.observe(reading, &mut out));
    assert!(ladder.emergency());
    assert_eq!(ladder.level(), 0);
    assert_eq!(out.gaps.len(), 1);
    assert_eq!(out.gaps[0].gap_kind, GapKind::Restart);
    reading.rss_bytes = Some(100);
    ladder.observe(reading, &mut out);
    assert!(!ladder.emergency());
}

#[test]
fn protected_rows_survive_a_level_that_drops_ordinary_reads() {
    let mut ladder = ladder();
    let mut out = Output::default();
    ladder.observe(sample(0, Some((90, 100)), false), &mut out);
    ladder.observe(sample(1, Some((90, 100)), false), &mut out);
    assert_eq!(ladder.level(), 2);
    let mut rows = vec![
        row("access", false),
        row("delete", false),
        row("access", true),
    ];
    ladder.retain_new_files(&mut rows, 0);
    let ops: Vec<_> = rows
        .iter()
        .map(|row| (row.op.as_str(), row.sensitive_rule.clone()))
        .collect();
    assert_eq!(
        ops,
        [("delete", None), ("access", Some("ssh-keys".to_owned()))]
    );
    assert_eq!(ladder.suppressed(), 1);
}
