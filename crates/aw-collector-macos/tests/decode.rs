//! Fixture decode for eslogger process lines. No macOS APIs.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use aw_collector_macos::{decode_line, LineDecoder, PidFilter, ProbeError};
use aw_core::{EventKind, Evidence, GapKind, NaReason, StartHow};

fn fixture(name: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

const TS_MONO: u64 = 5_000;
const TS_WALL: i64 = 1_700_000_000_000_000_000;

#[test]
fn exec_json_maps_process_start_fields() {
    let line = fixture("exec.json");
    let events = decode_line(&line, TS_MONO, TS_WALL);
    assert!(!events.is_empty(), "a line produces at least one record");
    let decoded = events.last().expect("record");
    assert_eq!(decoded.subject_pid, Some(200));
    assert_eq!(decoded.ppid, Some(100));
    assert_eq!(decoded.exe.as_deref(), Some("/opt/fixture/bin/echo"));
    let argv = decoded.argv.as_ref().expect("argv");
    assert_eq!(argv.as_slice(), ["echo", "a b"]);
    assert_eq!(decoded.cwd.as_deref(), Some("/opt/fixture"));
    assert_eq!(decoded.how, Some(StartHow::Exec));
    assert_eq!(decoded.es_version, Some(8));
    assert!(decoded.responsible.is_some());
    assert!(decoded.start_time_ns.is_none());

    let event = decoded.event.as_ref().expect("raw event");
    assert_eq!(event.source.as_str(), "macos.eslogger/exec");
    assert_eq!(event.evidence, Evidence::E1);
    assert_eq!(event.ts_mono_ns, TS_MONO);
    match &event.kind {
        EventKind::ProcessStart(start) => {
            assert_eq!(start.ppid, 100);
            assert_eq!(start.how, StartHow::Exec);
            assert_eq!(start.exe.as_deref(), Some("/opt/fixture/bin/echo"));
            let argv = start.argv.as_ref().expect("argv");
            assert_eq!(argv.len(), 2);
            assert_eq!(argv[0].as_str(), "echo");
            assert_eq!(argv[1].as_str(), "a b");
            assert_eq!(start.cwd.as_deref(), Some("/opt/fixture"));
            assert!(start.parent_uid.is_none());
            assert!(start.user.is_none());
            assert!(start.signer.is_none());
        }
        other => panic!("expected process_start, got {}", other.kind_name()),
    }
    assert!(event
        .field_evidence
        .get("start_time_ns")
        .is_some_and(Evidence::is_na));
    assert!(event
        .field_evidence
        .get("pidversion")
        .is_some_and(Evidence::is_na));
    // Unknown key `extra_unknown` did not fail the decode.
}

#[test]
fn exit_json_maps_process_exit_and_leaves_stat_unsplit() {
    let events = decode_line(&fixture("exit.json"), TS_MONO, TS_WALL);
    let decoded = events.last().expect("record");
    assert_eq!(decoded.subject_pid, Some(200));
    assert_eq!(decoded.exit_stat, Some(0));
    assert!(decoded.how.is_none());
    let event = decoded.event.as_ref().expect("raw event");
    assert_eq!(event.source.as_str(), "macos.eslogger/exit");
    match &event.kind {
        EventKind::ProcessExit(exit) => {
            assert!(exit.exit_code.is_none());
            assert!(exit.signal.is_none());
        }
        other => panic!("expected process_exit, got {}", other.kind_name()),
    }
    assert_eq!(
        event.field_evidence.get("exit_code"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    assert_eq!(
        event.field_evidence.get("signal"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
}

#[test]
fn seq_num_hole_emits_a_lost_by_os_gap() {
    let mut decoder = LineDecoder::new();
    let first = r#"{"event_type":"exit","seq_num":1,"global_seq_num":1,"version":1,"process":{"audit_token":{"pid":7}},"event":{"exit":{"stat":1}}}"#;
    let second = r#"{"event_type":"exit","seq_num":4,"global_seq_num":2,"version":1,"process":{"audit_token":{"pid":7}},"event":{"exit":{"stat":0}}}"#;
    let _ = first;
    let first_out = decoder.push(first, TS_MONO, TS_WALL).expect("push");
    assert!(
        first_out.iter().all(|ev| {
            !matches!(
                ev.event.as_ref().map(|e| &e.kind),
                Some(EventKind::Gap(gap)) if gap.gap_kind == GapKind::LostByOs
            )
        }),
        "the first sample is a baseline"
    );
    let second_out = decoder.push(second, TS_MONO, TS_WALL).expect("push");
    let gap = second_out
        .iter()
        .find_map(|ev| match ev.event.as_ref().map(|e| &e.kind) {
            Some(EventKind::Gap(gap)) if gap.gap_kind == GapKind::LostByOs => Some(gap),
            _ => None,
        })
        .expect("hole");
    assert_eq!(gap.count, Some(2));
    assert_eq!(gap.collector.as_str(), "macos.eslogger/seq");
    let detail = gap.detail.as_deref().unwrap_or("");
    assert!(detail.contains("seq_num"));
    assert!(detail.contains("exit"));
}

#[test]
fn pid_outside_the_scope_is_dropped_before_parse() {
    let filter = PidFilter::new([100]);
    let line = fixture("exec.json");
    assert!(
        !filter.contains(200),
        "the exec subject is the out-of-scope pid"
    );
    assert_eq!(filter.classify(&line), aw_collector_macos::LineAction::Drop);
    // In-scope subject is kept.
    let inside = r#"{"event":"exec","process":{"pid":100}}"#;
    assert_eq!(
        filter.classify(inside),
        aw_collector_macos::LineAction::Keep
    );
}

#[test]
fn missing_fields_are_na_not_defaults() {
    let decoded = decode_line(&fixture("exec_missing.json"), TS_MONO, TS_WALL)
        .pop()
        .expect("record");
    assert!(decoded.exe.is_none());
    assert!(decoded.argv.is_none());
    assert!(decoded.cwd.is_none());
    assert!(decoded.ppid.is_none());
    assert!(decoded.es_version.is_none());
    assert!(decoded.responsible.is_none());
    assert!(decoded.start_time_ns.is_none());
    let event = decoded.event.as_ref().expect("raw");
    for field in [
        "exe",
        "argv",
        "cwd",
        "ppid",
        "start_time_ns",
        "pidversion",
        "es_version",
    ] {
        assert_eq!(
            event.field_evidence.get(field),
            Some(&Evidence::NA(NaReason::CollectorUnavailable)),
            "{field}"
        );
    }
    // No ProcessStart was built: ppid is absent, and 0 must not stand in for it.
    assert!(
        !matches!(event.kind, EventKind::ProcessStart(_)),
        "missing ppid must not become ProcessStart {{ ppid: 0 }}"
    );
}

#[test]
fn probe_errors_name_the_check() {
    let err = ProbeError::full_disk_access_denied();
    assert!(err.to_string().contains("Full Disk Access"));
    assert!(ProbeError::NotRoot.to_string().contains("root"));
    assert!(ProbeError::BinaryMissing
        .to_string()
        .contains("/usr/bin/eslogger"));
}
