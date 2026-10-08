//! Replay of hand-written Kernel-Process fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//!
//! The files under `fixtures/process/` are not an ETW recording. SPIKE-02 was
//! not run elevated, and this process is not an administrator, so there is no
//! captured session to put here. Each line uses the property names from
//! windows.md §2.1. A property the line omits is absent — the decoder must
//! mark it `NA(collector_unavailable)`, not invent a zero.

use std::path::PathBuf;

use aw_collector_windows::etw::{
    decode_process, CachedProcess, DecodeClock, DecodedProcess, ProcessCache, ProcessProperties,
    EVENT_PROCESS_START, EVENT_PROCESS_STOP,
};
use aw_collector_windows::peb::{BackfillAnswer, ReadOutcome};
use aw_core::proc::{ProcessIdentity, StartTimeUnit};
use aw_core::{EventKind, Evidence, NaReason};

fn fixture(name: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("process");
    path.push(name);
    std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("read {}: {err}", path.display());
    })
}

fn props_from_line(line: &str) -> (ProcessProperties, DecodeClock, Vec<u8>, u64, Option<i64>) {
    // The fixture is one flat object. A JSON parser is not a direct dependency
    // of this crate, and these files are hand-written, so the reader only
    // accepts the keys windows.md §2.1 names plus the envelope. A missing key
    // is `None`. A present key with the wrong shape panics: that is a broken
    // fixture, not an absent field.
    let event_id = u64_key(line, "event_id").expect("event_id") as u16;
    let mut props = ProcessProperties::bare(event_id);
    props.process_id = u64_key(line, "process_id").map(|n| n as u32);
    props.create_time = i64_key(line, "create_time");
    props.parent_process_id = u64_key(line, "parent_process_id").map(|n| n as u32);
    props.session_id = u64_key(line, "session_id").map(|n| n as u32);
    props.image_name = string_key(line, "image_name");
    props.exit_time = i64_key(line, "exit_time");
    props.exit_code = i64_key(line, "exit_code").map(|n| n as i32);
    props.command_line = string_key(line, "command_line");
    props.tid = u64_key(line, "tid").map(|n| n as u32);
    let clock = DecodeClock {
        ts_mono_ns: u64_key(line, "ts_mono_ns").expect("ts_mono_ns"),
        ts_wall_ns: i64_key(line, "ts_wall_ns"),
    };
    let boot = string_key(line, "boot_id").expect("boot_id").into_bytes();
    let seq = u64_key(line, "seq").expect("seq");
    let parent_create = i64_key(line, "parent_create_time");
    (props, clock, boot, seq, parent_create)
}

fn u64_key(line: &str, key: &str) -> Option<u64> {
    i64_key(line, key).map(|n| n as u64)
}

fn i64_key(line: &str, key: &str) -> Option<i64> {
    let raw = value_span(line, key)?;
    if raw == "null" {
        return None;
    }
    Some(
        raw.parse()
            .unwrap_or_else(|_| panic!("{key} is not an integer")),
    )
}

fn string_key(line: &str, key: &str) -> Option<String> {
    let raw = value_span(line, key)?;
    if raw == "null" {
        return None;
    }
    let inner = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{key} is not a string"));
    Some(unescape(inner))
}

fn value_span<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pattern = format!("\"{key}\"");
    let start = line.find(&pattern)?;
    let after = &line[start + pattern.len()..];
    let after = after.trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    if let Some(rest) = after.strip_prefix('"') {
        let mut end = 0;
        let bytes = rest.as_bytes();
        while end < bytes.len() {
            if bytes[end] == b'\\' {
                end += 2;
                continue;
            }
            if bytes[end] == b'"' {
                return Some(&after[..=end + 1]);
            }
            end += 1;
        }
        panic!("{key} string is not closed");
    }
    let end = after.find([',', '}']).unwrap_or(after.len());
    Some(after[..end].trim())
}

fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('n') => out.push('\n'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn cache_with_parent(boot: &[u8], ppid: u32, parent_create_time: i64) -> ProcessCache {
    let mut cache = ProcessCache::new();
    let parent = ProcessIdentity::from_parts(
        boot,
        ppid,
        parent_create_time as u64,
        StartTimeUnit::HundredNanoseconds,
    )
    .expect("boot id fits");
    cache.insert(
        ppid,
        CachedProcess {
            uid: parent.uid,
            create_time: parent_create_time,
        },
    );
    cache
}

#[test]
fn replay_start_with_command_line_is_e1() {
    let line = fixture("start_with_command_line.jsonl");
    let (props, clock, boot, seq, parent_create) = props_from_line(line.trim());
    assert_eq!(props.event_id, EVENT_PROCESS_START);
    let parent_create = parent_create.expect("fixture names the parent's CreateTime");
    let cache = cache_with_parent(&boot, props.parent_process_id.expect("ppid"), parent_create);
    let decoded = decode_process(&props, &boot, seq, clock, &cache);
    let DecodedProcess::Start(start) = decoded else {
        panic!("fixture is a start");
    };
    assert_eq!(start.event.seq, 1);
    assert_eq!(start.event.ts_mono_ns, 1000);
    assert_eq!(start.event.ts_wall_ns, 2000);
    assert_eq!(start.event.source.as_str(), "windows.etw/kernel_process");
    assert_eq!(start.event.evidence, Evidence::E1);
    assert_eq!(start.event.field_evidence.get("argv"), Some(&Evidence::E1));
    assert_eq!(
        start.event.field_evidence.get("cwd"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    // SessionID is on the fixture and windows.md names it, but ProcessStart has
    // no field for it. It is NA, not silently dropped and not written elsewhere.
    assert_eq!(
        start.event.field_evidence.get("session_id"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    let expected = ProcessIdentity::from_parts(
        &boot,
        100,
        props.create_time.expect("create") as u64,
        StartTimeUnit::HundredNanoseconds,
    )
    .expect("boot");
    assert_eq!(start.event.proc.as_ref().map(|p| p.uid), Some(expected.uid));
    assert_eq!(start.event.proc.as_ref().map(|p| p.pid), Some(100));
    match &start.event.kind {
        EventKind::ProcessStart(body) => {
            let words: Vec<&str> = body
                .argv
                .as_ref()
                .unwrap()
                .iter()
                .map(|a| a.as_str())
                .collect();
            assert_eq!(words, vec!["cmd", "/c", "echo a b"]);
            assert!(body.cwd.is_none());
            assert_eq!(body.ppid, 4);
            assert!(body.parent_uid.is_some());
            assert_eq!(body.how, aw_core::StartHow::Spawn);
            assert!(body.env.is_none());
            assert_eq!(body.exe.as_deref(), Some("C:\\Windows\\System32\\cmd.exe"));
        }
        other => panic!("expected process_start, got {other:?}"),
    }
    let job = start.backfill.expect("cwd is not on the event");
    assert!(!job.want_argv);
    assert!(job.want_cwd);
}

#[test]
fn replay_absent_command_line_is_na_and_backfill_can_raise_it_to_s() {
    let line = fixture("start_command_line_absent.jsonl");
    let (props, clock, boot, seq, parent_create) = props_from_line(line.trim());
    assert!(
        parent_create.is_none(),
        "this fixture does not know the parent"
    );
    assert!(props.command_line.is_none());
    let cache = ProcessCache::new();
    let decoded = decode_process(&props, &boot, seq, clock, &cache);
    let DecodedProcess::Start(mut start) = decoded else {
        panic!("fixture is a start");
    };
    assert_eq!(
        start.event.field_evidence.get("argv"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    assert_eq!(
        start.event.field_evidence.get("cwd"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    assert_eq!(
        start.event.field_evidence.get("parent_uid"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    match &start.event.kind {
        EventKind::ProcessStart(body) => {
            assert!(body.argv.is_none());
            assert!(body.cwd.is_none());
            assert!(body.parent_uid.is_none());
            assert_eq!(body.ppid, 100);
        }
        other => panic!("expected process_start, got {other:?}"),
    }
    let job = start.backfill.expect("both fields pending");
    assert!(job.want_argv && job.want_cwd);
    // The back-fill is not in the fixture. The test supplies the answer a
    // reader would return, without opening a process.
    let answer = BackfillAnswer {
        argv: Some(ReadOutcome::Value("ping -n 1 127.0.0.1".to_owned())),
        cwd: Some(ReadOutcome::Value("C:\\work".to_owned())),
    };
    aw_collector_windows::etw::apply_backfill(&mut start.event, job, &answer);
    assert_eq!(start.event.field_evidence.get("argv"), Some(&Evidence::S));
    assert_eq!(start.event.field_evidence.get("cwd"), Some(&Evidence::S));
    match &start.event.kind {
        EventKind::ProcessStart(body) => {
            let words: Vec<&str> = body
                .argv
                .as_ref()
                .unwrap()
                .iter()
                .map(|a| a.as_str())
                .collect();
            assert_eq!(words, vec!["ping", "-n", "1", "127.0.0.1"]);
            assert_eq!(body.cwd.as_deref(), Some("C:\\work"));
        }
        other => panic!("expected process_start, got {other:?}"),
    }
}

#[test]
fn replay_stop_keeps_the_exit_code_and_marks_signal_na() {
    let line = fixture("stop_with_exit_code.jsonl");
    let (props, clock, boot, seq, _) = props_from_line(line.trim());
    assert_eq!(props.event_id, EVENT_PROCESS_STOP);
    let cache = ProcessCache::new();
    let decoded = decode_process(&props, &boot, seq, clock, &cache);
    let DecodedProcess::Stop(stop) = decoded else {
        panic!("fixture is a stop");
    };
    assert_eq!(
        stop.event.source.as_str(),
        "windows.etw/kernel_process_stop"
    );
    assert_eq!(stop.event.evidence, Evidence::E1);
    assert_eq!(stop.event.seq, 3);
    match &stop.event.kind {
        EventKind::ProcessExit(body) => {
            assert_eq!(body.exit_code, Some(7));
            assert!(body.signal.is_none());
        }
        other => panic!("expected process_exit, got {other:?}"),
    }
    assert_eq!(
        stop.event.field_evidence.get("signal"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    assert!(!stop.event.field_evidence.contains_key("exit_code"));
    let expected = ProcessIdentity::from_parts(
        &boot,
        100,
        props.create_time.expect("create") as u64,
        StartTimeUnit::HundredNanoseconds,
    )
    .expect("boot");
    assert_eq!(stop.event.proc.as_ref().map(|p| p.uid), Some(expected.uid));
}

#[test]
fn replay_parent_whose_create_time_is_not_earlier_is_not_the_parent() {
    let line = fixture("parent_create_time_not_earlier.jsonl");
    let (props, clock, boot, seq, parent_create) = props_from_line(line.trim());
    let parent_create = parent_create.expect("fixture names a parent CreateTime");
    assert_eq!(parent_create, props.create_time.expect("child"));
    let cache = cache_with_parent(&boot, 4, parent_create);
    let decoded = decode_process(&props, &boot, seq, clock, &cache);
    let DecodedProcess::Start(start) = decoded else {
        panic!("fixture is a start");
    };
    match &start.event.kind {
        EventKind::ProcessStart(body) => {
            assert!(body.parent_uid.is_none());
            assert_eq!(body.ppid, 4);
        }
        other => panic!("expected process_start, got {other:?}"),
    }
    assert_eq!(
        start.event.field_evidence.get("parent_uid"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
}

/// End-to-end against a live ETW session: `cmd /c "echo a b & ping -n 1 127.0.0.1"`
/// and a process that exits in under 50 ms.
///
/// Not run here. This process is not elevated, and the task forbids launching
/// a real session. `e2e` is off unless the caller opts in, and `#[ignore]`
/// keeps `cargo test --features e2e` from starting one by accident.
#[cfg(all(target_os = "windows", feature = "e2e"))]
#[test]
#[ignore = "needs an elevated token; opens a real ETW session and spawns cmd.exe"]
fn e2e_cmd_chain_and_short_lived_process() {
    // Body intentionally empty. A real run needs an elevated token and is not
    // part of this task. The assertion below fails if someone removes `ignore`
    // without writing the scenario, so a green result cannot be an accident.
    panic!(
        "not run: elevated ETW end-to-end (cmd /c child chain, argv with spaces, \
         exit code, process shorter than 50 ms) is unverified"
    );
}
