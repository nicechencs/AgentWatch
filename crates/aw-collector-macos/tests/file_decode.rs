//! Fixture decode for eslogger file lines. No macOS APIs and no file contents.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

use aw_collector_macos::{decode_line, FileSubscription, LineDecoder};
use aw_core::{EventKind, Evidence, FileAccessMode, GapKind, IoVia, NaReason};

const TS_MONO: u64 = 5_000;
const TS_WALL: i64 = 1_700_000_000_000_000_000;

fn fixture(name: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push(name);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn na(event: &aw_core::RawEvent, field: &str, reason: NaReason) -> bool {
    event.field_evidence.get(field) == Some(&Evidence::NA(reason))
}

#[test]
fn open_read_marks_bytes_unavailable_and_keeps_unknown_keys() {
    let events = decode_line(&fixture("open_read.json"), TS_MONO, TS_WALL);
    let decoded = events.last().expect("record");
    let event = decoded.event.as_ref().expect("raw event");
    assert_eq!(event.source.as_str(), "macos.eslogger/open");
    assert_eq!(event.evidence, Evidence::E1);
    match &event.kind {
        EventKind::FileOpen(open) => {
            assert_eq!(open.path, "/opt/fixture/notes.txt");
            assert_eq!(open.access, FileAccessMode::Read);
            assert!(open.handle.is_none());
            assert!(open.via.is_none());
        }
        other => panic!("expected file_open, got {}", other.kind_name()),
    }
    assert!(na(event, "bytes_read", NaReason::EsNoReadEvent));
    assert!(na(event, "reads", NaReason::EsNoReadEvent));
    assert!(na(event, "handle", NaReason::CollectorUnavailable));
}

#[test]
fn open_write_does_not_claim_a_read() {
    let event = decode_line(&fixture("open_write.json"), TS_MONO, TS_WALL)
        .pop()
        .and_then(|decoded| decoded.event)
        .expect("raw event");
    match &event.kind {
        EventKind::FileOpen(open) => assert_eq!(open.access, FileAccessMode::Write),
        other => panic!("expected file_open, got {}", other.kind_name()),
    }
    assert!(!event.field_evidence.contains_key("bytes_read"));
    assert!(!event.field_evidence.contains_key("reads"));
}

#[test]
fn modified_close_adds_a_write_without_a_byte_count() {
    let events = decode_line(&fixture("close_modified.json"), TS_MONO, TS_WALL);
    let kinds: Vec<_> = events
        .iter()
        .filter_map(|decoded| decoded.event.as_ref().map(|event| event.kind.kind_name()))
        .collect();
    assert_eq!(kinds, ["file_close", "file_write"]);
    let write = events
        .iter()
        .find_map(
            |decoded| match decoded.event.as_ref().map(|event| &event.kind) {
                Some(EventKind::FileWrite(write)) => Some(write),
                _ => None,
            },
        )
        .expect("write");
    assert_eq!(write.path.as_deref(), Some("/opt/fixture/out.txt"));
    assert_eq!(write.bytes, None, "an unseen byte count stays absent");
    let raw = events
        .iter()
        .find_map(|decoded| match decoded.event.as_ref() {
            Some(event) if matches!(event.kind, EventKind::FileWrite(_)) => Some(event),
            _ => None,
        })
        .expect("write event");
    assert!(na(raw, "bytes", NaReason::EsNoReadEvent));
}

#[test]
fn create_unlink_and_rename_keep_their_paths() {
    let create = decode_line(&fixture("create.json"), TS_MONO, TS_WALL)
        .pop()
        .and_then(|decoded| decoded.event)
        .expect("create");
    match &create.kind {
        EventKind::FileCreate(row) => {
            assert_eq!(row.path, "/opt/fixture/new.txt");
            assert!(!row.is_dir);
        }
        other => panic!("expected file_create, got {}", other.kind_name()),
    }

    let unlink = decode_line(&fixture("unlink.json"), TS_MONO, TS_WALL)
        .pop()
        .and_then(|decoded| decoded.event)
        .expect("unlink");
    match &unlink.kind {
        EventKind::FileDelete(row) => {
            assert_eq!(row.path, "/opt/fixture/old.txt");
            assert!(row.is_dir.is_none());
        }
        other => panic!("expected file_delete, got {}", other.kind_name()),
    }
    assert!(na(&unlink, "is_dir", NaReason::CollectorUnavailable));

    let rename = decode_line(&fixture("rename.json"), TS_MONO, TS_WALL)
        .pop()
        .and_then(|decoded| decoded.event)
        .expect("rename");
    match &rename.kind {
        EventKind::FileRename(row) => {
            assert_eq!(row.from, "/opt/fixture/a.txt");
            assert_eq!(row.to, "/opt/fixture/b.txt");
        }
        other => panic!("expected file_rename, got {}", other.kind_name()),
    }
}

#[test]
fn a_file_line_without_a_path_is_a_parse_gap() {
    let event = decode_line(&fixture("open_missing.json"), TS_MONO, TS_WALL)
        .pop()
        .and_then(|decoded| decoded.event)
        .expect("gap");
    match &event.kind {
        EventKind::Gap(gap) => {
            assert_eq!(gap.gap_kind, GapKind::ParseError);
            assert_eq!(gap.collector.as_str(), "macos.eslogger/open");
        }
        other => panic!("expected a parse gap, got {}", other.kind_name()),
    }
}

#[test]
fn mmap_marks_bytes_unavailable_for_a_different_reason() {
    let line = r#"{"version":8,"event_type":"mmap","process":{"audit_token":{"pid":200}},"event":{"mmap":{"source":{"path":"/opt/fixture/mapped.bin"}}}}"#;
    let value: serde_json::Value = serde_json::from_str(line).expect("mmap json");
    let mut files = FileSubscription::macos_default();
    files.mmap = true;
    let mut decoder = LineDecoder::new();
    decoder.set_files(files);
    let event = decoder
        .push(&value.to_string(), TS_MONO, TS_WALL)
        .expect("push")
        .pop()
        .and_then(|decoded| decoded.event)
        .expect("mmap");
    match &event.kind {
        EventKind::FileOpen(open) => {
            assert_eq!(open.path, "/opt/fixture/mapped.bin");
            assert_eq!(open.access, FileAccessMode::Unknown);
            assert_eq!(open.via, Some(IoVia::Mmap));
        }
        other => panic!("expected file_open, got {}", other.kind_name()),
    }
    assert!(na(&event, "bytes", NaReason::MmapNotObservable));
    assert!(na(&event, "bytes_read", NaReason::MmapNotObservable));
}

#[test]
fn unsubscribed_open_events_produce_nothing() {
    let value: serde_json::Value =
        serde_json::from_str(&fixture("open_read.json")).expect("fixture json");
    let mut decoder = LineDecoder::new();
    let events = decoder
        .push_file(
            &value,
            "open",
            FileSubscription::macos_default().without_open(),
            TS_MONO,
            TS_WALL,
        )
        .expect("push");
    assert!(events.is_empty(), "an unsubscribed open is not an event");
}
