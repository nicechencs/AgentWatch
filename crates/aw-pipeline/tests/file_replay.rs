//! P2-PIPE-01: file events through the default public replay chain.
//! Paths are synthetic fixtures. Nothing is opened, stated, or read from disk.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use aw_core::{
    EventKind, Evidence, FileAccessMode, FileClose, FileCreate, FileDelete, FileOpen, FileRead,
    FileRename, FileWrite, ProcRef, ProcUid, ProcessExit, RawEvent, SessionId, Source,
    SCHEMA_VERSION,
};
use aw_pipeline::{FileAccessRec, Output, Pipeline, PipelineConfig};

const MS: u64 = 1_000_000;
const SEC: u64 = 1_000_000_000;

fn event(seq: u64, at: u64, evidence: Evidence, kind: EventKind) -> RawEvent {
    checked(seq, at, evidence, kind, None)
}

fn checked(
    seq: u64,
    at: u64,
    evidence: Evidence,
    kind: EventKind,
    absent: Option<&str>,
) -> RawEvent {
    let mut field_evidence = BTreeMap::new();
    if let Some(field) = absent {
        field_evidence.insert(
            field.to_owned(),
            Evidence::NA(aw_core::NaReason::EsNoReadEvent),
        );
    }
    let row = RawEvent {
        v: SCHEMA_VERSION,
        seq,
        ts_mono_ns: at,
        ts_wall_ns: 1_700_000_000_000_000_000,
        session_id: Some(SessionId(1)),
        proc: Some(ProcRef {
            uid: ProcUid(21),
            pid: 200,
            tid: None,
        }),
        source: Source::new(format!("synthetic/{}", kind.kind_name())),
        evidence,
        field_evidence,
        kind,
    };
    row.check().expect("synthetic file event");
    row
}

fn open(seq: u64, at: u64, handle: Option<u64>, path: &str, access: FileAccessMode) -> RawEvent {
    event(
        seq,
        at,
        Evidence::E1,
        EventKind::FileOpen(FileOpen::new(
            handle, path, access, None, None, None, None, true,
        )),
    )
}

fn read(
    seq: u64,
    at: u64,
    handle: Option<u64>,
    path: Option<&str>,
    bytes: Option<u64>,
) -> RawEvent {
    checked(
        seq,
        at,
        Evidence::E1,
        EventKind::FileRead(FileRead::new(
            handle,
            path.map(str::to_owned),
            bytes,
            None,
            None,
        )),
        bytes.is_none().then_some("bytes"),
    )
}

fn write(
    seq: u64,
    at: u64,
    handle: Option<u64>,
    path: Option<&str>,
    bytes: Option<u64>,
) -> RawEvent {
    event(
        seq,
        at,
        Evidence::E1,
        EventKind::FileWrite(FileWrite::new(handle, path.map(str::to_owned), bytes, None)),
    )
}

fn close(seq: u64, at: u64, handle: Option<u64>, path: Option<&str>) -> RawEvent {
    event(
        seq,
        at,
        Evidence::E1,
        EventKind::FileClose(FileClose::new(handle, path.map(str::to_owned), None)),
    )
}

fn replay(events: Vec<RawEvent>) -> Output {
    Pipeline::replay(events, PipelineConfig::default())
}

fn rows_for<'a>(out: &'a Output, path: &str) -> Vec<&'a FileAccessRec> {
    out.file_access
        .iter()
        .filter(|row| row.path == path)
        .collect()
}

#[test]
fn reads_and_writes_collapse_to_one_row_on_close() {
    let path = "/fixture/work/notes.txt";
    let out = replay(vec![
        open(1, 0, Some(7), path, FileAccessMode::ReadWrite),
        write(2, 10 * MS, Some(7), None, Some(100)),
        read(3, 20 * MS, Some(7), None, Some(40)),
        write(4, 30 * MS, Some(7), None, Some(25)),
        close(5, 40 * MS, Some(7), Some(path)),
    ]);
    let rows = rows_for(&out, path);
    assert_eq!(rows.len(), 1, "open, reads, writes, and close are one row");
    let row = rows[0];
    assert_eq!(row.op, "access");
    assert_eq!(row.opens, 1);
    assert_eq!(row.reads, Some(1));
    assert_eq!(row.bytes_read, Some(40));
    assert_eq!(row.writes, Some(2));
    assert_eq!(row.bytes_written, Some(125));
    assert!(!row.partial);
    assert_eq!(row.evidence, Evidence::E1);
    assert_eq!(row.first_ns, 0);
    assert_eq!(row.last_ns, 40 * MS);
}

#[test]
fn process_exit_flushes_an_unclosed_handle() {
    let path = "/fixture/work/held.txt";
    let out = replay(vec![
        open(1, 0, Some(3), path, FileAccessMode::Read),
        read(2, MS, Some(3), None, Some(8)),
        event(
            3,
            2 * MS,
            Evidence::E1,
            EventKind::ProcessExit(ProcessExit::new(Some(0), None)),
        ),
    ]);
    let rows = rows_for(&out, path);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].bytes_read, Some(8));
    assert!(!rows[0].partial, "process exit closes the row");
    assert_eq!(rows[0].last_ns, 2 * MS);
}

#[test]
fn a_long_open_emits_a_partial_and_keeps_accumulating() {
    let path = "/fixture/work/long.txt";
    let out = replay(vec![
        open(1, 0, Some(9), path, FileAccessMode::Write),
        write(2, 10 * SEC, Some(9), None, Some(10)),
        write(3, 40 * SEC, Some(9), None, Some(15)),
        close(4, 41 * SEC, Some(9), Some(path)),
    ]);
    let rows = rows_for(&out, path);
    assert!(
        rows.iter()
            .any(|row| row.partial && row.bytes_written == Some(10)),
        "the flush interval emits the bytes seen so far: {rows:?}"
    );
    let finished = rows.iter().find(|row| !row.partial).expect("final row");
    assert_eq!(finished.bytes_written, Some(25));
    assert_eq!(finished.writes, Some(2));
}

#[test]
fn a_path_without_a_handle_still_aggregates() {
    let path = "/fixture/macos/notes.txt";
    let out = replay(vec![
        open(1, 0, None, path, FileAccessMode::Read),
        read(2, MS, None, Some(path), None),
        close(3, 2 * MS, None, Some(path)),
    ]);
    let rows = rows_for(&out, path);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].reads, Some(1));
    assert_eq!(rows[0].bytes_read, None, "a missing count stays missing");
    assert!(rows[0]
        .field_evidence
        .get("bytes_read")
        .is_some_and(|grade| grade.is_na()));
}

#[test]
fn repeated_read_only_opens_inside_the_window_merge() {
    let path = "/fixture/work/header.h";
    let out = replay(vec![
        open(1, 0, None, path, FileAccessMode::Read),
        close(2, 100 * MS, None, Some(path)),
        open(3, 400 * MS, None, path, FileAccessMode::Read),
        close(4, 500 * MS, None, Some(path)),
        open(5, 800 * MS, None, path, FileAccessMode::Read),
        close(6, 900 * MS, None, Some(path)),
    ]);
    let rows = rows_for(&out, path);
    assert_eq!(rows.len(), 1, "three read-only opens inside 1s merge");
    assert_eq!(rows[0].opens, 3);
    assert_eq!(rows[0].first_ns, 0);
    assert_eq!(rows[0].last_ns, 900 * MS);
}

#[test]
fn a_read_only_open_outside_the_window_stays_separate() {
    let path = "/fixture/work/later.h";
    let out = replay(vec![
        open(1, 0, None, path, FileAccessMode::Read),
        close(2, 100 * MS, None, Some(path)),
        open(3, 2 * SEC, None, path, FileAccessMode::Read),
        close(4, 2 * SEC + 100 * MS, None, Some(path)),
    ]);
    let rows = rows_for(&out, path);
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row.opens == 1));
}

#[test]
fn create_delete_rename_and_exec_are_not_aggregated() {
    let out = replay(vec![
        event(
            1,
            0,
            Evidence::E1,
            EventKind::FileCreate(FileCreate::new("/fixture/new.txt", false)),
        ),
        event(
            2,
            MS,
            Evidence::E1,
            EventKind::FileDelete(FileDelete::new("/fixture/old.txt", Some(false))),
        ),
        event(
            3,
            2 * MS,
            Evidence::E1,
            EventKind::FileRename(FileRename::new("/fixture/a.txt", "/fixture/b.txt")),
        ),
        open(
            4,
            3 * MS,
            Some(1),
            "/fixture/bin/tool",
            FileAccessMode::Exec,
        ),
    ]);
    let ops: Vec<_> = out.file_access.iter().map(|row| row.op.as_str()).collect();
    assert_eq!(ops, ["create", "delete", "rename", "exec"]);
    let renamed = out
        .file_access
        .iter()
        .find(|row| row.op == "rename")
        .expect("rename");
    assert_eq!(renamed.path_to.as_deref(), Some("/fixture/b.txt"));
}

#[test]
fn a_weaker_later_event_lowers_the_row_and_keeps_field_evidence() {
    let path = "/fixture/work/mixed.txt";
    let mut sampled = read(2, MS, Some(4), None, Some(9));
    sampled.evidence = Evidence::S;
    sampled.mark_na("offset", aw_core::NaReason::CollectorUnavailable);
    let out = replay(vec![
        open(1, 0, Some(4), path, FileAccessMode::Read),
        sampled,
        close(3, 2 * MS, Some(4), Some(path)),
    ]);
    let row = rows_for(&out, path).into_iter().next().expect("row");
    assert_eq!(
        row.evidence,
        Evidence::S,
        "record evidence follows the weakest event"
    );
    assert_eq!(row.bytes_read, Some(9));
    assert!(row
        .field_evidence
        .get("offset")
        .is_some_and(|grade| grade.is_na()));
}

#[test]
fn repeated_header_reads_collapse_far_below_the_event_count() {
    let mut events = Vec::new();
    let mut seq = 1_u64;
    for index in 0..200_u64 {
        let path = format!("/fixture/compile/include/header-{}.h", index % 20);
        let at = index * 4 * MS;
        events.push(open(seq, at, None, &path, FileAccessMode::Read));
        seq += 1;
        events.push(close(seq, at + MS, None, Some(&path)));
        seq += 1;
    }
    let out = replay(events);
    assert!(
        out.file_access.len() * 100 <= 400 * 5,
        "400 header events collapsed to {} rows, above the 5% ceiling",
        out.file_access.len()
    );
    assert!(out.file_access.iter().all(|row| row.opens >= 1));
    let again = replay({
        let mut events = Vec::new();
        let mut seq = 1_u64;
        for index in 0..200_u64 {
            let path = format!("/fixture/compile/include/header-{}.h", index % 20);
            let at = index * 4 * MS;
            events.push(open(seq, at, None, &path, FileAccessMode::Read));
            seq += 1;
            events.push(close(seq, at + MS, None, Some(&path)));
            seq += 1;
        }
        events
    });
    assert_eq!(out.file_access.len(), again.file_access.len());
    assert_eq!(
        out.file_access
            .iter()
            .map(|row| row.opens)
            .collect::<Vec<_>>(),
        again
            .file_access
            .iter()
            .map(|row| row.opens)
            .collect::<Vec<_>>()
    );
}
