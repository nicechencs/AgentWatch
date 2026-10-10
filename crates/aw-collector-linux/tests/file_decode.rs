//! P2-LNX-01: file records decoded from synthetic bytes.
//! Nothing is attached, loaded, or read from a real process.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use aw_collector_linux::{
    decode_file, encode_open, FdPathRead, FileCwdLookup, FileDecodeOutcome, FileProcIdentity,
    FileScopeView, OpenIn,
};
use aw_core::{EventKind, Evidence};

const TGID: u32 = 4242;
const PATH: &str = "/opt/fixture/notes.txt";

fn open_read() -> OpenIn {
    OpenIn {
        kind: 1,
        ts_mono_ns: 5_000,
        tgid: TGID,
        tid: Some(4243),
        fd: Some(7),
        dirfd: None,
        result: Some(0),
        access: Some(1),
        created: Some(false),
        truncated: Some(false),
        path_resolved: true,
        path_from: None,
        d_path_denied: false,
        path: Some(PATH.to_owned()),
        path_truncated: false,
        dst: None,
        dst_truncated: false,
        is_dir: Some(false),
    }
}

fn decode(bytes: &[u8], in_scope: bool) -> aw_collector_linux::FileDecode {
    let scope = if in_scope { vec![TGID] } else { Vec::new() };
    decode_file(
        bytes,
        FileDecodeOutcome {
            ts_wall_ns: Some(1_700_000_000_000_000_000),
            seq: 1,
            proc: FileProcIdentity {
                tgid: TGID,
                proc_uid: Some(90),
            },
            cwd: &FileCwdLookup::Unavailable,
        },
        FileScopeView { tgids: &scope },
        &FdPathRead::Unknown,
        None,
    )
    .expect("decode")
}

#[test]
fn a_resolved_read_open_keeps_the_path_and_does_not_invent_bytes() {
    let bytes = encode_open(&open_read()).expect("encode");
    let decoded = decode(&bytes, true);
    assert_eq!(decoded.events.len(), 1);
    let event = &decoded.events[0];
    assert_eq!(event.evidence, Evidence::E1);
    match &event.kind {
        EventKind::FileOpen(open) => {
            assert_eq!(open.path, PATH);
            assert!(open.path_resolved);
            assert_eq!(open.access, aw_core::FileAccessMode::Read);
        }
        other => panic!("expected file_open, got {}", other.kind_name()),
    }
}

#[test]
fn a_tgid_outside_the_scope_produces_no_event() {
    let bytes = encode_open(&open_read()).expect("encode");
    let decoded = decode(&bytes, false);
    assert!(decoded.events.is_empty());
}

#[test]
fn a_short_buffer_is_an_error_and_not_a_dropped_event() {
    let err = decode_file(
        &[1, 0, 0],
        FileDecodeOutcome {
            ts_wall_ns: None,
            seq: 1,
            proc: FileProcIdentity {
                tgid: TGID,
                proc_uid: None,
            },
            cwd: &FileCwdLookup::Unavailable,
        },
        FileScopeView { tgids: &[TGID] },
        &FdPathRead::Unknown,
        None,
    );
    assert!(err.is_err());
}
