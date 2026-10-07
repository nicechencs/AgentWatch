//! Snapshot and round-trip coverage for every [`aw_core::EventKind`] variant.
//!
//! Sample strings are placeholders. Nothing here is a real username, hostname, or token.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr as StdSocketAddr};

use serde_json::json;

use aw_core::{
    AgentRpc, AgentToolCall, BodyDigestRef, DnsAnswer, DnsQuery, DnsRecord, EnvMap, EventKind,
    Evidence, FileAccessMode, FileClose, FileCreate, FileDelete, FileOpen, FileRead, FileRename,
    FileWrite, FlowDirection, FlowKey, Gap, GapKind, HeaderList, HttpRequest, HttpResponse, IoVia,
    IpcClose, IpcDirection, IpcKind, IpcOpen, IpcTransfer, L4Proto, NaReason, NetClose, NetConnect,
    NetRecv, NetSend, ProcRef, ProcUid, ProcessExit, ProcessStart, RawEvent, RawEventParts,
    Redacted, SessionId, SocketAddr, Source, StartHow, TlsSni, ToolPhase, UserRef,
};

fn proc(uid: u64, pid: u32) -> ProcRef {
    ProcRef {
        uid: ProcUid(uid),
        pid,
        tid: Some(pid),
    }
}

fn flow() -> FlowKey {
    FlowKey::new(
        L4Proto::Tcp,
        StdSocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 51544)),
        StdSocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 443)),
        Some(88123),
    )
}

fn event(seq: u64, evidence: Evidence, source: &str, kind: EventKind) -> RawEvent {
    RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns: 5_021_000_000 + seq,
        ts_wall_ns: 1_791_273_662_000_000_000,
        session_id: Some(SessionId(7)),
        proc: Some(proc(0x9f3a_11c2_d4e5_f601, 5120)),
        source: Source::new(source),
        evidence,
        kind,
    })
    .unwrap_or_else(|err| panic!("sample event {seq} failed validation: {err}"))
}

fn json_of(event: &RawEvent) -> String {
    let value = serde_json::to_value(event).expect("serialize");
    serde_json::to_string_pretty(&value).expect("pretty")
}

fn assert_round_trip(event: &RawEvent) {
    let text = event.to_json().expect("to_json");
    let back = RawEvent::from_json(&text).expect("from_json");
    assert_eq!(&back, event);
}

fn snap(name: &str, event: &RawEvent) {
    assert_round_trip(event);
    insta::assert_snapshot!(name, json_of(event));
}

#[test]
fn snapshot_process_start() {
    let mut env = BTreeMap::new();
    env.insert("LANG".to_owned(), "C".to_owned());
    let ev = event(
        101,
        Evidence::E1,
        "linux.ebpf/sched_process_exec",
        EventKind::ProcessStart(ProcessStart::new(
            5101,
            Some(ProcUid(0x1b2c_3d4e_5f60_7182)),
            1_791_273_661_998_000_000,
            Some("/usr/bin/example".to_owned()),
            Some(vec![
                Redacted::new("example"),
                Redacted::new("/tmp/placeholder"),
            ]),
            Some("/tmp/work".to_owned()),
            Some(UserRef {
                id: "1000".to_owned(),
                name: Some("placeholder".to_owned()),
            }),
            StartHow::Exec,
            Some(EnvMap(env)),
            None,
        )),
    );
    snap("process_start", &ev);
}

#[test]
fn snapshot_process_exit() {
    snap(
        "process_exit",
        &event(
            102,
            Evidence::E1,
            "linux.ebpf/sched_process_exit",
            EventKind::ProcessExit(ProcessExit::new(Some(0), None)),
        ),
    );
}

#[test]
fn snapshot_file_open() {
    snap(
        "file_open",
        &event(
            103,
            Evidence::E1,
            "linux.ebpf/lsm_file_open",
            EventKind::FileOpen(FileOpen::new(
                Some(21_990_232_555_523),
                "/tmp/placeholder.txt",
                FileAccessMode::Read,
                Some(false),
                Some(false),
                Some(0),
                Some(IoVia::Syscall),
                true,
            )),
        ),
    );
}

#[test]
fn snapshot_file_read() {
    snap(
        "file_read",
        &event(
            104,
            Evidence::E1,
            "linux.ebpf/sys_exit_read",
            EventKind::FileRead(FileRead::new(
                Some(21_990_232_555_523),
                None,
                Some(412),
                Some(0),
                Some(IoVia::Syscall),
            )),
        ),
    );
}

#[test]
fn snapshot_file_write() {
    snap(
        "file_write",
        &event(
            105,
            Evidence::E1,
            "linux.ebpf/sys_exit_write",
            EventKind::FileWrite(FileWrite::new(
                Some(7),
                Some("/tmp/out.txt".to_owned()),
                Some(16),
                Some(0),
            )),
        ),
    );
}

#[test]
fn snapshot_file_close() {
    snap(
        "file_close",
        &event(
            106,
            Evidence::E1,
            "linux.ebpf/sys_enter_close",
            EventKind::FileClose(FileClose::new(Some(21_990_232_555_523), None, Some(false))),
        ),
    );
}

#[test]
fn snapshot_file_create() {
    snap(
        "file_create",
        &event(
            107,
            Evidence::E1,
            "linux.ebpf/lsm_file_open",
            EventKind::FileCreate(FileCreate::new("/tmp/new-dir", true)),
        ),
    );
}

#[test]
fn snapshot_file_delete() {
    snap(
        "file_delete",
        &event(
            108,
            Evidence::E1,
            "linux.ebpf/lsm_path_unlink",
            EventKind::FileDelete(FileDelete::new("/tmp/placeholder.txt", Some(false))),
        ),
    );
}

#[test]
fn snapshot_file_rename() {
    snap(
        "file_rename",
        &event(
            109,
            Evidence::E1,
            "linux.ebpf/lsm_path_rename",
            EventKind::FileRename(FileRename::new("/tmp/a.txt", "/tmp/b.txt")),
        ),
    );
}

#[test]
fn snapshot_net_connect() {
    snap(
        "net_connect",
        &event(
            121,
            Evidence::E1,
            "linux.ebpf/tcp_connect",
            EventKind::NetConnect(NetConnect::new(flow(), FlowDirection::Outbound, Some(0))),
        ),
    );
}

#[test]
fn snapshot_net_send() {
    snap(
        "net_send",
        &event(
            122,
            Evidence::E1,
            "linux.ebpf/tcp_sendmsg",
            EventKind::NetSend(NetSend::new(flow(), 5240, None)),
        ),
    );
}

#[test]
fn snapshot_net_recv() {
    snap(
        "net_recv",
        &event(
            123,
            Evidence::E1,
            "linux.ebpf/tcp_recvmsg",
            EventKind::NetRecv(NetRecv::new(flow(), 1280)),
        ),
    );
}

#[test]
fn snapshot_net_close() {
    snap(
        "net_close",
        &event(
            124,
            Evidence::S,
            "poll/sockets",
            EventKind::NetClose(NetClose::new(flow(), Some(5240), Some(1280))),
        ),
    );
}

#[test]
fn snapshot_dns_query() {
    snap(
        "dns_query",
        &event(
            130,
            Evidence::E1,
            "linux.ebpf/udp_dns",
            EventKind::DnsQuery(DnsQuery::new(
                "api.example.test",
                1,
                Some(0x1a2b),
                Some(SocketAddr::ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))),
            )),
        ),
    );
}

#[test]
fn snapshot_dns_answer() {
    snap(
        "dns_answer",
        &event(
            131,
            Evidence::E1,
            "linux.ebpf/udp_dns",
            EventKind::DnsAnswer(DnsAnswer::new(
                "api.example.test",
                1,
                0,
                vec![DnsRecord {
                    rtype: 1,
                    data: "203.0.113.10".to_owned(),
                }],
                Some(60),
            )),
        ),
    );
}

#[test]
fn snapshot_tls_sni() {
    snap(
        "tls_sni",
        &event(
            132,
            Evidence::E1,
            "linux.ebpf/tls_clienthello",
            EventKind::TlsSni(TlsSni::new(
                flow(),
                "api.example.test",
                vec!["h2".to_owned(), "http/1.1".to_owned()],
            )),
        ),
    );
}

#[test]
fn snapshot_http_request() {
    snap(
        "http_request",
        &event(
            140,
            Evidence::E2,
            "proxy/http",
            EventKind::HttpRequest(HttpRequest::new(
                9,
                StdSocketAddr::from((Ipv4Addr::new(10, 0, 0, 5), 51544)),
                Some(flow()),
                "GET",
                Redacted::new("https://api.example.test/v1/item"),
                "HTTP/1.1",
                HeaderList(vec![("accept".to_owned(), "application/json".to_owned())]),
                0,
                Some(BodyDigestRef {
                    chunks: 1,
                    digest_set_id: 42,
                }),
            )),
        ),
    );
}

#[test]
fn snapshot_http_response() {
    snap(
        "http_response",
        &event(
            141,
            Evidence::E2,
            "proxy/http",
            EventKind::HttpResponse(HttpResponse::new(
                9,
                200,
                HeaderList(vec![(
                    "content-type".to_owned(),
                    "application/json".to_owned(),
                )]),
                32,
                12,
            )),
        ),
    );
}

#[test]
fn snapshot_agent_tool_call() {
    snap(
        "agent_tool_call",
        &event(
            150,
            Evidence::E3,
            "agent.example/hook",
            EventKind::AgentToolCall(AgentToolCall::new(
                "example-agent",
                Some("session-placeholder".to_owned()),
                "Read",
                ToolPhase::Pre,
                json!({"path_len": 16}),
                Some("call-1".to_owned()),
            )),
        ),
    );
}

#[test]
fn snapshot_ipc_open() {
    snap(
        "ipc_open",
        &event(
            160,
            Evidence::E1,
            "linux.ebpf/unix_stream",
            EventKind::IpcOpen(IpcOpen::new(
                IpcKind::UnixStream,
                Some(proc(0x11, 6001)),
                Some("/tmp/placeholder.sock".to_owned()),
            )),
        ),
    );
}

#[test]
fn snapshot_ipc_transfer() {
    snap(
        "ipc_transfer",
        &event(
            161,
            Evidence::E1,
            "linux.ebpf/unix_stream",
            EventKind::IpcTransfer(IpcTransfer::new(7, IpcDirection::AToB, 128)),
        ),
    );
}

#[test]
fn snapshot_ipc_close() {
    snap(
        "ipc_close",
        &event(
            162,
            Evidence::E1,
            "linux.ebpf/unix_stream",
            EventKind::IpcClose(IpcClose::new(7, Some(128), Some(64))),
        ),
    );
}

#[test]
fn snapshot_agent_rpc() {
    snap(
        "agent_rpc",
        &event(
            170,
            Evidence::E2,
            "mcp-tap/jsonrpc",
            EventKind::AgentRpc(AgentRpc::new(
                "tools/call",
                Some("echo".to_owned()),
                Some(json!({"text": {"type": "string", "len": 4}})),
                Some(48),
                Some(20),
                Some(false),
                Some(1_500_000),
            )),
        ),
    );
}

#[test]
fn snapshot_gap() {
    let ev = RawEvent::try_new(RawEventParts {
        seq: 180,
        ts_mono_ns: 9_000,
        ts_wall_ns: 1_791_273_662_000_000_000,
        session_id: Some(SessionId(7)),
        proc: None,
        source: Source::new("linux.ebpf/ringbuf"),
        evidence: Evidence::E1,
        kind: EventKind::Gap(Gap::new(
            "linux.ebpf",
            GapKind::LostByOs,
            vec!["file".to_owned(), "net".to_owned()],
            1_000,
            2_000,
            Some(3),
            Some("ring buffer overrun".to_owned()),
        )),
    })
    .expect("gap");
    snap("gap", &ev);
}

#[test]
fn file_read_without_bytes_requires_na() {
    let err = RawEvent::try_new(RawEventParts {
        seq: 1,
        ts_mono_ns: 1,
        ts_wall_ns: 1,
        session_id: None,
        proc: Some(proc(1, 2)),
        source: Source::new("macos.eslogger/open"),
        evidence: Evidence::E1,
        kind: EventKind::FileRead(FileRead::new(None, None, None, None, Some(IoVia::Syscall))),
    })
    .expect_err("bytes is required");
    let message = err.to_string();
    assert!(message.contains("bytes"), "{message}");
    assert!(message.contains("file_read"), "{message}");

    let mut ev = RawEvent {
        v: aw_core::SCHEMA_VERSION,
        seq: 1,
        ts_mono_ns: 1,
        ts_wall_ns: 1,
        session_id: None,
        proc: Some(proc(1, 2)),
        source: Source::new("macos.eslogger/open"),
        evidence: Evidence::E1,
        field_evidence: BTreeMap::new(),
        kind: EventKind::FileRead(FileRead::new(None, None, None, None, Some(IoVia::Syscall))),
    };
    ev.mark_na("bytes", NaReason::EsNoReadEvent);
    ev.check().expect("NA(es_no_read_event) satisfies bytes");
    assert_round_trip(&ev);
}

#[test]
fn ipc_open_without_peer_requires_peer_unknown() {
    let err = RawEvent::try_new(RawEventParts {
        seq: 2,
        ts_mono_ns: 2,
        ts_wall_ns: 2,
        session_id: None,
        proc: Some(proc(1, 2)),
        source: Source::new("linux.ebpf/unix_stream"),
        evidence: Evidence::E1,
        kind: EventKind::IpcOpen(IpcOpen::new(IpcKind::Pipe, None, None)),
    })
    .expect_err("peer None without NA must fail");
    assert!(err.to_string().contains("peer"), "{err}");

    let mut ev = RawEvent {
        v: aw_core::SCHEMA_VERSION,
        seq: 2,
        ts_mono_ns: 2,
        ts_wall_ns: 2,
        session_id: None,
        proc: Some(proc(1, 2)),
        source: Source::new("linux.ebpf/unix_stream"),
        evidence: Evidence::E1,
        field_evidence: BTreeMap::new(),
        kind: EventKind::IpcOpen(IpcOpen::new(IpcKind::Pipe, None, None)),
    };
    ev.mark_na("peer", NaReason::PeerUnknown);
    ev.check().expect("peer_unknown");
    let text = ev.to_json().expect("json");
    assert!(text.contains("peer_unknown"), "{text}");
    assert_round_trip(&ev);
}

#[test]
fn agent_rpc_without_target_requires_protocol_not_observed() {
    let mut ev = RawEvent {
        v: aw_core::SCHEMA_VERSION,
        seq: 3,
        ts_mono_ns: 3,
        ts_wall_ns: 3,
        session_id: None,
        proc: None,
        source: Source::new("mcp-tap/jsonrpc"),
        evidence: Evidence::E2,
        field_evidence: BTreeMap::new(),
        kind: EventKind::AgentRpc(AgentRpc::new(
            "tools/call",
            None,
            None,
            None,
            None,
            None,
            None,
        )),
    };
    assert!(ev.check().is_err());
    ev.mark_na("target", NaReason::ProtocolNotObserved);
    ev.check().expect("protocol_not_observed");
    assert_round_trip(&ev);
}

#[test]
fn unknown_fields_are_ignored() {
    let text = r#"{
        "v": 1,
        "seq": 9,
        "ts_mono_ns": 1,
        "ts_wall_ns": 1,
        "session_id": null,
        "proc": null,
        "source": "poll/procs",
        "evidence": {"level": "S"},
        "kind": "process_exit",
        "exit_code": 0,
        "signal": null,
        "future_field": "ignored"
    }"#;
    let ev = RawEvent::from_json(text).expect("unknown field ignored");
    match ev.kind {
        EventKind::ProcessExit(body) => {
            assert_eq!(body.exit_code, Some(0));
            assert_eq!(body.signal, None);
        }
        other => panic!("unexpected kind {other:?}"),
    }
}

#[test]
fn unknown_enum_variants_fall_into_unknown() {
    let text = r#"{
        "v": 1,
        "seq": 10,
        "ts_mono_ns": 1,
        "ts_wall_ns": 1,
        "session_id": null,
        "proc": null,
        "source": "linux.ebpf/sched_process_exec",
        "evidence": {"level": "NA", "reason": "some_future_reason"},
        "kind": "process_start",
        "ppid": 1,
        "parent_uid": null,
        "start_time_ns": 1,
        "exe": null,
        "argv": null,
        "cwd": null,
        "user": null,
        "how": "clone3_future",
        "env": null,
        "signer": null
    }"#;
    let ev = RawEvent::from_json(text).expect("decode");
    assert!(matches!(ev.evidence, Evidence::NA(NaReason::Unknown)));
    match ev.kind {
        EventKind::ProcessStart(body) => assert_eq!(body.how, StartHow::Unknown),
        other => panic!("unexpected {other:?}"),
    }

    let channel: IpcOpen = serde_json::from_value(json!({
        "ipc_kind": "mach_port_future",
        "peer": null,
        "name": null
    }))
    .expect("ipc kind");
    assert_eq!(channel.kind, IpcKind::Unknown);

    let gap = r#"{
        "v": 1,
        "seq": 12,
        "ts_mono_ns": 1,
        "ts_wall_ns": 1,
        "session_id": null,
        "proc": null,
        "source": "poll/procs",
        "evidence": {"level": "E1"},
        "kind": "gap",
        "collector": "poll",
        "gap_kind": "future_gap",
        "affects": [],
        "from_mono_ns": 0,
        "to_mono_ns": 1,
        "count": null,
        "detail": null
    }"#;
    let ev = RawEvent::from_json(gap).expect("gap unknown kind");
    match ev.kind {
        EventKind::Gap(body) => assert_eq!(body.gap_kind, GapKind::Unknown),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn unknown_event_kind_is_retained() {
    let text = r#"{
        "v": 1,
        "seq": 13,
        "ts_mono_ns": 4,
        "ts_wall_ns": 5,
        "session_id": null,
        "proc": null,
        "source": "future.collector/probe",
        "evidence": {"level": "E1"},
        "kind": "widget_spawned",
        "widget": "placeholder"
    }"#;
    let ev = RawEvent::from_json(text).expect("unknown kind retained");
    match &ev.kind {
        EventKind::Unknown { raw } => {
            assert_eq!(raw["kind"], "widget_spawned");
            assert_eq!(raw["widget"], "placeholder");
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
    let again = ev.to_json().expect("re-encode");
    let back = RawEvent::from_json(&again).expect("re-decode");
    assert_eq!(back.kind, ev.kind);
}

#[test]
fn mismatched_major_version_is_an_error() {
    let text = r#"{
        "v": 2,
        "seq": 1,
        "ts_mono_ns": 1,
        "ts_wall_ns": 1,
        "session_id": null,
        "proc": null,
        "source": "poll/procs",
        "evidence": {"level": "E1"},
        "kind": "process_exit",
        "exit_code": 0,
        "signal": null
    }"#;
    let err = RawEvent::from_json(text).expect_err("v=2");
    let message = err.to_string();
    assert!(message.contains('2'), "{message}");
    assert!(message.contains('1'), "{message}");
    assert!(message.contains("not supported"), "{message}");
}

#[test]
fn debug_redacts_argv_env_url_and_headers() {
    let mut env = BTreeMap::new();
    env.insert("SECRET".to_owned(), "placeholder-token".to_owned());
    let start = ProcessStart::new(
        1,
        None,
        1,
        Some("/usr/bin/example".to_owned()),
        Some(vec![
            Redacted::new("--token"),
            Redacted::new("placeholder-token"),
        ]),
        None,
        None,
        StartHow::Exec,
        Some(EnvMap(env)),
        None,
    );
    let rendered = format!("{start:?}");
    assert!(!rendered.contains("placeholder-token"), "{rendered}");
    assert!(rendered.contains("<redacted"), "{rendered}");

    let http = HttpRequest::new(
        1,
        StdSocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 9)),
        None,
        "GET",
        Redacted::new("https://secret.example/token-placeholder"),
        "HTTP/1.1",
        HeaderList(vec![(
            "authorization".to_owned(),
            "Bearer placeholder-token".to_owned(),
        )]),
        0,
        None,
    );
    let rendered = format!("{http:?}");
    assert!(!rendered.contains("token-placeholder"), "{rendered}");
    assert!(!rendered.contains("Bearer"), "{rendered}");
    assert!(rendered.contains("<redacted"), "{rendered}");
}

#[test]
fn ipv6_socket_addr_round_trips() {
    let addr = SocketAddr::socket(StdSocketAddr::from((Ipv6Addr::LOCALHOST, 443)));
    let text = serde_json::to_string(&addr).unwrap();
    assert_eq!(text, "\"[::1]:443\"");
    let back: SocketAddr = serde_json::from_str(&text).unwrap();
    assert_eq!(back, addr);
}

#[test]
fn proc_uid_is_hex() {
    let uid = ProcUid(0x9f3a_11c2_d4e5_f601);
    let text = serde_json::to_string(&uid).unwrap();
    assert_eq!(text, "\"0x9f3a11c2d4e5f601\"");
    let back: ProcUid = serde_json::from_str(&text).unwrap();
    assert_eq!(back, uid);
}
