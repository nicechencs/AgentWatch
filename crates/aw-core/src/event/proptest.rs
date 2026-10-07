//! Property test: a generated event survives JSON and comes back equal.
//!
//! Values are synthetic. Addresses stay in documentation ranges, strings are
//! short placeholders, and nothing resembles a credential.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, SocketAddr as StdSocketAddr};

use proptest::prelude::*;
use serde_json::json;

use super::enums::{
    FileAccessMode, FlowDirection, GapKind, IoVia, IpcDirection, IpcKind, L4Proto, StartHow,
    ToolPhase,
};
use super::evidence::{Evidence, NaReason};
use super::ids::{ProcRef, ProcUid, SessionId, SocketAddr, Source, UserRef};
use super::kinds::{
    AgentRpc, AgentToolCall, DnsAnswer, DnsQuery, DnsRecord, EnvMap, FileClose, FileCreate,
    FileDelete, FileOpen, FileRead, FileRename, FileWrite, FlowKey, Gap, HeaderList, HttpRequest,
    HttpResponse, IpcClose, IpcOpen, IpcTransfer, NetClose, NetConnect, NetRecv, NetSend,
    ProcessExit, ProcessStart, Redacted, TlsSni,
};
use super::raw::{EventKind, RawEvent, RawEventParts};

fn arb_na() -> impl Strategy<Value = NaReason> {
    prop_oneof![
        Just(NaReason::EsNoReadEvent),
        Just(NaReason::MmapNotObservable),
        Just(NaReason::TlsNoProxy),
        Just(NaReason::DirectBypassProxy),
        Just(NaReason::CertPinned),
        Just(NaReason::Quic),
        Just(NaReason::Ech),
        Just(NaReason::NoDnsObserved),
        Just(NaReason::Preexisting),
        Just(NaReason::CollectorUnavailable),
        Just(NaReason::Redacted),
        Just(NaReason::AttributionBreak),
        Just(NaReason::PartialClientHello),
        Just(NaReason::H2Hpack),
        Just(NaReason::TooLarge),
        Just(NaReason::FileChanged),
        Just(NaReason::PeerUnknown),
        Just(NaReason::ProtocolNotObserved),
        Just(NaReason::Unknown),
    ]
}

fn arb_evidence() -> impl Strategy<Value = Evidence> {
    prop_oneof![
        Just(Evidence::E1),
        Just(Evidence::E2),
        Just(Evidence::E3),
        Just(Evidence::S),
        Just(Evidence::I),
        arb_na().prop_map(Evidence::NA),
    ]
}

fn arb_flow() -> impl Strategy<Value = FlowKey> {
    (any::<u16>(), any::<u16>(), any::<u32>(), any::<bool>()).prop_map(|(lp, rp, id, tcp)| {
        FlowKey::new(
            if tcp { L4Proto::Tcp } else { L4Proto::Udp },
            StdSocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), lp)),
            StdSocketAddr::from((Ipv4Addr::new(198, 51, 100, 20), rp)),
            Some(u64::from(id)),
        )
    })
}

fn arb_kind() -> impl Strategy<Value = EventKind> {
    let process_start = (any::<u32>(), any::<i64>(), any::<u8>()).prop_map(|(ppid, ts, how)| {
        let how = match how % 5 {
            0 => StartHow::Fork,
            1 => StartHow::Exec,
            2 => StartHow::Spawn,
            3 => StartHow::Snapshot,
            _ => StartHow::Unknown,
        };
        EventKind::ProcessStart(ProcessStart::new(
            ppid,
            None,
            ts,
            Some("/bin/placeholder".to_owned()),
            Some(vec![Redacted::new("placeholder")]),
            Some("/tmp".to_owned()),
            Some(UserRef {
                id: "1".to_owned(),
                name: Some("placeholder".to_owned()),
            }),
            how,
            Some(EnvMap(std::collections::BTreeMap::from([(
                "LANG".to_owned(),
                "C".to_owned(),
            )]))),
            None,
        ))
    });

    let process_exit = (any::<i32>(), any::<bool>()).prop_map(|(code, signaled)| {
        EventKind::ProcessExit(ProcessExit::new(Some(code), signaled.then_some(15)))
    });

    let file_open = any::<u64>().prop_map(|handle| {
        EventKind::FileOpen(FileOpen::new(
            Some(handle),
            "/tmp/placeholder",
            FileAccessMode::Read,
            Some(false),
            Some(false),
            Some(0),
            Some(IoVia::Syscall),
            true,
        ))
    });

    let file_read = any::<u64>().prop_map(|bytes| {
        EventKind::FileRead(FileRead::new(
            Some(1),
            None,
            Some(bytes),
            Some(0),
            Some(IoVia::Syscall),
        ))
    });

    let file_write = any::<u64>().prop_map(|bytes| {
        EventKind::FileWrite(FileWrite::new(Some(1), None, Some(bytes), Some(0)))
    });

    let file_close = any::<bool>()
        .prop_map(|modified| EventKind::FileClose(FileClose::new(Some(1), None, Some(modified))));

    let file_create = any::<bool>()
        .prop_map(|dir| EventKind::FileCreate(FileCreate::new("/tmp/placeholder", dir)));

    let file_delete = any::<bool>()
        .prop_map(|dir| EventKind::FileDelete(FileDelete::new("/tmp/placeholder", Some(dir))));

    let file_rename = Just(EventKind::FileRename(FileRename::new("/tmp/a", "/tmp/b")));

    let net_connect = arb_flow().prop_map(|flow| {
        EventKind::NetConnect(NetConnect::new(flow, FlowDirection::Outbound, Some(0)))
    });
    let net_send = (arb_flow(), any::<u64>()).prop_map(|(flow, bytes)| {
        EventKind::NetSend(NetSend::new(flow, bytes, Some(IoVia::Syscall)))
    });
    let net_recv = (arb_flow(), any::<u64>())
        .prop_map(|(flow, bytes)| EventKind::NetRecv(NetRecv::new(flow, bytes)));
    let net_close =
        arb_flow().prop_map(|flow| EventKind::NetClose(NetClose::new(flow, Some(1), Some(2))));

    let dns_query = any::<u16>().prop_map(|qtype| {
        EventKind::DnsQuery(DnsQuery::new(
            "example.test",
            qtype,
            Some(1),
            Some(SocketAddr::ip(std::net::IpAddr::V4(Ipv4Addr::new(
                1, 1, 1, 1,
            )))),
        ))
    });
    let dns_answer = any::<u16>().prop_map(|rcode| {
        EventKind::DnsAnswer(DnsAnswer::new(
            "example.test",
            1,
            rcode,
            vec![DnsRecord {
                rtype: 1,
                data: "203.0.113.10".to_owned(),
            }],
            Some(30),
        ))
    });
    let tls = arb_flow().prop_map(|flow| {
        EventKind::TlsSni(TlsSni::new(flow, "example.test", vec!["h2".to_owned()]))
    });

    let http_req = any::<u64>().prop_map(|id| {
        EventKind::HttpRequest(HttpRequest::new(
            id,
            StdSocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 9)),
            None,
            "GET",
            Redacted::new("https://example.test/placeholder"),
            "HTTP/1.1",
            HeaderList(vec![("accept".to_owned(), "*/*".to_owned())]),
            0,
            None,
        ))
    });
    let http_resp = any::<u16>().prop_map(|status| {
        EventKind::HttpResponse(HttpResponse::new(1, status, HeaderList(vec![]), 0, 1))
    });

    let tool = any::<bool>().prop_map(|pre| {
        EventKind::AgentToolCall(AgentToolCall::new(
            "example-agent",
            None,
            "Read",
            if pre { ToolPhase::Pre } else { ToolPhase::Post },
            json!({"n": 1}),
            None,
        ))
    });

    let ipc_open = Just(EventKind::IpcOpen(IpcOpen::new(
        IpcKind::Pipe,
        Some(ProcRef {
            uid: ProcUid(1),
            pid: 2,
            tid: None,
        }),
        Some("placeholder".to_owned()),
    )));
    let ipc_transfer = any::<u64>()
        .prop_map(|bytes| EventKind::IpcTransfer(IpcTransfer::new(1, IpcDirection::AToB, bytes)));
    let ipc_close =
        any::<u64>().prop_map(|n| EventKind::IpcClose(IpcClose::new(1, Some(n), Some(n))));
    let rpc = Just(EventKind::AgentRpc(AgentRpc::new(
        "tools/call",
        Some("echo".to_owned()),
        Some(json!({"text": {"type": "string", "len": 1}})),
        Some(1),
        Some(1),
        Some(false),
        Some(1),
    )));
    let gap = Just(EventKind::Gap(Gap::new(
        "poll",
        GapKind::Dropped,
        vec!["net".to_owned()],
        0,
        1,
        Some(1),
        None,
    )));

    prop_oneof![
        process_start,
        process_exit,
        file_open,
        file_read,
        file_write,
        file_close,
        file_create,
        file_delete,
        file_rename,
        net_connect,
        net_send,
        net_recv,
        net_close,
        dns_query,
        dns_answer,
        tls,
        http_req,
        http_resp,
        tool,
        ipc_open,
        ipc_transfer,
        ipc_close,
        rpc,
        gap,
    ]
}

fn arb_event() -> impl Strategy<Value = RawEvent> {
    (
        any::<u64>(),
        any::<u64>(),
        any::<i64>(),
        arb_evidence(),
        arb_kind(),
    )
        .prop_map(|(seq, mono, wall, evidence, kind)| {
            RawEvent::try_new(RawEventParts {
                seq,
                ts_mono_ns: mono,
                ts_wall_ns: wall,
                session_id: Some(SessionId(1)),
                proc: Some(ProcRef {
                    uid: ProcUid(0xabc),
                    pid: 10,
                    tid: Some(11),
                }),
                source: Source::new("poll/procs"),
                evidence,
                kind,
            })
            .expect("generated event satisfies required-field rules")
        })
}

proptest! {
    #[test]
    fn schema_roundtrip(event in arb_event()) {
        let text = event.to_json().expect("serialize");
        let back = RawEvent::from_json(&text).expect("deserialize");
        prop_assert_eq!(back, event);
    }
}
