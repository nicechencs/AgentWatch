//! P1-PIPE-06: synthetic DNS streams through the default public replay chain.
//! All names and addresses are reserved test data; no network or host state is read.

#![allow(clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use aw_core::{
    DnsAnswer, DnsQuery, DnsRecord, EventKind, Evidence, FlowDirection, FlowKey, L4Proto, NaReason,
    NetClose, NetConnect, NetRecv, NetSend, ProcRef, ProcUid, RawEvent, RawEventParts, SessionId,
    Source, TlsSni,
};
use aw_pipeline::{NetFlowRec, Output, Pipeline, PipelineConfig};

const SECOND: u64 = 1_000_000_000;
const REMOTE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const RESOLVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

#[derive(Clone, Copy)]
struct Actor {
    session: Option<SessionId>,
    uid: Option<ProcUid>,
}

const OWNER: Actor = Actor {
    session: Some(SessionId(1)),
    uid: Some(ProcUid(11)),
};
const PEER: Actor = Actor {
    session: Some(SessionId(1)),
    uid: Some(ProcUid(12)),
};
const GLOBAL: Actor = Actor {
    session: None,
    uid: None,
};

fn event(seq: u64, at: u64, actor: Actor, evidence: Evidence, kind: EventKind) -> RawEvent {
    let source = Source::new(format!("synthetic/{}", kind.kind_name()));
    RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns: at,
        // Deliberately unrelated to monotonic time: TTL must not use wall time.
        ts_wall_ns: 1_700_000_000_000_000_000,
        session_id: actor.session,
        // Reuse the OS pid across actors to exercise ProcUid, not pid, matching.
        proc: actor.uid.map(|uid| ProcRef {
            uid,
            pid: 100,
            tid: None,
        }),
        source,
        evidence,
        kind,
    })
    .expect("valid synthetic DNS or network event")
}

fn query(seq: u64, at: u64, actor: Actor, name: &str, evidence: Evidence) -> RawEvent {
    event(
        seq,
        at,
        actor,
        evidence,
        EventKind::DnsQuery(DnsQuery::new(
            name,
            1,
            Some(7),
            Some(SocketAddr::new(IpAddr::V4(RESOLVER), 53).into()),
        )),
    )
}

fn answer(
    seq: u64,
    at: u64,
    actor: Actor,
    name: &str,
    ttl: Option<u32>,
    evidence: Evidence,
) -> RawEvent {
    event(
        seq,
        at,
        actor,
        evidence,
        EventKind::DnsAnswer(DnsAnswer::new(
            name,
            1,
            0,
            vec![DnsRecord {
                rtype: 1,
                data: REMOTE.to_string(),
            }],
            ttl,
        )),
    )
}

fn flow(port: u16) -> FlowKey {
    FlowKey::new(
        L4Proto::Tcp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), port),
        SocketAddr::new(IpAddr::V4(REMOTE), 443),
        Some(u64::from(port)),
    )
}

fn connect(seq: u64, at: u64, actor: Actor, port: u16, evidence: Evidence) -> RawEvent {
    event(
        seq,
        at,
        actor,
        evidence,
        EventKind::NetConnect(NetConnect::new(
            flow(port),
            FlowDirection::Outbound,
            Some(0),
        )),
    )
}

fn close(seq: u64, at: u64, actor: Actor, port: u16, evidence: Evidence) -> RawEvent {
    event(
        seq,
        at,
        actor,
        evidence,
        EventKind::NetClose(NetClose::new(flow(port), None, None)),
    )
}

fn replay(events: Vec<RawEvent>) -> Output {
    Pipeline::replay(events, PipelineConfig::default())
}

fn final_flow(out: &Output, port: u16) -> &NetFlowRec {
    let mut rows = out
        .net_flows
        .iter()
        .filter(|row| row.local_port == Some(port) && !row.partial);
    let row = rows.next().expect("one final flow for this connection");
    assert!(
        rows.next().is_none(),
        "connection emitted duplicate final rows"
    );
    row
}

fn assert_domain(row: &NetFlowRec, name: Option<&str>, grade: Evidence) {
    assert_eq!(row.domain.as_deref(), name);
    assert_eq!(
        row.field_evidence.get("domain").unwrap_or(&row.evidence),
        &grade
    );
    if name.is_none() {
        assert_eq!(row.domain_source, None);
        assert_eq!(row.field_evidence.get("domain"), Some(&grade));
    }
}

#[test]
fn same_process_dns_reaches_final_flow_and_query_answer_merge_once() {
    let out = replay(vec![
        query(1, SECOND, OWNER, "own.agentwatch.test", Evidence::E1),
        answer(
            2,
            2 * SECOND,
            OWNER,
            "own.agentwatch.test",
            Some(30),
            Evidence::E1,
        ),
        connect(3, 3 * SECOND, OWNER, 41001, Evidence::S),
        event(
            4,
            3 * SECOND + 1,
            OWNER,
            Evidence::S,
            EventKind::NetSend(NetSend::new(flow(41001), 17, None)),
        ),
        event(
            5,
            3 * SECOND + 2,
            OWNER,
            Evidence::S,
            EventKind::NetRecv(NetRecv::new(flow(41001), 23)),
        ),
        close(6, 4 * SECOND, OWNER, 41001, Evidence::E1),
    ]);

    assert_eq!(out.dns.len(), 1, "query and answer must form one DNS row");
    let dns = &out.dns[0];
    assert_eq!(dns.session_id, OWNER.session);
    assert_eq!(dns.proc_uid, OWNER.uid);
    assert_eq!(dns.ts_ns, SECOND);
    assert_eq!(dns.qname, "own.agentwatch.test");
    assert_eq!(dns.qtype, 1);
    assert_eq!(dns.rcode, Some(0));
    assert_eq!(dns.answers, vec!["1 192.0.2.10"]);
    assert_eq!(dns.ttl_min, Some(30));
    assert_eq!(dns.server.as_deref(), Some("192.0.2.53:53"));
    assert_eq!(dns.evidence, Evidence::E1);
    assert_eq!(dns.source.as_str(), "synthetic/dns_answer");

    let row = final_flow(&out, 41001);
    assert_domain(row, Some("own.agentwatch.test"), Evidence::E1);
    assert!(row.domain_source.is_some());
    assert_ne!(row.domain_source.as_deref(), Some("sni"));
    assert_eq!(row.sni, None, "DNS must not manufacture an observed SNI");
    assert_eq!(
        row.evidence,
        Evidence::S,
        "opening event owns record evidence"
    );
    assert_eq!(row.source.as_str(), "synthetic/net_connect");
    assert_eq!(row.session_id, OWNER.session);
    assert_eq!(row.proc_uid, OWNER.uid);
    assert_eq!(row.bytes_up, Some(17));
    assert_eq!(row.bytes_down, Some(23));
    assert_eq!(row.start_ns, 3 * SECOND);
    assert_eq!(row.end_ns, Some(4 * SECOND));
}

#[test]
fn same_session_peer_and_global_dns_are_inferences() {
    for (resolver, name) in [
        (PEER, "peer.agentwatch.test"),
        (GLOBAL, "global.agentwatch.test"),
    ] {
        let out = replay(vec![
            answer(1, SECOND, resolver, name, Some(30), Evidence::E1),
            connect(2, 2 * SECOND, OWNER, 41002, Evidence::E1),
            close(3, 3 * SECOND, OWNER, 41002, Evidence::E1),
        ]);
        assert_eq!(out.dns.len(), 1);
        let row = final_flow(&out, 41002);
        assert_domain(row, Some(name), Evidence::I);
        assert!(row.domain_source.is_some());
        assert_eq!(row.sni, None);
        assert_eq!(row.evidence, Evidence::E1);
    }
}

#[test]
fn own_dns_then_session_peer_take_priority_over_newer_global_dns() {
    let out = replay(vec![
        answer(
            1,
            SECOND,
            OWNER,
            "own.agentwatch.test",
            Some(1),
            Evidence::E1,
        ),
        answer(
            2,
            SECOND + 1,
            PEER,
            "peer.agentwatch.test",
            Some(30),
            Evidence::E1,
        ),
        answer(
            3,
            SECOND + 2,
            GLOBAL,
            "global.agentwatch.test",
            Some(30),
            Evidence::E1,
        ),
        connect(4, SECOND + 3, OWNER, 41003, Evidence::E1),
        close(5, SECOND + 4, OWNER, 41003, Evidence::E1),
        connect(6, 2 * SECOND, OWNER, 41004, Evidence::E1),
        close(7, 2 * SECOND + 1, OWNER, 41004, Evidence::E1),
    ]);
    assert_domain(
        final_flow(&out, 41003),
        Some("own.agentwatch.test"),
        Evidence::E1,
    );
    assert_domain(
        final_flow(&out, 41004),
        Some("peer.agentwatch.test"),
        Evidence::I,
    );
    assert_eq!(out.dns.len(), 3);
}

#[test]
fn ttl_is_half_open_and_does_not_erase_the_domain_of_an_existing_flow() {
    let out = replay(vec![
        answer(
            1,
            SECOND,
            OWNER,
            "ttl.agentwatch.test",
            Some(1),
            Evidence::E1,
        ),
        connect(2, 2 * SECOND - 1, OWNER, 41005, Evidence::E1),
        connect(3, 2 * SECOND, OWNER, 41006, Evidence::E1),
        close(4, 2 * SECOND + 1, OWNER, 41005, Evidence::E1),
        close(5, 2 * SECOND + 2, OWNER, 41006, Evidence::E1),
    ]);
    assert_domain(
        final_flow(&out, 41005),
        Some("ttl.agentwatch.test"),
        Evidence::E1,
    );
    assert_domain(
        final_flow(&out, 41006),
        None,
        Evidence::NA(NaReason::NoDnsObserved),
    );
    assert_eq!(out.dns.len(), 1, "ticks must not re-emit drained DNS rows");
}

#[test]
fn no_answer_query_only_and_non_address_answers_remain_na() {
    let mut cname = answer(
        2,
        2 * SECOND,
        OWNER,
        "alias.agentwatch.test",
        Some(30),
        Evidence::E1,
    );
    if let EventKind::DnsAnswer(ref mut payload) = cname.kind {
        payload.answers = vec![DnsRecord {
            rtype: 5,
            data: "target.agentwatch.test".to_owned(),
        }];
    }
    for events in [
        vec![],
        vec![query(
            1,
            SECOND,
            OWNER,
            "pending.agentwatch.test",
            Evidence::E1,
        )],
        vec![cname],
    ] {
        let mut events = events;
        events.push(connect(3, 3 * SECOND, OWNER, 41007, Evidence::E1));
        events.push(close(4, 4 * SECOND, OWNER, 41007, Evidence::E1));
        let out = replay(events);
        let row = final_flow(&out, 41007);
        assert_domain(row, None, Evidence::NA(NaReason::NoDnsObserved));
        assert_eq!(row.sni, None);
        assert_eq!(row.evidence, Evidence::E1);
    }
}

#[test]
fn sampled_self_reported_and_inferred_dns_keep_their_source_evidence() {
    for grade in [Evidence::S, Evidence::E3, Evidence::I] {
        let out = replay(vec![
            query(1, SECOND, OWNER, "weak.agentwatch.test", Evidence::E1),
            answer(
                2,
                2 * SECOND,
                OWNER,
                "weak.agentwatch.test",
                Some(30),
                grade.clone(),
            ),
            connect(3, 3 * SECOND, OWNER, 41008, Evidence::E1),
            close(4, 4 * SECOND, OWNER, 41008, Evidence::E1),
        ]);
        assert_eq!(out.dns.len(), 1);
        assert_eq!(out.dns[0].evidence, grade);
        let row = final_flow(&out, 41008);
        assert_domain(row, Some("weak.agentwatch.test"), grade);
        assert_eq!(row.evidence, Evidence::E1);
    }
}

#[test]
fn dns_enrichment_does_not_upgrade_sampled_self_reported_or_inferred_flows() {
    for grade in [Evidence::S, Evidence::E3, Evidence::I] {
        let out = replay(vec![
            answer(
                1,
                SECOND,
                OWNER,
                "own.agentwatch.test",
                Some(30),
                Evidence::E1,
            ),
            connect(2, 2 * SECOND, OWNER, 41009, grade.clone()),
            close(3, 3 * SECOND, OWNER, 41009, Evidence::E1),
        ]);
        let row = final_flow(&out, 41009);
        assert_domain(row, Some("own.agentwatch.test"), Evidence::E1);
        assert_eq!(row.evidence, grade);
    }
}

#[test]
fn unknown_ttl_cannot_become_a_fresh_same_process_e1_match() {
    let out = replay(vec![
        answer(
            1,
            SECOND,
            OWNER,
            "unknown-ttl.agentwatch.test",
            None,
            Evidence::E1,
        ),
        connect(2, 2 * SECOND, OWNER, 41010, Evidence::E1),
        close(3, 3 * SECOND, OWNER, 41010, Evidence::E1),
    ]);
    assert_eq!(out.dns[0].ttl_min, None);
    assert_domain(
        final_flow(&out, 41010),
        Some("unknown-ttl.agentwatch.test"),
        Evidence::I,
    );
}

#[test]
fn sni_overrides_dns_and_keeps_its_value_and_evidence() {
    for grade in [Evidence::E1, Evidence::S, Evidence::E3, Evidence::I] {
        let out = replay(vec![
            answer(
                1,
                SECOND,
                OWNER,
                "dns.agentwatch.test",
                Some(30),
                Evidence::E1,
            ),
            connect(2, 2 * SECOND, OWNER, 41011, Evidence::E1),
            event(
                3,
                2 * SECOND + 1,
                OWNER,
                grade.clone(),
                EventKind::TlsSni(TlsSni::new(
                    flow(41011),
                    "sni.agentwatch.test",
                    vec!["h2".to_owned()],
                )),
            ),
            // Later DNS input cannot replace this flow's observed SNI.
            answer(
                4,
                2 * SECOND + 2,
                OWNER,
                "later.agentwatch.test",
                Some(30),
                Evidence::E1,
            ),
            close(5, 3 * SECOND, OWNER, 41011, Evidence::E1),
        ]);
        let row = final_flow(&out, 41011);
        assert_domain(row, Some("sni.agentwatch.test"), grade.clone());
        assert_eq!(row.sni.as_deref(), Some("sni.agentwatch.test"));
        assert_eq!(row.domain_source.as_deref(), Some("sni"));
        assert_eq!(
            row.field_evidence.get("sni").unwrap_or(&row.evidence),
            &grade
        );
        assert_eq!(row.evidence, Evidence::E1);
        assert_eq!(out.dns.len(), 2);
    }
}

#[test]
fn process_scoped_dns_does_not_cross_sessions_even_with_the_same_proc_uid() {
    for uid in [OWNER.uid, PEER.uid] {
        let other_session = Actor {
            session: Some(SessionId(2)),
            uid,
        };
        let out = replay(vec![
            query(
                1,
                SECOND,
                other_session,
                "isolated.agentwatch.test",
                Evidence::E1,
            ),
            answer(
                2,
                2 * SECOND,
                other_session,
                "isolated.agentwatch.test",
                Some(30),
                Evidence::E1,
            ),
            connect(3, 3 * SECOND, OWNER, 41012, Evidence::E1),
            close(4, 4 * SECOND, OWNER, 41012, Evidence::E1),
        ]);
        assert_domain(
            final_flow(&out, 41012),
            None,
            Evidence::NA(NaReason::NoDnsObserved),
        );
        assert_eq!(out.dns[0].session_id, other_session.session);
    }
}

#[test]
fn future_answer_cannot_influence_an_earlier_connection_in_replay_order() {
    // Input order is deliberately different from event time. The answer is already
    // in the cache when the earlier connect arrives, but is not historical to it.
    let out = replay(vec![
        answer(
            1,
            4 * SECOND,
            OWNER,
            "future.agentwatch.test",
            Some(30),
            Evidence::E1,
        ),
        connect(2, 2 * SECOND, OWNER, 41013, Evidence::E1),
        close(3, 3 * SECOND, OWNER, 41013, Evidence::E1),
    ]);
    assert_domain(
        final_flow(&out, 41013),
        None,
        Evidence::NA(NaReason::NoDnsObserved),
    );
}

#[test]
fn answer_after_connect_does_not_retroactively_fill_a_flow() {
    let out = replay(vec![
        query(1, SECOND, OWNER, "late.agentwatch.test", Evidence::E1),
        connect(2, 2 * SECOND, OWNER, 41014, Evidence::E1),
        answer(
            3,
            3 * SECOND,
            OWNER,
            "late.agentwatch.test",
            Some(30),
            Evidence::E1,
        ),
        close(4, 4 * SECOND, OWNER, 41014, Evidence::E1),
        connect(5, 4 * SECOND + 1, OWNER, 41015, Evidence::E1),
        close(6, 4 * SECOND + 2, OWNER, 41015, Evidence::E1),
    ]);
    assert_domain(
        final_flow(&out, 41014),
        None,
        Evidence::NA(NaReason::NoDnsObserved),
    );
    assert_domain(
        final_flow(&out, 41015),
        Some("late.agentwatch.test"),
        Evidence::E1,
    );
    assert_eq!(out.dns.len(), 1);
}

#[test]
fn continuous_answers_expire_and_dns_rows_are_drained_once_deterministically() {
    let mut events = Vec::new();
    let mut seq = 1;
    for index in 0_u16..32 {
        let at = (u64::from(index) * 3 + 1) * SECOND;
        let port = 42000 + index * 2;
        let name = format!("cycle-{index}.agentwatch.test");
        events.push(query(seq, at, OWNER, &name, Evidence::E1));
        events.push(answer(seq + 1, at + 1, OWNER, &name, Some(1), Evidence::E1));
        events.push(connect(seq + 2, at + 2, OWNER, port, Evidence::E1));
        events.push(close(seq + 3, at + 3, OWNER, port, Evidence::E1));
        events.push(connect(
            seq + 4,
            at + SECOND + 1,
            OWNER,
            port + 1,
            Evidence::E1,
        ));
        events.push(close(
            seq + 5,
            at + SECOND + 2,
            OWNER,
            port + 1,
            Evidence::E1,
        ));
        seq += 6;
    }
    let first = replay(events.clone());
    let second = replay(events);
    assert_eq!(first, second, "all final output must be deterministic");
    assert_eq!(first.dns.len(), 32);
    assert_eq!(first.net_flows.len(), 64);
    for index in 0_u16..32 {
        let port = 42000 + index * 2;
        let name = format!("cycle-{index}.agentwatch.test");
        assert_domain(final_flow(&first, port), Some(&name), Evidence::E1);
        assert_domain(
            final_flow(&first, port + 1),
            None,
            Evidence::NA(NaReason::NoDnsObserved),
        );
        assert_eq!(first.dns[usize::from(index)].qname, name);
    }
}

#[test]
fn unanswered_queries_finish_as_single_rows_without_inventing_answers() {
    let events = vec![
        query(1, SECOND, OWNER, "pending-own.agentwatch.test", Evidence::S),
        query(
            2,
            SECOND,
            PEER,
            "pending-peer.agentwatch.test",
            Evidence::E3,
        ),
        query(
            3,
            SECOND,
            GLOBAL,
            "pending-global.agentwatch.test",
            Evidence::I,
        ),
        connect(4, 2 * SECOND, OWNER, 41016, Evidence::E1),
        close(5, 3 * SECOND, OWNER, 41016, Evidence::E1),
    ];
    let first = replay(events.clone());
    assert_eq!(first, replay(events));
    assert_eq!(first.dns.len(), 3);
    for (actor, name, grade) in [
        (OWNER, "pending-own.agentwatch.test", Evidence::S),
        (PEER, "pending-peer.agentwatch.test", Evidence::E3),
        (GLOBAL, "pending-global.agentwatch.test", Evidence::I),
    ] {
        let rows: Vec<_> = first.dns.iter().filter(|row| row.qname == name).collect();
        assert_eq!(rows.len(), 1);
        let row = rows[0];
        assert_eq!(row.session_id, actor.session);
        assert_eq!(row.proc_uid, actor.uid);
        assert_eq!(row.ts_ns, SECOND);
        assert_eq!(row.rcode, None);
        assert!(row.answers.is_empty());
        assert_eq!(row.ttl_min, None);
        assert_eq!(row.server.as_deref(), Some("192.0.2.53:53"));
        assert_eq!(row.evidence, grade);
        assert_eq!(row.source.as_str(), "synthetic/dns_query");
    }
    assert_domain(
        final_flow(&first, 41016),
        None,
        Evidence::NA(NaReason::NoDnsObserved),
    );
}

#[test]
fn dns_field_evidence_is_not_upgraded_by_an_e1_event_envelope() {
    for field in ["qname", "answers"] {
        for grade in [Evidence::S, Evidence::E3, Evidence::I] {
            let mut dns = answer(
                1,
                SECOND,
                OWNER,
                "field.agentwatch.test",
                Some(30),
                Evidence::E1,
            );
            dns.field_evidence.insert(field.to_owned(), grade.clone());
            let out = replay(vec![
                dns,
                connect(2, 2 * SECOND, OWNER, 41017, Evidence::E1),
                close(3, 3 * SECOND, OWNER, 41017, Evidence::E1),
            ]);
            let row = final_flow(&out, 41017);
            assert_domain(row, Some("field.agentwatch.test"), grade);
            assert_eq!(row.evidence, Evidence::E1);
            assert_eq!(row.sni, None);
        }
    }
}

#[test]
fn sni_field_evidence_is_not_upgraded_by_an_e1_event_envelope() {
    for grade in [Evidence::S, Evidence::E3, Evidence::I] {
        let mut sni = event(
            2,
            2 * SECOND,
            OWNER,
            Evidence::E1,
            EventKind::TlsSni(TlsSni::new(
                flow(41018),
                "field-sni.agentwatch.test",
                vec![],
            )),
        );
        sni.field_evidence.insert("sni".to_owned(), grade.clone());
        let out = replay(vec![
            connect(1, SECOND, OWNER, 41018, Evidence::E1),
            sni,
            close(3, 3 * SECOND, OWNER, 41018, Evidence::E1),
        ]);
        let row = final_flow(&out, 41018);
        assert_domain(row, Some("field-sni.agentwatch.test"), grade.clone());
        assert_eq!(row.sni.as_deref(), Some("field-sni.agentwatch.test"));
        assert_eq!(
            row.field_evidence.get("sni").unwrap_or(&row.evidence),
            &grade
        );
        assert_eq!(row.evidence, Evidence::E1);
        assert!(out.dns.is_empty());
    }
}
