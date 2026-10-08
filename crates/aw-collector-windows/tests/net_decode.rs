//! Replay of hand-written Kernel-Network and DNS-Client fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//!
//! The files under `fixtures/net/` are not an ETW recording. SPIKE-02 was not
//! run elevated, and this process is not an administrator, so there is no
//! captured session to put here. Each line uses the property names from
//! windows.md §2.3 and §2.4. A property the line omits is absent — the decoder
//! must mark it `NA(collector_unavailable)`, not invent a zero.
//!
//! The 1 s window is driven by the timestamps in the test, not by the clock.

use std::net::IpAddr;
use std::path::PathBuf;

use aw_collector_windows::etw::{
    decode_dns, decode_network, flush_due, normalize_ip, DecodeClock, DecodedDns, DecodedNetwork,
    DnsAnswerCache, DnsProperties, FlowPreAgg, NetworkProperties, AGGREGATE_WINDOW_NS,
    PID_ATTRIBUTION_NOTE, PID_FIELD, SOURCE_DNS_CLIENT, SOURCE_KERNEL_NETWORK,
};
use aw_core::{EventKind, Evidence, FlowDirection, L4Proto, NaReason};

fn fixture(name: &str) -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("net");
    path.push(name);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

fn net_from_line(line: &str) -> (NetworkProperties, DecodeClock, u64) {
    let event_id = u64_key(line, "event_id").expect("event_id") as u16;
    let mut props = NetworkProperties::bare(event_id);
    props.pid = u64_key(line, "pid").map(|n| n as u32);
    props.size = u64_key(line, "size");
    props.saddr = ip_key(line, "saddr");
    props.sport = u64_key(line, "sport").map(|n| n as u16);
    props.daddr = ip_key(line, "daddr");
    props.dport = u64_key(line, "dport").map(|n| n as u16);
    props.connid = u64_key(line, "connid");
    props.mss = u64_key(line, "mss").map(|n| n as u32);
    props.tid = u64_key(line, "tid").map(|n| n as u32);
    let clock = DecodeClock {
        ts_mono_ns: u64_key(line, "ts_mono_ns").expect("ts_mono_ns"),
        ts_wall_ns: i64_key(line, "ts_wall_ns"),
    };
    let seq = u64_key(line, "seq").expect("seq");
    (props, clock, seq)
}

fn dns_from_line(line: &str) -> (DnsProperties, DecodeClock, u64) {
    let event_id = u64_key(line, "event_id").expect("event_id") as u16;
    let mut props = DnsProperties::bare(event_id);
    props.header_pid = u64_key(line, "header_pid").map(|n| n as u32);
    props.query_name = string_key(line, "query_name");
    props.query_type = u64_key(line, "query_type").map(|n| n as u16);
    props.query_status = u64_key(line, "query_status").map(|n| n as u32);
    props.query_results = string_key(line, "query_results");
    let clock = DecodeClock {
        ts_mono_ns: u64_key(line, "ts_mono_ns").expect("ts_mono_ns"),
        ts_wall_ns: i64_key(line, "ts_wall_ns"),
    };
    let seq = u64_key(line, "seq").expect("seq");
    (props, clock, seq)
}

fn ip_key(line: &str, key: &str) -> Option<IpAddr> {
    let text = string_key(line, key)?;
    Some(
        text.parse()
            .unwrap_or_else(|_| panic!("{key} is not an ip")),
    )
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
    Some(inner.to_owned())
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

fn clock_at(mono: u64) -> DecodeClock {
    DecodeClock {
        ts_mono_ns: mono,
        ts_wall_ns: Some(1_700_000_000_000_000_000),
    }
}

fn tcp_send(size: u64, mono: u64) -> NetworkProperties {
    let mut props = NetworkProperties::bare(10);
    props.pid = Some(100);
    props.size = Some(size);
    props.saddr = Some("10.0.0.2".parse().unwrap());
    props.sport = Some(40000);
    props.daddr = Some("93.184.216.34".parse().unwrap());
    props.dport = Some(443);
    props.connid = Some(7);
    let _ = mono;
    props
}

#[test]
fn normalize_mapped_ipv6_to_ipv4() {
    let mapped: IpAddr = "::ffff:93.184.216.34".parse().unwrap();
    assert_eq!(
        normalize_ip(mapped),
        "93.184.216.34".parse::<IpAddr>().unwrap()
    );
    let real: IpAddr = "2001:db8::2".parse().unwrap();
    assert_eq!(normalize_ip(real), real);
    let v4: IpAddr = "10.0.0.2".parse().unwrap();
    assert_eq!(normalize_ip(v4), v4);
}

#[test]
fn replay_ipv6_tcp_send_keeps_v6() {
    let line = fixture("tcp_send_v6.jsonl");
    let (props, clock, seq) = net_from_line(line.trim());
    let mut agg = FlowPreAgg::new();
    let decoded = decode_network(&props, seq, clock, &mut agg);
    assert!(matches!(decoded, DecodedNetwork::Aggregated));
    let mut flushed = agg.flush_all();
    assert_eq!(flushed.len(), 1);
    let event = flushed.pop().unwrap();
    assert_eq!(event.source.as_str(), SOURCE_KERNEL_NETWORK);
    assert_eq!(event.evidence, Evidence::E1);
    match event.kind {
        EventKind::NetSend(body) => {
            assert_eq!(body.bytes, 40);
            assert_eq!(body.flow.proto, L4Proto::Tcp);
            assert_eq!(body.flow.local.to_string(), "[2001:db8::1]:40000");
            assert_eq!(body.flow.remote.to_string(), "[2001:db8::2]:443");
            assert_eq!(body.flow.sock_id, Some(9));
        }
        other => panic!("expected net_send, got {other:?}"),
    }
}

#[test]
fn replay_ipv4_mapped_normalizes_before_store() {
    let line = fixture("tcp_send_v4_mapped.jsonl");
    let (props, clock, seq) = net_from_line(line.trim());
    let mut agg = FlowPreAgg::new();
    assert!(matches!(
        decode_network(&props, seq, clock, &mut agg),
        DecodedNetwork::Aggregated
    ));
    let event = agg.flush_all().pop().unwrap();
    match event.kind {
        EventKind::NetSend(body) => {
            assert_eq!(body.bytes, 15);
            // The event id was the IPv6 send (26). The addresses were mapped
            // and must come out as IPv4, not as ::ffff:…
            assert_eq!(body.flow.local.to_string(), "10.0.0.2:40000");
            assert_eq!(body.flow.remote.to_string(), "93.184.216.34:443");
        }
        other => panic!("expected net_send, got {other:?}"),
    }
}

#[test]
fn mapped_and_plain_ipv4_share_one_window() {
    let mut agg = FlowPreAgg::new();
    let plain = tcp_send(20, 0);
    let mut mapped = tcp_send(15, 0);
    mapped.saddr = Some("::ffff:10.0.0.2".parse().unwrap());
    mapped.daddr = Some("::ffff:93.184.216.34".parse().unwrap());
    let clock = clock_at(1_000_000_000);
    assert!(matches!(
        decode_network(&plain, 1, clock, &mut agg),
        DecodedNetwork::Aggregated
    ));
    assert!(matches!(
        decode_network(&mapped, 2, clock, &mut agg),
        DecodedNetwork::Aggregated
    ));
    assert_eq!(agg.pending(), 1);
    let event = agg.flush_all().pop().unwrap();
    match event.kind {
        EventKind::NetSend(body) => assert_eq!(body.bytes, 35),
        other => panic!("expected net_send, got {other:?}"),
    }
}

#[test]
fn same_second_sends_merge_next_second_does_not() {
    let mut agg = FlowPreAgg::new();
    let first = tcp_send(20, 0);
    let second = tcp_send(30, 0);
    // 1.10s and 1.90s are the same window. 2.10s is the next one.
    let t1 = clock_at(1_100_000_000);
    let t2 = clock_at(1_900_000_000);
    let t3 = clock_at(2_100_000_000);
    assert!(matches!(
        decode_network(&first, 1, t1, &mut agg),
        DecodedNetwork::Aggregated
    ));
    assert!(matches!(
        decode_network(&second, 2, t2, &mut agg),
        DecodedNetwork::Aggregated
    ));
    assert_eq!(agg.pending(), 1);
    let decoded = decode_network(&tcp_send(7, 0), 3, t3, &mut agg);
    let DecodedNetwork::Emitted(events) = decoded else {
        panic!("crossing the window must flush the previous second");
    };
    assert_eq!(events.len(), 1);
    match &events[0].kind {
        EventKind::NetSend(body) => {
            assert_eq!(body.bytes, 50);
            assert_eq!(events[0].ts_mono_ns, t1.ts_mono_ns);
            assert_eq!(events[0].seq, 1);
        }
        other => panic!("expected net_send, got {other:?}"),
    }
    // The new window is still open and holds only the third send.
    assert_eq!(agg.pending(), 1);
    let rest = agg.flush_all().pop().unwrap();
    match rest.kind {
        EventKind::NetSend(body) => {
            assert_eq!(body.bytes, 7);
            assert_eq!(rest.seq, 3);
            assert_eq!(rest.ts_mono_ns, t3.ts_mono_ns);
        }
        other => panic!("expected net_send, got {other:?}"),
    }
    let _ = AGGREGATE_WINDOW_NS;
}

#[test]
fn flush_due_emits_a_quiet_window_without_reading_a_clock() {
    let mut agg = FlowPreAgg::new();
    let clock = clock_at(500_000_000);
    assert!(matches!(
        decode_network(&tcp_send(8, 0), 1, clock, &mut agg),
        DecodedNetwork::Aggregated
    ));
    // Still inside the same second: nothing is due.
    assert!(flush_due(&mut agg, 900_000_000).is_empty());
    let due = flush_due(&mut agg, 1_000_000_000);
    assert_eq!(due.len(), 1);
    match &due[0].kind {
        EventKind::NetSend(body) => assert_eq!(body.bytes, 8),
        other => panic!("expected net_send, got {other:?}"),
    }
    assert_eq!(agg.pending(), 0);
}

#[test]
fn udp_send_to_port_53_marks_dns_unresolved() {
    let line = fixture("udp_send_v4.jsonl");
    let (props, clock, seq) = net_from_line(line.trim());
    let mut agg = FlowPreAgg::new();
    assert!(matches!(
        decode_network(&props, seq, clock, &mut agg),
        DecodedNetwork::Aggregated
    ));
    let event = agg.flush_all().pop().unwrap();
    assert_eq!(
        event.field_evidence.get("dns"),
        Some(&Evidence::NA(NaReason::NoDnsObserved))
    );
    // UDP row in §2.3 does not name saddr, sport, or connid. The fixture omits
    // them, so they are NA, not 0.0.0.0:0 without a marker.
    assert_eq!(
        event.field_evidence.get("saddr"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    assert_eq!(
        event.field_evidence.get("sport"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    assert_eq!(
        event.field_evidence.get("connid"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    match event.kind {
        EventKind::NetSend(body) => {
            assert_eq!(body.flow.proto, L4Proto::Udp);
            assert_eq!(body.bytes, 48);
            assert_eq!(body.flow.remote.to_string(), "1.1.1.1:53");
            assert!(body.flow.sock_id.is_none());
        }
        other => panic!("expected net_send, got {other:?}"),
    }
}

#[test]
fn udp_recv_ipv6_is_net_recv() {
    let line = fixture("udp_recv_v6.jsonl");
    let (props, clock, seq) = net_from_line(line.trim());
    let mut agg = FlowPreAgg::new();
    assert!(matches!(
        decode_network(&props, seq, clock, &mut agg),
        DecodedNetwork::Aggregated
    ));
    let event = agg.flush_all().pop().unwrap();
    assert_eq!(
        event.field_evidence.get("dns"),
        Some(&Evidence::NA(NaReason::NoDnsObserved))
    );
    match event.kind {
        EventKind::NetRecv(body) => {
            assert_eq!(body.flow.proto, L4Proto::Udp);
            assert_eq!(body.bytes, 64);
            assert_eq!(body.flow.local.to_string(), "[2001:db8::9]:53000");
            assert_eq!(body.flow.remote.to_string(), "[2001:db8::53]:53");
        }
        other => panic!("expected net_recv, got {other:?}"),
    }
}

#[test]
fn tcp_connect_is_outbound_and_accept_is_inbound() {
    let mut connect = tcp_send(0, 0);
    connect.event_id = 12;
    connect.size = None;
    let mut agg = FlowPreAgg::new();
    let decoded = decode_network(&connect, 1, clock_at(10), &mut agg);
    let DecodedNetwork::Emitted(events) = decoded else {
        panic!("connect is not aggregated");
    };
    assert_eq!(events.len(), 1);
    assert!(agg.pending() == 0);
    match &events[0].kind {
        EventKind::NetConnect(body) => assert_eq!(body.direction, FlowDirection::Outbound),
        other => panic!("expected net_connect, got {other:?}"),
    }
    assert_eq!(
        events[0].field_evidence.get("mss"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    assert_eq!(
        events[0].field_evidence.get("result"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );

    let mut accept = connect.clone();
    accept.event_id = 31;
    accept.saddr = Some("2001:db8::1".parse().unwrap());
    accept.daddr = Some("2001:db8::2".parse().unwrap());
    let decoded = decode_network(&accept, 2, clock_at(20), &mut agg);
    let DecodedNetwork::Emitted(events) = decoded else {
        panic!("accept is not aggregated");
    };
    match &events[0].kind {
        EventKind::NetConnect(body) => {
            assert_eq!(body.direction, FlowDirection::Inbound);
            assert_eq!(body.flow.local.to_string(), "[2001:db8::1]:40000");
        }
        other => panic!("expected net_connect, got {other:?}"),
    }
}

#[test]
fn tcp_disconnect_flushes_open_bytes_then_closes() {
    let mut agg = FlowPreAgg::new();
    assert!(matches!(
        decode_network(&tcp_send(11, 0), 1, clock_at(100), &mut agg),
        DecodedNetwork::Aggregated
    ));
    let mut close = tcp_send(0, 0);
    close.event_id = 13;
    close.size = None;
    let decoded = decode_network(&close, 2, clock_at(200), &mut agg);
    let DecodedNetwork::Emitted(events) = decoded else {
        panic!("disconnect emits");
    };
    assert_eq!(events.len(), 2);
    match &events[0].kind {
        EventKind::NetSend(body) => assert_eq!(body.bytes, 11),
        other => panic!("expected flushed net_send, got {other:?}"),
    }
    match &events[1].kind {
        EventKind::NetClose(body) => {
            assert!(body.total_sent.is_none());
            assert!(body.total_recv.is_none());
        }
        other => panic!("expected net_close, got {other:?}"),
    }
    assert_eq!(
        events[1].field_evidence.get("total_sent"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    assert_eq!(agg.pending(), 0);
}

#[test]
fn unknown_event_id_is_ignored() {
    let mut agg = FlowPreAgg::new();
    let props = NetworkProperties::bare(99);
    assert!(matches!(
        decode_network(&props, 1, clock_at(1), &mut agg),
        DecodedNetwork::Ignored { event_id: 99 }
    ));
}

#[test]
fn replay_ipv4_fixture_matches_builder() {
    let line = fixture("tcp_send_v4.jsonl");
    let (props, clock, seq) = net_from_line(line.trim());
    let mut agg = FlowPreAgg::new();
    assert!(matches!(
        decode_network(&props, seq, clock, &mut agg),
        DecodedNetwork::Aggregated
    ));
    let event = agg.flush_all().pop().unwrap();
    assert_eq!(event.evidence, Evidence::E1);
    assert_eq!(event.proc, None);
    assert_eq!(
        event.field_evidence.get("proc"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    match event.kind {
        EventKind::NetSend(body) => {
            assert_eq!(body.bytes, 20);
            assert_eq!(body.flow.remote.to_string(), "93.184.216.34:443");
            assert_eq!(body.flow.sock_id, Some(7));
            assert!(body.via.is_none());
        }
        other => panic!("expected net_send, got {other:?}"),
    }
}

#[test]
fn dns_3006_is_query_at_evidence_i() {
    let line = fixture("dns_3006.jsonl");
    let (props, clock, seq) = dns_from_line(line.trim());
    let decoded = decode_dns(&props, seq, clock, None);
    let DecodedDns::Event(event) = decoded else {
        panic!("3006 decodes");
    };
    let event = event.as_ref();
    assert_eq!(event.source.as_str(), SOURCE_DNS_CLIENT);
    assert_eq!(event.evidence, Evidence::I);
    assert_eq!(event.proc, None);
    assert_eq!(event.field_evidence.get(PID_FIELD), Some(&Evidence::I));
    assert_eq!(
        event.field_evidence.get(PID_ATTRIBUTION_NOTE),
        Some(&Evidence::I)
    );
    assert_ne!(event.evidence, Evidence::E1);
    match &event.kind {
        EventKind::DnsQuery(body) => {
            assert_eq!(body.qname, "sim.agentwatch.test");
            assert_eq!(body.qtype, 1);
            assert!(body.txid.is_none());
            assert!(body.server.is_none());
        }
        other => panic!("expected dns_query, got {other:?}"),
    }
}

#[test]
fn dns_3008_parses_results_and_keeps_unparsed_pieces() {
    let line = fixture("dns_3008.jsonl");
    let (props, clock, seq) = dns_from_line(line.trim());
    let mut cache = DnsAnswerCache::new();
    let decoded = decode_dns(&props, seq, clock, Some(&mut cache));
    let DecodedDns::Event(event) = decoded else {
        panic!("3008 decodes");
    };
    let event = event.as_ref();
    assert_eq!(event.evidence, Evidence::I);
    assert_eq!(event.field_evidence.get(PID_FIELD), Some(&Evidence::I));
    assert_eq!(
        event.field_evidence.get(PID_ATTRIBUTION_NOTE),
        Some(&Evidence::I)
    );
    // One piece did not parse. The answer is kept, and the field is NA.
    assert_eq!(
        event.field_evidence.get("answers"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    match &event.kind {
        EventKind::DnsAnswer(body) => {
            assert_eq!(body.qname, "sim.agentwatch.test");
            assert_eq!(body.qtype, 1);
            assert_eq!(body.rcode, 0);
            assert_eq!(body.answers.len(), 3);
            assert_eq!(body.answers[0].rtype, 1);
            assert_eq!(body.answers[0].data, "93.184.216.34");
            assert_eq!(body.answers[1].rtype, 28);
            assert_eq!(body.answers[1].data, "2001:db8::10");
            assert_eq!(body.answers[2].rtype, 0);
            assert_eq!(body.answers[2].data, "not-an-ip");
        }
        other => panic!("expected dns_answer, got {other:?}"),
    }
    // Process-independent: the header pid is stored beside the row, not as the key.
    assert_eq!(cache.rows().len(), 1);
    assert_eq!(cache.rows()[0].header_pid, Some(100));
    assert_eq!(
        cache.rows()[0].qname.as_deref(),
        Some("sim.agentwatch.test")
    );
}

#[test]
fn dns_3020_is_not_a_second_answer() {
    let mut props = DnsProperties::bare(3020);
    props.query_name = Some("sim.agentwatch.test".to_owned());
    props.query_results = Some("1.2.3.4".to_owned());
    let mut cache = DnsAnswerCache::new();
    let decoded = decode_dns(&props, 1, clock_at(1), Some(&mut cache));
    assert!(matches!(decoded, DecodedDns::Ignored { event_id: 3020 }));
    assert!(cache.rows().is_empty());
}

#[test]
fn dns_answer_without_results_is_not_dropped() {
    let mut props = DnsProperties::bare(3008);
    props.query_name = Some("sim.agentwatch.test".to_owned());
    props.query_type = Some(1);
    let decoded = decode_dns(&props, 1, clock_at(1), None);
    let DecodedDns::Event(event) = decoded else {
        panic!("absent QueryResults still emits");
    };
    let event = event.as_ref();
    assert_eq!(
        event.field_evidence.get("answers"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    assert_eq!(
        event.field_evidence.get("rcode"),
        Some(&Evidence::NA(NaReason::CollectorUnavailable))
    );
    match &event.kind {
        EventKind::DnsAnswer(body) => assert!(body.answers.is_empty()),
        other => panic!("expected dns_answer, got {other:?}"),
    }
}
