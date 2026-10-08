//! Userspace decoder for the TCP/UDP records described in `aw-ebpf`'s `net` module.
//!
//! The kernel probe is not loaded here (this crate runs on Windows, and Aya is
//! not a dependency). [`decode_net`] turns one already-copied record into
//! `NetConnect`, `NetSend`, `NetRecv`, `NetClose`, `DnsQuery`, or `DnsAnswer`.
//!
//! `aw-ebpf` is not a workspace member, so the layout is repeated here as plain
//! Rust the tests can build. The sizes are asserted against the comments in
//! `aw-ebpf/src/net.rs` (`ConnRecord` 80, `StateRecord` 80, `SockStatsDelta`
//! 104, `DnsPayload` 568).
//!
//! A field the record says was not read stays `None` and is marked
//! `NA(collector_unavailable)`. A zero port that *was* read stays zero: that is
//! what `tcp_connect` reports before the stack picks a local port.
//!
//! Records whose tgid the caller says is out of scope produce nothing. The
//! kernel filter is supposed to have done this already; the check is repeated
//! so a capture that skipped it does not attribute a bystander.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use aw_core::{
    DnsAnswer, DnsQuery, DnsRecord, EventKind, Evidence, FlowDirection, FlowKey, L4Proto, NaReason,
    NetClose, NetConnect, NetRecv, NetSend, ProcRef, ProcUid, RawEvent, SocketAddr as EventAddr,
    Source, SCHEMA_VERSION,
};

use crate::dns_parse::{parse_dns, DnsParse, DnsParseInput, ParsedDns};

/// `source` prefix. The probe name is appended.
pub const SOURCE_PREFIX: &str = "linux.ebpf";

/// systemd-resolved stub. A query here still belongs to the process that sent it.
pub const RESOLVED_STUB: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53));

/// Bytes of DNS payload the probe keeps. Matches `aw-ebpf`'s `DNS_PAYLOAD_CAP`.
pub const DNS_PAYLOAD_CAP: usize = 512;

const RECORD_CONN: u32 = 1;
const RECORD_STATE: u32 = 2;
const RECORD_STATS: u32 = 3;
const RECORD_DNS: u32 = 4;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

const DIR_INBOUND: u8 = 2;

/// Linux `TCP_CLOSE` (`include/net/tcp_states.h`).
const TCP_CLOSE: u8 = 7;

const PROTO_TCP: u8 = 1;
const PROTO_UDP: u8 = 2;

/// `ConnRecord` / `StateRecord` / `SockStats` width, in bytes.
const ADDR_RECORD_LEN: usize = 80;
/// `SockStatsDelta` width.
const DELTA_LEN: usize = 104;
/// `DnsPayload` width.
const DNS_RECORD_LEN: usize = 568;

/// One record, built by a test or by the (future) ringbuf reader.
///
/// Addresses are `Option` because the probe reports each field as known or not.
/// `None` is "not read". A known port of 0 is `Some(0)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetRecord {
    /// `tcp_connect` or `inet_csk_accept`.
    Connect(ConnectRecord),
    /// `sock:inet_sock_set_state`. Only `newstate == TCP_CLOSE` emits.
    State(StateRecord),
    /// One socket from a 1 s `sock_stats` walk.
    Stats(StatsDelta),
    /// UDP/53 payload prefix. Parsed and dropped.
    Dns(DnsRecordIn),
}

/// Connection event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRecord {
    /// Probe that produced it. `tcp_connect` or `inet_csk_accept`.
    pub probe: &'static str,
    /// `bpf_ktime_get_ns`.
    pub ts_mono_ns: u64,
    /// Wall clock the caller converted. `None` is `NA`, not epoch 0.
    pub ts_wall_ns: Option<i64>,
    /// Host tgid.
    pub tgid: u32,
    /// Host tid. `None` when the probe did not read it.
    pub tid: Option<u32>,
    /// `hash(pid, start_time, boot_id)` once the caller has a start time.
    /// Without it the pid is kept and `proc` is `NA`: a `ProcUid` of 0 would be a guess.
    pub proc_uid: Option<u64>,
    /// `sock` pointer.
    pub sock: u64,
    /// `true` for `inet_csk_accept`.
    pub inbound: bool,
    /// Tuple. Missing pieces stay missing.
    pub endpoint: Endpoint,
}

/// TCP state change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRecord {
    /// Always `inet_sock_set_state` for records this decoder emits from.
    pub probe: &'static str,
    /// `bpf_ktime_get_ns`.
    pub ts_mono_ns: u64,
    /// Wall clock. `None` is `NA`.
    pub ts_wall_ns: Option<i64>,
    /// Host tgid.
    pub tgid: u32,
    /// Host tid.
    pub tid: Option<u32>,
    /// See [`ConnectRecord::proc_uid`].
    pub proc_uid: Option<u64>,
    /// `sock` pointer.
    pub sock: u64,
    /// Previous state. `None` when the field was not read.
    pub oldstate: Option<u8>,
    /// New state. `None` when the field was not read; nothing is emitted then.
    pub newstate: Option<u8>,
    /// Tuple.
    pub endpoint: Endpoint,
    /// Totals from the last `sock_stats` sample, if the caller still has the row.
    /// `None` is `NA` on the close event, not zero.
    pub total_sent: Option<u64>,
    /// Same for received bytes.
    pub total_recv: Option<u64>,
}

/// One second of byte counters for one socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsDelta {
    /// `tcp_sendmsg`, `tcp_cleanup_rbuf`, `udp_sendmsg`, `udpv6_sendmsg`, or
    /// `udp_recvmsg`. Stamped on every event this delta emits. A delta that
    /// emits both directions uses this probe for both; the caller passes the
    /// probe that owns the map walk (`tcp_sendmsg` is not assumed).
    pub probe: &'static str,
    /// Time of the scan.
    pub ts_mono_ns: u64,
    /// Wall clock. `None` is `NA`.
    pub ts_wall_ns: Option<i64>,
    /// Host tgid.
    pub tgid: u32,
    /// Host tid.
    pub tid: Option<u32>,
    /// See [`ConnectRecord::proc_uid`].
    pub proc_uid: Option<u64>,
    /// `sock` pointer.
    pub sock: u64,
    /// TCP or UDP. `None` when the row did not say.
    pub proto: Option<L4Proto>,
    /// Tuple.
    pub endpoint: Endpoint,
    /// Current `tx_bytes`.
    pub tx_bytes: u64,
    /// Current `rx_bytes`.
    pub rx_bytes: u64,
    /// Previous `tx_bytes`. Zero on the first scan of a new socket.
    pub prev_tx_bytes: u64,
    /// Previous `rx_bytes`.
    pub prev_rx_bytes: u64,
    /// `true` when the walk could not read the row. No event is emitted.
    pub read_error: bool,
}

/// DNS copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecordIn {
    /// `udp_sendmsg`, `udpv6_sendmsg`, or `udp_recvmsg`.
    pub probe: &'static str,
    /// `bpf_ktime_get_ns`.
    pub ts_mono_ns: u64,
    /// Wall clock. `None` is `NA`.
    pub ts_wall_ns: Option<i64>,
    /// Host tgid. Kept even when the peer is `127.0.0.53`.
    pub tgid: u32,
    /// Host tid.
    pub tid: Option<u32>,
    /// See [`ConnectRecord::proc_uid`].
    pub proc_uid: Option<u64>,
    /// `sock` pointer.
    pub sock: u64,
    /// `true` when the copy came from `udp_recvmsg`. The parser trusts the QR bit.
    pub from_recv: bool,
    /// Tuple.
    pub endpoint: Endpoint,
    /// Real datagram length. May be greater than `payload.len()`.
    pub datagram_len: Option<usize>,
    /// Copied prefix. At most [`DNS_PAYLOAD_CAP`] bytes. Not retained on the event.
    pub payload: Vec<u8>,
}

/// One end of a socket, as far as the probe could read it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Endpoint {
    /// Local address.
    pub local_ip: Option<IpAddr>,
    /// Local port.
    pub local_port: Option<u16>,
    /// Remote address.
    pub remote_ip: Option<IpAddr>,
    /// Remote port.
    pub remote_port: Option<u16>,
}

impl Endpoint {
    /// Both addresses and both ports read.
    pub fn full(local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            local_ip: Some(normalize_ip(local.ip())),
            local_port: Some(local.port()),
            remote_ip: Some(normalize_ip(remote.ip())),
            remote_port: Some(remote.port()),
        }
    }
}

/// Why a record produced no event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// Caller said the tgid is outside the session.
    OutOfScope,
    /// TCP state was not `TCP_CLOSE`.
    StateNotClose {
        /// The state that was read, if it was read.
        newstate: Option<u8>,
    },
    /// Counters did not move, or the row could not be read.
    NoByteDelta,
    /// Tag byte was not a record this decoder knows.
    UnknownTag {
        /// The tag.
        tag: u32,
    },
    /// Buffer shorter than the tag, or shorter than the record the tag names.
    Truncated,
}

/// One decoded record.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodedNet {
    /// Zero or more events. Empty only when the record was well formed and
    /// deliberately had nothing to say (a stats row with a zero delta returns
    /// [`DecodedNet::Skipped`] instead).
    Events(Vec<RawEvent>),
    /// Nothing emitted.
    Skipped(SkipReason),
}

/// Decode one record.
///
/// `in_scope` is the session check. A `false` return drops the record. The
/// closure is not called when the record is too short to contain a tgid.
///
/// `seq` is the sequence of the first event. Further events from the same
/// record (a DNS payload also emits the byte event's sibling, or a stats delta
/// emits send and recv) take `seq + 1`, `seq + 2`, ...
pub fn decode_net(record: &NetRecord, seq: u64, in_scope: impl FnOnce(u32) -> bool) -> DecodedNet {
    let tgid = record_tgid(record);
    if !in_scope(tgid) {
        return DecodedNet::Skipped(SkipReason::OutOfScope);
    }
    match record {
        NetRecord::Connect(rec) => DecodedNet::Events(vec![emit_connect(rec, seq)]),
        NetRecord::State(rec) => match rec.newstate {
            Some(TCP_CLOSE) => DecodedNet::Events(vec![emit_close(rec, seq)]),
            other => DecodedNet::Skipped(SkipReason::StateNotClose { newstate: other }),
        },
        NetRecord::Stats(rec) => decode_stats(rec, seq),
        NetRecord::Dns(rec) => DecodedNet::Events(emit_dns(rec, seq)),
    }
}

/// `ProcUid` input the collector hashes once it knows a process start time.
///
/// This decoder does not hash. It also does not invent a uid from the pid:
/// `None` stays `None` and the event marks `proc` as `NA(collector_unavailable)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcIdentity {
    /// Host tgid.
    pub tgid: u32,
    /// Start time, when `/proc` still had it.
    pub start_time_ns: Option<i64>,
    /// Boot id, when it was read.
    pub boot_id: Option<u64>,
}

/// True when a uid can be computed. Both inputs have to be present.
pub fn proc_uid_ready(id: ProcIdentity) -> bool {
    id.start_time_ns.is_some() && id.boot_id.is_some()
}

fn record_tgid(record: &NetRecord) -> u32 {
    match record {
        NetRecord::Connect(rec) => rec.tgid,
        NetRecord::State(rec) => rec.tgid,
        NetRecord::Stats(rec) => rec.tgid,
        NetRecord::Dns(rec) => rec.tgid,
    }
}

fn decode_stats(rec: &StatsDelta, seq: u64) -> DecodedNet {
    if rec.read_error {
        return DecodedNet::Skipped(SkipReason::NoByteDelta);
    }
    let tx = rec.tx_bytes.saturating_sub(rec.prev_tx_bytes);
    let rx = rec.rx_bytes.saturating_sub(rec.prev_rx_bytes);
    // A counter that went backwards is not a wrap and not a negative send.
    let tx = (rec.tx_bytes >= rec.prev_tx_bytes).then_some(tx);
    let rx = (rec.rx_bytes >= rec.prev_rx_bytes).then_some(rx);
    let mut out = Vec::new();
    let mut next = seq;
    if let Some(bytes) = tx.filter(|n| *n > 0) {
        out.push(emit_bytes(rec, next, true, bytes));
        next = next.saturating_add(1);
    }
    if let Some(bytes) = rx.filter(|n| *n > 0) {
        out.push(emit_bytes(rec, next, false, bytes));
    }
    if out.is_empty() {
        DecodedNet::Skipped(SkipReason::NoByteDelta)
    } else {
        DecodedNet::Events(out)
    }
}

fn emit_connect(rec: &ConnectRecord, seq: u64) -> RawEvent {
    let (flow, missing) = flow_of(L4Proto::Tcp, rec.sock, &rec.endpoint);
    let direction = if rec.inbound {
        FlowDirection::Inbound
    } else {
        FlowDirection::Outbound
    };
    // The probe does not report an error code. A decoded connect is the attempt
    // the hook saw, not a known success, so `result` is NA rather than 0.
    let mut event = build(BuildParts {
        seq,
        probe: rec.probe,
        ts_mono_ns: rec.ts_mono_ns,
        ts_wall_ns: rec.ts_wall_ns,
        tgid: rec.tgid,
        tid: rec.tid,
        proc_uid: rec.proc_uid,
        kind: EventKind::NetConnect(NetConnect::new(flow, direction, None)),
    });
    event.mark_na("result", NaReason::CollectorUnavailable);
    apply_missing(&mut event, &missing);
    event
}

fn emit_close(rec: &StateRecord, seq: u64) -> RawEvent {
    let (flow, missing) = flow_of(L4Proto::Tcp, rec.sock, &rec.endpoint);
    let mut event = build(BuildParts {
        seq,
        probe: rec.probe,
        ts_mono_ns: rec.ts_mono_ns,
        ts_wall_ns: rec.ts_wall_ns,
        tgid: rec.tgid,
        tid: rec.tid,
        proc_uid: rec.proc_uid,
        kind: EventKind::NetClose(NetClose::new(flow, rec.total_sent, rec.total_recv)),
    });
    if rec.total_sent.is_none() {
        event.mark_na("total_sent", NaReason::CollectorUnavailable);
    }
    if rec.total_recv.is_none() {
        event.mark_na("total_recv", NaReason::CollectorUnavailable);
    }
    apply_missing(&mut event, &missing);
    event
}

fn emit_bytes(rec: &StatsDelta, seq: u64, send: bool, bytes: u64) -> RawEvent {
    let proto = rec.proto.unwrap_or(L4Proto::Unknown);
    let (flow, missing) = flow_of(proto, rec.sock, &rec.endpoint);
    let kind = if send {
        // `via` is not a field of these probes. `None` without a marker would
        // read as "not sendfile".
        EventKind::NetSend(NetSend::new(flow, bytes, None))
    } else {
        EventKind::NetRecv(NetRecv::new(flow, bytes))
    };
    let mut event = build(BuildParts {
        seq,
        probe: rec.probe,
        ts_mono_ns: rec.ts_mono_ns,
        ts_wall_ns: rec.ts_wall_ns,
        tgid: rec.tgid,
        tid: rec.tid,
        proc_uid: rec.proc_uid,
        kind,
    });
    if rec.proto.is_none() {
        event.mark_na("proto", NaReason::CollectorUnavailable);
    }
    if send {
        event.mark_na("via", NaReason::CollectorUnavailable);
    }
    apply_missing(&mut event, &missing);
    event
}

fn emit_dns(rec: &DnsRecordIn, seq: u64) -> Vec<RawEvent> {
    let server = dns_server(rec);
    let parsed = match rec.datagram_len {
        None => Err("dns length was not read"),
        Some(datagram_len) => match parse_dns(DnsParseInput {
            payload: &rec.payload,
            datagram_len,
        }) {
            DnsParse::Ok(parsed) => Ok(parsed),
            DnsParse::Failed { reason } => Err(reason),
        },
    };
    let mut event = match parsed {
        Ok(parsed) if !parsed.response => dns_query_event(rec, seq, &parsed, server),
        Ok(parsed) => dns_answer_event(rec, seq, &parsed),
        Err(reason) => dns_unparsed(rec, seq, server, reason),
    };
    if rec.endpoint.remote_ip == Some(RESOLVED_STUB) {
        // systemd-resolved's stub. The tgid on the record is the process that
        // sent the query, and that attribution stays E1 (network-attribution
        // §4.1). The field path records that the peer was the stub, so a reader
        // does not look for a second process. It is not NA: the sender was observed.
        event
            .field_evidence
            .insert("resolved_stub".to_owned(), Evidence::E1);
    }
    vec![event]
}

fn dns_server(rec: &DnsRecordIn) -> Option<EventAddr> {
    // A query's server is the remote side. A response was sent by the server,
    // so its address is the remote side of the socket too (we received it).
    match (rec.endpoint.remote_ip, rec.endpoint.remote_port) {
        (Some(ip), Some(port)) => Some(EventAddr::socket(SocketAddr::new(ip, port))),
        _ => None,
    }
}

fn dns_query_event(
    rec: &DnsRecordIn,
    seq: u64,
    parsed: &ParsedDns,
    server: Option<EventAddr>,
) -> RawEvent {
    let mut event = build(BuildParts {
        seq,
        probe: rec.probe,
        ts_mono_ns: rec.ts_mono_ns,
        ts_wall_ns: rec.ts_wall_ns,
        tgid: rec.tgid,
        tid: rec.tid,
        proc_uid: rec.proc_uid,
        kind: EventKind::DnsQuery(DnsQuery::new(
            parsed.qname.clone(),
            parsed.qtype,
            Some(parsed.txid),
            server,
        )),
    });
    if server.is_none() {
        event.mark_na("server", NaReason::CollectorUnavailable);
    }
    note_endpoint(&mut event, &rec.endpoint);
    event
}

fn dns_answer_event(rec: &DnsRecordIn, seq: u64, parsed: &ParsedDns) -> RawEvent {
    let answers = parsed
        .answers
        .iter()
        .map(|rr| DnsRecord {
            rtype: rr.rtype,
            data: rr.data.clone(),
        })
        .collect();
    let mut event = build(BuildParts {
        seq,
        probe: rec.probe,
        ts_mono_ns: rec.ts_mono_ns,
        ts_wall_ns: rec.ts_wall_ns,
        tgid: rec.tgid,
        tid: rec.tid,
        proc_uid: rec.proc_uid,
        kind: EventKind::DnsAnswer(DnsAnswer::new(
            parsed.qname.clone(),
            parsed.qtype,
            parsed.rcode,
            answers,
            parsed.ttl_min,
        )),
    });
    if parsed.answers.is_empty() {
        event.mark_na("answers", NaReason::NoDnsObserved);
    }
    note_endpoint(&mut event, &rec.endpoint);
    event
}

fn dns_unparsed(
    rec: &DnsRecordIn,
    seq: u64,
    server: Option<EventAddr>,
    reason: &'static str,
) -> RawEvent {
    // The kind still has to be one or the other. QR unread means we do not know;
    // a send hook is reported as a query and a recv hook as an answer, and every
    // field that would have come from the payload is NA. The hook direction is a
    // fact about which probe copied the bytes, not a parse of the message.
    let kind = if rec.from_recv {
        EventKind::DnsAnswer(DnsAnswer::new(String::new(), 0, 0, Vec::new(), None))
    } else {
        EventKind::DnsQuery(DnsQuery::new(String::new(), 0, None, server))
    };
    let mut event = build(BuildParts {
        seq,
        probe: rec.probe,
        ts_mono_ns: rec.ts_mono_ns,
        ts_wall_ns: rec.ts_wall_ns,
        tgid: rec.tgid,
        tid: rec.tid,
        proc_uid: rec.proc_uid,
        kind,
    });
    event.mark_na("qname", NaReason::CollectorUnavailable);
    event.mark_na("qtype", NaReason::CollectorUnavailable);
    if rec.from_recv {
        event.mark_na("rcode", NaReason::CollectorUnavailable);
        event.mark_na("answers", NaReason::CollectorUnavailable);
        event.mark_na("ttl_min", NaReason::CollectorUnavailable);
    } else {
        event.mark_na("txid", NaReason::CollectorUnavailable);
        if server.is_none() {
            event.mark_na("server", NaReason::CollectorUnavailable);
        }
    }
    event.mark_na("dns_parse", NaReason::CollectorUnavailable);
    let _ = reason;
    note_endpoint(&mut event, &rec.endpoint);
    event
}

fn note_endpoint(event: &mut RawEvent, endpoint: &Endpoint) {
    if endpoint.remote_ip.is_none() {
        event.mark_na("remote", NaReason::CollectorUnavailable);
    }
    if endpoint.remote_port.is_none() {
        event.mark_na("remote_port", NaReason::CollectorUnavailable);
    }
}

struct FlowGaps {
    local: bool,
    remote: bool,
}

fn flow_of(proto: L4Proto, sock: u64, endpoint: &Endpoint) -> (FlowKey, FlowGaps) {
    let local_missing = endpoint.local_ip.is_none() || endpoint.local_port.is_none();
    let remote_missing = endpoint.remote_ip.is_none() || endpoint.remote_port.is_none();
    let local = socket_or_unspec(endpoint.local_ip, endpoint.local_port);
    let remote = socket_or_unspec(endpoint.remote_ip, endpoint.remote_port);
    let flow = FlowKey::new(proto, local, remote, Some(sock));
    (
        flow,
        FlowGaps {
            local: local_missing,
            remote: remote_missing,
        },
    )
}

fn socket_or_unspec(ip: Option<IpAddr>, port: Option<u16>) -> EventAddr {
    match (ip, port) {
        (Some(ip), Some(port)) => EventAddr::socket(SocketAddr::new(ip, port)),
        (Some(ip), None) => EventAddr::ip(ip),
        (None, _) => EventAddr::socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
    }
}

fn apply_missing(event: &mut RawEvent, gaps: &FlowGaps) {
    if gaps.local {
        event.mark_na("local", NaReason::CollectorUnavailable);
    }
    if gaps.remote {
        event.mark_na("remote", NaReason::CollectorUnavailable);
    }
}

/// Shared header of every event this decoder emits. The six call sites used to
/// pass these as separate arguments, which clippy counts past the limit.
struct BuildParts {
    seq: u64,
    probe: &'static str,
    ts_mono_ns: u64,
    ts_wall_ns: Option<i64>,
    tgid: u32,
    tid: Option<u32>,
    proc_uid: Option<u64>,
    kind: EventKind,
}

fn build(parts: BuildParts) -> RawEvent {
    let BuildParts {
        seq,
        probe,
        ts_mono_ns,
        ts_wall_ns,
        tgid,
        tid,
        proc_uid,
        kind,
    } = parts;
    let proc = proc_uid.map(|uid| ProcRef {
        uid: ProcUid(uid),
        pid: tgid,
        tid,
    });
    let proc_missing = proc.is_none();
    let mut event = RawEvent {
        v: SCHEMA_VERSION,
        seq,
        ts_mono_ns,
        ts_wall_ns: ts_wall_ns.unwrap_or(0),
        session_id: None,
        proc,
        source: Source::new(format!("{SOURCE_PREFIX}/{probe}")),
        evidence: Evidence::E1,
        field_evidence: std::collections::BTreeMap::new(),
        kind,
    };
    if ts_wall_ns.is_none() {
        event.mark_na("ts_wall_ns", NaReason::CollectorUnavailable);
    }
    if proc_missing {
        event.mark_na("proc", NaReason::CollectorUnavailable);
    }
    let _ = event.check();
    event
}

/// Map `::ffff:a.b.c.d` to IPv4. Any other address is unchanged.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Read a `ConnRecord` image. `probe` is chosen from `direction`: outbound is
/// `tcp_connect`, inbound is `inet_csk_accept`.
pub fn connect_from_bytes(
    bytes: &[u8],
    ts_wall_ns: Option<i64>,
    proc_uid: Option<u64>,
) -> Result<ConnectRecord, SkipReason> {
    if bytes.len() < ADDR_RECORD_LEN {
        return Err(SkipReason::Truncated);
    }
    let tag = read_u32(bytes, 0);
    if tag != RECORD_CONN {
        return Err(SkipReason::UnknownTag { tag });
    }
    let direction = bytes[28];
    let probe = if direction == DIR_INBOUND {
        "inet_csk_accept"
    } else {
        "tcp_connect"
    };
    Ok(ConnectRecord {
        probe,
        ts_mono_ns: read_u64(bytes, 4),
        ts_wall_ns,
        tgid: read_u32(bytes, 12),
        tid: Some(read_u32(bytes, 16)),
        proc_uid,
        sock: read_u64(bytes, 20),
        inbound: direction == DIR_INBOUND,
        endpoint: endpoint_at(bytes, 28),
    })
}

/// Read a `StateRecord` image.
pub fn state_from_bytes(
    bytes: &[u8],
    ts_wall_ns: Option<i64>,
    proc_uid: Option<u64>,
    total_sent: Option<u64>,
    total_recv: Option<u64>,
) -> Result<StateRecord, SkipReason> {
    if bytes.len() < ADDR_RECORD_LEN {
        return Err(SkipReason::Truncated);
    }
    let tag = read_u32(bytes, 0);
    if tag != RECORD_STATE {
        return Err(SkipReason::UnknownTag { tag });
    }
    Ok(StateRecord {
        probe: "inet_sock_set_state",
        ts_mono_ns: read_u64(bytes, 4),
        ts_wall_ns,
        tgid: read_u32(bytes, 12),
        tid: Some(read_u32(bytes, 16)),
        proc_uid,
        sock: read_u64(bytes, 20),
        oldstate: flag_u8(bytes[28], bytes[30]),
        newstate: flag_u8(bytes[29], bytes[31]),
        // `newstate` sits where `ConnRecord.direction` sits, so the tail matches.
        endpoint: endpoint_at(bytes, 29),
        total_sent,
        total_recv,
    })
}

/// Read a `SockStatsDelta` image.
pub fn stats_from_bytes(
    bytes: &[u8],
    probe: &'static str,
    ts_wall_ns: Option<i64>,
    proc_uid: Option<u64>,
) -> Result<StatsDelta, SkipReason> {
    if bytes.len() < DELTA_LEN {
        return Err(SkipReason::Truncated);
    }
    let tag = read_u32(bytes, 0);
    if tag != RECORD_STATS {
        return Err(SkipReason::UnknownTag { tag });
    }
    let proto = match bytes[60] {
        PROTO_TCP => Some(L4Proto::Tcp),
        PROTO_UDP => Some(L4Proto::Udp),
        _ => None,
    };
    Ok(StatsDelta {
        probe,
        ts_mono_ns: read_u64(bytes, 4),
        ts_wall_ns,
        sock: read_u64(bytes, 12),
        tx_bytes: read_u64(bytes, 20),
        rx_bytes: read_u64(bytes, 28),
        prev_tx_bytes: read_u64(bytes, 36),
        prev_rx_bytes: read_u64(bytes, 44),
        tgid: read_u32(bytes, 52),
        tid: Some(read_u32(bytes, 56)),
        proto,
        // family is at 61. Then five known flags, inbound, read_error, pad,
        // and the ports at 72. `endpoint_at` expects the port-tail anchor one
        // byte before family, which this record does not have, so the address
        // pair is read here.
        endpoint: endpoint_tail(bytes, 61),
        read_error: bytes[69] == 1,
        proc_uid,
    })
}

/// Read a `DnsPayload` image. The payload is copied out so the caller can drop
/// the record; the event never keeps it.
pub fn dns_from_bytes(
    bytes: &[u8],
    probe: &'static str,
    ts_wall_ns: Option<i64>,
    proc_uid: Option<u64>,
) -> Result<DnsRecordIn, SkipReason> {
    if bytes.len() < DNS_RECORD_LEN {
        return Err(SkipReason::Truncated);
    }
    let tag = read_u32(bytes, 0);
    if tag != RECORD_DNS {
        return Err(SkipReason::UnknownTag { tag });
    }
    // recv(28), family(29), five known flags, len_known(36), len(38), then two
    // bytes of tail padding so the ports start at 40. Payload follows the two
    // addresses at 64.
    let len_known = bytes[36] == 1;
    let len = read_u16(bytes, 38) as usize;
    let copied = len.min(DNS_PAYLOAD_CAP);
    let payload = bytes[64..64 + copied].to_vec();
    Ok(DnsRecordIn {
        probe,
        ts_mono_ns: read_u64(bytes, 4),
        ts_wall_ns,
        tgid: read_u32(bytes, 12),
        tid: Some(read_u32(bytes, 16)),
        proc_uid,
        sock: read_u64(bytes, 20),
        from_recv: bytes[28] == 1,
        // `len` is a u16, so the ports start two bytes later than on a stats row.
        endpoint: endpoint_tail(bytes, 31),
        datagram_len: len_known.then_some(len),
        payload,
    })
}

fn flag_u8(value: u8, known: u8) -> Option<u8> {
    (known == 1).then_some(value)
}

/// Address tail whose `family` byte is at `family_at`, followed by five known
/// flags, one pad, the two ports, and the two addresses. `ConnRecord` and
/// `StateRecord` use this. Records with extra flags between the known bits and
/// the ports use [`endpoint_tail`].
fn endpoint_at(bytes: &[u8], at: usize) -> Endpoint {
    // `at` is the `direction` / `oldstate` byte. The shared tail is:
    // family, family_known, local_known, remote_known, local_port_known,
    // remote_port_known, pad, local_port, remote_port, local, remote.
    let family = bytes[at + 1];
    let family_known = bytes[at + 2] == 1;
    let local_known = bytes[at + 3] == 1;
    let remote_known = bytes[at + 4] == 1;
    let local_port_known = bytes[at + 5] == 1;
    let remote_port_known = bytes[at + 6] == 1;
    let local_port = read_u16(bytes, at + 8);
    let remote_port = read_u16(bytes, at + 10);
    let local = addr_at(bytes, at + 12, family, family_known, local_known);
    let remote = addr_at(bytes, at + 32, family, family_known, remote_known);
    Endpoint {
        local_ip: local,
        local_port: local_port_known.then_some(local_port),
        remote_ip: remote,
        remote_port: remote_port_known.then_some(remote_port),
    }
}

/// `SockStatsDelta` and `DnsPayload`: `family` at `family_at`, then five known
/// flags, then three more bytes before the ports: `inbound`, `read_error` and
/// a pad on a stats row, or `len_known` plus the two bytes of `len` on a DNS
/// row. Both leave the ports eleven bytes after `family`.
fn endpoint_tail(bytes: &[u8], family_at: usize) -> Endpoint {
    let family = bytes[family_at];
    let family_known = bytes[family_at + 1] == 1;
    let local_known = bytes[family_at + 2] == 1;
    let remote_known = bytes[family_at + 3] == 1;
    let local_port_known = bytes[family_at + 4] == 1;
    let remote_port_known = bytes[family_at + 5] == 1;
    let ports = family_at + 9;
    let local_port = read_u16(bytes, ports);
    let remote_port = read_u16(bytes, ports + 2);
    let local = addr_at(bytes, ports + 4, family, family_known, local_known);
    let remote = addr_at(bytes, ports + 24, family, family_known, remote_known);
    Endpoint {
        local_ip: local,
        local_port: local_port_known.then_some(local_port),
        remote_ip: remote,
        remote_port: remote_port_known.then_some(remote_port),
    }
}

fn addr_at(bytes: &[u8], at: usize, family: u8, family_known: bool, known: bool) -> Option<IpAddr> {
    if !known || !family_known {
        return None;
    }
    let ip = match family {
        AF_INET => IpAddr::V4(Ipv4Addr::new(
            bytes[at],
            bytes[at + 1],
            bytes[at + 2],
            bytes[at + 3],
        )),
        AF_INET6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[at + 4..at + 20]);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(normalize_ip(ip))
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// UDP port a DNS exchange uses. The decoder itself does not special-case it:
    /// the probe already selected UDP/53 before the record got here.
    const DNS_PORT: u16 = 53;

    const TGID: u32 = 4242;
    const SOCK: u64 = 0x00ff_ee00_11ab_cd00;
    const UID: u64 = 0x0a0b_0c0d_0e0f_1011;

    fn in_scope(tgid: u32) -> bool {
        tgid == TGID
    }

    fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), port)
    }

    fn connect_rec(inbound: bool) -> ConnectRecord {
        ConnectRecord {
            probe: if inbound {
                "inet_csk_accept"
            } else {
                "tcp_connect"
            },
            ts_mono_ns: 1_000,
            ts_wall_ns: Some(1_700_000_000_000_000_000),
            tgid: TGID,
            tid: Some(7),
            proc_uid: Some(UID),
            sock: SOCK,
            inbound,
            endpoint: Endpoint::full(v4(10, 0, 0, 2, 40000), v4(93, 184, 216, 34, 443)),
        }
    }

    fn events(decoded: DecodedNet) -> Vec<RawEvent> {
        match decoded {
            DecodedNet::Events(events) => events,
            DecodedNet::Skipped(why) => panic!("skipped: {why:?}"),
        }
    }

    #[test]
    fn tcp_connect_is_an_outbound_net_connect() {
        let events = events(decode_net(
            &NetRecord::Connect(connect_rec(false)),
            3,
            in_scope,
        ));
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.source.as_str(), "linux.ebpf/tcp_connect");
        assert_eq!(event.evidence, Evidence::E1);
        assert_eq!(event.seq, 3);
        assert_eq!(event.proc.as_ref().map(|p| p.pid), Some(TGID));
        match &event.kind {
            EventKind::NetConnect(net) => {
                assert_eq!(net.direction, FlowDirection::Outbound);
                assert_eq!(net.flow.proto, L4Proto::Tcp);
                assert_eq!(net.flow.sock_id, Some(SOCK));
                assert!(net.result.is_none());
            }
            other => panic!("{other:?}"),
        }
        assert!(event.field_evidence.contains_key("result"));
    }

    #[test]
    fn accept_is_inbound() {
        let events = events(decode_net(
            &NetRecord::Connect(connect_rec(true)),
            1,
            in_scope,
        ));
        match &events[0].kind {
            EventKind::NetConnect(net) => assert_eq!(net.direction, FlowDirection::Inbound),
            other => panic!("{other:?}"),
        }
        assert_eq!(events[0].source.as_str(), "linux.ebpf/inet_csk_accept");
    }

    #[test]
    fn a_stats_delta_emits_send_then_recv() {
        let rec = StatsDelta {
            probe: "tcp_sendmsg",
            ts_mono_ns: 2_000_000_000,
            ts_wall_ns: Some(9),
            tgid: TGID,
            tid: Some(7),
            proc_uid: Some(UID),
            sock: SOCK,
            proto: Some(L4Proto::Tcp),
            endpoint: Endpoint::full(v4(10, 0, 0, 2, 40000), v4(1, 1, 1, 1, 443)),
            tx_bytes: 1500,
            rx_bytes: 40,
            prev_tx_bytes: 1000,
            prev_rx_bytes: 0,
            read_error: false,
        };
        let events = events(decode_net(&NetRecord::Stats(rec), 5, in_scope));
        assert_eq!(events.len(), 2);
        match &events[0].kind {
            EventKind::NetSend(net) => assert_eq!(net.bytes, 500),
            other => panic!("{other:?}"),
        }
        match &events[1].kind {
            EventKind::NetRecv(net) => assert_eq!(net.bytes, 40),
            other => panic!("{other:?}"),
        }
        assert_eq!(events[0].source.as_str(), "linux.ebpf/tcp_sendmsg");
        assert_eq!(events[1].seq, 6);
    }

    #[test]
    fn udp_v6_delta_keeps_the_address() {
        let remote: Ipv6Addr = "2001:db8::55".parse().unwrap();
        let rec = StatsDelta {
            probe: "udpv6_sendmsg",
            ts_mono_ns: 3_000,
            ts_wall_ns: Some(9),
            tgid: TGID,
            tid: None,
            proc_uid: Some(UID),
            sock: SOCK,
            proto: Some(L4Proto::Udp),
            endpoint: Endpoint::full(
                SocketAddr::new(IpAddr::V6("fe80::1".parse().unwrap()), 53000),
                SocketAddr::new(IpAddr::V6(remote), DNS_PORT),
            ),
            tx_bytes: 32,
            rx_bytes: 0,
            prev_tx_bytes: 0,
            prev_rx_bytes: 0,
            read_error: false,
        };
        let events = events(decode_net(&NetRecord::Stats(rec), 1, in_scope));
        assert_eq!(events.len(), 1);
        match &events[0].kind {
            EventKind::NetSend(net) => {
                assert_eq!(net.flow.proto, L4Proto::Udp);
                assert_eq!(net.bytes, 32);
                assert_eq!(
                    net.flow.remote,
                    EventAddr::socket(SocketAddr::new(
                        IpAddr::V6("2001:db8::55".parse().unwrap()),
                        DNS_PORT
                    ))
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(events[0].source.as_str(), "linux.ebpf/udpv6_sendmsg");
    }

    #[test]
    fn ipv4_mapped_ipv6_is_stored_as_ipv4() {
        let mapped = std::net::Ipv4Addr::new(1, 2, 3, 4).to_ipv6_mapped();
        let rec = StatsDelta {
            probe: "tcp_sendmsg",
            ts_mono_ns: 1,
            ts_wall_ns: Some(1),
            tgid: TGID,
            tid: None,
            proc_uid: Some(UID),
            sock: 1,
            proto: Some(L4Proto::Tcp),
            endpoint: Endpoint::full(v4(10, 0, 0, 1, 9), SocketAddr::new(IpAddr::V6(mapped), 80)),
            tx_bytes: 1,
            rx_bytes: 0,
            prev_tx_bytes: 0,
            prev_rx_bytes: 0,
            read_error: false,
        };
        let events = events(decode_net(&NetRecord::Stats(rec), 1, in_scope));
        match &events[0].kind {
            EventKind::NetSend(net) => {
                assert_eq!(net.flow.remote, EventAddr::socket(v4(1, 2, 3, 4, 80)));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn close_carries_totals_and_other_states_do_not_emit() {
        let mut rec = StateRecord {
            probe: "inet_sock_set_state",
            ts_mono_ns: 9_000,
            ts_wall_ns: Some(9),
            tgid: TGID,
            tid: Some(1),
            proc_uid: Some(UID),
            sock: SOCK,
            oldstate: Some(1),
            newstate: Some(TCP_CLOSE),
            endpoint: Endpoint::full(v4(10, 0, 0, 2, 40000), v4(1, 2, 3, 4, 443)),
            total_sent: Some(500),
            total_recv: Some(40),
        };
        let events = events(decode_net(&NetRecord::State(rec.clone()), 8, in_scope));
        match &events[0].kind {
            EventKind::NetClose(net) => {
                assert_eq!(net.total_sent, Some(500));
                assert_eq!(net.total_recv, Some(40));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(events[0].source.as_str(), "linux.ebpf/inet_sock_set_state");
        rec.newstate = Some(1);
        assert_eq!(
            decode_net(&NetRecord::State(rec), 8, in_scope),
            DecodedNet::Skipped(SkipReason::StateNotClose { newstate: Some(1) })
        );
    }

    #[test]
    fn an_unknown_port_is_not_zero() {
        let mut rec = connect_rec(false);
        rec.endpoint.local_port = None;
        rec.proc_uid = None;
        let events = events(decode_net(&NetRecord::Connect(rec), 1, in_scope));
        let event = &events[0];
        assert!(event.field_evidence.contains_key("local"));
        assert!(event.field_evidence.contains_key("proc"));
        assert!(event.proc.is_none());
        match &event.kind {
            EventKind::NetConnect(net) => {
                assert_eq!(
                    net.flow.local,
                    EventAddr::ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_process_outside_scope_is_dropped() {
        let decoded = decode_net(&NetRecord::Connect(connect_rec(false)), 1, |_| false);
        assert_eq!(decoded, DecodedNet::Skipped(SkipReason::OutOfScope));
    }

    fn dns_query_bytes() -> Vec<u8> {
        let mut msg = vec![0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in ["example", "com"] {
            msg.push(label.len() as u8);
            msg.extend(label.as_bytes());
        }
        msg.push(0);
        msg.extend(1u16.to_be_bytes());
        msg.extend(1u16.to_be_bytes());
        msg
    }

    #[test]
    fn port_53_send_becomes_a_dns_query_owned_by_the_sender() {
        let payload = dns_query_bytes();
        let rec = DnsRecordIn {
            probe: "udp_sendmsg",
            ts_mono_ns: 50,
            ts_wall_ns: Some(50),
            tgid: TGID,
            tid: Some(3),
            proc_uid: Some(UID),
            sock: SOCK,
            from_recv: false,
            endpoint: Endpoint::full(
                v4(10, 1, 1, 5, 41000),
                SocketAddr::new(RESOLVED_STUB, DNS_PORT),
            ),
            datagram_len: Some(payload.len()),
            payload,
        };
        let events = events(decode_net(&NetRecord::Dns(rec), 2, in_scope));
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.source.as_str(), "linux.ebpf/udp_sendmsg");
        assert_eq!(event.evidence, Evidence::E1);
        assert_eq!(event.proc.as_ref().map(|p| p.pid), Some(TGID));
        match &event.kind {
            EventKind::DnsQuery(q) => {
                assert_eq!(q.qname, "example.com");
                assert_eq!(q.qtype, 1);
                assert_eq!(q.txid, Some(0xabcd));
                assert_eq!(
                    q.server,
                    Some(EventAddr::socket(SocketAddr::new(RESOLVED_STUB, DNS_PORT)))
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            event.field_evidence.get("resolved_stub"),
            Some(&Evidence::E1)
        );
    }

    #[test]
    fn port_53_recv_becomes_a_dns_answer() {
        let mut msg = vec![0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0];
        for label in ["example", "com"] {
            msg.push(label.len() as u8);
            msg.extend(label.as_bytes());
        }
        msg.push(0);
        msg.extend(1u16.to_be_bytes());
        msg.extend(1u16.to_be_bytes());
        msg.extend([0xc0, 0x0c]);
        msg.extend(1u16.to_be_bytes());
        msg.extend(1u16.to_be_bytes());
        msg.extend(30u32.to_be_bytes());
        msg.extend(4u16.to_be_bytes());
        msg.extend([93, 184, 216, 34]);
        let rec = DnsRecordIn {
            probe: "udp_recvmsg",
            ts_mono_ns: 80,
            ts_wall_ns: Some(80),
            tgid: TGID,
            tid: Some(3),
            proc_uid: Some(UID),
            sock: SOCK,
            from_recv: true,
            endpoint: Endpoint::full(
                v4(10, 1, 1, 5, 41000),
                SocketAddr::new(RESOLVED_STUB, DNS_PORT),
            ),
            datagram_len: Some(msg.len()),
            payload: msg,
        };
        let events = events(decode_net(&NetRecord::Dns(rec), 4, in_scope));
        match &events[0].kind {
            EventKind::DnsAnswer(a) => {
                assert_eq!(a.qname, "example.com");
                assert_eq!(a.rcode, 0);
                assert_eq!(a.ttl_min, Some(30));
                assert_eq!(a.answers.len(), 1);
                assert_eq!(a.answers[0].data, "93.184.216.34");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(events[0].proc.as_ref().map(|p| p.pid), Some(TGID));
    }

    #[test]
    fn a_payload_longer_than_512_is_not_parsed() {
        let rec = DnsRecordIn {
            probe: "udp_sendmsg",
            ts_mono_ns: 1,
            ts_wall_ns: Some(1),
            tgid: TGID,
            tid: None,
            proc_uid: Some(UID),
            sock: SOCK,
            from_recv: false,
            endpoint: Endpoint::full(v4(10, 0, 0, 1, 1), v4(1, 1, 1, 1, DNS_PORT)),
            datagram_len: Some(600),
            payload: vec![0; DNS_PAYLOAD_CAP],
        };
        let events = events(decode_net(&NetRecord::Dns(rec), 1, in_scope));
        match &events[0].kind {
            EventKind::DnsQuery(q) => {
                assert!(q.qname.is_empty());
                assert!(q.txid.is_none());
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            events[0].field_evidence.get("qname"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
        assert!(events[0].field_evidence.contains_key("dns_parse"));
    }

    #[test]
    fn a_zero_delta_emits_nothing() {
        let rec = StatsDelta {
            probe: "tcp_cleanup_rbuf",
            ts_mono_ns: 1,
            ts_wall_ns: Some(1),
            tgid: TGID,
            tid: None,
            proc_uid: None,
            sock: 1,
            proto: Some(L4Proto::Tcp),
            endpoint: Endpoint::default(),
            tx_bytes: 10,
            rx_bytes: 10,
            prev_tx_bytes: 10,
            prev_rx_bytes: 10,
            read_error: false,
        };
        assert_eq!(
            decode_net(&NetRecord::Stats(rec), 1, in_scope),
            DecodedNet::Skipped(SkipReason::NoByteDelta)
        );
    }

    /// A `ConnRecord` image laid out as `aw-ebpf/src/net.rs` documents it.
    /// Little-endian, 80 bytes. Local port is known and is 0, which must stay 0.
    #[test]
    fn a_packed_connect_record_decodes_with_a_real_zero_port() {
        let mut bytes = [0u8; 80];
        bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..12].copy_from_slice(&5_000u64.to_le_bytes());
        bytes[12..16].copy_from_slice(&TGID.to_le_bytes());
        bytes[16..20].copy_from_slice(&9u32.to_le_bytes());
        bytes[20..28].copy_from_slice(&SOCK.to_le_bytes());
        bytes[28] = 1; // outbound
        bytes[29] = 2; // AF_INET
        bytes[30] = 1; // family known
        bytes[31] = 1; // local known
        bytes[32] = 1; // remote known
        bytes[33] = 1; // local port known (value 0)
        bytes[34] = 1; // remote port known
        bytes[38..40].copy_from_slice(&443u16.to_le_bytes());
        bytes[40] = 10;
        bytes[60] = 1;
        bytes[61] = 2;
        bytes[62] = 3;
        bytes[63] = 4;
        let rec = connect_from_bytes(&bytes, Some(11), Some(UID)).expect("80-byte record");
        assert_eq!(rec.probe, "tcp_connect");
        assert_eq!(rec.tgid, TGID);
        assert_eq!(rec.sock, SOCK);
        assert!(!rec.inbound);
        assert_eq!(rec.endpoint.local_port, Some(0));
        assert_eq!(rec.endpoint.remote_port, Some(443));
        assert_eq!(
            rec.endpoint.remote_ip,
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
        assert!(connect_from_bytes(&[0; 8], None, None).is_err());
    }

    /// A `DnsPayload` image: length at byte 38, ports at 40, payload at 64.
    #[test]
    fn a_packed_dns_record_reads_the_payload_after_the_addresses() {
        let mut bytes = vec![0u8; 568];
        bytes[0..4].copy_from_slice(&4u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&TGID.to_le_bytes());
        bytes[28] = 0; // send
        bytes[29] = 2; // AF_INET
        bytes[30] = 1;
        bytes[31] = 1;
        bytes[32] = 1;
        bytes[33] = 1;
        bytes[34] = 1;
        bytes[36] = 1; // len known
        bytes[38..40].copy_from_slice(&12u16.to_le_bytes());
        bytes[42..44].copy_from_slice(&DNS_PORT.to_le_bytes());
        bytes[64] = 0xab;
        bytes[65] = 0xcd;
        let rec = dns_from_bytes(&bytes, "udp_sendmsg", Some(1), Some(UID)).expect("dns record");
        assert_eq!(rec.tgid, TGID);
        assert!(!rec.from_recv);
        assert_eq!(rec.datagram_len, Some(12));
        assert_eq!(rec.endpoint.remote_port, Some(DNS_PORT));
        assert_eq!(&rec.payload[..2], &[0xab, 0xcd]);
        assert_eq!(rec.payload.len(), 12);
    }
}
