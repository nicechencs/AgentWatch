//! pktap DNS payloads → `DnsQuery` / `DnsAnswer`.
//!
//! This module does not open a pktap interface, does not spawn `tcpdump`, and
//! does not link libpcap. macos.md §1.3 says the capture is
//! `tcpdump -i pktap,all -k …` **or** a libpcap open of the pktap device, and
//! marks the pcapng metadata layout 【待验证 SPIKE-03】. SPIKE-03 is 「未开始」,
//! so this decoder does not guess a pcapng framing. The caller hands it one
//! already-decoded UDP payload plus the process the `-k` metadata named.
//!
//! ## Assumed input
//!
//! [`DnsPacket`] is that payload:
//!
//! | field | meaning |
//! |---|---|
//! | `udp_payload` | UDP payload of one DNS message (RFC 1035 §4.1). Not an Ethernet frame, not a pcap record. |
//! | `process_name` | Process name from pktap `-k` metadata, compared as ASCII case-insensitive. |
//! | `pid` | Pid from the same metadata. `None` when `-k` did not carry one. |
//! | `local` / `remote` | The UDP sockets, if the caller has them. Port 53 on either side is what makes this a DNS packet. |
//! | `server` | The far end the query was sent to, when the caller knows it. |
//!
//! A packet whose ports are both known and neither is 53 is ignored. A packet
//! with no ports at all is still parsed: the caller already selected it as DNS
//! by giving it to this function. SNI is not parsed. TCP DNS (length-prefixed)
//! is not parsed. EDNS options, OPT records, and TSIG are skipped, not stored.
//!
//! ## Evidence
//!
//! CAP-DNS-01 lists pktap as E1, with the PID marked 【待验证】. CAP-DNS-02 is
//! the rule that decides attribution, and it is stricter: a query that belongs
//! to `mDNSResponder` has **no** original requester. The record evidence of that
//! query is [`Evidence::I`], not E1. The pid is kept on [`DecodedPktap`] and is
//! **not** written into `proc`. Putting it on `proc` would read as "we know who
//! asked". CAP-DNS-02 says we do not. `field_evidence["pid"]` is `I`, and
//! `field_evidence["requester"]` is `NA(attribution_break)`.
//!
//! A packet whose process is anything else keeps evidence E1 for the DNS
//! *message* (the name and the type were on the wire) and still leaves `proc`
//! as `None`: pktap gives a pid and not a process start time, so a [`ProcUid`]
//! cannot be hashed. That absence is `NA(collector_unavailable)`, which is a
//! missing identity, not a claim that the requester is unknown. The two cases
//! are different and the field paths say which.
//!
//! Answers attributed to `mDNSResponder` are also inserted into [`GlobalDnsCache`].
//! That is the cache P1-PIPE-03 reads back as I (CAP-DNS-04). This module does
//! not do the IP→name join itself.
//!
//! `source` is [`SOURCE_PKTAP_DNS`] (`macos.pktap/dns`).
//!
//! A payload that is not a DNS message becomes one `Gap{parse_error}`. It is
//! not dropped silently.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use aw_core::{
    DnsAnswer, DnsQuery, DnsRecord, EventKind, Evidence, Gap, GapKind, NaReason, RawEvent,
    SocketAddr, Source, SCHEMA_VERSION,
};

/// `macos.pktap/dns`. The task card names this string.
pub const SOURCE_PKTAP_DNS: &str = "macos.pktap/dns";

/// Process name macos.md §1.3 and CAP-DNS-02 assign the system resolver to.
pub const MDNS_RESPONDER: &str = "mDNSResponder";

/// DNS UDP port.
pub const DNS_PORT: u16 = 53;

/// `field_evidence` path whose value is [`Evidence::I`] for an mDNSResponder query.
///
/// The pid was observed. It is not the requester. [`Evidence::I`] carries no
/// reason string, so the path itself names the fact.
pub const PID_FIELD: &str = "pid";

/// `field_evidence` path marked `NA(attribution_break)` for an mDNSResponder query.
///
/// CAP-DNS-02: the original requesting process is not observable.
pub const REQUESTER_FIELD: &str = "requester";

/// One UDP payload the caller already took off the wire, plus who `-k` named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPacket<'a> {
    /// DNS message bytes. The UDP header is not included.
    pub udp_payload: &'a [u8],
    /// Process name from pktap metadata. Compared case-insensitively with
    /// [`MDNS_RESPONDER`].
    pub process_name: &'a str,
    /// Pid from pktap metadata. `None` when the metadata did not carry one.
    /// Not stored as `0`.
    pub pid: Option<u32>,
    /// Local UDP socket, if the caller parsed it out of the capture.
    pub local: Option<std::net::SocketAddr>,
    /// Remote UDP socket.
    pub remote: Option<std::net::SocketAddr>,
    /// Address the query was sent to. Stored on `DnsQuery::server` when present.
    pub server: Option<std::net::SocketAddr>,
}

/// Clock the caller supplies. This module does not read a system clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PktapClock {
    /// Monotonic nanoseconds in the daemon clock domain.
    pub ts_mono_ns: u64,
    /// Wall clock, Unix epoch nanoseconds. `None` is marked NA.
    pub ts_wall_ns: Option<i64>,
}

/// What [`decode_dns`] produced.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodedPktap {
    /// A query or an answer. Boxed: the event is much larger than [`Self::Ignored`].
    Event(Box<PktapEvent>),
    /// Ports were present and neither was 53. Not a loss.
    Ignored,
}

/// A decoded DNS event plus the attribution the [`RawEvent`] cannot store.
#[derive(Debug, Clone, PartialEq)]
pub struct PktapEvent {
    /// The event.
    pub event: RawEvent,
    /// `true` when `process_name` was `mDNSResponder`. The record evidence is I.
    pub global_cache: bool,
    /// Pid the metadata named. Not copied onto `event.proc`.
    pub pid: Option<u32>,
}

/// Answers whose process was `mDNSResponder`.
///
/// Keyed by the answer name only. CAP-DNS-02 says the pid is not the requester,
/// so it is not part of the key. P1-PIPE-03 reads this as I and joins on the
/// address; this cache just keeps the rows.
#[derive(Debug, Default, Clone)]
pub struct GlobalDnsCache {
    rows: Vec<GlobalDnsRow>,
}

/// One answer that entered the global cache.
#[derive(Debug, Clone, PartialEq)]
pub struct GlobalDnsRow {
    /// Question name, when the message had one.
    pub qname: Option<String>,
    /// Metadata pid, untrusted as a requester.
    pub pid: Option<u32>,
    /// The event, evidence I.
    pub event: RawEvent,
}

impl GlobalDnsCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Answers stored so far, oldest first.
    pub fn rows(&self) -> &[GlobalDnsRow] {
        &self.rows
    }

    fn push(&mut self, row: GlobalDnsRow) {
        self.rows.push(row);
    }
}

/// Decode one DNS payload.
///
/// `seq` comes from the caller. `cache` receives answers only, and only when
/// the process is `mDNSResponder`. Queries are returned and not cached: a query
/// has no address for a later connection to match (network-attribution §4.2
/// step 5 is an answer cache).
///
/// Passing `cache = None` still returns the event.
///
/// # Errors
///
/// This function does not return `Err`. A payload that is not DNS is a
/// `Gap{parse_error}` inside [`DecodedPktap::Event`]. A collector must not drop
/// an unreadable packet by failing the read loop.
pub fn decode_dns(
    packet: &DnsPacket<'_>,
    seq: u64,
    clock: PktapClock,
    cache: Option<&mut GlobalDnsCache>,
) -> Result<DecodedPktap, PktapError> {
    Ok(decode_inner(packet, seq, clock, cache))
}

fn decode_inner(
    packet: &DnsPacket<'_>,
    seq: u64,
    clock: PktapClock,
    cache: Option<&mut GlobalDnsCache>,
) -> DecodedPktap {
    if !ports_are_dns(packet) {
        return DecodedPktap::Ignored;
    }
    let via_mdns = is_mdns_responder(packet.process_name);
    let message = match parse_message(packet.udp_payload) {
        Ok(message) => message,
        Err(detail) => {
            return DecodedPktap::Event(Box::new(PktapEvent {
                event: parse_gap(seq, clock, detail),
                global_cache: via_mdns,
                pid: packet.pid,
            }));
        }
    };
    let evidence = if via_mdns { Evidence::I } else { Evidence::E1 };
    let event = if message.response {
        build_answer(packet, &message, seq, clock, evidence, via_mdns)
    } else {
        build_query(packet, &message, seq, clock, evidence, via_mdns)
    };
    if via_mdns && message.response {
        if let Some(cache) = cache {
            cache.push(GlobalDnsRow {
                qname: message.qname.clone(),
                pid: packet.pid,
                event: event.clone(),
            });
        }
    }
    DecodedPktap::Event(Box::new(PktapEvent {
        event,
        global_cache: via_mdns,
        pid: packet.pid,
    }))
}

fn is_mdns_responder(name: &str) -> bool {
    name.eq_ignore_ascii_case(MDNS_RESPONDER)
}

/// `true` when the caller did not give ports, or either port is 53.
///
/// Both ports known and neither 53 → not DNS. One side known and not 53, the
/// other unknown → still parsed: the unknown side might be 53, and dropping it
/// would hide a query.
fn ports_are_dns(packet: &DnsPacket<'_>) -> bool {
    let local = packet.local.map(|addr| addr.port());
    let remote = packet.remote.map(|addr| addr.port());
    match (local, remote) {
        (Some(local), Some(remote)) => local == DNS_PORT || remote == DNS_PORT,
        // One side was not supplied. The known port may be the ephemeral side
        // of a DNS exchange, so a non-53 port here is not enough to drop it.
        (Some(_), None) | (None, Some(_)) => true,
        (None, None) => true,
    }
}

struct Message {
    id: u16,
    response: bool,
    rcode: u16,
    qname: Option<String>,
    qtype: Option<u16>,
    answers: Vec<DnsRecord>,
    ttl_min: Option<u32>,
    /// A name or a record could not be read. The message is still returned.
    partial: bool,
}

fn parse_message(payload: &[u8]) -> Result<Message, &'static str> {
    if payload.len() < 12 {
        return Err("dns header is shorter than 12 bytes");
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let response = flags & 0x8000 != 0;
    let rcode = flags & 0x000f;
    let qd = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let an = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    let ns = u16::from_be_bytes([payload[8], payload[9]]) as usize;
    let ar = u16::from_be_bytes([payload[10], payload[11]]) as usize;

    let mut cur = 12;
    let mut qname = None;
    let mut qtype = None;
    let mut partial = false;
    for i in 0..qd {
        let (name, next) = match read_name(payload, cur) {
            Some(pair) => pair,
            None => return Err("dns question name does not fit"),
        };
        cur = next;
        if cur + 4 > payload.len() {
            return Err("dns question type does not fit");
        }
        let qtype_i = u16::from_be_bytes([payload[cur], payload[cur + 1]]);
        cur += 4; // qtype + qclass. Class is not stored.
        if i == 0 {
            qname = Some(name);
            qtype = Some(qtype_i);
        }
    }

    let mut answers = Vec::new();
    let mut ttl_min: Option<u32> = None;
    for _ in 0..an {
        match read_rr(payload, cur) {
            Some((rr, next)) => {
                cur = next;
                if let Some(ttl) = rr.ttl {
                    ttl_min = Some(ttl_min.map_or(ttl, |prev| prev.min(ttl)));
                }
                if let Some(record) = rr.record {
                    answers.push(record);
                } else {
                    partial = true;
                }
            }
            None => {
                partial = true;
                break;
            }
        }
    }
    // Authority and additional are not stored. They are skipped so a trailing
    // OPT record does not make the whole answer a parse gap. A skip that fails
    // marks the message partial and stops; the question and the answers already
    // read are kept.
    for _ in 0..(ns + ar) {
        match skip_rr(payload, cur) {
            Some(next) => cur = next,
            None => {
                partial = true;
                break;
            }
        }
    }
    let _ = cur;

    Ok(Message {
        id,
        response,
        rcode,
        qname,
        qtype,
        answers,
        ttl_min,
        partial,
    })
}

struct Rr {
    record: Option<DnsRecord>,
    ttl: Option<u32>,
}

/// Read one resource record. `None` when the header or the claimed rdata
/// length runs past the payload.
fn read_rr(payload: &[u8], at: usize) -> Option<(Rr, usize)> {
    let (next_after_name, rtype, _class, ttl, rdata) = rr_header(payload, at)?;
    let record = match rtype {
        1 if rdata.len() == 4 => Some(DnsRecord {
            rtype: 1,
            data: Ipv4Addr::from(TryInto::<[u8; 4]>::try_into(rdata).ok()?).to_string(),
        }),
        28 if rdata.len() == 16 => Some(DnsRecord {
            rtype: 28,
            data: Ipv6Addr::from(TryInto::<[u8; 16]>::try_into(rdata).ok()?).to_string(),
        }),
        5 => read_name_at(payload, rdata_offset(payload, at)?, rdata.len()).map(|name| DnsRecord {
            rtype: 5,
            data: name,
        }),
        _ => None,
    };
    Some((
        Rr {
            record,
            ttl: Some(ttl),
        },
        next_after_name,
    ))
}

fn rdata_offset(payload: &[u8], at: usize) -> Option<usize> {
    let (name_end, _) = skip_name(payload, at)?;
    Some(name_end + 10)
}

fn read_name_at(payload: &[u8], at: usize, len: usize) -> Option<String> {
    if at + len > payload.len() {
        return None;
    }
    // CNAME rdata is a domain name. Compression pointers may point outside the
    // rdata, into the message, which `read_name` already allows.
    read_name(payload, at).map(|(name, _)| name)
}

fn skip_rr(payload: &[u8], at: usize) -> Option<usize> {
    rr_header(payload, at).map(|(next, _, _, _, _)| next)
}

/// `(offset after this RR, type, class, ttl, rdata)`.
fn rr_header(payload: &[u8], at: usize) -> Option<(usize, u16, u16, u32, &[u8])> {
    let (name_end, _) = skip_name(payload, at)?;
    if name_end + 10 > payload.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([payload[name_end], payload[name_end + 1]]);
    let class = u16::from_be_bytes([payload[name_end + 2], payload[name_end + 3]]);
    let ttl = u32::from_be_bytes([
        payload[name_end + 4],
        payload[name_end + 5],
        payload[name_end + 6],
        payload[name_end + 7],
    ]);
    let rdlen = u16::from_be_bytes([payload[name_end + 8], payload[name_end + 9]]) as usize;
    let data_at = name_end + 10;
    if data_at + rdlen > payload.len() {
        return None;
    }
    Some((
        data_at + rdlen,
        rtype,
        class,
        ttl,
        &payload[data_at..data_at + rdlen],
    ))
}

/// Domain name at `at`, following compression pointers (RFC 1035 §4.1.4).
///
/// The returned offset is the first byte *after* the name on the wire, which
/// is not the pointer target. A pointer loop or a label that runs past the
/// payload is `None`.
fn read_name(payload: &[u8], at: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = at;
    let mut jumped = false;
    let mut end = at;
    let mut hops = 0;
    loop {
        if pos >= payload.len() || hops > 32 {
            return None;
        }
        hops += 1;
        let len = payload[pos];
        if len == 0 {
            if !jumped {
                end = pos + 1;
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= payload.len() {
                return None;
            }
            let ptr = (usize::from(len & 0x3f) << 8) | usize::from(payload[pos + 1]);
            if !jumped {
                end = pos + 2;
            }
            pos = ptr;
            jumped = true;
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let start = pos + 1;
        let stop = start + usize::from(len);
        if stop > payload.len() {
            return None;
        }
        let label = std::str::from_utf8(&payload[start..stop]).ok()?;
        labels.push(label);
        pos = stop;
        if !jumped {
            end = pos;
        }
    }
    let name = if labels.is_empty() {
        ".".to_owned()
    } else {
        labels.join(".")
    };
    Some((name, end))
}

/// Like [`read_name`] but only returns how far the on-wire name extends.
fn skip_name(payload: &[u8], at: usize) -> Option<(usize, ())> {
    read_name(payload, at).map(|(_, end)| (end, ()))
}

fn build_query(
    packet: &DnsPacket<'_>,
    message: &Message,
    seq: u64,
    clock: PktapClock,
    evidence: Evidence,
    via_mdns: bool,
) -> RawEvent {
    let qtype_known = message.qtype.is_some();
    let qtype = message.qtype.unwrap_or(0);
    let qname = message.qname.clone().unwrap_or_default();
    let server = packet.server.map(SocketAddr::socket);
    let kind = EventKind::DnsQuery(DnsQuery::new(qname, qtype, Some(message.id), server));
    let mut event = stamp(seq, clock, kind, evidence);
    mark_common(&mut event, packet, message, via_mdns);
    if message.qname.is_none() {
        event.mark_na("qname", NaReason::CollectorUnavailable);
    }
    if !qtype_known {
        event.mark_na("qtype", NaReason::CollectorUnavailable);
    }
    if packet.server.is_none() {
        event.mark_na("server", NaReason::CollectorUnavailable);
    }
    event
}

fn build_answer(
    packet: &DnsPacket<'_>,
    message: &Message,
    seq: u64,
    clock: PktapClock,
    evidence: Evidence,
    via_mdns: bool,
) -> RawEvent {
    let qtype_known = message.qtype.is_some();
    let qtype = message.qtype.unwrap_or(0);
    let qname = message.qname.clone().unwrap_or_default();
    let kind = EventKind::DnsAnswer(DnsAnswer::new(
        qname,
        qtype,
        message.rcode,
        message.answers.clone(),
        message.ttl_min,
    ));
    let mut event = stamp(seq, clock, kind, evidence);
    mark_common(&mut event, packet, message, via_mdns);
    if message.qname.is_none() {
        event.mark_na("qname", NaReason::CollectorUnavailable);
    }
    if !qtype_known {
        event.mark_na("qtype", NaReason::CollectorUnavailable);
    }
    if message.partial {
        event.mark_na("answers", NaReason::CollectorUnavailable);
    }
    if message.ttl_min.is_none() {
        event.mark_na("ttl_min", NaReason::CollectorUnavailable);
    }
    event
}

fn mark_common(event: &mut RawEvent, packet: &DnsPacket<'_>, _message: &Message, via_mdns: bool) {
    // No start time, so no ProcUid, for either attribution.
    event.mark_na("proc", NaReason::CollectorUnavailable);
    if via_mdns {
        // CAP-DNS-02. I, not E1. The pid is not the requester.
        event
            .field_evidence
            .insert(PID_FIELD.to_owned(), Evidence::I);
        event.mark_na(REQUESTER_FIELD, NaReason::AttributionBreak);
    }
    if packet.pid.is_none() && !via_mdns {
        event.mark_na("pid", NaReason::CollectorUnavailable);
    }
    let _ = packet.pid;
}

fn stamp(seq: u64, clock: PktapClock, kind: EventKind, evidence: Evidence) -> RawEvent {
    let wall_known = clock.ts_wall_ns.is_some();
    let mut event = RawEvent {
        v: SCHEMA_VERSION,
        seq,
        ts_mono_ns: clock.ts_mono_ns,
        ts_wall_ns: clock.ts_wall_ns.unwrap_or(0),
        session_id: None,
        proc: None,
        source: Source::new(SOURCE_PKTAP_DNS),
        evidence,
        field_evidence: BTreeMap::new(),
        kind,
    };
    if !wall_known {
        event.mark_na("ts_wall_ns", NaReason::CollectorUnavailable);
    }
    let _ = event.check();
    event
}

fn parse_gap(seq: u64, clock: PktapClock, detail: &'static str) -> RawEvent {
    let gap = Gap::new(
        SOURCE_PKTAP_DNS,
        GapKind::ParseError,
        vec!["net".to_owned()],
        clock.ts_mono_ns,
        clock.ts_mono_ns,
        Some(1),
        Some(detail.to_owned()),
    );
    stamp(seq, clock, EventKind::Gap(gap), Evidence::E1)
}

/// Reserved. Decoding does not fail the call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PktapError {
    /// No variant is constructed. A bad payload is a parse gap.
    Unused,
}

impl std::fmt::Display for PktapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unused => f.write_str("pktap dns decode does not fail the packet"),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    /// Build a minimal DNS query payload: one question, no answers.
    ///
    /// Tests use this. The name is a sequence of labels separated by `.`. A root
    /// name (`.`) is the empty label. This is not a general encoder.
    pub fn encode_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
        let mut buf = vec![0_u8; 12];
        buf[0..2].copy_from_slice(&id.to_be_bytes());
        // RD = 1. Not a response.
        buf[2] = 0x01;
        buf[3] = 0x00;
        buf[4] = 0x00;
        buf[5] = 0x01; // qdcount = 1
        write_name(&mut buf, qname);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1_u16.to_be_bytes()); // class IN
        buf
    }

    /// Build a minimal DNS response with one A or AAAA answer.
    ///
    /// `addr` selects the type (A for v4, AAAA for v6). `ttl` is the record TTL.
    pub fn encode_a_answer(id: u16, qname: &str, addr: IpAddr, ttl: u32) -> Vec<u8> {
        let qtype: u16 = match addr {
            IpAddr::V4(_) => 1,
            IpAddr::V6(_) => 28,
        };
        let mut buf = encode_query(id, qname, qtype);
        // QR = 1, rcode = 0.
        buf[2] = 0x81;
        buf[3] = 0x80;
        buf[6] = 0x00;
        buf[7] = 0x01; // ancount = 1
        write_name(&mut buf, qname);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&1_u16.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());
        match addr {
            IpAddr::V4(v4) => {
                buf.extend_from_slice(&4_u16.to_be_bytes());
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.extend_from_slice(&16_u16.to_be_bytes());
                buf.extend_from_slice(&v6.octets());
            }
        }
        buf
    }

    fn write_name(buf: &mut Vec<u8>, qname: &str) {
        if qname == "." || qname.is_empty() {
            buf.push(0);
            return;
        }
        let trimmed = qname.trim_end_matches('.');
        for label in trimmed.split('.') {
            let bytes = label.as_bytes();
            buf.push(u8::try_from(bytes.len()).unwrap_or(0));
            buf.extend_from_slice(bytes);
        }
        buf.push(0);
    }

    const CLOCK: PktapClock = PktapClock {
        ts_mono_ns: 2_000_000_000,
        ts_wall_ns: Some(1_700_000_000_000_000_000),
    };

    fn packet<'a>(payload: &'a [u8], name: &'a str, pid: u32) -> DnsPacket<'a> {
        DnsPacket {
            udp_payload: payload,
            process_name: name,
            pid: Some(pid),
            local: Some("10.0.0.5:53000".parse().expect("local")),
            remote: Some("10.0.0.1:53".parse().expect("remote")),
            server: Some("10.0.0.1:53".parse().expect("server")),
        }
    }

    #[test]
    fn query_from_another_process_is_e1() {
        let payload = encode_query(0x1a2b, "sim.agentwatch.test", 1);
        let decoded = decode_dns(&packet(&payload, "curl", 4242), 1, CLOCK, None).expect("decode");
        let DecodedPktap::Event(ev) = decoded else {
            panic!("expected an event");
        };
        let ev = ev.as_ref();
        assert!(!ev.global_cache);
        assert_eq!(ev.event.evidence, Evidence::E1);
        assert_eq!(ev.event.source.as_str(), SOURCE_PKTAP_DNS);
        assert!(ev.event.proc.is_none());
        match &ev.event.kind {
            EventKind::DnsQuery(query) => {
                assert_eq!(query.qname, "sim.agentwatch.test");
                assert_eq!(query.qtype, 1);
                assert_eq!(query.txid, Some(0x1a2b));
            }
            other => panic!("expected dns_query, got {}", other.kind_name()),
        }
    }

    #[test]
    fn mdns_responder_query_is_inference_not_e1() {
        let payload = encode_query(7, "sim.agentwatch.test", 1);
        let mut cache = GlobalDnsCache::new();
        let decoded = decode_dns(
            &packet(&payload, "mDNSResponder", 50),
            2,
            CLOCK,
            Some(&mut cache),
        )
        .expect("decode");
        let DecodedPktap::Event(ev) = decoded else {
            panic!("expected an event");
        };
        let ev = ev.as_ref();
        assert!(ev.global_cache);
        assert_eq!(ev.event.evidence, Evidence::I);
        assert_ne!(ev.event.evidence, Evidence::E1);
        assert!(ev.event.proc.is_none());
        assert_eq!(ev.pid, Some(50));
        assert_eq!(ev.event.field_evidence.get(PID_FIELD), Some(&Evidence::I));
        assert!(ev
            .event
            .field_evidence
            .get(REQUESTER_FIELD)
            .is_some_and(|mark| *mark == Evidence::NA(NaReason::AttributionBreak)));
        // A query has no address. It does not enter the answer cache.
        assert!(cache.rows().is_empty());
    }

    #[test]
    fn mdns_responder_answer_enters_the_global_cache() {
        let payload = encode_a_answer(
            7,
            "sim.agentwatch.test",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            60,
        );
        let mut cache = GlobalDnsCache::new();
        let decoded = decode_dns(
            &packet(&payload, "mDNSResponder", 50),
            3,
            CLOCK,
            Some(&mut cache),
        )
        .expect("decode");
        let DecodedPktap::Event(ev) = decoded else {
            panic!("expected an event");
        };
        let ev = ev.as_ref();
        assert_eq!(ev.event.evidence, Evidence::I);
        match &ev.event.kind {
            EventKind::DnsAnswer(answer) => {
                assert_eq!(answer.qname, "sim.agentwatch.test");
                assert_eq!(answer.answers.len(), 1);
                assert_eq!(answer.answers[0].rtype, 1);
                assert_eq!(answer.answers[0].data, "203.0.113.10");
                assert_eq!(answer.ttl_min, Some(60));
                assert_eq!(answer.rcode, 0);
            }
            other => panic!("expected dns_answer, got {}", other.kind_name()),
        }
        assert_eq!(cache.rows().len(), 1);
        assert_eq!(
            cache.rows()[0].qname.as_deref(),
            Some("sim.agentwatch.test")
        );
    }

    #[test]
    fn a_packet_that_is_not_port_53_is_ignored() {
        let payload = encode_query(1, "sim.agentwatch.test", 1);
        let mut pkt = packet(&payload, "curl", 1);
        pkt.local = Some("10.0.0.5:12345".parse().expect("local"));
        pkt.remote = Some("10.0.0.1:443".parse().expect("remote"));
        let decoded = decode_dns(&pkt, 4, CLOCK, None).expect("decode");
        assert!(matches!(decoded, DecodedPktap::Ignored));
    }

    #[test]
    fn a_short_payload_is_a_parse_gap() {
        let pkt = packet(&[0, 1, 2], "curl", 1);
        let decoded = decode_dns(&pkt, 5, CLOCK, None).expect("decode");
        let DecodedPktap::Event(ev) = decoded else {
            panic!("expected a gap event");
        };
        assert!(matches!(ev.event.kind, EventKind::Gap(_)));
    }
}
