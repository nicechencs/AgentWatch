//! Kernel-Network events → `NetConnect` / `NetClose` / `NetSend` / `NetRecv`.
//!
//! Field names and event ids are copied from windows.md §2.3. That section is
//! still marked 【待验证 SPIKE-02】, and SPIKE-02 has no measurement: it was not
//! run elevated and recorded no Kernel-Network event. A property this file does
//! not find is `NA(collector_unavailable)`. It is not filled with `0` or `""`.
//!
//! | event id | name | kind |
//! |---|---|---|
//! | 10 / 26 | TCP send (IPv4 / IPv6) | `NetSend` (1 s pre-aggregate) |
//! | 11 / 27 | TCP recv | `NetRecv` (1 s pre-aggregate) |
//! | 12 / 28 | TCP connect | `NetConnect` outbound |
//! | 13 / 29 | TCP disconnect | `NetClose` |
//! | 15 / 31 | TCP accept | `NetConnect` inbound |
//! | 42 / 58 | UDP send (IPv4 / IPv6) | `NetSend` |
//! | 43 / 59 | UDP recv | `NetRecv` |
//!
//! Mapped properties (windows.md §2.3, and only those):
//!
//! | property | field |
//! |---|---|
//! | `PID` | `proc.pid`. No `CreateTime` is on this event, so `proc.uid` cannot be hashed and stays unset; `proc` is `NA(collector_unavailable)`. |
//! | `size` | payload bytes. Summed inside one 1 s window for send/recv. |
//! | `saddr` / `sport` | local socket |
//! | `daddr` / `dport` | remote socket |
//! | `connid` | `FlowKey.sock_id` |
//!
//! UDP rows in §2.3 name `PID, size, daddr, dport, …`. `saddr` and `sport` are
//! inside that ellipsis and are not named, so a UDP event that omits them is
//! `NA`, not a guessed `0.0.0.0:0`. `connid` is not in the UDP row at all.
//!
//! `mss` is named on connect ("同上 + mss 等") and `NetConnect` has no field for
//! it, so it is recorded as `NA(collector_unavailable)` and the integer is not
//! copied onto another field.
//!
//! IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is normalized to IPv4 before it is stored.
//! The window clock is the caller-supplied timestamp. This module does not read
//! a system clock, so a test can replay the same inputs.
//!
//! A UDP flow whose remote or local port is 53 is marked
//! `dns = NA(no_dns_observed)`: a program that sends its own DNS query does not
//! produce a DNS-Client event (windows.md §2.4). The marker is the existing
//! `NaReason`, not a new string enum.
//!
//! The final 5 s bucket is the pipeline's job. This module only pre-aggregates.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use aw_core::{
    EventKind, Evidence, FlowDirection, FlowKey, L4Proto, NaReason, NetClose, NetConnect, NetRecv,
    NetSend, RawEvent, SocketAddr as EventAddr, Source, SCHEMA_VERSION,
};

use super::process::DecodeClock;

/// `source` for every Kernel-Network event. The task card names this string.
pub const SOURCE_KERNEL_NETWORK: &str = "windows.etw/kernel_network";

/// Pre-aggregation window. The task card says 1 s. Not the pipeline's 5 s bucket.
pub const AGGREGATE_WINDOW_NS: u64 = 1_000_000_000;

/// DNS port. A UDP flow that uses it is marked `NA(no_dns_observed)`.
pub const DNS_PORT: u16 = 53;

/// TCP send, IPv4. windows.md §2.3. 【待验证 SPIKE-02】.
pub const EVENT_TCP_SEND_V4: u16 = 10;
/// TCP recv, IPv4. 【待验证 SPIKE-02】.
pub const EVENT_TCP_RECV_V4: u16 = 11;
/// TCP connect, IPv4. 【待验证 SPIKE-02】.
pub const EVENT_TCP_CONNECT_V4: u16 = 12;
/// TCP disconnect, IPv4. 【待验证 SPIKE-02】.
pub const EVENT_TCP_DISCONNECT_V4: u16 = 13;
/// TCP accept, IPv4. 【待验证 SPIKE-02】.
pub const EVENT_TCP_ACCEPT_V4: u16 = 15;
/// TCP send, IPv6. 【待验证 SPIKE-02】.
pub const EVENT_TCP_SEND_V6: u16 = 26;
/// TCP recv, IPv6. 【待验证 SPIKE-02】.
pub const EVENT_TCP_RECV_V6: u16 = 27;
/// TCP connect, IPv6. 【待验证 SPIKE-02】.
pub const EVENT_TCP_CONNECT_V6: u16 = 28;
/// TCP disconnect, IPv6. 【待验证 SPIKE-02】.
pub const EVENT_TCP_DISCONNECT_V6: u16 = 29;
/// TCP accept, IPv6. 【待验证 SPIKE-02】.
pub const EVENT_TCP_ACCEPT_V6: u16 = 31;
/// UDP send, IPv4. 【待验证 SPIKE-02】.
pub const EVENT_UDP_SEND_V4: u16 = 42;
/// UDP recv, IPv4. 【待验证 SPIKE-02】.
pub const EVENT_UDP_RECV_V4: u16 = 43;
/// UDP send, IPv6. 【待验证 SPIKE-02】.
pub const EVENT_UDP_SEND_V6: u16 = 58;
/// UDP recv, IPv6. 【待验证 SPIKE-02】.
pub const EVENT_UDP_RECV_V6: u16 = 59;

/// One property from a decoded Kernel-Network event.
///
/// The session layer forwards headers only and does not parse properties. A
/// caller that has a schema (a fixture, or a later consumer) fills one of these
/// and hands it to [`decode_network`]. This module does not call ferrisetw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkProperties {
    /// `EventDescriptor.Id`. Ids outside the §2.3 table are ignored.
    pub event_id: u16,
    /// `PID`. Absent is not `0` (PID 0 is the Idle process).
    pub pid: Option<u32>,
    /// `size`, payload bytes. 【待验证 SPIKE-02】 whether this includes retransmits.
    /// Absent is not `0`: a zero-byte send is a real event, an absent property is not.
    pub size: Option<u64>,
    /// `saddr`, already parsed. An unparseable string is `None` (the caller
    /// could not read it), which the decoder marks `NA`.
    pub saddr: Option<IpAddr>,
    /// `sport`.
    pub sport: Option<u16>,
    /// `daddr`.
    pub daddr: Option<IpAddr>,
    /// `dport`.
    pub dport: Option<u16>,
    /// `connid`. TCP only in §2.3. Absent stays `None` (not `0`).
    pub connid: Option<u64>,
    /// `mss`, named on connect. `NetConnect` has no field for it.
    pub mss: Option<u32>,
    /// Event-header thread id, when the caller has one. Not a §2.3 property.
    pub tid: Option<u32>,
}

impl NetworkProperties {
    /// An event with an id and nothing else. Tests build from here.
    pub fn bare(event_id: u16) -> Self {
        Self {
            event_id,
            pid: None,
            size: None,
            saddr: None,
            sport: None,
            daddr: None,
            dport: None,
            connid: None,
            mss: None,
            tid: None,
        }
    }
}

/// What one event is, before aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetOp {
    /// TCP connect. `inbound` distinguishes accept (15/31) from connect (12/28).
    Connect { inbound: bool },
    /// TCP disconnect. Emitted immediately. Pending send/recv for the same
    /// connection are flushed first so their bytes are not lost.
    Disconnect,
    Send,
    Recv,
}

/// Protocol and which side of the address pair §2.3 names.
struct Classified {
    proto: L4Proto,
    op: NetOp,
    /// `true` for the IPv6 event ids (26–31, 58, 59). The address itself may
    /// still be IPv4 after mapping normalization.
    ipv6_event: bool,
}

fn classify(event_id: u16) -> Option<Classified> {
    let (proto, op, ipv6_event) = match event_id {
        EVENT_TCP_SEND_V4 => (L4Proto::Tcp, NetOp::Send, false),
        EVENT_TCP_RECV_V4 => (L4Proto::Tcp, NetOp::Recv, false),
        EVENT_TCP_CONNECT_V4 => (L4Proto::Tcp, NetOp::Connect { inbound: false }, false),
        EVENT_TCP_DISCONNECT_V4 => (L4Proto::Tcp, NetOp::Disconnect, false),
        EVENT_TCP_ACCEPT_V4 => (L4Proto::Tcp, NetOp::Connect { inbound: true }, false),
        EVENT_TCP_SEND_V6 => (L4Proto::Tcp, NetOp::Send, true),
        EVENT_TCP_RECV_V6 => (L4Proto::Tcp, NetOp::Recv, true),
        EVENT_TCP_CONNECT_V6 => (L4Proto::Tcp, NetOp::Connect { inbound: false }, true),
        EVENT_TCP_DISCONNECT_V6 => (L4Proto::Tcp, NetOp::Disconnect, true),
        EVENT_TCP_ACCEPT_V6 => (L4Proto::Tcp, NetOp::Connect { inbound: true }, true),
        EVENT_UDP_SEND_V4 => (L4Proto::Udp, NetOp::Send, false),
        EVENT_UDP_RECV_V4 => (L4Proto::Udp, NetOp::Recv, false),
        EVENT_UDP_SEND_V6 => (L4Proto::Udp, NetOp::Send, true),
        EVENT_UDP_RECV_V6 => (L4Proto::Udp, NetOp::Recv, true),
        _ => return None,
    };
    Some(Classified {
        proto,
        op,
        ipv6_event,
    })
}

/// Map `::ffff:a.b.c.d` to `a.b.c.d`. Any other address is unchanged.
///
/// The task card requires this. A mapped address stored as IPv6 would not match
/// the same peer seen on an IPv4 event.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Identity of one connection for the 1 s window.
///
/// Addresses are stored after [`normalize_ip`], so an IPv4 event and the mapped
/// form of the same peer share a bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    /// `PID` when the event had one. `None` does not collapse onto pid 0.
    pub pid: Option<u32>,
    /// TCP or UDP.
    pub proto: L4Proto,
    /// Local address after normalization. `None` when `saddr` was absent.
    pub local_ip: Option<IpAddr>,
    /// Local port. `None` when `sport` was absent.
    pub local_port: Option<u16>,
    /// Remote address after normalization.
    pub remote_ip: Option<IpAddr>,
    /// Remote port.
    pub remote_port: Option<u16>,
    /// `connid` for TCP. UDP has no such field in §2.3, so it stays `None`.
    pub connid: Option<u64>,
}

/// Direction of a byte bucket. Send and recv do not share a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Direction {
    Send,
    Recv,
}

/// One send or recv handed to the open window.
struct ByteSample {
    key: ConnectionKey,
    direction: Direction,
    bytes: u64,
    size_known: bool,
    seq: u64,
    clock: DecodeClock,
    tid: Option<u32>,
}

/// One open 1 s bucket. Flushed when the next event for this key falls in a
/// later window, or when [`FlowPreAgg::flush_before`] / [`FlowPreAgg::flush_all`]
/// is called.
#[derive(Debug)]
struct Bucket {
    window_start_ns: u64,
    bytes: u64,
    /// `true` once any event in the window carried `size`. A window where every
    /// `size` was absent emits `bytes` as `NA`, not as `0`.
    size_known: bool,
    /// Header time of the first event in the bucket. Later events in the same
    /// window do not move it: the bucket is "this second", not "the last send".
    clock: DecodeClock,
    seq: u64,
    tid: Option<u32>,
}

/// In-collector 1 s pre-aggregation of `NetSend` / `NetRecv`.
///
/// Connect and disconnect are not aggregated: §2.3 maps them to one event each.
/// The window is `ts_mono_ns / 1s` of the timestamp the caller passes in. This
/// type does not call `SystemTime` or `Instant`.
#[derive(Debug, Default)]
pub struct FlowPreAgg {
    open: HashMap<(ConnectionKey, Direction), Bucket>,
}

impl FlowPreAgg {
    /// Empty aggregator.
    pub fn new() -> Self {
        Self {
            open: HashMap::new(),
        }
    }

    /// How many buckets are still open. Tests use this; production does not.
    pub fn pending(&self) -> usize {
        self.open.len()
    }

    /// Flush every bucket whose window starts strictly before `ts_mono_ns`'s window.
    ///
    /// A caller that knows time has moved (the session clock) uses this so a
    /// quiet connection still emits. Passing the timestamp of the event just
    /// decoded does not flush that event's own window.
    pub fn flush_before(&mut self, ts_mono_ns: u64) -> Vec<RawEvent> {
        let boundary = window_start(ts_mono_ns);
        let mut due = Vec::new();
        self.open.retain(|(key, direction), bucket| {
            if bucket.window_start_ns < boundary {
                due.push(emit_bytes(key, *direction, bucket));
                false
            } else {
                true
            }
        });
        due
    }

    /// Flush every open bucket, in arbitrary map order.
    ///
    /// For session shutdown. A test that needs a stable order sorts by `seq`.
    pub fn flush_all(&mut self) -> Vec<RawEvent> {
        let mut out = Vec::with_capacity(self.open.len());
        for ((key, direction), bucket) in self.open.drain() {
            out.push(emit_bytes(&key, direction, &bucket));
        }
        out
    }

    fn add_bytes(&mut self, sample: ByteSample) -> Option<RawEvent> {
        let ByteSample {
            key,
            direction,
            bytes,
            size_known,
            seq,
            clock,
            tid,
        } = sample;
        let start = window_start(clock.ts_mono_ns);
        let map_key = (key, direction);
        if let Some(bucket) = self.open.get_mut(&map_key) {
            if bucket.window_start_ns == start {
                bucket.bytes = bucket.bytes.saturating_add(bytes);
                if size_known {
                    bucket.size_known = true;
                }
                return None;
            }
            let Some(finished) = self.open.remove(&map_key) else {
                // The `get_mut` above just found this key. A concurrent remove
                // cannot happen: `FlowPreAgg` is not shared across threads.
                return None;
            };
            self.open.insert(
                map_key,
                Bucket {
                    window_start_ns: start,
                    bytes,
                    size_known,
                    clock,
                    seq,
                    tid,
                },
            );
            return Some(emit_bytes(&key, direction, &finished));
        }
        self.open.insert(
            map_key,
            Bucket {
                window_start_ns: start,
                bytes,
                size_known,
                clock,
                seq,
                tid,
            },
        );
        None
    }
}

fn window_start(ts_mono_ns: u64) -> u64 {
    ts_mono_ns - (ts_mono_ns % AGGREGATE_WINDOW_NS)
}

/// What [`decode_network`] did with one event.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodedNetwork {
    /// Connect, disconnect, or a send/recv whose previous window just closed.
    ///
    /// `flushed` is the previous window of *this* connection, if the new event
    /// fell in a later second. Other connections are not touched; the caller
    /// uses [`flush_due`] for those.
    Emitted(Vec<RawEvent>),
    /// A send/recv that joined the open bucket for its second. Nothing to emit yet.
    Aggregated,
    /// Event id is not in the §2.3 table.
    Ignored { event_id: u16 },
}

/// Decode one Kernel-Network event.
///
/// `seq` is the caller's monotonic counter, consumed only when an event is
/// actually built (a connect, a disconnect, or the first event of a new
/// window). A send that only adds to the open bucket does not consume it: the
/// caller can reuse the same `seq` on the next call. `clock` is the
/// already-converted header time. This function does not read a clock.
///
/// `agg` is mutated. Connect and disconnect do not go through it, except that
/// a disconnect flushes that connection's open send and recv buckets first.
pub fn decode_network(
    props: &NetworkProperties,
    seq: u64,
    clock: DecodeClock,
    agg: &mut FlowPreAgg,
) -> DecodedNetwork {
    let Some(class) = classify(props.event_id) else {
        return DecodedNetwork::Ignored {
            event_id: props.event_id,
        };
    };
    let key = connection_key(props, class.proto);
    match class.op {
        NetOp::Send | NetOp::Recv => {
            let direction = match class.op {
                NetOp::Send => Direction::Send,
                _ => Direction::Recv,
            };
            // `size` absent: still open the window, but the bytes are not 0.
            // The emitted event marks `bytes` NA. A later event in the same
            // window that *does* carry `size` adds to the count; the NA stays
            // only when every event in the window lacked `size`.
            let (bytes, size_known) = match props.size {
                Some(n) => (n, true),
                None => (0, false),
            };
            let flushed = agg.add_bytes(ByteSample {
                key,
                direction,
                bytes,
                size_known,
                seq,
                clock,
                tid: props.tid,
            });
            match flushed {
                Some(event) => DecodedNetwork::Emitted(vec![event]),
                None => DecodedNetwork::Aggregated,
            }
        }
        NetOp::Connect { inbound } => {
            let event = emit_connect(props, &key, inbound, class.ipv6_event, seq, clock);
            DecodedNetwork::Emitted(vec![event])
        }
        NetOp::Disconnect => {
            let mut out = Vec::new();
            if let Some(bucket) = agg.open.remove(&(key, Direction::Send)) {
                out.push(emit_bytes(&key, Direction::Send, &bucket));
            }
            if let Some(bucket) = agg.open.remove(&(key, Direction::Recv)) {
                out.push(emit_bytes(&key, Direction::Recv, &bucket));
            }
            out.push(emit_close(&key, seq, clock, props.tid));
            DecodedNetwork::Emitted(out)
        }
    }
}

/// Flush buckets whose window is strictly before `ts_mono_ns`.
///
/// Same as [`FlowPreAgg::flush_before`]. Named at the module root so a caller
/// that only has the prelude can drive the clock without holding the type's
/// method list.
pub fn flush_due(agg: &mut FlowPreAgg, ts_mono_ns: u64) -> Vec<RawEvent> {
    agg.flush_before(ts_mono_ns)
}

fn connection_key(props: &NetworkProperties, proto: L4Proto) -> ConnectionKey {
    ConnectionKey {
        pid: props.pid,
        proto,
        local_ip: props.saddr.map(normalize_ip),
        local_port: props.sport,
        remote_ip: props.daddr.map(normalize_ip),
        remote_port: props.dport,
        connid: props.connid,
    }
}

fn flow_from_key(key: &ConnectionKey) -> (FlowKey, Vec<(&'static str, NaReason)>) {
    let mut missing = Vec::new();
    let local = match (key.local_ip, key.local_port) {
        (Some(ip), Some(port)) => EventAddr::socket(SocketAddr::new(ip, port)),
        (Some(ip), None) => {
            missing.push(("local_port", NaReason::CollectorUnavailable));
            EventAddr::ip(ip)
        }
        (None, _) => {
            missing.push(("saddr", NaReason::CollectorUnavailable));
            if key.local_port.is_none() {
                missing.push(("sport", NaReason::CollectorUnavailable));
            }
            // `FlowKey.local` is not optional. The unspecified address is stored
            // only together with the NA markers above, so it does not read as
            // "we observed 0.0.0.0".
            EventAddr::socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
    };
    let remote = match (key.remote_ip, key.remote_port) {
        (Some(ip), Some(port)) => EventAddr::socket(SocketAddr::new(ip, port)),
        (Some(ip), None) => {
            missing.push(("dport", NaReason::CollectorUnavailable));
            EventAddr::ip(ip)
        }
        (None, _) => {
            missing.push(("daddr", NaReason::CollectorUnavailable));
            if key.remote_port.is_none() {
                missing.push(("dport", NaReason::CollectorUnavailable));
            }
            EventAddr::socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
    };
    let flow = FlowKey::new(key.proto, local, remote, key.connid);
    (flow, missing)
}

fn dns_unresolved(key: &ConnectionKey) -> bool {
    key.proto == L4Proto::Udp && (key.local_port == Some(DNS_PORT) || key.remote_port == Some(DNS_PORT))
}

fn emit_bytes(key: &ConnectionKey, direction: Direction, bucket: &Bucket) -> RawEvent {
    let (flow, missing) = flow_from_key(key);
    let kind = match direction {
        Direction::Send => EventKind::NetSend(NetSend::new(flow, bucket.bytes, None)),
        Direction::Recv => EventKind::NetRecv(NetRecv::new(flow, bucket.bytes)),
    };
    let mut event = build_event(bucket.seq, bucket.clock, key, bucket.tid, kind);
    apply_flow_gaps(&mut event, key, &missing);
    if !bucket.size_known {
        // Every event in the window omitted `size`. `0` would read as a
        // measured empty send. `bytes` is a plain `u64`, so the integer stays
        // and the marker says it was not observed.
        event.mark_na("bytes", NaReason::CollectorUnavailable);
    }
    // `via` is not a Kernel-Network field. NetSend has the slot; leaving it
    // `None` without a marker would look like "not sendfile" rather than
    // "this collector does not observe the path".
    if matches!(direction, Direction::Send) {
        event.mark_na("via", NaReason::CollectorUnavailable);
    }
    event
}

fn emit_connect(
    props: &NetworkProperties,
    key: &ConnectionKey,
    inbound: bool,
    _ipv6_event: bool,
    seq: u64,
    clock: DecodeClock,
) -> RawEvent {
    let (flow, missing) = flow_from_key(key);
    let direction = if inbound {
        FlowDirection::Inbound
    } else {
        FlowDirection::Outbound
    };
    // `result` is not in the §2.3 column. A connect event that we decoded is
    // the establishment itself; the status code is not named, so it is NA
    // rather than a guessed 0 (success).
    let mut event = build_event(
        seq,
        clock,
        key,
        props.tid,
        EventKind::NetConnect(NetConnect::new(flow, direction, None)),
    );
    apply_flow_gaps(&mut event, key, &missing);
    event.mark_na("result", NaReason::CollectorUnavailable);
    // mss is named and has nowhere to go.
    let _ = props.mss;
    event.mark_na("mss", NaReason::CollectorUnavailable);
    event
}

fn emit_close(key: &ConnectionKey, seq: u64, clock: DecodeClock, tid: Option<u32>) -> RawEvent {
    let (flow, missing) = flow_from_key(key);
    // §2.3 names the same address fields and not a cumulative counter.
    // `total_sent` / `total_recv` are the platform cumulative (sock_diag /
    // nettop) per event-schema. Kernel-Network does not carry them, so both
    // are NA. The pre-aggregated bytes were already emitted as NetSend/NetRecv.
    let mut event = build_event(
        seq,
        clock,
        key,
        tid,
        EventKind::NetClose(NetClose::new(flow, None, None)),
    );
    apply_flow_gaps(&mut event, key, &missing);
    event.mark_na("total_sent", NaReason::CollectorUnavailable);
    event.mark_na("total_recv", NaReason::CollectorUnavailable);
    event
}

fn apply_flow_gaps(event: &mut RawEvent, key: &ConnectionKey, missing: &[(&str, NaReason)]) {
    if key.pid.is_none() {
        event.mark_na("pid", NaReason::CollectorUnavailable);
    }
    // No CreateTime on a network event (windows.md §2.3 does not list it), so
    // ProcUid cannot be computed. `proc` stays None. PID, when present, is
    // recorded on the key and surfaced as field evidence rather than forged
    // into a ProcRef.
    event.mark_na("proc", NaReason::CollectorUnavailable);
    if key.connid.is_none() {
        // UDP never has it. TCP that omitted it is the same fact: we do not
        // have a socket id, and `None` without a marker looks like "platform
        // has no such id" only when the schema says so. Windows TCP does, per
        // §2.3 (`connid`). UDP does not. Mark both: the reason is the same
        // code, and the field path says which.
        event.mark_na("connid", NaReason::CollectorUnavailable);
    }
    for (field, reason) in missing {
        event.mark_na(*field, reason.clone());
    }
    if dns_unresolved(key) {
        // windows.md §2.4: a program that sends its own UDP/53 query produces
        // no DNS-Client event. The connection is observed; the name is not.
        event.mark_na("dns", NaReason::NoDnsObserved);
    }
}

fn build_event(
    seq: u64,
    clock: DecodeClock,
    _key: &ConnectionKey,
    _tid: Option<u32>,
    kind: EventKind,
) -> RawEvent {
    let wall_known = clock.ts_wall_ns.is_some();
    let mut event = RawEvent {
        v: SCHEMA_VERSION,
        seq,
        ts_mono_ns: clock.ts_mono_ns,
        ts_wall_ns: clock.ts_wall_ns.unwrap_or(0),
        session_id: None,
        // No ProcUid. See `apply_flow_gaps`.
        proc: None,
        source: Source::new(SOURCE_KERNEL_NETWORK),
        evidence: Evidence::E1,
        field_evidence: std::collections::BTreeMap::new(),
        kind,
    };
    if !wall_known {
        event.mark_na("ts_wall_ns", NaReason::CollectorUnavailable);
    }
    let _ = event.check();
    event
}
