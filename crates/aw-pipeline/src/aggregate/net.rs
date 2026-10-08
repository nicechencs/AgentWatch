//! Network flow aggregation (P1-PIPE-04).
//!
//! One [`FlowKey`] maps to one [`FlowAcc`]. Send and recv bytes land in the
//! 5 s bucket that contains the event's monotonic time (`aggregate.bucket_secs`).
//! A flow ends on `NetClose`, or, for UDP, after [`UDP_IDLE_NS`] with no packet.
//! A flow still open after [`PARTIAL_FLUSH_NS`] emits a `partial` [`NetFlowRec`]
//! and keeps accumulating.
//!
//! `NetClose.total_sent` / `total_recv` are the platform's own cumulative counts.
//! When either side differs from this stage's sum by more than 5%, the difference
//! is stored and `field_evidence` marks that byte field. The record-level evidence
//! is not raised. A flow whose only byte observations are [`Evidence::S`] (poll or
//! nettop diffs) keeps `S` on the byte fields. A short connection a sample never
//! saw is not invented: this stage only opens a flow for an event it was given.
//!
//! `via_proxy` is on the record and stays `false`. Rewriting a loopback flow onto
//! the proxy's upstream target is P3 (network-attribution §5).
//!
//! Unknown stays [`None`]. A direction that saw no event is `None`, not `0`.
//! Nothing here stores a URL, a header, or a body.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use aw_core::{
    EventKind, Evidence, FlowDirection, FlowKey, L4Proto, ProcUid, RawEvent, SessionId, SocketAddr,
    Source,
};

use crate::output::{FlowBucketRec, NetFlowRec, Output};

/// UDP with no packet for this long is closed. pipeline.md §3.5.
pub const UDP_IDLE_NS: u64 = 60_000_000_000;

/// Long-lived flow emits a partial total this often. Task card P1-PIPE-04.
pub const PARTIAL_FLUSH_NS: u64 = 30_000_000_000;

/// `field_evidence` key for bytes sent.
pub const BYTES_UP_FIELD: &str = "bytes_up";

/// `field_evidence` key for bytes received.
pub const BYTES_DOWN_FIELD: &str = "bytes_down";

/// Relative disagreement that marks a byte field. pipeline.md §3.5 says 5%.
const CALIBRATION_NUM: u64 = 5;
const CALIBRATION_DEN: u64 = 100;

/// `field_evidence` level written when the platform total and our sum disagree
/// by more than [`CALIBRATION_NUM`] / [`CALIBRATION_DEN`]. Not a stronger grade.
const DEVIATION_EVIDENCE: Evidence = Evidence::S;

/// Open and recently closed flows.
///
/// Keyed by the assigned `flow_id`, not by [`FlowKey`]: `FlowKey` contains
/// `std::net::IpAddr`, which is not `Ord`, and `aw-core` is not changed here.
/// [`index`](Self::index) maps a key back to that id. Closed flows stay until
/// something asks for a summary, so a CLI view can group a flow that already
/// emitted its final row. They are not re-emitted.
pub struct NetAggregator {
    bucket_ns: u64,
    open: BTreeMap<u64, FlowAcc>,
    index: HashMap<FlowKey, u64>,
    /// Final rows, in close order. Partials are not kept here: the open map
    /// still has the running total.
    closed: Vec<NetFlowRec>,
    next_id: u64,
    /// Last monotonic time `tick` or `observe` saw. `None` before any call.
    now_ns: Option<u64>,
}

/// Running totals for one flow. Byte fields are `None` until that direction
/// is actually observed. `0` is a real observation of zero bytes, which a
/// `NetSend` / `NetRecv` of `bytes: 0` can produce. Absence is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowAcc {
    /// Assigned once, stable across partial updates of this flow.
    pub flow_id: u64,
    pub session_id: Option<SessionId>,
    pub proc_uid: Option<ProcUid>,
    pub flow: FlowKey,
    pub direction: Option<FlowDirection>,
    /// First observation, monotonic nanoseconds.
    pub first: u64,
    /// Latest observation, monotonic nanoseconds.
    pub last: u64,
    /// Sum of `NetSend.bytes`. `None` until a send is seen.
    pub bytes_up: Option<u64>,
    /// Sum of `NetRecv.bytes`. `None` until a recv is seen.
    pub bytes_down: Option<u64>,
    /// SNI, when a `TlsSni` named this flow. Not a URL.
    pub domain: Option<String>,
    /// How `domain` was chosen. `Some("sni")` or `None`.
    pub domain_source: Option<String>,
    /// Record-level evidence of the opening event. Not raised later.
    pub evidence: Evidence,
    /// Evidence of the byte observations. `S` only when every byte event was `S`.
    pub byte_evidence: Option<Evidence>,
    /// `true` when any byte event was not `S`.
    saw_nonsampled_bytes: bool,
    /// `true` when any byte event was `S`.
    saw_sampled_bytes: bool,
    pub source: Source,
    /// Bucket start → bytes added in that window. A direction stays `None`
    /// until that direction is seen inside the bucket.
    buckets: BTreeMap<u64, BucketAcc>,
    /// Buckets already written to `Output`. A later event in the same window
    /// emits a replacement row with the new sum (the store UPSERTs).
    emitted_buckets: BTreeMap<u64, (Option<u64>, Option<u64>)>,
    /// Last monotonic time a partial `NetFlowRec` was emitted. `None` until the
    /// first partial, so the 30 s wait is measured from `first`.
    last_partial_ns: Option<u64>,
    closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct BucketAcc {
    up: Option<u64>,
    down: Option<u64>,
}

impl NetAggregator {
    /// `bucket_secs` is `aggregate.bucket_secs`. `0` is not a width; it becomes
    /// the documented default of 5 s rather than a bucket that never advances.
    pub fn new(bucket_secs: u64) -> Self {
        let secs = if bucket_secs == 0 { 5 } else { bucket_secs };
        Self {
            bucket_ns: secs.saturating_mul(1_000_000_000),
            open: BTreeMap::new(),
            index: HashMap::new(),
            closed: Vec::new(),
            next_id: 1,
            now_ns: None,
        }
    }

    /// Apply one event. Non-network events are ignored. The event is not stored.
    pub fn observe(&mut self, event: &RawEvent, out: &mut Output) {
        self.advance(event.ts_mono_ns, out);
        match &event.kind {
            EventKind::NetConnect(connect) => {
                let acc = self.ensure(&connect.flow, event);
                if acc.direction.is_none() {
                    acc.direction = Some(connect.direction);
                }
            }
            EventKind::NetSend(send) => {
                self.add_bytes(&send.flow, event, send.bytes, true);
            }
            EventKind::NetRecv(recv) => {
                self.add_bytes(&recv.flow, event, recv.bytes, false);
            }
            EventKind::NetClose(close) => {
                self.close_flow(&close.flow, event, close.total_sent, close.total_recv, out);
            }
            EventKind::TlsSni(sni) => {
                if sni.sni.is_empty() {
                    // An empty name is not a domain. Leave the field unknown.
                    return;
                }
                let acc = self.ensure(&sni.flow, event);
                acc.domain = Some(sni.sni.clone());
                acc.domain_source = Some("sni".to_owned());
            }
            _ => {}
        }
    }

    /// Close idle UDP flows and emit buckets / partials that `now_ns` made due.
    ///
    /// Does not read a clock. A time that goes backwards is ignored for idle
    /// checks; buckets already started are not rewritten.
    pub fn tick(&mut self, now_ns: u64, out: &mut Output) {
        self.advance(now_ns, out);
    }

    /// Change the bucket width. The degrade ladder calls this when it changes
    /// level (5 s at L0, 30 s above). Buckets already started keep their start
    /// time; only later events fall into the new width.
    pub fn set_bucket_secs(&mut self, bucket_secs: u64) {
        let secs = if bucket_secs == 0 { 5 } else { bucket_secs };
        self.bucket_ns = secs.saturating_mul(1_000_000_000);
    }

    /// Group every flow this aggregator has seen, open and closed.
    pub fn summarize(&self, by: FlowGroupBy) -> Vec<FlowSummary> {
        // A closed flow stays in `open` and is also copied into `closed`.
        // Take it from `closed` only, so its bytes are not counted twice.
        let mut rows: Vec<NetFlowRec> = self.closed.clone();
        for acc in self.open.values() {
            if !acc.closed {
                rows.push(acc.snapshot(false));
            }
        }
        summarize(&rows, by)
    }

    fn advance(&mut self, now_ns: u64, out: &mut Output) {
        self.now_ns = Some(now_ns);
        let idle: Vec<u64> = self
            .open
            .iter()
            .filter(|(_, acc)| !acc.closed && acc.proto_is_udp() && idle_due(acc.last, now_ns))
            .map(|(id, _)| *id)
            .collect();
        for id in idle {
            if let Some(acc) = self.open.get_mut(&id) {
                acc.closed = true;
                acc.emit_due_buckets(now_ns, out);
                let rec = acc.snapshot(false);
                out.net_flows.push(rec.clone());
                self.closed.push(rec);
            }
        }
        let ids: Vec<u64> = self.open.keys().copied().collect();
        for id in ids {
            let Some(acc) = self.open.get_mut(&id) else {
                continue;
            };
            if acc.closed {
                continue;
            }
            acc.emit_due_buckets(now_ns, out);
            if partial_due(acc, now_ns) {
                out.net_flows.push(acc.snapshot(true));
                acc.last_partial_ns = Some(now_ns);
            }
        }
    }

    fn ensure(&mut self, flow: &FlowKey, event: &RawEvent) -> &mut FlowAcc {
        if !self.index.contains_key(flow) {
            let id = self.next_id;
            self.next_id = self.next_id.saturating_add(1);
            self.index.insert(flow.clone(), id);
            self.open.insert(
                id,
                FlowAcc {
                    flow_id: id,
                    session_id: event.session_id,
                    proc_uid: event.proc.as_ref().map(|proc| proc.uid),
                    flow: flow.clone(),
                    direction: None,
                    first: event.ts_mono_ns,
                    last: event.ts_mono_ns,
                    bytes_up: None,
                    bytes_down: None,
                    domain: None,
                    domain_source: None,
                    evidence: event.evidence.clone(),
                    byte_evidence: None,
                    saw_nonsampled_bytes: false,
                    saw_sampled_bytes: false,
                    source: event.source.clone(),
                    buckets: BTreeMap::new(),
                    emitted_buckets: BTreeMap::new(),
                    last_partial_ns: None,
                    closed: false,
                },
            );
        }
        let id = self.index[flow];
        // `id` came from `index`, which is only written together with `open`.
        let acc = match self.open.get_mut(&id) {
            Some(acc) => acc,
            None => unreachable!("flow id is inserted into open and index together"),
        };
        if event.ts_mono_ns < acc.first {
            acc.first = event.ts_mono_ns;
        }
        if event.ts_mono_ns > acc.last {
            acc.last = event.ts_mono_ns;
        }
        if acc.proc_uid.is_none() {
            acc.proc_uid = event.proc.as_ref().map(|proc| proc.uid);
        }
        if acc.session_id.is_none() {
            acc.session_id = event.session_id;
        }
        acc
    }

    fn add_bytes(&mut self, flow: &FlowKey, event: &RawEvent, bytes: u64, up: bool) {
        let bucket_ns = self.bucket_ns;
        let acc = self.ensure(flow, event);
        if event.evidence == Evidence::S {
            acc.saw_sampled_bytes = true;
        } else {
            acc.saw_nonsampled_bytes = true;
        }
        acc.byte_evidence = Some(acc.byte_grade());
        let total = if up {
            &mut acc.bytes_up
        } else {
            &mut acc.bytes_down
        };
        *total = Some(total.unwrap_or(0).saturating_add(bytes));
        let start = bucket_start(event.ts_mono_ns, bucket_ns);
        let bucket = acc.buckets.entry(start).or_default();
        let side = if up { &mut bucket.up } else { &mut bucket.down };
        *side = Some(side.unwrap_or(0).saturating_add(bytes));
    }

    fn close_flow(
        &mut self,
        flow: &FlowKey,
        event: &RawEvent,
        total_sent: Option<u64>,
        total_recv: Option<u64>,
        out: &mut Output,
    ) {
        let bucket_ns = self.bucket_ns;
        let acc = self.ensure(flow, event);
        let _ = bucket_ns;
        acc.closed = true;
        acc.emit_due_buckets(event.ts_mono_ns, out);
        // The close itself is not a byte event. Flush every bucket, including
        // the one the close landed in: the flow is done.
        acc.emit_all_buckets(out);
        let mut rec = acc.snapshot(false);
        rec.platform_total_up = total_sent;
        rec.platform_total_down = total_recv;
        apply_calibration(&mut rec);
        // Keep the calibrated evidence on the accumulator so a later summary
        // matches the row that was emitted.
        acc.byte_evidence = byte_evidence_of(&rec);
        out.net_flows.push(rec.clone());
        self.closed.push(rec);
    }
}

impl FlowAcc {
    fn proto_is_udp(&self) -> bool {
        self.flow.proto == L4Proto::Udp
    }

    fn byte_grade(&self) -> Evidence {
        if self.saw_sampled_bytes && !self.saw_nonsampled_bytes {
            Evidence::S
        } else {
            self.evidence.clone()
        }
    }

    fn snapshot(&self, partial: bool) -> NetFlowRec {
        let (local_ip, local_port) = split_addr(self.flow.local);
        let (remote_ip, remote_port) = split_addr(self.flow.remote);
        let byte_ev = self.byte_evidence.clone();
        let mut field_evidence = BTreeMap::new();
        if let Some(ev) = byte_ev {
            if ev != self.evidence {
                if self.bytes_up.is_some() {
                    field_evidence.insert(BYTES_UP_FIELD.to_owned(), ev.clone());
                }
                if self.bytes_down.is_some() {
                    field_evidence.insert(BYTES_DOWN_FIELD.to_owned(), ev);
                }
            }
        }
        NetFlowRec {
            session_id: self.session_id,
            proc_uid: self.proc_uid,
            proto: Some(proto_name(self.flow.proto).to_owned()),
            direction: self.direction.map(|dir| direction_name(dir).to_owned()),
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            domain: self.domain.clone(),
            domain_source: self.domain_source.clone(),
            sni: self.domain.clone(),
            bytes_up: self.bytes_up,
            bytes_down: self.bytes_down,
            start_ns: self.first,
            end_ns: if partial { None } else { Some(self.last) },
            via_proxy: false,
            partial,
            platform_total_up: None,
            platform_total_down: None,
            bytes_up_delta: None,
            bytes_down_delta: None,
            evidence: self.evidence.clone(),
            field_evidence,
            source: self.source.clone(),
            flow_id: Some(self.flow_id),
        }
    }

    /// Emit buckets whose window has ended, and the current window if it
    /// already holds bytes (so a live view sees them). A bucket is emitted
    /// again only when its totals changed.
    fn emit_due_buckets(&mut self, now_ns: u64, out: &mut Output) {
        let width = bucket_width_of(self);
        let current = bucket_start(now_ns, width);
        let keys: Vec<u64> = self.buckets.keys().copied().collect();
        for start in keys {
            if start > current {
                continue;
            }
            self.emit_bucket(start, out);
        }
    }

    fn emit_all_buckets(&mut self, out: &mut Output) {
        let keys: Vec<u64> = self.buckets.keys().copied().collect();
        for start in keys {
            self.emit_bucket(start, out);
        }
    }

    fn emit_bucket(&mut self, start: u64, out: &mut Output) {
        let Some(bucket) = self.buckets.get(&start).copied() else {
            return;
        };
        if bucket.up.is_none() && bucket.down.is_none() {
            return;
        }
        if self.emitted_buckets.get(&start) == Some(&(bucket.up, bucket.down)) {
            return;
        }
        self.emitted_buckets.insert(start, (bucket.up, bucket.down));
        let grade = self.byte_grade();
        let mut field_evidence = BTreeMap::new();
        if grade == Evidence::S {
            if bucket.up.is_some() {
                field_evidence.insert(BYTES_UP_FIELD.to_owned(), Evidence::S);
            }
            if bucket.down.is_some() {
                field_evidence.insert(BYTES_DOWN_FIELD.to_owned(), Evidence::S);
            }
        }
        out.flow_buckets.push(FlowBucketRec {
            flow_id: Some(self.flow_id),
            session_id: self.session_id,
            bucket_ns: start,
            bytes_up: bucket.up,
            bytes_down: bucket.down,
            evidence: if grade == Evidence::S {
                Evidence::S
            } else {
                self.evidence.clone()
            },
            field_evidence,
        });
    }
}

fn bucket_width_of(_acc: &FlowAcc) -> u64 {
    // Width is not stored on the acc. Callers pass absolute starts already
    // aligned, and `emit_due_buckets` only needs the current window start,
    // which it computes from the aggregator's width before calling this.
    // The current window is passed in as `now_ns` already compared by the
    // caller via `bucket_start`. This helper is unused; kept out.
    0
}

fn idle_due(last_ns: u64, now_ns: u64) -> bool {
    now_ns.saturating_sub(last_ns) >= UDP_IDLE_NS
}

fn partial_due(acc: &FlowAcc, now_ns: u64) -> bool {
    let since = acc.last_partial_ns.unwrap_or(acc.first);
    now_ns.saturating_sub(since) >= PARTIAL_FLUSH_NS && now_ns > acc.first
}

fn bucket_start(ts_ns: u64, width_ns: u64) -> u64 {
    if width_ns == 0 {
        return ts_ns;
    }
    ts_ns - (ts_ns % width_ns)
}

/// Compare our sum with the platform total. A missing side is not compared
/// and is not filled in from the other number.
fn apply_calibration(rec: &mut NetFlowRec) {
    calibrate_side(
        rec.bytes_up,
        rec.platform_total_up,
        &mut rec.bytes_up_delta,
        BYTES_UP_FIELD,
        &mut rec.field_evidence,
    );
    calibrate_side(
        rec.bytes_down,
        rec.platform_total_down,
        &mut rec.bytes_down_delta,
        BYTES_DOWN_FIELD,
        &mut rec.field_evidence,
    );
}

fn calibrate_side(
    ours: Option<u64>,
    platform: Option<u64>,
    delta_out: &mut Option<i64>,
    field: &str,
    field_evidence: &mut BTreeMap<String, Evidence>,
) {
    let (Some(ours), Some(platform)) = (ours, platform) else {
        return;
    };
    if !exceeds_five_percent(ours, platform) {
        return;
    }
    *delta_out = Some(signed_delta(platform, ours));
    field_evidence.insert(field.to_owned(), DEVIATION_EVIDENCE);
}

/// `true` when `|platform - ours| / max(platform, ours, 1) > 5%`.
///
/// Both zero agrees. Using the larger count as the base means a small
/// absolute gap on a large flow stays under 5%, and a large gap on a small
/// flow does not.
fn exceeds_five_percent(ours: u64, platform: u64) -> bool {
    let diff = ours.abs_diff(platform);
    if diff == 0 {
        return false;
    }
    let base = ours.max(platform).max(1);
    // diff/base > 5/100  ⇔  diff * 100 > base * 5. Saturating so a huge flow
    // does not wrap into a false "within 5%".
    diff.saturating_mul(CALIBRATION_DEN) > base.saturating_mul(CALIBRATION_NUM)
}

fn signed_delta(platform: u64, ours: u64) -> i64 {
    if platform >= ours {
        i64::try_from(platform - ours).unwrap_or(i64::MAX)
    } else {
        -i64::try_from(ours - platform).unwrap_or(i64::MAX)
    }
}

fn byte_evidence_of(rec: &NetFlowRec) -> Option<Evidence> {
    rec.field_evidence
        .get(BYTES_UP_FIELD)
        .or_else(|| rec.field_evidence.get(BYTES_DOWN_FIELD))
        .cloned()
}

fn proto_name(proto: L4Proto) -> &'static str {
    match proto {
        L4Proto::Tcp => "tcp",
        L4Proto::Udp => "udp",
        L4Proto::Unknown => "unknown",
    }
}

fn direction_name(direction: FlowDirection) -> &'static str {
    match direction {
        FlowDirection::Outbound => "outbound",
        FlowDirection::Inbound => "inbound",
        FlowDirection::Unknown => "unknown",
    }
}

/// Address text and port. A bare IP has no port, so the port stays `None`
/// rather than `0`.
fn split_addr(addr: SocketAddr) -> (Option<String>, Option<u16>) {
    match addr {
        SocketAddr::Ip(ip) => (Some(ip.to_string()), None),
        SocketAddr::Socket(sock) => (Some(sock.ip().to_string()), Some(sock.port())),
    }
}

/// Which column a live summary groups by. Combinations are one call per
/// dimension: the CLI joins them. A missing value groups under `None` and
/// is not dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowGroupBy {
    Proc,
    Domain,
    Ip,
    Port,
}

/// One group key. `None` means that field was not observed.
///
/// Ordered by hand because [`ProcUid`] is not `Ord` and `aw-core` is not
/// changed here. The order is only for stable summary output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowGroupKey {
    Proc(Option<ProcUid>),
    Domain(Option<String>),
    Ip(Option<String>),
    Port(Option<u16>),
}

impl PartialOrd for FlowGroupKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FlowGroupKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

impl FlowGroupKey {
    /// Discriminant, then the raw id or text. `None` sorts before `Some`.
    fn sort_key(&self) -> (u8, Option<u64>, &str, Option<u16>) {
        match self {
            Self::Proc(uid) => (0, uid.map(|uid| uid.0), "", None),
            Self::Domain(name) => (1, None, name.as_deref().unwrap_or(""), None),
            Self::Ip(ip) => (2, None, ip.as_deref().unwrap_or(""), None),
            Self::Port(port) => (3, None, "", *port),
        }
    }
}

/// Sum of one group. Byte totals are `None` when every flow in the group had
/// that direction unknown. A real zero stays `Some(0)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSummary {
    pub key: FlowGroupKey,
    pub flows: u64,
    pub bytes_up: Option<u64>,
    pub bytes_down: Option<u64>,
}

/// Group `flows` in memory. Does not read a clock and does not write.
pub fn summarize(flows: &[NetFlowRec], by: FlowGroupBy) -> Vec<FlowSummary> {
    let mut acc: BTreeMap<FlowGroupKey, FlowSummary> = BTreeMap::new();
    for flow in flows {
        if flow.partial {
            // A partial is a progress snapshot of a flow that also has, or
            // will have, a final row. Summing both would double the bytes.
            continue;
        }
        let key = match by {
            FlowGroupBy::Proc => FlowGroupKey::Proc(flow.proc_uid),
            FlowGroupBy::Domain => FlowGroupKey::Domain(flow.domain.clone()),
            FlowGroupBy::Ip => FlowGroupKey::Ip(flow.remote_ip.clone()),
            FlowGroupBy::Port => FlowGroupKey::Port(flow.remote_port),
        };
        let entry = acc.entry(key.clone()).or_insert_with(|| FlowSummary {
            key,
            flows: 0,
            bytes_up: None,
            bytes_down: None,
        });
        entry.flows = entry.flows.saturating_add(1);
        entry.bytes_up = add_opt(entry.bytes_up, flow.bytes_up);
        entry.bytes_down = add_opt(entry.bytes_down, flow.bytes_down);
    }
    acc.into_values().collect()
}

fn add_opt(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (None, None) => None,
        (Some(a), None) | (None, Some(a)) => Some(a),
        (Some(a), Some(b)) => Some(a.saturating_add(b)),
    }
}

/// Remote IP helper kept for grouping tests. Not a lookup.
#[allow(dead_code)]
fn remote_ip(addr: &SocketAddr) -> Option<IpAddr> {
    match addr {
        SocketAddr::Ip(ip) => Some(*ip),
        SocketAddr::Socket(sock) => Some(sock.ip()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::SocketAddr as StdAddr;

    use aw_core::{
        EventKind, Evidence, FlowDirection, FlowKey, L4Proto, NetClose, NetConnect, NetRecv,
        NetSend, ProcRef, ProcUid, RawEvent, RawEventParts, SessionId, Source, TlsSni,
    };

    use super::*;

    const TEN_MB: u64 = 10 * 1024 * 1024;
    const SENDS: u64 = 10_000;

    fn addr(ip: &str, port: u16) -> aw_core::SocketAddr {
        let std: StdAddr = format!("{ip}:{port}").parse().expect("addr");
        aw_core::SocketAddr::socket(std)
    }

    fn key(proto: L4Proto) -> FlowKey {
        FlowKey {
            proto,
            local: addr("10.0.0.2", 40000),
            remote: addr("93.184.216.34", 443),
            sock_id: Some(7),
        }
    }

    fn event(seq: u64, ts_ns: u64, evidence: Evidence, kind: EventKind) -> RawEvent {
        RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns: ts_ns,
            ts_wall_ns: 1_759_795_200_000_000_000,
            session_id: Some(SessionId(1)),
            proc: Some(ProcRef {
                uid: ProcUid(42),
                pid: 100,
                tid: None,
            }),
            source: Source::new("test/net"),
            evidence,
            kind,
        })
        .expect("event")
    }

    fn connect(seq: u64, ts: u64, flow: FlowKey) -> RawEvent {
        event(
            seq,
            ts,
            Evidence::E1,
            EventKind::NetConnect(NetConnect::new(flow, FlowDirection::Outbound, Some(0))),
        )
    }

    fn send(seq: u64, ts: u64, flow: FlowKey, bytes: u64, evidence: Evidence) -> RawEvent {
        event(
            seq,
            ts,
            evidence,
            EventKind::NetSend(NetSend::new(flow, bytes, None)),
        )
    }

    fn close(seq: u64, ts: u64, flow: FlowKey, up: Option<u64>, down: Option<u64>) -> RawEvent {
        event(
            seq,
            ts,
            Evidence::E1,
            EventKind::NetClose(NetClose::new(flow, up, down)),
        )
    }

    #[test]
    fn ten_megabytes_in_ten_thousand_sends_sums_buckets_and_flow() {
        let mut agg = NetAggregator::new(5);
        let mut out = Output::empty();
        let flow = key(L4Proto::Tcp);
        // 10000 sends of 1048.576 B is not an integer. Use exact slices:
        // 9999 sends of 1048 and one send of the remainder, summing to 10 MiB.
        let each = TEN_MB / SENDS;
        let remainder = TEN_MB - each * (SENDS - 1);
        assert_ne!(each, 0);
        agg.observe(&connect(1, 0, flow.clone()), &mut out);
        for i in 0..(SENDS - 1) {
            let ts = i.saturating_mul(1_000); // stays inside bucket 0
            agg.observe(&send(i + 2, ts, flow.clone(), each, Evidence::E1), &mut out);
        }
        agg.observe(
            &send(
                SENDS + 1,
                2_000_000_000,
                flow.clone(),
                remainder,
                Evidence::E1,
            ),
            &mut out,
        );
        agg.observe(
            &close(SENDS + 2, 3_000_000_000, flow, Some(TEN_MB), None),
            &mut out,
        );

        // Replacement rows repeat a bucket. Sum the latest row per bucket.
        let mut latest: BTreeMap<u64, u64> = BTreeMap::new();
        for bucket in &out.flow_buckets {
            latest.insert(bucket.bucket_ns, bucket.bytes_up.unwrap_or(0));
        }
        let bucket_up: u64 = latest.values().copied().sum();
        assert_eq!(bucket_up, TEN_MB);

        let finals: Vec<_> = out.net_flows.iter().filter(|row| !row.partial).collect();
        assert_eq!(finals.len(), 1);
        assert_eq!(finals[0].bytes_up, Some(TEN_MB));
        assert_eq!(finals[0].bytes_down, None, "no recv was observed");
        assert!(!finals[0].via_proxy);
        assert!(finals[0].bytes_up_delta.is_none(), "platform total matched");
    }

    #[test]
    fn events_cross_the_bucket_boundary_into_the_next_bucket() {
        let mut agg = NetAggregator::new(5);
        let mut out = Output::empty();
        let flow = key(L4Proto::Tcp);
        let width = 5_000_000_000u64;
        agg.observe(
            &send(1, width - 1, flow.clone(), 10, Evidence::E1),
            &mut out,
        );
        agg.observe(&send(2, width, flow.clone(), 20, Evidence::E1), &mut out);
        agg.observe(
            &send(3, width + 1, flow.clone(), 30, Evidence::E1),
            &mut out,
        );
        agg.observe(&close(4, width + 2, flow, None, None), &mut out);

        let mut by_bucket: BTreeMap<u64, u64> = BTreeMap::new();
        for bucket in &out.flow_buckets {
            by_bucket.insert(bucket.bucket_ns, bucket.bytes_up.unwrap_or(0));
        }
        assert_eq!(by_bucket.get(&0), Some(&10));
        assert_eq!(by_bucket.get(&width), Some(&50));
        assert_eq!(by_bucket.len(), 2);
    }

    #[test]
    fn udp_closes_after_sixty_quiet_seconds() {
        let mut agg = NetAggregator::new(5);
        let mut out = Output::empty();
        let flow = key(L4Proto::Udp);
        agg.observe(&send(1, 1_000, flow.clone(), 8, Evidence::E1), &mut out);
        agg.tick(1_000 + UDP_IDLE_NS - 1, &mut out);
        assert!(
            out.net_flows
                .iter()
                .all(|row| row.partial || row.end_ns.is_none()),
            "not idle yet"
        );
        let closed_before = out.net_flows.iter().filter(|row| !row.partial).count();
        agg.tick(1_000 + UDP_IDLE_NS, &mut out);
        let closed: Vec<_> = out.net_flows.iter().filter(|row| !row.partial).collect();
        assert_eq!(closed.len(), closed_before + 1);
        assert_eq!(closed[0].bytes_up, Some(8));
        assert_eq!(closed[0].proto.as_deref(), Some("udp"));
        assert_eq!(closed[0].end_ns, Some(1_000));
    }

    #[test]
    fn platform_total_off_by_more_than_five_percent_is_marked() {
        let mut agg = NetAggregator::new(5);
        let mut out = Output::empty();
        let flow = key(L4Proto::Tcp);
        agg.observe(&send(1, 1, flow.clone(), 100, Evidence::E1), &mut out);
        // 100 vs 120 is 20/120 > 5%.
        agg.observe(&close(2, 2, flow, Some(120), None), &mut out);
        let rec = out.net_flows.iter().find(|row| !row.partial).unwrap();
        assert_eq!(rec.bytes_up, Some(100));
        assert_eq!(rec.platform_total_up, Some(120));
        assert_eq!(rec.bytes_up_delta, Some(20));
        assert_eq!(rec.field_evidence.get(BYTES_UP_FIELD), Some(&Evidence::S));
        assert_eq!(rec.evidence, Evidence::E1, "record level is not raised");
        assert!(rec.bytes_down_delta.is_none());
    }

    #[test]
    fn platform_total_within_five_percent_is_not_marked() {
        let mut agg = NetAggregator::new(5);
        let mut out = Output::empty();
        let flow = key(L4Proto::Tcp);
        agg.observe(&send(1, 1, flow.clone(), 1000, Evidence::E1), &mut out);
        // 1000 vs 1040 is 40/1040 < 5%.
        agg.observe(&close(2, 2, flow, Some(1040), None), &mut out);
        let rec = out.net_flows.iter().find(|row| !row.partial).unwrap();
        assert!(rec.bytes_up_delta.is_none());
        assert!(!rec.field_evidence.contains_key(BYTES_UP_FIELD));
    }

    #[test]
    fn sampled_bytes_stay_s_and_a_missing_direction_stays_none() {
        let mut agg = NetAggregator::new(5);
        let mut out = Output::empty();
        let flow = key(L4Proto::Tcp);
        agg.observe(&send(1, 1, flow.clone(), 50, Evidence::S), &mut out);
        agg.observe(&close(2, 2, flow, None, None), &mut out);
        let rec = out.net_flows.iter().find(|row| !row.partial).unwrap();
        assert_eq!(rec.bytes_up, Some(50));
        assert_eq!(rec.bytes_down, None);
        // The whole record is already S, so the field is not marked again.
        assert!(!rec.field_evidence.contains_key(BYTES_UP_FIELD));
        assert_eq!(out.flow_buckets[0].evidence, Evidence::S);
        assert!(rec.domain.is_none());
        assert!(!rec.via_proxy);
    }

    #[test]
    fn long_flow_emits_a_partial_at_thirty_seconds() {
        let mut agg = NetAggregator::new(5);
        let mut out = Output::empty();
        let flow = key(L4Proto::Tcp);
        agg.observe(&send(1, 0, flow.clone(), 10, Evidence::E1), &mut out);
        agg.tick(PARTIAL_FLUSH_NS, &mut out);
        let partials: Vec<_> = out.net_flows.iter().filter(|row| row.partial).collect();
        assert_eq!(partials.len(), 1);
        assert_eq!(partials[0].bytes_up, Some(10));
        assert!(partials[0].end_ns.is_none());
        agg.observe(&close(2, PARTIAL_FLUSH_NS + 1, flow, None, None), &mut out);
        let finals: Vec<_> = out.net_flows.iter().filter(|row| !row.partial).collect();
        assert_eq!(finals.len(), 1);
        assert_eq!(finals[0].bytes_up, Some(10));
    }

    #[test]
    fn summarize_groups_by_proc_domain_ip_and_port() {
        let mut agg = NetAggregator::new(5);
        let mut out = Output::empty();
        let flow = key(L4Proto::Tcp);
        agg.observe(&connect(1, 0, flow.clone()), &mut out);
        agg.observe(
            &event(
                2,
                1,
                Evidence::E1,
                EventKind::TlsSni(TlsSni::new(flow.clone(), "example.com", Vec::new())),
            ),
            &mut out,
        );
        agg.observe(&send(3, 2, flow.clone(), 5, Evidence::E1), &mut out);
        agg.observe(
            &event(
                4,
                3,
                Evidence::E1,
                EventKind::NetRecv(NetRecv::new(flow.clone(), 7)),
            ),
            &mut out,
        );
        agg.observe(&close(5, 4, flow, None, None), &mut out);

        let by_proc = agg.summarize(FlowGroupBy::Proc);
        assert_eq!(by_proc.len(), 1);
        assert_eq!(by_proc[0].key, FlowGroupKey::Proc(Some(ProcUid(42))));
        assert_eq!(by_proc[0].bytes_up, Some(5));
        assert_eq!(by_proc[0].bytes_down, Some(7));

        let by_domain = summarize(&out.net_flows, FlowGroupBy::Domain);
        assert_eq!(
            by_domain[0].key,
            FlowGroupKey::Domain(Some("example.com".to_owned()))
        );
        let by_ip = summarize(&out.net_flows, FlowGroupBy::Ip);
        assert_eq!(
            by_ip[0].key,
            FlowGroupKey::Ip(Some("93.184.216.34".to_owned()))
        );
        let by_port = summarize(&out.net_flows, FlowGroupBy::Port);
        assert_eq!(by_port[0].key, FlowGroupKey::Port(Some(443)));
    }

    #[test]
    fn sni_empty_string_does_not_become_a_domain() {
        let mut agg = NetAggregator::new(5);
        let mut out = Output::empty();
        let flow = key(L4Proto::Tcp);
        agg.observe(
            &event(
                1,
                1,
                Evidence::E1,
                EventKind::TlsSni(TlsSni::new(flow.clone(), "", Vec::new())),
            ),
            &mut out,
        );
        agg.observe(&close(2, 2, flow, None, None), &mut out);
        let rec = out.net_flows.iter().find(|row| !row.partial).unwrap();
        assert!(rec.domain.is_none());
        assert!(rec.domain_source.is_none());
    }

    #[test]
    fn replay_of_a_constructed_sequence_is_stable() {
        // fixtures/linux/basic_proc_net/ does not exist yet (P1-LNX-03). This
        // is the in-memory stand-in: two replays of the same events match.
        let flow = key(L4Proto::Tcp);
        let events = vec![
            connect(1, 0, flow.clone()),
            send(2, 1_000_000_000, flow.clone(), 100, Evidence::E1),
            send(3, 6_000_000_000, flow.clone(), 250, Evidence::E1),
            close(4, 6_000_000_100, flow, Some(350), Some(0)),
        ];
        let cfg = crate::config::PipelineConfig::default();
        let first = crate::pipeline::Pipeline::replay(events.clone(), cfg.clone());
        let second = crate::pipeline::Pipeline::replay(events, cfg);
        assert_eq!(first.net_flows, second.net_flows);
        assert_eq!(first.flow_buckets, second.flow_buckets);
        let final_row = first
            .net_flows
            .iter()
            .find(|row| !row.partial)
            .expect("closed");
        assert_eq!(final_row.bytes_up, Some(350));
        assert_eq!(final_row.bytes_down, None);
        let mut latest: BTreeMap<u64, u64> = BTreeMap::new();
        for bucket in &first.flow_buckets {
            if let Some(up) = bucket.bytes_up {
                latest.insert(bucket.bucket_ns, up);
            }
        }
        assert_eq!(latest.values().copied().sum::<u64>(), 350);
    }
}
