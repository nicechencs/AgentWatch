//! nettop cumulative samples → `NetSend` / `NetRecv` / `NetConnect` / `NetClose`.
//!
//! This module does not spawn `nettop` and does not call a macOS API. It parses
//! one text sample and diffs it against the previous one. The process that would
//! run `nettop -L 0 -s 1 -x -J bytes_in,bytes_out -m tcp` (macos.md §1.2) belongs
//! behind `cfg(target_os = "macos")` and is not implemented here: this crate is
//! built on hosts that do not have that binary.
//!
//! ## Input formats
//!
//! macos.md §1.2 names the command and says the output is CSV, and that the
//! process column is `name.pid`. It does **not** name the columns. SPIKE-03 is
//! 「未开始」. Two layouts are accepted. Neither is treated as a measured byte
//! error; both are decoded as written.
//!
//! The column layout `nettop -P -L 1 -x` was assumed to print, which is what the
//! task card asks to assume when the document does not give one:
//!
//! ```text
//! time,process,interface,state,proto,local,remote,bytes_in,bytes_out
//! 1.000,curl.4242,en0,Established,tcp,10.0.0.5:51544,203.0.113.10:443,100,40
//! 1.000,curl.4242,,,udp,,,,,
//! ```
//!
//! The layout `nettop -L 1 -x -n -J bytes_in,bytes_out` actually prints on this
//! Mac (macOS, logging mode, no name resolution). A process row carries the
//! cumulative counters. Each following row whose first cell is a flow belongs to
//! that process, until the next process row:
//!
//! ```text
//! ,bytes_in,bytes_out,
//! 2.1.296.51854,3943,123596,
//! tcp4 192.168.8.53:60034<->198.18.3.149:443,3943,123596,
//! ```
//!
//! A flow cell is `tcp4`, `tcp6`, `udp4`, or `udp6`, then a space, then
//! `local<->remote`. `*` and `*.*` are an unspecified address. `.` separates an
//! IPv6 address from its port (`::1.8021`); `:` separates an IPv4 address from
//! its port. Bytes on a flow row are that flow's own cumulative counters. A flow
//! row with empty counters is a socket with no byte reading (a listener, for
//! example), not a zero transfer.
//!
//! Rules:
//!
//! - One sample is the lines between two blank lines, or one shot of lines passed
//!   to [`NettopDecoder::push_sample`]. A line whose first cell is `time` is a
//!   header and is skipped. A line that is empty or starts with `#` is skipped.
//!   A line whose only cells are empty or the names `bytes_in` / `bytes_out` is
//!   the column banner of `-J` and is skipped.
//! - Cells are split on `,`. A cell may be quoted with `"`; a doubled `""` inside
//!   quotes is one quote. Whitespace around a cell is trimmed.
//! - `process` is `name.pid`. The pid is the trailing `.` plus a decimal integer.
//!   A name that itself contains `.` is fine (`com.apple.curl.4242` → pid 4242).
//!   A row whose process cell has no trailing pid is not a flow and is dropped
//!   with a counted parse gap, not guessed as pid 0. A flow row with no preceding
//!   process row in the same sample is the same kind of gap: the pid was not in
//!   the text.
//! - `proto` is `tcp` or `udp` (ASCII, case-insensitive). Anything else, including
//!   an empty cell, is `L4Proto::Unknown`. UDP inclusion is 【待验证】 in macos.md
//!   §1.2, so a `udp` cell is accepted and not invented when the cell is empty.
//! - `local` and `remote` are `ip:port` or `[ipv6]:port`. An empty cell is a
//!   missing address, not `0.0.0.0:0`.
//! - `bytes_in` and `bytes_out` are **cumulative** decimal integers since the
//!   flow appeared, matching `-J bytes_in,bytes_out`. An empty cell is "not
//!   reported", not zero.
//! - A row with a five-tuple (proto plus both sockets) is a per-connection row.
//!   A row whose address cells are all empty is a process rollup (`-P`). Both
//!   are accepted in the same sample. Rollup rows do not produce connect/close.
//! - `state` is recorded and not interpreted. nettop's state strings are part of
//!   the unverified format. A row that disappears from the next sample is a close.
//!
//! ## What a sample emits
//!
//! | observation | event | evidence |
//! |---|---|---|
//! | connection present now, absent from the previous sample | `NetConnect` | S |
//! | connection present in the previous sample, absent now | `NetClose` | S |
//! | `bytes_out` grew since the previous sample | `NetSend` | S |
//! | `bytes_in` grew since the previous sample | `NetRecv` | S |
//! | first time a row is seen (no baseline) | no byte event | `bytes` is `NA(collector_unavailable)`, not `0` |
//! | counter went backwards | no byte event | `bytes` is `NA(collector_unavailable)` — a reset is not a negative delta |
//!
//! The first sample is a baseline. Connections already in it are **not** reported
//! as new: they were established before observation started, and saying otherwise
//! would be a guess. A later sample that adds one does emit `NetConnect`. A
//! connection that lives entirely between two samples is not invented.
//!
//! Only rows whose pid is inside the [`ProcessScope`] passed to the decoder are
//! kept. A pid outside the scope produces nothing — not a gap. The scope is the
//! caller's set; this module does not walk a process tree.
//!
//! `proc` stays `None`. nettop gives a pid and not a start time, so a [`ProcUid`]
//! cannot be hashed (process-tracking §2). Forging one from the pid alone would
//! collide after pid reuse. The pid that *was* observed is kept on [`NettopEvent`]
//! and the event marks `proc` `NA(collector_unavailable)`.
//!
//! A counter that is present is cumulative. The delta is the byte count. A delta
//! of exactly zero emits nothing: "no change this interval" is not a transfer.
//! The first observation of a counter has no previous value, so it emits no
//! `NetSend` / `NetRecv`. The same sample still records the cumulative numbers
//! on [`NettopEvent::baseline_bytes_in`] / [`NettopEvent::baseline_bytes_out`]
//! and, when a flow is also new, marks `bytes` NA on the connect event. A close
//! of a flow that never had a baseline leaves `total_sent` / `total_recv` as
//! `None` and marks both NA. A close of a flow that did have a baseline stores
//! the last cumulative totals (they were observed, not differenced).
//!
//! `source` is [`SOURCE_NETTOP_FLOW`] (`macos.nettop/flow`).

use std::collections::BTreeMap;
use std::str::FromStr;

use aw_core::{
    EventKind, Evidence, FlowDirection, FlowKey, Gap, GapKind, L4Proto, NaReason, NetClose,
    NetConnect, NetRecv, NetSend, RawEvent, SocketAddr, Source, SCHEMA_VERSION,
};

/// `macos.nettop/flow`. The task card names this string.
pub const SOURCE_NETTOP_FLOW: &str = "macos.nettop/flow";

/// Session note the task card requires.
///
/// Byte counts from nettop are a 1 s sample (evidence S). A connection that
/// exists for less than one sample interval can disappear without a row, so it
/// can be missed. Callers put this on the session record; the events themselves
/// already carry evidence S.
pub const SAMPLING_NOTE: &str = "macOS 网络字节为采样（S），持续不足 1 s 的连接可能遗漏";

/// The fixed sentence a session record should carry.
///
/// Returns [`SAMPLING_NOTE`]. A function, not only a constant, because the task
/// asks for a function the daemon can call without importing the string.
pub fn sampling_note() -> &'static str {
    SAMPLING_NOTE
}

/// Which pids a sample may emit events for.
///
/// An empty set keeps nothing. "Watch nobody" is not a scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessScope {
    members: Vec<u32>,
}

impl ProcessScope {
    /// Scope that accepts `members`. Duplicates are kept once, first-seen order.
    pub fn new(members: impl IntoIterator<Item = u32>) -> Self {
        let mut members: Vec<u32> = members.into_iter().collect();
        let mut seen = Vec::with_capacity(members.len());
        members.retain(|pid| {
            if seen.contains(pid) {
                false
            } else {
                seen.push(*pid);
                true
            }
        });
        Self { members }
    }

    /// Pids currently in scope, insertion order.
    pub fn members(&self) -> &[u32] {
        &self.members
    }

    /// `true` when `pid` is a current member.
    pub fn contains(&self, pid: u32) -> bool {
        self.members.contains(&pid)
    }
}

/// One parsed nettop row, before differencing.
///
/// Addresses and counters stay `Option`. Empty CSV cells are `None`, never a
/// zero address or a zero count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NettopRow {
    /// Process name from the `name.pid` cell, without the pid. Not used as an
    /// identity: names are not unique.
    pub name: String,
    /// Pid from the trailing `.pid`. Always present; a cell without one is not a row.
    pub pid: u32,
    /// `interface` cell, when it was non-empty.
    pub interface: Option<String>,
    /// `state` cell, uninterpreted.
    pub state: Option<String>,
    /// `tcp`, `udp`, or `Unknown` when the cell was empty or unrecognised.
    pub proto: L4Proto,
    /// Local socket. `None` when the cell was empty (a process rollup).
    pub local: Option<std::net::SocketAddr>,
    /// Remote socket. `None` when the cell was empty.
    pub remote: Option<std::net::SocketAddr>,
    /// Cumulative `bytes_in`. `None` when the cell was empty — not zero.
    pub bytes_in: Option<u64>,
    /// Cumulative `bytes_out`. `None` when the cell was empty — not zero.
    pub bytes_out: Option<u64>,
}

/// Identity of one flow inside the sampler.
///
/// A per-connection row is keyed by pid plus the five-tuple. A process rollup
/// (no addresses) is keyed by pid plus protocol only, so it cannot collide with
/// a connection of the same process. nettop has no socket id; `None` is the id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FlowId {
    pid: u32,
    proto: ProtoKey,
    local: Option<std::net::SocketAddr>,
    remote: Option<std::net::SocketAddr>,
    /// `true` when both address cells were empty. Rollups never connect or close.
    rollup: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ProtoKey {
    Tcp,
    Udp,
    Unknown,
}

impl FlowId {
    fn of(row: &NettopRow) -> Self {
        let proto = match row.proto {
            L4Proto::Tcp => ProtoKey::Tcp,
            L4Proto::Udp => ProtoKey::Udp,
            L4Proto::Unknown => ProtoKey::Unknown,
        };
        let rollup = row.local.is_none() && row.remote.is_none();
        Self {
            pid: row.pid,
            proto,
            local: row.local,
            remote: row.remote,
            rollup,
        }
    }

    fn is_connection(&self) -> bool {
        // A listener has a local address and no remote (`*:*`). That is still a
        // socket, not a process rollup. A rollup has neither address.
        !self.rollup && (self.local.is_some() || self.remote.is_some())
    }
}

/// Cumulative counters remembered from the previous sample that contained the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Baseline {
    bytes_in: Option<u64>,
    bytes_out: Option<u64>,
}

/// One decoded sample line's contribution, plus the fields [`RawEvent`] cannot store honestly.
///
/// `NetSend::bytes` is a plain `u64`. A first sample has no delta, and writing
/// `0` would claim a measured empty transfer. Those rows do not become a
/// `NetSend` / `NetRecv`. When the row is also a newly observed connection, the
/// connect event marks `bytes` `NA(collector_unavailable)` and the cumulative
/// readings (if the CSV had them) sit on this struct so a caller can see what
/// was *not* differenced.
#[derive(Debug, Clone, PartialEq)]
pub struct NettopEvent {
    /// The event. A parse gap, a connect, a close, or a differenced byte count.
    pub event: RawEvent,
    /// Pid the row named. Not a [`aw_core::ProcUid`].
    pub pid: Option<u32>,
    /// Cumulative `bytes_in` of a first observation. `None` when this event is
    /// not a baseline-only reading.
    pub baseline_bytes_in: Option<u64>,
    /// Cumulative `bytes_out` of a first observation.
    pub baseline_bytes_out: Option<u64>,
}

/// Clock the caller supplies. This module does not read a system clock, so a
/// test can replay the same text twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetSample {
    /// Monotonic nanoseconds in the daemon clock domain.
    pub ts_mono_ns: u64,
    /// Wall clock, Unix epoch nanoseconds. `None` is marked NA, not stored as `0`
    /// without a marker.
    pub ts_wall_ns: Option<i64>,
}

/// Stateful sampler. The previous sample is the baseline for the next one.
#[derive(Debug, Clone, Default)]
pub struct NettopDecoder {
    seen: BTreeMap<FlowId, Baseline>,
    /// `true` after the first sample. The first sample establishes the baseline
    /// and does not emit connect or byte events.
    started: bool,
    /// Next `RawEvent::seq`. Not a nettop column.
    next_seq: u64,
}

impl NettopDecoder {
    /// Decoder with no baseline and `seq` starting at 1.
    ///
    /// Sequence 0 is reserved by other collectors for a synthesized gap that has
    /// no clock. nettop samples are real observations, so they start at 1.
    pub fn new() -> Self {
        Self {
            seen: BTreeMap::new(),
            started: false,
            next_seq: 1,
        }
    }

    /// Parse `text` as one sample and diff it against the previous call.
    ///
    /// `scope` drops every row whose pid is not a member. Out-of-scope rows are
    /// not remembered, so a pid that later joins the scope is treated as new.
    ///
    /// A line that does not match the assumed format becomes one
    /// `Gap{parse_error}`. The rest of the sample is still decoded. An empty
    /// sample on a later call closes every connection the previous sample held
    /// that was in scope: they disappeared. The first call, even with no rows,
    /// only arms the baseline and emits nothing.
    ///
    /// # Errors
    ///
    /// This function does not return `Err`. A bad line is a parse gap inside the
    /// `Ok` value, because a collector must not discard one unreadable line by
    /// failing the whole sample. The `Result` is kept so a later macOS caller
    /// can still use `?` if the sink rejects the events.
    pub fn push_sample(
        &mut self,
        text: &str,
        scope: &ProcessScope,
        clock: NetSample,
    ) -> Result<Vec<NettopEvent>, NettopError> {
        Ok(self.push_inner(text, scope, clock))
    }

    fn push_inner(
        &mut self,
        text: &str,
        scope: &ProcessScope,
        clock: NetSample,
    ) -> Vec<NettopEvent> {
        let mut out = Vec::new();
        let mut current: BTreeMap<FlowId, NettopRow> = BTreeMap::new();
        // The logging layout prints a process row, then its flows. The pid is on
        // the process row only, so a flow row inherits the last one in this sample.
        let mut current_pid: Option<(String, u32)> = None;
        for (line_no, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match parse_line(line, current_pid.clone()) {
                LineParse::Header | LineParse::Skip => {}
                LineParse::Process(name, pid) => current_pid = Some((name, pid)),
                LineParse::Row(row) => {
                    current_pid = Some((row.name.clone(), row.pid));
                    if !scope.contains(row.pid) {
                        continue;
                    }
                    let id = FlowId::of(&row);
                    // Two rows of the same flow in one sample: keep the later
                    // counters. nettop prints a flow once; a duplicate is the
                    // same observation repeated, not a second connection.
                    current.insert(id, row);
                }
                LineParse::Bad { detail } => {
                    out.push(self.parse_gap(clock, line_no, detail));
                }
            }
        }

        if !self.started {
            self.started = true;
            self.remember(&current);
            // First sample: cumulative values, no delta. Connect would claim the
            // flow started inside the session. It did not; we only just looked.
            return out;
        }

        // Closes first, then connects, then byte deltas. A flow that vanished
        // and a different flow that appeared are independent.
        let previous_ids: Vec<FlowId> = self.seen.keys().cloned().collect();
        for id in &previous_ids {
            if current.contains_key(id) {
                continue;
            }
            if id.is_connection() {
                let baseline = self.seen.get(id).copied();
                out.push(self.emit_close(id, baseline, clock));
            }
        }

        for (id, row) in &current {
            let previous = self.seen.get(id).copied();
            if previous.is_none() && id.is_connection() {
                out.push(self.emit_connect(id, row, clock));
            }
            if let Some(delta) = byte_deltas(previous, row) {
                if let Some(sent) = delta.sent {
                    out.push(self.emit_bytes(id, row, Direction::Send, sent, clock));
                }
                if let Some(recv) = delta.recv {
                    out.push(self.emit_bytes(id, row, Direction::Recv, recv, clock));
                }
            }
        }

        self.seen.clear();
        self.remember(&current);
        out
    }

    fn remember(&mut self, current: &BTreeMap<FlowId, NettopRow>) {
        for (id, row) in current {
            self.seen.insert(
                id.clone(),
                Baseline {
                    bytes_in: row.bytes_in,
                    bytes_out: row.bytes_out,
                },
            );
        }
    }

    fn alloc_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }

    fn parse_gap(&mut self, clock: NetSample, line_no: usize, detail: &'static str) -> NettopEvent {
        let seq = self.alloc_seq();
        let gap = Gap::new(
            SOURCE_NETTOP_FLOW,
            GapKind::ParseError,
            vec!["net".to_owned()],
            clock.ts_mono_ns,
            clock.ts_mono_ns,
            Some(1),
            Some(format!("nettop line {line_no}: {detail}")),
        );
        let event = stamp(seq, clock, None, EventKind::Gap(gap), Evidence::E1);
        NettopEvent {
            event,
            pid: None,
            baseline_bytes_in: None,
            baseline_bytes_out: None,
        }
    }

    fn emit_connect(&mut self, id: &FlowId, row: &NettopRow, clock: NetSample) -> NettopEvent {
        let seq = self.alloc_seq();
        let flow = flow_key(id);
        // Direction is not a nettop column. Outbound is not assumed: the state
        // string is unverified, and a listener would look the same in this format.
        let kind = EventKind::NetConnect(NetConnect::new(flow, FlowDirection::Unknown, None));
        let mut event = stamp(seq, clock, Some(id.pid), kind, Evidence::S);
        event.mark_na("direction", NaReason::CollectorUnavailable);
        event.mark_na("result", NaReason::CollectorUnavailable);
        event.mark_na("proc", NaReason::CollectorUnavailable);
        // First time we see the counters there is no delta. The connect event
        // carries the NA so a reader does not treat a missing NetSend as "zero".
        event.mark_na("bytes", NaReason::CollectorUnavailable);
        mark_flow_gaps(&mut event, id);
        NettopEvent {
            event,
            pid: Some(id.pid),
            baseline_bytes_in: row.bytes_in,
            baseline_bytes_out: row.bytes_out,
        }
    }

    fn emit_close(
        &mut self,
        id: &FlowId,
        baseline: Option<Baseline>,
        clock: NetSample,
    ) -> NettopEvent {
        let seq = self.alloc_seq();
        let flow = flow_key(id);
        let (sent, recv) = match baseline {
            Some(baseline) => (baseline.bytes_out, baseline.bytes_in),
            None => (None, None),
        };
        let kind = EventKind::NetClose(NetClose::new(flow, sent, recv));
        let mut event = stamp(seq, clock, Some(id.pid), kind, Evidence::S);
        event.mark_na("proc", NaReason::CollectorUnavailable);
        if sent.is_none() {
            event.mark_na("total_sent", NaReason::CollectorUnavailable);
        }
        if recv.is_none() {
            event.mark_na("total_recv", NaReason::CollectorUnavailable);
        }
        mark_flow_gaps(&mut event, id);
        NettopEvent {
            event,
            pid: Some(id.pid),
            baseline_bytes_in: None,
            baseline_bytes_out: None,
        }
    }

    fn emit_bytes(
        &mut self,
        id: &FlowId,
        _row: &NettopRow,
        direction: Direction,
        bytes: u64,
        clock: NetSample,
    ) -> NettopEvent {
        let seq = self.alloc_seq();
        let flow = flow_key(id);
        let kind = match direction {
            Direction::Send => EventKind::NetSend(NetSend::new(flow, bytes, None)),
            Direction::Recv => EventKind::NetRecv(NetRecv::new(flow, bytes)),
        };
        let mut event = stamp(seq, clock, Some(id.pid), kind, Evidence::S);
        event.mark_na("proc", NaReason::CollectorUnavailable);
        if matches!(direction, Direction::Send) {
            // nettop does not say whether the bytes were sendfile. `None` without
            // a marker would read as "not sendfile".
            event.mark_na("via", NaReason::CollectorUnavailable);
        }
        mark_flow_gaps(&mut event, id);
        NettopEvent {
            event,
            pid: Some(id.pid),
            baseline_bytes_in: None,
            baseline_bytes_out: None,
        }
    }
}

#[derive(Clone, Copy)]
enum Direction {
    Send,
    Recv,
}

struct ByteDelta {
    sent: Option<u64>,
    recv: Option<u64>,
}

/// Positive deltas only.
///
/// `previous == None` is the first observation: both sides stay `None` (no
/// event). A counter that is absent this sample, or that moved backwards, is
/// also `None`. A zero delta is `None`: nothing was transferred this interval.
fn byte_deltas(previous: Option<Baseline>, row: &NettopRow) -> Option<ByteDelta> {
    let previous = previous?;
    let sent = diff_counter(previous.bytes_out, row.bytes_out);
    let recv = diff_counter(previous.bytes_in, row.bytes_in);
    if sent.is_none() && recv.is_none() {
        None
    } else {
        Some(ByteDelta { sent, recv })
    }
}

fn diff_counter(before: Option<u64>, after: Option<u64>) -> Option<u64> {
    match (before, after) {
        (Some(before), Some(after)) if after > before => Some(after - before),
        _ => None,
    }
}

fn flow_key(id: &FlowId) -> FlowKey {
    let proto = match id.proto {
        ProtoKey::Tcp => L4Proto::Tcp,
        ProtoKey::Udp => L4Proto::Udp,
        ProtoKey::Unknown => L4Proto::Unknown,
    };
    let local = id
        .local
        .map(SocketAddr::socket)
        .unwrap_or_else(unspecified_addr);
    let remote = id
        .remote
        .map(SocketAddr::socket)
        .unwrap_or_else(unspecified_addr);
    // nettop has no socket id. `None` is honest; it is not a fabricated inode.
    FlowKey::new(proto, local, remote, None)
}

fn unspecified_addr() -> SocketAddr {
    SocketAddr::socket(std::net::SocketAddr::from((
        std::net::Ipv4Addr::UNSPECIFIED,
        0,
    )))
}

fn mark_flow_gaps(event: &mut RawEvent, id: &FlowId) {
    if id.local.is_none() {
        event.mark_na("local", NaReason::CollectorUnavailable);
    }
    if id.remote.is_none() {
        event.mark_na("remote", NaReason::CollectorUnavailable);
    }
    // No sock_id column exists in the assumed format.
    event.mark_na("sock_id", NaReason::CollectorUnavailable);
}

fn stamp(
    seq: u64,
    clock: NetSample,
    _pid: Option<u32>,
    kind: EventKind,
    evidence: Evidence,
) -> RawEvent {
    let wall_known = clock.ts_wall_ns.is_some();
    let mut event = RawEvent {
        v: SCHEMA_VERSION,
        seq,
        ts_mono_ns: clock.ts_mono_ns,
        ts_wall_ns: clock.ts_wall_ns.unwrap_or(0),
        session_id: None,
        // Pid without a start time is not a ProcUid. See the module note.
        proc: None,
        source: Source::new(SOURCE_NETTOP_FLOW),
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

enum LineParse {
    Header,
    Skip,
    /// A process row in the logging layout. Its flows follow on later lines.
    Process(String, u32),
    Row(NettopRow),
    Bad {
        detail: &'static str,
    },
}

/// `current` is the process row this flow belongs to, when the sample has
/// printed one. The nine-column layout carries the pid on every row, so it
/// ignores `current`.
fn parse_line(line: &str, current: Option<(String, u32)>) -> LineParse {
    let cells = split_csv(line);
    if cells.is_empty() || cells.iter().all(|cell| cell.is_empty()) {
        return LineParse::Skip;
    }
    if cells[0].eq_ignore_ascii_case("time") {
        return LineParse::Header;
    }
    // `,bytes_in,bytes_out,` — the banner `-J` prints above the first process.
    if cells
        .iter()
        .all(|cell| cell.is_empty() || cell == "bytes_in" || cell == "bytes_out")
    {
        return LineParse::Skip;
    }
    if let Some(parsed) = parse_logging_line(&cells, current) {
        return parsed;
    }
    if cells.len() < 9 {
        return LineParse::Bad {
            detail: "fewer than 9 columns",
        };
    }
    let Some((name, pid)) = split_name_pid(&cells[1]) else {
        return LineParse::Bad {
            detail: "process cell has no trailing .pid",
        };
    };
    let proto = parse_proto(&cells[4]);
    let local = match parse_socket_cell(&cells[5]) {
        Ok(addr) => addr,
        Err(()) => {
            return LineParse::Bad {
                detail: "local address is not ip:port",
            };
        }
    };
    let remote = match parse_socket_cell(&cells[6]) {
        Ok(addr) => addr,
        Err(()) => {
            return LineParse::Bad {
                detail: "remote address is not ip:port",
            };
        }
    };
    let bytes_in = match parse_counter(&cells[7]) {
        Ok(n) => n,
        Err(()) => {
            return LineParse::Bad {
                detail: "bytes_in is not an integer",
            };
        }
    };
    let bytes_out = match parse_counter(&cells[8]) {
        Ok(n) => n,
        Err(()) => {
            return LineParse::Bad {
                detail: "bytes_out is not an integer",
            };
        }
    };
    LineParse::Row(NettopRow {
        name,
        pid,
        interface: non_empty(&cells[2]),
        state: non_empty(&cells[3]),
        proto,
        local,
        remote,
        bytes_in,
        bytes_out,
    })
}

/// The logging layout (`nettop -L -J bytes_in,bytes_out`).
///
/// A process cell (`name.pid`) with no `tcp4`/`udp6` prefix is a process row.
/// A flow cell belongs to `current`. `None` means this line is not that layout,
/// so the caller tries the nine-column layout.
fn parse_logging_line(cells: &[String], current: Option<(String, u32)>) -> Option<LineParse> {
    let first = cells.first()?.as_str();
    if let Some((prefix, rest)) = split_flow_prefix(first) {
        // A flow row names no pid of its own. Without the process row above it
        // there is nothing to attribute it to, and dropping the line would hide
        // that. The gap says so; the addresses are not copied into it.
        let Some((name, pid)) = current else {
            return Some(LineParse::Bad {
                detail: "flow row has no process row",
            });
        };
        let (local, remote) = split_endpoints(rest)?;
        let proto = if prefix.starts_with("tcp") {
            L4Proto::Tcp
        } else {
            L4Proto::Udp
        };
        let v6 = prefix.ends_with('6');
        let local = match parse_endpoint(local, v6) {
            Ok(addr) => addr,
            Err(()) => {
                return Some(LineParse::Bad {
                    detail: "local address is not ip:port",
                })
            }
        };
        let remote = match parse_endpoint(remote, v6) {
            Ok(addr) => addr,
            Err(()) => {
                return Some(LineParse::Bad {
                    detail: "remote address is not ip:port",
                })
            }
        };
        let bytes_in = parse_counter(cells.get(1).map(String::as_str).unwrap_or("")).ok()?;
        let bytes_out = parse_counter(cells.get(2).map(String::as_str).unwrap_or("")).ok()?;
        return Some(LineParse::Row(NettopRow {
            name,
            pid,
            interface: None,
            state: None,
            proto,
            local,
            remote,
            bytes_in,
            bytes_out,
        }));
    }
    // A process rollup: the first cell is `name.pid` and the next is a byte
    // counter. nettop prints the two cumulative counters here, and sometimes
    // more cells than the two `-J` asked for, so the cell count does not decide
    // this. The nine-column layout also has `name.pid`, but in its second cell
    // and followed by an interface name, so it does not match and falls through.
    let second_is_counter = cells
        .get(1)
        .is_some_and(|cell| cell.is_empty() || cell.bytes().all(|b| b.is_ascii_digit()));
    if second_is_counter {
        if let Some((name, pid)) = split_name_pid(first) {
            return Some(LineParse::Process(name, pid));
        }
    }
    None
}

/// `tcp4 10.0.0.1:1<->10.0.0.2:2` → `("tcp4", "10.0.0.1:1<->10.0.0.2:2")`.
///
/// `None` when the cell is not a flow. A process name is not a flow.
fn split_flow_prefix(cell: &str) -> Option<(&str, &str)> {
    let (prefix, rest) = cell.split_once(' ')?;
    if matches!(prefix, "tcp4" | "tcp6" | "udp4" | "udp6") {
        Some((prefix, rest))
    } else {
        None
    }
}

/// Split `local<->remote`. The marker is the separator nettop prints.
fn split_endpoints(cell: &str) -> Option<(&str, &str)> {
    cell.split_once("<->")
}

/// One side of a flow cell.
///
/// `*`, `*.*`, and an empty port are an unspecified address: `Ok(None)`, not
/// `0.0.0.0:0`. IPv4 uses `ip:port`. IPv6 uses `ip.port`, because the address
/// itself contains `:`. A side that is present but not that shape is `Err`.
fn parse_endpoint(cell: &str, v6: bool) -> Result<Option<std::net::SocketAddr>, ()> {
    let cell = cell.trim();
    if cell.is_empty() || cell == "*" || cell == "*.*" {
        return Ok(None);
    }
    if v6 {
        let (addr, port) = cell.rsplit_once('.').ok_or(())?;
        // `*.*` and `*.5353`: the address is unspecified. Same as the IPv4 `*:`.
        if addr == "*" {
            return Ok(None);
        }
        let port: u16 = port.parse().map_err(|_| ())?;
        // Link-local addresses carry the interface as `%en0`. The address is the
        // part before it; the zone is not part of the IP and is dropped.
        let addr = addr.split_once('%').map(|(ip, _)| ip).unwrap_or(addr);
        let ip: std::net::Ipv6Addr = addr.parse().map_err(|_| ())?;
        return Ok(Some(std::net::SocketAddr::from((ip, port))));
    }
    let (addr, port) = cell.rsplit_once(':').ok_or(())?;
    // `*:*` is the whole address unspecified, and `*:5353` is an unspecified
    // address with only a port. Neither is an IP, so both are "not observed"
    // rather than a parse error.
    if addr == "*" {
        return Ok(None);
    }
    let port: u16 = port.parse().map_err(|_| ())?;
    let ip: std::net::IpAddr = addr.parse().map_err(|_| ())?;
    Ok(Some(std::net::SocketAddr::from((ip, port))))
}

fn non_empty(cell: &str) -> Option<String> {
    if cell.is_empty() {
        None
    } else {
        Some(cell.to_owned())
    }
}

/// `name.pid`. The pid is the last `.` followed by digits only.
fn split_name_pid(cell: &str) -> Option<(String, u32)> {
    let (name, digits) = cell.rsplit_once('.')?;
    if name.is_empty() || digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let pid: u32 = digits.parse().ok()?;
    Some((name.to_owned(), pid))
}

fn parse_proto(cell: &str) -> L4Proto {
    if cell.eq_ignore_ascii_case("tcp") {
        L4Proto::Tcp
    } else if cell.eq_ignore_ascii_case("udp") {
        L4Proto::Udp
    } else {
        L4Proto::Unknown
    }
}

/// Empty → `Ok(None)`. A non-empty cell that is not a socket → `Err(())`.
fn parse_socket_cell(cell: &str) -> Result<Option<std::net::SocketAddr>, ()> {
    if cell.is_empty() {
        return Ok(None);
    }
    std::net::SocketAddr::from_str(cell)
        .map(Some)
        .map_err(|_| ())
}

fn parse_counter(cell: &str) -> Result<Option<u64>, ()> {
    if cell.is_empty() {
        return Ok(None);
    }
    cell.parse::<u64>().map(Some).map_err(|_| ())
}

/// Split one CSV line. Quotes are optional. No newline can appear inside a cell:
/// nettop prints one flow per line.
fn split_csv(line: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;
    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    cur.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push(ch);
            }
        } else if ch == '"' && cur.is_empty() {
            in_quotes = true;
        } else if ch == ',' {
            cells.push(std::mem::take(&mut cur).trim().to_owned());
        } else {
            cur.push(ch);
        }
    }
    cells.push(cur.trim().to_owned());
    cells
}

/// Decode error. No variant is constructed today: a bad line is a gap.
///
/// Kept so [`NettopDecoder::push_sample`]'s `Result` has a concrete error type
/// a later macOS caller can extend without changing the signature's shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NettopError {
    /// Reserved. Parsing does not fail the sample.
    Unused,
}

impl std::fmt::Display for NettopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unused => f.write_str("nettop decode does not fail the sample"),
        }
    }
}

/// Parse one sample with a fresh decoder. Tests and one-shot callers use this.
///
/// The first sample never emits connect or byte events. Pass the same text to
/// [`NettopDecoder`] twice to see a delta.
pub fn parse_nettop(
    text: &str,
    scope: &ProcessScope,
    clock: NetSample,
) -> Result<Vec<NettopEvent>, NettopError> {
    NettopDecoder::new().push_sample(text, scope, clock)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const CLOCK: NetSample = NetSample {
        ts_mono_ns: 1_000_000_000,
        ts_wall_ns: Some(1_700_000_000_000_000_000),
    };

    const HEADER: &str = "time,process,interface,state,proto,local,remote,bytes_in,bytes_out\n";

    fn scope(pids: &[u32]) -> ProcessScope {
        ProcessScope::new(pids.iter().copied())
    }

    fn row(pid: u32, bytes_in: u64, bytes_out: u64) -> String {
        format!(
            "1.000,curl.{pid},en0,Established,tcp,10.0.0.5:51544,203.0.113.10:443,{bytes_in},{bytes_out}\n"
        )
    }

    #[test]
    fn first_sample_emits_no_bytes_and_no_connect() {
        let text = format!("{HEADER}{}", row(4242, 100, 40));
        let events = parse_nettop(&text, &scope(&[4242]), CLOCK).expect("sample");
        assert!(
            events.is_empty(),
            "a first sample is a baseline, not a transfer"
        );
    }

    #[test]
    fn second_sample_diffs_bytes_at_evidence_s() {
        let mut dec = NettopDecoder::new();
        let first = format!("{HEADER}{}", row(4242, 100, 40));
        let second = format!("{HEADER}{}", row(4242, 150, 90));
        let _ = dec
            .push_sample(&first, &scope(&[4242]), CLOCK)
            .expect("baseline");
        let events = dec
            .push_sample(&second, &scope(&[4242]), CLOCK)
            .expect("delta");
        let sends: Vec<_> = events
            .iter()
            .filter(|ev| matches!(ev.event.kind, EventKind::NetSend(_)))
            .collect();
        let recvs: Vec<_> = events
            .iter()
            .filter(|ev| matches!(ev.event.kind, EventKind::NetRecv(_)))
            .collect();
        assert_eq!(sends.len(), 1);
        assert_eq!(recvs.len(), 1);
        match &sends[0].event.kind {
            EventKind::NetSend(send) => assert_eq!(send.bytes, 50),
            _ => unreachable!(),
        }
        match &recvs[0].event.kind {
            EventKind::NetRecv(recv) => assert_eq!(recv.bytes, 50),
            _ => unreachable!(),
        }
        assert_eq!(sends[0].event.evidence, Evidence::S);
        assert_eq!(sends[0].event.source.as_str(), SOURCE_NETTOP_FLOW);
        assert_eq!(sends[0].pid, Some(4242));
        assert!(sends[0].event.proc.is_none());
        assert!(sends[0]
            .event
            .field_evidence
            .get("proc")
            .is_some_and(Evidence::is_na));
    }

    #[test]
    fn pid_outside_scope_is_dropped() {
        let mut dec = NettopDecoder::new();
        let sample = format!("{HEADER}{}", row(7, 10, 10));
        let grown = format!("{HEADER}{}", row(7, 20, 30));
        let _ = dec
            .push_sample(&sample, &scope(&[4242]), CLOCK)
            .expect("base");
        let events = dec
            .push_sample(&grown, &scope(&[4242]), CLOCK)
            .expect("delta");
        assert!(events.is_empty(), "pid 7 is not in scope");
    }

    #[test]
    fn new_connection_on_the_second_sample_is_a_connect() {
        let mut dec = NettopDecoder::new();
        let _ = dec
            .push_sample(HEADER, &scope(&[4242]), CLOCK)
            .expect("empty baseline");
        let text = format!("{HEADER}{}", row(4242, 5, 5));
        let events = dec
            .push_sample(&text, &scope(&[4242]), CLOCK)
            .expect("appear");
        assert!(
            events
                .iter()
                .any(|ev| matches!(ev.event.kind, EventKind::NetConnect(_))),
            "a flow that was not in the baseline is a connect"
        );
        let connect = events
            .iter()
            .find(|ev| matches!(ev.event.kind, EventKind::NetConnect(_)))
            .expect("connect");
        assert_eq!(connect.event.evidence, Evidence::S);
        assert!(connect
            .event
            .field_evidence
            .get("bytes")
            .is_some_and(Evidence::is_na));
        assert_eq!(connect.baseline_bytes_in, Some(5));
        assert_eq!(connect.baseline_bytes_out, Some(5));
        assert!(
            events
                .iter()
                .all(|ev| !matches!(ev.event.kind, EventKind::NetSend(_) | EventKind::NetRecv(_))),
            "the first reading of a counter is not a delta"
        );
    }

    #[test]
    fn disappearance_is_a_close_with_last_totals() {
        let mut dec = NettopDecoder::new();
        let first = format!("{HEADER}{}", row(4242, 100, 40));
        let _ = dec
            .push_sample(&first, &scope(&[4242]), CLOCK)
            .expect("baseline");
        let events = dec
            .push_sample(HEADER, &scope(&[4242]), CLOCK)
            .expect("gone");
        assert_eq!(events.len(), 1);
        match &events[0].event.kind {
            EventKind::NetClose(close) => {
                assert_eq!(close.total_recv, Some(100));
                assert_eq!(close.total_sent, Some(40));
            }
            other => panic!("expected net_close, got {}", other.kind_name()),
        }
        assert_eq!(events[0].event.evidence, Evidence::S);
    }

    /// `nettop -L 1 -x -n -J bytes_in,bytes_out` as printed on this Mac.
    /// The process row carries the same totals as its one flow.
    const LOGGING: &str = "\
,bytes_in,bytes_out,
2.1.296.51854,3943,123596,
tcp4 192.168.8.53:60034<->198.18.3.149:443,3943,123596,
";

    #[test]
    fn logging_layout_first_sample_is_a_baseline() {
        let events = parse_nettop(LOGGING, &scope(&[51854]), CLOCK).expect("sample");
        assert!(
            events.is_empty(),
            "a connection already open at the first look is not a new connect"
        );
    }

    #[test]
    fn logging_layout_growth_is_a_delta_at_evidence_s() {
        let mut dec = NettopDecoder::new();
        let _ = dec
            .push_sample(LOGGING, &scope(&[51854]), CLOCK)
            .expect("baseline");
        let grown = LOGGING.replace("3943,123596,", "4000,124000,");
        let events = dec
            .push_sample(&grown, &scope(&[51854]), CLOCK)
            .expect("delta");
        let sends: Vec<_> = events
            .iter()
            .filter(|ev| matches!(ev.event.kind, EventKind::NetSend(_)))
            .collect();
        let recvs: Vec<_> = events
            .iter()
            .filter(|ev| matches!(ev.event.kind, EventKind::NetRecv(_)))
            .collect();
        assert_eq!(sends.len(), 1, "the process rollup is not a second flow");
        assert_eq!(recvs.len(), 1);
        match &sends[0].event.kind {
            EventKind::NetSend(send) => assert_eq!(send.bytes, 404),
            _ => unreachable!(),
        }
        match &recvs[0].event.kind {
            EventKind::NetRecv(recv) => assert_eq!(recv.bytes, 57),
            _ => unreachable!(),
        }
        assert_eq!(sends[0].event.evidence, Evidence::S);
        assert_eq!(sends[0].pid, Some(51854));
        match &sends[0].event.kind {
            EventKind::NetSend(send) => {
                assert_eq!(
                    send.flow.remote,
                    SocketAddr::socket("198.18.3.149:443".parse().unwrap())
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn logging_layout_listener_has_no_address_and_no_bytes() {
        let text = "\
,bytes_in,bytes_out,
launchd.1,0,0,
tcp4 127.0.0.1:8021<->*:*,,,
";
        let mut dec = NettopDecoder::new();
        let _ = dec.push_sample("", &scope(&[1]), CLOCK).expect("arm");
        let events = dec.push_sample(text, &scope(&[1]), CLOCK).expect("sample");
        assert!(
            events
                .iter()
                .any(|ev| matches!(ev.event.kind, EventKind::NetConnect(_))),
            "a socket that was not in the baseline is a connect"
        );
        assert!(
            events
                .iter()
                .all(|ev| !matches!(ev.event.kind, EventKind::NetSend(_) | EventKind::NetRecv(_))),
            "empty counters are not a zero-byte transfer"
        );
        assert!(
            events
                .iter()
                .all(|ev| !matches!(ev.event.kind, EventKind::Gap(_))),
            "`*:*` is an unspecified address, not a parse error"
        );
    }

    #[test]
    fn logging_layout_process_row_with_extra_cells_is_not_a_gap() {
        // A process row can carry more than the two counters `-J` asked for.
        // That is still the process, not a flow, and not a parse error.
        let text = "\
,bytes_in,bytes_out,
rapportd.656,46530,41102,7,
";
        let events = parse_nettop(text, &scope(&[656]), CLOCK).expect("sample");
        assert!(
            events
                .iter()
                .all(|ev| !matches!(ev.event.kind, EventKind::Gap(_))),
            "extra cells on a process row are not a parse error"
        );
    }

    #[test]
    fn logging_layout_flow_without_a_process_is_a_gap() {
        let text = "tcp4 192.168.8.53:60034<->198.18.3.149:443,3943,123596,\n";
        let events = parse_nettop(text, &scope(&[51854]), CLOCK).expect("sample");
        assert!(
            events
                .iter()
                .any(|ev| matches!(ev.event.kind, EventKind::Gap(_))),
            "a flow row with no process row has no pid"
        );
    }

    #[test]
    fn sampling_note_matches_the_required_sentence() {
        assert_eq!(
            sampling_note(),
            "macOS 网络字节为采样（S），持续不足 1 s 的连接可能遗漏"
        );
    }
}
