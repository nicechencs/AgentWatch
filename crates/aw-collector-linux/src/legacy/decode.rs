//! Pure decode of the legacy tier. No syscalls, no netlink, no `/proc`.
//!
//! Callers (tests, or the Linux stub in the parent module) hand in already-read
//! records. This module only maps them onto `aw-core` events and stamps evidence:
//!
//! | input | record evidence | field evidence |
//! |---|---|---|
//! | proc connector FORK / EXEC / EXIT | E1 | argv is S (read later from `/proc/<pid>/cmdline`, racy) |
//! | sock_diag `bytes_acked` / `bytes_received` delta | S | first sample has no baseline: bytes are `NA`, never `0` |
//! | AF_PACKET DNS packet joined to a socket by five-tuple | I | the five-tuple join is an inference, not an OS attribution |
//! | inode with no pid in the fd table | — | `NA(collector_unavailable)`, not pid `0` |
//!
//! Sources are the three strings linux.md §1 and the task card name:
//! `linux.legacy/proc_connector`, `linux.legacy/sock_diag`, `linux.legacy/af_packet`.

use aw_core::{
    DnsQuery, EventError, EventKind, Evidence, FlowKey, L4Proto, NaReason, NetRecv, NetSend,
    ProcessExit, ProcessStart, RawEvent, RawEventParts, SocketAddr, Source, StartHow,
};

/// `linux.legacy/proc_connector`.
pub const SOURCE_PROC_CONNECTOR: &str = "linux.legacy/proc_connector";
/// `linux.legacy/sock_diag`.
pub const SOURCE_SOCK_DIAG: &str = "linux.legacy/sock_diag";
/// `linux.legacy/af_packet`.
pub const SOURCE_AF_PACKET: &str = "linux.legacy/af_packet";

/// `field_evidence` key for argv. Differs from the E1 record.
pub const FIELD_ARGV: &str = "argv";
/// `field_evidence` key for a process the inode table did not contain.
pub const FIELD_PROC: &str = "proc";

/// One proc-connector event the kernel would have delivered.
///
/// The connector itself carries no argv. `argv` here is whatever a later
/// `/proc/<pid>/cmdline` read produced, and it is always stamped S — including
/// when the read returned nothing, which is `None`, not an empty success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcConnectorEvent {
    pub what: ProcWhat,
    /// Child (FORK) or the process itself (EXEC / EXIT).
    pub pid: u32,
    /// Parent. FORK and EXEC carry it; EXIT usually does not.
    pub ppid: Option<u32>,
    /// Exit status. Only meaningful for [`ProcWhat::Exit`].
    pub exit_code: Option<i32>,
    /// Signal that killed the process, if the connector reported one separately.
    pub signal: Option<i32>,
    /// Argv from `/proc/<pid>/cmdline`. `None` means the read missed (process
    /// already gone). Never invented.
    pub argv: Option<Vec<String>>,
    /// Executable path, same race as argv.
    pub exe: Option<String>,
    /// Monotonic start time in nanoseconds, when the caller already has one.
    /// `None` is not turned into `0`.
    pub start_time_ns: Option<i64>,
}

/// The three proc-connector event types this tier handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcWhat {
    Fork,
    Exec,
    Exit,
}

/// One socket row from a sock_diag sample.
///
/// Counters are cumulative `tcp_info` values. `None` means the sample did not
/// include that counter; it is not zero bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockSample {
    pub inode: u64,
    pub proto: L4Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// `tcpi_bytes_acked`. Cumulative. `None` if the diag reply omitted it.
    pub bytes_acked: Option<u64>,
    /// `tcpi_bytes_received`. Cumulative. `None` if the diag reply omitted it.
    pub bytes_received: Option<u64>,
}

/// One DNS packet seen on `AF_PACKET`, already reduced to the fields we keep.
///
/// The packet is attributed by five-tuple only. That join is [`Evidence::I`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPacket {
    pub proto: L4Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// Query name. Not logged by `Debug` of the resulting event beyond the schema type.
    pub qname: String,
    pub qtype: u16,
    pub txid: Option<u16>,
}

/// A socket the inode table knows about, used as the DNS join target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownSocket {
    pub inode: u64,
    pub proto: L4Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// What one counter did between two samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterStep {
    /// No earlier sample. Bytes must not be emitted.
    NoBaseline,
    /// Counter was absent on one side. Not the same as a zero delta.
    Missing,
    /// `current - previous`, including a `u64` wrap.
    Delta(u64),
}

/// Byte deltas for one socket that was present in the latest sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockDelta {
    pub inode: u64,
    pub proto: L4Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub sent: CounterStep,
    pub recv: CounterStep,
}

/// One inode → pid row from `/proc/<pid>/fd`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeOwner {
    pub inode: u64,
    pub pid: u32,
}

/// Why a proc-connector record was not turned into a [`RawEvent`].
///
/// `ProcessStart::ppid` and `ProcessStart::start_time_ns` are plain integers.
/// Writing `0` for a missing reading would claim a real parent or a real start
/// time, so the record is refused instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcSkip {
    /// FORK/EXEC arrived without a parent pid.
    MissingPpid,
    /// FORK/EXEC arrived without a start time.
    MissingStartTime,
    /// The assembled event failed schema validation.
    Invalid(EventError),
}

/// Process a proc-connector record decoded into, plus the argv stamp.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedProc {
    pub event: RawEvent,
}

/// sock_diag output for one socket in the latest sample.
///
/// A direction whose step is [`CounterStep::NoBaseline`] or [`CounterStep::Missing`]
/// produces no `NetSend` / `NetRecv`. A zero delta produces none either: nothing
/// moved. The caller still sees the step, so it can tell "no baseline" from "zero".
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedSock {
    pub delta: SockDelta,
    /// `NetSend` when `sent` is a non-zero [`CounterStep::Delta`].
    pub sent: Option<RawEvent>,
    /// `NetRecv` when `recv` is a non-zero [`CounterStep::Delta`].
    pub recv: Option<RawEvent>,
}

/// DNS packet joined to a socket, or explicitly not joined.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedDns {
    /// `Evidence::I` when a socket matched. `NA` when none did — the packet was
    /// seen, but it is not attributed to a process.
    pub event: RawEvent,
    /// Inode of the socket the five-tuple matched, if any.
    pub inode: Option<u64>,
}

/// Pid that owns `inode`, or why the table cannot say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeLookup {
    /// Exactly one pid had this inode open.
    Pid(u32),
    /// No row. Not pid 0.
    NotFound,
}

/// Map one proc-connector record to a process event.
///
/// Record evidence is E1. Argv, when present, is additionally marked S, because
/// it was read from `/proc` after the event and can already be stale. A missing
/// argv is `None` plus `NA(collector_unavailable)`, not an empty vector.
///
/// `ppid` and `start_time_ns` are required integers on `ProcessStart`. A missing
/// reading returns [`ProcSkip`] rather than writing `0`. EXIT does not need them:
/// a missing exit code stays `None` on the payload, which the schema allows.
pub fn decode_proc(
    event: &ProcConnectorEvent,
    seq: u64,
    ts_mono_ns: u64,
    ts_wall_ns: i64,
) -> Result<DecodedProc, ProcSkip> {
    let source = Source::new(SOURCE_PROC_CONNECTOR);
    let (kind, argv_na) = match event.what {
        ProcWhat::Exit => {
            let kind = EventKind::ProcessExit(ProcessExit::new(event.exit_code, event.signal));
            (kind, false)
        }
        ProcWhat::Fork | ProcWhat::Exec => {
            let ppid = event.ppid.ok_or(ProcSkip::MissingPpid)?;
            let start_time_ns = event.start_time_ns.ok_or(ProcSkip::MissingStartTime)?;
            let how = match event.what {
                ProcWhat::Fork => StartHow::Fork,
                ProcWhat::Exec => StartHow::Exec,
                ProcWhat::Exit => unreachable!("exit is handled above"),
            };
            let argv = event.argv.as_ref().map(|args| {
                args.iter()
                    .map(|arg| aw_core::Redacted::new(arg.clone()))
                    .collect()
            });
            let argv_na = argv.is_none();
            let kind = EventKind::ProcessStart(ProcessStart::new(
                ppid,
                None,
                start_time_ns,
                event.exe.clone(),
                argv,
                None,
                None,
                how,
                None,
                None,
            ));
            (kind, argv_na)
        }
    };

    let mut raw = RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns,
        ts_wall_ns,
        session_id: None,
        proc: None,
        source,
        evidence: Evidence::E1,
        kind,
    })
    .map_err(ProcSkip::Invalid)?;

    if argv_na {
        raw.mark_na(FIELD_ARGV, NaReason::CollectorUnavailable);
    } else if event.argv.is_some() && !matches!(event.what, ProcWhat::Exit) {
        raw.field_evidence
            .insert(FIELD_ARGV.to_string(), Evidence::S);
    }
    Ok(DecodedProc { event: raw })
}

/// Subtract two sock_diag samples.
///
/// `previous == None` is the first sample: every counter is [`CounterStep::NoBaseline`]
/// and no byte event is produced. A later sample subtracts with wrapping `u64`
/// arithmetic, so a counter that passed `u64::MAX` yields a small positive delta
/// instead of being dropped or reported as zero.
///
/// A delta of `0` is "nothing moved" and emits no event. It is not NA.
pub fn diff_sock(previous: Option<&SockSample>, current: &SockSample) -> SockDelta {
    let (sent, recv) = match previous {
        None => (CounterStep::NoBaseline, CounterStep::NoBaseline),
        Some(prev) => (
            step(prev.bytes_acked, current.bytes_acked),
            step(prev.bytes_received, current.bytes_received),
        ),
    };
    SockDelta {
        inode: current.inode,
        proto: current.proto,
        local: current.local,
        remote: current.remote,
        sent,
        recv,
    }
}

fn step(previous: Option<u64>, current: Option<u64>) -> CounterStep {
    match (previous, current) {
        (Some(prev), Some(curr)) => CounterStep::Delta(curr.wrapping_sub(prev)),
        _ => CounterStep::Missing,
    }
}

/// Turn one [`SockDelta`] into `NetSend` / `NetRecv` events.
///
/// Only a non-zero [`CounterStep::Delta`] becomes an event, at evidence S.
/// [`CounterStep::NoBaseline`] and [`CounterStep::Missing`] produce nothing:
/// emitting `bytes: 0` would claim a measurement that was not taken.
pub fn decode_sock_delta(
    delta: SockDelta,
    seq: &mut u64,
    ts_mono_ns: u64,
    ts_wall_ns: i64,
) -> Result<DecodedSock, EventError> {
    let flow = FlowKey::new(delta.proto, delta.local, delta.remote, Some(delta.inode));
    let sent = byte_event(delta.sent, true, &flow, seq, ts_mono_ns, ts_wall_ns)?;
    let recv = byte_event(delta.recv, false, &flow, seq, ts_mono_ns, ts_wall_ns)?;
    Ok(DecodedSock { delta, sent, recv })
}

fn byte_event(
    step: CounterStep,
    sent: bool,
    flow: &FlowKey,
    seq: &mut u64,
    ts_mono_ns: u64,
    ts_wall_ns: i64,
) -> Result<Option<RawEvent>, EventError> {
    let CounterStep::Delta(bytes) = step else {
        return Ok(None);
    };
    if bytes == 0 {
        return Ok(None);
    }
    let kind = if sent {
        EventKind::NetSend(NetSend::new(flow.clone(), bytes, None))
    } else {
        EventKind::NetRecv(NetRecv::new(flow.clone(), bytes))
    };
    let n = *seq;
    *seq = seq.saturating_add(1);
    RawEvent::try_new(RawEventParts {
        seq: n,
        ts_mono_ns,
        ts_wall_ns,
        session_id: None,
        proc: None,
        source: Source::new(SOURCE_SOCK_DIAG),
        evidence: Evidence::S,
        kind,
    })
    .map(Some)
}

/// Attribute one DNS packet to a socket by five-tuple.
///
/// A match is evidence I: the packet and the socket share a five-tuple, which
/// does not prove the process that owned the socket sent the packet. No match
/// is `NA(collector_unavailable)` on the record — the packet was captured, but
/// it is not assigned to inode 0 or pid 0.
pub fn attribute_dns(
    packet: &DnsPacket,
    sockets: &[KnownSocket],
    seq: u64,
    ts_mono_ns: u64,
    ts_wall_ns: i64,
) -> Result<DecodedDns, EventError> {
    let matched = sockets.iter().find(|sock| {
        sock.proto == packet.proto && sock.local == packet.local && sock.remote == packet.remote
    });
    let server = Some(packet.remote);
    let kind = EventKind::DnsQuery(DnsQuery::new(
        packet.qname.clone(),
        packet.qtype,
        packet.txid,
        server,
    ));
    let evidence = if matched.is_some() {
        Evidence::I
    } else {
        Evidence::NA(NaReason::CollectorUnavailable)
    };
    let event = RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns,
        ts_wall_ns,
        session_id: None,
        proc: None,
        source: Source::new(SOURCE_AF_PACKET),
        evidence,
        kind,
    })?;
    Ok(DecodedDns {
        event,
        inode: matched.map(|sock| sock.inode),
    })
}

/// Resolve a socket inode to a pid.
///
/// The first matching row wins. No row is [`InodeLookup::NotFound`], which the
/// caller stamps `NA(collector_unavailable)` — never pid `0`.
pub fn lookup_inode(inode: u64, owners: &[InodeOwner]) -> InodeLookup {
    match owners.iter().find(|owner| owner.inode == inode) {
        Some(owner) => InodeLookup::Pid(owner.pid),
        None => InodeLookup::NotFound,
    }
}

/// Evidence for a byte counter that was not measured, keyed by direction.
///
/// [`CounterStep::NoBaseline`] is the first sample: there is no previous total
/// to subtract, so the bytes are `NA(preexisting)`, not `0`.
/// [`CounterStep::Missing`] is a sample that omitted the counter:
/// `NA(collector_unavailable)`. A real [`CounterStep::Delta`] returns nothing,
/// because that value is the event's `bytes` field at evidence S.
pub fn counter_evidence(step: CounterStep, sent: bool) -> Option<(&'static str, Evidence)> {
    let field = if sent {
        "bytes_acked"
    } else {
        "bytes_received"
    };
    let reason = match step {
        CounterStep::NoBaseline => NaReason::Preexisting,
        CounterStep::Missing => NaReason::CollectorUnavailable,
        CounterStep::Delta(_) => return None,
    };
    Some((field, Evidence::NA(reason)))
}

/// Pid for `inode`, if the table has it.
///
/// A miss is `None`, never pid `0`. This does not build a [`aw_core::ProcRef`]:
/// that needs a [`aw_core::ProcUid`], and hashing pid alone would collide after
/// reuse. Callers keep `proc` as `None` and stamp [`FIELD_PROC`] with
/// `NA(collector_unavailable)` — [`inode_na`] is that stamp.
pub fn pid_for_inode(inode: u64, owners: &[InodeOwner]) -> Option<u32> {
    match lookup_inode(inode, owners) {
        InodeLookup::Pid(pid) => Some(pid),
        InodeLookup::NotFound => None,
    }
}

/// `field_evidence` entry for an inode [`pid_for_inode`] did not resolve.
pub fn inode_na() -> (&'static str, Evidence) {
    (FIELD_PROC, Evidence::NA(NaReason::CollectorUnavailable))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn fork_exec_exit() -> [ProcConnectorEvent; 3] {
        [
            ProcConnectorEvent {
                what: ProcWhat::Fork,
                pid: 20,
                ppid: Some(10),
                exit_code: None,
                signal: None,
                argv: None,
                exe: None,
                start_time_ns: Some(1_000),
            },
            ProcConnectorEvent {
                what: ProcWhat::Exec,
                pid: 20,
                ppid: Some(10),
                exit_code: None,
                signal: None,
                argv: Some(vec!["/bin/echo".into(), "hi".into()]),
                exe: Some("/bin/echo".into()),
                start_time_ns: Some(1_000),
            },
            ProcConnectorEvent {
                what: ProcWhat::Exit,
                pid: 20,
                ppid: None,
                exit_code: Some(0),
                signal: None,
                argv: None,
                exe: None,
                start_time_ns: None,
            },
        ]
    }

    fn addr(text: &str) -> SocketAddr {
        let parsed: std::net::SocketAddr = text.parse().expect("test address");
        SocketAddr::socket(parsed)
    }

    #[test]
    fn proc_connector_three_events_stamp_e1_and_argv_s() {
        let events = fork_exec_exit();
        let decoded: Vec<_> = events
            .iter()
            .enumerate()
            .map(|(i, ev)| {
                decode_proc(ev, i as u64, 1, 2).expect("fixture has ppid and start time")
            })
            .collect();

        assert!(decoded.iter().all(|d| d.event.evidence == Evidence::E1));
        assert!(decoded
            .iter()
            .all(|d| d.event.source.as_str() == SOURCE_PROC_CONNECTOR));

        match &decoded[0].event.kind {
            EventKind::ProcessStart(start) => {
                assert_eq!(start.how, StartHow::Fork);
                assert!(start.argv.is_none());
            }
            other => panic!("fork decoded as {other:?}"),
        }
        assert_eq!(
            decoded[0].event.field_evidence.get(FIELD_ARGV),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );

        match &decoded[1].event.kind {
            EventKind::ProcessStart(start) => {
                assert_eq!(start.how, StartHow::Exec);
                let argv = start.argv.as_ref().expect("exec argv was read");
                assert_eq!(argv.len(), 2);
                assert_eq!(argv[0].as_str(), "/bin/echo");
            }
            other => panic!("exec decoded as {other:?}"),
        }
        assert_eq!(
            decoded[1].event.field_evidence.get(FIELD_ARGV),
            Some(&Evidence::S),
            "argv is a later /proc read, so it is S even though the process event is E1"
        );

        match &decoded[2].event.kind {
            EventKind::ProcessExit(exit) => assert_eq!(exit.exit_code, Some(0)),
            other => panic!("exit decoded as {other:?}"),
        }
    }

    #[test]
    fn sock_diag_first_sample_does_not_invent_bytes() {
        let current = SockSample {
            inode: 7,
            proto: L4Proto::Tcp,
            local: addr("127.0.0.1:40000"),
            remote: addr("127.0.0.1:80"),
            bytes_acked: Some(100),
            bytes_received: Some(40),
        };
        let delta = diff_sock(None, &current);
        assert_eq!(delta.sent, CounterStep::NoBaseline);
        assert_eq!(delta.recv, CounterStep::NoBaseline);

        let mut seq = 1;
        let decoded = decode_sock_delta(delta, &mut seq, 10, 20).expect("valid sock delta");
        assert!(decoded.sent.is_none(), "first sample must not emit NetSend");
        assert!(decoded.recv.is_none(), "first sample must not emit NetRecv");
        assert_eq!(seq, 1, "no event was allocated a seq");
        // The counters on the wire are not zero; they are simply unpublished.
        assert_ne!(current.bytes_acked, Some(0));
        let (sent_field, sent_ev) =
            counter_evidence(decoded.delta.sent, true).expect("no baseline");
        let (recv_field, recv_ev) =
            counter_evidence(decoded.delta.recv, false).expect("no baseline");
        assert_eq!(sent_field, "bytes_acked");
        assert_eq!(recv_field, "bytes_received");
        assert_eq!(sent_ev, Evidence::NA(NaReason::Preexisting));
        assert_eq!(recv_ev, Evidence::NA(NaReason::Preexisting));
        assert_ne!(
            sent_ev,
            Evidence::S,
            "an absent baseline is not a sampled zero"
        );
    }

    #[test]
    fn sock_diag_delta_and_wrap() {
        let base = SockSample {
            inode: 7,
            proto: L4Proto::Tcp,
            local: addr("127.0.0.1:40000"),
            remote: addr("127.0.0.1:80"),
            bytes_acked: Some(100),
            bytes_received: Some(40),
        };
        let next = SockSample {
            bytes_acked: Some(150),
            bytes_received: Some(40),
            ..base.clone()
        };
        let delta = diff_sock(Some(&base), &next);
        assert_eq!(delta.sent, CounterStep::Delta(50));
        assert_eq!(delta.recv, CounterStep::Delta(0));

        let mut seq = 3;
        let decoded = decode_sock_delta(delta, &mut seq, 10, 20).expect("valid sock delta");
        let sent = decoded.sent.expect("50 bytes acked");
        assert_eq!(sent.evidence, Evidence::S);
        assert_eq!(sent.source.as_str(), SOURCE_SOCK_DIAG);
        match sent.kind {
            EventKind::NetSend(body) => assert_eq!(body.bytes, 50),
            other => panic!("expected NetSend, got {other:?}"),
        }
        assert!(
            decoded.recv.is_none(),
            "a zero delta is not an event and not NA"
        );
        assert_eq!(seq, 4);

        // Counter wrapped past u64::MAX: 5 bytes were acked after the wrap.
        let wrapped = SockSample {
            bytes_acked: Some(4),
            bytes_received: Some(40),
            ..base.clone()
        };
        let around = diff_sock(
            Some(&SockSample {
                bytes_acked: Some(u64::MAX - 1),
                ..base.clone()
            }),
            &wrapped,
        );
        assert_eq!(around.sent, CounterStep::Delta(6));
    }

    #[test]
    fn dns_five_tuple_is_inference() {
        let packet = DnsPacket {
            proto: L4Proto::Udp,
            local: addr("127.0.0.1:53000"),
            remote: addr("127.0.0.1:53"),
            qname: "example.test".into(),
            qtype: 1,
            txid: Some(9),
        };
        let sockets = [KnownSocket {
            inode: 42,
            proto: L4Proto::Udp,
            local: addr("127.0.0.1:53000"),
            remote: addr("127.0.0.1:53"),
        }];
        let hit = attribute_dns(&packet, &sockets, 1, 2, 3).expect("valid dns packet");
        assert_eq!(hit.event.evidence, Evidence::I);
        assert_eq!(hit.event.source.as_str(), SOURCE_AF_PACKET);
        assert_eq!(hit.inode, Some(42));
        match &hit.event.kind {
            EventKind::DnsQuery(q) => assert_eq!(q.qname, "example.test"),
            other => panic!("expected DnsQuery, got {other:?}"),
        }

        let miss = attribute_dns(&packet, &[], 1, 2, 3).expect("valid dns packet");
        assert_eq!(
            miss.event.evidence,
            Evidence::NA(NaReason::CollectorUnavailable)
        );
        assert_eq!(miss.inode, None);
    }

    #[test]
    fn inode_miss_is_na_not_pid_zero() {
        let owners = [InodeOwner { inode: 1, pid: 10 }];
        assert_eq!(lookup_inode(1, &owners), InodeLookup::Pid(10));
        assert_eq!(lookup_inode(99, &owners), InodeLookup::NotFound);

        let mut event = decode_proc(&fork_exec_exit()[2], 0, 1, 2)
            .expect("exit does not need ppid")
            .event;
        assert!(pid_for_inode(99, &owners).is_none());
        assert!(event.proc.is_none(), "a miss does not invent a ProcRef");
        let (field, evidence) = inode_na();
        event.field_evidence.insert(field.to_string(), evidence);
        assert_eq!(
            event.field_evidence.get(FIELD_PROC),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );

        assert_eq!(pid_for_inode(1, &owners), Some(10));
        assert_ne!(pid_for_inode(1, &owners), Some(0));
    }
}
