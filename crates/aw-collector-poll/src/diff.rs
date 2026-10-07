//! Pure diffs over two snapshots.
//!
//! The first snapshot a collector sees is a baseline: processes and connections
//! already present are not reported as new. A key that appears in a later sample
//! is a start or a connect. A key that disappears is an exit or a close. Anything
//! that lived entirely between two samples was not seen, so it is not invented.
//!
//! Process identity is `(pid, start marker)`. A pid reused with a different start
//! time is a different process. Connections are keyed by the four-tuple plus the
//! optional socket id. Windows `netstat` has no socket id, so `None` is part of
//! the key rather than a fabricated inode.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use aw_core::{
    proc::{ProcessIdentity, StartTimeUnit},
    EventKind, Evidence, FlowKey, L4Proto, NaReason, NetClose, NetConnect, ProcRef, ProcUid,
    ProcessExit, ProcessStart, RawEvent, RawEventParts, Source, StartHow,
};

use crate::bytes::connection_byte_counts;
use crate::source::{
    ConnectionRow, ConnectionSnapshot, ProcessRow, ProcessSnapshot, ProcessStartTime,
};

/// One process that appeared or disappeared between two samples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessDelta {
    /// Present in `after`, absent from `before`.
    Started(ProcessRow),
    /// Present in `before`, absent from `after`. The row is the last observation.
    Exited(ProcessRow),
}

/// One connection that appeared or disappeared between two samples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionDelta {
    /// Established flow present in `after` and not in `before`.
    Connected(ConnectionRow),
    /// Established flow present in `before` and not in `after`.
    Closed(ConnectionRow),
}

/// Identity key for one process row.
///
/// `Unavailable` start times stay in their own bucket. They are not treated as
/// unix time `0`, and two rows with the same pid and no start time collapse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ProcKey {
    pid: u32,
    start: ProcStartKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ProcStartKey {
    UnixSeconds(u64),
    Unavailable,
}

impl ProcKey {
    fn of(row: &ProcessRow) -> Self {
        let start = match row.start {
            ProcessStartTime::UnixSeconds(secs) => ProcStartKey::UnixSeconds(secs),
            ProcessStartTime::Unavailable => ProcStartKey::Unavailable,
        };
        Self {
            pid: row.pid,
            start,
        }
    }
}

/// Four-tuple plus socket id. Listeners never enter this map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FlowIdentity {
    proto: ProtoKey,
    local: SocketAddr,
    remote: SocketAddr,
    sock_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ProtoKey {
    Tcp,
    Udp,
    Unknown,
}

impl FlowIdentity {
    fn of(row: &ConnectionRow) -> Option<Self> {
        if row.listening {
            return None;
        }
        let remote = row.remote?;
        let proto = match row.proto {
            L4Proto::Tcp => ProtoKey::Tcp,
            L4Proto::Udp => ProtoKey::Udp,
            L4Proto::Unknown => ProtoKey::Unknown,
        };
        Some(Self {
            proto,
            local: row.local,
            remote,
            sock_id: row.sock_id,
        })
    }
}

/// Processes that appeared or disappeared.
///
/// Rows in `before` are the baseline. They produce no `Started` entries.
/// Duplicate keys inside one snapshot keep the first row.
pub fn diff_processes(before: &ProcessSnapshot, after: &ProcessSnapshot) -> Vec<ProcessDelta> {
    let previous = index_processes(&before.rows);
    let current = index_processes(&after.rows);
    let mut deltas = Vec::new();
    for (key, row) in &current {
        if !previous.contains_key(key) {
            deltas.push(ProcessDelta::Started(row.clone()));
        }
    }
    for (key, row) in &previous {
        if !current.contains_key(key) {
            deltas.push(ProcessDelta::Exited(row.clone()));
        }
    }
    deltas
}

/// Connections that appeared or disappeared. Listening rows are ignored.
pub fn diff_connections(
    before: &ConnectionSnapshot,
    after: &ConnectionSnapshot,
) -> Vec<ConnectionDelta> {
    let previous = index_connections(&before.rows);
    let current = index_connections(&after.rows);
    let mut deltas = Vec::new();
    for (key, row) in &current {
        if !previous.contains_key(key) {
            deltas.push(ConnectionDelta::Connected(row.clone()));
        }
    }
    for (key, row) in &previous {
        if !current.contains_key(key) {
            deltas.push(ConnectionDelta::Closed(row.clone()));
        }
    }
    deltas
}

fn index_processes(rows: &[ProcessRow]) -> BTreeMap<ProcKey, ProcessRow> {
    let mut map = BTreeMap::new();
    for row in rows {
        map.entry(ProcKey::of(row)).or_insert_with(|| row.clone());
    }
    map
}

fn index_connections(rows: &[ConnectionRow]) -> BTreeMap<FlowIdentity, ConnectionRow> {
    let mut map = BTreeMap::new();
    for row in rows {
        if let Some(key) = FlowIdentity::of(row) {
            map.entry(key).or_insert_with(|| row.clone());
        }
    }
    map
}

/// A process event that could not be built without inventing a required reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SkippedProcess {
    /// Pid the row carried. Not a [`ProcUid`].
    pub pid: u32,
    /// Which required reading was missing. A fixed label, never a path or argv.
    pub missing: &'static str,
}

/// Fields a process event marks `NA`, and the process the event is about.
pub(crate) struct BuiltProcessEvent {
    pub event_kind: EventKind,
    pub proc: Option<ProcRef>,
    /// `(field path, reason)` entries applied with [`RawEvent::mark_na`].
    pub na: Vec<(&'static str, NaReason)>,
}

/// Turn one process delta into a `ProcessStart` or `ProcessExit`.
///
/// `how` is [`StartHow::Spawn`] for a process that appeared after the baseline,
/// and [`StartHow::Snapshot`] for a one-shot attach snapshot.
///
/// Returns `Err` when the start time was not observed. `ProcessStart.start_time_ns`
/// is a required `i64`, so a sentinel (`0` or `i64::MIN`) would be a fake reading.
/// The collector records a [`aw_core::Gap`] instead of emitting that start.
/// A missing boot id does not invent a [`ProcUid`]: the event is still emitted
/// with `proc` left `None` and `proc` marked NA, but only when start time exists.
pub(crate) fn build_process_event(
    delta: &ProcessDelta,
    boot_id: Option<&[u8]>,
    how: StartHow,
    parent_uid: Option<ProcUid>,
) -> Result<BuiltProcessEvent, SkippedProcess> {
    match delta {
        ProcessDelta::Started(row) => build_start(row, boot_id, how, parent_uid),
        ProcessDelta::Exited(row) => Ok(build_exit(row, boot_id)),
    }
}

fn build_start(
    row: &ProcessRow,
    boot_id: Option<&[u8]>,
    how: StartHow,
    parent_uid: Option<ProcUid>,
) -> Result<BuiltProcessEvent, SkippedProcess> {
    let ProcessStartTime::UnixSeconds(secs) = row.start else {
        return Err(SkippedProcess {
            pid: row.pid,
            missing: "start_time_ns",
        });
    };
    // Second resolution, converted only so the required field has a unit.
    // Values that do not fit in `i64` nanoseconds are not a readable start time.
    let Some(start_time_ns) = secs
        .checked_mul(1_000_000_000)
        .and_then(|ns| i64::try_from(ns).ok())
    else {
        return Err(SkippedProcess {
            pid: row.pid,
            missing: "start_time_ns",
        });
    };
    // `ppid` is a required `u32`. `0` would mean "observed parent pid 0", which a
    // missing parent is not. Skip the start and let the collector emit a gap.
    let Some(ppid) = row.ppid else {
        return Err(SkippedProcess {
            pid: row.pid,
            missing: "ppid",
        });
    };

    let mut na = Vec::new();
    let proc = proc_ref(row, boot_id, &mut na);
    if parent_uid.is_none() {
        na.push(("parent_uid", NaReason::CollectorUnavailable));
    }
    if row.exe.is_none() {
        na.push(("exe", NaReason::CollectorUnavailable));
    }
    if row.argv.is_none() {
        na.push(("argv", NaReason::CollectorUnavailable));
    }
    if row.cwd.is_none() {
        na.push(("cwd", NaReason::CollectorUnavailable));
    }
    if row.user_id.is_none() {
        na.push(("user", NaReason::CollectorUnavailable));
    }
    na.push(("env", NaReason::CollectorUnavailable));
    na.push(("signer", NaReason::CollectorUnavailable));

    let argv = row.argv.as_ref().map(|args| {
        args.iter()
            .cloned()
            .map(aw_core::Redacted::new)
            .collect::<Vec<_>>()
    });
    let user = row.user_id.as_ref().map(|id| aw_core::UserRef {
        id: id.clone(),
        name: None,
    });
    let kind = EventKind::ProcessStart(ProcessStart::new(
        ppid,
        parent_uid,
        start_time_ns,
        row.exe.clone(),
        argv,
        row.cwd.clone(),
        user,
        how,
        None,
        None,
    ));
    Ok(BuiltProcessEvent {
        event_kind: kind,
        proc,
        na,
    })
}

fn build_exit(row: &ProcessRow, boot_id: Option<&[u8]>) -> BuiltProcessEvent {
    let mut na = Vec::new();
    let proc = proc_ref(row, boot_id, &mut na);
    na.push(("exit_code", NaReason::CollectorUnavailable));
    na.push(("signal", NaReason::CollectorUnavailable));
    BuiltProcessEvent {
        event_kind: EventKind::ProcessExit(ProcessExit::new(None, None)),
        proc,
        na,
    }
}

fn proc_ref(
    row: &ProcessRow,
    boot_id: Option<&[u8]>,
    na: &mut Vec<(&'static str, NaReason)>,
) -> Option<ProcRef> {
    let Some(boot_id) = boot_id else {
        na.push(("proc", NaReason::CollectorUnavailable));
        return None;
    };
    let ProcessStartTime::UnixSeconds(secs) = row.start else {
        na.push(("proc", NaReason::CollectorUnavailable));
        return None;
    };
    // Do not hash a missing start. `UnixSeconds(0)` is only reached when the
    // source claims it observed the unix epoch, which the sysinfo adapter does
    // not: it maps a reported 0 to `Unavailable`.
    let Some(identity) =
        ProcessIdentity::from_parts(boot_id, row.pid, secs, StartTimeUnit::Seconds)
    else {
        na.push(("proc", NaReason::CollectorUnavailable));
        return None;
    };
    Some(ProcRef {
        uid: identity.uid,
        pid: row.pid,
        tid: None,
    })
}

/// Parent uid when the parent is in the same snapshot and both identities hash.
pub(crate) fn parent_uid(row: &ProcessRow, snapshot: &ProcessSnapshot) -> Option<ProcUid> {
    let boot = snapshot.boot_id.as_deref()?;
    let ppid = row.ppid?;
    let parent = snapshot
        .rows
        .iter()
        .find(|candidate| candidate.pid == ppid)?;
    let ProcessStartTime::UnixSeconds(secs) = parent.start else {
        return None;
    };
    ProcessIdentity::from_parts(boot, parent.pid, secs, StartTimeUnit::Seconds).map(|id| id.uid)
}

/// Pid of every row whose identity hash equals one of `uids`.
pub(crate) fn pids_for_uids(snapshot: &ProcessSnapshot, uids: &[ProcUid]) -> Vec<u32> {
    let Some(boot) = snapshot.boot_id.as_deref() else {
        return Vec::new();
    };
    let mut pids = Vec::new();
    for row in &snapshot.rows {
        let ProcessStartTime::UnixSeconds(secs) = row.start else {
            continue;
        };
        let Some(identity) =
            ProcessIdentity::from_parts(boot, row.pid, secs, StartTimeUnit::Seconds)
        else {
            continue;
        };
        if uids.contains(&identity.uid) && !pids.contains(&row.pid) {
            pids.push(row.pid);
        }
    }
    pids
}

/// `root_pid` plus descendants by `ppid`, from a single snapshot.
///
/// Does not walk past a row whose parent pid is the row itself. Order is the
/// root, then descendants in snapshot order.
pub(crate) fn subtree_rows(snapshot: &ProcessSnapshot, root_pid: u32) -> Vec<ProcessRow> {
    let mut selected = Vec::new();
    let mut frontier = vec![root_pid];
    let mut seen = Vec::new();
    while let Some(pid) = frontier.first().copied() {
        frontier.remove(0);
        if seen.contains(&pid) {
            continue;
        }
        seen.push(pid);
        let Some(row) = snapshot.rows.iter().find(|row| row.pid == pid) else {
            continue;
        };
        selected.push(row.clone());
        for child in &snapshot.rows {
            if child.ppid == Some(pid) && child.pid != pid && !seen.contains(&child.pid) {
                frontier.push(child.pid);
            }
        }
    }
    selected
}

/// Stamp one built process payload onto a [`RawEvent`] at evidence S.
pub(crate) fn finish_event(
    built: BuiltProcessEvent,
    seq: u64,
    mono_ns: u64,
    wall_ns: i64,
    source: &Source,
) -> Result<RawEvent, ()> {
    let mut event = RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns: mono_ns,
        ts_wall_ns: wall_ns,
        session_id: None,
        proc: built.proc,
        source: source.clone(),
        evidence: Evidence::S,
        kind: built.event_kind,
    })
    .map_err(|_| ())?;
    for (field, reason) in built.na {
        event.mark_na(field, reason);
    }
    Ok(event)
}

/// NetConnect or NetClose for one connection delta.
///
/// Byte totals on close are `None` and marked NA. No `NetSend` / `NetRecv` is
/// built: those kinds cannot represent an unknown count without using `0`.
pub(crate) fn build_connection_event(
    delta: &ConnectionDelta,
    seq: u64,
    mono_ns: u64,
    wall_ns: i64,
    source: &Source,
    proc: Option<ProcRef>,
) -> Result<RawEvent, ()> {
    let (row, close) = match delta {
        ConnectionDelta::Connected(row) => (row, false),
        ConnectionDelta::Closed(row) => (row, true),
    };
    let Some(remote) = row.remote else {
        return Err(());
    };
    let flow = FlowKey::new(row.proto, row.local, remote, row.sock_id);
    let kind = if close {
        let counts = connection_byte_counts();
        debug_assert!(counts.sent.is_none() && counts.recv.is_none());
        EventKind::NetClose(NetClose::new(flow, counts.sent, counts.recv))
    } else {
        EventKind::NetConnect(NetConnect::new(flow, row.direction, None))
    };
    let mut event = RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns: mono_ns,
        ts_wall_ns: wall_ns,
        session_id: None,
        proc: proc.clone(),
        source: source.clone(),
        evidence: Evidence::S,
        kind,
    })
    .map_err(|_| ())?;
    if proc.is_none() {
        event.mark_na("proc", NaReason::CollectorUnavailable);
    }
    if !close {
        event.mark_na("result", NaReason::CollectorUnavailable);
    } else {
        event.mark_na("total_sent", NaReason::CollectorUnavailable);
        event.mark_na("total_recv", NaReason::CollectorUnavailable);
    }
    Ok(event)
}
