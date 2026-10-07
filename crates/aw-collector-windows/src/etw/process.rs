//! Kernel-Process event 1 / 2 → [`ProcessStart`] / [`ProcessExit`].
//!
//! Field names and event ids are copied from windows.md §2.1. That section is
//! still marked 【待验证 SPIKE-02】, and SPIKE-02 has no measurement: it was not
//! run elevated and recorded no event. A property this file does not find is
//! `NA(collector_unavailable)`. It is not filled with `0` or `""`.
//!
//! | event id | name | kind | source |
//! |---|---|---|---|
//! | 1 | ProcessStart | `ProcessStart` | `windows.etw/kernel_process` |
//! | 2 | ProcessStop | `ProcessExit` | `windows.etw/kernel_process_stop` |
//!
//! Mapped properties (windows.md §2.1, and only those):
//!
//! | kind | property | field |
//! |---|---|---|
//! | start | `ProcessID` | `proc.pid` |
//! | start | `CreateTime` | `ProcUid` input and `start_time_ns` |
//! | start | `ParentProcessID` | `ppid`, then `parent_uid` via the cache |
//! | start | `ImageName` | `exe` |
//! | start | `SessionID` | not a `ProcessStart` field; recorded as `NA(collector_unavailable)` on `session_id` |
//! | start | `CommandLine` | `argv`, evidence E1 when present |
//! | stop | `ProcessID`, `CreateTime` | `proc` |
//! | stop | `ExitCode` | `exit_code` |
//! | stop | `ExitTime` | not a `ProcessExit` field; `NA` on `exit_time` |
//! | stop | `ImageName` | not a `ProcessExit` field; `NA` on `image_name` |
//!
//! `CommandLine` is 【待验证】on the event itself. When the property is absent
//! the decoder does not block: it enqueues a [`BackfillJob`] and returns the
//! event with `argv` unset and evidence `NA(collector_unavailable)`. The pool
//! calls a [`ProcessReader`]. A value that comes back is evidence S. A process
//! that has already exited stays `NA(collector_unavailable)`. cwd is the same
//! shape: the event has no cwd property (windows.md §2.1), so cwd is always a
//! back-fill at evidence S, or `NA` when the read fails. WOW64 cwd that this
//! build cannot walk is `NA`, never `""`.
//!
//! `parent_uid` is resolved from [`ProcessCache`]. The cached parent's
//! `CreateTime` must be strictly earlier than the child's. A miss, or a parent
//! whose `CreateTime` is not earlier, leaves `parent_uid` as `None` and marks
//! `parent_uid` `NA(collector_unavailable)`. The raw `ppid` is still stored:
//! windows.md maps `ParentProcessID` onto the event, and the pid integer is not
//! the identity.
//!
//! `ProcUid` is [`aw_core::proc::ProcessIdentity::from_parts`] with
//! [`StartTimeUnit::HundredNanoseconds`]. This file does not hash on its own.

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use aw_core::proc::{ProcessIdentity, StartTimeUnit};
use aw_core::{
    EventKind, Evidence, NaReason, ProcRef, ProcUid, ProcessExit, ProcessStart, RawEvent, Redacted,
    Source, StartHow, SCHEMA_VERSION,
};

/// One argv element. `aw_core` exports this as [`Redacted`]; the `Arg` alias
/// stays crate-private there.
type Arg = Redacted;

use crate::peb::{BackfillAnswer, BackfillRequest, ProcessReader, ReadOutcome, UnavailableReason};

use super::session::filetime_to_unix_ns;

/// `source` for a ProcessStart. windows.md §2.1 via the task card.
pub const SOURCE_PROCESS_START: &str = "windows.etw/kernel_process";

/// `source` for a ProcessStop. The task card names this string.
pub const SOURCE_PROCESS_STOP: &str = "windows.etw/kernel_process_stop";

/// Kernel-Process event id for a process start. windows.md §2.1. 【待验证 SPIKE-02】.
pub const EVENT_PROCESS_START: u16 = 1;

/// Kernel-Process event id for a process stop. windows.md §2.1. 【待验证 SPIKE-02】.
pub const EVENT_PROCESS_STOP: u16 = 2;

/// One property from a decoded ETW event, already turned into a string or an integer.
///
/// The session layer (P1-WIN-01) forwards headers only and does not parse
/// properties. This type is the adapter: a caller that *does* have a schema
/// (a recorded fixture, or a later consumer) fills one [`ProcessProperties`]
/// and hands it to [`decode_process`]. This module does not call ferrisetw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessProperties {
    /// `EventDescriptor.Id`. Only 1 and 2 decode; anything else is not a process event.
    pub event_id: u16,
    /// `ProcessID`, when the property was present and fit in `u32`.
    pub process_id: Option<u32>,
    /// `CreateTime` as a FILETIME (100-ns ticks since 1601-01-01).
    ///
    /// windows.md §2.1 names the field and not the unit. FILETIME is what ETW
    /// kernel process events carry in public headers. SPIKE-02 has not confirmed
    /// the unit on a live session. A value that does not convert to a Unix time
    /// is treated as absent.
    pub create_time: Option<i64>,
    /// `ParentProcessID`. Start events only. Absent is not `0`.
    pub parent_process_id: Option<u32>,
    /// `SessionID`. Not a `ProcessStart` field. Presence is recorded; the value
    /// is not invented into another field.
    pub session_id: Option<u32>,
    /// `ImageName`. Mapped to `exe` on a start. On a stop the payload has no exe
    /// field, so the string is kept only to mark the field `NA` when absent.
    pub image_name: Option<String>,
    /// `ExitTime` as FILETIME. ProcessExit has no time field; see the module note.
    pub exit_time: Option<i64>,
    /// `ExitCode`. ProcessStop only. Absent stays `None` (not `0`).
    pub exit_code: Option<i32>,
    /// `CommandLine`, raw, not split. Present → argv evidence E1.
    ///
    /// 【待验证 SPIKE-02】: windows.md §2.1 says ProcessStart does not necessarily
    /// carry this property. Absence is `None`, which schedules a back-fill.
    pub command_line: Option<String>,
    /// Event-header thread id, when the caller has one. Not a §2.1 property.
    pub tid: Option<u32>,
}

impl ProcessProperties {
    /// An event with an id and nothing else. Tests build from here.
    pub fn bare(event_id: u16) -> Self {
        Self {
            event_id,
            process_id: None,
            create_time: None,
            parent_process_id: None,
            session_id: None,
            image_name: None,
            exit_time: None,
            exit_code: None,
            command_line: None,
            tid: None,
        }
    }
}

/// One process the cache can hand back as a parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedProcess {
    /// `ProcUid` computed from this row's own boot id, pid, and `CreateTime`.
    pub uid: ProcUid,
    /// `CreateTime` in FILETIME ticks, the same unit as the event property.
    pub create_time: i64,
}

/// `pid →` the process that currently owns it.
///
/// Inserted on a successful start decode, removed on a stop for that
/// `(pid, create_time)` pair. A stop whose `CreateTime` does not match the
/// cached row does not remove it: that stop is a different process, or a
/// property we could not read.
#[derive(Debug, Default, Clone)]
pub struct ProcessCache {
    by_pid: HashMap<u32, CachedProcess>,
}

impl ProcessCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self {
            by_pid: HashMap::new(),
        }
    }

    /// Remember `pid` as `cached`. Replaces a previous owner of the same pid.
    pub fn insert(&mut self, pid: u32, cached: CachedProcess) {
        self.by_pid.insert(pid, cached);
    }

    /// The process currently stored for `pid`.
    pub fn get(&self, pid: u32) -> Option<CachedProcess> {
        self.by_pid.get(&pid).copied()
    }

    /// Drop the row only when `create_time` matches. Returns whether a row was removed.
    pub fn remove_if(&mut self, pid: u32, create_time: i64) -> bool {
        match self.by_pid.get(&pid) {
            Some(row) if row.create_time == create_time => {
                self.by_pid.remove(&pid);
                true
            }
            _ => false,
        }
    }
}

/// Parent link after the CreateTime check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentLink {
    /// Cache had `ppid`, and that row's `CreateTime` is strictly earlier.
    Resolved(ProcUid),
    /// No row for `ppid`.
    UnknownParent,
    /// A row exists, but its `CreateTime` is not strictly earlier than the child.
    ///
    /// ADR-0007: a parent that started later (or at the same tick) is a reused
    /// pid. The row is not used.
    CreateTimeNotEarlier,
}

/// Resolve `parent_uid`. Does not insert and does not allocate.
pub fn resolve_parent(cache: &ProcessCache, ppid: u32, child_create_time: i64) -> ParentLink {
    match cache.get(ppid) {
        None => ParentLink::UnknownParent,
        Some(parent) if parent.create_time < child_create_time => ParentLink::Resolved(parent.uid),
        Some(_) => ParentLink::CreateTimeNotEarlier,
    }
}

/// Clock the decoder stamps onto `RawEvent`. Both values are supplied by the
/// caller (the session layer already converted the header). This module does
/// not read a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeClock {
    /// Monotonic nanoseconds.
    pub ts_mono_ns: u64,
    /// Unix epoch nanoseconds. `None` is unknown wall time; the event stores `0`
    /// and records `ts_wall_ns` as `NA(collector_unavailable)`. `RawEvent`
    /// cannot hold `Option<i64>` here, and `0` alone would look like the epoch.
    pub ts_wall_ns: Option<i64>,
}

/// What [`decode_process`] did with one event.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodedProcess {
    /// A start or a stop, plus the back-fill to run off the callback thread.
    Start(DecodedStart),
    /// A stop. No back-fill: command line and cwd are start facts.
    Stop(DecodedStop),
    /// Event id was not 1 or 2. Not a process event. Nothing was allocated.
    Ignored { event_id: u16 },
    /// Id was 1 or 2, but `ProcessID` or `CreateTime` was missing or unusable,
    /// so no `ProcUid` can be built. The fields that *were* present are named
    /// so the caller can record a gap without pretending the event decoded.
    Undecodable(Undecodable),
}

/// A start that decoded, and the job a pool should run for it.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedStart {
    /// The event. `argv` / `cwd` may still be `None` with `NA` evidence; the
    /// pool fills them later through [`apply_backfill`].
    pub event: RawEvent,
    /// `Some` when at least one of argv, cwd still needs a read.
    pub backfill: Option<BackfillJob>,
    /// Row to insert into [`ProcessCache`] *before* later events are decoded.
    pub cache_insert: (u32, CachedProcess),
}

/// A stop that decoded.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedStop {
    /// The exit event.
    pub event: RawEvent,
    /// `(pid, create_time)` the caller should [`ProcessCache::remove_if`].
    pub cache_remove: (u32, i64),
}

/// Why an event with the right id still did not become a `RawEvent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Undecodable {
    /// 1 or 2.
    pub event_id: u16,
    /// `ProcessID` was absent.
    pub missing_pid: bool,
    /// `CreateTime` was absent or did not convert.
    pub missing_create_time: bool,
}

/// Work item for [`BackfillPool`]. Carries the pid and which fields to read.
/// The event itself stays with the caller; the pool only returns an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackfillJob {
    /// Pid to open. Not a `ProcUid`.
    pub pid: u32,
    /// Read the command line. `false` when the event already had `CommandLine`.
    pub want_argv: bool,
    /// Read cwd. Always `true` for a start this decoder emits: the event has no
    /// cwd property (windows.md §2.1).
    pub want_cwd: bool,
}

impl BackfillJob {
    fn request(self) -> BackfillRequest {
        BackfillRequest {
            pid: self.pid,
            want_argv: self.want_argv,
            want_cwd: self.want_cwd,
        }
    }
}

/// Decode one Kernel-Process event.
///
/// `boot_id` is the opaque boot-id bytes [`ProcessIdentity::from_parts`] hashes.
/// An empty slice is a real value (the identity function says so); this
/// function does not invent one.
///
/// `seq` is the caller's monotonic counter. `clock` is the already-converted
/// header time. `cache` is borrowed and not mutated: the caller inserts
/// [`DecodedStart::cache_insert`] itself, so a decode of a fixture can be
/// replayed against a cache the test owns.
///
/// Does not open a process and does not block. Back-fill is a [`BackfillJob`],
/// not a read.
pub fn decode_process(
    props: &ProcessProperties,
    boot_id: &[u8],
    seq: u64,
    clock: DecodeClock,
    cache: &ProcessCache,
) -> DecodedProcess {
    if props.event_id != EVENT_PROCESS_START && props.event_id != EVENT_PROCESS_STOP {
        return DecodedProcess::Ignored {
            event_id: props.event_id,
        };
    }
    let Some(pid) = props.process_id else {
        return DecodedProcess::Undecodable(Undecodable {
            event_id: props.event_id,
            missing_pid: true,
            missing_create_time: props.create_time.is_none(),
        });
    };
    let Some(create_time) = props.create_time else {
        return DecodedProcess::Undecodable(Undecodable {
            event_id: props.event_id,
            missing_pid: false,
            missing_create_time: true,
        });
    };
    // FILETIME must convert. A value that does not is "CreateTime unusable",
    // same as absent: hashing it would invent an identity.
    let Some(start_ns) = filetime_to_unix_ns(create_time) else {
        return DecodedProcess::Undecodable(Undecodable {
            event_id: props.event_id,
            missing_pid: false,
            missing_create_time: true,
        });
    };
    let Some(identity) = ProcessIdentity::from_parts(
        boot_id,
        pid,
        create_time as u64,
        StartTimeUnit::HundredNanoseconds,
    ) else {
        // Boot id longer than the hasher accepts. Not a guessable identity.
        return DecodedProcess::Undecodable(Undecodable {
            event_id: props.event_id,
            missing_pid: false,
            missing_create_time: true,
        });
    };

    if props.event_id == EVENT_PROCESS_STOP {
        return decode_stop(props, identity, start_ns, seq, clock, create_time);
    }
    decode_start(props, identity, start_ns, seq, clock, cache, create_time)
}

fn decode_stop(
    props: &ProcessProperties,
    identity: ProcessIdentity,
    start_ns: i64,
    seq: u64,
    clock: DecodeClock,
    create_time: i64,
) -> DecodedProcess {
    let exit = ProcessExit::new(props.exit_code, None);
    let mut event = build_event(
        seq,
        clock,
        ProcRef {
            uid: identity.uid,
            pid: identity.pid,
            tid: props.tid,
        },
        Source::new(SOURCE_PROCESS_STOP),
        Evidence::E1,
        EventKind::ProcessExit(exit),
    );
    if props.exit_code.is_none() {
        // windows.md lists ExitCode. Absent is NA, not exit code 0.
        event.mark_na("exit_code", NaReason::CollectorUnavailable);
    }
    // Signal is not a Windows process-stop field. Leaving it None without a
    // marker would look like "no signal" rather than "this platform has none".
    event.mark_na("signal", NaReason::CollectorUnavailable);
    // ExitTime and ImageName are named in windows.md §2.1. `ProcessExit` has
    // no field for either, so both are NA whether or not the property was
    // present. The value is not copied onto another field.
    let _ = (props.exit_time, &props.image_name);
    event.mark_na("exit_time", NaReason::CollectorUnavailable);
    event.mark_na("image_name", NaReason::CollectorUnavailable);
    // CreateTime was consumed as identity. `start_ns` is not a ProcessExit
    // field; keep the binding so a future schema field can use it without
    // re-converting. Today it is intentionally unused beyond the identity.
    let _ = start_ns;
    DecodedProcess::Stop(DecodedStop {
        event,
        cache_remove: (identity.pid, create_time),
    })
}

fn decode_start(
    props: &ProcessProperties,
    identity: ProcessIdentity,
    start_ns: i64,
    seq: u64,
    clock: DecodeClock,
    cache: &ProcessCache,
    create_time: i64,
) -> DecodedProcess {
    // `ProcessStart::ppid` is a plain `u32`. `0` is a real pid (Idle), so an
    // absent ParentProcessID cannot be stored as `0` without a marker. The
    // integer is `0` only together with `field_evidence["ppid"] = NA`.
    let ppid_known = props.parent_process_id.is_some();
    let ppid = props.parent_process_id.unwrap_or(0);
    let parent = props
        .parent_process_id
        .map(|ppid| resolve_parent(cache, ppid, create_time));
    let parent_uid = match parent {
        Some(ParentLink::Resolved(uid)) => Some(uid),
        _ => None,
    };

    let (argv, argv_evidence) = match &props.command_line {
        Some(line) => (Some(split_command_line(line)), Some(Evidence::E1)),
        None => (None, None),
    };

    let start = ProcessStart::new(
        ppid,
        parent_uid,
        start_ns,
        props.image_name.clone(),
        argv,
        None,
        None,
        StartHow::Spawn,
        None,
        None,
    );
    let mut event = build_event(
        seq,
        clock,
        ProcRef {
            uid: identity.uid,
            pid: identity.pid,
            tid: props.tid,
        },
        Source::new(SOURCE_PROCESS_START),
        Evidence::E1,
        EventKind::ProcessStart(start),
    );

    if !ppid_known {
        event.mark_na("ppid", NaReason::CollectorUnavailable);
    }
    if !ppid_known || !matches!(parent, Some(ParentLink::Resolved(_))) {
        // A failed CreateTime check is the same NA: the cached row is not this
        // process's parent. The raw ppid integer stays, with its own marker
        // when the property itself was absent.
        event.mark_na("parent_uid", NaReason::CollectorUnavailable);
    }
    if props.image_name.is_none() {
        event.mark_na("exe", NaReason::CollectorUnavailable);
    }
    // SessionID is named in windows.md §2.1 and `ProcessStart` has no slot for
    // it. The integer is not written into another field. Absent → NA. Present
    // but unstorable is the same NA: dropping it silently would look like the
    // event never carried a session.
    let _ = props.session_id;
    event.mark_na("session_id", NaReason::CollectorUnavailable);
    // user, signer, env are not in §2.1. env is never recorded (task limit).
    event.mark_na("user", NaReason::CollectorUnavailable);
    event.mark_na("signer", NaReason::CollectorUnavailable);
    event.mark_na("env", NaReason::CollectorUnavailable);

    let want_argv = argv_evidence.is_none();
    if want_argv {
        // Not yet read. The pool replaces this when an answer arrives. Until
        // then the field is unavailable, not an empty argv.
        event.mark_na("argv", NaReason::CollectorUnavailable);
    } else if let Some(evidence) = argv_evidence {
        event.field_evidence.insert("argv".to_owned(), evidence);
    }
    // cwd is never on this event. Always a back-fill.
    event.mark_na("cwd", NaReason::CollectorUnavailable);

    let backfill = Some(BackfillJob {
        pid: identity.pid,
        want_argv,
        want_cwd: true,
    });

    DecodedProcess::Start(DecodedStart {
        event,
        backfill,
        cache_insert: (
            identity.pid,
            CachedProcess {
                uid: identity.uid,
                create_time,
            },
        ),
    })
}

fn build_event(
    seq: u64,
    clock: DecodeClock,
    proc: ProcRef,
    source: Source,
    evidence: Evidence,
    kind: EventKind,
) -> RawEvent {
    let wall_known = clock.ts_wall_ns.is_some();
    // Built directly. `try_new` would reject a required `None` without an NA
    // entry; `ProcessStart` and `ProcessExit` have none, so the check passes.
    // A later schema change that fails the check must still emit the event:
    // dropping a decoded process is a silent discard.
    let mut event = RawEvent {
        v: SCHEMA_VERSION,
        seq,
        ts_mono_ns: clock.ts_mono_ns,
        ts_wall_ns: clock.ts_wall_ns.unwrap_or(0),
        session_id: None,
        proc: Some(proc),
        source,
        evidence,
        field_evidence: std::collections::BTreeMap::new(),
        kind,
    };
    if !wall_known {
        event.mark_na("ts_wall_ns", NaReason::CollectorUnavailable);
    }
    let _ = event.check();
    event
}

/// Split a Windows command line into argv elements.
///
/// Rules, in order: a `"` starts or ends a quoted span; inside a quoted span
/// spaces are literal; two quotes in a row *inside* a quoted span are one
/// literal `"`. A `"` that arrives while not in a span opens one, so `""` at
/// the start of an element is an empty element, not a literal quote. Outside
/// quotes, whitespace separates elements. This is the CommandLineToArgvW shape
/// minus the backslash rules, which SPIKE-02 has not confirmed against a live
/// event. A backslash is kept as a character.
///
/// An empty command line is an empty `Vec`, not `None`. `None` means the
/// property was absent.
pub fn split_command_line(line: &str) -> Vec<Arg> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    let mut started = false;
    while let Some(ch) = chars.next() {
        if ch == '"' {
            if quoted {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    quoted = false;
                }
            } else {
                quoted = true;
                started = true;
            }
            continue;
        }
        if ch.is_whitespace() && !quoted {
            if started {
                out.push(Arg::new(std::mem::take(&mut current)));
                started = false;
            }
            continue;
        }
        started = true;
        current.push(ch);
    }
    if started {
        out.push(Arg::new(current));
    }
    out
}

/// Write a pool answer back onto a start event.
///
/// | answer | `argv` | `cwd` |
/// |---|---|---|
/// | [`ReadOutcome::Value`] | evidence S, value stored | evidence S, value stored |
/// | [`ReadOutcome::Exited`] | stays `None`, `NA(collector_unavailable)` | same |
/// | [`ReadOutcome::Unavailable`] | stays `None`, `NA(collector_unavailable)` | same |
///
/// A value replaces a previous `NA`. An exit or a failure does not invent `""`.
/// Fields the job did not ask about are left alone, so an event that already
/// had `CommandLine` (evidence E1) is not overwritten by a back-fill of cwd.
pub fn apply_backfill(event: &mut RawEvent, job: BackfillJob, answer: &BackfillAnswer) {
    let EventKind::ProcessStart(_) = &event.kind else {
        return;
    };
    if job.want_argv {
        match &answer.argv {
            Some(ReadOutcome::Value(line)) => {
                let argv = split_command_line(line);
                if let EventKind::ProcessStart(start) = &mut event.kind {
                    start.argv = Some(argv);
                }
                event.field_evidence.insert("argv".to_owned(), Evidence::S);
            }
            Some(ReadOutcome::Exited) | Some(ReadOutcome::Unavailable(_)) => {
                if let EventKind::ProcessStart(start) = &mut event.kind {
                    start.argv = None;
                }
                event.mark_na("argv", NaReason::CollectorUnavailable);
            }
            None => {}
        }
    }
    if job.want_cwd {
        match &answer.cwd {
            Some(ReadOutcome::Value(cwd)) => {
                let cwd = cwd.clone();
                if let EventKind::ProcessStart(start) = &mut event.kind {
                    start.cwd = Some(cwd);
                }
                event.field_evidence.insert("cwd".to_owned(), Evidence::S);
            }
            Some(ReadOutcome::Exited) | Some(ReadOutcome::Unavailable(_)) => {
                if let EventKind::ProcessStart(start) = &mut event.kind {
                    start.cwd = None;
                }
                event.mark_na("cwd", NaReason::CollectorUnavailable);
            }
            None => {}
        }
    }
}

/// Why a back-fill did not produce a value the caller can store. Mirrors
/// [`UnavailableReason`] plus "the worker never ran".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackfillMiss {
    /// The reader said the process was already gone.
    Exited,
    /// PPL. The reader must not have opened it for VM_READ.
    Ppl,
    /// WOW64 PEB walk is not implemented. cwd only.
    Wow64Unimplemented,
    /// Any other read failure.
    Unreadable,
}

/// One finished job. `argv` / `cwd` are `None` when that field was not requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackfillReport {
    /// The pid the job named.
    pub pid: u32,
    /// Command line, when requested.
    pub argv: Option<Result<String, BackfillMiss>>,
    /// cwd, when requested.
    pub cwd: Option<Result<String, BackfillMiss>>,
}

fn outcome_to_result(outcome: ReadOutcome) -> Result<String, BackfillMiss> {
    match outcome {
        ReadOutcome::Value(value) => Ok(value),
        ReadOutcome::Exited => Err(BackfillMiss::Exited),
        ReadOutcome::Unavailable(UnavailableReason::Exited) => Err(BackfillMiss::Exited),
        ReadOutcome::Unavailable(UnavailableReason::Ppl) => Err(BackfillMiss::Ppl),
        ReadOutcome::Unavailable(UnavailableReason::Wow64Unimplemented) => {
            Err(BackfillMiss::Wow64Unimplemented)
        }
        ReadOutcome::Unavailable(UnavailableReason::Unreadable) => Err(BackfillMiss::Unreadable),
    }
}

/// A small worker set that runs [`ProcessReader::read`] off the decode path.
///
/// [`BackfillPool::submit`] only queues. It does not call the reader. The
/// decode function therefore cannot block on a process open. Shutdown drops
/// the queue sender and joins the workers.
///
/// The pool is generic over the reader so a test can pass a double that never
/// opens a process. [`BackfillPool::new`] is the Windows constructor;
/// [`BackfillPool::with_reader`] takes any reader.
pub struct BackfillPool<R: ProcessReader> {
    tx: Mutex<Option<Sender<BackfillJob>>>,
    reports: Receiver<BackfillReport>,
    workers: Vec<JoinHandle<()>>,
    reader: Arc<R>,
}

impl<R: ProcessReader + 'static> BackfillPool<R> {
    /// `workers` threads, all sharing `reader`. `workers == 0` is treated as 1:
    /// a pool that cannot run a job would silently leave every argv at `NA`.
    pub fn with_reader(reader: R, workers: usize) -> Self {
        let (job_tx, job_rx) = mpsc::channel::<BackfillJob>();
        let (report_tx, report_rx) = mpsc::channel::<BackfillReport>();
        let job_rx = Arc::new(Mutex::new(job_rx));
        let reader = Arc::new(reader);
        let n = workers.max(1);
        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let rx = Arc::clone(&job_rx);
            let tx = report_tx.clone();
            let reader = Arc::clone(&reader);
            handles.push(thread::spawn(move || worker_loop(rx, tx, reader)));
        }
        Self {
            tx: Mutex::new(Some(job_tx)),
            reports: report_rx,
            workers: handles,
            reader,
        }
    }

    /// Queue `job`. `false` means the pool is shut down and the job was not queued.
    ///
    /// Never calls [`ProcessReader::read`]. A full queue cannot happen: the
    /// channel is unbounded. The bound on work is the caller's event rate, and
    /// a dropped report is observed by [`BackfillPool::try_recv`] returning
    /// disconnected after shutdown.
    pub fn submit(&self, job: BackfillJob) -> bool {
        match self.tx.lock() {
            Ok(guard) => match guard.as_ref() {
                Some(tx) => tx.send(job).is_ok(),
                None => false,
            },
            // A poisoned lock means a worker panicked while we held it. We
            // never hold it inside a worker, so this is a caller-side panic.
            // Treat it as "not queued" rather than panicking the decode path.
            Err(_) => false,
        }
    }

    /// Next finished job, if one is ready. Does not wait.
    ///
    /// `None` is both "nothing yet" and "the workers are gone". Callers that
    /// need to tell those apart shut the pool down and join.
    pub fn try_recv(&self) -> Option<BackfillReport> {
        self.reports.try_recv().ok()
    }

    /// Wait up to `timeout` for one report. `None` on timeout or disconnect.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<BackfillReport> {
        self.reports.recv_timeout(timeout).ok()
    }

    /// Shared reader. Tests assert the pool used the reader they passed in.
    pub fn reader(&self) -> &R {
        &self.reader
    }

    /// Stop accepting jobs and join the workers. Queued jobs still run.
    pub fn shutdown(mut self) {
        if let Ok(mut guard) = self.tx.lock() {
            guard.take();
        }
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

impl BackfillPool<crate::peb::NtProcessReader> {
    /// Pool that reads real processes. Not used by the decode tests.
    #[cfg(target_os = "windows")]
    pub fn new(workers: usize) -> Self {
        Self::with_reader(crate::peb::NtProcessReader, workers)
    }
}

fn worker_loop<R: ProcessReader>(
    jobs: Arc<Mutex<Receiver<BackfillJob>>>,
    reports: Sender<BackfillReport>,
    reader: Arc<R>,
) {
    loop {
        let job = {
            let guard = match jobs.lock() {
                Ok(guard) => guard,
                Err(_) => return,
            };
            match guard.recv() {
                Ok(job) => job,
                Err(_) => return,
            }
        };
        let answer = reader.read(&job.request());
        let report = BackfillReport {
            pid: job.pid,
            argv: job.want_argv.then(|| {
                answer
                    .argv
                    .map(outcome_to_result)
                    .unwrap_or(Err(BackfillMiss::Unreadable))
            }),
            cwd: job.want_cwd.then(|| {
                answer
                    .cwd
                    .map(outcome_to_result)
                    .unwrap_or(Err(BackfillMiss::Unreadable))
            }),
        };
        if reports.send(report).is_err() {
            return;
        }
    }
}

/// Apply a [`BackfillReport`] with the same rules as [`apply_backfill`].
pub fn apply_report(event: &mut RawEvent, job: BackfillJob, report: &BackfillReport) {
    let answer = BackfillAnswer {
        argv: report.argv.as_ref().map(result_to_outcome),
        cwd: report.cwd.as_ref().map(result_to_outcome),
    };
    apply_backfill(event, job, &answer);
}

fn result_to_outcome(result: &Result<String, BackfillMiss>) -> ReadOutcome {
    match result {
        Ok(value) => ReadOutcome::Value(value.clone()),
        Err(BackfillMiss::Exited) => ReadOutcome::Exited,
        Err(BackfillMiss::Ppl) => ReadOutcome::Unavailable(UnavailableReason::Ppl),
        Err(BackfillMiss::Wow64Unimplemented) => {
            ReadOutcome::Unavailable(UnavailableReason::Wow64Unimplemented)
        }
        Err(BackfillMiss::Unreadable) => ReadOutcome::Unavailable(UnavailableReason::Unreadable),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::peb::{UnavailableReader, BackfillRequest as Req};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Boot id used by the unit tests. Not a host name.
    const BOOT: &[u8] = b"11111111-1111-1111-1111-111111111111";

    /// FILETIME ticks for 2020-01-01T00:00:00Z. Chosen so it is obviously not
    /// "zero means unknown". 100-ns ticks: unix_ns = (filetime - epoch) * 100.
    fn filetime_2020() -> i64 {
        // 1970→2020 is 1_577_836_800 seconds. Epoch offset is the constant
        // `filetime_to_unix_ns` uses: 11_644_473_600 seconds.
        let unix_seconds: i64 = 1_577_836_800;
        let epoch_seconds: i64 = 11_644_473_600;
        (epoch_seconds + unix_seconds) * 10_000_000
    }

    fn clock() -> DecodeClock {
        DecodeClock {
            ts_mono_ns: 50,
            ts_wall_ns: Some(60),
        }
    }

    fn start_props() -> ProcessProperties {
        let mut props = ProcessProperties::bare(EVENT_PROCESS_START);
        props.process_id = Some(100);
        props.create_time = Some(filetime_2020());
        props.parent_process_id = Some(4);
        props.session_id = Some(1);
        props.image_name = Some("C:\\Windows\\System32\\cmd.exe".to_owned());
        props.tid = Some(7);
        props
    }

    struct ScriptedReader {
        answer: BackfillAnswer,
        calls: AtomicUsize,
    }

    impl ProcessReader for ScriptedReader {
        fn read(&self, request: &Req) -> BackfillAnswer {
            self.calls.fetch_add(1, Ordering::SeqCst);
            BackfillAnswer {
                argv: request.want_argv.then(|| {
                    self.answer
                        .argv
                        .clone()
                        .unwrap_or(ReadOutcome::Unavailable(UnavailableReason::Unreadable))
                }),
                cwd: request.want_cwd.then(|| {
                    self.answer
                        .cwd
                        .clone()
                        .unwrap_or(ReadOutcome::Unavailable(UnavailableReason::Unreadable))
                }),
            }
        }
    }

    #[test]
    fn command_line_on_the_event_is_e1_and_cwd_stays_pending() {
        let mut props = start_props();
        props.command_line = Some("cmd /c \"echo a b\" ping".to_owned());
        let mut cache = ProcessCache::new();
        let parent_time = filetime_2020() - 10_000_000;
        let parent = ProcessIdentity::from_parts(BOOT, 4, parent_time as u64, StartTimeUnit::HundredNanoseconds)
            .expect("boot id fits");
        cache.insert(
            4,
            CachedProcess {
                uid: parent.uid,
                create_time: parent_time,
            },
        );
        let decoded = decode_process(&props, BOOT, 1, clock(), &cache);
        let DecodedProcess::Start(start) = decoded else {
            panic!("expected a start");
        };
        assert_eq!(start.event.source.as_str(), SOURCE_PROCESS_START);
        assert_eq!(start.event.evidence, Evidence::E1);
        assert_eq!(start.event.field_evidence.get("argv"), Some(&Evidence::E1));
        assert_eq!(
            start.event.field_evidence.get("cwd"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
        match &start.event.kind {
            EventKind::ProcessStart(body) => {
                let argv = body.argv.as_ref().expect("argv present");
                let words: Vec<&str> = argv.iter().map(|a| a.as_str()).collect();
                assert_eq!(words, vec!["cmd", "/c", "echo a b", "ping"]);
                assert!(body.cwd.is_none());
                assert_eq!(body.ppid, 4);
                assert_eq!(body.parent_uid, Some(parent.uid));
                assert_eq!(body.how, StartHow::Spawn);
                assert!(body.env.is_none());
                assert_eq!(body.exe.as_deref(), Some("C:\\Windows\\System32\\cmd.exe"));
            }
            other => panic!("expected process_start, got {other:?}"),
        }
        assert_eq!(start.event.proc.as_ref().map(|p| p.pid), Some(100));
        let job = start.backfill.expect("cwd still needs a read");
        assert!(!job.want_argv);
        assert!(job.want_cwd);
    }

    #[test]
    fn missing_command_line_is_na_until_a_backfill_returns_s() {
        let props = start_props();
        let cache = ProcessCache::new();
        let decoded = decode_process(&props, BOOT, 2, clock(), &cache);
        let DecodedProcess::Start(mut start) = decoded else {
            panic!("expected a start");
        };
        assert_eq!(
            start.event.field_evidence.get("argv"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
        assert_eq!(
            start.event.field_evidence.get("parent_uid"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
        match &start.event.kind {
            EventKind::ProcessStart(body) => {
                assert!(body.argv.is_none());
                assert!(body.parent_uid.is_none());
                assert!(body.env.is_none());
            }
            other => panic!("expected process_start, got {other:?}"),
        }
        let job = start.backfill.expect("both fields pending");
        assert!(job.want_argv);
        let answer = BackfillAnswer {
            argv: Some(ReadOutcome::Value("ping -n 1 127.0.0.1".to_owned())),
            cwd: Some(ReadOutcome::Value("C:\\work".to_owned())),
        };
        apply_backfill(&mut start.event, job, &answer);
        assert_eq!(start.event.field_evidence.get("argv"), Some(&Evidence::S));
        assert_eq!(start.event.field_evidence.get("cwd"), Some(&Evidence::S));
        match &start.event.kind {
            EventKind::ProcessStart(body) => {
                let words: Vec<&str> = body
                    .argv
                    .as_ref()
                    .expect("argv")
                    .iter()
                    .map(|a| a.as_str())
                    .collect();
                assert_eq!(words, vec!["ping", "-n", "1", "127.0.0.1"]);
                assert_eq!(body.cwd.as_deref(), Some("C:\\work"));
            }
            other => panic!("expected process_start, got {other:?}"),
        }
    }

    #[test]
    fn exited_process_stays_na_and_wow64_cwd_is_not_an_empty_string() {
        let props = start_props();
        let cache = ProcessCache::new();
        let DecodedProcess::Start(mut start) = decode_process(&props, BOOT, 3, clock(), &cache)
        else {
            panic!("expected a start");
        };
        let job = start.backfill.expect("pending");
        let answer = BackfillAnswer {
            argv: Some(ReadOutcome::Exited),
            cwd: Some(ReadOutcome::Unavailable(
                UnavailableReason::Wow64Unimplemented,
            )),
        };
        apply_backfill(&mut start.event, job, &answer);
        assert_eq!(
            start.event.field_evidence.get("argv"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
        assert_eq!(
            start.event.field_evidence.get("cwd"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
        match &start.event.kind {
            EventKind::ProcessStart(body) => {
                assert!(body.argv.is_none());
                assert!(body.cwd.is_none());
                assert_ne!(body.cwd.as_deref(), Some(""));
            }
            other => panic!("expected process_start, got {other:?}"),
        }
    }

    #[test]
    fn parent_create_time_must_be_strictly_earlier() {
        let props = start_props();
        let child = filetime_2020();
        let mut cache = ProcessCache::new();
        let same = ProcessIdentity::from_parts(BOOT, 4, child as u64, StartTimeUnit::HundredNanoseconds)
            .expect("boot");
        cache.insert(
            4,
            CachedProcess {
                uid: same.uid,
                create_time: child,
            },
        );
        assert_eq!(
            resolve_parent(&cache, 4, child),
            ParentLink::CreateTimeNotEarlier
        );
        let DecodedProcess::Start(start) = decode_process(&props, BOOT, 4, clock(), &cache) else {
            panic!("expected a start");
        };
        match &start.event.kind {
            EventKind::ProcessStart(body) => {
                assert!(body.parent_uid.is_none());
                assert_eq!(body.ppid, 4);
            }
            other => panic!("expected process_start, got {other:?}"),
        }
        assert_eq!(
            start.event.field_evidence.get("parent_uid"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );

        let later = child + 10_000_000;
        let later_id =
            ProcessIdentity::from_parts(BOOT, 4, later as u64, StartTimeUnit::HundredNanoseconds)
                .expect("boot");
        cache.insert(
            4,
            CachedProcess {
                uid: later_id.uid,
                create_time: later,
            },
        );
        assert_eq!(
            resolve_parent(&cache, 4, child),
            ParentLink::CreateTimeNotEarlier
        );

        cache.remove_if(4, later);
        assert_eq!(resolve_parent(&cache, 4, child), ParentLink::UnknownParent);
    }

    #[test]
    fn proc_uid_uses_aw_core_and_stop_maps_exit_code() {
        let mut props = start_props();
        props.command_line = Some("cmd.exe".to_owned());
        let cache = ProcessCache::new();
        let DecodedProcess::Start(start) = decode_process(&props, BOOT, 5, clock(), &cache) else {
            panic!("expected a start");
        };
        let expected = ProcessIdentity::from_parts(
            BOOT,
            100,
            filetime_2020() as u64,
            StartTimeUnit::HundredNanoseconds,
        )
        .expect("boot");
        assert_eq!(start.event.proc.as_ref().map(|p| p.uid), Some(expected.uid));
        assert_eq!(start.cache_insert.0, 100);
        assert_eq!(start.cache_insert.1.uid, expected.uid);

        let mut stop = ProcessProperties::bare(EVENT_PROCESS_STOP);
        stop.process_id = Some(100);
        stop.create_time = Some(filetime_2020());
        stop.exit_code = Some(7);
        stop.exit_time = Some(filetime_2020() + 10_000_000);
        stop.image_name = Some("C:\\Windows\\System32\\cmd.exe".to_owned());
        let DecodedProcess::Stop(decoded) = decode_process(&stop, BOOT, 6, clock(), &cache) else {
            panic!("expected a stop");
        };
        assert_eq!(decoded.event.source.as_str(), SOURCE_PROCESS_STOP);
        assert_eq!(decoded.event.evidence, Evidence::E1);
        assert_eq!(decoded.event.proc.as_ref().map(|p| p.uid), Some(expected.uid));
        match &decoded.event.kind {
            EventKind::ProcessExit(body) => {
                assert_eq!(body.exit_code, Some(7));
                assert!(body.signal.is_none());
            }
            other => panic!("expected process_exit, got {other:?}"),
        }
        assert_eq!(
            decoded.event.field_evidence.get("signal"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
        assert!(!decoded.event.field_evidence.contains_key("exit_code"));
        assert_eq!(decoded.cache_remove, (100, filetime_2020()));
    }

    #[test]
    fn absent_exit_code_is_na_not_zero_and_other_ids_are_ignored() {
        let mut stop = ProcessProperties::bare(EVENT_PROCESS_STOP);
        stop.process_id = Some(100);
        stop.create_time = Some(filetime_2020());
        let cache = ProcessCache::new();
        let DecodedProcess::Stop(decoded) = decode_process(&stop, BOOT, 8, clock(), &cache) else {
            panic!("expected a stop");
        };
        match &decoded.event.kind {
            EventKind::ProcessExit(body) => assert_eq!(body.exit_code, None),
            other => panic!("expected process_exit, got {other:?}"),
        }
        assert_eq!(
            decoded.event.field_evidence.get("exit_code"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
        assert_eq!(
            decoded.event.field_evidence.get("exit_time"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
        assert!(matches!(
            decode_process(&ProcessProperties::bare(5), BOOT, 9, clock(), &cache),
            DecodedProcess::Ignored { event_id: 5 }
        ));
        let mut broken = start_props();
        broken.process_id = None;
        assert!(matches!(
            decode_process(&broken, BOOT, 10, clock(), &cache),
            DecodedProcess::Undecodable(_)
        ));
    }

    #[test]
    fn fields_the_doc_does_not_define_are_na() {
        let mut props = start_props();
        props.session_id = None;
        props.image_name = None;
        props.command_line = Some("a".to_owned());
        let cache = ProcessCache::new();
        let DecodedProcess::Start(start) = decode_process(&props, BOOT, 11, clock(), &cache) else {
            panic!("expected a start");
        };
        for key in ["exe", "user", "signer", "env", "cwd"] {
            assert_eq!(
                start.event.field_evidence.get(key),
                Some(&Evidence::NA(NaReason::CollectorUnavailable)),
                "{key}"
            );
        }
        match &start.event.kind {
            EventKind::ProcessStart(body) => {
                assert!(body.exe.is_none());
                assert!(body.user.is_none());
                assert!(body.signer.is_none());
                assert!(body.env.is_none());
            }
            other => panic!("expected process_start, got {other:?}"),
        }
    }

    #[test]
    fn pool_runs_the_reader_off_the_submit_call() {
        let reader = ScriptedReader {
            answer: BackfillAnswer {
                argv: Some(ReadOutcome::Value("echo hi".to_owned())),
                cwd: Some(ReadOutcome::Unavailable(UnavailableReason::Ppl)),
            },
            calls: AtomicUsize::new(0),
        };
        let pool = BackfillPool::with_reader(reader, 2);
        assert_eq!(pool.reader().calls.load(Ordering::SeqCst), 0);
        let job = BackfillJob {
            pid: 100,
            want_argv: true,
            want_cwd: true,
        };
        assert!(pool.submit(job));
        let report = pool
            .recv_timeout(Duration::from_secs(2))
            .expect("worker should finish without a real process");
        assert_eq!(report.pid, 100);
        assert_eq!(report.argv, Some(Ok("echo hi".to_owned())));
        assert_eq!(report.cwd, Some(Err(BackfillMiss::Ppl)));
        assert!(pool.reader().calls.load(Ordering::SeqCst) >= 1);

        let mut props = start_props();
        let cache = ProcessCache::new();
        let DecodedProcess::Start(mut start) = decode_process(&props, BOOT, 12, clock(), &cache)
        else {
            panic!("expected a start");
        };
        props.command_line = None;
        apply_report(&mut start.event, job, &report);
        assert_eq!(start.event.field_evidence.get("argv"), Some(&Evidence::S));
        assert_eq!(
            start.event.field_evidence.get("cwd"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
        match &start.event.kind {
            EventKind::ProcessStart(body) => assert!(body.cwd.is_none()),
            other => panic!("expected process_start, got {other:?}"),
        }
        pool.shutdown();
    }

    #[test]
    fn unavailable_reader_reports_unreadable_without_opening_anything() {
        let pool = BackfillPool::with_reader(UnavailableReader, 1);
        let job = BackfillJob {
            pid: 1,
            want_argv: true,
            want_cwd: false,
        };
        assert!(pool.submit(job));
        let report = pool.recv_timeout(Duration::from_secs(2)).expect("report");
        assert_eq!(report.argv, Some(Err(BackfillMiss::Unreadable)));
        assert!(report.cwd.is_none());
        pool.shutdown();
    }

    #[test]
    fn quoted_command_line_keeps_spaces_inside_quotes() {
        let argv = split_command_line("\"C:\\Program Files\\app.exe\" --name \"a b\" \"\"");
        let words: Vec<&str> = argv.iter().map(|a| a.as_str()).collect();
        assert_eq!(
            words,
            vec!["C:\\Program Files\\app.exe", "--name", "a b", ""]
        );
    }
}
