//! `sched_process_*` and `cgroup_attach_task` records → [`RawEvent`].
//!
//! The byte layout is the one `aw-ebpf` `proc` documents (P1-LNX-02, linux.md
//! §2.1). This module does not read it from that crate: `aw-ebpf` is not a
//! workspace member and is not linked here. Integers are little-endian.
//!
//! ```text
//! off  len  field
//!   0    4  kind            1 fork, 2 exec, 3 exit, 4 cgroup_attach_task
//!   4    4  tgid            child on fork; subject otherwise
//!   8    4  parent_tgid     valid when HAS_PARENT
//!  12    4  old_pid         sched_process_exec, valid when HAS_OLD_PID
//!  16    8  start_time_ns   task->start_time, monotonic ns since boot
//!  24    4  uid             valid when HAS_UID
//!  28    4  gid             valid when HAS_GID
//!  32    8  cgroup_id       cgroup the task is in (the one being left, on attach)
//!  40    8  dst_cgroup_id   cgroup_attach_task destination
//!  48    4  exit_code_raw   task->exit_code as i32; valid when HAS_EXIT_CODE
//!  52    4  flags
//!  56    2  argv_len        bytes of the argv tail, ≤ ARGV_CAP
//!  58    2  filename_len    bytes of the filename tail, ≤ FILENAME_CAP
//!  60    4  reserved        ignored
//!  64       filename bytes, then argv bytes
//! ```
//!
//! `proc_uid` is [`ProcessIdentity::from_parts`] over `(boot_id, tgid,
//! start_time_ns)` with [`StartTimeUnit::Nanoseconds`]. This file does not
//! hash. `start_time_ns` is the kernel value; the 10 ms truncation happens
//! inside `aw-core`, which is what keeps it aligned with `/proc/<pid>/stat`
//! field 22 once that jiffy count is converted to nanoseconds (ADR-0007).
//!
//! What each probe emits:
//!
//! | probe | source | event |
//! |---|---|---|
//! | `sched_process_fork` | `linux.ebpf/sched_process_fork` | `ProcessStart`, `how=fork`, no argv |
//! | `sched_process_exec` | `linux.ebpf/sched_process_exec` | `ProcessStart`, `how=exec`, argv from the tail |
//! | `sched_process_exit` | `linux.ebpf/sched_process_exit` | `ProcessExit`, and only for the thread-group leader |
//! | `cgroup_attach_task` | `linux.ebpf/cgroup_attach_task` | `Gap` when a scoped tgid leaves a session cgroup |
//!
//! cwd is not in the record. The caller reads `/proc/<tgid>/cwd` and passes
//! the outcome in; a value is evidence S, a miss is `NA(collector_unavailable)`.
//! Environment variables are not decoded. A fork flagged as a thread emits
//! nothing.

use std::collections::BTreeMap;

use aw_core::proc::{ProcessIdentity, StartTimeUnit};
use aw_core::{
    EventKind, Evidence, Gap, GapKind, NaReason, ProcRef, ProcUid, ProcessExit, ProcessStart,
    RawEvent, Redacted, Source, StartHow, UserRef, SCHEMA_VERSION,
};

/// `sched_process_fork`.
pub const KIND_FORK: u32 = 1;
/// `sched_process_exec`.
pub const KIND_EXEC: u32 = 2;
/// `sched_process_exit`.
pub const KIND_EXIT: u32 = 3;
/// `cgroup_attach_task`.
pub const KIND_CGROUP: u32 = 4;

/// Argv copy cap. A longer `mm->arg_start..arg_end` sets `truncated`.
pub const ARGV_CAP: usize = 4096;

/// Filename cap. A longer tail is a malformed record.
pub const FILENAME_CAP: usize = 4096;

/// Bytes before the filename and argv tails.
pub const HEADER_LEN: usize = 64;

/// `parent_tgid` was read.
pub const HAS_PARENT: u32 = 1 << 0;
/// `uid` was read.
pub const HAS_UID: u32 = 1 << 1;
/// `gid` was read.
pub const HAS_GID: u32 = 1 << 2;
/// `exit_code_raw` is `task->exit_code`.
pub const HAS_EXIT_CODE: u32 = 1 << 3;
/// The subject is the thread-group leader. An exit without this emits nothing.
pub const IS_LEADER: u32 = 1 << 4;
/// The argv region was longer than [`ARGV_CAP`].
pub const ARGV_TRUNCATED: u32 = 1 << 5;
/// The fork was `CLONE_THREAD`. No process event is emitted.
pub const IS_THREAD: u32 = 1 << 6;
/// `old_pid` was read.
pub const HAS_OLD_PID: u32 = 1 << 7;
/// A filename tail follows the header.
pub const HAS_FILENAME: u32 = 1 << 8;
/// `start_time_ns` was read. Without it a `ProcUid` cannot be built.
pub const HAS_START_TIME: u32 = 1 << 9;
/// An argv tail follows the filename. Unset means argv was not copied.
pub const HAS_ARGV: u32 = 1 << 10;
/// `cgroup_id` was read.
pub const HAS_CGROUP: u32 = 1 << 11;
/// `dst_cgroup_id` was read.
pub const HAS_DST_CGROUP: u32 = 1 << 12;

/// `source` for a fork. The probe name is the sub-source.
pub const SOURCE_FORK: &str = "linux.ebpf/sched_process_fork";
/// `source` for an exec.
pub const SOURCE_EXEC: &str = "linux.ebpf/sched_process_exec";
/// `source` for an exit.
pub const SOURCE_EXIT: &str = "linux.ebpf/sched_process_exit";
/// `source` for a cgroup attach.
pub const SOURCE_CGROUP: &str = "linux.ebpf/cgroup_attach_task";

/// What the caller learned from `/proc/<tgid>/cwd` while handling an exec.
///
/// The read itself is not done here. A decoded event never opens a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CwdRead {
    /// The symlink resolved. Stored at evidence S (linux.md §2.1).
    Value(String),
    /// The process was already gone, or the read failed. `cwd` stays unset
    /// and is marked `NA(collector_unavailable)`.
    Unavailable,
}

/// Where the record sits in the collector clock, plus the boot id for `ProcUid`.
///
/// `boot_id` is the raw bytes of `/proc/sys/kernel/random/boot_id`. An empty
/// slice is not a substitute for "unknown": callers that have no boot id must
/// not call [`decode_proc`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeContext<'a> {
    /// Monotonic nanoseconds in the daemon clock domain.
    pub ts_mono_ns: u64,
    /// Wall clock, Unix epoch nanoseconds. `None` is recorded as `NA`, not `0`.
    pub ts_wall_ns: Option<i64>,
    /// Daemon-local sequence number.
    pub seq: u64,
    /// Boot id bytes. Passed through to [`ProcessIdentity::from_parts`].
    pub boot_id: &'a [u8],
}

/// One decoded process record.
#[derive(Debug, Clone, PartialEq)]
pub enum ProcDecoded {
    /// `sched_process_fork` or `sched_process_exec`.
    ///
    /// `old_pid` is the `sched_process_exec` field of that name. `ProcessStart`
    /// has no slot for it (linux.md §2.1 lists it; the schema does not), so it
    /// stays beside the event instead of being written into `ppid` or `pid`.
    /// A fork has no `old_pid`.
    Start {
        event: RawEvent,
        old_pid: Option<u32>,
    },
    /// `sched_process_exit` of a thread-group leader.
    Exit(RawEvent),
    /// `cgroup_attach_task` that left a session cgroup.
    Escape(RawEvent),
    /// A thread fork, a non-leader exit, or a cgroup move that stays inside
    /// the session. Not an error and not a discarded event.
    Ignored,
}

/// Why a record was not decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcDecodeError {
    /// Shorter than the 64-byte header, or the declared tails run past the buffer.
    TruncatedRecord,
    /// `kind` is not one of the four probes.
    UnknownKind(u32),
    /// `argv_len` is above [`ARGV_CAP`], or `filename_len` is above [`FILENAME_CAP`].
    LengthOverCap,
    /// `boot_id` is longer than [`ProcessIdentity::from_parts`] accepts.
    BootIdRejected,
    /// A fork, exec, or exit without `HAS_START_TIME`. No `ProcUid` is invented.
    MissingStartTime,
    /// An exec whose filename bytes are not UTF-8. The bytes are not replaced.
    FilenameNotUtf8,
    /// An exec whose argv tail is not NUL-separated UTF-8.
    ArgvNotUtf8,
}

/// Session cgroups the escape check compares against.
///
/// Membership is a `u64` compare. This type does not read a cgroup filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCgroups {
    ids: Vec<u64>,
}

impl SessionCgroups {
    /// No session cgroup. Every attach decodes as [`ProcDecoded::Ignored`].
    pub fn empty() -> Self {
        Self { ids: Vec::new() }
    }

    /// One cgroup id.
    pub fn one(id: u64) -> Self {
        Self { ids: vec![id] }
    }

    /// Whether `id` is one of the session cgroups.
    pub fn contains(&self, id: u64) -> bool {
        self.ids.contains(&id)
    }
}

/// Decode one record.
///
/// `scoped` is the set of tgids currently inside the session. It is only
/// consulted for `cgroup_attach_task`. `cwd` is only consulted for an exec;
/// a fork has no cwd in linux.md §2.1, so it is marked `NA` regardless.
///
/// A thread fork (`IS_THREAD`) and a non-leader exit return [`ProcDecoded::Ignored`].
pub fn decode_proc(
    bytes: &[u8],
    ctx: DecodeContext<'_>,
    scoped: &[u32],
    session: &SessionCgroups,
    cwd: CwdRead,
) -> Result<ProcDecoded, ProcDecodeError> {
    let header = parse_header(bytes)?;
    match header.kind {
        KIND_FORK => decode_fork(&header, ctx),
        KIND_EXEC => decode_exec(&header, bytes, ctx, cwd),
        KIND_EXIT => decode_exit(&header, ctx),
        KIND_CGROUP => decode_cgroup(&header, ctx, scoped, session),
        other => Err(ProcDecodeError::UnknownKind(other)),
    }
}

/// Fixed fields of one record, after the length check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    kind: u32,
    tgid: u32,
    parent_tgid: u32,
    old_pid: u32,
    start_time_ns: u64,
    uid: u32,
    gid: u32,
    cgroup_id: u64,
    dst_cgroup_id: u64,
    exit_code_raw: i32,
    flags: u32,
    argv_len: u16,
    filename_len: u16,
}

fn parse_header(bytes: &[u8]) -> Result<Header, ProcDecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(ProcDecodeError::TruncatedRecord);
    }
    let argv_len = u16::from_le_bytes([bytes[56], bytes[57]]);
    let filename_len = u16::from_le_bytes([bytes[58], bytes[59]]);
    if argv_len as usize > ARGV_CAP || filename_len as usize > FILENAME_CAP {
        return Err(ProcDecodeError::LengthOverCap);
    }
    let tail = filename_len as usize + argv_len as usize;
    if bytes.len() < HEADER_LEN + tail {
        return Err(ProcDecodeError::TruncatedRecord);
    }
    Ok(Header {
        kind: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        tgid: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        parent_tgid: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        old_pid: u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
        start_time_ns: u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]),
        uid: u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
        gid: u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]),
        cgroup_id: u64::from_le_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]),
        dst_cgroup_id: u64::from_le_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47],
        ]),
        exit_code_raw: i32::from_le_bytes([bytes[48], bytes[49], bytes[50], bytes[51]]),
        flags: u32::from_le_bytes([bytes[52], bytes[53], bytes[54], bytes[55]]),
        argv_len,
        filename_len,
    })
}

fn flag(header: &Header, bit: u32) -> bool {
    header.flags & bit != 0
}

fn identity(header: &Header, boot_id: &[u8]) -> Result<ProcessIdentity, ProcDecodeError> {
    if !flag(header, HAS_START_TIME) {
        return Err(ProcDecodeError::MissingStartTime);
    }
    ProcessIdentity::from_parts(
        boot_id,
        header.tgid,
        header.start_time_ns,
        StartTimeUnit::Nanoseconds,
    )
    .ok_or(ProcDecodeError::BootIdRejected)
}

fn decode_fork(header: &Header, ctx: DecodeContext<'_>) -> Result<ProcDecoded, ProcDecodeError> {
    if flag(header, IS_THREAD) {
        return Ok(ProcDecoded::Ignored);
    }
    let ident = identity(header, ctx.boot_id)?;
    let parent_known = flag(header, HAS_PARENT);
    // `ppid` is a plain u32. `0` is a real pid, so an absent parent is stored
    // as `0` only together with `field_evidence["ppid"] = NA`.
    let ppid = if parent_known { header.parent_tgid } else { 0 };
    let parent_uid = if parent_known {
        ProcessIdentity::from_parts(
            ctx.boot_id,
            header.parent_tgid,
            header.start_time_ns,
            StartTimeUnit::Nanoseconds,
        )
        .map(|parent| parent.uid)
    } else {
        None
    };
    let start = ProcessStart::new(
        ppid,
        parent_uid,
        start_time_i64(header.start_time_ns),
        None,
        None,
        None,
        user_of(header),
        StartHow::Fork,
        None,
        None,
    );
    let mut event = build_event(
        ctx,
        proc_ref(ident.uid, header.tgid),
        Source::new(SOURCE_FORK),
        Evidence::E1,
        EventKind::ProcessStart(start),
    );
    if !parent_known {
        event.mark_na("ppid", NaReason::CollectorUnavailable);
        event.mark_na("parent_uid", NaReason::CollectorUnavailable);
    } else if parent_uid.is_none() {
        event.mark_na("parent_uid", NaReason::CollectorUnavailable);
    }
    // linux.md §2.1: a fork carries no filename, argv, or cwd.
    event.mark_na("exe", NaReason::CollectorUnavailable);
    event.mark_na("argv", NaReason::CollectorUnavailable);
    event.mark_na("cwd", NaReason::CollectorUnavailable);
    mark_common_absent(&mut event, header);
    Ok(ProcDecoded::Start {
        event,
        old_pid: None,
    })
}

fn decode_exec(
    header: &Header,
    bytes: &[u8],
    ctx: DecodeContext<'_>,
    cwd: CwdRead,
) -> Result<ProcDecoded, ProcDecodeError> {
    let ident = identity(header, ctx.boot_id)?;
    let filename = filename_of(header, bytes)?;
    let (argv, truncated) = argv_of(header, bytes)?;
    let parent_known = flag(header, HAS_PARENT);
    let ppid = if parent_known { header.parent_tgid } else { 0 };
    let (cwd_value, cwd_known) = match cwd {
        CwdRead::Value(path) => (Some(path), true),
        CwdRead::Unavailable => (None, false),
    };
    let start = ProcessStart::new(
        ppid,
        None,
        start_time_i64(header.start_time_ns),
        filename,
        argv,
        cwd_value,
        user_of(header),
        StartHow::Exec,
        None,
        None,
    );
    let mut event = build_event(
        ctx,
        proc_ref(ident.uid, header.tgid),
        Source::new(SOURCE_EXEC),
        Evidence::E1,
        EventKind::ProcessStart(start),
    );
    if !parent_known {
        event.mark_na("ppid", NaReason::CollectorUnavailable);
    }
    // The exec record does not carry the parent's start time, so the parent's
    // ProcUid cannot be hashed here. The raw ppid stays; the uid is NA.
    event.mark_na("parent_uid", NaReason::CollectorUnavailable);
    if !flag(header, HAS_FILENAME) {
        event.mark_na("exe", NaReason::CollectorUnavailable);
    }
    if !flag(header, HAS_ARGV) {
        event.mark_na("argv", NaReason::CollectorUnavailable);
    } else if truncated {
        // The copied prefix is still the real prefix. The field is E1, and
        // `truncated` says the kernel stopped at ARGV_CAP.
        event.field_evidence.insert("argv".to_owned(), Evidence::E1);
        event
            .field_evidence
            .insert("argv.truncated".to_owned(), Evidence::E1);
    }
    if cwd_known {
        event.field_evidence.insert("cwd".to_owned(), Evidence::S);
    } else {
        event.mark_na("cwd", NaReason::CollectorUnavailable);
    }
    mark_common_absent(&mut event, header);
    let old_pid = if flag(header, HAS_OLD_PID) {
        Some(header.old_pid)
    } else {
        None
    };
    Ok(ProcDecoded::Start { event, old_pid })
}

fn decode_exit(header: &Header, ctx: DecodeContext<'_>) -> Result<ProcDecoded, ProcDecodeError> {
    if !flag(header, IS_LEADER) {
        return Ok(ProcDecoded::Ignored);
    }
    let ident = identity(header, ctx.boot_id)?;
    let (exit_code, signal) = if flag(header, HAS_EXIT_CODE) {
        split_exit(header.exit_code_raw)
    } else {
        (None, None)
    };
    let exit = ProcessExit::new(exit_code, signal);
    let mut event = build_event(
        ctx,
        proc_ref(ident.uid, header.tgid),
        Source::new(SOURCE_EXIT),
        Evidence::E1,
        EventKind::ProcessExit(exit),
    );
    if !flag(header, HAS_EXIT_CODE) {
        event.mark_na("exit_code", NaReason::CollectorUnavailable);
        event.mark_na("signal", NaReason::CollectorUnavailable);
    } else if signal.is_none() {
        event.mark_na("signal", NaReason::CollectorUnavailable);
    } else {
        // Signalled: there is no wait-status exit code. `None` is not `0`.
        event.mark_na("exit_code", NaReason::CollectorUnavailable);
    }
    Ok(ProcDecoded::Exit(event))
}

fn decode_cgroup(
    header: &Header,
    ctx: DecodeContext<'_>,
    scoped: &[u32],
    session: &SessionCgroups,
) -> Result<ProcDecoded, ProcDecodeError> {
    let in_scope = scoped.contains(&header.tgid);
    let leaving = flag(header, HAS_CGROUP) && session.contains(header.cgroup_id);
    let arriving = flag(header, HAS_DST_CGROUP) && session.contains(header.dst_cgroup_id);
    // CAP-SCOPE-04: a scoped process moved out of a session cgroup. A move
    // whose destination is still a session cgroup is not an escape.
    if !in_scope || !leaving || arriving {
        return Ok(ProcDecoded::Ignored);
    }
    let ident = identity(header, ctx.boot_id).ok();
    let proc = ident.map(|ident| proc_ref(ident.uid, header.tgid));
    let proc_missing = proc.is_none();
    let dst_known = flag(header, HAS_DST_CGROUP);
    let detail = match dst_known {
        true => format!(
            "tgid {} left session cgroup {} for cgroup {}",
            header.tgid, header.cgroup_id, header.dst_cgroup_id
        ),
        false => format!(
            "tgid {} left session cgroup {}; destination cgroup was not in the record",
            header.tgid, header.cgroup_id
        ),
    };
    // No GapKind names a cgroup escape. `AttributionUnknown` is the one for an
    // event that can no longer be tied to the watched scope. `ScopeRace` means
    // the opposite: the process was not yet inside the scope. The detail says
    // which cgroup the process left.
    let gap = Gap::new(
        Source::new(SOURCE_CGROUP),
        GapKind::AttributionUnknown,
        vec!["proc".to_owned()],
        ctx.ts_mono_ns,
        ctx.ts_mono_ns,
        Some(1),
        Some(detail),
    );
    let mut event = build_event(
        ctx,
        proc_ref_or_absent(proc, header.tgid),
        Source::new(SOURCE_CGROUP),
        Evidence::E1,
        EventKind::Gap(gap),
    );
    if proc_missing {
        event.mark_na("proc", NaReason::CollectorUnavailable);
    }
    if !dst_known {
        event.mark_na("dst_cgroup_id", NaReason::CollectorUnavailable);
    }
    Ok(ProcDecoded::Escape(event))
}

/// Linux `task->exit_code`: the wait status. Low 7 bits are the signal;
/// bit 7 is a core dump; the next byte is the `exit(2)` code.
fn split_exit(raw: i32) -> (Option<i32>, Option<i32>) {
    let status = raw as u32;
    let signal = (status & 0x7f) as i32;
    if signal == 0 {
        let code = ((status >> 8) & 0xff) as i32;
        (Some(code), None)
    } else {
        (None, Some(signal))
    }
}

fn filename_of(header: &Header, bytes: &[u8]) -> Result<Option<String>, ProcDecodeError> {
    if !flag(header, HAS_FILENAME) {
        return Ok(None);
    }
    let start = HEADER_LEN;
    let end = start + header.filename_len as usize;
    let slice = bytes
        .get(start..end)
        .ok_or(ProcDecodeError::TruncatedRecord)?;
    let text = std::str::from_utf8(slice).map_err(|_| ProcDecodeError::FilenameNotUtf8)?;
    Ok(Some(text.to_owned()))
}

/// Split the argv tail on NUL. A trailing NUL does not add an empty element.
///
/// Returns the elements and whether the kernel stopped at [`ARGV_CAP`].
fn argv_of(
    header: &Header,
    bytes: &[u8],
) -> Result<(Option<Vec<Redacted>>, bool), ProcDecodeError> {
    if !flag(header, HAS_ARGV) {
        return Ok((None, false));
    }
    let start = HEADER_LEN + header.filename_len as usize;
    let end = start + header.argv_len as usize;
    let slice = bytes
        .get(start..end)
        .ok_or(ProcDecodeError::TruncatedRecord)?;
    let mut out = Vec::new();
    for part in slice.split(|b| *b == 0) {
        if part.is_empty() {
            continue;
        }
        let text = std::str::from_utf8(part).map_err(|_| ProcDecodeError::ArgvNotUtf8)?;
        out.push(Redacted::new(text));
    }
    let truncated = flag(header, ARGV_TRUNCATED) || header.argv_len as usize == ARGV_CAP;
    Ok((Some(out), truncated))
}

fn user_of(header: &Header) -> Option<UserRef> {
    if !flag(header, HAS_UID) {
        return None;
    }
    let id = if flag(header, HAS_GID) {
        format!("{}:{}", header.uid, header.gid)
    } else {
        header.uid.to_string()
    };
    Some(UserRef { id, name: None })
}

fn mark_common_absent(event: &mut RawEvent, header: &Header) {
    if !flag(header, HAS_UID) {
        event.mark_na("user", NaReason::CollectorUnavailable);
    }
    // Not recorded. An absent env is not an empty environment.
    event.mark_na("env", NaReason::CollectorUnavailable);
    event.mark_na("signer", NaReason::CollectorUnavailable);
}

fn start_time_i64(ns: u64) -> i64 {
    i64::try_from(ns).unwrap_or(i64::MAX)
}

fn proc_ref(uid: ProcUid, pid: u32) -> ProcRef {
    ProcRef {
        uid,
        pid,
        tid: None,
    }
}

fn proc_ref_or_absent(proc: Option<ProcRef>, pid: u32) -> ProcRef {
    proc.unwrap_or(ProcRef {
        uid: ProcUid(0),
        pid,
        tid: None,
    })
}

fn build_event(
    ctx: DecodeContext<'_>,
    proc: ProcRef,
    source: Source,
    evidence: Evidence,
    kind: EventKind,
) -> RawEvent {
    let wall_known = ctx.ts_wall_ns.is_some();
    let mut event = RawEvent {
        v: SCHEMA_VERSION,
        seq: ctx.seq,
        ts_mono_ns: ctx.ts_mono_ns,
        ts_wall_ns: ctx.ts_wall_ns.unwrap_or(0),
        session_id: None,
        proc: Some(proc),
        source,
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

/// Write one record. Tests and a future ring-buffer reader share this, so the
/// decoder is not checked against a layout the writer does not produce.
pub fn encode_proc(record: &ProcRecord) -> Vec<u8> {
    let filename = record.filename.as_deref().unwrap_or("");
    let filename_bytes = filename.as_bytes();
    let argv_bytes = record.argv_bytes.as_deref().unwrap_or(&[]);
    let mut flags = record.flags;
    if record.parent_tgid.is_some() {
        flags |= HAS_PARENT;
    }
    if record.uid.is_some() {
        flags |= HAS_UID;
    }
    if record.gid.is_some() {
        flags |= HAS_GID;
    }
    if record.exit_code_raw.is_some() {
        flags |= HAS_EXIT_CODE;
    }
    if record.old_pid.is_some() {
        flags |= HAS_OLD_PID;
    }
    if record.filename.is_some() {
        flags |= HAS_FILENAME;
    }
    if record.start_time_ns.is_some() {
        flags |= HAS_START_TIME;
    }
    if record.argv_bytes.is_some() {
        flags |= HAS_ARGV;
    }
    if record.cgroup_id.is_some() {
        flags |= HAS_CGROUP;
    }
    if record.dst_cgroup_id.is_some() {
        flags |= HAS_DST_CGROUP;
    }
    if record.truncated {
        flags |= ARGV_TRUNCATED;
    }
    if record.thread {
        flags |= IS_THREAD;
    }
    if record.leader {
        flags |= IS_LEADER;
    }
    let argv_len = u16::try_from(argv_bytes.len()).unwrap_or(u16::MAX);
    let filename_len = u16::try_from(filename_bytes.len()).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(HEADER_LEN + filename_bytes.len() + argv_bytes.len());
    out.extend_from_slice(&record.kind.to_le_bytes());
    out.extend_from_slice(&record.tgid.to_le_bytes());
    out.extend_from_slice(&record.parent_tgid.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&record.old_pid.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&record.start_time_ns.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&record.uid.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&record.gid.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&record.cgroup_id.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&record.dst_cgroup_id.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&record.exit_code_raw.unwrap_or(0).to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&argv_len.to_le_bytes());
    out.extend_from_slice(&filename_len.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(filename_bytes);
    out.extend_from_slice(argv_bytes);
    out
}

/// A record before it is bytes. `None` means the probe did not read the field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcRecord {
    /// [`KIND_FORK`], [`KIND_EXEC`], [`KIND_EXIT`], or [`KIND_CGROUP`].
    pub kind: u32,
    /// Child tgid on fork; the subject tgid otherwise.
    pub tgid: u32,
    /// Parent tgid.
    pub parent_tgid: Option<u32>,
    /// `sched_process_exec` old pid.
    pub old_pid: Option<u32>,
    /// `task->start_time` in monotonic nanoseconds.
    pub start_time_ns: Option<u64>,
    /// Real uid.
    pub uid: Option<u32>,
    /// Real gid.
    pub gid: Option<u32>,
    /// Cgroup the task is in, or the one it is leaving.
    pub cgroup_id: Option<u64>,
    /// Destination cgroup.
    pub dst_cgroup_id: Option<u64>,
    /// Raw `task->exit_code`.
    pub exit_code_raw: Option<i32>,
    /// Filename, present or not. Not truncated by [`encode_proc`].
    pub filename: Option<String>,
    /// Argv bytes already capped by the caller. `None` means not copied.
    pub argv_bytes: Option<Vec<u8>>,
    /// The kernel stopped at [`ARGV_CAP`].
    pub truncated: bool,
    /// `CLONE_THREAD` fork.
    pub thread: bool,
    /// Thread-group leader.
    pub leader: bool,
    /// Extra flag bits. Presence bits are derived from the `Option` fields.
    pub flags: u32,
}

impl ProcRecord {
    /// A record of `kind` with every optional field unset.
    pub fn bare(kind: u32, tgid: u32) -> Self {
        Self {
            kind,
            tgid,
            parent_tgid: None,
            old_pid: None,
            start_time_ns: None,
            uid: None,
            gid: None,
            cgroup_id: None,
            dst_cgroup_id: None,
            exit_code_raw: None,
            filename: None,
            argv_bytes: None,
            truncated: false,
            thread: false,
            leader: false,
            flags: 0,
        }
    }
}

/// Join argv elements with a trailing NUL each, the way `mm->arg_start` stores them.
pub fn argv_bytes(args: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for arg in args {
        out.extend_from_slice(arg.as_bytes());
        out.push(0);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &[u8] = b"11111111-1111-1111-1111-111111111111";

    fn ctx(seq: u64) -> DecodeContext<'static> {
        DecodeContext {
            ts_mono_ns: 1_000_000_000 + seq,
            ts_wall_ns: Some(1_700_000_000_000_000_000),
            seq,
            boot_id: BOOT,
        }
    }

    fn exec_record(args: &[&str]) -> ProcRecord {
        let mut record = ProcRecord::bare(KIND_EXEC, 4242);
        record.parent_tgid = Some(4241);
        record.old_pid = Some(4240);
        record.start_time_ns = Some(5_000_000_000);
        record.uid = Some(1000);
        record.gid = Some(1000);
        record.cgroup_id = Some(9);
        record.filename = Some("/bin/echo".to_owned());
        record.argv_bytes = Some(argv_bytes(args));
        record
    }

    fn must_decode(bytes: &[u8], seq: u64, cwd: CwdRead) -> ProcDecoded {
        match decode_proc(bytes, ctx(seq), &[], &SessionCgroups::empty(), cwd) {
            Ok(decoded) => decoded,
            Err(err) => panic!("record {seq} failed: {err:?}"),
        }
    }

    fn must_decode_scoped(
        bytes: &[u8],
        seq: u64,
        scoped: &[u32],
        session: &SessionCgroups,
    ) -> ProcDecoded {
        match decode_proc(bytes, ctx(seq), scoped, session, CwdRead::Unavailable) {
            Ok(decoded) => decoded,
            Err(err) => panic!("record {seq} failed: {err:?}"),
        }
    }

    fn ident(pid: u32, start: u64) -> ProcessIdentity {
        match ProcessIdentity::from_parts(BOOT, pid, start, StartTimeUnit::Nanoseconds) {
            Some(identity) => identity,
            None => panic!("boot id is a short UUID"),
        }
    }

    fn start_of(decoded: ProcDecoded) -> RawEvent {
        match decoded {
            ProcDecoded::Start { event, .. } => event,
            other => panic!("expected a start, got {other:?}"),
        }
    }

    fn argv_strings(event: &RawEvent) -> Vec<String> {
        match &event.kind {
            EventKind::ProcessStart(start) => start
                .argv
                .as_ref()
                .map(|args| args.iter().map(|a| a.as_str().to_owned()).collect())
                .unwrap_or_default(),
            other => panic!("expected ProcessStart, got {other:?}"),
        }
    }

    #[test]
    fn exec_fields_round_trip() {
        let bytes = encode_proc(&exec_record(&["/bin/echo", "a b", "中文"]));
        let decoded = must_decode(&bytes, 1, CwdRead::Value("/tmp".to_owned()));
        let ProcDecoded::Start { old_pid, .. } = &decoded else {
            panic!("expected a start");
        };
        assert_eq!(*old_pid, Some(4240));
        let event = start_of(decoded);
        assert_eq!(event.source.as_str(), SOURCE_EXEC);
        assert_eq!(event.evidence, Evidence::E1);
        let EventKind::ProcessStart(start) = &event.kind else {
            panic!("kind");
        };
        assert_eq!(start.how, StartHow::Exec);
        assert_eq!(start.ppid, 4241);
        assert_eq!(start.exe.as_deref(), Some("/bin/echo"));
        assert_eq!(start.cwd.as_deref(), Some("/tmp"));
        assert_eq!(argv_strings(&event), vec!["/bin/echo", "a b", "中文"]);
        assert_eq!(
            event.field_evidence.get("cwd"),
            Some(&Evidence::S),
            "cwd is a userspace read"
        );
        assert!(!event.field_evidence.contains_key("argv.truncated"));
        let Some(proc) = &event.proc else {
            panic!("proc");
        };
        assert_eq!(proc.pid, 4242);
        assert_eq!(proc.uid, ident(4242, 5_000_000_000).uid);
        assert_eq!(start.start_time_ns, 5_000_000_000);
        let Some(user) = &start.user else {
            panic!("user");
        };
        assert_eq!(user.id, "1000:1000");
        assert!(start.env.is_none());
        assert_eq!(
            event.field_evidence.get("env"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
    }

    #[test]
    fn fork_is_a_start_without_argv_and_a_thread_fork_is_ignored() {
        let mut record = ProcRecord::bare(KIND_FORK, 50);
        record.parent_tgid = Some(40);
        record.start_time_ns = Some(8_000_000_000);
        let event = start_of(must_decode(&encode_proc(&record), 2, CwdRead::Unavailable));
        assert_eq!(event.source.as_str(), SOURCE_FORK);
        let EventKind::ProcessStart(start) = &event.kind else {
            panic!("kind");
        };
        assert_eq!(start.how, StartHow::Fork);
        assert_eq!(start.ppid, 40);
        assert!(start.argv.is_none());
        assert!(start.exe.is_none());
        assert_eq!(
            event.field_evidence.get("argv"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
        assert_eq!(
            event.field_evidence.get("cwd"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
        let Some(parent) = start.parent_uid else {
            panic!("parent uid");
        };
        assert_eq!(parent, ident(40, 8_000_000_000).uid);

        record.thread = true;
        let decoded = must_decode(&encode_proc(&record), 3, CwdRead::Unavailable);
        assert_eq!(decoded, ProcDecoded::Ignored);
    }

    #[test]
    fn exit_emits_only_for_the_leader_and_splits_the_wait_status() {
        let mut record = ProcRecord::bare(KIND_EXIT, 50);
        record.start_time_ns = Some(8_000_000_000);
        record.exit_code_raw = Some(0x0000);
        let ignored = must_decode(&encode_proc(&record), 4, CwdRead::Unavailable);
        assert_eq!(ignored, ProcDecoded::Ignored, "a non-leader exit is silent");

        record.leader = true;
        record.exit_code_raw = Some(0x0100);
        let ProcDecoded::Exit(event) = must_decode(&encode_proc(&record), 5, CwdRead::Unavailable)
        else {
            panic!("expected an exit");
        };
        assert_eq!(event.source.as_str(), SOURCE_EXIT);
        let EventKind::ProcessExit(exit) = &event.kind else {
            panic!("kind");
        };
        assert_eq!(exit.exit_code, Some(1));
        assert_eq!(exit.signal, None);

        record.exit_code_raw = Some(0x0009);
        let ProcDecoded::Exit(signalled) =
            must_decode(&encode_proc(&record), 6, CwdRead::Unavailable)
        else {
            panic!("expected an exit");
        };
        let EventKind::ProcessExit(exit) = &signalled.kind else {
            panic!("kind");
        };
        assert_eq!(exit.signal, Some(9));
        assert_eq!(exit.exit_code, None);
        assert_eq!(
            signalled.field_evidence.get("exit_code"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
    }

    #[test]
    fn missing_cwd_is_na_not_an_empty_string() {
        let event = start_of(must_decode(
            &encode_proc(&exec_record(&["/bin/true"])),
            7,
            CwdRead::Unavailable,
        ));
        let EventKind::ProcessStart(start) = &event.kind else {
            panic!("kind");
        };
        assert_eq!(start.cwd, None);
        assert_eq!(
            event.field_evidence.get("cwd"),
            Some(&Evidence::NA(NaReason::CollectorUnavailable))
        );
    }

    #[test]
    fn argv_over_4k_is_truncated() {
        let mut args = Vec::new();
        args.push("/bin/bash".to_owned());
        let mut blob = String::new();
        while blob.len() < ARGV_CAP {
            blob.push('x');
        }
        args.push(blob);
        let mut raw = argv_bytes(&args.iter().map(String::as_str).collect::<Vec<_>>());
        assert!(raw.len() > ARGV_CAP);
        raw.truncate(ARGV_CAP);
        let mut record = exec_record(&[]);
        record.argv_bytes = Some(raw);
        record.truncated = true;
        let event = start_of(must_decode(&encode_proc(&record), 8, CwdRead::Unavailable));
        assert_eq!(
            event.field_evidence.get("argv.truncated"),
            Some(&Evidence::E1)
        );
        let copied = argv_strings(&event);
        assert!(!copied.is_empty());
        let stored: usize = copied.iter().map(String::len).sum();
        assert!(stored <= ARGV_CAP);
    }

    #[test]
    fn exactly_4k_of_argv_is_also_marked_truncated() {
        let mut raw = vec![b'a'; ARGV_CAP - 1];
        raw.push(0);
        assert_eq!(raw.len(), ARGV_CAP);
        let mut record = exec_record(&[]);
        record.argv_bytes = Some(raw);
        let event = start_of(must_decode(&encode_proc(&record), 9, CwdRead::Unavailable));
        assert_eq!(
            event.field_evidence.get("argv.truncated"),
            Some(&Evidence::E1),
            "a full 4 KiB copy cannot prove the region ended there"
        );
    }

    #[test]
    fn five_thousand_exec_records_all_decode() {
        let mut decoded = 0_u32;
        for n in 0..5000_u32 {
            let mut record = ProcRecord::bare(KIND_EXEC, 10_000 + n);
            record.parent_tgid = Some(1);
            record.start_time_ns = Some(1_000_000_000 + u64::from(n));
            record.filename = Some("/bin/true".to_owned());
            record.argv_bytes = Some(argv_bytes(&["/bin/true"]));
            let event = start_of(must_decode(
                &encode_proc(&record),
                u64::from(n),
                CwdRead::Unavailable,
            ));
            assert_eq!(event.source.as_str(), SOURCE_EXEC);
            let Some(proc) = &event.proc else {
                panic!("proc {n}");
            };
            assert_eq!(proc.pid, 10_000 + n);
            decoded += 1;
        }
        assert_eq!(decoded, 5000);
    }

    #[test]
    fn cgroup_leave_is_an_escape_gap_and_a_stay_is_not() {
        let mut record = ProcRecord::bare(KIND_CGROUP, 77);
        record.start_time_ns = Some(2_000_000_000);
        record.cgroup_id = Some(100);
        record.dst_cgroup_id = Some(200);
        let ProcDecoded::Escape(event) =
            must_decode_scoped(&encode_proc(&record), 10, &[77], &SessionCgroups::one(100))
        else {
            panic!("expected an escape");
        };
        assert_eq!(event.source.as_str(), SOURCE_CGROUP);
        let EventKind::Gap(gap) = &event.kind else {
            panic!("kind");
        };
        // ScopeRace would mean the process was not yet in scope. A process that
        // left the session cgroup can no longer be attributed to it.
        assert_eq!(gap.gap_kind, GapKind::AttributionUnknown);
        assert!(
            !event.field_evidence.contains_key("gap_kind"),
            "the kind is known; it is not an NA"
        );
        let Some(detail) = &gap.detail else {
            panic!("detail");
        };
        assert!(detail.contains("left session cgroup 100"));
        assert!(detail.contains("200"));
        assert_eq!(gap.affects, vec!["proc".to_owned()]);

        let stayed =
            must_decode_scoped(&encode_proc(&record), 11, &[77], &SessionCgroups::one(200));
        assert_eq!(
            stayed,
            ProcDecoded::Ignored,
            "arriving in a session cgroup is not an escape"
        );

        let outsider =
            must_decode_scoped(&encode_proc(&record), 12, &[], &SessionCgroups::one(100));
        assert_eq!(outsider, ProcDecoded::Ignored);
    }

    #[test]
    fn a_short_buffer_is_rejected() {
        let err = match decode_proc(
            &[0_u8; 8],
            ctx(13),
            &[],
            &SessionCgroups::empty(),
            CwdRead::Unavailable,
        ) {
            Ok(_) => panic!("a short buffer must not decode"),
            Err(err) => err,
        };
        assert_eq!(err, ProcDecodeError::TruncatedRecord);
    }

    #[test]
    fn header_is_64_bytes_and_kind_is_first() {
        let bytes = encode_proc(&exec_record(&["/bin/true"]));
        assert!(bytes.len() > HEADER_LEN);
        assert_eq!(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            KIND_EXEC
        );
        assert_eq!(&bytes[64..64 + "/bin/echo".len()], b"/bin/echo");
    }
}
