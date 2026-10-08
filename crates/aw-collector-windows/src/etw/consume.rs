//! Drain one ETW session into `RawEvent`s.
//!
//! The callback in [`super::trace`] forwards headers and returns. This is the
//! side that turns them into events, so the schema parse and the file cache
//! stay off the ETW thread.
//!
//! Kernel-File is the exception that arrives already parsed. Its `EventRecord`
//! does not outlive the callback, so the callback copies the properties into
//! [`SessionMessage::File`] and folds Read and Write into the [`IoTally`] both
//! sides share. This module owns that tally's other half: on Close it reads the
//! totals back out, and it owns the [`FileObjectMap`] that joins a `FileObject`
//! to the path from its Create.
//!
//! Process and network events still arrive as a bare [`SessionMessage::Header`].
//! Their property parsers are not wired — the record is gone by the time a
//! header is read — so a header becomes a `Gap { kind: parse_error }` rather
//! than a decoded event with invented fields. The gap is counted.
//!
//! An id this module does not know is counted and dropped. Nothing is emitted
//! for it, and the count is not reset, so the skip stays visible.

use std::sync::{Arc, Mutex};

use aw_core::{EventKind, Evidence, Gap, GapKind, NaReason, RawEvent, Source};

use crate::file_map::{DecodedFile, FileDecoder, KnownProcess};

use super::file::{self, FileOp, IoTally};
use super::process::DecodeClock;
use super::session::{self, EtwStamp};
use super::trace::{FileEvent, Session, SessionMessage};

/// `source` of a gap this consumer emits for an event it could not decode.
///
/// Distinct from [`session::SESSION_SOURCE`], which is the OS-loss gap. This
/// one is the collector giving up on a single event.
const SOURCE_CONSUMER: &str = "windows.etw/consumer";

/// Reads [`SessionMessage`]s and emits [`RawEvent`]s.
///
/// One per session. The [`IoTally`] and the [`FileDecoder`] live here, not on
/// the callback: they are per-session state, and the callback only borrows the
/// tally long enough to add one read or write.
pub struct Consumer {
    session: Session,
    files: FileDecoder,
    /// Read/write totals. `None` when the session did not enable Kernel-File,
    /// in which case no file event arrives and the cache stays empty.
    tally: Option<Arc<Mutex<IoTally>>>,
    next_seq: u64,
    /// Kernel-File ids outside the §2.2 table. The callback counts its own
    /// skips; this counts the ones that reached the channel anyway.
    skipped_file: u64,
    /// Headers whose provider this build cannot decode yet (process, network,
    /// DNS). Each one also produced a gap.
    undecoded_headers: u64,
    /// Last monotonic time a decoded event carried, so a gap at shutdown has a
    /// range. `None` until the first event.
    last_mono_ns: Option<u64>,
}

impl Consumer {
    /// A consumer for a session that is already running.
    ///
    /// Takes the tally handle from the session, so the callback's writes and
    /// this consumer's reads are the same map.
    pub fn new(session: Session) -> Self {
        let tally = session.file_tally();
        Self {
            session,
            files: FileDecoder::new(),
            tally,
            next_seq: 1,
            skipped_file: 0,
            undecoded_headers: 0,
            last_mono_ns: None,
        }
    }

    /// File events the callback skipped plus the ones this consumer skipped.
    ///
    /// An unknown Kernel-File id is counted in one of the two, never in both:
    /// the callback drops it before the channel.
    pub fn skipped_file(&self) -> u64 {
        self.session
            .file_skipped()
            .saturating_add(self.skipped_file)
    }

    /// Headers that became a parse gap because their properties were not on the
    /// message. Process, network, and DNS, until their parsers move here.
    pub fn undecoded_headers(&self) -> u64 {
        self.undecoded_headers
    }

    /// Events the callback could not queue because the channel was full.
    pub fn channel_full(&self) -> u64 {
        self.session.channel_full()
    }

    /// Block until the next event, a loss notice, or the channel closes.
    ///
    /// `None` means the session stopped and nothing more will arrive. A loss
    /// notice comes back as one gap. One Kernel-File record can come back as
    /// several events: a Create whose disposition creates is a `FileCreate` and
    /// a `FileOpen`, and a Close flushes the accumulated read and write first.
    pub fn recv(&mut self) -> Option<Vec<RawEvent>> {
        match self.session.receiver().recv() {
            Ok(message) => Some(self.dispatch(message)),
            Err(_) => None,
        }
    }

    /// Like [`Self::recv`], but returns `None` when nothing is waiting.
    pub fn try_recv(&mut self) -> Option<Vec<RawEvent>> {
        match self.session.receiver().try_recv() {
            Ok(message) => Some(self.dispatch(message)),
            Err(_) => None,
        }
    }

    /// Stop the session.
    ///
    /// Rows still in the file cache have no Close, so they become one
    /// `Gap { kind: cache_evicted }` instead of a finished event. The same for
    /// read/write totals nobody closed. Both are returned ahead of the stop, so
    /// a caller drains them before dropping the consumer.
    pub fn stop(mut self) -> Result<Vec<RawEvent>, super::session::SessionError> {
        let mut tail = Vec::new();
        let mono = self.last_mono_ns.unwrap_or(0);
        let clock = DecodeClock {
            ts_mono_ns: mono,
            ts_wall_ns: None,
        };
        let seq = self.alloc_seq();
        if let Some(gap) = self.files.eviction_gap(seq, clock) {
            tail.push(gap);
        }
        let dropped = self
            .tally
            .as_ref()
            .and_then(|tally| tally.lock().ok())
            .map(|mut tally| tally.clear())
            .unwrap_or(0);
        if dropped > 0 {
            tail.push(self.gap(
                GapKind::CacheEvicted,
                "file",
                dropped,
                "read/write tally dropped on session stop",
                clock,
            ));
        }
        self.session.stop()?;
        Ok(tail)
    }

    fn dispatch(&mut self, message: SessionMessage) -> Vec<RawEvent> {
        match message {
            SessionMessage::File(event) => self.on_file(event),
            SessionMessage::Header(header) => {
                // The record was not kept, so there is no property to decode.
                // Emitting a process or network event from the header alone
                // would fill every field with a guess. Count it and say so.
                self.undecoded_headers = self.undecoded_headers.saturating_add(1);
                let clock = self.clock_for(header.raw_timestamp);
                vec![self.gap(
                    GapKind::ParseError,
                    provider_affects(&header.provider),
                    1,
                    "event properties were not parsed",
                    clock,
                )]
            }
            SessionMessage::Loss(delta) => {
                let to = self.last_mono_ns.unwrap_or(0);
                let seq = self.alloc_seq();
                vec![super::trace::gap_from_delta(delta, seq, to, to, None)]
            }
        }
    }

    fn on_file(&mut self, event: FileEvent) -> Vec<RawEvent> {
        let FileEvent { header, props } = event;
        // An id the table does not name. `file::classify` is the same check the
        // callback made; an event that got here with a strange id is counted
        // and dropped, not decoded into a guessed kind.
        if file::classify(props.event_id).is_none() {
            self.skipped_file = self.skipped_file.saturating_add(1);
            return Vec::new();
        }
        let clock = self.clock_for(header.raw_timestamp);
        self.last_mono_ns = Some(clock.ts_mono_ns);
        // Kernel-File carries no process `CreateTime` (windows.md §2.2), and the
        // process events arrive as bare headers, so there is no identity to join.
        // `None` leaves `proc` empty and the decoder marks it NA.
        let process = None;
        // The decoder's own tally is not the one the callback filled. Reads and
        // writes never reach this function; they are already in `self.tally`.
        // Create, delete, rename, and close go through the cache. `seq` is a
        // placeholder: the numbers are stamped below, once the gap is known.
        let decoded = self.files.decode(&props, 0, clock, process);
        let mut out = match decoded {
            DecodedFile::Emitted(events) => events,
            DecodedFile::Cached | DecodedFile::Accumulated => Vec::new(),
            DecodedFile::Ignored { .. } => {
                self.skipped_file = self.skipped_file.saturating_add(1);
                Vec::new()
            }
            DecodedFile::Undecodable { .. } => {
                // The decoder refused the event rather than emit one with an
                // empty path. The task card says an unresolvable path is still
                // an event, so build it here with the path marked NA.
                self.undecodable_file(&props, clock, process)
            }
        };
        if matches!(file::classify(props.event_id), Some(FileOp::Close)) {
            self.attach_io(&mut out, &props);
        }
        if let Some(gap) = self.files.eviction_gap(0, clock) {
            out.push(gap);
        }
        for event in &mut out {
            event.seq = self.alloc_seq();
        }
        out
    }

    /// Replace the decoder's empty read/write with the totals the callback
    /// accumulated, on the `FileClose` it just emitted.
    ///
    /// The decoder emits `FileRead` and `FileWrite` only from its own tally,
    /// which the callback never touches, so a Close arrives with neither. The
    /// totals are looked up by the `FileObject` and removed, the way Close
    /// ends the file. `None` counts stay `None` with the tally's NA reason.
    fn attach_io(&mut self, events: &mut Vec<RawEvent>, props: &file::FileProperties) {
        let Some(file_object) = props.file_object else {
            return;
        };
        let Some(tally) = &self.tally else {
            return;
        };
        let Ok(mut tally) = tally.lock() else {
            return;
        };
        let pid = props.pid.unwrap_or(0);
        // A delayed write was stored under PID 4. Prefer the header pid, then
        // the System row, so a cache-manager write is not left behind.
        let totals = tally
            .take(pid, file_object)
            .or_else(|| tally.take(file::PID_SYSTEM, file_object));
        let Some(totals) = totals else {
            return;
        };
        let close_at = events
            .iter()
            .rposition(|event| matches!(event.kind, EventKind::FileClose(_)));
        let Some(close_at) = close_at else {
            return;
        };
        let close = &events[close_at];
        let proc = close.proc.clone();
        let (path, path_missing) = match &close.kind {
            EventKind::FileClose(closed) => (closed.path.clone(), closed.path.is_none()),
            _ => (None, true),
        };
        let mut extra = Vec::new();
        if totals.reads > 0 {
            extra.push(io_event(
                proc.clone(),
                close,
                EventKind::FileRead(aw_core::FileRead::new(
                    Some(file_object),
                    path.clone(),
                    totals.bytes_read,
                    totals.read_offset,
                    None,
                )),
                totals.bytes_read.is_none(),
                totals.read_offset.is_none(),
                path_missing,
                true,
            ));
        }
        if totals.writes > 0 {
            extra.push(io_event(
                proc,
                close,
                EventKind::FileWrite(aw_core::FileWrite::new(
                    Some(file_object),
                    path.clone(),
                    totals.bytes_written,
                    totals.write_offset,
                )),
                totals.bytes_written.is_none(),
                totals.write_offset.is_none(),
                path_missing,
                false,
            ));
        }
        let modified = totals.writes > 0;
        if let EventKind::FileClose(closed) = &mut events[close_at].kind {
            closed.modified = Some(modified);
        }
        events[close_at].field_evidence.remove("modified");
        // `extra` keeps `seq` at 0. The whole batch is numbered once, after this
        // returns, so the read and write land just before the close.
        let insert_at = close_at;
        events.splice(insert_at..insert_at, extra);
    }

    /// An event the cache decoder would not emit, rebuilt with the path absent.
    ///
    /// Dropping it would hide the operation. The kind comes from the same table
    /// the decoder uses, and every field the event did not carry is marked
    /// `NA(collector_unavailable)`.
    fn undecodable_file(
        &self,
        props: &file::FileProperties,
        clock: DecodeClock,
        process: Option<KnownProcess>,
    ) -> Vec<RawEvent> {
        let pid = props.pid.unwrap_or(0);
        let uid = process
            .filter(|known| Some(known.pid) == props.pid)
            .map(|known| known.uid);
        let proc = uid.map(|uid| aw_core::ProcRef {
            uid,
            pid,
            tid: props.tid,
        });
        let kind = match file::classify(props.event_id) {
            Some(FileOp::Create) => EventKind::FileOpen(aw_core::FileOpen::new(
                props.file_object,
                String::new(),
                aw_core::FileAccessMode::Unknown,
                None,
                None,
                props.status,
                None,
                false,
            )),
            Some(FileOp::CreateNew) => {
                EventKind::FileCreate(aw_core::FileCreate::new(String::new(), false))
            }
            Some(FileOp::Delete) => {
                EventKind::FileDelete(aw_core::FileDelete::new(String::new(), None))
            }
            Some(FileOp::Rename) => {
                EventKind::FileRename(aw_core::FileRename::new(String::new(), String::new()))
            }
            Some(FileOp::Close) => {
                EventKind::FileClose(aw_core::FileClose::new(props.file_object, None, None))
            }
            Some(FileOp::Read)
            | Some(FileOp::Write)
            | Some(FileOp::NameCreate)
            | Some(FileOp::NameDelete)
            | None => {
                return Vec::new();
            }
        };
        let proc_known = proc.is_some();
        let mut event = bare_event(clock, proc, kind);
        event.mark_na("path", file::unavailable());
        if props.pid.is_none() {
            event.mark_na("pid", file::unavailable());
        }
        if !proc_known {
            event.mark_na("proc", file::unavailable());
        }
        if matches!(event.kind, EventKind::FileOpen(_)) {
            event.mark_na("access", file::unavailable());
            event.mark_na("created", file::unavailable());
            event.mark_na("truncated", file::unavailable());
            event.mark_na("via", file::unavailable());
            if props.status.is_none() {
                event.mark_na("result", file::unavailable());
            }
        }
        if matches!(event.kind, EventKind::FileClose(_)) {
            event.mark_na("modified", file::unavailable());
        }
        if matches!(event.kind, EventKind::FileDelete(_)) {
            event.mark_na("is_dir", file::unavailable());
        }
        if matches!(event.kind, EventKind::FileCreate(_)) {
            event.mark_na("is_dir", file::unavailable());
        }
        if matches!(event.kind, EventKind::FileRename(_)) {
            event.mark_na("from", file::unavailable());
            event.mark_na("to", file::unavailable());
        }
        vec![event]
    }

    fn clock_for(&self, raw_timestamp: i64) -> DecodeClock {
        match self.session.stamp(raw_timestamp) {
            Some(EtwStamp {
                ts_mono_ns,
                ts_wall_ns,
            }) => DecodeClock {
                ts_mono_ns,
                ts_wall_ns,
            },
            None => DecodeClock {
                ts_mono_ns: self.last_mono_ns.unwrap_or(0),
                ts_wall_ns: None,
            },
        }
    }

    fn alloc_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }

    fn gap(
        &mut self,
        kind: GapKind,
        affects: &str,
        count: u64,
        detail: &str,
        clock: DecodeClock,
    ) -> RawEvent {
        let gap = Gap::new(
            Source::new(SOURCE_CONSUMER),
            kind,
            vec![affects.to_owned()],
            clock.ts_mono_ns,
            clock.ts_mono_ns,
            Some(count),
            Some(detail.to_owned()),
        );
        let mut event = bare_event(clock, None, EventKind::Gap(gap));
        event.seq = self.alloc_seq();
        event
    }
}

/// Which event class a header belongs to, for the gap's `affects`.
fn provider_affects(provider: &super::trace::ProviderId) -> &'static str {
    let guid = format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        provider.data1,
        provider.data2,
        provider.data3,
        provider.data4[0],
        provider.data4[1],
        provider.data4[2],
        provider.data4[3],
        provider.data4[4],
        provider.data4[5],
        provider.data4[6],
        provider.data4[7],
    );
    match session::classify_provider(&guid) {
        session::ProviderClass::P1 if guid.eq_ignore_ascii_case(session::KERNEL_PROCESS_GUID) => {
            "proc"
        }
        session::ProviderClass::P1 if guid.eq_ignore_ascii_case(session::DNS_CLIENT_GUID) => "dns",
        session::ProviderClass::KernelFile => "file",
        _ => "net",
    }
}

fn io_event(
    proc: Option<aw_core::ProcRef>,
    close: &RawEvent,
    kind: EventKind,
    bytes_missing: bool,
    offset_missing: bool,
    path_missing: bool,
    has_via: bool,
) -> RawEvent {
    // The wall time is copied off the Close, which already carries the NA mark
    // when the clock could not name one. Re-deriving it here would disagree.
    let clock = DecodeClock {
        ts_mono_ns: close.ts_mono_ns,
        ts_wall_ns: if close.field_evidence.contains_key("ts_wall_ns") {
            None
        } else {
            Some(close.ts_wall_ns)
        },
    };
    let mut event = bare_event(clock, proc, kind);
    // `None` is "not observed". The tally leaves the sum at `None` when no
    // event in the row carried `IOSize`; writing `0` would say nothing was read.
    if bytes_missing {
        event.mark_na("bytes", NaReason::CollectorUnavailable);
    }
    if offset_missing {
        event.mark_na("offset", NaReason::CollectorUnavailable);
    }
    if path_missing {
        event.mark_na("path", NaReason::CollectorUnavailable);
    }
    if has_via {
        event.mark_na("via", NaReason::CollectorUnavailable);
    }
    let _ = event.check();
    event
}

fn bare_event(clock: DecodeClock, proc: Option<aw_core::ProcRef>, kind: EventKind) -> RawEvent {
    let wall_known = clock.ts_wall_ns.is_some();
    let proc_known = proc.is_some();
    let mut event = RawEvent {
        v: aw_core::SCHEMA_VERSION,
        seq: 0,
        ts_mono_ns: clock.ts_mono_ns,
        ts_wall_ns: clock.ts_wall_ns.unwrap_or(0),
        session_id: None,
        proc,
        source: file::source(),
        evidence: Evidence::E1,
        field_evidence: std::collections::BTreeMap::new(),
        kind,
    };
    if !wall_known {
        event.mark_na("ts_wall_ns", NaReason::CollectorUnavailable);
    }
    if !proc_known {
        event.mark_na("proc", NaReason::CollectorUnavailable);
    }
    let _ = event.check();
    event
}
