//! eslogger file lines → file events.
//!
//! Paths follow macos.md §1.1. Every one of them is still marked
//! 【待验证 SPIKE-03】, so a path is read only when the JSON object actually
//! contains it. A missing path becomes `None` plus `NA(collector_unavailable)`.
//! A wrong JSON type is treated as missing, not as a guess. Unknown keys are
//! ignored: eslogger's format is not stable (RISK-03).
//!
//! | eslogger event | EventKind |
//! |---|---|
//! | `open` | `FileOpen`. `fflag` becomes the read/write intent. |
//! | `close` | `FileClose`. `modified = true` also yields a `FileWrite` with no byte count. |
//! | `create` | `FileCreate` |
//! | `unlink` | `FileDelete` |
//! | `rename` | `FileRename` |
//! | `truncate` | `FileWrite` with no byte count |
//! | `mmap` | `FileOpen` with `via = mmap`, only when the caller subscribed it |
//!
//! `write` is not decoded. The default subscription uses `close.modified`
//! instead, and a line that still arrives is a parse gap rather than a guessed
//! write. Byte counts are never filled in: macOS has no read event and
//! `fs_usage` is out of scope, so `bytes` stays `None` and is marked
//! `NA(es_no_read_event)`. A file size is not used as a stand-in.

use aw_core::{
    EventKind, Evidence, FileAccessMode, FileClose, FileCreate, FileDelete, FileOpen, FileRename,
    FileWrite, Gap, GapKind, IoVia, NaReason, ProcRef, RawEvent, RawEventParts, Source,
};

use super::decode::{es_version, pointer, string_at, AuditToken, EsEvent, LineDecoder};

/// `macos.eslogger/<probe>`. Probe names match the eslogger event.
pub const SOURCE_PREFIX: &str = "macos.eslogger";

/// Why `bytes` / `bytes_read` / `reads` cannot be filled from an eslogger line.
///
/// CAP-FILE-02: Endpoint Security has no read event. The same reason covers a
/// `FileWrite` synthesized from `close.modified` or `truncate`, because those
/// events also carry no byte count and this task must not estimate one.
pub const BYTES_NA: NaReason = NaReason::EsNoReadEvent;

/// File event names this decoder understands.
pub const FILE_EVENTS: [&str; 7] = [
    "open", "close", "create", "unlink", "rename", "truncate", "mmap",
];

/// Which file events the caller asked eslogger to emit.
///
/// `write` is absent on purpose. `mmap` is off unless the caller opts in.
/// `open` can be turned off after the CPU budget is exceeded (P2-MAC-02);
/// the other four stay on, because `close.modified` is what still reports a
/// write once `open` is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSubscription {
    /// `open`. Default on. Cleared by [`crate::eslogger::budget::OpenBudget`].
    pub open: bool,
    /// `close`, including the extra `FileWrite` when `modified` is true.
    pub close: bool,
    /// `create`.
    pub create: bool,
    /// `unlink`.
    pub unlink: bool,
    /// `rename`.
    pub rename: bool,
    /// `truncate`, mapped to a `FileWrite` with no byte count.
    pub truncate: bool,
    /// `mmap`. Optional. Default off.
    pub mmap: bool,
}

impl FileSubscription {
    /// Task default: `open`, `close`, `create`, `unlink`, `rename`, `truncate`.
    /// No `write`. No `mmap`.
    pub const fn macos_default() -> Self {
        Self {
            open: true,
            close: true,
            create: true,
            unlink: true,
            rename: true,
            truncate: true,
            mmap: false,
        }
    }

    /// What remains after `open` is dropped for CPU: `close`, `create`,
    /// `unlink`, `rename`. `truncate` stays too — it is a write signal, not an
    /// open — and `mmap` keeps whatever the caller had set.
    pub const fn without_open(self) -> Self {
        Self {
            open: false,
            ..self
        }
    }

    /// eslogger argv for this set, in a stable order.
    ///
    /// Empty means "subscribe to nothing". The caller must not spawn eslogger
    /// with an empty list; that is a configuration, not a guess this function
    /// fills in.
    pub fn eslogger_args(self) -> Vec<&'static str> {
        let mut args = Vec::with_capacity(7);
        if self.open {
            args.push("open");
        }
        if self.close {
            args.push("close");
        }
        if self.create {
            args.push("create");
        }
        if self.unlink {
            args.push("unlink");
        }
        if self.rename {
            args.push("rename");
        }
        if self.truncate {
            args.push("truncate");
        }
        if self.mmap {
            args.push("mmap");
        }
        args
    }

    /// `true` when `name` is one of the events this set asked for.
    pub fn accepts(self, name: &str) -> bool {
        match name {
            "open" => self.open,
            "close" => self.close,
            "create" => self.create,
            "unlink" => self.unlink,
            "rename" => self.rename,
            "truncate" => self.truncate,
            "mmap" => self.mmap,
            _ => false,
        }
    }
}

impl Default for FileSubscription {
    fn default() -> Self {
        Self::macos_default()
    }
}

/// How eslogger's `open.fflag` was read.
///
/// The numeric value is an `open(2)` flag word. SPIKE-03 has not published a
/// sample, so only the POSIX read/write bits are consulted
/// (`O_ACCMODE = 0b11`, `O_RDONLY = 0`, `O_WRONLY = 1`, `O_RDWR = 2`).
/// `O_EXEC` / `O_SEARCH` differ between Darwin releases and are not guessed:
/// a word that only says "not read and not write" stays [`FileAccessMode::Unknown`]
/// and the field is marked `NA(collector_unavailable)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenIntent {
    /// Access the flag word supports. `Unknown` when the word was absent,
    /// not an integer, or named no read/write bit this decoder understands.
    pub access: FileAccessMode,
    /// `true` when the word was present and was a non-negative integer.
    pub flag_present: bool,
}

impl OpenIntent {
    /// `O_ACCMODE`.
    const ACCMODE: i64 = 0b11;
    /// `O_WRONLY`.
    const WRONLY: i64 = 1;
    /// `O_RDWR`.
    const RDWR: i64 = 2;

    /// Decode `fflag`. `None`, a negative word, or a word whose low bits are
    /// outside the POSIX read/write set yields [`FileAccessMode::Unknown`].
    ///
    /// `O_RDONLY` is `0`. That value is a real read only when the key was
    /// present and non-negative. A missing key must not take the same path.
    pub fn from_fflag(fflag: Option<i64>) -> Self {
        let Some(word) = fflag else {
            return Self {
                access: FileAccessMode::Unknown,
                flag_present: false,
            };
        };
        if word < 0 {
            return Self {
                access: FileAccessMode::Unknown,
                flag_present: false,
            };
        }
        let access = match word & Self::ACCMODE {
            Self::WRONLY => FileAccessMode::Write,
            Self::RDWR => FileAccessMode::ReadWrite,
            0 => FileAccessMode::Read,
            _ => FileAccessMode::Unknown,
        };
        Self {
            access,
            flag_present: true,
        }
    }

    /// Read-side open: `Read` or `ReadWrite`.
    ///
    /// These are the events P2-MAC-02 marks `bytes_read` and `reads` as
    /// `NA(es_no_read_event)`. A write-only open does not claim a read.
    /// `Unknown` does not either: marking it would invent a read we did not see.
    pub const fn is_read(self) -> bool {
        matches!(
            self.access,
            FileAccessMode::Read | FileAccessMode::ReadWrite
        )
    }
}

impl LineDecoder {
    /// Decode one file line.
    ///
    /// Sequence holes are reported by the caller ([`LineDecoder::observe_loss`])
    /// before this runs, so a file line and a process line share one counter.
    /// An event this `subscription` does not include produces no events: the
    /// line was not asked for. A known event with a missing path produces one
    /// `Gap{parse_error}` — the line is not dropped and no path is invented.
    ///
    /// # Errors
    ///
    /// Never `Err`. A bad line is a parse gap inside `Ok`. See
    /// [`LineDecoder::push`].
    pub fn push_file(
        &mut self,
        value: &serde_json::Value,
        event_name: &str,
        subscription: FileSubscription,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
    ) -> Result<Vec<EsEvent>, super::decode::DecodeError> {
        Ok(self.decode_file(value, event_name, subscription, ts_mono_ns, ts_wall_ns))
    }

    /// File-line body of [`Self::push_file`]. Crate-visible so `push_inner` can
    /// share the sequence counter without a second `Result` layer.
    pub(super) fn decode_file(
        &mut self,
        value: &serde_json::Value,
        event_name: &str,
        subscription: FileSubscription,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
    ) -> Vec<EsEvent> {
        if !subscription.accepts(event_name) {
            return Vec::new();
        }
        let pid = AuditToken::from_value(value.pointer("/process/audit_token")).pid;
        let version = es_version(value);
        match event_name {
            "open" => self.decode_open(value, pid, version, false, ts_mono_ns, ts_wall_ns),
            "mmap" => self.decode_open(value, pid, version, true, ts_mono_ns, ts_wall_ns),
            "close" => self.decode_close(value, pid, version, ts_mono_ns, ts_wall_ns),
            "create" => self.decode_create(value, pid, version, ts_mono_ns, ts_wall_ns),
            "unlink" => self.decode_unlink(value, pid, version, ts_mono_ns, ts_wall_ns),
            "rename" => self.decode_rename(value, pid, version, ts_mono_ns, ts_wall_ns),
            "truncate" => self.decode_truncate(value, pid, version, ts_mono_ns, ts_wall_ns),
            _ => Vec::new(),
        }
    }

    fn decode_open(
        &mut self,
        value: &serde_json::Value,
        pid: Option<u32>,
        es_version: Option<i64>,
        mmap: bool,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
    ) -> Vec<EsEvent> {
        // macos.md §1.1. `mmap` uses `event.mmap.source.path`; protection is
        // named but not given a key, so it is not read.
        let (probe, path) = if mmap {
            (
                "mmap",
                string_at(value, &["event", "mmap", "source", "path"]),
            )
        } else {
            ("open", string_at(value, &["event", "open", "file", "path"]))
        };
        let Some(path) = path else {
            return vec![self.file_parse_gap(
                ts_mono_ns,
                ts_wall_ns,
                probe,
                &format!("eslogger `{probe}` has no path"),
            )];
        };
        // mmap protection is named by macos.md and not given a key. Marking the
        // open as Read would claim a read that was not observed.
        let intent = if mmap {
            OpenIntent {
                access: FileAccessMode::Unknown,
                flag_present: false,
            }
        } else {
            OpenIntent::from_fflag(fflag_at(value))
        };
        let mut missing = vec!["handle", "created", "truncated", "result"];
        if pid.is_none() {
            missing.push("proc");
        }
        if es_version.is_none() {
            missing.push("es_version");
        }
        if mmap || !intent.flag_present {
            missing.push("access");
        }
        // A read open cannot report how many bytes were read. `bytes_read` and
        // `reads` are the names P2-MAC-02 requires. A write-only open did not
        // read, so it does not carry those marks. mmap bytes are a different
        // reason: the mapping is visible, the traffic is not.
        if mmap || intent.is_read() {
            missing.push("bytes_read");
            missing.push("reads");
        }
        let via = if mmap { Some(IoVia::Mmap) } else { None };
        let mmap_bytes = [
            ("bytes", NaReason::MmapNotObservable),
            ("bytes_read", NaReason::MmapNotObservable),
            ("reads", NaReason::MmapNotObservable),
        ];
        let byte_fields: &[(&str, NaReason)] = if mmap {
            &mmap_bytes
        } else if intent.is_read() {
            BYTES_NA_FIELDS
        } else {
            &[]
        };
        let open = FileOpen::new(None, path, intent.access, None, None, None, via, false);
        vec![self.file_event(
            ts_mono_ns,
            ts_wall_ns,
            probe,
            pid,
            es_version,
            EventKind::FileOpen(open),
            &missing,
            byte_fields,
        )]
    }

    fn decode_close(
        &mut self,
        value: &serde_json::Value,
        pid: Option<u32>,
        es_version: Option<i64>,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
    ) -> Vec<EsEvent> {
        let path = string_at(value, &["event", "close", "target", "path"]);
        let modified = bool_at(value, &["event", "close", "modified"]);
        if path.is_none() && modified.is_none() {
            return vec![self.file_parse_gap(
                ts_mono_ns,
                ts_wall_ns,
                "close",
                "eslogger `close` has no path and no modified flag",
            )];
        }
        let mut missing = vec!["handle"];
        if path.is_none() {
            missing.push("path");
        }
        if modified.is_none() {
            missing.push("modified");
        }
        if pid.is_none() {
            missing.push("proc");
        }
        if es_version.is_none() {
            missing.push("es_version");
        }
        let close = FileClose::new(None, path.clone(), modified);
        let mut out = vec![self.file_event(
            ts_mono_ns,
            ts_wall_ns,
            "close",
            pid,
            es_version,
            EventKind::FileClose(close),
            &missing,
            &[],
        )];
        // modified = true is the write signal. The byte count is not on this
        // event. Some(0) would say the write was empty, which was not observed.
        if modified == Some(true) {
            let write_missing = ["bytes", "handle", "offset"];
            let write = FileWrite::new(None, path, None, None);
            out.push(self.file_event(
                ts_mono_ns,
                ts_wall_ns,
                "close",
                pid,
                es_version,
                EventKind::FileWrite(write),
                &write_missing,
                &[("bytes", BYTES_NA)],
            ));
        }
        out
    }

    fn decode_create(
        &mut self,
        value: &serde_json::Value,
        pid: Option<u32>,
        es_version: Option<i64>,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
    ) -> Vec<EsEvent> {
        // macos.md names `event.create.destination` and does not say whether
        // that node is the path string or an object with `.path`. Both shapes
        // occur in ES JSON depending on version, so both are accepted. A third
        // shape is a missing path, not a guessed one.
        let path = destination_path(value, &["event", "create", "destination"]);
        let Some(path) = path else {
            return vec![self.file_parse_gap(
                ts_mono_ns,
                ts_wall_ns,
                "create",
                "eslogger `create` has no destination path",
            )];
        };
        // `destination_type` is not in the path table. `is_dir` stays false
        // only when a directory marker is present and says so; otherwise the
        // field is marked NA and the struct keeps `false` because `FileCreate`
        // stores `is_dir` as `bool` (aw-core, not changed here).
        let is_dir = destination_is_dir(value, &["event", "create", "destination"]);
        let mut missing = Vec::new();
        if is_dir.is_none() {
            missing.push("is_dir");
        }
        if pid.is_none() {
            missing.push("proc");
        }
        if es_version.is_none() {
            missing.push("es_version");
        }
        let create = FileCreate::new(path, is_dir.unwrap_or(false));
        vec![self.file_event(
            ts_mono_ns,
            ts_wall_ns,
            "create",
            pid,
            es_version,
            EventKind::FileCreate(create),
            &missing,
            &[],
        )]
    }

    fn decode_unlink(
        &mut self,
        value: &serde_json::Value,
        pid: Option<u32>,
        es_version: Option<i64>,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
    ) -> Vec<EsEvent> {
        let path = string_at(value, &["event", "unlink", "target", "path"]);
        let Some(path) = path else {
            return vec![self.file_parse_gap(
                ts_mono_ns,
                ts_wall_ns,
                "unlink",
                "eslogger `unlink` has no path",
            )];
        };
        let mut missing = vec!["is_dir"];
        if pid.is_none() {
            missing.push("proc");
        }
        if es_version.is_none() {
            missing.push("es_version");
        }
        let delete = FileDelete::new(path, None);
        vec![self.file_event(
            ts_mono_ns,
            ts_wall_ns,
            "unlink",
            pid,
            es_version,
            EventKind::FileDelete(delete),
            &missing,
            &[],
        )]
    }

    fn decode_rename(
        &mut self,
        value: &serde_json::Value,
        pid: Option<u32>,
        es_version: Option<i64>,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
    ) -> Vec<EsEvent> {
        let from = string_at(value, &["event", "rename", "source", "path"]);
        let to = destination_path(value, &["event", "rename", "destination"]);
        let (Some(from), Some(to)) = (from, to) else {
            return vec![self.file_parse_gap(
                ts_mono_ns,
                ts_wall_ns,
                "rename",
                "eslogger `rename` is missing source.path or destination",
            )];
        };
        let mut missing = Vec::new();
        if pid.is_none() {
            missing.push("proc");
        }
        if es_version.is_none() {
            missing.push("es_version");
        }
        let rename = FileRename::new(from, to);
        vec![self.file_event(
            ts_mono_ns,
            ts_wall_ns,
            "rename",
            pid,
            es_version,
            EventKind::FileRename(rename),
            &missing,
            &[],
        )]
    }

    fn decode_truncate(
        &mut self,
        value: &serde_json::Value,
        pid: Option<u32>,
        es_version: Option<i64>,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
    ) -> Vec<EsEvent> {
        let path = string_at(value, &["event", "truncate", "target", "path"]);
        let Some(path) = path else {
            return vec![self.file_parse_gap(
                ts_mono_ns,
                ts_wall_ns,
                "truncate",
                "eslogger `truncate` has no path",
            )];
        };
        // No length on this event. `bytes: None` plus NA. Not `Some(0)`.
        let write = FileWrite::new(None, Some(path), None, None);
        let mut missing = vec!["bytes", "handle", "offset"];
        if pid.is_none() {
            missing.push("proc");
        }
        if es_version.is_none() {
            missing.push("es_version");
        }
        vec![self.file_event(
            ts_mono_ns,
            ts_wall_ns,
            "truncate",
            pid,
            es_version,
            EventKind::FileWrite(write),
            &missing,
            &[("bytes", BYTES_NA)],
        )]
    }

    #[allow(clippy::too_many_arguments)]
    fn file_event(
        &mut self,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
        probe: &str,
        pid: Option<u32>,
        es_version: Option<i64>,
        kind: EventKind,
        missing: &[&str],
        byte_fields: &[(&str, NaReason)],
    ) -> EsEvent {
        let seq = self.alloc_seq();
        let proc = pid.and_then(|pid| {
            super::decode::proc_uid_from_token(pid).map(|uid| ProcRef {
                uid,
                pid,
                tid: None,
            })
        });
        // `FileWrite.bytes` is a required Option. try_new rejects it until NA
        // is recorded, so the mark is applied on the built value and `check`
        // runs after. Building first with the mark missing would drop the line.
        let mut event = RawEvent {
            v: aw_core::SCHEMA_VERSION,
            seq,
            ts_mono_ns,
            ts_wall_ns,
            session_id: None,
            proc,
            source: Source::new(format!("{SOURCE_PREFIX}/{probe}")),
            evidence: Evidence::E1,
            field_evidence: std::collections::BTreeMap::new(),
            kind,
        };
        for (field, reason) in byte_fields {
            event.mark_na(*field, reason.clone());
        }
        for field in missing {
            if !byte_fields.iter().any(|(name, _)| name == field) {
                event.mark_na(*field, NaReason::CollectorUnavailable);
            }
        }
        // FileWrite.bytes is a required Option. check() refuses it unless the
        // NA mark above is in place. A refusal becomes a parse gap; the line
        // is not dropped and the byte count is not back-filled.
        if let Err(err) = event.check() {
            return self.file_parse_gap(
                ts_mono_ns,
                ts_wall_ns,
                probe,
                &format!("file event failed RawEvent::check: {err}"),
            );
        }
        side(Some(event), pid, es_version)
    }

    fn file_parse_gap(
        &mut self,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
        probe: &str,
        detail: &str,
    ) -> EsEvent {
        let seq = self.alloc_seq();
        let gap = Gap::new(
            Source::new(format!("{SOURCE_PREFIX}/{probe}")),
            GapKind::ParseError,
            vec!["file".to_owned()],
            ts_mono_ns,
            ts_mono_ns,
            None,
            Some(detail.to_owned()),
        );
        let event = file_gap_event(seq, ts_mono_ns, ts_wall_ns, gap);
        side(Some(event), None, None)
    }
}

/// Field names whose NA reason is [`BYTES_NA`] rather than `collector_unavailable`.
const BYTES_NA_FIELDS: &[(&str, NaReason)] = &[("bytes_read", BYTES_NA), ("reads", BYTES_NA)];

fn side(event: Option<RawEvent>, subject_pid: Option<u32>, es_version: Option<i64>) -> EsEvent {
    EsEvent {
        event,
        exe: None,
        argv: None,
        cwd: None,
        how: None,
        ppid: None,
        start_time_ns: None,
        es_version,
        responsible: None,
        subject_pid,
        exit_stat: None,
    }
}

fn file_gap_event(seq: u64, ts_mono_ns: u64, ts_wall_ns: i64, gap: Gap) -> RawEvent {
    let source = gap.collector.clone();
    match RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns,
        ts_wall_ns,
        session_id: None,
        proc: None,
        source: source.clone(),
        evidence: Evidence::E1,
        kind: EventKind::Gap(gap),
    }) {
        Ok(event) => event,
        Err(_) => RawEvent {
            v: aw_core::SCHEMA_VERSION,
            seq,
            ts_mono_ns,
            ts_wall_ns,
            session_id: None,
            proc: None,
            source,
            evidence: Evidence::E1,
            field_evidence: std::collections::BTreeMap::new(),
            kind: EventKind::Gap(Gap::new(
                Source::new(format!("{SOURCE_PREFIX}/parse")),
                GapKind::ParseError,
                vec!["file".to_owned()],
                ts_mono_ns,
                ts_mono_ns,
                None,
                Some("file gap event could not be built; the line was not dropped".to_owned()),
            )),
        },
    }
}

/// `event.open.fflag`. Accepts a number. A string of digits is not accepted:
/// coercing it would hide a shape SPIKE-03 has not confirmed.
fn fflag_at(value: &serde_json::Value) -> Option<i64> {
    match pointer(value, &["event", "open", "fflag"])? {
        serde_json::Value::Number(n) => n
            .as_i64()
            .or_else(|| n.as_u64().and_then(|v| i64::try_from(v).ok())),
        _ => None,
    }
}

fn bool_at(value: &serde_json::Value, path: &[&str]) -> Option<bool> {
    match pointer(value, path)? {
        serde_json::Value::Bool(v) => Some(*v),
        _ => None,
    }
}

/// Path at `destination`, which eslogger writes either as a string or as an
/// object with `path` (macos.md names the node, not the shape).
fn destination_path(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    let node = pointer(value, path)?;
    match node {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
        serde_json::Value::Object(_) => match node.get("path")? {
            serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// Directory bit, only when the destination object actually carries one.
///
/// `None` when the marker is absent. Callers must not treat that as `false`.
fn destination_is_dir(value: &serde_json::Value, path: &[&str]) -> Option<bool> {
    let node = pointer(value, path)?;
    let marker = node.get("destination_type").or_else(|| node.get("type"))?;
    match marker {
        serde_json::Value::String(s) => match s.as_str() {
            "dir" | "directory" => Some(true),
            "file" => Some(false),
            _ => None,
        },
        _ => None,
    }
}
