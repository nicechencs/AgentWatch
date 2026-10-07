//! One eslogger JSON object → a process start, a process exit, or a loss.
//!
//! Paths that macos.md §1.1 names (all of them still marked 【待验证 SPIKE-03】):
//!
//! | event | paths read |
//! |---|---|
//! | `exec` | `event.exec.target.executable.path`, `event.exec.args`, `event.exec.cwd.path`, `process.audit_token.pid`, `process.ppid`, `process.responsible_audit_token` |
//! | `fork` | `event.fork.child.audit_token` |
//! | `exit` | `event.exit.stat` |
//!
//! Also read, because the same section requires them and does not give a path:
//! `version` (ES message version; location is not specified, so both a top-level
//! `version` and `event.version` are accepted), `seq_num`, `global_seq_num`,
//! and `process.audit_token` as an object. `pidversion` and the process start
//! time are **not** given a JSON path. They stay absent and are marked
//! `NA(collector_unavailable)`. ProcUid is not hashed here: process-tracking §2
//! says the macOS formula is `pidversion` plus `proc_bsdinfo` start time, and
//! both inputs are waiting on SPIKE-03. Inventing a uid from pid alone would
//! collide on pid reuse.
//!
//! Unknown keys are ignored. A key that is present but the wrong JSON type is
//! treated as missing, not as a guess.

use aw_core::{
    EventKind, Evidence, Gap, GapKind, NaReason, ProcRef, ProcUid, ProcessExit, RawEvent,
    RawEventParts, Source, StartHow,
};
use serde_json::Value;

use super::loss::{LossDetector, SequenceLoss};

/// `macos.eslogger/<probe>`. Probe names match the eslogger event (`exec`, `fork`, `exit`).
pub const SOURCE_PREFIX: &str = "macos.eslogger";

/// Substring the pre-parse filter and this decoder both treat as the event name key.
const EVENT_KEY: &str = "event";

/// Decoded audit token fields the JSON actually carried.
///
/// macos.md names `process.audit_token` and, for a fork, `event.fork.child.audit_token`.
/// It does not list the token's members. Only `pid` is read, because the exec row
/// names `process.audit_token.pid`. `pidversion` is intentionally not read: SPIKE-03
/// has not confirmed the key, and a wrong key would look like a real version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditToken {
    /// `audit_token.pid` when that key is a non-negative integer fitting in `u32`.
    pub pid: Option<u32>,
}

impl AuditToken {
    /// Read `pid` from an audit-token object. Any other shape yields `pid: None`.
    ///
    /// `pidversion` is not read. SPIKE-03 has not confirmed that key.
    pub fn from_value(value: Option<&Value>) -> Self {
        let pid = value.and_then(|token| u32_at(token, &["pid"]));
        Self { pid }
    }
}

/// `responsible_audit_token`, kept for P1-MAC-03's I-level attribution.
///
/// The task says to retain it. The schema's `ProcessStart` has no field for it,
/// and this crate must not change `aw-core`. The token is therefore a side value
/// on [`EsEvent`], not a field of the [`RawEvent`].
#[derive(Clone, PartialEq, Eq)]
pub struct ResponsibleToken {
    /// Raw JSON object (or other value) as eslogger wrote it.
    ///
    /// Not interpreted. Debug must not dump it: a token can carry an audit uid.
    pub raw: Value,
}

impl std::fmt::Debug for ResponsibleToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResponsibleToken(<retained>)")
    }
}

/// One decoded process line, plus fields [`RawEvent`] cannot store honestly.
///
/// `ProcessStart::ppid` and `ProcessStart::start_time_ns` are plain integers in
/// `aw-core`, so a missing observation cannot be `None` there. Writing `0`
/// would claim a real ppid or a real timestamp. Those two stay on this struct
/// as `Option`, and `field_evidence` on `event` still records
/// `NA(collector_unavailable)` when they are `None`.
///
/// `proc.uid` is the same problem: process-tracking §2's macOS formula needs
/// `pidversion` and a start time, and neither has a confirmed JSON path
/// (SPIKE-03). A pid-only hash would collide after pid reuse. When the uid
/// cannot be built, `event.proc` is `None` and `subject_pid` carries the pid
/// that *was* observed.
#[derive(Debug, Clone, PartialEq)]
pub struct EsEvent {
    /// Process exit, a loss gap, or a parse gap.
    ///
    /// `None` for `exec` and `fork`. Those need `ppid` and `start_time_ns`, and
    /// `aw-core` stores both as bare integers, so a missing reading cannot be
    /// represented without writing `0`. The mapped fields live on this struct
    /// instead. See the module note at the bottom of the file.
    pub event: Option<RawEvent>,
    /// Executable path for an exec. Fork has no path in macos.md.
    pub exe: Option<String>,
    /// argv for an exec, still raw (redaction is the pipeline's job).
    pub argv: Option<Vec<String>>,
    /// cwd for an exec.
    pub cwd: Option<String>,
    /// `Exec` or `Fork` when this line is a process start. `None` for exit and gaps.
    pub how: Option<StartHow>,
    /// `process.ppid` for an exec, or the forking process's pid for a fork.
    /// `None` when that path was absent — not `Some(0)`.
    pub ppid: Option<u32>,
    /// Process start time in nanoseconds. Always `None` until SPIKE-03 names a path.
    pub start_time_ns: Option<i64>,
    /// ES message `version`, if either candidate path had an integer.
    ///
    /// `None` means the field was absent. The same fact is on
    /// `event.field_evidence["es_version"]` as `NA(collector_unavailable)`.
    pub es_version: Option<i64>,
    /// Retained responsible token. `None` when the key was absent (also marked NA
    /// on a process start).
    pub responsible: Option<ResponsibleToken>,
    /// Subject pid taken from the audit token, when present.
    ///
    /// Copied onto `event.proc.pid` only when a [`ProcUid`] could also be built.
    /// Today that never happens (no pidversion path), so this is the only place
    /// the pid is kept.
    pub subject_pid: Option<u32>,
    /// `event.exit.stat` as eslogger wrote it, uninterpreted.
    ///
    /// macos.md names the path and not the encoding. It is not split into
    /// `exit_code` / `signal`. `None` when the key was absent.
    pub exit_stat: Option<i64>,
}

/// Stateful decoder: sequence counters survive across lines.
#[derive(Debug, Clone, Default)]
pub struct LineDecoder {
    loss: LossDetector,
    /// Next `RawEvent::seq` this decoder will stamp. Not eslogger's `seq_num`.
    next_seq: u64,
}

impl LineDecoder {
    /// Decoder with both counters unset and `seq` starting at 1.
    ///
    /// Sequence 0 is reserved by other collectors for a synthesized gap that has
    /// no clock. eslogger lines are real observations, so they start at 1.
    pub fn new() -> Self {
        Self {
            loss: LossDetector::new(),
            next_seq: 1,
        }
    }

    /// Decode `line`.
    ///
    /// On success the `Vec` holds the process event and, before it, one
    /// [`EventKind::Gap`] per counter that jumped (`seq_num`, then
    /// `global_seq_num`). An unparsable line or an event name other than
    /// `exec` / `fork` / `exit` becomes a single `Gap{parse_error}` — the line
    /// is not dropped.
    ///
    /// `ts_mono_ns` and `ts_wall_ns` are the daemon clock, supplied by the
    /// caller. eslogger's `mach_time` / `time` conversion is 【待验证 SPIKE-03】
    /// (event-schema §4) and is not attempted.
    ///
    /// # Errors
    ///
    /// This function does not return `Err`. A bad line is a parse gap inside
    /// the `Ok` value, because a collector must not discard an unreadable line
    /// by failing the whole read loop. The `Result` is kept so a later macOS
    /// caller can still use `?` if the sink rejects the events.
    pub fn push(&mut self, line: &str, ts_mono_ns: u64, ts_wall_ns: i64) -> Result<Vec<EsEvent>, DecodeError> {
        Ok(self.push_inner(line, ts_mono_ns, ts_wall_ns))
    }

    fn push_inner(&mut self, line: &str, ts_mono_ns: u64, ts_wall_ns: i64) -> Vec<EsEvent> {
        let value: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => {
                return vec![self.parse_gap(
                    ts_mono_ns,
                    ts_wall_ns,
                    "eslogger line is not a JSON object",
                )];
            }
        };
        if !value.is_object() {
            return vec![self.parse_gap(
                ts_mono_ns,
                ts_wall_ns,
                "eslogger line is not a JSON object",
            )];
        }

        let event_name = string_at(&value, &[EVENT_KEY])
            .or_else(|| string_at(&value, &["event_type"]));
        let seq_num = u64_at(&value, &["seq_num"]);
        let global = u64_at(&value, &["global_seq_num"]);

        let mut out = Vec::new();
        if let Some(name) = event_name.as_deref() {
            if let Some(seq) = seq_num {
                if let Some(loss) = self.loss.observe_seq(name, seq) {
                    out.push(self.loss_gap(ts_mono_ns, ts_wall_ns, &loss));
                }
            }
        }
        if let Some(seq) = global {
            if let Some(loss) = self.loss.observe_global(seq) {
                out.push(self.loss_gap(ts_mono_ns, ts_wall_ns, &loss));
            }
        }

        let built = match event_name.as_deref() {
            Some("exec") => self.decode_exec(&value, ts_mono_ns, ts_wall_ns),
            Some("fork") => self.decode_fork(&value, ts_mono_ns, ts_wall_ns),
            Some("exit") => self.decode_exit(&value, ts_mono_ns, ts_wall_ns),
            Some(other) => self.parse_gap(
                ts_mono_ns,
                ts_wall_ns,
                &format!("eslogger event `{other}` is not a P1 process event"),
            ),
            None => self.parse_gap(
                ts_mono_ns,
                ts_wall_ns,
                "eslogger line has no event name",
            ),
        };
        out.push(built);
        out
    }

    fn decode_exec(&mut self, value: &Value, ts_mono_ns: u64, ts_wall_ns: i64) -> EsEvent {
        // macos.md §1.1 exec paths. Every one is 【待验证 SPIKE-03】.
        let exe = string_at(value, &["event", "exec", "target", "executable", "path"]);
        let cwd = string_at(value, &["event", "exec", "cwd", "path"]);
        let argv = string_list_at(value, &["event", "exec", "args"]);
        let ppid = u32_at(value, &["process", "ppid"]);
        let pid = AuditToken::from_value(value.pointer("/process/audit_token")).pid;
        let responsible = value
            .pointer("/process/responsible_audit_token")
            .filter(|v| !v.is_null())
            .cloned()
            .map(|raw| ResponsibleToken { raw });
        let es_version = es_version(value);

        let mut missing = Vec::new();
        if exe.is_none() {
            missing.push("exe");
        }
        if cwd.is_none() {
            missing.push("cwd");
        }
        if argv.is_none() {
            missing.push("argv");
        }
        if ppid.is_none() {
            missing.push("ppid");
        }
        if pid.is_none() {
            missing.push("proc");
        }
        if responsible.is_none() {
            missing.push("responsible_audit_token");
        }
        if es_version.is_none() {
            missing.push("es_version");
        }
        // Not in the JSON path table. Always unavailable until SPIKE-03.
        missing.push("pidversion");
        missing.push("start_time_ns");
        missing.push("parent_uid");
        missing.push("user");
        missing.push("signer");

        // start_time_ns has no path. ProcessStart requires an i64, so the RawEvent
        // carries 0 and field_evidence marks it NA. EsEvent::start_time_ns stays
        // None. A missing ppid cannot use that same trick: 0 would be a real pid
        // (launchd). That line has no ProcessStart.
        self.finish_start(
            ts_mono_ns,
            ts_wall_ns,
            "exec",
            pid,
            ppid,
            exe.clone(),
            argv.clone(),
            cwd.clone(),
            StartHow::Exec,
            es_version,
            responsible,
            &missing,
        )
    }

    fn decode_fork(&mut self, value: &Value, ts_mono_ns: u64, ts_wall_ns: i64) -> EsEvent {
        // macos.md names only `event.fork.child.audit_token`. The child pid is
        // read as `.pid` on that token, matching the exec token shape. Parent
        // pid is `process.audit_token.pid` (the forking process). ppid of the
        // child is that parent pid when we have it; the path `process.ppid` is
        // the forking process's own parent, not the child's, so it is not used
        // as the child's ppid.
        let child_pid = AuditToken::from_value(value.pointer("/event/fork/child/audit_token")).pid;
        let parent_pid = AuditToken::from_value(value.pointer("/process/audit_token")).pid;
        let es_version = es_version(value);
        let responsible = value
            .pointer("/process/responsible_audit_token")
            .filter(|v| !v.is_null())
            .cloned()
            .map(|raw| ResponsibleToken { raw });

        let mut missing = vec![
            "exe",
            "argv",
            "cwd",
            "pidversion",
            "start_time_ns",
            "parent_uid",
            "user",
            "signer",
        ];
        if child_pid.is_none() {
            missing.push("proc");
        }
        if parent_pid.is_none() {
            missing.push("ppid");
        }
        if responsible.is_none() {
            missing.push("responsible_audit_token");
        }
        if es_version.is_none() {
            missing.push("es_version");
        }

        self.finish_start(
            ts_mono_ns,
            ts_wall_ns,
            "fork",
            child_pid,
            parent_pid,
            None,
            None,
            None,
            StartHow::Fork,
            es_version,
            responsible,
            &missing,
        )
    }

    fn decode_exit(&mut self, value: &Value, ts_mono_ns: u64, ts_wall_ns: i64) -> EsEvent {
        // macos.md names `event.exit.stat` and nothing else. `stat` is a
        // wait(2) status. The schema wants `exit_code` and `signal` separately.
        // SPIKE-03 has not said whether `stat` is already an exit code, a wait
        // status, or something else. It is therefore NOT split into a code and
        // a signal. Both schema fields stay None and are marked NA. The raw
        // integer, when present, is kept only so a later spike can see that the
        // field existed — it is not written into ProcessExit.
        let stat = value.pointer("/event/exit/stat").filter(|v| !v.is_null());
        let pid = AuditToken::from_value(value.pointer("/process/audit_token")).pid;
        let es_version = es_version(value);

        let mut missing = vec!["exit_code", "signal"];
        if pid.is_none() {
            missing.push("proc");
        }
        if es_version.is_none() {
            missing.push("es_version");
        }
        if stat.is_none() {
            missing.push("exit.stat");
        }

        let stat = match stat {
            Some(Value::Number(n)) => n.as_i64(),
            _ => None,
        };
        let exit = ProcessExit::new(None, None);
        self.finish_event(
            ts_mono_ns,
            ts_wall_ns,
            "exit",
            pid,
            None,
            None,
            es_version,
            None,
            stat,
            EventKind::ProcessExit(exit),
            &missing,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_start(
        &mut self,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
        probe: &str,
        pid: Option<u32>,
        ppid: Option<u32>,
        exe: Option<String>,
        argv: Option<Vec<String>>,
        cwd: Option<String>,
        how: StartHow,
        es_version: Option<i64>,
        responsible: Option<ResponsibleToken>,
        missing: &[&str],
    ) -> EsEvent {
        // start_time_ns has no JSON path (SPIKE-03). ProcessStart stores it as
        // i64, so the struct carries 0 and field_evidence marks the field NA.
        // EsEvent::start_time_ns stays None: that is the value callers must use.
        // A missing ppid is not given the same treatment — 0 is a real pid — so
        // that line is a gap plus the EsEvent fields, not a ProcessStart.
        let event = if let Some(ppid_value) = ppid {
            let start = aw_core::ProcessStart::new(
                ppid_value,
                None,
                0,
                exe.clone(),
                argv.clone()
                    .map(|args| args.into_iter().map(aw_core::Redacted::new).collect()),
                cwd.clone(),
                None,
                how,
                None,
                None,
            );
            let mut event = match self.raw_event(
                ts_mono_ns,
                ts_wall_ns,
                probe,
                pid,
                EventKind::ProcessStart(start),
            ) {
                Some(event) => event,
                None => self.na_gap(ts_mono_ns, ts_wall_ns, probe, missing),
            };
            for field in missing {
                event.mark_na(*field, NaReason::CollectorUnavailable);
            }
            event
        } else {
            self.na_gap(ts_mono_ns, ts_wall_ns, probe, missing)
        };
        EsEvent {
            event: Some(event),
            exe,
            argv,
            cwd,
            how: Some(how),
            ppid,
            start_time_ns: None,
            es_version,
            responsible,
            subject_pid: pid,
            exit_stat: None,
        }
    }

    fn raw_event(
        &mut self,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
        probe: &str,
        pid: Option<u32>,
        kind: EventKind,
    ) -> Option<RawEvent> {
        let seq = self.alloc_seq();
        let proc = pid.and_then(|pid| {
            proc_uid_from_token(pid).map(|uid| ProcRef {
                uid,
                pid,
                tid: None,
            })
        });
        match RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns,
            ts_wall_ns,
            session_id: None,
            proc,
            source: Source::new(format!("{SOURCE_PREFIX}/{probe}")),
            evidence: Evidence::E1,
            kind,
        }) {
            Ok(event) => Some(event),
            Err(_) => {
                // The sequence number was not published. Give it back so the
                // fallback gap does not leave a hole that looks like a loss.
                self.next_seq = seq;
                None
            }
        }
    }

    fn na_gap(
        &mut self,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
        probe: &str,
        missing: &[&str],
    ) -> RawEvent {
        let seq = self.alloc_seq();
        let gap = Gap::new(
            Source::new(format!("{SOURCE_PREFIX}/{probe}")),
            GapKind::ParseError,
            vec!["proc".to_owned()],
            ts_mono_ns,
            ts_mono_ns,
            None,
            Some(
                "process start kept on EsEvent; aw-core ProcessStart cannot store a missing ppid or start_time_ns without 0"
                    .to_owned(),
            ),
        );
        let mut event = gap_event(seq, ts_mono_ns, ts_wall_ns, gap);
        for field in missing {
            event.mark_na(*field, NaReason::CollectorUnavailable);
        }
        event
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_event(
        &mut self,
        ts_mono_ns: u64,
        ts_wall_ns: i64,
        probe: &str,
        pid: Option<u32>,
        ppid: Option<u32>,
        start_time_ns: Option<i64>,
        es_version: Option<i64>,
        responsible: Option<ResponsibleToken>,
        exit_stat: Option<i64>,
        kind: EventKind,
        missing: &[&str],
    ) -> EsEvent {
        let seq = self.alloc_seq();
        // No ProcUid until pidversion and start time have a confirmed path.
        // The `Some` arm is what a later spike fills; today `proc_uid_from_token`
        // returns None so a pid-only hash cannot collide after reuse.
        let proc = pid.and_then(|pid| {
            proc_uid_from_token(pid).map(|uid| ProcRef {
                uid,
                pid,
                tid: None,
            })
        });
        let mut event = match RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns,
            ts_wall_ns,
            session_id: None,
            proc,
            source: Source::new(format!("{SOURCE_PREFIX}/{probe}")),
            evidence: Evidence::E1,
            kind,
        }) {
            Ok(event) => event,
            // Process events have no schema-required Option. A failure here means
            // the schema gained one; still surface a parse gap rather than drop.
            Err(_) => {
                return self.parse_gap(
                    ts_mono_ns,
                    ts_wall_ns,
                    "process event failed RawEvent::try_new",
                );
            }
        };
        for field in missing {
            event.mark_na(*field, NaReason::CollectorUnavailable);
        }
        EsEvent {
            event: Some(event),
            exe: None,
            argv: None,
            cwd: None,
            how: None,
            ppid,
            start_time_ns,
            es_version,
            responsible,
            subject_pid: pid,
            exit_stat,
        }
    }

    fn loss_gap(&mut self, ts_mono_ns: u64, ts_wall_ns: i64, loss: &SequenceLoss) -> EsEvent {
        let which = match loss.kind {
            super::loss::SequenceKind::PerEvent => "seq_num",
            super::loss::SequenceKind::Global => "global_seq_num",
        };
        let event_name = loss.event.as_deref().unwrap_or("global");
        let detail = format!(
            "{which} for {event_name} jumped from {prev} to {obs}",
            prev = loss.previous,
            obs = loss.observed,
        );
        let seq = self.alloc_seq();
        let gap = Gap::new(
            Source::new(format!("{SOURCE_PREFIX}/seq")),
            GapKind::LostByOs,
            vec!["proc".to_owned()],
            ts_mono_ns,
            ts_mono_ns,
            Some(loss.missing),
            Some(detail),
        );
        let event = gap_event(seq, ts_mono_ns, ts_wall_ns, gap);
        empty_side(Some(event))
    }

    fn parse_gap(&mut self, ts_mono_ns: u64, ts_wall_ns: i64, detail: &str) -> EsEvent {
        let seq = self.alloc_seq();
        let gap = Gap::new(
            Source::new(format!("{SOURCE_PREFIX}/parse")),
            GapKind::ParseError,
            vec!["proc".to_owned()],
            ts_mono_ns,
            ts_mono_ns,
            None,
            Some(detail.to_owned()),
        );
        let event = gap_event(seq, ts_mono_ns, ts_wall_ns, gap);
        empty_side(Some(event))
    }

    fn alloc_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }
}

/// ProcUid from an audit token.
///
/// Always `None` until SPIKE-03 confirms `pidversion` and the start-time path.
/// `pid` is accepted so the call site already has the shape the spike will fill;
/// it is not hashed on its own.
fn proc_uid_from_token(_pid: u32) -> Option<ProcUid> {
    None
}

fn empty_side(event: Option<RawEvent>) -> EsEvent {
    EsEvent {
        event,
        exe: None,
        argv: None,
        cwd: None,
        how: None,
        ppid: None,
        start_time_ns: None,
        es_version: None,
        responsible: None,
        subject_pid: None,
        exit_stat: None,
    }
}

fn gap_event(seq: u64, ts_mono_ns: u64, ts_wall_ns: i64, gap: Gap) -> RawEvent {
    let source = gap.collector.clone();
    let kind = EventKind::Gap(gap);
    match RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns,
        ts_wall_ns,
        session_id: None,
        proc: None,
        source: source.clone(),
        evidence: Evidence::E1,
        kind,
    }) {
        Ok(event) => event,
        // try_new only fails when a required Option is None without NA. Gap has
        // no such field today. If a later schema adds one, rebuild with the kind
        // moved out of the error path by reconstructing from what we still hold.
        // We cannot get `kind` back from `Err`, so this arm builds a parse gap
        // that still records the loss instead of dropping it.
        Err(_) => RawEvent::try_new(RawEventParts {
            seq,
            ts_mono_ns,
            ts_wall_ns,
            session_id: None,
            proc: None,
            source,
            evidence: Evidence::E1,
            kind: EventKind::Gap(Gap::new(
                Source::new(format!("{SOURCE_PREFIX}/parse")),
                GapKind::ParseError,
                vec!["proc".to_owned()],
                ts_mono_ns,
                ts_mono_ns,
                None,
                Some("gap event could not be built; the loss was not dropped".to_owned()),
            )),
        })
        .unwrap_or_else(|_| backup_gap(seq, ts_mono_ns, ts_wall_ns)),
    }
}

fn backup_gap(seq: u64, ts_mono_ns: u64, ts_wall_ns: i64) -> RawEvent {
    // Direct struct: `try_new` refused a Gap twice. Still emit one so the count
    // of "something was lost" stays visible. `field_evidence` is empty because
    // this gap has no optional field that the schema treats as required.
    RawEvent {
        v: aw_core::SCHEMA_VERSION,
        seq,
        ts_mono_ns,
        ts_wall_ns,
        session_id: None,
        proc: None,
        source: Source::new(format!("{SOURCE_PREFIX}/parse")),
        evidence: Evidence::E1,
        field_evidence: std::collections::BTreeMap::new(),
        kind: EventKind::Gap(Gap::new(
            Source::new(format!("{SOURCE_PREFIX}/parse")),
            GapKind::ParseError,
            vec!["proc".to_owned()],
            ts_mono_ns,
            ts_mono_ns,
            None,
            Some("gap event could not be built; the loss was not dropped".to_owned()),
        )),
    }
}

/// Decode a single line with a fresh decoder (no prior sequence baseline).
///
/// Use [`LineDecoder`] when holes across lines matter.
pub fn decode_line(line: &str, ts_mono_ns: u64, ts_wall_ns: i64) -> Vec<EsEvent> {
    LineDecoder::new()
        .push_inner(line, ts_mono_ns, ts_wall_ns)
}

/// `push` does not fail today: a bad line is a parse gap inside `Ok`.
///
/// The type stays in the signature so a later macOS caller can still use `?`
/// if reading the child process fails. The decoder does not construct `Unused`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Present so the type is not uninhabited. The decoder does not build it.
    #[allow(dead_code)]
    Unused,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("eslogger decode error")
    }
}

impl std::error::Error for DecodeError {}

fn es_version(value: &Value) -> Option<i64> {
    i64_at(value, &["version"]).or_else(|| i64_at(value, &["event", "version"]))
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    match pointer(value, path) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn string_list_at(value: &Value, path: &[&str]) -> Option<Vec<String>> {
    let Value::Array(items) = pointer(value, path)? else {
        return None;
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::String(s) = item else {
            return None;
        };
        out.push(s.clone());
    }
    Some(out)
}

fn u32_at(value: &Value, path: &[&str]) -> Option<u32> {
    i64_at(value, path).and_then(|n| u32::try_from(n).ok())
}

fn u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    match pointer(value, path)? {
        Value::Number(n) => n.as_u64().or_else(|| n.as_i64().and_then(|v| u64::try_from(v).ok())),
        _ => None,
    }
}

fn i64_at(value: &Value, path: &[&str]) -> Option<i64> {
    match pointer(value, path)? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_u64().and_then(|v| i64::try_from(v).ok())),
        _ => None,
    }
}

fn pointer<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = value;
    for key in path {
        cur = cur.as_object()?.get(*key)?;
    }
    Some(cur)
}
