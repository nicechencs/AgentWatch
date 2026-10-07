//! `sim eval`: recall and byte-error report against a ground-truth log.
//!
//! # Export JSONL (interim)
//!
//! P1-STORE-03 (`aw export`) does not exist yet. This module reads a **minimal**
//! JSONL stand-in so CI can score a session without a running daemon. When
//! `aw export` lands, align these fields with its session JSONL and delete the
//! notes below. Do not grow this format to imitate the full `RawEvent` envelope.
//!
//! One JSON object per line. Unknown keys are ignored. A line is skipped (and
//! counted in `unparsed`) when it is not JSON or has no usable `kind`.
//!
//! Common fields:
//!
//! | field | required | meaning |
//! |---|---|---|
//! | `kind` | yes | `process_start`, `net_connect`, `net_close`, `dns_query`, `gap`, or anything else (counted, not matched) |
//! | `evidence` | no | record level: `E1`, `E2`, `E3`, `S`, `I`, or `{"level":"NA","reason":"..."}` (aw-core `Evidence`) |
//! | `source` | no | `"<collector>/<probe>"`, same spelling as aw-core `Source` |
//! | `ts_wall_ns` | no | Unix epoch nanoseconds. Compared with truth `t_wall_ns` (± 1 s) for processes |
//! | `pid` | process | subject pid. Also accepted as `proc.pid` |
//! | `exe` | process | executable path. Also accepted as `payload.exe` |
//!
//! Kind-specific:
//!
//! - `process_start`: `pid`, `exe`, `ts_wall_ns`. Optional `lifetime_ms` (how long
//!   the process lived). A start whose source begins with `poll/` or whose
//!   evidence is `S` is an S-tier observation.
//! - `net_connect`: `local_port`, `remote_port` (u16). Optional `proto`.
//! - `net_close`: `local_port`, `remote_port`, `bytes_sent`, `bytes_recv`
//!   (u64). `null` on a byte field means the collector did not observe it
//!   (aw-core `Option`, never `0` for unknown). A close with no matching
//!   connect still counts as the connection for matching.
//! - `dns_query`: `qname` (compared case-insensitively, trailing dot stripped).
//! - `gap`: `gap_kind` (string), optional `affects` (string list), optional
//!   `detail`. These are listed, not matched to truth rows.
//!
//! # Matching
//!
//! - Process: `(pid, exe, start time ± 1 s)`. `exe` is the last path segment,
//!   case-insensitive. A missing export timestamp still matches on pid + exe.
//! - Connection: `(local_port, remote_port)`.
//! - DNS: `qname`.
//!
//! Truth rows come from [`crate::truth::TruthLine`] (`sim/src/truth.rs`).
//! Process ground truth is `spawn_enter` (the child's pid and `t_wall_ns`).
//! The parent `spawn` row may add `lifetime_ms` and `spawned_pid`. A process is
//! short-lived when its id is `short` or that lifetime is below 100 ms.
//! Short-lived processes stay in the report. They leave the asserted
//! denominator when the platform tier is `S`, or when every `process_start` in
//! the export is S-tier (poll). An E1 export that observed other processes is
//! still scored on a missed short-lived one.
//!
//! Connections are `http_upload`, `http_download`, `udp_send`, and `long_conn`.
//! Both `local` and `remote` must be `ip:port` (or `[ip]:port`); a row missing
//! either port cannot match. `http_upload` today often omits `local` — that
//! row is unmatched until the truth log records the client port. Upload and
//! UDP bytes are the sent side (`app_bytes`); download bytes are the received
//! side. `long_conn` has no body, so it counts for recall only. DNS is
//! `dns_lookup.name`. Rows with `ok: false` or `skip: true` are not in the
//! denominator.
//!
//! # Thresholds
//!
//! `sim/thresholds/p1.toml`. The active platform is `--platform` or the host
//! OS. E1 tiers assert recall and byte error. macOS `m1` uses the wider byte
//! budget (`--platform macos-m1`). Below a threshold the command exits 1.
//!
//! `--session <id|@last>` is **not** implemented. The evaluator must not open
//! the store or talk to a daemon (P1-SIM-02). Pass `--export`.
//!
//! [`crate::truth::TruthLine`]: crate::truth::TruthLine

mod match_rules;
mod report;
mod thresholds;

use std::fs;
use std::path::Path;

use serde::Deserialize;

/// CLI entry. Prints Markdown, and JSON unless `--json-out` was given.
/// `Err` is a usage or IO failure. A scored miss is [`EvalStatus::Fail`]
/// after the report has been written.
pub fn run(args: Vec<String>) -> Result<EvalStatus, String> {
    let opts = parse_args(args)?;
    let truth = load_truth(&opts.truth)?;
    let (export, unparsed) = load_export(&opts.export)?;
    let thresholds = thresholds::Thresholds::load(&opts.thresholds)?;
    let platform = opts.platform.clone().unwrap_or_else(host_platform);
    let active = thresholds.select(&platform)?;
    let report = match_rules::score_with(&truth, &export, &active, unparsed);
    let markdown = report.to_markdown();
    let json = report
        .to_json()
        .map_err(|err| format!("encode report: {err}"))?;
    if let Some(path) = &opts.json_out {
        fs::write(path, &json).map_err(|err| format!("write {}: {err}", path.display()))?;
    }
    if let Some(path) = &opts.markdown_out {
        fs::write(path, &markdown).map_err(|err| format!("write {}: {err}", path.display()))?;
    }
    print!("{markdown}");
    if opts.json_out.is_none() {
        println!("{json}");
    }
    Ok(if report.passed {
        EvalStatus::Pass
    } else {
        EvalStatus::Fail
    })
}

/// Whether the scored report met every asserted threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalStatus {
    Pass,
    Fail,
}

/// Score already-parsed inputs. Unit tests call this directly.
#[cfg(test)]
pub fn evaluate(
    truth: &[TruthAction],
    export: &[ExportEvent],
    thresholds: &thresholds::Thresholds,
    platform: &str,
) -> Result<report::EvalReport, String> {
    let active = thresholds.select(platform)?;
    Ok(match_rules::score_with(truth, export, &active, 0))
}

#[derive(Debug)]
struct Opts {
    truth: std::path::PathBuf,
    export: std::path::PathBuf,
    thresholds: std::path::PathBuf,
    platform: Option<String>,
    json_out: Option<std::path::PathBuf>,
    markdown_out: Option<std::path::PathBuf>,
}

fn parse_args(args: Vec<String>) -> Result<Opts, String> {
    let mut truth = None;
    let mut export = None;
    let mut thresholds = None;
    let mut platform = None;
    let mut json_out = None;
    let mut markdown_out = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let next = |flag: &str, iter: &mut std::vec::IntoIter<String>| -> Result<String, String> {
            iter.next()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match arg.as_str() {
            "--truth" => truth = Some(std::path::PathBuf::from(next("--truth", &mut iter)?)),
            "--export" => export = Some(std::path::PathBuf::from(next("--export", &mut iter)?)),
            "--thresholds" => {
                thresholds = Some(std::path::PathBuf::from(next("--thresholds", &mut iter)?));
            }
            "--platform" => platform = Some(next("--platform", &mut iter)?),
            "--json-out" => {
                json_out = Some(std::path::PathBuf::from(next("--json-out", &mut iter)?));
            }
            "--markdown-out" => {
                markdown_out = Some(std::path::PathBuf::from(next("--markdown-out", &mut iter)?));
            }
            "--session" => {
                return Err(
                    "--session is not implemented: sim eval does not open the store or talk to a daemon (P1-SIM-02). Pass --export."
                        .to_string(),
                );
            }
            "-h" | "--help" => return Err(usage()),
            other => return Err(format!("unknown eval flag `{other}`\n{}", usage())),
        }
    }
    Ok(Opts {
        truth: truth.ok_or_else(|| format!("missing --truth\n{}", usage()))?,
        export: export.ok_or_else(|| format!("missing --export\n{}", usage()))?,
        thresholds: thresholds.ok_or_else(|| format!("missing --thresholds\n{}", usage()))?,
        platform,
        json_out,
        markdown_out,
    })
}

fn usage() -> String {
    "usage: sim eval --truth <truth.jsonl> --export <file.jsonl> --thresholds <p1.toml> [--platform linux|windows|macos] [--json-out <file>] [--markdown-out <file>]\n\n--session is not available. The evaluator reads files only.\n".to_string()
}

/// One ground-truth action the scorer understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruthAction {
    pub category: Category,
    pub pid: u32,
    pub exe: Option<String>,
    /// Wall time in Unix nanoseconds (`TruthLine.t_wall_ns`).
    pub t_wall_ns: u128,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub qname: Option<String>,
    /// Upload (`http_upload`, `udp_send`) bytes. `None` if this row has none.
    pub bytes_up: Option<u64>,
    /// Download (`http_download`) bytes.
    pub bytes_down: Option<u64>,
    /// `true` when the process lived < 100 ms, or the spawn id is `short`.
    pub short_lived: bool,
    /// Stable label for the unmatched-item list. Not a secret.
    pub label: String,
}

/// Categories the report scores separately. `file` is accepted so a later
/// export can be counted, but P1 truth has no file rows in the denominator
/// unless a fixture includes them (this card does not score files).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Proc,
    Net,
    Dns,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proc => "proc",
            Self::Net => "net",
            Self::Dns => "dns",
        }
    }
}

/// One exported observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportEvent {
    pub kind: ExportKind,
    pub evidence: Option<String>,
    pub source: Option<String>,
    pub pid: Option<u32>,
    pub exe: Option<String>,
    pub ts_wall_ns: Option<i64>,
    pub local_port: Option<u16>,
    pub remote_port: Option<u16>,
    pub qname: Option<String>,
    pub bytes_sent: Option<u64>,
    pub bytes_recv: Option<u64>,
    pub lifetime_ms: Option<u64>,
    pub gap_kind: Option<String>,
    pub gap_affects: Vec<String>,
    pub gap_detail: Option<String>,
}

impl ExportEvent {
    /// S-tier: poll source, or the record's own evidence is `S`.
    pub fn is_s_tier(&self) -> bool {
        if self.evidence.as_deref() == Some("S") {
            return true;
        }
        self.source
            .as_deref()
            .is_some_and(|source| source.starts_with("poll/") || source == "poll")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    ProcessStart,
    NetConnect,
    NetClose,
    DnsQuery,
    Gap,
    Other,
}

#[derive(Debug, Deserialize)]
struct RawTruth {
    t_wall_ns: u128,
    pid: u32,
    action: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    local: Option<String>,
    #[serde(default)]
    remote: Option<String>,
    #[serde(default)]
    app_bytes: Option<u64>,
    #[serde(default)]
    bytes: Option<u64>,
    #[serde(default)]
    spawned_pid: Option<u32>,
    ok: bool,
    #[serde(default)]
    extra: std::collections::BTreeMap<String, serde_json::Value>,
    /// Flattened keys (`lifetime_ms`, `skip`) land here when the writer used
    /// `#[serde(flatten)] extra`. Serde also accepts them as top-level fields
    /// via `extra` only if we flatten. TruthLine flattens `extra`, so read both.
    #[serde(flatten)]
    flat: std::collections::BTreeMap<String, serde_json::Value>,
}

pub fn load_truth(path: &Path) -> Result<Vec<TruthAction>, String> {
    let text = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    parse_truth(&text)
}

pub fn parse_truth(text: &str) -> Result<Vec<TruthAction>, String> {
    let mut rows = Vec::new();
    let mut spawns: Vec<SpawnMeta> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let raw: RawTruth = serde_json::from_str(line)
            .map_err(|err| format!("truth line {}: {err}", index + 1))?;
        if !raw.ok || flag_true(&raw, "skip") {
            continue;
        }
        match raw.action.as_str() {
            "spawn" => spawns.push(SpawnMeta {
                spawned_pid: raw.spawned_pid,
                id: raw.id.clone(),
                lifetime_ms: number_u64(&raw, "lifetime_ms"),
            }),
            "spawn_enter" => {
                let short = is_short(&raw.id, None, &spawns, raw.pid);
                rows.push(TruthAction {
                    category: Category::Proc,
                    pid: raw.pid,
                    exe: exe_of(&raw),
                    t_wall_ns: raw.t_wall_ns,
                    local_port: None,
                    remote_port: None,
                    qname: None,
                    bytes_up: None,
                    bytes_down: None,
                    short_lived: short,
                    label: format!("proc pid={} id={}", raw.pid, raw.id.as_deref().unwrap_or("-")),
                });
            }
            "http_upload" | "http_download" | "udp_send" | "long_conn" => {
                let (local_port, remote_port) = ports_of(&raw)?;
                let nbytes = raw.app_bytes.or(raw.bytes);
                let upload = matches!(raw.action.as_str(), "http_upload" | "udp_send");
                rows.push(TruthAction {
                    category: Category::Net,
                    pid: raw.pid,
                    exe: None,
                    t_wall_ns: raw.t_wall_ns,
                    local_port,
                    remote_port,
                    qname: None,
                    bytes_up: if upload { nbytes } else { None },
                    bytes_down: if upload { None } else { nbytes },
                    short_lived: false,
                    label: format!(
                        "{} {}:{}",
                        raw.action,
                        local_port.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                        remote_port.map(|p| p.to_string()).unwrap_or_else(|| "-".into())
                    ),
                });
            }
            "dns_lookup" => {
                let qname = raw.name.clone().ok_or_else(|| {
                    format!("truth line {}: dns_lookup has no name", index + 1)
                })?;
                rows.push(TruthAction {
                    category: Category::Dns,
                    pid: raw.pid,
                    exe: None,
                    t_wall_ns: raw.t_wall_ns,
                    local_port: None,
                    remote_port: None,
                    qname: Some(qname.clone()),
                    bytes_up: None,
                    bytes_down: None,
                    short_lived: false,
                    label: format!("dns {qname}"),
                });
            }
            _ => {}
        }
    }
    // Parent `spawn` is written after the child, so short-lived is known only then.
    apply_spawn_lifetimes(&mut rows, &spawns);
    Ok(rows)
}

struct SpawnMeta {
    spawned_pid: Option<u32>,
    id: Option<String>,
    lifetime_ms: Option<u64>,
}

fn apply_spawn_lifetimes(rows: &mut [TruthAction], spawns: &[SpawnMeta]) {
    for row in rows.iter_mut().filter(|row| row.category == Category::Proc) {
        if is_short(&None, Some(row.pid), spawns, row.pid) {
            row.short_lived = true;
        }
    }
}

fn is_short(id: &Option<String>, pid: Option<u32>, spawns: &[SpawnMeta], self_pid: u32) -> bool {
    if id.as_deref() == Some("short") {
        return true;
    }
    let pid = pid.unwrap_or(self_pid);
    spawns.iter().any(|spawn| {
        spawn.spawned_pid == Some(pid)
            && (spawn.id.as_deref() == Some("short") || spawn.lifetime_ms.is_some_and(|ms| ms < 100))
    })
}

fn exe_of(raw: &RawTruth) -> Option<String> {
    raw.flat
        .get("exe")
        .or_else(|| raw.extra.get("exe"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn flag_true(raw: &RawTruth, key: &str) -> bool {
    raw.flat
        .get(key)
        .or_else(|| raw.extra.get(key))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn number_u64(raw: &RawTruth, key: &str) -> Option<u64> {
    raw.flat
        .get(key)
        .or_else(|| raw.extra.get(key))
        .and_then(|v| v.as_u64())
}

fn ports_of(raw: &RawTruth) -> Result<(Option<u16>, Option<u16>), String> {
    Ok((port_of(raw.local.as_deref()), port_of(raw.remote.as_deref())))
}

fn port_of(addr: Option<&str>) -> Option<u16> {
    let addr = addr?;
    let port = addr.rsplit(':').next()?;
    port.parse().ok()
}

#[derive(Debug, Deserialize)]
struct RawExport {
    kind: String,
    #[serde(default)]
    evidence: Option<serde_json::Value>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    proc_: Option<ProcPid>,
    #[serde(default)]
    exe: Option<String>,
    #[serde(default)]
    ts_wall_ns: Option<i64>,
    #[serde(default)]
    local_port: Option<u16>,
    #[serde(default)]
    remote_port: Option<u16>,
    #[serde(default)]
    qname: Option<String>,
    #[serde(default)]
    bytes_sent: Option<u64>,
    #[serde(default)]
    bytes_recv: Option<u64>,
    #[serde(default)]
    lifetime_ms: Option<u64>,
    #[serde(default)]
    gap_kind: Option<String>,
    #[serde(default)]
    affects: Vec<String>,
    #[serde(default)]
    detail: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProcPid {
    pid: u32,
}

pub fn load_export(path: &Path) -> Result<(Vec<ExportEvent>, u64), String> {
    let text = fs::read_to_string(path).map_err(|err| format!("read {}: {err}", path.display()))?;
    Ok(parse_export_counted(&text))
}

pub fn parse_export_counted(text: &str) -> (Vec<ExportEvent>, u64) {
    let mut rows = Vec::new();
    let mut unparsed = 0u64;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(_) => {
                unparsed += 1;
                continue;
            }
        };
        let mut raw: RawExport = match serde_json::from_value(rewrite_proc(value)) {
            Ok(raw) => raw,
            Err(_) => {
                unparsed += 1;
                continue;
            }
        };
        if raw.pid.is_none() {
            raw.pid = raw.proc_.as_ref().map(|p| p.pid);
        }
        let kind = match raw.kind.as_str() {
            "process_start" => ExportKind::ProcessStart,
            "net_connect" => ExportKind::NetConnect,
            "net_close" => ExportKind::NetClose,
            "dns_query" => ExportKind::DnsQuery,
            "gap" => ExportKind::Gap,
            _ => ExportKind::Other,
        };
        rows.push(ExportEvent {
            kind,
            evidence: evidence_label(raw.evidence.as_ref()),
            source: raw.source,
            pid: raw.pid,
            exe: raw.exe,
            ts_wall_ns: raw.ts_wall_ns,
            local_port: raw.local_port,
            remote_port: raw.remote_port,
            qname: raw.qname,
            bytes_sent: raw.bytes_sent,
            bytes_recv: raw.bytes_recv,
            lifetime_ms: raw.lifetime_ms,
            gap_kind: raw.gap_kind,
            gap_affects: raw.affects,
            gap_detail: raw.detail,
        });
    }
    (rows, unparsed)
}

/// `proc` is a Rust keyword, so the helper renames a nested `proc.pid` before serde.
fn rewrite_proc(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        if let Some(proc) = obj.remove("proc") {
            obj.insert("proc_".to_string(), proc);
        }
        if obj.get("exe").is_none() {
            if let Some(exe) = obj
                .get("payload")
                .and_then(|p| p.get("exe"))
                .cloned()
            {
                obj.insert("exe".to_string(), exe);
            }
        }
    }
    value
}

fn host_platform() -> String {
    match std::env::consts::OS {
        "linux" => "linux",
        "windows" => "windows",
        "macos" => "macos",
        other => other,
    }
    .to_string()
}

fn evidence_label(value: Option<&serde_json::Value>) -> Option<String> {
    let value = value?;
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Object(map) => map
            .get("level")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::*;

    fn events(text: &str) -> Vec<ExportEvent> {
        parse_export_counted(text).0
    }

    fn thresholds() -> thresholds::Thresholds {
        thresholds::Thresholds::parse(include_str!("../../thresholds/p1.toml")).unwrap()
    }

    fn truth() -> Vec<TruthAction> {
        parse_truth(include_str!("../../tests/fixtures/eval/truth.jsonl")).unwrap()
    }

    #[test]
    fn one_missed_process_is_half_recall() {
        let export = events(include_str!(
            "../../tests/fixtures/eval/export_miss_one.jsonl"
        ));
        let report = evaluate(&truth(), &export, &thresholds(), "linux").unwrap();
        let proc = report
            .categories
            .iter()
            .find(|row| row.category == "proc")
            .unwrap();
        assert_eq!(proc.truth, 2);
        assert_eq!(proc.hit, 1);
        assert_eq!(proc.recall, Some(0.5));
        assert!(!report.passed);
        assert!(report.unmatched_truth.iter().any(|item| item.contains("pid=21")));
    }

    #[test]
    fn six_percent_byte_error_fails_e1() {
        let export = events(include_str!(
            "../../tests/fixtures/eval/export_byte_6pct.jsonl"
        ));
        let report = evaluate(&truth(), &export, &thresholds(), "windows").unwrap();
        let up = report.connections.iter().find(|row| row.local_port == 40000).unwrap();
        assert_eq!(up.err_up, Some(0.06));
        assert!(!report.passed);
        assert!(report.failures.iter().any(|item| item.contains("6.0%")));

        let m1 = evaluate(&truth(), &export, &thresholds(), "macos-m1").unwrap();
        assert!(m1.passed, "{:?}", m1.failures);
    }

    #[test]
    fn short_lived_is_not_asserted_when_export_is_s_tier() {
        let export = events(
            r#"{"kind":"process_start","pid":20,"exe":"sim.exe","ts_wall_ns":1000000000000,"evidence":"S","source":"poll/sysinfo"}
"#,
        );
        let report = evaluate(&truth(), &export, &thresholds(), "linux").unwrap();
        let proc = report
            .categories
            .iter()
            .find(|row| row.category == "proc")
            .unwrap();
        // The long-lived child is still asserted and hit. The short one is reported only.
        assert_eq!((proc.truth, proc.hit, proc.reported_only), (1, 1, 1));
        assert!(report.passed || report.failures.iter().any(|item| item.contains("net")));
        assert!(!report.short_lived_reported.is_empty());
    }
}
