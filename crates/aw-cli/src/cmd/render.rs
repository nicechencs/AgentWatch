//! Table and JSON rendering shared by the query commands.
//!
//! Every table goes through [`crate::output::write_table`], which appends the
//! evidence column. JSON for a whole command is one document so `--json` stays
//! one parse. Unknown cells are the text `不可得`.

use std::io::{self, Write};

use serde_json::{json, Value};

use aw_core::Evidence;

use crate::output::{self, OutputMode, Row, Table};

use super::query::{
    opt_i64, opt_text, AroundItem, FileItem, FlowItem, GapItem, ProcItem, SearchHit, SessionItem,
    SessionShow, TimelineItem,
};

/// Print a table, or the JSON document when `mode` is JSON.
///
/// # Errors
///
/// A short write, or a JSON encode failure mapped to `io::Error`.
pub(crate) fn write_out(
    out: &mut dyn Write,
    mode: OutputMode,
    table: &Table,
    json_doc: &Value,
) -> io::Result<()> {
    match mode {
        OutputMode::Json => {
            let mut bytes = serde_json::to_vec_pretty(json_doc)
                .map_err(|err| io::Error::other(format!("编码 JSON 失败：{err}")))?;
            bytes.push(b'\n');
            out.write_all(&bytes)
        }
        OutputMode::Table => out.write_all(render_uncut(table).as_bytes()),
    }
}

/// Aligned columns, evidence last, no 80-column clip.
///
/// [`output::write_table`] shrinks cells to a terminal width. A wide query row
/// would lose the evidence badge. Cells are not cut here.
fn render_uncut(table: &Table) -> String {
    let mut headers = table.headers.clone();
    headers.push("evidence".to_owned());
    let mut grid: Vec<Vec<String>> = Vec::with_capacity(table.rows.len() + 1);
    grid.push(headers);
    for row in &table.rows {
        let mut cells = Vec::with_capacity(table.headers.len() + 1);
        for index in 0..table.headers.len() {
            cells.push(
                row.cells
                    .get(index)
                    .cloned()
                    .filter(|cell| !cell.is_empty())
                    .unwrap_or_else(|| "不可得".to_owned()),
            );
        }
        cells.push(output::evidence_badge(&row.evidence).to_owned());
        grid.push(cells);
    }
    let cols = grid.first().map(Vec::len).unwrap_or(0);
    let mut widths = vec![0_usize; cols];
    for row in &grid {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(display_width(cell));
        }
    }
    let mut out = String::new();
    for row in &grid {
        let mut line = String::new();
        for (index, cell) in row.iter().enumerate() {
            if index > 0 {
                line.push_str("  ");
            }
            let pad = widths[index].saturating_sub(display_width(cell));
            line.push_str(cell);
            line.push_str(&" ".repeat(pad));
        }
        while line.ends_with(' ') {
            line.pop();
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn display_width(text: &str) -> usize {
    text.chars()
        .map(|ch| {
            if ('\u{2E80}'..='\u{9FFF}').contains(&ch) || ('\u{FF00}'..='\u{FF60}').contains(&ch) {
                2
            } else {
                1
            }
        })
        .sum()
}

/// Evidence object for JSON. NA keeps the reason code; the level is not raised.
pub(crate) fn evidence_json(evidence: &Evidence) -> Value {
    match evidence {
        Evidence::NA(reason) => json!({
            "level": "NA",
            "reason": na_code(reason),
        }),
        other => json!({ "level": output::evidence_code(other) }),
    }
}

fn na_code(reason: &aw_core::NaReason) -> &'static str {
    use aw_core::NaReason;
    match reason {
        NaReason::EsNoReadEvent => "es_no_read_event",
        NaReason::MmapNotObservable => "mmap_not_observable",
        NaReason::TlsNoProxy => "tls_no_proxy",
        NaReason::DirectBypassProxy => "direct_bypass_proxy",
        NaReason::CertPinned => "cert_pinned",
        NaReason::Quic => "quic",
        NaReason::Ech => "ech",
        NaReason::NoDnsObserved => "no_dns_observed",
        NaReason::Preexisting => "preexisting",
        NaReason::CollectorUnavailable => "collector_unavailable",
        NaReason::Redacted => "redacted",
        NaReason::AttributionBreak => "attribution_break",
        NaReason::PartialClientHello => "partial_client_hello",
        NaReason::H2Hpack => "h2_hpack",
        NaReason::TooLarge => "too_large",
        NaReason::FileChanged => "file_changed",
        NaReason::PeerUnknown => "peer_unknown",
        NaReason::ProtocolNotObserved => "protocol_not_observed",
        NaReason::Unknown => "unknown",
    }
}

/// Record-level evidence for a row that may not have one (a mixed group).
pub(crate) fn evidence_or_na(evidence: Option<&Evidence>) -> Evidence {
    evidence
        .cloned()
        .unwrap_or(Evidence::NA(aw_core::NaReason::Unknown))
}

pub(crate) fn session_table(items: &[SessionItem]) -> Table {
    Table {
        headers: vec![
            "id".to_owned(),
            "name".to_owned(),
            "mode".to_owned(),
            "agent".to_owned(),
            "started_ns".to_owned(),
            "ended_ns".to_owned(),
            "pinned".to_owned(),
        ],
        rows: items
            .iter()
            .map(|item| Row {
                cells: vec![
                    item.public_id.clone(),
                    opt_text(item.name.as_deref()),
                    item.mode.clone(),
                    opt_text(item.agent.as_deref()),
                    opt_i64(item.started_ns),
                    opt_i64(item.ended_ns),
                    super::query::yes_no(item.pinned).to_owned(),
                ],
                evidence: item.evidence.clone(),
            })
            .collect(),
    }
}

pub(crate) fn session_json(items: &[SessionItem]) -> Value {
    json!({
        "sessions": items.iter().map(session_item_json).collect::<Vec<_>>()
    })
}

fn session_item_json(item: &SessionItem) -> Value {
    json!({
        "id": item.public_id,
        "name": item.name,
        "mode": item.mode,
        "agent": item.agent,
        "started_ns": item.started_ns,
        "ended_ns": item.ended_ns,
        "pinned": item.pinned,
        "evidence": evidence_json(&item.evidence),
    })
}

pub(crate) fn show_table(show: &SessionShow) -> Table {
    let mut rows = vec![
        stat_row(
            "name",
            opt_text(show.item.name.as_deref()),
            &show.item.evidence,
        ),
        stat_row("mode", show.item.mode.clone(), &show.item.evidence),
        stat_row(
            "agent",
            opt_text(show.item.agent.as_deref()),
            &show.item.evidence,
        ),
        stat_row(
            "started_ns",
            opt_i64(show.item.started_ns),
            &show.item.evidence,
        ),
        stat_row("ended_ns", opt_i64(show.item.ended_ns), &show.item.evidence),
        stat_row(
            "pinned",
            super::query::yes_no(show.item.pinned).to_owned(),
            &show.item.evidence,
        ),
        stat_row(
            "processes",
            opt_i64(show.process_count),
            &show.item.evidence,
        ),
        stat_row("flows", opt_i64(show.flow_count), &show.item.evidence),
        stat_row("dns", opt_i64(show.dns_count), &show.item.evidence),
        stat_row("gaps", opt_i64(show.gap_count), &Evidence::E1),
        stat_row("bytes_up", opt_i64(show.bytes_up), &show.item.evidence),
        stat_row("bytes_down", opt_i64(show.bytes_down), &show.item.evidence),
    ];
    if show.gap_summaries.is_empty() {
        rows.push(stat_row(
            "gap",
            "不可得".to_owned(),
            &Evidence::NA(aw_core::NaReason::Unknown),
        ));
    } else {
        for summary in &show.gap_summaries {
            rows.push(stat_row("gap", summary.clone(), &Evidence::E1));
        }
    }
    for cap in &show.capabilities {
        let value = format!(
            "{} source {}",
            cap.category,
            opt_text(cap.source.as_deref())
        );
        rows.push(stat_row("capability", value, &cap.evidence));
    }
    Table {
        headers: vec!["field".to_owned(), "value".to_owned()],
        rows,
    }
}

fn stat_row(field: &str, value: String, evidence: &Evidence) -> Row {
    Row {
        cells: vec![field.to_owned(), value],
        evidence: evidence.clone(),
    }
}

pub(crate) fn show_json(show: &SessionShow) -> Value {
    json!({
        "session": session_item_json(&show.item),
        "stats": {
            "processes": show.process_count,
            "flows": show.flow_count,
            "dns": show.dns_count,
            "gaps": show.gap_count,
            "bytes_up": show.bytes_up,
            "bytes_down": show.bytes_down,
        },
        "gap_summaries": show.gap_summaries,
        "capabilities": show.capabilities.iter().map(|cap| json!({
            "category": cap.category,
            "source": cap.source,
            "evidence": evidence_json(&cap.evidence),
        })).collect::<Vec<_>>(),
    })
}

pub(crate) fn timeline_table(rows: &[TimelineItem], color: bool) -> Table {
    Table {
        headers: vec![
            "ts_ns".to_owned(),
            "cat".to_owned(),
            "id".to_owned(),
            "proc".to_owned(),
            "summary".to_owned(),
        ],
        rows: rows
            .iter()
            .map(|row| {
                let summary = if row.is_gap {
                    format!("{} {}", super::query::gap_marker(color), row.summary)
                } else {
                    row.summary.clone()
                };
                Row {
                    cells: vec![
                        row.ts_ns.to_string(),
                        row.cat.clone(),
                        row.id.to_string(),
                        opt_i64(row.proc_uid),
                        summary,
                    ],
                    evidence: row.evidence.clone(),
                }
            })
            .collect(),
    }
}

pub(crate) fn timeline_json(rows: &[TimelineItem], live_connected: bool) -> Value {
    json!({
        "live_connected": live_connected,
        "note": if live_connected {
            Value::Null
        } else {
            json!("没有订阅实时 /sessions/{sid}/live（真实订阅未接通）；这些行来自注入的数据源")
        },
        "events": rows.iter().map(|row| json!({
            "ts_ns": row.ts_ns,
            "cat": row.cat,
            "id": row.id,
            "proc_uid": row.proc_uid,
            "summary": row.summary,
            "gap": row.is_gap,
            "evidence": evidence_json(&row.evidence),
        })).collect::<Vec<_>>(),
    })
}

/// Flat process rows. `depth` is the tree depth when `tree` is set.
pub(crate) fn flatten_proc_rows(nodes: &[ProcItem], tree: bool) -> Vec<(ProcItem, usize)> {
    let mut out = Vec::new();
    walk(nodes, 0, tree, &mut out);
    out
}

fn walk(nodes: &[ProcItem], depth: usize, tree: bool, out: &mut Vec<(ProcItem, usize)>) {
    for node in nodes {
        let children = node.children.clone();
        let mut flat = node.clone();
        flat.children.clear();
        out.push((flat, depth));
        if tree {
            walk(&children, depth + 1, true, out);
        }
    }
}

/// P1 redaction is a placeholder. The column says so on every row, including
/// rows whose argv was not observed.
pub(crate) const ARGV_NOTE: &str = "P1 脱敏为占位";

pub(crate) fn procs_table(nodes: &[ProcItem], tree: bool) -> Table {
    Table {
        headers: vec![
            "proc".to_owned(),
            "pid".to_owned(),
            "exe".to_owned(),
            "argv".to_owned(),
            "退出码".to_owned(),
            "redaction".to_owned(),
        ],
        rows: flatten_proc_rows(nodes, tree)
            .into_iter()
            .map(|(node, depth)| {
                let indent = if tree {
                    "  ".repeat(depth)
                } else {
                    String::new()
                };
                Row {
                    cells: vec![
                        format!("{indent}{}", node.proc_uid),
                        node.pid.to_string(),
                        opt_text(node.exe_name.as_deref()),
                        opt_text(node.argv_redacted.as_deref()),
                        node.exit_code
                            .map_or_else(|| "没采".to_owned(), |code| code.to_string()),
                        ARGV_NOTE.to_owned(),
                    ],
                    evidence: node.evidence,
                }
            })
            .collect(),
    }
}

pub(crate) fn procs_json(nodes: &[ProcItem], tree: bool) -> Value {
    json!({
        "redaction": ARGV_NOTE,
        "tree": tree,
        "processes": flatten_proc_rows(nodes, tree).into_iter().map(|(node, depth)| json!({
            "proc_uid": node.proc_uid,
            "pid": node.pid,
            "parent_uid": node.parent_uid,
            "depth": if tree { Some(depth) } else { None },
            "exe": node.exe_name,
            "argv": node.argv_redacted,
            "exit_code": node.exit_code,
            "redaction": ARGV_NOTE,
            "evidence": evidence_json(&node.evidence),
        })).collect::<Vec<_>>(),
    })
}

pub(crate) fn flows_table(rows: &[FlowItem]) -> Table {
    Table {
        headers: vec![
            "local_port".to_owned(),
            "remote_port".to_owned(),
            "ip".to_owned(),
            "domain".to_owned(),
            "domain_source".to_owned(),
            "domain_evidence".to_owned(),
            "up".to_owned(),
            "down".to_owned(),
            "proc".to_owned(),
            "n".to_owned(),
        ],
        rows: rows
            .iter()
            .map(|row| Row {
                cells: vec![
                    opt_i64(row.local_port),
                    opt_i64(row.remote_port),
                    opt_text(row.remote_ip.as_deref()),
                    opt_text(row.domain.as_deref()),
                    opt_text(row.domain_source.as_deref()),
                    domain_evidence_cell(row),
                    opt_i64(row.bytes_up),
                    opt_i64(row.bytes_down),
                    opt_i64(row.proc_uid),
                    row.count.to_string(),
                ],
                evidence: evidence_or_na(row.evidence.as_ref()),
            })
            .collect(),
    }
}

fn domain_evidence_cell(row: &FlowItem) -> String {
    match &row.domain_evidence {
        Some(evidence) => output::evidence_badge(evidence).to_owned(),
        None => "不可得".to_owned(),
    }
}

pub(crate) fn flows_json(rows: &[FlowItem]) -> Value {
    let bytes_up = fold_side(rows, |row| row.bytes_up);
    let bytes_down = fold_side(rows, |row| row.bytes_down);
    json!({
        "bytes_up": bytes_up,
        "bytes_down": bytes_down,
        "bytes_total": super::query::add_opt(bytes_up, bytes_down),
        "flows": rows.iter().map(|row| json!({
            "id": row.id,
            "proc_uid": row.proc_uid,
            "local_port": row.local_port,
            "remote_port": row.remote_port,
            "remote_ip": row.remote_ip,
            "domain": row.domain,
            "domain_source": row.domain_source,
            "domain_evidence": row.domain_evidence.as_ref().map(evidence_json),
            "bytes_up": row.bytes_up,
            "bytes_down": row.bytes_down,
            "count": row.count,
            "evidence": row.evidence.as_ref().map(evidence_json),
        })).collect::<Vec<_>>(),
    })
}

fn fold_side(rows: &[FlowItem], pick: impl Fn(&FlowItem) -> Option<i64>) -> Option<i64> {
    let mut acc = None;
    for row in rows {
        acc = super::query::add_opt(acc, pick(row));
    }
    acc
}

pub(crate) fn gaps_table(rows: &[GapItem]) -> Table {
    Table {
        headers: vec![
            "id".to_owned(),
            "collector".to_owned(),
            "kind".to_owned(),
            "affects".to_owned(),
            "from_ns".to_owned(),
            "to_ns".to_owned(),
            "count".to_owned(),
            "detail".to_owned(),
        ],
        rows: rows
            .iter()
            .map(|row| Row {
                cells: vec![
                    row.id.to_string(),
                    row.collector.clone(),
                    row.kind.clone(),
                    row.affects.clone(),
                    row.from_ns.to_string(),
                    row.to_ns.to_string(),
                    opt_i64(row.count),
                    opt_text(row.detail.as_deref()),
                ],
                evidence: row.evidence.clone(),
            })
            .collect(),
    }
}

pub(crate) fn gaps_json(rows: &[GapItem]) -> Value {
    json!({
        "gaps": rows.iter().map(|row| json!({
            "id": row.id,
            "collector": row.collector,
            "kind": row.kind,
            "affects": row.affects,
            "from_ns": row.from_ns,
            "to_ns": row.to_ns,
            "count": row.count,
            "detail": row.detail,
            "evidence": evidence_json(&row.evidence),
        })).collect::<Vec<_>>(),
    })
}

/// One-line confirmation for a mutation (`rename`, `pin`, `delete`).
pub(crate) fn mutation_json(action: &str, detail: &Value) -> Value {
    json!({ "action": action, "result": detail })
}

/// Byte cell for a file row. `None` is `n/a`, never `0` (P2-CLI-01).
///
/// A counted zero is still `0`: the API sent a number. Missing is the only
/// case that becomes `n/a`.
#[must_use]
pub(crate) fn bytes_cell(value: Option<i64>) -> String {
    match value {
        Some(n) => n.to_string(),
        None => "n/a".to_owned(),
    }
}

/// File rows. A sensitive hit is wrapped in ANSI bold only when `color` is set.
pub(crate) fn files_table(rows: &[FileItem], color: bool) -> Table {
    Table {
        headers: vec![
            "time".to_owned(),
            "proc".to_owned(),
            "op".to_owned(),
            "path".to_owned(),
            "opens".to_owned(),
            "read".to_owned(),
            "write".to_owned(),
            "sensitive".to_owned(),
        ],
        rows: rows
            .iter()
            .map(|row| {
                let path = highlight_sensitive(&row.path, row.sensitive_rule.is_some(), color);
                Row {
                    cells: vec![
                        row.first_ns.to_string(),
                        proc_cell(row),
                        row.op.clone(),
                        path,
                        opt_i64(row.opens),
                        bytes_cell(row.bytes_read),
                        bytes_cell(row.bytes_written),
                        opt_text(row.sensitive_rule.as_deref()),
                    ],
                    evidence: evidence_or_na(row.evidence.as_ref()),
                }
            })
            .collect(),
    }
}

fn proc_cell(row: &FileItem) -> String {
    match (&row.proc_exe, row.proc_pid, row.proc_uid) {
        (Some(exe), Some(pid), _) => format!("{exe} {pid}"),
        (Some(exe), None, _) => exe.clone(),
        (None, _, Some(uid)) => uid.to_string(),
        (None, _, None) => "不可得".to_owned(),
    }
}

/// ANSI bold around `text` when the row hit a sensitive-path rule and the
/// caller asked for color. A non-TTY caller passes `color = false` and gets
/// the path unchanged.
fn highlight_sensitive(text: &str, sensitive: bool, color: bool) -> String {
    if sensitive && color {
        format!("\u{1b}[1m{text}\u{1b}[0m")
    } else {
        text.to_owned()
    }
}

pub(crate) fn files_json(rows: &[FileItem]) -> Value {
    json!({
        "files": rows.iter().map(|row| json!({
            "id": row.id,
            "proc_uid": row.proc_uid,
            "proc": {
                "pid": row.proc_pid,
                "exe_name": row.proc_exe,
            },
            "op": row.op,
            "path": row.path,
            "path_to": row.path_to,
            "dir": row.dir,
            "access": row.access,
            "first_ns": row.first_ns,
            "opens": row.opens,
            "bytes_read": row.bytes_read,
            "bytes_written": row.bytes_written,
            "result": row.result,
            "sensitive_rule": row.sensitive_rule,
            "na_reason": row.na_reason,
            "count": row.count,
            "evidence": row.evidence.as_ref().map(evidence_json),
        })).collect::<Vec<_>>(),
    })
}

/// Neighbours of one record. The anchor row is marked in the `anchor` column.
pub(crate) fn around_table(rows: &[AroundItem], color: bool) -> Table {
    Table {
        headers: vec![
            "time".to_owned(),
            "ref".to_owned(),
            "table".to_owned(),
            "summary".to_owned(),
            "anchor".to_owned(),
        ],
        rows: rows
            .iter()
            .map(|row| {
                let summary = if row.is_gap {
                    format!("{} {}", super::query::gap_marker(color), row.summary)
                } else {
                    highlight_sensitive(&row.summary, row.sensitive_rule.is_some(), color)
                };
                Row {
                    cells: vec![
                        row.ts_ns.to_string(),
                        row.reference.clone(),
                        row.table.clone(),
                        summary,
                        if row.anchor { "yes" } else { "no" }.to_owned(),
                    ],
                    evidence: row.evidence.clone(),
                }
            })
            .collect(),
    }
}

pub(crate) fn around_json(rows: &[AroundItem]) -> Value {
    json!({
        "events": rows.iter().map(|row| json!({
            "ref": row.reference,
            "ts_ns": row.ts_ns,
            "table": row.table,
            "summary": row.summary,
            "anchor": row.anchor,
            "gap": row.is_gap,
            "sensitive_rule": row.sensitive_rule,
            "evidence": evidence_json(&row.evidence),
        })).collect::<Vec<_>>(),
    })
}

/// Cross-session hits. Grouping by session is the caller's job; this prints
/// one row per hit so `--json` length is the hit count.
pub(crate) fn search_table(rows: &[SearchHit], color: bool) -> Table {
    Table {
        headers: vec![
            "session".to_owned(),
            "kind".to_owned(),
            "time".to_owned(),
            "ref".to_owned(),
            "summary".to_owned(),
        ],
        rows: rows
            .iter()
            .map(|row| Row {
                cells: vec![
                    row.session.clone(),
                    row.kind.clone(),
                    opt_i64(row.ts_ns),
                    row.reference.clone(),
                    highlight_sensitive(&row.summary, row.sensitive_rule.is_some(), color),
                ],
                evidence: row.evidence.clone(),
            })
            .collect(),
    }
}

pub(crate) fn search_json(rows: &[SearchHit]) -> Value {
    json!({
        "hits": rows.iter().map(|row| json!({
            "session": row.session,
            "session_name": row.session_name,
            "kind": row.kind,
            "ref": row.reference,
            "ts_ns": row.ts_ns,
            "summary": row.summary,
            "sensitive_rule": row.sensitive_rule,
            "evidence": evidence_json(&row.evidence),
        })).collect::<Vec<_>>(),
    })
}
