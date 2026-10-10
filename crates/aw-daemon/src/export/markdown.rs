//! Markdown session report (P3-DAEMON-01).
//!
//! The finished document is passed to [`aw_pipeline::wording::lint`] before any
//! byte is returned. A hit fails the export and returns the violation list.
//! The report body is not included in that error.
//!
//! `evidence.content_match` sentences are the one lint exception
//! ([`aw_pipeline::wording::RuleId::ContentMatchPhrase`]). They are scanned
//! with that rule allowed, then omitted from the document scan. Every other
//! paragraph is scanned with no allow-list.
//!
//! Prose does not say a session is safe, risk-free, or that a file was
//! uploaded or leaked. A NULL column is 「不可得」 plus a reason, never `0`
//! and never an empty string standing in for unknown.
//!
//! The SELECT for the session header, gaps, top domains, and top files is in
//! this file because `aw-store` has no findings reader and its flow/file
//! helpers do not return the columns this report prints. Those statements
//! filter `sessions.user_id`. They do not select `argv`, `cwd`, or `stats`.

use std::collections::BTreeMap;

use aw_pipeline::wording::{lint, lint_allowing, Lang, RuleId, Violation};
use aw_store::{redact_host_field, redact_user_paths, session_summary, SessionSummary, Store};

use crate::api::share::{
    error_response, findings_for_report, flag_on, json_response, open_owned, parse_lang,
    query_pairs, ApiResponse, ApiState, Caller, FindingView,
};

/// `GET` or `POST /sessions/{sid}/export?format=md`.
///
/// Other formats are not handled here. The caller leaves them on the 501 path.
pub(crate) fn export_markdown(
    state: &ApiState,
    caller: &Caller,
    sid: &str,
    query: &str,
) -> ApiResponse {
    let pairs = query_pairs(query);
    let lang = match parse_lang(pairs.get("lang").map(String::as_str)) {
        Ok(lang) => lang,
        Err(response) => return response,
    };
    let redact_paths = flag_on(pairs.get("redact_paths").map(String::as_str));
    let redact_hosts = flag_on(pairs.get("redact_hosts").map(String::as_str));
    // `tz`: the reader's offset from UTC in minutes (the page sends it), so
    // times read in their own clock. Absent or invalid: UTC, labelled so.
    let tz = parse_tz(pairs.get("tz").map(String::as_str));

    let opened = match open_owned(state, &caller.user_id, sid) {
        Ok(Some(pair)) => pair,
        Ok(None) => return error_response(404, "not_found", "session not found"),
        Err(response) => return response,
    };
    let (store, session_id) = opened;
    match build_report(
        &store,
        session_id,
        &caller.user_id,
        Reader { lang, tz },
        redact_paths,
        redact_hosts,
    ) {
        Ok(markdown) => markdown_response(markdown, sid),
        Err(ReportError::Store(message)) => error_response(500, "store", &message),
        Err(ReportError::Lint(violations)) => lint_response(&violations),
    }
}

#[derive(Debug)]
enum ReportError {
    Store(String),
    Lint(Vec<Violation>),
}

/// Who reads the report: language and UTC offset (minutes).
#[derive(Debug, Clone, Copy)]
struct Reader {
    lang: Lang,
    tz: i32,
}

/// `tz` query value: minutes east of UTC, within ±14 h. Anything else is UTC.
fn parse_tz(raw: Option<&str>) -> i32 {
    raw.and_then(|text| text.trim().parse::<i32>().ok())
        .filter(|minutes| minutes.abs() <= 14 * 60)
        .unwrap_or(0)
}

/// `2026-10-10 21:15:03 (UTC+08:00)` for Unix nanoseconds at `tz` minutes.
fn local_time(ns: i64, tz: i32) -> String {
    let secs = ns.div_euclid(1_000_000_000) + i64::from(tz) * 60;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let sign = if tz < 0 { '-' } else { '+' };
    let off = tz.unsigned_abs();
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} (UTC{sign}{:02}:{:02})",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        off / 60,
        off % 60
    )
}

/// `6s`, `1m 05s`, `2h 03m`.
fn duration_text(ns: i64) -> String {
    let secs = ns.max(0) / 1_000_000_000;
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

/// The session's display name, as the session list shows it: the name, else
/// the command (`argv`, redacted when stored), else nothing.
fn session_label(summary: &SessionSummary) -> Option<String> {
    if let Some(name) = summary
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
    {
        return Some(name.to_owned());
    }
    let argv: Vec<String> = summary
        .argv
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();
    let command = argv.join(" ");
    let command = command.trim();
    (!command.is_empty()).then(|| command.to_owned())
}

fn build_report(
    store: &Store,
    session_id: i64,
    user_id: &str,
    reader: Reader,
    redact_paths: bool,
    redact_hosts: bool,
) -> Result<String, ReportError> {
    let lang = reader.lang;
    let conn = store.connection();
    let summary = session_summary(conn, user_id, session_id)
        .map_err(|err| ReportError::Store(err.to_string()))?
        .ok_or_else(|| ReportError::Store("session not found".to_owned()))?;
    let header = load_header(conn, session_id, user_id)?;
    // A database whose http/findings migration never ran has no `findings`
    // table: no rule has written anything, so the section is empty. Any other
    // error is still a 500.
    let findings = if table_exists(conn, "findings") {
        findings_for_report(conn, session_id, user_id, lang).map_err(ReportError::Store)?
    } else {
        Vec::new()
    };
    let gaps = load_gaps(conn, session_id, user_id)?;
    let domains = load_domains(conn, session_id, user_id, redact_hosts)?;
    // Same for `file_access` (migration 0003): absent means no file rows.
    let files = if table_exists(conn, "file_access") {
        load_files(conn, session_id, user_id, redact_paths)?
    } else {
        Vec::new()
    };

    let mut prose = String::new();
    push_overview(&mut prose, &summary, &header, reader);
    push_capabilities(&mut prose, &header, lang);
    push_gaps(&mut prose, &gaps, lang);
    let match_sentences = push_findings(&mut prose, &findings, lang)?;
    push_domains(&mut prose, &domains, lang);
    push_files(&mut prose, &files, lang);
    push_evidence_footer(&mut prose, lang);

    let mut hits = lint(&prose);
    for sentence in &match_sentences {
        hits.extend(lint_allowing(sentence, &[RuleId::ContentMatchPhrase]));
    }
    if !hits.is_empty() {
        return Err(ReportError::Lint(hits));
    }

    let mut out = prose;
    if !match_sentences.is_empty() {
        out.push_str(if lang == Lang::En {
            "\n## Content match\n\n"
        } else {
            "\n## 内容匹配\n\n"
        });
        for sentence in &match_sentences {
            out.push_str("- ");
            out.push_str(sentence);
            out.push('\n');
        }
    }
    Ok(out)
}

struct HeaderBits {
    mode: String,
    platform: Option<String>,
    os_version: Option<String>,
    collectors: Option<String>,
    collector_profile: Option<String>,
    proxy_enabled: Option<i64>,
}

fn load_header(
    conn: &rusqlite::Connection,
    session_id: i64,
    user_id: &str,
) -> Result<HeaderBits, ReportError> {
    // argv, cwd, and stats are not selected.
    conn.query_row(
        "SELECT mode, platform, os_version, collectors, collector_profile, proxy_enabled \
         FROM sessions WHERE id = ?1 AND user_id = ?2",
        rusqlite::params![session_id, user_id],
        |row| {
            Ok(HeaderBits {
                mode: row.get(0)?,
                platform: row.get(1)?,
                os_version: row.get(2)?,
                collectors: row.get(3)?,
                collector_profile: row.get(4)?,
                proxy_enabled: row.get(5)?,
            })
        },
    )
    .map_err(|err| ReportError::Store(err.to_string()))
}

fn table_exists(conn: &rusqlite::Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get::<_, bool>(0),
    )
    .unwrap_or(false)
}

struct GapLine {
    collector: String,
    kind: String,
    count: Option<i64>,
    reason: Option<String>,
}

fn load_gaps(
    conn: &rusqlite::Connection,
    session_id: i64,
    user_id: &str,
) -> Result<Vec<GapLine>, ReportError> {
    let mut stmt = conn
        .prepare(
            "SELECT collector, kind, count, detail FROM gaps \
             WHERE session_id = ?1 \
               AND EXISTS ( \
                 SELECT 1 FROM sessions s \
                 WHERE s.id = gaps.session_id AND s.user_id = ?2) \
             ORDER BY from_ns, id LIMIT 50",
        )
        .map_err(|err| ReportError::Store(err.to_string()))?;
    let mut rows = stmt
        .query(rusqlite::params![session_id, user_id])
        .map_err(|err| ReportError::Store(err.to_string()))?;
    let mut out = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| ReportError::Store(err.to_string()))?
    {
        out.push(GapLine {
            collector: row
                .get(0)
                .map_err(|err| ReportError::Store(err.to_string()))?,
            kind: row
                .get(1)
                .map_err(|err| ReportError::Store(err.to_string()))?,
            count: row
                .get(2)
                .map_err(|err| ReportError::Store(err.to_string()))?,
            reason: row
                .get(3)
                .map_err(|err| ReportError::Store(err.to_string()))?,
        });
    }
    Ok(out)
}

struct DomainLine {
    domain: Option<String>,
    flows: i64,
    bytes_up: Option<i64>,
    bytes_down: Option<i64>,
}

fn load_domains(
    conn: &rusqlite::Connection,
    session_id: i64,
    user_id: &str,
    redact_hosts: bool,
) -> Result<Vec<DomainLine>, ReportError> {
    let mut stmt = conn
        .prepare(
            "SELECT domain, COUNT(*), SUM(bytes_up), SUM(bytes_down) \
             FROM net_flows \
             WHERE session_id = ?1 \
               AND EXISTS ( \
                 SELECT 1 FROM sessions s \
                 WHERE s.id = net_flows.session_id AND s.user_id = ?2) \
             GROUP BY domain \
             ORDER BY COUNT(*) DESC \
             LIMIT 10",
        )
        .map_err(|err| ReportError::Store(err.to_string()))?;
    let mut rows = stmt
        .query(rusqlite::params![session_id, user_id])
        .map_err(|err| ReportError::Store(err.to_string()))?;
    let mut out = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| ReportError::Store(err.to_string()))?
    {
        let mut domain: Option<String> = row
            .get(0)
            .map_err(|err| ReportError::Store(err.to_string()))?;
        if redact_hosts {
            domain = domain.map(|name| redact_host_field(&name));
        }
        out.push(DomainLine {
            domain,
            flows: row
                .get(1)
                .map_err(|err| ReportError::Store(err.to_string()))?,
            bytes_up: row
                .get(2)
                .map_err(|err| ReportError::Store(err.to_string()))?,
            bytes_down: row
                .get(3)
                .map_err(|err| ReportError::Store(err.to_string()))?,
        });
    }
    Ok(out)
}

struct FileLine {
    path: String,
    op: String,
    hits: i64,
}

fn load_files(
    conn: &rusqlite::Connection,
    session_id: i64,
    user_id: &str,
    redact_paths: bool,
) -> Result<Vec<FileLine>, ReportError> {
    let mut stmt = conn
        .prepare(
            "SELECT path, op, COUNT(*) FROM file_access \
             WHERE session_id = ?1 \
               AND EXISTS ( \
                 SELECT 1 FROM sessions s \
                 WHERE s.id = file_access.session_id AND s.user_id = ?2) \
             GROUP BY path, op \
             ORDER BY COUNT(*) DESC \
             LIMIT 10",
        )
        .map_err(|err| ReportError::Store(err.to_string()))?;
    let mut rows = stmt
        .query(rusqlite::params![session_id, user_id])
        .map_err(|err| ReportError::Store(err.to_string()))?;
    let mut out = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|err| ReportError::Store(err.to_string()))?
    {
        let mut path: String = row
            .get(0)
            .map_err(|err| ReportError::Store(err.to_string()))?;
        if redact_paths {
            path = redact_user_paths(&path);
        }
        out.push(FileLine {
            path,
            op: row
                .get(1)
                .map_err(|err| ReportError::Store(err.to_string()))?,
            hits: row
                .get(2)
                .map_err(|err| ReportError::Store(err.to_string()))?,
        });
    }
    Ok(out)
}

fn push_overview(out: &mut String, summary: &SessionSummary, header: &HeaderBits, reader: Reader) {
    let lang = reader.lang;
    let label = session_label(summary);
    let started = local_time(summary.started_ns, reader.tz);
    let ended = summary.ended_ns.map(|ns| local_time(ns, reader.tz));
    let duration = summary
        .ended_ns
        .map(|ns| duration_text(ns.saturating_sub(summary.started_ns)));
    if lang == Lang::En {
        out.push_str("# Session report\n\n");
        out.push_str("This report lists what was recorded. It does not judge the session.\n\n");
        out.push_str("## Session\n\n");
        en_line(out, "Session ID", Some(summary.public_id.as_str()));
        en_line(out, "Name", label.as_deref());
        en_line(out, "Agent", summary.agent.as_deref());
        en_line(out, "Source", Some(mode_en(&header.mode).as_str()));
        en_line(out, "Platform", header.platform.as_deref());
        en_line(out, "OS version", header.os_version.as_deref());
        out.push_str(&format!("- Started: {started}\n"));
        match (&ended, &duration) {
            (Some(at), Some(took)) => {
                out.push_str(&format!("- Ended: {at}\n"));
                out.push_str(&format!("- Duration: {took}\n"));
            }
            _ => out.push_str("- Ended: not yet (still recording, or no end time was recorded)\n"),
        }
        out.push_str(&format!("- Process records: {}\n", summary.process_count));
        out.push_str(&format!("- Network flow records: {}\n", summary.flow_count));
        out.push_str(&format!("- DNS records: {}\n", summary.dns_count));
        out.push_str(&format!("- Gap records: {}\n", summary.gap_count));
        byte_line(
            out,
            "Bytes up",
            summary.bytes_up,
            "no network flow recorded bytes sent",
        );
        byte_line(
            out,
            "Bytes down",
            summary.bytes_down,
            "no network flow recorded bytes received",
        );
        proxy_line(out, header.proxy_enabled, false);
    } else {
        out.push_str("# 会话报告\n\n");
        out.push_str("本报告只列出已记录的内容，不对会话下结论。\n\n");
        out.push_str("## 会话\n\n");
        zh_line(out, "会话编号", Some(summary.public_id.as_str()));
        zh_line(out, "名称", label.as_deref());
        zh_line(out, "智能体", summary.agent.as_deref());
        zh_line(out, "来源", Some(mode_zh(&header.mode).as_str()));
        zh_line(out, "平台", header.platform.as_deref());
        zh_line(out, "系统版本", header.os_version.as_deref());
        out.push_str(&format!("- 开始：{started}\n"));
        match (&ended, &duration) {
            (Some(at), Some(took)) => {
                out.push_str(&format!("- 结束：{at}\n"));
                out.push_str(&format!("- 时长：{took}\n"));
            }
            _ => out.push_str("- 结束：还没有（仍在录制，或没有记录结束时间）\n"),
        }
        out.push_str(&format!("- 进程记录：{}\n", summary.process_count));
        out.push_str(&format!("- 网络流记录：{}\n", summary.flow_count));
        out.push_str(&format!("- DNS 记录：{}\n", summary.dns_count));
        out.push_str(&format!("- 缺口记录：{}\n", summary.gap_count));
        zh_byte(
            out,
            "上行字节",
            summary.bytes_up,
            "每条网络流都没有记录上行字节数",
        );
        zh_byte(
            out,
            "下行字节",
            summary.bytes_down,
            "每条网络流都没有记录下行字节数",
        );
        proxy_line(out, header.proxy_enabled, true);
    }
    out.push('\n');
}

fn push_capabilities(out: &mut String, header: &HeaderBits, lang: Lang) {
    let collectors = collectors_text(header.collectors.as_deref(), lang);
    if lang == Lang::En {
        out.push_str("## Collectors\n\n");
        en_line(out, "Profile", header.collector_profile.as_deref());
        en_line(out, "Collectors", collectors.as_deref());
    } else {
        out.push_str("## 采集能力\n\n");
        zh_line(out, "配置", header.collector_profile.as_deref());
        zh_line(out, "采集器", collectors.as_deref());
    }
    out.push('\n');
}

/// `launch` / `attach` become a reader-facing word; anything else stays as stored.
fn mode_zh(mode: &str) -> String {
    match mode {
        "launch" => "启动".to_owned(),
        "attach" => "附着".to_owned(),
        other => other.to_owned(),
    }
}

fn mode_en(mode: &str) -> String {
    match mode {
        "launch" => "Launch".to_owned(),
        "attach" => "Attach".to_owned(),
        other => other.to_owned(),
    }
}

/// Collector list as stored: a JSON array (`["poll"]`), plain text, or NULL.
/// Known names are translated and joined; an unknown name stays as stored.
fn collectors_text(raw: Option<&str>, lang: Lang) -> Option<String> {
    let raw = raw.map(str::trim).filter(|text| !text.is_empty())?;
    let names = collector_names(raw);
    if names.is_empty() {
        return None;
    }
    let sep = if lang == Lang::En { ", " } else { "、" };
    Some(
        names
            .iter()
            .map(|name| collector_name(name, lang))
            .collect::<Vec<_>>()
            .join(sep),
    )
}

/// JSON array of names when the column is one — each item a string or an
/// object with a `name` field (`{"name":"poll","mode":"poll"}`); otherwise
/// the text itself.
fn collector_names(raw: &str) -> Vec<String> {
    if let Ok(list) = serde_json::from_str::<Vec<serde_json::Value>>(raw) {
        let names: Vec<String> = list.iter().filter_map(collector_item_name).collect();
        if !names.is_empty() {
            return names;
        }
    }
    vec![raw.to_owned()]
}

fn collector_item_name(item: &serde_json::Value) -> Option<String> {
    let name = match item {
        serde_json::Value::String(name) => name.as_str(),
        serde_json::Value::Object(object) => object.get("name")?.as_str()?,
        _ => return None,
    };
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

fn collector_name(name: &str, lang: Lang) -> String {
    if lang == Lang::En {
        match name {
            "poll" => "process polling",
            "ebpf" => "eBPF kernel collector",
            "etw" => "ETW events",
            "esf" => "EndpointSecurity",
            "fanotify" => "file watching",
            "proxy" => "proxy",
            "dns" => "DNS",
            other => return other.to_owned(),
        }
        .to_owned()
    } else {
        match name {
            "poll" => "进程轮询",
            "ebpf" => "eBPF 内核采集",
            "etw" => "ETW 事件采集",
            "esf" => "EndpointSecurity 采集",
            "fanotify" => "文件监视",
            "proxy" => "代理",
            "dns" => "DNS",
            other => return other.to_owned(),
        }
        .to_owned()
    }
}

fn push_gaps(out: &mut String, gaps: &[GapLine], lang: Lang) {
    if lang == Lang::En {
        out.push_str("## Gaps\n\n");
        if gaps.is_empty() {
            out.push_str("No gap rows were stored for this session.\n\n");
            return;
        }
    } else {
        out.push_str("## 缺口\n\n");
        if gaps.is_empty() {
            out.push_str("此会话没有记录缺口行。\n\n");
            return;
        }
    }
    for gap in gaps {
        let count = match gap.count {
            Some(n) => n.to_string(),
            None => {
                if lang == Lang::En {
                    "unavailable (count was not recorded)".to_owned()
                } else {
                    "不可得（未记录条数）".to_owned()
                }
            }
        };
        let reason = gap.reason.as_deref().filter(|text| !text.is_empty());
        let collector = collector_name(&gap.collector, lang);
        let kind = gap_kind(&gap.kind, lang);
        let sep = if lang == Lang::En { ": " } else { "：" };
        out.push_str(&format!("- {collector} / {kind}{sep}{count}"));
        match reason {
            Some(text) => out.push_str(&format!(" ({text})\n")),
            None => {
                if lang == Lang::En {
                    out.push_str(" (reason unavailable)\n");
                } else {
                    out.push_str("（原因不可得）\n");
                }
            }
        }
    }
    out.push('\n');
}

fn push_findings(
    out: &mut String,
    findings: &[FindingView],
    lang: Lang,
) -> Result<Vec<String>, ReportError> {
    let mut grouped: BTreeMap<&str, Vec<&FindingView>> = BTreeMap::new();
    let mut matches = Vec::new();
    for finding in findings {
        if finding.kind == "content_match" || finding.wording_id == "evidence.content_match" {
            match finding.text.clone() {
                Some(text) => matches.push(text),
                None => matches.push(unavailable_render(finding, lang)),
            }
            continue;
        }
        grouped
            .entry(finding.evidence.as_str())
            .or_default()
            .push(finding);
    }
    if lang == Lang::En {
        out.push_str("## Findings\n\n");
        out.push_str(
            "Grouped by the evidence label stored on the row. A label is not a conclusion.\n\n",
        );
    } else {
        out.push_str("## 发现\n\n");
        out.push_str("按记录上的证据等级分组。等级不是结论。\n\n");
    }
    if grouped.is_empty() {
        if lang == Lang::En {
            out.push_str("No finding rows outside content match.\n\n");
        } else {
            out.push_str("除内容匹配外没有发现行。\n\n");
        }
    }
    for (evidence, rows) in &grouped {
        out.push_str(&format!("### {evidence}\n\n"));
        for row in rows {
            let sentence = row
                .text
                .clone()
                .unwrap_or_else(|| unavailable_render(row, lang));
            out.push_str(&format!("- [{sev}] {sentence}\n", sev = row.severity));
        }
        out.push('\n');
    }
    Ok(matches)
}

fn unavailable_render(finding: &FindingView, lang: Lang) -> String {
    let reason = finding
        .error
        .as_deref()
        .filter(|text| !text.is_empty())
        .unwrap_or("render failed");
    if lang == Lang::En {
        format!(
            "unavailable (sentence `{id}` did not render: {reason})",
            id = finding.wording_id
        )
    } else {
        format!(
            "不可得（句子 `{id}` 未能生成：{reason}）",
            id = finding.wording_id
        )
    }
}

fn push_domains(out: &mut String, domains: &[DomainLine], lang: Lang) {
    if lang == Lang::En {
        out.push_str("## Top domains\n\n");
        if domains.is_empty() {
            out.push_str("No flow rows, so there is no domain list.\n\n");
            return;
        }
    } else {
        out.push_str("## 域名（按流记录条数）\n\n");
        if domains.is_empty() {
            out.push_str("没有流记录，因此没有域名列表。\n\n");
            return;
        }
    }
    for row in domains {
        let name = match row.domain.as_deref().filter(|text| !text.is_empty()) {
            Some(name) => name.to_owned(),
            None => {
                if lang == Lang::En {
                    "unavailable (domain was not recorded)".to_owned()
                } else {
                    "不可得（未记录域名）".to_owned()
                }
            }
        };
        let up = opt_num(row.bytes_up, lang);
        let down = opt_num(row.bytes_down, lang);
        if lang == Lang::En {
            out.push_str(&format!(
                "- {name}: {flows} flows, bytes up {up}, bytes down {down}\n",
                flows = row.flows
            ));
        } else {
            out.push_str(&format!(
                "- {name}：{flows} 条网络流，上行字节 {up}，下行字节 {down}\n",
                flows = row.flows
            ));
        }
    }
    out.push('\n');
}

fn push_files(out: &mut String, files: &[FileLine], lang: Lang) {
    if lang == Lang::En {
        out.push_str("## Top files\n\n");
        if files.is_empty() {
            out.push_str("No file-access rows, so there is no path list.\n\n");
            return;
        }
    } else {
        out.push_str("## 文件（按访问行数）\n\n");
        if files.is_empty() {
            out.push_str("没有文件访问行，因此没有路径列表。\n\n");
            return;
        }
    }
    for row in files {
        let path = if row.path.is_empty() {
            if lang == Lang::En {
                "unavailable (path was empty)".to_owned()
            } else {
                "不可得（路径为空）".to_owned()
            }
        } else {
            row.path.clone()
        };
        let op = file_op(&row.op, lang);
        if lang == Lang::En {
            out.push_str(&format!("- {path} ({op}): {hits} rows\n", hits = row.hits));
        } else {
            out.push_str(&format!("- {path}（{op}）：{hits} 行\n", hits = row.hits));
        }
    }
    out.push('\n');
}

fn push_evidence_footer(out: &mut String, lang: Lang) {
    if lang == Lang::En {
        out.push_str("## Evidence labels\n\n");
        out.push_str("- E1: observed by the operating system.\n");
        out.push_str("- E2: observed in a protocol the proxy decoded.\n");
        out.push_str("- E3: reported by the agent itself, not checked against the system.\n");
        out.push_str("- S: a sample, not every event in the window.\n");
        out.push_str("- I: an inference. Not a fact.\n");
        out.push_str("- NA: unavailable, with a reason on the field.\n");
        out.push_str("\nA label describes how a field was obtained. It is not a verdict.\n");
    } else {
        out.push_str("## 证据等级说明\n\n");
        out.push_str("- E1：操作系统观测到的。\n");
        out.push_str("- E2：代理解码到的协议字段。\n");
        out.push_str("- E3：代理进程自己报告的，没有与系统记录对照。\n");
        out.push_str("- S：采样，不是该时段的全部事件。\n");
        out.push_str("- I：推测。不是事实。\n");
        out.push_str("- NA：不可得，字段上带有原因。\n");
        out.push_str("\n等级只说明字段是怎么得到的，不是裁决。\n");
    }
}

fn en_line(out: &mut String, label: &str, value: Option<&str>) {
    field_line(out, label, ": ", value, "unavailable (not recorded)")
}

fn zh_line(out: &mut String, label: &str, value: Option<&str>) {
    field_line(out, label, "：", value, "不可得（未记录）")
}

fn field_line(out: &mut String, label: &str, sep: &str, value: Option<&str>, missing: &str) {
    match value.map(str::trim).filter(|text| !text.is_empty()) {
        Some(text) => out.push_str(&format!("- {label}{sep}{text}\n")),
        None => out.push_str(&format!("- {label}{sep}{missing}\n")),
    }
}

fn byte_line(out: &mut String, label: &str, value: Option<i64>, reason: &str) {
    match value {
        Some(n) => out.push_str(&format!("- {label}: {n}\n")),
        None => out.push_str(&format!("- {label}: unavailable ({reason})\n")),
    }
}

fn zh_byte(out: &mut String, label: &str, value: Option<i64>, reason: &str) {
    match value {
        Some(n) => out.push_str(&format!("- {label}：{n}\n")),
        None => out.push_str(&format!("- {label}：不可得（{reason}）\n")),
    }
}

/// Known file-access ops. An unknown op stays as stored.
fn file_op(op: &str, lang: Lang) -> String {
    if lang == Lang::En {
        return op.to_owned();
    }
    match op {
        "read" => "读取",
        "write" => "写入",
        "open" => "打开",
        "create" => "创建",
        "delete" | "unlink" => "删除",
        "rename" => "重命名",
        "exec" | "execute" => "执行",
        other => return other.to_owned(),
    }
    .to_owned()
}

/// Known gap kinds. An unknown kind stays as stored.
fn gap_kind(kind: &str, lang: Lang) -> String {
    if lang == Lang::En {
        return match kind {
            "overflow" => "overflow",
            "restart" => "restart",
            "permission" => "permission",
            "dropped" => "dropped",
            other => return other.to_owned(),
        }
        .to_owned();
    }
    match kind {
        "overflow" => "溢出",
        "restart" => "重启",
        "permission" => "权限不足",
        "dropped" => "丢弃",
        other => return other.to_owned(),
    }
    .to_owned()
}

fn proxy_line(out: &mut String, enabled: Option<i64>, zh: bool) {
    match enabled {
        Some(0) => {
            if zh {
                out.push_str("- 代理：未启用（没有 URL 记录）\n");
            } else {
                out.push_str("- Proxy: off (no URL rows)\n");
            }
        }
        Some(_) => {
            if zh {
                out.push_str("- 代理：已启用\n");
            } else {
                out.push_str("- Proxy: on\n");
            }
        }
        None => {
            if zh {
                out.push_str("- 代理：不可得（未记录是否启用）\n");
            } else {
                out.push_str("- Proxy: unavailable (not recorded)\n");
            }
        }
    }
}

fn opt_num(value: Option<i64>, lang: Lang) -> String {
    match value {
        Some(n) => n.to_string(),
        None => {
            if lang == Lang::En {
                "unavailable".to_owned()
            } else {
                "不可得".to_owned()
            }
        }
    }
}

/// Named like the JSONL/CSV exports (`agentwatch-<sid>.md`), not a fixed
/// `session.md` that every export overwrote.
fn markdown_response(body: String, sid: &str) -> ApiResponse {
    let mut headers = BTreeMap::new();
    headers.insert(
        "content-type".to_owned(),
        "text/markdown; charset=utf-8".to_owned(),
    );
    headers.insert(
        "content-disposition".to_owned(),
        format!(
            "attachment; filename=\"agentwatch-{}.md\"",
            super::data::safe_name(sid)
        ),
    );
    ApiResponse {
        status: 200,
        headers,
        body: body.into_bytes(),
    }
}

fn lint_response(violations: &[Violation]) -> ApiResponse {
    let items: Vec<serde_json::Value> = violations
        .iter()
        .map(|hit| {
            serde_json::json!({
                "rule": rule_name(hit.rule),
                "offset": hit.offset,
                "suggestion": hit.suggestion,
            })
        })
        .collect();
    json_response(
        422,
        &serde_json::json!({
            "error": {
                "code": "wording_lint",
                "message": "markdown export refused: wording lint reported violations",
                "violations": items,
            }
        }),
    )
}

fn rule_name(rule: RuleId) -> &'static str {
    match rule {
        RuleId::UploadedFile => "uploaded_file",
        RuleId::Intent => "intent",
        RuleId::BareEvilDomain => "bare_evil_domain",
        RuleId::AgentRead => "agent_read",
        RuleId::UnprovableNegative => "unprovable_negative",
        RuleId::ZeroBytes => "zero_bytes",
        RuleId::AllTraffic => "all_traffic",
        RuleId::InstructedSteal => "instructed_steal",
        RuleId::UploadedVia => "uploaded_via",
        RuleId::ContentMatchPhrase => "content_match_phrase",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_report, collectors_text, duration_text, load_gaps, local_time, markdown_response,
        parse_tz, Reader,
    };
    use aw_pipeline::wording::Lang;

    /// Test-bot #144: the report said 「名称: 不可得（未记录）」 while the list
    /// showed `sleep 9`, and times were raw `started_ns`.
    #[test]
    fn report_names_an_unnamed_session_by_its_command_and_shows_local_times() {
        let dir = std::env::temp_dir().join(format!(
            "aw-md-label-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        assert!(std::fs::create_dir_all(&dir).is_ok());
        let Ok(store) = aw_store::Store::open(dir.join("t.db")) else {
            panic!("store");
        };
        let inserted = store.connection().execute(
            "INSERT INTO sessions (id, public_id, name, mode, started_ns, ended_ns, platform, user_id, collectors, argv) \
             VALUES (1, 's-1', NULL, 'launch', 1791638103000000000, 1791638112000000000, 'linux', 'u', '[\"poll\"]', '[\"sleep\",\"9\"]')",
            [],
        );
        assert!(inserted.is_ok(), "{inserted:?}");
        let zh = build_report(
            &store,
            1,
            "u",
            Reader {
                lang: Lang::Zh,
                tz: 480,
            },
            false,
            false,
        );
        let zh = zh.unwrap_or_else(|err| panic!("{err:?}"));
        assert!(zh.contains("- 名称：sleep 9\n"), "{zh}");
        assert!(
            zh.contains("- 开始：2026-10-10 21:15:03 (UTC+08:00)\n"),
            "{zh}"
        );
        assert!(
            zh.contains("- 结束：2026-10-10 21:15:12 (UTC+08:00)\n"),
            "{zh}"
        );
        assert!(zh.contains("- 时长：9s\n"), "{zh}");
        assert!(zh.contains("- 来源：启动\n"), "{zh}");
        assert!(zh.contains("- 采集器：进程轮询\n"), "{zh}");
        assert!(!zh.contains("started_ns"), "{zh}");
        assert!(!zh.contains("[\"poll\"]"), "{zh}");
        assert!(!zh.contains("launch"), "{zh}");
        assert!(!zh.contains("public id"), "{zh}");
        assert!(!zh.contains("bytes_up"), "{zh}");
        let en = build_report(
            &store,
            1,
            "u",
            Reader {
                lang: Lang::En,
                tz: 0,
            },
            false,
            false,
        );
        let en = en.unwrap_or_else(|err| panic!("{err:?}"));
        assert!(en.contains("- Name: sleep 9\n"), "{en}");
        assert!(
            en.contains("- Started: 2026-10-10 13:15:03 (UTC+00:00)\n"),
            "{en}"
        );
        assert!(en.contains("- Source: Launch\n"), "{en}");
        assert!(en.contains("- Collectors: process polling\n"), "{en}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collectors_text_reads_name_from_object_items() {
        assert_eq!(
            collectors_text(Some(r#"[{"name":"poll"}]"#), Lang::Zh),
            Some("进程轮询".into())
        );
    }

    #[test]
    fn report_times_are_local_date_times_not_raw_ns() {
        // 2026-10-10 13:15:03 UTC.
        let ns = 1_791_638_103_000_000_000;
        assert_eq!(local_time(ns, 0), "2026-10-10 13:15:03 (UTC+00:00)");
        assert_eq!(local_time(ns, 480), "2026-10-10 21:15:03 (UTC+08:00)");
        assert_eq!(local_time(ns, -420), "2026-10-10 06:15:03 (UTC-07:00)");
        assert_eq!(parse_tz(Some("480")), 480);
        assert_eq!(parse_tz(Some("9999")), 0);
        assert_eq!(parse_tz(None), 0);
        assert_eq!(duration_text(6_400_000_000), "6s");
        assert_eq!(duration_text(65_000_000_000), "1m 05s");
        assert_eq!(duration_text(7_380_000_000_000), "2h 03m");
    }

    #[test]
    fn markdown_file_is_named_after_the_session() {
        let response = markdown_response("# x".to_owned(), "s-1/../x");
        assert_eq!(
            response
                .headers
                .get("content-disposition")
                .map(String::as_str),
            Some("attachment; filename=\"agentwatch-s-1____x.md\"")
        );
    }

    #[test]
    fn gap_query_matches_the_migrated_schema() {
        // `gaps` has `detail`, not `reason`. The report query ran only against a
        // real database, so a wrong column was a 500 on every md export.
        let dir = std::env::temp_dir().join(format!(
            "aw-md-gaps-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        assert!(std::fs::create_dir_all(&dir).is_ok());
        let store = aw_store::Store::open(dir.join("t.db"));
        assert!(store.is_ok());
        if let Ok(store) = store {
            let rows = load_gaps(store.connection(), 1, "u");
            assert!(rows.is_ok());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
