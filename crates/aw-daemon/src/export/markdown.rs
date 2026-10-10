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
        lang,
        redact_paths,
        redact_hosts,
    ) {
        Ok(markdown) => markdown_response(markdown),
        Err(ReportError::Store(message)) => error_response(500, "store", &message),
        Err(ReportError::Lint(violations)) => lint_response(&violations),
    }
}

enum ReportError {
    Store(String),
    Lint(Vec<Violation>),
}

fn build_report(
    store: &Store,
    session_id: i64,
    user_id: &str,
    lang: Lang,
    redact_paths: bool,
    redact_hosts: bool,
) -> Result<String, ReportError> {
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
    push_overview(&mut prose, &summary, &header, lang);
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

fn push_overview(out: &mut String, summary: &SessionSummary, header: &HeaderBits, lang: Lang) {
    if lang == Lang::En {
        out.push_str("# Session report\n\n");
        out.push_str("This report lists what was recorded. It does not judge the session.\n\n");
        out.push_str("## Session\n\n");
        en_line(out, "public id", Some(summary.public_id.as_str()));
        en_line(out, "name", summary.name.as_deref());
        en_line(out, "agent", summary.agent.as_deref());
        en_line(out, "mode", Some(header.mode.as_str()));
        en_line(out, "platform", header.platform.as_deref());
        en_line(out, "os", header.os_version.as_deref());
        out.push_str(&format!("- started_ns: {}\n", summary.started_ns));
        match summary.ended_ns {
            Some(ns) => out.push_str(&format!("- ended_ns: {ns}\n")),
            None => out.push_str("- ended_ns: unavailable (session has no end timestamp)\n"),
        }
        out.push_str(&format!("- process rows: {}\n", summary.process_count));
        out.push_str(&format!("- flow rows: {}\n", summary.flow_count));
        out.push_str(&format!("- dns rows: {}\n", summary.dns_count));
        out.push_str(&format!("- gap rows: {}\n", summary.gap_count));
        byte_line(
            out,
            "bytes up",
            summary.bytes_up,
            "every flow left bytes_up unset",
        );
        byte_line(
            out,
            "bytes down",
            summary.bytes_down,
            "every flow left bytes_down unset",
        );
        proxy_line(out, header.proxy_enabled, false);
    } else {
        out.push_str("# 会话报告\n\n");
        out.push_str("本报告只列出已记录的内容，不对会话下结论。\n\n");
        out.push_str("## 会话\n\n");
        zh_line(out, "public id", Some(summary.public_id.as_str()));
        zh_line(out, "名称", summary.name.as_deref());
        zh_line(out, "agent", summary.agent.as_deref());
        zh_line(out, "模式", Some(header.mode.as_str()));
        zh_line(out, "平台", header.platform.as_deref());
        zh_line(out, "系统版本", header.os_version.as_deref());
        out.push_str(&format!("- started_ns: {}\n", summary.started_ns));
        match summary.ended_ns {
            Some(ns) => out.push_str(&format!("- ended_ns: {ns}\n")),
            None => out.push_str("- ended_ns: 不可得（会话没有结束时间）\n"),
        }
        out.push_str(&format!("- 进程行数: {}\n", summary.process_count));
        out.push_str(&format!("- 流记录行数: {}\n", summary.flow_count));
        out.push_str(&format!("- dns 行数: {}\n", summary.dns_count));
        out.push_str(&format!("- 缺口行数: {}\n", summary.gap_count));
        zh_byte(
            out,
            "上行字节",
            summary.bytes_up,
            "每条流的 bytes_up 都未记录",
        );
        zh_byte(
            out,
            "下行字节",
            summary.bytes_down,
            "每条流的 bytes_down 都未记录",
        );
        proxy_line(out, header.proxy_enabled, true);
    }
    out.push('\n');
}

fn push_capabilities(out: &mut String, header: &HeaderBits, lang: Lang) {
    if lang == Lang::En {
        out.push_str("## Collectors\n\n");
        en_line(out, "profile", header.collector_profile.as_deref());
        en_line(out, "collectors", header.collectors.as_deref());
    } else {
        out.push_str("## 采集能力\n\n");
        zh_line(out, "配置", header.collector_profile.as_deref());
        zh_line(out, "采集器", header.collectors.as_deref());
    }
    out.push('\n');
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
        out.push_str(&format!("- {} / {}: {count}", gap.collector, gap.kind));
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
            "unavailable (wording id `{id}` did not render: {reason})",
            id = finding.wording_id
        )
    } else {
        format!(
            "不可得（措辞 `{id}` 未能生成：{reason}）",
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
                "- {name}: {flows} 条流记录，上行字节 {up}，下行字节 {down}\n",
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
        if lang == Lang::En {
            out.push_str(&format!(
                "- {path} ({op}): {hits} rows\n",
                op = row.op,
                hits = row.hits
            ));
        } else {
            out.push_str(&format!(
                "- {path}（{op}）: {hits} 行\n",
                op = row.op,
                hits = row.hits
            ));
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
    field_line(out, label, value, "unavailable (not recorded)")
}

fn zh_line(out: &mut String, label: &str, value: Option<&str>) {
    field_line(out, label, value, "不可得（未记录）")
}

fn field_line(out: &mut String, label: &str, value: Option<&str>, missing: &str) {
    match value.map(str::trim).filter(|text| !text.is_empty()) {
        Some(text) => out.push_str(&format!("- {label}: {text}\n")),
        None => out.push_str(&format!("- {label}: {missing}\n")),
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
        Some(n) => out.push_str(&format!("- {label}: {n}\n")),
        None => out.push_str(&format!("- {label}: 不可得（{reason}）\n")),
    }
}

fn proxy_line(out: &mut String, enabled: Option<i64>, zh: bool) {
    match enabled {
        Some(0) => {
            if zh {
                out.push_str("- 代理: 未启用（没有 URL 记录）\n");
            } else {
                out.push_str("- proxy: off (no URL rows)\n");
            }
        }
        Some(_) => {
            if zh {
                out.push_str("- 代理: 已启用\n");
            } else {
                out.push_str("- proxy: on\n");
            }
        }
        None => {
            if zh {
                out.push_str("- 代理: 不可得（未记录是否启用）\n");
            } else {
                out.push_str("- proxy: unavailable (not recorded)\n");
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

fn markdown_response(body: String) -> ApiResponse {
    let mut headers = BTreeMap::new();
    headers.insert(
        "content-type".to_owned(),
        "text/markdown; charset=utf-8".to_owned(),
    );
    headers.insert(
        "content-disposition".to_owned(),
        "attachment; filename=\"session.md\"".to_owned(),
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
    use super::load_gaps;

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
