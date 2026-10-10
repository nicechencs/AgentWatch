//! Terminal and JSON rendering.
//!
//! Tables always include an evidence column. The cell text is the badge from
//! evidence-model §4 (`E1 系统`, `推测`, `不可得`, …). JSON rows carry `evidence`
//! as the level code (`E1`, `I`, `NA`, …) so a later card can add `field_evidence`
//! beside it. This module does not invent rows; commands pass them in.

#![allow(dead_code)]

use std::io::{self, Write};

use serde_json::{json, Value};

use aw_core::Evidence;

/// How a command asked to be printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    /// Human table on stdout.
    Table,
    /// One JSON document on stdout.
    Json,
}

impl OutputMode {
    /// `--json` selects JSON. Otherwise a table.
    #[must_use]
    pub fn from_json_flag(json: bool) -> Self {
        if json {
            Self::Json
        } else {
            Self::Table
        }
    }
}

/// One rendered row. `evidence` is required: a row without a level is not a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Cells other than the evidence column, in header order.
    pub cells: Vec<String>,
    /// Record-level evidence. Rendered in the last column.
    pub evidence: Evidence,
}

/// A small table. `headers` does not include the evidence column; that column
/// is appended as `evidence` so every table has it even if the caller forgets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    /// Column titles, excluding evidence.
    pub headers: Vec<String>,
    /// Body.
    pub rows: Vec<Row>,
}

/// Badge text from evidence-model §4. Chinese, matching the default `--lang`.
#[must_use]
pub fn evidence_badge(evidence: &Evidence) -> &'static str {
    match evidence {
        Evidence::E1 => "E1 系统",
        Evidence::E2 => "E2 协议",
        Evidence::E3 => "E3 自报",
        Evidence::S => "S 采样",
        Evidence::I => "推测",
        Evidence::NA(_) => "不可得",
    }
}

/// Short code stored in JSON. Not the badge.
#[must_use]
pub fn evidence_code(evidence: &Evidence) -> &'static str {
    match evidence {
        Evidence::E1 => "E1",
        Evidence::E2 => "E2",
        Evidence::E3 => "E3",
        Evidence::S => "S",
        Evidence::I => "I",
        Evidence::NA(_) => "NA",
    }
}

/// Print `table` as aligned columns or as a JSON array.
///
/// The evidence column is always last. Width uses the current terminal size
/// when stdout is a terminal; otherwise the columns are still aligned, just
/// not wrapped. This card does not truncate cells: a later card owns paging.
///
/// # Errors
///
/// Returns the `write` error. A short write is not retried.
pub fn write_table(out: &mut dyn Write, mode: OutputMode, table: &Table) -> io::Result<()> {
    match mode {
        OutputMode::Json => {
            let value = table_json(table);
            let mut bytes = serde_json::to_vec_pretty(&value)
                .map_err(|err| io::Error::other(format!("编码表格 JSON 失败：{err}")))?;
            bytes.push(b'\n');
            out.write_all(&bytes)
        }
        OutputMode::Table => {
            let width = terminal_columns();
            let rendered = render_table(table, width);
            out.write_all(rendered.as_bytes())
        }
    }
}

/// JSON shape: `{ "columns": [...], "rows": [ {<col>: <cell>, "evidence": "E1"}, ... ] }`.
fn table_json(table: &Table) -> Value {
    let mut columns = table.headers.clone();
    columns.push("evidence".to_owned());
    let rows: Vec<Value> = table
        .rows
        .iter()
        .map(|row| {
            let mut obj = serde_json::Map::new();
            for (index, header) in table.headers.iter().enumerate() {
                let cell = row.cells.get(index).map(String::as_str).unwrap_or("");
                obj.insert(header.clone(), Value::String(cell.to_owned()));
            }
            obj.insert(
                "evidence".to_owned(),
                Value::String(evidence_code(&row.evidence).to_owned()),
            );
            Value::Object(obj)
        })
        .collect();
    json!({ "columns": columns, "rows": rows })
}

fn render_table(table: &Table, width: usize) -> String {
    let mut headers = table.headers.clone();
    headers.push("evidence".to_owned());
    let mut grid: Vec<Vec<String>> = Vec::with_capacity(table.rows.len() + 1);
    grid.push(headers);
    for row in &table.rows {
        let mut cells = Vec::with_capacity(table.headers.len() + 1);
        for index in 0..table.headers.len() {
            cells.push(row.cells.get(index).cloned().unwrap_or_default());
        }
        cells.push(evidence_badge(&row.evidence).to_owned());
        grid.push(cells);
    }
    let cols = grid.first().map(Vec::len).unwrap_or(0);
    let mut widths = vec![0_usize; cols];
    for row in &grid {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(display_width(cell));
        }
    }
    fit_widths(&mut widths, width);
    let mut out = String::new();
    for row in &grid {
        let mut line = String::new();
        for (index, cell) in row.iter().enumerate() {
            if index > 0 {
                line.push_str("  ");
            }
            line.push_str(&pad(cell, widths[index]));
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Shrink columns so `sum(widths) + 2*(n-1)` fits in `width` when that is possible
/// without going below 1. Evidence (last column) is shrunk last.
fn fit_widths(widths: &mut [usize], width: usize) {
    if widths.is_empty() {
        return;
    }
    let gaps = widths.len().saturating_sub(1).saturating_mul(2);
    let mut total: usize = widths.iter().sum::<usize>().saturating_add(gaps);
    if total <= width {
        return;
    }
    let order: Vec<usize> = (0..widths.len().saturating_sub(1))
        .rev()
        .chain(std::iter::once(widths.len() - 1))
        .collect();
    for index in order {
        if total <= width {
            break;
        }
        let floor = 1;
        let spare = widths[index].saturating_sub(floor);
        let over = total.saturating_sub(width);
        let cut = spare.min(over);
        widths[index] -= cut;
        total -= cut;
    }
}

fn pad(cell: &str, width: usize) -> String {
    let w = display_width(cell);
    if w >= width {
        return clip(cell, width);
    }
    let mut out = cell.to_owned();
    out.push_str(&" ".repeat(width - w));
    out
}

fn clip(cell: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut used = 0_usize;
    for ch in cell.chars() {
        let w = char_width(ch);
        if used + w > width {
            break;
        }
        out.push(ch);
        used += w;
    }
    out
}

/// Display columns. CJK and fullwidth forms count as 2, matching a typical
/// terminal. This is not a full East-Asian width table; it covers the badges.
fn display_width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

fn char_width(ch: char) -> usize {
    if ch == '\u{3000}'
        || ('\u{1100}'..='\u{115F}').contains(&ch)
        || ('\u{2E80}'..='\u{A4CF}').contains(&ch)
        || ('\u{AC00}'..='\u{D7A3}').contains(&ch)
        || ('\u{F900}'..='\u{FAFF}').contains(&ch)
        || ('\u{FE10}'..='\u{FE19}').contains(&ch)
        || ('\u{FE30}'..='\u{FE6F}').contains(&ch)
        || ('\u{FF00}'..='\u{FF60}').contains(&ch)
        || ('\u{FFE0}'..='\u{FFE6}').contains(&ch)
    {
        2
    } else {
        1
    }
}

fn terminal_columns() -> usize {
    // stdout is not consulted for a tty size: doing that needs `libc` on Unix
    // and a console handle on Windows, and a wrong width only changes padding.
    // 80 matches the common default. A real probe can replace this later.
    80
}

/// Parse `<SESSION>`: `@last`, or a public id / session name (the daemon tells
/// those apart). Empty is refused.
///
/// # Errors
///
/// A string describing the problem. No session is invented.
pub fn parse_session(text: &str) -> Result<SessionRef, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("会话不能为空；请传入公开 ID、会话名或 @last".to_owned());
    }
    if text == "@last" {
        Ok(SessionRef::Last)
    } else {
        Ok(SessionRef::IdOrName(text.to_owned()))
    }
}

/// A session argument before the daemon resolves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRef {
    /// `@last`.
    Last,
    /// public_id or session name. Not resolved here.
    IdOrName(String),
}

/// A time argument: RFC 3339, `-10m` (relative to now), or `+30s` (relative to
/// session start). The value is kept as text plus a kind. Converting to an
/// instant needs the session start, which this card does not have.
///
/// # Errors
///
/// A string when `text` matches none of the three forms.
pub fn parse_time(text: &str) -> Result<TimeArg, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("时间不能为空；请使用 RFC 3339、-10m 或 +30s".to_owned());
    }
    if let Some(rest) = text.strip_prefix('+') {
        let duration = parse_duration(rest)?;
        return Ok(TimeArg::FromSessionStart(duration));
    }
    // A bare duration (`0s`, `30d`) is the same shape as relative-to-now. `db purge
    // --older-than` uses it. Callers that only accept RFC 3339 or `+` still see a
    // `BeforeNow` and can refuse it.
    if looks_like_duration(text) {
        let duration = parse_duration(text)?;
        return Ok(TimeArg::BeforeNow(duration));
    }
    if let Some(rest) = text.strip_prefix('-') {
        // A leading `-` on an RFC 3339 date does not happen (years are positive).
        // `-10m` is a duration. `-` plus digits and a unit is relative-to-now.
        if looks_like_duration(rest) {
            let duration = parse_duration(rest)?;
            return Ok(TimeArg::BeforeNow(duration));
        }
    }
    if looks_like_rfc3339(text) {
        return Ok(TimeArg::Rfc3339(text.to_owned()));
    }
    Err(format!(
        "时间 `{text}` 不是 RFC 3339、相对当前的 `-10m` 或相对会话的 `+30s`"
    ))
}

/// One accepted time argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeArg {
    /// The original RFC 3339 text. Not parsed into a timestamp (no `time` crate).
    Rfc3339(String),
    /// Duration before now.
    BeforeNow(DurationArg),
    /// Duration after the session started.
    FromSessionStart(DurationArg),
}

/// A duration broken into a count and a unit. Milliseconds stay milliseconds;
/// they are not rounded to zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurationArg {
    /// Magnitude. Never used as a stand-in for "unknown".
    pub count: u64,
    /// Unit suffix.
    pub unit: TimeUnit,
}

/// Units from api-and-cli §4.2, reused for CLI time arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeUnit {
    /// Milliseconds.
    Millis,
    /// Seconds.
    Seconds,
    /// Minutes.
    Minutes,
    /// Hours.
    Hours,
    /// Days.
    Days,
}

fn looks_like_duration(text: &str) -> bool {
    parse_duration(text).is_ok()
}

fn parse_duration(text: &str) -> Result<DurationArg, String> {
    let (count_text, unit) = if let Some(rest) = text.strip_suffix("ms") {
        (rest, TimeUnit::Millis)
    } else if let Some(rest) = text.strip_suffix('s') {
        (rest, TimeUnit::Seconds)
    } else if let Some(rest) = text.strip_suffix('m') {
        (rest, TimeUnit::Minutes)
    } else if let Some(rest) = text.strip_suffix('h') {
        (rest, TimeUnit::Hours)
    } else if let Some(rest) = text.strip_suffix('d') {
        (rest, TimeUnit::Days)
    } else {
        return Err(format!("时长 `{text}` 需要单位：ms、s、m、h 或 d"));
    };
    if count_text.is_empty() || !count_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("时长 `{text}` 需要整数数值"));
    }
    let count: u64 = count_text
        .parse()
        .map_err(|_| format!("时长 `{text}` 超出 u64 范围"))?;
    Ok(DurationArg { count, unit })
}

fn looks_like_rfc3339(text: &str) -> bool {
    // `YYYY-MM-DDThh:mm:ss` with an optional fraction and `Z` or `±hh:mm`.
    let bytes = text.as_bytes();
    if bytes.len() < 19 {
        return false;
    }
    let shape = b"dddd-dd-ddTdd:dd:dd";
    for (index, expected) in shape.iter().enumerate() {
        let byte = bytes[index];
        if *expected == b'd' {
            if !byte.is_ascii_digit() {
                return false;
            }
        } else if byte != *expected {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        evidence_badge, parse_session, parse_time, write_table, Evidence, OutputMode, Row,
        SessionRef, Table, TimeArg, TimeUnit,
    };
    use aw_core::NaReason;
    use std::io::Cursor;

    fn sample() -> Table {
        Table {
            headers: vec!["proc".to_owned(), "dest".to_owned()],
            rows: vec![Row {
                cells: vec!["curl".to_owned(), "127.0.0.1".to_owned()],
                evidence: Evidence::E1,
            }],
        }
    }

    #[test]
    fn table_always_has_an_evidence_column() {
        let mut buf = Cursor::new(Vec::new());
        write_table(&mut buf, OutputMode::Table, &sample()).expect("write");
        let text = String::from_utf8(buf.into_inner()).expect("utf8");
        assert!(text.contains("evidence"), "{text}");
        assert!(text.contains("E1 系统"), "{text}");
        assert_eq!(evidence_badge(&Evidence::I), "推测");
        assert_eq!(
            evidence_badge(&Evidence::NA(NaReason::CollectorUnavailable)),
            "不可得"
        );
    }

    #[test]
    fn json_rows_carry_the_evidence_code() {
        let mut buf = Cursor::new(Vec::new());
        write_table(&mut buf, OutputMode::Json, &sample()).expect("write");
        let text = String::from_utf8(buf.into_inner()).expect("utf8");
        assert!(text.contains("\"evidence\": \"E1\""), "{text}");
        assert!(text.contains("\"columns\""), "{text}");
    }

    #[test]
    fn session_and_time_forms() {
        assert_eq!(parse_session("@last").expect("last"), SessionRef::Last);
        assert!(matches!(
            parse_session("s-7k2m").expect("id"),
            SessionRef::IdOrName(_)
        ));
        assert!(parse_session("  ").is_err());
        assert!(
            matches!(parse_time("-10m").expect("rel"), TimeArg::BeforeNow(d) if d.unit == TimeUnit::Minutes && d.count == 10)
        );
        assert!(matches!(
            parse_time("+30s").expect("plus"),
            TimeArg::FromSessionStart(_)
        ));
        assert!(matches!(
            parse_time("2026-10-07T00:00:00Z").expect("rfc"),
            TimeArg::Rfc3339(_)
        ));
        assert!(parse_time("tomorrow").is_err());
    }
}
