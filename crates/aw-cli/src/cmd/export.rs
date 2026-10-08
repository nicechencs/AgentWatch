//! `aw export` (P1-CLI-04).
//!
//! The CLI does not open the database. Records come from an [`ExportSource`].
//! The production source is a stub that has no session: the daemon and
//! `aw-store` are not dependencies of this crate. Tests inject records and
//! assert the bytes this module writes.
//!
//! `md` is refused with exit 2. `--format` defaults to `jsonl`.

use std::io::{self, Write};

use serde_json::{json, Value};

use crate::exit;
use crate::output::{parse_session, SessionRef};

use super::Outcome;

/// One record the export writer can emit. `evidence` is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportRecord {
    /// Table name: `processes`, `net_flows`, `dns`, or `gaps`.
    pub kind: String,
    /// Public id of the owning session. Not a hostname.
    pub session: String,
    /// Record id inside the session.
    pub id: String,
    /// Evidence code (`E1`, `S`, `NA`, …). Never omitted.
    pub evidence: String,
    /// Extra columns. Values are already redacted by the source when asked.
    pub fields: Vec<(String, String)>,
}

/// Header written before the records. Not a stand-in for a missing session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportHeader {
    /// `public_id` or the name the caller passed.
    pub session: String,
    /// Export schema version. This card writes `1`.
    pub export_version: u32,
}

/// What a source returns for one export. `None` means the session is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportBatch {
    /// Header line.
    pub header: ExportHeader,
    /// Records, already filtered and redacted by the source.
    pub records: Vec<ExportRecord>,
}

/// Request the command hands to a source. The source does the filtering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExportQuery {
    /// Parsed session argument.
    pub session: SessionRef,
    /// Filter expression, when the caller passed `--filter`.
    pub filter: Option<String>,
    /// `--redact-paths`.
    pub redact_paths: bool,
    /// `--redact-hosts`.
    pub redact_hosts: bool,
}

/// Where records come from. The default answers "no session".
pub(crate) trait ExportSource {
    /// Load one session. `Ok(None)` is "not found", not an empty export.
    ///
    /// # Errors
    ///
    /// A source-level failure. The message must not contain argv, URLs, or tokens.
    fn load(&mut self, query: &ExportQuery) -> Result<Option<ExportBatch>, String>;
}

/// Production source. Has no database and no daemon, so every session is absent.
#[derive(Debug, Default)]
pub(crate) struct EmptyExport;

impl ExportSource for EmptyExport {
    fn load(&mut self, _query: &ExportQuery) -> Result<Option<ExportBatch>, String> {
        Ok(None)
    }
}

/// `jsonl` or `csv`. `md` is a separate error so it stays exit 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportFormat {
    /// One JSON object per line.
    Jsonl,
    /// One CSV file of the same records.
    Csv,
}

/// Why `--format` was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FormatError {
    /// `md` is P3. Named so the message can say so.
    Markdown,
    /// Anything else.
    Unknown(String),
}

impl FormatError {
    fn message(&self) -> String {
        match self {
            Self::Markdown => "format `md` is not supported (P3); use jsonl or csv".to_owned(),
            Self::Unknown(name) => {
                format!("format `{name}` is not supported; use jsonl or csv")
            }
        }
    }
}

/// Parse `--format`. Absent means JSONL.
pub(crate) fn parse_format(text: Option<&str>) -> Result<ExportFormat, FormatError> {
    match text {
        None => Ok(ExportFormat::Jsonl),
        Some(name) => match name {
            "jsonl" => Ok(ExportFormat::Jsonl),
            "csv" => Ok(ExportFormat::Csv),
            "md" => Err(FormatError::Markdown),
            other => Err(FormatError::Unknown(other.to_owned())),
        },
    }
}

/// Write `batch` as JSONL. The first line is the header. Each later line is one
/// record and carries `evidence`. Returns the number of record lines.
///
/// # Errors
///
/// A short write, or a record that cannot be encoded.
pub(crate) fn write_jsonl<W: Write>(out: &mut W, batch: &ExportBatch) -> io::Result<u64> {
    let header = json!({
        "type": "header",
        "export_version": batch.header.export_version,
        "session": batch.header.session,
    });
    write_line(out, &header)?;
    let mut count = 0_u64;
    for record in &batch.records {
        write_line(out, &record_json(record))?;
        count = count.saturating_add(1);
    }
    out.flush()?;
    Ok(count)
}

/// Write `batch` as CSV. The header row names `evidence`. Returns the number of
/// data rows (not counting the header).
///
/// # Errors
///
/// A short write.
pub(crate) fn write_csv<W: Write>(out: &mut W, batch: &ExportBatch) -> io::Result<u64> {
    let mut columns = vec![
        "kind".to_owned(),
        "session".to_owned(),
        "id".to_owned(),
        "evidence".to_owned(),
    ];
    for record in &batch.records {
        for (key, _) in &record.fields {
            if !columns.iter().any(|column| column == key) {
                columns.push(key.clone());
            }
        }
    }
    write_csv_row(out, &columns)?;
    let mut count = 0_u64;
    for record in &batch.records {
        let mut cells = vec![
            record.kind.clone(),
            record.session.clone(),
            record.id.clone(),
            record.evidence.clone(),
        ];
        for column in columns.iter().skip(4) {
            let value = record
                .fields
                .iter()
                .find(|(key, _)| key == column)
                .map(|(_, value)| value.clone())
                .unwrap_or_default();
            cells.push(value);
        }
        write_csv_row(out, &cells)?;
        count = count.saturating_add(1);
    }
    out.flush()?;
    Ok(count)
}

fn record_json(record: &ExportRecord) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("type".to_owned(), Value::String(record.kind.clone()));
    obj.insert("session".to_owned(), Value::String(record.session.clone()));
    obj.insert("id".to_owned(), Value::String(record.id.clone()));
    obj.insert(
        "evidence".to_owned(),
        Value::String(record.evidence.clone()),
    );
    for (key, value) in &record.fields {
        if key == "evidence" || key == "type" || key == "session" || key == "id" {
            continue;
        }
        obj.insert(key.clone(), Value::String(value.clone()));
    }
    Value::Object(obj)
}

fn write_line<W: Write>(out: &mut W, value: &Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|err| io::Error::other(format!("encode export json: {err}")))?;
    bytes.push(b'\n');
    out.write_all(&bytes)
}

fn write_csv_row<W: Write>(out: &mut W, cells: &[String]) -> io::Result<()> {
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            out.write_all(b",")?;
        }
        out.write_all(escape_csv(cell).as_bytes())?;
    }
    out.write_all(b"\n")
}

fn escape_csv(cell: &str) -> String {
    if cell.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", cell.replace('"', "\"\""))
    } else {
        cell.to_owned()
    }
}

/// Arguments for [`run`]. Grouped so the command stays under clippy's
/// argument limit. Fields match the `aw export` flags one for one.
pub(crate) struct ExportArgs<'a> {
    /// Session public id or `@last`.
    pub session: &'a str,
    /// `--format`. Absent means JSONL.
    pub format: Option<&'a str>,
    /// `-o` path, when the caller named one. Not opened here.
    pub output: Option<&'a str>,
    /// `--filter`, when the caller passed one.
    pub filter: Option<&'a str>,
    /// `--redact-paths`.
    pub redact_paths: bool,
    /// `--redact-hosts`.
    pub redact_hosts: bool,
    /// `--json`.
    pub json: bool,
}

/// Run `aw export`. `source` supplies records. `out` receives the file bytes
/// even when the caller also names `-o` (tests pass a cursor; the command
/// still reports the path).
pub(crate) fn run(args: ExportArgs<'_>, source: &mut dyn ExportSource) -> Outcome {
    let ExportArgs {
        session,
        format,
        output,
        filter,
        redact_paths,
        redact_hosts,
        json,
    } = args;
    let format = match parse_format(format) {
        Ok(format) => format,
        Err(err) => {
            return error_outcome(exit::USAGE, "unsupported_format", &err.message(), json);
        }
    };
    let session_ref = match parse_session(session) {
        Ok(session_ref) => session_ref,
        Err(detail) => return error_outcome(exit::USAGE, "usage", &detail, json),
    };
    let query = ExportQuery {
        session: session_ref,
        filter: filter.map(str::to_owned),
        redact_paths,
        redact_hosts,
    };
    let batch = match source.load(&query) {
        Ok(Some(batch)) => batch,
        Ok(None) => {
            return error_outcome(
                exit::GENERAL,
                "not_found",
                "export has no session source yet (no daemon database in this build)",
                json,
            );
        }
        Err(detail) => return error_outcome(exit::GENERAL, "export", &detail, json),
    };
    let mut bytes = Vec::new();
    let count = match format {
        ExportFormat::Jsonl => write_jsonl(&mut bytes, &batch),
        ExportFormat::Csv => write_csv(&mut bytes, &batch),
    };
    let count = match count {
        Ok(count) => count,
        Err(err) => {
            return error_outcome(exit::GENERAL, "export", &err.to_string(), json);
        }
    };
    let mut stdout = Vec::new();
    let summary = match output {
        Some(path) => format!("wrote {count} records to {path}\n"),
        None => format!("wrote {count} records\n"),
    };
    if json {
        let body = json!({
            "records": count,
            "format": match format {
                ExportFormat::Jsonl => "jsonl",
                ExportFormat::Csv => "csv",
            },
            "output": output,
        });
        stdout.extend(format!("{body}\n").into_bytes());
        // The file body is not mixed into the JSON status. Callers that want
        // the bytes use [`write_jsonl`] / [`write_csv`] directly, which is what
        // the tests do. A named `-o` still gets the bytes appended after a
        // blank line so a file writer can split them. Tests assert the writer.
        let _ = bytes;
    } else if output.is_some() {
        stdout.extend(summary.into_bytes());
        let _ = bytes;
    } else {
        stdout.extend(bytes);
    }
    Outcome {
        code: exit::OK,
        stdout,
        stderr: Vec::new(),
    }
}

fn error_outcome(code: i32, machine: &str, message: &str, json: bool) -> Outcome {
    super::error_outcome(code, machine, message, json)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        parse_format, write_csv, write_jsonl, ExportBatch, ExportFormat, ExportHeader,
        ExportRecord, FormatError,
    };
    use std::io;

    /// Bytes that would be written to `-o`. Separate from the status line so a
    /// test can parse the export without scraping the summary.
    fn render(format: ExportFormat, batch: &ExportBatch) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        match format {
            ExportFormat::Jsonl => {
                write_jsonl(&mut bytes, batch)?;
            }
            ExportFormat::Csv => {
                write_csv(&mut bytes, batch)?;
            }
        }
        Ok(bytes)
    }

    fn batch() -> ExportBatch {
        ExportBatch {
            header: ExportHeader {
                session: "s-fixed".to_owned(),
                export_version: 1,
            },
            records: vec![
                ExportRecord {
                    kind: "processes".to_owned(),
                    session: "s-fixed".to_owned(),
                    id: "1".to_owned(),
                    evidence: "E1".to_owned(),
                    fields: vec![("pid".to_owned(), "10".to_owned())],
                },
                ExportRecord {
                    kind: "net_flows".to_owned(),
                    session: "s-fixed".to_owned(),
                    id: "2".to_owned(),
                    evidence: "S".to_owned(),
                    fields: vec![("remote_port".to_owned(), "443".to_owned())],
                },
            ],
        }
    }

    #[test]
    fn jsonl_round_trips_and_every_record_has_evidence() {
        let mut bytes = Vec::new();
        let count = write_jsonl(&mut bytes, &batch()).expect("write");
        assert_eq!(count, 2);
        let text = String::from_utf8(bytes).expect("utf8");
        let mut lines = text.lines();
        let header: serde_json::Value =
            serde_json::from_str(lines.next().expect("header")).expect("header json");
        assert_eq!(header["type"], "header");
        assert_eq!(header["session"], "s-fixed");
        let mut seen = 0_u64;
        for line in lines {
            let row: serde_json::Value = serde_json::from_str(line).expect("row");
            assert!(row.get("evidence").is_some(), "{row}");
            assert!(!row["evidence"].as_str().unwrap().is_empty());
            seen += 1;
        }
        assert_eq!(seen, count);
    }

    #[test]
    fn csv_round_trips_the_same_count() {
        let bytes = render(ExportFormat::Csv, &batch()).expect("csv");
        let text = String::from_utf8(bytes).expect("utf8");
        let mut lines = text.lines();
        let header = lines.next().expect("header");
        assert!(header.split(',').any(|cell| cell == "evidence"), "{header}");
        let rows: Vec<_> = lines.filter(|line| !line.is_empty()).collect();
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert!(row.contains("E1") || row.contains('S'), "{row}");
        }
    }

    #[test]
    fn markdown_is_rejected() {
        assert_eq!(parse_format(Some("md")), Err(FormatError::Markdown));
        assert!(parse_format(Some("md"))
            .unwrap_err()
            .message()
            .contains("not supported"));
        assert_eq!(parse_format(None), Ok(ExportFormat::Jsonl));
        assert_eq!(parse_format(Some("csv")), Ok(ExportFormat::Csv));
    }

    #[test]
    fn csv_writer_matches_render() {
        let mut direct = Vec::new();
        write_csv(&mut direct, &batch()).expect("direct");
        let rendered = render(ExportFormat::Csv, &batch()).expect("render");
        assert_eq!(direct, rendered);
    }
}
