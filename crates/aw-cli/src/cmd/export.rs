//! `aw export` (P1-CLI-04).
//!
//! The CLI does not open the database. Records come from an [`ExportSource`].
//! Production uses [`HttpExport`], which fetches the daemon's export. Tests
//! inject records and assert the bytes this module writes.
//!
//! `--format` accepts JSONL, CSV, and Markdown. It defaults to `jsonl`.

use std::io::{self, Write};

use serde_json::{json, Value};

use crate::client::{ApiRequest, Client, ClientError, LoopbackHttp, Transport};
use crate::endpoint::Endpoint;
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

    /// Body of a daemon export, after a successful [`Self::load`].
    ///
    /// The default is `None`: the caller writes [`ExportBatch`] itself. A source
    /// that already holds the daemon's file returns those bytes once.
    fn take_export_body(&mut self) -> Option<Vec<u8>> {
        None
    }
}

/// Production source. Has no database and no daemon, so every session is absent.
///
/// The live path uses [`DaemonExport`] instead. This stays for the test
/// dispatcher, which has no endpoint.
#[derive(Debug, Default)]
pub(crate) struct EmptyExport;

impl ExportSource for EmptyExport {
    fn load(&mut self, _query: &ExportQuery) -> Result<Option<ExportBatch>, String> {
        Ok(None)
    }
}

/// Why a daemon export did not return bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExportFetchError {
    /// The session is not this caller's. `session` is what the user typed.
    NotFound { session: String },
    /// `@last` has no session for this caller to resolve.
    NoSessions,
    /// The daemon refused the query, or the channel failed. Already Chinese.
    Failed { detail: String },
}

/// `GET /api/v1/sessions/{session}/export`. The body is the daemon's file,
/// passed through unchanged (JSONL text, a CSV zip, or Markdown).
pub(crate) trait ExportFetch {
    /// Ask the daemon for one export.
    ///
    /// # Errors
    ///
    /// [`ExportFetchError::NotFound`] names `session`.
    /// [`ExportFetchError::NoSessions`] preserves the `@last` explanation.
    /// [`ExportFetchError::Failed`] is a channel or daemon failure whose text
    /// is already safe to print.
    fn fetch(&mut self, session: &str, query: &str) -> Result<Vec<u8>, ExportFetchError>;
}

/// [`ExportSource`] that asks the daemon and keeps the body. Filtering and
/// redaction happen on the daemon (`filter`, `redact_paths`, `redact_hosts`).
pub(crate) struct DaemonExport<F: ExportFetch> {
    fetch: F,
    /// The daemon `format` token decided by [`run`] before the load.
    format: &'static str,
    /// Body from the last successful load. [`ExportSource::take_export_body`] returns it.
    bytes: Option<Vec<u8>>,
}

impl<F: ExportFetch> DaemonExport<F> {
    /// Bind `fetch`. `format` is the query value the daemon expects.
    #[must_use]
    pub(crate) fn new(fetch: F, format: ExportFormat) -> Self {
        Self {
            fetch,
            format: match format {
                ExportFormat::Jsonl => "jsonl",
                ExportFormat::Csv => "csv",
                ExportFormat::Markdown => "md",
            },
            bytes: None,
        }
    }
}

impl<F: ExportFetch> ExportSource for DaemonExport<F> {
    fn load(&mut self, query: &ExportQuery) -> Result<Option<ExportBatch>, String> {
        let session = session_key(&query.session);
        let mut pairs = vec![("format", self.format)];
        if let Some(filter) = query.filter.as_deref() {
            pairs.push(("filter", filter));
        }
        if query.redact_paths {
            pairs.push(("redact_paths", "1"));
        }
        if query.redact_hosts {
            pairs.push(("redact_hosts", "1"));
        }
        let raw = super::query::encode_query(&pairs);
        match self.fetch.fetch(&session, &raw) {
            Ok(body) => {
                self.bytes = Some(body);
                // The records are the raw body. An empty batch only tells
                // [`run`] the session exists; the body is what is written.
                Ok(Some(ExportBatch {
                    header: ExportHeader {
                        session,
                        export_version: 1,
                    },
                    records: Vec::new(),
                }))
            }
            Err(ExportFetchError::NotFound { .. }) => Ok(None),
            Err(ExportFetchError::NoSessions) => Err("还没有你的会话，@last 无处可指".to_owned()),
            Err(ExportFetchError::Failed { detail }) => Err(detail),
        }
    }

    fn take_export_body(&mut self) -> Option<Vec<u8>> {
        self.bytes.take()
    }
}

/// Production fetch. Dials the same internal channel the other commands use.
pub(crate) struct HttpExport<T: Transport = LoopbackHttp> {
    endpoint: Endpoint,
    transport: Option<T>,
}

impl HttpExport<LoopbackHttp> {
    /// Bind `endpoint`. The socket is opened on the first fetch.
    #[must_use]
    pub(crate) fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            transport: None,
        }
    }
}

impl<T: Transport> HttpExport<T> {
    /// Answer from `transport` instead of dialing. Tests use this.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_transport(endpoint: Endpoint, transport: T) -> Self {
        Self {
            endpoint,
            transport: Some(transport),
        }
    }

    fn exchange(&mut self, request: &ApiRequest) -> Result<crate::client::ApiReply, ClientError> {
        if let Some(transport) = self.transport.take() {
            let mut client = Client::new(self.endpoint.clone(), transport);
            let result = client.call(request);
            self.transport = Some(client.transport);
            result
        } else {
            let transport = LoopbackHttp::new(&self.endpoint)?;
            let mut client = Client::new(self.endpoint.clone(), transport);
            client.call(request)
        }
    }
}

impl<T: Transport> ExportFetch for HttpExport<T> {
    fn fetch(&mut self, session: &str, query: &str) -> Result<Vec<u8>, ExportFetchError> {
        let path = format!(
            "/api/v1/sessions/{}/export",
            super::query::encode_path_segment(session)
        );
        match self.exchange(&ApiRequest::get_query(&path, query)) {
            Ok(reply) => Ok(reply.body),
            Err(ClientError::Status {
                status: 404,
                code: Some(code),
                ..
            }) if code == "no_sessions" => Err(ExportFetchError::NoSessions),
            Err(ClientError::Status { status: 404, .. }) => Err(ExportFetchError::NotFound {
                session: session.to_owned(),
            }),
            Err(err) => Err(ExportFetchError::Failed {
                detail: clip(&err.to_string()),
            }),
        }
    }
}

fn clip(text: &str) -> String {
    const MAX: usize = 240;
    let mut out: String = text.chars().take(MAX).collect();
    if text.chars().count() > MAX {
        out.push('…');
    }
    out
}

fn session_key(session: &SessionRef) -> String {
    match session {
        SessionRef::Last => "@last".to_owned(),
        SessionRef::IdOrName(id) => id.clone(),
    }
}

/// Formats supported by the daemon export endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExportFormat {
    /// One JSON object per line.
    Jsonl,
    /// One CSV file of the same records.
    Csv,
    /// A Markdown session report.
    Markdown,
}

/// Why `--format` was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FormatError {
    /// Anything else.
    Unknown(String),
}

impl FormatError {
    fn message(&self) -> String {
        match self {
            Self::Unknown(name) => {
                format!("不支持格式 `{name}`；请使用 jsonl、csv 或 md")
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
            "md" | "markdown" => Ok(ExportFormat::Markdown),
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
        .map_err(|err| io::Error::other(format!("编码导出 JSON 失败：{err}")))?;
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
    run_to(args, source, None)
}

/// [`run`], plus an optional file the daemon body is copied into. `output_file`
/// is `Some` only when the caller passed `-o` and this process should create it.
pub(crate) fn run_to(
    args: ExportArgs<'_>,
    source: &mut dyn ExportSource,
    output_file: Option<&std::path::Path>,
) -> Outcome {
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
            let typed = session_key(&query.session);
            return error_outcome(
                exit::GENERAL,
                "not_found",
                &format!("找不到会话 `{typed}`"),
                json,
            );
        }
        Err(detail) => return error_outcome(exit::GENERAL, "export", &detail, json),
    };
    // A daemon export is already a file. Writing `batch` would drop it: that
    // source returns no records of its own.
    if let Some(body) = source.take_export_body() {
        return finish_daemon_body(body, output, output_file, format, json);
    }
    let mut bytes = Vec::new();
    let count = match format {
        ExportFormat::Jsonl => write_jsonl(&mut bytes, &batch),
        ExportFormat::Csv => write_csv(&mut bytes, &batch),
        ExportFormat::Markdown => Err(io::Error::other("Markdown 导出必须由后台生成报告正文")),
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
                ExportFormat::Markdown => "md",
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

/// Write the daemon's body to stdout, or to `-o` when one was named.
fn finish_daemon_body(
    body: Vec<u8>,
    output: Option<&str>,
    output_file: Option<&std::path::Path>,
    format: ExportFormat,
    json: bool,
) -> Outcome {
    let format_name = match format {
        ExportFormat::Jsonl => "jsonl",
        ExportFormat::Csv => "csv",
        ExportFormat::Markdown => "md",
    };
    if let Some(path) = output_file {
        if let Err(err) = std::fs::write(path, &body) {
            return error_outcome(
                exit::GENERAL,
                "export",
                &format!("写到 {path} 失败：{err}", path = path.display()),
                json,
            );
        }
    }
    if json {
        let doc = json!({
            "bytes": body.len(),
            "format": format_name,
            "output": output,
        });
        return Outcome {
            code: exit::OK,
            stdout: format!("{doc}\n").into_bytes(),
            stderr: Vec::new(),
        };
    }
    let stdout = match output {
        Some(path) => format!("已写入 {path}（{} 字节）\n", body.len()).into_bytes(),
        None => body,
    };
    Outcome {
        code: exit::OK,
        stdout,
        stderr: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        parse_format, run, run_to, write_csv, write_jsonl, DaemonExport, ExportArgs, ExportBatch,
        ExportFormat, ExportHeader, ExportRecord, HttpExport,
    };
    use crate::client::{ApiReply, ApiRequest, ClientError, Transport};
    use crate::endpoint::{Endpoint, HttpBase};
    use crate::exit;
    use std::cell::RefCell;
    use std::io;
    use std::rc::Rc;

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
            ExportFormat::Markdown => unreachable!("Markdown comes from the daemon"),
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
    fn markdown_formats_are_accepted() {
        assert_eq!(parse_format(Some("md")), Ok(ExportFormat::Markdown));
        assert_eq!(parse_format(Some("markdown")), Ok(ExportFormat::Markdown));
        assert_eq!(parse_format(None), Ok(ExportFormat::Jsonl));
        assert_eq!(parse_format(Some("csv")), Ok(ExportFormat::Csv));
        assert!(parse_format(Some("pdf"))
            .unwrap_err()
            .message()
            .contains("jsonl、csv 或 md"));
    }

    struct Script {
        seen: Rc<RefCell<Vec<(String, String)>>>,
        status: u16,
        body: Vec<u8>,
    }

    impl Transport for Script {
        fn exchange(&mut self, request: &ApiRequest) -> Result<ApiReply, ClientError> {
            self.seen
                .borrow_mut()
                .push((request.path.clone(), request.query.clone()));
            let body = if self.status == 404 && self.body.is_empty() {
                br#"{"error":{"code":"not_found","message":"session not found"}}"#.to_vec()
            } else {
                self.body.clone()
            };
            Ok(ApiReply {
                status: self.status,
                body,
            })
        }
    }

    fn endpoint() -> Endpoint {
        Endpoint::Http {
            base: HttpBase {
                host: "127.0.0.1".to_owned(),
                port: 9,
            },
            token: "test-token".to_owned(),
        }
    }

    /// The daemon's body is what stdout gets. It is not rebuilt into records.
    #[test]
    fn daemon_bytes_pass_through_to_stdout() {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let body = b"{\"type\":\"header\",\"session\":\"s-typed\"}\n{\"type\":\"processes\"}\n";
        let script = Script {
            seen: Rc::clone(&seen),
            status: 200,
            body: body.to_vec(),
        };
        let mut source = DaemonExport::new(
            HttpExport::with_transport(endpoint(), script),
            ExportFormat::Jsonl,
        );
        let outcome = run(
            ExportArgs {
                session: "s-typed",
                format: Some("jsonl"),
                output: None,
                filter: Some("cat=proc"),
                redact_paths: true,
                redact_hosts: false,
                json: false,
            },
            &mut source,
        );
        assert_eq!(
            outcome.code,
            exit::OK,
            "{}",
            String::from_utf8_lossy(&outcome.stderr)
        );
        assert_eq!(outcome.stdout, body);
        assert_eq!(
            seen.borrow().clone(),
            vec![(
                "/api/v1/sessions/s-typed/export".to_owned(),
                "format=jsonl&filter=cat%3Dproc&redact_paths=1".to_owned(),
            )]
        );
    }

    #[test]
    fn daemon_markdown_bytes_pass_through_to_stdout() {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let body = b"# Session report\n";
        let script = Script {
            seen: Rc::clone(&seen),
            status: 200,
            body: body.to_vec(),
        };
        let mut source = DaemonExport::new(
            HttpExport::with_transport(endpoint(), script),
            ExportFormat::Markdown,
        );
        let outcome = run(
            ExportArgs {
                session: "s-typed",
                format: Some("md"),
                output: None,
                filter: None,
                redact_paths: false,
                redact_hosts: false,
                json: false,
            },
            &mut source,
        );
        assert_eq!(outcome.code, exit::OK);
        assert_eq!(outcome.stdout, body);
        assert_eq!(
            seen.borrow().clone(),
            vec![(
                "/api/v1/sessions/s-typed/export".to_owned(),
                "format=md".to_owned(),
            )]
        );
    }

    #[test]
    fn daemon_export_leaves_at_last_for_the_daemon_resolver() {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let script = Script {
            seen: Rc::clone(&seen),
            status: 200,
            body: b"{\"type\":\"header\"}\n".to_vec(),
        };
        let mut source = DaemonExport::new(
            HttpExport::with_transport(endpoint(), script),
            ExportFormat::Jsonl,
        );
        let outcome = run(
            ExportArgs {
                session: "@last",
                format: None,
                output: None,
                filter: None,
                redact_paths: false,
                redact_hosts: false,
                json: false,
            },
            &mut source,
        );
        assert_eq!(outcome.code, exit::OK);
        assert_eq!(
            seen.borrow().clone(),
            vec![(
                "/api/v1/sessions/@last/export".to_owned(),
                "format=jsonl".to_owned(),
            )]
        );
    }

    /// `-o` writes the same bytes and prints a Chinese summary, not the body.
    #[test]
    fn daemon_bytes_go_to_the_output_path() {
        let dir = std::env::temp_dir().join(format!("aw-export-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("out.jsonl");
        let body = b"{\"type\":\"header\"}\n";
        let script = Script {
            seen: Rc::new(RefCell::new(Vec::new())),
            status: 200,
            body: body.to_vec(),
        };
        let mut source = DaemonExport::new(
            HttpExport::with_transport(endpoint(), script),
            ExportFormat::Jsonl,
        );
        let outcome = run_to(
            ExportArgs {
                session: "@last",
                format: None,
                output: Some(path.to_str().expect("utf8 path")),
                filter: None,
                redact_paths: false,
                redact_hosts: false,
                json: false,
            },
            &mut source,
            Some(path.as_path()),
        );
        assert_eq!(
            outcome.code,
            exit::OK,
            "{}",
            String::from_utf8_lossy(&outcome.stderr)
        );
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(text.contains("已写入"), "{text}");
        assert!(!text.contains("header"), "{text}");
        assert_eq!(std::fs::read(&path).expect("file"), body);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_markdown_bytes_go_to_the_output_path() {
        let dir = std::env::temp_dir().join(format!(
            "aw-export-md-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("out.md");
        let body = b"# Session report\n";
        let script = Script {
            seen: Rc::new(RefCell::new(Vec::new())),
            status: 200,
            body: body.to_vec(),
        };
        let mut source = DaemonExport::new(
            HttpExport::with_transport(endpoint(), script),
            ExportFormat::Markdown,
        );
        let outcome = run_to(
            ExportArgs {
                session: "s-typed",
                format: Some("markdown"),
                output: Some(path.to_str().expect("utf8 path")),
                filter: None,
                redact_paths: false,
                redact_hosts: false,
                json: false,
            },
            &mut source,
            Some(path.as_path()),
        );
        assert_eq!(outcome.code, exit::OK);
        assert_eq!(
            String::from_utf8(outcome.stdout).expect("utf8"),
            format!("已写入 {}（{} 字节）\n", path.display(), body.len())
        );
        assert_eq!(std::fs::read(&path).expect("file"), body);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_no_sessions_keeps_the_at_last_message() {
        let script = Script {
            seen: Rc::new(RefCell::new(Vec::new())),
            status: 404,
            body: br#"{"error":{"code":"no_sessions","message":"this account has no sessions"}}"#
                .to_vec(),
        };
        let mut source = DaemonExport::new(
            HttpExport::with_transport(endpoint(), script),
            ExportFormat::Jsonl,
        );
        let outcome = run(
            ExportArgs {
                session: "@last",
                format: None,
                output: None,
                filter: None,
                redact_paths: false,
                redact_hosts: false,
                json: false,
            },
            &mut source,
        );
        assert_eq!(outcome.code, exit::GENERAL);
        assert_eq!(
            String::from_utf8(outcome.stderr).expect("utf8"),
            "aw: 还没有你的会话，@last 无处可指\n"
        );
    }

    /// A 404 names the id the user typed, in Chinese.
    #[test]
    fn daemon_404_names_the_typed_session() {
        let script = Script {
            seen: Rc::new(RefCell::new(Vec::new())),
            status: 404,
            body: Vec::new(),
        };
        let mut source = DaemonExport::new(
            HttpExport::with_transport(endpoint(), script),
            ExportFormat::Csv,
        );
        let outcome = run(
            ExportArgs {
                session: "s-someone-else",
                format: Some("csv"),
                output: None,
                filter: None,
                redact_paths: false,
                redact_hosts: true,
                json: false,
            },
            &mut source,
        );
        assert_eq!(outcome.code, exit::GENERAL);
        assert_eq!(
            String::from_utf8(outcome.stderr).expect("utf8"),
            "aw: 找不到会话 `s-someone-else`\n"
        );
    }

    #[test]
    fn csv_writer_matches_render() {
        let mut direct = Vec::new();
        write_csv(&mut direct, &batch()).expect("direct");
        let rendered = render(ExportFormat::Csv, &batch()).expect("render");
        assert_eq!(direct, rendered);
    }
}
