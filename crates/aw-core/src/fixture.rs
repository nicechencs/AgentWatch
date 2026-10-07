//! JSONL fixtures: one header line, then one [`RawEvent`] per line.
//!
//! Compression is not implemented. A path whose name ends in `.zst` returns
//! [`FixtureError::ZstdNotImplemented`] instead of reading or writing bytes.
//!
//! Errors name the line number and the decode failure. They do not include the
//! raw line, so argv, environment values, URLs, and headers cannot leak through
//! `Display`.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::event::{RawEvent, SCHEMA_VERSION};
use crate::EventError;

/// Exact text returned when a caller asks for a `.jsonl.zst` fixture.
pub const ZSTD_NOT_IMPLEMENTED: &str = "zstd fixtures are not implemented yet";

/// First line of a fixture file.
///
/// `v` must equal [`SCHEMA_VERSION`]. `recorded_at` is an author-chosen RFC 3339
/// UTC string, not a clock reading taken at read time. `collector` is one name
/// (the P0-SIM-01 contract); it is not a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureHeader {
    /// Schema major version. Must equal [`SCHEMA_VERSION`].
    pub v: u16,
    /// Platform placeholder, for example `"placeholder"` or `"linux"`.
    pub platform: String,
    /// OS version placeholder. Never a real hostname.
    pub os_version: String,
    /// Collector that produced the recording, or `"handwritten"`.
    pub collector: String,
    /// Author-chosen RFC 3339 UTC timestamp.
    pub recorded_at: String,
    /// Scenario name, matching the case directory.
    pub scenario: String,
}

/// Failure while reading or writing a fixture.
#[derive(Debug, Error)]
pub enum FixtureError {
    /// The path ends in `.zst`. Compression is deferred; no bytes were touched.
    #[error("{ZSTD_NOT_IMPLEMENTED}")]
    ZstdNotImplemented,

    /// Header `v` is not the major version this build reads.
    #[error("fixture header version {found} does not match schema version {expected}")]
    HeaderVersionMismatch {
        /// Version written in the header.
        found: u16,
        /// [`SCHEMA_VERSION`] compiled into this crate.
        expected: u16,
    },

    /// Line 1 was missing, empty, or not a header object.
    #[error("fixture header (line 1): {0}")]
    Header(String),

    /// An event line could not be decoded. `line` is 1-based in the file.
    ///
    /// `message` names the failure class. It never includes the raw line, so argv,
    /// environment values, URLs, and headers cannot leak through [`std::fmt::Display`].
    #[error("fixture event on line {line}: {message}")]
    Event {
        /// 1-based line number. The header is line 1, so the first event is line 2.
        line: u64,
        /// Failure class, without the raw JSON.
        message: String,
    },

    /// An event could not be encoded. This is not a file line.
    ///
    /// The message names the failure class. It does not debug the event or quote
    /// argv, environment values, URLs, or headers.
    #[error("could not encode fixture event: {0}")]
    Encode(String),

    /// Filesystem or other I/O failure. The path is included; event payloads are not.
    #[error("fixture i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// Writes a header line and then one JSON object per event.
pub struct FixtureWriter<W> {
    inner: W,
    wrote_header: bool,
}

impl<W: Write> FixtureWriter<W> {
    /// Wrap `inner`. The caller writes the header before any event.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            wrote_header: false,
        }
    }

    /// Create or truncate `path` and wrap it.
    ///
    /// A path ending in `.zst` is refused before the file is created.
    pub fn create(path: &Path) -> Result<FixtureWriter<File>, FixtureError> {
        reject_zstd(path)?;
        Ok(FixtureWriter::new(File::create(path)?))
    }

    /// Write the header as line 1. Calling this twice is an error.
    pub fn write_header(&mut self, header: &FixtureHeader) -> Result<(), FixtureError> {
        if self.wrote_header {
            return Err(FixtureError::Header(
                "header was already written".to_owned(),
            ));
        }
        if header.v != SCHEMA_VERSION {
            return Err(FixtureError::HeaderVersionMismatch {
                found: header.v,
                expected: SCHEMA_VERSION,
            });
        }
        let line = serde_json::to_string(header)
            .map_err(|err| FixtureError::Header(format!("could not encode header: {err}")))?;
        writeln!(self.inner, "{line}")?;
        self.wrote_header = true;
        Ok(())
    }

    /// Append one event. The header must already have been written.
    pub fn write_event(&mut self, event: &RawEvent) -> Result<(), FixtureError> {
        if !self.wrote_header {
            return Err(FixtureError::Header(
                "write the header before events".to_owned(),
            ));
        }
        let line = event
            .to_json()
            .map_err(|err| FixtureError::Encode(encode_message(&err)))?;
        writeln!(self.inner, "{line}")?;
        Ok(())
    }

    /// Flush buffered bytes.
    pub fn flush(&mut self) -> Result<(), FixtureError> {
        self.inner.flush()?;
        Ok(())
    }

    /// Return the inner writer after flushing.
    pub fn into_inner(mut self) -> Result<W, FixtureError> {
        self.flush()?;
        Ok(self.inner)
    }
}

/// Reads a fixture header and then each event line.
pub struct FixtureReader<R> {
    lines: std::io::Lines<BufReader<R>>,
    header: FixtureHeader,
    /// Next 1-based line number. The header consumed line 1.
    next_line: u64,
}

impl FixtureReader<File> {
    /// Open `path`, parse line 1 as a header, and leave the reader on line 2.
    pub fn open(path: &Path) -> Result<Self, FixtureError> {
        reject_zstd(path)?;
        let file = File::open(path)?;
        Self::from_reader(file)
    }
}

impl<R: std::io::Read> FixtureReader<R> {
    /// Parse a header from `reader` and yield later lines as events.
    pub fn from_reader(reader: R) -> Result<Self, FixtureError> {
        let mut lines = BufReader::new(reader).lines();
        let first = match lines.next() {
            Some(line) => line?,
            None => {
                return Err(FixtureError::Header(
                    "file is empty; expected a header JSON object".to_owned(),
                ));
            }
        };
        let header = parse_header(&first)?;
        Ok(Self {
            lines,
            header,
            next_line: 2,
        })
    }

    /// Header from line 1.
    pub fn header(&self) -> &FixtureHeader {
        &self.header
    }

    /// Read every remaining event. A bad line stops the read; nothing is skipped.
    pub fn read_all(mut self) -> Result<(FixtureHeader, Vec<RawEvent>), FixtureError> {
        let mut events = Vec::new();
        while let Some(event) = self.next_event()? {
            events.push(event);
        }
        Ok((self.header, events))
    }

    /// Next event, or `Ok(None)` at end of file.
    ///
    /// A blank line or malformed JSON is [`FixtureError::Event`] with that line number.
    pub fn next_event(&mut self) -> Result<Option<RawEvent>, FixtureError> {
        let line_no = self.next_line;
        let Some(line) = self.lines.next() else {
            return Ok(None);
        };
        self.next_line = line_no.saturating_add(1);
        let line = line?;
        if line.is_empty() {
            return Err(FixtureError::Event {
                line: line_no,
                message: "blank line is not an event".to_owned(),
            });
        }
        match RawEvent::from_json(&line) {
            Ok(event) => Ok(Some(event)),
            Err(err) => Err(event_error(line_no, err)),
        }
    }
}

fn event_error(line: u64, err: EventError) -> FixtureError {
    // `EventError::Decode` is a serde message. That text often quotes the input
    // (`invalid type: string "..."`), which would put argv, URLs, or headers into
    // `Display`. Keep the line number and drop the snippet.
    let message = match err {
        EventError::Decode(_) => "failed to decode event JSON".to_owned(),
        other => other.to_string(),
    };
    FixtureError::Event { line, message }
}

fn encode_message(err: &EventError) -> String {
    match err {
        EventError::Decode(_) => "failed to encode event JSON".to_owned(),
        other => other.to_string(),
    }
}

fn parse_header(line: &str) -> Result<FixtureHeader, FixtureError> {
    if line.is_empty() {
        return Err(FixtureError::Header(
            "line is empty; expected a header JSON object".to_owned(),
        ));
    }
    let value: serde_json::Value = serde_json::from_str(line).map_err(|err| {
        FixtureError::Header(format!(
            "not valid JSON at line {} column {}",
            err.line(),
            err.column()
        ))
    })?;
    let found = match value.get("v") {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| FixtureError::Header(format!("field `v` (`{n}`) is not a u16")))?,
        Some(other) => {
            return Err(FixtureError::Header(format!(
                "field `v` has unexpected JSON type {}",
                json_type_name(other)
            )));
        }
        None => {
            return Err(FixtureError::Header(
                "missing required field `v`".to_owned(),
            ));
        }
    };
    if found != SCHEMA_VERSION {
        return Err(FixtureError::HeaderVersionMismatch {
            found,
            expected: SCHEMA_VERSION,
        });
    }
    serde_json::from_value(value).map_err(|err| FixtureError::Header(header_decode_message(&err)))
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn header_decode_message(err: &serde_json::Error) -> String {
    // Data errors quote the offending value. Report the class, not that text.
    if err.is_data() {
        "could not decode header".to_owned()
    } else {
        format!(
            "could not decode header at line {} column {}",
            err.line(),
            err.column()
        )
    }
}

fn reject_zstd(path: &Path) -> Result<(), FixtureError> {
    let Some(name) = path.file_name() else {
        return Ok(());
    };
    // Compare bytes so a non-ASCII name cannot panic on a char boundary.
    // `as_encoded_bytes` keeps an ASCII suffix intact on every platform.
    let bytes = name.as_encoded_bytes();
    if bytes.len() >= 4 && bytes[bytes.len() - 4..].eq_ignore_ascii_case(b".zst") {
        return Err(FixtureError::ZstdNotImplemented);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::io::Cursor;
    use std::path::PathBuf;

    use super::*;
    use crate::event::{
        EnvMap, EventKind, Evidence, ProcRef, ProcUid, ProcessStart, RawEventParts, Redacted,
        SessionId, Source, StartHow, UserRef,
    };

    fn sample_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/common/placeholder-process/events.jsonl")
    }

    fn expected_snap_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/common/placeholder-process/expected.snap")
    }

    fn sample_event() -> RawEvent {
        let mut env = std::collections::BTreeMap::new();
        env.insert("LANG".to_owned(), "C".to_owned());
        RawEvent::try_new(RawEventParts {
            seq: 1,
            ts_mono_ns: 1_000,
            ts_wall_ns: 1_759_795_200_000_000_000,
            session_id: Some(SessionId(1)),
            proc: Some(ProcRef {
                uid: ProcUid(0x0000_0000_0000_0001),
                pid: 100,
                tid: Some(100),
            }),
            source: Source::new("handwritten/placeholder"),
            evidence: Evidence::E1,
            kind: EventKind::ProcessStart(ProcessStart::new(
                1,
                Some(ProcUid(0x0000_0000_0000_0002)),
                1_759_795_200_000_000_000,
                Some("/tmp/placeholder".to_owned()),
                Some(vec![
                    Redacted::new("placeholder"),
                    Redacted::new("/tmp/placeholder"),
                ]),
                Some("/tmp/placeholder".to_owned()),
                Some(UserRef {
                    id: "1000".to_owned(),
                    name: Some("placeholder".to_owned()),
                }),
                StartHow::Exec,
                Some(EnvMap(env)),
                None,
            )),
        })
        .expect("sample process_start")
    }

    fn must_err<T, E>(result: Result<T, E>) -> E {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(err) => err,
        }
    }

    fn sample_header() -> FixtureHeader {
        FixtureHeader {
            v: SCHEMA_VERSION,
            platform: "placeholder".to_owned(),
            os_version: "placeholder".to_owned(),
            collector: "handwritten".to_owned(),
            recorded_at: "2026-10-07T00:00:00Z".to_owned(),
            scenario: "placeholder-process".to_owned(),
        }
    }

    #[test]
    fn reads_handwritten_sample_count_and_kind() {
        let (header, events) = FixtureReader::open(&sample_path())
            .expect("open sample")
            .read_all()
            .expect("read sample");
        assert_eq!(header, sample_header());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind.kind_name(), "process_start");

        let snap = std::fs::read_to_string(expected_snap_path()).expect("expected.snap");
        let expected_json = snap
            .lines()
            .skip_while(|line| !line.starts_with('{'))
            .collect::<Vec<_>>()
            .join("\n");
        let expected: RawEvent = serde_json::from_str(&expected_json).expect("expected.snap event");
        assert_eq!(events[0], expected);
    }

    #[test]
    fn header_version_mismatch_names_both_versions() {
        let text = concat!(
            r#"{"v":2,"platform":"placeholder","os_version":"placeholder","#,
            r#""collector":"handwritten","recorded_at":"2026-10-07T00:00:00Z","#,
            r#""scenario":"placeholder-process"}"#,
            "\n",
        );
        let err = must_err(FixtureReader::from_reader(Cursor::new(text.as_bytes())));
        let shown = err.to_string();
        assert!(
            shown.contains('2') && shown.contains('1'),
            "error should name found and expected versions, got {shown}"
        );
        match err {
            FixtureError::HeaderVersionMismatch { found, expected } => {
                assert_eq!(found, 2);
                assert_eq!(expected, SCHEMA_VERSION);
            }
            other => panic!("expected HeaderVersionMismatch, got {other}"),
        }
    }

    #[test]
    fn round_trip_sample_through_writer() {
        let header = sample_header();
        let event = sample_event();
        let mut writer = FixtureWriter::new(Vec::<u8>::new());
        writer.write_header(&header).expect("header");
        writer.write_event(&event).expect("event");
        let bytes = writer.into_inner().expect("flush");

        let reader = FixtureReader::from_reader(Cursor::new(bytes)).expect("read back");
        let (got_header, events) = reader.read_all().expect("events");
        assert_eq!(got_header, header);
        assert_eq!(events, vec![event]);
    }

    #[test]
    fn round_trip_file_sample_through_writer() {
        let (header, events) = FixtureReader::open(&sample_path())
            .expect("open")
            .read_all()
            .expect("read");
        let mut writer = FixtureWriter::new(Vec::<u8>::new());
        writer.write_header(&header).expect("header");
        for event in &events {
            writer.write_event(event).expect("event");
        }
        let bytes = writer.into_inner().expect("flush");
        let (again_header, again_events) = FixtureReader::from_reader(Cursor::new(bytes))
            .expect("reopen")
            .read_all()
            .expect("reread");
        assert_eq!(again_header, header);
        assert_eq!(again_events, events);
    }

    #[test]
    fn zstd_path_is_not_implemented() {
        let read_err = must_err(FixtureReader::open(Path::new("events.jsonl.zst")));
        assert_eq!(read_err.to_string(), ZSTD_NOT_IMPLEMENTED);
        let write_err = must_err(FixtureWriter::<File>::create(Path::new("EVENTS.JSONL.ZST")));
        assert_eq!(write_err.to_string(), ZSTD_NOT_IMPLEMENTED);
    }

    #[test]
    fn zstd_suffix_check_does_not_panic_on_non_ascii_names() {
        let zstd = must_err(FixtureReader::open(Path::new("\u{1F600}.zst")));
        assert_eq!(zstd.to_string(), ZSTD_NOT_IMPLEMENTED);
        // A 4-byte scalar whose tail overlaps the last four bytes used to panic.
        let io_err = must_err(FixtureReader::open(Path::new("\u{1F600}x")));
        assert!(matches!(io_err, FixtureError::Io(_)));
    }

    #[test]
    fn malformed_event_line_reports_line_number() {
        let text = "{\"v\":1,\"platform\":\"placeholder\",\"os_version\":\"placeholder\",\"collector\":\"handwritten\",\"recorded_at\":\"2026-10-07T00:00:00Z\",\"scenario\":\"placeholder-process\"}\n{not-json}\n";
        let mut reader = FixtureReader::from_reader(Cursor::new(text.as_bytes())).expect("header");
        let err = reader.next_event().unwrap_err();
        match err {
            FixtureError::Event { line, message } => {
                assert_eq!(line, 2);
                assert!(!message.is_empty());
                assert!(!message.contains("not-json"));
            }
            other => panic!("expected Event, got {other}"),
        }
    }

    #[test]
    fn blank_line_is_not_skipped() {
        let header = serde_json::to_string(&sample_header()).unwrap();
        let text = format!("{header}\n\n");
        let mut reader =
            FixtureReader::from_reader(Cursor::new(text.into_bytes())).expect("header");
        let err = reader.next_event().unwrap_err();
        match err {
            FixtureError::Event { line, .. } => assert_eq!(line, 2),
            other => panic!("expected Event, got {other}"),
        }
    }
}
