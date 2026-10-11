//! JSONL and CSV zip round-trip for one small session (P1-STORE-03).
//!
//! The task card asks to unzip with Python's `csv` module. This crate's tests
//! run in Rust and do not install Python. A small zip32 reader and a CSV parser
//! stand in for that check: they assert `README.txt`, the four stable headers,
//! and that an unquoted empty field is SQL NULL rather than zero.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use aw_store::{ensure_timeline, write_csv_zip, write_jsonl, ExportError, ExportOptions};
use rusqlite::Connection;

const SCHEMA: &str = include_str!("../migrations/0001_init.sql");

const PROC_HEADER: &str = "session_id,proc_uid,pid,parent_uid,ppid,depth,start_ns,exit_ns,exit_code,exit_signal,how,user_id,signer,evidence,field_evidence,source,agent";
const NET_HEADER: &str = "id,session_id,proc_uid,proto,direction,local_ip,local_port,remote_ip,remote_port,domain,domain_source,domain_alts,sni,alpn,start_ns,end_ns,bytes_up,bytes_down,via_proxy,direct,preexisting,is_loopback,result,platform_total_up,platform_total_down,evidence,na_reason,field_evidence,source";
const DNS_HEADER: &str =
    "id,session_id,proc_uid,ts_ns,qname,qtype,rcode,answers,ttl_min,server,evidence,source";
const GAP_HEADER: &str = "id,session_id,collector,kind,affects,from_ns,to_ns,count,detail,evidence";

fn open_db() -> Connection {
    let conn = aw_store::open_in_memory_connection().unwrap();
    conn.execute_batch(SCHEMA).unwrap();
    ensure_timeline(&conn).unwrap();
    conn
}

fn seed(conn: &Connection) {
    conn.execute(
        "INSERT INTO sessions (id, public_id, name, mode, agent, started_ns, ended_ns, platform, user_id, collectors) \
         VALUES (1, 'pub-a', 'demo', 'launch', 'codex', 1, NULL, 'windows', 'user-a', '[\"etw\"]')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO sessions (id, public_id, name, mode, agent, started_ns, platform, user_id, collectors) \
         VALUES (2, 'pub-b', NULL, 'attach', NULL, 1, 'windows', 'user-b', '[]')",
        [],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO processes (session_id, proc_uid, pid, parent_uid, ppid, depth, start_ns, exit_code, how, user_id, evidence, field_evidence, source, agent) \
         VALUES (1, 8, 400, NULL, NULL, 0, 10, 7, 'spawn', 'user-a', 'E1', '{\"pid\":\"E1\"}', 'etw', 'codex')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO processes (session_id, proc_uid, pid, parent_uid, ppid, depth, start_ns, how, evidence, field_evidence, source) \
         VALUES (1, 1, 401, 8, 400, 1, 20, 'spawn', 'E1', NULL, 'etw')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO process_images (session_id, proc_uid, seq, ts_ns, exe, evidence, source) \
         VALUES (1, 8, 0, 10, 'C:\\tools\\node.exe', 'E1', 'etw')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO process_images (session_id, proc_uid, seq, ts_ns, exe, evidence, source) \
         VALUES (1, 1, 0, 20, 'C:\\tools\\curl.exe', 'E1', 'etw')",
        [],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO dns (id, session_id, proc_uid, ts_ns, qname, qtype, rcode, answers, evidence, source) \
         VALUES (2, 1, 8, 20, 'laptop', 1, 0, '[\"10.0.0.2\"]', 'E3', 'etw')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO dns (id, session_id, proc_uid, ts_ns, qname, qtype, answers, evidence, source) \
         VALUES (3, 1, 1, 20, 'a.example.com', 1, NULL, 'E1', 'etw')",
        [],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO net_flows (id, session_id, proc_uid, proto, direction, local_ip, local_port, remote_ip, remote_port, domain, start_ns, bytes_up, bytes_down, evidence, source) \
         VALUES (4, 1, 8, 'tcp', 'outbound', '10.0.0.8', 44000, '93.184.216.34', 443, 'example.com', 30, NULL, NULL, 'E2', 'etw')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO net_flows (id, session_id, proc_uid, proto, direction, local_ip, local_port, remote_ip, remote_port, domain, sni, start_ns, bytes_up, bytes_down, evidence, source) \
         VALUES (5, 1, 1, 'tcp', 'outbound', '10.0.0.8', 44001, '10.0.0.9', 443, 'pc.local', 'pc.local', 40, 5, 6, 'E1', 'etw')",
        [],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO gaps (id, session_id, collector, kind, affects, from_ns, to_ns, count, detail) \
         VALUES (6, 1, 'etw', 'lost', '[\"net\"]', 50, 60, NULL, '/Users/alice/notes')",
        [],
    )
    .unwrap();
}

fn options<'a>(filter: Option<&'a str>, redact: bool) -> ExportOptions<'a> {
    ExportOptions {
        user_id: "user-a",
        session_id: 1,
        filter,
        now_ns: None,
        redact_paths: redact,
        redact_hosts: redact,
        page_size: Some(1),
    }
}

fn json_object(line: &str) -> BTreeMap<String, serde_mini::Value> {
    serde_mini::parse_object(line)
}

/// Minimal JSON reader for the shapes this export writes. Not a general parser.
mod serde_mini {
    use std::collections::BTreeMap;

    #[derive(Clone, Debug, PartialEq)]
    pub enum Value {
        Null,
        Bool(bool),
        Number(i64),
        String(String),
        Array(Vec<Value>),
        Object(BTreeMap<String, Value>),
    }

    pub fn parse_object(input: &str) -> BTreeMap<String, Value> {
        let mut p = Parser {
            bytes: input.as_bytes(),
            i: 0,
        };
        match p.value() {
            Value::Object(map) => {
                p.skip();
                assert!(p.i == p.bytes.len(), "trailing json");
                map
            }
            other => panic!("expected object, got {other:?}"),
        }
    }

    struct Parser<'a> {
        bytes: &'a [u8],
        i: usize,
    }

    impl<'a> Parser<'a> {
        fn skip(&mut self) {
            while self.i < self.bytes.len() && self.bytes[self.i].is_ascii_whitespace() {
                self.i += 1;
            }
        }

        fn value(&mut self) -> Value {
            self.skip();
            match self.bytes[self.i] {
                b'n' => {
                    self.eat(b"null");
                    Value::Null
                }
                b't' => {
                    self.eat(b"true");
                    Value::Bool(true)
                }
                b'f' => {
                    self.eat(b"false");
                    Value::Bool(false)
                }
                b'"' => Value::String(self.string()),
                b'[' => self.array(),
                b'{' => self.object(),
                b'-' | b'0'..=b'9' => self.number(),
                other => panic!("bad json byte {other}"),
            }
        }

        fn eat(&mut self, lit: &[u8]) {
            assert!(self.bytes[self.i..].starts_with(lit));
            self.i += lit.len();
        }

        fn string(&mut self) -> String {
            assert_eq!(self.bytes[self.i], b'"');
            self.i += 1;
            let mut out = String::new();
            while self.bytes[self.i] != b'"' {
                if self.bytes[self.i] == b'\\' {
                    self.i += 1;
                    let ch = match self.bytes[self.i] {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        other => panic!("bad escape {other}"),
                    };
                    out.push(ch);
                    self.i += 1;
                } else {
                    let rest = std::str::from_utf8(&self.bytes[self.i..]).unwrap();
                    let ch = rest.chars().next().unwrap();
                    out.push(ch);
                    self.i += ch.len_utf8();
                }
            }
            self.i += 1;
            out
        }

        fn number(&mut self) -> Value {
            let start = self.i;
            if self.bytes[self.i] == b'-' {
                self.i += 1;
            }
            while self.i < self.bytes.len() && self.bytes[self.i].is_ascii_digit() {
                self.i += 1;
            }
            let text = std::str::from_utf8(&self.bytes[start..self.i]).unwrap();
            Value::Number(text.parse().unwrap())
        }

        fn array(&mut self) -> Value {
            self.i += 1;
            let mut items = Vec::new();
            self.skip();
            if self.bytes[self.i] == b']' {
                self.i += 1;
                return Value::Array(items);
            }
            loop {
                items.push(self.value());
                self.skip();
                if self.bytes[self.i] == b']' {
                    self.i += 1;
                    break;
                }
                assert_eq!(self.bytes[self.i], b',');
                self.i += 1;
            }
            Value::Array(items)
        }

        fn object(&mut self) -> Value {
            self.i += 1;
            let mut map = BTreeMap::new();
            self.skip();
            if self.bytes[self.i] == b'}' {
                self.i += 1;
                return Value::Object(map);
            }
            loop {
                self.skip();
                let key = self.string();
                self.skip();
                assert_eq!(self.bytes[self.i], b':');
                self.i += 1;
                map.insert(key, self.value());
                self.skip();
                if self.bytes[self.i] == b'}' {
                    self.i += 1;
                    break;
                }
                assert_eq!(self.bytes[self.i], b',');
                self.i += 1;
            }
            Value::Object(map)
        }
    }
}

fn str_field<'a>(obj: &'a BTreeMap<String, serde_mini::Value>, key: &str) -> &'a str {
    match obj.get(key) {
        Some(serde_mini::Value::String(s)) => s,
        other => panic!("{key} is not a string: {other:?}"),
    }
}

fn num_field(obj: &BTreeMap<String, serde_mini::Value>, key: &str) -> i64 {
    match obj.get(key) {
        Some(serde_mini::Value::Number(n)) => *n,
        other => panic!("{key} is not a number: {other:?}"),
    }
}

fn is_null(obj: &BTreeMap<String, serde_mini::Value>, key: &str) -> bool {
    matches!(obj.get(key), Some(serde_mini::Value::Null))
}

fn db_record_count(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT \
            (SELECT COUNT(*) FROM processes WHERE session_id = 1) + \
            (SELECT COUNT(*) FROM net_flows WHERE session_id = 1) + \
            (SELECT COUNT(*) FROM dns WHERE session_id = 1) + \
            (SELECT COUNT(*) FROM gaps WHERE session_id = 1)",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

#[test]
fn jsonl_round_trip_matches_the_database() {
    let conn = open_db();
    seed(&conn);
    let mut buf = Vec::new();
    let opts = options(None, false);
    let written = write_jsonl(&conn, &opts, &mut buf).unwrap();
    let text = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(written as usize, lines.len() - 1);
    assert_eq!(written, db_record_count(&conn) as u64);

    let header = json_object(lines[0]);
    assert_eq!(str_field(&header, "type"), "header");
    assert_eq!(num_field(&header, "export_version"), 1);
    assert!(!header.contains_key("evidence"));
    let gaps = match header.get("gaps_summary") {
        Some(serde_mini::Value::Object(obj)) => obj,
        other => panic!("gaps_summary: {other:?}"),
    };
    assert_eq!(num_field(gaps, "rows"), 1);
    assert!(is_null(gaps, "lost"));

    let mut kinds = Vec::new();
    for line in &lines[1..] {
        let obj = json_object(line);
        let evidence = str_field(&obj, "evidence");
        assert!(!evidence.is_empty(), "record line missing evidence");
        kinds.push((
            str_field(&obj, "type").to_string(),
            obj.get("id")
                .or_else(|| obj.get("proc_uid"))
                .and_then(|v| match v {
                    serde_mini::Value::Number(n) => Some(*n),
                    _ => None,
                })
                .unwrap(),
        ));
    }
    assert_eq!(
        kinds,
        vec![
            ("processes".to_string(), 8),
            ("dns".to_string(), 2),
            ("dns".to_string(), 3),
            ("processes".to_string(), 1),
            ("net_flows".to_string(), 4),
            ("net_flows".to_string(), 5),
            ("gaps".to_string(), 6),
        ]
    );

    // Test-bot #144: process rows carry the executable name (basename of the
    // newest process_images.exe), so a JSONL reader sees "curl.exe", not a pid.
    assert_eq!(str_field(&json_object(lines[1]), "exe_name"), "node.exe");
    assert_eq!(str_field(&json_object(lines[4]), "exe_name"), "curl.exe");
    assert_eq!(num_field(&json_object(lines[1]), "exit_code"), 7);
    assert!(is_null(&json_object(lines[4]), "exit_code"));

    let net4 = json_object(lines[5]);
    assert!(is_null(&net4, "bytes_up"));
    assert!(is_null(&net4, "bytes_down"));
}

#[test]
fn filter_narrows_records_but_not_the_gap_summary() {
    let conn = open_db();
    seed(&conn);

    let mut net = Vec::new();
    let n = write_jsonl(&conn, &options(Some("kind:net"), false), &mut net).unwrap();
    assert_eq!(n, 2);
    let net_text = String::from_utf8(net).unwrap();
    let net_lines: Vec<&str> = net_text.lines().collect();
    assert_eq!(net_lines.len(), 3);
    for line in &net_lines[1..] {
        assert_eq!(str_field(&json_object(line), "type"), "net_flows");
    }
    let summary = match json_object(net_lines[0]).remove("gaps_summary") {
        Some(serde_mini::Value::Object(obj)) => obj,
        other => panic!("{other:?}"),
    };
    assert_eq!(num_field(&summary, "rows"), 1);

    let mut proc = Vec::new();
    let n = write_jsonl(&conn, &options(Some("proc:node.exe"), false), &mut proc).unwrap();
    assert_eq!(n, 3);
    let proc_text = String::from_utf8(proc).unwrap();
    let ids: Vec<(String, i64)> = proc_text
        .lines()
        .skip(1)
        .map(|line| {
            let obj = json_object(line);
            (
                str_field(&obj, "type").to_string(),
                match obj.get("proc_uid") {
                    Some(serde_mini::Value::Number(n)) => *n,
                    other => panic!("{other:?}"),
                },
            )
        })
        .collect();
    assert_eq!(
        ids,
        vec![
            ("processes".to_string(), 8),
            ("dns".to_string(), 8),
            ("net_flows".to_string(), 8),
        ]
    );
}

#[test]
fn bad_filter_and_foreign_session_write_nothing() {
    let conn = open_db();
    seed(&conn);

    let mut buf = Vec::new();
    let err = write_jsonl(&conn, &options(Some("path:foo"), false), &mut buf).unwrap_err();
    assert!(matches!(err, ExportError::Query(_)));
    assert!(buf.is_empty());

    let mut buf = Vec::new();
    let foreign = ExportOptions {
        user_id: "user-a",
        session_id: 2,
        filter: None,
        now_ns: None,
        redact_paths: false,
        redact_hosts: false,
        page_size: Some(1),
    };
    let err = write_jsonl(&conn, &foreign, &mut buf).unwrap_err();
    assert!(matches!(err, ExportError::NotFound { session_id: 2 }));
    assert!(buf.is_empty());
}

#[test]
fn redact_rewrites_user_segments_and_intranet_hosts() {
    let conn = open_db();
    seed(&conn);
    let mut buf = Vec::new();
    write_jsonl(&conn, &options(None, true), &mut buf).unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(text.contains("<host>"));
    assert!(text.contains("/Users/<user>/notes"));
    assert!(!text.contains("laptop"));
    assert!(!text.contains("pc.local"));
    assert!(text.contains("example.com"));
    assert!(!text.contains("/Users/alice"));

    let laptop = text
        .lines()
        .find(|line| line.contains("\"type\":\"dns\"") && line.contains("\"id\":2"))
        .unwrap();
    assert_eq!(str_field(&json_object(laptop), "qname"), "<host>");
    let public = text.lines().find(|line| line.contains("\"id\":3")).unwrap();
    assert_eq!(str_field(&json_object(public), "qname"), "a.example.com");
    let intranet = text.lines().find(|line| line.contains("\"id\":5")).unwrap();
    assert_eq!(str_field(&json_object(intranet), "domain"), "<host>.local");
}

struct ZipEntry {
    name: String,
    body: Vec<u8>,
}

fn unzip(bytes: &[u8]) -> Vec<ZipEntry> {
    let mut i = 0;
    let mut entries = Vec::new();
    while i + 4 <= bytes.len() {
        let sig = u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        if sig != 0x0403_4b50 {
            break;
        }
        assert!(i + 30 <= bytes.len());
        let method = u16::from_le_bytes(bytes[i + 8..i + 10].try_into().unwrap());
        assert_eq!(method, 0, "store only");
        let comp = u32::from_le_bytes(bytes[i + 18..i + 22].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes(bytes[i + 26..i + 28].try_into().unwrap()) as usize;
        let extra = u16::from_le_bytes(bytes[i + 28..i + 30].try_into().unwrap()) as usize;
        let name_at = i + 30;
        let name = String::from_utf8(bytes[name_at..name_at + name_len].to_vec()).unwrap();
        let data_at = name_at + name_len + extra;
        let body = bytes[data_at..data_at + comp].to_vec();
        entries.push(ZipEntry { name, body });
        i = data_at + comp;
    }
    entries
}

/// Unquoted empty field is `None` (SQL NULL). Quoted text, including `""`, is `Some`.
fn parse_csv(text: &str) -> Vec<Vec<Option<String>>> {
    let mut rows = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut row = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut saw_quotes = false;
    let mut field_started = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_quotes {
            if b == b'"' {
                if bytes.get(i + 1) == Some(&b'"') {
                    field.push('"');
                    i += 2;
                    continue;
                }
                in_quotes = false;
                i += 1;
                continue;
            }
            field.push(b as char);
            i += 1;
            continue;
        }
        match b {
            b'"' => {
                in_quotes = true;
                saw_quotes = true;
                field_started = true;
                i += 1;
            }
            b',' => {
                row.push(if !field_started && !saw_quotes {
                    None
                } else {
                    Some(field.clone())
                });
                field.clear();
                saw_quotes = false;
                field_started = false;
                i += 1;
            }
            b'\n' => {
                row.push(if !field_started && !saw_quotes {
                    None
                } else {
                    Some(field.clone())
                });
                rows.push(std::mem::take(&mut row));
                field.clear();
                saw_quotes = false;
                field_started = false;
                i += 1;
            }
            b'\r' => i += 1,
            other => {
                field_started = true;
                field.push(other as char);
                i += 1;
            }
        }
    }
    rows
}

#[test]
fn csv_zip_has_readme_and_stable_headers() {
    let conn = open_db();
    seed(&conn);
    let mut buf = Vec::new();
    let rows = write_csv_zip(&conn, &options(None, false), &mut buf).unwrap();
    assert_eq!(rows, db_record_count(&conn) as u64);
    let entries = unzip(&buf);
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "processes.csv",
            "net_flows.csv",
            "dns.csv",
            "gaps.csv",
            "README.txt"
        ]
    );
    let readme = std::str::from_utf8(&entries[4].body).unwrap();
    assert!(readme.contains("SQL NULL"));
    assert!(readme.contains("bytes_up"));

    let processes = parse_csv(std::str::from_utf8(&entries[0].body).unwrap());
    let nets = parse_csv(std::str::from_utf8(&entries[1].body).unwrap());
    let dns = parse_csv(std::str::from_utf8(&entries[2].body).unwrap());
    let gaps = parse_csv(std::str::from_utf8(&entries[3].body).unwrap());

    assert_eq!(
        processes[0]
            .iter()
            .map(|c| c.as_deref().unwrap())
            .collect::<Vec<_>>()
            .join(","),
        PROC_HEADER
    );
    assert_eq!(
        nets[0]
            .iter()
            .map(|c| c.as_deref().unwrap())
            .collect::<Vec<_>>()
            .join(","),
        NET_HEADER
    );
    assert_eq!(
        dns[0]
            .iter()
            .map(|c| c.as_deref().unwrap())
            .collect::<Vec<_>>()
            .join(","),
        DNS_HEADER
    );
    assert_eq!(
        gaps[0]
            .iter()
            .map(|c| c.as_deref().unwrap())
            .collect::<Vec<_>>()
            .join(","),
        GAP_HEADER
    );

    assert_eq!(processes.len(), 3);
    assert_eq!(nets.len(), 3);
    assert_eq!(dns.len(), 3);
    assert_eq!(gaps.len(), 2);

    let root = processes
        .iter()
        .find(|row| row[1].as_deref() == Some("8"))
        .unwrap();
    assert_eq!(root[8].as_deref(), Some("7"));
    let unknown_exit = processes
        .iter()
        .find(|row| row[1].as_deref() == Some("1"))
        .unwrap();
    assert!(unknown_exit[8].is_none(), "unknown exit code stays empty");

    let example = nets
        .iter()
        .find(|row| row[9].as_deref() == Some("example.com"))
        .unwrap();
    assert!(example[16].is_none(), "bytes_up NULL is not zero");
    assert!(example[17].is_none(), "bytes_down NULL is not zero");
    let local = nets
        .iter()
        .find(|row| row[9].as_deref() == Some("pc.local"))
        .unwrap();
    assert_eq!(local[16].as_deref(), Some("5"));
    assert_eq!(local[17].as_deref(), Some("6"));
    assert_eq!(gaps[1][9].as_deref(), Some("E1"));
    assert!(gaps[1][7].is_none(), "unknown gap count stays empty");
}
