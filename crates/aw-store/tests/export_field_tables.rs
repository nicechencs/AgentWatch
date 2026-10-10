//! Pins JSONL keys and CSV headers to the field tables in storage.md §3 and §7.
//!
//! The documented columns are the `CREATE TABLE` bodies in
//! `docs/01-architecture/storage.md` §3 (the export writer says it mirrors those
//! columns). storage.md §7 adds two export-only fields that are not table
//! columns: every JSONL line carries `type`, and a `processes` JSONL line also
//! carries `exe_name`. CSV stays the table columns, except `gaps.csv`, which
//! adds the `evidence` column §7 requires and which the table does not have.
//!
//! The lists are parsed from the markdown at compile time, so a doc edit that
//! drops or reorders a column fails this test instead of drifting quietly.
//! The parser only accepts the shape those two sections have today; a rewrite
//! that it cannot read fails the test rather than matching a guessed list.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use aw_store::{ensure_timeline, write_csv_zip, write_jsonl, ExportOptions};
use rusqlite::Connection;

const SCHEMA: &str = include_str!("../migrations/0001_init.sql");

/// The only document that lists export fields. `CARGO_MANIFEST_DIR` is
/// `crates/aw-store`.
const STORAGE_MD: &str = include_str!("../../../docs/01-architecture/storage.md");

const SECTION_DDL: &str = "## 3. DDL";
const SECTION_AFTER_DDL: &str = "### 3.1 ";
const SECTION_EXPORT: &str = "## 7. 导出格式";

/// `processes` JSONL adds this key; CSV does not (README: exe is not a column).
const PROCESSES_JSONL_EXTRA: &str = "exe_name";
/// `gaps` has no evidence column. Both formats emit the literal `E1` (§7, §3.1).
const GAPS_EVIDENCE: &str = "evidence";

fn open_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(SCHEMA).unwrap();
    ensure_timeline(&conn).unwrap();
    conn
}

/// One session, one row of each kind the P1 exporter writes.
///
/// `mode` and `collectors` are English machine values (`launch`, `poll`), so
/// the export can be checked for not translating them.
fn seed(conn: &Connection) {
    conn.execute(
        "INSERT INTO sessions \
         (id, public_id, name, mode, agent, started_ns, platform, user_id, collectors) \
         VALUES (1, 'pub-fields', 'field-tables', 'launch', 'codex', 1000, 'linux', \
                 'user-a', ?)",
        [r#"[{"name":"poll","mode":"poll","version":"0"}]"#],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO processes \
         (session_id, proc_uid, pid, parent_uid, ppid, depth, start_ns, exit_ns, \
          exit_code, exit_signal, how, user_id, signer, evidence, field_evidence, \
          source, agent) \
         VALUES (1, 7, 4242, NULL, NULL, 0, 2000, NULL, NULL, NULL, 'spawn', \
                 'user-a', NULL, 'S', NULL, 'poll', 'codex')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO process_images \
         (session_id, proc_uid, seq, ts_ns, exe, evidence, source) \
         VALUES (1, 7, 0, 2000, '/usr/bin/sleep', 'S', 'poll')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO net_flows \
         (id, session_id, proc_uid, proto, direction, local_ip, local_port, remote_ip, \
          remote_port, domain, domain_source, start_ns, bytes_up, bytes_down, \
          evidence, source) \
         VALUES (11, 1, 7, 'tcp', 'outbound', '127.0.0.1', 40000, '93.184.216.34', 443, \
                 'example.com', 'sni', 3000, NULL, NULL, 'S', 'poll')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO dns \
         (id, session_id, proc_uid, ts_ns, qname, qtype, rcode, answers, evidence, source) \
         VALUES (12, 1, 7, 4000, 'example.com', 1, 0, '[{\"rtype\":\"A\",\"data\":\"93.184.216.34\"}]', \
                 'S', 'poll')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO gaps \
         (id, session_id, collector, kind, affects, from_ns, to_ns, count, detail) \
         VALUES (13, 1, 'poll', 'collector_unavailable', '[\"file\"]', 5000, 5000, NULL, NULL)",
        [],
    )
    .unwrap();
}

fn options() -> ExportOptions<'static> {
    ExportOptions {
        user_id: "user-a",
        session_id: 1,
        filter: None,
        now_ns: None,
        redact_paths: false,
        redact_hosts: false,
        page_size: Some(100),
    }
}

/// Slice of storage.md from `start_heading` up to the next line that begins
/// with `end_prefix`.
fn section_between<'a>(text: &'a str, start_heading: &str, end_prefix: &str) -> &'a str {
    let start = text
        .find(start_heading)
        .unwrap_or_else(|| panic!("storage.md has no {start_heading}"));
    let rest = &text[start + start_heading.len()..];
    let end = rest
        .find(end_prefix)
        .unwrap_or_else(|| panic!("storage.md: {start_heading} never reaches {end_prefix}"));
    &rest[..end]
}

/// Column names of one `CREATE TABLE`, in source order.
///
/// A line counts when its first word is a lowercase identifier and its second
/// word is an SQL type. Constraints, indexes, and comments fail that test, so
/// they are not columns.
fn create_table_columns(ddl: &str, table: &str) -> Vec<String> {
    let marker = format!("CREATE TABLE {table} (");
    let start = ddl
        .find(&marker)
        .unwrap_or_else(|| panic!("storage.md §3 has no CREATE TABLE {table}"));
    let body = &ddl[start + marker.len()..];
    let end = body
        .find(");")
        .unwrap_or_else(|| panic!("CREATE TABLE {table} is not closed with );"));
    let mut columns = Vec::new();
    for line in body[..end].lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("--") {
            continue;
        }
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else {
            continue;
        };
        let Some(kind) = words.next() else {
            continue;
        };
        let is_name = name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
        let is_type = matches!(
            kind.trim_end_matches(','),
            "INTEGER" | "TEXT" | "REAL" | "BLOB"
        );
        if is_name && is_type {
            columns.push(name.to_string());
        }
    }
    assert!(
        !columns.is_empty(),
        "parsed no columns for {table}; the DDL shape changed"
    );
    columns
}

/// JSONL key order: `type`, then the documented table columns, with `inserts`
/// placed immediately after the named column, then `extra` appended.
///
/// An insert names the column it follows. Matching the column itself would
/// emit the extra key and then repeat the column.
fn jsonl_keys(columns: &[String], inserts: &[(&str, &str)], extra: &[&str]) -> Vec<String> {
    let mut keys = Vec::with_capacity(1 + columns.len() + inserts.len() + extra.len());
    keys.push("type".to_string());
    for column in columns {
        keys.push(column.clone());
        for (after, name) in inserts {
            if column == after {
                keys.push((*name).to_string());
            }
        }
    }
    keys.extend(extra.iter().map(|name| (*name).to_string()));
    keys
}

fn documented_jsonl_keys() -> BTreeMap<&'static str, Vec<String>> {
    let ddl = section_between(STORAGE_MD, SECTION_DDL, SECTION_AFTER_DDL);
    let mut out = BTreeMap::new();
    let processes = create_table_columns(ddl, "processes");
    // exe_name is the export-only key §7 adds. The writer places it immediately
    // after `pid` (before parent_uid); §7 does not fix that position.
    out.insert(
        "processes",
        jsonl_keys(&processes, &[("pid", PROCESSES_JSONL_EXTRA)], &[]),
    );
    out.insert(
        "net_flows",
        jsonl_keys(&create_table_columns(ddl, "net_flows"), &[], &[]),
    );
    out.insert(
        "dns",
        jsonl_keys(&create_table_columns(ddl, "dns"), &[], &[]),
    );
    // The table has no evidence column. JSONL appends evidence and the
    // field_evidence the writer emits as null (export module comment, §3.1).
    out.insert(
        "gaps",
        jsonl_keys(
            &create_table_columns(ddl, "gaps"),
            &[],
            &[GAPS_EVIDENCE, "field_evidence"],
        ),
    );
    out
}

fn documented_csv_headers() -> BTreeMap<&'static str, Vec<String>> {
    let ddl = section_between(STORAGE_MD, SECTION_DDL, SECTION_AFTER_DDL);
    let mut out = BTreeMap::new();
    out.insert("processes.csv", create_table_columns(ddl, "processes"));
    out.insert("net_flows.csv", create_table_columns(ddl, "net_flows"));
    out.insert("dns.csv", create_table_columns(ddl, "dns"));
    let mut gaps = create_table_columns(ddl, "gaps");
    gaps.push(GAPS_EVIDENCE.to_string());
    out.insert("gaps.csv", gaps);
    out
}

/// §7 names these CSV entries, in this order. Parsing the prose sentence is
/// too brittle, so the list lives here and each name must still occur in §7.
const DOCUMENTED_CSV_FILES: [&str; 13] = [
    "processes.csv",
    "file_access.csv",
    "net_flows.csv",
    "dns.csv",
    "http.csv",
    "findings.csv",
    "gaps.csv",
    "watch_groups.csv",
    "agent_instances.csv",
    "ipc_channels.csv",
    "agent_rpc.csv",
    "agent_links.csv",
    "README.txt",
];

/// P1 files the exporter actually writes, in zip order (export module comment).
const P1_CSV_FILES: [&str; 5] = [
    "processes.csv",
    "net_flows.csv",
    "dns.csv",
    "gaps.csv",
    "README.txt",
];

fn export_section() -> &'static str {
    let start = STORAGE_MD
        .find(SECTION_EXPORT)
        .expect("storage.md has no §7");
    &STORAGE_MD[start..]
}

/// Object keys in the order written, not sorted.
fn object_keys(line: &str) -> Vec<String> {
    match parse_value(line.as_bytes(), &mut 0) {
        Json::Object(keys) => keys.into_iter().map(|(key, _)| key).collect(),
        other => panic!("expected object, got {other:?}"),
    }
}

fn object_fields(line: &str) -> BTreeMap<String, Json> {
    match parse_value(line.as_bytes(), &mut 0) {
        Json::Object(pairs) => pairs.into_iter().collect(),
        other => panic!("expected object, got {other:?}"),
    }
}

#[derive(Debug)]
enum Json {
    Null,
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
    Other,
}

fn parse_value(bytes: &[u8], i: &mut usize) -> Json {
    skip(bytes, i);
    match bytes.get(*i).copied() {
        Some(b'n') => {
            *i += 4;
            Json::Null
        }
        Some(b't') => {
            *i += 4;
            Json::Other
        }
        Some(b'f') => {
            *i += 5;
            Json::Other
        }
        Some(b'"') => Json::String(parse_string(bytes, i)),
        Some(b'[') => {
            *i += 1;
            let mut items = Vec::new();
            loop {
                skip(bytes, i);
                if bytes.get(*i) == Some(&b']') {
                    *i += 1;
                    break;
                }
                items.push(parse_value(bytes, i));
                skip(bytes, i);
                if bytes.get(*i) == Some(&b',') {
                    *i += 1;
                }
            }
            Json::Array(items)
        }
        Some(b'{') => {
            *i += 1;
            let mut pairs = Vec::new();
            loop {
                skip(bytes, i);
                if bytes.get(*i) == Some(&b'}') {
                    *i += 1;
                    break;
                }
                let key = parse_string(bytes, i);
                skip(bytes, i);
                assert_eq!(bytes.get(*i), Some(&b':'));
                *i += 1;
                pairs.push((key, parse_value(bytes, i)));
                skip(bytes, i);
                if bytes.get(*i) == Some(&b',') {
                    *i += 1;
                }
            }
            Json::Object(pairs)
        }
        Some(b'-') | Some(b'0'..=b'9') => {
            while matches!(bytes.get(*i), Some(b'-' | b'0'..=b'9')) {
                *i += 1;
            }
            Json::Other
        }
        other => panic!("bad json byte {other:?} at {i}"),
    }
}

fn parse_string(bytes: &[u8], i: &mut usize) -> String {
    assert_eq!(bytes.get(*i), Some(&b'"'));
    *i += 1;
    let mut out = String::new();
    while bytes.get(*i) != Some(&b'"') {
        let b = bytes[*i];
        *i += 1;
        if b == b'\\' {
            let esc = bytes[*i];
            *i += 1;
            out.push(match esc {
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                b'n' => '\n',
                other => panic!("bad escape {other}"),
            });
        } else {
            out.push(b as char);
        }
    }
    *i += 1;
    out
}

fn skip(bytes: &[u8], i: &mut usize) {
    while matches!(bytes.get(*i), Some(b' ' | b'\n' | b'\r' | b'\t')) {
        *i += 1;
    }
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
        let comp = u32::from_le_bytes(bytes[i + 18..i + 22].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes(bytes[i + 26..i + 28].try_into().unwrap()) as usize;
        let extra = u16::from_le_bytes(bytes[i + 28..i + 30].try_into().unwrap()) as usize;
        let name_at = i + 30;
        let name = String::from_utf8(bytes[name_at..name_at + name_len].to_vec()).unwrap();
        let data_at = name_at + name_len + extra;
        entries.push(ZipEntry {
            name,
            body: bytes[data_at..data_at + comp].to_vec(),
        });
        i = data_at + comp;
    }
    entries
}

fn csv_header(text: &str) -> Vec<String> {
    let line = text.lines().next().expect("csv has a header");
    line.split(',').map(str::to_string).collect()
}

#[test]
fn section_seven_names_every_listed_csv_file() {
    let section = export_section();
    for name in DOCUMENTED_CSV_FILES {
        assert!(
            section.contains(name),
            "storage.md §7 does not mention {name}"
        );
    }
    assert!(
        section.contains(PROCESSES_JSONL_EXTRA),
        "storage.md §7 does not mention {PROCESSES_JSONL_EXTRA}"
    );
    assert!(section.contains("evidence"));
}

#[test]
fn jsonl_key_order_matches_the_documented_columns() {
    let conn = open_db();
    seed(&conn);
    let mut buf = Vec::new();
    let rows = write_jsonl(&conn, &options(), &mut buf).unwrap();
    assert_eq!(rows, 4, "one row of each P1 kind");
    let text = String::from_utf8(buf).unwrap();
    let mut lines = text.lines();

    let header_line = lines.next().unwrap();
    let header = object_fields(header_line);
    // Written order, not the sorted map. §7 lists these five names; the module
    // comment fixes this sequence.
    assert_eq!(
        object_keys(header_line),
        vec![
            "type",
            "export_version",
            "session",
            "collectors",
            "gaps_summary",
        ]
    );
    match &header["type"] {
        Json::String(value) => assert_eq!(value, "header"),
        other => panic!("{other:?}"),
    }
    match &header["session"] {
        Json::Object(pairs) => {
            let keys: Vec<&str> = pairs.iter().map(|(key, _)| key.as_str()).collect();
            assert_eq!(
                keys,
                vec![
                    "id",
                    "public_id",
                    "name",
                    "mode",
                    "agent",
                    "started_ns",
                    "ended_ns",
                    "platform",
                    "user_id",
                ]
            );
            assert!(
                matches!(&pairs[3].1, Json::String(value) if value == "launch"),
                "mode is the English machine value"
            );
        }
        other => panic!("session: {other:?}"),
    }
    match &header["collectors"] {
        Json::Array(items) => match &items[0] {
            Json::Object(pairs) => {
                let name = pairs.iter().find(|(key, _)| key == "name").unwrap();
                assert!(matches!(&name.1, Json::String(value) if value == "poll"));
            }
            other => panic!("collector: {other:?}"),
        },
        other => panic!("collectors: {other:?}"),
    }

    let expected = documented_jsonl_keys();
    let mut seen = BTreeMap::<String, Vec<String>>::new();
    for line in lines {
        let keys = object_keys(line);
        let kind = match object_fields(line).remove("type") {
            Some(Json::String(value)) => value,
            other => panic!("record line has no type string: {other:?}"),
        };
        assert!(
            !seen.contains_key(&kind),
            "more than one {kind} line; the seed inserts one of each"
        );
        seen.insert(kind, keys);
    }
    assert_eq!(seen.len(), expected.len(), "kinds: {seen:?}");
    for (kind, want) in &expected {
        let got = seen.get(*kind).unwrap_or_else(|| panic!("no {kind} line"));
        assert_eq!(got, want, "{kind} key order drifted from storage.md §3/§7");
    }
}

#[test]
fn csv_headers_match_the_documented_columns() {
    let conn = open_db();
    seed(&conn);
    let mut buf = Vec::new();
    write_csv_zip(&conn, &options(), &mut buf).unwrap();
    let entries = unzip(&buf);
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, P1_CSV_FILES, "P1 zip entries");

    let expected = documented_csv_headers();
    for entry in &entries {
        if entry.name == "README.txt" {
            let readme = std::str::from_utf8(&entry.body).unwrap();
            assert!(readme.contains("processes.csv"));
            assert!(readme.contains("evidence"));
            continue;
        }
        let want = expected
            .get(entry.name.as_str())
            .unwrap_or_else(|| panic!("{} has no documented column list", entry.name));
        let text = std::str::from_utf8(&entry.body).unwrap();
        let header = csv_header(text);
        assert_eq!(
            header, *want,
            "{} header drifted from storage.md §3/§7",
            entry.name
        );
        assert!(
            text.lines().nth(1).is_some(),
            "{} has a header but no data row",
            entry.name
        );
    }
}

#[test]
fn machine_values_stay_english() {
    let conn = open_db();
    seed(&conn);

    let mut jsonl = Vec::new();
    write_jsonl(&conn, &options(), &mut jsonl).unwrap();
    let text = String::from_utf8(jsonl).unwrap();
    let process = text
        .lines()
        .find(|line| line.contains("\"type\":\"processes\""))
        .unwrap();
    let fields = object_fields(process);
    assert!(matches!(fields.get("how"), Some(Json::String(value)) if value == "spawn"));
    assert!(matches!(fields.get("source"), Some(Json::String(value)) if value == "poll"));
    assert!(matches!(fields.get("evidence"), Some(Json::String(value)) if value == "S"));
    assert!(matches!(fields.get("exe_name"), Some(Json::String(value)) if value == "sleep"));

    let flow = text
        .lines()
        .find(|line| line.contains("\"type\":\"net_flows\""))
        .unwrap();
    let fields = object_fields(flow);
    assert!(matches!(fields.get("proto"), Some(Json::String(value)) if value == "tcp"));
    assert!(matches!(fields.get("direction"), Some(Json::String(value)) if value == "outbound"));
    assert!(matches!(fields.get("domain_source"), Some(Json::String(value)) if value == "sni"));

    let mut zip = Vec::new();
    write_csv_zip(&conn, &options(), &mut zip).unwrap();
    let entries = unzip(&zip);
    let processes = std::str::from_utf8(
        &entries
            .iter()
            .find(|entry| entry.name == "processes.csv")
            .unwrap()
            .body,
    )
    .unwrap();
    let row = processes.lines().nth(1).unwrap();
    assert!(row.contains("\"spawn\""), "{row}");
    assert!(row.contains("\"poll\""), "{row}");
    assert!(row.contains("\"S\""), "{row}");
    let flows = std::str::from_utf8(
        &entries
            .iter()
            .find(|entry| entry.name == "net_flows.csv")
            .unwrap()
            .body,
    )
    .unwrap();
    let row = flows.lines().nth(1).unwrap();
    assert!(row.contains("\"tcp\""), "{row}");
    assert!(row.contains("\"outbound\""), "{row}");
    assert!(row.contains("\"sni\""), "{row}");
}
