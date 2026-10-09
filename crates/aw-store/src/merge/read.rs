//! Read one JSONL export produced by [`crate::export`].
//!
//! Only the header, `processes`, and `net_flows` lines are kept. Other record
//! types (`dns`, `gaps`) are skipped: they are not inputs to pairing and this
//! merge does not re-export them. A line that is not one JSON object is an
//! error. The line text is not copied into the error.
//!
//! Addresses and ports stay `Option`. Absence is not turned into `0` or
//! `0.0.0.0` here. The database insert later has to satisfy `NOT NULL`; that
//! conversion is local to the writer and those rows do not enter pairing.

use std::path::Path;

use super::{read_line, MergeError};

/// Fields taken from the header `session` object.
#[derive(Clone, Debug)]
pub struct HeaderFields {
    pub id: i64,
    pub public_id: String,
    pub name: Option<String>,
    pub mode: String,
    pub agent: Option<String>,
    pub started_ns: i64,
    pub ended_ns: Option<i64>,
    pub platform: String,
    pub user_id: String,
    pub collectors_json: String,
}

/// One `processes` line. Images, argv, and env are not in this export.
#[derive(Clone, Debug)]
pub struct ProcessFields {
    pub proc_uid: i64,
    pub pid: i64,
    pub parent_uid: Option<i64>,
    pub ppid: Option<i64>,
    pub depth: i64,
    pub start_ns: i64,
    pub exit_ns: Option<i64>,
    pub exit_code: Option<i64>,
    pub exit_signal: Option<i64>,
    pub how: String,
    pub user_id: Option<String>,
    pub signer: Option<String>,
    pub evidence: String,
    pub field_evidence: Option<String>,
    pub source: String,
    pub agent: Option<String>,
}

/// One `net_flows` line. Tuple fields are `Option` so a missing value stays
/// missing.
#[derive(Clone, Debug)]
pub struct FlowFields {
    pub session_id: i64,
    pub proc_uid: i64,
    pub proto: String,
    pub direction: String,
    pub local_ip: Option<String>,
    pub local_port: Option<u16>,
    pub remote_ip: Option<String>,
    pub remote_port: Option<u16>,
    pub domain: Option<String>,
    pub domain_source: Option<String>,
    pub domain_alts: Option<String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub start_ns: Option<i64>,
    pub end_ns: Option<i64>,
    pub bytes_up: Option<i64>,
    pub bytes_down: Option<i64>,
    pub via_proxy: Option<i64>,
    pub direct: Option<i64>,
    pub preexisting: Option<i64>,
    pub is_loopback: Option<i64>,
    pub result: Option<i64>,
    pub platform_total_up: Option<i64>,
    pub platform_total_down: Option<i64>,
    pub evidence: String,
    pub na_reason: Option<String>,
    pub field_evidence: Option<String>,
    pub source: String,
}

impl FlowFields {
    /// True when proto and both endpoints are present. Port `0` and the
    /// unspecified addresses are treated as absent: the exporter writes a real
    /// port as an integer, and this importer refuses to pair on a zero port.
    pub fn tuple_complete(&self) -> bool {
        let local_ok = matches!(
            self.local_ip.as_deref(),
            Some(ip) if !ip.is_empty() && ip != "0.0.0.0" && ip != "::"
        );
        let remote_ok = matches!(
            self.remote_ip.as_deref(),
            Some(ip) if !ip.is_empty() && ip != "0.0.0.0" && ip != "::"
        );
        local_ok
            && remote_ok
            && self.local_port.is_some_and(|port| port != 0)
            && self.remote_port.is_some_and(|port| port != 0)
            && !self.proto.is_empty()
    }
}

/// One loaded export. `session_id` is the header id, or `1` when the header
/// omitted it (then both files would collide; the caller remaps).
#[derive(Clone, Debug)]
pub struct LoadedExport {
    pub session_id: i64,
    pub header: HeaderFields,
    pub processes: Vec<ProcessFields>,
    pub flows: Vec<FlowFields>,
}

pub(crate) fn load_export(path: &Path) -> Result<LoadedExport, MergeError> {
    let mut reader = super::open_text(path)?;
    let mut line_no = 0_u64;
    let mut header: Option<HeaderFields> = None;
    let mut processes = Vec::new();
    let mut flows = Vec::new();
    while let Some(line) = read_line(&mut reader, path)? {
        line_no += 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let obj = JsonObj::parse(trimmed).ok_or(MergeError::BadExport {
            path: path.to_path_buf(),
            line: line_no,
            detail: "line is not one JSON object",
        })?;
        let kind = obj.string("type").ok_or(MergeError::BadExport {
            path: path.to_path_buf(),
            line: line_no,
            detail: "line has no type string",
        })?;
        match kind.as_str() {
            "header" => {
                if header.is_some() {
                    return Err(MergeError::BadExport {
                        path: path.to_path_buf(),
                        line: line_no,
                        detail: "more than one header",
                    });
                }
                header = Some(parse_header(&obj, path, line_no)?);
            }
            "processes" => processes.push(parse_process(&obj, path, line_no)?),
            "net_flows" => flows.push(parse_flow(&obj, path, line_no)?),
            "dns" | "gaps" => {}
            _ => {
                return Err(MergeError::BadExport {
                    path: path.to_path_buf(),
                    line: line_no,
                    detail: "unknown record type",
                });
            }
        }
    }
    let header = header.ok_or(MergeError::BadExport {
        path: path.to_path_buf(),
        line: 1,
        detail: "export has no header",
    })?;
    let session_id = header.id;
    // Flow lines repeat session_id, but a hand-built line may omit it. The
    // header id is the session this file belongs to. 0 is not a session.
    for flow in &mut flows {
        if flow.session_id == 0 {
            flow.session_id = session_id;
        }
    }
    Ok(LoadedExport {
        session_id,
        header,
        processes,
        flows,
    })
}

fn parse_header(obj: &JsonObj, path: &Path, line: u64) -> Result<HeaderFields, MergeError> {
    let session = obj.object("session").ok_or(MergeError::BadExport {
        path: path.to_path_buf(),
        line,
        detail: "header has no session object",
    })?;
    let id = session.i64("id").ok_or(MergeError::BadExport {
        path: path.to_path_buf(),
        line,
        detail: "session.id is missing",
    })?;
    let public_id = session.string("public_id").ok_or(MergeError::BadExport {
        path: path.to_path_buf(),
        line,
        detail: "session.public_id is missing",
    })?;
    let mode = session
        .string("mode")
        .unwrap_or_else(|| "attach".to_owned());
    let mode = if mode == "launch" || mode == "attach" {
        mode
    } else {
        "attach".to_owned()
    };
    let started_ns = session.i64("started_ns").ok_or(MergeError::BadExport {
        path: path.to_path_buf(),
        line,
        detail: "session.started_ns is missing",
    })?;
    let user_id = session
        .string("user_id")
        .unwrap_or_else(|| "unknown".to_owned());
    let platform = session
        .string("platform")
        .unwrap_or_else(|| "unknown".to_owned());
    let collectors_json = obj
        .raw("collectors")
        .filter(|text| text != "null")
        .unwrap_or_else(|| "[]".to_owned());
    Ok(HeaderFields {
        id,
        public_id,
        name: session.opt_string("name"),
        mode,
        agent: session.opt_string("agent"),
        started_ns,
        ended_ns: session.opt_i64("ended_ns"),
        platform,
        user_id,
        collectors_json,
    })
}

fn parse_process(obj: &JsonObj, path: &Path, line: u64) -> Result<ProcessFields, MergeError> {
    Ok(ProcessFields {
        proc_uid: required_i64(obj, "proc_uid", path, line)?,
        pid: required_i64(obj, "pid", path, line)?,
        parent_uid: obj.opt_i64("parent_uid"),
        ppid: obj.opt_i64("ppid"),
        depth: obj.i64("depth").unwrap_or(0),
        start_ns: required_i64(obj, "start_ns", path, line)?,
        exit_ns: obj.opt_i64("exit_ns"),
        exit_code: obj.opt_i64("exit_code"),
        exit_signal: obj.opt_i64("exit_signal"),
        how: obj.string("how").unwrap_or_else(|| "unknown".to_owned()),
        user_id: obj.opt_string("user_id"),
        signer: obj.opt_string("signer"),
        evidence: obj.string("evidence").unwrap_or_else(|| "NA".to_owned()),
        field_evidence: obj.raw("field_evidence").filter(|text| text != "null"),
        source: obj
            .string("source")
            .unwrap_or_else(|| "offline.merge/import".to_owned()),
        agent: obj.opt_string("agent"),
    })
}

fn parse_flow(obj: &JsonObj, path: &Path, line: u64) -> Result<FlowFields, MergeError> {
    Ok(FlowFields {
        session_id: obj.i64("session_id").unwrap_or(0),
        proc_uid: required_i64(obj, "proc_uid", path, line)?,
        proto: obj.string("proto").unwrap_or_default(),
        direction: obj
            .string("direction")
            .unwrap_or_else(|| "unknown".to_owned()),
        local_ip: present_addr(obj.opt_string("local_ip")),
        local_port: present_port(obj.opt_i64("local_port")),
        remote_ip: present_addr(obj.opt_string("remote_ip")),
        remote_port: present_port(obj.opt_i64("remote_port")),
        domain: obj.opt_string("domain"),
        domain_source: obj.opt_string("domain_source"),
        domain_alts: obj.raw("domain_alts").filter(|text| text != "null"),
        sni: obj.opt_string("sni"),
        alpn: obj.opt_string("alpn"),
        start_ns: obj.opt_i64("start_ns"),
        end_ns: obj.opt_i64("end_ns"),
        bytes_up: obj.opt_i64("bytes_up"),
        bytes_down: obj.opt_i64("bytes_down"),
        via_proxy: obj.opt_i64("via_proxy"),
        direct: obj.opt_i64("direct"),
        preexisting: obj.opt_i64("preexisting"),
        is_loopback: obj.opt_i64("is_loopback"),
        result: obj.opt_i64("result"),
        platform_total_up: obj.opt_i64("platform_total_up"),
        platform_total_down: obj.opt_i64("platform_total_down"),
        evidence: obj.string("evidence").unwrap_or_else(|| "NA".to_owned()),
        na_reason: obj.opt_string("na_reason"),
        field_evidence: obj.raw("field_evidence").filter(|text| text != "null"),
        source: obj
            .string("source")
            .unwrap_or_else(|| "offline.merge/import".to_owned()),
    })
}

fn present_addr(value: Option<String>) -> Option<String> {
    value.and_then(|text| {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

/// A port outside `1..=65535` is absent. Zero is not a real port.
fn present_port(value: Option<i64>) -> Option<u16> {
    value
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
}

fn required_i64(
    obj: &JsonObj,
    key: &'static str,
    path: &Path,
    line: u64,
) -> Result<i64, MergeError> {
    obj.i64(key).ok_or(MergeError::BadExport {
        path: path.to_path_buf(),
        line,
        detail: match key {
            "proc_uid" => "proc_uid is missing",
            "pid" => "pid is missing",
            "start_ns" => "start_ns is missing",
            _ => "a required integer is missing",
        },
    })
}

/// Flat JSON object. Nested objects are kept as raw text under their key.
/// Enough for the export shape: one level of `session`, plus scalar columns.
struct JsonObj {
    fields: Vec<(String, JsonVal)>,
}

enum JsonVal {
    Null,
    String(String),
    Number(i64),
    Raw(String),
}

impl JsonObj {
    fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        let mut i = skip_ws(bytes, 0);
        if i >= bytes.len() || bytes[i] != b'{' {
            return None;
        }
        i += 1;
        let mut fields = Vec::new();
        loop {
            i = skip_ws(bytes, i);
            if i >= bytes.len() {
                return None;
            }
            if bytes[i] == b'}' {
                i += 1;
                i = skip_ws(bytes, i);
                if i != bytes.len() {
                    return None;
                }
                return Some(Self { fields });
            }
            if !fields.is_empty() {
                if bytes[i] != b',' {
                    return None;
                }
                i += 1;
                i = skip_ws(bytes, i);
            }
            let key = parse_string(bytes, &mut i)?;
            i = skip_ws(bytes, i);
            if i >= bytes.len() || bytes[i] != b':' {
                return None;
            }
            i += 1;
            i = skip_ws(bytes, i);
            let (val, next) = parse_val(bytes, i)?;
            i = next;
            fields.push((key, val));
        }
    }

    fn get(&self, key: &str) -> Option<&JsonVal> {
        self.fields
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, val)| val)
    }

    fn string(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            JsonVal::String(text) => Some(text.clone()),
            _ => None,
        }
    }

    fn opt_string(&self, key: &str) -> Option<String> {
        match self.get(key) {
            Some(JsonVal::String(text)) => Some(text.clone()),
            _ => None,
        }
    }

    fn i64(&self, key: &str) -> Option<i64> {
        match self.get(key)? {
            JsonVal::Number(n) => Some(*n),
            _ => None,
        }
    }

    fn opt_i64(&self, key: &str) -> Option<i64> {
        match self.get(key) {
            Some(JsonVal::Number(n)) => Some(*n),
            _ => None,
        }
    }

    fn object(&self, key: &str) -> Option<JsonObj> {
        match self.get(key)? {
            JsonVal::Raw(text) => JsonObj::parse(text),
            _ => None,
        }
    }

    fn raw(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            JsonVal::Null => Some("null".to_owned()),
            JsonVal::String(text) => Some(format!("\"{text}\"")),
            JsonVal::Number(n) => Some(n.to_string()),
            JsonVal::Raw(text) => Some(text.clone()),
        }
    }
}

fn parse_val(bytes: &[u8], mut i: usize) -> Option<(JsonVal, usize)> {
    if i >= bytes.len() {
        return None;
    }
    match bytes[i] {
        b'n' => {
            eat(bytes, &mut i, b"null")?;
            Some((JsonVal::Null, i))
        }
        b't' => {
            eat(bytes, &mut i, b"true")?;
            Some((JsonVal::Raw("true".to_owned()), i))
        }
        b'f' => {
            eat(bytes, &mut i, b"false")?;
            Some((JsonVal::Raw("false".to_owned()), i))
        }
        b'"' => {
            let text = parse_string(bytes, &mut i)?;
            Some((JsonVal::String(text), i))
        }
        b'-' | b'0'..=b'9' => {
            let start = i;
            let n = parse_i64(bytes, &mut i)?;
            // Non-integer JSON numbers are kept raw so we do not pretend they
            // were observed as integers.
            if bytes[start..i].contains(&b'.')
                || bytes[start..i].contains(&b'e')
                || bytes[start..i].contains(&b'E')
            {
                Some((
                    JsonVal::Raw(String::from_utf8_lossy(&bytes[start..i]).into_owned()),
                    i,
                ))
            } else {
                Some((JsonVal::Number(n), i))
            }
        }
        b'{' | b'[' => {
            let start = i;
            if !skip_container(bytes, &mut i) {
                return None;
            }
            let raw = String::from_utf8_lossy(&bytes[start..i]).into_owned();
            Some((JsonVal::Raw(raw), i))
        }
        _ => None,
    }
}

fn eat(bytes: &[u8], i: &mut usize, lit: &[u8]) -> Option<()> {
    if bytes[*i..].starts_with(lit) {
        *i += lit.len();
        Some(())
    } else {
        None
    }
}

fn parse_string(bytes: &[u8], i: &mut usize) -> Option<String> {
    if *i >= bytes.len() || bytes[*i] != b'"' {
        return None;
    }
    *i += 1;
    let mut out = String::new();
    while *i < bytes.len() {
        let b = bytes[*i];
        *i += 1;
        match b {
            b'"' => return Some(out),
            b'\\' => {
                if *i >= bytes.len() {
                    return None;
                }
                let esc = bytes[*i];
                *i += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hex = bytes.get(*i..*i + 4)?;
                        let text = std::str::from_utf8(hex).ok()?;
                        let code = u32::from_str_radix(text, 16).ok()?;
                        let ch = char::from_u32(code)?;
                        out.push(ch);
                        *i += 4;
                    }
                    _ => return None,
                }
            }
            _ => {
                // Step back and take one UTF-8 char.
                *i -= 1;
                let rest = std::str::from_utf8(&bytes[*i..]).ok()?;
                let ch = rest.chars().next()?;
                out.push(ch);
                *i += ch.len_utf8();
            }
        }
    }
    None
}

fn parse_i64(bytes: &[u8], i: &mut usize) -> Option<i64> {
    let start = *i;
    if bytes.get(*i) == Some(&b'-') {
        *i += 1;
    }
    if *i >= bytes.len() || !bytes[*i].is_ascii_digit() {
        return None;
    }
    while *i < bytes.len() && bytes[*i].is_ascii_digit() {
        *i += 1;
    }
    // Stop at a fraction or exponent; the caller notices those bytes.
    let end = *i;
    if *i < bytes.len() && bytes[*i] == b'.' {
        *i += 1;
        while *i < bytes.len() && bytes[*i].is_ascii_digit() {
            *i += 1;
        }
    }
    if *i < bytes.len() && (bytes[*i] == b'e' || bytes[*i] == b'E') {
        *i += 1;
        if *i < bytes.len() && (bytes[*i] == b'+' || bytes[*i] == b'-') {
            *i += 1;
        }
        while *i < bytes.len() && bytes[*i].is_ascii_digit() {
            *i += 1;
        }
    }
    let text = std::str::from_utf8(&bytes[start..end]).ok()?;
    let _ = end;
    text.parse().ok()
}

fn skip_container(bytes: &[u8], i: &mut usize) -> bool {
    if *i >= bytes.len() {
        return false;
    }
    let open = bytes[*i];
    let close = if open == b'{' { b'}' } else { b']' };
    *i += 1;
    let mut depth = 1_i32;
    let mut in_str = false;
    let mut escape = false;
    while *i < bytes.len() {
        let b = bytes[*i];
        *i += 1;
        if in_str {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return b == close;
                }
            }
            _ => {}
        }
    }
    false
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}
