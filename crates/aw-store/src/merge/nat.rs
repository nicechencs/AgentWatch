//! Caller-supplied NAT map. One `ip:port -> ip:port` per line.
//!
//! Blank lines and lines whose first non-whitespace character is `#` are
//! skipped. The file is the only source: nothing is read from `/etc` or the
//! host routing table. A missing file is the caller's problem (they passed a
//! path); a merge with no `--nat` never opens one.

use std::collections::BTreeMap;
use std::path::Path;

use super::{read_line, MergeError};

/// One rewritten endpoint. Addresses stay as the caller wrote them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    /// Address text, not parsed into a numeric form.
    pub ip: String,
    /// Port. Never invented: the line had to contain one.
    pub port: u16,
}

/// `from -> to` rewrites applied to both sides before mirror matching.
#[derive(Clone, Debug, Default)]
pub struct NatMap {
    map: BTreeMap<(String, u16), Endpoint>,
}

impl NatMap {
    pub(crate) fn empty() -> Self {
        Self {
            map: BTreeMap::new(),
        }
    }

    /// Rewrite `ip:port` when the map has an entry. Otherwise return the input.
    pub(crate) fn rewrite<'a>(&'a self, ip: &'a str, port: u16) -> (&'a str, u16) {
        for ((from_ip, from_port), to) in &self.map {
            if *from_port == port && from_ip == ip {
                return (to.ip.as_str(), to.port);
            }
        }
        (ip, port)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Load a NAT map. JSON object form `{"ip:port": "ip:port", ...}` is also
/// accepted when the file starts with `{`.
pub(crate) fn load(path: &Path) -> Result<NatMap, MergeError> {
    let mut reader = super::open_text(path)?;
    let mut map = NatMap::empty();
    let mut line_no = 0_u64;
    let mut first = true;
    let mut json = String::new();
    while let Some(line) = read_line(&mut reader, path)? {
        line_no += 1;
        if first {
            first = false;
            let trimmed = line.trim();
            if trimmed.starts_with('{') {
                json.push_str(trimmed);
                continue;
            }
        }
        if !json.is_empty() {
            json.push_str(line.trim());
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (from, to) = split_arrow(trimmed).ok_or(MergeError::BadNat {
            path: path.to_path_buf(),
            line: line_no,
        })?;
        let from = parse_endpoint(from).ok_or(MergeError::BadNat {
            path: path.to_path_buf(),
            line: line_no,
        })?;
        let to = parse_endpoint(to).ok_or(MergeError::BadNat {
            path: path.to_path_buf(),
            line: line_no,
        })?;
        map.map.insert((from.ip, from.port), to);
    }
    if !json.is_empty() {
        parse_json_map(&json, path, &mut map)?;
    }
    let _ = map.is_empty();
    Ok(map)
}

fn parse_json_map(text: &str, path: &Path, map: &mut NatMap) -> Result<(), MergeError> {
    let text = text.trim();
    if !text.starts_with('{') || !text.ends_with('}') {
        return Err(MergeError::BadNat {
            path: path.to_path_buf(),
            line: 1,
        });
    }
    let body = &text[1..text.len() - 1];
    if body.trim().is_empty() {
        return Ok(());
    }
    for (idx, part) in split_json_pairs(body).into_iter().enumerate() {
        let line = u64::try_from(idx).unwrap_or(1) + 1;
        let (key, value) = split_colon_pair(part).ok_or(MergeError::BadNat {
            path: path.to_path_buf(),
            line,
        })?;
        let key = unquote(key).ok_or(MergeError::BadNat {
            path: path.to_path_buf(),
            line,
        })?;
        let value = unquote(value).ok_or(MergeError::BadNat {
            path: path.to_path_buf(),
            line,
        })?;
        let from = parse_endpoint(&key).ok_or(MergeError::BadNat {
            path: path.to_path_buf(),
            line,
        })?;
        let to = parse_endpoint(&value).ok_or(MergeError::BadNat {
            path: path.to_path_buf(),
            line,
        })?;
        map.map.insert((from.ip, from.port), to);
    }
    Ok(())
}

fn split_json_pairs(body: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut in_str = false;
    let mut escape = false;
    for (idx, ch) in body.char_indices() {
        if in_str {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        if ch == '"' {
            in_str = true;
            continue;
        }
        if ch == ',' {
            out.push(body[start..idx].trim());
            start = idx + 1;
        }
    }
    let last = body[start..].trim();
    if !last.is_empty() {
        out.push(last);
    }
    out
}

fn split_colon_pair(part: &str) -> Option<(&str, &str)> {
    let mut in_str = false;
    let mut escape = false;
    for (idx, ch) in part.char_indices() {
        if in_str {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        if ch == '"' {
            in_str = true;
            continue;
        }
        if ch == ':' {
            return Some((part[..idx].trim(), part[idx + 1..].trim()));
        }
    }
    None
}

fn unquote(text: &str) -> Option<String> {
    let text = text.trim();
    if text.len() < 2 || !text.starts_with('"') || !text.ends_with('"') {
        return None;
    }
    let inner = &text[1..text.len() - 1];
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                other => out.push(other),
            }
        } else {
            out.push(ch);
        }
    }
    Some(out)
}

fn split_arrow(line: &str) -> Option<(&str, &str)> {
    let (left, right) = line.split_once("->")?;
    let left = left.trim();
    let right = right.trim();
    if left.is_empty() || right.is_empty() {
        return None;
    }
    Some((left, right))
}

/// `ip:port` or `[ipv6]:port`. No default address and no default port.
pub(crate) fn parse_endpoint(text: &str) -> Option<Endpoint> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let (ip, port_text) = if let Some(rest) = text.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']')?;
        let tail = tail.strip_prefix(':')?;
        (addr, tail)
    } else {
        let (addr, tail) = text.rsplit_once(':')?;
        (addr, tail)
    };
    if ip.is_empty() || ip == "0.0.0.0" || ip == "::" {
        // A map entry that names "any" is not a concrete endpoint.
        return None;
    }
    let port: u16 = port_text.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some(Endpoint {
        ip: ip.to_owned(),
        port,
    })
}
