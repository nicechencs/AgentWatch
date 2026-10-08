//! `multipart/form-data` split, enough to hash each part.
//!
//! This is not a general MIME parser. It finds the boundary from `Content-Type`,
//! splits the body on it, and reads each part's headers only to recover that
//! part's own `Content-Type`. Header values are not retained after the split
//! except that one field.

/// One part. `body` borrows the decoded request body.
pub struct Part<'a> {
    /// This part's `Content-Type`, when it had one.
    pub content_type: Option<String>,
    /// Bytes after the part's header block.
    pub body: &'a [u8],
}

/// Boundary token from a `multipart/form-data` Content-Type, without `--`.
pub fn boundary_of(content_type: &str) -> Option<String> {
    for param in content_type.split(';').skip(1) {
        let (name, value) = param.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("boundary") {
            continue;
        }
        let value = value.trim().trim_matches('"');
        if value.is_empty() || value.len() > 70 || value.as_bytes().contains(&b';') {
            return None;
        }
        return Some(value.to_owned());
    }
    None
}

/// Split `body` into parts on `boundary`.
///
/// A body that does not contain the closing boundary yields whatever parts were
/// opened. Parts are not required to be well-formed beyond the delimiter; a
/// part with no header block is treated as a body with no content type.
pub fn split<'a>(body: &'a [u8], boundary: &str) -> Vec<Part<'a>> {
    let marker = {
        let mut m = Vec::with_capacity(boundary.len() + 4);
        m.extend_from_slice(b"\r\n--");
        m.extend_from_slice(boundary.as_bytes());
        m
    };
    let opener = {
        let mut m = Vec::with_capacity(boundary.len() + 2);
        m.extend_from_slice(b"--");
        m.extend_from_slice(boundary.as_bytes());
        m
    };

    let rest = if body.starts_with(&opener) {
        &body[opener.len()..]
    } else if let Some(at) = find_sub(body, &marker) {
        &body[at + marker.len()..]
    } else {
        return Vec::new();
    };

    let mut parts = Vec::new();
    let mut cursor = rest;
    loop {
        if cursor.starts_with(b"--") {
            break;
        }
        if let Some(stripped) = cursor.strip_prefix(b"\r\n") {
            cursor = stripped;
        }
        let Some(next) = find_sub(cursor, &marker) else {
            // No further delimiter. Hash the tail only if it is not the epilogue
            // of a missing close; drop it rather than invent a part.
            break;
        };
        let raw = &cursor[..next];
        parts.push(parse_part(raw));
        let after = &cursor[next + marker.len()..];
        if after.starts_with(b"--") {
            break;
        }
        cursor = after;
    }
    parts
}

fn parse_part(raw: &[u8]) -> Part<'_> {
    let (header_bytes, body) = split_headers(raw);
    let content_type = header_value(header_bytes, "content-type");
    Part { content_type, body }
}

fn split_headers(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(at) = find_sub(raw, b"\r\n\r\n") {
        return (&raw[..at], &raw[at + 4..]);
    }
    if let Some(at) = find_sub(raw, b"\n\n") {
        return (&raw[..at], &raw[at + 2..]);
    }
    (b"", raw)
}

fn header_value(headers: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(headers);
    for line in text.split("\r\n").flat_map(|l| l.split('\n')) {
        let (raw_name, value) = line.split_once(':')?;
        if raw_name.trim().eq_ignore_ascii_case(name) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_owned());
            }
        }
    }
    None
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}
