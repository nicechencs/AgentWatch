//! Standard base64 (RFC 4648 §4), no extra crate.
//!
//! The `base64` crate is not in `Cargo.lock`. This decodes one JSON string into
//! a caller-owned buffer. A string that is not base64 returns `false` and
//! leaves the buffer unchanged, so the caller can skip it.
//!
//! Accepted: the standard alphabet, optional `=` padding, and ASCII whitespace
//! between characters (JSON sometimes wraps a long value). Rejected: the URL-safe
//! alphabet, a missing nibble, and a non-zero padding tail. Those are far more
//! often ordinary prose than a payload, and hashing them as decoded bytes would
//! invent chunks the file side cannot match.

/// Decode `text` into `out`, appending.
///
/// `true` only when every non-whitespace character was consumed and at least
/// one byte was produced. On `false`, `out` is left as it was.
pub fn decode_standard(text: &str, out: &mut Vec<u8>) -> bool {
    let compact = strip_ws(text);
    if compact.len() < 4 || !compact.len().is_multiple_of(4) {
        return false;
    }
    let start = out.len();
    let bytes = compact.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let (a, b, c, d) = (bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]);
        let (Some(va), Some(vb)) = (val(a), val(b)) else {
            out.truncate(start);
            return false;
        };
        if c == b'=' {
            // `xx==` — one output byte. The next must also be padding, and the
            // unused low bits of `vb` must be zero.
            if d != b'=' || i + 4 != bytes.len() || vb & 0b00_001111 != 0 {
                out.truncate(start);
                return false;
            }
            out.push((va << 2) | (vb >> 4));
            break;
        }
        let Some(vc) = val(c) else {
            out.truncate(start);
            return false;
        };
        if d == b'=' {
            if i + 4 != bytes.len() || vc & 0b00_000011 != 0 {
                out.truncate(start);
                return false;
            }
            out.push((va << 2) | (vb >> 4));
            out.push((vb << 4) | (vc >> 2));
            break;
        }
        let Some(vd) = val(d) else {
            out.truncate(start);
            return false;
        };
        out.push((va << 2) | (vb >> 4));
        out.push((vb << 4) | (vc >> 2));
        out.push((vc << 6) | vd);
        i += 4;
    }
    if out.len() == start {
        return false;
    }
    true
}

fn strip_ws(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if !ch.is_ascii_whitespace() {
            out.push(ch);
        }
    }
    out
}

fn val(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
