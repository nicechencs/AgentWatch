//! `Content-Encoding` handling for [`super::hash_body`].
//!
//! gzip is inflated with `flate2`'s pure-Rust backend. brotli and zstd are named
//! here only so the caller can report them: their crates are not dependencies.
//! Anything else is also unsupported, including `deflate` and `compress`,
//! because hashing those bytes as if they were the file would fake a miss.

use std::io::{self, Read};

use flate2::read::GzDecoder;

/// A `Content-Encoding` token this hasher knows what to do with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyEncoding {
    /// No encoding, or `identity`.
    Identity,
    /// gzip (`gzip` or `x-gzip`).
    Gzip,
    /// A token this build will not inflate. The string is lower-case.
    Unsupported(String),
}

impl BodyEncoding {
    /// Parse one `Content-Encoding` header value.
    ///
    /// Multiple encodings (a comma-separated list) are unsupported: applying
    /// only the outer one would hash still-compressed bytes. An empty value is
    /// identity.
    pub fn parse(header: Option<&str>) -> Self {
        let Some(raw) = header else {
            return Self::Identity;
        };
        let token = raw.split(',').next().unwrap_or(raw).trim();
        if token.is_empty() || raw.contains(',') {
            if raw.contains(',') {
                return Self::Unsupported(raw.trim().to_ascii_lowercase());
            }
            return Self::Identity;
        }
        match token.to_ascii_lowercase().as_str() {
            "identity" => Self::Identity,
            "gzip" | "x-gzip" => Self::Gzip,
            other => Self::Unsupported(other.to_owned()),
        }
    }
}

/// Read and, for gzip, inflate `input` into `out`, stopping at `max_bytes`.
///
/// Returns `true` when the decoded output hit `max_bytes` before the input
/// ended. `out` is appended to and is not wiped here; the caller wipes it.
pub fn read_decoded(
    input: &mut dyn Read,
    encoding: BodyEncoding,
    max_bytes: u64,
    out: &mut Vec<u8>,
) -> io::Result<bool> {
    match encoding {
        BodyEncoding::Identity => read_capped(input, max_bytes, out),
        BodyEncoding::Gzip => {
            let mut decoder = GzDecoder::new(input);
            read_capped(&mut decoder, max_bytes, out)
        }
        // `hash_body` returns before calling this. Kept so a future caller
        // cannot accidentally treat the compressed bytes as plaintext.
        BodyEncoding::Unsupported(_) => Ok(false),
    }
}

fn read_capped(input: &mut dyn Read, max_bytes: u64, out: &mut Vec<u8>) -> io::Result<bool> {
    let max_bytes = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    let mut buf = [0u8; 8 * 1024];
    loop {
        if out.len() >= max_bytes {
            return Ok(true);
        }
        let n = match input.read(&mut buf) {
            Ok(0) => return Ok(false),
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        let room = max_bytes.saturating_sub(out.len());
        if n > room {
            out.extend_from_slice(&buf[..room]);
            buf[..n].fill(0);
            return Ok(true);
        }
        out.extend_from_slice(&buf[..n]);
        buf[..n].fill(0);
    }
}
