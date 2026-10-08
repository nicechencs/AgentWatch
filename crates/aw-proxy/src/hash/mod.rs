//! Request-body chunk hashes (P3-PROXY-04).
//!
//! The body is read once, decoded in memory, chunked with [`aw_core::chunk`], and
//! then wiped. Nothing is written to disk, to the log, or to a swap-friendly
//! buffer we keep. The digest set stays in the returned value; the caller keeps
//! it in memory and drops it with the session.
//!
//! Decoding:
//!
//! - `Content-Encoding: gzip` is inflated with `flate2` (`rust_backend`).
//! - `br` and `zstd` are **not** decoded. Those crates are not in `Cargo.lock`
//!   and must not be added. The result is [`HashError::UnsupportedEncoding`],
//!   not an empty set and not a hash of the still-compressed bytes.
//! - `Content-Type: application/json` is parsed with `serde_json::from_slice`
//!   (the 32 MB cap bounds the allocation). String values are already
//!   unescaped by that parser. A string that is valid standard base64 is
//!   decoded and chunked too; a string that is not base64 is left as text and
//!   still chunked. There is no `base64` crate in the lockfile, so the decoder
//!   lives in [`base64`].
//! - `multipart/form-data` is split on its boundary. Each part is chunked. A
//!   part whose own `Content-Type` is JSON is expanded the same way.
//!
//! The decoded buffer is capped at [`HashLimits::max_decoded_bytes`] (default
//! 32 MB). Past that the decoder stops, sets [`BodyHashes::truncated`], and
//! hashes only what was kept.

mod base64;
mod decode;
mod multipart;

use std::io::{self, Read};

use aw_core::{ChunkSet, Chunked};
use thiserror::Error;
use zeroize::Zeroize;

pub use decode::BodyEncoding;

/// Default cap on decoded bytes. Past this, hashing stops and `truncated` is set.
pub const DEFAULT_MAX_DECODED: u64 = 32 * 1024 * 1024;

/// Headers the hasher looks at. Names are matched case-insensitively.
///
/// Values are the raw header values. This struct's `Debug` prints lengths, not
/// the values: a `Content-Type` can carry a boundary token.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct BodyHeaders {
    /// `Content-Type`, without the header name. `None` if the request had none.
    pub content_type: Option<String>,
    /// `Content-Encoding`. `None` means identity (no compression).
    pub content_encoding: Option<String>,
}

impl std::fmt::Debug for BodyHeaders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyHeaders")
            .field("content_type", &self.content_type.as_ref().map(|s| s.len()))
            .field(
                "content_encoding",
                &self.content_encoding.as_ref().map(|s| s.len()),
            )
            .finish()
    }
}

impl BodyHeaders {
    /// Headers from already-split name/value pairs. Unknown names are ignored.
    /// A repeated header keeps the first value.
    pub fn from_pairs<'a, I>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut headers = Self::default();
        for (name, value) in pairs {
            if name.eq_ignore_ascii_case("content-type") && headers.content_type.is_none() {
                headers.content_type = Some(value.to_owned());
            } else if name.eq_ignore_ascii_case("content-encoding")
                && headers.content_encoding.is_none()
            {
                headers.content_encoding = Some(value.to_owned());
            }
        }
        headers
    }
}

/// Caps for one hash pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashLimits {
    /// Decoded (inflated, after a part is split out) bytes to keep.
    pub max_decoded_bytes: u64,
}

impl Default for HashLimits {
    fn default() -> Self {
        Self {
            max_decoded_bytes: DEFAULT_MAX_DECODED,
        }
    }
}

/// Digests of one request body. The set is the only thing worth keeping.
#[derive(Clone, PartialEq, Eq)]
pub struct BodyHashes {
    /// Distinct chunk digests, from the raw decoded body and from every
    /// expanded JSON string and multipart part.
    pub digests: ChunkSet,
    /// Chunks emitted, counting duplicates. A coverage check uses the file
    /// side's count, not this one.
    pub chunk_count: u32,
    /// `true` when decoding stopped at [`HashLimits::max_decoded_bytes`].
    pub truncated: bool,
    /// Bytes actually decoded and hashed, after inflation. Not the wire size.
    pub decoded_bytes: u64,
}

impl std::fmt::Debug for BodyHashes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyHashes")
            .field("chunk_count", &self.chunk_count)
            .field("distinct", &self.digests.len())
            .field("truncated", &self.truncated)
            .field("decoded_bytes", &self.decoded_bytes)
            .finish_non_exhaustive()
    }
}

/// Why a body could not be hashed.
#[derive(Debug, Error)]
pub enum HashError {
    /// `Content-Encoding` is one this build does not inflate.
    ///
    /// `br` and `zstd` land here. The body is not hashed as if it were plain,
    /// and it is not skipped silently.
    #[error("content encoding `{encoding}` is not supported")]
    UnsupportedEncoding {
        /// The encoding token, lower-cased, with parameters removed.
        encoding: String,
    },

    /// Reading the body failed. The message is the I/O error's `Display`,
    /// which does not include the bytes that were read.
    #[error("reading request body: {message}")]
    Read {
        /// `std::io::Error` display.
        message: String,
    },
}

impl From<io::Error> for HashError {
    fn from(err: io::Error) -> Self {
        Self::Read {
            message: err.to_string(),
        }
    }
}

/// Hash one request body.
///
/// `input` is the raw body as it arrived on the wire (still compressed, if
/// `headers` say so). Plaintext buffers inside this call are wiped before it
/// returns. On [`HashError::UnsupportedEncoding`] nothing is hashed.
pub fn hash_body(
    input: &mut dyn Read,
    headers: &BodyHeaders,
    limits: &HashLimits,
) -> Result<BodyHashes, HashError> {
    let encoding = BodyEncoding::parse(headers.content_encoding.as_deref());
    if let BodyEncoding::Unsupported(name) = encoding {
        return Err(HashError::UnsupportedEncoding { encoding: name });
    }

    let mut decoded = Vec::new();
    let truncated = decode::read_decoded(input, encoding, limits.max_decoded_bytes, &mut decoded)?;
    let decoded_bytes = u64::try_from(decoded.len()).unwrap_or(u64::MAX);

    let mut acc = Accumulator::default();
    expand_and_hash(&decoded, headers.content_type.as_deref(), &mut acc);
    decoded.zeroize();

    Ok(BodyHashes {
        digests: acc.digests,
        chunk_count: acc.chunk_count,
        truncated,
        decoded_bytes,
    })
}

/// Chunk `bytes`, then expand JSON strings or multipart parts on top.
fn expand_and_hash(bytes: &[u8], content_type: Option<&str>, acc: &mut Accumulator) {
    acc.add(aw_core::chunk_bytes(bytes));
    let Some(content_type) = content_type else {
        return;
    };
    let mime = media_type(content_type);
    if mime == "application/json" || mime.ends_with("+json") {
        expand_json(bytes, acc);
    } else if mime == "multipart/form-data" {
        if let Some(boundary) = multipart::boundary_of(content_type) {
            for part in multipart::split(bytes, &boundary) {
                expand_and_hash(part.body, part.content_type.as_deref(), acc);
                // `part.body` borrows `bytes`, which the caller wipes.
                let _ = part;
            }
        }
    }
}

/// Chunk every JSON string, and chunk its base64 decoding when that succeeds.
fn expand_json(bytes: &[u8], acc: &mut Accumulator) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return;
    };
    let mut scratch = Vec::new();
    walk_strings(&value, acc, &mut scratch);
    scratch.zeroize();
}

fn walk_strings(value: &serde_json::Value, acc: &mut Accumulator, scratch: &mut Vec<u8>) {
    match value {
        serde_json::Value::String(text) => {
            acc.add(aw_core::chunk_bytes(text.as_bytes()));
            scratch.clear();
            if base64::decode_standard(text, scratch) {
                acc.add(aw_core::chunk_bytes(scratch));
                scratch.zeroize();
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                walk_strings(item, acc, scratch);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                walk_strings(item, acc, scratch);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

/// `type/subtype`, lower-cased, with parameters removed.
fn media_type(content_type: &str) -> String {
    let head = content_type.split(';').next().unwrap_or(content_type);
    head.trim().to_ascii_lowercase()
}

#[derive(Default)]
struct Accumulator {
    digests: ChunkSet,
    chunk_count: u32,
}

impl Accumulator {
    fn add(&mut self, chunked: Chunked) {
        self.chunk_count = self.chunk_count.saturating_add(chunked.chunk_count);
        self.digests.extend(chunked.digests);
    }
}
