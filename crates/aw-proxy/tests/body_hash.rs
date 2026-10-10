//! P3-PROXY-04: unprivileged body-hash checks on fixture bytes.
//!
//! Digests are compared as sets. Fixture bytes stay in local buffers and are not
//! printed: `BodyHashes`'s `Debug` hides the digest values, and failures here
//! report counts and overlap only.
//!
//! gzip is produced with `flate2`, already a dependency of `aw-proxy`
//! (`rust_backend`). No crate was added for this file. `br` and `zstd` are not
//! inflated; the unsupported-encoding case uses `br`.

#![allow(clippy::expect_used)]

use std::io::{Cursor, Write};

use aw_proxy::hash::{hash_body, BodyHeaders, HashError, HashLimits};
use flate2::write::GzEncoder;
use flate2::Compression;

/// Fixture payload. Not a secret, not a real request body.
const PAYLOAD: &[u8] = b"agentwatch-fixture-payload-v1";

fn hash_with(
    bytes: &[u8],
    headers: &BodyHeaders,
    limits: &HashLimits,
) -> aw_proxy::hash::BodyHashes {
    hash_body(&mut Cursor::new(bytes), headers, limits).expect("hash")
}

fn overlap(left: &aw_proxy::hash::BodyHashes, right: &aw_proxy::hash::BodyHashes) -> usize {
    left.digests.intersection(&right.digests).count()
}

/// Standard base64 (RFC 4648 §4) of `bytes`, with `=` padding.
///
/// The `base64` crate is not a dependency. This encoder exists only so the JSON
/// fixture is valid standard base64 for the decoder already in `aw-proxy`.
fn standard_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n =
            (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8) | u32::from(bytes[i + 2]);
        out.push(ALPHABET[(n >> 18) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push(ALPHABET[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rest = bytes.len() - i;
    if rest == 1 {
        let n = u32::from(bytes[i]) << 16;
        out.push(ALPHABET[(n >> 18) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rest == 2 {
        let n = (u32::from(bytes[i]) << 16) | (u32::from(bytes[i + 1]) << 8);
        out.push(ALPHABET[(n >> 18) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        out.push('=');
    }
    out
}

fn gzip_bytes(plain: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plain).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

#[test]
fn gzip_body_shares_digests_with_the_plain_bytes() {
    let limits = HashLimits::default();
    let plain = hash_with(
        PAYLOAD,
        &BodyHeaders {
            content_type: None,
            content_encoding: None,
        },
        &limits,
    );
    let compressed = gzip_bytes(PAYLOAD);
    assert_ne!(
        compressed, PAYLOAD,
        "gzip member should differ from the fixture bytes"
    );
    let inflated = hash_with(
        &compressed,
        &BodyHeaders {
            content_type: None,
            content_encoding: Some("gzip".to_owned()),
        },
        &limits,
    );
    assert!(!plain.truncated);
    assert!(!inflated.truncated);
    assert_eq!(
        inflated.decoded_bytes,
        u64::try_from(PAYLOAD.len()).expect("len")
    );
    let shared = overlap(&plain, &inflated);
    assert!(
        shared > 0,
        "gzip and plain digest sets do not overlap (plain {}, gzip {})",
        plain.digests.len(),
        inflated.digests.len()
    );
}

#[test]
fn json_base64_field_shares_a_digest_with_the_raw_payload() {
    let encoded = standard_base64(PAYLOAD);
    let body = format!(r#"{{"blob":"{encoded}"}}"#);
    let limits = HashLimits::default();
    let wrapped = hash_with(
        body.as_bytes(),
        &BodyHeaders {
            content_type: Some("application/json".to_owned()),
            content_encoding: None,
        },
        &limits,
    );
    let raw = hash_with(
        PAYLOAD,
        &BodyHeaders {
            content_type: None,
            content_encoding: None,
        },
        &limits,
    );
    let shared = overlap(&wrapped, &raw);
    assert!(
        shared > 0,
        "json field and raw payload do not overlap (json {}, raw {})",
        wrapped.digests.len(),
        raw.digests.len()
    );
}

#[test]
fn multipart_part_shares_digests_with_the_raw_payload() {
    let boundary = "aw-fixture-boundary";
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"blob\"\r\n\
         Content-Type: application/octet-stream\r\n\
         \r\n\
         {payload}\r\n\
         --{boundary}--\r\n",
        payload = std::str::from_utf8(PAYLOAD).expect("utf8"),
    );
    let limits = HashLimits::default();
    let wrapped = hash_with(
        body.as_bytes(),
        &BodyHeaders {
            content_type: Some(format!("multipart/form-data; boundary={boundary}")),
            content_encoding: None,
        },
        &limits,
    );
    let raw = hash_with(
        PAYLOAD,
        &BodyHeaders {
            content_type: None,
            content_encoding: None,
        },
        &limits,
    );
    let shared = overlap(&wrapped, &raw);
    assert!(
        shared > 0,
        "multipart part and raw payload do not overlap (part {}, raw {})",
        wrapped.digests.len(),
        raw.digests.len()
    );
}

#[test]
fn brotli_encoding_is_unsupported() {
    let err = hash_body(
        &mut Cursor::new(PAYLOAD),
        &BodyHeaders {
            content_type: None,
            content_encoding: Some("br".to_owned()),
        },
        &HashLimits::default(),
    );
    match err {
        Err(HashError::UnsupportedEncoding { encoding }) => {
            assert_eq!(encoding, "br");
        }
        other => panic!("expected UnsupportedEncoding, got {other:?}"),
    }
}

#[test]
fn a_body_past_the_decoded_cap_is_truncated() {
    // 256 bytes of one repeated value. Well under a megabyte; the cap is 64.
    let body = vec![0x61_u8; 256];
    let limits = HashLimits {
        max_decoded_bytes: 64,
    };
    let hashed = hash_with(
        &body,
        &BodyHeaders {
            content_type: None,
            content_encoding: None,
        },
        &limits,
    );
    assert!(hashed.truncated);
    assert!(hashed.decoded_bytes <= 64);
    assert!(hashed.decoded_bytes > 0);
}
