//! ClientHello parser (P3-PIPE-02). RFC 8446 record and handshake layout.
//!
//! Only the ClientHello is read. ServerHello, certificates, and anything after
//! the extensions are not touched. A short buffer is [`ParseError::Incomplete`],
//! never a panic: a collector may hand over a truncated first packet.
//!
//! Encrypted ClientHello (draft-ietf-tls-esni, extension `0xfe0d`) hides the
//! inner name. When that extension is present, [`ClientHelloInfo::sni`] is
//! `None`. The outer `public_name` is recorded only when its length-prefixed
//! fields parse; a shape this parser does not recognise leaves
//! [`EchInfo::public_name`] as `None` rather than guessing a name.

use std::fmt;

/// TLS handshake record (RFC 8446 §5.1).
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
/// ClientHello handshake type (RFC 8446 §4).
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
/// server_name (RFC 6066).
const EXT_SERVER_NAME: u16 = 0;
/// application_layer_protocol_negotiation (RFC 7301).
const EXT_ALPN: u16 = 16;
/// encrypted_client_hello (draft-ietf-tls-esni-18 and later).
const EXT_ECH: u16 = 0xfe0d;
/// host_name name type inside the SNI extension.
const NAME_TYPE_HOST: u8 = 0;
/// ECHClientHello.type = outer.
const ECH_OUTER: u8 = 0;
/// ECHClientHello.type = inner. The payload is encrypted; there is no public_name.
const ECH_INNER: u8 = 1;

/// Why [`parse_client_hello`] refused the buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The buffer ended before a length-prefixed field finished.
    ///
    /// Every short read takes this variant. Callers retry with more bytes or
    /// record the SNI as unavailable; they do not treat it as a bad handshake.
    Incomplete,
    /// The record content type is not handshake (`22`).
    NotHandshake,
    /// The buffer is long enough but does not match the ClientHello layout:
    /// wrong handshake type, a length that runs past its parent, or a string
    /// that is not UTF-8.
    Malformed,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => f.write_str("ClientHello truncated"),
            Self::NotHandshake => f.write_str("TLS record is not a handshake"),
            Self::Malformed => f.write_str("ClientHello is malformed"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Outer ECH identity, when the extension was present.
///
/// `public_name` is the name a middlebox can still see. `None` means the
/// extension was recognised but its public_name could not be read — the parser
/// does not invent one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchInfo {
    /// Outer public_name, or `None` when the ECH body did not yield one.
    pub public_name: Option<String>,
}

/// Fields a later stage needs from one ClientHello.
///
/// `sni` is the first host_name entry of the server_name extension. It is
/// `None` when that extension is absent, when ECH is present (the inner name
/// is encrypted; the outer name lives on [`Self::ech`]), or when the only
/// server_name entries are not host names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// First host_name, or `None`. Never an empty string standing in for unknown.
    pub sni: Option<String>,
    /// ALPN protocol ids, in the order the ClientHello listed them.
    pub alpn: Vec<String>,
    /// legacy_version from the handshake body (not the record-layer version).
    pub legacy_version: u16,
    /// Present when extension `0xfe0d` was seen. Forces [`Self::sni`] to `None`.
    pub ech: Option<EchInfo>,
}

/// Parse one TLS record that should contain a ClientHello.
///
/// `input` is the record as captured, starting at the 5-byte record header.
/// A record shorter than its declared length, or a handshake shorter than its
/// declared length, is [`ParseError::Incomplete`]. Bytes after the handshake
/// message are ignored: a coalesced record is still one ClientHello.
pub fn parse_client_hello(input: &[u8]) -> Result<ClientHelloInfo, ParseError> {
    let mut cur = Cursor::new(input);
    let content_type = cur.u8()?;
    if content_type != CONTENT_TYPE_HANDSHAKE {
        // A short buffer already returned Incomplete above. Anything else that
        // is not a handshake record is a different protocol, not a bad hello.
        return Err(ParseError::NotHandshake);
    }
    let _record_version = cur.u16()?;
    let record_len = cur.u16()? as usize;
    let record = cur.take(record_len)?;

    let mut body = Cursor::new(record);
    let hs_type = body.u8()?;
    if hs_type != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(ParseError::Malformed);
    }
    let hs_len = body.u24()?;
    let hello = body.take(hs_len)?;

    let mut msg = Cursor::new(hello);
    let legacy_version = msg.u16()?;
    let _random = msg.take(32)?;
    let session_id_len = msg.u8()? as usize;
    let _session_id = msg.take(session_id_len)?;
    let cipher_len = msg.u16()? as usize;
    if cipher_len < 2 || !cipher_len.is_multiple_of(2) {
        return Err(ParseError::Malformed);
    }
    let _ciphers = msg.take(cipher_len)?;
    let comp_len = msg.u8()? as usize;
    if comp_len < 1 {
        return Err(ParseError::Malformed);
    }
    let _compression = msg.take(comp_len)?;

    // Extensions are optional in TLS 1.2. End of the handshake is "no extensions",
    // not a truncated packet. A length that runs past the bytes still in hand is
    // Incomplete, including a declared extension block.
    let mut sni = None;
    let mut alpn = Vec::new();
    let mut ech = None;
    if !msg.is_empty() {
        let ext_len = msg.u16()? as usize;
        let ext_bytes = msg.take(ext_len)?;
        let mut exts = Cursor::new(ext_bytes);
        while !exts.is_empty() {
            let ext_type = exts.u16()?;
            let this_len = exts.u16()? as usize;
            let data = exts.take(this_len)?;
            match ext_type {
                EXT_SERVER_NAME if sni.is_none() => {
                    sni = parse_sni(data)?;
                }
                EXT_ALPN if alpn.is_empty() => {
                    alpn = parse_alpn(data)?;
                }
                EXT_ECH if ech.is_none() => {
                    ech = Some(parse_ech(data)?);
                }
                _ => {}
            }
        }
    }

    // ECH encrypts the inner ClientHello, which is where the real SNI lives.
    // Drop whatever the cleartext server_name said; do not guess from it.
    if ech.is_some() {
        sni = None;
    }

    Ok(ClientHelloInfo {
        sni,
        alpn,
        legacy_version,
        ech,
    })
}

/// First host_name in the list. Other name types are skipped, not errors:
/// RFC 6066 says a client sends at most one host_name, but a parser that
/// rejects the rest would turn a future name type into a lost SNI.
fn parse_sni(data: &[u8]) -> Result<Option<String>, ParseError> {
    let mut cur = Cursor::new(data);
    let list_len = cur.u16()? as usize;
    let list = cur.take(list_len)?;
    let mut names = Cursor::new(list);
    while !names.is_empty() {
        let name_type = names.u8()?;
        let name_len = names.u16()? as usize;
        let name = names.take(name_len)?;
        if name_type == NAME_TYPE_HOST {
            let text = std::str::from_utf8(name).map_err(|_| ParseError::Malformed)?;
            if text.is_empty() {
                return Err(ParseError::Malformed);
            }
            return Ok(Some(text.to_owned()));
        }
    }
    Ok(None)
}

fn parse_alpn(data: &[u8]) -> Result<Vec<String>, ParseError> {
    let mut cur = Cursor::new(data);
    let list_len = cur.u16()? as usize;
    if list_len < 2 {
        // RFC 7301: the list must hold at least one non-empty protocol id.
        return Err(ParseError::Malformed);
    }
    let list = cur.take(list_len)?;
    let mut protos = Cursor::new(list);
    let mut out = Vec::new();
    while !protos.is_empty() {
        let n = protos.u8()? as usize;
        if n == 0 {
            return Err(ParseError::Malformed);
        }
        let id = protos.take(n)?;
        let text = std::str::from_utf8(id).map_err(|_| ParseError::Malformed)?;
        out.push(text.to_owned());
    }
    if out.is_empty() {
        return Err(ParseError::Malformed);
    }
    Ok(out)
}

/// ECH extension body (draft-ietf-tls-esni).
///
/// Outer: `type=0`, then a u16 KDF, a u16 AEAD, a u8 config id, a u16-prefixed
/// enc, a u16-prefixed payload, and a u8-prefixed public_name. A short outer
/// body is [`ParseError::Incomplete`], not a guessed name.
/// Inner: `type=1`, ciphertext only — no public_name.
/// Any other type still means ECH is in use. public_name stays `None`.
fn parse_ech(data: &[u8]) -> Result<EchInfo, ParseError> {
    let Some(kind) = data.first().copied() else {
        return Err(ParseError::Incomplete);
    };
    let public_name = if kind == ECH_OUTER {
        ech_outer_public_name(data)?
    } else {
        // Inner has no public_name. An unrecognised type is not one we invent.
        let _ = ECH_INNER;
        None
    };
    Ok(EchInfo { public_name })
}

fn ech_outer_public_name(data: &[u8]) -> Result<Option<String>, ParseError> {
    let mut cur = Cursor::new(data);
    if cur.u8()? != ECH_OUTER {
        return Ok(None);
    }
    let _kdf = cur.u16()?;
    let _aead = cur.u16()?;
    let _config_id = cur.u8()?;
    let enc_len = cur.u16()? as usize;
    let _enc = cur.take(enc_len)?;
    let payload_len = cur.u16()? as usize;
    let _payload = cur.take(payload_len)?;
    let name_len = cur.u8()? as usize;
    if name_len == 0 {
        return Ok(None);
    }
    let name = cur.take(name_len)?;
    let text = std::str::from_utf8(name).map_err(|_| ParseError::Malformed)?;
    if text.is_empty() {
        return Ok(None);
    }
    Ok(Some(text.to_owned()))
}

struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.at)
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        let b = self.take(1)?;
        Ok(b[0])
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<usize, ParseError> {
        let b = self.take(3)?;
        Ok(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(ParseError::Malformed)?;
        if end > self.buf.len() {
            return Err(ParseError::Incomplete);
        }
        let out = &self.buf[self.at..end];
        self.at = end;
        Ok(out)
    }
}
