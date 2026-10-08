//! Minimal DNS parser for the first 512 B of a UDP/53 payload.
//!
//! `hickory-proto` is not a workspace dependency (P1-LNX-03 forbids adding one),
//! so this covers the messages the byte probes actually copy:
//!
//! - one question, type A (1) or AAAA (28), class IN (1);
//! - a query (`QR = 0`) or a response (`QR = 1`);
//! - answers in the answer section that are A, AAAA, or CNAME (5), class IN,
//!   with names compressed by a backward pointer;
//! - `rcode` from the header, and the smallest TTL among the parsed answers.
//!
//! Anything else is [`DnsParse::Failed`] with a reason. The caller marks the
//! event `NA`. The datagram is never stored.
//!
//! Not parsed, on purpose: EDNS, OPT, TSIG, multiple questions, types other
//! than A/AAAA/CNAME, names that point forward, and pointers that loop. A
//! truncated copy (datagram longer than the 512 B the probe kept) is refused
//! rather than parsed as a short message.

/// DNS type A.
pub const QTYPE_A: u16 = 1;
/// DNS type CNAME. Parsed in answers only; a question of this type is refused.
pub const QTYPE_CNAME: u16 = 5;
/// DNS type AAAA.
pub const QTYPE_AAAA: u16 = 28;
/// DNS class IN.
pub const CLASS_IN: u16 = 1;

/// Header flags this parser reads. The rest are ignored, not rejected.
const FLAG_QR: u16 = 0x8000;
const FLAG_TC: u16 = 0x0200;
const RCODE_MASK: u16 = 0x000f;

const HEADER_LEN: usize = 12;
const POINTER_MASK: u8 = 0xC0;
/// Cap on compression hops so a pointer cycle cannot spin.
const MAX_NAME_HOPS: usize = 16;
/// A domain name is at most 255 octets (RFC 1035).
const MAX_NAME_LEN: usize = 255;

/// What the probe asked the parser to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsParseInput<'a> {
    /// Bytes the probe copied. Never more than 512.
    pub payload: &'a [u8],
    /// Datagram length before the copy. Greater than `payload.len()` means the
    /// tail was not captured and the message must not be parsed.
    pub datagram_len: usize,
}

/// A parsed message. Names are lowercase ASCII. Answer `data` is an IPv4
/// string, an IPv6 string, or a CNAME target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDns {
    /// Header id.
    pub txid: u16,
    /// `true` when `QR` is set (a response).
    pub response: bool,
    /// Question name.
    pub qname: String,
    /// Question type. A or AAAA.
    pub qtype: u16,
    /// `rcode`. Zero on a query; the header value on a response.
    pub rcode: u16,
    /// Answer-section records this parser understood. Empty when the section
    /// was empty. A response whose answers were all of an unsupported type is
    /// a failure, not an empty success.
    pub answers: Vec<ParsedAnswer>,
    /// Smallest TTL among `answers`. `None` when there are none.
    pub ttl_min: Option<u32>,
}

/// One answer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAnswer {
    /// Type code. A, AAAA, or CNAME.
    pub rtype: u16,
    /// Dotted name, IPv4, or IPv6.
    pub data: String,
    /// TTL in seconds.
    pub ttl: u32,
}

/// Parser outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsParse {
    /// Message matched the subset above.
    Ok(ParsedDns),
    /// `reason` is a fixed phrase the caller copies into `field_evidence` detail.
    /// No part of the payload is included.
    Failed {
        /// Why.
        reason: &'static str,
    },
}

/// Parse one datagram prefix.
pub fn parse_dns(input: DnsParseInput<'_>) -> DnsParse {
    if input.datagram_len > input.payload.len() {
        return fail("dns payload truncated past 512 bytes");
    }
    if input.payload.len() < HEADER_LEN {
        return fail("dns header shorter than 12 bytes");
    }
    let payload = &input.payload[..input.datagram_len];
    let flags = u16_at(payload, 2);
    if flags & FLAG_TC != 0 {
        return fail("dns truncated bit set");
    }
    let qd = u16_at(payload, 4) as usize;
    let an = u16_at(payload, 6) as usize;
    if qd != 1 {
        return fail("dns question count is not 1");
    }
    let response = flags & FLAG_QR != 0;
    let mut cursor = HEADER_LEN;
    let qname = match read_name(payload, &mut cursor) {
        Name::Ok(name) => name,
        Name::Bad(reason) => return fail(reason),
    };
    if cursor + 4 > payload.len() {
        return fail("dns question truncated");
    }
    let qtype = u16_at(payload, cursor);
    let qclass = u16_at(payload, cursor + 2);
    cursor += 4;
    if qclass != CLASS_IN {
        return fail("dns question class is not IN");
    }
    if qtype != QTYPE_A && qtype != QTYPE_AAAA {
        return fail("dns question type is not A or AAAA");
    }
    if !response {
        if an != 0 || u16_at(payload, 8) != 0 || u16_at(payload, 10) != 0 {
            return fail("dns query carries answer records");
        }
        return DnsParse::Ok(ParsedDns {
            txid: u16_at(payload, 0),
            response: false,
            qname,
            qtype,
            rcode: flags & RCODE_MASK,
            answers: Vec::new(),
            ttl_min: None,
        });
    }
    let mut answers = Vec::with_capacity(an);
    let mut skipped_unsupported = 0usize;
    for _ in 0..an {
        match read_rr(payload, &mut cursor) {
            Rr::Answer(rr) => answers.push(rr),
            Rr::Skip => skipped_unsupported += 1,
            Rr::Bad(reason) => return fail(reason),
        }
    }
    if an > 0 && answers.is_empty() {
        return fail("dns answer types are not A, AAAA, or CNAME");
    }
    // Authority and additional sections are not read. Their presence is not an
    // error: a response can carry an SOA and still have the A record we need.
    let _ = skipped_unsupported;
    let ttl_min = answers.iter().map(|rr| rr.ttl).min();
    DnsParse::Ok(ParsedDns {
        txid: u16_at(payload, 0),
        response: true,
        qname,
        qtype,
        rcode: flags & RCODE_MASK,
        answers,
        ttl_min,
    })
}

enum Name {
    Ok(String),
    Bad(&'static str),
}

enum Rr {
    Answer(ParsedAnswer),
    Skip,
    Bad(&'static str),
}

fn fail(reason: &'static str) -> DnsParse {
    DnsParse::Failed { reason }
}

fn u16_at(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

fn u32_at(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

/// Read a name starting at `*cursor`, advancing `*cursor` past the first-level
/// encoding (a pointer consumes two bytes and stops). Compression targets are
/// followed without moving `*cursor` into them.
fn read_name(buf: &[u8], cursor: &mut usize) -> Name {
    let mut out = String::new();
    let mut at = *cursor;
    let mut hops = 0usize;
    let mut jumped = false;
    loop {
        if hops > MAX_NAME_HOPS {
            return Name::Bad("dns name compression loop");
        }
        hops += 1;
        if at >= buf.len() {
            return Name::Bad("dns name truncated");
        }
        let len = buf[at];
        if len == 0 {
            if !jumped {
                *cursor = at + 1;
            }
            if out.is_empty() {
                return Name::Bad("dns name is empty");
            }
            return Name::Ok(out);
        }
        if len & POINTER_MASK == POINTER_MASK {
            if at + 1 >= buf.len() {
                return Name::Bad("dns name pointer truncated");
            }
            let target = (((len & !POINTER_MASK) as usize) << 8) | buf[at + 1] as usize;
            if target >= at {
                // Only backward pointers. A forward pointer can loop without
                // repeating an offset we have already counted.
                return Name::Bad("dns name pointer is not backward");
            }
            if !jumped {
                *cursor = at + 2;
                jumped = true;
            }
            at = target;
            continue;
        }
        if len & POINTER_MASK != 0 {
            return Name::Bad("dns name label length is reserved");
        }
        let start = at + 1;
        let end = start + len as usize;
        if end > buf.len() {
            return Name::Bad("dns name label truncated");
        }
        if !out.is_empty() {
            out.push('.');
        }
        if out.len() + len as usize > MAX_NAME_LEN {
            return Name::Bad("dns name longer than 255 octets");
        }
        match std::str::from_utf8(&buf[start..end]) {
            Ok(label) if label_is_plain(label) => out.push_str(&label.to_ascii_lowercase()),
            _ => return Name::Bad("dns name label is not ascii"),
        }
        at = end;
    }
}

fn label_is_plain(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn read_rr(buf: &[u8], cursor: &mut usize) -> Rr {
    let name = match read_name(buf, cursor) {
        Name::Ok(name) => name,
        Name::Bad(reason) => return Rr::Bad(reason),
    };
    if *cursor + 10 > buf.len() {
        return Rr::Bad("dns record header truncated");
    }
    let rtype = u16_at(buf, *cursor);
    let class = u16_at(buf, *cursor + 2);
    let ttl = u32_at(buf, *cursor + 4);
    let rdlen = u16_at(buf, *cursor + 8) as usize;
    *cursor += 10;
    if *cursor + rdlen > buf.len() {
        return Rr::Bad("dns rdata truncated");
    }
    let rdata = &buf[*cursor..*cursor + rdlen];
    *cursor += rdlen;
    if class != CLASS_IN {
        return Rr::Skip;
    }
    let data = match rtype {
        QTYPE_A if rdlen == 4 => format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]),
        QTYPE_AAAA if rdlen == 16 => format_v6(rdata),
        QTYPE_CNAME => {
            let mut at = *cursor - rdlen;
            match read_name(buf, &mut at) {
                Name::Ok(target) => target,
                Name::Bad(reason) => return Rr::Bad(reason),
            }
        }
        QTYPE_A | QTYPE_AAAA => return Rr::Bad("dns rdata length does not match type"),
        _ => return Rr::Skip,
    };
    let _ = name;
    Rr::Answer(ParsedAnswer { rtype, data, ttl })
}

fn format_v6(octets: &[u8]) -> String {
    let mut groups = [0u16; 8];
    for (i, group) in groups.iter_mut().enumerate() {
        *group = u16::from_be_bytes([octets[i * 2], octets[i * 2 + 1]]);
    }
    // Longest zero run, at least two groups, compressed once. Ties take the
    // leftmost run (RFC 5952).
    let mut best_at = None;
    let mut best_len = 0usize;
    let mut i = 0usize;
    while i < 8 {
        if groups[i] == 0 {
            let start = i;
            while i < 8 && groups[i] == 0 {
                i += 1;
            }
            let len = i - start;
            if len > best_len && len >= 2 {
                best_at = Some(start);
                best_len = len;
            }
        } else {
            i += 1;
        }
    }
    let mut out = String::new();
    let mut i = 0usize;
    while i < 8 {
        if Some(i) == best_at {
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with("::") {
            out.push(':');
        }
        out.push_str(&format!("{:x}", groups[i]));
        i += 1;
    }
    if out.ends_with("::") || out.is_empty() {
        // `::` already covers a trailing run. A message of all zeroes is `::`.
    }
    if out.is_empty() {
        out.push_str("::");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for label in labels {
            out.push(label.len() as u8);
            out.extend(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn header(flags: u16, qd: u16, an: u16) -> Vec<u8> {
        let mut out = vec![0x12, 0x34];
        out.extend(flags.to_be_bytes());
        out.extend(qd.to_be_bytes());
        out.extend(an.to_be_bytes());
        out.extend(0u16.to_be_bytes());
        out.extend(0u16.to_be_bytes());
        out
    }

    fn question(labels: &[&str], qtype: u16) -> Vec<u8> {
        let mut out = name(labels);
        out.extend(qtype.to_be_bytes());
        out.extend(CLASS_IN.to_be_bytes());
        out
    }

    #[test]
    fn parses_an_a_query() {
        let mut msg = header(0x0100, 1, 0);
        msg.extend(question(&["Example", "COM"], QTYPE_A));
        let parsed = match parse_dns(DnsParseInput {
            payload: &msg,
            datagram_len: msg.len(),
        }) {
            DnsParse::Ok(parsed) => parsed,
            DnsParse::Failed { reason } => panic!("{reason}"),
        };
        assert!(!parsed.response);
        assert_eq!(parsed.txid, 0x1234);
        assert_eq!(parsed.qname, "example.com");
        assert_eq!(parsed.qtype, QTYPE_A);
        assert!(parsed.answers.is_empty());
        assert_eq!(parsed.rcode, 0);
    }

    #[test]
    fn parses_an_aaaa_response_with_a_compressed_name() {
        let mut msg = header(0x8180, 1, 1);
        msg.extend(question(&["example", "com"], QTYPE_AAAA));
        let question_name_at = HEADER_LEN as u16;
        msg.push(0xC0);
        msg.push(question_name_at as u8);
        msg.extend(QTYPE_AAAA.to_be_bytes());
        msg.extend(CLASS_IN.to_be_bytes());
        msg.extend(60u32.to_be_bytes());
        msg.extend(16u16.to_be_bytes());
        msg.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let parsed = match parse_dns(DnsParseInput {
            payload: &msg,
            datagram_len: msg.len(),
        }) {
            DnsParse::Ok(parsed) => parsed,
            DnsParse::Failed { reason } => panic!("{reason}"),
        };
        assert!(parsed.response);
        assert_eq!(parsed.qtype, QTYPE_AAAA);
        assert_eq!(parsed.rcode, 0);
        assert_eq!(parsed.ttl_min, Some(60));
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].rtype, QTYPE_AAAA);
        assert_eq!(parsed.answers[0].data, "2001:db8::1");
    }

    #[test]
    fn a_truncated_copy_is_not_parsed() {
        let mut msg = header(0x0100, 1, 0);
        msg.extend(question(&["example", "com"], QTYPE_A));
        let err = parse_dns(DnsParseInput {
            payload: &msg,
            datagram_len: msg.len() + 40,
        });
        assert_eq!(
            err,
            DnsParse::Failed {
                reason: "dns payload truncated past 512 bytes"
            }
        );
    }

    #[test]
    fn an_mx_question_is_refused() {
        let mut msg = header(0x0100, 1, 0);
        msg.extend(question(&["example", "com"], 15));
        assert!(matches!(
            parse_dns(DnsParseInput {
                payload: &msg,
                datagram_len: msg.len(),
            }),
            DnsParse::Failed { .. }
        ));
    }
}
