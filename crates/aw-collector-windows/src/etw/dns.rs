//! DNS-Client events 3006 / 3008 → `DnsQuery` / `DnsAnswer`.
//!
//! Field names and event ids are copied from windows.md §2.4. That section is
//! still marked 【待验证 SPIKE-02】, and SPIKE-02 did not measure whether the
//! event-header PID is the original requester when the Dnscache service queries
//! on a process's behalf. The task card's conservative branch applies: every
//! decoded DNS event is stored in a process-independent cache, the record
//! evidence is [`Evidence::I`], and `field_evidence["pid"]` says why. It is
//! not E1. A later spike that confirms the PID can change this in one place.
//!
//! | event id | kind | properties used |
//! |---|---|---|
//! | 3006 | `DnsQuery` | `QueryName`, `QueryType` |
//! | 3008 | `DnsAnswer` | `QueryName`, `QueryStatus`, `QueryResults` |
//!
//! 3020 is named in §2.4 as a supplementary answer ("收到应答（来自指定服务器）")
//! and is not in the task card's "3006 → DnsQuery, 3008 → DnsAnswer" mapping.
//! It is ignored here so a supplementary event is not emitted as a second
//! answer the card did not ask for.
//!
//! `QueryResults` is a `;`-separated list. Each piece is parsed as an IP
//! (A → rtype 1, AAAA → rtype 28). A piece that is not an IP is kept as a
//! record with `rtype` marked `NA(collector_unavailable)` — the whole answer
//! is not dropped. `QueryType`, `QueryStatus`, and the server address are not
//! given a unit or a layout by §2.4 beyond the names, so a missing one is
//! `NA`, not a guessed `0`.
//!
//! Event 3006 does not carry `txid` or a server. Both slots exist on
//! `DnsQuery` and are `NA(collector_unavailable)`.
//!
//! No URL, header, or response body is stored. SNI is not parsed.

use std::net::IpAddr;

use aw_core::{
    DnsAnswer, DnsQuery, DnsRecord, EventKind, Evidence, NaReason, RawEvent, Source, SCHEMA_VERSION,
};

use super::process::DecodeClock;

/// `source` for every DNS-Client event. The task card names this string.
pub const SOURCE_DNS_CLIENT: &str = "windows.etw/dns_client";

/// DNS-Client "query started". windows.md §2.4. 【待验证 SPIKE-02】.
pub const EVENT_DNS_QUERY: u16 = 3006;

/// DNS-Client "query completed". windows.md §2.4. 【待验证 SPIKE-02】.
pub const EVENT_DNS_QUERY_COMPLETED: u16 = 3008;

/// Field path whose value is [`Evidence::I`] because the header PID is not a
/// confirmed requester.
///
/// `Evidence::I` carries no reason string, and [`RawEvent::mark_na`] only
/// accepts `NA`. The task card asks for the reason in `field_evidence`, so a
/// second entry ([`PID_ATTRIBUTION_NOTE`]) holds the same [`Evidence::I`] under
/// a path that names the reason. Neither path is a new evidence enum.
pub const PID_FIELD: &str = "pid";

/// `field_evidence` key that states why `pid` is I.
///
/// Text: SPIKE-02 未证实 PID 归属. The key is ASCII so it stays a stable field
/// path; the Chinese reason is the comment a reader of this constant sees, and
/// the key itself spells the same fact (`spike02_pid_unconfirmed`).
pub const PID_ATTRIBUTION_NOTE: &str = "pid_spike02_unconfirmed";

/// One property from a decoded DNS-Client event.
///
/// Strings are already decoded from UTF-16 by the caller. This module does not
/// call ferrisetw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsProperties {
    /// `EventDescriptor.Id`. Only 3006 and 3008 decode.
    pub event_id: u16,
    /// Event-header PID. Stored so a later confirmed attribution can use it.
    /// It is **not** written into `proc`: SPIKE-02 did not show it is the
    /// requester. Absent stays `None` (not `0`).
    pub header_pid: Option<u32>,
    /// `QueryName`. Absent is not `""`.
    pub query_name: Option<String>,
    /// `QueryType`. §2.4 names it and not the numeric mapping. A present value
    /// is stored as the `u16` the caller parsed. Absent is `NA`.
    pub query_type: Option<u16>,
    /// `QueryStatus`. 3008 only. Absent is not rcode 0.
    pub query_status: Option<u32>,
    /// `QueryResults`, the raw `;`-separated string. 3008 only.
    pub query_results: Option<String>,
    /// Event-header thread id, when the caller has one. Not a §2.4 property.
    pub tid: Option<u32>,
}

impl DnsProperties {
    /// An event with an id and nothing else.
    pub fn bare(event_id: u16) -> Self {
        Self {
            event_id,
            header_pid: None,
            query_name: None,
            query_type: None,
            query_status: None,
            query_results: None,
            tid: None,
        }
    }
}

/// What [`decode_dns`] did with one event.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodedDns {
    /// A query or an answer. Already inserted into `cache` when the call was
    /// given one. Boxed so the `Ignored` variant does not carry a `RawEvent`.
    Event(Box<RawEvent>),
    /// Event id was not 3006 or 3008. 3020 lands here on purpose.
    Ignored { event_id: u16 },
}

/// Process-independent DNS cache.
///
/// SPIKE-02 did not confirm that the header PID is the original requester, so
/// rows are keyed by query name only. The PID is kept beside the row for a
/// later spike and is not used as a key. This is the "全局缓存" the task card
/// asks for when attribution is I.
#[derive(Debug, Default, Clone)]
pub struct DnsAnswerCache {
    rows: Vec<DnsCacheRow>,
}

/// One completed answer, plus the header PID that was *not* trusted.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsCacheRow {
    /// `QueryName` as observed. `None` when the property was absent.
    pub qname: Option<String>,
    /// Header PID, untrusted. `None` when the header did not carry one.
    pub header_pid: Option<u32>,
    /// The event, evidence I.
    pub event: RawEvent,
}

impl DnsAnswerCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Every answer stored so far, oldest first.
    pub fn rows(&self) -> &[DnsCacheRow] {
        &self.rows
    }

    fn push(&mut self, row: DnsCacheRow) {
        self.rows.push(row);
    }
}

/// Decode one DNS-Client event.
///
/// `seq` and `clock` come from the caller. This function does not read a
/// clock. `cache` receives answers only (3008). Queries are returned and not
/// cached: a query has no address to match a later connection against
/// (network-attribution §4.2 step 5 is an answer cache).
///
/// Passing `cache = None` still returns the event. Tests that only check the
/// decode use that.
pub fn decode_dns(
    props: &DnsProperties,
    seq: u64,
    clock: DecodeClock,
    cache: Option<&mut DnsAnswerCache>,
) -> DecodedDns {
    match props.event_id {
        EVENT_DNS_QUERY => DecodedDns::Event(Box::new(decode_query(props, seq, clock))),
        EVENT_DNS_QUERY_COMPLETED => {
            let event = decode_answer(props, seq, clock);
            if let Some(cache) = cache {
                cache.push(DnsCacheRow {
                    qname: props.query_name.clone(),
                    header_pid: props.header_pid,
                    event: event.clone(),
                });
            }
            DecodedDns::Event(Box::new(event))
        }
        other => DecodedDns::Ignored { event_id: other },
    }
}

fn decode_query(props: &DnsProperties, seq: u64, clock: DecodeClock) -> RawEvent {
    // qtype is a plain u16. 0 together with an NA marker is "not observed",
    // not "query type 0".
    let qtype_known = props.query_type.is_some();
    let qtype = props.query_type.unwrap_or(0);
    let qname = props.query_name.clone().unwrap_or_default();
    let mut event = build_event(
        seq,
        clock,
        EventKind::DnsQuery(DnsQuery::new(qname, qtype, None, None)),
    );
    mark_attribution(&mut event, props.header_pid);
    if props.query_name.is_none() {
        event.mark_na("qname", NaReason::CollectorUnavailable);
    }
    if !qtype_known {
        event.mark_na("qtype", NaReason::CollectorUnavailable);
    }
    // §2.4 does not name a transaction id or a server on 3006.
    event.mark_na("txid", NaReason::CollectorUnavailable);
    event.mark_na("server", NaReason::CollectorUnavailable);
    let _ = props.tid;
    event
}

fn decode_answer(props: &DnsProperties, seq: u64, clock: DecodeClock) -> RawEvent {
    let qtype_known = props.query_type.is_some();
    let qtype = props.query_type.unwrap_or(0);
    let qname = props.query_name.clone().unwrap_or_default();
    // QueryStatus is named, not given a width. Values that fit in u16 are the
    // rcode. A value that does not fit is not truncated into a different code:
    // it is treated as absent.
    let (rcode, rcode_known) = match props.query_status {
        Some(status) => match u16::try_from(status) {
            Ok(code) => (code, true),
            Err(_) => (0, false),
        },
        None => (0, false),
    };
    let (answers, answer_gaps) = match &props.query_results {
        Some(raw) => parse_query_results(raw),
        None => (Vec::new(), true),
    };
    // ttl is not a §2.4 field.
    let mut event = build_event(
        seq,
        clock,
        EventKind::DnsAnswer(DnsAnswer::new(qname, qtype, rcode, answers, None)),
    );
    mark_attribution(&mut event, props.header_pid);
    if props.query_name.is_none() {
        event.mark_na("qname", NaReason::CollectorUnavailable);
    }
    if !qtype_known {
        event.mark_na("qtype", NaReason::CollectorUnavailable);
    }
    if !rcode_known {
        event.mark_na("rcode", NaReason::CollectorUnavailable);
    }
    if answer_gaps {
        // The whole list was absent, or at least one piece did not parse as an
        // IP. The answer event is still emitted. The marker says the list is
        // not complete.
        event.mark_na("answers", NaReason::CollectorUnavailable);
    }
    event.mark_na("ttl_min", NaReason::CollectorUnavailable);
    let _ = props.tid;
    event
}

/// Split `QueryResults` on `;` and parse each piece.
///
/// Returns the records and whether any piece failed to parse (or the string
/// was empty of records). An empty piece from a trailing semicolon is skipped,
/// not counted as a failure: `"1.2.3.4;"` is one address.
///
/// A piece that parses as an IP becomes A (rtype 1) or AAAA (rtype 28). A
/// piece that does not is kept with `rtype = 0` and the caller marks the
/// `answers` field `NA`. The data string is the raw piece, so the unparsed
/// text is not discarded.
pub fn parse_query_results(raw: &str) -> (Vec<DnsRecord>, bool) {
    let mut records = Vec::new();
    let mut any_bad = false;
    let mut any = false;
    for piece in raw.split(';') {
        let piece = piece.trim();
        if piece.is_empty() {
            continue;
        }
        any = true;
        match piece.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) => records.push(DnsRecord {
                rtype: 1,
                data: v4.to_string(),
            }),
            Ok(IpAddr::V6(v6)) => records.push(DnsRecord {
                rtype: 28,
                data: v6.to_string(),
            }),
            Err(_) => {
                any_bad = true;
                records.push(DnsRecord {
                    rtype: 0,
                    data: piece.to_owned(),
                });
            }
        }
    }
    if !any {
        any_bad = true;
    }
    (records, any_bad)
}

/// Record-level evidence is I. The PID field path carries the same I and the
/// reason "SPIKE-02 未证实 PID 归属", whether or not a header PID was present:
/// presence does not make it the requester.
fn mark_attribution(event: &mut RawEvent, header_pid: Option<u32>) {
    // Header PID is deliberately not copied onto `proc`. `ProcUid` also cannot
    // be hashed: §2.4 has no CreateTime. Keeping the integer here only so a
    // later confirmed spike can see that the decoder received it.
    let _ = header_pid;
    event.evidence = Evidence::I;
    event.mark_na("proc", NaReason::CollectorUnavailable);
    // Two entries, one fact. `pid` is I (not E1). `pid_spike02_unconfirmed` is
    // the reason the task card requires: SPIKE-02 未证实 PID 归属. The value
    // cannot be a sentence; `Evidence::I` has no payload.
    event
        .field_evidence
        .insert(PID_FIELD.to_owned(), Evidence::I);
    event
        .field_evidence
        .insert(PID_ATTRIBUTION_NOTE.to_owned(), Evidence::I);
}

fn build_event(seq: u64, clock: DecodeClock, kind: EventKind) -> RawEvent {
    let wall_known = clock.ts_wall_ns.is_some();
    let mut event = RawEvent {
        v: SCHEMA_VERSION,
        seq,
        ts_mono_ns: clock.ts_mono_ns,
        ts_wall_ns: clock.ts_wall_ns.unwrap_or(0),
        session_id: None,
        proc: None,
        source: Source::new(SOURCE_DNS_CLIENT),
        // Overwritten by `mark_attribution`. Set here so a path that forgets
        // the call still does not default to E1.
        evidence: Evidence::I,
        field_evidence: std::collections::BTreeMap::new(),
        kind,
    };
    if !wall_known {
        event.mark_na("ts_wall_ns", NaReason::CollectorUnavailable);
    }
    let _ = event.check();
    event
}
