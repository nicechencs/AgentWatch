//! Domain attribution for one connection (P3-PIPE-02).
//!
//! Network-attribution §4.2 lists TLS SNI first. This card places SNI after the
//! same-process DNS answer and before another process in the same session:
//!
//! 1. Proxy `CONNECT` target (E2).
//! 2. Same process, DNS answer whose TTL still covers the connect, newest first (E1).
//! 3. TLS SNI for this flow (E1).
//! 4. Another process in the same session → [`Evidence::I`].
//! 5. Daemon-wide DNS cache → [`Evidence::I`].
//! 6. Nothing → `domain = None`. No PTR lookup, no empty string, no IP used as a name.
//!
//! A same-process answer that disagrees with SNI wins; the SNI is kept as a
//! candidate. SNI wins over a peer or global name, and that DNS name is kept
//! as a candidate. The same string from two sources is not a conflict.
//!
//! There is no second DNS cache here. Rows come from [`DnsCache::records`].

use std::net::IpAddr;

use aw_core::{Evidence, ProcUid, SessionId};

use super::dns::DnsCache;
use crate::output::DnsRec;

/// A/AAAA. Same values the DNS cache indexes. CNAME is not an address.
const RTYPE_A: u16 = 1;
const RTYPE_AAAA: u16 = 28;

/// One end of a flow, as far as domain attribution needs it.
///
/// `at_ns` is the connect time on the same monotonic clock as the DNS rows.
/// This module does not read a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowEndpoint<'a> {
    /// Remote address the connect observed. Not a domain.
    pub ip: IpAddr,
    /// Connect time, monotonic nanoseconds.
    pub at_ns: u64,
    /// Process that connected. `None` when the connect was not attributed.
    pub proc_uid: Option<ProcUid>,
    /// Session the connect was scoped into. `None` before scope assigns one.
    pub session_id: Option<SessionId>,
    /// Proxy `CONNECT` host, already split from its port.
    ///
    /// This function does not parse `host:port`. An IPv6 literal contains
    /// colons, and guessing the split would invent a name.
    pub proxy_connect: Option<&'a str>,
}

/// DNS answers already recorded. Not a cache: nothing here is inserted.
#[derive(Debug, Clone, Copy)]
pub struct DnsObservations<'a> {
    rows: &'a [DnsRec],
}

impl<'a> DnsObservations<'a> {
    /// View the merged rows [`DnsCache::records`] already produced.
    pub fn from_cache(cache: &'a DnsCache) -> Self {
        Self {
            rows: cache.records(),
        }
    }

    /// View stored `dns` rows. Same shape as [`Self::from_cache`].
    ///
    /// `answers` entries are the `"rtype data"` text the cache writes. A row
    /// that does not match that shape simply does not hit.
    pub fn from_records(rows: &'a [DnsRec]) -> Self {
        Self { rows }
    }
}

/// Where the chosen domain came from.
///
/// [`Self::Sni`] is the value P3-PIPE-02 adds. The others are the sources in
/// network-attribution §4.2. [`Self::as_str`] is the `domain_source` text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainSource {
    /// Proxy saw `CONNECT host:port`.
    ProxyConnect,
    /// The connecting process's own DNS answer, still inside its TTL.
    DnsSameProcess,
    /// TLS ClientHello SNI for this flow.
    Sni,
    /// A different process in the same session answered this IP.
    DnsSessionPeer,
    /// A resolver answer with no process on the event.
    DnsGlobal,
}

impl DomainSource {
    /// Value stored in `domain_source`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProxyConnect => "proxy_connect",
            Self::DnsSameProcess => "dns_same_process",
            Self::Sni => "sni",
            Self::DnsSessionPeer => "dns_session_peer",
            Self::DnsGlobal => "dns_global",
        }
    }
}

/// A name that was seen and not chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The name that lost.
    pub domain: String,
    /// Who offered it.
    pub source: DomainSource,
}

/// Result of one attribution.
///
/// `domain == None` means nothing was observed. It is not `""` and not the IP.
/// `evidence == None` in that case as well: this function does not invent
/// [`Evidence::NA`]. The caller knows whether the reason is "no DNS" or ECH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainAttribution {
    /// Chosen name, or `None`.
    pub domain: Option<String>,
    /// Why [`Self::domain`] was chosen. `None` when there is no domain.
    pub domain_source: Option<DomainSource>,
    /// Grade of the chosen name. Not raised above the source that produced it.
    pub evidence: Option<Evidence>,
    /// Other names that were not chosen, highest priority first.
    pub candidates: Vec<Candidate>,
}

/// Pick a domain for `flow`.
///
/// `sni` is the cleartext ClientHello name. Pass `None` when the hello was
/// encrypted (ECH) or was not captured. This function does not parse TLS and
/// does not look the name up. An empty string is treated as no name.
pub fn attribute_domain(
    flow: &FlowEndpoint<'_>,
    dns: &DnsObservations<'_>,
    sni: Option<&str>,
) -> DomainAttribution {
    let mut offers = Vec::new();
    if let Some(host) = non_empty(flow.proxy_connect) {
        push_offer(&mut offers, host, DomainSource::ProxyConnect, &Evidence::E2);
    }
    add_rows(
        &mut offers,
        &same_process_rows(dns, flow),
        DomainSource::DnsSameProcess,
        &Evidence::E1,
    );
    if let Some(name) = non_empty(sni) {
        push_offer(&mut offers, name, DomainSource::Sni, &Evidence::E1);
    }
    add_rows(
        &mut offers,
        &session_peer_rows(dns, flow),
        DomainSource::DnsSessionPeer,
        &Evidence::I,
    );
    add_rows(
        &mut offers,
        &global_rows(dns, flow),
        DomainSource::DnsGlobal,
        &Evidence::I,
    );
    finish(offers)
}

#[derive(Clone)]
struct Offer {
    domain: String,
    source: DomainSource,
    evidence: Evidence,
}

fn same_process_rows<'a>(dns: &DnsObservations<'a>, flow: &FlowEndpoint<'_>) -> Vec<&'a DnsRec> {
    let Some(proc) = flow.proc_uid else {
        return Vec::new();
    };
    // This session first. Only when it has nothing do we look at answers stored
    // before scope assigned a session. A different session is not this process's
    // E1, matching `DnsCache::resolve`.
    if let Some(session) = flow.session_id {
        let hits = collect_rows(dns, flow, |row| {
            row.proc_uid == Some(proc) && row.session_id == Some(session)
        });
        if !hits.is_empty() {
            return hits;
        }
    }
    collect_rows(dns, flow, |row| {
        row.proc_uid == Some(proc) && row.session_id.is_none()
    })
}

fn session_peer_rows<'a>(dns: &DnsObservations<'a>, flow: &FlowEndpoint<'_>) -> Vec<&'a DnsRec> {
    let Some(session) = flow.session_id else {
        return Vec::new();
    };
    collect_rows(dns, flow, |row| {
        row.session_id == Some(session) && row.proc_uid.is_some() && row.proc_uid != flow.proc_uid
    })
}

fn global_rows<'a>(dns: &DnsObservations<'a>, flow: &FlowEndpoint<'_>) -> Vec<&'a DnsRec> {
    // No process on the DNS event: the resolver cache, whatever session it carried.
    collect_rows(dns, flow, |row| row.proc_uid.is_none())
}

fn collect_rows<'a>(
    dns: &DnsObservations<'a>,
    flow: &FlowEndpoint<'_>,
    pred: impl Fn(&DnsRec) -> bool,
) -> Vec<&'a DnsRec> {
    let mut hits = Vec::new();
    for row in dns.rows {
        if !pred(row) || row.qname.is_empty() {
            continue;
        }
        if !live_at(row, flow.at_ns) || !answer_has_ip(row, flow.ip) {
            continue;
        }
        hits.push(row);
    }
    hits.sort_by(|left, right| {
        right
            .ts_ns
            .cmp(&left.ts_ns)
            .then(left.qname.cmp(&right.qname))
    });
    hits
}

/// `true` when `at_ns` is still inside `[ts_ns, ts_ns + ttl)`.
///
/// A missing TTL does not expire. The window matches the DNS cache. On a merged
/// query+answer row, [`DnsRec::ts_ns`] is the query time, which is the only
/// timestamp the public row carries, so the window can start slightly earlier
/// than the answer itself.
fn live_at(row: &DnsRec, at_ns: u64) -> bool {
    if at_ns < row.ts_ns {
        return false;
    }
    let Some(ttl) = row.ttl_min else {
        return true;
    };
    let window = u64::from(ttl).saturating_mul(1_000_000_000);
    at_ns.saturating_sub(row.ts_ns) < window
}

/// `DnsRec.answers` is `"rtype data"` text written by the DNS cache.
///
/// Parse failures are misses, not guesses. This does not parse DNS wire format
/// and does not query anything.
fn answer_has_ip(row: &DnsRec, ip: IpAddr) -> bool {
    for text in &row.answers {
        let Some((rtype, data)) = text.split_once(' ') else {
            continue;
        };
        let Ok(rtype) = rtype.parse::<u16>() else {
            continue;
        };
        if rtype != RTYPE_A && rtype != RTYPE_AAAA {
            continue;
        }
        if let Ok(addr) = data.parse::<IpAddr>() {
            if addr == ip {
                return true;
            }
        }
    }
    false
}

fn add_rows(offers: &mut Vec<Offer>, rows: &[&DnsRec], source: DomainSource, evidence: &Evidence) {
    for row in rows {
        push_offer(offers, &row.qname, source, evidence);
    }
}

fn push_offer(offers: &mut Vec<Offer>, domain: &str, source: DomainSource, evidence: &Evidence) {
    if domain.is_empty() || offers.iter().any(|offer| offer.domain.as_str() == domain) {
        return;
    }
    offers.push(Offer {
        domain: domain.to_owned(),
        source,
        evidence: evidence.clone(),
    });
}

fn finish(offers: Vec<Offer>) -> DomainAttribution {
    let Some(winner) = offers.first().cloned() else {
        return none();
    };
    let candidates = offers
        .into_iter()
        .skip(1)
        .map(|offer| Candidate {
            domain: offer.domain,
            source: offer.source,
        })
        .collect();
    DomainAttribution {
        domain: Some(winner.domain),
        domain_source: Some(winner.source),
        evidence: Some(winner.evidence),
        candidates,
    }
}

fn none() -> DomainAttribution {
    DomainAttribution {
        domain: None,
        domain_source: None,
        evidence: None,
        candidates: Vec::new(),
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.filter(|text| !text.is_empty())
}
