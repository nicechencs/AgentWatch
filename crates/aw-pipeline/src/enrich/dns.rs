//! DNS answer cache and IP → domain back-fill (P1-PIPE-03).
//!
//! Cache key is `(session?, ip)` → `[(qname, ts, ttl, source_evidence)]`. A query
//! the process itself sent (the event carries a [`ProcUid`]) is stored in that
//! session. A query with no process — a system resolver such as mDNSResponder
//! asking on someone else's behalf — is stored in the global cache.
//!
//! Matching follows network-attribution §4.2, in order:
//!
//! 1. TLS SNI, flow-scoped.
//! 2. Proxy `CONNECT` target.
//! 3. Same process, DNS answer whose TTL still covers the connect, newest first.
//! 4. Another process in the same session → [`Evidence::I`].
//! 5. The daemon-wide cache → [`Evidence::I`].
//! 6. Nothing → [`Evidence::NA`] [`NaReason::NoDnsObserved`].
//!
//! P1 has no SNI capture and no proxy, so steps 1 and 2 are placeholders that
//! always return [`MatchStep::NotImplemented`]. They never report a hit. There
//! is no PTR lookup and no code that opens a socket.
//!
//! Every timestamp is an argument. This module does not read a clock.
//!
//! [`crate::output::DnsRec`] is the merged query+answer row. [`NetFlowRec`] has
//! no `field_evidence` and no `domain_alts`, and this card may not change that
//! type, so the back-fill result is [`ConnectDomain`] here. A later aggregate
//! card copies `domain` onto the flow.

use std::collections::HashMap;
use std::net::IpAddr;

use aw_core::{
    DnsAnswer, DnsQuery, DnsRecord, Evidence, NaReason, ProcUid, SessionId, SocketAddr, Source,
};

use crate::output::DnsRec;

/// `field_evidence` key for the domain written onto a connection.
pub const DOMAIN_FIELD: &str = "domain";

/// A/AAAA rtypes. CNAME and other records are not addresses and are not indexed.
const RTYPE_A: u16 = 1;
const RTYPE_AAAA: u16 = 28;

/// One cached answer for an IP.
///
/// `source_evidence` is the evidence of the DNS event itself. The grade written
/// onto a connection is decided later, from who is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CacheEntry {
    qname: String,
    /// Answer time, monotonic nanoseconds, supplied by the caller.
    ts_ns: u64,
    /// TTL in seconds. `None` means the answer carried no TTL, so it cannot
    /// expire and cannot be treated as a fresh E1 window either: a missing TTL
    /// is not `0`.
    ttl_secs: Option<u32>,
    /// Evidence on the DNS event that produced this row.
    source_evidence: Evidence,
    /// Process that sent the query. `None` is the global (resolver) cache.
    proc_uid: Option<ProcUid>,
    session_id: Option<SessionId>,
}

impl CacheEntry {
    /// `true` when `at_ns` is still inside `[ts_ns, ts_ns + ttl)`.
    ///
    /// A missing TTL does not expire: there is no number to expire against.
    /// The caller still prefers a newer answer when several are live.
    fn live_at(&self, at_ns: u64) -> bool {
        if at_ns < self.ts_ns {
            return false;
        }
        let Some(ttl) = self.ttl_secs else {
            return true;
        };
        let window = u64::from(ttl).saturating_mul(1_000_000_000);
        at_ns.saturating_sub(self.ts_ns) < window
    }
}

/// Where an answer is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CacheScope {
    /// Process-attributed query. `session` is `None` when scope has not assigned one.
    Session { session: Option<SessionId> },
    /// No process on the event. Shared by every session.
    Global,
}

/// `(session?, ip)` → answers, newest observation kept alongside older ones.
#[derive(Debug, Default)]
pub struct DnsCache {
    /// Session-scoped and global rows, keyed by the answer IP.
    by_ip: HashMap<(CacheScope, IpAddr), Vec<CacheEntry>>,
    /// Open queries waiting for an answer, keyed by `(scope, proc?, qname, qtype)`.
    pending: HashMap<PendingKey, PendingQuery>,
    /// Merged query+answer rows, in observation order.
    records: Vec<DnsRec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingKey {
    scope: CacheScope,
    proc_uid: Option<ProcUid>,
    qname: String,
    qtype: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingQuery {
    ts_ns: u64,
    txid: Option<u16>,
    server: Option<SocketAddr>,
    evidence: Evidence,
    source: Source,
}

impl DnsCache {
    /// Empty cache. No I/O.
    pub fn new() -> Self {
        Self::default()
    }

    /// Merged DNS rows produced so far, oldest first.
    pub fn records(&self) -> &[DnsRec] {
        &self.records
    }

    /// Note a query. It is not indexed by IP: a query has no address yet.
    ///
    /// A later [`Self::observe_answer`] with the same session, process, qname,
    /// and qtype consumes it. Time is `ts_ns`, not the host clock.
    pub fn observe_query(&mut self, query: &DnsQuery, ctx: &DnsObs) {
        let key = pending_key(ctx, &query.qname, query.qtype);
        self.pending.insert(
            key,
            PendingQuery {
                ts_ns: ctx.ts_ns,
                txid: query.txid,
                server: query.server,
                evidence: ctx.evidence.clone(),
                source: ctx.source.clone(),
            },
        );
    }

    /// Note an answer. Index every A/AAAA address, and emit one [`DnsRec`].
    ///
    /// If a matching query is pending, the record uses the query's time, txid,
    /// and server. The answer's evidence is kept: the answer is what carries
    /// the addresses. A query that never arrives still produces a record; its
    /// server stays `None`.
    pub fn observe_answer(&mut self, answer: &DnsAnswer, ctx: &DnsObs) {
        let key = pending_key(ctx, &answer.qname, answer.qtype);
        let pending = self.pending.remove(&key);
        let ts_ns = pending.as_ref().map(|row| row.ts_ns).unwrap_or(ctx.ts_ns);
        let server = pending.as_ref().and_then(|row| row.server);
        let evidence = ctx.evidence.clone();
        let source = ctx.source.clone();

        let ips = answer_ips(&answer.answers);
        let scope = scope_of(ctx);
        for ip in &ips {
            let rows = self.by_ip.entry((scope, *ip)).or_default();
            rows.push(CacheEntry {
                qname: answer.qname.clone(),
                ts_ns: ctx.ts_ns,
                ttl_secs: answer.ttl_min,
                source_evidence: evidence.clone(),
                proc_uid: ctx.proc_uid,
                session_id: ctx.session_id,
            });
        }

        self.records.push(DnsRec {
            session_id: ctx.session_id,
            proc_uid: ctx.proc_uid,
            ts_ns,
            qname: answer.qname.clone(),
            qtype: answer.qtype,
            rcode: Some(answer.rcode),
            answers: answer
                .answers
                .iter()
                .map(|rec| format!("{} {}", rec.rtype, rec.data))
                .collect(),
            ttl_min: answer.ttl_min,
            server: server.map(|addr| addr.to_string()),
            evidence,
            source,
        });
    }

    /// Back-fill `ip` for a connection observed at `at_ns`.
    ///
    /// `proc_uid` / `session_id` are the connection's, not the resolver's.
    /// `sni` and `proxy_connect` are accepted so the six-step order has a place
    /// to plug in later; both placeholders return [`MatchStep::NotImplemented`]
    /// and are skipped. Passing `Some` does not invent a hit.
    pub fn resolve(
        &self,
        ip: IpAddr,
        at_ns: u64,
        proc_uid: Option<ProcUid>,
        session_id: Option<SessionId>,
        sni: Option<&str>,
        proxy_connect: Option<&str>,
    ) -> ConnectDomain {
        let _ = (sni_step(sni), proxy_step(proxy_connect));

        if proc_uid.is_some() {
            // Same process, this session first. A row stored before scope assigned
            // a session is still this process's own answer.
            let own_scopes = [
                CacheScope::Session {
                    session: session_id,
                },
                CacheScope::Session { session: None },
            ];
            for scope in own_scopes {
                if let Some(found) = self.pick(scope, ip, at_ns, |row| row.proc_uid == proc_uid) {
                    return found.into_domain(Evidence::E1);
                }
            }
        }

        if let Some(session) = session_id {
            if let Some(found) = self.pick(
                CacheScope::Session {
                    session: Some(session),
                },
                ip,
                at_ns,
                |row| row.proc_uid.is_some() && row.proc_uid != proc_uid,
            ) {
                return found.into_domain(Evidence::I);
            }
        }

        if let Some(found) = self.pick(CacheScope::Global, ip, at_ns, |_| true) {
            return found.into_domain(Evidence::I);
        }

        ConnectDomain::not_observed()
    }

    /// Live answers for `(scope, ip)` matching `pred`, newest `ts_ns` first.
    fn pick(
        &self,
        scope: CacheScope,
        ip: IpAddr,
        at_ns: u64,
        pred: impl Fn(&CacheEntry) -> bool,
    ) -> Option<Picked> {
        let mut hits: Vec<&CacheEntry> = Vec::new();
        if let Some(rows) = self.by_ip.get(&(scope, ip)) {
            for row in rows {
                if row.live_at(at_ns) && pred(row) {
                    hits.push(row);
                }
            }
        }
        if hits.is_empty() {
            return None;
        }
        hits.sort_by(|a, b| b.ts_ns.cmp(&a.ts_ns).then(a.qname.cmp(&b.qname)));
        let primary = hits[0];
        // Other names only. A second answer for the same name is not another
        // candidate (network-attribution §4.2: UI shows "另有 N 个候选").
        let mut alt = Vec::new();
        for row in hits.iter().skip(1) {
            if row.qname != primary.qname && !alt.contains(&row.qname) {
                alt.push(row.qname.clone());
            }
        }
        Some(Picked {
            qname: primary.qname.clone(),
            alt_domains: alt,
        })
    }
}

struct Picked {
    qname: String,
    alt_domains: Vec<String>,
}

impl Picked {
    fn into_domain(self, evidence: Evidence) -> ConnectDomain {
        ConnectDomain {
            domain: Some(self.qname),
            alt_domains: self.alt_domains,
            field_evidence: {
                let mut map = std::collections::BTreeMap::new();
                map.insert(DOMAIN_FIELD.to_owned(), evidence);
                map
            },
            step: MatchStep::Hit,
        }
    }
}

/// Caller-supplied context for one DNS event. No clock is read from here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsObs {
    /// Monotonic nanoseconds. Required; this module will not invent one.
    pub ts_ns: u64,
    /// Session the event was scoped into. `None` keeps the row global.
    pub session_id: Option<SessionId>,
    /// Process that sent the query. `None` means a resolver with no requester.
    pub proc_uid: Option<ProcUid>,
    /// Evidence on the event. Stored with the cache row; not upgraded.
    pub evidence: Evidence,
    /// Collector source copied onto the [`DnsRec`].
    pub source: Source,
}

fn pending_key(ctx: &DnsObs, qname: &str, qtype: u16) -> PendingKey {
    PendingKey {
        scope: scope_of(ctx),
        proc_uid: ctx.proc_uid,
        qname: qname.to_owned(),
        qtype,
    }
}

fn scope_of(ctx: &DnsObs) -> CacheScope {
    // A process on the event is that process's own query, session or not.
    // Only a missing process is the resolver's global cache.
    if ctx.proc_uid.is_some() {
        CacheScope::Session {
            session: ctx.session_id,
        }
    } else {
        CacheScope::Global
    }
}

fn answer_ips(records: &[DnsRecord]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for rec in records {
        if rec.rtype != RTYPE_A && rec.rtype != RTYPE_AAAA {
            continue;
        }
        if let Ok(ip) = rec.data.parse::<IpAddr>() {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    ips
}

/// One step of network-attribution §4.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchStep {
    /// This step produced the domain.
    Hit,
    /// P1 does not implement this step. Not a hit.
    NotImplemented,
    /// The step ran and found nothing.
    Miss,
}

/// Step 1. P1 has no SNI on the flow, so this never hits.
fn sni_step(sni: Option<&str>) -> MatchStep {
    let _ = sni;
    MatchStep::NotImplemented
}

/// Step 2. P1 has no proxy CONNECT target, so this never hits.
fn proxy_step(target: Option<&str>) -> MatchStep {
    let _ = target;
    MatchStep::NotImplemented
}

/// Domain written back onto a connection, plus the field-level grade.
///
/// `domain == None` is "not observed", never an empty string. `alt_domains`
/// holds the other live names for the same IP, newest first after the primary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectDomain {
    /// Best name, or `None` when nothing matched.
    pub domain: Option<String>,
    /// Other names for the same IP, excluding `domain`.
    pub alt_domains: Vec<String>,
    /// Always contains [`DOMAIN_FIELD`].
    pub field_evidence: std::collections::BTreeMap<String, Evidence>,
    /// Which implemented step produced this, or [`MatchStep::Miss`] for NA.
    pub step: MatchStep,
}

impl ConnectDomain {
    fn not_observed() -> Self {
        let mut field_evidence = std::collections::BTreeMap::new();
        field_evidence.insert(
            DOMAIN_FIELD.to_owned(),
            Evidence::NA(NaReason::NoDnsObserved),
        );
        Self {
            domain: None,
            alt_domains: Vec::new(),
            field_evidence,
            step: MatchStep::Miss,
        }
    }

    /// Evidence stored for [`DOMAIN_FIELD`], when present.
    pub fn domain_evidence(&self) -> Option<&Evidence> {
        self.field_evidence.get(DOMAIN_FIELD)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aw_core::Source;

    fn src() -> Source {
        Source::new("test/dns")
    }

    fn obs(ts_ns: u64, session: Option<u64>, proc: Option<u64>, evidence: Evidence) -> DnsObs {
        DnsObs {
            ts_ns,
            session_id: session.map(SessionId),
            proc_uid: proc.map(ProcUid),
            evidence,
            source: src(),
        }
    }

    fn answer(qname: &str, ip: &str, ttl: Option<u32>) -> DnsAnswer {
        DnsAnswer::new(
            qname,
            RTYPE_A,
            0,
            vec![DnsRecord {
                rtype: RTYPE_A,
                data: ip.to_owned(),
            }],
            ttl,
        )
    }

    fn domain_ev(found: &ConnectDomain) -> &Evidence {
        found
            .field_evidence
            .get(DOMAIN_FIELD)
            .expect("domain field evidence")
    }

    #[test]
    fn same_process_hit_is_e1() {
        let mut cache = DnsCache::new();
        let ctx = obs(1_000, Some(1), Some(10), Evidence::E1);
        cache.observe_answer(&answer("api.example", "1.2.3.4", Some(60)), &ctx);
        let found = cache.resolve(
            "1.2.3.4".parse().unwrap(),
            5_000,
            Some(ProcUid(10)),
            Some(SessionId(1)),
            None,
            None,
        );
        assert_eq!(found.domain.as_deref(), Some("api.example"));
        assert_eq!(domain_ev(&found), &Evidence::E1);
        assert!(found.alt_domains.is_empty());
    }

    #[test]
    fn global_cache_hit_is_inference() {
        let mut cache = DnsCache::new();
        // No proc: system resolver. Evidence on the event is not raised.
        let ctx = obs(1_000, None, None, Evidence::E1);
        cache.observe_answer(&answer("cdn.example", "9.9.9.9", Some(30)), &ctx);
        let found = cache.resolve(
            "9.9.9.9".parse().unwrap(),
            2_000,
            Some(ProcUid(10)),
            Some(SessionId(1)),
            Some("ignored.example"),
            Some("also-ignored.example"),
        );
        assert_eq!(found.domain.as_deref(), Some("cdn.example"));
        assert_eq!(domain_ev(&found), &Evidence::I);
        assert_eq!(sni_step(Some("ignored.example")), MatchStep::NotImplemented);
        assert_eq!(
            proxy_step(Some("also-ignored.example")),
            MatchStep::NotImplemented
        );
    }

    #[test]
    fn expired_ttl_does_not_hit() {
        let mut cache = DnsCache::new();
        let ctx = obs(0, Some(1), Some(10), Evidence::E1);
        cache.observe_answer(&answer("old.example", "1.2.3.4", Some(1)), &ctx);
        // 1s TTL. One nanosecond past the window is a miss, not a stale E1.
        let at = 1_000_000_000;
        let found = cache.resolve(
            "1.2.3.4".parse().unwrap(),
            at,
            Some(ProcUid(10)),
            Some(SessionId(1)),
            None,
            None,
        );
        assert_eq!(found.domain, None);
        assert_eq!(domain_ev(&found), &Evidence::NA(NaReason::NoDnsObserved));
    }

    #[test]
    fn no_record_is_na() {
        let cache = DnsCache::new();
        let found = cache.resolve(
            "8.8.8.8".parse().unwrap(),
            1,
            Some(ProcUid(10)),
            Some(SessionId(1)),
            None,
            None,
        );
        assert_eq!(found.domain, None);
        assert!(found.alt_domains.is_empty());
        assert_eq!(domain_ev(&found), &Evidence::NA(NaReason::NoDnsObserved));
        assert_eq!(found.step, MatchStep::Miss);
    }

    #[test]
    fn several_names_keep_the_newest_and_alts() {
        let mut cache = DnsCache::new();
        let older = obs(1_000, Some(1), Some(10), Evidence::E1);
        cache.observe_answer(&answer("old.example", "1.2.3.4", Some(60)), &older);
        let newer = obs(2_000, Some(1), Some(10), Evidence::E1);
        cache.observe_answer(&answer("new.example", "1.2.3.4", Some(60)), &newer);
        let found = cache.resolve(
            "1.2.3.4".parse().unwrap(),
            3_000,
            Some(ProcUid(10)),
            Some(SessionId(1)),
            None,
            None,
        );
        assert_eq!(found.domain.as_deref(), Some("new.example"));
        assert_eq!(found.alt_domains, vec!["old.example".to_owned()]);
        assert_eq!(domain_ev(&found), &Evidence::E1);
    }

    #[test]
    fn other_process_in_session_is_inference_not_e1() {
        let mut cache = DnsCache::new();
        let ctx = obs(1_000, Some(1), Some(99), Evidence::E1);
        cache.observe_answer(&answer("peer.example", "1.2.3.4", Some(60)), &ctx);
        let found = cache.resolve(
            "1.2.3.4".parse().unwrap(),
            2_000,
            Some(ProcUid(10)),
            Some(SessionId(1)),
            None,
            None,
        );
        assert_eq!(found.domain.as_deref(), Some("peer.example"));
        assert_eq!(domain_ev(&found), &Evidence::I);
    }

    #[test]
    fn query_and_answer_merge_into_one_dns_rec() {
        let mut cache = DnsCache::new();
        let source = src();
        let query_ctx = DnsObs {
            ts_ns: 100,
            session_id: Some(SessionId(1)),
            proc_uid: Some(ProcUid(10)),
            evidence: Evidence::E1,
            source: source.clone(),
        };
        cache.observe_query(
            &DnsQuery::new("api.example", RTYPE_A, Some(7), None),
            &query_ctx,
        );
        let answer_ctx = DnsObs {
            ts_ns: 200,
            session_id: Some(SessionId(1)),
            proc_uid: Some(ProcUid(10)),
            evidence: Evidence::E1,
            source,
        };
        cache.observe_answer(&answer("api.example", "1.2.3.4", Some(30)), &answer_ctx);
        assert_eq!(cache.records().len(), 1);
        let rec = &cache.records()[0];
        assert_eq!(rec.qname, "api.example");
        assert_eq!(rec.ts_ns, 100, "merged row keeps the query time");
        assert_eq!(rec.rcode, Some(0));
        assert_eq!(rec.ttl_min, Some(30));
        assert_eq!(rec.answers.len(), 1);
    }
}
