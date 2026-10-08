//! Enrich lookups. P1-PIPE-02 owns the process cache; DNS and other lookups are later cards.

mod dns;
mod domain;
mod proc_cache;
mod proxy;

pub use dns::{ConnectDomain, DnsCache, DnsObs, MatchStep, DOMAIN_FIELD};
pub use domain::{
    attribute_domain, Candidate, DnsObservations, DomainAttribution, DomainSource, FlowEndpoint,
};
pub use proc_cache::{ProcCache, ProcCacheConfig, ProcInfo, DEFAULT_CAPACITY, DEFAULT_LINGER_SECS};
pub use proxy::{
    apply_via_proxy, note_url_na, plan, url_evidence, DirectMark, FlowMark, HttpAttribution,
    LoopbackFlow, ProxyObservation, ProxyPlan, ProxySelf, ProxySession, ViaProxy, DOMAIN_SOURCE_PROXY,
    QUIC_PORT, URL_FIELD,
};
