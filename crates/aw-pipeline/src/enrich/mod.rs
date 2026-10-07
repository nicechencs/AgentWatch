//! Enrich lookups. P1-PIPE-02 owns the process cache; DNS and other lookups are later cards.

mod dns;
mod proc_cache;

pub use dns::{ConnectDomain, DnsCache, DnsObs, MatchStep, DOMAIN_FIELD};
pub use proc_cache::{ProcCache, ProcCacheConfig, ProcInfo, DEFAULT_CAPACITY, DEFAULT_LINGER_SECS};
