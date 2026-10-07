//! Enrich lookups. P1-PIPE-02 owns the process cache; DNS and other lookups are later cards.

mod proc_cache;

pub use proc_cache::{ProcCache, ProcCacheConfig, ProcInfo, DEFAULT_CAPACITY, DEFAULT_LINGER_SECS};
