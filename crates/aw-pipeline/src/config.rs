//! Pipeline configuration. Values only; later cards implement the stages that read them.
//!
//! Field names follow the task card (`[aggregate]`, `[store]`, `[limits]`).
//! architecture.md §7 lists `[storage]` and `[correlation]` and says the schema lives in
//! `aw-core::config`. This crate does not own that schema and does not change `aw-core`.
//!
//! An unlimited rate is [`None`], never `0`. `0` would look like "drop everything".

/// Defaults from pipeline.md §3.5, §3.6, §3.7, and §5.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PipelineConfig {
    /// `[aggregate]` bucket width, file flush, and coalesce window.
    pub aggregate: AggregateConfig,
    /// `[store]` batch flush bounds. The batcher itself is a later card.
    pub store: StoreConfig,
    /// `[limits]` per-process token-bucket settings. `None` means unlimited.
    pub limits: LimitsConfig,
    /// `[correlation]` window cap. Correlation itself is a later card.
    pub correlation: CorrelationConfig,
}

/// `[aggregate]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateConfig {
    /// `aggregate.bucket_secs`. Default 5.
    pub bucket_secs: u64,
    /// `aggregate.file_flush_secs`. Default 30.
    pub file_flush_secs: u64,
    /// `aggregate.coalesce_window_ms`. pipeline.md §3.5 describes a 1 second window. Default 1000.
    pub coalesce_window_ms: u64,
}

/// `[store]` batch bounds. Writing is not this card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreConfig {
    /// `store.batch_max_rows`. Default 1000.
    pub batch_max_rows: u64,
    /// `store.batch_max_ms`. Default 100.
    pub batch_max_ms: u64,
}

/// `[limits]`. A missing rate is unlimited (`None`), not zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitsConfig {
    /// `file_open`: 2000/s, burst 10000.
    pub file_open: RateLimit,
    /// `file_rw`: unlimited. Only counters, no records (later card).
    pub file_rw: Option<RateLimit>,
    /// `process_start`: 200/s, burst 1000.
    pub process_start: RateLimit,
    /// `net_connect`: 500/s, burst 2000.
    pub net_connect: RateLimit,
    /// `dns`: 500/s, burst 2000.
    pub dns: RateLimit,
    /// `ipc_transfer`: unlimited.
    pub ipc_transfer: Option<RateLimit>,
    /// `agent_rpc`: 200/s, burst 1000.
    pub agent_rpc: RateLimit,
}

/// `[correlation]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationConfig {
    /// `correlation.max_window_secs`. Default 300.
    pub max_window_secs: u64,
}

/// One token-bucket pair. Both numbers are configured limits, not observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Sustained events per second.
    pub per_sec: u64,
    /// Burst size.
    pub burst: u64,
}

impl Default for AggregateConfig {
    fn default() -> Self {
        Self {
            bucket_secs: 5,
            file_flush_secs: 30,
            coalesce_window_ms: 1000,
        }
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            batch_max_rows: 1000,
            batch_max_ms: 100,
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            file_open: RateLimit {
                per_sec: 2000,
                burst: 10_000,
            },
            file_rw: None,
            process_start: RateLimit {
                per_sec: 200,
                burst: 1000,
            },
            net_connect: RateLimit {
                per_sec: 500,
                burst: 2000,
            },
            dns: RateLimit {
                per_sec: 500,
                burst: 2000,
            },
            ipc_transfer: None,
            agent_rpc: RateLimit {
                per_sec: 200,
                burst: 1000,
            },
        }
    }
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            max_window_secs: 300,
        }
    }
}
