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
    /// `[sensitive_paths]` extras and the session home used to expand `~`.
    pub sensitive: SensitiveConfig,
    /// `[redaction]` session salt and the unsafe whole-engine switch.
    pub redaction: RedactionConfig,
    /// Resource readings the degrade ladder consumes. Replay leaves them idle.
    pub degrade: DegradeConfig,
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
    /// Open file-access rows kept per session. Default 100_000.
    ///
    /// Past this the oldest open row is emitted early and counted. `0` is not a
    /// cap; it becomes the default rather than "keep nothing".
    pub file_state_cap: u64,
    /// Directory prefixes folded into one counted row. Empty uses the built-in
    /// list (`/proc`, `/sys`, `/dev`, dynamic-library and locale directories).
    pub noise_prefixes: Vec<String>,
    /// Path suffixes treated as noise even outside those prefixes
    /// (`.so`, `.dylib`, locale catalogs). Empty uses the built-in list.
    pub noise_suffixes: Vec<String>,
    /// Sample paths kept on a folded directory row. Default 8.
    pub noise_sample_cap: u64,
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

/// `[sensitive_paths]`. Built-in rules stay on. This only adds rules and names
/// the home directory `~` expands to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SensitiveConfig {
    /// Session user's home. `None` leaves a leading `~` unmatched rather than
    /// expanding it to the daemon user's home.
    pub home: Option<String>,
    /// `true` on Windows: path compare ignores ASCII case. Replay of a Windows
    /// fixture sets this; the host OS is not consulted.
    pub case_insensitive: bool,
    /// Extra rules from configuration. Built-in rules are not in this list and
    /// cannot be removed through it.
    pub extra: Vec<SensitiveRuleConfig>,
}

/// One user-supplied sensitive-path rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveRuleConfig {
    /// Rule id. A duplicate of a built-in id is ignored.
    pub id: String,
    /// `linux`, `macos`, `windows`, or `any`.
    pub platform: String,
    /// Glob. `~` is the session home. `*` does not cross a separator; `**` does.
    pub glob: String,
    /// Paths that match `glob` but must not be labelled.
    pub exclude: Vec<String>,
}

/// `[redaction]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedactionConfig {
    /// Per-session salt mixed into the optional 8-hex suffix.
    ///
    /// Default is empty: replacements are `«redacted:<rule_id>»` with no hash.
    /// A live session fills this from an OS random source and does not persist it.
    pub salt: Vec<u8>,
    /// `true` only for `--unsafe-no-redact`. Turns every built-in rule off and
    /// sets [`Self::unsafe_no_redact`], which the session row must keep.
    pub unsafe_no_redact: bool,
    /// Also replace the user-name segment of a path (security-privacy §3.2 F).
    /// Off unless the caller asked. Export-time redaction is a separate path.
    pub redact_paths: bool,
    /// User-name segment replaced when [`Self::redact_paths`] is on.
    /// `None` replaces nothing: there is no name to look for.
    pub path_user: Option<String>,
}

/// Resource readings for the degrade ladder (P2-PIPE-04).
///
/// Replay does not sample the host. A caller that has a queue depth, a CPU
/// sample, a session size, or a free-disk reading sets the matching field.
/// `None` means "not observed", and that signal does not by itself enter a level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradeConfig {
    /// `limits.hard_rss_bytes`. Default 512 MiB. `None` disables the RSS stop.
    pub hard_rss_bytes: Option<u64>,
    /// Pipeline CPU budget, millicores of one core (1000 = one full core).
    /// The ladder enters when a sample stays over twice this for 10 s.
    /// Default 150, which is the 15% pressure budget in performance-budget §1.
    pub cpu_budget_millicores: u64,
    /// `max_session_bytes`. `None` means the volume signal is not configured.
    pub max_session_bytes: Option<u64>,
    /// How many detail records one process keeps at L3. Default 64.
    pub l3_keep_per_proc: u64,
    /// Seconds a triggering condition must stay clear before one level is left.
    /// performance-budget §4 says 30.
    pub recover_secs: u64,
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
            file_state_cap: 100_000,
            noise_prefixes: Vec::new(),
            noise_suffixes: Vec::new(),
            noise_sample_cap: 8,
        }
    }
}

impl Default for DegradeConfig {
    fn default() -> Self {
        Self {
            hard_rss_bytes: Some(512 * 1024 * 1024),
            cpu_budget_millicores: 150,
            max_session_bytes: None,
            l3_keep_per_proc: 64,
            recover_secs: 30,
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
