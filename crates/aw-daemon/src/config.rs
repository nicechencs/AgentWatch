//! Daemon configuration (TOML).
//!
//! architecture.md §7 lists file locations and a key registry. It does not number
//! an override ladder. The priority this binary actually applies is:
//!
//! 1. `--config PATH` selects the file. If omitted, the platform default path
//!    from [`crate::paths::default_config_path`] is used when that file exists.
//!    A missing default file is not an error: built-in defaults are used, and
//!    the system directory is not created just to look.
//! 2. Keys present in the file override built-in defaults.
//! 3. `storage.data_dir`, when set, replaces the platform default data directory.
//!    Tests and `--foreground` use this so they never touch the system directories.
//! 4. §7.2 environment variables (`AW_SESSION`, `AW_FORCE_MODE`,
//!    `AW_FORCE_SNI_FALLBACK`, `AW_UI_DEV_URL`) belong to other components. This
//!    card does not treat them as daemon config overrides.
//!
//! Unknown keys are warnings, not hard errors, and are not silently dropped:
//! [`parse_toml`] returns them. Illegal values refuse the load and name the key.
//!
//! The JSON Schema is hand-written. schemars is MIT, but its derive stack
//! (syn, dyn-clone, ref-cast) is heavier than this card needs. The schema lists
//! the same fields as [`DaemonConfig`].

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use thiserror::Error;

use crate::paths::{default_config_path, default_data_dir};

/// Bytes in one mebibyte. `proxy.max_hash_body` defaults to 50 of these.
pub const MIB: u64 = 1024 * 1024;

/// One unknown key found while walking a TOML document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    /// Dotted path, for example `retention.extra`.
    pub key: String,
}

impl ConfigWarning {
    /// Stable log / stderr line. Tests match this wording.
    pub fn message(&self) -> String {
        format!("unknown config key `{}` ignored", self.key)
    }
}

/// Why a config file or value was refused.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("failed to read config `{}`: {source}", path.display())]
    Read {
        /// Path that was requested.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// TOML syntax is invalid. No key path is available.
    #[error("invalid config TOML: {0}")]
    Toml(String),

    /// A known key has a value this build will not accept.
    #[error("invalid config value for key `{key}`: {detail}")]
    Invalid {
        /// Dotted key path.
        key: String,
        /// What was wrong, without echoing secret-shaped values.
        detail: String,
    },

    /// The platform default data or config path cannot be resolved.
    #[error("{0}")]
    Paths(#[source] io::Error),
}

/// Top-level daemon configuration. Field names match §7 sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    /// Where sqlite and the lock file live. `None` means the platform default.
    pub storage: StorageConfig,
    /// Retention caps. Enforced by a later store card; parsed here so the keys exist.
    pub retention: RetentionConfig,
    /// Redaction knobs. Empty in this card; unknown children warn.
    pub redaction: RedactionConfig,
    /// Extra sensitive path globs. Empty in this card.
    pub sensitive_paths: SensitivePathsConfig,
    /// Explicit MITM proxy knobs that §7 registers.
    pub proxy: ProxyConfig,
    /// Optional collectors. Defaults keep every optional probe off.
    pub collectors: CollectorsConfig,
    /// Rate limits. Empty in this card.
    pub limits: LimitsConfig,
    /// Correlation caps registered in §7.
    pub correlation: CorrelationConfig,
    /// Local API. Empty in this card (P1-DAEMON-03 owns the listener).
    pub api: ApiConfig,
    /// Debug switches registered in §7.
    pub debug: DebugConfig,
}

/// `[storage]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageConfig {
    /// Override for the platform data directory. Tests set this to a temp dir.
    pub data_dir: Option<PathBuf>,
}

/// `[retention]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionConfig {
    /// `retention.max_db_size_mb`, default 2048.
    pub max_db_size_mb: u64,
    /// `retention.max_age_days`, default 30.
    pub max_age_days: u64,
}

/// `[redaction]`. No registered keys yet; the section must still parse.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RedactionConfig {}

/// `[sensitive_paths]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SensitivePathsConfig {
    /// Extra path globs treated as sensitive. Values are paths, not file contents.
    pub extra: Vec<String>,
}

/// `[proxy]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// `fail` or `tunnel`. Anything else refuses startup.
    pub on_tls_reject: TlsReject,
    /// `proxy.max_hash_body` in bytes. Default 50 MiB.
    pub max_hash_body: u64,
}

/// `proxy.on_tls_reject`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsReject {
    /// Refuse the connection when the client rejects the session CA.
    Fail,
    /// Tunnel the bytes without decrypting.
    Tunnel,
}

impl TlsReject {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "fail" => Some(Self::Fail),
            "tunnel" => Some(Self::Tunnel),
            _ => None,
        }
    }
}

/// `[collectors]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorsConfig {
    /// `[collectors.windows]`.
    pub windows: WindowsCollectors,
    /// `[collectors.linux]`.
    pub linux: LinuxCollectors,
}

/// `[collectors.windows]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsCollectors {
    /// `collectors.windows.sni`, default false.
    pub sni: bool,
}

/// `[collectors.linux]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCollectors {
    /// `collectors.linux.tls_uprobe`, default false.
    pub tls_uprobe: bool,
    /// `collectors.linux.ipc_payload_peek`, default false.
    pub ipc_payload_peek: bool,
}

/// `[limits]`. No registered keys yet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LimitsConfig {}

/// `[correlation]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationConfig {
    /// `correlation.max_hash_file_size` in bytes. Default 10 MiB.
    pub max_hash_file_size: u64,
}

/// `[api]`. No registered keys yet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApiConfig {}

/// `[debug]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugConfig {
    /// `debug.keep_raw_events`, default false.
    pub keep_raw_events: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            storage: StorageConfig { data_dir: None },
            retention: RetentionConfig {
                max_db_size_mb: 2048,
                max_age_days: 30,
            },
            redaction: RedactionConfig {},
            sensitive_paths: SensitivePathsConfig { extra: Vec::new() },
            proxy: ProxyConfig {
                on_tls_reject: TlsReject::Fail,
                max_hash_body: 50 * MIB,
            },
            collectors: CollectorsConfig {
                windows: WindowsCollectors { sni: false },
                linux: LinuxCollectors {
                    tls_uprobe: false,
                    ipc_payload_peek: false,
                },
            },
            limits: LimitsConfig {},
            correlation: CorrelationConfig {
                max_hash_file_size: 10 * MIB,
            },
            api: ApiConfig {},
            debug: DebugConfig {
                keep_raw_events: false,
            },
        }
    }
}

/// Data directory after applying `storage.data_dir` over the platform default.
///
/// # Errors
///
/// Returns [`ConfigError::Paths`] when the platform default cannot be resolved
/// and the file did not override it.
pub fn resolve_data_dir(config: &DaemonConfig) -> Result<PathBuf, ConfigError> {
    if let Some(dir) = &config.storage.data_dir {
        return Ok(dir.clone());
    }
    default_data_dir().map_err(ConfigError::Paths)
}

/// Parse TOML text. Unknown keys become warnings. Illegal values name the key.
///
/// # Errors
///
/// Returns [`ConfigError::Toml`] or [`ConfigError::Invalid`]. Does not touch the filesystem.
pub fn parse_toml(text: &str) -> Result<(DaemonConfig, Vec<ConfigWarning>), ConfigError> {
    let value: toml::Value =
        toml::from_str(text).map_err(|err| ConfigError::Toml(err.to_string()))?;
    let Some(table) = value.as_table() else {
        return Err(ConfigError::Invalid {
            key: "<root>".to_owned(),
            detail: "config document must be a table".to_owned(),
        });
    };

    let mut warnings = Vec::new();
    let mut config = DaemonConfig::default();
    for (key, child) in table {
        match key.as_str() {
            "storage" => config.storage = parse_storage(child, "storage", &mut warnings)?,
            "retention" => config.retention = parse_retention(child, "retention", &mut warnings)?,
            "redaction" => {
                warn_unknown_children(child, "redaction", &mut warnings)?;
            }
            "sensitive_paths" => {
                config.sensitive_paths =
                    parse_sensitive_paths(child, "sensitive_paths", &mut warnings)?;
            }
            "proxy" => config.proxy = parse_proxy(child, "proxy", &mut warnings)?,
            "collectors" => {
                config.collectors = parse_collectors(child, "collectors", &mut warnings)?
            }
            "limits" => {
                warn_unknown_children(child, "limits", &mut warnings)?;
            }
            "correlation" => {
                config.correlation = parse_correlation(child, "correlation", &mut warnings)?;
            }
            "api" => {
                warn_unknown_children(child, "api", &mut warnings)?;
            }
            "debug" => config.debug = parse_debug(child, "debug", &mut warnings)?,
            other => warnings.push(ConfigWarning {
                key: other.to_owned(),
            }),
        }
    }
    Ok((config, warnings))
}

/// Load a config file from disk.
///
/// # Errors
///
/// Read failures and illegal values are returned. Unknown keys are warnings.
pub fn load_path(path: &Path) -> Result<(DaemonConfig, Vec<ConfigWarning>), ConfigError> {
    let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    parse_toml(&text)
}

/// Resolve which file to read.
///
/// `cli_config` is `--config`. When it is `None` and the platform default file
/// is absent, returns `Ok(None)` (built-in defaults, no directory created).
///
/// # Errors
///
/// An explicit `--config` that cannot be read, or a file with illegal values,
/// is an error. A missing platform default path (for example unset `ProgramData`
/// when no `--config` was given and no override is possible) is also an error
/// only when we must name that path and the environment cannot.
pub fn load_selected(
    cli_config: Option<&Path>,
) -> Result<(DaemonConfig, Vec<ConfigWarning>, Option<PathBuf>), ConfigError> {
    if let Some(path) = cli_config {
        let (config, warnings) = load_path(path)?;
        return Ok((config, warnings, Some(path.to_path_buf())));
    }
    let default_path = default_config_path().map_err(ConfigError::Paths)?;
    if !default_path.is_file() {
        return Ok((DaemonConfig::default(), Vec::new(), None));
    }
    let (config, warnings) = load_path(&default_path)?;
    Ok((config, warnings, Some(default_path)))
}

/// JSON Schema document whose `properties` match [`DaemonConfig`] 1:1.
pub fn config_schema_json() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://agentwatch.local/schema/daemon-config.json",
        "title": "DaemonConfig",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "storage": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "data_dir": { "type": "string", "description": "Override for the platform data directory." }
                }
            },
            "retention": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "max_db_size_mb": { "type": "integer", "minimum": 1, "default": 2048 },
                    "max_age_days": { "type": "integer", "minimum": 1, "default": 30 }
                }
            },
            "redaction": {
                "type": "object",
                "additionalProperties": false,
                "properties": {}
            },
            "sensitive_paths": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "extra": { "type": "array", "items": { "type": "string" } }
                }
            },
            "proxy": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "on_tls_reject": { "type": "string", "enum": ["fail", "tunnel"], "default": "fail" },
                    "max_hash_body": { "type": "integer", "minimum": 1, "default": 50 * MIB }
                }
            },
            "collectors": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "windows": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "sni": { "type": "boolean", "default": false }
                        }
                    },
                    "linux": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "tls_uprobe": { "type": "boolean", "default": false },
                            "ipc_payload_peek": { "type": "boolean", "default": false }
                        }
                    }
                }
            },
            "limits": {
                "type": "object",
                "additionalProperties": false,
                "properties": {}
            },
            "correlation": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "max_hash_file_size": { "type": "integer", "minimum": 1, "default": 10 * MIB }
                }
            },
            "api": {
                "type": "object",
                "additionalProperties": false,
                "properties": {}
            },
            "debug": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "keep_raw_events": { "type": "boolean", "default": false }
                }
            }
        }
    })
}

/// Pretty-printed schema for `agentwatchd config schema`.
///
/// # Errors
///
/// Returns an error if the in-memory schema cannot be serialized (it is built
/// from literals, so this is a programming failure surfaced instead of panicking).
pub fn config_schema_pretty() -> Result<String, String> {
    serde_json::to_string_pretty(&config_schema_json()).map_err(|err| err.to_string())
}

fn parse_storage(
    value: &toml::Value,
    prefix: &str,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<StorageConfig, ConfigError> {
    let table = expect_table(value, prefix)?;
    let mut data_dir = None;
    for (key, child) in table {
        match key.as_str() {
            "data_dir" => {
                let raw = expect_string(child, &dot(prefix, "data_dir"))?;
                if raw.is_empty() {
                    return Err(invalid(&dot(prefix, "data_dir"), "path must not be empty"));
                }
                data_dir = Some(PathBuf::from(raw));
            }
            other => warnings.push(ConfigWarning {
                key: dot(prefix, other),
            }),
        }
    }
    Ok(StorageConfig { data_dir })
}

fn parse_retention(
    value: &toml::Value,
    prefix: &str,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<RetentionConfig, ConfigError> {
    let mut out = RetentionConfig {
        max_db_size_mb: 2048,
        max_age_days: 30,
    };
    let table = expect_table(value, prefix)?;
    for (key, child) in table {
        match key.as_str() {
            "max_db_size_mb" => {
                out.max_db_size_mb = expect_positive_int(child, &dot(prefix, "max_db_size_mb"))?;
            }
            "max_age_days" => {
                out.max_age_days = expect_positive_int(child, &dot(prefix, "max_age_days"))?;
            }
            other => warnings.push(ConfigWarning {
                key: dot(prefix, other),
            }),
        }
    }
    Ok(out)
}

fn parse_sensitive_paths(
    value: &toml::Value,
    prefix: &str,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<SensitivePathsConfig, ConfigError> {
    let table = expect_table(value, prefix)?;
    let mut extra = Vec::new();
    for (key, child) in table {
        match key.as_str() {
            "extra" => {
                let items = child.as_array().ok_or_else(|| {
                    invalid(&dot(prefix, "extra"), "expected an array of strings")
                })?;
                for (index, item) in items.iter().enumerate() {
                    let path_key = format!("{prefix}.extra[{index}]");
                    extra.push(expect_string(item, &path_key)?.to_owned());
                }
            }
            other => warnings.push(ConfigWarning {
                key: dot(prefix, other),
            }),
        }
    }
    Ok(SensitivePathsConfig { extra })
}

fn parse_proxy(
    value: &toml::Value,
    prefix: &str,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<ProxyConfig, ConfigError> {
    let mut out = ProxyConfig {
        on_tls_reject: TlsReject::Fail,
        max_hash_body: 50 * MIB,
    };
    let table = expect_table(value, prefix)?;
    for (key, child) in table {
        match key.as_str() {
            "on_tls_reject" => {
                let raw = expect_string(child, &dot(prefix, "on_tls_reject"))?;
                out.on_tls_reject = TlsReject::parse(raw).ok_or_else(|| {
                    invalid(&dot(prefix, "on_tls_reject"), "expected `fail` or `tunnel`")
                })?;
            }
            "max_hash_body" => {
                out.max_hash_body = expect_positive_int(child, &dot(prefix, "max_hash_body"))?;
            }
            other => warnings.push(ConfigWarning {
                key: dot(prefix, other),
            }),
        }
    }
    Ok(out)
}

fn parse_collectors(
    value: &toml::Value,
    prefix: &str,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<CollectorsConfig, ConfigError> {
    let mut out = CollectorsConfig {
        windows: WindowsCollectors { sni: false },
        linux: LinuxCollectors {
            tls_uprobe: false,
            ipc_payload_peek: false,
        },
    };
    let table = expect_table(value, prefix)?;
    for (key, child) in table {
        match key.as_str() {
            "windows" => out.windows = parse_windows(child, &dot(prefix, "windows"), warnings)?,
            "linux" => out.linux = parse_linux(child, &dot(prefix, "linux"), warnings)?,
            other => warnings.push(ConfigWarning {
                key: dot(prefix, other),
            }),
        }
    }
    Ok(out)
}

fn parse_windows(
    value: &toml::Value,
    prefix: &str,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<WindowsCollectors, ConfigError> {
    let mut sni = false;
    let table = expect_table(value, prefix)?;
    for (key, child) in table {
        match key.as_str() {
            "sni" => sni = expect_bool(child, &dot(prefix, "sni"))?,
            other => warnings.push(ConfigWarning {
                key: dot(prefix, other),
            }),
        }
    }
    Ok(WindowsCollectors { sni })
}

fn parse_linux(
    value: &toml::Value,
    prefix: &str,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<LinuxCollectors, ConfigError> {
    let mut tls_uprobe = false;
    let mut ipc_payload_peek = false;
    let table = expect_table(value, prefix)?;
    for (key, child) in table {
        match key.as_str() {
            "tls_uprobe" => tls_uprobe = expect_bool(child, &dot(prefix, "tls_uprobe"))?,
            "ipc_payload_peek" => {
                ipc_payload_peek = expect_bool(child, &dot(prefix, "ipc_payload_peek"))?;
            }
            other => warnings.push(ConfigWarning {
                key: dot(prefix, other),
            }),
        }
    }
    Ok(LinuxCollectors {
        tls_uprobe,
        ipc_payload_peek,
    })
}

fn parse_correlation(
    value: &toml::Value,
    prefix: &str,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<CorrelationConfig, ConfigError> {
    let mut max_hash_file_size = 10 * MIB;
    let table = expect_table(value, prefix)?;
    for (key, child) in table {
        match key.as_str() {
            "max_hash_file_size" => {
                max_hash_file_size =
                    expect_positive_int(child, &dot(prefix, "max_hash_file_size"))?;
            }
            other => warnings.push(ConfigWarning {
                key: dot(prefix, other),
            }),
        }
    }
    Ok(CorrelationConfig { max_hash_file_size })
}

fn parse_debug(
    value: &toml::Value,
    prefix: &str,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<DebugConfig, ConfigError> {
    let mut keep_raw_events = false;
    let table = expect_table(value, prefix)?;
    for (key, child) in table {
        match key.as_str() {
            "keep_raw_events" => {
                keep_raw_events = expect_bool(child, &dot(prefix, "keep_raw_events"))?;
            }
            other => warnings.push(ConfigWarning {
                key: dot(prefix, other),
            }),
        }
    }
    Ok(DebugConfig { keep_raw_events })
}

fn warn_unknown_children(
    value: &toml::Value,
    prefix: &str,
    warnings: &mut Vec<ConfigWarning>,
) -> Result<(), ConfigError> {
    let table = expect_table(value, prefix)?;
    for (key, _) in table {
        warnings.push(ConfigWarning {
            key: dot(prefix, key),
        });
    }
    Ok(())
}

fn expect_table<'a>(
    value: &'a toml::Value,
    key: &str,
) -> Result<&'a toml::map::Map<String, toml::Value>, ConfigError> {
    value
        .as_table()
        .ok_or_else(|| invalid(key, "expected a table"))
}

fn expect_string<'a>(value: &'a toml::Value, key: &str) -> Result<&'a str, ConfigError> {
    value
        .as_str()
        .ok_or_else(|| invalid(key, "expected a string"))
}

fn expect_bool(value: &toml::Value, key: &str) -> Result<bool, ConfigError> {
    value
        .as_bool()
        .ok_or_else(|| invalid(key, "expected a boolean"))
}

fn expect_positive_int(value: &toml::Value, key: &str) -> Result<u64, ConfigError> {
    let number = value
        .as_integer()
        .ok_or_else(|| invalid(key, "expected a positive integer"))?;
    if number <= 0 {
        return Err(invalid(key, "expected a positive integer"));
    }
    u64::try_from(number).map_err(|_| invalid(key, "integer is out of range"))
}

fn invalid(key: &str, detail: &str) -> ConfigError {
    ConfigError::Invalid {
        key: key.to_owned(),
        detail: detail.to_owned(),
    }
}

fn dot(prefix: &str, key: &str) -> String {
    format!("{prefix}.{key}")
}

#[cfg(test)]
mod tests {
    use super::{config_schema_json, parse_toml, ConfigError, TlsReject};

    #[test]
    fn minimal_keys_override_defaults() -> Result<(), ConfigError> {
        let text = "\n[retention]\nmax_db_size_mb = 10\nmax_age_days = 2\n\n[debug]\nkeep_raw_events = true\n";
        let (config, warnings) = parse_toml(text)?;
        if !warnings.is_empty() {
            return Err(ConfigError::Invalid {
                key: "warnings".to_owned(),
                detail: warnings[0].message(),
            });
        }
        if config.retention.max_db_size_mb != 10 || config.retention.max_age_days != 2 {
            return Err(ConfigError::Invalid {
                key: "retention".to_owned(),
                detail: "defaults were not overridden".to_owned(),
            });
        }
        if !config.debug.keep_raw_events {
            return Err(ConfigError::Invalid {
                key: "debug.keep_raw_events".to_owned(),
                detail: "expected true".to_owned(),
            });
        }
        if config.proxy.on_tls_reject != TlsReject::Fail {
            return Err(ConfigError::Invalid {
                key: "proxy.on_tls_reject".to_owned(),
                detail: "default drifted".to_owned(),
            });
        }
        Ok(())
    }

    #[test]
    fn unknown_key_warns() -> Result<(), ConfigError> {
        let (config, warnings) = parse_toml("not_a_real_key = 1\n[retention]\nnope = true\n")?;
        if config.retention.max_age_days != 30 {
            return Err(ConfigError::Invalid {
                key: "retention.max_age_days".to_owned(),
                detail: "unknown key changed a default".to_owned(),
            });
        }
        let messages: Vec<String> = warnings.iter().map(super::ConfigWarning::message).collect();
        if messages.len() != 2 {
            return Err(ConfigError::Invalid {
                key: "warnings".to_owned(),
                detail: format!("expected 2 warnings, got {messages:?}"),
            });
        }
        Ok(())
    }

    #[test]
    fn illegal_value_names_the_key() -> Result<(), ConfigError> {
        let err = match parse_toml("[proxy]\non_tls_reject = \"drop\"\n") {
            Ok(_) => {
                return Err(ConfigError::Invalid {
                    key: "proxy.on_tls_reject".to_owned(),
                    detail: "illegal value was accepted".to_owned(),
                });
            }
            Err(err) => err,
        };
        match err {
            ConfigError::Invalid { key, .. } if key == "proxy.on_tls_reject" => Ok(()),
            ConfigError::Invalid { key, detail } => Err(ConfigError::Invalid {
                key,
                detail: format!("expected proxy.on_tls_reject, detail was {detail}"),
            }),
            other => Err(ConfigError::Invalid {
                key: "proxy.on_tls_reject".to_owned(),
                detail: other.to_string(),
            }),
        }
    }

    #[test]
    fn schema_is_json_object_covering_sections() -> Result<(), String> {
        let schema = config_schema_json();
        let props = schema
            .get("properties")
            .and_then(|v| v.as_object())
            .ok_or_else(|| "schema properties missing".to_owned())?;
        for name in [
            "storage",
            "retention",
            "redaction",
            "sensitive_paths",
            "proxy",
            "collectors",
            "limits",
            "correlation",
            "api",
            "debug",
        ] {
            if !props.contains_key(name) {
                return Err(format!("schema missing {name}"));
            }
        }
        Ok(())
    }
}
