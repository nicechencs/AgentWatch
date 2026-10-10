//! `aw config show|get|set|edit|schema` and `aw config rules list` (P2-CLI-02).
//!
//! Configuration is read and written through the daemon, which hot-reloads it.
//! This command does not open the config file and does not open the database.
//!
//! - `GET /api/v1/config` — `show`. `?effective=1` asks for the merged value.
//! - `GET /api/v1/config?key=<dotted>` — `get`.
//! - `PUT /api/v1/config` with `{ "key", "value" }` — `set`. The daemon checks
//!   the value against the JSON Schema and reloads. PUT is administrator-only.
//! - `GET /api/v1/config/schema` — `schema`.
//! - `GET /api/v1/rules` — `rules list`.
//!
//! `rules test` is P3 and stays unimplemented. `edit` fetches the document,
//! refuses to spawn an editor in this build (no editor is a side effect this
//! card owns), and tells the operator to use `set`.
//!
//! [`UnwiredConfig`] is the production client: the routes are still stubs, so
//! every call is exit 3 instead of printing a fake empty config.

use serde_json::{json, Value};

use crate::exit;

use super::tree::{ConfigCmd, RulesCmd};
use super::Outcome;

/// Why a config call did not return a document.
///
/// `Failed`, `Forbidden`, and `Invalid` are returned by a live client. The
/// production client only returns `Unreachable` until the daemon serves
/// `/config`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum ConfigError {
    /// Nothing is listening, or this build has no client.
    Unreachable { detail: String },
    /// The daemon answered, but not with a usable document.
    Failed { detail: String },
    /// Authenticated and refused. Exit 4.
    Forbidden { detail: String },
    /// The value does not match the schema. Exit 2.
    Invalid { detail: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { detail }
            | Self::Failed { detail }
            | Self::Forbidden { detail }
            | Self::Invalid { detail } => write!(f, "{detail}"),
        }
    }
}

/// One config document plus the schema the daemon validated it with.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ConfigDoc {
    /// Effective or file values. Unknown keys are absent, not filled with defaults
    /// the CLI invented.
    pub value: Value,
    /// `true` when `value` is the merged effective config.
    pub effective: bool,
}

/// Daemon calls for `aw config`. Implementations must not read the config file.
pub(crate) trait ConfigApi {
    /// `GET /api/v1/config`.
    ///
    /// # Errors
    ///
    /// A daemon or transport failure.
    fn show(&mut self, effective: bool) -> Result<ConfigDoc, ConfigError>;

    /// `GET /api/v1/config?key=`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when `key` is not in the schema.
    fn get(&mut self, key: &str) -> Result<Value, ConfigError>;

    /// `PUT /api/v1/config`. The daemon reloads; this call does not restart it.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when `value` fails schema validation.
    /// [`ConfigError::Forbidden`] when the caller is not an administrator.
    fn set(&mut self, key: &str, value: &Value) -> Result<ConfigDoc, ConfigError>;

    /// `GET /api/v1/config/schema`.
    ///
    /// # Errors
    ///
    /// A daemon or transport failure.
    fn schema(&mut self) -> Result<Value, ConfigError>;

    /// `GET /api/v1/rules`.
    ///
    /// # Errors
    ///
    /// A daemon or transport failure.
    fn rules(&mut self) -> Result<Vec<RuleInfo>, ConfigError>;
}

/// One loaded rule, already safe to print. No rule body, no sample text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleInfo {
    /// Rule id.
    pub id: String,
    /// `true` when the rule ships with the daemon and cannot be disabled here.
    pub builtin: bool,
}

/// Production client. No socket is opened.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct UnwiredConfig;

const UNWIRED: &str = "daemon config API is not connected; GET /api/v1/config is still a stub, so this command does not read the config file. Start it with `aw daemon start`, or pass --no-daemon (polling collectors, all evidence S)";

impl ConfigApi for UnwiredConfig {
    fn show(&mut self, _: bool) -> Result<ConfigDoc, ConfigError> {
        Err(ConfigError::Unreachable {
            detail: UNWIRED.to_owned(),
        })
    }

    fn get(&mut self, _: &str) -> Result<Value, ConfigError> {
        Err(ConfigError::Unreachable {
            detail: UNWIRED.to_owned(),
        })
    }

    fn set(&mut self, _: &str, _: &Value) -> Result<ConfigDoc, ConfigError> {
        Err(ConfigError::Unreachable {
            detail: UNWIRED.to_owned(),
        })
    }

    fn schema(&mut self) -> Result<Value, ConfigError> {
        Err(ConfigError::Unreachable {
            detail: UNWIRED.to_owned(),
        })
    }

    fn rules(&mut self) -> Result<Vec<RuleInfo>, ConfigError> {
        Err(ConfigError::Unreachable {
            detail: UNWIRED.to_owned(),
        })
    }
}

/// Production client for `GET`/`PUT /api/v1/config`.
///
/// [`UnwiredConfig`] stays for tests. `schema` and `rules` have no daemon
/// route; those methods return [`ConfigError::Failed`] naming the missing
/// route instead of an empty document.
pub(crate) struct HttpConfigApi {
    endpoint: crate::endpoint::Endpoint,
}

impl HttpConfigApi {
    /// Bind to `endpoint`. Does not connect.
    #[must_use]
    pub(crate) fn new(endpoint: crate::endpoint::Endpoint) -> Self {
        Self { endpoint }
    }

    fn call(&self, request: &crate::client::ApiRequest) -> Result<Value, ConfigError> {
        let transport =
            crate::client::LoopbackHttp::new(&self.endpoint).map_err(client_to_config)?;
        let mut client = crate::client::Client::new(self.endpoint.clone(), transport);
        let reply = client.call(request).map_err(client_to_config)?;
        reply.json().ok_or_else(|| ConfigError::Failed {
            detail: "daemon returned a non-JSON body".to_owned(),
        })
    }
}

impl ConfigApi for HttpConfigApi {
    fn show(&mut self, effective: bool) -> Result<ConfigDoc, ConfigError> {
        let body = self.call(&show_request(effective, None))?;
        let value = match body.get("config") {
            Some(value) => value.clone(),
            None => body,
        };
        Ok(ConfigDoc { value, effective })
    }

    fn get(&mut self, key: &str) -> Result<Value, ConfigError> {
        let body = self.call(&show_request(true, Some(key)))?;
        // The daemon ignores `?key=` and returns the whole in-memory document.
        // Walk it. A missing key is not `null` invented by this process.
        let root = body.get("config").unwrap_or(&body);
        lookup_key(root, key)
    }

    fn set(&mut self, key: &str, value: &Value) -> Result<ConfigDoc, ConfigError> {
        let body = self.call(&set_request(key, value))?;
        // PUT replaces the in-memory document with the body and answers
        // `{ "applied": "memory" }`. That is not the new document. Re-read it.
        let _ = body;
        self.show(false)
    }

    fn schema(&mut self) -> Result<Value, ConfigError> {
        // `GET /api/v1/config/schema` is not a route. Do not print `{}`.
        Err(ConfigError::Failed {
            detail:
                "GET /api/v1/config/schema is not served; this command does not invent a schema"
                    .to_owned(),
        })
    }

    fn rules(&mut self) -> Result<Vec<RuleInfo>, ConfigError> {
        // `GET /api/v1/rules` is not a route. `rules list` does not use this
        // client (it loads files offline). A call that does reach here must
        // not claim there are no rules.
        Err(ConfigError::Failed {
            detail:
                "GET /api/v1/rules is not served; this command does not invent an empty rule list"
                    .to_owned(),
        })
    }
}

fn lookup_key(root: &Value, key: &str) -> Result<Value, ConfigError> {
    let mut current = root;
    for part in key.split('.') {
        match current.get(part) {
            Some(child) => current = child,
            None => {
                return Err(ConfigError::Invalid {
                    detail: format!("config has no key `{key}`"),
                });
            }
        }
    }
    Ok(current.clone())
}

fn client_to_config(err: crate::client::ClientError) -> ConfigError {
    match &err {
        crate::client::ClientError::Unreachable { .. } => ConfigError::Unreachable {
            detail: clip_config(&err.to_string()),
        },
        crate::client::ClientError::Forbidden { .. }
        | crate::client::ClientError::Status {
            status: 401 | 403, ..
        } => ConfigError::Forbidden {
            detail: clip_config(&err.to_string()),
        },
        crate::client::ClientError::Status { status: 400, .. } => ConfigError::Invalid {
            detail: clip_config(&err.to_string()),
        },
        crate::client::ClientError::Status { .. }
        | crate::client::ClientError::Transport { .. } => ConfigError::Failed {
            detail: clip_config(&err.to_string()),
        },
    }
}

fn clip_config(text: &str) -> String {
    let mut out: String = text.chars().take(240).collect();
    if text.chars().count() > 240 {
        out.push('…');
    }
    out
}

/// `GET /api/v1/config` with the `effective` and `key` query this command uses.
#[must_use]
pub(crate) fn show_request(effective: bool, key: Option<&str>) -> crate::client::ApiRequest {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    if effective {
        pairs.push(("effective", "1"));
    }
    if let Some(key) = key {
        pairs.push(("key", key));
    }
    crate::client::ApiRequest::get_query("/api/v1/config", encode_pairs(&pairs))
}

/// `PUT /api/v1/config`.
#[must_use]
pub(crate) fn set_request(key: &str, value: &Value) -> crate::client::ApiRequest {
    crate::client::ApiRequest::put_json("/api/v1/config", &json!({ "key": key, "value": value }))
}

/// `GET /api/v1/config/schema`.
#[must_use]
pub(crate) fn schema_request() -> crate::client::ApiRequest {
    crate::client::ApiRequest::get("/api/v1/config/schema")
}

/// `GET /api/v1/rules`.
#[must_use]
pub(crate) fn rules_request() -> crate::client::ApiRequest {
    crate::client::ApiRequest::get("/api/v1/rules")
}

fn encode_pairs(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (index, (key, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        out.push_str(&encode_component(key));
        out.push('=');
        out.push_str(&encode_component(value));
    }
    out
}

fn encode_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Run one `config` subcommand.
pub(crate) fn run(cmd: &ConfigCmd, json: bool, api: &mut dyn ConfigApi) -> Outcome {
    match cmd {
        ConfigCmd::Show { effective } => {
            let _request = show_request(*effective, None);
            match api.show(*effective) {
                Ok(doc) => doc_outcome(&doc, json),
                Err(err) => config_error(err, json),
            }
        }
        ConfigCmd::Get { key } => {
            if let Some(detail) = bad_key(key) {
                return super::error_outcome(exit::USAGE, "usage", &detail, json);
            }
            let _request = show_request(true, Some(key));
            match api.get(key) {
                Ok(value) => value_outcome(key, &value, json),
                Err(err) => config_error(err, json),
            }
        }
        ConfigCmd::Set { key, value } => {
            if let Some(detail) = bad_key(key) {
                return super::error_outcome(exit::USAGE, "usage", &detail, json);
            }
            let parsed = match parse_set_value(value) {
                Ok(parsed) => parsed,
                Err(detail) => {
                    return super::error_outcome(exit::USAGE, "usage", &detail, json);
                }
            };
            let _request = set_request(key, &parsed);
            match api.set(key, &parsed) {
                Ok(doc) => doc_outcome(&doc, json),
                Err(err) => config_error(err, json),
            }
        }
        ConfigCmd::Edit => super::error_outcome(
            exit::GENERAL,
            "not_implemented",
            "`config edit` does not spawn an editor in this build; use `aw config set <key> <value>` (尚未实现)",
            json,
        ),
        ConfigCmd::Schema => {
            let _request = schema_request();
            match api.schema() {
                Ok(schema) => value_outcome("schema", &schema, json),
                Err(err) => config_error(err, json),
            }
        }
        ConfigCmd::Rules(RulesCmd::List) => {
            let _request = rules_request();
            match api.rules() {
                Ok(rules) => rules_outcome(&rules, json),
                Err(err) => config_error(err, json),
            }
        }
        ConfigCmd::Rules(RulesCmd::Test { .. }) => super::error_outcome(
            exit::GENERAL,
            "not_implemented",
            "`config rules test` is not implemented yet (尚未实现); it belongs to P3",
            json,
        ),
    }
}

/// Dotted keys: `retention.max_age_days`. Empty segments and characters outside
/// the schema's ident set are refused before the request is built.
fn bad_key(key: &str) -> Option<String> {
    if key.is_empty() {
        return Some("config key is empty".to_owned());
    }
    let ok = key.split('.').all(|part| {
        !part.is_empty()
            && part
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    });
    if ok {
        None
    } else {
        Some(format!(
            "`{key}` is not a dotted config key (letters, digits, underscore)"
        ))
    }
}

/// `set` values: JSON when the text is a JSON literal (`true`, `7`, `"text"`,
/// `[...]`), otherwise a string. A bare `7` is a number, matching
/// `retention.max_age_days`.
fn parse_set_value(text: &str) -> Result<Value, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("config value is empty".to_owned());
    }
    if trimmed == "true" || trimmed == "false" || trimmed == "null" {
        return serde_json::from_str(trimmed).map_err(|err| err.to_string());
    }
    if trimmed.starts_with('{')
        || trimmed.starts_with('[')
        || trimmed.starts_with('"')
        || trimmed
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_digit() || ch == '-')
    {
        return serde_json::from_str(trimmed)
            .map_err(|err| format!("`{trimmed}` is not valid JSON for a config value ({err})"));
    }
    Ok(Value::String(trimmed.to_owned()))
}

fn doc_outcome(doc: &ConfigDoc, json_mode: bool) -> Outcome {
    let text = if json_mode {
        format!(
            "{}\n",
            json!({ "effective": doc.effective, "config": doc.value })
        )
    } else {
        format!("{}\n", pretty_tomlish(&doc.value))
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn value_outcome(key: &str, value: &Value, json_mode: bool) -> Outcome {
    let text = if json_mode {
        format!("{}\n", json!({ "key": key, "value": value }))
    } else {
        format!("{}\n", pretty_scalar(value))
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn rules_outcome(rules: &[RuleInfo], json_mode: bool) -> Outcome {
    let text = if json_mode {
        format!(
            "{}\n",
            json!({
                "rules": rules.iter().map(|rule| json!({
                    "id": rule.id,
                    "builtin": rule.builtin,
                })).collect::<Vec<_>>(),
            })
        )
    } else if rules.is_empty() {
        "no rules loaded\n".to_owned()
    } else {
        let mut lines = String::new();
        for rule in rules {
            let kind = if rule.builtin { "builtin" } else { "custom" };
            lines.push_str(&format!("{kind} {}\n", rule.id));
        }
        lines
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn config_error(err: ConfigError, json_mode: bool) -> Outcome {
    let (code, machine) = match &err {
        ConfigError::Unreachable { .. } => (exit::UNREACHABLE, "unreachable"),
        ConfigError::Forbidden { .. } => (exit::PERMISSION, "permission"),
        ConfigError::Invalid { .. } => (exit::USAGE, "usage"),
        ConfigError::Failed { .. } => (exit::GENERAL, "config"),
    };
    super::error_outcome(code, machine, &err.to_string(), json_mode)
}

/// One level of a JSON object as `key = value` lines. Nested objects indent.
/// This is a display, not a TOML encoder: the daemon owns the file format.
fn pretty_tomlish(value: &Value) -> String {
    let mut lines = String::new();
    write_value(&mut lines, value, 0);
    if lines.is_empty() {
        lines.push_str("不可得");
    }
    lines
}

fn write_value(out: &mut String, value: &Value, depth: usize) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let pad = "  ".repeat(depth);
                if child.is_object() {
                    out.push_str(&format!("{pad}[{key}]\n"));
                    write_value(out, child, depth + 1);
                } else {
                    out.push_str(&format!("{pad}{key} = {}\n", pretty_scalar(child)));
                }
            }
        }
        other => out.push_str(&pretty_scalar(other)),
    }
}

fn pretty_scalar(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "不可得".to_owned(),
        other => other.to_string(),
    }
}
