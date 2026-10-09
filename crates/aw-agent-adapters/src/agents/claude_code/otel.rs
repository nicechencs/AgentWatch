//! Claude Code OpenTelemetry mapping (P5-AGENT-04).
//!
//! SPIKE-07 §5.1 (document survey, 2026-10-07) names the variables and the
//! `claude_code.tool_result` attributes. This module has not confirmed them
//! against a running `claude` binary. Fixtures under
//! `fixtures/agents/claude-code/otel/` are synthetic.
//!
//! Prompt fields are dropped before a summary is built. If the user already
//! points `OTEL_EXPORTER_OTLP_ENDPOINT` somewhere, injection does not replace
//! it. When hooks and OTEL both report the same `call_id`, the hook call is
//! kept and the OTEL call is dropped.

use std::collections::BTreeMap;

use aw_core::{AgentToolCall, ToolPhase};
use serde_json::{Map, Value};

use super::map::{self, truncate_chars, AGENT_ID};

/// Source string for an E3 call taken from OTEL.
pub const AGENT_SOURCE_OTEL: &str = "agent.claude-code/otel";

/// Env var that turns Claude Code telemetry on. Name is from the survey.
const ENABLE_TELEMETRY: &str = "CLAUDE_CODE_ENABLE_TELEMETRY";

/// Exporter selection. Name is from the survey.
const LOGS_EXPORTER: &str = "OTEL_LOGS_EXPORTER";

/// Endpoint. Name is from the survey. A value already in the environment wins.
const OTLP_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// Attribute / body keys that carry prompt text. Dropped, not truncated.
const PROMPT_KEYS: &[&str] = &[
    "prompt",
    "user_prompt",
    "user_prompts",
    "system_prompt",
    "messages",
    "message",
    "content",
    "completion",
    "model_output",
    "tool_output",
    "tool_response",
    "output",
];

/// What to put in the child environment.
///
/// 【待验证】Variable names come from SPIKE-07's document survey, not from a
/// local `claude` run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtelEnvPlan {
    /// When false, `assignments` is empty and `notice` explains why.
    pub inject: bool,
    /// Name/value pairs to set. Empty when the user's endpoint is kept.
    pub assignments: BTreeMap<String, String>,
    /// Short reason. No endpoint URL is copied into this string.
    pub notice: String,
}

/// Decide which telemetry variables to set for this launch.
///
/// `env_has` reports whether the child would already see that variable name.
/// Values are not read. A set `OTEL_EXPORTER_OTLP_ENDPOINT` means the user
/// already has an exporter; this function then injects nothing.
///
/// `local_endpoint` is the session's loopback OTLP base URL. It is not used
/// when injection is skipped, so a caller's URL is not written into a notice.
#[must_use]
pub fn otel_env(env_has: impl Fn(&str) -> bool, local_endpoint: &str) -> OtelEnvPlan {
    if env_has(OTLP_ENDPOINT) {
        return OtelEnvPlan {
            inject: false,
            assignments: BTreeMap::new(),
            notice: "user already set an OTLP endpoint; not attaching".to_owned(),
        };
    }
    let mut assignments = BTreeMap::new();
    assignments.insert(ENABLE_TELEMETRY.to_owned(), "1".to_owned());
    assignments.insert(LOGS_EXPORTER.to_owned(), "otlp".to_owned());
    assignments.insert(OTLP_ENDPOINT.to_owned(), local_endpoint.to_owned());
    // Do not set OTEL_LOG_USER_PROMPTS or OTEL_LOG_TOOL_CONTENT. Those switches
    // ask Claude Code to export prompt and tool bodies. This adapter would
    // drop them, but it should not request them.
    OtelEnvPlan {
        inject: true,
        assignments,
        notice: "telemetry env prepared for this launch; variable names are unverified 【待验证】"
            .to_owned(),
    }
}

/// True when the user already named an OTLP endpoint.
///
/// Same rule as [`otel_env`]: the name's presence is enough. The value is not
/// compared, so a placeholder and a real URL are treated the same.
#[must_use]
pub fn user_otlp_already_set(env_has: impl Fn(&str) -> bool) -> bool {
    env_has(OTLP_ENDPOINT)
}

/// One OTEL log record after mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct OtelMap {
    /// Tool calls only. Metrics are not timeline events.
    pub calls: Vec<AgentToolCall>,
    /// Token or cost figures, if present. Not tool calls.
    pub session_metrics: SessionMetrics,
}

/// Session-level figures from a metrics payload.
///
/// Absent keys stay `None`. Zero is not used as a stand-in for "unknown".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionMetrics {
    /// Input tokens, when a metric named them.
    pub input_tokens: Option<u64>,
    /// Output tokens, when a metric named them.
    pub output_tokens: Option<u64>,
    /// Cost in the exporter's minor units, when a metric named it.
    ///
    /// The unit is not converted: the survey does not fix a currency scale.
    pub cost_units: Option<u64>,
}

/// Map an OTLP/HTTP JSON logs body (`resourceLogs` / `resource_logs`).
///
/// Prompt attributes are removed before any summary is built. A record that
/// is not `claude_code.tool_result` does not become a tool call. Metrics
/// payloads are accepted by [`map_otlp_metrics`] instead.
#[must_use]
pub fn map_otlp_logs(payload: &Value) -> OtelMap {
    let mut calls = Vec::new();
    for record in log_records(payload) {
        if let Some(call) = map_tool_result(&record) {
            calls.push(call);
        }
    }
    OtelMap {
        calls,
        session_metrics: SessionMetrics::default(),
    }
}

/// Map an OTLP JSON metrics body into session figures.
///
/// Nothing here is a timeline event. Unknown metric names are ignored.
#[must_use]
pub fn map_otlp_metrics(payload: &Value) -> SessionMetrics {
    let mut metrics = SessionMetrics::default();
    for (name, value) in metric_points(payload) {
        let slot = match name.as_str() {
            "input_tokens" | "claude_code.input_tokens" | "gen_ai.usage.input_tokens" => {
                Some(&mut metrics.input_tokens)
            }
            "output_tokens" | "claude_code.output_tokens" | "gen_ai.usage.output_tokens" => {
                Some(&mut metrics.output_tokens)
            }
            "cost" | "claude_code.cost" => Some(&mut metrics.cost_units),
            _ => None,
        };
        if let Some(slot) = slot {
            if slot.is_none() {
                *slot = Some(value);
            }
        }
    }
    metrics
}

/// Drop OTEL calls whose `call_id` is already present on a hook call.
///
/// Hook calls are returned unchanged, in their original order, then OTEL calls
/// that did not collide. An OTEL call with no `call_id` is kept: there is
/// nothing to match it against. Matching is exact string equality.
#[must_use]
pub fn dedupe_with_hooks(hooks: &[AgentToolCall], otel: &[AgentToolCall]) -> Vec<AgentToolCall> {
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    for call in hooks {
        if let Some(id) = call.call_id.as_deref() {
            seen.insert(id.to_owned(), ());
        }
    }
    let mut out = Vec::with_capacity(hooks.len() + otel.len());
    out.extend(hooks.iter().cloned());
    for call in otel {
        match call.call_id.as_deref() {
            Some(id) if seen.contains_key(id) => {}
            Some(id) => {
                seen.insert(id.to_owned(), ());
                out.push(call.clone());
            }
            None => out.push(call.clone()),
        }
    }
    out
}

fn map_tool_result(record: &Value) -> Option<AgentToolCall> {
    let obj = record.as_object()?;
    let attrs = attributes_of(obj);
    // Drop prompt-shaped keys first, then read what remains.
    let attrs = drop_prompt_keys(attrs);
    let event_name = record_event_name(obj, &attrs);
    // Only the post-tool log is a tool call. `tool_decision` is a permission
    // decision; SPIKE-07 says not to treat it as a second execution.
    if event_name.as_deref() != Some("claude_code.tool_result") {
        return None;
    }
    let tool = attr_string(&attrs, &["tool_name"])?;
    let tool = truncate_chars(&tool, 128);
    if tool.is_empty() {
        return None;
    }
    let (tool, summary) = project_otel(&tool, &attrs);
    let session =
        attr_string(&attrs, &["session.id", "session_id"]).or_else(|| resource_session(obj));
    let call_id = attr_string(&attrs, &["tool_use_id"]);
    Some(AgentToolCall::new(
        AGENT_ID,
        session,
        tool,
        ToolPhase::Post,
        summary,
        call_id,
    ))
}

/// OTEL tool parameters, when present, use the names in the survey.
///
/// `tool_parameters` may be a JSON string. `tool_input` may be a string or an
/// object. Bodies inside those values are not copied: only the task-card keys.
fn project_otel(tool: &str, attrs: &Map<String, Value>) -> (String, Value) {
    let params = merged_params(attrs);
    if tool.starts_with("mcp:") || tool.starts_with("mcp__") {
        let renamed = if let Some((server, name)) = split_simple_mcp(tool) {
            format!("mcp:{server}/{name}")
        } else {
            tool.to_owned()
        };
        return (renamed, Value::Object(Map::new()));
    }
    match tool {
        "Bash" | "PowerShell" => {
            let command = params
                .as_ref()
                .and_then(|map| map::string_field(map, "command"))
                .or_else(|| map::string_field(attrs, "bash_command"))
                .or_else(|| map::string_field(attrs, "full_command"))
                .or_else(|| {
                    params
                        .as_ref()
                        .and_then(|map| map::string_field(map, "bash_command"))
                })
                .or_else(|| {
                    params
                        .as_ref()
                        .and_then(|map| map::string_field(map, "full_command"))
                });
            (
                tool.to_owned(),
                map::summary_field("command", command.as_deref()),
            )
        }
        "Read" | "Edit" | "Write" => {
            let path = params.as_ref().and_then(|map| {
                map::string_field(map, "file_path").or_else(|| map::string_field(map, "path"))
            });
            (tool.to_owned(), map::summary_field("path", path.as_deref()))
        }
        "WebFetch" => {
            let url = params
                .as_ref()
                .and_then(|map| map::string_field(map, "url"));
            (tool.to_owned(), map::summary_field("url", url.as_deref()))
        }
        "WebSearch" => {
            let query = params.as_ref().and_then(|map| {
                map::string_field(map, "query").or_else(|| map::string_field(map, "search_query"))
            });
            (
                tool.to_owned(),
                map::summary_field("query", query.as_deref()),
            )
        }
        _ => (tool.to_owned(), Value::Object(Map::new())),
    }
}

fn split_simple_mcp(tool: &str) -> Option<(&str, &str)> {
    let rest = tool.strip_prefix("mcp__")?;
    rest.split_once("__")
}

fn merged_params(attrs: &Map<String, Value>) -> Option<Map<String, Value>> {
    let mut merged = Map::new();
    for key in ["tool_parameters", "tool_input"] {
        let Some(value) = attrs.get(key) else {
            continue;
        };
        let parsed = match value {
            Value::Object(map) => Some(map.clone()),
            Value::String(text) => serde_json::from_str::<Value>(text)
                .ok()
                .and_then(|value| value.as_object().cloned()),
            _ => None,
        };
        if let Some(map) = parsed {
            for (name, item) in map {
                if is_prompt_key(&name) {
                    continue;
                }
                merged.entry(name).or_insert(item);
            }
        }
    }
    if merged.is_empty() {
        None
    } else {
        Some(merged)
    }
}

fn drop_prompt_keys(mut attrs: Map<String, Value>) -> Map<String, Value> {
    attrs.retain(|key, _| !is_prompt_key(key));
    attrs
}

fn is_prompt_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    PROMPT_KEYS.iter().any(|name| lower == *name)
        || lower.contains("prompt")
        || lower.contains("user_message")
}

fn record_event_name(obj: &Map<String, Value>, attrs: &Map<String, Value>) -> Option<String> {
    map::string_field(obj, "eventName")
        .or_else(|| map::string_field(obj, "event_name"))
        .or_else(|| attr_string(attrs, &["event.name", "event_name"]))
}

fn attr_string(attrs: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = map::string_field(attrs, key) {
            return Some(value);
        }
    }
    None
}

fn attributes_of(record: &Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    if let Some(list) = record.get("attributes").and_then(Value::as_array) {
        extend_kv_list(&mut out, list);
    }
    if let Some(body) = record.get("body") {
        match body {
            Value::Object(map) => {
                for (key, value) in map {
                    if !is_prompt_key(key) {
                        out.entry(key.clone()).or_insert(value.clone());
                    }
                }
            }
            Value::String(text) => {
                if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text) {
                    for (key, value) in map {
                        if !is_prompt_key(&key) {
                            out.entry(key).or_insert(value);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn resource_session(record: &Map<String, Value>) -> Option<String> {
    // A flattened fixture may put the resource attribute next to the record.
    map::string_field(record, "session.id")
}

fn extend_kv_list(out: &mut Map<String, Value>, list: &[Value]) {
    for item in list {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let Some(key) = map::string_field(obj, "key") else {
            continue;
        };
        if is_prompt_key(&key) {
            continue;
        }
        let Some(value) = obj.get("value") else {
            continue;
        };
        if let Some(text) = otlp_any_string(value) {
            out.insert(key, Value::String(text));
        }
    }
}

/// OTLP AnyValue JSON: `{ "stringValue": "..." }` or `{ "string_value": "..." }`.
fn otlp_any_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Object(map) => {
            for key in ["stringValue", "string_value"] {
                if let Some(text) = map::string_field(map, key) {
                    return Some(text);
                }
            }
            None
        }
        _ => None,
    }
}

fn log_records(payload: &Value) -> Vec<Value> {
    let mut found = Vec::new();
    let Some(root) = payload.as_object() else {
        return found;
    };
    // A single record, already unwrapped. Used by small fixtures.
    let looks_like_record = root.contains_key("attributes")
        || root.contains_key("body")
        || root.contains_key("eventName");
    let is_export = root.contains_key("resourceLogs") || root.contains_key("resource_logs");
    if looks_like_record && !is_export {
        found.push(payload.clone());
        return found;
    }
    let resources = root
        .get("resourceLogs")
        .or_else(|| root.get("resource_logs"))
        .and_then(Value::as_array);
    let Some(resources) = resources else {
        return found;
    };
    for resource in resources {
        let Some(resource) = resource.as_object() else {
            continue;
        };
        let session = resource_attr_session(resource);
        let scopes = resource
            .get("scopeLogs")
            .or_else(|| resource.get("scope_logs"))
            .and_then(Value::as_array);
        let Some(scopes) = scopes else {
            continue;
        };
        for scope in scopes {
            let Some(records) = scope
                .get("logRecords")
                .or_else(|| scope.get("log_records"))
                .and_then(Value::as_array)
            else {
                continue;
            };
            for record in records {
                let mut record = record.clone();
                if let (Some(session), Some(obj)) = (session.as_ref(), record.as_object_mut()) {
                    obj.entry("session.id".to_owned())
                        .or_insert_with(|| Value::String(session.clone()));
                }
                found.push(record);
            }
        }
    }
    found
}

fn resource_attr_session(resource: &Map<String, Value>) -> Option<String> {
    let attrs = resource.get("resource")?.get("attributes")?.as_array()?;
    let mut map = Map::new();
    extend_kv_list(&mut map, attrs);
    map::string_field(&map, "session.id")
}

fn metric_points(payload: &Value) -> Vec<(String, u64)> {
    let mut points = Vec::new();
    let Some(root) = payload.as_object() else {
        return points;
    };
    let resources = root
        .get("resourceMetrics")
        .or_else(|| root.get("resource_metrics"))
        .and_then(Value::as_array);
    let Some(resources) = resources else {
        return points;
    };
    for resource in resources {
        let Some(scopes) = resource
            .get("scopeMetrics")
            .or_else(|| resource.get("scope_metrics"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for scope in scopes {
            let Some(metrics) = scope.get("metrics").and_then(Value::as_array) else {
                continue;
            };
            for metric in metrics {
                let Some(name) = metric.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if let Some(value) = first_number(metric) {
                    points.push((name.to_owned(), value));
                }
            }
        }
    }
    points
}

fn first_number(metric: &Value) -> Option<u64> {
    let sum = metric.get("sum").or_else(|| metric.get("gauge"))?;
    let points = sum.get("dataPoints").or_else(|| sum.get("data_points"))?;
    let point = points.as_array()?.first()?;
    point
        .get("asInt")
        .or_else(|| point.get("as_int"))
        .and_then(Value::as_u64)
        .or_else(|| {
            point
                .get("asInt")
                .or_else(|| point.get("as_int"))
                .and_then(Value::as_str)
                .and_then(|text| text.parse().ok())
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env_with<'a>(keys: &'a [&'a str]) -> impl Fn(&str) -> bool + 'a {
        move |name| keys.contains(&name)
    }

    #[test]
    fn injection_sets_endpoint_when_user_has_none() {
        let plan = otel_env(env_with(&[]), "http://127.0.0.1:9");
        assert!(plan.inject);
        assert_eq!(
            plan.assignments.get(ENABLE_TELEMETRY).map(String::as_str),
            Some("1")
        );
        assert_eq!(
            plan.assignments.get(LOGS_EXPORTER).map(String::as_str),
            Some("otlp")
        );
        assert_eq!(
            plan.assignments.get(OTLP_ENDPOINT).map(String::as_str),
            Some("http://127.0.0.1:9")
        );
        assert!(!plan.assignments.contains_key("OTEL_LOG_USER_PROMPTS"));
        assert!(plan.notice.contains("待验证"));
    }

    #[test]
    fn user_endpoint_is_not_overwritten() {
        let plan = otel_env(env_with(&[OTLP_ENDPOINT]), "http://127.0.0.1:9");
        assert!(!plan.inject);
        assert!(plan.assignments.is_empty());
        assert!(user_otlp_already_set(env_with(&[OTLP_ENDPOINT])));
        assert!(!plan.notice.contains("127.0.0.1"));
        assert!(plan.notice.contains("not attaching"));
    }

    #[test]
    fn prompt_attribute_is_dropped() {
        let payload = json!({
            "resourceLogs": [{
                "resource": {
                    "attributes": [
                        {"key": "session.id", "value": {"stringValue": "sess-otel"}}
                    ]
                },
                "scopeLogs": [{
                    "logRecords": [{
                        "eventName": "claude_code.tool_result",
                        "attributes": [
                            {"key": "tool_name", "value": {"stringValue": "Bash"}},
                            {"key": "tool_use_id", "value": {"stringValue": "tu-otel"}},
                            {"key": "prompt", "value": {"stringValue": "SECRET_PROMPT_TEXT"}},
                            {"key": "user_prompt", "value": {"stringValue": "ALSO_SECRET"}},
                            {"key": "tool_parameters", "value": {"stringValue": "{\"command\":\"echo ok\",\"content\":\"file-body\"}"}}
                        ]
                    }]
                }]
            }]
        });
        let mapped = map_otlp_logs(&payload);
        assert_eq!(mapped.calls.len(), 1);
        let call = &mapped.calls[0];
        assert_eq!(call.phase, ToolPhase::Post);
        assert_eq!(call.call_id.as_deref(), Some("tu-otel"));
        assert_eq!(call.agent_session.as_deref(), Some("sess-otel"));
        assert_eq!(call.summary, json!({"command": "echo ok"}));
        let rendered = serde_json::to_string(call).expect("call");
        assert!(!rendered.contains("SECRET_PROMPT_TEXT"), "{rendered}");
        assert!(!rendered.contains("ALSO_SECRET"), "{rendered}");
        assert!(!rendered.contains("file-body"), "{rendered}");
    }

    #[test]
    fn hooks_win_on_the_same_call_id() {
        let hook = AgentToolCall::new(
            AGENT_ID,
            Some("s".to_owned()),
            "Bash",
            ToolPhase::Pre,
            json!({"command": "from-hook"}),
            Some("same-id".to_owned()),
        );
        let otel = AgentToolCall::new(
            AGENT_ID,
            Some("s".to_owned()),
            "Bash",
            ToolPhase::Post,
            json!({"command": "from-otel"}),
            Some("same-id".to_owned()),
        );
        let other = AgentToolCall::new(
            AGENT_ID,
            Some("s".to_owned()),
            "Read",
            ToolPhase::Post,
            json!({"path": "a.rs"}),
            Some("only-otel".to_owned()),
        );
        let merged = dedupe_with_hooks(std::slice::from_ref(&hook), &[otel, other.clone()]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0], hook);
        assert_eq!(merged[1], other);
        let rendered = serde_json::to_string(&merged).expect("merged");
        assert!(!rendered.contains("from-otel"), "{rendered}");
    }

    #[test]
    fn claude_code_otel_replays_fixtures_and_drops_prompts() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/agents/claude-code");
        let load = |name: &str| -> Value {
            let path = dir.join(name);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
            serde_json::from_str(&text)
                .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
        };

        let bash = map_otlp_logs(&load("otel/tool-result-bash.json"));
        assert_eq!(bash.calls.len(), 1);
        let call = &bash.calls[0];
        assert_eq!(call.tool, "Bash");
        assert_eq!(call.phase, ToolPhase::Post);
        assert_eq!(call.call_id.as_deref(), Some("tu-otel-bash"));
        assert_eq!(call.agent_session.as_deref(), Some("sess-synthetic-otel"));
        assert_eq!(call.summary, json!({"command": "echo ok"}));
        let rendered = serde_json::to_string(call).expect("call");
        assert!(!rendered.contains("PROMPT_MUST_BE_DROPPED"), "{rendered}");
        assert!(
            !rendered.contains("USER_PROMPT_MUST_BE_DROPPED"),
            "{rendered}"
        );
        assert!(!rendered.contains("body-must-be-dropped"), "{rendered}");

        let read = map_otlp_logs(&load("otel/tool-result-read.json"));
        assert_eq!(read.calls.len(), 1);
        assert_eq!(read.calls[0].summary, json!({"path": "src/lib.rs"}));
        let rendered = serde_json::to_string(&read.calls[0]).expect("call");
        assert!(
            !rendered.contains("file-body-must-be-dropped"),
            "{rendered}"
        );

        let metrics = map_otlp_metrics(&load("otel/metrics.json"));
        assert_eq!(metrics.input_tokens, Some(12));
        assert_eq!(metrics.output_tokens, Some(3));
        assert_eq!(metrics.cost_units, Some(1));
        assert!(map_otlp_logs(&load("otel/metrics.json")).calls.is_empty());
    }

    #[test]
    fn claude_code_hooks_and_otel_do_not_duplicate() {
        let hook_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/agents/claude-code/bash-pre.json");
        let hook_body: Value =
            serde_json::from_str(&std::fs::read_to_string(&hook_path).expect("hook fixture"))
                .expect("hook json");
        let hook = &crate::agents::claude_code::parse_claude_hook(&hook_body)[0];

        let otel_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/agents/claude-code/otel/tool-result-bash.json");
        let mut otel_body: Value =
            serde_json::from_str(&std::fs::read_to_string(&otel_path).expect("otel fixture"))
                .expect("otel json");
        let records = otel_body
            .pointer_mut("/resourceLogs/0/scopeLogs/0/logRecords/0/attributes")
            .and_then(Value::as_array_mut)
            .expect("attributes");
        for item in records.iter_mut() {
            if item.get("key").and_then(Value::as_str) == Some("tool_use_id") {
                item["value"]["stringValue"] = Value::String("tu-bash-1".to_owned());
            }
        }
        let otel = map_otlp_logs(&otel_body);
        let merged = dedupe_with_hooks(std::slice::from_ref(hook), &otel.calls);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].call_id.as_deref(), Some("tu-bash-1"));
        assert_eq!(merged[0].phase, ToolPhase::Pre);
        assert_eq!(merged[0].summary, json!({"command": "echo ok"}));
    }

    #[test]
    fn metrics_stay_off_the_timeline() {
        let logs = map_otlp_logs(&json!({
            "resourceLogs": [{
                "scopeLogs": [{
                    "logRecords": [{
                        "body": {"event.name": "claude_code.tool_decision", "tool_name": "Bash"}
                    }]
                }]
            }]
        }));
        assert!(logs.calls.is_empty());

        let metrics = map_otlp_metrics(&json!({
            "resourceMetrics": [{
                "scopeMetrics": [{
                    "metrics": [
                        {"name": "claude_code.input_tokens", "sum": {"dataPoints": [{"asInt": "12"}]}},
                        {"name": "claude_code.output_tokens", "sum": {"dataPoints": [{"asInt": "3"}]}},
                        {"name": "claude_code.cost", "gauge": {"dataPoints": [{"asInt": "1"}]}}
                    ]
                }]
            }]
        }));
        assert_eq!(metrics.input_tokens, Some(12));
        assert_eq!(metrics.output_tokens, Some(3));
        assert_eq!(metrics.cost_units, Some(1));
    }
}
