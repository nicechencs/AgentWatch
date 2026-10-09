//! Hook stdin → [`AgentToolCall`] for Claude Code.
//!
//! Field names follow SPIKE-07 §5.1 (document survey, 2026-10-07) and the
//! P5-AGENT-03 mapping table. Samples in `fixtures/agents/claude-code/` are
//! synthetic: the spike recorded no stdin.
//!
//! Kept summary keys: `command`, `path`, `url`, `query`. MCP tools are renamed
//! to `mcp:<server>/<tool>` and do not copy arguments. Unknown tools keep the
//! original name and an empty summary.

use aw_core::{AgentToolCall, ToolPhase};
use serde_json::{Map, Value};

/// Profile id. Matches `profiles/claude-code.toml`.
pub const AGENT_ID: &str = "claude-code";

/// `summary.command` cap, in Unicode scalars. Same bound as the shared parser.
const MAX_COMMAND_CHARS: usize = 256;

/// Paths, URLs, and queries. Tight enough that a document cannot hide here.
const MAX_FIELD_CHARS: usize = 512;

const MAX_ID_CHARS: usize = 128;
const MAX_TOOL_CHARS: usize = 128;
const MAX_SERVER_CHARS: usize = 64;

/// Result of mapping one hook payload.
#[derive(Debug, Clone, PartialEq)]
pub struct HookMap {
    /// Zero or one tool call. Session boundaries are not tool calls.
    pub calls: Vec<AgentToolCall>,
}

/// One call plus the source string. The source is not part of `AgentToolCall`.
#[derive(Debug, Clone, PartialEq)]
pub struct MappedCall {
    /// The call. `summary` has only allow-listed keys.
    pub call: AgentToolCall,
    /// Always [`super::HOOK_SOURCE`] for this module.
    pub source: &'static str,
}

/// Map one JSON value. Non-objects and non-tool events yield no calls.
#[must_use]
pub fn map_hook(payload: &Value) -> HookMap {
    let Some(obj) = payload.as_object() else {
        return HookMap { calls: Vec::new() };
    };
    let phase = match string_field(obj, "hook_event_name").as_deref() {
        Some("PreToolUse") => ToolPhase::Pre,
        Some("PostToolUse") => ToolPhase::Post,
        // PostToolUseFailure carries `error`, which may echo command output.
        // Session boundaries are handled by `map_session_boundary`.
        _ => return HookMap { calls: Vec::new() },
    };
    let Some(tool) = string_field(obj, "tool_name") else {
        return HookMap { calls: Vec::new() };
    };
    let tool = truncate_chars(&tool, MAX_TOOL_CHARS);
    if tool.is_empty() {
        return HookMap { calls: Vec::new() };
    }
    let input = obj.get("tool_input").and_then(Value::as_object);
    // SPIKE-07: `mcp_server` is a sibling of `tool_input` on PostToolUse
    // (documented from v2.1.274, not verified on a binary). Also accept it
    // inside `tool_input` so a flattened fixture still maps.
    let mcp_server = string_field(obj, "mcp_server")
        .or_else(|| input.and_then(|map| string_field(map, "mcp_server")));
    let (tool, summary) = project(&tool, input, mcp_server.as_deref());
    let call = AgentToolCall::new(
        AGENT_ID,
        id_field(obj, "session_id"),
        tool,
        phase,
        summary,
        id_field(obj, "tool_use_id"),
    );
    HookMap { calls: vec![call] }
}

/// Apply the task-card table.
///
/// `input` is `tool_input`. Keys not listed below are not read, including
/// `content`, `file_text`, `old_string`, `new_string`, and any prompt field.
fn project(
    tool: &str,
    input: Option<&Map<String, Value>>,
    mcp_server: Option<&str>,
) -> (String, Value) {
    match tool {
        "Bash" | "PowerShell" => {
            let command = input.and_then(|map| string_field(map, "command"));
            (
                tool.to_owned(),
                summary_field("command", command.as_deref()),
            )
        }
        "Read" | "Edit" | "Write" => {
            // Documented examples use `file_path`. `path` is accepted as the
            // same idea under the task card's `{path}` name. Neither is a
            // claim that both appear in a recorded sample.
            let path = input.and_then(|map| {
                string_field(map, "file_path").or_else(|| string_field(map, "path"))
            });
            (tool.to_owned(), summary_field("path", path.as_deref()))
        }
        "WebFetch" => {
            let url = input.and_then(|map| string_field(map, "url"));
            (tool.to_owned(), summary_field("url", url.as_deref()))
        }
        "WebSearch" => {
            let query = input.and_then(|map| {
                string_field(map, "query").or_else(|| string_field(map, "search_query"))
            });
            (tool.to_owned(), summary_field("query", query.as_deref()))
        }
        _ => mcp_or_unknown(tool, mcp_server),
    }
}

/// MCP tools become `mcp:<server>/<tool>`.
///
/// SPIKE-07: PostToolUse may carry `mcp_server` (documented from v2.1.274, not
/// verified here). A `mcp__<server>__<tool>` name is the other documented
/// shape (Gemini uses `mcp_<server>_<tool>`; Claude Code's double underscore
/// is the form this adapter recognises, 【待验证】 against a real payload).
/// Arguments are not copied.
fn mcp_or_unknown(tool: &str, mcp_server: Option<&str>) -> (String, Value) {
    if let Some((server, name)) = split_mcp_tool_name(tool) {
        let renamed = format!("mcp:{server}/{name}");
        return (truncate_chars(&renamed, MAX_TOOL_CHARS), empty_object());
    }
    if let Some(server) = mcp_server {
        let server = sanitize_token(server, MAX_SERVER_CHARS);
        if !server.is_empty() {
            let name = sanitize_token(tool, MAX_SERVER_CHARS);
            let renamed = format!("mcp:{server}/{name}");
            return (truncate_chars(&renamed, MAX_TOOL_CHARS), empty_object());
        }
    }
    // Unknown tool: keep the name, leave summary empty.
    (tool.to_owned(), empty_object())
}

/// `mcp__server__tool` or `mcp__server__tool__rest` → (`server`, `tool__rest`).
fn split_mcp_tool_name(tool: &str) -> Option<(String, String)> {
    let rest = tool.strip_prefix("mcp__")?;
    let (server, name) = rest.split_once("__")?;
    let server = sanitize_token(server, MAX_SERVER_CHARS);
    let name = sanitize_token(name, MAX_SERVER_CHARS);
    if server.is_empty() || name.is_empty() {
        return None;
    }
    Some((server, name))
}

/// One allow-listed string, truncated. Empty and missing become an empty object
/// rather than `""`.
pub(crate) fn summary_field(key: &str, value: Option<&str>) -> Value {
    let mut summary = Map::new();
    if let Some(value) = value {
        let value = match key {
            "command" => truncate_chars(value, MAX_COMMAND_CHARS),
            _ => truncate_chars(value, MAX_FIELD_CHARS),
        };
        if !value.is_empty() {
            summary.insert(key.to_owned(), Value::String(value));
        }
    }
    Value::Object(summary)
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}

pub(crate) fn id_field(obj: &Map<String, Value>, key: &str) -> Option<String> {
    let value = string_field(obj, key)?;
    let value = truncate_chars(&value, MAX_ID_CHARS);
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

pub(crate) fn string_field(obj: &Map<String, Value>, key: &str) -> Option<String> {
    match obj.get(key)? {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        _ => None,
    }
}

/// Drop characters that would make `mcp:<server>/<tool>` ambiguous.
fn sanitize_token(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index >= max_chars {
            break;
        }
        if ch == '/' || ch == ':' || ch.is_control() {
            continue;
        }
        out.push(ch);
    }
    out
}

pub(crate) fn truncate_chars(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index >= max_chars {
            break;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn one(payload: Value) -> AgentToolCall {
        let calls = map_hook(&payload).calls;
        assert_eq!(calls.len(), 1, "expected one call");
        calls.into_iter().next().expect("one")
    }

    #[test]
    fn bash_read_webfetch_follow_the_table() {
        let bash = one(json!({
            "hook_event_name": "PreToolUse",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_use_id": "tu-bash",
            "tool_input": {"command": "echo ok", "content": "do-not-keep"}
        }));
        assert_eq!(bash.tool, "Bash");
        assert_eq!(bash.phase, ToolPhase::Pre);
        assert_eq!(bash.call_id.as_deref(), Some("tu-bash"));
        assert_eq!(bash.summary, json!({"command": "echo ok"}));

        let read = one(json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_use_id": "tu-read",
            "tool_input": {"file_path": "src/lib.rs", "content": "file-body"}
        }));
        assert_eq!(read.phase, ToolPhase::Post);
        assert_eq!(read.summary, json!({"path": "src/lib.rs"}));

        let fetch = one(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "WebFetch",
            "tool_use_id": "tu-web",
            "tool_input": {"url": "https://example.test/a", "prompt": "user prompt text"}
        }));
        assert_eq!(fetch.summary, json!({"url": "https://example.test/a"}));
        let rendered = serde_json::to_string(&fetch.summary).expect("summary");
        assert!(!rendered.contains("prompt"));
    }

    #[test]
    fn websearch_edit_write_and_unknown() {
        let search = one(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "WebSearch",
            "tool_use_id": "tu-s",
            "tool_input": {"query": "rust truncate"}
        }));
        assert_eq!(search.summary, json!({"query": "rust truncate"}));

        let edit = one(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_use_id": "tu-e",
            "tool_input": {"path": "README.md", "old_string": "secret-old", "new_string": "secret-new"}
        }));
        assert_eq!(edit.summary, json!({"path": "README.md"}));
        let rendered = serde_json::to_string(&edit.summary).expect("summary");
        assert!(!rendered.contains("secret-old"));
        assert!(!rendered.contains("secret-new"));

        let write = one(json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Write",
            "tool_use_id": "tu-w",
            "tool_input": {"file_path": "notes.txt", "content": "whole file"}
        }));
        assert_eq!(write.summary, json!({"path": "notes.txt"}));

        let unknown = one(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "NotebookEdit",
            "tool_use_id": "tu-u",
            "tool_input": {"notebook_path": "a.ipynb", "new_source": "cells"}
        }));
        assert_eq!(unknown.tool, "NotebookEdit");
        assert_eq!(unknown.summary, json!({}));
    }

    #[test]
    fn mcp_renames_and_drops_arguments() {
        let from_name = one(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__docs__search",
            "tool_use_id": "tu-m",
            "tool_input": {"query": "should-not-copy", "arguments": {"q": "x"}}
        }));
        assert_eq!(from_name.tool, "mcp:docs/search");
        assert_eq!(from_name.summary, json!({}));

        let from_field = one(json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "search",
            "tool_use_id": "tu-m2",
            "mcp_server": "docs",
            "tool_input": {"query": "also-dropped"},
            "tool_response": {"text": "model output"}
        }));
        assert_eq!(from_field.tool, "mcp:docs/search");
        assert_eq!(from_field.phase, ToolPhase::Post);
        assert_eq!(from_field.summary, json!({}));
    }

    #[test]
    fn missing_tool_name_is_empty() {
        assert!(map_hook(&json!({"hook_event_name": "PreToolUse"}))
            .calls
            .is_empty());
        assert!(map_hook(&json!({"hook_event_name": "Notification"}))
            .calls
            .is_empty());
        assert!(map_hook(&Value::Null).calls.is_empty());
    }
}
