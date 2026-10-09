//! Built-in [`HookParser`]s for `claude-code`, `codex`, and `cursor`.
//!
//! Each parser reads one JSON object and returns at most one [`AgentToolCall`].
//! A payload that is not an object, or that is not a documented tool event,
//! returns an empty `Vec`. That is "nothing to record", not an error: the
//! registry contract is that [`parse_hook`](super::parse_hook) never fails.
//!
//! Output is self-reported. Nothing here sets an evidence level, and nothing
//! here upgrades a field. A missing key stays absent (`None`, or a summary
//! object that simply omits it). Empty strings are treated as missing.
//!
//! Only keys named in SPIKE-07 (2026-10-07 document survey) are read. Unverified
//! shapes are not guessed. `tool_response`, `output`, `error`, prompt text, and
//! file contents are never copied into the call. `Debug` for [`AgentToolCall`]
//! already redacts `summary`; these parsers do not log the payload.

use serde_json::{Map, Value};

use aw_core::{AgentToolCall, ToolPhase};

use super::HookParser;

/// Longest command text kept in `summary.command`, in Unicode scalar values.
///
/// The summary gate in [`super::bound_tool_call`] allows 512. This is tighter
/// on purpose: a hook command is a structured field, not a transcript.
const MAX_COMMAND_CHARS: usize = 256;

/// `session_id` and `tool_use_id` are identifiers, not documents.
const MAX_ID_CHARS: usize = 128;

/// Tool names are short labels (`Bash`, `apply_patch`, `mcp_<server>_<tool>`).
const MAX_TOOL_CHARS: usize = 128;

/// Register the three built-in parsers.
///
/// A later [`super::register_hook`] for the same agent id replaces the built-in,
/// so a test or a user adapter can override one. Calling this more than once
/// is safe: registration replaces by id.
pub fn install_builtin_parsers() {
    super::register_hook(Box::new(ClaudeCodeParser));
    super::register_hook(Box::new(CodexParser));
    super::register_hook(Box::new(CursorParser));
}

struct ClaudeCodeParser;

impl HookParser for ClaudeCodeParser {
    fn agent_id(&self) -> &str {
        "claude-code"
    }

    fn parse_hook(&self, payload: &Value) -> Vec<AgentToolCall> {
        let Some(obj) = payload.as_object() else {
            return Vec::new();
        };
        // SPIKE-07 §5.1: only PreToolUse and PostToolUse carry a tool call.
        // PostToolUseFailure is a failure, not a second execution to record
        // here: its `error` string can contain command output, and the spike
        // says not to store that string.
        let phase = match string_field(obj, "hook_event_name").as_deref() {
            Some("PreToolUse") => ToolPhase::Pre,
            Some("PostToolUse") => ToolPhase::Post,
            _ => return Vec::new(),
        };
        claude_like(self.agent_id(), obj, phase)
    }
}

struct CodexParser;

impl HookParser for CodexParser {
    fn agent_id(&self) -> &str {
        "codex"
    }

    fn parse_hook(&self, payload: &Value) -> Vec<AgentToolCall> {
        let Some(obj) = payload.as_object() else {
            return Vec::new();
        };
        // SPIKE-07 §5.2: Codex hook events use the same names as Claude Code.
        // `notify` (`agent-turn-complete`) is not a tool call and is ignored.
        let phase = match string_field(obj, "hook_event_name").as_deref() {
            Some("PreToolUse") => ToolPhase::Pre,
            Some("PostToolUse") => ToolPhase::Post,
            _ => return Vec::new(),
        };
        claude_like(self.agent_id(), obj, phase)
    }
}

struct CursorParser;

impl HookParser for CursorParser {
    fn agent_id(&self) -> &str {
        "cursor"
    }

    fn parse_hook(&self, payload: &Value) -> Vec<AgentToolCall> {
        let Some(obj) = payload.as_object() else {
            return Vec::new();
        };
        // SPIKE-07 §5.3 names these tool events. camelCase is what the page
        // uses. PascalCase is accepted only as the same documented name with
        // different capitalization, not as a new schema.
        let event = string_field(obj, "hook_event_name");
        let phase = match event.as_deref().map(cursor_event_phase) {
            Some(Some(phase)) => phase,
            _ => return Vec::new(),
        };
        if is_shell_event(event.as_deref()) {
            cursor_shell(obj, phase)
        } else {
            cursor_tool(obj, phase)
        }
    }
}

/// Claude Code and Codex share the documented keys: `tool_name`, `tool_input`,
/// `tool_use_id`, `session_id`.
fn claude_like(agent: &str, obj: &Map<String, Value>, phase: ToolPhase) -> Vec<AgentToolCall> {
    let Some(tool) = string_field(obj, "tool_name") else {
        // SPIKE-07: a missing tool name means do not invent a tool call.
        return Vec::new();
    };
    let input = obj.get("tool_input").and_then(Value::as_object);
    // Both products document the shell command at `tool_input.command`.
    // Claude Code's Bash example and Codex's Bash / shell match both use it.
    // Other tools (apply_patch, file tools) have no verified command key here,
    // so the summary stays empty rather than guessing `path` or `url`.
    let command = input.and_then(|map| string_field(map, "command"));
    one_call(agent, obj, &tool, phase, command.as_deref())
}

fn cursor_tool(obj: &Map<String, Value>, phase: ToolPhase) -> Vec<AgentToolCall> {
    // Documented key is `tool_name` (`preToolUse` example). `toolName` is the
    // same field in camelCase, accepted because the task allows that alias.
    // `arguments` is the same allowance for `tool_input`. Neither alias is a
    // claim that Cursor's page uses it.
    let tool = string_field(obj, "tool_name").or_else(|| string_field(obj, "toolName"));
    let Some(tool) = tool else {
        return Vec::new();
    };
    let input = obj
        .get("tool_input")
        .or_else(|| obj.get("arguments"))
        .and_then(Value::as_object);
    let command = input.and_then(|map| string_field(map, "command"));
    one_call("cursor", obj, &tool, phase, command.as_deref())
}

fn cursor_shell(obj: &Map<String, Value>, phase: ToolPhase) -> Vec<AgentToolCall> {
    // `beforeShellExecution` / `afterShellExecution` put `command` on the
    // object itself, not under `tool_input`. The spike's mapping uses
    // tool = "Shell" when the event does not carry its own tool_name.
    // `output` and `duration` are intentionally not read.
    let tool = string_field(obj, "tool_name")
        .or_else(|| string_field(obj, "toolName"))
        .unwrap_or_else(|| "Shell".to_owned());
    let command = string_field(obj, "command");
    one_call("cursor", obj, &tool, phase, command.as_deref())
}

fn one_call(
    agent: &str,
    obj: &Map<String, Value>,
    tool: &str,
    phase: ToolPhase,
    command: Option<&str>,
) -> Vec<AgentToolCall> {
    let tool = truncate_chars(tool, MAX_TOOL_CHARS);
    if tool.is_empty() {
        return Vec::new();
    }
    let session = non_empty_id(obj, &["session_id"]);
    // `tool_use_id` is documented for Claude Code, Codex, and Cursor
    // `preToolUse`. Cursor shell events have none; the key is simply absent.
    let call_id = non_empty_id(obj, &["tool_use_id"]);
    let summary = command_summary(command);
    vec![AgentToolCall::new(
        agent, session, tool, phase, summary, call_id,
    )]
}

/// `summary` keeps `command` only, truncated. No other `tool_input` key is
/// copied: file contents, prompts, and URLs are not verified as safe to keep
/// from these payloads, and the summary allow-list is enforced again later.
fn command_summary(command: Option<&str>) -> Value {
    let mut summary = Map::new();
    if let Some(command) = command {
        let command = truncate_chars(command, MAX_COMMAND_CHARS);
        if !command.is_empty() {
            summary.insert("command".to_owned(), Value::String(command));
        }
    }
    Value::Object(summary)
}

fn non_empty_id(obj: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = string_field(obj, key) {
            let value = truncate_chars(&value, MAX_ID_CHARS);
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// A string field. JSON null, a non-string, or `""` are all "not present".
fn string_field(obj: &Map<String, Value>, key: &str) -> Option<String> {
    match obj.get(key)? {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        _ => None,
    }
}

fn cursor_event_phase(name: &str) -> Option<ToolPhase> {
    match name {
        "preToolUse" | "PreToolUse" => Some(ToolPhase::Pre),
        "postToolUse" | "PostToolUse" => Some(ToolPhase::Post),
        "beforeShellExecution" | "BeforeShellExecution" => Some(ToolPhase::Pre),
        "afterShellExecution" | "AfterShellExecution" => Some(ToolPhase::Post),
        "beforeMCPExecution" | "BeforeMCPExecution" => Some(ToolPhase::Pre),
        "afterMCPExecution" | "AfterMCPExecution" => Some(ToolPhase::Post),
        // Documented, but not a tool-call record we can fill without storing
        // file contents (`afterFileEdit`) or reading a file body (`beforeReadFile`).
        _ => None,
    }
}

fn is_shell_event(name: Option<&str>) -> bool {
    matches!(
        name,
        Some(
            "beforeShellExecution"
                | "BeforeShellExecution"
                | "afterShellExecution"
                | "AfterShellExecution"
        )
    )
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
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
    use crate::parse_hook;

    fn payload(json: &str) -> Value {
        serde_json::from_str(json).expect("payload")
    }

    #[test]
    fn claude_bash_keeps_command_and_drops_response() {
        let calls = parse_hook(
            "claude-code",
            &payload(
                r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_use_id":"tu-1","session_id":"s-1","tool_input":{"command":"echo hi","content":"secret-body"},"tool_response":{"output":"secret-output"}}"#,
            ),
        );
        assert_eq!(calls.len(), 1);
        let call = &calls[0];
        assert_eq!(call.tool, "Bash");
        assert_eq!(
            call.summary.get("command").and_then(Value::as_str),
            Some("echo hi")
        );
        let rendered = serde_json::to_string(&call.summary).expect("summary");
        assert!(!rendered.contains("secret-body"), "{rendered}");
        assert!(!rendered.contains("secret-output"), "{rendered}");
    }

    #[test]
    fn missing_tool_name_and_unknown_agent_are_empty() {
        let no_tool =
            payload(r#"{"hook_event_name":"PostToolUse","tool_input":{"command":"true"}}"#);
        assert!(parse_hook("claude-code", &no_tool).is_empty());
        assert!(parse_hook("aider", &no_tool).is_empty());
        assert!(parse_hook("claude-code", &Value::Null).is_empty());
        let empty_name = payload(r#"{"hook_event_name":"PreToolUse","tool_name":""}"#);
        assert!(parse_hook("codex", &empty_name).is_empty());
    }

    #[test]
    fn command_truncates_to_256_scalars() {
        let command = "a".repeat(300);
        let body = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command }
        });
        let calls = parse_hook("codex", &body);
        let kept = calls[0]
            .summary
            .get("command")
            .and_then(Value::as_str)
            .expect("command");
        assert_eq!(kept.chars().count(), 256);
    }

    #[test]
    fn cursor_shell_uses_top_level_command_and_ignores_output() {
        let calls = parse_hook(
            "cursor",
            &payload(
                r#"{"hook_event_name":"beforeShellExecution","command":"ls","output":"secret-listing","cwd":"/tmp/placeholder"}"#,
            ),
        );
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].tool, "Shell");
        assert_eq!(
            calls[0].summary.get("command").and_then(Value::as_str),
            Some("ls")
        );
        let rendered = serde_json::to_string(&calls[0].summary).expect("summary");
        assert!(!rendered.contains("secret-listing"), "{rendered}");
        assert!(!rendered.contains("/tmp/placeholder"), "{rendered}");
    }
}
