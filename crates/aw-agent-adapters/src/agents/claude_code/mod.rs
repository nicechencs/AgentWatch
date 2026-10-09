//! Claude Code adapter (P5-AGENT-03, P5-AGENT-04).
//!
//! Hook stdin and OTEL logs become [`AgentToolCall`] values. Nothing here stores
//! a prompt, model output, `tool_response`, or file contents. Nothing here writes
//! `~/.claude/` or reads a session transcript.
//!
//! SPIKE-07 (2026-10-07) is a document survey. It did not record hook stdin and
//! did not run `claude` on a machine. Field names below follow that survey and
//! the task card. Launch injection uses `--settings <file>` as the preferred
//! path and is marked unverified: this crate has not confirmed the flag on a
//! real binary.
//!
//! The shared hook registry ([`crate::parse_hook`]) still owns the generic
//! Claude Code parser used by `aw hook`. This module is the product mapping:
//! it also fills `path` / `url` / `query`, renames MCP tools, and pairs Pre
//! with Post on `tool_use_id`.

mod map;
pub mod otel;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aw_core::{AgentToolCall, ToolPhase};
use serde_json::{Map, Value};

use crate::channel::{ChannelError, SelfReportSource, SessionHandle};

pub use map::{map_hook, HookMap, MappedCall, AGENT_ID};
pub use otel::{
    dedupe_with_hooks, map_otlp_logs, otel_env, user_otlp_already_set, OtelEnvPlan, OtelMap,
    AGENT_SOURCE_OTEL,
};

/// Source string stored beside an E3 call that came from a hook.
pub const HOOK_SOURCE: &str = "agent.claude-code/hook";

/// Channel id for the temporary-settings injector.
pub const HOOKS_CHANNEL_ID: &str = "claude-code/hooks";

/// How a session asks Claude Code to load the audit hook.
///
/// SPIKE-07 §5.1 lists three options. This adapter implements the first and
/// falls back to the third. It never writes a project settings file and never
/// touches `~/.claude/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectMode {
    /// Preferred. A temp JSON file plus `--settings <path>` on this launch only.
    ///
    /// 【待验证】The flag and its merge behaviour come from the 2026-10-07
    /// document survey. They have not been confirmed against a `claude` binary.
    TempSettings {
        /// Ordinary file the caller will pass to `--settings`. Not created here.
        path: PathBuf,
    },
    /// Automatic injection is not available. The caller prints [`manual_snippet`].
    ManualOnly,
}

/// One prepared launch. Holds the settings document; does not touch the disk
/// outside the path the caller already chose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    mode: InjectMode,
    /// Settings JSON. Present only for [`InjectMode::TempSettings`].
    settings_json: Option<String>,
    /// Argv suffix, for example `--settings` and the temp path.
    extra_args: Vec<String>,
    /// Human-readable note. No paths from the user's home directory.
    note: String,
}

impl LaunchPlan {
    /// Chosen mode.
    #[must_use]
    pub fn mode(&self) -> &InjectMode {
        &self.mode
    }

    /// Settings document to write at the temp path, if any.
    #[must_use]
    pub fn settings_json(&self) -> Option<&str> {
        self.settings_json.as_deref()
    }

    /// Arguments to append to this launch. Empty when injection is manual.
    #[must_use]
    pub fn extra_args(&self) -> &[String] {
        &self.extra_args
    }

    /// Why this mode was chosen. Safe to show; it does not contain payloads.
    #[must_use]
    pub fn note(&self) -> &str {
        &self.note
    }
}

/// Build the preferred launch plan: a temp settings file and `--settings`.
///
/// `settings_path` must be a path the caller owns for this session (for example
/// under the daemon's session directory). This function does not create the
/// file and does not look at `~/.claude/`.
///
/// 【待验证】Whether `claude --settings <file>` actually loads these hooks is
/// not confirmed. SPIKE-07 recorded the flag from documentation only.
#[must_use]
pub fn plan_temp_settings(settings_path: &Path) -> LaunchPlan {
    let path = settings_path.to_path_buf();
    let settings_json = hook_settings_json();
    let extra_args = vec!["--settings".to_owned(), path.display().to_string()];
    LaunchPlan {
        mode: InjectMode::TempSettings { path },
        settings_json: Some(settings_json),
        extra_args,
        note:
            "temp --settings file for this launch only; not verified on a claude binary 【待验证】"
                .to_owned(),
    }
}

/// Fallback when a temp settings file cannot be used.
///
/// Returns no args and no document. The caller shows [`manual_snippet`] and
/// does not write a settings file.
#[must_use]
pub fn plan_manual_only() -> LaunchPlan {
    LaunchPlan {
        mode: InjectMode::ManualOnly,
        settings_json: None,
        extra_args: Vec::new(),
        note: "no automatic injection; print the manual hook snippet".to_owned(),
    }
}

/// Settings document for the temp file.
///
/// Hooks only. No other keys, so a caller that writes this file is not copying
/// a user config. The command is `aw hook claude-code` and matches every tool.
#[must_use]
pub fn hook_settings_json() -> String {
    // Stable key order. Not built from a map that could pick up extra fields.
    "{\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\n        \"matcher\": \"*\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"aw hook claude-code\"\n          }\n        ]\n      }\n    ],\n    \"PostToolUse\": [\n      {\n        \"matcher\": \"*\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"aw hook claude-code\"\n          }\n        ]\n      }\n    ],\n    \"SessionStart\": [\n      {\n        \"matcher\": \"*\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"aw hook claude-code\"\n          }\n        ]\n      }\n    ],\n    \"SessionEnd\": [\n      {\n        \"matcher\": \"*\",\n        \"hooks\": [\n          {\n            \"type\": \"command\",\n            \"command\": \"aw hook claude-code\"\n          }\n        ]\n      }\n    ]\n  }\n}\n".to_owned()
}

/// Text the user can paste when automatic injection is off.
///
/// This is a fragment, not an instruction to edit `~/.claude/`. It names the
/// hook command and the events. It does not include a home-directory path.
#[must_use]
pub fn manual_snippet() -> &'static str {
    "# claude-code hook fragment (manual). Do not write this into ~/.claude/.\n\
     # Point a settings file you control at `aw hook claude-code` for\n\
     # PreToolUse, PostToolUse, SessionStart, and SessionEnd, matcher \"*\".\n\
     # 【待验证】CLI flag --settings was not confirmed on a real binary.\n"
}

/// Session start or end, taken from a hook payload.
///
/// Tool calls are not included. A missing session id stays `None`; it is not
/// replaced with a pid or an empty string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSessionNote {
    /// `session_id` from the hook, truncated. Absent when the field is missing.
    pub agent_session: Option<String>,
    /// `SessionStart` or `SessionEnd`.
    pub event: SessionBoundary,
}

/// Which boundary the hook reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBoundary {
    /// `SessionStart`.
    Start,
    /// `SessionEnd`.
    End,
}

/// Read `SessionStart` / `SessionEnd`. Any other event returns `None`.
///
/// `transcript_path` is ignored. This function does not open that path.
#[must_use]
pub fn map_session_boundary(payload: &Value) -> Option<AgentSessionNote> {
    let obj = payload.as_object()?;
    let event = match map::string_field(obj, "hook_event_name").as_deref() {
        Some("SessionStart") => SessionBoundary::Start,
        Some("SessionEnd") => SessionBoundary::End,
        _ => return None,
    };
    Some(AgentSessionNote {
        agent_session: map::id_field(obj, "session_id"),
        event,
    })
}

/// Map one Claude Code hook payload into tool calls.
///
/// `SessionStart` / `SessionEnd` yield no tool calls; use [`map_session_boundary`]
/// for those. Unknown tools keep their name and an empty summary. See [`map_hook`].
#[must_use]
pub fn parse_claude_hook(payload: &Value) -> Vec<AgentToolCall> {
    map_hook(payload).calls
}

/// Hooks channel. Preparing a plan does not write the user's config.
///
/// `start` only checks that a temp path was supplied when temp injection was
/// requested. Writing the file is the caller's job, and only at that path.
#[derive(Debug)]
pub struct ClaudeHooks {
    plan: LaunchPlan,
    started: bool,
}

impl ClaudeHooks {
    /// Temp-settings plan. 【待验证】
    #[must_use]
    pub fn temp_settings(settings_path: &Path) -> Self {
        Self {
            plan: plan_temp_settings(settings_path),
            started: false,
        }
    }

    /// Manual-only plan. No file, no args.
    #[must_use]
    pub fn manual_only() -> Self {
        Self {
            plan: plan_manual_only(),
            started: false,
        }
    }

    /// The plan chosen at construction.
    #[must_use]
    pub fn plan(&self) -> &LaunchPlan {
        &self.plan
    }
}

impl SelfReportSource for ClaudeHooks {
    fn id(&self) -> &str {
        HOOKS_CHANNEL_ID
    }

    fn start(&mut self, session: &SessionHandle) -> Result<(), ChannelError> {
        if session.session_id().is_empty() {
            return Err(ChannelError::new("session id is empty"));
        }
        match &self.plan.mode {
            InjectMode::TempSettings { path } => {
                if path.as_os_str().is_empty() {
                    return Err(ChannelError::new("temp settings path is empty"));
                }
                // Refuse a path that is the user config tree. The string check
                // is a guard, not a claim that we inspected the user's files.
                let rendered = path.display().to_string();
                if rendered.contains("/.claude/") || rendered.contains("\\.claude\\") {
                    return Err(ChannelError::new("refusing a settings path under .claude"));
                }
            }
            InjectMode::ManualOnly => {}
        }
        self.started = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ChannelError> {
        self.started = false;
        Ok(())
    }
}

/// Whether `start` has succeeded and `stop` has not run since.
impl ClaudeHooks {
    /// True after a successful `start` until `stop`.
    #[must_use]
    pub fn is_started(&self) -> bool {
        self.started
    }
}

/// Pair Pre and Post calls that share a `call_id`.
///
/// Order is kept. Calls without a `call_id` stay as they are. This does not
/// drop either side: pairing is for the caller that wants both phases of one
/// invocation. Duplicate ids are left in place; dedupe across channels is
/// [`dedupe_with_hooks`].
#[must_use]
pub fn pair_by_call_id(
    calls: &[AgentToolCall],
) -> BTreeMap<String, (Option<ToolPhase>, Option<ToolPhase>)> {
    let mut paired: BTreeMap<String, (Option<ToolPhase>, Option<ToolPhase>)> = BTreeMap::new();
    for call in calls {
        let Some(id) = call.call_id.as_deref() else {
            continue;
        };
        let slot = paired.entry(id.to_owned()).or_insert((None, None));
        match call.phase {
            ToolPhase::Pre => slot.0 = Some(ToolPhase::Pre),
            ToolPhase::Post => slot.1 = Some(ToolPhase::Post),
            ToolPhase::Unknown => {}
        }
    }
    paired
}

/// Summary object with one string field, or empty when `value` is missing.
#[must_use]
pub fn summary_field(key: &str, value: Option<&str>) -> Value {
    map::summary_field(key, value)
}

/// Empty summary object. Used for unknown tools.
#[must_use]
pub fn empty_summary() -> Value {
    Value::Object(Map::new())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fs;

    use super::*;
    use serde_json::{json, Value};

    fn fixture(name: &str) -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/agents/claude-code")
            .join(name);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        serde_json::from_str(&text).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
    }

    fn assert_dropped(summary: &Value, needles: &[&str]) {
        let rendered = serde_json::to_string(summary).expect("summary");
        for needle in needles {
            assert!(!rendered.contains(needle), "{rendered} still has {needle}");
        }
    }

    #[test]
    fn temp_settings_plan_names_hook_command_and_flag() {
        let plan = plan_temp_settings(Path::new("/var/tmp/aw-session/claude-settings.json"));
        assert!(matches!(plan.mode(), InjectMode::TempSettings { .. }));
        assert_eq!(
            plan.extra_args(),
            &[
                "--settings".to_owned(),
                "/var/tmp/aw-session/claude-settings.json".to_owned(),
            ]
        );
        let doc = plan.settings_json().expect("json");
        assert!(doc.contains("aw hook claude-code"));
        assert!(doc.contains("PreToolUse"));
        assert!(doc.contains("PostToolUse"));
        assert!(!doc.contains(".claude"));
        assert!(plan.note().contains("待验证"));
    }

    #[test]
    fn manual_plan_has_no_args_and_snippet_avoids_home_edit() {
        let plan = plan_manual_only();
        assert_eq!(plan.mode(), &InjectMode::ManualOnly);
        assert!(plan.extra_args().is_empty());
        assert!(plan.settings_json().is_none());
        let snippet = manual_snippet();
        assert!(snippet.contains("aw hook claude-code"));
        assert!(snippet.contains("Do not write this into ~/.claude/"));
    }

    #[test]
    fn hooks_source_refuses_user_config_tree() {
        let mut hooks =
            ClaudeHooks::temp_settings(Path::new("/home/placeholder/.claude/settings.json"));
        let err = hooks
            .start(&SessionHandle::new("s-1"))
            .expect_err("under .claude");
        assert!(err.message().contains(".claude"));
        assert!(!hooks.is_started());

        let mut ok = ClaudeHooks::temp_settings(Path::new("/var/tmp/aw-session/settings.json"));
        ok.start(&SessionHandle::new("s-1")).expect("start");
        assert!(ok.is_started());
        ok.stop().expect("stop");
        assert!(!ok.is_started());
    }

    #[test]
    fn session_boundary_ignores_transcript_path() {
        let start = json!({
            "hook_event_name": "SessionStart",
            "session_id": "sess-synthetic",
            "transcript_path": "/home/placeholder/.claude/projects/x.jsonl"
        });
        let note = map_session_boundary(&start).expect("start");
        assert_eq!(note.event, SessionBoundary::Start);
        assert_eq!(note.agent_session.as_deref(), Some("sess-synthetic"));

        let end = json!({"hook_event_name": "SessionEnd", "session_id": "sess-synthetic"});
        assert_eq!(
            map_session_boundary(&end).expect("end").event,
            SessionBoundary::End
        );
        assert!(map_session_boundary(&json!({"hook_event_name": "PreToolUse"})).is_none());
    }

    #[test]
    fn claude_code_replays_hook_fixtures() {
        let bash = &parse_claude_hook(&fixture("bash-pre.json"))[0];
        assert_eq!(bash.agent, "claude-code");
        assert_eq!(bash.tool, "Bash");
        assert_eq!(bash.phase, ToolPhase::Pre);
        assert_eq!(bash.call_id.as_deref(), Some("tu-bash-1"));
        assert_eq!(bash.agent_session.as_deref(), Some("sess-synthetic-1"));
        assert_eq!(bash.summary, json!({"command": "echo ok"}));
        assert_dropped(&bash.summary, &["do-not-store-body", "do-not-store-output"]);

        let read = &parse_claude_hook(&fixture("read-post.json"))[0];
        assert_eq!(read.tool, "Read");
        assert_eq!(read.phase, ToolPhase::Post);
        assert_eq!(read.call_id.as_deref(), Some("tu-read-1"));
        assert_eq!(read.summary, json!({"path": "src/lib.rs"}));
        assert_dropped(&read.summary, &["file-body-must-not-be-stored"]);

        let edit = &parse_claude_hook(&fixture("edit-pre.json"))[0];
        assert_eq!(edit.tool, "Edit");
        assert_eq!(edit.summary, json!({"path": "README.md"}));
        assert_dropped(
            &edit.summary,
            &["old-text-must-not-be-stored", "new-text-must-not-be-stored"],
        );

        let write = &parse_claude_hook(&fixture("write-post.json"))[0];
        assert_eq!(write.tool, "Write");
        assert_eq!(write.phase, ToolPhase::Post);
        assert_eq!(write.summary, json!({"path": "notes.txt"}));
        assert_dropped(&write.summary, &["whole-file-must-not-be-stored"]);

        let fetch = &parse_claude_hook(&fixture("webfetch-pre.json"))[0];
        assert_eq!(fetch.tool, "WebFetch");
        assert_eq!(fetch.summary, json!({"url": "https://example.test/docs"}));
        assert_dropped(&fetch.summary, &["prompt-must-not-be-stored"]);

        let search = &parse_claude_hook(&fixture("websearch-pre.json"))[0];
        assert_eq!(search.tool, "WebSearch");
        assert_eq!(search.summary, json!({"query": "placeholder query"}));

        let mcp = &parse_claude_hook(&fixture("mcp-pre.json"))[0];
        assert_eq!(mcp.tool, "mcp:docs/search");
        assert_eq!(mcp.summary, json!({}));
        assert_dropped(&mcp.summary, &["argument-must-not-be-stored"]);

        let mcp_post = &parse_claude_hook(&fixture("mcp-post.json"))[0];
        assert_eq!(mcp_post.tool, "mcp:docs/search");
        assert_eq!(mcp_post.phase, ToolPhase::Post);
        assert_eq!(mcp_post.call_id.as_deref(), Some("tu-mcp-2"));
        assert_eq!(mcp_post.summary, json!({}));
        assert_dropped(&mcp_post.summary, &["model-output-must-not-be-stored"]);

        let unknown = &parse_claude_hook(&fixture("unknown-pre.json"))[0];
        assert_eq!(unknown.tool, "NotebookEdit");
        assert_eq!(unknown.summary, json!({}));
        assert_dropped(&unknown.summary, &["cell-source-must-not-be-stored"]);

        let boundary = map_session_boundary(&fixture("session-start.json")).expect("session");
        assert_eq!(boundary.event, SessionBoundary::Start);
        assert_eq!(boundary.agent_session.as_deref(), Some("sess-synthetic-1"));
        assert!(parse_claude_hook(&fixture("session-start.json")).is_empty());
    }

    #[test]
    fn pair_pre_and_post_on_tool_use_id() {
        let calls = parse_claude_hook(&json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "tu-9",
            "session_id": "s",
            "tool_input": {"file_path": "src/lib.rs"}
        }));
        let mut both = calls;
        both.extend(parse_claude_hook(&json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_use_id": "tu-9",
            "session_id": "s",
            "tool_input": {"file_path": "src/lib.rs"},
            "tool_response": {"content": "file body must not be stored"}
        })));
        let paired = pair_by_call_id(&both);
        assert_eq!(
            paired.get("tu-9"),
            Some(&(Some(ToolPhase::Pre), Some(ToolPhase::Post)))
        );
        let rendered = serde_json::to_string(&both[1].summary).expect("summary");
        assert!(!rendered.contains("file body"));
    }
}
