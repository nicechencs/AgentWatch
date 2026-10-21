//! Claude Code hook decision JSON (P5-SEC-02).
//!
//! Field names follow the Claude Code hooks page as checked on 2026-10-21
//! (`permissionDecision`, `permissionDecisionReason`, `updatedInput`,
//! `updatedToolOutput`). An allow that does not rewrite produces no JSON:
//! printing `allow` would approve the tool, and the design says allow is
//! "do not interfere".

use serde_json::{json, Map, Value};

/// One decision the hook process will print. `None` means print nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookDecision {
    /// `allow` / `deny` / `ask`. `allow` is only present when `updated` is.
    pub permission: String,
    /// Shown to the agent. Already a short sentence, not a payload.
    pub reason: Option<String>,
    /// Replacement tool input, for PreToolUse. The whole object.
    pub updated_input: Option<Value>,
    /// Replacement model-facing output, for PostToolUse.
    pub updated_output: Option<Value>,
}

impl HookDecision {
    /// JSON object for stdout. `None` when there is nothing to say.
    #[must_use]
    pub fn to_json(&self) -> Option<Value> {
        if self.permission == "allow"
            && self.updated_input.is_none()
            && self.updated_output.is_none()
        {
            return None;
        }
        let mut specific = Map::new();
        specific.insert(
            "permissionDecision".to_owned(),
            Value::String(self.permission.to_owned()),
        );
        if let Some(reason) = &self.reason {
            specific.insert(
                "permissionDecisionReason".to_owned(),
                Value::String(reason.clone()),
            );
        }
        if let Some(input) = &self.updated_input {
            specific.insert("updatedInput".to_owned(), input.clone());
        }
        if let Some(output) = &self.updated_output {
            specific.insert("updatedToolOutput".to_owned(), output.clone());
        }
        Some(json!({ "hookSpecificOutput": Value::Object(specific) }))
    }
}

/// Build a decision.
///
/// `permission` is `allow`, `deny`, or `ask`. `updated_input` replaces the
/// whole `tool_input` (PreToolUse). `updated_output` replaces what the model
/// sees (PostToolUse). Passing both is the caller's bug; input wins and
/// output is dropped so the object stays one event's shape.
#[must_use]
pub fn claude_decision(
    permission: &str,
    reason: Option<&str>,
    updated_input: Option<&Value>,
    updated_output: Option<&Value>,
) -> Option<HookDecision> {
    let permission = match permission {
        "allow" | "deny" | "ask" => permission.to_owned(),
        _ => return None,
    };
    if permission == "allow" && updated_input.is_none() && updated_output.is_none() {
        return None;
    }
    let (updated_input, updated_output) = if updated_input.is_some() {
        (updated_input.cloned(), None)
    } else {
        (None, updated_output.cloned())
    };
    Some(HookDecision {
        permission,
        reason: reason.map(str::to_owned),
        updated_input,
        updated_output,
    })
}

/// Settings document that points every tool event at `aw`.
///
/// `command` is the absolute path of this binary. `args` are
/// `hook claude-code` plus whatever else the caller needs (`--session` is
/// not required: `AW_SESSION` is injected into the child). `on_failure_block`
/// adds `"onFailure": "block"` so a hook that fails to start is a deny.
/// That field needs Claude Code 2.1.295 or newer; the caller says so when it
/// cannot check the version.
#[must_use]
pub fn intercept_settings_json(command: &str, args: &[&str], on_failure_block: bool) -> String {
    let hook = hook_object(command, args, on_failure_block);
    let events = ["PreToolUse", "PostToolUse", "SessionStart", "SessionEnd"];
    let mut body = String::from("{\n  \"hooks\": {\n");
    for (index, event) in events.iter().enumerate() {
        let comma = if index + 1 == events.len() { "" } else { "," };
        body.push_str(&format!(
            "    \"{event}\": [\n      {{\n        \"matcher\": \"*\",\n        \"hooks\": [\n          {hook}\n        ]\n      }}\n    ]{comma}\n"
        ));
    }
    body.push_str("  }\n}\n");
    body
}

fn hook_object(command: &str, args: &[&str], on_failure_block: bool) -> String {
    let command = json!(command);
    let args = json!(args);
    if on_failure_block {
        format!(
            "{{\"type\": \"command\", \"command\": {command}, \"args\": {args}, \"onFailure\": \"block\"}}"
        )
    } else {
        format!("{{\"type\": \"command\", \"command\": {command}, \"args\": {args}}}")
    }
}

/// Manual fragment. Not written to `~/.claude/`.
#[must_use]
pub fn intercept_manual_snippet(command: &str) -> String {
    format!(
        "# claude-code intercept fragment (manual). Do not write this into ~/.claude/.\n\
         # Point a settings file you control at `{command}` with args\n\
         # [\"hook\", \"claude-code\"] for PreToolUse, PostToolUse, SessionStart,\n\
         # and SessionEnd. Set onFailure to \"block\" (Claude Code 2.1.295+).\n"
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deny_and_ask_and_rewrite_have_the_documented_shape() {
        let deny = claude_decision("deny", Some("不允许递归删除"), None, None)
            .unwrap()
            .to_json()
            .unwrap();
        assert_eq!(
            deny["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );
        assert_eq!(
            deny["hookSpecificOutput"]["permissionDecisionReason"],
            json!("不允许递归删除")
        );

        let ask = claude_decision("ask", None, None, None)
            .unwrap()
            .to_json()
            .unwrap();
        assert_eq!(
            ask["hookSpecificOutput"]["permissionDecision"],
            json!("ask")
        );

        let input = json!({"command": "terraform plan", "extra": true});
        let rewrite = claude_decision("allow", Some("只允许 plan"), Some(&input), None)
            .unwrap()
            .to_json()
            .unwrap();
        assert_eq!(
            rewrite["hookSpecificOutput"]["permissionDecision"],
            json!("allow")
        );
        assert_eq!(rewrite["hookSpecificOutput"]["updatedInput"], input);
        assert!(rewrite["hookSpecificOutput"]
            .get("updatedToolOutput")
            .is_none());
    }

    #[test]
    fn bare_allow_prints_nothing() {
        assert!(claude_decision("allow", None, None, None).is_none());
    }

    #[test]
    fn post_tool_output_is_separate_from_input() {
        let output = json!({"ok": false});
        let decision = claude_decision("allow", None, None, Some(&output))
            .unwrap()
            .to_json()
            .unwrap();
        assert_eq!(decision["hookSpecificOutput"]["updatedToolOutput"], output);
    }

    #[test]
    fn settings_use_exec_form_and_block_on_failure() {
        let doc = intercept_settings_json("/usr/bin/aw", &["hook", "claude-code"], true);
        let value: Value = serde_json::from_str(&doc).unwrap();
        let hook = &value["hooks"]["PreToolUse"][0]["hooks"][0];
        assert_eq!(hook["type"], json!("command"));
        assert_eq!(hook["command"], json!("/usr/bin/aw"));
        assert_eq!(hook["args"], json!(["hook", "claude-code"]));
        assert_eq!(hook["onFailure"], json!("block"));
        assert!(value["hooks"].get("PostToolUse").is_some());
    }
}
