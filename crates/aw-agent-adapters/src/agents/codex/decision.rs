//! Codex hook decision JSON (P5-SEC-02).
//!
//! Field names follow the Codex hooks page as checked on 2026-10-21.
//! `permissionDecision: "deny"`, or `"allow"` plus `updatedInput`. Bash and
//! `apply_patch` rewrites must keep a string `command`. Codex has no `ask`:
//! the caller downgrades that to deny before calling here.
//!
//! A bare allow prints nothing. Printing `allow` without `updatedInput` is
//! not how this tool stays out of the way.

use serde_json::{json, Map, Value};

/// One Codex decision. `None` from [`codex_decision`] means print nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexDecision {
    /// `deny` or `allow`.
    pub permission: String,
    /// Shown to the agent.
    pub reason: Option<String>,
    /// Replacement tool input. Required for an allow that rewrites.
    pub updated_input: Option<Value>,
    /// The input's `hook_event_name`. Codex examples include it; omitting it
    /// makes the hook output fail open.
    pub hook_event_name: String,
}

impl CodexDecision {
    /// JSON object for stdout.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut specific = Map::new();
        specific.insert(
            "hookEventName".to_owned(),
            Value::String(self.hook_event_name.clone()),
        );
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
        json!({ "hookSpecificOutput": Value::Object(specific) })
    }
}

/// Build a Codex decision.
///
/// `ask` is refused (`None`): the caller must already have downgraded it.
/// An allow without `updated_input` is also `None` (print nothing).
/// For `Bash` and `apply_patch`, `updated_input.command` must be a string;
/// otherwise this returns `None` and the caller treats it as `on_error`.
#[must_use]
pub fn codex_decision(
    permission: &str,
    reason: Option<&str>,
    tool: Option<&str>,
    updated_input: Option<&Value>,
    hook_event_name: &str,
) -> Option<CodexDecision> {
    if hook_event_name.is_empty() {
        return None;
    }
    match permission {
        "deny" => Some(CodexDecision {
            permission: "deny".to_owned(),
            reason: reason.map(str::to_owned),
            updated_input: None,
            hook_event_name: hook_event_name.to_owned(),
        }),
        "allow" => {
            let input = updated_input?;
            if tool_needs_command(tool) && input.get("command").and_then(Value::as_str).is_none() {
                return None;
            }
            Some(CodexDecision {
                permission: "allow".to_owned(),
                reason: reason.map(str::to_owned),
                updated_input: Some(input.clone()),
                hook_event_name: hook_event_name.to_owned(),
            })
        }
        _ => None,
    }
}

fn tool_needs_command(tool: Option<&str>) -> bool {
    matches!(
        tool,
        Some("Bash" | "apply_patch" | "shell" | "exec_command")
    )
}

/// Manual fragment. Not written to `~/.codex/`. Automatic injection is
/// unverified (`-c` and a temporary profile both say 未确认 in the design).
#[must_use]
pub fn manual_snippet(command: &str) -> String {
    format!(
        "# codex hook fragment (manual). Do not write this into ~/.codex/.\n\
         # Whether `codex -c` or a temporary profile loads a hook for one run\n\
         # was not confirmed on 2026-10-21. Until that is confirmed, aw does not\n\
         # edit Codex config and does not pass --dangerously-bypass-hook-trust.\n\
         # Point a PreToolUse hook you trust at `{command}` with args\n\
         # [\"hook\", \"codex\"]. Codex has no onFailure=block: a hook that fails\n\
         # to start may let the tool run. aw cannot promise a deny in that case.\n"
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn deny_and_bash_rewrite() {
        let deny = codex_decision(
            "deny",
            Some("不允许递归删除"),
            Some("Bash"),
            None,
            "PreToolUse",
        )
        .unwrap();
        let body = deny.to_json();
        assert_eq!(
            body["hookSpecificOutput"]["hookEventName"],
            json!("PreToolUse")
        );
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("deny")
        );

        let input = json!({"command": "terraform plan", "cwd": "/work"});
        let rewrite = codex_decision(
            "allow",
            Some("只允许 plan"),
            Some("Bash"),
            Some(&input),
            "PreToolUse",
        )
        .unwrap();
        let body = rewrite.to_json();
        assert_eq!(
            body["hookSpecificOutput"]["permissionDecision"],
            json!("allow")
        );
        assert_eq!(
            body["hookSpecificOutput"]["updatedInput"]["command"],
            json!("terraform plan")
        );
    }

    #[test]
    fn ask_is_rejected_and_bash_without_command_is_rejected() {
        assert!(codex_decision("ask", None, Some("Bash"), None, "PreToolUse").is_none());
        let input = json!({"cmd": "terraform plan"});
        assert!(codex_decision("allow", None, Some("Bash"), Some(&input), "PreToolUse").is_none());
        assert!(codex_decision(
            "allow",
            None,
            Some("apply_patch"),
            Some(&input),
            "PreToolUse"
        )
        .is_none());
    }

    #[test]
    fn bare_allow_prints_nothing() {
        assert!(codex_decision("allow", None, Some("Bash"), None, "PreToolUse").is_none());
    }

    #[test]
    fn snippet_does_not_edit_home() {
        let text = manual_snippet("/usr/bin/aw");
        assert!(text.contains("Do not write this into ~/.codex/"));
        assert!(text.contains("未确认") || text.contains("not confirmed"));
    }
}
