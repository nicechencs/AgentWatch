//! Apply one policy decision to one MCP JSON-RPC frame (P5-SEC-03).
//!
//! The wrapper still owns the bytes. This module only says what to forward.
//! A frame that is not JSON, or not a request, is [`FrameAction::Forward`]
//! only when the decision is allow. A deny of bytes this module cannot label
//! drops them: forwarding a refused line would run the call.
//!
//! `ask` is a deny. Step 1 has no way to ask the user from a stdio tap.

use serde_json::{json, Map, Value};

/// What the copy loop should write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameAction {
    /// Write the original frame, delimiter included.
    Forward,
    /// Do not write the frame to the server. Write `response` to the client
    /// instead. `response` is one JSON line without the trailing newline;
    /// the wrapper adds the newline it stripped. An empty `response` means
    /// write nothing (a notification has no id to answer).
    Reject { response: String },
    /// Write `bytes` (already rewritten, no trailing newline) instead of the
    /// original frame.
    Rewrite { bytes: String },
}

/// One field the policy asked to replace. The adapter does not know rules;
/// the CLI passes the names and the new text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldChange {
    /// `command`, `arg.<name>`, or a result field name.
    pub field: String,
    /// Replacement text. Not interpreted.
    pub value: String,
}

/// The decision the CLI already computed. This crate does not load a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameVerdict {
    /// Nothing matched, or the rule said allow. Forward the bytes.
    Allow,
    /// Do not forward the request. Answer the client with `reason` when it
    /// has an id. `ask` arrives here already: step 1 cannot ask from stdio.
    Deny,
    /// Replace the named fields, then forward the new line.
    Rewrite,
}

/// One already-decided frame, plus the replacement fields when it is a rewrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameDecision<'a> {
    /// What to do.
    pub verdict: FrameVerdict,
    /// Shown in the JSON-RPC error. Not a secret. Unused for allow.
    pub reason: Option<&'a str>,
    /// Fields to replace. Only read when [`Self::verdict`] is rewrite.
    pub fields: &'a [FieldChange],
}

/// Labels a request frame carries, for the policy subject the CLI builds.
///
/// A line that is not a JSON object returns `None`. The wrapper then forwards
/// it: a rule cannot name bytes this function cannot label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrameSubject {
    /// JSON-RPC `method`, when present.
    pub method: Option<String>,
    /// `params.name`, the MCP tool.
    pub tool: Option<String>,
    /// `params.arguments.command`, when that argument is a string.
    pub command: Option<String>,
    /// String arguments only. Numbers and objects are not matched.
    pub args: Vec<(String, String)>,
}

/// Labels for one request or response frame. `direction` is recorded by the
/// caller; this function only reads the JSON.
///
/// A request contributes `method`, `params.name`, and string arguments. A
/// response has none of those; its string fields under `result` become
/// `arg.<name>` so a rule can match and rewrite the tool result. Nested
/// objects are walked one level (`result.content.0.text` stays unreachable:
/// only a string value is a label).
#[must_use]
pub fn subject_from_frame(frame: &str) -> Option<FrameSubject> {
    let value: Value = serde_json::from_str(frame).ok()?;
    let object = value.as_object()?;
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let params = object.get("params").and_then(Value::as_object);
    let tool = params
        .and_then(|map| map.get("name"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    let arguments = params
        .and_then(|map| map.get("arguments"))
        .and_then(Value::as_object);
    let mut args: Vec<(String, String)> = arguments
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|text| (key.clone(), text.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(result) = object.get("result").and_then(Value::as_object) {
        for (key, value) in result {
            if let Some(text) = value.as_str() {
                if !args.iter().any(|(name, _)| name == key) {
                    args.push((key.clone(), text.to_owned()));
                }
            }
        }
    }
    let command = arguments
        .and_then(|map| map.get("command"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            object
                .get("result")
                .and_then(|result| result.get("command"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    Some(FrameSubject {
        method,
        tool,
        command,
        args,
    })
}

/// Decide one client-to-server frame.
///
/// `frame` is the line without its delimiter. `decision` is already computed;
/// this function only applies it. A non-JSON frame is forwarded only when the
/// decision is allow. A deny of a line that is not one JSON object drops the
/// line: there is no id to answer, and forwarding it would run the call.
#[must_use]
pub fn apply_request(frame: &str, decision: &FrameDecision<'_>) -> FrameAction {
    if decision.verdict == FrameVerdict::Allow {
        return FrameAction::Forward;
    }
    let Ok(value) = serde_json::from_str::<Value>(frame) else {
        return drop_denied();
    };
    if !value.is_object() {
        // An array (a JSON-RPC batch) or a scalar is not one request. The
        // caller decides each element itself; applying a single-frame deny
        // here must not forward the whole batch.
        return drop_denied();
    }
    if decision.verdict == FrameVerdict::Deny {
        let Some(response) = jsonrpc_error(&value, decision.reason) else {
            // A notification has no id. There is nowhere to send an error,
            // and forwarding it would run the call. Dropping a notification
            // is the deny. The wrapper writes nothing for this frame.
            return drop_denied();
        };
        return FrameAction::Reject { response };
    }
    let Some(rewritten) = rewrite_frame(&value, decision.fields) else {
        // The rule asked for a rewrite and the frame has nowhere to put it.
        // Forwarding the original would be the rewrite the audit already
        // claimed, with the old bytes. Drop it; the caller treats a missing
        // rewrite as `on_error`.
        return drop_denied();
    };
    FrameAction::Rewrite { bytes: rewritten }
}

/// A deny that cannot be turned into a JSON-RPC error. Write nothing.
fn drop_denied() -> FrameAction {
    FrameAction::Reject {
        response: String::new(),
    }
}

/// Decide one server-to-client frame. Only a rewrite of the result is
/// applied. A deny on the way back cannot un-run the tool; the wrapper
/// forwards. Step 1 rewrites `result` fields the rule named.
#[must_use]
pub fn apply_response(frame: &str, decision: &FrameDecision<'_>) -> FrameAction {
    if decision.verdict != FrameVerdict::Rewrite {
        return FrameAction::Forward;
    }
    let Ok(value) = serde_json::from_str::<Value>(frame) else {
        return FrameAction::Forward;
    };
    let Some(rewritten) = rewrite_frame(&value, decision.fields) else {
        // Same as a request: a rewrite that does not land must not forward
        // the original bytes under a rewrite verdict.
        return drop_denied();
    };
    FrameAction::Rewrite { bytes: rewritten }
}

fn jsonrpc_error(request: &Value, reason: Option<&str>) -> Option<String> {
    let id = request.get("id").cloned()?;
    let message = reason.unwrap_or("aw 在工具转接层拒绝了这一次调用");
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": -32000, "message": message }
    });
    serde_json::to_string(&body).ok()
}

fn rewrite_frame(value: &Value, fields: &[FieldChange]) -> Option<String> {
    let mut next = value.clone();
    let object = next.as_object_mut()?;
    for change in fields {
        if !set_dotted(object, &change.field, &change.value) {
            return None;
        }
    }
    serde_json::to_string(&next).ok()
}

/// Write one rewritten field back into the frame.
///
/// `arg.<name>` and `command` land in `params.arguments` on a request and in
/// `result` on a response. `mcp_tool` and `tool` are `params.name`: a rule that
/// rewrites the tool name has to change the name the server will call.
/// Returns false when the frame has nowhere to put the field, so the caller
/// does not forward the original and claim a rewrite.
fn set_dotted(object: &mut Map<String, Value>, field: &str, text: &str) -> bool {
    if field == "mcp_tool" || field == "tool" {
        let Some(params) = object.get_mut("params").and_then(Value::as_object_mut) else {
            return false;
        };
        params.insert("name".to_owned(), Value::String(text.to_owned()));
        return true;
    }
    let name = field.strip_prefix("arg.").unwrap_or(field);
    if object.contains_key("params") {
        let Some(params) = object.get_mut("params").and_then(Value::as_object_mut) else {
            return false;
        };
        let arguments = params
            .entry("arguments")
            .or_insert_with(|| Value::Object(Map::new()));
        let Some(arguments) = arguments.as_object_mut() else {
            return false;
        };
        arguments.insert(name.to_owned(), Value::String(text.to_owned()));
        return true;
    }
    if let Some(result) = object.get_mut("result").and_then(Value::as_object_mut) {
        result.insert(name.to_owned(), Value::String(text.to_owned()));
        return true;
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn deny() -> FrameDecision<'static> {
        FrameDecision {
            verdict: FrameVerdict::Deny,
            reason: Some("不允许"),
            fields: &[],
        }
    }

    #[test]
    fn deny_returns_the_same_id_and_does_not_echo_the_arguments() {
        let frame = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run","arguments":{"command":"rm -rf /tmp"}}}"#;
        let action = apply_request(frame, &deny());
        match action {
            FrameAction::Reject { response } => {
                let value: Value = serde_json::from_str(&response).unwrap();
                assert_eq!(value["id"], json!(7));
                assert!(value.get("error").is_some());
                assert!(!response.contains("rm -rf"));
                assert_eq!(value["error"]["message"], json!("不允许"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rewrite_keeps_other_argument_fields() {
        let frame = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run","arguments":{"command":"terraform apply","dry":false}}}"#;
        let fields = [FieldChange {
            field: "command".to_owned(),
            value: "terraform plan".to_owned(),
        }];
        let decision = FrameDecision {
            verdict: FrameVerdict::Rewrite,
            reason: None,
            fields: &fields,
        };
        match apply_request(frame, &decision) {
            FrameAction::Rewrite { bytes } => {
                let value: Value = serde_json::from_str(&bytes).unwrap();
                assert_eq!(
                    value["params"]["arguments"]["command"],
                    json!("terraform plan")
                );
                assert_eq!(value["params"]["arguments"]["dry"], json!(false));
                assert_eq!(value["id"], json!(1));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn allow_is_forward() {
        let decision = FrameDecision {
            verdict: FrameVerdict::Allow,
            reason: None,
            fields: &[],
        };
        let frame = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        assert!(matches!(
            apply_request(frame, &decision),
            FrameAction::Forward
        ));
    }

    /// A response rewrite names `result.text`. The client must see the
    /// replacement, not the server's original field.
    #[test]
    fn rewrite_result_text_is_what_the_client_sees() {
        let frame = r#"{"jsonrpc":"2.0","id":5,"result":{"text":"SECRET","ok":true}}"#;
        let fields = [FieldChange {
            field: "arg.text".to_owned(),
            value: "XXX".to_owned(),
        }];
        let decision = FrameDecision {
            verdict: FrameVerdict::Rewrite,
            reason: None,
            fields: &fields,
        };
        match apply_response(frame, &decision) {
            FrameAction::Rewrite { bytes } => {
                let value: Value = serde_json::from_str(&bytes).unwrap();
                assert_eq!(value["result"]["text"], json!("XXX"));
                assert_eq!(value["result"]["ok"], json!(true));
                assert_eq!(value["id"], json!(5));
                assert!(!bytes.contains("SECRET"));
            }
            other => panic!("{other:?}"),
        }
    }

    /// `mcp_tool` is `params.name`. A rewrite that cannot write that key back
    /// must not claim the frame changed.
    #[test]
    fn rewrite_mcp_tool_writes_params_name() {
        let frame = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"oldtool","arguments":{"command":"echo"}}}"#;
        let fields = [FieldChange {
            field: "mcp_tool".to_owned(),
            value: "newtool".to_owned(),
        }];
        let decision = FrameDecision {
            verdict: FrameVerdict::Rewrite,
            reason: None,
            fields: &fields,
        };
        match apply_request(frame, &decision) {
            FrameAction::Rewrite { bytes } => {
                let value: Value = serde_json::from_str(&bytes).unwrap();
                assert_eq!(value["params"]["name"], json!("newtool"));
                assert_eq!(value["params"]["arguments"]["command"], json!("echo"));
                assert!(!bytes.contains("oldtool"));
            }
            other => panic!("mcp_tool was not written back: {other:?}"),
        }
    }

    /// A deny of a line that is not one JSON object must not forward it.
    #[test]
    fn deny_of_non_json_does_not_forward() {
        let decision = deny();
        let action = apply_request("not json", &decision);
        assert!(
            matches!(action, FrameAction::Reject { .. }),
            "non-json deny was forwarded: {action:?}"
        );
        let batch = r#"[{"jsonrpc":"2.0","id":2,"method":"tools/call"}]"#;
        let action = apply_request(batch, &decision);
        assert!(
            matches!(action, FrameAction::Reject { .. }),
            "array deny was forwarded: {action:?}"
        );
    }
}
