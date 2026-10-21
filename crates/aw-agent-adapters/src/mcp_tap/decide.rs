//! Apply one policy decision to one MCP JSON-RPC frame (P5-SEC-03).
//!
//! The wrapper still owns the bytes. This module only says what to forward.
//! A frame that is not JSON, or not a request, is [`FrameAction::Forward`]:
//! changing it would break a session the rule did not name.
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

/// Labels for one request frame. `direction` is recorded by the caller; this
/// function only reads the JSON.
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
    let args = arguments
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|text| (key.clone(), text.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default();
    let command = arguments
        .and_then(|map| map.get("command"))
        .and_then(Value::as_str)
        .map(str::to_owned);
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
/// this function only applies it. A non-JSON frame is forwarded.
#[must_use]
pub fn apply_request(frame: &str, decision: &FrameDecision<'_>) -> FrameAction {
    if decision.verdict == FrameVerdict::Allow {
        return FrameAction::Forward;
    }
    let Ok(value) = serde_json::from_str::<Value>(frame) else {
        return FrameAction::Forward;
    };
    if decision.verdict == FrameVerdict::Deny {
        let Some(response) = jsonrpc_error(&value, decision.reason) else {
            // A notification has no id. There is nowhere to send an error,
            // and forwarding it would run the call. Dropping a notification
            // is the deny. The wrapper writes nothing for this frame.
            return FrameAction::Reject {
                response: String::new(),
            };
        };
        return FrameAction::Reject { response };
    }
    let Some(rewritten) = rewrite_frame(&value, decision.fields) else {
        return FrameAction::Forward;
    };
    FrameAction::Rewrite { bytes: rewritten }
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
        return FrameAction::Forward;
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
        set_dotted(object, &change.field, &change.value);
    }
    serde_json::to_string(&next).ok()
}

fn set_dotted(object: &mut Map<String, Value>, field: &str, text: &str) {
    let name = field.strip_prefix("arg.").unwrap_or(field);
    if let Some(params) = object.get_mut("params").and_then(Value::as_object_mut) {
        if let Some(arguments) = params.get_mut("arguments").and_then(Value::as_object_mut) {
            if arguments.contains_key(name) || name == "command" {
                arguments.insert(name.to_owned(), Value::String(text.to_owned()));
                return;
            }
        }
    }
    if let Some(result) = object.get_mut("result").and_then(Value::as_object_mut) {
        result.insert(name.to_owned(), Value::String(text.to_owned()));
    }
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
}
