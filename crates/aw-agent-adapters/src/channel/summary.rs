//! Bound an `AgentToolCall` before it is retained.
//!
//! security-privacy §3 and the task card: `summary` keeps structured fields
//! only (tool name, path, command, URL), never a prompt, model output, or file
//! contents, and one call is at most 4 KB. This is a size-and-shape gate. The
//! pipeline Redact stage (ADR-0012) still has to run before a real database
//! write; this crate does not call it, and this function does not pretend to
//! be that stage.

use serde_json::{Map, Value};

use aw_core::AgentToolCall;

/// One stored call, JSON-encoded, must fit in this many bytes.
pub const MAX_CALL_BYTES: usize = 4 * 1024;

/// Keys a summary is allowed to keep. Anything else is dropped, not truncated:
/// a prompt or a file body must not survive as a shorter string.
const SUMMARY_KEYS: &[&str] = &["command", "path", "url", "query", "tool"];

/// Cap string fields and `summary`, then drop the call's JSON if it is still
/// over [`MAX_CALL_BYTES`]. `None` means the call cannot be retained at this
/// size; the caller records a gap instead of writing a partial secret.
#[must_use]
pub fn bound_tool_call(call: AgentToolCall) -> Option<AgentToolCall> {
    let mut call = call;
    call.agent = truncate_chars(&call.agent, 64);
    call.tool = truncate_chars(&call.tool, 128);
    call.agent_session = call
        .agent_session
        .map(|value| truncate_chars(&value, 128))
        .filter(|value| !value.is_empty());
    call.call_id = call
        .call_id
        .map(|value| truncate_chars(&value, 128))
        .filter(|value| !value.is_empty());
    call.summary = keep_structured(call.summary);
    let encoded = serde_json::to_vec(&call).ok()?;
    if encoded.len() > MAX_CALL_BYTES {
        None
    } else {
        Some(call)
    }
}

fn keep_structured(summary: Value) -> Value {
    let Value::Object(map) = summary else {
        return Value::Object(Map::new());
    };
    let mut kept = Map::new();
    for key in SUMMARY_KEYS {
        let Some(value) = map.get(*key) else {
            continue;
        };
        let Value::String(text) = value else {
            continue;
        };
        // A structured field, not a document. 512 bytes is enough for a path,
        // a command line, or a URL, and far too small for a prompt or a file.
        kept.insert((*key).to_owned(), Value::String(truncate_chars(text, 512)));
    }
    Value::Object(kept)
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
