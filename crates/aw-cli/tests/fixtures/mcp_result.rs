//! MCP stdio stand-in that answers `tools/call` with a fixed result.
//!
//! `aw mcp-tap` integration tests need a server whose response carries a
//! field a rule can match (`result.text`). The echo stand-in answers with the
//! command the server received, which is the request direction. This one
//! always answers `{"result":{"text":"SECRET"}}`, so a response rewrite is
//! visible on the client's stdout.
//!
//! `initialize` is answered like the echo stand-in. Any other method exits
//! without a reply. Nothing is written to a file.
//!
//! `AW_MCP_RESULT_TEXT` (when set and non-empty) replaces the fixed `"SECRET"`
//! in a `tools/call` result. Tests that need a result the rule cannot rewrite
//! set it; the default stays `"SECRET"` so existing callers do not change.

use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let value: serde_json::Value = match serde_json::from_str(line.trim()) {
        Ok(value) => value,
        Err(_) => return,
    };
    // A batch is one array. Answer each element, so a test can see which
    // response elements the tap rewrote and which it replaced with an error.
    if let Some(items) = value.as_array() {
        let replies: Vec<serde_json::Value> = items.iter().filter_map(reply_for).collect();
        if replies.is_empty() {
            return;
        }
        write_stdout(&serde_json::Value::Array(replies));
        return;
    }
    let Some(reply) = reply_for(&value) else {
        return;
    };
    write_stdout(&reply);
}

fn reply_for(value: &serde_json::Value) -> Option<serde_json::Value> {
    let id = value.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let method = value
        .get("method")
        .and_then(|item| item.as_str())
        .unwrap_or("");
    let reply = if method == "initialize" {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "protocolVersion": "2024-11-05" }
        })
    } else if method == "tools/call" {
        let text = std::env::var("AW_MCP_RESULT_TEXT")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "SECRET".to_owned());
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "text": text }
        })
    } else {
        return None;
    };
    Some(reply)
}

fn write_stdout(reply: &serde_json::Value) {
    let mut out = io::stdout().lock();
    let Ok(bytes) = serde_json::to_vec(reply) else {
        return;
    };
    let _ = out.write_all(&bytes);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}
