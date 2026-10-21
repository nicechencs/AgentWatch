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
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "text": "SECRET" }
        })
    } else {
        return;
    };
    let mut out = io::stdout().lock();
    let Ok(bytes) = serde_json::to_vec(&reply) else {
        return;
    };
    let _ = out.write_all(&bytes);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}
