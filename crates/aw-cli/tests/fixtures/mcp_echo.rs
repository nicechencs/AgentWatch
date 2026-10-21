//! Tiny MCP stdio stand-in for the `aw mcp-tap` integration test.
//!
//! Reads one JSON-RPC line from stdin, writes one JSON-RPC line to stdout, and
//! exits. `initialize` is echoed. `tools/call` answers with the command string
//! the server actually received, so a rewrite is visible and a deny (nothing
//! arrives) is visible too. No other method is answered.
//!
//! Argument values are written only into this process's stdout, which the test
//! captures. Nothing is written to a file.

use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
        // EOF before a frame. A denied `tools/call` closes stdin without
        // writing, and this process must exit so `aw mcp-tap` can exit too.
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
        let command = value
            .pointer("/params/arguments/command")
            .and_then(|item| item.as_str())
            .unwrap_or("");
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "command": command }
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
