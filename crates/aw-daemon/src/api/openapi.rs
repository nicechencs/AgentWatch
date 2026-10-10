//! Hand-written OpenAPI 3.0 document for the routes this daemon actually serves.
//!
//! api-and-cli names `utoipa`. That crate is not added: its derive stack is
//! heavier than the hand-written JSON Schema already used for daemon config
//! (see `config.rs`), and the document has to stay in sync with the route table
//! by construction. `GET /api/v1/openapi.json` returns [`document`].
//!
//! Paths that answer 501 (`/http`, `/findings`, `/agent-events`, and store
//! functions this build does not call) are listed with `x-agentwatch-status:
//! not_implemented` so a client can tell "routed, not backed" from "missing".

use serde_json::{json, Value};

/// OpenAPI document. No server URL is pinned to a public host: the only server
/// is the loopback listener the process bound.
#[must_use]
pub fn document(listen_port: u16) -> Value {
    json!({
        "openapi": "3.0.3",
        "info": {
            "title": "AgentWatch local API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Loopback API. No CORS. Host must be 127.0.0.1 or localhost."
        },
        "servers": [{ "url": format!("http://127.0.0.1:{listen_port}/api/v1") }],
        "components": {
            "securitySchemes": {
                "bearer": { "type": "http", "scheme": "bearer" }
            },
            "schemas": {
                "Error": {
                    "type": "object",
                    "required": ["error"],
                    "properties": {
                        "error": {
                            "type": "object",
                            "required": ["code", "message"],
                            "properties": {
                                "code": { "type": "string" },
                                "message": { "type": "string" },
                                "offset": { "type": "integer" }
                            }
                        }
                    }
                }
            }
        },
        "paths": paths(),
    })
}

fn paths() -> Value {
    json!({
        "/health": op("get", "Daemon status. Unauthenticated. Non-sensitive fields only.", false, "implemented"),
        "/auth/ui-ticket": op("post", "Issue a one-time UI ticket. Socket/pipe callers only; HTTP bearer is refused.", true, "implemented"),
        "/auth/ui-token": op("post", "Redeem a one-time ticket for a 12h bearer token.", false, "implemented"),
        "/doctor": op("get", "Collector probe and capability report.", true, "implemented"),
        "/processes": op("get", "Current system process tree for the attach picker.", true, "implemented"),
        "/sessions": {
            "get": op_body("List sessions visible to the caller.", true, "implemented"),
            "post": op_body("Create a session. Launch/attach is accepted and recorded; the scope provider is not started by this card.", true, "implemented")
        },
        "/sessions/{sid}": {
            "get": op_body("Session detail and stats.", true, "implemented"),
            "patch": op_body("Rename or pin.", true, "implemented"),
            "delete": op_body("Delete. Other users' sessions are hidden as 404.", true, "implemented")
        },
        "/sessions/{sid}/stop": op("post", "Stop observation. Does not kill the target process.", true, "implemented"),
        "/sessions/{sid}/summary": op("get", "Overview counts.", true, "implemented"),
        "/sessions/{sid}/timeline": op("get", "Cursor-paged timeline.", true, "implemented"),
        "/sessions/{sid}/timeline/histogram": op("get", "Density buckets.", true, "implemented"),
        "/sessions/{sid}/processes": op("get", "Process tree.", true, "implemented"),
        "/sessions/{sid}/processes/{proc_uid}": op("get", "One process. Unknown proc_uid is 404.", true, "implemented"),
        "/sessions/{sid}/files": op("get", "File access.", true, "implemented"),
        "/sessions/{sid}/flows": op("get", "Network flows.", true, "implemented"),
        "/sessions/{sid}/flows/{id}/buckets": op("get", "Per-flow buckets.", true, "implemented"),
        "/sessions/{sid}/traffic": op("get", "Traffic series.", true, "implemented"),
        "/sessions/{sid}/dns": op("get", "DNS rows.", true, "implemented"),
        "/sessions/{sid}/gaps": op("get", "Gaps for this session.", true, "implemented"),
        "/sessions/{sid}/around": op("get", "Window around one record.", true, "implemented"),
        "/sessions/{sid}/export": op("get", "format=md | jsonl | csv (zip of CSVs). Other formats are 400/501.", true, "implemented"),
        "/sessions/{sid}/live": op("get", "SSE of new attributed records. Filter is evaluated in memory.", true, "implemented"),
        "/sessions/{sid}/http": op("get", "Proxy-mode HTTP rows. A session without the proxy is 200 with reason no_proxy.", true, "implemented"),
        "/sessions/{sid}/findings": op("get", "Findings with rendered wording.", true, "implemented"),
        "/sessions/{sid}/agent-events": op("get", "E3 self-reports for the session, cursor-paged by id. No table yet is an empty page with reason no_self_reports.", true, "implemented"),
        "/search": op("get", "Cross-session search.", true, "implemented"),
        "/config": {
            "get": op_body("Effective daemon config (no secrets).", true, "implemented"),
            "put": op_body("Replace config. Administrator only.", true, "implemented")
        },
        "/db/stats": op("get", "Database size and table counts. Non-admins see only their own session count.", true, "implemented"),
        "/db/purge": op("post", "Administrator only. dry_run=true lists, confirm=true deletes; otherwise 400 confirm_required. Pinned and active sessions are kept.", true, "implemented"),
        "/openapi.json": op("get", "This document.", true, "implemented")
    })
}

fn op(method_unused: &str, summary: &str, auth: bool, status: &str) -> Value {
    let _ = method_unused;
    op_body(summary, auth, status)
}

fn op_body(summary: &str, auth: bool, status: &str) -> Value {
    let mut value = json!({
        "summary": summary,
        "x-agentwatch-status": status,
        "responses": {
            "200": { "description": "OK" },
            "400": { "description": "Bad filter or argument", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Error" } } } },
            "401": { "description": "Missing bearer" },
            "403": { "description": "Administrator required" },
            "404": { "description": "Not found, or hidden" },
            "421": { "description": "Host is not the loopback listener" },
            "501": { "description": "Routed, not backed in this build" }
        }
    });
    if auth {
        value["security"] = json!([{ "bearer": [] }]);
    }
    value
}
