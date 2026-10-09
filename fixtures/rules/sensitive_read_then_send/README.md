# sensitive_read_then_send

Rule: `crates/aw-pipeline/rules/sensitive_read_then_send.toml` (version 1).
Evidence stays `I` on every path. `upgrade_if` only picks a wording template.

Step `a`: `file_access` with `op = "access"`, `access` in `read` or `read_write`, and a `sensitive` tag.
Step `b`: `net_flow` with `bytes_up > 0` and not loopback, within 10s, same session.
Wording, from the flow's flags: no `proxy_enabled` selects `infer.temporal_no_proxy`; `proxy_enabled` and `hash_compared` selects `infer.temporal_hash_miss`; otherwise `infer.temporal`.

- Lines 1–2 are a sensitive read and, 2 s later in the same session, a non-loopback send of 412 bytes with `proxy_enabled` and `hash_compared` false. That is the proxy, not-yet-compared shape.
- Lines 3–4 repeat the pair 20 s later, which is outside the 10 s window, and the flow has `proxy_enabled` false. The window should keep them apart. The flag is recorded so a closer pair would be the no-proxy wording, not so this pair is claimed to match.
- Lines 5–6 are a read with no sensitive tag and a loopback flow with `bytes_up = 0`, in another session. Neither step's `where` should accept them.

`remote.ip` is `127.0.0.1` and the domain is `api.agentwatch.test`. No file bytes and no request body are stored. The 412 is a length, matching the bait size in `sim/scenarios/read_then_send.toml`, not content.

`expected.json` is the `--json` stdout of `aw config rules test` on this input. Lines 1–2 produced one finding, evidence `I`, wording `infer.temporal`. The `delta` param rendered as `不可得`: no record carries that name, and the engine does not compute it. Lines 3–6 produced nothing.
