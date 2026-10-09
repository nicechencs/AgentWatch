# direct_bypass_proxy

Rule: `crates/aw-pipeline/rules/direct_bypass_proxy.toml` (version 1).
One step, `record = "net_flow"`, `where = "direct:true"`.

- Line 1 has `direct: true`.
- Line 2 is the same destination with `direct: false` and `via_proxy: true`. The `where` should reject it.

`remote.ip` is the loopback placeholder `127.0.0.1` with port 9 (discard). The domain is `api.agentwatch.test`. Nothing here is a real peer.

`expected.json` is the `--json` stdout of `aw config rules test` on this input. Line 1 produced one finding; line 2 did not.
