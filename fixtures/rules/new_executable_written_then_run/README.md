# new_executable_written_then_run

Rule: `crates/aw-pipeline/rules/new_executable_written_then_run.toml` (version 1).
Step `a` is `op = "create"`. Step `b` is `op = "exec" and path = a.path`, within 300s, same session.

- Lines 1–2 are a create then an exec of the same path, inside one session and inside the window.
- Lines 3–4 are a create of one path and an exec of a different path. The `path = a.path` term should not bind.

`expected.json` is the `--json` stdout of `aw config rules test` on this input. Lines 1–2 produced one finding. The `within` param rendered as `不可得`: the rule asks for `within`, and the engine only fills that name from a step that declares `within`. Step `b` declares it; the lookup reads step `a`, which does not. Lines 3–4 produced nothing.
