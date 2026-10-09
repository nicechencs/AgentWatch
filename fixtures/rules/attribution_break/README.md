# attribution_break

Rule: `crates/aw-pipeline/rules/attribution_break.toml` (version 1).
One step, `record = "attribution_break"`, empty `where`.

- Line 1 is that record type.
- Line 2 is a `net_flow`. The rule does not read that type.

`expected.json` is the `--json` stdout of `aw config rules test` on this input. Line 1 produced one finding; line 2 did not.
