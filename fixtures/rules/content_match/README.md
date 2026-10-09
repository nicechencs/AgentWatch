# content_match

Rule: `crates/aw-pipeline/rules/content_match.toml` (version 1).
One step, `record = "content_match"`, empty `where`. The rule does not compute a hash. It only words and dedups a match some other stage already recorded.

- Line 1 is that record type. `matched`, `total`, and `pct` are template params, not a claim that a hash was computed here.
- Line 2 is the file read that would have preceded a real match. This rule does not read `file_access`.

The URL host is `api.agentwatch.test`. No request body and no file bytes are stored.

`expected.json` is the `--json` stdout of `aw config rules test` on this input. Line 1 produced one finding. The rendered path redacts the `.ssh` segment. Line 2 produced nothing.
