# self_report_mismatch

Rule: `crates/aw-pipeline/rules/self_report_mismatch.toml` (version 1).
One step, `record = "self_report_mismatch"`, empty `where`.

- Line 1 is the record type the rule matches.
- Line 2 is a `file_access` of the same path. The rule does not read that type, so it is the non-match.

`expected.json` is the `--json` stdout of `aw config rules test` on this input. Line 1 produced one finding; line 2 did not.
