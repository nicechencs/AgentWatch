# fixtures/rules

One directory per rule file in `crates/aw-pipeline/rules/`.

`input.jsonl` is the line shape `aw config rules test` documents: one JSON
object per line, with `record` (or `record_type`), `id`, `ts_ns`, and the
`fields` / `numbers` / `bools` / `params` / `tags` the matcher reads. A `#`
line is a comment. Paths are placeholders (`/tmp/placeholder/...`). Names are
`placeholder`. Hosts are under `agentwatch.test`. No file contents are stored.

`expected.json` is the stdout of

```
aw config rules test crates/aw-pipeline/rules/<id>.toml fixtures/rules/<id>/input.jsonl --json
```

captured from that command, not written by hand. The wording renderer redacts
path segments that look like a home directory, so a saved sentence may say
`«redacted:path»` where the input said `.ssh`. Re-run the command with
`--expect fixtures/rules/<id>/expected.json` to check.

`sensitive_paths/` has no `expected.json`. That toml is the glob table, not a
correlation rule, and the same command refuses it (`missing [rule]`).
