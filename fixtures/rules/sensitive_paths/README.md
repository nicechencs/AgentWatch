# sensitive_paths

Source data: `crates/aw-pipeline/rules/sensitive_paths.toml`.
That file is the sensitive-path glob table (`[[rule]]` with `glob` / `exclude`), not a correlation rule. `rules/load.rs` does not compile it in, and `aw config rules test` would not load it as one rule.

- Line 1 is a read of a path shaped like an SSH private key, tagged `sensitive.ssh-keys`, which is what the `ssh-keys` glob is for.
- Line 2 is a `*.pub` path. The `ssh-keys` rule excludes `~/.ssh/**/*.pub`, so a tagger should not mark it. The line carries no tag.

`/tmp/placeholder/home` stands in for `~`. No key material is in this file.

No `expected.json`. `aw config rules test crates/aw-pipeline/rules/sensitive_paths.toml fixtures/rules/sensitive_paths/input.jsonl` exits 1 with `missing [rule]`. The file is not a correlation rule, so there is no engine output to save.
