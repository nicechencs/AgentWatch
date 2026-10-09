# sensitive_access

Rule: `crates/aw-pipeline/rules/sensitive_access.toml` (version 1).
One step, `where = 'tag:sensitive'`. The engine treats that as any tag equal to `sensitive` or starting with `sensitive.`.

- Line 1 carries `sensitive.ssh-keys`. That is the hit shape.
- Line 2 is a read of a non-sensitive path and has no tag. That is the miss.

`/tmp/placeholder/...` stands in for a home path. This file does not store file contents.

`expected.json` is the `--json` stdout of `aw config rules test` on this input. Line 1 produced one finding. The rendered path redacts the `.ssh` segment. Line 2 produced nothing.
