# fixtures

Recorded or handwritten `RawEvent` streams used by unprivileged replay tests.

## Layout

```text
fixtures/
├── README.md
└── common/
    └── <case>/
        ├── events.jsonl
        ├── expected.snap
        └── README.md
```

`<case>` is kebab-case and names the scenario (`placeholder-process`). Platform-specific captures, when a recorder exists, go under `fixtures/<platform>/<case>/` with the same three files. This tree is handwritten only.

## File format

`events.jsonl` is UTF-8. Line 1 is a header object. Each later line is one `RawEvent` JSON value (internally tagged `kind`). A trailing newline after the last event is fine. A blank line is an error; lines are never skipped.

Header fields, in the P0-SIM-01 contract:

| Field | Meaning |
|---|---|
| `v` | Schema major version. Must equal `SCHEMA_VERSION` (currently 1). A mismatch is an error that names both the found version and the expected version. |
| `platform` | Platform label. Use `placeholder` until the event was actually recorded on that platform. |
| `os_version` | OS version string. Use `placeholder` in handwritten cases. Not a hostname. |
| `collector` | One collector name, or `handwritten`. A single string, not an array. |
| `recorded_at` | Author-chosen RFC 3339 UTC timestamp (`2026-10-07T00:00:00Z`). It is not read from the clock when the file is loaded. |
| `scenario` | Same name as the case directory. |

`FixtureReader` and `FixtureWriter` in `aw-core` (`crates/aw-core/src/fixture.rs`) read and write this shape.

Draft docs (`docs/05-dev/testing.md`, `docs/05-dev/repo-layout.md`) show an older header (`fixture_header`, `collectors` as an array). Those docs are not changed by this task. Readers accept the fields in the table above.

## Recording

There is no recorder yet. Cases in this directory are handwritten JSON that already matches `RawEvent`. Do not invent a CLI to produce them.

When a recorder exists, a real capture must be scrubbed before commit. There is no `aw fixtures scrub` command yet. Until there is one, do not commit a capture from a machine: replace identifiers by hand, or do not add the file.

## Placeholders

Fixtures must not contain real usernames, hostnames, tokens, `Authorization` values, `Cookie` values, file contents, or HTTP bodies.

| Kind of value | Placeholder |
|---|---|
| User name | `placeholder` |
| Host | `placeholder` |
| Filesystem path | `/tmp/placeholder` |
| URL host | `example.test` |

`expected.snap` is plain text committed next to the JSONL. The `aw-core` fixture test compares the decoded sample event to the JSON object in that file. It is not an insta snapshot under `crates/aw-core/tests/snapshots/`.

## Compression

`.jsonl.zst` is not implemented. `FixtureReader` and `FixtureWriter` refuse a path whose file name ends in `.zst` (any case) and return:

```text
zstd fixtures are not implemented yet
```

No compression crate is linked. Do not treat a `.zst` path as a readable fixture.
