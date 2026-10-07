# fixtures/db

Empty SQLite file produced by the P1 migrator. Schema only: no sessions, processes, flows, or other rows besides `schema_meta`.

## Generate

From the repository root, with PowerShell 7:

```text
Remove-Item -Force fixtures/db/v1.db, fixtures/db/v1.db-wal, fixtures/db/v1.db-shm -ErrorAction SilentlyContinue
cargo run -p aw-store --example init_empty --offline -- fixtures/db/v1.db
```

`init_empty` calls `aw_store::Store::open` and exits. That applies `crates/aw-store/migrations/0001_init.sql` and inserts four `schema_meta` rows in the same transaction:

| key | value |
|---|---|
| `schema_version` | `1` |
| `created_ns` | Unix time in nanoseconds when the file was generated |
| `app_version` | `CARGO_PKG_VERSION` of `aw-store` (`0.1.0`) |
| `host_id` | random UUID version 4 from SQLite `randomblob(16)`, not a hostname |

Do not copy a bench database or a machine capture into this path. Regenerating the file changes `created_ns` and `host_id`; both are still non-identifying.
