# placeholder-process

One handwritten `process_start` event. It is not a capture from a machine.

- Platform, OS version, user name, and paths are placeholders (`placeholder`, `/tmp/placeholder`).
- No host name, token, request header, file content, or HTTP body is present.
- `recorded_at` is the authored timestamp `2026-10-07T00:00:00Z` (RFC 3339, UTC), not a clock reading.
- `expected.snap` repeats the event JSON so the `aw-core` fixture test can compare it without insta.
