# mass_delete

Rule: `crates/aw-pipeline/rules/mass_delete.toml` (version 1).
One step, `op = "delete"`, `within = "10s"`, `threshold = 50`.
The engine fires only when the count in the window is strictly greater than the threshold (`count > threshold`), and it groups by process and session.

- Lines 1–50 are fifty deletes from `proc_uid` 10, spaced 100 ms apart, so all fifty sit inside one 10 s window. Fifty is the boundary and should not fire.
- Line 51 is another delete from the same process, but 14.1 s after line 50, so it is outside that window. It is the non-match for the threshold.
- Line 52 is `op = "access"`, not a delete. The step's `where` should reject it.

`expected.json` is the `--json` stdout of `aw config rules test` on this input: `{"findings":[]}`. Fifty deletes in one window did not fire, the late delete did not fire, and the non-delete did not fire. A fifty-first delete inside the same 10 s window is what would cross the threshold; it is intentionally not in this file.
