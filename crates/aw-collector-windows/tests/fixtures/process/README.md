# Hand-written Kernel-Process fixtures

These files are **not** an ETW recording. This machine is not an elevated
session, and SPIKE-02 was never run with a live trace, so nothing here was
captured with `logman`, `eslogger`, or ferrisetw.

Each line is one event this crate's decoder accepts: the property names from
`docs/02-platforms/windows.md` §2.1, plus the envelope fields the unit test
needs (`event_id`, `boot_id`, `seq`, `ts_mono_ns`, `ts_wall_ns`). Property
names that windows.md does not list are not invented.

`command_line_absent` omits `CommandLine` on purpose. The decoder must mark
`argv` as `NA(collector_unavailable)` and leave the value unset. The back-fill
that would turn that into evidence S is not in the fixture; the unit test
drives it with a fake reader.
