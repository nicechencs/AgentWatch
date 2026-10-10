//! Live process and connection adapters.
//!
//! [`crate::PollCollector::with_host`] is the only production constructor, and
//! collector unit tests use the static sources instead. One test in this module
//! builds a [`HostProcessSource`] restricted to the test process itself, to prove
//! that a child started after the baseline is returned.
//!
//! `sysinfo::System` and raw `netstat` text are not `Debug`: both can carry command
//! lines. Nothing in this module prints a process row.

use std::collections::HashSet;

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use aw_core::NaReason;

use crate::source::{
    ConnectionSnapshot, ConnectionSource, ProcessRow, ProcessSnapshot, ProcessSource,
    ProcessStartTime, SourceError,
};

/// Reads the process table through `sysinfo`.
///
/// Not `Debug`: the inner [`System`] retains command lines.
pub struct HostProcessSource {
    system: System,
    /// `None` returns every process. `Some(pids)` returns those pids and their
    /// descendants, and an empty slice touches nothing.
    restrict: Option<Vec<u32>>,
}

impl HostProcessSource {
    pub(crate) fn new() -> Self {
        Self {
            system: System::new(),
            restrict: None,
        }
    }
}

impl ProcessSource for HostProcessSource {
    fn snapshot(&mut self) -> Result<ProcessSnapshot, SourceError> {
        let kind = ProcessRefreshKind::nothing()
            .without_tasks()
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_cwd(UpdateKind::OnlyIfNotSet);
        if matches!(self.restrict.as_deref(), Some([])) {
            // Launch mode, or an attach whose roots are not in the table yet.
            // Do not scan the machine.
            return Ok(ProcessSnapshot {
                boot_id: read_boot_id(),
                rows: Vec::new(),
            });
        }
        // A pid list is not enough to refresh: `sysinfo` only discovers a pid it
        // is asked to enumerate, so refreshing just the watched pids would never
        // show a child started after the baseline (BUGS B4). The table is read
        // in full and narrowed to the watched subtree afterwards.
        self.system
            .refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
        let all: Vec<ProcessRow> = self
            .system
            .processes()
            .values()
            .map(row_from_process)
            .collect();
        let rows = match self.restrict.as_deref() {
            Some(roots) => keep_subtrees(all, roots),
            None => all,
        };
        Ok(ProcessSnapshot {
            boot_id: read_boot_id(),
            rows,
        })
    }

    fn set_restrict(&mut self, restrict: Option<&[u32]>) {
        self.restrict = restrict.map(<[u32]>::to_vec);
    }
}

/// Rows for `roots` and every descendant of them, by `ppid`.
///
/// A child whose parent is in the set is kept even when it appeared after the
/// last sample, and so is a grandchild started in the same interval. Rows
/// outside the subtrees are dropped here so the collector never sees them.
fn keep_subtrees(rows: Vec<ProcessRow>, roots: &[u32]) -> Vec<ProcessRow> {
    let mut keep: HashSet<u32> = roots.iter().copied().collect();
    loop {
        let before = keep.len();
        for row in &rows {
            if !keep.contains(&row.pid) && row.ppid.is_some_and(|ppid| keep.contains(&ppid)) {
                keep.insert(row.pid);
            }
        }
        if keep.len() == before {
            break;
        }
    }
    rows.into_iter()
        .filter(|row| keep.contains(&row.pid))
        .collect()
}

fn row_from_process(process: &sysinfo::Process) -> ProcessRow {
    let start = match process.start_time() {
        0 => ProcessStartTime::Unavailable,
        secs => ProcessStartTime::UnixSeconds(secs),
    };
    let ppid = process.parent().map(|pid| pid.as_u32());
    // `sysinfo` reports an empty path when `/proc/<pid>/exe` cannot be read.
    // An empty string is not a path, so it stays unavailable.
    let exe = process
        .exe()
        .filter(|path| !path.as_os_str().is_empty())
        .and_then(|path| path.to_str().map(str::to_owned));
    // Windows hides the command line without elevation. An empty list is that
    // case, not "the process had no arguments". Do not elevate.
    let argv = {
        let cmd = process.cmd();
        if cmd.is_empty() {
            None
        } else {
            let mut args = Vec::with_capacity(cmd.len());
            let mut lossy = false;
            for part in cmd {
                match part.to_str() {
                    Some(text) => args.push(text.to_owned()),
                    None => lossy = true,
                }
            }
            if lossy {
                None
            } else {
                Some(args)
            }
        }
    };
    let cwd = process
        .cwd()
        .filter(|path| !path.as_os_str().is_empty())
        .and_then(|path| path.to_str().map(str::to_owned));
    // `sysinfo::Uid` is not displayed. Looking it up would also yield a user
    // name, which this crate does not store.
    ProcessRow {
        pid: process.pid().as_u32(),
        ppid,
        start,
        exe,
        argv,
        cwd,
        user_id: None,
    }
}

/// Connection listing. On Windows this runs `netstat -ano` with no elevation.
/// On every other target [`ConnectionSource::snapshot`] returns an empty table
/// and [`ConnectionSource::unavailable_reason`] explains that, so the collector
/// declares net as `NA` instead of emitting a gap on every tick.
///
/// Not `Debug`: a failed spawn must not be formatted with the command line.
pub struct HostConnectionSource {
    unavailable: Option<NaReason>,
}

impl HostConnectionSource {
    pub(crate) fn new() -> Self {
        Self {
            unavailable: platform_net_unavailable(),
        }
    }
}

impl ConnectionSource for HostConnectionSource {
    fn snapshot(&mut self) -> Result<ConnectionSnapshot, SourceError> {
        if self.unavailable.is_some() {
            return Ok(ConnectionSnapshot::default());
        }
        read_netstat()
    }

    fn unavailable_reason(&self) -> Option<NaReason> {
        self.unavailable.clone()
    }
}

/// `Some` where this build has no connection lister.
///
/// Windows can run `netstat -ano` without elevation. Other targets return an
/// empty stub rather than failing to compile.
fn platform_net_unavailable() -> Option<NaReason> {
    if cfg!(windows) {
        None
    } else {
        Some(NaReason::CollectorUnavailable)
    }
}

#[cfg(windows)]
fn read_netstat() -> Result<ConnectionSnapshot, SourceError> {
    let output = std::process::Command::new("netstat")
        .args(["-ano"])
        .output()
        .map_err(|_| SourceError::disconnected())?;
    if !output.status.success() {
        return Err(SourceError::permission());
    }
    // Lossy would invent characters inside an address. Non-UTF8 is a failed sample.
    let text = std::str::from_utf8(&output.stdout).map_err(|_| SourceError::parse())?;
    crate::netstat::parse_netstat_ano(text)
}

#[cfg(not(windows))]
fn read_netstat() -> Result<ConnectionSnapshot, SourceError> {
    Ok(ConnectionSnapshot::default())
}

/// Boot identity used as the `proc_uid` hash input.
///
/// * Linux: `/proc/sys/kernel/random/boot_id` (ADR-0007). Not `sysinfo`'s
///   `boot_time`, which is `/proc/stat` `btime` or an uptime fallback.
/// * Windows: `System::boot_time()`, which is `GetTickCount64` subtracted from
///   the wall clock and rounded down to seconds. `0` and `u64::MAX` mean the
///   helper failed.
/// * macOS: `System::boot_time()` is `sysctl(KERN_BOOTTIME)` (`kern.boottime`).
///   process-tracking names that value; ADR-0007 names `kern.bootsessionuuid`.
///   This crate does not add the sysctl FFI for the UUID. A non-zero value is
///   the decimal seconds. `0` is unavailable.
/// * Anything else: unavailable. An empty slice is never returned.
fn read_boot_id() -> Option<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        read_linux_boot_id()
    }
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        read_sysinfo_boot_seconds()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn read_linux_boot_id() -> Option<Vec<u8>> {
    // Kernel path, not a user home. Failure or an empty file is "no boot id".
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.as_bytes().to_vec())
    }
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn read_sysinfo_boot_seconds() -> Option<Vec<u8>> {
    let secs = System::boot_time();
    if secs == 0 || secs == u64::MAX {
        None
    } else {
        Some(secs.to_string().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::keep_subtrees;
    use crate::source::{ProcessRow, ProcessSource, ProcessStartTime};

    fn row(pid: u32, ppid: Option<u32>) -> ProcessRow {
        ProcessRow::bare(pid, ppid, ProcessStartTime::UnixSeconds(1_700_000_000))
    }

    fn pids(rows: &[ProcessRow]) -> Vec<u32> {
        let mut out: Vec<u32> = rows.iter().map(|row| row.pid).collect();
        out.sort_unstable();
        out
    }

    #[test]
    fn subtree_keeps_new_children_and_grandchildren_only() {
        let rows = vec![
            row(1, None),
            row(10, Some(1)),
            row(11, Some(10)),
            row(12, Some(11)),
            row(20, Some(2)),
        ];
        assert_eq!(pids(&keep_subtrees(rows.clone(), &[10])), vec![10, 11, 12]);
        assert_eq!(pids(&keep_subtrees(rows, &[1])), vec![1, 10, 11, 12]);
    }

    /// BUGS B4: the host source only refreshed the watched pids, so a process
    /// started after the baseline never appeared. This spawns a real child of
    /// the test process and expects the restricted snapshot to return it.
    #[test]
    fn restricted_host_snapshot_sees_a_child_started_later() {
        let me = std::process::id();
        let mut source = super::HostProcessSource::new();
        source.set_restrict(Some(&[me]));
        let before = source.snapshot().map(|snap| pids(&snap.rows));
        assert!(before.as_ref().is_ok_and(|rows| rows.contains(&me)));

        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        // Re-run this test binary on a test that only sleeps, so the child is
        // alive while the next snapshot is taken. Works on every runner.
        let child = std::process::Command::new(exe)
            .args([
                "--exact",
                "host::tests::sleeper_for_child_test",
                "--ignored",
                "--test-threads=1",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let Ok(mut child) = child else {
            panic!("could not spawn the child test process");
        };
        let child_pid = child.id();
        let mut seen = false;
        for _ in 0..20 {
            if source
                .snapshot()
                .is_ok_and(|snap| snap.rows.iter().any(|row| row.pid == child_pid))
            {
                seen = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
        assert!(seen, "a child started after the baseline must be returned");
    }

    #[test]
    #[ignore = "helper process for restricted_host_snapshot_sees_a_child_started_later"]
    fn sleeper_for_child_test() {
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
