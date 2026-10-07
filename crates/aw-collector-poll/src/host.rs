//! Live process and connection adapters.
//!
//! Tests do not construct these types. [`crate::PollCollector::with_host`] is the
//! only constructor that does, and unit tests use the static sources instead.
//!
//! `sysinfo::System` and raw `netstat` text are not `Debug`: both can carry command
//! lines. Nothing in this module prints a process row.

use std::process::Command;

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use aw_core::NaReason;

use crate::netstat::parse_netstat_ano;
use crate::source::{
    ConnectionSnapshot, ConnectionSource, ProcessRow, ProcessSnapshot, ProcessSource,
    ProcessStartTime, SourceError,
};

/// Reads the process table through `sysinfo`.
///
/// Not `Debug`: the inner [`System`] retains command lines.
pub(crate) struct HostProcessSource {
    system: System,
    /// `None` refreshes every process. `Some` refreshes only those pids, and an
    /// empty slice refreshes nothing.
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
        match self.restrict.as_deref() {
            Some([]) => {
                // Launch mode, or an attach whose roots are not in the table yet.
                // Do not scan the machine.
            }
            Some(pids) => {
                let owned: Vec<Pid> = pids.iter().copied().map(Pid::from_u32).collect();
                self.system.refresh_processes_specifics(
                    ProcessesToUpdate::Some(&owned),
                    true,
                    kind,
                );
            }
            None => {
                self.system
                    .refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
            }
        }
        let mut rows = Vec::new();
        for process in self.system.processes().values() {
            let pid = process.pid().as_u32();
            if let Some(only) = self.restrict.as_deref() {
                if !only.contains(&pid) {
                    continue;
                }
            }
            rows.push(row_from_process(process));
        }
        Ok(ProcessSnapshot {
            boot_id: read_boot_id(),
            rows,
        })
    }

    fn set_restrict(&mut self, restrict: Option<&[u32]>) {
        self.restrict = restrict.map(<[u32]>::to_vec);
    }
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
pub(crate) struct HostConnectionSource {
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
    let output = Command::new("netstat")
        .args(["-ano"])
        .output()
        .map_err(|_| SourceError::disconnected())?;
    if !output.status.success() {
        return Err(SourceError::permission());
    }
    // Lossy would invent characters inside an address. Non-UTF8 is a failed sample.
    let text = std::str::from_utf8(&output.stdout).map_err(|_| SourceError::parse())?;
    parse_netstat_ano(text)
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
