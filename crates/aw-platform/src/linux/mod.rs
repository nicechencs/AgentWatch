//! Linux launch remains in `aw-daemon::api::launch_as` for this track; no second gate is invented here.
use crate::{
    IdentifiedCaller, Owner, Platform, PlatformError, ProcessEntry, ProcessKey, ReapOutcome,
    SamplingProcess, SpawnRequest, UnsupportedKind,
};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::path::{Path, PathBuf};
use std::{fs, io};
pub(crate) struct CurrentPlatform;
fn no(capability: &'static str) -> PlatformError {
    PlatformError::Unsupported {
        capability,
        os: "linux",
        kind: UnsupportedKind::NotInThisBuild,
    }
}
fn entry(pid: u32) -> Result<Option<ProcessEntry>, PlatformError> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let stat = match fs::read_to_string(root.join("stat")) {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let tail = stat
        .rsplit_once(')')
        .ok_or(PlatformError::Invalid {
            capability: "process_identity",
            detail: "unreadable proc stat",
        })?
        .1
        .trim_start();
    let ppid = tail.split_whitespace().nth(1).and_then(|v| v.parse().ok());
    let start_time = tail
        .split_whitespace()
        .nth(19)
        .and_then(|v| v.parse().ok())
        .ok_or(PlatformError::Invalid {
            capability: "process_identity",
            detail: "missing proc start time",
        })?;
    let status = fs::read_to_string(root.join("status")).ok();
    let nums = |name: &str| {
        status
            .as_ref()?
            .lines()
            .find(|l| l.starts_with(name))
            .map(|l| {
                l[name.len()..]
                    .split_whitespace()
                    .filter_map(|v| v.parse().ok())
                    .collect::<Vec<u32>>()
            })
    };
    let owner = nums("Uid:").and_then(|u| {
        Some(Owner::Unix {
            ruid: *u.first()?,
            euid: *u.get(1)?,
            suid: *u.get(2)?,
            groups: nums("Groups:").unwrap_or_default(),
        })
    });
    let argv = fs::read(root.join("cmdline")).ok().map(|b| {
        b.split(|x| *x == 0)
            .filter(|x| !x.is_empty())
            .map(|x| String::from_utf8_lossy(x).into_owned())
            .collect()
    });
    Ok(Some(ProcessEntry {
        key: ProcessKey { pid, start_time },
        ppid,
        exe: fs::read_link(root.join("exe")).ok(),
        argv,
        owner,
    }))
}

fn boot_id() -> Result<Vec<u8>, PlatformError> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim();
    if value.is_empty() {
        return Err(PlatformError::Invalid {
            capability: "sampling_process",
            detail: "empty boot id",
        });
    }
    Ok(value.as_bytes().to_vec())
}

fn btime_secs() -> Result<u64, PlatformError> {
    let stat = fs::read_to_string("/proc/stat")?;
    stat.lines()
        .find_map(|line| line.strip_prefix("btime "))
        .and_then(|value| value.trim().parse().ok())
        .ok_or(PlatformError::Invalid {
            capability: "sampling_process",
            detail: "missing boot time",
        })
}

fn sampling_entry(
    pid: u32,
    boot: &[u8],
    btime: u64,
) -> Result<Option<SamplingProcess>, PlatformError> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let tail = stat
        .rsplit_once(')')
        .ok_or(PlatformError::Invalid {
            capability: "sampling_process",
            detail: "unreadable proc stat",
        })?
        .1
        .trim_start();
    let mut fields = tail.split_whitespace();
    let _state = fields.next();
    let ppid =
        fields
            .next()
            .and_then(|value| value.parse().ok())
            .ok_or(PlatformError::Invalid {
                capability: "sampling_process",
                detail: "missing parent pid",
            })?;
    let ticks = tail
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(PlatformError::Invalid {
            capability: "sampling_process",
            detail: "missing proc start time",
        })?;
    // Linux's clock tick value used by the poll collector.  Keeping this
    // conversion here means shared sampler code never reads /proc.
    const LINUX_CLK_TCK: u64 = 100;
    let start_ns = btime
        .checked_mul(1_000_000_000)
        .and_then(|base| {
            ticks
                .checked_mul(1_000_000_000)
                .map(|elapsed| base + elapsed / LINUX_CLK_TCK)
        })
        .ok_or(PlatformError::Invalid {
            capability: "sampling_process",
            detail: "invalid proc start time",
        })?;
    Ok(Some(SamplingProcess {
        key: ProcessKey {
            pid,
            start_time: ticks,
        },
        ppid,
        start_ns,
        boot_id: boot.to_vec(),
    }))
}
impl Platform for CurrentPlatform {
    fn os(&self) -> &'static str {
        "linux"
    }
    fn spawn_suspended(
        &self,
        caller: &IdentifiedCaller,
        _: &SpawnRequest,
    ) -> Result<Box<dyn crate::HeldChild>, PlatformError> {
        let _ = caller.owner();
        Err(no("spawn_suspended"))
    }
    fn process_identity(&self, pid: u32) -> Result<Option<ProcessEntry>, PlatformError> {
        entry(pid)
    }
    fn process_table(&self) -> Result<Vec<ProcessEntry>, PlatformError> {
        let mut out = Vec::new();
        for e in fs::read_dir("/proc")? {
            let e = e?;
            let Ok(pid) = e.file_name().to_string_lossy().parse() else {
                continue;
            };
            if let Some(v) = entry(pid)? {
                out.push(v)
            }
        }
        Ok(out)
    }
    fn sampling_process(&self, pid: u32) -> Result<Option<SamplingProcess>, PlatformError> {
        sampling_entry(pid, &boot_id()?, btime_secs()?)
    }
    fn sampling_process_table(&self) -> Result<Vec<SamplingProcess>, PlatformError> {
        let boot = boot_id()?;
        let btime = btime_secs()?;
        let mut out = Vec::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let Ok(pid) = entry.file_name().to_string_lossy().parse() else {
                continue;
            };
            if let Some(process) = sampling_entry(pid, &boot, btime)? {
                out.push(process);
            }
        }
        Ok(out)
    }
    fn reap_child(&self, key: ProcessKey) -> Result<ReapOutcome, PlatformError> {
        match waitpid(Pid::from_raw(key.pid as i32), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, c)) => Ok(ReapOutcome::Exited(c)),
            Ok(WaitStatus::Signaled(_, s, _)) => Ok(ReapOutcome::Signaled(s as i32)),
            Ok(WaitStatus::StillAlive) | Ok(_) => Ok(ReapOutcome::StillRunning),
            Err(nix::errno::Errno::ECHILD) => Ok(ReapOutcome::NotOurChild),
            Err(e) => Err(io::Error::from_raw_os_error(e as i32).into()),
        }
    }
    /// Explicit 0700 hardening lands with the Linux track; retain existing behavior.
    fn secure_data_dir(&self, p: &Path) -> Result<(), PlatformError> {
        fs::create_dir_all(p)?;
        Ok(())
    }
    fn default_data_dir(&self) -> Result<PathBuf, PlatformError> {
        Ok(PathBuf::from("/var/lib/agentwatch"))
    }
    fn default_config_path(&self) -> Result<PathBuf, PlatformError> {
        Ok(PathBuf::from("/etc/agentwatch/config.toml"))
    }
    fn is_privileged(&self) -> Option<bool> {
        aw_collector_linux::privilege::is_privileged()
    }
    fn current_user_id(&self) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        fs::metadata("/proc/self")
            .ok()
            .map(|meta| meta.uid().to_string())
    }
}
