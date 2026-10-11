use crate::{
    Capability, CapabilityStatus, HeldChild, IdentifiedCaller, Owner, PeerIdentity, Platform,
    PlatformError, ProcessEntry, ProcessKey, ReapOutcome, ReleasedChild, SamplingProcess,
    SpawnRequest, UnsupportedKind,
};
use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};
use nix::unistd::{pipe2, write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::{fs, io};

pub(crate) struct CurrentPlatform;

fn no(capability: &'static str) -> PlatformError {
    PlatformError::Unsupported {
        capability,
        os: "linux",
        kind: UnsupportedKind::NotInThisBuild,
    }
}

pub fn identify_unix_peer(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerIdentity, PlatformError> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials).map_err(
            |_| PlatformError::PeerNotIdentified {
                reason: "SO_PEERCRED unavailable",
            },
        )?;
    let pid = u32::try_from(credentials.pid()).map_err(|_| PlatformError::PeerNotIdentified {
        reason: "SO_PEERCRED returned an invalid pid",
    })?;
    // SO_PEERCRED is captured by the kernel for this connection. Do not use
    // /proc for its uid/gid: the pid can exit and be reused between the two
    // reads. `/proc/<pid>/status` is only a best-effort source of groups.
    let uid = credentials.uid();
    let gid = credentials.gid();
    let groups = peer_groups(pid, uid)?;
    let owner = Owner::Unix {
        ruid: uid,
        euid: uid,
        suid: uid,
        rgid: gid,
        egid: gid,
        sgid: gid,
        groups,
    };
    Ok(PeerIdentity::new(owner, Some(pid)))
}

/// Return groups only when `/proc` still describes the peer authenticated by
/// `SO_PEERCRED`. A missing or unreadable proc entry leaves groups unavailable;
/// it must not turn an otherwise authenticated peer into an unknown caller.
fn peer_groups(pid: u32, peer_uid: u32) -> Result<Option<Vec<u32>>, PlatformError> {
    let status = match fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(status) => status,
        Err(_) => return Ok(None),
    };
    let Some(Owner::Unix {
        ruid,
        groups: Some(groups),
        ..
    }) = owner_from_status(&status)
    else {
        return Ok(None);
    };
    if ruid != peer_uid {
        return Err(PlatformError::PeerNotIdentified {
            reason: "peer pid ownership changed while reading proc status",
        });
    }
    Ok(Some(groups))
}

fn owner_from_status(status: &str) -> Option<Owner> {
    let numbers = |name: &str| {
        status
            .lines()
            .find(|line| line.starts_with(name))
            .map(|line| {
                line[name.len()..]
                    .split_whitespace()
                    .filter_map(|value| value.parse().ok())
                    .collect::<Vec<u32>>()
            })
    };
    let uid = numbers("Uid:")?;
    let gid = numbers("Gid:")?;
    Some(Owner::Unix {
        ruid: *uid.first()?,
        euid: *uid.get(1)?,
        suid: *uid.get(2)?,
        rgid: *gid.first()?,
        egid: *gid.get(1)?,
        sgid: *gid.get(2)?,
        groups: Some(numbers("Groups:").unwrap_or_default()),
    })
}

fn entry(pid: u32) -> Result<Option<ProcessEntry>, PlatformError> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let stat = match fs::read_to_string(root.join("stat")) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let tail = stat
        .rsplit_once(')')
        .ok_or(PlatformError::Invalid {
            capability: "process_identity",
            detail: "unreadable proc stat",
        })?
        .1
        .trim_start();
    let ppid = tail
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok());
    let start_time = tail
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse().ok())
        .ok_or(PlatformError::Invalid {
            capability: "process_identity",
            detail: "missing proc start time",
        })?;
    let owner = fs::read_to_string(root.join("status"))
        .ok()
        .and_then(|status| owner_from_status(&status));
    let argv = fs::read(root.join("cmdline")).ok().map(|bytes| {
        bytes
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
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
    let ppid = tail
        .split_whitespace()
        .nth(1)
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

const GATE_FD_ENV: &str = "AW_PLATFORM_GATE_FD";

struct LinuxHeldChild {
    child: Option<Child>,
    release_fd: Option<OwnedFd>,
}
struct LinuxReleasedChild {
    child: Child,
}

fn reap_outcome(status: std::process::ExitStatus) -> ReapOutcome {
    match status.code() {
        Some(code) => ReapOutcome::Exited(code),
        None => ReapOutcome::Signaled(status.signal().unwrap_or_default()),
    }
}

impl LinuxHeldChild {
    fn terminate(&mut self) -> Result<(), PlatformError> {
        self.release_fd.take();
        if let Some(mut child) = self.child.take() {
            match child.kill() {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
                Err(error) => return Err(error.into()),
            }
            let _ = child.wait();
        }
        Ok(())
    }
}
impl Drop for LinuxHeldChild {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}
impl HeldChild for LinuxHeldChild {
    fn pid(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }
    fn release(mut self: Box<Self>) -> Result<Box<dyn ReleasedChild>, PlatformError> {
        #[cfg(feature = "test-hold-delay")]
        if let Some(delay) = hold_delay() {
            std::thread::sleep(std::time::Duration::from_millis(delay.min(10_000)));
        }
        let fd = self.release_fd.take().ok_or(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "child has already been released",
        })?;
        let mut remaining = &b"1\n"[..];
        while !remaining.is_empty() {
            match write(&fd, remaining) {
                Ok(0) => {
                    return Err(PlatformError::Invalid {
                        capability: "spawn_suspended",
                        detail: "gate accepted no release data",
                    })
                }
                Ok(written) => remaining = &remaining[written..],
                Err(error) => return Err(io::Error::from_raw_os_error(error as i32).into()),
            }
        }
        let child = self.child.take().ok_or(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "held child is unavailable",
        })?;
        Ok(Box::new(LinuxReleasedChild { child }))
    }
    fn abort(&mut self) -> Result<(), PlatformError> {
        self.terminate()
    }
}

#[cfg(feature = "test-hold-delay")]
fn hold_delay() -> Option<u64> {
    std::env::var("AW_TEST_HOLD_DELAY_MS")
        .ok()?
        .parse::<u64>()
        .ok()
        .map(|delay| delay.min(10_000))
}
impl ReleasedChild for LinuxReleasedChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }
    fn try_reap(&mut self) -> Result<ReapOutcome, PlatformError> {
        Ok(self
            .child
            .try_wait()?
            .map_or(ReapOutcome::StillRunning, reap_outcome))
    }
    fn wait(mut self: Box<Self>) -> Result<ReapOutcome, PlatformError> {
        Ok(reap_outcome(self.child.wait()?))
    }
}

fn spawn_gate(request: &SpawnRequest) -> Result<Box<dyn HeldChild>, PlatformError> {
    let (read_fd, write_fd) =
        pipe2(OFlag::O_CLOEXEC).map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    let fd_number = read_fd.as_raw_fd();
    let flags = fcntl(&read_fd, FcntlArg::F_GETFD)
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    let flags = FdFlag::from_bits_truncate(flags) & !FdFlag::FD_CLOEXEC;
    fcntl(&read_fd, FcntlArg::F_SETFD(flags))
        .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    let (program, args) = request
        .command
        .split_first()
        .ok_or(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "empty command",
        })?;
    // The shell exits before exec on EOF. The inherited descriptor is closed
    // before target exec, so released programs have no daemon-death coupling.
    let script =
        format!("IFS= read -r _ <&{fd_number} || exit 125; exec {fd_number}<&-; exec \"$@\"");
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(script)
        .arg("aw-platform")
        .arg(program)
        .args(args);
    if let Some(cwd) = &request.cwd {
        command.current_dir(cwd);
    }
    command.envs(request.env.iter().map(|(key, value)| (key, value)));
    command.env_remove(GATE_FD_ENV);
    let child = command.spawn()?;
    drop(read_fd);
    Ok(Box::new(LinuxHeldChild {
        child: Some(child),
        release_fd: Some(write_fd),
    }))
}

impl Platform for CurrentPlatform {
    fn os(&self) -> &'static str {
        "linux"
    }
    fn capability(&self, capability: Capability) -> CapabilityStatus {
        match capability {
            Capability::SpawnSuspended
            | Capability::SpawnAsCaller
            | Capability::ProcessIdentity
            | Capability::ProcessTable
            | Capability::PeerIdentity
            | Capability::ExitCode => CapabilityStatus::Available,
            Capability::SecureDataDir => CapabilityStatus::NotInThisBuild,
        }
    }
    fn spawn_suspended(
        &self,
        caller: &IdentifiedCaller,
        request: &SpawnRequest,
    ) -> Result<Box<dyn HeldChild>, PlatformError> {
        if caller.owner() != &self.current_owner()? {
            return Err(no("spawn_suspended_for_other_user"));
        }
        spawn_gate(request)
    }
    fn process_identity(&self, pid: u32) -> Result<Option<ProcessEntry>, PlatformError> {
        entry(pid)
    }
    fn process_table(&self) -> Result<Vec<ProcessEntry>, PlatformError> {
        let mut result = Vec::new();
        for item in fs::read_dir("/proc")? {
            let item = item?;
            let Ok(pid) = item.file_name().to_string_lossy().parse() else {
                continue;
            };
            if let Some(process) = entry(pid)? {
                result.push(process);
            }
        }
        Ok(result)
    }
    fn sampling_process(&self, pid: u32) -> Result<Option<SamplingProcess>, PlatformError> {
        sampling_entry(pid, &boot_id()?, btime_secs()?)
    }
    fn sampling_process_table(&self) -> Result<Vec<SamplingProcess>, PlatformError> {
        let boot = boot_id()?;
        let btime = btime_secs()?;
        let mut result = Vec::new();
        for item in fs::read_dir("/proc")? {
            let item = item?;
            let Ok(pid) = item.file_name().to_string_lossy().parse() else {
                continue;
            };
            if let Some(process) = sampling_entry(pid, &boot, btime)? {
                result.push(process);
            }
        }
        Ok(result)
    }
    fn secure_data_dir(&self, _: &Path) -> Result<(), PlatformError> {
        Err(no("secure_data_dir"))
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
        self.current_owner().ok().and_then(|owner| match owner {
            Owner::Unix { euid, .. } => Some(euid.to_string()),
            Owner::Windows { .. } => None,
        })
    }
    fn current_owner(&self) -> Result<Owner, PlatformError> {
        entry(std::process::id())?
            .and_then(|process| process.owner)
            .ok_or(PlatformError::PeerNotIdentified {
                reason: "current process ownership is unavailable",
            })
    }
}

/// `PRETTY_NAME` from `/etc/os-release`. `None` when the file or the field is
/// missing: the caller prints 「不可得」, never an empty string.
pub fn os_version() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    for line in text.lines() {
        let value = line.strip_prefix("PRETTY_NAME=")?;
        let value = value.trim().trim_matches('"').trim();
        if !value.is_empty() {
            return Some(value.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "test-hold-delay")]
    use super::hold_delay;

    #[cfg(not(feature = "test-hold-delay"))]
    #[test]
    fn delay_off() {
        assert!(!std::hint::black_box(cfg!(feature = "test-hold-delay")));
    }

    #[cfg(feature = "test-hold-delay")]
    #[test]
    fn delay_is_capped_inside_release() {
        std::env::set_var("AW_TEST_HOLD_DELAY_MS", "10001");
        assert_eq!(hold_delay(), Some(10_000));
        std::env::remove_var("AW_TEST_HOLD_DELAY_MS");
    }
}
