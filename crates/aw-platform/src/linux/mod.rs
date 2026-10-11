use crate::{
    Capability, CapabilityStatus, HeldChild, IdentifiedCaller, Owner, PeerIdentity, Platform,
    PlatformError, ProcessEntry, ProcessKey, SamplingProcess, SpawnRequest, UnsupportedKind,
};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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

/// Make the daemon's data directory private before it is used.  The expected
/// owner is supplied separately so tests can exercise the hostile-existing-dir
/// case without needing to change a real directory's ownership.
fn secure_data_dir_for_owner(path: &Path, expected_uid: u32) -> Result<(), PlatformError> {
    let absolute = absolute_path(path)?;
    let existed = validate_directory_path(&absolute)?;
    if existed {
        let metadata = fs::symlink_metadata(&absolute)?;
        if metadata.uid() != expected_uid {
            return Err(PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "data directory owner is not the daemon user",
            });
        }
    }

    // No files are opened below the directory before this returns.  Check a
    // second time after creation so a link or non-directory substituted while
    // create_dir_all was running is refused rather than followed later.
    fs::create_dir_all(&absolute)?;
    if !validate_directory_path(&absolute)? {
        return Err(PlatformError::Invalid {
            capability: "secure_data_dir",
            detail: "data directory disappeared while it was being created",
        });
    }
    let metadata = fs::symlink_metadata(&absolute)?;
    if metadata.uid() != expected_uid {
        return Err(PlatformError::Invalid {
            capability: "secure_data_dir",
            detail: "data directory owner changed while it was being secured",
        });
    }
    fs::set_permissions(&absolute, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf, PlatformError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Return whether the final directory existed. Every existing component must
/// be a real directory; `symlink_metadata` deliberately does not follow a
/// symlink, so both a data-dir link and a parent link are rejected.
fn validate_directory_path(path: &Path) -> Result<bool, PlatformError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(PlatformError::Invalid {
                        capability: "secure_data_dir",
                        detail: "data directory path contains a symlink",
                    });
                }
                if !metadata.is_dir() {
                    return Err(PlatformError::Invalid {
                        capability: "secure_data_dir",
                        detail: "data directory path contains a non-directory",
                    });
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(true)
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

fn spawn_gate(
    caller: &IdentifiedCaller,
    request: &SpawnRequest,
) -> Result<Box<dyn HeldChild>, PlatformError> {
    // The hold stage is a forked child that blocks on a CLOEXEC pipe. Clearing
    // FD_CLOEXEC in this process, then calling `Command::spawn`, let every other
    // thread's spawn inherit that read end. `unix::hold` never has a
    // non-CLOEXEC gate fd in the parent.
    crate::unix::hold::spawn(caller, request)
}

impl Platform for CurrentPlatform {
    fn os(&self) -> &'static str {
        "linux"
    }
    fn host_anchor_pid(&self) -> u32 {
        1
    }
    fn capability(&self, capability: Capability) -> CapabilityStatus {
        match capability {
            Capability::SpawnSuspended
            | Capability::SpawnAsCaller
            | Capability::ProcessIdentity
            | Capability::ProcessTable
            | Capability::PeerIdentity
            | Capability::ExitCode => CapabilityStatus::Available,
            Capability::SecureDataDir => CapabilityStatus::Available,
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
        spawn_gate(caller, request)
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
    fn secure_data_dir(&self, path: &Path) -> Result<(), PlatformError> {
        let Owner::Unix { euid, .. } = self.current_owner()? else {
            return Err(PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "current process is not a Unix account",
            });
        };
        secure_data_dir_for_owner(path, euid)
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
    use super::secure_data_dir_for_owner;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

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

    fn temp_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "agentwatch-platform-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ))
    }

    #[test]
    fn secure_data_dir_sets_owner_only_mode() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_dir("mode");
        let data = root.join("data");
        std::fs::create_dir_all(&root)?;
        let uid = std::fs::metadata(&root)?.uid();
        secure_data_dir_for_owner(&data, uid)?;
        let mode = std::fs::metadata(&data)?.permissions().mode() & 0o777;
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(mode, 0o700);
        Ok(())
    }

    #[test]
    fn secure_data_dir_refuses_precreated_other_owner() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_dir("foreign-owner");
        let data = root.join("data");
        std::fs::create_dir_all(&data)?;
        let actual = std::fs::metadata(&data)?.uid();
        let expected = actual.checked_add(1).unwrap_or(actual.saturating_sub(1));
        let Err(error) = secure_data_dir_for_owner(&data, expected) else {
            return Err("an existing directory with another owner must be refused".into());
        };
        let _ = std::fs::remove_dir_all(&root);
        assert!(matches!(
            error,
            crate::PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "data directory owner is not the daemon user",
            }
        ));
        Ok(())
    }

    #[test]
    fn secure_data_dir_refuses_symlink_in_path() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_dir("symlink");
        let target = root.join("target");
        let link = root.join("link");
        std::fs::create_dir_all(&target)?;
        symlink(&target, &link)?;
        let uid = std::fs::metadata(&root)?.uid();
        let Err(error) = secure_data_dir_for_owner(&link.join("data"), uid) else {
            return Err("a parent symlink must be refused".into());
        };
        let _ = std::fs::remove_dir_all(&root);
        assert!(matches!(
            error,
            crate::PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "data directory path contains a symlink",
            }
        ));
        Ok(())
    }
}
