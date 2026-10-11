use crate::{
    Capability, CapabilityStatus, HeldChild, IdentifiedCaller, Owner, PeerIdentity, Platform,
    PlatformError, ProcessEntry, ProcessKey, SamplingProcess, SpawnRequest, UnsupportedKind,
};
use nix::dir::Dir;
use nix::fcntl::{open, openat, AtFlags, OFlag};
use nix::sys::stat::{fchmod, fstat, fstatat, Mode, SFlag};
use nix::unistd::{dup, fchown, geteuid, getuid, mkdir, Uid};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
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

#[derive(Clone, Copy)]
struct DataDirPolicy {
    expected_uid: u32,
    privileged: bool,
    /// The policy test keeps this explicit: a custom path cannot relax a
    /// privileged daemon's ownership rule.
    official_path: bool,
}

impl DataDirPolicy {
    fn for_daemon(real_uid: u32, effective_uid: u32, official_path: bool) -> Self {
        Self {
            // A root daemon never accepts a user-owned directory, including a
            // custom --data-dir. A user daemon only accepts its own account.
            expected_uid: if real_uid == 0 { 0 } else { effective_uid },
            privileged: real_uid == 0,
            official_path,
        }
    }

    fn accepts_owner(self, owner: u32) -> bool {
        owner == self.expected_uid
    }

    fn permits_path(self) -> bool {
        !self.official_path || self.privileged
    }
}

struct ResolvedDataDir {
    canonical: PathBuf,
    create_base: PathBuf,
    missing: Vec<std::ffi::OsString>,
}

fn invalid<T>(detail: &'static str) -> Result<T, PlatformError> {
    Err(PlatformError::Invalid {
        capability: "secure_data_dir",
        detail,
    })
}

fn absolute_path(path: &Path) -> Result<PathBuf, PlatformError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Resolve only the existing ancestor chain. A final link is always refused.
/// An ancestor link is allowed solely for the root/self-owned, non-swappable
/// system links used by e.g. macOS `/tmp`; Linux shares this implementation.
fn resolve_data_dir_path(
    path: &Path,
    policy: DataDirPolicy,
) -> Result<ResolvedDataDir, PlatformError> {
    let absolute = absolute_path(path)?;
    let components: Vec<_> = absolute.components().collect();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    if index + 1 == components.len() {
                        return invalid("data directory path contains a symlink");
                    }
                    if metadata.uid() != 0 && metadata.uid() != policy.expected_uid {
                        return invalid("data directory ancestor symlink owner is not trusted");
                    }
                    let Some(parent) = current.parent() else {
                        return invalid("data directory ancestor symlink has no parent");
                    };
                    let parent_metadata = fs::metadata(parent)?;
                    if parent_metadata.mode() & 0o022 != 0 && parent_metadata.mode() & 0o1000 == 0 {
                        return invalid("data directory ancestor is writable by other users");
                    }
                } else if !metadata.is_dir() {
                    return invalid("data directory path contains a non-directory");
                } else if index + 1 < components.len()
                    && metadata.mode() & 0o022 != 0
                    && metadata.mode() & 0o1000 == 0
                {
                    return invalid("data directory ancestor is writable by other users");
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let Some(parent) = current.parent() else {
                    return invalid("data directory has no existing ancestor");
                };
                let create_base = fs::canonicalize(parent)?;
                let missing = components[index..]
                    .iter()
                    .map(|item| item.as_os_str().to_os_string())
                    .collect::<Vec<_>>();
                let canonical = missing
                    .iter()
                    .fold(create_base.clone(), |path, item| path.join(item));
                return Ok(ResolvedDataDir {
                    canonical,
                    create_base,
                    missing,
                });
            }
            Err(error) => return Err(error.into()),
        }
    }
    let canonical = fs::canonicalize(&absolute)?;
    Ok(ResolvedDataDir {
        create_base: canonical.clone(),
        canonical,
        missing: Vec::new(),
    })
}

fn create_missing_directories(
    resolved: &ResolvedDataDir,
    policy: DataDirPolicy,
) -> Result<(), PlatformError> {
    let mut current = resolved.create_base.clone();
    for name in &resolved.missing {
        current.push(name);
        match mkdir(&current, Mode::S_IRWXU) {
            Ok(()) => {}
            Err(nix::errno::Errno::EEXIST) => {
                // A racing creator may have installed this component. Pin it
                // before reading its owner or repairing its permissions; do
                // not make a metadata decision on a replaceable pathname.
                let handle = open_final_directory(&current)?;
                secure_handle(&handle, true, policy)?;
            }
            Err(error) => return Err(nix_error(error)),
        }
    }
    Ok(())
}

fn open_final_directory(path: &Path) -> Result<OwnedFd, PlatformError> {
    open(
        path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == nix::errno::Errno::ELOOP {
            PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "data directory path contains a symlink",
            }
        } else {
            nix_error(error)
        }
    })
}

fn secure_handle(
    handle: &OwnedFd,
    is_directory: bool,
    policy: DataDirPolicy,
) -> Result<(), PlatformError> {
    let metadata = fstat(handle).map_err(nix_error)?;
    if !policy.accepts_owner(metadata.st_uid) {
        return invalid("data directory owner is not the daemon user");
    }
    // Root makes intended ownership explicit through the pinned descriptor;
    // user daemons reject another owner rather than taking it over.
    if policy.privileged {
        fchown(handle, Some(Uid::from_raw(policy.expected_uid)), None).map_err(nix_error)?;
    }
    let mode = if is_directory {
        Mode::S_IRWXU
    } else {
        Mode::S_IRUSR | Mode::S_IWUSR
    };
    fchmod(handle, mode).map_err(nix_error)
}

fn secure_directory_tree(directory: &OwnedFd, policy: DataDirPolicy) -> Result<(), PlatformError> {
    secure_handle(directory, true, policy)?;
    // `Dir` consumes its descriptor, so enumerate a duplicate. The original
    // final-directory descriptor stays pinned throughout security work.
    let mut entries = Dir::from_fd(dup(directory).map_err(nix_error)?).map_err(nix_error)?;
    for entry in entries.iter() {
        let entry = entry.map_err(nix_error)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let metadata = fstatat(directory, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(nix_error)?;
        let kind = SFlag::from_bits_truncate(metadata.st_mode);
        if kind == SFlag::S_IFLNK {
            return invalid("data directory contains a symlink");
        }
        if kind == SFlag::S_IFDIR {
            let child = openat(
                directory,
                name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(nix_error)?;
            secure_directory_tree(&child, policy)?;
        } else if kind == SFlag::S_IFREG {
            let child = openat(
                directory,
                name,
                OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(nix_error)?;
            secure_handle(&child, false, policy)?;
        } else {
            return invalid("data directory contains an unsupported file type");
        }
    }
    Ok(())
}

fn nix_error(error: nix::errno::Errno) -> PlatformError {
    PlatformError::Io(io::Error::from_raw_os_error(error as i32))
}

/// Make the daemon's data directory private before it is used. After the
/// final O_NOFOLLOW open, all inspection and repair operates through handles.
fn secure_data_dir_with_policy(
    path: &Path,
    default: &Path,
    policy: DataDirPolicy,
) -> Result<PathBuf, PlatformError> {
    let resolved = resolve_data_dir_path(path, policy)?;
    let default = resolve_data_dir_path(default, policy)?;
    let official = resolved.canonical == default.canonical;
    let policy = DataDirPolicy {
        official_path: official,
        ..policy
    };
    if !policy.permits_path() {
        return invalid("official data directory requires a privileged daemon");
    }
    create_missing_directories(&resolved, policy)?;
    let directory = open_final_directory(&resolved.canonical)?;
    secure_directory_tree(&directory, policy)?;
    Ok(resolved.canonical)
}

/// Kept explicit for ownership tests. Product code gets both IDs from the
/// daemon process and never from an argument, environment variable, or config.
#[cfg(test)]
fn secure_data_dir_for_owner(path: &Path, expected_uid: u32) -> Result<(), PlatformError> {
    secure_data_dir_with_policy(
        path,
        Path::new("/var/lib/agentwatch"),
        DataDirPolicy::for_daemon(expected_uid, expected_uid, false),
    )
    .map(drop)
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
    fn secure_data_dir(&self, path: &Path) -> Result<PathBuf, PlatformError> {
        // This is deliberately the daemon process's real/effective uid, not
        // a caller, environment variable, or command-line policy switch.
        let real_uid = getuid().as_raw();
        let effective_uid = geteuid().as_raw();
        secure_data_dir_with_policy(
            path,
            Path::new("/var/lib/agentwatch"),
            DataDirPolicy::for_daemon(real_uid, effective_uid, false),
        )
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
    use super::{secure_data_dir_for_owner, secure_data_dir_with_policy, DataDirPolicy};
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
        let Err(error) = secure_data_dir_for_owner(&link, uid) else {
            return Err("a data-dir symlink must be refused".into());
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

    #[test]
    fn secure_data_dir_accepts_a_trusted_sticky_ancestor_symlink(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_dir("trusted-ancestor-link");
        let target = root.join("target");
        let link = root.join("link");
        std::fs::create_dir_all(&target)?;
        symlink(&target, &link)?;
        let uid = std::fs::metadata(&root)?.uid();
        secure_data_dir_for_owner(&link.join("data"), uid)?;
        let created = target.join("data").is_dir();
        let _ = std::fs::remove_dir_all(&root);
        assert!(created);
        Ok(())
    }

    #[test]
    fn data_dir_policy_matrix_requires_admin_for_official_paths() {
        for (real_uid, effective_uid, official_path, owner, allowed) in [
            // user daemon: official / self, root, and another user
            (1000, 1000, true, 1000, false),
            (1000, 1000, true, 0, false),
            (1000, 1000, true, 1001, false),
            // user daemon: non-official / self, root, and another user
            (1000, 1000, false, 1000, true),
            (1000, 1000, false, 0, false),
            (1000, 1000, false, 1001, false),
            // privileged daemon: official and custom paths both require root.
            (0, 0, true, 0, true),
            (0, 0, true, 1000, false),
            (0, 0, true, 1001, false),
            (0, 0, false, 0, true),
            (0, 0, false, 1000, false),
            (0, 0, false, 1001, false),
        ] {
            let policy = DataDirPolicy::for_daemon(real_uid, effective_uid, official_path);
            assert_eq!(
                policy.permits_path() && policy.accepts_owner(owner),
                allowed,
                "real={real_uid}, effective={effective_uid}, official={official_path}, owner={owner}"
            );
        }
    }

    #[test]
    fn secure_data_dir_refuses_the_official_path_for_a_user_daemon(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_dir("official-user");
        std::fs::create_dir_all(&root)?;
        let uid = std::fs::metadata(&root)?.uid();
        let Err(error) =
            secure_data_dir_with_policy(&root, &root, DataDirPolicy::for_daemon(1000, uid, false))
        else {
            return Err("a normal daemon must not use the official location".into());
        };
        let _ = std::fs::remove_dir_all(&root);
        assert!(matches!(
            error,
            crate::PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "official data directory requires a privileged daemon",
            }
        ));
        Ok(())
    }

    #[test]
    fn secure_data_dir_corrects_self_owned_writable_entries(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_dir("writable-tree");
        let data = root.join("data");
        std::fs::create_dir_all(&data)?;
        let uid = std::fs::metadata(&data)?.uid();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o777))?;
        std::fs::write(data.join("secret"), b"metadata only")?;
        std::fs::set_permissions(data.join("secret"), std::fs::Permissions::from_mode(0o666))?;

        secure_data_dir_for_owner(&data, uid)?;
        let dir_mode = std::fs::metadata(&data)?.permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(data.join("secret"))?.permissions().mode() & 0o777;
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        Ok(())
    }

    #[test]
    fn secure_data_dir_refuses_a_nested_symlink() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_dir("nested-link");
        let data = root.join("data");
        let target = root.join("target");
        std::fs::create_dir_all(&target)?;
        let uid = std::fs::metadata(&root)?.uid();
        secure_data_dir_for_owner(&data, uid)?;
        symlink(&target, data.join("evil"))?;
        let Err(error) = secure_data_dir_for_owner(&data, uid) else {
            return Err("a nested data-dir symlink must be refused".into());
        };
        let _ = std::fs::remove_dir_all(&root);
        assert!(matches!(
            error,
            crate::PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "data directory contains a symlink",
            }
        ));
        Ok(())
    }
}
