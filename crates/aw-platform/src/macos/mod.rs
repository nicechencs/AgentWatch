//! macOS process identity and process table.
//!
//! `proc_pidinfo(PROC_PIDTBSDINFO)` is the identity source: real, effective,
//! and saved uid and gid, plus the start time. A short or empty buffer is
//! "not available", never a zeroed struct reported as a real process.
//! Supplementary groups have no per-pid source (`getgroups` describes only the
//! calling process, and `proc_bsdinfo` does not list them), so `groups` stays
//! empty and the reason is recorded. Not verified on a real Mac.
//!
//! `unsafe_code` is `deny` for this crate. Only `ffi` opts back in, and every
//! call there has a `SAFETY` comment.

/// Ordering tests for the suspended launch. The live spawn is [`spawn`].
#[allow(dead_code)]
mod launch;

use crate::{
    Capability, CapabilityStatus, IdentifiedCaller, Owner, PeerIdentity, Platform, PlatformError,
    ProcessEntry, ProcessKey, SamplingProcess, SpawnRequest,
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

pub const NO_DAEMON_HELP: &str = "不经过后台，直接运行程序，不做记录；`aw` 一退出，程序和它启动的子程序会跟着结束。子程序要是自己脱离了进程组（比如在后台另起服务），在 Mac 上不保证会跟着结束。";

#[derive(Clone, Copy)]
struct DataDirPolicy {
    expected_uid: u32,
    privileged: bool,
    /// Custom paths cannot relax the privileged-daemon ownership rule.
    official_path: bool,
}

impl DataDirPolicy {
    fn for_daemon(real_uid: u32, effective_uid: u32, official_path: bool) -> Self {
        Self {
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

/// Resolve existing ancestors before use. A final link is refused; a trusted
/// root/self-owned ancestor link is accepted only under a non-swappable (or
/// sticky) parent. This permits the system `/tmp` and `/var` aliases.
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
                // If a racing creator supplied this component, inspect and
                // repair only the pinned O_NOFOLLOW descriptor.
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

fn secure_data_dir_with_policy(
    path: &Path,
    default: &Path,
    policy: DataDirPolicy,
) -> Result<PathBuf, PlatformError> {
    let resolved = resolve_data_dir_path(path, policy)?;
    let default = resolve_data_dir_path(default, policy)?;
    let policy = DataDirPolicy {
        official_path: resolved.canonical == default.canonical,
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

#[cfg(test)]
fn secure_data_dir_for_owner(path: &Path, expected_uid: u32) -> Result<(), PlatformError> {
    secure_data_dir_with_policy(
        path,
        Path::new("/Library/Application Support/AgentWatch"),
        DataDirPolicy::for_daemon(expected_uid, expected_uid, false),
    )
    .map(drop)
}

/// Why a per-pid group list cannot be read. Kept as the documented reason even
/// though `Owner::Unix` has no field for it in this interface version.
#[allow(dead_code)]
const GROUPS_UNAVAILABLE: &str =
    "macOS has no per-pid getgroups; supplementary groups are not in proc_bsdinfo";

/// `getpeereid` for the uid and gid, `LOCAL_PEERPID` for the pid. Either
/// failing is [`PlatformError::PeerNotIdentified`]: the caller refuses the
/// connection instead of treating the peer as an ordinary user. The credential
/// carries one gid, not the supplementary group list.
pub fn identify_unix_peer(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerIdentity, PlatformError> {
    let (uid, gid) =
        nix::unistd::getpeereid(stream).map_err(|_| PlatformError::PeerNotIdentified {
            reason: "getpeereid unavailable",
        })?;
    // LOCAL_PEERPID is not available on every socket configuration. The uid
    // and gid above are enough to authenticate the caller, so preserve that
    // identity when the optional pid cannot be obtained. Darwin's peer API
    // does not provide supplementary groups; represent that absence as none.
    let pid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerPid)
        .ok()
        .and_then(|pid| u32::try_from(pid).ok());
    let uid = uid.as_raw();
    let gid = gid.as_raw();
    Ok(PeerIdentity::new(
        Owner::Unix {
            ruid: uid,
            euid: uid,
            suid: uid,
            rgid: gid,
            egid: gid,
            sgid: gid,
            // getpeereid/LOCAL_PEERPID cannot report supplementary groups.
            groups: None,
        },
        pid,
    ))
}

impl Platform for CurrentPlatform {
    fn os(&self) -> &'static str {
        "macos"
    }
    fn host_anchor_pid(&self) -> u32 {
        1
    }

    fn capability(&self, capability: Capability) -> CapabilityStatus {
        match capability {
            // Compiled in this commit. `POSIX_SPAWN_START_SUSPENDED` and the
            // watchdog have not been run on a real Mac (【待验证】).
            Capability::SpawnSuspended
            | Capability::ProcessIdentity
            | Capability::ProcessTable
            | Capability::PeerIdentity
            | Capability::ExitCode => CapabilityStatus::Available,
            // `spawn_suspended` can drop to the caller, but the session route
            // still answers 503 `collector_unavailable` before it is called.
            // Reporting this as available would claim a launch the API refuses.
            Capability::SpawnAsCaller => CapabilityStatus::NotInThisBuild,
            Capability::SecureDataDir => CapabilityStatus::Available,
        }
    }

    fn spawn_suspended(
        &self,
        caller: &IdentifiedCaller,
        request: &SpawnRequest,
    ) -> Result<Box<dyn crate::HeldChild>, PlatformError> {
        crate::unix::hold::spawn(caller, request)
    }

    fn process_identity(&self, pid: u32) -> Result<Option<ProcessEntry>, PlatformError> {
        identity(pid)
    }

    fn process_table(&self) -> Result<Vec<ProcessEntry>, PlatformError> {
        let mut out = Vec::new();
        for pid in list_pids()? {
            if let Some(entry) = identity(pid)? {
                out.push(entry);
            }
        }
        Ok(out)
    }

    fn sampling_process(&self, pid: u32) -> Result<Option<SamplingProcess>, PlatformError> {
        Ok(identity(pid)?.map(|entry| sampling_from(&entry)))
    }

    fn sampling_process_table(&self) -> Result<Vec<SamplingProcess>, PlatformError> {
        Ok(self.process_table()?.iter().map(sampling_from).collect())
    }

    fn secure_data_dir(&self, path: &Path) -> Result<PathBuf, PlatformError> {
        // Use only the daemon's kernel-provided IDs. Do not derive a policy
        // from a requester, environment variable, or command-line argument.
        let real_uid = getuid().as_raw();
        let effective_uid = geteuid().as_raw();
        secure_data_dir_with_policy(
            path,
            Path::new("/Library/Application Support/AgentWatch"),
            DataDirPolicy::for_daemon(real_uid, effective_uid, false),
        )
    }

    fn default_data_dir(&self) -> Result<PathBuf, PlatformError> {
        Ok(PathBuf::from("/Library/Application Support/AgentWatch"))
    }

    fn default_config_path(&self) -> Result<PathBuf, PlatformError> {
        Ok(PathBuf::from(
            "/Library/Application Support/AgentWatch/config.toml",
        ))
    }

    fn is_privileged(&self) -> Option<bool> {
        aw_collector_macos::privilege::is_privileged()
    }

    fn current_user_id(&self) -> Option<String> {
        self.current_owner().ok().and_then(|owner| match owner {
            Owner::Unix { euid, .. } => Some(euid.to_string()),
            Owner::Windows { .. } => None,
        })
    }

    fn current_owner(&self) -> Result<Owner, PlatformError> {
        identity(std::process::id())?
            .and_then(|process| process.owner)
            .ok_or(PlatformError::PeerNotIdentified {
                reason: "current process ownership is unavailable",
            })
    }
}

/// Product version string for `aw doctor`, from `kern.osproductversion`
/// (`14.6.1` style, not the Darwin kernel version). `None` when the call
/// fails: the caller prints 「不可得」, never an empty string.
pub fn os_version() -> Option<String> {
    ffi::product_version()
}

fn sampling_from(entry: &ProcessEntry) -> SamplingProcess {
    let start_ns = entry.key.start_time.saturating_mul(1_000);
    SamplingProcess {
        key: entry.key,
        ppid: entry.ppid.unwrap_or(0),
        start_ns,
        // Decimal seconds of `kern.boottime`, the same bytes the poll collector
        // hashes (`sysinfo::System::boot_time`, which is `sysctl(KERN_BOOTTIME)`
        // `tv_sec`). An empty boot id hashes to a different `ProcUid` than that
        // collector, so a launched pid would never pair with its stored row.
        // `None` (the sysctl failed) stays empty: inventing a boot id would
        // attach the row to a different process.
        boot_id: boot_id_bytes().unwrap_or_default(),
    }
}

/// `kern.boottime` seconds, decimal ASCII. `None` when the sysctl fails or
/// returns 0: that is "unavailable", not a boot id of zero.
fn boot_id_bytes() -> Option<Vec<u8>> {
    let secs = ffi::boot_time_secs()?;
    if secs == 0 {
        return None;
    }
    Some(secs.to_string().into_bytes())
}

fn identity(pid: u32) -> Result<Option<ProcessEntry>, PlatformError> {
    let Some(info) = ffi::bsd_info(pid)? else {
        return Ok(None);
    };
    // Microseconds, not seconds: dropping tv_usec would collapse two processes
    // that started in the same second into one key and hide a pid reuse.
    let start_time = info
        .pbi_start_tvsec
        .saturating_mul(1_000_000)
        .saturating_add(info.pbi_start_tvusec);
    if info.pbi_pid == 0 || start_time == 0 {
        // A zero pid or a zero start time is the kernel saying "no such
        // process" through a filled buffer. Never report that as a real key.
        return Ok(None);
    }
    Ok(Some(ProcessEntry {
        key: ProcessKey {
            pid: info.pbi_pid,
            start_time,
        },
        ppid: Some(info.pbi_ppid),
        exe: ffi::pid_path(pid),
        argv: ffi::read_argv(pid).and_then(|buf| decode_procargs(&buf)),
        owner: Some(Owner::Unix {
            ruid: info.pbi_ruid,
            euid: info.pbi_uid,
            suid: info.pbi_svuid,
            rgid: info.pbi_rgid,
            egid: info.pbi_gid,
            sgid: info.pbi_svgid,
            // Not in `proc_bsdinfo`, and `getgroups` is the calling process
            // only. Empty means unavailable; the reason is `GROUPS_UNAVAILABLE`.
            // Not in `proc_bsdinfo`, and `getgroups` is the calling process
            // only. None means unavailable; the reason is `GROUPS_UNAVAILABLE`.
            groups: None,
        }),
    }))
}

/// `sysctl(KERN_PROCARGS2)` layout: `argc` (`c_int`), then the executable path
/// as a NUL-terminated string, then `argc` NUL-terminated arguments. A buffer
/// that does not contain every argument is `None`, never a shorter argv.
fn decode_procargs(buf: &[u8]) -> Option<Vec<String>> {
    if buf.len() < 4 {
        return None;
    }
    let argc = i32::from_ne_bytes(buf[..4].try_into().ok()?) as usize;
    // A pathological argc would walk off the buffer. Cap it.
    if argc > 4096 {
        return None;
    }
    let mut rest = &buf[4..];
    // Skip the executable path (NUL-terminated, then padding NULs).
    let exe_end = rest.iter().position(|b| *b == 0)?;
    rest = &rest[exe_end..];
    while rest.first() == Some(&0) {
        rest = &rest[1..];
    }
    let mut argv = Vec::with_capacity(argc);
    for _ in 0..argc {
        if rest.is_empty() {
            return None;
        }
        let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
        argv.push(String::from_utf8_lossy(&rest[..end]).into_owned());
        rest = rest.get(end + 1..).unwrap_or(&[]);
    }
    Some(argv)
}

fn list_pids() -> Result<Vec<u32>, PlatformError> {
    let mut count = ffi::list_count();
    if count < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // The table can grow between the two calls. One retry covers that; a
    // second shortfall is reported instead of looping.
    for _ in 0..2 {
        let bytes = count.saturating_mul(4);
        let mut buf = vec![0u8; bytes.max(0) as usize];
        let wrote = ffi::list_into(&mut buf, bytes);
        if wrote < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if wrote <= count {
            let n = wrote.max(0) as usize;
            let mut pids = Vec::with_capacity(n);
            let (chunks, _) = buf.as_chunks::<4>();
            for chunk in chunks.iter().take(n) {
                let pid = i32::from_ne_bytes(*chunk);
                if pid > 0 {
                    pids.push(pid as u32);
                }
            }
            return Ok(pids);
        }
        count = wrote;
    }
    Err(PlatformError::Invalid {
        capability: "process_table",
        detail: "proc_listallpids kept growing",
    })
}

/// The only `unsafe` in the macOS module. Each call names what it trusts.
#[allow(unsafe_code)]
mod ffi {
    use super::PlatformError;

    /// `proc_pidinfo` returns the number of bytes written. Anything shorter
    /// than `proc_bsdinfo` (including 0 for a dead pid) is unavailable, not a
    /// result we trust. The buffer starts zeroed because a `libc` struct must
    /// not be built from uninitialized memory.
    pub(super) fn bsd_info(pid: u32) -> Result<Option<libc::proc_bsdinfo>, PlatformError> {
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let wrote = unsafe {
            // SAFETY: `info` is writable storage of exactly one `proc_bsdinfo`,
            // and that size is what we pass. The kernel fills it in place.
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast::<libc::c_void>(),
                std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int,
            )
        };
        if wrote <= 0 {
            return Ok(None);
        }
        if (wrote as usize) < std::mem::size_of::<libc::proc_bsdinfo>() {
            return Err(PlatformError::Invalid {
                capability: "process_identity",
                detail: "proc_pidinfo returned a short buffer",
            });
        }
        // SAFETY: the kernel wrote at least `size_of::<proc_bsdinfo>()` bytes
        // into storage that was already zeroed, so no byte is uninitialized.
        Ok(Some(unsafe { info.assume_init() }))
    }

    pub(super) fn pid_path(pid: u32) -> Option<std::path::PathBuf> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let n = unsafe {
            // SAFETY: `buf` is writable and its length is what we pass. The
            // call writes a NUL-terminated path and returns the byte count
            // excluding the NUL, or 0 on failure.
            libc::proc_pidpath(
                pid as libc::c_int,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len() as u32,
            )
        };
        if n <= 0 {
            return None;
        }
        let n = (n as usize).min(buf.len());
        let end = buf[..n].iter().position(|b| *b == 0).unwrap_or(n);
        let path = std::path::PathBuf::from(String::from_utf8_lossy(&buf[..end]).into_owned());
        if path.as_os_str().is_empty() {
            None
        } else {
            Some(path)
        }
    }

    /// Raw `KERN_PROCARGS2` bytes. `None` on any failure, including a raced
    /// pid or a buffer the kernel will not size. Decoding is separate so the
    /// layout can be tested without a syscall.
    pub(super) fn read_argv(pid: u32) -> Option<Vec<u8>> {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
        let mut len: libc::size_t = 0;
        let probe = unsafe {
            // SAFETY: size query. `oldp` is null, `oldlenp` points at `len`.
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if probe != 0 || len == 0 || len > 1_048_576 {
            return None;
        }
        let mut buf = vec![0u8; len];
        let filled = unsafe {
            // SAFETY: `buf` is writable and `len` is its length. The kernel
            // writes at most `len` bytes and updates `len` to what it wrote.
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if filled != 0 {
            return None;
        }
        buf.truncate(len);
        Some(buf)
    }

    pub(super) fn list_count() -> libc::c_int {
        unsafe {
            // SAFETY: a null buffer asks for the byte count only; nothing is written.
            libc::proc_listallpids(std::ptr::null_mut(), 0)
        }
    }

    pub(super) fn list_into(buf: &mut [u8], bytes: libc::c_int) -> libc::c_int {
        unsafe {
            // SAFETY: `buf` is writable and `bytes` is its length.
            libc::proc_listallpids(buf.as_mut_ptr().cast::<libc::c_void>(), bytes)
        }
    }

    /// `sysctl(KERN_BOOTTIME)` `tv_sec`. `None` when the call fails. `0` is a
    /// real return (the kernel wrote a zero timeval) and the caller treats it
    /// as unavailable.
    pub(super) fn boot_time_secs() -> Option<i64> {
        let mut boot = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let mut len = std::mem::size_of::<libc::timeval>();
        let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
        let rc = unsafe {
            // SAFETY: `mib` is the two-int name of `kern.boottime`, `boot` is
            // writable storage of one `timeval`, and `len` is that size. The
            // kernel writes the timeval in place.
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                (&mut boot as *mut libc::timeval).cast::<libc::c_void>(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc < 0 {
            None
        } else {
            Some(boot.tv_sec)
        }
    }

    /// `sysctlbyname("kern.osproductversion")`. `None` on any failure, including
    /// a value that is not text. Never returns an empty string.
    pub(super) fn product_version() -> Option<String> {
        let name = std::ffi::CString::new("kern.osproductversion").ok()?;
        let mut len: libc::size_t = 0;
        let probe = unsafe {
            // SAFETY: size query. `oldp` is null, `oldlenp` points at `len`.
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if probe != 0 || len == 0 || len > 128 {
            return None;
        }
        let mut buf = vec![0u8; len];
        let filled = unsafe {
            // SAFETY: `buf` is writable and `len` is its length.
            libc::sysctlbyname(
                name.as_ptr(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if filled != 0 {
            return None;
        }
        buf.truncate(len);
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        let text = String::from_utf8_lossy(&buf[..end]).trim().to_owned();
        if text.is_empty() {
            None
        } else {
            Some(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    #[test]
    fn procargs_splits_argc_exe_and_argv() {
        // argc = 2, exe path, then two arguments. Padding NULs sit between
        // the exe path and argv, which is what the kernel actually writes.
        let mut buf = Vec::new();
        buf.extend_from_slice(&2i32.to_ne_bytes());
        buf.extend_from_slice(b"/bin/sh\0\0\0");
        buf.extend_from_slice(b"sh\0-c\0");
        let Some(argv) = decode_procargs(&buf) else {
            panic!("decoded");
        };
        assert_eq!(argv, vec!["sh".to_string(), "-c".to_string()]);
    }

    #[test]
    fn procargs_short_buffer_is_none() {
        assert!(decode_procargs(&[]).is_none());
        assert!(decode_procargs(&1i32.to_ne_bytes()).is_none());
    }

    #[test]
    fn procargs_does_not_invent_argv_past_buffer() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&3i32.to_ne_bytes());
        buf.extend_from_slice(b"/bin/sh\0only-one\0");
        // argc says 3 but only one argument is present.
        assert!(decode_procargs(&buf).is_none());
    }

    #[test]
    fn groups_unavailable_is_stated() {
        // Pin the reason so a later edit cannot silently report an empty group
        // list as "this process has no supplementary groups".
        assert!(GROUPS_UNAVAILABLE.contains("no per-pid"));
    }

    #[test]
    fn secure_data_dir_sets_owner_only_mode() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "agentwatch-platform-macos-mode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
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
    fn secure_data_dir_refuses_a_different_existing_owner() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = std::env::temp_dir().join(format!(
            "agentwatch-platform-macos-owner-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
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
            PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "data directory owner is not the daemon user",
            }
        ));
        Ok(())
    }

    #[test]
    fn secure_data_dir_accepts_the_system_tmp_alias() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "agentwatch-platform-macos-tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let data = root.join("data");
        let uid = geteuid().as_raw();
        let canonical = secure_data_dir_with_policy(
            &data,
            Path::new("/Library/Application Support/AgentWatch"),
            DataDirPolicy::for_daemon(uid, uid, false),
        )?;
        let created = data.is_dir();
        let expected = std::fs::canonicalize(&data)?;
        let _ = std::fs::remove_dir_all(&root);
        assert!(created);
        assert_eq!(canonical, expected);
        Ok(())
    }

    #[test]
    fn secure_data_dir_refuses_final_symlink_but_accepts_trusted_ancestor(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "agentwatch-platform-macos-link-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let target = root.join("target");
        let link = root.join("link");
        std::fs::create_dir_all(&target)?;
        symlink(&target, &link)?;
        let uid = std::fs::metadata(&root)?.uid();
        let Err(error) = secure_data_dir_for_owner(&link, uid) else {
            return Err("a data-dir symlink must be refused".into());
        };
        assert!(matches!(
            error,
            PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "data directory path contains a symlink",
            }
        ));
        secure_data_dir_for_owner(&link.join("data"), uid)?;
        let created = target.join("data").is_dir();
        let _ = std::fs::remove_dir_all(&root);
        assert!(created);
        Ok(())
    }

    #[test]
    fn data_dir_policy_matrix_requires_admin_for_official_paths() {
        for (real_uid, effective_uid, official_path, owner, allowed) in [
            (1000, 1000, true, 1000, false),
            (1000, 1000, true, 0, false),
            (1000, 1000, true, 1001, false),
            (1000, 1000, false, 1000, true),
            (1000, 1000, false, 0, false),
            (1000, 1000, false, 1001, false),
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
        let root = std::env::temp_dir().join(format!(
            "agentwatch-platform-macos-official-user-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
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
            PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "official data directory requires a privileged daemon",
            }
        ));
        Ok(())
    }

    #[test]
    fn secure_data_dir_corrects_self_owned_files_and_refuses_nested_links(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "agentwatch-platform-macos-tree-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        let data = root.join("data");
        let target = root.join("target");
        std::fs::create_dir_all(&data)?;
        std::fs::create_dir_all(&target)?;
        let uid = std::fs::metadata(&data)?.uid();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o777))?;
        std::fs::write(data.join("secret"), b"metadata only")?;
        std::fs::set_permissions(data.join("secret"), std::fs::Permissions::from_mode(0o666))?;
        secure_data_dir_for_owner(&data, uid)?;
        let directory_mode = std::fs::metadata(&data)?.permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(data.join("secret"))?.permissions().mode() & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);
        symlink(&target, data.join("evil"))?;
        let Err(error) = secure_data_dir_for_owner(&data, uid) else {
            return Err("a nested data-dir symlink must be refused".into());
        };
        let _ = std::fs::remove_dir_all(&root);
        assert!(matches!(
            error,
            PlatformError::Invalid {
                capability: "secure_data_dir",
                detail: "data directory contains a symlink",
            }
        ));
        Ok(())
    }
}
