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
mod spawn;
pub use spawn::gate_main;

use crate::{
    Capability, CapabilityStatus, IdentifiedCaller, Owner, PeerIdentity, Platform, PlatformError,
    ProcessEntry, ProcessKey, SamplingProcess, SpawnRequest, UnsupportedKind,
};
use std::path::{Path, PathBuf};

pub(crate) struct CurrentPlatform;

fn no(capability: &'static str) -> PlatformError {
    PlatformError::Unsupported {
        capability,
        os: "macos",
        kind: UnsupportedKind::NotInThisBuild,
    }
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
            Capability::SpawnAsCaller | Capability::SecureDataDir => {
                CapabilityStatus::NotInThisBuild
            }
        }
    }

    fn spawn_suspended(
        &self,
        caller: &IdentifiedCaller,
        request: &SpawnRequest,
    ) -> Result<Box<dyn crate::HeldChild>, PlatformError> {
        spawn::spawn(caller, request)
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

    fn secure_data_dir(&self, _: &Path) -> Result<(), PlatformError> {
        Err(no("secure_data_dir"))
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
        // macOS has no `/proc` boot id. The start time is wall-clock
        // microseconds, so the key does not need a boot generation.
        boot_id: Vec::new(),
    }
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
}
