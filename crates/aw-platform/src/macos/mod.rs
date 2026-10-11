//! macOS process identity, process table, and child reaping.
//!
//! `proc_pidinfo(PROC_PIDTBSDINFO)` is the identity source: it carries real,
//! effective, and saved uid plus the start time. A short buffer is "not
//! available", never a zeroed struct. Supplementary groups have no per-pid
//! equivalent of `getgroups`, so `groups` stays empty and
//! `groups_unavailable` says why.
//!
//! `unsafe_code` is `deny` for this crate (see `Cargo.toml`). Only `ffi` opts
//! back in, and every call there has a `SAFETY` comment.

use crate::{
    IdentifiedCaller, Owner, Platform, PlatformError, ProcessEntry, ProcessKey, ReapOutcome,
    SpawnRequest, UnsupportedKind,
};
pub(crate) mod spawn;

use std::path::{Path, PathBuf};

pub(crate) struct CurrentPlatform;

#[allow(dead_code)]
fn no(capability: &'static str) -> PlatformError {
    PlatformError::Unsupported {
        capability,
        os: "macos",
        kind: UnsupportedKind::NotInThisBuild,
    }
}

/// Why a per-pid group list cannot be read. macOS `getgroups` only describes
/// the calling process; nothing in `proc_bsdinfo` lists supplementary groups.
const GROUPS_UNAVAILABLE: &str =
    "macOS has no per-pid getgroups; supplementary groups are not in proc_bsdinfo";

impl Platform for CurrentPlatform {
    fn os(&self) -> &'static str {
        "macos"
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
    fn reap_child(&self, key: ProcessKey) -> Result<ReapOutcome, PlatformError> {
        reap(key)
    }
    fn secure_data_dir(&self, p: &Path) -> Result<(), PlatformError> {
        std::fs::create_dir_all(p).map_err(Into::into)
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
}

/// `getpeereid` for the uid, `LOCAL_PEERPID` for the pid. Either failing is
/// `NotIdentified`: the daemon refuses the connection instead of treating the
/// peer as an ordinary user. The credential has no supplementary groups.
pub fn peer_identity(stream: &std::os::unix::net::UnixStream) -> crate::PeerIdentity {
    let (uid, gid) = match nix::unistd::getpeereid(stream) {
        Ok(pair) => pair,
        Err(_) => {
            return crate::PeerIdentity::NotIdentified {
                reason: "getpeereid failed",
            };
        }
    };
    let pid = match nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::LocalPeerPid)
    {
        Ok(pid) if pid > 0 => Some(pid as u32),
        _ => {
            return crate::PeerIdentity::NotIdentified {
                reason: "LOCAL_PEERPID failed",
            };
        }
    };
    crate::PeerIdentity::Identified {
        owner: Owner::Unix {
            ruid: uid.as_raw(),
            euid: uid.as_raw(),
            suid: uid.as_raw(),
            groups: vec![gid.as_raw()],
            groups_unavailable: Some(
                "getpeereid carries one gid, not the supplementary group list",
            ),
        },
        pid,
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
            groups: Vec::new(),
            groups_unavailable: Some(GROUPS_UNAVAILABLE),
        }),
    }))
}

/// `sysctl(KERN_PROCARGS2)` layout: `argc` (`c_int`), then the executable path
/// as a NUL-terminated string, then `argc` NUL-terminated arguments. A buffer
/// that does not contain every argument is `None`, never a shorter argv.
fn decode_procargs(buf: &[u8]) -> Option<Vec<String>> {
    if buf.len() < std::mem::size_of::<libc::c_int>() {
        return None;
    }
    let argc = i32::from_ne_bytes(buf[..4].try_into().ok()?) as usize;
    // A pathological argc would walk off the buffer. Cap it.
    if argc > 4096 {
        return None;
    }
    let mut rest = &buf[std::mem::size_of::<libc::c_int>()..];
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
        let bytes = count.saturating_mul(std::mem::size_of::<libc::pid_t>() as libc::c_int);
        let mut buf = vec![0u8; bytes.max(0) as usize];
        let wrote = ffi::list_into(&mut buf, bytes);
        if wrote < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if wrote <= count {
            let n = wrote.max(0) as usize;
            let (chunks, _) = buf.as_chunks::<{ std::mem::size_of::<libc::pid_t>() }>();
            let mut pids = Vec::with_capacity(n);
            for chunk in chunks.iter().take(n) {
                let pid = libc::pid_t::from_ne_bytes(*chunk);
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

/// Reap one child this process spawned. `ECHILD` is `NotOurChild`: the sampler
/// calls this for pids it did not spawn, and that must not invent an exit code.
/// A signal death is `Signaled`, never `Exited(0)`.
fn reap(key: ProcessKey) -> Result<ReapOutcome, PlatformError> {
    let mut status: libc::c_int = 0;
    let rc = ffi::wait_once(key.pid, &mut status);
    if rc == 0 {
        return Ok(ReapOutcome::StillRunning);
    }
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ECHILD) {
            return Ok(ReapOutcome::NotOurChild);
        }
        return Err(err.into());
    }
    if libc::WIFEXITED(status) {
        return Ok(ReapOutcome::Exited(libc::WEXITSTATUS(status)));
    }
    if libc::WIFSIGNALED(status) {
        return Ok(ReapOutcome::Signaled(libc::WTERMSIG(status)));
    }
    Ok(ReapOutcome::StillRunning)
}

/// The only `unsafe` in the macOS module. Each call names what it trusts.
#[allow(unsafe_code)]
mod ffi {
    use super::PlatformError;
    use std::path::PathBuf;

    /// `proc_pidinfo` returns the number of bytes written. Anything shorter
    /// than `proc_bsdinfo` (including 0 for a dead pid) is unavailable, not a
    /// result we trust. The buffer starts zeroed because `libc` structs must
    /// not be built with `MaybeUninit::uninit` + `assume_init`.
    pub(super) fn bsd_info(pid: u32) -> Result<Option<libc::proc_bsdinfo>, PlatformError> {
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
        let wrote = unsafe {
            // SAFETY: `info` is writable storage of exactly one `proc_bsdinfo`,
            // and that size is what we pass. The kernel fills it in place.
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr() as *mut libc::c_void,
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

    pub(super) fn pid_path(pid: u32) -> Option<PathBuf> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let n = unsafe {
            // SAFETY: `buf` is writable and its length is what we pass. The
            // call writes a NUL-terminated path and returns the byte count
            // excluding the NUL, or 0 on failure.
            libc::proc_pidpath(
                pid as libc::c_int,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as u32,
            )
        };
        if n <= 0 {
            return None;
        }
        let n = (n as usize).min(buf.len());
        let end = buf[..n].iter().position(|b| *b == 0).unwrap_or(n);
        let path = PathBuf::from(String::from_utf8_lossy(&buf[..end]).into_owned());
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
                buf.as_mut_ptr() as *mut libc::c_void,
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
            libc::proc_listallpids(buf.as_mut_ptr() as *mut libc::c_void, bytes)
        }
    }

    pub(super) fn wait_once(pid: u32, status: &mut libc::c_int) -> libc::pid_t {
        unsafe {
            // SAFETY: `status` is a valid writable int. `WNOHANG` returns
            // immediately and does not block.
            libc::waitpid(pid as libc::pid_t, status, libc::WNOHANG)
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
}
