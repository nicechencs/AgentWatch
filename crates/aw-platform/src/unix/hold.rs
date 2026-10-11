//! Suspended start on macOS, and the same shape on any Unix that later shares it.
//!
//! The hold stage is the forked child, not a second copy of this binary.
//! `Command` cannot do this: its `spawn` does not return until the child has
//! exec'd, and the child must not exec until the creator writes the release
//! byte. So this module forks itself.
//!
//! In the child, before `execve`, and using only calls that are safe after a
//! fork (every buffer was allocated in the parent):
//!
//! 1. If the caller is another account, switch first: `setgroups` of the
//!    caller's groups, `setgid`, `setuid`, then check real and effective uid
//!    and gid, and that `setuid(0)` fails. Nothing the caller supplied is used
//!    while the process is still root.
//! 2. `chdir` to the caller's directory only after that switch.
//! 3. Block on a `read` of the gate pipe. EOF (the creator died, or aborted
//!    before release) `_exit`s without exec. One byte means release: close the
//!    pipe and `execve` the target. The target inherits this process's
//!    environment with the caller's pairs applied over it, at `execve` and
//!    not before. `DYLD_INSERT_LIBRARIES` and `LD_PRELOAD` are unset in the
//!    hold stage itself, so a caller-controlled loader is not in force while
//!    the process is still privileged.
//!
//! The gate pipe is `CLOEXEC` on both ends from the moment `pipe` returns. The
//! read end is inherited across the fork (close-on-exec applies at exec, not
//! at fork) and closed before `execve`, so the target never sees it. A
//! process-wide mutex covers `pipe` through `fork`, so no other thread of this
//! process can fork in that window and inherit either end.
//!
//! Each failed step `_exit`s with its own code (121–127). Those are not a
//! clean run: a clean run replaced the process. Exactly one owner waits, on
//! the pid this module forked. There is no `SIGCHLD` reaper and no second
//! `waitpid`. 【待验证】not run on a real Mac.

use crate::{
    HeldChild, IdentifiedCaller, Owner, PlatformError, ReapOutcome, ReleasedChild, SpawnRequest,
};

/// Exit codes of the hold stage, one per step. A clean exit is never one of
/// these: the target replaced the process. Documented in macos.md §4.
pub const EXIT_SPEC: i32 = 121;
pub const EXIT_SETGROUPS: i32 = 122;
pub const EXIT_SETGID: i32 = 123;
pub const EXIT_SETUID: i32 = 124;
pub const EXIT_SWITCH_CHECK: i32 = 125;
pub const EXIT_CHDIR: i32 = 126;
pub const EXIT_EXEC: i32 = 127;

/// What the child does before exec. Built in the parent; the child only reads it.
struct Prepared {
    /// `None` when the caller is already this account: no switch.
    switch: Option<PreparedSwitch>,
    /// `chdir` target, or `None` to keep the directory the parent is in.
    cwd: Option<std::ffi::CString>,
    program: std::ffi::CString,
    argv: Vec<std::ffi::CString>,
    /// `NAME=value`. This process's environment, then the caller's overrides.
    /// Applied only at `execve`.
    env: Vec<std::ffi::CString>,
    /// Read end of the gate pipe. Closed in the child before exec.
    gate_read: std::os::fd::RawFd,
}

struct PreparedSwitch {
    groups: Vec<libc::gid_t>,
    gid: libc::gid_t,
    uid: libc::uid_t,
}

pub(crate) fn spawn(
    caller: &IdentifiedCaller,
    request: &SpawnRequest,
) -> Result<Box<dyn HeldChild>, PlatformError> {
    let Owner::Unix {
        euid, egid, groups, ..
    } = caller.owner()
    else {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "macOS launch requires a Unix caller",
        });
    };
    let (program, _args) = request
        .command
        .split_first()
        .ok_or(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "empty command",
        })?;
    let our_euid = ffi::geteuid();
    if *euid != our_euid && our_euid != 0 {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "not root, refusing to launch as another account",
        });
    }
    let switch = if *euid == our_euid {
        None
    } else {
        // Groups come from the authenticated caller. A peer that could not
        // name them is refused rather than launched with this process's groups.
        let groups = groups.clone().ok_or(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "caller groups are unavailable; refusing to launch",
        })?;
        Some(PreparedSwitch {
            groups: groups.iter().map(|gid| *gid as libc::gid_t).collect(),
            gid: *egid as libc::gid_t,
            uid: *euid as libc::uid_t,
        })
    };
    let cwd = match &request.cwd {
        Some(dir) => Some(ffi::c_string(dir.as_os_str(), "cwd is not valid text")?),
        None => None,
    };
    let mut argv = Vec::with_capacity(request.command.len());
    for arg in &request.command {
        argv.push(ffi::c_string(
            std::ffi::OsStr::new(arg),
            "argument contains NUL",
        )?);
    }
    // The target inherits this process's environment, then the caller's
    // overrides. Linux `aw run` used to do the same through `Command`: a child
    // of `sh -c 'exit "$AW_TEST_CODE"'` with only `AW_TEST_CODE` set still saw
    // `PATH`. Replacing the environment outright would drop that. `DYLD_*` and
    // `LD_PRELOAD` are still cleared in the hold stage before it reads the
    // gate, and come back only if the caller named them here.
    let mut env_pairs: Vec<(String, String)> = std::env::vars()
        .filter(|(key, _)| !request.env.iter().any(|(name, _)| name == key))
        .collect();
    env_pairs.extend(request.env.iter().cloned());
    // `execve` does not search PATH, and `execvp` is not async-signal-safe.
    // Resolve a bare program name here, before fork, against the PATH the
    // target will see.
    let search_path = env_pairs
        .iter()
        .rev()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| value.as_str());
    let resolved = resolve_program(program, search_path)?;
    let program = ffi::c_string(resolved.as_os_str(), "program is not valid text")?;
    let mut env = Vec::with_capacity(env_pairs.len());
    for (key, value) in &env_pairs {
        let pair = format!("{key}={value}");
        env.push(ffi::c_string(
            std::ffi::OsStr::new(&pair),
            "argument contains NUL",
        )?);
    }
    // Held across pipe creation and fork. Both ends are CLOEXEC before the
    // lock is released, so no other fork of this process inherits them.
    let _pipe_lock = PIPE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (gate_read, gate_write) = ffi::pipe_cloexec()?;
    let prepared = Prepared {
        switch,
        cwd,
        program,
        argv,
        env,
        gate_read: std::os::fd::AsRawFd::as_raw_fd(&gate_read),
    };
    // SAFETY: the child calls only async-signal-safe functions, then `_exit`
    // or `execve`. It does not return. The parent closes its copy of the read
    // end below. No Rust destructor runs in the child.
    let pid = ffi::fork();
    if pid < 0 {
        return Err(PlatformError::Io(std::io::Error::last_os_error()));
    }
    if pid == 0 {
        // Own process group, so a test harness that reaps its group does not
        // collect this child out from under the one owner. Both sides call it:
        // the parent to win the race before the child execs, the child in case
        // the parent has not run yet.
        ffi::set_own_group(0);
        // The parent's copy of every fd is still open here; close the write
        // end so the creator's later close is a real EOF, then hold.
        ffi::child_hold(&prepared, std::os::fd::AsRawFd::as_raw_fd(&gate_write));
    }
    ffi::set_own_group(pid);
    // Parent. The child has its own copy of the read end.
    drop(gate_read);
    drop(_pipe_lock);
    Ok(Box::new(MacHeld {
        pid: Some(pid as u32),
        gate: Some(gate_write),
    }))
}

/// Process-wide: `pipe` and the `fork` that inherits the read end are one
/// critical section. Poisoned is fine; the lock still excludes other forks.
/// Default search path when the target environment has no `PATH`.
const DEFAULT_SEARCH_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Find `program` the way a shell would, before fork. A name containing `/`
/// is used as given. Otherwise each absolute `PATH` entry is tried; relative
/// entries (including empty ones, which mean ".") are skipped on purpose.
/// Nothing found is `NotFound`, which callers render as 找不到程序「…」.
fn resolve_program(
    program: &str,
    search_path: Option<&str>,
) -> Result<std::path::PathBuf, PlatformError> {
    use std::os::unix::fs::PermissionsExt;
    if program.contains('/') {
        return Ok(std::path::PathBuf::from(program));
    }
    for dir in search_path.unwrap_or(DEFAULT_SEARCH_PATH).split(':') {
        if !dir.starts_with('/') {
            continue;
        }
        let candidate = std::path::Path::new(dir).join(program);
        if let Ok(meta) = std::fs::metadata(&candidate) {
            if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                return Ok(candidate);
            }
        }
    }
    Err(PlatformError::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("program not found on PATH: {program}"),
    )))
}

static PIPE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct MacHeld {
    /// `None` once the pid has moved to the released handle, or been reaped by
    /// abort. Drop waits only while it is still `Some`, so release and abort
    /// are never a second wait.
    pid: Option<u32>,
    /// Write end of the gate pipe. Dropped on release (after the byte) and on
    /// abort, which is the EOF the child treats as "creator died".
    gate: Option<std::os::fd::OwnedFd>,
}

impl HeldChild for MacHeld {
    fn pid(&self) -> u32 {
        self.pid.unwrap_or(0)
    }

    fn release(mut self: Box<Self>) -> Result<Box<dyn ReleasedChild>, PlatformError> {
        #[cfg(feature = "test-hold-delay")]
        if let Some(delay) = hold_delay() {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
        let gate = self.gate.take().ok_or(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "child has already been released",
        })?;
        let pid = self.pid.take().ok_or(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "held child is unavailable",
        })?;
        // One byte, then close. The child reads the byte and execs. Closing
        // without the byte is abort, not release. The pid moves to the
        // released handle, which is the only wait from here on.
        ffi::write_all(&gate, b"1")?;
        drop(gate);
        Ok(Box::new(MacReleased { pid }))
    }

    fn abort(&mut self) -> Result<(), PlatformError> {
        // Closing the pipe is the EOF. The child exits by itself; this wait
        // is the one owner. A released child has no pid left here.
        self.gate.take();
        if let Some(pid) = self.pid.take() {
            let _ = ffi::wait_block(pid);
        }
        Ok(())
    }
}

impl Drop for MacHeld {
    fn drop(&mut self) {
        let _ = self.abort();
    }
}

/// A released child this process forked. `try_reap` and `wait` use `waitpid`
/// on that pid only. Nothing else waits on it.
struct MacReleased {
    pid: u32,
}

impl ReleasedChild for MacReleased {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn try_reap(&mut self) -> Result<ReapOutcome, PlatformError> {
        ffi::wait_once(self.pid).map_err(PlatformError::Io)
    }

    fn wait(self: Box<Self>) -> Result<ReapOutcome, PlatformError> {
        ffi::wait_outcome(self.pid).map_err(PlatformError::Io)
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

/// Which step of the hold stage failed. The code is what the child `_exit`s.
#[derive(Debug, Clone, Copy)]
enum GateStep {
    Spec,
    Setgroups,
    Setgid,
    Setuid,
    SwitchCheck,
    Chdir,
    Exec,
}

impl GateStep {
    const fn code(self) -> i32 {
        match self {
            Self::Spec => EXIT_SPEC,
            Self::Setgroups => EXIT_SETGROUPS,
            Self::Setgid => EXIT_SETGID,
            Self::Setuid => EXIT_SETUID,
            Self::SwitchCheck => EXIT_SWITCH_CHECK,
            Self::Chdir => EXIT_CHDIR,
            Self::Exec => EXIT_EXEC,
        }
    }
}

/// The only `unsafe` for the launch path.
#[allow(unsafe_code)]
mod ffi {
    use super::{GateStep, PlatformError, Prepared};
    use std::ffi::{CString, OsStr};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;

    pub(super) fn geteuid() -> u32 {
        unsafe {
            // SAFETY: geteuid takes no pointer and cannot fail.
            libc::geteuid()
        }
    }

    pub(super) fn c_string(text: &OsStr, detail: &'static str) -> Result<CString, PlatformError> {
        CString::new(text.as_bytes()).map_err(|_| PlatformError::Invalid {
            capability: "spawn_suspended",
            detail,
        })
    }

    /// `setpgid(pid, pid)`: the child becomes its own process group. `pid` 0
    /// means the calling process. Failure is ignored; a child that stays in
    /// the parent's group still runs, it is only easier for someone else to reap.
    pub(super) fn set_own_group(pid: libc::pid_t) {
        let pgid = if pid == 0 {
            unsafe { libc::getpid() }
        } else {
            pid
        };
        unsafe {
            // SAFETY: setpgid only changes this child's process group. It is
            // async-signal-safe, so the child may call it too.
            libc::setpgid(pid, pgid);
        }
    }

    pub(super) fn fork() -> libc::pid_t {
        unsafe {
            // SAFETY: the caller guarantees the child only uses async-signal-safe
            // calls and does not return. `fork` itself is async-signal-safe.
            libc::fork()
        }
    }

    /// The whole hold stage. Never returns: it execs, or `_exit`s.
    pub(super) fn child_hold(prepared: &Prepared, gate_write: RawFd) -> ! {
        unsafe {
            // SAFETY: closing the inherited write end. The parent keeps its own.
            libc::close(gate_write);
        }
        // A caller-controlled loader must not be in force while this process
        // is still privileged. The target receives its own env at execve.
        clear_preload();
        if let Some(switch) = &prepared.switch {
            switch_ids(&switch.groups, switch.gid, switch.uid);
        }
        if let Some(dir) = &prepared.cwd {
            chdir_or_exit(dir);
        }
        wait_for_release(prepared.gate_read);
        unsafe {
            // SAFETY: the read end was inherited and is no longer needed. It is
            // also CLOEXEC, so an exec would drop it; closing it here means the
            // creator's later close is not waited on by the target.
            libc::close(prepared.gate_read);
        }
        exec(prepared);
    }

    /// `unsetenv` of the two loader names. Async-signal-safe; no allocation.
    fn clear_preload() {
        for name in [c"DYLD_INSERT_LIBRARIES", c"LD_PRELOAD"] {
            unsafe {
                // SAFETY: both names are NUL-terminated literals. `unsetenv`
                // is async-signal-safe and only changes this process.
                libc::unsetenv(name.as_ptr());
            }
        }
    }

    /// `setgroups`, then `setgid`, then `setuid`. Afterwards real and effective
    /// uid and gid must be the caller's, and `setuid(0)` must fail. Each step
    /// `_exit`s with its own code. The group slice was allocated in the parent.
    fn switch_ids(groups: &[libc::gid_t], gid: libc::gid_t, uid: libc::uid_t) {
        unsafe {
            // SAFETY: `groups` is a live slice allocated in the parent. These
            // calls only change this process's credentials and are
            // async-signal-safe. On failure we `_exit` and never exec.
            if setgroups_count(groups.len(), groups.as_ptr()) != 0 {
                exit_step(GateStep::Setgroups);
            }
            if libc::setgid(gid) != 0 {
                exit_step(GateStep::Setgid);
            }
            if libc::setuid(uid) != 0 {
                exit_step(GateStep::Setuid);
            }
            if libc::getuid() != uid || libc::geteuid() != uid || libc::getgid() != gid {
                exit_step(GateStep::SwitchCheck);
            }
            if libc::setuid(0) == 0 {
                exit_step(GateStep::SwitchCheck);
            }
        }
    }

    /// `setgroups` takes `c_int` on macOS and the BSDs, `size_t` on Linux.
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    unsafe fn setgroups_count(count: usize, groups: *const libc::gid_t) -> libc::c_int {
        libc::setgroups(count as libc::c_int, groups)
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    unsafe fn setgroups_count(count: usize, groups: *const libc::gid_t) -> libc::c_int {
        libc::setgroups(count, groups)
    }

    fn chdir_or_exit(path: &std::ffi::CStr) {
        let rc = unsafe {
            // SAFETY: `path` is NUL-terminated and was allocated in the parent.
            // chdir is async-signal-safe and only affects this process.
            libc::chdir(path.as_ptr())
        };
        if rc != 0 {
            exit_step(GateStep::Chdir);
        }
    }

    /// Block until the creator writes the release byte, or `_exit` on EOF.
    fn wait_for_release(fd: RawFd) {
        let mut byte = [0_u8; 1];
        loop {
            let got = unsafe {
                // SAFETY: `byte` is one byte and `fd` is the pipe end this child
                // inherited. `read` is async-signal-safe. EINTR retries.
                libc::read(fd, byte.as_mut_ptr().cast(), 1)
            };
            if got < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                exit_step(GateStep::Spec);
            }
            if got == 0 {
                // Creator died, or aborted before release. Do not exec.
                exit_step(GateStep::Spec);
            }
            return;
        }
    }

    /// `execve` with the caller's argv and environment. Only returns on failure,
    /// which `_exit`s 127.
    fn exec(prepared: &Prepared) -> ! {
        if prepared.argv.is_empty() {
            exit_step(GateStep::Exec);
        }
        let mut argv: Vec<*const libc::c_char> =
            prepared.argv.iter().map(|arg| arg.as_ptr()).collect();
        argv.push(std::ptr::null());
        let mut env: Vec<*const libc::c_char> = prepared.env.iter().map(|e| e.as_ptr()).collect();
        env.push(std::ptr::null());
        unsafe {
            // SAFETY: both arrays are NULL-terminated and point at strings
            // allocated in the parent, which outlive this call. `execve`
            // replaces the process; it only returns on failure.
            libc::execve(prepared.program.as_ptr(), argv.as_ptr(), env.as_ptr());
        }
        exit_step(GateStep::Exec);
    }

    fn exit_step(step: GateStep) -> ! {
        unsafe {
            // SAFETY: `_exit` is async-signal-safe and does not run destructors,
            // which would not be safe in the forked child.
            libc::_exit(step.code());
        }
    }

    /// A pipe whose both ends are `CLOEXEC` before this function returns.
    /// `pipe` then `fcntl`; macOS has no `pipe2`. The caller holds
    /// [`super::PIPE_LOCK`] across this and the fork.
    pub(super) fn pipe_cloexec() -> Result<(OwnedFd, OwnedFd), PlatformError> {
        let mut fds = [0; 2];
        let rc = unsafe {
            // SAFETY: `fds` is a 2-int buffer; pipe writes both ends.
            libc::pipe(fds.as_mut_ptr())
        };
        if rc != 0 {
            return Err(PlatformError::Io(io::Error::last_os_error()));
        }
        if let Err(err) = cloexec(fds[0]).and_then(|_| cloexec(fds[1])) {
            unsafe {
                // SAFETY: both ends were just opened and are not wrapped yet.
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(PlatformError::Io(err));
        }
        let (read, write) = unsafe {
            // SAFETY: both ends were just opened and have not been wrapped
            // elsewhere. Each `OwnedFd` closes its end on drop.
            (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))
        };
        Ok((read, write))
    }

    fn cloexec(fd: RawFd) -> io::Result<()> {
        unsafe {
            // SAFETY: F_GETFD/F_SETFD on an fd this process just opened.
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub(super) fn write_all(fd: &OwnedFd, mut buf: &[u8]) -> Result<(), PlatformError> {
        while !buf.is_empty() {
            let wrote = unsafe {
                // SAFETY: `buf` is a live slice and `fd` is a pipe end this
                // process owns. A short write is retried by the loop.
                libc::write(fd.as_raw_fd(), buf.as_ptr().cast(), buf.len())
            };
            if wrote < 0 {
                return Err(PlatformError::Io(io::Error::last_os_error()));
            }
            if wrote == 0 {
                return Err(PlatformError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "gate accepted no release",
                )));
            }
            buf = &buf[wrote as usize..];
        }
        Ok(())
    }

    /// `WNOHANG`. `Ok(StillRunning)` when the child has not exited.
    pub(super) fn wait_once(pid: u32) -> io::Result<super::ReapOutcome> {
        use super::ReapOutcome;
        let mut status: libc::c_int = 0;
        let got = unsafe {
            // SAFETY: `status` is a live c_int. `WNOHANG` returns immediately.
            libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG)
        };
        if got == 0 {
            return Ok(ReapOutcome::StillRunning);
        }
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(outcome_of(status))
    }

    /// Blocking wait. A stopped child is not an exit: keep waiting until it
    /// exits or dies by signal. This is the only wait on the child.
    pub(super) fn wait_outcome(pid: u32) -> io::Result<super::ReapOutcome> {
        loop {
            let mut status: libc::c_int = 0;
            let got = unsafe {
                // SAFETY: `status` is a live c_int. We forked `pid`, so waitpid
                // reaps it. EINTR retries.
                libc::waitpid(pid as libc::pid_t, &mut status, 0)
            };
            if got < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                return Ok(outcome_of(status));
            }
        }
    }

    pub(super) fn wait_block(pid: u32) -> io::Result<()> {
        wait_outcome(pid).map(drop)
    }

    fn outcome_of(status: libc::c_int) -> super::ReapOutcome {
        use super::ReapOutcome;
        if libc::WIFEXITED(status) {
            return ReapOutcome::Exited(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return ReapOutcome::Signaled(libc::WTERMSIG(status));
        }
        ReapOutcome::Signaled(0)
    }
}

/// Names the hold stage removes from its own environment before it reads the
/// gate. The target's copy of these, if the caller asked for one, is applied
/// later by `execve` and is not removed. The child clears them by name; this
/// constant exists so the test checks the same names.
#[cfg(test)]
const HOLD_CLEARED_PRELOAD: [&str; 2] = ["DYLD_INSERT_LIBRARIES", "LD_PRELOAD"];

/// True when none of [`HOLD_CLEARED_PRELOAD`] is set. That is the hold stage's
/// own environment, checked before `execve`.
#[cfg(test)]
fn caller_preload_absent_before_exec() -> bool {
    HOLD_CLEARED_PRELOAD
        .iter()
        .all(|key| std::env::var_os(key).is_none())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        caller_preload_absent_before_exec, GateStep, EXIT_CHDIR, EXIT_EXEC, EXIT_SETGID,
        EXIT_SETGROUPS, EXIT_SETUID, EXIT_SPEC, EXIT_SWITCH_CHECK, HOLD_CLEARED_PRELOAD,
    };

    #[test]
    fn each_hold_step_has_its_own_exit_code() {
        // A failed switch is not a clean exit, and the codes differ so a real
        // Mac can say which step stopped. 125 is the switch self-check only.
        assert_eq!(GateStep::Spec.code(), EXIT_SPEC);
        assert_eq!(EXIT_SPEC, 121);
        assert_eq!(GateStep::Setgroups.code(), EXIT_SETGROUPS);
        assert_eq!(EXIT_SETGROUPS, 122);
        assert_eq!(GateStep::Setgid.code(), EXIT_SETGID);
        assert_eq!(EXIT_SETGID, 123);
        assert_eq!(GateStep::Setuid.code(), EXIT_SETUID);
        assert_eq!(EXIT_SETUID, 124);
        assert_eq!(GateStep::SwitchCheck.code(), EXIT_SWITCH_CHECK);
        assert_eq!(EXIT_SWITCH_CHECK, 125);
        assert_eq!(GateStep::Chdir.code(), EXIT_CHDIR);
        assert_eq!(EXIT_CHDIR, 126);
        assert_eq!(GateStep::Exec.code(), EXIT_EXEC);
        assert_eq!(EXIT_EXEC, 127);
        let codes = [
            EXIT_SPEC,
            EXIT_SETGROUPS,
            EXIT_SETGID,
            EXIT_SETUID,
            EXIT_SWITCH_CHECK,
            EXIT_CHDIR,
            EXIT_EXEC,
        ];
        let mut unique = codes.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), codes.len());
        assert!(codes.iter().all(|code| *code != 0));
    }

    #[test]
    fn signal_death_is_not_exit_zero() {
        use crate::ReapOutcome;
        let signaled = ReapOutcome::Signaled(9);
        assert!(matches!(signaled, ReapOutcome::Signaled(_)));
        assert!(!matches!(signaled, ReapOutcome::Exited(0)));
    }

    /// The hold stage's own environment, before exec, does not contain a
    /// caller `DYLD_INSERT_LIBRARIES` or `LD_PRELOAD`. The child unsets both
    /// before it reads the gate; this process checks the same predicate on
    /// its own environment after unsetting them, which is the state the child
    /// is in at the exec point. The names are still data for the target: they
    /// are applied at `execve`, after the switch, and not before.
    #[cfg(unix)]
    #[test]
    fn caller_preload_is_absent_before_exec() {
        let saved: Vec<_> = HOLD_CLEARED_PRELOAD
            .iter()
            .map(|key| (*key, std::env::var_os(key)))
            .collect();
        for key in HOLD_CLEARED_PRELOAD {
            std::env::set_var(key, "/no/such/libaw-preload.so");
        }
        assert!(
            !caller_preload_absent_before_exec(),
            "the predicate must see a preload that is still set"
        );
        for key in HOLD_CLEARED_PRELOAD {
            std::env::remove_var(key);
        }
        assert!(
            caller_preload_absent_before_exec(),
            "DYLD_INSERT_LIBRARIES and LD_PRELOAD must be absent before exec"
        );
        for (key, value) in saved {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    /// The forked child does not run the target until the release byte, and
    /// the target's exit code comes back through the one owning handle.
    #[cfg(unix)]
    #[test]
    fn forked_child_holds_until_release_and_returns_the_exit_code() {
        use crate::{IdentifiedCaller, SpawnRequest};
        let caller = IdentifiedCaller::current_user().expect("current user");
        let dir = std::env::temp_dir().join(format!("aw-hold-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let marker = dir.join("ran");
        let request = SpawnRequest {
            command: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "printf ran > \"$1\"; exit 5".to_owned(),
                "aw-hold".to_owned(),
                marker.to_string_lossy().into_owned(),
            ],
            cwd: None,
            env: vec![("AW_TEST_CODE".to_owned(), "5".to_owned())],
        };
        let held = super::spawn(&caller, &request).expect("held");
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!marker.exists(), "the target ran before release");
        let released = held.release().expect("release");
        let outcome = released.wait().expect("wait");
        assert_eq!(outcome, crate::ReapOutcome::Exited(5));
        assert!(marker.is_file(), "the target did not run after release");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Closing the gate without the release byte exits the child before exec.
    #[cfg(unix)]
    #[test]
    fn closing_the_gate_before_release_exits_without_running() {
        use crate::{IdentifiedCaller, SpawnRequest};
        let caller = IdentifiedCaller::current_user().expect("current user");
        let dir = std::env::temp_dir().join(format!("aw-hold-abort-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let marker = dir.join("ran");
        let request = SpawnRequest {
            command: vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "printf ran > \"$1\"".to_owned(),
                "aw-hold".to_owned(),
                marker.to_string_lossy().into_owned(),
            ],
            cwd: None,
            env: Vec::new(),
        };
        let mut held = super::spawn(&caller, &request).expect("held");
        held.abort().expect("abort");
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!marker.exists(), "abort exec'd the target");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "test-hold-delay")]
    #[test]
    fn delay_is_capped_inside_release() {
        std::env::set_var("AW_TEST_HOLD_DELAY_MS", "10001");
        assert_eq!(super::hold_delay(), Some(10_000));
        std::env::remove_var("AW_TEST_HOLD_DELAY_MS");
    }
}
