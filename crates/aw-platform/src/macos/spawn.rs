//! Suspended start on macOS.
//!
//! The child is this same binary, started with a fixed environment
//! (`PATH=/usr/bin:/bin` and nothing else). It blocks on a close-on-exec pipe
//! the creator holds. EOF before release means the creator died: the child
//! exits and never execs. Release writes one byte; the child then switches to
//! the caller's uid, gid and supplementary groups, checks that `setuid(0)`
//! fails, and only then enters the caller's directory and execs the program
//! with the caller's environment. Those values travel as data on the pipe,
//! never as this process's environment, arguments or working directory.
//!
//! Nothing from the caller is used while the process is still root. Same uid
//! as the creator skips the switch but still waits on the pipe, so `--cwd`
//! works on both paths. 【待验证】not run on a real Mac.

use crate::{
    HeldChild, IdentifiedCaller, Owner, PlatformError, ReapOutcome, ReleasedChild, SpawnRequest,
};

/// argv[1] of the hold-stage copy of this binary.
pub const GATE_ARG: &str = "aw-mac-gate";

/// Exit codes of the hold stage, one per step. A clean exit is never one of
/// these: the target replaced the process. Documented in macos.md §4.
pub const EXIT_SPEC: i32 = 121;
pub const EXIT_SETGROUPS: i32 = 122;
pub const EXIT_SETGID: i32 = 123;
pub const EXIT_SETUID: i32 = 124;
pub const EXIT_SWITCH_CHECK: i32 = 125;
pub const EXIT_CHDIR: i32 = 126;
pub const EXIT_EXEC: i32 = 127;

pub(super) fn spawn(
    caller: &IdentifiedCaller,
    request: &SpawnRequest,
) -> Result<Box<dyn HeldChild>, PlatformError> {
    let Owner::Unix { euid, egid, .. } = caller.owner() else {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "macOS launch requires a Unix caller",
        });
    };
    if request.command.is_empty() {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "empty command",
        });
    }
    let our_euid = ffi::geteuid();
    if *euid != our_euid && our_euid != 0 {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "not root, refusing to launch as another account",
        });
    }
    // The name is only needed when a real switch happens. A same-uid launch
    // must not fail because the account has no passwd entry.
    let user = if *euid == our_euid {
        String::new()
    } else {
        ffi::user_name(*euid).ok_or(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "caller has no passwd entry; refusing to launch",
        })?
    };
    let (gate_read, gate_write) = ffi::pipe_cloexec()?;
    let spec = gate_spec(request, *euid, *egid, &user)?;
    let child = match ffi::spawn_gate(gate_read) {
        Ok(pid) => pid,
        Err(err) => {
            ffi::close(gate_read);
            drop(gate_write);
            return Err(err);
        }
    };
    // The child has its own copy. Closing ours is what makes EOF mean we died.
    ffi::close(gate_read);
    if let Err(err) = write_spec(&gate_write, &spec) {
        let _ = ffi::kill(child, libc::SIGKILL);
        let _ = ffi::wait_block(child);
        return Err(PlatformError::Io(err));
    }
    Ok(Box::new(MacHeld {
        pid: child as u32,
        gate: Some(gate_write),
    }))
}

/// One JSON object: the account to become, then the program. The hold stage
/// reads this only after it is running, and uses it only after the switch.
fn gate_spec(
    request: &SpawnRequest,
    uid: u32,
    gid: u32,
    user: &str,
) -> Result<String, PlatformError> {
    let cwd = match &request.cwd {
        Some(dir) => Some(dir.to_str().ok_or(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "cwd is not valid text",
        })?),
        None => None,
    };
    Ok(serde_json::json!({
        "uid": uid,
        "gid": gid,
        "user": user,
        "cwd": cwd,
        "argv": request.command,
        "env": request.env,
    })
    .to_string())
}

fn write_spec(gate: &ffi::PipeWrite, spec: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut bytes = spec.as_bytes();
    while !bytes.is_empty() {
        let wrote = ffi::write_fd(gate.as_raw_fd(), bytes)?;
        if wrote == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "gate accepted no spec",
            ));
        }
        bytes = &bytes[wrote..];
    }
    Ok(())
}

struct MacHeld {
    pid: u32,
    /// Write end of the gate pipe. Dropped on release (after the byte) and on
    /// abort, which is the EOF the child treats as "creator died".
    gate: Option<ffi::PipeWrite>,
}

impl HeldChild for MacHeld {
    fn pid(&self) -> u32 {
        self.pid
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
        // One byte, then close. The child reads the byte and execs. Closing
        // without the byte is abort, not release.
        ffi::write_fd(std::os::fd::AsRawFd::as_raw_fd(&gate), b"1").map_err(PlatformError::Io)?;
        drop(gate);
        Ok(Box::new(MacReleased { pid: self.pid }))
    }

    fn abort(&mut self) -> Result<(), PlatformError> {
        self.gate.take();
        let _ = ffi::kill(self.pid as i32, libc::SIGKILL);
        let _ = ffi::wait_block(self.pid as i32);
        Ok(())
    }
}

impl Drop for MacHeld {
    fn drop(&mut self) {
        self.gate.take();
        let _ = ffi::kill(self.pid as i32, libc::SIGKILL);
        let _ = ffi::wait_block(self.pid as i32);
    }
}

/// A released child this process spawned. `try_reap` and `wait` use `waitpid`
/// on that pid only. `ECHILD` is an error, not an invented exit code: this
/// handle never reaps a pid it does not own, and nothing else waits on it.
struct MacReleased {
    pid: u32,
}

impl ReleasedChild for MacReleased {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn try_reap(&mut self) -> Result<ReapOutcome, PlatformError> {
        match ffi::wait_once(self.pid as i32) {
            Ok(None) => Ok(ReapOutcome::StillRunning),
            Ok(Some(outcome)) => Ok(outcome),
            Err(err) => Err(PlatformError::Io(err)),
        }
    }

    fn wait(self: Box<Self>) -> Result<ReapOutcome, PlatformError> {
        ffi::wait_outcome(self.pid as i32).map_err(PlatformError::Io)
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

/// Entry point for the hold stage. The daemon's `main` calls this before
/// anything else when argv[1] is [`GATE_ARG`]. Never returns: it execs, or
/// exits with the step's code.
pub fn gate_main() -> ! {
    let code = match gate_run() {
        Ok(()) => 0,
        Err(step) => step.code(),
    };
    std::process::exit(code);
}

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

/// Which fd the creator handed the spec pipe on. Fixed: the spawn actions put
/// it here, and the child never inherits any other descriptor of ours.
const GATE_FD: i32 = 3;

#[derive(serde::Deserialize)]
struct GateSpec {
    uid: u32,
    gid: u32,
    user: String,
    cwd: Option<String>,
    argv: Vec<String>,
    env: Vec<(String, String)>,
}

#[allow(dead_code)]
fn gate_run() -> Result<(), GateStep> {
    // Block until the creator writes the release byte, or die on EOF. The spec
    // is already in the pipe; reading stops at the byte the creator appends.
    let mut buf = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let got = ffi::read_fd(GATE_FD, &mut byte).map_err(|_| GateStep::Spec)?;
        if got == 0 {
            // Creator died, or aborted. Do not exec.
            return Err(GateStep::Spec);
        }
        if byte[0] == b'1' {
            break;
        }
        buf.push(byte[0]);
    }
    let spec: GateSpec = serde_json::from_slice(&buf).map_err(|_| GateStep::Spec)?;
    if spec.argv.is_empty() {
        return Err(GateStep::Spec);
    }
    let ours = ffi::geteuid();
    if spec.uid != ours {
        // Switch first. cwd and the caller's env are not touched before this.
        ffi::switch_account(&spec.user, spec.gid, spec.uid)?;
    }
    if let Some(dir) = spec.cwd.as_deref() {
        ffi::chdir(dir)?;
    }
    ffi::exec_argv(&spec.argv, &spec.env)
}

/// Map a waited status. A signal death is `Signaled` and never `Exited(0)`.
fn outcome_of(status: libc::c_int) -> Option<ReapOutcome> {
    if libc::WIFEXITED(status) {
        return Some(ReapOutcome::Exited(libc::WEXITSTATUS(status)));
    }
    if libc::WIFSIGNALED(status) {
        return Some(ReapOutcome::Signaled(libc::WTERMSIG(status)));
    }
    None
}

/// The only `unsafe` for the launch path.
#[allow(unsafe_code)]
mod ffi {
    use super::{outcome_of, GateStep, PlatformError, ReapOutcome, GATE_ARG, GATE_FD};
    use std::ffi::{CStr, CString};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::ptr;

    pub(super) struct PipeWrite(std::fs::File);

    impl AsRawFd for PipeWrite {
        fn as_raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
    }

    pub(super) fn geteuid() -> u32 {
        unsafe {
            // SAFETY: geteuid takes no pointer and cannot fail.
            libc::geteuid()
        }
    }

    /// Account name for `initgroups`. `None` when there is no passwd entry or
    /// the name is not text the spec can carry.
    pub(super) fn user_name(uid: u32) -> Option<String> {
        let pwd = unsafe {
            // SAFETY: getpwuid returns a pointer into static storage, or null.
            // The name is copied out before any other passwd call.
            libc::getpwuid(uid)
        };
        if pwd.is_null() {
            return None;
        }
        // SAFETY: a non-null `passwd` has a NUL-terminated `pw_name`.
        let name = unsafe { CStr::from_ptr((*pwd).pw_name) };
        name.to_str().ok().map(str::to_owned)
    }

    /// `initgroups` (the caller's supplementary groups), then `setgid`, then
    /// `setuid`. Afterwards real and effective uid must be the caller's, and
    /// `setuid(0)` must fail. Each step has its own exit code. Called only
    /// from the hold stage, which was started with a fixed environment.
    #[allow(dead_code)]
    pub(super) fn switch_account(user: &str, gid: u32, uid: u32) -> Result<(), GateStep> {
        let user = CString::new(user).map_err(|_| GateStep::Setgroups)?;
        unsafe {
            // SAFETY: `user` is a NUL-terminated name. The calls only change
            // this process's credentials. On failure we do not exec.
            if libc::initgroups(user.as_ptr(), gid as libc::c_int) != 0 {
                return Err(GateStep::Setgroups);
            }
            if libc::setgid(gid) != 0 {
                return Err(GateStep::Setgid);
            }
            if libc::setuid(uid) != 0 {
                return Err(GateStep::Setuid);
            }
            if libc::getuid() != uid || libc::geteuid() != uid {
                return Err(GateStep::SwitchCheck);
            }
            if libc::setuid(0) == 0 {
                return Err(GateStep::SwitchCheck);
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn chdir(path: &str) -> Result<(), GateStep> {
        let path = CString::new(path).map_err(|_| GateStep::Chdir)?;
        let rc = unsafe {
            // SAFETY: `path` is NUL-terminated. chdir only affects this process,
            // and it runs only after the account switch.
            libc::chdir(path.as_ptr())
        };
        if rc != 0 {
            Err(GateStep::Chdir)
        } else {
            Ok(())
        }
    }

    /// `execve` of an absolute program. `env` is the caller's, applied here and
    /// nowhere earlier. A relative program is refused: this process does not
    /// search a caller-supplied `PATH` while it might still be privileged, and
    /// after the switch a relative name would depend on the directory just
    /// entered. Callers resolve the program first.
    #[allow(dead_code)]
    pub(super) fn exec_argv(argv: &[String], env: &[(String, String)]) -> Result<(), GateStep> {
        if argv.is_empty() || !std::path::Path::new(&argv[0]).is_absolute() {
            return Err(GateStep::Exec);
        }
        let owned = argv
            .iter()
            .map(|s| CString::new(s.as_str()).map_err(|_| GateStep::Exec))
            .collect::<Result<Vec<_>, _>>()?;
        let env_owned = env
            .iter()
            .map(|(k, v)| CString::new(format!("{k}={v}")).map_err(|_| GateStep::Exec))
            .collect::<Result<Vec<_>, _>>()?;
        let mut argv_ptrs: Vec<*const libc::c_char> = owned.iter().map(|s| s.as_ptr()).collect();
        argv_ptrs.push(ptr::null());
        let mut env_ptrs: Vec<*const libc::c_char> = env_owned.iter().map(|s| s.as_ptr()).collect();
        env_ptrs.push(ptr::null());
        unsafe {
            // SAFETY: both arrays are NULL-terminated and outlive the call.
            // execve only returns on failure.
            libc::execve(argv_ptrs[0], argv_ptrs.as_ptr(), env_ptrs.as_ptr());
        }
        Err(GateStep::Exec)
    }

    /// A pipe whose both ends are `CLOEXEC` before this function returns.
    /// `pipe` then `fcntl` is two steps; macOS has no `pipe2`. The spawn below
    /// sets `POSIX_SPAWN_CLOEXEC_DEFAULT`, so a descriptor another thread
    /// creates in between cannot reach a child this module starts.
    pub(super) fn pipe_cloexec() -> Result<(RawFd, PipeWrite), PlatformError> {
        let mut fds = [0; 2];
        let rc = unsafe {
            // SAFETY: `fds` is a 2-int buffer; pipe writes both ends.
            libc::pipe(fds.as_mut_ptr())
        };
        if rc != 0 {
            return Err(PlatformError::Io(io::Error::last_os_error()));
        }
        if let Err(err) = cloexec(fds[0]).and_then(|_| cloexec(fds[1])) {
            close(fds[0]);
            close(fds[1]);
            return Err(PlatformError::Io(err));
        }
        let write = unsafe {
            // SAFETY: fds[1] is the write end we just opened and have not
            // wrapped elsewhere. File closes it on drop.
            std::fs::File::from_raw_fd(fds[1])
        };
        Ok((fds[0], PipeWrite(write)))
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

    pub(super) fn close(fd: RawFd) {
        unsafe {
            // SAFETY: closing an fd this process owns. Callers close each fd once.
            libc::close(fd);
        }
    }

    pub(super) fn write_fd(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
        let wrote = unsafe {
            // SAFETY: `buf` is a live slice and `fd` is a pipe end this process
            // owns. A short write is returned, not retried here.
            libc::write(fd, buf.as_ptr().cast(), buf.len())
        };
        if wrote < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(wrote as usize)
        }
    }

    #[allow(dead_code)]
    pub(super) fn read_fd(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let got = unsafe {
                // SAFETY: `buf` is a live slice and `fd` is the pipe end the
                // creator placed on GATE_FD. EINTR retries.
                libc::read(fd, buf.as_mut_ptr().cast(), buf.len())
            };
            if got < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            return Ok(got as usize);
        }
    }

    pub(super) fn kill(pid: i32, sig: i32) -> io::Result<()> {
        let rc = unsafe {
            // SAFETY: a positive pid and a standard signal. ESRCH is returned.
            libc::kill(pid, sig)
        };
        if rc != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// `WNOHANG`. `Ok(None)` is still running.
    pub(super) fn wait_once(pid: i32) -> io::Result<Option<ReapOutcome>> {
        let mut status: libc::c_int = 0;
        let got = unsafe {
            // SAFETY: `status` is a live c_int. `WNOHANG` returns immediately.
            libc::waitpid(pid, &mut status, libc::WNOHANG)
        };
        if got == 0 {
            return Ok(None);
        }
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(outcome_of(status))
    }

    /// Blocking wait. A stopped child is not an exit: keep waiting until it
    /// exits or dies by signal. This is the only wait on the child.
    pub(super) fn wait_outcome(pid: i32) -> io::Result<ReapOutcome> {
        loop {
            let mut status: libc::c_int = 0;
            let got = unsafe {
                // SAFETY: `status` is a live c_int. We spawned `pid`, so
                // waitpid reaps it. EINTR retries.
                libc::waitpid(pid, &mut status, 0)
            };
            if got < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if let Some(outcome) = outcome_of(status) {
                return Ok(outcome);
            }
        }
    }

    pub(super) fn wait_block(pid: i32) -> io::Result<()> {
        wait_outcome(pid).map(drop)
    }

    /// Start the hold stage: this binary, argv `[exe, GATE_ARG]`, environment
    /// exactly `PATH=/usr/bin:/bin`, working directory `/`. The spec pipe is
    /// dup2'd onto [`GATE_FD`] and is the only inherited descriptor; every
    /// other fd is close-on-exec in the child (`POSIX_SPAWN_CLOEXEC_DEFAULT`,
    /// 0x4000). The child is not suspended: it blocks itself by reading.
    pub(super) fn spawn_gate(spec_read: RawFd) -> Result<i32, PlatformError> {
        let exe = std::env::current_exe().map_err(PlatformError::Io)?;
        let exe = c_string(exe.to_str().ok_or(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "daemon path is not valid text",
        })?)?;
        let arg = c_string(GATE_ARG)?;
        let path = c_string("PATH=/usr/bin:/bin")?;
        let argv = [
            exe.as_ptr().cast_mut(),
            arg.as_ptr().cast_mut(),
            ptr::null_mut(),
        ];
        let envp = [path.as_ptr().cast_mut(), ptr::null_mut()];
        unsafe {
            // SAFETY: file actions and attr are init'd before use and destroyed
            // on every path after. adddup2 maps the spec pipe onto GATE_FD.
            // CLOEXEC_DEFAULT plus adddup2 of 0/1/2 means the child inherits
            // only the standard streams and the spec pipe. argv and envp are
            // NULL-terminated and outlive the call. envp is the fixed PATH,
            // never the caller's and never ours.
            let mut actions: libc::posix_spawn_file_actions_t = ptr::null_mut();
            let rc = libc::posix_spawn_file_actions_init(&mut actions);
            if rc != 0 {
                return Err(io_err(rc));
            }
            let rc = libc::posix_spawn_file_actions_adddup2(&mut actions, spec_read, GATE_FD);
            if rc != 0 {
                libc::posix_spawn_file_actions_destroy(&mut actions);
                return Err(io_err(rc));
            }
            for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
                let rc = libc::posix_spawn_file_actions_adddup2(&mut actions, fd, fd);
                if rc != 0 {
                    libc::posix_spawn_file_actions_destroy(&mut actions);
                    return Err(io_err(rc));
                }
            }
            let mut attr: libc::posix_spawnattr_t = ptr::null_mut();
            let rc = libc::posix_spawnattr_init(&mut attr);
            if rc != 0 {
                libc::posix_spawn_file_actions_destroy(&mut actions);
                return Err(io_err(rc));
            }
            // 0x4000: POSIX_SPAWN_CLOEXEC_DEFAULT. libc 0.2.189 does not name it.
            let rc = libc::posix_spawnattr_setflags(&mut attr, 0x4000);
            if rc != 0 {
                libc::posix_spawnattr_destroy(&mut attr);
                libc::posix_spawn_file_actions_destroy(&mut actions);
                return Err(io_err(rc));
            }
            let mut pid: libc::pid_t = 0;
            let rc = libc::posix_spawn(
                &mut pid,
                exe.as_ptr(),
                &actions,
                &attr,
                argv.as_ptr(),
                envp.as_ptr(),
            );
            libc::posix_spawnattr_destroy(&mut attr);
            libc::posix_spawn_file_actions_destroy(&mut actions);
            if rc != 0 {
                return Err(io_err(rc));
            }
            Ok(pid)
        }
    }

    fn c_string(s: &str) -> Result<CString, PlatformError> {
        CString::new(s).map_err(|_| PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "argument contains NUL",
        })
    }

    fn io_err(rc: libc::c_int) -> PlatformError {
        PlatformError::Io(io::Error::from_raw_os_error(rc))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GateStep, EXIT_CHDIR, EXIT_EXEC, EXIT_SETGID, EXIT_SETGROUPS, EXIT_SETUID, EXIT_SPEC,
        EXIT_SWITCH_CHECK,
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

    #[cfg(feature = "test-hold-delay")]
    #[test]
    fn delay_is_capped_inside_release() {
        std::env::set_var("AW_TEST_HOLD_DELAY_MS", "10001");
        assert_eq!(super::hold_delay(), Some(10_000));
        std::env::remove_var("AW_TEST_HOLD_DELAY_MS");
    }
}
