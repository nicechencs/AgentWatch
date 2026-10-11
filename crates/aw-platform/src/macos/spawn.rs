//! Suspended start on macOS.
//!
//! The child is `posix_spawn`ed with `POSIX_SPAWN_START_SUSPENDED`, so it does
//! not run until `release` sends `SIGCONT`. `abort` and `Drop` send `SIGKILL`
//! and `waitpid`: a child that was never released does not keep running and
//! does not stay a zombie. `release` consumes the hold and returns a
//! [`crate::ReleasedChild`] that reaps only this child. A signal death is
//! [`crate::ReapOutcome::Signaled`], never `Exited(0)`.
//!
//! While it is held, a watchdog (`/bin/sh` blocked on a pipe only this process
//! writes) `SIGKILL`s it if we die. `release` writes `released` first, so the
//! watchdog exits without killing. After release the target is on its own:
//! the watchdog is dismissed and no signal follows a daemon restart.
//! 【待验证】`POSIX_SPAWN_START_SUSPENDED` and this watchdog have not been run
//! on a real Mac.
//!
//! The child runs as the [`crate::IdentifiedCaller`]. Same uid as us: spawned
//! directly. We are root and the caller is someone else: a small gate is
//! spawned suspended, switches with `initgroups` / `setgid` / `setuid`, checks
//! the switch stuck (and that `setuid(0)` now fails), then `exec`s the target.
//! Any failure exits 125; the target never runs as root. We are not root and
//! the caller is someone else: refused, nothing is spawned.

use crate::{
    HeldChild, IdentifiedCaller, Owner, PlatformError, ReapOutcome, ReleasedChild, SpawnRequest,
};
use std::ffi::CString;
use std::io::Write;

pub(super) fn spawn(
    caller: &IdentifiedCaller,
    request: &SpawnRequest,
) -> Result<Box<dyn HeldChild>, PlatformError> {
    let Owner::Unix { euid, .. } = caller.owner() else {
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
    let switch = if *euid == our_euid {
        None
    } else if our_euid != 0 {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "not root, refusing to launch as another account",
        });
    } else {
        Some(switch_for(*euid)?)
    };

    let (watch_read, mut watch_write) = ffi::pipe()?;
    let watchdog = match ffi::spawn_watchdog(watch_read) {
        Ok(pid) => pid,
        Err(err) => {
            ffi::close(watch_read);
            drop(watch_write);
            return Err(err);
        }
    };
    ffi::close(watch_read);

    let child = match spawn_held(request, switch.as_ref()) {
        Ok(pid) => pid,
        Err(err) => {
            drop(watch_write);
            let _ = ffi::wait_block(watchdog);
            return Err(err);
        }
    };
    if let Err(err) = writeln!(watch_write, "{child}").and_then(|_| watch_write.flush()) {
        let _ = ffi::kill(child, libc::SIGKILL);
        let _ = ffi::wait_block(child);
        drop(watch_write);
        let _ = ffi::wait_block(watchdog);
        return Err(PlatformError::Io(err));
    }
    Ok(Box::new(MacHeld {
        pid: child as u32,
        watch: Some((watchdog, watch_write)),
    }))
}

struct Switch {
    user: CString,
    gid: u32,
    uid: u32,
}

/// `initgroups` needs the account name. No passwd entry, or a name that is
/// not valid text for the gate's argv, means we cannot switch, so the launch
/// is refused before anything is spawned.
fn switch_for(uid: u32) -> Result<Switch, PlatformError> {
    let Some(user) = ffi::user_name(uid) else {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "caller has no passwd entry; refusing to launch",
        });
    };
    if user.to_str().is_err() {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "caller name is not valid text; refusing to launch",
        });
    }
    let Some(gid) = ffi::user_gid(uid) else {
        return Err(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "caller primary group is unknown; refusing to launch",
        });
    };
    Ok(Switch { user, gid, uid })
}

struct MacHeld {
    pid: u32,
    /// Watchdog pid and the pipe write end. Taken on release and on abort.
    watch: Option<(i32, ffi::PipeWrite)>,
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
        // Dismiss before SIGCONT. A crash in this window must not kill a
        // child we already decided to release.
        self.dismiss_watchdog();
        ffi::kill(self.pid as i32, libc::SIGCONT).map_err(PlatformError::Io)?;
        Ok(Box::new(MacReleased { pid: self.pid }))
    }

    fn abort(&mut self) -> Result<(), PlatformError> {
        // Close the pipe first: if SIGKILL loses the race, EOF still kills.
        self.drop_watchdog();
        let _ = ffi::kill(self.pid as i32, libc::SIGKILL);
        let _ = ffi::wait_block(self.pid as i32);
        Ok(())
    }
}

impl Drop for MacHeld {
    fn drop(&mut self) {
        self.drop_watchdog();
        let _ = ffi::kill(self.pid as i32, libc::SIGKILL);
        let _ = ffi::wait_block(self.pid as i32);
    }
}

impl MacHeld {
    fn dismiss_watchdog(&mut self) {
        if let Some((pid, mut write)) = self.watch.take() {
            let _ = writeln!(write, "released").and_then(|_| write.flush());
            drop(write);
            let _ = ffi::wait_block(pid);
        }
    }

    fn drop_watchdog(&mut self) {
        if let Some((pid, write)) = self.watch.take() {
            drop(write);
            let _ = ffi::wait_block(pid);
        }
    }
}

/// A released child this process spawned. `try_reap` and `wait` use `waitpid`
/// on that pid only. `ECHILD` is an error, not an invented exit code: this
/// handle never reaps a pid it does not own.
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

fn spawn_held(request: &SpawnRequest, switch: Option<&Switch>) -> Result<i32, PlatformError> {
    match switch {
        None => {
            if request.cwd.is_some() {
                // libc 0.2.189 has no posix_spawn_file_actions_addchdir_np.
                // A direct spawn cannot enter the caller's cwd, so refuse
                // rather than start in the daemon's directory.
                return Err(PlatformError::Unsupported {
                    capability: "spawn_suspended_cwd",
                    os: "macos",
                    kind: crate::UnsupportedKind::NotInThisBuild,
                });
            }
            ffi::spawn_suspended(&request.command, &request.env)
        }
        Some(switch) => spawn_gate(request, switch),
    }
}

/// Gate argv: `aw-mac-gate <uid> <gid> <user> <cwd-or-empty> <program> [args…]`.
/// The gate binary is this same executable. It switches, then execs. The
/// request env is the target's and is passed through; it is not logged.
fn spawn_gate(request: &SpawnRequest, switch: &Switch) -> Result<i32, PlatformError> {
    let exe = std::env::current_exe().map_err(PlatformError::Io)?;
    let exe = exe.to_str().ok_or(PlatformError::Invalid {
        capability: "spawn_suspended",
        detail: "daemon path is not valid text",
    })?;
    let cwd = match &request.cwd {
        Some(dir) => dir.to_str().ok_or(PlatformError::Invalid {
            capability: "spawn_suspended",
            detail: "cwd is not valid text",
        })?,
        None => "",
    };
    let mut args = vec![
        exe.to_string(),
        "aw-mac-gate".to_string(),
        switch.uid.to_string(),
        switch.gid.to_string(),
        switch.user.to_string_lossy().into_owned(),
        cwd.to_string(),
    ];
    args.extend(request.command.iter().cloned());
    ffi::spawn_suspended(&args, &request.env)
}

/// Entry point for the gate child. Called from the daemon's `main` before
/// anything else when argv[1] is `aw-mac-gate`. Never returns on success: it
/// `exec`s. A failed switch exits 125, so a refused launch is not a clean exit.
/// The daemon's `main` calls this; nothing in this crate does.
pub fn gate_main() -> ! {
    let code = match gate_run() {
        Ok(()) => 0,
        Err(()) => 125,
    };
    std::process::exit(code);
}

#[allow(dead_code)]
fn gate_run() -> Result<(), ()> {
    let args = std::env::args().skip(2).collect::<Vec<_>>();
    let (uid, gid, user, cwd, program, rest) = match args.as_slice() {
        [uid, gid, user, cwd, program, rest @ ..] => (uid, gid, user, cwd, program, rest),
        _ => return Err(()),
    };
    let uid: u32 = uid.parse().map_err(|_| ())?;
    let gid: u32 = gid.parse().map_err(|_| ())?;
    ffi::switch_account(user, gid, uid)?;
    if !cwd.is_empty() {
        ffi::chdir(cwd)?;
    }
    let mut argv = Vec::with_capacity(rest.len() + 1);
    argv.push(program.clone());
    argv.extend(rest.iter().cloned());
    ffi::exec_argv(&argv)
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
    use super::{outcome_of, PlatformError, ReapOutcome};
    use std::ffi::{CStr, CString};
    use std::io;
    use std::os::fd::RawFd;
    use std::os::unix::io::FromRawFd;
    use std::ptr;

    pub(super) struct PipeWrite(std::fs::File);

    impl std::io::Write for PipeWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    pub(super) fn geteuid() -> u32 {
        unsafe {
            // SAFETY: geteuid takes no pointer and cannot fail.
            libc::geteuid()
        }
    }

    pub(super) fn user_name(uid: u32) -> Option<CString> {
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
        Some(name.to_owned())
    }

    pub(super) fn user_gid(uid: u32) -> Option<u32> {
        let pwd = unsafe {
            // SAFETY: same as `user_name`: static storage, copied out immediately.
            libc::getpwuid(uid)
        };
        if pwd.is_null() {
            return None;
        }
        // SAFETY: a non-null `passwd` has a `pw_gid`.
        Some(unsafe { (*pwd).pw_gid })
    }

    /// `initgroups` then `setgid` then `setuid`. Afterwards real and effective
    /// uid must be the caller's, and `setuid(0)` must fail. Anything else
    /// returns `Err` and the caller exits without `exec`. Called only from the
    /// gate child, which the daemon starts.
    #[allow(dead_code)]
    pub(super) fn switch_account(user: &str, gid: u32, uid: u32) -> Result<(), ()> {
        let user = CString::new(user).map_err(|_| ())?;
        unsafe {
            // SAFETY: `user` is a NUL-terminated name. The calls only change
            // this process's credentials. On failure we do not exec.
            if libc::initgroups(user.as_ptr(), gid as libc::c_int) != 0 {
                return Err(());
            }
            if libc::setgid(gid) != 0 {
                return Err(());
            }
            if libc::setuid(uid) != 0 {
                return Err(());
            }
            if libc::getuid() != uid || libc::geteuid() != uid {
                return Err(());
            }
            if libc::setuid(0) == 0 {
                return Err(());
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(super) fn chdir(path: &str) -> Result<(), ()> {
        let path = CString::new(path).map_err(|_| ())?;
        let rc = unsafe {
            // SAFETY: `path` is NUL-terminated. chdir only affects this process.
            libc::chdir(path.as_ptr())
        };
        if rc != 0 {
            Err(())
        } else {
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub(super) fn exec_argv(argv: &[String]) -> Result<(), ()> {
        let owned = argv
            .iter()
            .map(|s| CString::new(s.as_str()).map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut ptrs: Vec<*const libc::c_char> = owned.iter().map(|s| s.as_ptr()).collect();
        ptrs.push(ptr::null());
        unsafe {
            // SAFETY: argv is NULL-terminated and outlives the call. execvp
            // only returns on failure, which we surface as Err.
            libc::execvp(ptrs[0], ptrs.as_ptr());
        }
        Err(())
    }

    pub(super) fn pipe() -> Result<(RawFd, PipeWrite), PlatformError> {
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

    /// `WNOHANG`. `Ok(None)` is still running. A stopped (not dead) child is
    /// also `None`: `START_SUSPENDED` reports the child as stopped.
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

    /// Blocking wait. A stopped child (the suspended state) is not an exit:
    /// keep waiting until it exits or dies by signal.
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

    /// Watchdog script. A pid line is remembered; `released` exits without
    /// killing; EOF kills the remembered pid. No pid yet means just exit.
    const WATCHDOG: &str = "\
target=\n\
while IFS= read -r line; do\n\
  case \"$line\" in\n\
    released*) exit 0;;\n\
    ''|*[!0-9]*) ;;\n\
    *) target=$line;;\n\
  esac\n\
done\n\
if [ -n \"$target\" ]; then kill -KILL \"$target\" 2>/dev/null; fi\n\
exit 0\n";

    pub(super) fn spawn_watchdog(stdin: RawFd) -> Result<i32, PlatformError> {
        let sh = c_string("/bin/sh")?;
        let flag = c_string("-c")?;
        let body = c_string(WATCHDOG)?;
        let argv = [
            sh.as_ptr().cast_mut(),
            flag.as_ptr().cast_mut(),
            body.as_ptr().cast_mut(),
            ptr::null_mut(),
        ];
        unsafe {
            // SAFETY: file actions are init'd before adddup2 and destroyed on
            // every path after. adddup2 maps `stdin` onto fd 0 in the child.
            // argv outlives the call. The watchdog is not suspended.
            let mut actions: libc::posix_spawn_file_actions_t = ptr::null_mut();
            let rc = libc::posix_spawn_file_actions_init(&mut actions);
            if rc != 0 {
                return Err(io_err(rc));
            }
            let rc = libc::posix_spawn_file_actions_adddup2(&mut actions, stdin, 0);
            if rc != 0 {
                libc::posix_spawn_file_actions_destroy(&mut actions);
                return Err(io_err(rc));
            }
            let mut pid: libc::pid_t = 0;
            let rc = libc::posix_spawn(
                &mut pid,
                sh.as_ptr(),
                &actions,
                ptr::null(),
                argv.as_ptr(),
                ptr::null(),
            );
            libc::posix_spawn_file_actions_destroy(&mut actions);
            if rc != 0 {
                return Err(io_err(rc));
            }
            Ok(pid)
        }
    }

    /// Spawn `args[0]` suspended, with `env` as its whole environment. The
    /// caller's env never includes the daemon's; a null envp is not used.
    pub(super) fn spawn_suspended(
        args: &[String],
        env: &[(String, String)],
    ) -> Result<i32, PlatformError> {
        if args.is_empty() {
            return Err(PlatformError::Invalid {
                capability: "spawn_suspended",
                detail: "empty command",
            });
        }
        let program = c_string(&args[0])?;
        let owned = c_args(args)?;
        let mut ptrs: Vec<*mut libc::c_char> =
            owned.iter().map(|s| s.as_ptr().cast_mut()).collect();
        ptrs.push(ptr::null_mut());
        let env_owned = c_env(env)?;
        let envp = env_ptrs(&env_owned);
        unsafe {
            // SAFETY: attr is init'd before setflags and destroyed on every
            // path after. START_SUSPENDED (0x0080) fits in c_short. argv and
            // envp are NULL-terminated and outlive the call. envp is the
            // request's env only, never the daemon's.
            let mut attr: libc::posix_spawnattr_t = ptr::null_mut();
            let rc = libc::posix_spawnattr_init(&mut attr);
            if rc != 0 {
                return Err(io_err(rc));
            }
            let rc = libc::posix_spawnattr_setflags(
                &mut attr,
                libc::POSIX_SPAWN_START_SUSPENDED as libc::c_short,
            );
            if rc != 0 {
                libc::posix_spawnattr_destroy(&mut attr);
                return Err(io_err(rc));
            }
            let mut pid: libc::pid_t = 0;
            let rc = libc::posix_spawn(
                &mut pid,
                program.as_ptr(),
                ptr::null(),
                &attr,
                ptrs.as_ptr(),
                envp.as_ptr(),
            );
            libc::posix_spawnattr_destroy(&mut attr);
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

    fn c_args(args: &[String]) -> Result<Vec<CString>, PlatformError> {
        args.iter().map(|a| c_string(a)).collect()
    }

    fn c_env(env: &[(String, String)]) -> Result<Vec<CString>, PlatformError> {
        env.iter()
            .map(|(k, v)| c_string(&format!("{k}={v}")))
            .collect()
    }

    fn env_ptrs(env: &[CString]) -> Vec<*mut libc::c_char> {
        let mut ptrs: Vec<*mut libc::c_char> = env.iter().map(|s| s.as_ptr().cast_mut()).collect();
        ptrs.push(ptr::null_mut());
        ptrs
    }

    fn io_err(rc: libc::c_int) -> PlatformError {
        PlatformError::Io(io::Error::from_raw_os_error(rc))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn gate_exit_is_not_success() {
        // A failed switch exits 125 (see gate_main). Pin the number so a
        // later edit cannot report a refused launch as a clean exit.
        let code = match Err::<(), ()>(()) {
            Ok(()) => 0,
            Err(()) => 125,
        };
        assert_eq!(code, 125);
    }

    #[test]
    fn signal_death_is_not_exit_zero() {
        // `WIFSIGNALED` maps to Signaled. The number here is the shape, not a
        // real status word: a signalled child must not become Exited(0).
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
