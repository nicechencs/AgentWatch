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
//! 3. When the request says the creator owns stdin's foreground terminal, make
//!    this new process group foreground before the gate can be read. This
//!    prevents an immediately-reading target from being stopped with `SIGTTIN`
//!    in the release-to-parent-handoff window. The decision belongs to the
//!    caller before `fork`; this platform layer never infers it from `isatty`.
//! 4. Block on a `read` of the gate pipe. EOF (the creator died, or aborted
//!    before release) `_exit`s without exec. One byte means release: close the
//!    pipe and `execve` the target. The target's environment is the pointer
//!    array built in the parent, applied at `execve` and not before. What goes
//!    into that array is the request's [`crate::EnvSource`]: `Exact` is the
//!    privileged daemon path and is exactly the pairs the caller handed in
//!    (built from scratch: `HOME`, `USER`, `LOGNAME`, `SHELL` of the target
//!    account, `PATH` = [`DEFAULT_TARGET_PATH`], plus the request's own names).
//!    `Inherit` is `aw run` / `--no-daemon`, which already runs as the user:
//!    this process's environment, minus `DYLD_INSERT_LIBRARIES` and
//!    `LD_PRELOAD` unless the caller named them, then the request's names.
//!    A non-UTF-8 entry is skipped and counted in the parent; it is not a panic.
//!
//! The gate pipe is `CLOEXEC` on both ends from the moment `pipe` returns. The
//! read end is inherited across the fork (close-on-exec applies at exec, not
//! at fork) and closed before `execve`, so the target never sees it. A
//! process-wide mutex covers `pipe` through `fork`, so no other thread of this
//! process can fork in that window and inherit either end.
//!
//! Each failed step `_exit`s with its own code (121–128). Those are not a
//! clean run: a clean run replaced the process. Exactly one owner waits, on
//! the pid this module forked. There is no `SIGCHLD` reaper and no second
//! `waitpid`. 【待验证】not run on a real Mac.

use crate::{
    HeldChild, IdentifiedCaller, Owner, PlatformError, ReapOutcome, ReleasedChild, SpawnFailure,
    SpawnRequest,
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
pub const EXIT_TERMINAL: i32 = 128;

/// `PATH` for a target whose environment is built from scratch
/// ([`crate::EnvSource::Exact`]). It is not this process's `PATH`: a privileged
/// daemon does not know the target user's shell `PATH`, and copying the
/// daemon's would hand over whatever the daemon was started with. The request
/// can still name `PATH` and override this. The daemon's `base_env` uses the
/// same string.
pub(crate) const DEFAULT_TARGET_PATH: &str =
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// What the child does before exec. Built in the parent; the child only reads it.
struct Prepared {
    /// `None` when the caller is already this account: no switch.
    switch: Option<PreparedSwitch>,
    /// `chdir` target, or `None` to keep the directory the parent is in.
    cwd: Option<std::ffi::CString>,
    /// Every path the child may `execve`, in order. Built as strings in the
    /// parent; the child tries them after the identity switch. Empty when the
    /// name was bare and no absolute PATH entry survived the skip rules.
    program_paths: Vec<std::ffi::CString>,
    _argv: Vec<std::ffi::CString>,
    /// NUL-terminated `execve` argv pointers. Built in the parent so the
    /// post-fork child only indexes preallocated memory.
    argv_pointers: Vec<*const libc::c_char>,
    /// `NAME=value`, applied only at `execve`. The child reads these through
    /// the pointer array built here; it never reads the process environment.
    _env: Vec<std::ffi::CString>,
    /// NUL-terminated `execve` environment pointers, also built before fork.
    env_pointers: Vec<*const libc::c_char>,
    /// Read end of the gate pipe. Closed in the child before exec.
    gate_read: std::os::fd::RawFd,
    /// Test-only stdout capture. Production launchers leave this `None`; the
    /// target otherwise inherits the caller's standard output unchanged.
    stdout: Option<std::os::fd::RawFd>,
    /// Write end of the failure pipe. The child writes one record here and
    /// `_exit`s; a successful `execve` closes it (it is `CLOEXEC`) and the parent
    /// sees EOF. The parent keeps the read end.
    report: std::os::fd::RawFd,
    /// Captured by the caller before `fork`. When true, the child must take
    /// the terminal before it reads the gate.
    terminal_handoff: bool,
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
    spawn_inner(caller, request, None)
}

/// Check an exited direct child with `waitid(WNOWAIT)`.  The caller remains
/// responsible for the single later `waitpid`, after it has cleaned the group
/// while the leader's pid cannot yet be reused.
pub(crate) fn peek_exit_without_reaping(pid: u32) -> std::io::Result<Option<ReapOutcome>> {
    ffi::peek_exit_without_reaping(pid)
}

#[cfg(test)]
fn spawn_capturing_stdout(
    caller: &IdentifiedCaller,
    request: &SpawnRequest,
    stdout: std::os::fd::OwnedFd,
) -> Result<Box<dyn HeldChild>, PlatformError> {
    spawn_inner(caller, request, Some(stdout))
}

fn spawn_inner(
    caller: &IdentifiedCaller,
    request: &SpawnRequest,
    stdout: Option<std::os::fd::OwnedFd>,
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
    // The pointer array is the whole environment `execve` applies. Which pairs
    // go into it is `request.env_source`, decided by the caller:
    // `Exact` (the privileged daemon) is `request.env` alone, built from
    // scratch, so a root daemon's own variables never reach the target.
    // `Inherit` (`aw run`, which already runs as the user) starts from this
    // process and overlays the request. A non-UTF-8 name or value is skipped
    // and logged here, in the parent; `std::env::vars()` would panic on it.
    let env_pairs = env_pairs_for(request);
    // `execve` does not search PATH, and the parent must not either: a privileged
    // daemon that stat'd the caller's PATH would be looking at directories as
    // root. The parent only joins strings. The child, after the identity switch
    // and `chdir`, tries each candidate. A name containing `/` is one candidate,
    // taken relative to the target's cwd. A bare name uses the PATH the target
    // will see; an empty entry, `.`, and any relative entry are skipped.
    let search_path = env_pairs
        .iter()
        .rev()
        .find(|(key, _)| key == "PATH")
        .map(|(_, value)| value.as_str());
    let candidates = program_candidates(program, search_path);
    let mut program_paths = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        program_paths.push(ffi::c_string(
            std::ffi::OsStr::new(candidate),
            "program is not valid text",
        )?);
    }
    let mut env = Vec::with_capacity(env_pairs.len());
    for (key, value) in &env_pairs {
        let pair = format!("{key}={value}");
        env.push(ffi::c_string(
            std::ffi::OsStr::new(&pair),
            "argument contains NUL",
        )?);
    }
    // `execve` takes pointer arrays rather than Rust vectors of strings. Build
    // both arrays before fork: after fork the child must not allocate.
    let argv_pointers = argv
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let env_pointers = env
        .iter()
        .map(|entry| entry.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    // Held across pipe creation and fork. Both ends are CLOEXEC before the
    // lock is released, so no other fork of this process inherits them.
    let _pipe_lock = PIPE_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let (gate_read, gate_write) = ffi::pipe_cloexec()?;
    let (report_read, report_write) = ffi::pipe_cloexec()?;
    let prepared = Prepared {
        switch,
        cwd,
        program_paths,
        _argv: argv,
        argv_pointers,
        _env: env,
        env_pointers,
        gate_read: std::os::fd::AsRawFd::as_raw_fd(&gate_read),
        stdout: stdout.as_ref().map(std::os::fd::AsRawFd::as_raw_fd),
        report: std::os::fd::AsRawFd::as_raw_fd(&report_write),
        terminal_handoff: request.terminal_handoff,
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
        // This is intentionally in the forked child, after setpgid and before
        // it can read the release gate. A parent-side handoff after release
        // races an immediately-reading target, which the terminal stops with
        // SIGTTIN. The helper uses raw async-signal-safe syscalls only.
        // Close the inherited writer before a possible terminal-handoff
        // failure waits on the gate. Otherwise aborting the held child could
        // never produce EOF because the child would still own a writer.
        ffi::close_fd(std::os::fd::AsRawFd::as_raw_fd(&gate_write));
        ffi::child_take_foreground(&prepared);
        ffi::child_restore_terminal_signal_defaults(&prepared);
        ffi::child_hold(&prepared);
    }
    ffi::set_own_group(pid);
    // Parent. The child has its own copy of the read end.
    drop(gate_read);
    drop(report_write);
    drop(stdout);
    drop(_pipe_lock);
    Ok(Box::new(MacHeld {
        pid: Some(pid as u32),
        gate: Some(gate_write),
        report: Some(report_read),
    }))
}

/// Process-wide: `pipe` and the `fork` that inherits the read end are one
/// critical section. Poisoned is fine; the lock still excludes other forks.
/// `NAME=value` pairs for the target, in the parent, before `fork`.
///
/// [`crate::EnvSource::Exact`] copies `request.env` and nothing else: the
/// process environment is not read. [`crate::EnvSource::Inherit`] starts from
/// this process (`vars_os`, so a non-UTF-8 value is not a panic), drops the two
/// loader names unless the request names them, then overlays `request.env`.
/// A pair that is not UTF-8 is skipped; the parent logs how many, never the
/// value.
fn env_pairs_for(request: &crate::SpawnRequest) -> Vec<(String, String)> {
    match request.env_source {
        crate::EnvSource::Exact => request.env.clone(),
        crate::EnvSource::Inherit => {
            let mut skipped = 0_u32;
            let mut pairs = Vec::new();
            for (key, value) in std::env::vars_os() {
                let Some(key) = key.to_str() else {
                    skipped += 1;
                    continue;
                };
                if request.env.iter().any(|(name, _)| name == key) {
                    continue;
                }
                if PRELOAD_KEYS.contains(&key) {
                    continue;
                }
                let Some(value) = value.to_str() else {
                    skipped += 1;
                    continue;
                };
                pairs.push((key.to_owned(), value.to_owned()));
            }
            if skipped > 0 {
                // Count only. The names and values can carry secrets, so they
                // are not printed. stderr, not a new dependency: this crate
                // does not link tracing.
                eprintln!(
                    "agentwatch: skipped {skipped} non-UTF-8 environment entries while building the target environment"
                );
            }
            pairs.extend(request.env.iter().cloned());
            pairs
        }
    }
}

/// Loader names the parent's environment must not hand to the target. The
/// caller can still set either one: their pair is appended after this filter.
/// [`crate::EnvSource::Exact`] never reads the parent, so these names only
/// matter on the inherit path.
const PRELOAD_KEYS: [&str; 2] = ["DYLD_INSERT_LIBRARIES", "LD_PRELOAD"];

/// Default search path when the target environment has no `PATH`.
const DEFAULT_SEARCH_PATH: &str = DEFAULT_TARGET_PATH;

/// Candidate paths for `program`, as strings. This function does not touch the
/// filesystem: no `stat`, no `access`, no `open`. The child tries them after it
/// has switched identity.
///
/// A name containing `/` is one candidate, used as given (relative to the
/// target cwd, which the child enters first). A bare name is joined to each
/// absolute `PATH` entry. An empty entry, `.`, and any entry that does not
/// start with `/` are skipped: they would search the daemon's own directory or
/// a directory named relative to it.
pub(crate) fn program_candidates(program: &str, search_path: Option<&str>) -> Vec<String> {
    if program.contains('/') {
        return vec![program.to_owned()];
    }
    if program.is_empty() {
        return Vec::new();
    }
    let mut candidates = Vec::new();
    for dir in search_path.unwrap_or(DEFAULT_SEARCH_PATH).split(':') {
        if !absolute_path_entry(dir) {
            continue;
        }
        candidates.push(format!("{dir}/{program}"));
    }
    candidates
}

/// An entry the search may use: absolute, and not empty or `.`.
fn absolute_path_entry(dir: &str) -> bool {
    dir.starts_with('/')
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
    /// Read end of the failure pipe. Release reads it after the release byte:
    /// EOF means the target exec'd, a record means the child failed and has
    /// exited (or is about to).
    report: Option<std::os::fd::OwnedFd>,
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
        // The child writes its raw errno and exits, or execs and the CLOEXEC
        // write end closes. Either way this read finishes. An errno means a
        // failed step: reap that child here, so it is never a zombie, then use
        // its documented exit status to classify the failed step.
        let report = self.report.take();
        let Some(report) = report else {
            return Err(PlatformError::Invalid {
                capability: "spawn_suspended",
                detail: "held child has no error pipe",
            });
        };
        if let Some(errno) = ffi::read_failure(&report).map_err(PlatformError::Io)? {
            let outcome = ffi::wait_outcome(pid).map_err(PlatformError::Io)?;
            return Err(failure_error(outcome, errno));
        }
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

/// The error a failed step becomes. The child writes only its raw errno to the
/// close-on-exec pipe; its `_exit` status says whether `chdir` or `execve`
/// produced it. Both can return `ENOENT`, so that status keeps their public
/// errors distinct.
fn failure_error(outcome: ReapOutcome, errno: i32) -> PlatformError {
    let permitted = matches!(errno, libc::EACCES | libc::EPERM);
    PlatformError::Spawn(match outcome {
        ReapOutcome::Exited(EXIT_CHDIR) if permitted => SpawnFailure::CwdNotPermitted,
        ReapOutcome::Exited(EXIT_CHDIR) => SpawnFailure::CwdNotFound,
        // `exec` keeps searching candidates after EACCES, and reports it over
        // ENOENT when any candidate denied execution (execvp semantics).
        ReapOutcome::Exited(EXIT_EXEC) if permitted => SpawnFailure::ProgramNotPermitted,
        ReapOutcome::Exited(EXIT_EXEC) => SpawnFailure::ProgramNotFound,
        ReapOutcome::Exited(EXIT_TERMINAL) => {
            return PlatformError::Invalid {
                capability: "spawn_suspended",
                detail: "held child could not take terminal foreground",
            }
        }
        _ => {
            return PlatformError::Invalid {
                capability: "spawn_suspended",
                detail: "hold child reported errno with an unexpected exit status",
            }
        }
    })
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
    Terminal,
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
            Self::Terminal => EXIT_TERMINAL,
        }
    }
}

/// The only `unsafe` for the launch path.
#[allow(unsafe_code)]
mod ffi {
    use super::{GateStep, PlatformError, Prepared, ReapOutcome};
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

    pub(super) fn peek_exit_without_reaping(pid: u32) -> io::Result<Option<ReapOutcome>> {
        let mut info = unsafe {
            // SAFETY: a zeroed siginfo_t is the documented initial value for
            // `waitid(WNOHANG)`, where the kernel leaves it zero when no child
            // state is available.
            std::mem::MaybeUninit::<libc::siginfo_t>::zeroed().assume_init()
        };
        let result = unsafe {
            // SAFETY: `info` is valid writable storage and this process owns
            // the specified direct child. WNOWAIT deliberately preserves its
            // status for the caller's one later blocking waitpid.
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let child_pid = unsafe {
            // SAFETY: `waitid` initialized `info`; the accessor is valid for
            // a SIGCHLD siginfo_t and returns zero for WNOHANG/no event.
            info.si_pid()
        };
        if child_pid == 0 {
            return Ok(None);
        }
        let status = unsafe {
            // SAFETY: a nonzero child pid means this is a populated SIGCHLD
            // result, for which si_status is the documented exit/signal value.
            info.si_status()
        };
        match info.si_code {
            libc::CLD_EXITED => Ok(Some(ReapOutcome::Exited(status))),
            libc::CLD_KILLED | libc::CLD_DUMPED => Ok(Some(ReapOutcome::Signaled(status))),
            _ => Ok(None),
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
    pub(super) fn child_hold(prepared: &Prepared) -> ! {
        if let Some(stdout) = prepared.stdout {
            redirect_stdout_or_exit(stdout, prepared.report);
        }
        if let Some(switch) = &prepared.switch {
            switch_ids(&switch.groups, switch.gid, switch.uid);
        }
        // Wait before chdir. A missing directory used to _exit here, which closed
        // the gate's read end before the parent wrote the release byte, and that
        // write came back EPIPE — the parent never got to read the failure record.
        wait_for_release(prepared.gate_read);
        if let Some(dir) = &prepared.cwd {
            chdir_or_exit(dir, prepared.report);
        }
        unsafe {
            // SAFETY: the read end was inherited and is no longer needed. It is
            // also CLOEXEC, so an exec would drop it; closing it here means the
            // creator's later close is not waited on by the target.
            libc::close(prepared.gate_read);
        }
        exec(prepared);
    }

    fn redirect_stdout_or_exit(stdout: RawFd, prepared_report: RawFd) {
        let duplicated = unsafe {
            // SAFETY: `stdout` is an inherited pipe descriptor created before
            // fork. `dup2` changes only this hold child and is async-signal-safe.
            libc::dup2(stdout, libc::STDOUT_FILENO)
        };
        if duplicated != libc::STDOUT_FILENO {
            report_and_exit(prepared_report, GateStep::Spec, errno_now());
        }
        if stdout != libc::STDOUT_FILENO {
            unsafe {
                // SAFETY: stdout now refers to the duplicated descriptor; this
                // closes only the inherited source descriptor in the child.
                libc::close(stdout);
            }
        }
    }

    /// Make this held child's process group foreground before it is allowed to
    /// read the release gate. All work here is post-fork-safe: stack storage
    /// plus raw POSIX calls. A failure is reported before the gate is read;
    /// the child then waits for its creator's release/abort so the parent's
    /// gate write cannot race a closed read end.
    pub(super) fn child_take_foreground(prepared: &Prepared) {
        if !prepared.terminal_handoff {
            return;
        }
        if handoff_stdin_to_own_group() {
            return;
        }
        report_errno(prepared.report, errno_now());
        wait_for_release(prepared.gate_read);
        exit_step(GateStep::Terminal);
    }

    /// A process launched from a test runner can inherit ignored terminal
    /// signals. `execve` preserves that disposition, so reset them after the
    /// foreground handoff and before the target can run. This is deliberately
    /// limited to terminal launches: non-terminal callers may intentionally
    /// arrange their own signal handling.
    pub(super) fn child_restore_terminal_signal_defaults(prepared: &Prepared) {
        if !prepared.terminal_handoff {
            return;
        }
        for signal in [libc::SIGINT, libc::SIGQUIT, libc::SIGHUP] {
            if set_default_disposition(signal) {
                continue;
            }
            report_errno(prepared.report, errno_now());
            wait_for_release(prepared.gate_read);
            exit_step(GateStep::Terminal);
        }
    }

    fn set_default_disposition(signal: libc::c_int) -> bool {
        let mut action = unsafe {
            // SAFETY: the structure is initialized before `sigaction` reads
            // it, and only this child's signal disposition is changed.
            std::mem::MaybeUninit::<libc::sigaction>::zeroed().assume_init()
        };
        unsafe {
            // SAFETY: `action` is writable stack storage. `sigaction` is an
            // async-signal-safe POSIX call, so it is valid after `fork`.
            libc::sigemptyset(&mut action.sa_mask) == 0 && {
                action.sa_sigaction = libc::SIG_DFL;
                libc::sigaction(signal, &action, std::ptr::null_mut()) == 0
            }
        }
    }

    /// Close an inherited descriptor in the forked child without invoking a
    /// Rust destructor.
    pub(super) fn close_fd(fd: RawFd) {
        unsafe {
            // SAFETY: the child owns its inherited descriptor copy.
            libc::close(fd);
        }
    }

    /// Block `SIGTTOU` while handing stdin's terminal to the child group, then
    /// restore exactly the inherited mask. `tcsetpgrp`, `getpgrp`, and
    /// `sigprocmask` are async-signal-safe POSIX calls.
    fn handoff_stdin_to_own_group() -> bool {
        let mut block = unsafe {
            // SAFETY: `sigset_t` is immediately initialized by sigemptyset.
            std::mem::MaybeUninit::<libc::sigset_t>::zeroed().assume_init()
        };
        let mut previous = unsafe {
            // SAFETY: libc fills this before it is read by the restore call.
            std::mem::MaybeUninit::<libc::sigset_t>::zeroed().assume_init()
        };
        unsafe {
            // SAFETY: both pointers name writable stack signal sets. The
            // signal mask and foreground group belong only to this child.
            if libc::sigemptyset(&mut block) != 0
                || libc::sigaddset(&mut block, libc::SIGTTOU) != 0
                || libc::sigprocmask(libc::SIG_BLOCK, &block, &mut previous) != 0
            {
                return false;
            }
            let switched = libc::tcsetpgrp(libc::STDIN_FILENO, libc::getpgrp()) == 0;
            let restored =
                libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) == 0;
            switched && restored
        }
    }

    /// `execve` errno that means "not this candidate, try the next". `execvp`
    /// treats these the same way: the name is not a file here, so keep looking.
    fn try_next(errno: i32) -> bool {
        matches!(
            errno,
            libc::ENOENT | libc::ENOTDIR | libc::ESTALE | libc::ENODEV | libc::ETIMEDOUT
        )
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

    fn chdir_or_exit(path: &std::ffi::CStr, prepared_report: RawFd) {
        let rc = unsafe {
            // SAFETY: `path` is NUL-terminated and was allocated in the parent.
            // chdir is async-signal-safe and only affects this process.
            libc::chdir(path.as_ptr())
        };
        if rc != 0 {
            // Raw errno: building a `std::io::Error` allocates, and this runs
            // after `fork` in a process that has other threads.
            report_and_exit(prepared_report, GateStep::Chdir, errno_now());
        }
    }

    /// The current errno, without allocating. `std::io::Error::last_os_error`
    /// builds an owned error, which is not safe after `fork`.
    fn errno_now() -> i32 {
        #[cfg(target_os = "linux")]
        unsafe {
            // SAFETY: `__errno_location` returns this thread's errno and cannot fail.
            *libc::__errno_location()
        }
        #[cfg(not(target_os = "linux"))]
        unsafe {
            // SAFETY: `__error` is the macOS equivalent and cannot fail.
            *libc::__error()
        }
    }

    /// Write only the raw errno integer, then `_exit`. Never returns. The
    /// write is a raw syscall: this runs after `fork`, so nothing here
    /// allocates or formats a string.
    fn report_and_exit(fd: RawFd, step: GateStep, errno: i32) -> ! {
        report_errno(fd, errno);
        exit_step(step);
    }

    /// Write the raw errno without exiting. The terminal-handoff path must
    /// remain alive at the gate so its creator can reliably observe the error.
    fn report_errno(fd: RawFd, errno: i32) {
        let bytes = errno.max(0).to_ne_bytes();
        unsafe {
            // SAFETY: `bytes` is the raw integer and `fd` is the pipe end this
            // child inherited. `write` is async-signal-safe. A short or failed
            // write still exits; the parent treats a partial record as I/O
            // failure, never as a successful exec.
            libc::write(fd, bytes.as_ptr().cast(), bytes.len());
        }
    }

    /// Read one raw errno. `None` is EOF: the child exec'd and the CLOEXEC
    /// write end closed, which is success. A partial integer is I/O failure,
    /// never success.
    pub(super) fn read_failure(fd: &OwnedFd) -> io::Result<Option<i32>> {
        let mut bytes = [0_u8; 4];
        let mut got = 0_usize;
        while got < bytes.len() {
            let read = unsafe {
                // SAFETY: `bytes` is live and `fd` is the pipe end this process
                // owns. A short read is retried; EOF before four bytes is "no
                // record", which the caller treats as a failed exec.
                libc::read(
                    fd.as_raw_fd(),
                    bytes[got..].as_mut_ptr().cast(),
                    bytes.len() - got,
                )
            };
            if read < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if read == 0 {
                return if got == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "partial held-child errno record",
                    ))
                };
            }
            got += read as usize;
        }
        Ok(Some(i32::from_ne_bytes(bytes)))
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
                if errno_now() == libc::EINTR {
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

    /// `execve` each candidate with the caller's argv and environment. Only
    /// returns on failure, which `_exit`s 127. `ENOENT`/`ENOTDIR` and the other
    /// "not here" errnos try the next candidate; `EACCES` is remembered and the
    /// search continues; any other errno stops. The errno left for the parent is
    /// `EACCES` when one was seen, otherwise the last errno.
    fn exec(prepared: &Prepared) -> ! {
        if prepared.argv_pointers.len() <= 1 || prepared.program_paths.is_empty() {
            // No candidate at all is "not found", the same answer `execvp` gives
            // for a bare name whose PATH produced nothing.
            report_and_exit(prepared.report, GateStep::Exec, libc::ENOENT);
        }
        let mut saw_eacces = false;
        let mut last = libc::ENOENT;
        for path in &prepared.program_paths {
            unsafe {
                // SAFETY: both arrays are NULL-terminated and point at strings
                // allocated in the parent, which outlive this call. `path` is
                // one of those strings. `execve` replaces the process; it only
                // returns on failure, and this child does not allocate.
                libc::execve(
                    path.as_ptr(),
                    prepared.argv_pointers.as_ptr(),
                    prepared.env_pointers.as_ptr(),
                );
            }
            let errno = errno_now();
            if try_next(errno) {
                last = errno;
                continue;
            }
            if errno == libc::EACCES {
                saw_eacces = true;
                last = errno;
                continue;
            }
            report_and_exit(prepared.report, GateStep::Exec, errno);
        }
        report_and_exit(
            prepared.report,
            GateStep::Exec,
            if saw_eacces { libc::EACCES } else { last },
        );
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        GateStep, EXIT_CHDIR, EXIT_EXEC, EXIT_SETGID, EXIT_SETGROUPS, EXIT_SETUID, EXIT_SPEC,
        EXIT_SWITCH_CHECK, EXIT_TERMINAL,
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
        assert_eq!(GateStep::Terminal.code(), EXIT_TERMINAL);
        assert_eq!(EXIT_TERMINAL, 128);
        let codes = [
            EXIT_SPEC,
            EXIT_SETGROUPS,
            EXIT_SETGID,
            EXIT_SETUID,
            EXIT_SWITCH_CHECK,
            EXIT_CHDIR,
            EXIT_EXEC,
            EXIT_TERMINAL,
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

    /// A directory no other test in this process uses. The name includes a counter,
    /// not just the process id: cargo runs these tests on threads of one process,
    /// and two of them writing the same script races the child's exec.
    fn private_dir(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "aw-hold-{label}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        dir
    }

    /// The forked child does not run the target until the release byte, and
    /// the target's exit code comes back through the one owning handle.
    #[cfg(unix)]
    #[test]
    fn forked_child_holds_until_release_and_returns_the_exit_code() {
        use crate::{IdentifiedCaller, SpawnRequest};
        let caller = IdentifiedCaller::current_user().expect("current user");
        let dir = private_dir("run");
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
            terminal_handoff: false,
            env_source: crate::EnvSource::Inherit,
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
        let dir = private_dir("abort");
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
            terminal_handoff: false,
            env_source: crate::EnvSource::Inherit,
        };
        let mut held = super::spawn(&caller, &request).expect("held");
        held.abort().expect("abort");
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!marker.exists(), "abort exec'd the target");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Candidate building is string work. A directory that does not exist, an
    /// empty entry, and `.` never produce a path this process would stat: the
    /// empty entry and `.` are absent, and the missing directory is only text.
    #[cfg(unix)]
    #[test]
    fn candidate_building_skips_empty_and_dot_and_touches_nothing() {
        let missing = format!("/no/such/aw-path-{}", std::process::id());
        let path = format!(":{missing}:.::/usr/bin:rel");
        let got = super::program_candidates("sh", Some(&path));
        assert_eq!(
            got,
            vec![format!("{missing}/sh"), "/usr/bin/sh".to_owned()],
            "empty, `.`, and a relative entry are skipped"
        );
        assert!(
            !std::path::Path::new(&missing).exists(),
            "building the list must not create or require the directory"
        );
        // A name with a slash is the name itself, even when it is relative.
        assert_eq!(
            super::program_candidates("bin/sh", Some(&path)),
            vec!["bin/sh".to_owned()]
        );
    }

    /// A bare `sh` runs. The parent did not turn it into an absolute path; the
    /// child found it on the target PATH after the identity switch (here a no-op,
    /// because the caller is this account).
    #[cfg(unix)]
    #[test]
    fn bare_sh_runs_from_the_target_path() {
        use crate::{IdentifiedCaller, SpawnRequest};
        let caller = IdentifiedCaller::current_user().expect("current user");
        let request = SpawnRequest {
            command: vec!["sh".to_owned(), "-c".to_owned(), "exit 0".to_owned()],
            cwd: Some(std::path::PathBuf::from("/")),
            env: Vec::new(),
            terminal_handoff: false,
            env_source: crate::EnvSource::Inherit,
        };
        let held = super::spawn(&caller, &request).expect("held");
        let released = held.release().expect("release");
        assert_eq!(
            released.wait().expect("wait"),
            crate::ReapOutcome::Exited(0)
        );
    }

    /// A program that is not on PATH fails at exec, and the child is reaped:
    /// there is no zombie left for this pid.
    #[cfg(unix)]
    #[test]
    fn missing_program_is_reaped_and_reported() {
        use crate::{IdentifiedCaller, PlatformError, SpawnFailure, SpawnRequest};
        let caller = IdentifiedCaller::current_user().expect("current user");
        let request = SpawnRequest {
            command: vec!["aw-no-such-prog-xyz".to_owned()],
            cwd: Some(std::path::PathBuf::from("/")),
            env: Vec::new(),
            terminal_handoff: false,
            env_source: crate::EnvSource::Inherit,
        };
        let held = super::spawn(&caller, &request).expect("held");
        let pid = held.pid();
        let Err(error) = held.release() else {
            panic!("a missing program released");
        };
        let PlatformError::Spawn(SpawnFailure::ProgramNotFound) = error else {
            panic!("expected a typed program-not-found error");
        };
        // Reaped: a second wait finds no child.
        let still = std::process::Command::new("ps")
            .args(["-p", &pid.to_string()])
            .output();
        if let Ok(output) = still {
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(
                !text
                    .lines()
                    .any(|line| line.split_whitespace().next() == Some(&pid.to_string())),
                "the failed child is still around: {text}"
            );
        }
    }

    /// The root hold path must not reveal whether a program exists below a
    /// root-owned 0700 directory. The child switches to `nobody` before it
    /// tries either form of the identical absolute candidate.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root and a normal account"]
    fn root_hold_does_not_distinguish_a_program_in_a_private_directory() {
        use crate::{
            EnvSource, IdentifiedCaller, Owner, PeerIdentity, PlatformError, SpawnFailure,
            SpawnRequest,
        };
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(nix::unistd::geteuid().as_raw(), 0, "run this test as root");
        let nobody = nix::unistd::User::from_name("nobody")
            .expect("nobody lookup")
            .expect("this test needs the nobody account");
        let uid = nobody.uid.as_raw();
        let gid = nobody.gid.as_raw();
        let caller = IdentifiedCaller::from_peer(PeerIdentity::new(
            Owner::Unix {
                ruid: uid,
                euid: uid,
                suid: uid,
                rgid: gid,
                egid: gid,
                sgid: gid,
                groups: Some(vec![gid]),
            },
            None,
        ));
        let dir = private_dir("root-hidden");
        let hidden = dir.join("root-only");
        std::fs::create_dir(&hidden).expect("root-only directory");
        std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o700))
            .expect("root-only directory permissions");
        let program = hidden.join("program");
        std::fs::write(&program, "#!/bin/sh\nexit 0\n").expect("hidden program");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
            .expect("hidden program permissions");

        let attempt = |path: &std::path::Path| {
            let request = SpawnRequest {
                command: vec![path.to_string_lossy().into_owned()],
                cwd: Some(std::path::PathBuf::from("/")),
                env: Vec::new(),
                terminal_handoff: false,
                env_source: EnvSource::Exact,
            };
            let held = super::spawn(&caller, &request).expect("held child");
            let error = match held.release() {
                Err(error) => error,
                Ok(_) => panic!("inaccessible program must fail"),
            };
            let PlatformError::Spawn(kind) = error else {
                panic!("expected a typed child exec failure, got {error:?}");
            };
            kind
        };

        let present = attempt(&program);
        std::fs::remove_file(&program).expect("remove hidden program");
        let absent = attempt(&program);
        assert_eq!(present, SpawnFailure::ProgramNotPermitted);
        assert_eq!(present, absent, "presence below 0700 changed the result");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A working directory that does not exist fails at `chdir`, which is a
    /// different error from a missing program.
    #[cfg(unix)]
    #[test]
    fn missing_cwd_is_not_a_missing_program() {
        use crate::{IdentifiedCaller, PlatformError, SpawnFailure, SpawnRequest};
        let caller = IdentifiedCaller::current_user().expect("current user");
        let request = SpawnRequest {
            command: vec!["sh".to_owned(), "-c".to_owned(), "exit 0".to_owned()],
            cwd: Some(std::path::PathBuf::from(format!(
                "/no/such/aw-cwd-{}",
                std::process::id()
            ))),
            env: Vec::new(),
            terminal_handoff: false,
            env_source: crate::EnvSource::Inherit,
        };
        let held = super::spawn(&caller, &request).expect("held");
        let Err(error) = held.release() else {
            panic!("a missing directory released");
        };
        let PlatformError::Spawn(SpawnFailure::CwdNotFound) = error else {
            panic!("expected a typed cwd-not-found error");
        };
    }

    /// `execvp` semantics retain a permission denial even if later PATH
    /// entries do not contain the requested name.  The hold-pipe record must
    /// preserve that distinction for the caller, rather than flattening it to
    /// a missing program.
    #[cfg(unix)]
    #[test]
    fn non_executable_path_candidate_beats_later_missing_candidates() {
        use crate::{IdentifiedCaller, PlatformError, SpawnFailure, SpawnRequest};
        use std::os::unix::fs::PermissionsExt;
        let caller = IdentifiedCaller::current_user().expect("current user");
        let dir = private_dir("eacces");
        let program = dir.join("aw-no-exec");
        std::fs::write(&program, "#!/bin/sh\nexit 0\n").expect("script");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let request = SpawnRequest {
            command: vec!["aw-no-exec".to_owned()],
            cwd: Some(dir.clone()),
            env: vec![(
                "PATH".to_owned(),
                format!("{}:/no/such/aw-path", dir.display()),
            )],
            terminal_handoff: false,
            env_source: crate::EnvSource::Inherit,
        };
        let held = super::spawn(&caller, &request).expect("held");
        let Err(error) = held.release() else {
            panic!("a non-executable program released");
        };
        assert!(matches!(
            error,
            PlatformError::Spawn(SpawnFailure::ProgramNotPermitted)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A relative program name that contains `/` is resolved against the target
    /// cwd, not this process's directory. The script lives only in that cwd.
    #[cfg(unix)]
    #[test]
    fn relative_program_runs_from_the_target_cwd() {
        use crate::{IdentifiedCaller, SpawnRequest};
        use std::os::unix::fs::PermissionsExt;
        let caller = IdentifiedCaller::current_user().expect("current user");
        let dir = private_dir("rel");
        let script = dir.join("aw-rel-script");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").expect("script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let request = SpawnRequest {
            command: vec!["./aw-rel-script".to_owned()],
            cwd: Some(dir.clone()),
            env: Vec::new(),
            terminal_handoff: false,
            env_source: crate::EnvSource::Inherit,
        };
        let held = super::spawn(&caller, &request).expect("held");
        let released = held.release().expect("release");
        assert_eq!(
            released.wait().expect("wait"),
            crate::ReapOutcome::Exited(0)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Privileged-daemon path: the target's environment is exactly the five
    /// account basics plus the names the request added. Nothing this process
    /// has — including a sentinel set here, and `LD_PRELOAD` — is in that set.
    /// The comparison is the whole set, not "the secret is absent".
    #[cfg(unix)]
    #[test]
    fn exact_env_is_only_the_base_five_plus_the_request() {
        use crate::{EnvSource, IdentifiedCaller, SpawnRequest};
        use std::io::Read;
        let caller = IdentifiedCaller::current_user().expect("current user");
        // A name this process has and the target must not. The value is a
        // sentinel, not a real secret; the assertion is that the name is absent
        // and that the printed set equals the requested set.
        std::env::set_var("AW_HOLD_SENTINEL", "present-in-parent");
        std::env::set_var("LD_PRELOAD", "/no/such/libaw-preload.so");
        let base = account_base_env(caller_uid(&caller));
        let mut env = base.clone();
        env.push(("AW_RV".to_owned(), "1".to_owned()));
        let (out, capture) = super::ffi::pipe_cloexec().expect("stdout pipe");
        let request = SpawnRequest {
            command: vec!["/usr/bin/env".to_owned()],
            cwd: None,
            env,
            terminal_handoff: false,
            env_source: EnvSource::Exact,
        };
        let held = super::spawn_capturing_stdout(&caller, &request, capture).expect("held");
        let released = held.release().expect("release");
        assert_eq!(
            released.wait().expect("wait"),
            crate::ReapOutcome::Exited(0)
        );
        let mut text = String::new();
        std::fs::File::from(out)
            .read_to_string(&mut text)
            .expect("env output");
        let mut got: Vec<String> = text.lines().map(str::to_owned).collect();
        got.sort();
        let mut want: Vec<String> = base
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .chain(std::iter::once("AW_RV=1".to_owned()))
            .collect();
        want.sort();
        assert_eq!(got, want, "target env is not exactly the base plus AW_RV");
        assert!(!got.iter().any(|line| line.starts_with("AW_HOLD_SENTINEL=")));
        assert!(!got.iter().any(|line| line.starts_with("LD_PRELOAD=")));
        std::env::remove_var("AW_HOLD_SENTINEL");
        std::env::remove_var("LD_PRELOAD");
    }

    /// The five names a privileged launch builds from the target account, the
    /// same five `base_env` in the daemon starts from. `PATH` is the documented
    /// default, not this process's `PATH`. `uid` is the account being launched,
    /// which is the caller — not whoever this process happens to be.
    #[cfg(unix)]
    fn account_base_env(uid: u32) -> Vec<(String, String)> {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .expect("passwd entry for the current user");
        let path = |p: &std::path::Path| p.display().to_string();
        vec![
            ("HOME".to_owned(), path(&user.dir)),
            ("USER".to_owned(), user.name.clone()),
            ("LOGNAME".to_owned(), user.name),
            ("SHELL".to_owned(), path(&user.shell)),
            ("PATH".to_owned(), super::DEFAULT_TARGET_PATH.to_owned()),
        ]
    }

    /// The account `spawn` launches as: the caller's effective uid.
    #[cfg(unix)]
    fn caller_uid(caller: &crate::IdentifiedCaller) -> u32 {
        match caller.owner() {
            crate::Owner::Unix { euid, .. } => *euid,
            crate::Owner::Windows { .. } => 0,
        }
    }

    #[cfg(feature = "test-hold-delay")]
    #[test]
    fn delay_is_capped_inside_release() {
        std::env::set_var("AW_TEST_HOLD_DELAY_MS", "10001");
        assert_eq!(super::hold_delay(), Some(10_000));
        std::env::remove_var("AW_TEST_HOLD_DELAY_MS");
    }
}
