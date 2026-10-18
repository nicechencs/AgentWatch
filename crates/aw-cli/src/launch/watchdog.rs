//! Re-exec'd Linux watchdog for non-interactive programs started by `aw`.
//!
//! The parent CLI and this helper use an inherited private Unix socket. Command
//! and environment values never become helper argv or environment data. The
//! helper becomes a new session and Linux child subreaper before it creates the
//! held program, so cleanup reaches descendants which daemonize with `setsid`.

#[cfg(not(test))]
use std::io::IsTerminal;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, ExitStatus};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc,
};
use std::time::Duration;

use aw_platform::{
    platform, EnvSource, HeldChild, IdentifiedCaller, PlatformError, ReapOutcome, SpawnFailure,
    SpawnRequest,
};
use nix::errno::Errno;
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};

use super::RunSpec;

const INTERNAL_ARGUMENT: &str = "__aw_internal_linux_watchdog";
const READY: u8 = b'R';
const CONFIG: u8 = b'C';
const START: u8 = b'S';
const RELEASED: u8 = b'G';
const FAILED: u8 = b'F';
const MAX_CONFIG_BYTES: usize = 1 << 20;
const SIGNAL_POLL: Duration = Duration::from_millis(5);

/// A started watchdog. `aw` owns this helper while the helper owns the target.
pub struct Watchdog {
    child: Child,
    control: UnixStream,
    program_pid: u32,
    released: bool,
}

/// Failure that crossed the private watchdog protocol.
#[derive(Debug, Clone, Copy)]
pub enum WatchdogError {
    /// The held target reported its typed post-gate launch failure.
    Spawn(SpawnFailure),
    /// The helper or private control channel ended unexpectedly.
    Unavailable,
}

/// `true` when this executable invocation is the private watchdog helper.
#[must_use]
pub fn is_internal() -> bool {
    std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == INTERNAL_ARGUMENT)
}

/// A terminal target must remain in the terminal session so the terminal layer
/// can hand its process group foreground control. See the design note for this
/// necessary session-boundary exception.
#[must_use]
pub fn should_wrap() -> bool {
    // Library unit tests execute the test harness rather than this CLI
    // binary, so it cannot dispatch the private re-exec argument. End-to-end
    // tests exercise the actual binary and watchdog path instead.
    #[cfg(test)]
    {
        false
    }
    #[cfg(not(test))]
    {
        !io::stdin().is_terminal()
    }
}

/// Run the re-exec'd helper and return the program's conventional exit code.
/// No error text is written because the control protocol only carries status.
pub fn run_internal() -> i32 {
    let Some(fd) = std::env::args_os()
        .nth(2)
        .and_then(|text| text.into_string().ok())
        .and_then(|text| text.parse().ok())
    else {
        return 1;
    };
    let Ok(mut control) = aw_platform::take_watchdog_control(fd) else {
        return 1;
    };
    let parent_pid = parent_pid_from_control(&control);
    let died = Arc::new(AtomicBool::new(false));
    let Ok(signal_id) =
        signal_hook::flag::register(signal_hook::consts::signal::SIGUSR1, Arc::clone(&died))
    else {
        return 1;
    };
    let result = run_inner(&mut control, parent_pid, &died);
    let _ = signal_hook::low_level::unregister(signal_id);
    result
}

fn parent_pid_from_control(control: &UnixStream) -> u32 {
    let _ = control;
    std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|text| text.rsplit_once(')').map(|(_, tail)| tail.to_owned()))
        .and_then(|tail| tail.split_whitespace().nth(1)?.parse().ok())
        .unwrap_or(0)
}

fn run_inner(control: &mut UnixStream, parent_pid: u32, died: &AtomicBool) -> i32 {
    if aw_platform::prepare_watchdog(parent_pid).is_err() {
        return 1;
    }
    // This descriptor is inherited solely across the helper re-exec. Mark it
    // close-on-exec before the held target is forked, so neither the target nor
    // its descendants can keep the parent-liveness channel open.
    if set_cloexec(control.as_fd()).is_err() {
        return 1;
    }
    let Ok(request) = receive_config(control) else {
        return 1;
    };
    let Ok(mut held) = start_held_program(&request) else {
        return 1;
    };
    let pid = held.pid();
    if send_pid(control, READY, pid).is_err() {
        let _ = held.abort();
        return 1;
    }

    let mut start = [0_u8; 1];
    if control.read_exact(&mut start).is_err() || start[0] != START || died.load(Ordering::Relaxed)
    {
        let _ = held.abort();
        return 1;
    }
    let mut released = match held.release() {
        Ok(released) => released,
        Err(error) => {
            let _ = send_release_failure(control, error);
            return 1;
        }
    };
    if control
        .write_all(&[RELEASED, 0])
        .and_then(|_| control.flush())
        .is_err()
    {
        aw_platform::cleanup_watchdog_descendants();
        return 1;
    }

    let (ended, events) = mpsc::channel();
    if let Ok(mut watch) = control.try_clone() {
        std::thread::spawn(move || {
            let mut byte = [0_u8; 1];
            let _ = watch.read(&mut byte);
            let _ = ended.send(());
        });
    }

    loop {
        if died.load(Ordering::Relaxed) || events.try_recv().is_ok() {
            aw_platform::cleanup_watchdog_descendants();
            return 1;
        }
        match released.try_reap() {
            Ok(ReapOutcome::Exited(code)) => {
                aw_platform::cleanup_watchdog_descendants();
                return code;
            }
            Ok(ReapOutcome::Signaled(signal)) => {
                aw_platform::cleanup_watchdog_descendants();
                return 128 + signal;
            }
            Ok(ReapOutcome::StillRunning) => std::thread::sleep(SIGNAL_POLL),
            Err(_) => {
                aw_platform::cleanup_watchdog_descendants();
                return 1;
            }
        }
    }
}

fn start_held_program(request: &Request) -> Result<Box<dyn HeldChild>, PlatformError> {
    let caller = IdentifiedCaller::current_user()?;
    platform().spawn_suspended(
        &caller,
        &SpawnRequest {
            command: request.command.clone(),
            cwd: request.cwd.clone().map(Into::into),
            env: request.env.clone(),
            env_source: EnvSource::Inherit,
        },
    )
}

fn receive_config(control: &mut UnixStream) -> io::Result<Request> {
    let mut header = [0_u8; 5];
    control.read_exact(&mut header)?;
    if header[0] != CONFIG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing config"));
    }
    let length = u32::from_be_bytes(header[1..].try_into().unwrap_or([0; 4])) as usize;
    if length > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized config",
        ));
    }
    let mut bytes = vec![0; length];
    control.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid config"))
}

fn send_pid(control: &mut UnixStream, kind: u8, pid: u32) -> io::Result<()> {
    control.write_all(&[kind])?;
    control.write_all(&pid.to_be_bytes())?;
    control.flush()
}

fn send_release_failure(control: &mut UnixStream, error: PlatformError) -> io::Result<()> {
    let kind = match error {
        PlatformError::Spawn(SpawnFailure::ProgramNotFound) => 1,
        PlatformError::Spawn(SpawnFailure::ProgramNotPermitted) => 2,
        PlatformError::Spawn(SpawnFailure::CwdNotFound) => 3,
        PlatformError::Spawn(SpawnFailure::CwdNotPermitted) => 4,
        _ => 0,
    };
    control.write_all(&[FAILED, kind])?;
    control.flush()
}

#[derive(Serialize, Deserialize)]
struct Request {
    command: Vec<String>,
    cwd: Option<String>,
    env: Vec<(String, String)>,
}

impl From<&RunSpec> for Request {
    fn from(spec: &RunSpec) -> Self {
        Self {
            command: spec.command.clone(),
            cwd: spec.cwd.clone(),
            env: spec.env.clone(),
        }
    }
}

impl Watchdog {
    /// Spawn a held watchdog. Its target exists but cannot exec until release.
    pub fn spawn(spec: &RunSpec) -> Result<Self, WatchdogError> {
        let bytes =
            serde_json::to_vec(&Request::from(spec)).map_err(|_| WatchdogError::Unavailable)?;
        let (mut parent, child_control) =
            UnixStream::pair().map_err(|_| WatchdogError::Unavailable)?;
        clear_cloexec(child_control.as_fd()).map_err(|_| WatchdogError::Unavailable)?;
        let executable = std::env::current_exe().map_err(|_| WatchdogError::Unavailable)?;
        let child = std::process::Command::new(executable)
            .arg(INTERNAL_ARGUMENT)
            .arg(child_control.as_raw_fd().to_string())
            .spawn()
            .map_err(|_| WatchdogError::Unavailable)?;
        drop(child_control);
        send_config(&mut parent, &bytes).map_err(|_| WatchdogError::Unavailable)?;
        let mut reply = [0_u8; 5];
        parent
            .read_exact(&mut reply)
            .map_err(|_| WatchdogError::Unavailable)?;
        if reply[0] != READY {
            return Err(WatchdogError::Unavailable);
        }
        Ok(Self {
            child,
            control: parent,
            program_pid: u32::from_be_bytes(reply[1..].try_into().unwrap_or([0; 4])),
            released: false,
        })
    }

    #[must_use]
    pub fn pid(&self) -> u32 {
        self.program_pid
    }

    /// Release the held program after its daemon session has adopted the pid.
    pub fn release(&mut self) -> Result<(), WatchdogError> {
        self.control
            .write_all(&[START])
            .and_then(|_| self.control.flush())
            .map_err(|_| WatchdogError::Unavailable)?;
        let mut reply = [0_u8; 2];
        self.control
            .read_exact(&mut reply)
            .map_err(|_| WatchdogError::Unavailable)?;
        match reply {
            [RELEASED, _] => {
                self.released = true;
                Ok(())
            }
            [FAILED, kind] => Err(spawn_failure(kind)
                .map(WatchdogError::Spawn)
                .unwrap_or(WatchdogError::Unavailable)),
            _ => Err(WatchdogError::Unavailable),
        }
    }

    /// Wait for the helper while relaying ordinary supervisor signals to the
    /// target group. Terminal Ctrl-C is not used here: interactive launches
    /// retain the terminal-specific path instead.
    pub fn wait(&mut self) -> Result<i32, WatchdogError> {
        let pending = Arc::new(AtomicUsize::new(0));
        let mut registrations = Vec::new();
        for signal in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
            let id = signal_hook::flag::register_usize(
                signal as i32,
                Arc::clone(&pending),
                signal as usize,
            )
            .map_err(|_| WatchdogError::Unavailable)?;
            registrations.push(id);
        }
        let result = loop {
            if let Some(signal) = take_signal(&pending) {
                if let Err(error) = forward_group(self.program_pid, signal) {
                    break Err(error);
                }
            }
            match self
                .child
                .try_wait()
                .map_err(|_| WatchdogError::Unavailable)?
            {
                Some(status) => break Ok(status_code(status)),
                None => std::thread::sleep(SIGNAL_POLL),
            }
        };
        for id in registrations {
            let _ = signal_hook::low_level::unregister(id);
        }
        result
    }

    /// Abort a held target, or end a released target through the helper so it
    /// can still reap descendants before it exits.
    pub fn abort(&mut self) {
        if self.released {
            let _ = forward_group(self.program_pid, Signal::SIGKILL);
        } else {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        if !self.released {
            self.abort();
        }
    }
}

fn spawn_failure(kind: u8) -> Option<SpawnFailure> {
    match kind {
        1 => Some(SpawnFailure::ProgramNotFound),
        2 => Some(SpawnFailure::ProgramNotPermitted),
        3 => Some(SpawnFailure::CwdNotFound),
        4 => Some(SpawnFailure::CwdNotPermitted),
        _ => None,
    }
}

fn take_signal(pending: &AtomicUsize) -> Option<Signal> {
    match pending.swap(0, Ordering::SeqCst) {
        number if number == Signal::SIGINT as usize => Some(Signal::SIGINT),
        number if number == Signal::SIGTERM as usize => Some(Signal::SIGTERM),
        number if number == Signal::SIGHUP as usize => Some(Signal::SIGHUP),
        _ => None,
    }
}

fn forward_group(pid: u32, signal: Signal) -> Result<(), WatchdogError> {
    let pid = i32::try_from(pid).map_err(|_| WatchdogError::Unavailable)?;
    match killpg(Pid::from_raw(pid), signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(_) => Err(WatchdogError::Unavailable),
    }
}

fn status_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

fn send_config(control: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "config too large"))?;
    control.write_all(&[CONFIG])?;
    control.write_all(&length.to_be_bytes())?;
    control.write_all(bytes)?;
    control.flush()
}

fn clear_cloexec(fd: std::os::fd::BorrowedFd<'_>) -> nix::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    fcntl(fd, FcntlArg::F_SETFD(FdFlag::empty())).map(drop)
}

fn set_cloexec(fd: std::os::fd::BorrowedFd<'_>) -> nix::Result<()> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map(drop)
}
