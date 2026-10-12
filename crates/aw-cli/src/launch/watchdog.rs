//! Re-exec'd Linux watchdog for non-interactive programs started by `aw`.
//!
//! The parent CLI and this helper use an inherited private Unix socket. Command
//! and environment values never become helper argv or environment data. The
//! helper becomes a new session and Linux child subreaper before it creates the
//! held program, so cleanup reaches descendants which daemonize with `setsid`.

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, ExitStatus};
use std::sync::{
    atomic::{AtomicBool, Ordering},
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
const ABORT: u8 = b'A';
const CLEANUP: u8 = b'L';
const MAX_CONFIG_BYTES: usize = 1 << 20;
const SIGNAL_POLL: Duration = Duration::from_millis(5);

/// A started watchdog. `aw` owns this helper while the helper owns the target.
pub struct Watchdog {
    child: Child,
    control: UnixStream,
    program_pid: u32,
    released: bool,
    cleanup: Option<CleanupReport>,
    pending: PendingSignals,
    registrations: Vec<signal_hook::SigId>,
}

/// Bounded cleanup data that can safely cross the private watchdog socket and
/// be attached to a daemon-backed session.  It contains identifiers only, no
/// command text, environment, or process data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CleanupReport {
    pub(crate) count: u32,
    pub(crate) pids: Vec<u32>,
    pub(crate) eperm_pid: Option<u32>,
}

enum SupervisorEvent {
    Signal(Signal),
    Abort,
    Closed,
}

struct PendingSignals {
    interrupt: Arc<AtomicBool>,
    terminate: Arc<AtomicBool>,
    hangup: Arc<AtomicBool>,
}

impl PendingSignals {
    fn new() -> Self {
        Self {
            interrupt: Arc::new(AtomicBool::new(false)),
            terminate: Arc::new(AtomicBool::new(false)),
            hangup: Arc::new(AtomicBool::new(false)),
        }
    }

    fn take_all(&self) -> [Option<Signal>; 3] {
        [
            self.interrupt
                .swap(false, Ordering::SeqCst)
                .then_some(Signal::SIGINT),
            self.terminate
                .swap(false, Ordering::SeqCst)
                .then_some(Signal::SIGTERM),
            self.hangup
                .swap(false, Ordering::SeqCst)
                .then_some(Signal::SIGHUP),
        ]
    }
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

/// Non-interactive Linux CLI-created targets are supervised by the re-exec'd
/// subreaper. Foreground terminal targets retain a direct parent so the
/// terminal waiter can observe WUNTRACED and implement the shell job-control
/// contract.
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
        true
    }
}

/// Run the re-exec'd helper and return the program's conventional exit code.
/// The control protocol carries only status; an exceptional leftover report is
/// printed with the fixed evidence-preserving wording after cleanup.
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
    let died = Arc::new(AtomicBool::new(false));
    let Ok(signal_id) =
        signal_hook::flag::register(signal_hook::consts::signal::SIGUSR1, Arc::clone(&died))
    else {
        return 1;
    };
    let result = run_inner(&mut control, &died);
    let _ = signal_hook::low_level::unregister(signal_id);
    result
}

fn run_inner(control: &mut UnixStream, died: &AtomicBool) -> i32 {
    // This descriptor is inherited solely across the helper re-exec. Mark it
    // close-on-exec before the held target is forked, so neither the target nor
    // its descendants can keep the parent-liveness channel open.
    if set_cloexec(control.as_fd()).is_err() {
        return 1;
    }
    let Ok(request) = receive_config(control) else {
        return 1;
    };
    // The creator supplies its pid through the authenticated private socket;
    // reading the helper's own `/proc/self/stat` merely proves its current
    // parent, not who is entitled to supervise this launch.
    if aw_platform::prepare_watchdog(request.parent_pid, request.terminal_handoff).is_err() {
        return 1;
    }
    let Ok(mut held) = start_held_program(&request) else {
        return 1;
    };
    let pid = held.pid();
    if send_pid(control, READY, pid).is_err() {
        let _ = held.abort();
        return 1;
    }

    let mut start = [0_u8; 1];
    if control.read_exact(&mut start).is_err() || died.load(Ordering::Relaxed) {
        let _ = held.abort();
        return 1;
    }
    if start[0] == ABORT {
        let _ = held.abort();
        return 1;
    }
    if start[0] != START {
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
        return finish_cleanup(control, 1);
    }

    let (events_tx, events) = mpsc::channel();
    // The cleanup report is written on `control` after the target exits, so
    // the parent reads it from the socket it already holds. A cloned reader
    // would consume that report and the parent would treat a normal exit as a
    // missing report.
    if let Ok(watch) = control.try_clone() {
        std::thread::spawn(move || {
            let mut watch = watch;
            let mut byte = [0_u8; 1];
            loop {
                match watch.read(&mut byte) {
                    Ok(0) | Err(_) => {
                        let _ = events_tx.send(SupervisorEvent::Closed);
                        return;
                    }
                    Ok(_) if byte[0] == ABORT => {
                        let _ = events_tx.send(SupervisorEvent::Abort);
                    }
                    Ok(_) => {
                        if let Ok(signal) = Signal::try_from(i32::from(byte[0])) {
                            let _ = events_tx.send(SupervisorEvent::Signal(signal));
                        }
                    }
                }
            }
        });
    }

    loop {
        // Reap adopted short-lived descendants continuously. Waiting only
        // after the root exits lets zombies accumulate under the subreaper.
        aw_platform::reap_watchdog_children(pid);
        if died.load(Ordering::Relaxed) {
            return finish_cleanup(control, 1);
        }
        match events.try_recv() {
            Ok(SupervisorEvent::Signal(signal)) => {
                if forward_group(pid, signal).is_err() {
                    return finish_cleanup(control, 1);
                }
            }
            Ok(SupervisorEvent::Abort | SupervisorEvent::Closed) => {
                return finish_cleanup(control, 1);
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                return finish_cleanup(control, 1);
            }
        }
        match released.try_reap() {
            Ok(ReapOutcome::Exited(code)) => {
                return finish_cleanup(control, code);
            }
            Ok(ReapOutcome::Signaled(signal)) => {
                return finish_cleanup(control, 128 + signal);
            }
            Ok(ReapOutcome::StillRunning) => std::thread::sleep(SIGNAL_POLL),
            Err(_) => {
                return finish_cleanup(control, 1);
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
            terminal_handoff: false,
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
    parent_pid: u32,
    terminal_handoff: bool,
}

impl Request {
    fn from_run(spec: &RunSpec, terminal_handoff: bool) -> Self {
        Self {
            command: spec.command.clone(),
            cwd: spec.cwd.clone(),
            env: spec.env.clone(),
            parent_pid: std::process::id(),
            terminal_handoff,
        }
    }
}

impl Watchdog {
    /// Spawn a held watchdog. Its target exists but cannot exec until release.
    pub fn spawn(spec: &RunSpec, terminal_handoff: bool) -> Result<Self, WatchdogError> {
        aw_platform::prepare_watchdog_fallback().map_err(|_| WatchdogError::Unavailable)?;
        // Register before the target is released. The default action for each
        // of these exits aw, and a signal arriving before `wait` would be
        // reported as aw's own death instead of the program's exit code.
        // Do not preset SIG_IGN: signal-hook chains the disposition it finds,
        // and chaining SIG_IGN jumps to address 1.
        let pending = PendingSignals::new();
        let mut registrations = Vec::new();
        for (signal, flag) in [
            (Signal::SIGINT, &pending.interrupt),
            (Signal::SIGTERM, &pending.terminate),
            (Signal::SIGHUP, &pending.hangup),
        ] {
            registrations.push(
                signal_hook::flag::register(signal as i32, Arc::clone(flag))
                    .map_err(|_| WatchdogError::Unavailable)?,
            );
        }
        let bytes = serde_json::to_vec(&Request::from_run(spec, terminal_handoff))
            .map_err(|_| WatchdogError::Unavailable)?;
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
            cleanup: None,
            pending,
            registrations,
        })
    }

    #[must_use]
    pub fn pid(&self) -> u32 {
        self.program_pid
    }

    /// The direct helper process owned by the CLI.  This differs from
    /// [`Self::pid`], which deliberately reports the program pid to daemon
    /// adoption and terminal process-group control.
    #[must_use]
    pub(crate) fn process_pid(&self) -> u32 {
        self.child.id()
    }

    /// A terminal waiter forwards signals over this private socket.  The
    /// watchdog, never the parent CLI, owns `killpg` for the program group.
    pub(crate) fn control_clone(&self) -> Result<UnixStream, WatchdogError> {
        self.control
            .try_clone()
            .map_err(|_| WatchdogError::Unavailable)
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
        // The handlers were installed in `spawn`, before the target could run,
        // so a signal delivered while the daemon adopted the pid is still
        // waiting in the flags. This waiter runs only when aw has no terminal
        // of its own, so a SIGHUP here was delivered to aw directly and is
        // forwarded like the others. A real terminal disconnect is observed by
        // the terminal waiter instead, which forwards that one SIGHUP over the
        // control socket.
        let result = loop {
            let mut relay_error = None;
            for signal in self.pending.take_all().into_iter().flatten() {
                if let Err(error) = self.forward(signal) {
                    relay_error = Some(error);
                    break;
                }
            }
            if let Some(error) = relay_error {
                break Err(error);
            }
            match self
                .child
                .try_wait()
                .map_err(|_| WatchdogError::Unavailable)?
            {
                Some(status) => {
                    use std::os::unix::process::ExitStatusExt;
                    if status.signal().is_some() {
                        // The helper did not send a conventional program
                        // result.  It may have been killed by `killall aw`; as
                        // the fallback subreaper, clean the adopted tree and
                        // do not misreport that helper signal as the target's.
                        self.record_fallback_cleanup();
                        break Ok(1);
                    }
                    if self.read_cleanup_report().is_err() {
                        // A helper that exits without its terminal report is
                        // not trusted to have completed cleanup. The CLI is
                        // already the fallback subreaper, so it takes over
                        // and never reports the helper's status as the
                        // program's status.
                        self.record_fallback_cleanup();
                        break Ok(1);
                    }
                    break Ok(status_code(status));
                }
                None => std::thread::sleep(SIGNAL_POLL),
            }
        };
        for id in self.registrations.drain(..) {
            let _ = signal_hook::low_level::unregister(id);
        }
        result
    }

    /// Abort a held target, or end a released target through the helper so it
    /// can still reap descendants before it exits.
    pub fn abort(&mut self) {
        if self
            .control
            .write_all(&[ABORT])
            .and_then(|_| self.control.flush())
            .is_err()
        {
            // The helper died before it could consume the control request.
            // The parent is also a subreaper and takes over descendant cleanup.
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if self.released && self.read_cleanup_report().is_err() {
            self.record_fallback_cleanup();
        }
    }

    fn forward(&mut self, signal: Signal) -> Result<(), WatchdogError> {
        self.control
            .write_all(&[signal as u8])
            .and_then(|_| self.control.flush())
            .map_err(|_| WatchdogError::Unavailable)
    }

    /// Consume the cleanup status exactly once after `wait`. A missing value
    /// means the cleanup completed within its budget; callers must not invent
    /// a zero-count report.
    pub(crate) fn cleanup_leftovers(&mut self) -> Option<CleanupReport> {
        self.cleanup.take()
    }

    fn read_cleanup_report(&mut self) -> Result<(), WatchdogError> {
        let report =
            receive_cleanup_report(&mut self.control).map_err(|_| WatchdogError::Unavailable)?;
        self.cleanup = report;
        Ok(())
    }

    fn record_fallback_cleanup(&mut self) {
        self.cleanup = cleanup_report(aw_platform::cleanup_watchdog_descendants());
        if let Some(report) = &self.cleanup {
            report_leftovers(report);
        }
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

fn forward_group(pid: u32, signal: Signal) -> Result<(), WatchdogError> {
    let pid = i32::try_from(pid).map_err(|_| WatchdogError::Unavailable)?;
    match killpg(Pid::from_raw(pid), signal) {
        Ok(()) | Err(Errno::ESRCH) => Ok(()),
        Err(_) => Err(WatchdogError::Unavailable),
    }
}

fn finish_cleanup(control: &mut UnixStream, code: i32) -> i32 {
    let report = cleanup_report(aw_platform::cleanup_watchdog_descendants());
    let _ = send_cleanup_report(control, report.as_ref());
    if let Some(report) = &report {
        report_leftovers(report);
    }
    code
}

fn cleanup_report(cleanup: aw_platform::WatchdogCleanup) -> Option<CleanupReport> {
    if cleanup.survivors.is_empty() {
        return None;
    }
    let pids = cleanup
        .survivors
        .iter()
        .copied()
        .filter_map(|pid| u32::try_from(pid).ok())
        .take(5)
        .collect();
    let eperm_pid = cleanup
        .eperm_survivors
        .into_iter()
        .find_map(|pid| u32::try_from(pid).ok());
    Some(CleanupReport {
        count: u32::try_from(cleanup.survivors.len()).unwrap_or(u32::MAX),
        pids,
        eperm_pid,
    })
}

fn report_leftovers(report: &CleanupReport) {
    if report.count == 0 {
        return;
    }
    let listed = report
        .pids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("、");
    let suffix = if usize::try_from(report.count).unwrap_or(usize::MAX) > report.pids.len() {
        "等"
    } else {
        ""
    };
    if let Some(pid) = report.eperm_pid {
        eprintln!(
            "程序已经结束，但它启动的 {} 个子程序没能结束，可能还在运行（进程号：{listed}{suffix}）。其中进程号 {pid} 属于别的用户，需要用 `sudo kill -9 {pid}` 结束。",
            report.count
        );
    } else {
        eprintln!(
            "程序已经结束，但它启动的 {} 个子程序没能结束，可能还在运行（进程号：{listed}{suffix}）。可以用 `kill -9 进程号` 手动结束。",
            report.count
        );
    }
}

fn send_cleanup_report(control: &mut UnixStream, report: Option<&CleanupReport>) -> io::Result<()> {
    let report = report.cloned().unwrap_or(CleanupReport {
        count: 0,
        pids: Vec::new(),
        eperm_pid: None,
    });
    let listed = u8::try_from(report.pids.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many cleanup pids"))?;
    control.write_all(&[CLEANUP])?;
    control.write_all(&report.count.to_be_bytes())?;
    control.write_all(&[listed])?;
    for pid in report.pids {
        control.write_all(&pid.to_be_bytes())?;
    }
    control.write_all(&report.eperm_pid.unwrap_or(0).to_be_bytes())?;
    control.flush()
}

fn receive_cleanup_report(control: &mut UnixStream) -> io::Result<Option<CleanupReport>> {
    let mut header = [0_u8; 6];
    control.read_exact(&mut header)?;
    if header[0] != CLEANUP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing cleanup report",
        ));
    }
    let count = u32::from_be_bytes(header[1..5].try_into().unwrap_or([0; 4]));
    let listed = usize::from(header[5]);
    if listed > 5
        || (count == 0 && listed != 0)
        || u32::try_from(listed).unwrap_or(u32::MAX) > count
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid cleanup report",
        ));
    }
    let mut pids = Vec::with_capacity(listed);
    for _ in 0..listed {
        let mut raw = [0_u8; 4];
        control.read_exact(&mut raw)?;
        let pid = u32::from_be_bytes(raw);
        if pid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid cleanup pid",
            ));
        }
        pids.push(pid);
    }
    let mut raw = [0_u8; 4];
    control.read_exact(&mut raw)?;
    let eperm_pid = u32::from_be_bytes(raw);
    if count == 0 {
        return Ok(None);
    }
    Ok(Some(CleanupReport {
        count,
        pids,
        eperm_pid: (eperm_pid != 0).then_some(eperm_pid),
    }))
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
