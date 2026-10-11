//! Foreground-terminal handoff for `aw run` on Unix.
//!
//! A target is always put in a process group of its own.  When `aw` owns stdin
//! as a controlling terminal, that group must become foreground before a
//! program may read from it.  This module also waits with `WUNTRACED`, so a
//! terminal stop returns the foreground group to `aw` before `aw` stops
//! itself.  It intentionally has no platform-specific branches: Linux and
//! macOS use the same POSIX job-control rules.

// `aw-cli` also has a small library target exposing the Linux state machine.
// On macOS that library compiles this shared module without linking the CLI
// launcher, so its otherwise-live entry points are intentionally unused there.
#![allow(dead_code)]

use std::io;
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use nix::sys::signal::{killpg, SigSet, SigmaskHow, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{getpgrp, isatty, tcgetpgrp, tcsetpgrp, Pid};

/// How often the waiter observes its signal relay.  Polling is deliberate:
/// signal-hook may install handlers with `SA_RESTART`, in which case a blocking
/// `waitpid` would not necessarily return after the handler records a signal.
const SIGNAL_POLL: Duration = Duration::from_millis(10);
/// Give cooperative leftover processes a bounded chance to flush and exit
/// before freezing the process group and killing any survivors.
const LEFTOVER_GRACE: Duration = Duration::from_secs(2);
/// Cleanup (including terminal restoration and reaping the direct child) must
/// not make an error path hang indefinitely.  The final wait is therefore
/// non-blocking and shares this one deadline with the TERM grace period.
const CLEANUP_LIMIT: Duration = Duration::from_secs(5);

/// A pre-fork terminal decision.  `aw run` may hand a terminal to the target
/// only while its own process group is already foreground on stdin.  Keeping
/// this value lets the held-child platform code obey the caller without doing
/// a second, racy terminal probe after `fork`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TerminalDecision {
    controls_terminal: bool,
}

impl TerminalDecision {
    #[must_use]
    pub(crate) fn before_fork() -> Self {
        let stdin = io::stdin();
        let controls_terminal = isatty(stdin.as_fd()).unwrap_or(false)
            && tcgetpgrp(stdin.as_fd())
                .map(|foreground| foreground == getpgrp())
                .unwrap_or(false);
        Self { controls_terminal }
    }

    #[must_use]
    pub(crate) const fn handoff_requested(self) -> bool {
        self.controls_terminal
    }
}

/// A released child and the terminal state that belongs to the foreground
/// `aw run` invocation.  Dropping it restores `aw`'s group before unregistering
/// signal handlers, including during unwinding on an error path.
pub(crate) struct TerminalChild {
    /// The direct child owned by this CLI and therefore the only pid this
    /// waiter may reap. With the Linux watchdog this is the watchdog, while
    /// `child_group` remains the program's distinct process group.
    direct_child: Pid,
    child_group: Pid,
    aw_group: Pid,
    controls_terminal: bool,
    child_is_foreground: bool,
    pending_signals: PendingSignals,
    /// The terminal sends SIGINT/SIGQUIT to the child foreground group. Keep
    /// them actually ignored in `aw`, rather than forwarding them twice.
    ignored_interrupts: Option<aw_platform::TerminalInterruptIgnore>,
    relay_registrations: Vec<signal_hook::SigId>,
    signal_route: SignalRoute,
}

enum SignalRoute {
    Group,
    #[cfg(target_os = "linux")]
    Watchdog(UnixStream),
}

/// One pending bit per signal.  A previous single atomic slot let a later
/// signal overwrite an earlier one before the polling waiter observed it.
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

    fn flag(&self, signal: Signal) -> Arc<AtomicBool> {
        match signal {
            Signal::SIGINT => Arc::clone(&self.interrupt),
            Signal::SIGTERM => Arc::clone(&self.terminate),
            Signal::SIGHUP => Arc::clone(&self.hangup),
            _ => unreachable!("only relayed signals have pending flags"),
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

impl TerminalChild {
    /// Install the run-local signal relay before the child is released.  A
    /// non-TTY still gets the relay, but never calls `tcsetpgrp`.
    pub(crate) fn new(pid: u32, decision: TerminalDecision) -> Result<Self, String> {
        Self::new_inner(pid, pid, decision, SignalRoute::Group)
    }

    /// The Linux watchdog owns program-group signals and descendant cleanup.
    /// The terminal waiter still owns the direct watchdog child and terminal
    /// foreground restoration, while forwarding relay bytes over its private
    /// socket rather than calling `killpg` itself.
    #[cfg(target_os = "linux")]
    pub(crate) fn new_with_watchdog(
        watchdog_pid: u32,
        program_pid: u32,
        decision: TerminalDecision,
        control: UnixStream,
    ) -> Result<Self, String> {
        Self::new_inner(
            watchdog_pid,
            program_pid,
            decision,
            SignalRoute::Watchdog(control),
        )
    }

    fn new_inner(
        direct_pid: u32,
        group_pid: u32,
        decision: TerminalDecision,
        signal_route: SignalRoute,
    ) -> Result<Self, String> {
        let direct_raw =
            i32::try_from(direct_pid).map_err(|_| "子进程号超出 Unix pid 范围".to_owned())?;
        let group_raw =
            i32::try_from(group_pid).map_err(|_| "子进程号超出 Unix pid 范围".to_owned())?;
        let aw_group = getpgrp();
        let controls_terminal = decision.controls_terminal;
        let pending_signals = PendingSignals::new();
        let mut relay_registrations = Vec::new();
        let relayed: &[Signal] = if controls_terminal {
            &[Signal::SIGTERM, Signal::SIGHUP]
        } else {
            &[Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP]
        };
        for signal in relayed {
            match signal_hook::flag::register(*signal as i32, pending_signals.flag(*signal)) {
                Ok(id) => relay_registrations.push(id),
                Err(_) => {
                    for id in relay_registrations {
                        let _ = signal_hook::low_level::unregister(id);
                    }
                    return Err("无法安装程序信号转发".to_owned());
                }
            }
        }
        let ignored_interrupts = if controls_terminal {
            match aw_platform::ignore_terminal_interrupts() {
                Ok(guard) => Some(guard),
                Err(_) => {
                    for id in relay_registrations {
                        let _ = signal_hook::low_level::unregister(id);
                    }
                    return Err("无法安装终端信号处理".to_owned());
                }
            }
        } else {
            None
        };

        Ok(Self {
            direct_child: Pid::from_raw(direct_raw),
            child_group: Pid::from_raw(group_raw),
            aw_group,
            controls_terminal,
            child_is_foreground: false,
            pending_signals,
            ignored_interrupts,
            relay_registrations,
            signal_route,
        })
    }

    /// The held child performs the first foreground handoff before it reads
    /// its gate. Arm restoration *before* releasing that gate, so every error
    /// and unwind path returns the terminal to `aw`'s original group.
    pub(crate) fn expect_child_foreground(&mut self) {
        self.child_is_foreground = self.controls_terminal;
    }

    /// Put the target's process group back in the foreground after `aw` was
    /// resumed from a job-control stop. Signals
    /// which would otherwise stop a background caller of `tcsetpgrp` are
    /// blocked only for the switch and the previous mask is restored exactly.
    pub(crate) fn give_child_foreground(&mut self) -> Result<(), String> {
        if !self.controls_terminal {
            return Ok(());
        }
        self.switch_foreground(self.child_group)?;
        self.child_is_foreground = true;
        Ok(())
    }

    /// Wait for the directly owned child.  This is called only after the
    /// platform release handle has been consumed by the CLI: no other code
    /// waits on this PID.  A forwarded terminal signal is delivered to the
    /// whole child process group. Once the root exits, leftovers receive
    /// SIGTERM, a two-second grace period, then SIGSTOP and SIGKILL. The root
    /// status is observed with `waitid(WNOWAIT)` first, so cleanup runs before
    /// its process-group id can be reused and never changes `aw`'s exit code.
    pub(crate) fn wait(&mut self) -> Result<i32, String> {
        let mut saw_hup = false;
        loop {
            for signal in self.take_pending_signals().into_iter().flatten() {
                saw_hup |= signal == Signal::SIGHUP;
                // Keep a foreground target foreground while forwarding
                // SIGTERM: terminal applications often restore terminal modes
                // in their handler and must not be stopped with SIGTTOU.
                // SIGHUP is the disconnect case, where restoration can fail
                // because the terminal is already gone.
                if signal == Signal::SIGHUP && self.restore_aw_foreground().is_err() {
                    // Continue to relay the actual hangup. The cleanup path
                    // below will make a second best-effort restoration.
                }
                if self.forward_signal(signal).is_err() {
                    if saw_hup {
                        self.cleanup_after_error();
                        return Ok(128 + Signal::SIGHUP as i32);
                    }
                    self.cleanup_after_error();
                    return Err("无法转发信号给子进程".to_owned());
                }
            }

            match aw_platform::unix_peek_exit(self.direct_child.as_raw() as u32) {
                Ok(Some(outcome)) => {
                    let cleanup_deadline = std::time::Instant::now() + CLEANUP_LIMIT;
                    self.finish_after_exit(cleanup_deadline);
                    self.reap_after_cleanup(cleanup_deadline);
                    return Ok(match outcome {
                        aw_platform::ReapOutcome::Exited(code) => code,
                        aw_platform::ReapOutcome::Signaled(signal) => 128 + signal,
                        aw_platform::ReapOutcome::StillRunning => {
                            unreachable!("waitid reported exit")
                        }
                    });
                }
                Ok(None) => {}
                Err(_) if saw_hup => {
                    // The controlling terminal may have vanished before this
                    // polling waiter can observe the child. Do not leave a
                    // direct child running merely because the kernel reports
                    // EIO or ECHILD during terminal teardown.
                    self.cleanup_after_error();
                    return Ok(128 + Signal::SIGHUP as i32);
                }
                Err(_) => {
                    self.cleanup_after_error();
                    return Err("等待程序结束失败".to_owned());
                }
            }

            match waitpid(
                self.direct_child,
                Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED),
            ) {
                Ok(WaitStatus::Exited(_, code)) => {
                    // `waitid(WNOWAIT)` above is the normal exit path. Keep
                    // this defensive fallback for a transition that races its
                    // no-hang poll.
                    self.finish_after_exit(std::time::Instant::now() + CLEANUP_LIMIT);
                    return Ok(code);
                }
                Ok(WaitStatus::Signaled(_, signal, _)) => {
                    // With a real terminal, Ctrl+C is delivered by the tty
                    // driver straight to the foreground child group, rather
                    // than to aw's relay.  Clean the group in that case too:
                    // a descendant that ignored SIGINT must not survive after
                    // its group leader has ended.
                    self.finish_after_exit(std::time::Instant::now() + CLEANUP_LIMIT);
                    return Ok(128 + signal as i32);
                }
                Ok(WaitStatus::Stopped(_, _)) => {
                    if let Err(error) = self.handle_child_stop() {
                        self.cleanup_after_error();
                        return Err(error);
                    }
                }
                Ok(WaitStatus::StillAlive) | Ok(WaitStatus::Continued(_)) => {
                    std::thread::sleep(SIGNAL_POLL);
                }
                #[cfg(target_os = "linux")]
                Ok(WaitStatus::PtraceEvent(_, _, _)) | Ok(WaitStatus::PtraceSyscall(_)) => {
                    std::thread::sleep(SIGNAL_POLL);
                }
                Err(_) if saw_hup => {
                    // The controlling terminal may have vanished before this
                    // polling waiter can reap the child. Do not leave a direct
                    // child running merely because the kernel reports EIO or
                    // ECHILD during terminal teardown.
                    self.cleanup_after_error();
                    return Ok(128 + Signal::SIGHUP as i32);
                }
                Err(_) => {
                    self.cleanup_after_error();
                    return Err("等待程序结束失败".to_owned());
                }
            }
        }
    }

    /// Abort a released target after a launch-state-machine error. This uses
    /// the same bounded restore, TERM, grace, STOP/KILL, and reap sequence as
    /// a terminal wait error; callers must not replace it with bare SIGKILL.
    pub(crate) fn abort_and_reap(&mut self) {
        self.cleanup_after_error();
    }

    fn take_pending_signals(&self) -> [Option<Signal>; 3] {
        self.pending_signals.take_all()
    }

    fn handle_child_stop(&mut self) -> Result<(), String> {
        if !self.controls_terminal {
            // A non-interactive caller has no shell job-control contract.  Do
            // not leave its run permanently stopped merely because a target
            // sent itself SIGTSTP/SIGSTOP.
            return self.forward_signal(Signal::SIGCONT);
        }

        self.restore_aw_foreground()?;
        // signal-hook implements the default *stop* action as SIGSTOP, so it
        // cannot be ignored by an inherited SIGTSTP disposition.  Once the
        // shell runs `fg`/SIGCONT, this call returns and we restore the target
        // foreground group before resuming its process group.
        signal_hook::low_level::emulate_default_handler(Signal::SIGTSTP as i32)
            .map_err(|_| "无法暂停 aw 以交还终端".to_owned())?;
        self.give_child_foreground()?;
        self.forward_signal(Signal::SIGCONT)
    }

    fn finish_after_exit(&mut self, cleanup_deadline: std::time::Instant) {
        let _ = self.restore_aw_foreground();
        if self.owns_group_cleanup() {
            self.cleanup_leftovers(cleanup_deadline);
        }
    }

    /// Failure cleanup always restores first, then gives every group member a
    /// cooperative SIGTERM phase. SIGHUP is deliberately absent here: it is
    /// sent only when `aw` itself received a real terminal disconnect.
    fn cleanup_after_error(&mut self) {
        let deadline = std::time::Instant::now() + CLEANUP_LIMIT;
        let _ = self.restore_aw_foreground();
        if self.owns_group_cleanup() {
            self.cleanup_leftovers(deadline);
        } else {
            self.abort_watchdog();
        }
        self.reap_after_cleanup(deadline);
    }

    fn cleanup_leftovers(&self, cleanup_deadline: std::time::Instant) {
        let _ = killpg(self.child_group, Signal::SIGTERM);
        let grace_deadline =
            std::cmp::min(cleanup_deadline, std::time::Instant::now() + LEFTOVER_GRACE);
        while group_exists(self.child_group) && std::time::Instant::now() < grace_deadline {
            std::thread::sleep(SIGNAL_POLL);
        }
        if group_exists(self.child_group) {
            // Freeze before SIGKILL so a forking survivor cannot add another
            // member between the survivor check and the kill.
            let _ = killpg(self.child_group, Signal::SIGSTOP);
            let _ = killpg(self.child_group, Signal::SIGKILL);
        }
    }

    fn reap_after_cleanup(&mut self, cleanup_deadline: std::time::Instant) {
        while std::time::Instant::now() < cleanup_deadline {
            match waitpid(
                self.direct_child,
                Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED),
            ) {
                Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) => return,
                Ok(WaitStatus::Stopped(_, _)) => {
                    let _ = self.forward_signal(Signal::SIGCONT);
                }
                Ok(WaitStatus::Continued(_)) | Ok(WaitStatus::StillAlive) => {
                    std::thread::sleep(SIGNAL_POLL);
                }
                #[cfg(target_os = "linux")]
                Ok(WaitStatus::PtraceEvent(_, _, _)) | Ok(WaitStatus::PtraceSyscall(_)) => {
                    std::thread::sleep(SIGNAL_POLL);
                }
                Err(_) => return,
            }
        }
    }

    fn forward_signal(&mut self, signal: Signal) -> Result<(), String> {
        match &mut self.signal_route {
            SignalRoute::Group => forward_group(self.child_group, signal),
            #[cfg(target_os = "linux")]
            SignalRoute::Watchdog(control) => {
                use std::io::Write;
                control
                    .write_all(&[signal as u8])
                    .and_then(|_| control.flush())
                    .map_err(|_| "无法转发信号给子进程".to_owned())
            }
        }
    }

    fn owns_group_cleanup(&self) -> bool {
        matches!(&self.signal_route, SignalRoute::Group)
    }

    fn abort_watchdog(&mut self) {
        #[cfg(target_os = "linux")]
        if let SignalRoute::Watchdog(control) = &mut self.signal_route {
            use std::io::Write;
            let _ = control.write_all(&[b'A']);
            let _ = control.flush();
        }
    }

    fn restore_aw_foreground(&mut self) -> Result<(), String> {
        if !self.controls_terminal || !self.child_is_foreground {
            return Ok(());
        }
        self.switch_foreground(self.aw_group)?;
        self.child_is_foreground = false;
        Ok(())
    }

    fn switch_foreground(&self, group: Pid) -> Result<(), String> {
        switch_foreground_group(group)
    }
}

/// Perform one foreground-group switch while blocking job-control stop
/// signals. Kept outside `TerminalChild` for the narrow window where a held
/// child performed terminal handoff but installing the guard itself failed.
fn switch_foreground_group(group: Pid) -> Result<(), String> {
    let mut stop_signals = SigSet::empty();
    stop_signals.add(Signal::SIGTTOU);
    stop_signals.add(Signal::SIGTTIN);
    let previous = stop_signals
        .thread_swap_mask(SigmaskHow::SIG_BLOCK)
        .map_err(|_| "无法切换终端前台程序组".to_owned())?;
    let stdin = io::stdin();
    let switched = tcsetpgrp(stdin.as_fd(), group).is_ok();
    let restored_mask = previous.thread_set_mask().is_ok();
    if switched && restored_mask {
        Ok(())
    } else {
        Err("无法切换终端前台程序组".to_owned())
    }
}

/// The held spawn path can hand the terminal to a child before the parent has
/// installed its [`TerminalChild`] guard. If guard creation then fails, still
/// restore the caller and clean the exact just-created process group with the
/// normal bounded order.
pub(crate) fn abort_unmanaged_child(pid: u32, decision: TerminalDecision) {
    let Ok(raw_pid) = i32::try_from(pid) else {
        return;
    };
    let group = Pid::from_raw(raw_pid);
    if decision.controls_terminal {
        let _ = switch_foreground_group(getpgrp());
    }
    let deadline = std::time::Instant::now() + CLEANUP_LIMIT;
    let _ = killpg(group, Signal::SIGTERM);
    let grace = std::cmp::min(deadline, std::time::Instant::now() + LEFTOVER_GRACE);
    while group_exists(group) && std::time::Instant::now() < grace {
        std::thread::sleep(SIGNAL_POLL);
    }
    if group_exists(group) {
        let _ = killpg(group, Signal::SIGSTOP);
        let _ = killpg(group, Signal::SIGKILL);
    }
    while std::time::Instant::now() < deadline {
        match waitpid(group, Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED)) {
            Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) | Err(_) => return,
            Ok(WaitStatus::Stopped(_, _)) => {
                let _ = killpg(group, Signal::SIGKILL);
            }
            Ok(WaitStatus::Continued(_)) | Ok(WaitStatus::StillAlive) => {
                std::thread::sleep(SIGNAL_POLL);
            }
            #[cfg(target_os = "linux")]
            Ok(WaitStatus::PtraceEvent(_, _, _)) | Ok(WaitStatus::PtraceSyscall(_)) => {
                std::thread::sleep(SIGNAL_POLL);
            }
        }
    }
}

impl Drop for TerminalChild {
    fn drop(&mut self) {
        let _ = self.restore_aw_foreground();
        for id in self.relay_registrations.drain(..) {
            let _ = signal_hook::low_level::unregister(id);
        }
        self.ignored_interrupts.take();
    }
}

/// Relay one signal to the target process group.  Kept public to the two
/// platform launchers' legacy `Launcher::forward_interrupt` implementation.
#[allow(dead_code)] // the lib target compiles this helper without the CLI launcher
pub(crate) fn forward_to_group(pid: u32, signal: Signal) -> Result<(), String> {
    let raw_pid = i32::try_from(pid).map_err(|_| "子进程号超出 Unix pid 范围".to_owned())?;
    forward_group(Pid::from_raw(raw_pid), signal)
}

fn forward_group(group: Pid, signal: Signal) -> Result<(), String> {
    match killpg(group, signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(_) => Err("无法转发信号给子进程".to_owned()),
    }
}

fn group_exists(group: Pid) -> bool {
    !matches!(
        killpg(group, Option::<Signal>::None),
        Err(nix::errno::Errno::ESRCH)
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::os::unix::process::CommandExt;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use nix::sys::signal::kill;

    use super::{Signal, TerminalChild, TerminalDecision};

    fn guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    #[test]
    fn wait_keeps_a_signalled_child_status_as_128_plus_signal() {
        let _guard = guard();
        let mut command = std::process::Command::new("sh");
        command.args(["-c", "kill -TERM $$"]);
        command.process_group(0);
        let child = command.spawn().expect("spawn target");
        let mut terminal = TerminalChild::new(child.id(), TerminalDecision::before_fork())
            .expect("terminal relay");
        drop(child);
        assert_eq!(terminal.wait().expect("wait target"), 143);
    }

    #[test]
    fn forwarded_interrupt_reaches_the_group_and_removes_grandchild() {
        let _guard = guard();
        let marker = std::env::temp_dir().join(format!(
            "aw-terminal-grandchild-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        let mut command = std::process::Command::new("python3");
        command.args([
            "-c",
            // Cargo's test harness can inherit SIGINT ignored. Reset it in
            // the direct-child fixture so this test exercises forwarding,
            // not inherited target disposition.
            "import signal, subprocess, sys\nsignal.signal(signal.SIGINT, signal.SIG_DFL)\nchild = subprocess.Popen(['sleep', '300'])\nopen(sys.argv[1], 'w').write(str(child.pid))\nchild.wait()",
            &marker.to_string_lossy(),
        ]);
        command.process_group(0);
        let child = command.spawn().expect("spawn target");
        let mut terminal = TerminalChild::new(child.id(), TerminalDecision::before_fork())
            .expect("terminal relay");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !marker.is_file() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(marker.is_file(), "target did not publish grandchild pid");
        let grandchild: i32 = std::fs::read_to_string(&marker)
            .expect("grandchild pid")
            .trim()
            .parse()
            .expect("numeric grandchild pid");
        terminal
            .pending_signals
            .interrupt
            .store(true, std::sync::atomic::Ordering::SeqCst);
        drop(child);
        assert_eq!(terminal.wait().expect("wait target"), 130);
        let gone_by = Instant::now() + Duration::from_secs(2);
        while kill(nix::unistd::Pid::from_raw(grandchild), None).is_ok() && Instant::now() < gone_by
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            kill(nix::unistd::Pid::from_raw(grandchild), None).is_err(),
            "grandchild {grandchild} survived the forwarded interrupt"
        );
        let _ = std::fs::remove_file(marker);
    }
}
