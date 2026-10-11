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
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use nix::sys::signal::{killpg, SigSet, SigmaskHow, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{getpgrp, isatty, tcsetpgrp, Pid};

/// How often the waiter observes its signal relay.  Polling is deliberate:
/// signal-hook may install handlers with `SA_RESTART`, in which case a blocking
/// `waitpid` would not necessarily return after the handler records a signal.
const SIGNAL_POLL: Duration = Duration::from_millis(10);

// Temporary CI diagnosis for the macOS terminal-job-control regression.  The
// dispatch workflow enables it only while collecting the failing wait order.
// Keep the production expansion empty so this cannot add CLI output.
#[cfg(test)]
macro_rules! macred_diag {
    ($($arg:tt)*) => {
        if std::env::var_os("AW_MACRED_DIAG").is_some() {
            eprintln!("macred-diag: {}", format_args!($($arg)*));
        }
    };
}

#[cfg(not(test))]
macro_rules! macred_diag {
    ($($arg:tt)*) => {};
}

/// A released child and the terminal state that belongs to the foreground
/// `aw run` invocation.  Dropping it restores `aw`'s group before unregistering
/// signal handlers, including during unwinding on an error path.
pub(crate) struct TerminalChild {
    child_group: Pid,
    aw_group: Pid,
    controls_terminal: bool,
    child_is_foreground: bool,
    pending_signal: Arc<AtomicUsize>,
    /// The terminal sends SIGINT/SIGQUIT to the child foreground group. Keep
    /// them actually ignored in `aw`, rather than forwarding them twice.
    ignored_interrupts: Option<aw_platform::TerminalInterruptIgnore>,
    relay_registrations: Vec<signal_hook::SigId>,
}

impl TerminalChild {
    /// Install the run-local signal relay before the child is released.  A
    /// non-TTY still gets the relay, but never calls `tcsetpgrp`.
    pub(crate) fn new(pid: u32) -> Result<Self, String> {
        let raw_pid = i32::try_from(pid).map_err(|_| "子进程号超出 Unix pid 范围".to_owned())?;
        let aw_group = getpgrp();
        let stdin = io::stdin();
        // This is a capability check only. The held child performs the actual
        // pre-release handoff with raw syscalls; the parent never races it.
        let controls_terminal = isatty(stdin.as_fd()).unwrap_or(false);
        let pending_signal = Arc::new(AtomicUsize::new(0));
        let mut relay_registrations = Vec::new();
        let relayed: &[Signal] = if controls_terminal {
            &[Signal::SIGTERM, Signal::SIGHUP]
        } else {
            &[Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP]
        };
        for signal in relayed {
            match signal_hook::flag::register_usize(
                *signal as i32,
                Arc::clone(&pending_signal),
                *signal as usize,
            ) {
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
            child_group: Pid::from_raw(raw_pid),
            aw_group,
            controls_terminal,
            child_is_foreground: false,
            pending_signal,
            ignored_interrupts,
            relay_registrations,
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
    /// whole child process group; once the root exits, a final SIGKILL makes
    /// sure a direct child or same-group descendant cannot survive this run.
    pub(crate) fn wait(&mut self) -> Result<i32, String> {
        let mut saw_hup = false;
        loop {
            if let Some(signal) = self.take_pending_signal() {
                saw_hup |= signal == Signal::SIGHUP;
                macred_diag!(
                    "forward sender_pid={} target_group={} signal={signal:?}",
                    std::process::id(),
                    self.child_group
                );
                // A terminal close can make `tcsetpgrp` fail because there is
                // no longer a terminal to restore. The guard still attempted
                // restoration with SIGTTOU masked; continue relaying SIGHUP so
                // the target's signal status, rather than a local I/O error,
                // determines `aw run`'s result.
                if self.restore_aw_foreground().is_err() && signal != Signal::SIGHUP {
                    return Err("无法切换终端前台程序组".to_owned());
                }
                if forward_group(self.child_group, signal).is_err() {
                    if saw_hup {
                        self.finish_after_exit();
                        return Ok(128 + Signal::SIGHUP as i32);
                    }
                    return Err("无法转发信号给子进程".to_owned());
                }
            }

            match waitpid(
                self.child_group,
                Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED),
            ) {
                Ok(_status @ WaitStatus::Exited(_, code)) => {
                    macred_diag!(
                        "target_group={} wait_status={_status:?} group_exists_before_cleanup={}",
                        self.child_group,
                        killpg(self.child_group, Option::<Signal>::None).is_ok()
                    );
                    self.finish_after_exit();
                    return Ok(code);
                }
                Ok(_status @ WaitStatus::Signaled(_, signal, _)) => {
                    // With a real terminal, Ctrl+C is delivered by the tty
                    // driver straight to the foreground child group, rather
                    // than to aw's relay.  Clean the group in that case too:
                    // a descendant that ignored SIGINT must not survive after
                    // its group leader has ended.
                    macred_diag!(
                        "target_group={} wait_status={_status:?} group_exists_before_cleanup={}",
                        self.child_group,
                        killpg(self.child_group, Option::<Signal>::None).is_ok()
                    );
                    self.finish_after_exit();
                    return Ok(128 + signal as i32);
                }
                Ok(WaitStatus::Stopped(_, _)) => self.handle_child_stop()?,
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
                    self.finish_after_exit();
                    return Ok(128 + Signal::SIGHUP as i32);
                }
                Err(_) => return Err("等待程序结束失败".to_owned()),
            }
        }
    }

    fn take_pending_signal(&self) -> Option<Signal> {
        match self.pending_signal.swap(0, Ordering::SeqCst) {
            number if number == Signal::SIGINT as usize => Some(Signal::SIGINT),
            number if number == Signal::SIGTERM as usize => Some(Signal::SIGTERM),
            number if number == Signal::SIGHUP as usize => Some(Signal::SIGHUP),
            _ => None,
        }
    }

    fn handle_child_stop(&mut self) -> Result<(), String> {
        if !self.controls_terminal {
            // A non-interactive caller has no shell job-control contract.  Do
            // not leave its run permanently stopped merely because a target
            // sent itself SIGTSTP/SIGSTOP.
            return forward_group(self.child_group, Signal::SIGCONT);
        }

        self.restore_aw_foreground()?;
        // signal-hook implements the default *stop* action as SIGSTOP, so it
        // cannot be ignored by an inherited SIGTSTP disposition.  Once the
        // shell runs `fg`/SIGCONT, this call returns and we restore the target
        // foreground group before resuming its process group.
        signal_hook::low_level::emulate_default_handler(Signal::SIGTSTP as i32)
            .map_err(|_| "无法暂停 aw 以交还终端".to_owned())?;
        self.give_child_foreground()?;
        forward_group(self.child_group, Signal::SIGCONT)
    }

    fn finish_after_exit(&mut self) {
        let _ = self.restore_aw_foreground();
        // The child group is named by its leader PID, so it cannot be reused
        // while an in-group descendant remains. ESRCH just means the target
        // already ended every group member. Run this even after normal exit:
        // a shell may otherwise leave a direct background child behind.
        macred_diag!(
            "cleanup sender_pid={} target_group={} signal=SIGKILL",
            std::process::id(),
            self.child_group
        );
        let _ = killpg(self.child_group, Signal::SIGKILL);
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::os::unix::process::CommandExt;
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};

    use nix::sys::signal::kill;

    use super::{Signal, TerminalChild};

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
        let mut terminal = TerminalChild::new(child.id()).expect("terminal relay");
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
        let signal_log = marker.with_extension("signals");
        let mut command = std::process::Command::new("sh");
        command.args([
            "-c",
            "trap 'printf \"INT target_pid=%s\\n\" \"$$\" >> \"$2\"; trap - INT; kill -INT $$' INT; trap 'printf \"HUP target_pid=%s\\n\" \"$$\" >> \"$2\"; trap - HUP; kill -HUP $$' HUP; sleep 300 & echo $! > \"$1\"; wait",
            "aw-terminal-test",
            &marker.to_string_lossy(),
            &signal_log.to_string_lossy(),
        ]);
        command.process_group(0);
        let child = command.spawn().expect("spawn target");
        let mut terminal = TerminalChild::new(child.id()).expect("terminal relay");
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
            .pending_signal
            .store(Signal::SIGINT as usize, std::sync::atomic::Ordering::SeqCst);
        macred_diag!(
            "test_pid={} root_pid={} grandchild_pid={} queued_signal=SIGINT",
            std::process::id(),
            child.id(),
            grandchild
        );
        drop(child);
        let exit = terminal.wait().expect("wait target");
        let target_signals = std::fs::read_to_string(&signal_log)
            .unwrap_or_else(|_| "no target signal record".to_owned());
        macred_diag!("target_signal_log={target_signals:?}");
        assert_eq!(exit, 130, "target signal record: {target_signals:?}");
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
        let _ = std::fs::remove_file(signal_log);
    }
}
