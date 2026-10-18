//! Linux-only primitives used by the CLI-local launch watchdog.
//!
//! This module deliberately owns the raw process calls. The CLI re-execs its
//! watchdog before using these functions, so no Rust allocation or lock is
//! held across the fork that created that process. The watchdog itself starts
//! the target only after [`prepare_watchdog`] has made it a child subreaper.

use std::collections::HashMap;
use std::io;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

/// A setup failure which means the watchdog must not start the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogPrepareError {
    Session,
    ParentDeathSignal,
    ParentDied,
    SignalDisposition,
}

/// Move this re-exec'd process out of the terminal's session, make it a
/// subreaper, and arm a parent-death notification.
///
/// The caller installs its `SIGUSR1` flag before this call. `getppid` after
/// `PR_SET_PDEATHSIG` closes the documented race where the parent disappears
/// between the two syscalls. No identity switch occurs in this launcher; if
/// one is introduced it must happen before this function is called.
#[allow(unsafe_code)]
pub fn prepare_watchdog(parent_pid: u32) -> Result<(), WatchdogPrepareError> {
    // SAFETY: `setsid`, `prctl`, and `getppid` take no Rust pointers. They run
    // in the dedicated re-exec'd watchdog before it starts any target.
    unsafe {
        if libc::setsid() < 0 {
            return Err(WatchdogPrepareError::Session);
        }
        // A background shell may have started `aw` with these signals ignored.
        // The watchdog relays signals from `aw` itself, so the newly created
        // target must start with their ordinary default dispositions instead
        // of inheriting a shell's ignored disposition.
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_DFL;
            if libc::sigemptyset(&mut action.sa_mask) != 0
                || libc::sigaction(signal, &action, std::ptr::null_mut()) != 0
            {
                return Err(WatchdogPrepareError::SignalDisposition);
            }
        }
        if libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 {
            return Err(WatchdogPrepareError::ParentDeathSignal);
        }
        // SIGUSR1 is observed by the watchdog's pre-installed flag handler;
        // SIGKILL would prevent it from freezing and reaping descendants.
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGUSR1, 0, 0, 0) != 0 {
            return Err(WatchdogPrepareError::ParentDeathSignal);
        }
        if libc::getppid() != parent_pid as libc::pid_t {
            return Err(WatchdogPrepareError::ParentDied);
        }
    }
    Ok(())
}

/// Take the inherited private control socket. The CLI passes only this fd
/// number through the re-exec environment; command text and environment values
/// are written over the socket after the watchdog is running.
#[allow(unsafe_code)]
pub fn take_watchdog_control(fd: RawFd) -> Result<UnixStream, io::Error> {
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid watchdog control fd",
        ));
    }
    // SAFETY: the internal watchdog owns this one inherited descriptor and
    // calls this conversion once. `UnixStream` closes it on drop.
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

#[derive(Clone, Copy)]
struct ProcessIdentity {
    pid: libc::pid_t,
    ppid: libc::pid_t,
    start_time: u64,
    state: u8,
}

/// Freeze, kill, rescan, and reap every current descendant of this watchdog.
///
/// A signal is sent only after rereading `/proc/<pid>/stat` and matching the
/// pid, parent pid, and start time captured in the scan. This avoids signaling
/// a reused pid. `SIGSTOP` precedes `SIGKILL` so a forking descendant cannot
/// race the kill scan by creating a new child between the two phases.
pub fn cleanup_watchdog_descendants() {
    let self_pid = std::process::id() as libc::pid_t;
    loop {
        let snapshot = process_snapshot();
        let targets = descendants_of(self_pid, &snapshot);
        if targets.is_empty() {
            reap_children();
            if descendants_of(self_pid, &process_snapshot()).is_empty() {
                return;
            }
            continue;
        }

        for target in &targets {
            signal_if_same(*target, libc::SIGSTOP);
        }
        // A new scan is required after freezing: children already exiting can
        // be reparented to the subreaper during this interval.
        for target in descendants_of(self_pid, &process_snapshot()) {
            signal_if_same(target, libc::SIGKILL);
        }
        reap_children();
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn process_snapshot() -> Vec<ProcessIdentity> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .parse::<libc::pid_t>()
                .ok()
        })
        .filter_map(read_identity)
        .collect()
}

fn read_identity(pid: libc::pid_t) -> Option<ProcessIdentity> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, tail) = text.rsplit_once(')')?;
    let mut fields = tail.split_whitespace();
    let state = fields.next()?.as_bytes().first().copied()?;
    let ppid = fields.next()?.parse::<libc::pid_t>().ok()?;
    // `/proc/<pid>/stat` field 22 is starttime. `tail` starts at field 3.
    let start_time = fields.nth(17)?.parse::<u64>().ok()?;
    Some(ProcessIdentity {
        pid,
        ppid,
        start_time,
        state,
    })
}

fn descendants_of(root: libc::pid_t, snapshot: &[ProcessIdentity]) -> Vec<ProcessIdentity> {
    let by_pid: HashMap<libc::pid_t, ProcessIdentity> = snapshot
        .iter()
        .copied()
        .map(|item| (item.pid, item))
        .collect();
    snapshot
        .iter()
        .copied()
        .filter(|item| {
            let mut parent = item.ppid;
            while parent > 0 {
                if parent == root {
                    return true;
                }
                let Some(next) = by_pid.get(&parent) else {
                    return false;
                };
                if next.ppid == parent {
                    return false;
                }
                parent = next.ppid;
            }
            false
        })
        .collect()
}

#[allow(unsafe_code)]
fn signal_if_same(target: ProcessIdentity, signal: libc::c_int) {
    if target.state == b'Z'
        || read_identity(target.pid).is_none_or(|current| {
            current.ppid != target.ppid || current.start_time != target.start_time
        })
    {
        return;
    }
    // SAFETY: the pid has just been verified against its parent and start
    // time. `kill` has no Rust pointers and the signal is a fixed constant.
    unsafe {
        libc::kill(target.pid, signal);
    }
}

#[allow(unsafe_code)]
fn reap_children() {
    loop {
        let mut status = 0;
        // SAFETY: this process is the only owner/reaper for its own children;
        // `status` is a valid mutable `c_int` for `waitpid` to fill.
        let result = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if result > 0 {
            continue;
        }
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return;
    }
}

#[cfg(test)]
mod tests {
    use super::{descendants_of, ProcessIdentity};

    #[test]
    fn descendant_walk_stops_at_the_watchdog() {
        let snapshot = [
            ProcessIdentity {
                pid: 20,
                ppid: 10,
                start_time: 1,
                state: b'S',
            },
            ProcessIdentity {
                pid: 30,
                ppid: 20,
                start_time: 2,
                state: b'S',
            },
            ProcessIdentity {
                pid: 40,
                ppid: 1,
                start_time: 3,
                state: b'S',
            },
        ];
        let found: Vec<_> = descendants_of(10, &snapshot)
            .into_iter()
            .map(|item| item.pid)
            .collect();
        assert_eq!(found, vec![20, 30]);
    }
}
