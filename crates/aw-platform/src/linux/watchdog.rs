//! Linux-only primitives used by the CLI-local launch watchdog.
//!
//! This module deliberately owns the raw process calls. The CLI re-execs its
//! watchdog before using these functions, so no Rust allocation or lock is
//! held across the fork that created that process. The watchdog itself starts
//! the target only after [`prepare_watchdog`] has made it a child subreaper.

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const LEFTOVER_GRACE: Duration = Duration::from_secs(2);
const CLEANUP_LIMIT: Duration = Duration::from_secs(5);

/// Bounded result of a watchdog cleanup.  The actual survivor count is the
/// length of `survivors`; callers truncate only for display, never before the
/// count is known. `eperm_survivors` is a subset retained for the truthful
/// cross-account remediation wording.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatchdogCleanup {
    /// Descendant pids still observable when the deadline elapsed.
    pub survivors: Vec<i32>,
    /// Survivors for which a signal was refused with `EPERM`.
    pub eperm_survivors: Vec<i32>,
}

/// A setup failure which means the watchdog must not start the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogPrepareError {
    Session,
    ParentDeathSignal,
    ParentDied,
    SignalDisposition,
}

/// Make the CLI a fallback subreaper before it starts its watchdog child.  If
/// that helper is killed unexpectedly, its target is reparented here and the
/// CLI can run the same bounded descendant cleanup instead of reporting the
/// watchdog's signal as if it were the program's result.
#[allow(unsafe_code)]
pub fn prepare_watchdog_fallback() -> io::Result<()> {
    let result = unsafe {
        // SAFETY: PR_SET_CHILD_SUBREAPER changes only this process's Linux
        // child-reaping role and uses no caller pointers.
        libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Move this re-exec'd process out of the terminal's session, make it a
/// subreaper, and arm a parent-death notification.
///
/// The caller installs its `SIGUSR1` flag before this call. `getppid` after
/// `PR_SET_PDEATHSIG` closes the documented race where the parent disappears
/// between the two syscalls. No identity switch occurs in this launcher; if
/// one is introduced it must happen before this function is called.
#[allow(unsafe_code)]
pub fn prepare_watchdog(
    parent_pid: u32,
    stays_in_terminal_session: bool,
) -> Result<(), WatchdogPrepareError> {
    // SAFETY: `setsid`, `prctl`, and `getppid` take no Rust pointers. They run
    // in the dedicated re-exec'd watchdog before it starts any target.
    unsafe {
        if stays_in_terminal_session {
            // A foreground target must stay in aw's session: only a process
            // group in that session can become the terminal foreground group.
            // The re-exec'd helper is not a group leader yet, so this gives it
            // an isolated group without stealing the terminal.
            if libc::setpgid(0, 0) != 0 {
                return Err(WatchdogPrepareError::Session);
            }
        } else if libc::setsid() < 0 {
            return Err(WatchdogPrepareError::Session);
        }
        // The watchdog must outlive the CLI long enough to clean descendants.
        // Terminal and supervisor signals belong to the target group and are
        // delivered over the private control socket, never to this helper.
        for signal in [
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGHUP,
            libc::SIGQUIT,
            libc::SIGTSTP,
            libc::SIGTTIN,
            libc::SIGTTOU,
        ] {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = libc::SIG_IGN;
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

/// Terminate, freeze, kill, rescan, and reap every current descendant of this
/// watchdog.
///
/// A signal is sent only after rereading `/proc/<pid>/stat` and matching the
/// pid, parent pid, and start time captured in the scan. This avoids signaling
/// a reused pid. Every cleanup begins with SIGTERM and a two-second grace
/// period; only survivors are frozen and killed. SIGHUP is never a cleanup
/// signal: it belongs solely to an actual terminal disconnect path.
pub fn cleanup_watchdog_descendants() -> WatchdogCleanup {
    let self_pid = std::process::id() as libc::pid_t;
    let cleanup_deadline = Instant::now() + CLEANUP_LIMIT;
    let mut denied = BTreeSet::new();
    for target in descendants_of(self_pid, &process_snapshot()) {
        signal_if_same(target, libc::SIGTERM, &mut denied);
    }
    let deadline = Instant::now() + LEFTOVER_GRACE;
    while Instant::now() < deadline {
        reap_children();
        if descendants_of(self_pid, &process_snapshot()).is_empty() {
            return WatchdogCleanup::default();
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    loop {
        let snapshot = process_snapshot();
        let targets = descendants_of(self_pid, &snapshot);
        if targets.is_empty() {
            reap_children();
            if descendants_of(self_pid, &process_snapshot()).is_empty() {
                return WatchdogCleanup::default();
            }
            if Instant::now() >= cleanup_deadline {
                return remaining_cleanup(self_pid, &denied);
            }
            continue;
        }

        for target in &targets {
            signal_if_same(*target, libc::SIGSTOP, &mut denied);
        }
        // A new scan is required after freezing: children already exiting can
        // be reparented to the subreaper during this interval.
        for target in descendants_of(self_pid, &process_snapshot()) {
            signal_if_same(target, libc::SIGKILL, &mut denied);
        }
        reap_children();
        if Instant::now() >= cleanup_deadline {
            return remaining_cleanup(self_pid, &denied);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Reap every exited direct/adopted child without waiting.  The watchdog calls
/// this during normal execution so short-lived background programs cannot pile
/// up as zombies until the root exits.
pub fn reap_watchdog_children() {
    reap_children();
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
fn remaining_cleanup(root: libc::pid_t, denied: &BTreeSet<libc::pid_t>) -> WatchdogCleanup {
    let survivors: Vec<i32> = descendants_of(root, &process_snapshot())
        .into_iter()
        .map(|target| target.pid)
        .collect();
    let eperm_survivors = survivors
        .iter()
        .copied()
        .filter(|pid| denied.contains(pid))
        .collect();
    WatchdogCleanup {
        survivors,
        eperm_survivors,
    }
}

fn signal_if_same(
    target: ProcessIdentity,
    signal: libc::c_int,
    denied: &mut BTreeSet<libc::pid_t>,
) {
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
        if libc::kill(target.pid, signal) != 0
            && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
        {
            denied.insert(target.pid);
        }
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
