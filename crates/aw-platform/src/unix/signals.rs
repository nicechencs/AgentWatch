//! Small Unix signal-disposition guards used by foreground CLI job control.

use std::io;

/// Restores the `SIGINT` and `SIGQUIT` dispositions that were in force before
/// an interactive `aw run` ignored them.
pub struct TerminalInterruptIgnore {
    previous_int: libc::sighandler_t,
    previous_quit: libc::sighandler_t,
}

/// Ignore terminal interrupt and quit signals until the returned guard drops.
///
/// The foreground child group receives these terminal-generated signals. The
/// waiting CLI must ignore them rather than forward them a second time.
pub fn ignore_terminal_interrupts() -> io::Result<TerminalInterruptIgnore> {
    let previous_int = unsafe {
        // SAFETY: `signal` changes this process's SIGINT disposition only; the
        // guard saves its exact return value for restoration on drop.
        libc::signal(libc::SIGINT, libc::SIG_IGN)
    };
    if previous_int == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    let previous_quit = unsafe {
        // SAFETY: same as SIGINT above, for SIGQUIT.
        libc::signal(libc::SIGQUIT, libc::SIG_IGN)
    };
    if previous_quit == libc::SIG_ERR {
        unsafe {
            // SAFETY: restore the SIGINT disposition saved immediately above.
            libc::signal(libc::SIGINT, previous_int);
        }
        return Err(io::Error::last_os_error());
    }
    Ok(TerminalInterruptIgnore {
        previous_int,
        previous_quit,
    })
}

impl Drop for TerminalInterruptIgnore {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: both saved handlers came from `signal` in this process;
            // restoring them is the paired operation for this guard.
            libc::signal(libc::SIGQUIT, self.previous_quit);
            libc::signal(libc::SIGINT, self.previous_int);
        }
    }
}
