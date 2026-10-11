#!/usr/bin/env python3
"""Record every caught signal with signo and si_pid (sigwaitinfo).

Temporary mac129 diagnosis. Invoked as:
    python3 mac129_sigrec.py <log> <role> [<child-log> <child-role>]

With a child log this process stands in for the waited job: it starts one
background child (the same script, no further child) that ignores SIGINT the
way a non-interactive POSIX sh `child &` does, publishes the child's pid, and
then waits. Without a child log it is that background child and just sleeps
until something signals it.
"""

import os
import signal
import sys
import time

CAUGHT = [
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGTERM",
    "SIGUSR1",
    "SIGUSR2",
    "SIGCONT",
]


def append(log_path, line):
    try:
        with open(log_path, "a") as handle:
            handle.write(line)
            handle.flush()
    except OSError:
        pass


def note(log_path, role, text):
    append(
        log_path,
        "mac129-sig role=%s pid=%s ppid=%s pgid=%s %s\n"
        % (role, os.getpid(), os.getppid(), os.getpgrp(), text),
    )


def watch(log_path, role, fatal):
    """Block in sigwaitinfo and log signo plus si_pid for every caught signal."""
    numbers = []
    for name in CAUGHT:
        number = getattr(signal, name, None)
        if number is not None:
            numbers.append(number)
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, set(numbers))
    del blocked
    while True:
        try:
            info = signal.sigwaitinfo(numbers)
        except OSError:
            continue
        note(
            log_path,
            role,
            "signo=%s si_pid=%s si_uid=%s"
            % (info.si_signo, info.si_pid, getattr(info, "si_uid", "-")),
        )
        if info.si_signo in fatal:
            sys.exit(128 + info.si_signo)


def main():
    log_path, role = sys.argv[1], sys.argv[2]
    child_log = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else ""
    child_role = sys.argv[4] if len(sys.argv) > 4 else "child"
    fatal = {signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM}

    if not child_log:
        # Background child: ignore SIGINT, exactly as non-interactive sh does
        # for `child &`, and stay alive until a different signal arrives.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        fatal.discard(signal.SIGINT)
        note(log_path, role, "event=start")
        watch(log_path, role, fatal)
        return

    script = os.path.abspath(__file__)
    pid = os.fork()
    if pid == 0:
        os.execv(sys.executable, [sys.executable, script, child_log, child_role])
    note(log_path, role, "event=spawned-child child=%s" % pid)
    marker = os.environ.get("AW_MAC129_MARKER")
    if marker:
        with open(marker, "w") as handle:
            handle.write(str(pid))
    note(log_path, role, "event=waiting")
    waiter_pid = os.fork()
    if waiter_pid == 0:
        watch(log_path, role, fatal)
    while True:
        try:
            waited, status = os.waitpid(-1, 0)
        except OSError:
            note(log_path, role, "event=wait-error")
            sys.exit(1)
        if not waited:
            continue
        if os.WIFSIGNALED(status):
            text = "signaled sig=%s" % os.WTERMSIG(status)
        elif os.WIFEXITED(status):
            text = "exited code=%s" % os.WEXITSTATUS(status)
        else:
            text = "status=%s" % status
        note(log_path, role, "event=reaped pid=%s %s" % (waited, text))
        if waited == pid:
            # Same convention as bash: 128 + the signal that killed the waited
            # job, otherwise the job's own exit code.
            os.kill(waiter_pid, signal.SIGKILL)
            os.waitpid(waiter_pid, 0)
            if os.WIFSIGNALED(status):
                sys.exit(128 + os.WTERMSIG(status))
            sys.exit(os.WEXITSTATUS(status))
        if waited == waiter_pid:
            # The waiter exits 128+N when this process itself was signalled.
            code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            sys.exit(code)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 - diagnosis must not die silently
        sys.stderr.write("mac129-sigrec failed: %s\n" % error)
        sys.exit(1)
