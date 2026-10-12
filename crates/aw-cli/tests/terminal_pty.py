#!/usr/bin/env python3
"""Exercise `aw run` through a real pseudo-terminal on Unix."""

import errno
import fcntl
import os
import pty
import select
import shutil
import signal
import sys
import tempfile
import termios
import time

AW = sys.argv[1]
PYTHON = shutil.which("python3")


def read_for(fd, seconds):
    data = b""
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        readable, _, _ = select.select([fd], [], [], 0.05)
        if not readable:
            continue
        try:
            part = os.read(fd, 4096)
        except OSError as error:
            # mac129 diagnosis: an EIO here is the slave closing. Keep what was
            # already captured instead of discarding it.
            data += ("\n[read EIO errno=%s]\n" % error.errno).encode()
            break
        if not part:
            break
        data += part
    return data


def wait_for_exit(pid, seconds, label):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.02)
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    raise AssertionError("%s did not exit" % label)


def spawn(mode, argv):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(AW, [AW, "run", "-q"] + mode + ["--"] + argv)
    return pid, fd


def interactive(mode, label, argv, inputs, expected):
    pid, fd = spawn(mode, argv)
    output = read_for(fd, 0.3)
    try:
        for text in inputs:
            os.write(fd, text)
            output += read_for(fd, 0.35)
        os.write(fd, b"\x04")
        output += read_for(fd, 1.5)
    except OSError as error:
        # mac129 diagnosis: the write itself failed (macOS EIO is errno 5).
        # Print everything aw already produced, then aw's exit code.
        sys.stderr.write(
            "mac129-pty: %s write failed errno=%s; captured so far:\n%s\n"
            % (label, error.errno, output)
        )
        code = wait_for_exit(pid, 3, label)
        sys.stderr.write("mac129-pty: %s aw exit code after failed write: %s\n" % (label, code))
        raise
    code = wait_for_exit(pid, 3, label)
    os.close(fd)
    for item in expected:
        if item not in output:
            raise AssertionError("%s missing %r in %r" % (label, item, output))
    if code != 0:
        raise AssertionError("%s returned %s: %r" % (label, code, output))


def marker_program(marker):
    return [
        PYTHON,
        "-c",
        "import os, pathlib, signal, sys, time; signal.signal(signal.SIGHUP, signal.SIG_DFL); pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(120)",
        marker,
    ]


def assert_gone(pid, label):
    until = time.monotonic() + 2
    while time.monotonic() < until:
        try:
            os.kill(pid, 0)
        except OSError as error:
            if error.errno == errno.ESRCH:
                return
        time.sleep(0.02)
    raise AssertionError("%s direct child %s survived" % (label, pid))


def terminal_signal(mode, label, close_terminal):
    marker = tempfile.mktemp(prefix="aw-pty-child-")
    pid, fd = spawn(mode, marker_program(marker))
    until = time.monotonic() + 3
    while not os.path.exists(marker) and time.monotonic() < until:
        read_for(fd, 0.05)
    if not os.path.exists(marker):
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise AssertionError("%s did not publish its pid" % label)
    child = int(open(marker).read())
    if close_terminal:
        os.close(fd)
        expected = 129
    else:
        os.write(fd, b"\x03")
        read_for(fd, 0.3)
        os.close(fd)
        expected = 130
    code = wait_for_exit(pid, 3, label)
    if code != expected:
        raise AssertionError("%s returned %s, expected %s" % (label, code, expected))
    assert_gone(child, label)
    os.unlink(marker)


def ctrl_z_stops_aw_and_resumes_the_child(mode, label):
    marker = tempfile.mktemp(prefix="aw-pty-stop-")
    pid, fd = spawn(mode, marker_program(marker))
    until = time.monotonic() + 3
    while not os.path.exists(marker) and time.monotonic() < until:
        read_for(fd, 0.05)
    if not os.path.exists(marker):
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise AssertionError("%s did not publish its pid" % label)
    child = int(open(marker).read())
    os.write(fd, b"\x1a")
    until = time.monotonic() + 3
    while time.monotonic() < until:
        waited, status = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
        if waited:
            if os.WIFSTOPPED(status):
                break
            raise AssertionError("%s exited instead of stopping" % label)
        time.sleep(0.02)
    else:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        raise AssertionError("%s did not stop after Ctrl+Z" % label)
    os.kill(pid, signal.SIGCONT)
    read_for(fd, 0.2)
    os.write(fd, b"\x03")
    read_for(fd, 0.3)
    code = wait_for_exit(pid, 3, label)
    os.close(fd)
    if code != 130:
        raise AssertionError("%s returned %s, expected 130" % (label, code))
    assert_gone(child, label)
    os.unlink(marker)


def restored_foreground(mode, label, argv, expected_code):
    """Run aw below a pty-owning shell and prove it hands the tty back.

    `pty.fork()` makes aw both session leader and its initial foreground group,
    which cannot distinguish a correct restore from leaving the target's group
    foreground. This miniature shell stays in its own pgrp, waits for aw, and
    reports the terminal foreground pgrp after both a normal and an error path.
    """
    master, slave = os.openpty()
    report_read, report_write = os.pipe()
    shell = os.fork()
    if shell == 0:
        try:
            os.close(master)
            os.close(report_read)
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            shell_group = os.getpgrp()
            os.tcsetpgrp(slave, shell_group)
            aw = os.fork()
            if aw == 0:
                os.close(report_write)
                os.dup2(slave, 0)
                os.dup2(slave, 1)
                os.dup2(slave, 2)
                if slave > 2:
                    os.close(slave)
                os.execv(AW, [AW, "run"] + mode + ["--"] + argv)
            _, status = os.waitpid(aw, 0)
            code = os.waitstatus_to_exitcode(status)
            foreground = os.tcgetpgrp(slave)
            os.write(report_write, ("%d %d %d" % (code, foreground, shell_group)).encode())
        finally:
            os._exit(0)
    os.close(slave)
    os.close(report_write)
    data = os.read(report_read, 128)
    os.close(report_read)
    _, status = os.waitpid(shell, 0)
    os.close(master)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise AssertionError("%s shell harness failed" % label)
    try:
        code, foreground, shell_group = [int(value) for value in data.split()]
    except ValueError:
        raise AssertionError("%s did not report foreground state: %r" % (label, data))
    if code != expected_code:
        raise AssertionError("%s returned %s, expected %s" % (label, code, expected_code))
    if foreground != shell_group:
        raise AssertionError(
            "%s left terminal foreground pgrp %s, expected shell pgrp %s"
            % (label, foreground, shell_group)
        )


def main():
    if PYTHON is None:
        print("pty terminal regression skipped: python3 is unavailable")
        return
    scenarios = [
        ("cat", ["cat"], [b"cat-line\n"], [b"cat-line"]),
        (
            "while-read",
            ["sh", "-c", "while read l; do echo got:$l; done"],
            [b"first\n", b"second\n"],
            [b"got:first", b"got:second"],
        ),
        (
            "python-input",
            [PYTHON, "-c", "print('got:' + input(), flush=True)"],
            [b"python-line\n"],
            [b"got:python-line"],
        ),
        (
            "immediate-read",
            [PYTHON, "-c", "import os; os.write(1, b'immediate:' + os.read(0, 128))"],
            [b"race-line\n"],
            [b"immediate:race-line"],
        ),
    ]
    for mode in ([], ["--no-daemon"]):
        prefix = "default" if not mode else "no-daemon"
        for name, argv, inputs, expected in scenarios:
            interactive(mode, prefix + " " + name, argv, inputs, expected)
        ctrl_z_stops_aw_and_resumes_the_child(mode, prefix + " ctrl-z")
        terminal_signal(mode, prefix + " ctrl-c", False)
        terminal_signal(mode, prefix + " terminal-close", True)
        restored_foreground(mode, prefix + " normal foreground restore", ["sh", "-c", "exit 0"], 0)
        restored_foreground(
            mode,
            prefix + " failed launch foreground restore",
            ["/no/such/aw-pty-program"],
            1,
        )


if __name__ == "__main__":
    main()
