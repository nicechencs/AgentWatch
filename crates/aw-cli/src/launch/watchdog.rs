//! Re-exec'd Linux watchdog for programs started by `aw` itself.
//!
//! The parent CLI and this helper use an inherited private Unix socket. Command
//! and environment values never become helper argv or environment data. The
//! helper is a new session and Linux child subreaper before it starts the
//! program; its cleanup reaches children which daemonize with `setsid`.

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::RunSpec;

const INTERNAL_FLAG: &str = "AW_INTERNAL_LINUX_WATCHDOG";
const CONTROL_FD: &str = "AW_INTERNAL_LINUX_WATCHDOG_FD";
const READY: u8 = b'R';
const CONFIG: u8 = b'C';
const START: u8 = b'S';
const PID: u8 = b'P';

/// A started watchdog. It is the child `aw` owns and reaps; the target is its
/// child and is reported separately once it has been released.
pub struct Watchdog {
    child: Child,
    control: UnixStream,
    released: bool,
}

/// `true` when this executable invocation is the private watchdog helper.
#[must_use]
pub fn is_internal() -> bool {
    std::env::var_os(INTERNAL_FLAG).is_some()
}

/// Run the re-exec'd helper and return the program's conventional exit code.
/// No error text is written because the control protocol only carries status.
pub fn run_internal() -> i32 {
    let Some(fd) = std::env::var(CONTROL_FD)
        .ok()
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
    // The parent is still the one that inherited the socket when this helper
    // begins. The platform setup immediately checks it again after PR_SET_PDEATHSIG.
    let _ = control;
    // `/proc` is used here before the target starts and failure means setup
    // refuses below.
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
    let Ok(request) = receive_config(control) else {
        return 1;
    };
    if control.write_all(&[READY]).is_err() || control.flush().is_err() {
        return 1;
    }
    let mut start = [0_u8; 1];
    if control.read_exact(&mut start).is_err() || start[0] != START || died.load(Ordering::Relaxed)
    {
        return 1;
    }
    let Ok(mut program) = start_program(&request) else {
        return 1;
    };
    let pid = program.id();
    if control
        .write_all(&[PID])
        .and_then(|_| control.write_all(&pid.to_be_bytes()))
        .and_then(|_| control.flush())
        .is_err()
    {
        aw_platform::cleanup_watchdog_descendants();
        return 1;
    }

    let mut eof_control = control.try_clone().ok();
    let (done, events) = mpsc::channel();
    if let Some(mut watch) = eof_control.take() {
        std::thread::spawn(move || {
            let mut byte = [0_u8; 1];
            let ended = match watch.read(&mut byte) {
                Ok(0) | Err(_) => true,
                Ok(_) => false,
            };
            let _ = done.send(ended);
        });
    }

    loop {
        if died.load(Ordering::Relaxed) || events.try_recv().is_ok() {
            aw_platform::cleanup_watchdog_descendants();
            return 1;
        }
        match program.try_wait() {
            Ok(Some(status)) => {
                let code = status_code(status);
                aw_platform::cleanup_watchdog_descendants();
                return code;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => {
                aw_platform::cleanup_watchdog_descendants();
                return 1;
            }
        }
    }
}

fn receive_config(control: &mut UnixStream) -> io::Result<Request> {
    let mut header = [0_u8; 5];
    control.read_exact(&mut header)?;
    if header[0] != CONFIG {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing config"));
    }
    let length = u32::from_be_bytes(header[1..].try_into().unwrap_or([0; 4]));
    let mut bytes = vec![0; length as usize];
    control.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid config"))
}

fn start_program(request: &Request) -> io::Result<Child> {
    let Some((program, args)) = request.command.split_first() else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty program"));
    };
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        // The signal/TTY owner in `run.rs` addresses this group, while this
        // watchdog stays in its separate session and survives terminal HUP.
        .process_group(0);
    if let Some(cwd) = &request.cwd {
        command.current_dir(cwd);
    }
    command.envs(request.env.iter().cloned());
    command.spawn()
}

fn status_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
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
    /// Spawn a held watchdog. Its target is not started until [`Self::release`].
    pub fn spawn(spec: &RunSpec) -> Result<Self, String> {
        let request = Request::from(spec);
        let bytes = serde_json::to_vec(&request).map_err(|_| "无法准备启动看护".to_owned())?;
        let (mut parent, child_control) =
            UnixStream::pair().map_err(|_| "无法建立退出看护".to_owned())?;
        clear_cloexec(child_control.as_fd()).map_err(|_| "无法保护退出看护".to_owned())?;
        let executable = std::env::current_exe().map_err(|_| "无法启动退出看护".to_owned())?;
        let child = Command::new(executable)
            .env(INTERNAL_FLAG, "1")
            .env(CONTROL_FD, child_control.as_raw_fd().to_string())
            .spawn()
            .map_err(|_| "无法启动退出看护".to_owned())?;
        drop(child_control);
        send_config(&mut parent, &bytes).map_err(|_| "无法配置退出看护".to_owned())?;
        let mut ready = [0_u8; 1];
        parent
            .read_exact(&mut ready)
            .map_err(|_| "退出看护未能就绪".to_owned())?;
        if ready[0] != READY {
            return Err("退出看护未能就绪".to_owned());
        }
        Ok(Self {
            child,
            control: parent,
            released: false,
        })
    }

    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Release the actual program and return its process-group leader pid.
    pub fn release(&mut self) -> Result<u32, String> {
        self.control
            .write_all(&[START])
            .and_then(|_| self.control.flush())
            .map_err(|_| "无法放行退出看护".to_owned())?;
        let mut reply = [0_u8; 5];
        self.control
            .read_exact(&mut reply)
            .map_err(|_| "退出看护未能启动程序".to_owned())?;
        if reply[0] != PID {
            return Err("退出看护未能启动程序".to_owned());
        }
        self.released = true;
        Ok(u32::from_be_bytes(reply[1..].try_into().unwrap_or([0; 4])))
    }

    pub fn wait(&mut self) -> Result<i32, String> {
        let status = self
            .child
            .wait()
            .map_err(|_| "等待程序结束失败".to_owned())?;
        Ok(status_code(status))
    }

    pub fn abort(&mut self) {
        if !self.released {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.abort();
    }
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
