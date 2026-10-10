//! `aw run` (P1-CLI-02).
//!
//! `--no-daemon` starts the target as the calling user through an injected
//! [`Launcher`], then prints a session summary. The default daemon path first
//! records `/sessions/run`, starts the child as the caller behind a Unix pipe
//! gate, and hands it over through `/adopt` before releasing it to exec. On
//! Windows the local production launcher is
//! [`launch::production`]: Job assignment is unavailable, so no process is
//! created. On macOS it spawns with `Command` and says suspension was not
//! applied. On Linux [`launch::LocalCgroupHost`] places the child in a delegated
//! cgroup v2 directory, or returns an error and starts nothing. Tests pass a
//! fake and assert the target's exit code comes back unchanged.
//!
//! `--self-report` and `--unsafe-no-redact` are refused with a pointer at the
//! later card. `--mcp-tap` is refused on its own: no per-agent MCP config
//! injection exists (SPIKE-09), so `aw run` does not rewrite a config and does
//! not launch. The manual wrapper is `aw mcp-tap -- <cmd>`. `--proxy` is a
//! launch-mode injection plan
//! ([`aw_proxy::plan_injection`]): this process does not open a listener,
//! because the daemon has no "open a proxy and return its port" call and has
//! no tokio runtime to host [`aw_proxy::MitmProxy`]. The plan names the
//! variables and whether each one overwrites; it does not invent a port.
//! Nothing here disables redaction, writes a shell rc, or touches a
//! certificate store.
//!
//! Command text, environment values, and the working directory are inputs to
//! the launcher. They are not written to stdout, stderr, or an error string.

use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::{Child, Command};

#[cfg(unix)]
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
#[cfg(unix)]
use nix::unistd::{pipe, write};

use aw_proxy::{plan_injection, Injection, ProxyOnReject};

use serde_json::{json, Value};

use crate::exit;
use crate::launch::{self, LaunchDispatchError, Launched, RunSpec, UnixLauncher};

use super::attach::{BeginRunRequest, ControlError, DaemonSessions};
use super::Outcome;

/// Flags `aw run` acts on. Built by dispatch from the parsed command.
///
/// `command`, `cwd`, and `env` stay on this struct so the launcher can use them.
/// Formatters in this module do not read those three fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunArgs<'a> {
    /// `--agent`.
    pub agent: Option<&'a str>,
    /// `--name`, the session label.
    pub name: Option<&'a str>,
    /// `--no-follow-children`.
    pub no_follow_children: bool,
    /// `--cwd`. Not printed.
    pub cwd: Option<&'a str>,
    /// `--env K=V` pairs, still unsplit. Not printed.
    pub env: &'a [String],
    /// `--summary none|short|full`. `None` means `short`.
    pub summary: Option<&'a str>,
    /// `--pin`.
    pub pin: bool,
    /// `--no-daemon`.
    pub no_daemon: bool,
    /// `--raw <file>`. The path is not echoed back.
    pub raw: Option<&'a str>,
    /// Target command. Not printed.
    pub command: &'a [String],
    /// `--json`.
    pub json: bool,
    /// `-q`: skip the `[aw]` lines.
    pub quiet: bool,
}

/// Later-card flags. Present means the command stops before any launch,
/// except the proxy pair, which [`proxy_plan`] turns into an injection plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DeferredFlags<'a> {
    /// `--proxy`.
    pub proxy: bool,
    /// `--proxy-on-reject` was set.
    pub proxy_on_reject: bool,
    /// The value, when the flag was set. Not a secret.
    pub proxy_on_reject_value: Option<&'a str>,
    /// `--self-report` was set.
    pub self_report: bool,
    /// `--mcp-tap`.
    pub mcp_tap: bool,
    /// `--unsafe-no-redact`.
    pub unsafe_no_redact: bool,
    /// `--include-proc` was set. Scope extension is not this card.
    pub include_proc: bool,
    /// `--group` was set. Groups are a later card.
    pub group: bool,
}

/// How much of the summary to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SummaryLevel {
    /// `--summary none`.
    None,
    /// Default, and `--summary short`.
    Short,
    /// `--summary full`. Same figures, plus the level note on its own line.
    Full,
}

/// One domain row. The name is a registrable label the summary source already
/// decided is safe to print. This module does not resolve DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DomainCount {
    /// Domain label. Not a URL.
    pub name: String,
    /// How many flows named it. A real zero is allowed; a missing count is not
    /// represented by omitting the row.
    pub flows: u64,
}

/// Figures for the end-of-session summary (api-and-cli §2.1).
///
/// Counts are `Option` because "the collector did not answer" is not zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Summary {
    /// Public session id, when one was assigned.
    pub session_id: Option<String>,
    /// Process rows observed.
    pub processes: Option<u64>,
    /// Bytes sent. `None` when no flow reported a byte count.
    pub bytes_up: Option<u64>,
    /// Bytes received.
    pub bytes_down: Option<u64>,
    /// Domains, most flows first. At most five are printed.
    pub top_domains: Vec<DomainCount>,
    /// Gap rows.
    pub gaps: Option<u64>,
    /// One line naming the evidence level of this session. Not a claim about
    /// what the target did.
    pub level_note: String,
}

/// Where the summary comes from. Production has no store, so it returns `None`.
pub(crate) trait SessionSummary {
    /// Figures for the session that just ended.
    ///
    /// `Ok(None)` means the figures are unavailable. Callers print that fact.
    /// They do not substitute zero.
    ///
    /// # Errors
    ///
    /// A source failure. The message must not contain argv, environment values,
    /// URLs, or header contents.
    fn summarize(&mut self, session_hint: Option<&str>) -> Result<Option<Summary>, String>;
}

/// Production summary. Nothing was recorded, and that is said explicitly.
#[derive(Debug, Default)]
pub(crate) struct EmptySummary;

impl SessionSummary for EmptySummary {
    fn summarize(&mut self, _session_hint: Option<&str>) -> Result<Option<Summary>, String> {
        Ok(None)
    }
}

/// Summary for a daemon-recorded session: `GET /api/v1/sessions/{id}` after
/// the target exits. Counts are what the daemon has stored at that moment; a
/// missing count stays unknown, never zero.
pub(crate) struct DaemonSummary {
    endpoint: crate::endpoint::Endpoint,
}

impl DaemonSummary {
    /// Bind to the endpoint `aw run` used. Does not connect.
    #[must_use]
    pub(crate) fn new(endpoint: crate::endpoint::Endpoint) -> Self {
        Self { endpoint }
    }
}

/// Fixed sentence for a daemon-recorded run. Not a claim about the target.
const DAEMON_LEVEL_NOTE: &str =
    "证据 S（后台轮询采样）· 数字为目标退出时后台已记录的部分，会话由后台在根进程退出后结束";

impl SessionSummary for DaemonSummary {
    fn summarize(&mut self, session_hint: Option<&str>) -> Result<Option<Summary>, String> {
        let Some(id) = session_hint else {
            return Ok(None);
        };
        let path = format!("/api/v1/sessions/{}", super::query::encode_path_segment(id));
        let transport =
            crate::client::LoopbackHttp::new(&self.endpoint).map_err(|err| err.to_string())?;
        let mut client = crate::client::Client::new(self.endpoint.clone(), transport);
        let reply = client
            .call(&crate::client::ApiRequest::get(&path))
            .map_err(|err| err.to_string())?;
        let body = reply
            .json()
            .ok_or_else(|| "后台返回的响应体不是 JSON".to_owned())?;
        let stats = body.get("stats").cloned().unwrap_or(Value::Null);
        let count = |key: &str| stats.get(key).and_then(Value::as_u64);
        Ok(Some(Summary {
            session_id: Some(id.to_owned()),
            processes: count("process_count"),
            bytes_up: count("bytes_up"),
            bytes_down: count("bytes_down"),
            top_domains: Vec::new(),
            gaps: count("gap_count"),
            level_note: DAEMON_LEVEL_NOTE.to_owned(),
        }))
    }
}

/// Starts a process and can forward one interrupt. Tests use a fake.
#[allow(dead_code)]
pub(crate) trait Launcher {
    /// Start `spec` as the calling user and wait for it to exit.
    ///
    /// # Errors
    ///
    /// The platform launcher failed before an exit code existed.
    fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError>;

    /// Forward Ctrl-C to `pid`. Does not send a signal itself; the platform
    /// launcher does, and tests record the call.
    ///
    /// # Errors
    ///
    /// The launcher could not forward.
    fn forward_interrupt(&mut self, pid: u32) -> Result<(), LaunchDispatchError>;
}

/// A caller-created child after a daemon launch session has been registered.
pub(crate) trait SpawnedChild {
    /// Process id supplied to `/adopt`.
    fn pid(&self) -> u32;

    /// Reap the child and return its target exit code. A signalled child is a
    /// general CLI failure because it has no numeric exit code to forward.
    fn wait(&mut self) -> Result<i32, String>;

    /// Let a held Unix child exec its target after the daemon accepted
    /// `/adopt`. Direct-spawn platforms have no gate, so this is a no-op.
    ///
    /// # Errors
    ///
    /// The pipe gate could not be released. The caller must reap the child.
    fn release(&mut self) -> Result<(), String>;

    /// Stop and reap a child that the daemon refused to adopt.
    fn kill_and_reap(&mut self);
}

/// Spawn a child for the default daemon-backed `aw run` path.
pub(crate) trait Spawner {
    /// Spawn the target as this CLI's user, with inherited standard streams.
    ///
    /// # Errors
    ///
    /// A short OS error class with no argv or environment values.
    fn spawn(&mut self, spec: &RunSpec) -> Result<Box<dyn SpawnedChild>, String>;
}

/// Production caller-side spawner. It never creates a cgroup: the daemon
/// records the adopted root pid and performs its own scope handling.
/// Plain Chinese sentence for a failed spawn, by error kind, with the same
/// codes the daemon uses (`program_not_found`, `program_not_permitted`,
/// `spawn_failed`). The program and its arguments are not repeated (they can
/// carry secrets).
pub(crate) fn spawn_error_text(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => {
            "无法启动程序：找不到这个程序或工作目录（program_not_found）".to_owned()
        }
        std::io::ErrorKind::PermissionDenied => {
            "无法启动程序：没有权限运行它或进入工作目录（program_not_permitted）".to_owned()
        }
        _ => format!("无法启动程序（spawn_failed，{}）", os_code(error)),
    }
}

/// Plain Chinese sentence when waiting for the started program failed.
pub(crate) fn wait_error_text(error: &std::io::Error) -> String {
    format!("等待程序结束失败（{}）", os_code(error))
}

fn os_code(error: &std::io::Error) -> String {
    error.raw_os_error().map_or_else(
        || "系统没有给出错误码".to_owned(),
        |code| format!("系统错误码 {code}"),
    )
}

#[derive(Debug, Default)]
pub(crate) struct CommandSpawner;

#[cfg(not(unix))]
struct ProcessChild(Child);

#[cfg(not(unix))]
impl SpawnedChild for ProcessChild {
    fn pid(&self) -> u32 {
        self.0.id()
    }

    fn wait(&mut self) -> Result<i32, String> {
        self.0
            .wait()
            .map(|status| status.code().unwrap_or(exit::GENERAL))
            .map_err(|error| wait_error_text(&error))
    }

    fn release(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn kill_and_reap(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The shell runs with the pipe read end open, and cannot reach the target
/// `exec` until the parent writes to the other end. The write end is
/// close-on-exec, so an eventual target cannot accidentally keep the gate open.
/// `dash` accepts dynamic redirections only for one-digit descriptors, so the
/// read uses the portable `/dev/fd/N` alias. A higher-numbered read end is
/// harmless after EOF and is left for target exit rather than turning a valid
/// launch into shell exit 125.
#[cfg(unix)]
const GATE_SHELL: &str = r#"fd=$1; shift; IFS= read -r _ < "/dev/fd/$fd" || exit 125; case "$fd" in [0-9]) eval "exec $fd<&-" ;; esac; exec "$@""#;

#[cfg(unix)]
struct GatedChild {
    child: Child,
    release_fd: Option<OwnedFd>,
}

#[cfg(unix)]
impl SpawnedChild for GatedChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn wait(&mut self) -> Result<i32, String> {
        self.child
            .wait()
            .map(|status| status.code().unwrap_or(exit::GENERAL))
            .map_err(|error| wait_error_text(&error))
    }

    fn release(&mut self) -> Result<(), String> {
        let Some(fd) = self.release_fd.take() else {
            return Ok(());
        };
        let mut remaining = &b"1\n"[..];
        while !remaining.is_empty() {
            match write(&fd, remaining) {
                Ok(0) => return Err("启动闸门未写入任何数据".to_owned()),
                Ok(written) => remaining = &remaining[written..],
                Err(error) => {
                    return Err(format!("无法释放启动闸门（系统错误码 {}）", error as i32));
                }
            }
        }
        Ok(())
    }

    fn kill_and_reap(&mut self) {
        // Drop the write end before reaping. If a signal races with the shell,
        // EOF makes it choose exit 125 rather than reaching the target exec.
        self.release_fd.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Spawner for CommandSpawner {
    fn spawn(&mut self, spec: &RunSpec) -> Result<Box<dyn SpawnedChild>, String> {
        let Some((program, args)) = spec.command.split_first() else {
            return Err("程序名为空".to_owned());
        };
        #[cfg(unix)]
        {
            let (read_fd, write_fd) = pipe().map_err(nix_spawn_error_text)?;
            let flags = fcntl(&write_fd, FcntlArg::F_GETFD).map_err(nix_spawn_error_text)?;
            let flags = FdFlag::from_bits_truncate(flags) | FdFlag::FD_CLOEXEC;
            fcntl(&write_fd, FcntlArg::F_SETFD(flags)).map_err(nix_spawn_error_text)?;
            let mut command = Command::new("/bin/sh");
            command
                .arg("-c")
                .arg(GATE_SHELL)
                .arg("aw-run")
                .arg(read_fd.as_raw_fd().to_string())
                .arg(program)
                .args(args);
            configure_command(&mut command, spec);
            let child = command.spawn().map_err(|error| spawn_error_text(&error))?;
            // The shell owns the read end now. Once this copy is dropped, an
            // aw crash closes the only write end and the shell exits 125.
            drop(read_fd);
            Ok(Box::new(GatedChild {
                child,
                release_fd: Some(write_fd),
            }))
        }
        #[cfg(not(unix))]
        {
            let mut command = Command::new(program);
            command.args(args);
            configure_command(&mut command, spec);
            command
                .spawn()
                .map(|child| Box::new(ProcessChild(child)) as Box<dyn SpawnedChild>)
                .map_err(|error| spawn_error_text(&error))
        }
    }
}

fn configure_command(command: &mut Command, spec: &RunSpec) {
    if let Some(cwd) = spec.cwd.as_deref() {
        command.current_dir(cwd);
    }
    for (key, value) in &spec.env {
        command.env(key, value);
    }
}

#[cfg(unix)]
fn nix_spawn_error_text(error: nix::errno::Errno) -> String {
    spawn_error_text(&std::io::Error::from_raw_os_error(error as i32))
}

/// Windows production launcher.
///
/// Uses [`launch::production`]. Job assignment is unavailable in this crate
/// (`forbid(unsafe_code)`, no `windows` dependency), so no process is created.
/// The error is [`crate::launch::LaunchError::JobFailed`] and does not claim a
/// Job. A real suspended `CreateProcess` needs the `windows` crate, which is
/// out of scope for `aw-cli`.
#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
pub(crate) struct PlatformLauncher;

#[cfg(target_os = "windows")]
impl Launcher for PlatformLauncher {
    fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
        let mut api = launch::production();
        launch::dispatch_windows(&mut api, spec)
    }

    fn forward_interrupt(&mut self, _pid: u32) -> Result<(), LaunchDispatchError> {
        Err(LaunchDispatchError::Windows(
            crate::launch::LaunchError::NotVerified {
                step: "GenerateConsoleCtrlEvent",
            },
        ))
    }
}

/// Linux production launcher.
///
/// [`launch::LocalCgroupHost`] creates the session directory and moves the
/// child into it. A cgroup failure is returned and the target is not left
/// running outside the scope. Other non-Windows, non-macOS targets keep
/// [`launch::UnsupportedUnixLauncher`].
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub(crate) struct PlatformLauncher;

#[cfg(target_os = "linux")]
impl Launcher for PlatformLauncher {
    fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
        launch_linux(spec, &mut |program, argv, cwd, env| {
            launch::LocalCgroupHost.launch(program, argv, cwd, env, session_token())
        })
    }

    fn forward_interrupt(&mut self, _pid: u32) -> Result<(), LaunchDispatchError> {
        Err(LaunchDispatchError::NotImplemented {
            detail: "中断转发尚未接通；将等待子进程结束，不转发信号".to_owned(),
        })
    }
}

/// One cgroup-scoped launch attempt (production: [`launch::LocalCgroupHost`]).
#[cfg(target_os = "linux")]
type CgroupAttempt<'a> = dyn FnMut(
        &std::ffi::OsStr,
        &[std::ffi::OsString],
        Option<&str>,
        &[(String, String)],
    ) -> Result<launch::LinuxLaunchResult, launch::LinuxLaunchError>
    + 'a;

/// Whether a failed cgroup attempt may fall back to process-tree tracking.
///
/// Only failures that happen before any child exists qualify: cgroup v1 /
/// unknown hierarchy, and a parent that is not delegated or not writable
/// (`CreateFailed`, e.g. "no delegated controllers"). A failure after the
/// child started (procs write, wait) is not retried, so the program never
/// runs twice; a spawn failure is the program's own problem.
#[cfg(target_os = "linux")]
pub(crate) fn cgroup_fallback_allowed(err: &launch::LinuxLaunchError) -> bool {
    matches!(
        err,
        launch::LinuxLaunchError::CgroupV1NoLaunch | launch::LinuxLaunchError::CreateFailed { .. }
    )
}

/// Linux `aw run --no-daemon`: try the cgroup scope, else track the process
/// tree by pid (scope_pids) and say which capability is missing.
#[cfg(target_os = "linux")]
fn launch_linux(
    spec: &RunSpec,
    attempt: &mut CgroupAttempt<'_>,
) -> Result<Launched, LaunchDispatchError> {
    let Some((program, args)) = spec.command.split_first() else {
        return Err(LaunchDispatchError::NotImplemented {
            detail: "启动命令为空".to_owned(),
        });
    };
    let argv: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
    match attempt(
        std::ffi::OsStr::new(program),
        &argv,
        spec.cwd.as_deref(),
        &spec.env,
    ) {
        Ok(done) => Ok(Launched {
            // A signalled child has no exit code. That is not success.
            code: done.code.unwrap_or(exit::GENERAL),
            pid: done.pid,
            note: Some(if done.scoped {
                POST_SPAWN_MOVE_NOTE
            } else {
                PID_TREE_FALLBACK_NOTE
            }),
            sampling: spec.no_daemon,
        }),
        Err(err) if cgroup_fallback_allowed(&err) => {
            let mut child = std::process::Command::new(program);
            child.args(&argv);
            if let Some(dir) = spec.cwd.as_deref() {
                child.current_dir(dir);
            }
            for (key, value) in &spec.env {
                child.env(key, value);
            }
            let mut spawned =
                child
                    .spawn()
                    .map_err(|error| LaunchDispatchError::NotImplemented {
                        detail: format!(
                            "{}；cgroup 不可用，已改按进程树跟踪，仍没能启动",
                            spawn_error_text(&error)
                        ),
                    })?;
            let pid = spawned.id();
            let status = spawned
                .wait()
                .map_err(|error| LaunchDispatchError::NotImplemented {
                    detail: wait_error_text(&error),
                })?;
            Ok(Launched {
                code: status.code().unwrap_or(exit::GENERAL),
                pid,
                note: Some(PID_TREE_FALLBACK_NOTE),
                sampling: spec.no_daemon,
            })
        }
        Err(err) => Err(LaunchDispatchError::NotImplemented {
            detail: err.to_string(),
        }),
    }
}

/// Fixed sentence when no delegated cgroup v2 was available. Names the
/// missing capability; not a claim about the target.
#[cfg(target_os = "linux")]
pub(crate) const PID_TREE_FALLBACK_NOTE: &str =
    "没采：cgroup 会话范围（本机没有可委派、可用的 cgroup v2），已退化为按进程树跟踪（scope_pids）；脱离进程树的子进程可能漏记";

/// Fixed sentence for the post-spawn cgroup move. Not a claim about the target.
#[cfg(target_os = "linux")]
const POST_SPAWN_MOVE_NOTE: &str = "子进程在写入 cgroup.procs 之前已经启动，这段窗口记为缺口";

/// Session directory suffix. Not a stored id; unique for one launch.
#[cfg(target_os = "linux")]
fn session_token() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1)
}

/// Non-Linux, non-Windows, non-macOS production launcher.
///
/// Names the cards that will provide a real Unix launcher.
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
#[derive(Debug, Default)]
pub(crate) struct PlatformLauncher;

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
impl Launcher for PlatformLauncher {
    fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
        let mut inner = launch::UnsupportedUnixLauncher;
        launch::dispatch_unix(&mut inner, spec)
    }

    fn forward_interrupt(&mut self, pid: u32) -> Result<(), LaunchDispatchError> {
        let mut inner = launch::UnsupportedUnixLauncher;
        inner.forward_interrupt(pid)
    }
}

/// macOS production launcher.
///
/// [`launch::production`] spawns the child with `Command`. Suspension is not
/// applied: `POSIX_SPAWN_START_SUSPENDED` is not available without `unsafe` or
/// an extra crate. The returned note says so. This is not E1 scope, and
/// grandchild tracking is left to the collector.
#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
pub(crate) struct PlatformLauncher;

#[cfg(target_os = "macos")]
impl Launcher for PlatformLauncher {
    fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
        let mut api = launch::production();
        let (code, pid, note, sampling) =
            launch::launch_command(&mut api, spec.command.clone(), spec.no_daemon).map_err(
                |err| LaunchDispatchError::NotImplemented {
                    detail: err.to_string(),
                },
            )?;
        Ok(Launched {
            code,
            pid,
            note,
            sampling,
        })
    }

    fn forward_interrupt(&mut self, _pid: u32) -> Result<(), LaunchDispatchError> {
        // No process group was created. A signal would need libc, which this
        // crate does not link. Do not claim the interrupt was forwarded.
        Err(LaunchDispatchError::NotImplemented {
            detail: "中断转发不可用；没有创建进程组，且未链接 libc".to_owned(),
        })
    }
}

/// Run `aw run`.
///
/// On success the outcome code is the target's exit code. A refused flag is
/// exit 1. A launcher failure is exit 1, or exit 3 when the launcher reports
/// the daemon path and the caller did not pass `--no-daemon`.
pub(crate) fn run(
    args: &RunArgs<'_>,
    deferred: DeferredFlags,
    launcher: &mut dyn Launcher,
    summary: &mut dyn SessionSummary,
) -> Outcome {
    let (level, spec) = match prepare(args, deferred) {
        Ok(prepared) => prepared,
        Err(outcome) => return outcome,
    };

    let launched = match launcher.launch(&spec) {
        Ok(launched) => launched,
        Err(err) => {
            let code = if args.no_daemon {
                exit::GENERAL
            } else if mentions_daemon(&err) {
                exit::UNREACHABLE
            } else {
                exit::GENERAL
            };
            return super::error_outcome(code, "launch", &err.to_string(), args.json);
        }
    };

    if level == SummaryLevel::None || args.quiet {
        return Outcome {
            code: launched.code,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
    }

    let figures = summary.summarize(args.name);
    let mut stderr = Vec::new();
    if let Err(err) = write_summary(
        &mut stderr,
        args,
        level,
        &launched,
        &figures,
        None,
        PinState::Unknown,
    ) {
        return super::error_outcome(exit::GENERAL, "summary", &err.to_string(), args.json);
    }
    Outcome {
        code: launched.code,
        stdout: Vec::new(),
        stderr,
    }
}

/// Validate and normalize run arguments before any daemon session request.
///
/// The returned [`RunSpec`] still contains environment values for the local
/// spawner, but callers must not serialize it into the daemon request.
pub(crate) fn preflight(args: &RunArgs<'_>, deferred: DeferredFlags) -> Result<(), Outcome> {
    daemon_prepare(args, deferred).map(|_| ())
}

/// [`prepare`] plus the refusals that apply only when the daemon records the
/// session: its poll sampler always follows children, so
/// `--no-follow-children` would be silently ignored.
fn daemon_prepare(
    args: &RunArgs<'_>,
    deferred: DeferredFlags,
) -> Result<(SummaryLevel, RunSpec), Outcome> {
    let prepared = prepare(args, deferred)?;
    if args.no_follow_children {
        return Err(super::error_outcome(
            exit::GENERAL,
            "not_available",
            "后台记录会话时不支持 --no-follow-children（轮询采样器总是跟随子进程）；请移除此参数或使用 --no-daemon",
            args.json,
        ));
    }
    Ok(prepared)
}

fn prepare(
    args: &RunArgs<'_>,
    deferred: DeferredFlags,
) -> Result<(SummaryLevel, RunSpec), Outcome> {
    let planned = match proxy_plan(args, deferred) {
        Ok(planned) => planned,
        Err(detail) => {
            return Err(super::error_outcome(
                exit::USAGE,
                "usage",
                &detail,
                args.json,
            ));
        }
    };
    // A proxy plan stops here. Printing it and then launching would turn a
    // successful plan into a launch, and this process has no listener. No
    // process is created, which is also what the child-start gap requires.
    if let Some(plan) = &planned {
        let mut stderr = Vec::new();
        if let Err(err) = write_proxy_plan(&mut stderr, plan) {
            return Err(super::error_outcome(
                exit::GENERAL,
                "proxy",
                &err.to_string(),
                args.json,
            ));
        }
        return Err(Outcome {
            code: exit::GENERAL,
            stdout: Vec::new(),
            stderr,
        });
    }
    if let Some(detail) = deferred_reason(deferred) {
        return Err(super::error_outcome(
            exit::GENERAL,
            "not_available",
            &detail,
            args.json,
        ));
    }
    let level = match parse_summary(args.summary) {
        Ok(level) => level,
        Err(detail) => {
            return Err(super::error_outcome(
                exit::USAGE,
                "usage",
                &detail,
                args.json,
            ));
        }
    };
    let env = match split_env(args.env) {
        Ok(pairs) => pairs,
        Err(detail) => {
            return Err(super::error_outcome(
                exit::USAGE,
                "usage",
                &detail,
                args.json,
            ));
        }
    };
    let mut spec = match RunSpec::new(args.command.to_vec()) {
        Ok(spec) => spec,
        Err(err) => {
            return Err(super::error_outcome(
                exit::USAGE,
                "usage",
                &err.to_string(),
                args.json,
            ));
        }
    };
    spec.cwd = args.cwd.map(str::to_owned);
    spec.env = env;
    spec.no_follow_children = args.no_follow_children;
    spec.no_daemon = args.no_daemon;
    Ok((level, spec))
}

/// Whether the pin result is known after a completed run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinState {
    /// The local launcher has no daemon pin operation.
    Unknown,
    /// The daemon acknowledged the pin request.
    Confirmed,
    /// The daemon did not acknowledge the pin request.
    Failed,
}

/// Run the default daemon-backed launch flow.
///
/// The daemon is asked to create a pending session before the child exists.
/// If adoption fails, the caller-created child is killed and reaped so it is
/// never left running outside an observed session.
pub(crate) fn daemon_run(
    args: &RunArgs<'_>,
    deferred: DeferredFlags,
    sessions: &mut dyn DaemonSessions,
    spawner: &mut dyn Spawner,
    summary: &mut dyn SessionSummary,
) -> Outcome {
    let (level, spec) = match daemon_prepare(args, deferred) {
        Ok(prepared) => prepared,
        Err(outcome) => return outcome,
    };
    let request = BeginRunRequest {
        argv: spec.command.clone(),
        cwd: spec.cwd.clone(),
        name: args.name.map(str::to_owned),
        agent: args.agent.map(str::to_owned),
    };
    let launch = match sessions.begin_run(&request) {
        Ok(launch) => launch,
        Err(error) => return daemon_error_outcome(error, args.json, false),
    };
    let mut child = match spawner.spawn(&spec) {
        Ok(child) => child,
        Err(detail) => {
            let _ = sessions.stop_monitoring(&launch.public_id);
            return super::error_outcome(exit::GENERAL, "spawn_failed", &detail, args.json);
        }
    };
    if let Err(error) = sessions.adopt(&launch, child.pid()) {
        child.kill_and_reap();
        return daemon_error_outcome(error, args.json, true);
    }
    if let Err(detail) = child.release() {
        child.kill_and_reap();
        return super::error_outcome(exit::GENERAL, "gate_release_failed", &detail, args.json);
    }

    let (pin_state, pin_warning) = if args.pin {
        match sessions.pin(&launch.public_id) {
            Ok(()) => (PinState::Confirmed, None),
            Err(error) => (
                PinState::Failed,
                Some(format!("[aw] 警告：后台没有保留这个会话：{error}\n")),
            ),
        }
    } else {
        (PinState::Unknown, None)
    };
    let code = match child.wait() {
        Ok(code) => code,
        Err(detail) => {
            return super::error_outcome(exit::GENERAL, "wait_failed", &detail, args.json)
        }
    };
    let exit_warning = sessions
        .record_exit(&launch, code)
        .err()
        .map(|error| format!("[aw] 警告：daemon 未记录程序退出码：{error}\n"));
    if level == SummaryLevel::None || args.quiet {
        let mut stderr = pin_warning.unwrap_or_default();
        if let Some(warning) = exit_warning {
            stderr.push_str(&warning);
        }
        return Outcome {
            code,
            stdout: Vec::new(),
            stderr: stderr.into_bytes(),
        };
    }
    let launched = Launched {
        code,
        pid: child.pid(),
        note: None,
        sampling: false,
    };
    let figures = summary.summarize(Some(&launch.public_id));
    let mut stderr = Vec::new();
    if let Err(error) = write_summary(
        &mut stderr,
        args,
        level,
        &launched,
        &figures,
        Some(&launch.public_id),
        pin_state,
    ) {
        return super::error_outcome(exit::GENERAL, "summary", &error.to_string(), args.json);
    }
    if let Some(warning) = pin_warning {
        stderr.extend_from_slice(warning.as_bytes());
    }
    if let Some(warning) = exit_warning {
        stderr.extend_from_slice(warning.as_bytes());
    }
    Outcome {
        code,
        stdout: Vec::new(),
        stderr,
    }
}

fn daemon_error_outcome(error: ControlError, json: bool, child_stopped: bool) -> Outcome {
    let mut message = error.to_string();
    if child_stopped {
        message.push_str("；后台没有接管程序，已将其结束");
    }
    if error.collector_unavailable() {
        message.push_str("；请在此平台使用 --no-daemon");
    }
    super::error_outcome(error.exit_code(), error.machine_code(), &message, json)
}

/// Why a launch-mode `--proxy` plan has no port.
///
/// `aw run` returns in this process. The daemon session helper
/// `prepare_proxy` only plans an environment for a port the caller already
/// holds, and the daemon runtime has no tokio runtime, so
/// [`aw_proxy::MitmProxy::bind`] cannot run there either. Binding in the CLI
/// would leave a listener whose events nobody reads. The plan therefore
/// records that no port exists.
const PROXY_PORT_UNBOUND: &str = "监听未启动，没有可用端口";

/// One line on stderr. Says the child was not started and nothing on the
/// system was changed. Does not claim the listener is missing from this build.
const PROXY_PLAN_NOTE: &str =
    "子进程启动尚未接入，本次只给出注入计划，没有设置系统代理，没有改证书库";

/// `<session_tmp>` is the directory a later card will pass to
/// [`aw_proxy::write_session_material`]. These are the planned paths only.
const SESSION_CA_PEM: &str = "<session_tmp>/ca.pem";
const SESSION_BUNDLE_PEM: &str = "<session_tmp>/bundle.pem";

/// A launch-mode injection plan. Holds no environment values.
struct ProxyPlan {
    /// Parsed `--proxy-on-reject`. Default `fail` when the flag was absent.
    on_reject: ProxyOnReject,
    /// Names, overwrite marks, and the static hint. Values stay inside.
    injection: Injection,
}

/// Turn a launch-mode `--proxy` into a plan, or refuse the flag.
///
/// `Ok(None)` means the command did not ask for a proxy. `Err` is a usage
/// error: `--proxy-on-reject` without `--proxy`, or a value other than
/// `fail` / `tunnel`. Exit code is [`crate::exit::USAGE`], the same code the
/// other bad arguments of this command use.
///
/// No listener is bound, so the port `plan_injection` writes into its proxy
/// URL is discarded before the plan is kept. [`write_proxy_plan`] prints
/// [`PROXY_PORT_UNBOUND`] and never a loopback URL. `NO_PROXY` still comes from
/// [`plan_injection`]; this function does not rewrite it.
fn proxy_plan(args: &RunArgs<'_>, flags: DeferredFlags) -> Result<Option<ProxyPlan>, String> {
    if !flags.proxy && !flags.proxy_on_reject {
        return Ok(None);
    }
    if flags.proxy_on_reject && !flags.proxy {
        return Err("`--proxy-on-reject` 需要同时指定 `--proxy`".to_owned());
    }
    let on_reject = match flags.proxy_on_reject_value {
        None => ProxyOnReject::Fail,
        Some(text) => ProxyOnReject::parse(text)
            .ok_or_else(|| "`--proxy-on-reject` 只接受 fail 或 tunnel".to_owned())?,
    };
    let exe = args.command.first().map(String::as_str);
    // `plan_injection` takes a port and writes it into the proxy URL. Nothing
    // is listening, so that URL is not a plan this process may keep: drop every
    // value and keep the names, the overwrite marks, and the hint. `NO_PROXY`
    // is still produced by `plan_injection` (appended, not replaced); this
    // function does not build its own value.
    let raw = plan_injection(0, SESSION_CA_PEM, SESSION_BUNDLE_PEM, &[], exe);
    let injection = Injection {
        vars: raw
            .vars
            .into_iter()
            .map(|(name, _value)| (name, String::new()))
            .collect(),
        overwritten: raw.overwritten,
        hints: raw.hints,
    };
    Ok(Some(ProxyPlan {
        on_reject,
        injection,
    }))
}

/// Print the plan. Variable values are not written: [`Injection`]'s `Debug`
/// already lists names only, and this follows that.
fn write_proxy_plan(out: &mut dyn Write, plan: &ProxyPlan) -> io::Result<()> {
    writeln!(out, "[aw] {PROXY_PLAN_NOTE}")?;
    writeln!(
        out,
        "[aw] 代理端口：{PROXY_PORT_UNBOUND}。未绑定的端口不会被印成可用代理"
    )?;
    writeln!(
        out,
        "[aw] --proxy-on-reject {}。CA 计划路径 {SESSION_CA_PEM}，bundle 计划路径 {SESSION_BUNDLE_PEM}。证书库未修改",
        plan.on_reject.as_str()
    )?;
    let names: Vec<&str> = plan
        .injection
        .vars
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    let overwritten: Vec<&str> = plan
        .injection
        .overwritten
        .iter()
        .map(|row| row.name.as_str())
        .collect();
    writeln!(out, "[aw] 注入变量（仅名称）: {}", names.join(", "))?;
    if overwritten.is_empty() {
        writeln!(out, "[aw] 覆盖: 无（调用方没有传入已有环境）")?;
    } else {
        writeln!(out, "[aw] 覆盖: {}", overwritten.join(", "))?;
    }
    writeln!(
        out,
        "[aw] NO_PROXY 由注入计划生成：已有值则追加 localhost,127.0.0.1,::1，否则只写这三项。不在此处另写一套"
    )?;
    for hint in &plan.injection.hints {
        // The hint says the operator must add `--proxy-server` themselves.
        // Nothing here appends it to argv.
        writeln!(out, "[aw] {hint}")?;
    }
    Ok(())
}

fn deferred_reason(flags: DeferredFlags) -> Option<String> {
    // `--mcp-tap` on `aw run` is not a generic missing feature. SPIKE-09 has no
    // verified per-agent MCP config injection, so this process must not rewrite
    // a config and must not launch. The wrapper itself is `aw mcp-tap`.
    if flags.mcp_tap {
        return Some(
            "`aw run` 不支持 --mcp-tap：尚未实现每个 Agent 的 MCP 配置注入（SPIKE-09）；请手动使用 `aw mcp-tap -- <cmd>`。没有启动程序"
                .to_owned(),
        );
    }
    let mut which = Vec::new();
    if flags.self_report {
        which.push("--self-report");
    }
    if flags.unsafe_no_redact {
        which.push("--unsafe-no-redact");
    }
    if flags.include_proc {
        which.push("--include-proc");
    }
    if flags.group {
        which.push("--group");
    }
    if which.is_empty() {
        return None;
    }
    Some(format!(
        "此构建不支持 {}（P3/P5 提供）；没有启动程序",
        which.join(", ")
    ))
}

fn parse_summary(text: Option<&str>) -> Result<SummaryLevel, String> {
    match text {
        None | Some("short") => Ok(SummaryLevel::Short),
        Some("none") => Ok(SummaryLevel::None),
        Some("full") => Ok(SummaryLevel::Full),
        Some(other) => Err(format!("--summary `{other}` 不是 none、short 或 full")),
    }
}

/// Split `KEY=VALUE`. The value is kept for the launcher and never formatted.
fn split_env(raw: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut pairs = Vec::with_capacity(raw.len());
    for item in raw {
        let Some((key, value)) = item.split_once('=') else {
            return Err("--env 条目缺少 `=`；请传入 KEY=VALUE（不会显示值）".to_owned());
        };
        if key.is_empty()
            || key
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
        {
            return Err("--env 名称只能含 ASCII 字母、数字或 `_`".to_owned());
        }
        pairs.push((key.to_owned(), value.to_owned()));
    }
    Ok(pairs)
}

fn mentions_daemon(err: &LaunchDispatchError) -> bool {
    matches!(
        err,
        LaunchDispatchError::Windows(crate::launch::LaunchError::AdoptTimeout)
            | LaunchDispatchError::Windows(crate::launch::LaunchError::AdoptFailed { .. })
            | LaunchDispatchError::Windows(crate::launch::LaunchError::HandleHandoffFailed { .. })
    )
}

fn write_summary(
    out: &mut dyn Write,
    args: &RunArgs<'_>,
    level: SummaryLevel,
    launched: &Launched,
    figures: &Result<Option<Summary>, String>,
    session_id: Option<&str>,
    pin_state: PinState,
) -> io::Result<()> {
    if args.json {
        let body = summary_json(args, launched, figures, session_id, pin_state);
        let mut bytes = serde_json::to_vec(&body)
            .map_err(|err| io::Error::other(format!("编码摘要失败：{err}")))?;
        bytes.push(b'\n');
        // The summary is an `[aw]` side channel. JSON still goes to stderr so the
        // target's own stdout stays untouched.
        return out.write_all(&bytes);
    }
    match figures {
        Ok(Some(summary)) => {
            let processes = if !args.no_daemon && summary.processes == Some(0) {
                "退出太快没采到".to_owned()
            } else {
                count_text(summary.processes)
            };
            let up = bytes_text(summary.bytes_up);
            let down = bytes_text(summary.bytes_down);
            let gaps = count_text(summary.gaps);
            let domains = domain_text(&summary.top_domains);
            let session = session_id
                .or(summary.session_id.as_deref())
                .or(args.name)
                .unwrap_or("未命名");
            writeln!(
                out,
                "[aw] 会话 {session} 结束 · 进程 {processes} · 上传 {up} · 下载 {down} · 前 5 域名 {domains} · 缺口 {gaps}"
            )?;
            // The level note is part of the summary at every level except `none`
            // (api-and-cli §2.1 asks for 等级说明).
            writeln!(out, "[aw] {}", summary.level_note)?;
            if level == SummaryLevel::Full {
                writeln!(
                    out,
                    "[aw] 摘要级别 full · 域名列出前 5 个 · 未知计数显示为不可得，不显示为 0"
                )?;
            }
        }
        Ok(None) => {
            if let Some(session_id) = session_id {
                writeln!(out, "[aw] 会话 {session_id}")?;
            }
            writeln!(
                out,
                "[aw] 摘要不可用 · 本构建没有会话存储，不能用 0 表示未知"
            )?;
        }
        Err(detail) => {
            if let Some(session_id) = session_id {
                writeln!(out, "[aw] 会话 {session_id}")?;
            }
            writeln!(out, "[aw] 摘要不可用 · {detail}")?;
        }
    }
    if args.no_daemon {
        writeln!(
            out,
            "[aw] 已请求采样模式（--no-daemon）；实际采集状态不可得，未经采集器确认"
        )?;
    }
    match (args.pin, pin_state) {
        (true, PinState::Unknown) => {
            writeln!(
                out,
                "[aw] 已请求会话保留（--pin）；本构建未执行保留，保留状态不可得"
            )?;
        }
        (true, PinState::Confirmed) => writeln!(out, "[aw] 会话已标记为保留（--pin）")?,
        (true, PinState::Failed) | (false, _) => {}
    }
    if args.raw.is_some() {
        writeln!(out, "[aw] --raw 已记录为请求；本构建不写原始事件文件")?;
    }
    if let Some(note) = launched.note {
        writeln!(out, "[aw] {note}")?;
    }
    let _ = args.agent;
    Ok(())
}

fn summary_json(
    args: &RunArgs<'_>,
    launched: &Launched,
    figures: &Result<Option<Summary>, String>,
    session_id: Option<&str>,
    pin_state: PinState,
) -> Value {
    let summary = figures.as_ref().ok().and_then(Option::as_ref);
    // Neither the launcher flag nor Summary confirms collector activity or a
    // persisted pin. Keep those results unknown even when figures are present.
    let mut body = json!({
        "available": summary.is_some(),
        "session": session_id.or(summary.and_then(|item| item.session_id.as_deref())),
        "processes": summary.and_then(|item| item.processes),
        "bytes_up": summary.and_then(|item| item.bytes_up),
        "bytes_down": summary.and_then(|item| item.bytes_down),
        "top_domains": summary.map(|item| {
            item.top_domains.iter().take(5).map(|domain| json!({
                "name": domain.name,
                "flows": domain.flows,
            })).collect::<Vec<_>>()
        }),
        "gaps": summary.and_then(|item| item.gaps),
        "level_note": summary.map(|item| item.level_note.as_str()),
        "sampling": null,
        "sampling_reason": "实际采集状态不可得，未经采集器确认",
        "sampling_requested": args.no_daemon,
        "pinned": if pin_state == PinState::Confirmed { Some(true) } else { None },
        "pinned_reason": if pin_state == PinState::Unknown {
            Some("本构建未执行保留，保留状态不可得")
        } else if pin_state == PinState::Failed {
            Some("后台未确认保留状态")
        } else {
            None
        },
        "pin_requested": args.pin,
        "target_exit": launched.code,
        "launch_note": launched.note,
    });
    match figures {
        Ok(Some(_)) => {}
        Ok(None) => body["reason"] = json!("摘要不可用"),
        Err(detail) => body["reason"] = json!(detail),
    }
    if !args.no_daemon && summary.and_then(|item| item.processes) == Some(0) {
        body["processes_note"] = json!("exited_before_sampled");
    }
    body
}

fn count_text(value: Option<u64>) -> String {
    match value {
        Some(count) => count.to_string(),
        None => "不可得".to_owned(),
    }
}

fn bytes_text(value: Option<u64>) -> String {
    match value {
        Some(count) => count.to_string(),
        None => "不可得".to_owned(),
    }
}

fn domain_text(domains: &[DomainCount]) -> String {
    if domains.is_empty() {
        return "不可得".to_owned();
    }
    domains
        .iter()
        .take(5)
        .map(|item| format!("{} ({})", item.name, item.flows))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A [`UnixLauncher`] seen as a [`Launcher`], so a test fake can sit behind
/// either trait. Not used on the production Windows path.
pub(crate) struct UnixAdapter<T>(pub T);

impl<T: UnixLauncher> Launcher for UnixAdapter<T> {
    fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
        launch::dispatch_unix(&mut self.0, spec)
    }

    fn forward_interrupt(&mut self, pid: u32) -> Result<(), LaunchDispatchError> {
        self.0.forward_interrupt(pid)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::{
        daemon_run, run, DeferredFlags, DomainCount, EmptySummary, RunArgs, SessionSummary,
        SpawnedChild, Spawner, Summary, UnixAdapter,
    };
    use crate::cmd::attach::{
        AttachRequest, BeginRunRequest, ControlError, DaemonSessions, LaunchSession, SessionHandle,
    };
    use crate::exit;
    use crate::launch::{LaunchDispatchError, Launched, RunSpec, UnixLauncher};

    struct FakeLaunch {
        code: i32,
        sampling_seen: Option<bool>,
        forwarded: Vec<u32>,
        env_len: Option<usize>,
        fail: Option<LaunchDispatchError>,
    }

    impl UnixLauncher for FakeLaunch {
        fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
            self.sampling_seen = Some(spec.no_daemon);
            self.env_len = Some(spec.env.len());
            if let Some(err) = self.fail.clone() {
                return Err(err);
            }
            Ok(Launched {
                code: self.code,
                pid: 42,
                note: None,
                sampling: spec.no_daemon,
            })
        }

        fn forward_interrupt(&mut self, pid: u32) -> Result<(), LaunchDispatchError> {
            self.forwarded.push(pid);
            Ok(())
        }
    }

    struct FixedSummary(Option<Summary>);

    impl SessionSummary for FixedSummary {
        fn summarize(&mut self, _: Option<&str>) -> Result<Option<Summary>, String> {
            Ok(self.0.clone())
        }
    }

    struct FailedSummary {
        calls: usize,
    }

    struct FakeChild {
        pid: u32,
        code: i32,
        log: Rc<RefCell<Vec<&'static str>>>,
    }

    impl SpawnedChild for FakeChild {
        fn pid(&self) -> u32 {
            self.pid
        }

        fn wait(&mut self) -> Result<i32, String> {
            self.log.borrow_mut().push("wait");
            Ok(self.code)
        }

        fn release(&mut self) -> Result<(), String> {
            self.log.borrow_mut().push("release");
            Ok(())
        }

        fn kill_and_reap(&mut self) {
            self.log.borrow_mut().push("kill");
        }
    }

    struct FakeSpawner {
        log: Rc<RefCell<Vec<&'static str>>>,
        spawned: usize,
        code: i32,
        fail: Option<String>,
    }

    impl Spawner for FakeSpawner {
        fn spawn(&mut self, _: &RunSpec) -> Result<Box<dyn SpawnedChild>, String> {
            self.spawned = self.spawned.saturating_add(1);
            self.log.borrow_mut().push("spawn");
            if let Some(error) = self.fail.take() {
                return Err(error);
            }
            Ok(Box::new(FakeChild {
                pid: 71,
                code: self.code,
                log: Rc::clone(&self.log),
            }))
        }
    }

    struct FakeSessions {
        log: Rc<RefCell<Vec<&'static str>>>,
        begin: Option<ControlError>,
        adopt: Option<ControlError>,
        exit: Option<ControlError>,
        seen_begin: Option<BeginRunRequest>,
        stops: Vec<String>,
    }

    impl FakeSessions {
        fn new(log: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self {
                log,
                begin: None,
                adopt: None,
                exit: None,
                seen_begin: None,
                stops: Vec::new(),
            }
        }
    }

    impl DaemonSessions for FakeSessions {
        fn begin_run(&mut self, request: &BeginRunRequest) -> Result<LaunchSession, ControlError> {
            self.log.borrow_mut().push("begin");
            self.seen_begin = Some(request.clone());
            match self.begin.take() {
                Some(error) => Err(error),
                None => Ok(LaunchSession {
                    public_id: "s-daemon".to_owned(),
                    ticket: "ticket".to_owned(),
                }),
            }
        }

        fn adopt(&mut self, _: &LaunchSession, _: u32) -> Result<(), ControlError> {
            self.log.borrow_mut().push("adopt");
            match self.adopt.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        fn record_exit(&mut self, _: &LaunchSession, _: i32) -> Result<(), ControlError> {
            self.log.borrow_mut().push("exit");
            match self.exit.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        fn attach(&mut self, _: &AttachRequest) -> Result<SessionHandle, ControlError> {
            Err(ControlError::BadReply {
                detail: "run test must not attach".to_owned(),
            })
        }

        fn stop_monitoring(&mut self, session: &str) -> Result<String, ControlError> {
            self.stops.push(session.to_owned());
            Ok(session.to_owned())
        }

        fn pin(&mut self, _: &str) -> Result<(), ControlError> {
            self.log.borrow_mut().push("pin");
            Ok(())
        }
    }

    impl SessionSummary for FailedSummary {
        fn summarize(&mut self, _: Option<&str>) -> Result<Option<Summary>, String> {
            self.calls += 1;
            Err("摘要源不可用".to_owned())
        }
    }

    fn fake_exit_7() -> FakeLaunch {
        FakeLaunch {
            code: 7,
            sampling_seen: None,
            forwarded: Vec::new(),
            env_len: None,
            fail: None,
        }
    }

    fn assert_unknown_json(body: &serde_json::Value, pin: bool, no_daemon: bool) {
        for field in ["sampling", "pinned"] {
            assert_eq!(body.get(field), Some(&serde_json::Value::Null), "{field}");
        }
        assert_eq!(body["pin_requested"], pin);
        assert_eq!(body["sampling_requested"], no_daemon);
        assert_eq!(body["target_exit"], 7);
        assert_eq!(
            body["sampling_reason"],
            "实际采集状态不可得，未经采集器确认"
        );
        assert_eq!(body["pinned_reason"], "本构建未执行保留，保留状态不可得");
    }

    fn assert_unavailable_json(body: &serde_json::Value) {
        assert_eq!(body["available"], false);
        for field in [
            "session",
            "processes",
            "bytes_up",
            "bytes_down",
            "top_domains",
            "gaps",
            "level_note",
        ] {
            assert_eq!(body.get(field), Some(&serde_json::Value::Null), "{field}");
        }
    }

    fn args<'a>(command: &'a [String]) -> RunArgs<'a> {
        RunArgs {
            agent: None,
            name: None,
            no_follow_children: false,
            cwd: None,
            env: &[],
            summary: None,
            pin: false,
            no_daemon: false,
            raw: None,
            command,
            json: false,
            quiet: false,
        }
    }

    fn none() -> DeferredFlags<'static> {
        DeferredFlags {
            proxy: false,
            proxy_on_reject: false,
            proxy_on_reject_value: None,
            self_report: false,
            mcp_tap: false,
            unsafe_no_redact: false,
            include_proc: false,
            group: false,
        }
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    #[test]
    fn target_exit_code_is_forwarded() {
        let command = vec!["tool".to_owned()];
        let mut launcher = FakeLaunch {
            code: 7,
            sampling_seen: None,
            forwarded: Vec::new(),
            env_len: None,
            fail: None,
        };
        let mut summary = FixedSummary(Some(sample_summary()));
        let outcome = run(
            &args(&command),
            none(),
            &mut UnixAdapter(&mut launcher),
            &mut summary,
        );
        assert_eq!(outcome.code, 7);
        let err = text(&outcome.stderr);
        assert!(err.contains("进程 3"), "{err}");
        assert!(err.contains("上传 10"), "{err}");
        assert!(err.contains("下载 20"), "{err}");
        assert!(err.contains("example.test (2)"), "{err}");
        assert!(err.contains("缺口 1"), "{err}");
        assert!(err.contains("E1 系统"), "{err}");
        assert!(!err.contains("上传了"), "{err}");
    }

    #[test]
    fn daemon_zero_process_summary_says_it_exited_before_sampling() {
        let command = vec!["tool".to_owned()];
        let zero = Summary {
            session_id: Some("s-fast".to_owned()),
            processes: Some(0),
            bytes_up: Some(0),
            bytes_down: Some(0),
            top_domains: Vec::new(),
            gaps: Some(0),
            level_note: "证据 S".to_owned(),
        };
        let mut launcher = fake_exit_7();
        let outcome = run(
            &args(&command),
            none(),
            &mut UnixAdapter(&mut launcher),
            &mut FixedSummary(Some(zero.clone())),
        );
        let text = text(&outcome.stderr);
        assert!(text.contains("进程 退出太快没采到"), "{text}");
        assert!(!text.contains("进程 0"), "{text}");

        let mut json_args = args(&command);
        json_args.json = true;
        let mut launcher = fake_exit_7();
        let outcome = run(
            &json_args,
            none(),
            &mut UnixAdapter(&mut launcher),
            &mut FixedSummary(Some(zero)),
        );
        let body: serde_json::Value =
            serde_json::from_slice(&outcome.stderr).expect("JSON summary");
        assert_eq!(body["processes"], 0);
        assert_eq!(body["processes_note"], "exited_before_sampled");
    }

    #[test]
    fn unavailable_summary_is_not_zero() {
        let command = vec!["tool".to_owned()];
        let mut launcher = FakeLaunch {
            code: 0,
            sampling_seen: None,
            forwarded: Vec::new(),
            env_len: None,
            fail: None,
        };
        let mut summary = EmptySummary;
        let outcome = run(
            &args(&command),
            none(),
            &mut UnixAdapter(&mut launcher),
            &mut summary,
        );
        assert_eq!(outcome.code, exit::OK);
        let err = text(&outcome.stderr);
        assert!(err.contains("摘要不可用"), "{err}");
        assert!(!err.contains("进程 0"), "{err}");
        assert!(!err.contains("缺口 0"), "{err}");
    }

    #[test]
    fn unknown_counts_inside_a_summary_say_unavailable() {
        let command = vec!["tool".to_owned()];
        let mut launcher = FakeLaunch {
            code: 0,
            sampling_seen: None,
            forwarded: Vec::new(),
            env_len: None,
            fail: None,
        };
        let mut summary = FixedSummary(Some(Summary {
            session_id: Some("s-1".to_owned()),
            processes: None,
            bytes_up: None,
            bytes_down: None,
            top_domains: Vec::new(),
            gaps: None,
            level_note: "等级不可得".to_owned(),
        }));
        let outcome = run(
            &args(&command),
            none(),
            &mut UnixAdapter(&mut launcher),
            &mut summary,
        );
        let err = text(&outcome.stderr);
        assert!(err.contains("进程 不可得"), "{err}");
        assert!(err.contains("上传 不可得"), "{err}");
        assert!(err.contains("前 5 域名 不可得"), "{err}");
        assert!(err.contains("缺口 不可得"), "{err}");
        assert!(!err.contains("进程 0"), "{err}");
    }

    #[test]
    fn proxy_flag_points_at_later_cards_and_does_not_launch() {
        let command = vec!["tool".to_owned()];
        let mut launcher = FakeLaunch {
            code: 7,
            sampling_seen: None,
            forwarded: Vec::new(),
            env_len: None,
            fail: None,
        };
        let mut flags = none();
        flags.proxy = true;
        let mut summary = EmptySummary;
        let outcome = run(
            &args(&command),
            flags,
            &mut UnixAdapter(&mut launcher),
            &mut summary,
        );
        assert_eq!(outcome.code, exit::GENERAL);
        let err = text(&outcome.stderr);
        assert!(err.contains("注入计划"), "{err}");
        assert!(err.contains("监听未启动"), "{err}");
        assert!(!err.contains("127.0.0.1:0"), "{err}");
        assert!(!err.contains("not available in this build"), "{err}");
        assert!(launcher.sampling_seen.is_none(), "launcher must not run");
    }

    #[test]
    fn sensitive_inputs_never_appear_in_summary_output() {
        let command = vec!["private-tool".to_owned(), "--secret".to_owned()];
        let env = vec!["TOKEN=super-secret-value".to_owned()];
        for json in [false, true] {
            let mut ran = args(&command);
            ran.env = &env;
            ran.cwd = Some("/private/cwd-marker");
            ran.raw = Some("/private/raw-marker");
            ran.pin = true;
            ran.no_daemon = true;
            ran.json = json;
            let mut empty = EmptySummary;
            let mut fixed = FixedSummary(Some(sample_summary()));
            let mut failed = FailedSummary { calls: 0 };
            let sources: [&mut dyn SessionSummary; 3] = [&mut empty, &mut fixed, &mut failed];
            for summary in sources {
                let mut launcher = fake_exit_7();
                let outcome = run(&ran, none(), &mut UnixAdapter(&mut launcher), summary);
                assert_eq!(outcome.code, 7);
                assert!(outcome.stdout.is_empty());
                let err = text(&outcome.stderr);
                for marker in [
                    "private-tool",
                    "--secret",
                    "super-secret-value",
                    "TOKEN",
                    "cwd-marker",
                    "raw-marker",
                ] {
                    assert!(!err.contains(marker), "input marker appeared: {marker}");
                }
                assert_eq!(launcher.env_len, Some(1));
            }
        }
    }

    #[test]
    fn requests_do_not_override_fixed_summary_evidence_or_confirm_a_pin() {
        let command = vec!["tool".to_owned()];
        for json in [false, true] {
            let mut ran = args(&command);
            ran.no_daemon = true;
            ran.pin = true;
            ran.summary = Some("full");
            ran.json = json;
            let mut launcher = fake_exit_7();
            let mut summary = FixedSummary(Some(sample_summary()));
            let outcome = run(&ran, none(), &mut UnixAdapter(&mut launcher), &mut summary);
            assert_eq!(outcome.code, 7);
            assert!(outcome.stdout.is_empty());
            assert_eq!(launcher.sampling_seen, Some(true));
            let err = text(&outcome.stderr);
            if json {
                let body: serde_json::Value = serde_json::from_str(&err).expect("json summary");
                assert_unknown_json(&body, true, true);
                assert_eq!(body["available"], true);
                assert_eq!(body["level_note"], sample_summary().level_note);
                assert_eq!(body["processes"], 3);
                assert_eq!(body["bytes_up"], 10);
                assert_eq!(body["bytes_down"], 20);
                assert_eq!(body["gaps"], 1);
                assert_eq!(body["top_domains"][0]["name"], "example.test");
                assert_eq!(body["top_domains"][0]["flows"], 2);
            } else {
                assert!(err.contains("已请求采样模式（--no-daemon）"), "{err}");
                assert!(err.contains("实际采集状态不可得"), "{err}");
                assert!(err.contains("已请求会话保留（--pin）"), "{err}");
                assert!(err.contains("保留状态不可得"), "{err}");
                assert!(err.contains(&sample_summary().level_note), "{err}");
                assert!(!err.contains("等级 S"), "{err}");
                assert!(!err.contains("会话已标记为保留"), "{err}");
            }
        }
    }

    #[test]
    fn empty_summary_keeps_pin_and_sampling_unknown() {
        let command = vec!["tool".to_owned()];
        for pin in [false, true] {
            for no_daemon in [false, true] {
                for json in [false, true] {
                    let mut ran = args(&command);
                    ran.pin = pin;
                    ran.no_daemon = no_daemon;
                    ran.json = json;
                    let mut launcher = fake_exit_7();
                    let outcome = run(
                        &ran,
                        none(),
                        &mut UnixAdapter(&mut launcher),
                        &mut EmptySummary,
                    );
                    assert_eq!(outcome.code, 7);
                    assert!(outcome.stdout.is_empty());
                    assert_eq!(launcher.sampling_seen, Some(no_daemon));
                    let err = text(&outcome.stderr);
                    if json {
                        let body: serde_json::Value =
                            serde_json::from_str(&err).expect("json summary");
                        assert_unknown_json(&body, pin, no_daemon);
                        assert_unavailable_json(&body);
                        assert_eq!(body["reason"], "摘要不可用");
                    } else {
                        assert!(err.contains("摘要不可用"), "{err}");
                        assert_eq!(err.contains("已请求会话保留"), pin, "{err}");
                        assert_eq!(err.contains("已请求采样模式"), no_daemon, "{err}");
                        assert!(!err.contains("会话已标记为保留"), "{err}");
                        assert!(!err.contains("等级 S"), "{err}");
                        assert!(!err.contains("进程 0"), "{err}");
                        assert!(!err.contains("缺口 0"), "{err}");
                    }
                }
            }
        }
    }

    #[test]
    fn summary_failure_keeps_target_exit_and_unknown_results() {
        let command = vec!["tool".to_owned()];
        for json in [false, true] {
            let mut ran = args(&command);
            ran.pin = true;
            ran.no_daemon = true;
            ran.json = json;
            let mut launcher = fake_exit_7();
            let mut summary = FailedSummary { calls: 0 };
            let outcome = run(&ran, none(), &mut UnixAdapter(&mut launcher), &mut summary);
            assert_eq!(outcome.code, 7);
            assert!(outcome.stdout.is_empty());
            assert_eq!(summary.calls, 1);
            let err = text(&outcome.stderr);
            if json {
                let body: serde_json::Value = serde_json::from_str(&err).expect("json summary");
                assert_unknown_json(&body, true, true);
                assert_unavailable_json(&body);
                assert_eq!(body["reason"], "摘要源不可用");
            } else {
                assert!(err.contains("摘要不可用 · 摘要源不可用"), "{err}");
                assert!(err.contains("保留状态不可得"), "{err}");
                assert!(err.contains("实际采集状态不可得"), "{err}");
                assert!(!err.contains("会话已标记为保留"), "{err}");
                assert!(!err.contains("等级 S"), "{err}");
            }
        }
    }

    #[test]
    fn quiet_or_summary_none_skips_requests_and_summary_source() {
        let command = vec!["tool".to_owned()];
        for json in [false, true] {
            for (quiet, level) in [(true, Some("full")), (false, Some("none"))] {
                let mut ran = args(&command);
                ran.pin = true;
                ran.no_daemon = true;
                ran.json = json;
                ran.quiet = quiet;
                ran.summary = level;
                let mut launcher = fake_exit_7();
                let mut summary = FailedSummary { calls: 0 };
                let outcome = run(&ran, none(), &mut UnixAdapter(&mut launcher), &mut summary);
                assert_eq!(outcome.code, 7);
                assert!(outcome.stdout.is_empty());
                assert!(outcome.stderr.is_empty());
                assert_eq!(summary.calls, 0);
                assert_eq!(launcher.sampling_seen, Some(true));
            }
        }
    }

    #[test]
    fn json_unknown_counts_are_null_and_domain_array_is_preserved() {
        let command = vec!["tool".to_owned()];
        let mut ran = args(&command);
        ran.json = true;
        let mut launcher = fake_exit_7();
        let mut summary = FixedSummary(Some(Summary {
            session_id: None,
            processes: None,
            bytes_up: None,
            bytes_down: None,
            top_domains: Vec::new(),
            gaps: None,
            level_note: "等级不可得".to_owned(),
        }));
        let outcome = run(&ran, none(), &mut UnixAdapter(&mut launcher), &mut summary);
        assert_eq!(outcome.code, 7);
        let body: serde_json::Value =
            serde_json::from_slice(&outcome.stderr).expect("json summary");
        assert_unknown_json(&body, false, false);
        assert_eq!(body["available"], true);
        assert_eq!(body["level_note"], "等级不可得");
        assert_eq!(body["top_domains"], serde_json::json!([]));
        for field in ["session", "processes", "bytes_up", "bytes_down", "gaps"] {
            assert_eq!(body.get(field), Some(&serde_json::Value::Null), "{field}");
        }
    }

    #[test]
    fn interrupt_is_a_launcher_call() {
        let mut launcher = FakeLaunch {
            code: 0,
            sampling_seen: None,
            forwarded: Vec::new(),
            env_len: None,
            fail: None,
        };
        UnixLauncher::forward_interrupt(&mut launcher, 42).expect("forward");
        assert_eq!(launcher.forwarded, vec![42]);
    }

    #[test]
    fn daemon_run_holds_then_adopts_releases_and_waits_without_sending_env() {
        let command = vec!["tool".to_owned(), "argument".to_owned()];
        let env = vec!["TOKEN=super-secret-value".to_owned()];
        let mut parsed = args(&command);
        parsed.env = &env;
        parsed.cwd = Some("/work");
        parsed.name = Some("session-name");
        parsed.agent = Some("agent-a");
        parsed.pin = true;
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut sessions = FakeSessions::new(Rc::clone(&log));
        let mut spawner = FakeSpawner {
            log: Rc::clone(&log),
            spawned: 0,
            code: 7,
            fail: None,
        };
        let outcome = daemon_run(
            &parsed,
            none(),
            &mut sessions,
            &mut spawner,
            &mut EmptySummary,
        );
        assert_eq!(outcome.code, 7);
        assert_eq!(
            *log.borrow(),
            vec!["begin", "spawn", "adopt", "release", "pin", "wait", "exit"]
        );
        let request = sessions.seen_begin.expect("begin request");
        assert_eq!(request.argv, command);
        assert_eq!(request.cwd.as_deref(), Some("/work"));
        assert_eq!(request.name.as_deref(), Some("session-name"));
        assert_eq!(request.agent.as_deref(), Some("agent-a"));
        assert!(!format!("{request:?}").contains("super-secret-value"));
        let text = text(&outcome.stderr);
        assert!(text.contains("会话 s-daemon"), "{text}");
    }

    #[test]
    fn adopt_failure_kills_and_reaps_the_child() {
        let command = vec!["tool".to_owned()];
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut sessions = FakeSessions::new(Rc::clone(&log));
        sessions.adopt = Some(ControlError::Status {
            status: 410,
            code: None,
            message: "adopt_timeout".to_owned(),
        });
        let mut spawner = FakeSpawner {
            log: Rc::clone(&log),
            spawned: 0,
            code: 0,
            fail: None,
        };
        let mut parsed = args(&command);
        parsed.json = true;
        let outcome = daemon_run(
            &parsed,
            none(),
            &mut sessions,
            &mut spawner,
            &mut EmptySummary,
        );
        assert_eq!(outcome.code, exit::USAGE);
        assert_eq!(*log.borrow(), vec!["begin", "spawn", "adopt", "kill"]);
        assert!(text(&outcome.stderr).contains("后台没有接管程序，已将其结束"));
    }

    #[test]
    fn exit_code_report_failure_is_a_warning_and_keeps_the_target_status() {
        let command = vec!["tool".to_owned()];
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut sessions = FakeSessions::new(Rc::clone(&log));
        sessions.exit = Some(ControlError::Unreachable {
            detail: "down".to_owned(),
        });
        let mut spawner = FakeSpawner {
            log: Rc::clone(&log),
            spawned: 0,
            code: 7,
            fail: None,
        };
        let mut parsed = args(&command);
        parsed.summary = Some("none");
        let outcome = daemon_run(
            &parsed,
            none(),
            &mut sessions,
            &mut spawner,
            &mut EmptySummary,
        );
        assert_eq!(outcome.code, 7);
        assert!(text(&outcome.stderr).contains("未记录程序退出码"));
        assert_eq!(
            *log.borrow(),
            vec!["begin", "spawn", "adopt", "release", "wait", "exit"]
        );
    }

    #[test]
    fn unreachable_begin_does_not_spawn() {
        let command = vec!["tool".to_owned()];
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut sessions = FakeSessions::new(Rc::clone(&log));
        sessions.begin = Some(ControlError::Unreachable {
            detail: "down".to_owned(),
        });
        let mut spawner = FakeSpawner {
            log: Rc::clone(&log),
            spawned: 0,
            code: 0,
            fail: None,
        };
        let outcome = daemon_run(
            &args(&command),
            none(),
            &mut sessions,
            &mut spawner,
            &mut EmptySummary,
        );
        assert_eq!(outcome.code, exit::UNREACHABLE);
        assert_eq!(spawner.spawned, 0);
        assert_eq!(*log.borrow(), vec!["begin"]);
    }

    /// Forced fallback: the cgroup attempt fails the way this box does
    /// ("no delegated controllers"); a real child must still run and its exit
    /// code come back, with the missing capability named.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_without_delegation_really_runs_the_child_by_process_tree() {
        let command = vec!["sh".to_owned(), "-c".to_owned(), "exit 4".to_owned()];
        let mut spec = RunSpec::new(command).expect("spec");
        spec.no_daemon = true;
        let mut attempts = 0;
        let launched = super::launch_linux(&spec, &mut |_, _, _, _| {
            attempts += 1;
            Err(crate::launch::LinuxLaunchError::CreateFailed {
                detail: "cgroup mkdir: /sys/fs/cgroup/agent/cgroup.subtree_control has no delegated controllers".to_owned(),
            })
        })
        .expect("fallback launch");
        assert_eq!(attempts, 1);
        assert_eq!(launched.code, 4, "real child exit code");
        assert!(launched.pid > 0);
        assert_eq!(launched.note, Some(super::PID_TREE_FALLBACK_NOTE));
    }

    /// The fallback decision: only pre-spawn cgroup failures fall back.
    #[cfg(target_os = "linux")]
    #[test]
    fn only_pre_spawn_cgroup_failures_fall_back() {
        use crate::launch::LinuxLaunchError as E;
        assert!(super::cgroup_fallback_allowed(&E::CgroupV1NoLaunch));
        assert!(super::cgroup_fallback_allowed(&E::CreateFailed {
            detail: "no delegated controllers".to_owned()
        }));
        for after in [
            E::ForkFailed {
                detail: "x".to_owned(),
            },
            E::WriteProcsFailed {
                detail: "x".to_owned(),
            },
            E::WaitFailed {
                detail: "x".to_owned(),
            },
        ] {
            assert!(!super::cgroup_fallback_allowed(&after), "{after}");
        }
        // A failure after the child started is reported, not retried.
        let spec = RunSpec::new(vec!["true".to_owned()]).expect("spec");
        let err = super::launch_linux(&spec, &mut |_, _, _, _| {
            Err(E::WriteProcsFailed {
                detail: "denied".to_owned(),
            })
        })
        .expect_err("no fallback");
        assert!(err.to_string().contains("cgroup.procs"), "{err}");
    }

    /// The production launcher on this machine: really spawns, and the note
    /// says which path it took. Without delegation (CI runners, this box) it
    /// must be the process-tree fallback, never an error.
    #[cfg(target_os = "linux")]
    #[test]
    fn production_linux_launcher_runs_with_or_without_delegation() {
        use super::Launcher;
        let mut spec = RunSpec::new(vec!["sh".to_owned(), "-c".to_owned(), "exit 6".to_owned()])
            .expect("spec");
        spec.no_daemon = true;
        let launched = super::PlatformLauncher.launch(&spec).expect("launch");
        assert_eq!(launched.code, 6);
        assert!(
            launched.note == Some(super::PID_TREE_FALLBACK_NOTE)
                || launched.note == Some(super::POST_SPAWN_MOVE_NOTE),
            "{:?}",
            launched.note
        );
    }

    #[test]
    fn no_follow_children_is_refused_before_the_daemon_is_asked() {
        let command = vec!["tool".to_owned()];
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut sessions = FakeSessions::new(Rc::clone(&log));
        let mut spawner = FakeSpawner {
            log: Rc::clone(&log),
            spawned: 0,
            code: 0,
            fail: None,
        };
        let mut ran = args(&command);
        ran.no_follow_children = true;
        let outcome = daemon_run(&ran, none(), &mut sessions, &mut spawner, &mut EmptySummary);
        assert_eq!(outcome.code, exit::GENERAL);
        assert!(text(&outcome.stderr).contains("--no-follow-children"));
        assert!(log.borrow().is_empty(), "no daemon call, no spawn");
    }

    /// The production spawner really starts the program as this user, applies
    /// `--env` only to the child, adopts its real pid, and forwards its exit code.
    #[cfg(unix)]
    #[test]
    fn command_spawner_runs_a_real_child_and_forwards_its_exit_code() {
        let command = vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "exit \"$AW_TEST_CODE\"".to_owned(),
        ];
        let env = vec!["AW_TEST_CODE=5".to_owned()];
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut sessions = FakeSessions::new(Rc::clone(&log));
        let mut ran = args(&command);
        ran.env = &env;
        let outcome = daemon_run(
            &ran,
            none(),
            &mut sessions,
            &mut super::CommandSpawner,
            &mut EmptySummary,
        );
        assert_eq!(outcome.code, 5, "{}", text(&outcome.stderr));
        assert_eq!(*log.borrow(), vec!["begin", "adopt", "exit"]);
        let begin = sessions.seen_begin.expect("begin request");
        assert_eq!(begin.argv, command);
        assert!(text(&outcome.stderr).contains("s-daemon"));
    }

    #[cfg(unix)]
    #[test]
    fn command_spawner_pipe_gate_holds_the_target_until_release() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let dir = std::env::temp_dir().join(format!(
            "aw-cli-gate-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("test directory");
        let marker = dir.join("target-ran");
        let command = vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "printf ran > \"$1\"".to_owned(),
            "aw-gate-test".to_owned(),
            marker.to_string_lossy().into_owned(),
        ];
        let spec = RunSpec::new(command).expect("run spec");
        let mut child = super::CommandSpawner.spawn(&spec).expect("held child");
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(
            !marker.exists(),
            "the target ran before daemon adoption released its gate"
        );
        child.release().expect("release gate");
        assert_eq!(child.wait().expect("wait target"), 0);
        assert!(marker.is_file(), "the target did not run after release");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collector_unavailable_suggests_the_local_mode_without_spawning() {
        let command = vec!["tool".to_owned()];
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut sessions = FakeSessions::new(Rc::clone(&log));
        sessions.begin = Some(ControlError::Status {
            status: 503,
            code: Some("collector_unavailable".to_owned()),
            message: "collector unavailable".to_owned(),
        });
        let mut spawner = FakeSpawner {
            log,
            spawned: 0,
            code: 0,
            fail: None,
        };
        let outcome = daemon_run(
            &args(&command),
            none(),
            &mut sessions,
            &mut spawner,
            &mut EmptySummary,
        );
        assert_eq!(outcome.code, exit::GENERAL);
        assert_eq!(spawner.spawned, 0);
        assert!(text(&outcome.stderr).contains("请在此平台使用 --no-daemon"));
    }

    #[test]
    fn spawn_errors_are_plain_chinese_by_kind() {
        use std::io::{Error, ErrorKind};
        let not_found = super::spawn_error_text(&Error::from(ErrorKind::NotFound));
        assert!(not_found.contains("找不到") && not_found.contains("program_not_found"));
        let denied = super::spawn_error_text(&Error::from(ErrorKind::PermissionDenied));
        assert!(denied.contains("没有权限") && denied.contains("program_not_permitted"));
        let other = super::spawn_error_text(&Error::from_raw_os_error(7));
        assert!(
            other.contains("spawn_failed") && other.contains("系统错误码 7"),
            "{other}"
        );
        let wait = super::wait_error_text(&Error::from(ErrorKind::Other));
        assert!(wait.starts_with("等待程序结束失败"), "{wait}");
        for text in [not_found, denied, other, wait] {
            assert!(
                !text.contains("entity") && !text.contains("could not"),
                "{text}"
            );
        }
    }

    #[test]
    fn spawn_failure_stops_the_pending_session_without_printing_argv() {
        let command = vec!["private-tool".to_owned(), "--secret".to_owned()];
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut sessions = FakeSessions::new(Rc::clone(&log));
        let mut spawner = FakeSpawner {
            log: Rc::clone(&log),
            spawned: 0,
            code: 0,
            fail: Some(super::spawn_error_text(&std::io::Error::from(
                std::io::ErrorKind::NotFound,
            ))),
        };
        let mut parsed = args(&command);
        parsed.json = true;
        let outcome = daemon_run(
            &parsed,
            none(),
            &mut sessions,
            &mut spawner,
            &mut EmptySummary,
        );
        assert_eq!(outcome.code, exit::GENERAL);
        assert_eq!(sessions.stops, vec!["s-daemon".to_owned()]);
        let text = text(&outcome.stderr);
        let body: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert_eq!(body["error"]["code"], "spawn_failed");
        assert!(!text.contains("private-tool"), "{text}");
        assert!(!text.contains("--secret"), "{text}");
    }

    #[test]
    fn daemon_json_summary_keeps_the_real_session_id() {
        let command = vec!["tool".to_owned()];
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut sessions = FakeSessions::new(Rc::clone(&log));
        let mut spawner = FakeSpawner {
            log,
            spawned: 0,
            code: 0,
            fail: None,
        };
        let mut parsed = args(&command);
        parsed.json = true;
        let outcome = daemon_run(
            &parsed,
            none(),
            &mut sessions,
            &mut spawner,
            &mut EmptySummary,
        );
        let body: serde_json::Value = serde_json::from_slice(&outcome.stderr).expect("json");
        assert_eq!(body["session"], "s-daemon");
    }

    #[test]
    fn no_daemon_uses_the_local_launcher_without_a_daemon_call() {
        let command = vec!["tool".to_owned()];
        let log = Rc::new(RefCell::new(Vec::new()));
        let sessions = FakeSessions::new(log);
        let mut launcher = fake_exit_7();
        let mut parsed = args(&command);
        parsed.no_daemon = true;
        let outcome = run(
            &parsed,
            none(),
            &mut UnixAdapter(&mut launcher),
            &mut EmptySummary,
        );
        assert_eq!(outcome.code, 7);
        assert!(sessions.seen_begin.is_none());
        assert!(sessions.stops.is_empty());
    }

    fn sample_summary() -> Summary {
        Summary {
            session_id: Some("s-test".to_owned()),
            processes: Some(3),
            bytes_up: Some(10),
            bytes_down: Some(20),
            top_domains: vec![DomainCount {
                name: "example.test".to_owned(),
                flows: 2,
            }],
            gaps: Some(1),
            level_note: "等级 E1 系统 · 来自注入的摘要，不是对目标行为的断定".to_owned(),
        }
    }
}
