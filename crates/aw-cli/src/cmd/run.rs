//! `aw run` (P1-CLI-02).
//!
//! `--no-daemon` starts the target as the calling user through an injected
//! [`Launcher`], then prints a session summary. The default daemon path first
//! records `/sessions/run`, starts the child held (Linux and macOS through
//! `aw-platform`'s suspended spawn, Windows through `aw-platform`'s suspended
//! Job), and hands it over through `/adopt` before releasing it. On Windows
//! `aw-platform` owns the suspended Job and process handles; release returns
//! the sole reap handle. On macOS the suspended start lives in `aw-platform`
//! and has not been run on a real Mac. On Linux [`launch::LocalCgroupHost`]
//! places the child in a delegated
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

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use aw_platform::PlatformError;
#[cfg(windows)]
use aw_platform::ReapOutcome;
#[cfg(any(target_os = "linux", windows))]
use aw_platform::{platform, HeldChild, IdentifiedCaller, ReleasedChild, SpawnRequest};
use aw_proxy::{plan_injection, Injection, ProxyOnReject};
use std::io::{self, Write};
#[cfg(not(any(unix, windows)))]
use std::process::{Child, Command};

use serde_json::{json, Value};

use crate::exit;
use crate::launch::{self, LaunchDispatchError, Launched, RunSpec, UnixLauncher};

use super::attach::{
    user_locale_env, BeginRunRequest, CleanupLeftovers, ControlError, DaemonSessions,
};
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
    /// `--intercept`. Writes a temp Claude Code settings file for this launch.
    pub intercept: bool,
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

    /// Release a child held until the daemon accepted `/adopt`: the Unix pipe
    /// gate lets it `exec`, while Windows resumes its primary thread.
    ///
    /// # Errors
    ///
    /// The launch gate could not be released. The machine code distinguishes
    /// a target/cwd error from a broken gate; the caller must reap any child it
    /// still owns.
    fn release(&mut self) -> Result<(), (&'static str, String)>;

    /// Stop and reap a child that the daemon refused to adopt.
    fn kill_and_reap(&mut self);

    /// Remaining descendants reported by a bounded supervisor cleanup.  The
    /// default has no report because a child that was fully cleaned up must
    /// not be represented by a made-up zero.
    fn cleanup_leftovers(&mut self) -> Option<CleanupLeftovers> {
        None
    }
}

/// Spawn a child for the default daemon-backed `aw run` path.
pub(crate) trait Spawner {
    /// Spawn the target as this CLI's user, with inherited standard streams.
    ///
    /// # Errors
    ///
    /// A machine code plus a Chinese sentence. The sentence has no error code
    /// and no English; the code is for the log and for `--json`.
    fn spawn(&mut self, spec: &RunSpec) -> Result<Box<dyn SpawnedChild>, (&'static str, String)>;
}

/// Production caller-side spawner. It never creates a cgroup: the daemon
/// records the adopted root pid and performs its own scope handling.
/// Plain Chinese sentence for a target `exec` failure. Callers must check a
/// requested working directory before calling this function: `Command` folds
/// its `chdir` and `exec` failures into one `io::Error`, while the hold/error
/// pipe carries the step explicitly. The program name, but never its arguments,
/// is safe and useful to show.
pub(crate) fn spawn_error_text(
    program: &str,
    _cwd: Option<&str>,
    error: &std::io::Error,
) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => format!("找不到程序「{program}」，请检查名字或路径"),
        std::io::ErrorKind::PermissionDenied => {
            format!("程序「{program}」没有执行权限，请检查文件权限后再试。")
        }
        _ => "无法启动程序：发生系统错误".to_owned(),
    }
}

/// Machine code for a spawn failure, matching the daemon's launch errors.
pub(crate) fn spawn_error_code(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::NotFound => "program_not_found",
        std::io::ErrorKind::PermissionDenied => "program_not_permitted",
        _ => "spawn_failed",
    }
}

/// The two working-directory outcomes. They are separate from program errors
/// even when the operating system reports the same errno for both operations.
fn cwd_error_text(cwd: &str, error: &std::io::Error) -> (&'static str, String) {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => (
            "cwd_not_permitted",
            format!("没有权限进入工作目录「{cwd}」，请换一个目录或检查权限。"),
        ),
        _ => ("cwd_not_found", format!("找不到工作目录「{cwd}」")),
    }
}

/// Check the directory before using a platform API whose spawn error does not
/// identify whether `chdir` or `exec` failed. The held launch path does not
/// need this preflight: its close-on-exec error pipe reports the real step.
#[cfg(not(any(target_os = "macos", windows)))]
fn check_cwd(cwd: Option<&str>) -> Result<(), (&'static str, String)> {
    let Some(cwd) = cwd else {
        return Ok(());
    };
    match std::fs::metadata(cwd) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(("cwd_not_found", format!("找不到工作目录「{cwd}」"))),
        Err(error) => Err(cwd_error_text(cwd, &error)),
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn spawn_error(program: &str, cwd: Option<&str>, error: &std::io::Error) -> (&'static str, String) {
    (
        spawn_error_code(error),
        spawn_error_text(program, cwd, error),
    )
}

/// Plain Chinese sentence when waiting for the started program failed.
#[cfg(any(not(any(unix, windows)), test))]
pub(crate) fn wait_error_text(_error: &std::io::Error) -> String {
    "等待程序结束失败".to_owned()
}

#[derive(Debug, Default)]
pub(crate) struct CommandSpawner;

#[cfg(not(any(unix, windows)))]
struct ProcessChild {
    child: Child,
}

#[cfg(not(any(unix, windows)))]
impl SpawnedChild for ProcessChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn wait(&mut self) -> Result<i32, String> {
        self.child
            .wait()
            .map(|status| status.code().unwrap_or(exit::GENERAL))
            .map_err(|error| wait_error_text(&error))
    }

    fn release(&mut self) -> Result<(), (&'static str, String)> {
        Ok(())
    }

    fn kill_and_reap(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// macOS `aw run` child. `aw-platform` forks it and the child blocks on the
/// gate pipe before exec, so this CLI is the creator: dropping the hold before
/// `release` closes the pipe and the child exits without running. After
/// `release` the returned handle reaps only this child. 【待验证】not run on a
/// real Mac.
#[cfg(target_os = "macos")]
struct PlatformChild {
    held: Option<Box<dyn aw_platform::HeldChild>>,
    released: Option<Box<dyn aw_platform::ReleasedChild>>,
    /// The program name, for the one launch error that may repeat it (the
    /// child reports a lookup miss at release). Not an argument.
    program: String,
    /// The working directory the caller asked for, for the directory sentence.
    cwd: Option<String>,
    terminal: Option<crate::launch::terminal::TerminalChild>,
}

#[cfg(target_os = "macos")]
impl SpawnedChild for PlatformChild {
    fn pid(&self) -> u32 {
        self.held
            .as_ref()
            .map(|child| child.pid())
            .or_else(|| self.released.as_ref().map(|child| child.pid()))
            .unwrap_or(0)
    }

    fn wait(&mut self) -> Result<i32, String> {
        let Some(child) = self.released.take() else {
            return Err("程序还被挂住，不能等待它结束".to_owned());
        };
        let mut terminal = self
            .terminal
            .take()
            .ok_or_else(|| "终端等待尚未准备好".to_owned())?;
        // The released platform handle is consumed here.  On Unix it owns a
        // direct child and has no other resources; `TerminalChild` becomes the
        // sole `waitpid(WUNTRACED)` caller so it can implement job control.
        drop(child);
        terminal.wait()
    }

    fn release(&mut self) -> Result<(), (&'static str, String)> {
        let Some(held) = self.held.take() else {
            return Err(("spawn_failed", "启动闸门已经放行".to_owned()));
        };
        match held.release() {
            Ok(released) => {
                self.released = Some(released);
                Ok(())
            }
            // A lookup or cwd miss is reported by the child at release; use
            // the same sentence (with the program name) as Linux and Windows.
            Err(error) => Err(platform_spawn_error(
                &self.program,
                self.cwd.as_deref(),
                error,
            )),
        }
    }

    fn kill_and_reap(&mut self) {
        if let Some(mut held) = self.held.take() {
            let _ = held.abort();
        }
        if let Some(released) = self.released.take() {
            if let Some(mut terminal) = self.terminal.take() {
                // The terminal owner must restore the foreground group and
                // perform the bounded cooperative cleanup, including a
                // daemon commit failure after the target was released.
                drop(released);
                terminal.abort_and_reap();
                return;
            }
            let _ = crate::launch::terminal::forward_to_group(
                released.pid(),
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = released.wait();
        }
        // The guard is armed as soon as spawn succeeds, including an adopt or
        // release failure before a `ReleasedChild` exists.
        self.terminal.take();
    }
}

/// Linux and Windows held children are owned by `aw-platform`. This thin CLI adapter only
/// translates the pre-existing `Spawner` state machine to its ownership API;
/// it deliberately does not contain a second pipe gate implementation.
#[cfg(any(target_os = "linux", windows))]
struct PlatformGatedChild {
    held: Option<Box<dyn HeldChild>>,
    released: Option<Box<dyn ReleasedChild>>,
    /// The program name, for the one launch error that may repeat it. Not an
    /// argument and not an environment value.
    program: String,
    /// The working directory the caller asked for, for the directory sentence.
    cwd: Option<String>,
    #[cfg(unix)]
    terminal: Option<crate::launch::terminal::TerminalChild>,
}

#[cfg(any(target_os = "linux", windows))]
impl SpawnedChild for PlatformGatedChild {
    fn pid(&self) -> u32 {
        self.held
            .as_ref()
            .map(|child| child.pid())
            .or_else(|| self.released.as_ref().map(|child| child.pid()))
            .unwrap_or_default()
    }

    fn wait(&mut self) -> Result<i32, String> {
        #[cfg(unix)]
        {
            let child = self
                .released
                .take()
                .ok_or_else(|| "无法等待尚未放行的程序".to_owned())?;
            let mut terminal = self
                .terminal
                .take()
                .ok_or_else(|| "终端等待尚未准备好".to_owned())?;
            // See PlatformChild: consuming the Unix release object leaves a
            // single WUNTRACED waiter for this direct child.
            drop(child);
            terminal.wait()
        }
        #[cfg(windows)]
        {
            let child = self
                .released
                .take()
                .ok_or_else(|| "无法等待尚未放行的程序".to_owned())?;
            match child
                .wait()
                .map_err(|error| platform_child_error(error).1)?
            {
                ReapOutcome::Exited(code) | ReapOutcome::Signaled(code) => Ok(code),
                ReapOutcome::StillRunning => Ok(exit::GENERAL),
            }
        }
    }

    fn release(&mut self) -> Result<(), (&'static str, String)> {
        let held = self
            .held
            .take()
            .ok_or_else(|| ("spawn_failed", "启动闸门已经放行".to_owned()))?;
        let released = held
            .release()
            .map_err(|error| platform_spawn_error(&self.program, self.cwd.as_deref(), error))?;
        self.released = Some(released);
        Ok(())
    }

    fn kill_and_reap(&mut self) {
        if let Some(mut held) = self.held.take() {
            let _ = held.abort();
        }
        #[cfg(unix)]
        if let Some(released) = self.released.take() {
            if let Some(mut terminal) = self.terminal.take() {
                // Do not bypass TERM/grace/STOP/KILL merely because a daemon
                // operation failed after release.
                drop(released);
                terminal.abort_and_reap();
                return;
            }
            let _ = crate::launch::terminal::forward_to_group(
                released.pid(),
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = released.wait();
        }
        #[cfg(unix)]
        self.terminal.take();
    }
}

/// Linux's CLI-created root is held by the private watchdog until daemon
/// adoption. The daemon records the real program pid; it never owns the
/// watchdog's cleanup boundary.
#[cfg(target_os = "linux")]
struct LinuxWatchdogChild {
    watchdog: crate::launch::watchdog::Watchdog,
    program: String,
    cwd: Option<String>,
    terminal: Option<crate::launch::terminal::TerminalChild>,
}

#[cfg(target_os = "linux")]
impl SpawnedChild for LinuxWatchdogChild {
    fn pid(&self) -> u32 {
        self.watchdog.pid()
    }

    fn wait(&mut self) -> Result<i32, String> {
        if let Some(mut terminal) = self.terminal.take() {
            return terminal.wait();
        }
        self.watchdog
            .wait()
            .map_err(|_| "等待程序结束失败".to_owned())
    }

    fn release(&mut self) -> Result<(), (&'static str, String)> {
        self.watchdog.release().map_err(|error| match error {
            crate::launch::watchdog::WatchdogError::Spawn(failure) => platform_spawn_error(
                &self.program,
                self.cwd.as_deref(),
                PlatformError::Spawn(failure),
            ),
            crate::launch::watchdog::WatchdogError::Unavailable => (
                "spawn_failed",
                "程序启动到一半出错，已经结束，没有运行：无法完成启动".to_owned(),
            ),
        })
    }

    fn kill_and_reap(&mut self) {
        // Drop restores aw's foreground process group before the watchdog
        // starts its bounded cleanup sequence.
        self.terminal.take();
        self.watchdog.abort();
    }

    fn cleanup_leftovers(&mut self) -> Option<CleanupLeftovers> {
        self.watchdog
            .cleanup_leftovers()
            .map(|report| CleanupLeftovers {
                count: report.count,
                pids: report.pids,
                eperm_pid: report.eperm_pid,
            })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn platform_child_error(error: PlatformError) -> (&'static str, String) {
    match error {
        PlatformError::Spawn(kind) => (
            kind.code(),
            "程序启动到一半出错，已经结束，没有运行：无法完成启动".to_owned(),
        ),
        PlatformError::Io(error) => (
            spawn_error_code(&error),
            "程序启动到一半出错，已经结束，没有运行：无法完成启动".to_owned(),
        ),
        PlatformError::Unsupported {
            kind: aw_platform::UnsupportedKind::NotInThisBuild,
            ..
        } => (
            "not_in_this_build",
            "这个操作本版本未接入：不能替其他用户启动程序。".to_owned(),
        ),
        PlatformError::Unsupported { .. } => (
            "not_supported_on_this_os",
            "这个系统不支持启动这个程序。".to_owned(),
        ),
        PlatformError::PeerNotIdentified { .. } | PlatformError::PipePeerNotIdentified { .. } => (
            "identity_unavailable",
            "认不出当前用户，已停止启动：系统没有提供可确认的身份。".to_owned(),
        ),
        PlatformError::Invalid { .. } => (
            "spawn_failed",
            "程序启动到一半出错，已经结束，没有运行：启动条件不符合要求".to_owned(),
        ),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn platform_spawn_error(
    program: &str,
    cwd: Option<&str>,
    error: PlatformError,
) -> (&'static str, String) {
    match error {
        PlatformError::Spawn(kind) => typed_spawn_error(program, cwd, kind),
        PlatformError::Io(error) => (
            spawn_step_code(&error),
            spawn_step_text(program, cwd, &error),
        ),
        other => platform_child_error(other),
    }
}

#[cfg(windows)]
fn platform_spawn_dispatch_error(
    program: &str,
    cwd: Option<&str>,
    error: PlatformError,
) -> LaunchDispatchError {
    let (code, detail) = platform_spawn_error(program, cwd, error);
    LaunchDispatchError::Spawn { code, detail }
}

#[cfg(target_os = "linux")]
fn io_spawn_dispatch_error(
    program: &str,
    cwd: Option<&str>,
    error: std::io::Error,
) -> LaunchDispatchError {
    let (code, detail) = spawn_error(program, cwd, &error);
    LaunchDispatchError::Spawn { code, detail }
}

fn typed_spawn_error(
    program: &str,
    cwd: Option<&str>,
    failure: aw_platform::SpawnFailure,
) -> (&'static str, String) {
    match failure {
        aw_platform::SpawnFailure::ProgramNotFound => (
            "program_not_found",
            format!("找不到程序「{program}」，请检查名字或路径"),
        ),
        aw_platform::SpawnFailure::ProgramNotPermitted => (
            "program_not_permitted",
            format!("程序「{program}」没有执行权限，请检查文件权限后再试。"),
        ),
        aw_platform::SpawnFailure::CwdNotFound => (
            "cwd_not_found",
            format!("找不到工作目录「{}」", cwd.unwrap_or(".")),
        ),
        // The public API uses program_not_permitted for either execution or
        // directory-entry denial only on older daemons. Keep the typed cause
        // explicit for current CLI, App, and OpenAPI clients.
        aw_platform::SpawnFailure::CwdNotPermitted => (
            "cwd_not_permitted",
            format!(
                "没有权限进入工作目录「{}」，请换一个目录或检查权限。",
                cwd.unwrap_or(".")
            ),
        ),
    }
}

/// Which sentence a failed launch gets. The hold stage reports the step in the
/// error text (`chdir:` or `exec:`), so a missing working directory and a
/// missing program are not the same sentence. `cwd` is the directory the caller
/// asked for; it is a path, never an argument or an environment value.
fn spawn_step_text(program: &str, cwd: Option<&str>, error: &std::io::Error) -> String {
    let text = error.to_string();
    if text.starts_with("chdir:") {
        let dir = cwd.unwrap_or(".");
        return cwd_error_text(dir, error).1;
    }
    if text.starts_with("exec:") || matches!(error.kind(), std::io::ErrorKind::NotFound) {
        return spawn_error_text(program, cwd, error);
    }
    spawn_error_text(program, cwd, error)
}

/// Machine code for a failed launch step. A `chdir` failure is `cwd_not_found`;
/// an `exec` failure keeps `program_not_found` / `program_not_permitted`.
fn spawn_step_code(error: &std::io::Error) -> &'static str {
    if error.to_string().starts_with("chdir:") {
        return match error.kind() {
            std::io::ErrorKind::PermissionDenied => "cwd_not_permitted",
            _ => "cwd_not_found",
        };
    }
    spawn_error_code(error)
}

/// A caller identity failure is distinct from a program spawn failure.  Keep
/// its machine code in the tuple so text output never has to inspect a message.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn caller_identity_error() -> (&'static str, String) {
    (
        "identity_unavailable",
        "认不出当前用户，已停止启动：无法确认当前用户".to_owned(),
    )
}

impl Spawner for CommandSpawner {
    fn spawn(&mut self, spec: &RunSpec) -> Result<Box<dyn SpawnedChild>, (&'static str, String)> {
        #[cfg(target_os = "linux")]
        {
            let Some((program, args)) = spec.command.split_first() else {
                return Err(("spawn_failed", "程序名为空".to_owned()));
            };
            let terminal_decision = crate::launch::terminal::TerminalDecision::before_fork();
            // The watchdog becomes the program's parent.  A foreground
            // terminal job must instead be waited with WUNTRACED by the CLI
            // itself so Ctrl-Z can return the terminal to the shell before
            // `aw` stops.  Background/no-TTY launches use the watchdog,
            // which is the subreaper and owns their bounded descendant
            // cleanup.
            if crate::launch::watchdog::should_wrap() && !terminal_decision.handoff_requested() {
                return crate::launch::watchdog::Watchdog::spawn(
                    spec,
                    terminal_decision.handoff_requested(),
                )
                .and_then(|watchdog| {
                    let terminal = if terminal_decision.handoff_requested() {
                        let mut terminal =
                            crate::launch::terminal::TerminalChild::new_with_watchdog(
                                // The watchdog is the direct child; the real
                                // program owns the target process group.
                                watchdog.process_pid(),
                                watchdog.pid(),
                                terminal_decision,
                                watchdog.control_clone()?,
                            )
                            .map_err(|_| crate::launch::watchdog::WatchdogError::Unavailable)?;
                        terminal.expect_child_foreground();
                        Some(terminal)
                    } else {
                        None
                    };
                    Ok(Box::new(LinuxWatchdogChild {
                        watchdog,
                        program: program.clone(),
                        cwd: spec.cwd.clone(),
                        terminal,
                    }) as Box<dyn SpawnedChild>)
                })
                .map_err(|_| {
                    (
                        "spawn_failed",
                        "程序启动到一半出错，已经结束，没有运行：无法完成启动".to_owned(),
                    )
                });
            }
            // The program name is not resolved here. The hold stage's parent
            // only builds candidate strings; the child tries them after it has
            // switched identity, so this process never stats a PATH directory.
            let caller = IdentifiedCaller::current_user().map_err(|_| caller_identity_error())?;
            let request = SpawnRequest {
                command: std::iter::once(program.clone())
                    .chain(args.iter().cloned())
                    .collect(),
                cwd: spec.cwd.as_ref().map(std::path::PathBuf::from),
                env: spec.env.clone(),
                terminal_handoff: terminal_decision.handoff_requested(),
                env_source: aw_platform::EnvSource::Inherit,
            };
            let mut held = platform()
                .spawn_suspended(&caller, &request)
                .map_err(|error| platform_spawn_error(program, spec.cwd.as_deref(), error))?;
            // The held child can perform its handoff before it reads the gate.
            // Build this guard immediately after `spawn_suspended`, rather
            // than at release, so adopt and every other early error restores
            // aw's foreground group.
            let mut terminal =
                match crate::launch::terminal::TerminalChild::new(held.pid(), terminal_decision) {
                    Ok(terminal) => terminal,
                    Err(error) => {
                        let pid = held.pid();
                        let _ = held.abort();
                        crate::launch::terminal::abort_unmanaged_child(pid, terminal_decision);
                        return Err(("spawn_failed", error));
                    }
                };
            terminal.expect_child_foreground();
            Ok(Box::new(PlatformGatedChild {
                held: Some(held),
                released: None,
                program: program.clone(),
                cwd: spec.cwd.clone(),
                terminal: Some(terminal),
            }))
        }
        #[cfg(target_os = "macos")]
        {
            let Some((program, args)) = spec.command.split_first() else {
                return Err(("spawn_failed", "程序名为空".to_owned()));
            };
            // Same as Linux: the hold stage resolves the name in the child,
            // after the identity switch. This process does not stat PATH.
            let caller = aw_platform::IdentifiedCaller::current_user()
                .map_err(|_| caller_identity_error())?;
            let terminal_decision = crate::launch::terminal::TerminalDecision::before_fork();
            let request = aw_platform::SpawnRequest {
                command: std::iter::once(program.clone())
                    .chain(args.iter().cloned())
                    .collect(),
                cwd: spec.cwd.clone().map(std::path::PathBuf::from),
                env: spec.env.clone(),
                terminal_handoff: terminal_decision.handoff_requested(),
                env_source: aw_platform::EnvSource::Inherit,
            };
            let mut held = aw_platform::platform()
                .spawn_suspended(&caller, &request)
                .map_err(|error| platform_spawn_error(program, spec.cwd.as_deref(), error))?;
            let mut terminal =
                match crate::launch::terminal::TerminalChild::new(held.pid(), terminal_decision) {
                    Ok(terminal) => terminal,
                    Err(error) => {
                        let pid = held.pid();
                        let _ = held.abort();
                        crate::launch::terminal::abort_unmanaged_child(pid, terminal_decision);
                        return Err(("spawn_failed", error));
                    }
                };
            terminal.expect_child_foreground();
            Ok(Box::new(PlatformChild {
                held: Some(held),
                released: None,
                program: program.clone(),
                cwd: spec.cwd.clone(),
                terminal: Some(terminal),
            }))
        }
        #[cfg(windows)]
        {
            let program = spec
                .command
                .first()
                .ok_or_else(|| ("spawn_failed", "程序名为空".to_owned()))?;
            let caller = IdentifiedCaller::current_user().map_err(|_| caller_identity_error())?;
            let request = SpawnRequest {
                command: spec.command.clone(),
                cwd: spec.cwd.as_ref().map(Into::into),
                env: spec.env.clone(),
                terminal_handoff: false,
                env_source: aw_platform::EnvSource::Inherit,
            };
            let held = platform()
                .spawn_suspended(&caller, &request)
                .map_err(|error| platform_spawn_error(program, spec.cwd.as_deref(), error))?;
            Ok(Box::new(PlatformGatedChild {
                held: Some(held),
                released: None,
                program: program.clone(),
                cwd: spec.cwd.clone(),
            }))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let Some((program, args)) = spec.command.split_first() else {
                return Err(("spawn_failed", "程序名为空".to_owned()));
            };
            check_cwd(spec.cwd.as_deref())?;
            let mut command = Command::new(program);
            command.args(args);
            configure_command(&mut command, spec);
            command
                .spawn()
                .map(|child| Box::new(ProcessChild { child }) as Box<dyn SpawnedChild>)
                .map_err(|error| spawn_error(program, spec.cwd.as_deref(), &error))
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn configure_command(command: &mut Command, spec: &RunSpec) {
    if let Some(cwd) = spec.cwd.as_deref() {
        command.current_dir(cwd);
    }
    for (key, value) in &spec.env {
        command.env(key, value);
    }
}

/// Windows production launcher. `aw-platform` holds the target in a Job until
/// release and returns the owning reap handle after release.
#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
pub(crate) struct PlatformLauncher;

#[cfg(target_os = "windows")]
impl Launcher for PlatformLauncher {
    fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
        let caller =
            IdentifiedCaller::current_user().map_err(|error| LaunchDispatchError::Platform {
                detail: platform_child_error(error).1,
            })?;
        let request = SpawnRequest {
            command: spec.command.clone(),
            cwd: spec.cwd.as_ref().map(Into::into),
            env: spec.env.clone(),
            terminal_handoff: false,
            env_source: aw_platform::EnvSource::Inherit,
        };
        let program = spec.command.first().map(String::as_str).unwrap_or("");
        let held = platform()
            .spawn_suspended(&caller, &request)
            .map_err(|error| platform_spawn_dispatch_error(program, spec.cwd.as_deref(), error))?;
        let pid = held.pid();
        let released = held
            .release()
            .map_err(|error| platform_spawn_dispatch_error(program, spec.cwd.as_deref(), error))?;
        let code = match released
            .wait()
            .map_err(|error| LaunchDispatchError::Platform {
                detail: platform_child_error(error).1,
            })? {
            ReapOutcome::Exited(code) => code,
            ReapOutcome::Signaled(_) | ReapOutcome::StillRunning => exit::GENERAL,
        };
        Ok(Launched {
            code,
            pid,
            note: None,
            sampling: spec.no_daemon,
        })
    }

    fn forward_interrupt(&mut self, _pid: u32) -> Result<(), LaunchDispatchError> {
        Err(LaunchDispatchError::NotImplemented {
            detail: "中断转发不可用；Windows 启动器未创建控制台进程组".to_owned(),
        })
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
        // Use the same held-child launcher as the daemon-backed route. In
        // particular, the child gives itself the terminal before it reads the
        // gate; a `Command::spawn` plus parent-side handoff races an immediate
        // terminal read and can leave the target stopped by SIGTTIN.
        let mut child = CommandSpawner
            .spawn(spec)
            .map_err(|(code, detail)| LaunchDispatchError::Spawn { code, detail })?;
        let pid = child.pid();
        child
            .release()
            .map_err(|(code, detail)| LaunchDispatchError::Spawn { code, detail })?;
        let code = child
            .wait()
            .map_err(|detail| LaunchDispatchError::NotImplemented { detail })?;
        Ok(Launched {
            code,
            pid,
            note: None,
            sampling: spec.no_daemon,
        })
    }

    fn forward_interrupt(&mut self, pid: u32) -> Result<(), LaunchDispatchError> {
        crate::launch::terminal::forward_to_group(pid, nix::sys::signal::Signal::SIGINT)
            .map_err(|detail| LaunchDispatchError::NotImplemented { detail })
    }
}

/// One cgroup-scoped launch attempt (production: [`launch::LocalCgroupHost`]).
#[cfg(target_os = "linux")]
type CgroupAttempt<'a> = dyn FnMut(
        &std::ffi::OsStr,
        &[std::ffi::OsString],
        Option<&str>,
        &[(String, String)],
        &mut dyn FnMut(u32),
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
#[allow(dead_code)]
fn launch_linux(
    spec: &RunSpec,
    attempt: &mut CgroupAttempt<'_>,
) -> Result<Launched, LaunchDispatchError> {
    launch_linux_with_started(spec, attempt, &mut |_| {})
}

/// Linux launch with a notification immediately after the target exists.
/// Production uses this narrow hook only to arm Unix signal forwarding; the
/// cgroup host still owns scope setup and reaping.
#[cfg(target_os = "linux")]
fn launch_linux_with_started(
    spec: &RunSpec,
    attempt: &mut CgroupAttempt<'_>,
    started: &mut dyn FnMut(u32),
) -> Result<Launched, LaunchDispatchError> {
    let Some((program, args)) = spec.command.split_first() else {
        return Err(LaunchDispatchError::NotImplemented {
            detail: "启动命令为空".to_owned(),
        });
    };
    check_cwd(spec.cwd.as_deref())
        .map_err(|(code, detail)| LaunchDispatchError::Spawn { code, detail })?;
    let argv: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
    match attempt(
        std::ffi::OsStr::new(program),
        &argv,
        spec.cwd.as_deref(),
        &spec.env,
        started,
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
            use std::os::unix::process::CommandExt;

            let terminal_decision = crate::launch::terminal::TerminalDecision::before_fork();
            let mut child = std::process::Command::new(program);
            child.args(&argv);
            // The relay below addresses this group, so descendants that keep
            // the normal process group see the same terminal signal.
            child.process_group(0);
            if let Some(dir) = spec.cwd.as_deref() {
                child.current_dir(dir);
            }
            for (key, value) in &spec.env {
                child.env(key, value);
            }
            let spawned = child
                .spawn()
                .map_err(|error| io_spawn_dispatch_error(program, spec.cwd.as_deref(), error))?;
            let pid = spawned.id();
            started(pid);
            let mut terminal =
                match crate::launch::terminal::TerminalChild::new(pid, terminal_decision) {
                    Ok(terminal) => terminal,
                    Err(detail) => {
                        crate::launch::terminal::abort_unmanaged_child(pid, terminal_decision);
                        return Err(LaunchDispatchError::NotImplemented { detail });
                    }
                };
            if let Err(detail) = terminal.give_child_foreground() {
                terminal.abort_and_reap();
                return Err(LaunchDispatchError::NotImplemented { detail });
            }
            drop(spawned);
            Ok(Launched {
                code: terminal
                    .wait()
                    .map_err(|detail| LaunchDispatchError::NotImplemented { detail })?,
                pid,
                note: Some(PID_TREE_FALLBACK_NOTE),
                sampling: spec.no_daemon,
            })
        }
        Err(launch::LinuxLaunchError::ForkFailed {
            kind: Some(kind), ..
        }) => Err(io_spawn_dispatch_error(
            program,
            spec.cwd.as_deref(),
            std::io::Error::from(kind),
        )),
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
#[allow(dead_code)]
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
/// `aw-platform` starts a hold stage that blocks on a pipe, then execs the
/// program as the current user once released. `--no-daemon` releases and waits
/// here; there is no daemon to adopt. 【待验证】not run on a real Mac.
/// Grandchild tracking is left to the collector.
#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
pub(crate) struct PlatformLauncher;

#[cfg(target_os = "macos")]
impl Launcher for PlatformLauncher {
    fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
        let mut child = CommandSpawner
            .spawn(spec)
            .map_err(|(code, detail)| LaunchDispatchError::Spawn { code, detail })?;
        let pid = child.pid();
        child
            .release()
            .map_err(|(code, detail)| LaunchDispatchError::Spawn { code, detail })?;
        let code = child
            .wait()
            .map_err(|detail| LaunchDispatchError::NotImplemented { detail })?;
        Ok(Launched {
            code,
            pid,
            note: None,
            sampling: spec.no_daemon,
        })
    }

    fn forward_interrupt(&mut self, pid: u32) -> Result<(), LaunchDispatchError> {
        crate::launch::terminal::forward_to_group(pid, nix::sys::signal::Signal::SIGINT)
            .map_err(|detail| LaunchDispatchError::NotImplemented { detail })
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
    let (level, mut spec) = match prepare(args, deferred) {
        Ok(prepared) => prepared,
        Err(outcome) => return outcome,
    };
    let omitted = enabled_omitted_note();
    let (intercept_dir, rewrites) = match inject_claude_intercept(args, deferred, &mut spec, None) {
        Ok(Some((dir, rewrites))) => (Some(dir), rewrites),
        Ok(None) => (None, false),
        Err(outcome) => return outcome,
    };
    let notice = rewrite_notice(rewrites);

    let launched = match launcher.launch(&spec) {
        Ok(launched) => launched,
        Err(err) => {
            let cleanup = intercept_dir
                .as_deref()
                .and_then(|dir| cleanup_intercept_dir(dir).err());
            let error_code = err.code().unwrap_or("launch");
            let code = if args.no_daemon {
                exit::GENERAL
            } else if mentions_daemon(&err) {
                exit::UNREACHABLE
            } else {
                exit::GENERAL
            };
            let mut outcome = super::error_outcome(code, error_code, &err.to_string(), args.json);
            append_cleanup_note(&mut outcome, cleanup);
            return outcome;
        }
    };

    if level == SummaryLevel::None || args.quiet {
        let cleanup = intercept_dir
            .as_deref()
            .and_then(|dir| cleanup_intercept_dir(dir).err());
        let mut stderr = notice.unwrap_or("").to_owned();
        if let Some(note) = omitted {
            stderr.push_str(&note);
        }
        let mut outcome = Outcome {
            code: launched.code,
            stdout: Vec::new(),
            stderr: stderr.into_bytes(),
        };
        append_cleanup_note(&mut outcome, cleanup);
        return outcome;
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
        let cleanup = intercept_dir
            .as_deref()
            .and_then(|dir| cleanup_intercept_dir(dir).err());
        let mut outcome =
            super::error_outcome(exit::GENERAL, "summary", &err.to_string(), args.json);
        append_cleanup_note(&mut outcome, cleanup);
        return outcome;
    }
    let cleanup = intercept_dir
        .as_deref()
        .and_then(|dir| cleanup_intercept_dir(dir).err());
    let mut outcome = Outcome {
        code: launched.code,
        stdout: Vec::new(),
        stderr,
    };
    if let Some(notice) = notice {
        outcome.stderr.extend_from_slice(notice.as_bytes());
    }
    if let Some(note) = omitted {
        outcome.stderr.extend_from_slice(note.as_bytes());
    }
    append_cleanup_note(&mut outcome, cleanup);
    outcome
}

/// A cleanup failure is a note on the outcome, not a swallowed error and not a
/// changed exit code: the target already ran.
fn append_cleanup_note(outcome: &mut Outcome, note: Option<String>) {
    if let Some(note) = note {
        outcome.stderr.extend(format!("[aw] {note}\n").into_bytes());
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
    if args.raw.is_some() {
        return Err(super::error_outcome(
            exit::NOT_IN_BUILD,
            "not_in_build",
            "`--raw` 本版本未接入",
            args.json,
        ));
    }
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
            exit::NOT_IN_BUILD,
            "not_in_build",
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
    // Validation only. Writing the settings file here would run twice: `preflight`
    // calls this, then `daemon_run` calls it again, and each call minted a new
    // `aw-intercept-<pid>-<ns>` directory and appended another `--settings`.
    claude_intercept_enabled(args, deferred, &spec)?;
    Ok((level, spec))
}

/// Claude Code intercept injection (P5-SEC-02).
///
/// Off unless `--intercept` was passed or the policy file is enabled. When it
/// is on, [`inject_claude_intercept`] writes one temp settings file (not under
/// `~/.claude/`) and appends `--settings <path>` once. The hook command is this
/// binary's absolute path, `args` are `["hook", "claude-code"]`, and
/// `onFailure` is `block`. Codex is not injected: that path is unverified, and
/// the manual fragment lives in the adapter.
///
/// `Err` means the launch must not start: the policy file could not be read.
/// `Ok(None)` means intercept is off for this command. `Ok(Some(true))` means
/// the policy that is on contains a rewrite rule.
fn claude_intercept_enabled(
    args: &RunArgs<'_>,
    deferred: DeferredFlags,
    spec: &crate::launch::RunSpec,
) -> Result<Option<bool>, Outcome> {
    let agent = args.agent.unwrap_or("");
    let looks_like_claude = agent == "claude-code"
        || agent == "claude"
        || spec
            .command
            .first()
            .is_some_and(|program| program.rsplit(['/', '\\']).next() == Some("claude"));
    if !looks_like_claude {
        return Ok(None);
    }
    let policy = super::policy_file::load_policy(
        std::env::var_os(super::policy_file::POLICY_ENV)
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .as_deref(),
        super::policy_file::user_config_home().as_deref(),
    );
    // A broken file is not "off". `aw hook` denies it (design §5.3). Injecting
    // is what makes that deny run; skipping it would let the tool run.
    let enabled = deferred.intercept
        || matches!(
            policy,
            super::policy_file::PolicyLoad::On(_) | super::policy_file::PolicyLoad::Broken
        );
    if enabled {
        let rewrites = match &policy {
            super::policy_file::PolicyLoad::On(policy) => policy
                .rules()
                .iter()
                .any(|rule| rule.action == aw_pipeline::Action::Rewrite),
            _ => false,
        };
        Ok(Some(rewrites))
    } else {
        Ok(None)
    }
}

/// One stderr line when a rewrite rule is in force.
///
/// A hook rewrite is printed as `permissionDecision: "allow"` plus
/// `updatedInput`, and Claude Code treats that `allow` as approval: the
/// rewritten command runs without the permission prompt. The operator asked
/// for the rewrite, but should see that it also approves. `ask` is not the
/// alternative: under `claude -p` nobody answers it (design §5.2).
fn rewrite_notice(rewrites: bool) -> Option<&'static str> {
    if rewrites {
        Some("[aw] 提示：规则里有改写。命中的命令会带着改后的参数直接执行，不再弹出权限确认。\n")
    } else {
        None
    }
}

/// stderr when the policy file has `[[rule]]` and never sets `enabled`.
///
/// The file loads as off (the default is closed), so nothing is injected. An
/// operator who wrote the rules and forgot the switch, or who typed `enable`
/// and had the unknown key refused, needs to see which of the two it was.
/// `enable` is a load error and takes the broken-file path instead; this note
/// is only the quiet omission. `None` when the file sets `enabled`, has no
/// rules, or cannot be read as TOML.
fn enabled_omitted_note() -> Option<String> {
    let path = policy_path_in_env();
    let text = std::fs::read_to_string(&path).ok()?;
    if aw_pipeline::rules_without_enabled(&text) {
        Some(
            "[aw] 提示：规则文件里有规则，但没有写 enabled，拦截没有打开。要打开请写 enabled = true。\n"
                .to_owned(),
        )
    } else {
        None
    }
}

/// `AW_POLICY` when it is set, otherwise the per-user file. Empty when neither
/// can be named: there is then nothing to warn about.
fn policy_path_in_env() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os(super::policy_file::POLICY_ENV) {
        if !path.is_empty() {
            return std::path::PathBuf::from(path);
        }
    }
    super::policy_file::default_policy_path(super::policy_file::user_config_home().as_deref())
        .unwrap_or_default()
}

/// Write one settings file and append `--settings` exactly once.
///
/// Called from the launch paths ([`run`], [`daemon_run`]), never from
/// [`prepare`]: that function also runs as a preflight, and writing there
/// produced a second `aw-intercept-<pid>-<ns>` directory and a second
/// `--settings` on the same command. The returned directory is removed when
/// the launch outcome is built; a failure before that still removes it here.
///
/// `Err` is a failed launch, not a launch without the hook the operator asked
/// for. `Ok(None)` means intercept is off and nothing was written.
/// `Ok(Some((dir, rewrites)))` wrote the settings file; `rewrites` is whether
/// the policy contains a rewrite rule, which the caller prints once.
fn inject_claude_intercept(
    args: &RunArgs<'_>,
    deferred: DeferredFlags,
    spec: &mut crate::launch::RunSpec,
    session: Option<&str>,
) -> Result<Option<(std::path::PathBuf, bool)>, Outcome> {
    let Some(rewrites) = claude_intercept_enabled(args, deferred, spec)? else {
        return Ok(None);
    };
    let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("aw"));
    let command = exe.display().to_string();
    // The daemon's public id, once it has assigned one. The hook reads
    // `AW_SESSION` and `--session`. mcp-tap, started later in the same process
    // tree, reads the variable. Both are how an intercept row gets a session.
    let mut hook_args = vec!["hook".to_owned(), "claude-code".to_owned()];
    if let Some(id) = session.map(str::trim).filter(|id| !id.is_empty()) {
        hook_args.push("--session".to_owned());
        hook_args.push(id.to_owned());
        spec.env
            .push((super::hook::SESSION_ENV.to_owned(), id.to_owned()));
    }
    let hook_refs: Vec<&str> = hook_args.iter().map(String::as_str).collect();
    let doc = aw_agent_adapters::agents::claude_code::decision::intercept_settings_json(
        &command,
        &hook_refs,
        true,
    );
    let dir = std::env::temp_dir().join(format!(
        "aw-intercept-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    if std::fs::create_dir_all(&dir).is_err() {
        return Err(super::error_outcome(
            exit::GENERAL,
            "intercept",
            "拦截的临时设置目录写不了，这次没有启动",
            args.json,
        ));
    }
    let path = dir.join("claude-settings.json");
    if std::fs::write(&path, doc).is_err() {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(super::error_outcome(
            exit::GENERAL,
            "intercept",
            "拦截的临时设置文件写不了，这次没有启动",
            args.json,
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    spec.command.push("--settings".to_owned());
    spec.command.push(path.display().to_string());
    // `AW_SESSION` and `--session` are set above when the caller already has
    // the daemon's public id. `aw run` without a daemon has no id to give.
    Ok(Some((dir, rewrites)))
}

/// Remove the temp settings directory. A failure is reported, not hidden:
/// the file holds the hook command path, and leaving it behind is visible.
fn cleanup_intercept_dir(dir: &std::path::Path) -> Result<(), String> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!(
            "拦截的临时设置目录没有删掉（{}）：{err}",
            dir.display()
        )),
    }
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
    let (level, mut spec) = match daemon_prepare(args, deferred) {
        Ok(prepared) => prepared,
        Err(outcome) => return outcome,
    };
    let omitted = enabled_omitted_note();
    // The public id exists only after the daemon accepts the run. Inject after
    // that, so the hook command and `AW_SESSION` name this session. The argv
    // sent to `begin_run` is the operator's command, without `--settings`.
    let request = BeginRunRequest {
        argv: spec.command.clone(),
        cwd: spec.cwd.clone(),
        name: args.name.map(str::to_owned),
        agent: args.agent.map(str::to_owned),
        env: user_locale_env(|name| std::env::var(name).ok()),
    };
    let launch = match sessions.begin_run(&request) {
        Ok(launch) => launch,
        Err(error) => return daemon_error_outcome(error, args.json, false),
    };
    // One settings file for this launch. `preflight` already validated the
    // policy and wrote nothing, so this is the only `--settings`.
    let (intercept_dir, rewrites) = match inject_claude_intercept(
        args,
        deferred,
        &mut spec,
        Some(launch.public_id.as_str()),
    ) {
        Ok(Some((dir, rewrites))) => (Some(dir), rewrites),
        Ok(None) => (None, false),
        Err(outcome) => {
            // The reservation has no child. Drop it; do not leave a pending run.
            let _ = sessions.discard_run(&launch);
            return outcome;
        }
    };
    let notice = rewrite_notice(rewrites);
    let mut child = match spawner.spawn(&spec) {
        Ok(child) => child,
        Err((code, detail)) => {
            // A pending run has no executed program.  It is not a stopped
            // session: discard the reservation so callers never observe an
            // empty launch after a local spawn failure.
            let _ = sessions.discard_run(&launch);
            return finish_daemon(
                intercept_dir.as_deref(),
                super::error_outcome(exit::GENERAL, code, &detail, args.json),
            );
        }
    };
    if let Err(error) = sessions.adopt(&launch, child.pid()) {
        child.kill_and_reap();
        // Adoption did not make the held process runnable.  This is still a
        // failed launch, not a recorded session with zero useful events.
        let _ = sessions.discard_run(&launch);
        return finish_daemon(
            intercept_dir.as_deref(),
            daemon_error_outcome(error, args.json, true),
        );
    }
    if let Err((code, detail)) = child.release() {
        child.kill_and_reap();
        let _ = sessions.discard_run(&launch);
        return finish_daemon(
            intercept_dir.as_deref(),
            super::error_outcome(exit::GENERAL, code, &detail, args.json),
        );
    }
    if let Err(error) = sessions.commit_run(&launch) {
        child.kill_and_reap();
        let _ = sessions.discard_run(&launch);
        return finish_daemon(
            intercept_dir.as_deref(),
            daemon_error_outcome(error, args.json, true),
        );
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
            return finish_daemon(
                intercept_dir.as_deref(),
                super::error_outcome(exit::GENERAL, "wait_failed", &detail, args.json),
            );
        }
    };
    let leftovers_warning = child.cleanup_leftovers().and_then(|leftovers| {
        sessions
            .record_leftovers(&launch, &leftovers)
            .err()
            .map(|error| format!("[aw] 警告：后台没有记录未结束的子程序：{error}\n"))
    });
    let exit_warning = sessions
        .record_exit(&launch, code)
        .err()
        .map(|error| format!("[aw] 警告：daemon 未记录程序退出码：{error}\n"));
    if level == SummaryLevel::None || args.quiet {
        let mut stderr = notice.unwrap_or("").to_owned();
        if let Some(note) = &omitted {
            stderr.push_str(note);
        }
        if let Some(warning) = pin_warning.clone() {
            stderr.push_str(&warning);
        }
        if let Some(warning) = leftovers_warning {
            stderr.push_str(&warning);
        }
        if let Some(warning) = exit_warning {
            stderr.push_str(&warning);
        }
        return finish_daemon(
            intercept_dir.as_deref(),
            Outcome {
                code,
                stdout: Vec::new(),
                stderr: stderr.into_bytes(),
            },
        );
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
        return finish_daemon(
            intercept_dir.as_deref(),
            super::error_outcome(exit::GENERAL, "summary", &error.to_string(), args.json),
        );
    }
    if let Some(notice) = notice {
        stderr.extend_from_slice(notice.as_bytes());
    }
    if let Some(note) = omitted {
        stderr.extend_from_slice(note.as_bytes());
    }
    if let Some(warning) = pin_warning {
        stderr.extend_from_slice(warning.as_bytes());
    }
    if let Some(warning) = leftovers_warning {
        stderr.extend_from_slice(warning.as_bytes());
    }
    if let Some(warning) = exit_warning {
        stderr.extend_from_slice(warning.as_bytes());
    }
    finish_daemon(
        intercept_dir.as_deref(),
        Outcome {
            code,
            stdout: Vec::new(),
            stderr,
        },
    )
}

/// Delete the intercept settings directory, then return `outcome`.
///
/// The directory exists only for this launch. Removing it after the child has
/// exited (or after the launch failed) is the whole cleanup: Claude reads
/// `--settings` at start, so the file is not needed once the process is gone.
/// A delete that fails is named on stderr and does not change the exit code.
fn finish_daemon(intercept_dir: Option<&std::path::Path>, mut outcome: Outcome) -> Outcome {
    if let Some(dir) = intercept_dir {
        append_cleanup_note(&mut outcome, cleanup_intercept_dir(dir).err());
    }
    outcome
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
        return Some("`--mcp-tap` 本版本未接入".to_owned());
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
    Some(format!("`{}` 本版本未接入", which.join(", ")))
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

fn mentions_daemon(_: &LaunchDispatchError) -> bool {
    // The Windows Job launch no longer performs the retired local
    // handoff/adopt state machine. Daemon-path errors arrive through
    // `daemon_run`, not through this local launcher.
    false
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod intercept_inject_tests {
    use super::*;

    #[test]
    fn broken_policy_still_injects_settings_without_the_flag() {
        let dir = std::env::temp_dir().join(format!("aw-inject-broken-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let policy = dir.join("policy.toml");
        std::fs::write(&policy, "enabled = true\n[[rule]]\naction = \"nope\"\n").unwrap();
        // Same lock as the hook tests. A panic still clears the variable.
        let _guard = super::super::policy_file::env_lock();
        let _env = super::super::policy_file::EnvVarGuard::set(
            super::super::policy_file::POLICY_ENV,
            &policy,
        );
        let command = Vec::<String>::new();
        let args = RunArgs {
            agent: Some("claude-code"),
            name: None,
            no_follow_children: false,
            cwd: None,
            env: &[],
            summary: None,
            pin: false,
            no_daemon: true,
            raw: None,
            command: &command,
            json: false,
            quiet: true,
        };
        let mut spec = crate::launch::RunSpec::new(vec!["claude".to_owned()]).unwrap();
        let deferred = DeferredFlags {
            proxy: false,
            proxy_on_reject: false,
            proxy_on_reject_value: None,
            self_report: false,
            mcp_tap: false,
            unsafe_no_redact: false,
            include_proc: false,
            group: false,
            intercept: false,
        };
        let outcome = inject_claude_intercept(&args, deferred, &mut spec, None);
        if let Ok(Some((settings_dir, _))) = &outcome {
            let _ = std::fs::remove_dir_all(settings_dir);
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(outcome.is_ok(), "broken policy must not skip the launch");
        assert!(
            matches!(outcome, Ok(Some(_))),
            "broken policy did not write settings"
        );
        assert_eq!(
            spec.command
                .iter()
                .filter(|arg| *arg == "--settings")
                .count(),
            1,
            "broken policy injected --settings more than once: {:?}",
            spec.command
        );
    }

    /// `preflight` validates and writes nothing. One launch writes one file and
    /// one `--settings`; the directory is gone after the session cleanup.
    #[test]
    fn intercept_settings_are_written_once_and_removed() {
        let policy_root = std::env::temp_dir().join(format!(
            "aw-inject-once-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&policy_root);
        std::fs::create_dir_all(&policy_root).unwrap();
        let policy = policy_root.join("policy.toml");
        std::fs::write(&policy, "enabled = true\n").unwrap();
        let _guard = super::super::policy_file::env_lock();
        let _env = super::super::policy_file::EnvVarGuard::set(
            super::super::policy_file::POLICY_ENV,
            &policy,
        );

        let command = vec!["claude".to_owned()];
        let args = RunArgs {
            agent: Some("claude-code"),
            name: None,
            no_follow_children: false,
            cwd: None,
            env: &[],
            summary: None,
            pin: false,
            no_daemon: false,
            raw: None,
            command: &command,
            json: false,
            quiet: true,
        };
        let deferred = DeferredFlags {
            proxy: false,
            proxy_on_reject: false,
            proxy_on_reject_value: None,
            self_report: false,
            mcp_tap: false,
            unsafe_no_redact: false,
            include_proc: false,
            group: false,
            intercept: true,
        };
        let before = ours_in_temp();
        let preflight = preflight(&args, deferred);
        assert!(preflight.is_ok(), "preflight refused a valid intercept run");
        assert_eq!(
            ours_in_temp(),
            before,
            "preflight wrote a settings directory"
        );

        let mut spec = crate::launch::RunSpec::new(command.clone()).unwrap();
        let written = match inject_claude_intercept(&args, deferred, &mut spec, None) {
            Ok(Some((dir, _))) => dir,
            Ok(None) => panic!("intercept did not write settings"),
            Err(_) => panic!("intercept settings could not be written"),
        };
        let created: Vec<_> = ours_in_temp()
            .into_iter()
            .filter(|path| !before.contains(path))
            .collect();
        assert_eq!(
            created,
            vec![written.clone()],
            "expected exactly one new dir"
        );
        assert_eq!(
            spec.command
                .iter()
                .filter(|arg| *arg == "--settings")
                .count(),
            1,
            "{:?}",
            spec.command
        );
        assert!(written.join("claude-settings.json").is_file());
        assert!(cleanup_intercept_dir(&written).is_ok());
        assert!(
            !written.exists(),
            "settings dir survived: {}",
            written.display()
        );

        let _ = std::fs::remove_dir_all(&policy_root);
    }

    /// `[[rule]]` with no `enabled` used to load as off and say nothing, so an
    /// operator who mistyped the switch (or forgot it) thought intercept was on.
    /// `aw run` names that on stderr and does not inject. A file that sets
    /// `enabled = false` stays quiet: that one is deliberate.
    #[test]
    fn rules_without_enabled_are_named_on_stderr() {
        let dir = scratch_policy("no-enabled");
        let policy = dir.join("policy.toml");
        std::fs::write(
            &policy,
            "version = 1\n[[rule]]\nid = \"r\"\naction = \"deny\"\n",
        )
        .unwrap();
        let _guard = super::super::policy_file::env_lock();
        let _env = super::super::policy_file::EnvVarGuard::set(
            super::super::policy_file::POLICY_ENV,
            &policy,
        );
        let _home = isolate_home();
        let command = vec!["claude".to_owned()];
        let args = RunArgs {
            agent: Some("claude-code"),
            name: None,
            no_follow_children: false,
            cwd: None,
            env: &[],
            summary: None,
            pin: false,
            no_daemon: true,
            raw: None,
            command: &command,
            json: false,
            quiet: true,
        };
        let deferred = DeferredFlags {
            proxy: false,
            proxy_on_reject: false,
            proxy_on_reject_value: None,
            self_report: false,
            mcp_tap: false,
            unsafe_no_redact: false,
            include_proc: false,
            group: false,
            intercept: false,
        };
        let note = enabled_omitted_note();
        assert!(
            note.is_some(),
            "a rule file with no enabled key produced no stderr note"
        );
        let text = note.unwrap();
        assert!(
            text.contains("enabled") && text.contains("没有打开"),
            "stderr did not say the switch is missing: {text}"
        );
        let mut spec = crate::launch::RunSpec::new(command.clone()).unwrap();
        let injected = inject_claude_intercept(&args, deferred, &mut spec, None)
            .unwrap_or_else(|_| panic!("inject failed"));
        assert!(
            injected.is_none(),
            "a file that never sets enabled must not inject hooks"
        );
        assert!(
            !spec.command.iter().any(|arg| arg == "--settings"),
            "settings were appended: {:?}",
            spec.command
        );

        std::fs::write(&policy, "version = 1\nenabled = false\n").unwrap();
        assert!(
            enabled_omitted_note().is_none(),
            "enabled = false is deliberate and must stay quiet"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A daemon launch already has a public id. The hook command and the child
    /// environment both carry it, so the audit row is not stored with an empty
    /// session. Without an id, neither is invented.
    #[test]
    fn injected_hook_carries_the_daemon_session() {
        let dir = scratch_policy("session");
        let policy = dir.join("policy.toml");
        std::fs::write(&policy, "enabled = true\n[[rule]]\naction = \"deny\"\n").unwrap();
        let _guard = super::super::policy_file::env_lock();
        let _env = super::super::policy_file::EnvVarGuard::set(
            super::super::policy_file::POLICY_ENV,
            &policy,
        );
        let _home = isolate_home();
        let command = vec!["claude".to_owned()];
        let args = RunArgs {
            agent: Some("claude-code"),
            name: None,
            no_follow_children: false,
            cwd: None,
            env: &[],
            summary: None,
            pin: false,
            no_daemon: false,
            raw: None,
            command: &command,
            json: false,
            quiet: true,
        };
        let deferred = DeferredFlags {
            proxy: false,
            proxy_on_reject: false,
            proxy_on_reject_value: None,
            self_report: false,
            mcp_tap: false,
            unsafe_no_redact: false,
            include_proc: false,
            group: false,
            intercept: true,
        };
        let mut spec = crate::launch::RunSpec::new(command.clone()).unwrap();
        let written = match inject_claude_intercept(&args, deferred, &mut spec, Some("s-public")) {
            Ok(Some((dir, _))) => dir,
            Ok(None) => panic!("intercept did not write settings"),
            Err(_) => panic!("intercept settings could not be written"),
        };
        let doc = std::fs::read_to_string(written.join("claude-settings.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&doc).unwrap();
        let args_json = hook_command_args(&value);
        assert_eq!(
            args_json,
            vec![
                "hook".to_owned(),
                "claude-code".to_owned(),
                "--session".to_owned(),
                "s-public".to_owned(),
            ],
            "settings hook args: {doc}"
        );
        assert_eq!(
            spec.env,
            vec![(super::super::hook::SESSION_ENV.to_owned(), "s-public".to_owned())],
            "child env did not receive AW_SESSION"
        );
        let _ = cleanup_intercept_dir(&written);

        let mut bare = crate::launch::RunSpec::new(command.clone()).unwrap();
        let bare_dir = match inject_claude_intercept(&args, deferred, &mut bare, None) {
            Ok(Some((dir, _))) => dir,
            Ok(None) => panic!("intercept did not write settings"),
            Err(_) => panic!("intercept settings could not be written"),
        };
        let bare_doc = std::fs::read_to_string(bare_dir.join("claude-settings.json")).unwrap();
        let bare_value: serde_json::Value = serde_json::from_str(&bare_doc).unwrap();
        assert_eq!(
            hook_command_args(&bare_value),
            vec!["hook".to_owned(), "claude-code".to_owned()],
            "a launch with no session invented one: {bare_doc}"
        );
        assert!(
            bare.env.is_empty(),
            "AW_SESSION was set with no session: {:?}",
            bare.env
        );
        let _ = cleanup_intercept_dir(&bare_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every PreToolUse / PostToolUse hook command in the injected settings.
    fn hook_command_args(value: &serde_json::Value) -> Vec<String> {
        let hooks = value
            .get("hooks")
            .and_then(|hooks| hooks.as_object())
            .expect("settings have no hooks object");
        let mut found = Vec::new();
        for event in ["PreToolUse", "PostToolUse"] {
            let Some(groups) = hooks.get(event).and_then(|entry| entry.as_array()) else {
                continue;
            };
            for group in groups {
                let Some(entries) = group.get("hooks").and_then(|entry| entry.as_array()) else {
                    continue;
                };
                for entry in entries {
                    if entry.get("type").and_then(|kind| kind.as_str()) != Some("command") {
                        continue;
                    }
                    let Some(args) = entry.get("args").and_then(|args| args.as_array()) else {
                        continue;
                    };
                    found.push(
                        args.iter()
                            .filter_map(|arg| arg.as_str().map(str::to_owned))
                            .collect::<Vec<_>>(),
                    );
                }
            }
        }
        assert!(!found.is_empty(), "no hook command args in {value}");
        let first = found[0].clone();
        assert!(
            found.iter().all(|args| args == &first),
            "hook commands disagree: {found:?}"
        );
        first
    }

    /// Scratch policy directory inside this crate, never `/tmp`.
    fn scratch_policy(name: &str) -> std::path::PathBuf {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("run-tests")
            .join(format!(
                "{name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Point the per-user config lookup at an empty directory so a developer's
    /// real `policy.toml` cannot decide this test. Restored on drop.
    fn isolate_home() -> super::super::policy_file::HomeEnvGuard {
        super::super::policy_file::HomeEnvGuard::isolate()
    }

    /// `aw-intercept-<this pid>-*` left in the temp dir by this process.
    fn ours_in_temp() -> Vec<std::path::PathBuf> {
        let prefix = format!("aw-intercept-{}-", std::process::id());
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return found;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(&prefix) {
                found.push(entry.path());
            }
        }
        found.sort();
        found
    }
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

    #[cfg(windows)]
    use super::{Launcher, PlatformLauncher};

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
        release: Option<(&'static str, String)>,
    }

    impl SpawnedChild for FakeChild {
        fn pid(&self) -> u32 {
            self.pid
        }

        fn wait(&mut self) -> Result<i32, String> {
            self.log.borrow_mut().push("wait");
            Ok(self.code)
        }

        fn release(&mut self) -> Result<(), (&'static str, String)> {
            self.log.borrow_mut().push("release");
            self.release.take().map_or(Ok(()), Err)
        }

        fn kill_and_reap(&mut self) {
            self.log.borrow_mut().push("kill");
        }
    }

    struct FakeSpawner {
        log: Rc<RefCell<Vec<&'static str>>>,
        spawned: usize,
        code: i32,
        fail: Option<(&'static str, String)>,
    }

    impl Spawner for FakeSpawner {
        fn spawn(&mut self, _: &RunSpec) -> Result<Box<dyn SpawnedChild>, (&'static str, String)> {
            self.spawned = self.spawned.saturating_add(1);
            self.log.borrow_mut().push("spawn");
            if let Some(error) = self.fail.take() {
                return Err(error);
            }
            Ok(Box::new(FakeChild {
                pid: 71,
                code: self.code,
                log: Rc::clone(&self.log),
                release: None,
            }))
        }
    }

    struct ReleaseFailSpawner {
        log: Rc<RefCell<Vec<&'static str>>>,
        release: (&'static str, String),
    }

    impl Spawner for ReleaseFailSpawner {
        fn spawn(&mut self, _: &RunSpec) -> Result<Box<dyn SpawnedChild>, (&'static str, String)> {
            self.log.borrow_mut().push("spawn");
            Ok(Box::new(FakeChild {
                pid: 71,
                code: 0,
                log: Rc::clone(&self.log),
                release: Some(self.release.clone()),
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
        discards: Vec<String>,
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
                discards: Vec::new(),
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

        fn commit_run(&mut self, _: &LaunchSession) -> Result<(), ControlError> {
            self.log.borrow_mut().push("commit");
            Ok(())
        }

        fn record_exit(&mut self, _: &LaunchSession, _: i32) -> Result<(), ControlError> {
            self.log.borrow_mut().push("exit");
            match self.exit.take() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        fn discard_run(&mut self, session: &LaunchSession) -> Result<(), ControlError> {
            self.log.borrow_mut().push("discard");
            self.discards.push(session.public_id.clone());
            Ok(())
        }

        fn attach(&mut self, _: &AttachRequest) -> Result<SessionHandle, ControlError> {
            Err(ControlError::BadReply {
                detail: "run test must not attach".to_owned(),
            })
        }

        fn stop_monitoring(
            &mut self,
            session: &str,
            _: Option<&str>,
        ) -> Result<String, ControlError> {
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
            intercept: false,
        }
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    /// A rewrite rule prints `allow` plus the new arguments, which Claude Code
    /// treats as approval. The launch says so once, on stderr.
    #[test]
    fn rewrite_rule_is_named_on_stderr() {
        let _guard = super::super::policy_file::env_lock();
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("run-tests")
            .join(format!("rewrite-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let policy = dir.join("policy.toml");
        std::fs::write(
            &policy,
            "enabled = true\n[[rule]]\nid = \"force-dry-run\"\nlayer = [\"hook\"]\n\
             action = \"rewrite\"\nrewrite.command = { replace = [\"a\", \"b\"] }\n",
        )
        .unwrap();
        let _policy = super::super::policy_file::EnvVarGuard::set(
            super::super::policy_file::POLICY_ENV,
            &policy,
        );
        let _home = ["XDG_CONFIG_HOME", "HOME", "APPDATA"]
            .into_iter()
            .map(|key| super::super::policy_file::EnvVarGuard::set_text(key, &dir))
            .collect::<Vec<_>>();
        let command = vec!["claude".to_owned()];
        let mut launcher = FakeLaunch {
            code: 0,
            sampling_seen: None,
            forwarded: Vec::new(),
            env_len: None,
            fail: None,
        };
        let mut summary = FixedSummary(None);
        let outcome = run(
            &args(&command),
            none(),
            &mut UnixAdapter(&mut launcher),
            &mut summary,
        );
        let err = text(&outcome.stderr);
        assert!(err.contains("改写"), "{err}");
        assert!(err.contains("权限确认"), "{err}");
        assert!(!err.contains("上传了"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
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
                assert_eq!(outcome.code, exit::NOT_IN_BUILD);
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
                assert!(err.contains("`--raw` 本版本未接入"), "{err}");
                assert_eq!(launcher.env_len, None);
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
            vec!["begin", "spawn", "adopt", "release", "commit", "pin", "wait", "exit"]
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
            waited_seconds: None,
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
        assert_eq!(
            *log.borrow(),
            vec!["begin", "spawn", "adopt", "kill", "discard"]
        );
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
            vec!["begin", "spawn", "adopt", "release", "commit", "wait", "exit"]
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
        let launched = super::launch_linux(&spec, &mut |_, _, _, _, _| {
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
                kind: None,
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
        let err = super::launch_linux(&spec, &mut |_, _, _, _, _| {
            Err(E::WriteProcsFailed {
                detail: "denied".to_owned(),
            })
        })
        .expect_err("no fallback");
        assert!(err.to_string().contains("cgroup.procs"), "{err}");
    }

    /// The production local launcher uses the held child, so a target which
    /// reads stdin at startup cannot run before it has terminal foreground.
    #[cfg(target_os = "linux")]
    #[test]
    fn production_linux_launcher_uses_the_held_child() {
        use super::Launcher;
        let mut spec = RunSpec::new(vec!["sh".to_owned(), "-c".to_owned(), "exit 6".to_owned()])
            .expect("spec");
        spec.no_daemon = true;
        let launched = super::PlatformLauncher.launch(&spec).expect("launch");
        assert_eq!(launched.code, 6);
        assert_eq!(launched.note, None);
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
        #[cfg(target_os = "linux")]
        let _gate_test_guard = gate_test_guard();
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
        assert_eq!(*log.borrow(), vec!["begin", "adopt", "commit", "exit"]);
        let begin = sessions.seen_begin.expect("begin request");
        assert_eq!(begin.argv, command);
        assert!(text(&outcome.stderr).contains("s-daemon"));
    }

    #[cfg(unix)]
    #[test]
    fn command_spawner_pipe_gate_holds_the_target_until_release() {
        #[cfg(target_os = "linux")]
        let _gate_test_guard = gate_test_guard();
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

    #[cfg(target_os = "linux")]
    #[test]
    fn command_spawner_does_not_leak_the_gate_pipe_into_the_target() {
        let _gate_test_guard = gate_test_guard();
        use std::time::{SystemTime, UNIX_EPOCH};

        let dir = std::env::temp_dir().join(format!(
            "aw-cli-gate-fds-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("test directory");
        // A plain spawn inherits whatever non-CLOEXEC descriptors this test
        // process already holds (runners differ; fd 4 is one such extra). The
        // gate pipe is the only descriptor the spawner may add, and the target
        // must not keep it, so the two fd sets have to match.
        let script = "ls /proc/self/fd > \"$1\"";
        let baseline_path = dir.join("baseline-fds");
        let baseline_status = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .arg("aw-gate-fd-test")
            .arg(&baseline_path)
            .status()
            .expect("baseline spawn");
        assert!(
            baseline_status.success(),
            "baseline ls failed: {baseline_status}"
        );
        let fds = dir.join("target-fds");
        let command = vec![
            "sh".to_owned(),
            "-c".to_owned(),
            script.to_owned(),
            "aw-gate-fd-test".to_owned(),
            fds.to_string_lossy().into_owned(),
        ];
        let spec = RunSpec::new(command).expect("run spec");
        let mut child = super::CommandSpawner.spawn(&spec).expect("held child");
        child.release().expect("release gate");
        assert_eq!(child.wait().expect("wait target"), 0);
        // The gate occupies fd 3 in the shell child (closing whatever the test
        // harness may have inherited there), so the gated target can have
        // fewer descriptors than a plain spawn, never one the plain spawn lacks.
        let gated = listed_fds(&fds);
        let plain = listed_fds(&baseline_path);
        assert!(
            gated.iter().all(|fd| plain.contains(fd)),
            "the gate pipe must not remain in the target: gated {gated:?}, plain {plain:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);

        fn listed_fds(path: &std::path::Path) -> Vec<u32> {
            let mut open_fds: Vec<u32> = std::fs::read_to_string(path)
                .expect("fd list")
                .lines()
                .map(|fd| fd.parse().expect("numeric fd"))
                .collect();
            open_fds.sort_unstable();
            open_fds
        }
    }

    /// `CommandSpawner` uses an inheritable gate descriptor on Linux. These
    /// real-spawn tests must not race each other, or one test's gate can be
    /// inherited while another test is measuring the target descriptors.
    #[cfg(target_os = "linux")]
    fn gate_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static GATE_TEST_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
            std::sync::OnceLock::new();
        GATE_TEST_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Fifty held children, started together from many threads, ten times.
    ///
    /// The old Linux gate cleared `FD_CLOEXEC` on the pipe's read end in this
    /// process and only then called `Command::spawn`. Any sibling spawn in that
    /// window inherited the read end, so the target's `/proc/self/fd` listed two
    /// descriptors a plain spawn did not have, and one of those spawns failed
    /// with 「无法启动程序：发生系统错误」. The hold stage keeps both ends
    /// `CLOEXEC` in the parent and closes the read end before exec, so none of these
    /// targets may see an extra descriptor, and none may fail to start.
    #[cfg(unix)]
    #[test]
    fn command_spawner_concurrent_holds_leak_no_gate_fd() {
        use std::sync::{Arc, Mutex};
        use std::time::{SystemTime, UNIX_EPOCH};

        const ROUNDS: usize = 10;
        const CHILDREN: usize = 50;
        // `/dev/fd` is the same directory on Linux and macOS. `/proc/self/fd`
        // is not there on macOS, so a count taken from it cannot guard the
        // macOS hold path.
        let script = "ls /dev/fd > \"$1\"";
        let dir = std::env::temp_dir().join(format!(
            "aw-cli-gate-concurrent-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("test directory");
        let baseline_path = dir.join("baseline-fds");
        let baseline_status = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .arg("aw-gate-fd-test")
            .arg(&baseline_path)
            .status()
            .expect("baseline spawn");
        assert!(
            baseline_status.success(),
            "baseline ls failed: {baseline_status}"
        );
        let plain = listed_fds(&baseline_path);
        let failures = Arc::new(Mutex::new(Vec::new()));
        for round in 0..ROUNDS {
            let mut threads = Vec::with_capacity(CHILDREN);
            for index in 0..CHILDREN {
                let failures = Arc::clone(&failures);
                let dir = dir.clone();
                let plain = plain.clone();
                threads.push(std::thread::spawn(move || {
                    let fds = dir.join(format!("fds-{round}-{index}"));
                    let command = vec![
                        "sh".to_owned(),
                        "-c".to_owned(),
                        script.to_owned(),
                        "aw-gate-fd-test".to_owned(),
                        fds.to_string_lossy().into_owned(),
                    ];
                    let spec = match RunSpec::new(command) {
                        Ok(spec) => spec,
                        Err(error) => {
                            failures
                                .lock()
                                .expect("failures")
                                .push(format!("round {round} child {index}: spec {error}"));
                            return;
                        }
                    };
                    let mut child = match super::CommandSpawner.spawn(&spec) {
                        Ok(child) => child,
                        Err((_, message)) => {
                            failures
                                .lock()
                                .expect("failures")
                                .push(format!("round {round} child {index}: spawn {message}"));
                            return;
                        }
                    };
                    if let Err((_, message)) = child.release() {
                        failures
                            .lock()
                            .expect("failures")
                            .push(format!("round {round} child {index}: release {message}"));
                        child.kill_and_reap();
                        return;
                    }
                    match child.wait() {
                        Ok(0) => {}
                        Ok(code) => {
                            failures
                                .lock()
                                .expect("failures")
                                .push(format!("round {round} child {index}: exit {code}"));
                            return;
                        }
                        Err(message) => {
                            failures
                                .lock()
                                .expect("failures")
                                .push(format!("round {round} child {index}: wait {message}"));
                            return;
                        }
                    }
                    let gated = listed_fds(&fds);
                    if gated.iter().any(|fd| !plain.contains(fd)) {
                        failures.lock().expect("failures").push(format!(
                            "round {round} child {index}: extra fd gated {gated:?} plain {plain:?}"
                        ));
                    }
                }));
            }
            for thread in threads {
                thread.join().expect("spawner thread");
            }
        }
        let failures = failures.lock().expect("failures");
        assert!(
            failures.is_empty(),
            "{} of {} spawns failed:\n{}",
            failures.len(),
            ROUNDS * CHILDREN,
            failures.join("\n")
        );
        let _ = std::fs::remove_dir_all(&dir);

        fn listed_fds(path: &std::path::Path) -> Vec<u32> {
            let mut open_fds: Vec<u32> = std::fs::read_to_string(path)
                .expect("fd list")
                .lines()
                .filter_map(|fd| fd.parse().ok())
                .collect();
            open_fds.sort_unstable();
            open_fds
        }
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
            waited_seconds: None,
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

    #[cfg(unix)]
    #[test]
    fn no_daemon_spawn_failures_are_each_precise() {
        use super::{typed_spawn_error, CommandSpawner, Spawner};
        use crate::launch::RunSpec;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("aw-resolve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let plain = dir.join("plain");
        std::fs::write(&plain, "x").expect("write");
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let path = format!("{}:/usr/bin:/bin", dir.display());
        // The parent only builds the candidate list. It does not stat, so a
        // non-executable file is still a candidate; the child finds out.
        let sh = aw_platform::unix_program_candidates("sh", Some(&path));
        assert!(
            sh.iter()
                .any(|candidate| candidate == "/usr/bin/sh" || candidate == "/bin/sh"),
            "sh is searched on the absolute PATH entries: {sh:?}"
        );
        let missing = aw_platform::unix_program_candidates("aw-no-such-prog-xyz", Some(&path));
        assert!(missing
            .iter()
            .any(|candidate| candidate.ends_with("/aw-no-such-prog-xyz")));
        let plain_name = aw_platform::unix_program_candidates("plain", Some(&path));
        assert!(plain_name
            .iter()
            .any(|candidate| candidate.ends_with("/plain")));
        // A name containing `/` is one candidate, relative to the target cwd.
        assert_eq!(
            aw_platform::unix_program_candidates("./plain", None),
            vec!["./plain".to_owned()]
        );

        // Through the real spawner. The parent holds the child without looking
        // at the filesystem; the child reports the miss when it is released,
        // and that report is the Chinese sentence with no English in it.
        let spec = RunSpec {
            command: vec!["aw-no-such-prog-xyz".to_owned()],
            cwd: None,
            env: Vec::new(),
            no_follow_children: false,
            allow_breakaway: false,
            no_daemon: false,
        };
        let mut spawned = CommandSpawner
            .spawn(&spec)
            .expect("the parent holds the child; the miss is reported at release");
        let (code, error) = spawned.release().expect_err("a missing program");
        assert_eq!(code, "program_not_found");
        assert_eq!(error, "找不到程序「aw-no-such-prog-xyz」，请检查名字或路径");
        assert!(!error.contains("not found"), "{error}");
        assert!(
            error.contains("找不到程序「aw-no-such-prog-xyz」"),
            "{error}"
        );

        let non_executable = RunSpec {
            command: vec![plain.to_string_lossy().into_owned()],
            cwd: None,
            env: Vec::new(),
            no_follow_children: false,
            allow_breakaway: false,
            no_daemon: false,
        };
        let mut spawned = CommandSpawner
            .spawn(&non_executable)
            .expect("the parent holds the child; permission is reported at release");
        let (code, error) = spawned.release().expect_err("a non-executable program");
        assert_eq!(code, "program_not_permitted");
        assert_eq!(
            error,
            format!(
                "程序「{}」没有执行权限，请检查文件权限后再试。",
                plain.display()
            )
        );

        for (failure, cwd, expected_code, expected) in [
            (
                aw_platform::SpawnFailure::CwdNotFound,
                "/no/such/work",
                "cwd_not_found",
                "找不到工作目录「/no/such/work」",
            ),
            (
                aw_platform::SpawnFailure::CwdNotPermitted,
                "/private/work",
                "cwd_not_permitted",
                "没有权限进入工作目录「/private/work」，请换一个目录或检查权限。",
            ),
        ] {
            assert_eq!(
                typed_spawn_error("tool", Some(cwd), failure),
                (expected_code, expected.to_owned())
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spawn_errors_are_precise_for_the_program_or_directory() {
        use std::io::{Error, ErrorKind};
        let not_found = super::spawn_error_text("npm", None, &Error::from(ErrorKind::NotFound));
        assert_eq!(not_found, "找不到程序「npm」，请检查名字或路径");
        assert_eq!(
            super::spawn_error_code(&Error::from(ErrorKind::NotFound)),
            "program_not_found"
        );
        let denied =
            super::spawn_error_text("/tmp/npm", None, &Error::from(ErrorKind::PermissionDenied));
        assert_eq!(
            denied,
            "程序「/tmp/npm」没有执行权限，请检查文件权限后再试。"
        );
        assert_eq!(
            super::spawn_error_code(&Error::from(ErrorKind::PermissionDenied)),
            "program_not_permitted"
        );
        let other = super::spawn_error_text("npm", None, &Error::from_raw_os_error(7));
        assert_eq!(other, "无法启动程序：发生系统错误");
        assert_eq!(
            super::spawn_error_code(&Error::from_raw_os_error(7)),
            "spawn_failed"
        );
        assert!(!other.contains("系统错误码"), "{other}");
        let wait = super::wait_error_text(&Error::from(ErrorKind::Other));
        assert_eq!(wait, "等待程序结束失败");
        for text in [not_found, denied, other, wait] {
            assert!(
                !text.contains("entity")
                    && !text.contains("could not")
                    && !text.contains("platform_error"),
                "{text}"
            );
        }
    }

    #[test]
    fn spawn_failure_discards_the_uncommitted_session_without_printing_argv() {
        let command = vec!["private-tool".to_owned(), "--secret".to_owned()];
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut sessions = FakeSessions::new(Rc::clone(&log));
        let mut spawner = FakeSpawner {
            log: Rc::clone(&log),
            spawned: 0,
            code: 0,
            fail: Some((
                "spawn_failed",
                super::spawn_error_text(
                    "private-tool",
                    None,
                    &std::io::Error::from(std::io::ErrorKind::Other),
                ),
            )),
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
        assert_eq!(sessions.discards, vec!["s-daemon".to_owned()]);
        let text = text(&outcome.stderr);
        let body: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert_eq!(body["error"]["code"], "spawn_failed");
        assert!(!text.contains("private-tool"), "{text}");
        assert!(!text.contains("--secret"), "{text}");
    }

    #[test]
    fn daemon_backed_run_reports_the_four_precise_spawn_sentences() {
        for (code, expected) in [
            (
                "program_not_found",
                "找不到程序「private-tool」，请检查名字或路径",
            ),
            ("cwd_not_found", "找不到工作目录「/no/such/work」"),
            (
                "program_not_permitted",
                "程序「private-tool」没有执行权限，请检查文件权限后再试。",
            ),
            (
                "cwd_not_permitted",
                "没有权限进入工作目录「/private/work」，请换一个目录或检查权限。",
            ),
        ] {
            let command = vec!["private-tool".to_owned()];
            let log = Rc::new(RefCell::new(Vec::new()));
            let mut sessions = FakeSessions::new(Rc::clone(&log));
            let mut spawner = ReleaseFailSpawner {
                log: Rc::clone(&log),
                release: (code, expected.to_owned()),
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
            assert_eq!(outcome.code, exit::GENERAL, "{code}");
            assert_eq!(sessions.discards, vec!["s-daemon".to_owned()], "{code}");
            assert_eq!(
                *log.borrow(),
                vec!["begin", "spawn", "adopt", "release", "kill", "discard"],
                "{code}"
            );
            let body: serde_json::Value = serde_json::from_slice(&outcome.stderr).expect("json");
            assert_eq!(body["error"]["code"], code, "{code}");
            assert_eq!(body["error"]["message"], expected, "{code}");
        }
    }

    #[test]
    fn identity_failure_uses_the_tuple_code_without_putting_it_in_the_message() {
        let command = vec!["private-tool".to_owned()];
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut sessions = FakeSessions::new(Rc::clone(&log));
        let mut spawner = FakeSpawner {
            log,
            spawned: 0,
            code: 0,
            fail: Some((
                "identity_unavailable",
                "认不出当前用户，已停止启动：无法确认当前用户".to_owned(),
            )),
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
        let body: serde_json::Value = serde_json::from_slice(&outcome.stderr).expect("json");
        assert_eq!(body["error"]["code"], "identity_unavailable");
        assert_eq!(
            body["error"]["message"],
            "认不出当前用户，已停止启动：无法确认当前用户"
        );
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

    #[test]
    fn no_daemon_preserves_the_four_precise_spawn_sentences() {
        for (code, expected) in [
            ("program_not_found", "找不到程序「tool」，请检查名字或路径"),
            ("cwd_not_found", "找不到工作目录「/no/such/work」"),
            (
                "program_not_permitted",
                "程序「/private/tool」没有执行权限，请检查文件权限后再试。",
            ),
            (
                "cwd_not_permitted",
                "没有权限进入工作目录「/private/work」，请换一个目录或检查权限。",
            ),
        ] {
            let command = vec!["tool".to_owned()];
            let mut parsed = args(&command);
            parsed.no_daemon = true;
            parsed.json = true;
            let mut launcher = FakeLaunch {
                code: 0,
                sampling_seen: None,
                forwarded: Vec::new(),
                env_len: None,
                fail: Some(LaunchDispatchError::Spawn {
                    code,
                    detail: expected.to_owned(),
                }),
            };
            let outcome = run(
                &parsed,
                none(),
                &mut UnixAdapter(&mut launcher),
                &mut EmptySummary,
            );
            let body: serde_json::Value = serde_json::from_slice(&outcome.stderr).expect("json");
            assert_eq!(outcome.code, exit::GENERAL, "{code}");
            assert_eq!(body["error"]["code"], code, "{code}");
            assert_eq!(body["error"]["message"], expected, "{code}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_no_daemon_releases_the_held_child_and_keeps_exit_7() {
        let spec = RunSpec::new(vec!["cmd".to_owned(), "/c".to_owned(), "exit 7".to_owned()])
            .expect("spec");
        let launched = PlatformLauncher.launch(&spec).expect("Windows launch");
        assert_eq!(launched.code, 7);
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
