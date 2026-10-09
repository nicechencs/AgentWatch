//! `aw run` (P1-CLI-02).
//!
//! Starts the target as the calling user through an injected [`Launcher`], then
//! prints a session summary. The production launcher does not create a process:
//! on Windows it uses the unverified Job stub, and on other targets it reports
//! that P1-LNX-04 / P1-MAC-03 have not landed. Tests pass a fake and assert the
//! target's exit code comes back unchanged.
//!
//! `--self-report`, `--mcp-tap`, and `--unsafe-no-redact` are refused with a
//! pointer at the later card. `--proxy` is a launch-mode injection plan
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

use aw_proxy::{plan_injection, Injection, ProxyOnReject};

use serde_json::{json, Value};

use crate::exit;
use crate::launch::{self, LaunchDispatchError, Launched, RunSpec, UnixLauncher};

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

/// Windows production launcher. The Job API is the unverified stub, so the
/// first step returns [`crate::launch::LaunchError::NotVerified`] and no
/// process is created.
#[cfg(target_os = "windows")]
#[derive(Debug, Default)]
pub(crate) struct PlatformLauncher;

#[cfg(target_os = "windows")]
impl Launcher for PlatformLauncher {
    fn launch(&mut self, spec: &RunSpec) -> Result<Launched, LaunchDispatchError> {
        let mut api = launch::UnverifiedJobApi;
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

/// Non-Windows production launcher. Names the cards that will provide it.
#[cfg(not(target_os = "windows"))]
#[derive(Debug, Default)]
pub(crate) struct PlatformLauncher;

#[cfg(not(target_os = "windows"))]
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
    let planned = match proxy_plan(args, deferred) {
        Ok(planned) => planned,
        Err(detail) => {
            return super::error_outcome(exit::USAGE, "usage", &detail, args.json);
        }
    };
    // The production launcher does not create the child (P1-WIN-04 is still the
    // unverified stub). Printing the plan and then calling it would turn a
    // successful plan into a launch error, so a proxy plan stops here. No
    // process is created, which is also what the child-start gap requires.
    if let Some(plan) = &planned {
        let mut stderr = Vec::new();
        if let Err(err) = write_proxy_plan(&mut stderr, plan) {
            return super::error_outcome(exit::GENERAL, "proxy", &err.to_string(), args.json);
        }
        return Outcome {
            code: exit::GENERAL,
            stdout: Vec::new(),
            stderr,
        };
    }
    if let Some(detail) = deferred_reason(deferred) {
        return super::error_outcome(exit::GENERAL, "not_available", &detail, args.json);
    }
    let level = match parse_summary(args.summary) {
        Ok(level) => level,
        Err(detail) => {
            return super::error_outcome(exit::USAGE, "usage", &detail, args.json);
        }
    };
    let env = match split_env(args.env) {
        Ok(pairs) => pairs,
        Err(detail) => {
            return super::error_outcome(exit::USAGE, "usage", &detail, args.json);
        }
    };
    let mut spec = match RunSpec::new(args.command.to_vec()) {
        Ok(spec) => spec,
        Err(err) => {
            return super::error_outcome(exit::USAGE, "usage", &err.to_string(), args.json);
        }
    };
    spec.cwd = args.cwd.map(str::to_owned);
    spec.env = env;
    spec.no_follow_children = args.no_follow_children;
    spec.no_daemon = args.no_daemon;

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
    if let Err(err) = write_summary(&mut stderr, args, level, &launched, &figures) {
        return super::error_outcome(exit::GENERAL, "summary", &err.to_string(), args.json);
    }
    Outcome {
        code: launched.code,
        stdout: Vec::new(),
        stderr,
    }
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
const PROXY_PLAN_NOTE: &str = "子进程启动尚未接入，本次只给出注入计划，没有设置系统代理，没有改证书库";

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
    writeln!(out, "[aw] 代理端口：{PROXY_PORT_UNBOUND}。未绑定的端口不会被印成可用代理")?;
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
    let mut which = Vec::new();
    if flags.self_report {
        which.push("--self-report");
    }
    if flags.mcp_tap {
        which.push("--mcp-tap");
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
        "{} is not available in this build (P3/P5 提供); nothing was launched",
        which.join(", ")
    ))
}

fn parse_summary(text: Option<&str>) -> Result<SummaryLevel, String> {
    match text {
        None | Some("short") => Ok(SummaryLevel::Short),
        Some("none") => Ok(SummaryLevel::None),
        Some("full") => Ok(SummaryLevel::Full),
        Some(other) => Err(format!(
            "--summary `{other}` is not one of none, short, full"
        )),
    }
}

/// Split `KEY=VALUE`. The value is kept for the launcher and never formatted.
fn split_env(raw: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut pairs = Vec::with_capacity(raw.len());
    for item in raw {
        let Some((key, value)) = item.split_once('=') else {
            return Err(
                "--env entry is missing '='; pass KEY=VALUE (the value is not shown)".to_owned(),
            );
        };
        if key.is_empty()
            || key
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_'))
        {
            return Err("--env name must be ASCII letters, digits, or '_'".to_owned());
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
) -> io::Result<()> {
    if args.json {
        let body = summary_json(args, launched, figures);
        let mut bytes = serde_json::to_vec(&body)
            .map_err(|err| io::Error::other(format!("encode summary: {err}")))?;
        bytes.push(b'\n');
        // The summary is an `[aw]` side channel. JSON still goes to stderr so the
        // target's own stdout stays untouched.
        return out.write_all(&bytes);
    }
    match figures {
        Ok(Some(summary)) => {
            let processes = count_text(summary.processes);
            let up = bytes_text(summary.bytes_up);
            let down = bytes_text(summary.bytes_down);
            let gaps = count_text(summary.gaps);
            let domains = domain_text(&summary.top_domains);
            let session = summary
                .session_id
                .as_deref()
                .or(args.name)
                .unwrap_or("未命名");
            writeln!(
                out,
                "[aw] 会话 {session} 结束 · 进程 {processes} · 上传 {up} · 下载 {down} · Top 域名 {domains} · 缺口 {gaps}"
            )?;
            // The level note is part of the summary at every level except `none`
            // (api-and-cli §2.1 asks for 等级说明).
            writeln!(out, "[aw] {}", summary.level_note)?;
            if level == SummaryLevel::Full {
                writeln!(
                    out,
                    "[aw] 摘要级别 full · 域名列出前 5 个 · 未知的计数显示为不可得，不显示为 0"
                )?;
            }
            if launched.sampling {
                writeln!(out, "[aw] 采样模式 · 等级 S · 短事件可能未被采到")?;
            }
        }
        Ok(None) => {
            writeln!(
                out,
                "[aw] 摘要不可用 · 本构建没有会话存储，不能用 0 表示未知"
            )?;
        }
        Err(detail) => {
            writeln!(out, "[aw] 摘要不可用 · {detail}")?;
        }
    }
    if args.pin {
        writeln!(out, "[aw] 会话已标记为保留，不参与自动清理")?;
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
) -> Value {
    match figures {
        Ok(Some(summary)) => json!({
            "available": true,
            "session": summary.session_id,
            "processes": summary.processes,
            "bytes_up": summary.bytes_up,
            "bytes_down": summary.bytes_down,
            "top_domains": summary.top_domains.iter().take(5).map(|item| json!({
                "name": item.name,
                "flows": item.flows,
            })).collect::<Vec<_>>(),
            "gaps": summary.gaps,
            "level_note": summary.level_note,
            "sampling": launched.sampling,
            "pinned": args.pin,
            "target_exit": launched.code,
        }),
        Ok(None) => json!({
            "available": false,
            "reason": "摘要不可用",
            "sampling": launched.sampling,
            "target_exit": launched.code,
        }),
        Err(detail) => json!({
            "available": false,
            "reason": detail,
            "sampling": launched.sampling,
            "target_exit": launched.code,
        }),
    }
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
    use super::{
        run, DeferredFlags, DomainCount, EmptySummary, RunArgs, SessionSummary, Summary,
        UnixAdapter,
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
        assert!(err.contains("Top 域名 不可得"), "{err}");
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
    fn env_values_never_appear_in_the_summary() {
        let command = vec!["tool".to_owned(), "--secret".to_owned()];
        let env = vec!["TOKEN=super-secret-value".to_owned()];
        let mut ran = args(&command);
        ran.env = &env;
        let mut launcher = FakeLaunch {
            code: 0,
            sampling_seen: None,
            forwarded: Vec::new(),
            env_len: None,
            fail: None,
        };
        let mut summary = EmptySummary;
        let outcome = run(&ran, none(), &mut UnixAdapter(&mut launcher), &mut summary);
        let err = text(&outcome.stderr);
        assert!(!err.contains("super-secret-value"), "{err}");
        assert!(!err.contains("--secret"), "{err}");
        assert!(!err.contains("TOKEN"), "{err}");
        assert_eq!(launcher.env_len, Some(1));
    }

    #[test]
    fn no_daemon_marks_sampling_mode() {
        let command = vec!["tool".to_owned()];
        let mut ran = args(&command);
        ran.no_daemon = true;
        ran.summary = Some("full");
        let mut launcher = FakeLaunch {
            code: 0,
            sampling_seen: None,
            forwarded: Vec::new(),
            env_len: None,
            fail: None,
        };
        let mut summary = FixedSummary(Some(sample_summary()));
        let outcome = run(&ran, none(), &mut UnixAdapter(&mut launcher), &mut summary);
        let err = text(&outcome.stderr);
        assert!(err.contains("采样模式"), "{err}");
        assert!(err.contains('S'), "{err}");
        assert_eq!(launcher.sampling_seen, Some(true));
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
