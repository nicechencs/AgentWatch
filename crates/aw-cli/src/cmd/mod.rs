//! Command dispatch (P1-CLI-01).
//!
//! This card only routes. A recognised command that is not `version` probes the
//! daemon with `GET /health` and then reports that the command is not implemented.
//! Unreachable is exit 3. A 2xx health check followed by "not implemented" is
//! exit 1, so a live daemon is never a silent success.

mod around;
mod attach;
mod config;
mod config_rules;
mod daemon;
mod db;
mod doctor;
mod export;
mod files;
mod findings;
mod flows;
mod gaps;
mod hook;
mod http;
mod procs;
mod proxy;
mod ps;
mod query;
mod render;
mod run;
mod search;
mod sessions;
mod stop;
mod timeline;
mod tree;

use std::io::{self, Write};

use clap::error::ErrorKind;
use clap::Parser;

use crate::client::{ApiRequest, Client, ClientError, LoopbackHttp, Transport};
use crate::endpoint::{self, Endpoint, EndpointError, EndpointInput};
use crate::exit::{self, from_http_status};
use crate::output::OutputMode;

use self::query::{QuerySource, UnavailableSource};
use self::tree::{command_label, Cli, Command};

/// What one invocation printed and which code it would exit with.
pub(crate) struct Outcome {
    /// Process exit code.
    pub code: i32,
    /// Bytes for stdout.
    pub stdout: Vec<u8>,
    /// Bytes for stderr.
    pub stderr: Vec<u8>,
}

/// Open the HTTP transport for one resolved endpoint. Tests substitute a stub.
pub(crate) trait HttpFactory {
    /// Build a transport. Called only for an HTTP endpoint, and only when a
    /// command is about to probe the daemon.
    fn open(&mut self, endpoint: &Endpoint) -> Result<Box<dyn Transport>, ClientError>;
}

/// Production factory. Dials inside [`LoopbackHttp::exchange`], not here.
struct LiveHttp;

impl HttpFactory for LiveHttp {
    fn open(&mut self, endpoint: &Endpoint) -> Result<Box<dyn Transport>, ClientError> {
        Ok(Box::new(LoopbackHttp::new(endpoint)?))
    }
}

/// Parse `args` (without argv0), read `AW_TOKEN`, and dispatch.
///
/// Query commands (`sessions`, `timeline`, `procs`, `flows`, `gaps`, `files`,
/// `around`, `search`) read an injected [`QuerySource`]. The production source
/// reports that the daemon query API is not connected. They do not probe
/// `/health`. `db` and `config` call an injected API client instead of a store.
///
/// # Errors
///
/// Only a failure to write the outcome. The process exit code is [`Outcome::code`].
pub(crate) fn execute_args(args: &[String]) -> io::Result<Outcome> {
    let env_token = EndpointInput::from_args(None, None, None).token_env;
    let mut source = UnavailableSource;
    execute_args_with(args, env_token, &mut LiveHttp, &mut source)
}

/// Same as [`execute_args`], with the token, HTTP factory, and query source injected.
///
/// `env_token` is the value tests would have put in `AW_TOKEN`. Passing it here
/// keeps tests from mutating the process environment. `source` answers the five
/// query commands; other commands ignore it.
pub(crate) fn execute_args_with(
    args: &[String],
    env_token: Option<String>,
    http: &mut dyn HttpFactory,
    source: &mut dyn QuerySource,
) -> io::Result<Outcome> {
    match Cli::try_parse_from(std::iter::once("aw".to_owned()).chain(args.iter().cloned())) {
        Ok(cli) => dispatch(cli, env_token, http, source),
        Err(err) => Ok(usage_outcome(err)),
    }
}

fn usage_outcome(err: clap::Error) -> Outcome {
    let code = match err.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => exit::OK,
        _ => exit::USAGE,
    };
    let message = err.render().to_string();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if code == exit::OK {
        stdout.extend(message.into_bytes());
    } else {
        stderr.extend(message.into_bytes());
    }
    Outcome {
        code,
        stdout,
        stderr,
    }
}

fn dispatch(
    cli: Cli,
    env_token: Option<String>,
    http: &mut dyn HttpFactory,
    source: &mut dyn QuerySource,
) -> io::Result<Outcome> {
    let json = cli.json;
    // `--lang` selects the wording table for `findings` and `config rules test`.
    // `-q` and `-v` are part of the tree. This card does not branch on them.
    let lang = cli.lang.as_deref();
    let _quiet = cli.quiet;
    let _verbose = cli.verbose;

    if let Command::Version { check } = &cli.command {
        return Ok(version_outcome(*check, json));
    }
    if let Some(outcome) = hook_command(&cli, env_token.as_deref()) {
        return Ok(outcome);
    }
    if let Some(outcome) = proxy_command(&cli.command, json) {
        return Ok(outcome);
    }
    if let Some(outcome) = launch_command(&cli, json) {
        return Ok(outcome);
    }
    if let Some(outcome) = query_command(&cli.command, json, lang, source)? {
        return Ok(outcome);
    }
    if let Some(outcome) = ops_command(&cli.command, json, lang) {
        return Ok(outcome);
    }
    if let Some(detail) = usage_gap(&cli.command) {
        return Ok(error_outcome(exit::USAGE, "usage", &detail, json));
    }

    let input = EndpointInput {
        socket: cli.socket.clone(),
        http: cli.http.clone(),
        token: cli.token.clone(),
        token_env: env_token,
    };
    let endpoint = match endpoint::resolve(&input) {
        Ok(endpoint) => endpoint,
        Err(err) => return Ok(endpoint_outcome(err, json)),
    };

    let label = command_label(&cli.command);
    match probe(&endpoint, http) {
        Ok(()) => Ok(error_outcome(
            exit::GENERAL,
            "not_implemented",
            &format!("`{label}` is not implemented yet (尚未实现)"),
            json,
        )),
        Err(err) => Ok(client_outcome(err, &endpoint, json)),
    }
}

/// `aw hook` (P5-AGENT-02). Always exit 0, before any daemon probe.
///
/// A usage error (missing `<AGENT>`) never reaches here: clap rejects it first.
/// Daemon flags on the same command line are forwarded so the hook can find the
/// listener. Failure to find it is still exit 0.
fn hook_command(cli: &Cli, env_token: Option<&str>) -> Option<Outcome> {
    let Command::Hook { agent, session } = &cli.command else {
        return None;
    };
    let env_session = std::env::var(hook::SESSION_ENV).ok();
    let input = EndpointInput {
        socket: cli.socket.clone(),
        http: cli.http.clone(),
        token: cli.token.clone(),
        token_env: env_token.map(str::to_owned),
    };
    Some(hook::run_from_stdio(
        agent,
        session.as_deref(),
        env_session.as_deref(),
        &input,
    ))
}

/// `aw proxy` (P3-PROXY-01). Does not read `ca.key` and does not probe `/health`.
fn proxy_command(command: &Command, json: bool) -> Option<Outcome> {
    let Command::Proxy(cmd) = command else {
        return None;
    };
    // `--confirm` is not on the shared clap tree. Without it, `trust` / `untrust`
    // stop at the prompt and do not call a certificate tool.
    Some(proxy::run(cmd, json, false, &mut proxy::UnwiredProxy))
}

/// `run`, `attach`, `stop`, and `ps` (P1-CLI-02).
///
/// These do not probe `/health`. Each one calls an injected trait; the
/// production values start no process and open no daemon session. `None` for
/// every other command.
///
/// `usage_gap` still runs first for an empty `run` or an `attach` with neither
/// `--pid` nor `--name`, via the check below this function's caller. An empty
/// command never reaches here: `usage_gap` is checked before the health probe,
/// and this branch returns only when the command is one of the four.
fn launch_command(cli: &Cli, json: bool) -> Option<Outcome> {
    // Argument errors stay on the usage path so they do not look like a launch.
    if usage_gap(&cli.command).is_some() {
        return None;
    }
    match &cli.command {
        Command::Run {
            agent,
            name,
            proxy,
            proxy_on_reject,
            no_follow_children,
            include_proc,
            self_report,
            cwd,
            env_vars,
            summary,
            pin,
            group,
            mcp_tap,
            no_daemon,
            raw,
            unsafe_no_redact,
            cmd,
        } => {
            let args = run::RunArgs {
                agent: agent.as_deref(),
                name: name.as_deref(),
                no_follow_children: *no_follow_children,
                cwd: cwd.as_deref(),
                env: env_vars,
                summary: summary.as_deref(),
                pin: *pin,
                no_daemon: *no_daemon,
                raw: raw.as_deref(),
                command: cmd,
                json,
                quiet: cli.quiet,
            };
            let deferred = run::DeferredFlags {
                proxy: *proxy,
                proxy_on_reject: proxy_on_reject.is_some(),
                proxy_on_reject_value: proxy_on_reject.as_deref(),
                self_report: self_report.is_some(),
                mcp_tap: *mcp_tap,
                unsafe_no_redact: *unsafe_no_redact,
                include_proc: !include_proc.is_empty(),
                group: group.is_some(),
            };
            Some(run::run(
                &args,
                deferred,
                &mut run::PlatformLauncher,
                &mut run::EmptySummary,
            ))
        }
        Command::Attach {
            pid,
            name,
            no_follow_children,
            no_existing_children,
            move_to_cgroup,
            agent,
            pin,
            group,
            until_exit,
            duration,
        } => {
            let args = attach::AttachArgs {
                pid: *pid,
                name: name.as_deref(),
                no_follow_children: *no_follow_children,
                no_existing_children: *no_existing_children,
                move_to_cgroup: *move_to_cgroup,
                until_exit: *until_exit,
                duration: duration.as_deref(),
                agent: agent.as_deref(),
                pin: *pin,
                group: group.as_deref(),
                json,
            };
            Some(attach::run(&args, &mut attach::UnwiredControl))
        }
        Command::Stop { session } => Some(stop::run(session, json, &mut attach::UnwiredControl)),
        Command::Ps {
            agents_only,
            filter,
        } => Some(ps::run(
            *agents_only,
            filter.as_deref(),
            json,
            &mut ps::UnwiredTable,
        )),
        _ => None,
    }
}

/// `sessions`, `timeline`, `procs`, `flows`, `gaps`, `files`, `around`, `search`,
/// `http`, and `findings`. `None` for every other command.
///
/// These do not open an HTTP transport. `http` and `findings` use the same
/// [`QuerySource`] as the other query commands (P3-CLI-01). The production source
/// returns `Unavailable` instead of an empty list, so they never reach the
/// health probe.
fn query_command(
    command: &Command,
    json: bool,
    lang: Option<&str>,
    source: &mut dyn QuerySource,
) -> io::Result<Option<Outcome>> {
    match command {
        Command::Sessions(cmd) => Ok(Some(sessions::run(cmd, json, source)?)),
        Command::Timeline {
            session,
            filter,
            from,
            to,
            follow,
            limit,
        } => Ok(Some(timeline::run(
            timeline::TimelineArgs {
                session,
                filter: filter.as_deref(),
                from: from.as_deref(),
                to: to.as_deref(),
                follow: *follow,
                limit: *limit,
                json,
                color: false,
            },
            source,
        )?)),
        Command::Procs { session, tree, .. } => Ok(Some(procs::run(session, *tree, json, source)?)),
        Command::Flows {
            session,
            group_by,
            sort,
            ..
        } => Ok(Some(flows::run(
            session,
            group_by.as_deref(),
            sort.as_deref(),
            json,
            source,
        )?)),
        Command::Gaps { session } => Ok(Some(gaps::run(session, json, source)?)),
        Command::Files {
            session,
            filter,
            group_by,
            sort,
        } => Ok(Some(files::run(
            files::FilesArgs {
                session,
                filter: filter.as_deref(),
                group_by: group_by.as_deref(),
                sort: sort.as_deref(),
                json,
                color: false,
            },
            source,
        )?)),
        Command::Around {
            session,
            reference,
            window,
        } => Ok(Some(around::run(
            around::AroundArgs {
                session,
                reference,
                window: window.as_deref(),
                json,
                color: false,
            },
            source,
        )?)),
        Command::Search { text, since, kind } => Ok(Some(search::run(
            search::SearchArgs {
                text,
                since: since.as_deref(),
                kind: kind.as_deref(),
                json,
                color: false,
            },
            source,
        )?)),
        Command::Http { session, filter } => Ok(Some(http::run(
            http::HttpArgs {
                session,
                filter: filter.as_deref(),
                json,
            },
            source,
        )?)),
        Command::Findings {
            session,
            min_severity,
            evidence,
            lang: finding_lang,
        } => Ok(Some(findings::run(
            findings::FindingsArgs {
                session,
                min_severity: min_severity.as_deref(),
                evidence: evidence.as_deref(),
                lang: finding_lang.as_deref().or(lang),
                json,
            },
            source,
        )?)),
        _ => Ok(None),
    }
}

/// `export`, `doctor`, `daemon`, and `db` (P1-CLI-04).
///
/// These do not open an HTTP transport and do not touch a service manager or a
/// database. Each command calls an injected trait; the production values are
/// empty stubs. `None` for every other command.
fn ops_command(command: &Command, json: bool, lang: Option<&str>) -> Option<Outcome> {
    let privilege = daemon::NotAdmin;
    match command {
        Command::Export {
            session,
            format,
            output,
            filter,
            redact_paths,
            redact_hosts,
            ..
        } => Some(export::run(
            export::ExportArgs {
                session,
                format: format.as_deref(),
                output: output.as_deref(),
                filter: filter.as_deref(),
                redact_paths: *redact_paths,
                redact_hosts: *redact_hosts,
                json,
            },
            &mut export::EmptyExport,
        )),
        Command::Doctor { perf } => Some(doctor::run(*perf, json, &mut doctor::Unprobed)),
        Command::Daemon(cmd) => {
            let op = match cmd {
                tree::DaemonCmd::Status => daemon::DaemonOp::Status,
                tree::DaemonCmd::Start => daemon::DaemonOp::Start,
                tree::DaemonCmd::Stop => daemon::DaemonOp::Stop,
                tree::DaemonCmd::Restart => daemon::DaemonOp::Restart,
                tree::DaemonCmd::Install { yes } => daemon::DaemonOp::Install { confirm: *yes },
                tree::DaemonCmd::Uninstall { purge, check } => daemon::DaemonOp::Uninstall {
                    purge: *purge,
                    check: *check,
                },
                tree::DaemonCmd::Logs { follow } => daemon::DaemonOp::Logs { follow: *follow },
            };
            Some(daemon::run(
                op,
                json,
                &privilege,
                &mut daemon::PlannedControl,
            ))
        }
        Command::Db(cmd) => {
            let op = match cmd {
                tree::DbCmd::Stats => db::DbOp::Stats,
                tree::DbCmd::Vacuum => db::DbOp::Vacuum,
                tree::DbCmd::Migrate { dry_run } => db::DbOp::Migrate { dry_run: *dry_run },
                tree::DbCmd::Purge {
                    older_than,
                    all,
                    yes,
                } => db::DbOp::Purge {
                    older_than: older_than.clone(),
                    all: *all,
                    yes: *yes,
                },
            };
            // Production has no daemon client and no TTY. `vacuum` and `purge`
            // therefore refuse unless the caller already passed `--yes` (purge)
            // or is calling `db::run` from a test that injects both. Stats and
            // migrate still answer from the unwired client (exit 3).
            Some(db::run(
                op,
                json,
                &privilege,
                &db::FixedClock(0),
                &mut db::UnwiredApi,
                &mut db::NotInteractive,
            ))
        }
        // `rules list` and `rules test` load files offline. They do not call the
        // unwired config client, so a down daemon is not exit 3 for them.
        Command::Config(tree::ConfigCmd::Rules(tree::RulesCmd::List)) => {
            Some(config_rules::list(json))
        }
        Command::Config(tree::ConfigCmd::Rules(tree::RulesCmd::Test {
            rule,
            fixture,
            expect,
        })) => Some(config_rules::test(
            rule,
            fixture,
            expect.as_deref(),
            lang,
            json,
        )),
        Command::Config(cmd) => Some(config::run(cmd, json, &mut config::UnwiredConfig)),
        _ => None,
    }
}

/// Commands whose own arguments are already wrong. These do not contact the daemon.
fn usage_gap(command: &Command) -> Option<String> {
    match command {
        Command::Run { cmd, .. } if cmd.is_empty() => {
            Some("`aw run` needs a command after the flags".to_owned())
        }
        Command::McpTap { cmd, .. } if cmd.is_empty() => {
            Some("`aw mcp-tap` needs a command to wrap".to_owned())
        }
        Command::Dev { args, .. } if args.is_empty() => {
            Some("`aw dev` needs the arguments of the single-process mode".to_owned())
        }
        Command::Attach { pid, name, .. } if pid.is_none() && name.is_none() => {
            Some("`aw attach` needs --pid or --name".to_owned())
        }
        _ => None,
    }
}

fn version_outcome(check: bool, json: bool) -> Outcome {
    if check {
        return error_outcome(
            exit::GENERAL,
            "not_implemented",
            "`aw version --check` does not contact the network and is not implemented yet (尚未实现)",
            json,
        );
    }
    let text = if json {
        "{\"version\":\"0.1.0\"}\n".to_owned()
    } else {
        "aw 0.1.0\n".to_owned()
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

/// `GET /health`. Socket and pipe endpoints fail inside [`Client::call`] and never
/// call `open`. A 2xx body is discarded: the command itself is still a stub.
fn probe(endpoint: &Endpoint, http: &mut dyn HttpFactory) -> Result<(), ClientError> {
    let transport: Box<dyn Transport> = match endpoint {
        Endpoint::Http { .. } => http.open(endpoint)?,
        Endpoint::Unix { .. } | Endpoint::Pipe { .. } => {
            Box::new(crate::client::MemoryTransport::default())
        }
    };
    let mut client = Client::new(endpoint.clone(), transport);
    let _reply = client.call(&ApiRequest::get("/health"))?;
    Ok(())
}

fn endpoint_outcome(err: EndpointError, json: bool) -> Outcome {
    let (code, machine) = match &err {
        EndpointError::MissingToken => (exit::GENERAL, "missing_token"),
        EndpointError::BadHttpUrl { .. } | EndpointError::NoPlatformDefault => {
            (exit::USAGE, "usage")
        }
    };
    error_outcome(code, machine, &err.to_string(), json)
}

fn client_outcome(err: ClientError, endpoint: &Endpoint, json: bool) -> Outcome {
    let code = err.exit_code();
    let machine = match &err {
        ClientError::Unreachable { .. } => "unreachable",
        ClientError::Transport { .. } => "transport",
        ClientError::Status { status, .. } => match *status {
            401 => "unauthorized",
            403 => "forbidden",
            421 => "misdirected",
            _ => "status",
        },
    };
    let mut message = err.to_string();
    if matches!(err, ClientError::Status { .. }) {
        message.push_str("; ");
        message.push_str(&endpoint.to_string());
    }
    // `from_http_status` is what `ClientError::exit_code` uses. Keep the call so
    // a status this match does not name still maps.
    let _ = from_http_status;
    error_outcome(code, machine, &message, json)
}

pub(crate) fn error_outcome(code: i32, machine: &str, message: &str, json: bool) -> Outcome {
    let text = if json {
        let body = serde_json::json!({
            "error": { "code": machine, "message": message }
        });
        format!("{body}\n")
    } else {
        format!("aw: {message}\n")
    };
    Outcome {
        code,
        stdout: Vec::new(),
        stderr: text.into_bytes(),
    }
}

impl Outcome {
    /// Write stdout and stderr. The caller exits with [`Outcome::code`].
    ///
    /// # Errors
    ///
    /// A short write on either stream.
    pub(crate) fn write_to(
        &self,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
    ) -> io::Result<()> {
        stdout.write_all(&self.stdout)?;
        stderr.write_all(&self.stderr)?;
        Ok(())
    }
}

/// Render mode selected by `--json`. Commands that print tables use this later.
#[must_use]
#[allow(dead_code)]
pub(crate) fn output_mode(json: bool) -> OutputMode {
    OutputMode::from_json_flag(json)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{execute_args_with, output_mode, HttpFactory, Outcome};
    use crate::client::{ApiReply, ClientError, MemoryTransport, Transport};
    use crate::endpoint::Endpoint;
    use crate::exit;
    use crate::output::OutputMode;
    use std::cell::RefCell;
    use std::rc::Rc;

    const TOKEN: &str = "cli-test-token-WXYZ";

    struct Script {
        status: u16,
        body: Vec<u8>,
        opened: u32,
        seen: Rc<RefCell<Vec<String>>>,
    }

    impl HttpFactory for Script {
        fn open(&mut self, endpoint: &Endpoint) -> Result<Box<dyn Transport>, ClientError> {
            let shown = endpoint.to_string();
            assert!(
                !shown.contains(TOKEN),
                "factory must not observe the full token: {shown}"
            );
            let paths = Rc::clone(&self.seen);
            self.opened += 1;
            let status = self.status;
            let body = self.body.clone();
            Ok(Box::new(Recording {
                inner: MemoryTransport::replying(status, body),
                paths,
            }))
        }
    }

    struct Recording {
        inner: MemoryTransport,
        paths: Rc<RefCell<Vec<String>>>,
    }

    impl Transport for Recording {
        fn exchange(
            &mut self,
            request: &crate::client::ApiRequest,
        ) -> Result<ApiReply, ClientError> {
            self.paths.borrow_mut().push(request.path.clone());
            self.inner.exchange(request)
        }
    }

    fn script(status: u16, body: &str) -> Script {
        Script {
            status,
            body: body.as_bytes().to_vec(),
            opened: 0,
            seen: Rc::new(RefCell::new(Vec::new())),
        }
    }

    fn paths(http: &Script) -> Vec<String> {
        http.seen.borrow().clone()
    }

    fn run(args: &[&str], env_token: Option<&str>, http: &mut Script) -> Outcome {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        let mut source = super::query::UnavailableSource;
        execute_args_with(&owned, env_token.map(str::to_owned), http, &mut source)
            .expect("dispatch")
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    #[test]
    fn health_200_then_unimplemented_is_exit_1() {
        let mut http = script(200, r#"{"status":"ok"}"#);
        // `ps` is implemented (P1-CLI-02) and does not probe `/health`.
        // `ui` is still a stub, so a live daemon stays exit 1.
        let outcome = run(
            &["--http", "http://127.0.0.1:7456", "--token", TOKEN, "ui"],
            None,
            &mut http,
        );
        assert_eq!(outcome.code, exit::GENERAL);
        let err = text(&outcome.stderr);
        assert!(err.contains("not implemented"), "{err}");
        assert!(err.contains("尚未实现"), "{err}");
        assert!(!err.contains(TOKEN), "{err}");
        assert_eq!(http.opened, 1);
        assert_eq!(paths(&http), vec!["/health".to_owned()]);
    }

    #[test]
    fn health_401_is_exit_4_and_shows_only_the_hint() {
        let mut http = script(
            401,
            r#"{"error":{"code":"unauthorized","message":"bearer token required"}}"#,
        );
        let outcome = run(
            &["--http", "http://127.0.0.1:7456", "--token", TOKEN, "ui"],
            None,
            &mut http,
        );
        assert_eq!(outcome.code, exit::PERMISSION);
        let err = text(&outcome.stderr);
        assert!(err.contains("401"), "{err}");
        assert!(err.contains("len=19"), "{err}");
        assert!(err.contains("WXYZ"), "{err}");
        assert!(!err.contains(TOKEN), "{err}");
        assert_eq!(paths(&http), vec!["/health".to_owned()]);
    }

    #[test]
    fn missing_token_does_not_open_a_transport() {
        let mut http = script(200, r#"{"status":"ok"}"#);
        let outcome = run(&["--http", "http://127.0.0.1:7456", "ui"], None, &mut http);
        assert_eq!(outcome.code, exit::GENERAL);
        let err = text(&outcome.stderr);
        assert!(err.contains("AW_TOKEN") || err.contains("missing"), "{err}");
        assert!(err.contains("token"), "{err}");
        assert_eq!(http.opened, 0);
        assert!(paths(&http).is_empty());
    }

    #[test]
    fn env_token_is_accepted_and_still_hidden() {
        let mut http = script(200, r#"{"status":"ok"}"#);
        let outcome = run(
            &["--http", "http://localhost:7456", "sessions", "list"],
            Some(TOKEN),
            &mut http,
        );
        // `sessions` is a query command. It does not probe `/health`; the
        // production source reports that the daemon query API is not connected.
        assert_eq!(outcome.code, exit::GENERAL);
        let err = text(&outcome.stderr);
        assert!(
            err.contains("not connected") || err.contains("stub"),
            "{err}"
        );
        assert!(!err.contains(TOKEN), "{err}");
        assert_eq!(http.opened, 0);
    }

    #[test]
    fn default_socket_is_unreachable_and_does_not_open() {
        let mut http = script(200, r#"{"status":"ok"}"#);
        let outcome = run(&["ui"], None, &mut http);
        assert_eq!(outcome.code, exit::UNREACHABLE);
        let err = text(&outcome.stderr);
        assert!(err.contains("aw daemon start"), "{err}");
        assert!(err.contains("--no-daemon"), "{err}");
        assert_eq!(http.opened, 0);
    }

    #[test]
    fn version_does_not_contact_the_daemon() {
        let mut http = script(200, r#"{"status":"ok"}"#);
        let outcome = run(&["version"], None, &mut http);
        assert_eq!(outcome.code, exit::OK);
        assert_eq!(text(&outcome.stdout), "aw 0.1.0\n");
        assert_eq!(http.opened, 0);

        let check = run(&["version", "--check"], None, &mut http);
        assert_eq!(check.code, exit::GENERAL);
        let err = text(&check.stderr);
        assert!(err.contains("does not contact the network"), "{err}");
        assert!(err.contains("尚未实现"), "{err}");
        assert_eq!(http.opened, 0);
    }

    #[test]
    fn empty_run_is_usage_and_does_not_open() {
        let mut http = script(200, "{}");
        let outcome = run(&["run"], None, &mut http);
        assert_eq!(outcome.code, exit::USAGE);
        assert_eq!(http.opened, 0);
        let attach = run(&["attach"], None, &mut http);
        assert_eq!(attach.code, exit::USAGE);
        assert_eq!(http.opened, 0);
    }

    #[test]
    fn port_zero_is_usage() {
        let mut http = script(200, "{}");
        let outcome = run(
            &["--http", "http://127.0.0.1:0", "--token", TOKEN, "ui"],
            None,
            &mut http,
        );
        assert_eq!(outcome.code, exit::USAGE);
        assert!(
            text(&outcome.stderr).contains("port 0"),
            "{}",
            text(&outcome.stderr)
        );
        assert!(!text(&outcome.stderr).contains(TOKEN));
        assert_eq!(http.opened, 0);
    }

    #[test]
    fn json_errors_use_the_machine_code() {
        let mut http = script(200, r#"{"status":"ok"}"#);
        // `doctor` is implemented (P1-CLI-04) and does not probe `/health`.
        // A still-stub command keeps the machine error code.
        let outcome = run(
            &[
                "--json",
                "--http",
                "http://127.0.0.1:7456",
                "--token",
                TOKEN,
                "ui",
            ],
            None,
            &mut http,
        );
        assert_eq!(outcome.code, exit::GENERAL);
        let err = text(&outcome.stderr);
        assert!(err.contains("\"not_implemented\""), "{err}");
        assert!(!err.contains(TOKEN), "{err}");
        assert_eq!(output_mode(true), OutputMode::Json);
    }

    #[test]
    fn help_lists_the_tree_and_exits_0() {
        let mut http = script(200, "{}");
        let outcome = run(&["--help"], None, &mut http);
        assert_eq!(outcome.code, exit::OK, "{}", text(&outcome.stderr));
        assert_eq!(http.opened, 0);
        let help = text(&outcome.stdout);
        assert!(!help.contains('\u{1b}'), "help must be plain text");
        for name in [
            "run", "attach", "stop", "ps", "sessions", "timeline", "procs", "files", "flows",
            "http", "findings", "gaps", "around", "search", "export", "ui", "doctor", "daemon",
            "config", "proxy", "db", "fixtures", "group", "agents", "links", "rpc", "chain",
            "merge", "hook", "mcp-tap", "dev", "version",
        ] {
            assert!(
                help.lines()
                    .any(|line| line.split_whitespace().next() == Some(name)),
                "missing subcommand `{name}` in:\n{help}"
            );
        }
        insta::assert_snapshot!(help);
    }

    #[test]
    fn run_proxy_is_refused_before_any_launch() {
        let mut http = script(200, "{}");
        let outcome = run(&["run", "--proxy", "--", "tool"], None, &mut http);
        assert_eq!(outcome.code, exit::GENERAL);
        let err = text(&outcome.stderr);
        assert!(err.contains("P3/P5"), "{err}");
        assert!(err.contains("--proxy"), "{err}");
        assert!(!err.contains("tool"), "{err}");
        assert_eq!(http.opened, 0);
    }

    #[test]
    fn attach_and_ps_stubs_are_exit_3_and_do_not_open_http() {
        let mut http = script(200, "{}");
        let attach = run(&["attach", "--pid", "100"], None, &mut http);
        assert_eq!(attach.code, exit::UNREACHABLE, "{}", text(&attach.stderr));
        let err = text(&attach.stderr);
        assert!(err.contains("not connected"), "{err}");
        assert!(
            err.contains("aw daemon start") || err.contains("--no-daemon"),
            "{err}"
        );

        let stop = run(&["stop", "s-1"], None, &mut http);
        assert_eq!(stop.code, exit::UNREACHABLE, "{}", text(&stop.stderr));

        let ps = run(&["ps", "--agents-only"], None, &mut http);
        assert_eq!(ps.code, exit::UNREACHABLE, "{}", text(&ps.stderr));
        let ps_err = text(&ps.stderr);
        assert!(
            ps_err.contains("不可用") || ps_err.contains("not available"),
            "{ps_err}"
        );
        assert_eq!(http.opened, 0);
    }

    #[test]
    fn run_platform_stub_does_not_echo_the_command() {
        let mut http = script(200, "{}");
        let outcome = run(
            &["run", "--", "tool", "--token", "super-secret-value"],
            None,
            &mut http,
        );
        // Windows: unverified Job API, exit 1. Other targets: no Unix launcher, exit 1.
        assert_eq!(outcome.code, exit::GENERAL, "{}", text(&outcome.stderr));
        let err = text(&outcome.stderr);
        assert!(!err.contains("super-secret-value"), "{err}");
        assert_eq!(http.opened, 0);
    }
}
