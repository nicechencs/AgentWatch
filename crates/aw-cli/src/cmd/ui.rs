//! `aw ui` and `aw daemon start|status` over the internal channel.
//!
//! `aw ui` asks the daemon for a one-time `ui_ticket` on the Unix socket or
//! named pipe (api-and-cli §1), then opens `http://127.0.0.1:<port>/#ticket=…`.
//! The ticket is valid for 60 seconds and only once. Over `--http` there is no
//! way to mint one: the daemon refuses a bearer caller, so this command says
//! so instead of probing.
//!
//! `aw daemon start` starts `agentwatchd --foreground` when nothing answers on
//! the channel, then waits until `/health` answers. It does not register a
//! service; `aw daemon install` prints that plan. `aw daemon status` reads
//! `/health` on the channel.

use std::path::PathBuf;
use std::process::{Command as Process, Stdio};
use std::thread;
use std::time::Duration;

use serde_json::{json, Value};

use crate::client::{ApiRequest, Client, ClientError, Transport};
use crate::endpoint::Endpoint;
use crate::exit;

use super::{error_outcome, Outcome};

/// Default loopback UI port (api-and-cli §1). `aw ui --port` overrides it.
pub(crate) const DEFAULT_UI_PORT: u16 = 7456;

/// Opens a URL for the user. Production starts the desktop's URL handler.
pub(crate) trait Opener {
    /// `Err` with a short reason when nothing could be started.
    fn open(&mut self, url: &str) -> Result<(), String>;
}

/// The desktop URL handler. The only per-OS choice is the program name.
pub(crate) struct SystemOpener;

impl Opener for SystemOpener {
    fn open(&mut self, url: &str) -> Result<(), String> {
        let (program, args): (&str, Vec<&str>) = if cfg!(target_os = "windows") {
            ("cmd", vec!["/C", "start", ""])
        } else if cfg!(target_os = "macos") {
            ("open", Vec::new())
        } else {
            ("xdg-open", Vec::new())
        };
        Process::new(program)
            .args(args)
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|err| format!("{program}: {}", err.kind()))
    }
}

/// `aw ui`.
pub(crate) fn ui(
    endpoint: &Endpoint,
    transport: Box<dyn Transport>,
    port: Option<u16>,
    no_open: bool,
    json: bool,
    opener: &mut dyn Opener,
) -> Outcome {
    if matches!(endpoint, Endpoint::Http { .. }) {
        return error_outcome(
            exit::USAGE,
            "usage",
            "aw ui asks for a ticket on the socket or named pipe; a bearer over --http cannot mint one. Drop --http",
            json,
        );
    }
    let mut client = Client::new(endpoint.clone(), transport);
    let reply = match client.call(&ApiRequest::post_json("/api/v1/auth/ui-ticket", &json!({}))) {
        Ok(reply) => reply,
        Err(err) => return client_error(&err, endpoint, json),
    };
    let Some(ticket) = reply
        .json()
        .and_then(|value| {
            value
                .get("ticket")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .filter(|ticket| !ticket.is_empty())
    else {
        return error_outcome(
            exit::GENERAL,
            "bad_reply",
            "daemon answered without a ticket",
            json,
        );
    };
    let url = format!(
        "http://127.0.0.1:{}/#ticket={ticket}",
        port.unwrap_or(DEFAULT_UI_PORT)
    );
    let opened = if no_open {
        None
    } else {
        Some(opener.open(&url))
    };
    let text = if json {
        let opened_value = match &opened {
            None => Value::Bool(false),
            Some(Ok(())) => Value::Bool(true),
            Some(Err(_)) => Value::Bool(false),
        };
        format!(
            "{}\n",
            json!({ "url": url, "ttl_s": 60, "opened": opened_value })
        )
    } else {
        match &opened {
            Some(Ok(())) => format!("opened {url}\nthe ticket is valid once, for 60 s\n"),
            Some(Err(reason)) => {
                format!("could not open a browser ({reason}); open this URL within 60 s:\n{url}\n")
            }
            None => format!("{url}\nthe ticket is valid once, for 60 s\n"),
        }
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

/// Starts the daemon process. Production spawns `agentwatchd --foreground`.
pub(crate) trait Starter {
    /// Start the daemon. `Ok(pid)` when a process was started.
    fn start(&mut self) -> Result<u32, String>;
}

/// Passed to the started daemon as `--config` when set (development runs).
pub(crate) const DAEMON_CONFIG_ENV: &str = "AW_DAEMON_CONFIG";

/// Spawns `agentwatchd` from next to `aw`, else from `PATH`.
pub(crate) struct ProcessStarter;

impl Starter for ProcessStarter {
    fn start(&mut self) -> Result<u32, String> {
        let program = daemon_program();
        let mut process = Process::new(&program);
        process.arg("--foreground");
        if let Some(config) = std::env::var_os(DAEMON_CONFIG_ENV).filter(|v| !v.is_empty()) {
            process.arg("--config").arg(config);
        }
        process
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|child| child.id())
            .map_err(|err| format!("could not start agentwatchd: {}", err.kind()))
    }
}

fn daemon_program() -> PathBuf {
    let name = if cfg!(windows) {
        "agentwatchd.exe"
    } else {
        "agentwatchd"
    };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(name);
            if sibling.is_file() {
                return sibling;
            }
        }
    }
    PathBuf::from(name)
}

/// How long `aw daemon start` waits for `/health`.
pub(crate) const START_WAIT: Duration = Duration::from_secs(10);
const START_POLL: Duration = Duration::from_millis(100);

/// `aw daemon status`: `/health` on the channel. Unreachable is exit 3.
pub(crate) fn daemon_status(
    endpoint: &Endpoint,
    transport: Box<dyn Transport>,
    json: bool,
) -> Outcome {
    let mut client = Client::new(endpoint.clone(), transport);
    match client.call(&ApiRequest::get("/health")) {
        Ok(reply) => {
            let version = reply
                .json()
                .and_then(|v| v.get("version").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_default();
            running_outcome(endpoint, &version, None, json)
        }
        Err(err) => client_error(&err, endpoint, json),
    }
}

/// `aw daemon start`.
pub(crate) fn daemon_start(
    endpoint: &Endpoint,
    open: &mut dyn FnMut() -> Box<dyn Transport>,
    starter: &mut dyn Starter,
    wait: Duration,
    json: bool,
) -> Outcome {
    if let Some(version) = health(endpoint, open()) {
        return running_outcome(endpoint, &version, Some("already running"), json);
    }
    let pid = match starter.start() {
        Ok(pid) => pid,
        Err(detail) => return error_outcome(exit::GENERAL, "daemon", &detail, json),
    };
    let mut waited = Duration::ZERO;
    loop {
        if let Some(version) = health(endpoint, open()) {
            let note = format!("started pid {pid}");
            return running_outcome(endpoint, &version, Some(&note), json);
        }
        if waited >= wait {
            return error_outcome(
                exit::UNREACHABLE,
                "unreachable",
                &format!(
                    "agentwatchd pid {pid} started but {endpoint} did not answer within {} s; see the daemon log",
                    wait.as_secs()
                ),
                json,
            );
        }
        thread::sleep(START_POLL);
        waited += START_POLL;
    }
}

fn health(endpoint: &Endpoint, transport: Box<dyn Transport>) -> Option<String> {
    let mut client = Client::new(endpoint.clone(), transport);
    let reply = client.call(&ApiRequest::get("/health")).ok()?;
    Some(
        reply
            .json()
            .and_then(|v| v.get("version").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_default(),
    )
}

fn running_outcome(endpoint: &Endpoint, version: &str, note: Option<&str>, json: bool) -> Outcome {
    let text = if json {
        format!(
            "{}\n",
            json!({ "state": "running", "version": version, "channel": endpoint.to_string(), "detail": note })
        )
    } else {
        match note {
            Some(note) => format!("running: {note} · {endpoint} · v{version}\n"),
            None => format!("running: {endpoint} · v{version}\n"),
        }
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn client_error(err: &ClientError, endpoint: &Endpoint, json: bool) -> Outcome {
    let machine = match err {
        ClientError::Unreachable { .. } => "unreachable",
        ClientError::Transport { .. } => "transport",
        ClientError::Status { .. } => "status",
    };
    error_outcome(
        err.exit_code(),
        machine,
        &format!("{err} [{endpoint}]"),
        json,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{daemon_start, daemon_status, ui, Opener, Starter};
    use crate::client::{MemoryTransport, Transport};
    use crate::endpoint::{Endpoint, HttpBase};
    use crate::exit;

    fn sock() -> Endpoint {
        Endpoint::Unix {
            path: PathBuf::from("/tmp/aw-test.sock"),
        }
    }

    struct Recorder(Vec<String>);
    impl Opener for Recorder {
        fn open(&mut self, url: &str) -> Result<(), String> {
            self.0.push(url.to_owned());
            Ok(())
        }
    }

    fn reply(status: u16, body: &str) -> Box<dyn Transport> {
        Box::new(MemoryTransport::replying(status, body.as_bytes().to_vec()))
    }

    #[test]
    fn ui_gets_a_ticket_on_the_socket_and_opens_the_url() {
        let mut opener = Recorder(Vec::new());
        let out = ui(
            &sock(),
            reply(200, r#"{"ticket":"abc123","ttl_s":60}"#),
            None,
            false,
            false,
            &mut opener,
        );
        assert_eq!(out.code, exit::OK);
        assert_eq!(opener.0, vec!["http://127.0.0.1:7456/#ticket=abc123"]);
    }

    #[test]
    fn ui_no_open_prints_and_port_is_used() {
        let mut opener = Recorder(Vec::new());
        let out = ui(
            &sock(),
            reply(200, r#"{"ticket":"t"}"#),
            Some(9000),
            true,
            false,
            &mut opener,
        );
        assert_eq!(out.code, exit::OK);
        assert!(opener.0.is_empty());
        let text = String::from_utf8(out.stdout).expect("utf8");
        assert!(text.contains("http://127.0.0.1:9000/#ticket=t"), "{text}");
    }

    #[test]
    fn ui_over_http_is_refused_without_a_request() {
        let mut opener = Recorder(Vec::new());
        let endpoint = Endpoint::Http {
            base: HttpBase {
                host: "127.0.0.1".to_owned(),
                port: 7456,
            },
            token: "unit-token".to_owned(),
        };
        let out = ui(&endpoint, reply(200, "{}"), None, true, false, &mut opener);
        assert_eq!(out.code, exit::USAGE);
    }

    #[test]
    fn ui_unreachable_daemon_is_exit_3() {
        let mut opener = Recorder(Vec::new());
        let out = ui(
            &sock(),
            Box::new(MemoryTransport::failing("nobody listening")),
            None,
            true,
            false,
            &mut opener,
        );
        assert_eq!(out.code, exit::UNREACHABLE);
    }

    #[test]
    fn status_running_and_down() {
        let up = daemon_status(
            &sock(),
            reply(200, r#"{"status":"ok","version":"0.1.0"}"#),
            false,
        );
        assert_eq!(up.code, exit::OK);
        let down = daemon_status(&sock(), Box::new(MemoryTransport::failing("down")), false);
        assert_eq!(down.code, exit::UNREACHABLE);
    }

    struct CountStarter(u32);
    impl Starter for CountStarter {
        fn start(&mut self) -> Result<u32, String> {
            self.0 += 1;
            Ok(4242)
        }
    }

    #[test]
    fn start_does_not_spawn_when_already_running() {
        let mut starter = CountStarter(0);
        let mut open = || reply(200, r#"{"status":"ok"}"#);
        let out = daemon_start(&sock(), &mut open, &mut starter, Duration::ZERO, false);
        assert_eq!(out.code, exit::OK);
        assert_eq!(starter.0, 0);
    }

    #[test]
    fn start_spawns_then_waits_for_health() {
        let mut starter = CountStarter(0);
        let mut calls = 0;
        let mut open = || {
            calls += 1;
            if calls == 1 {
                Box::new(MemoryTransport::failing("down")) as Box<dyn Transport>
            } else {
                reply(200, r#"{"status":"ok","version":"0.1.0"}"#)
            }
        };
        let out = daemon_start(
            &sock(),
            &mut open,
            &mut starter,
            Duration::from_secs(1),
            false,
        );
        assert_eq!(out.code, exit::OK);
        assert_eq!(starter.0, 1);
        let text = String::from_utf8(out.stdout).expect("utf8");
        assert!(text.contains("started pid 4242"), "{text}");
    }

    #[test]
    fn start_times_out_as_exit_3() {
        let mut starter = CountStarter(0);
        let mut open = || Box::new(MemoryTransport::failing("down")) as Box<dyn Transport>;
        let out = daemon_start(&sock(), &mut open, &mut starter, Duration::ZERO, false);
        assert_eq!(out.code, exit::UNREACHABLE);
    }
}
