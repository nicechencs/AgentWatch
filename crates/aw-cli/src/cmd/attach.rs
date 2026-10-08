//! `aw attach` (P1-CLI-02).
//!
//! Attaches monitoring to a process the caller already named by pid or by a
//! name pattern. The daemon call goes through [`SessionControl`]. The production
//! control is a stub: the session API is not wired into this CLI, so it returns
//! [`ControlError::Unreachable`] and exits 3. Tests inject a fake.
//!
//! `--duration` ends the monitoring session when it elapses. It does not end
//! the target process: the only control call on that path is `stop_monitoring`.

use std::time::Duration;

use serde_json::json;

use crate::exit;
use crate::output::{parse_time, TimeArg};

use super::Outcome;

/// Parsed `aw attach` flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachArgs<'a> {
    /// `--pid`.
    pub pid: Option<u32>,
    /// `--name` process pattern. Not a session name (see `tree.rs`).
    pub name: Option<&'a str>,
    /// `--no-follow-children`.
    pub no_follow_children: bool,
    /// `--no-existing-children`.
    pub no_existing_children: bool,
    /// `--move-to-cgroup` (Linux). Recorded; this card does not move a cgroup.
    pub move_to_cgroup: bool,
    /// `--until-exit`.
    pub until_exit: bool,
    /// `--duration` text, before parsing.
    pub duration: Option<&'a str>,
    /// `--agent`.
    pub agent: Option<&'a str>,
    /// `--pin`.
    pub pin: bool,
    /// `--group`. Groups are not this card; a value is refused.
    pub group: Option<&'a str>,
    /// `--json`.
    pub json: bool,
}

/// What attach asks the daemon to watch. No argv, no environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachRequest {
    /// Target pid, when `--pid` was passed.
    pub pid: Option<u32>,
    /// Name pattern, when `--name` was passed.
    pub name: Option<String>,
    /// Root process only.
    pub no_follow_children: bool,
    /// Do not pull in children that already exist.
    pub no_existing_children: bool,
    /// Ask for a cgroup move. The control may report that it did not happen.
    pub move_to_cgroup: bool,
    /// Keep watching until the root exits.
    pub until_exit: bool,
    /// Stop monitoring after this long. `None` means no timer.
    pub duration: Option<Duration>,
    /// Agent label.
    pub agent: Option<String>,
    /// Pin the session.
    pub pin: bool,
}

/// A session the control opened or stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionHandle {
    /// Public id. Not a hostname.
    pub public_id: String,
}

/// Why a control call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum ControlError {
    /// The daemon session API is not reachable from this CLI.
    Unreachable { detail: String },
    /// The daemon answered and refused.
    Rejected { detail: String },
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { detail } | Self::Rejected { detail } => write!(f, "{detail}"),
        }
    }
}

/// Daemon session operations used by `attach` and `stop`.
///
/// `stop_monitoring` stops collection. It must not terminate the target.
/// There is no method on this trait that ends a process.
pub(crate) trait SessionControl {
    /// Begin monitoring. Returns the session id the daemon assigned.
    ///
    /// # Errors
    ///
    /// [`ControlError::Unreachable`] when no daemon API is wired, or
    /// [`ControlError::Rejected`] when the daemon refuses.
    fn attach(&mut self, request: &AttachRequest) -> Result<SessionHandle, ControlError>;

    /// Stop monitoring `session`. Does not end the watched process.
    ///
    /// # Errors
    ///
    /// [`ControlError::Unreachable`] or [`ControlError::Rejected`].
    fn stop_monitoring(&mut self, session: &str) -> Result<(), ControlError>;
}

/// Production control. The daemon session routes are not connected.
#[derive(Debug, Default)]
pub(crate) struct UnwiredControl;

const UNWIRED: &str = "daemon session API is not connected; attach and stop have no daemon to call (try `aw daemon start` once the API is wired, or `--no-daemon` for launch mode)";

impl SessionControl for UnwiredControl {
    fn attach(&mut self, _request: &AttachRequest) -> Result<SessionHandle, ControlError> {
        Err(ControlError::Unreachable {
            detail: UNWIRED.to_owned(),
        })
    }

    fn stop_monitoring(&mut self, _session: &str) -> Result<(), ControlError> {
        Err(ControlError::Unreachable {
            detail: UNWIRED.to_owned(),
        })
    }
}

/// Run `aw attach`.
///
/// When `--duration` parses, the control is asked to attach and then, because
/// this process does not sleep, immediately to `stop_monitoring`. The target
/// process is not signalled: [`SessionControl`] has no terminate method, and
/// this function does not call one.
pub(crate) fn run(args: &AttachArgs<'_>, control: &mut dyn SessionControl) -> Outcome {
    if args.pid.is_none() && args.name.is_none() {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "`aw attach` needs --pid or --name",
            args.json,
        );
    }
    if args.group.is_some() {
        return super::error_outcome(
            exit::GENERAL,
            "not_available",
            "--group is not available on attach in this build (P3/P5 提供)",
            args.json,
        );
    }
    if args.until_exit && args.duration.is_some() {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "--until-exit and --duration are alternative end conditions",
            args.json,
        );
    }
    let duration = match args.duration.map(parse_attach_duration).transpose() {
        Ok(duration) => duration,
        Err(detail) => {
            return super::error_outcome(exit::USAGE, "usage", &detail, args.json);
        }
    };
    let request = AttachRequest {
        pid: args.pid,
        name: args.name.map(str::to_owned),
        no_follow_children: args.no_follow_children,
        no_existing_children: args.no_existing_children,
        move_to_cgroup: args.move_to_cgroup,
        until_exit: args.until_exit,
        duration,
        agent: args.agent.map(str::to_owned),
        pin: args.pin,
    };
    let handle = match control.attach(&request) {
        Ok(handle) => handle,
        Err(err) => return control_outcome(err, args.json),
    };
    if duration.is_some() {
        if let Err(err) = control.stop_monitoring(&handle.public_id) {
            return control_outcome(err, args.json);
        }
        return attached_outcome(&handle, true, args.json);
    }
    attached_outcome(&handle, false, args.json)
}

/// `--duration 10s`. A leading `-` or `+` belongs to the query time syntax, not
/// to a watch length, so those are refused rather than treated as zero.
fn parse_attach_duration(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    if text.starts_with('+') || text.starts_with('-') {
        return Err(format!(
            "--duration `{text}` must be a length such as 10s, not a relative time"
        ));
    }
    match parse_time(text) {
        Ok(TimeArg::BeforeNow(span)) => span_to_duration(span.count, span.unit),
        Ok(_) => Err(format!("--duration `{text}` must be a length such as 10s")),
        Err(detail) => Err(detail),
    }
}

fn span_to_duration(count: u64, unit: crate::output::TimeUnit) -> Result<Duration, String> {
    use crate::output::TimeUnit;
    let millis = match unit {
        TimeUnit::Millis => count,
        TimeUnit::Seconds => count.saturating_mul(1_000),
        TimeUnit::Minutes => count.saturating_mul(60_000),
        TimeUnit::Hours => count.saturating_mul(3_600_000),
        TimeUnit::Days => count.saturating_mul(86_400_000),
    };
    Ok(Duration::from_millis(millis))
}

fn control_outcome(err: ControlError, json: bool) -> Outcome {
    let (code, machine) = match &err {
        ControlError::Unreachable { .. } => (exit::UNREACHABLE, "unreachable"),
        ControlError::Rejected { .. } => (exit::GENERAL, "rejected"),
    };
    super::error_outcome(code, machine, &err.to_string(), json)
}

fn attached_outcome(handle: &SessionHandle, stopped_on_duration: bool, json: bool) -> Outcome {
    let note = if stopped_on_duration {
        "监控已按 --duration 结束；目标进程未被结束"
    } else {
        "监控已附着；停止监控不会结束目标进程"
    };
    let text = if json {
        let body = json!({
            "session": handle.public_id,
            "monitoring": if stopped_on_duration { "stopped" } else { "attached" },
            "process_terminated": false,
            "message": note,
        });
        format!("{body}\n")
    } else {
        format!("[aw] 会话 {} · {note}\n", handle.public_id)
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{run, AttachArgs, AttachRequest, ControlError, SessionControl, SessionHandle};
    use crate::exit;
    use std::time::Duration;

    #[derive(Default)]
    struct FakeControl {
        attached: Vec<AttachRequest>,
        stopped: Vec<String>,
        terminated: u32,
    }

    impl SessionControl for FakeControl {
        fn attach(&mut self, request: &AttachRequest) -> Result<SessionHandle, ControlError> {
            self.attached.push(request.clone());
            Ok(SessionHandle {
                public_id: "s-attach".to_owned(),
            })
        }

        fn stop_monitoring(&mut self, session: &str) -> Result<(), ControlError> {
            self.stopped.push(session.to_owned());
            Ok(())
        }
    }

    fn args() -> AttachArgs<'static> {
        AttachArgs {
            pid: Some(100),
            name: None,
            no_follow_children: false,
            no_existing_children: false,
            move_to_cgroup: false,
            until_exit: false,
            duration: None,
            agent: None,
            pin: false,
            group: None,
            json: false,
        }
    }

    #[test]
    fn duration_stops_monitoring_and_does_not_terminate() {
        let mut control = FakeControl::default();
        let mut ran = args();
        ran.duration = Some("10s");
        let outcome = run(&ran, &mut control);
        assert_eq!(outcome.code, exit::OK);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(text.contains("目标进程未被结束"), "{text}");
        assert_eq!(control.stopped, vec!["s-attach".to_owned()]);
        assert_eq!(control.attached.len(), 1);
        assert_eq!(control.attached[0].duration, Some(Duration::from_secs(10)));
        assert_eq!(control.terminated, 0);
    }

    #[test]
    fn without_duration_there_is_no_stop() {
        let mut control = FakeControl::default();
        let outcome = run(&args(), &mut control);
        assert_eq!(outcome.code, exit::OK);
        assert!(control.stopped.is_empty());
        assert_eq!(control.terminated, 0);
    }
}
