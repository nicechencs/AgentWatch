//! `aw stop <SESSION>` (P1-CLI-02).
//!
//! Stops monitoring. It does not end the watched process. The only control
//! method this command calls is [`super::attach::SessionControl::stop_monitoring`],
//! which has no terminate counterpart.

use serde_json::json;

use crate::exit;
use crate::output::{parse_session, SessionRef};

use super::attach::{ControlError, SessionControl};
use super::Outcome;

/// Run `aw stop`.
pub(crate) fn run(session: &str, json: bool, control: &mut dyn SessionControl) -> Outcome {
    let parsed = match parse_session(session) {
        Ok(parsed) => parsed,
        Err(detail) => {
            return super::error_outcome(exit::USAGE, "usage", &detail, json);
        }
    };
    let key = match &parsed {
        SessionRef::Last => "@last",
        SessionRef::IdOrName(name) => name.as_str(),
    };
    match control.stop_monitoring(key) {
        Ok(()) => stopped_outcome(key, json),
        Err(ControlError::Unreachable { detail }) => {
            super::error_outcome(exit::UNREACHABLE, "unreachable", &detail, json)
        }
        Err(ControlError::Rejected { detail }) => {
            super::error_outcome(exit::GENERAL, "rejected", &detail, json)
        }
    }
}

fn stopped_outcome(session: &str, json: bool) -> Outcome {
    const NOTE: &str = "已停止监控；目标进程未被结束";
    let text = if json {
        let body = json!({
            "session": session,
            "monitoring": "stopped",
            "process_terminated": false,
            "message": NOTE,
        });
        format!("{body}\n")
    } else {
        format!("[aw] 会话 {session} · {NOTE}\n")
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
    use super::run;
    use crate::cmd::attach::{AttachRequest, ControlError, SessionControl, SessionHandle};
    use crate::exit;

    #[derive(Default)]
    struct FakeControl {
        stopped: Vec<String>,
        attached: u32,
    }

    impl SessionControl for FakeControl {
        fn attach(&mut self, _request: &AttachRequest) -> Result<SessionHandle, ControlError> {
            self.attached += 1;
            Err(ControlError::Rejected {
                detail: "stop must not attach".to_owned(),
            })
        }

        fn stop_monitoring(&mut self, session: &str) -> Result<(), ControlError> {
            self.stopped.push(session.to_owned());
            Ok(())
        }
    }

    #[test]
    fn stop_only_stops_monitoring() {
        let mut control = FakeControl::default();
        let outcome = run("s-1", false, &mut control);
        assert_eq!(outcome.code, exit::OK);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(text.contains("已停止监控"), "{text}");
        assert!(text.contains("目标进程未被结束"), "{text}");
        assert_eq!(control.stopped, vec!["s-1".to_owned()]);
        assert_eq!(control.attached, 0);
    }
}
