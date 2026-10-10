//! `aw stop <SESSION>` (P1-CLI-02).
//!
//! Stops monitoring through the daemon session API. It does not end the watched
//! process. `@last` and names are resolved to a public id first (the daemon
//! routes take public ids only); the printed id is the one that was stopped.

use serde_json::json;

use crate::exit;
use crate::output::{parse_session, SessionRef};

use super::attach::DaemonSessions;
use super::Outcome;

/// Run `aw stop`.
pub(crate) fn run(session: &str, json: bool, control: &mut dyn DaemonSessions) -> Outcome {
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
        Ok(public_id) => stopped_outcome(&public_id, json),
        Err(error) if error.not_found() => super::error_outcome(
            error.exit_code(),
            "not_found",
            "找不到会话（或它不属于当前账户）",
            json,
        ),
        Err(error) => super::attach::control_outcome(error, json),
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
    use crate::cmd::attach::{
        AttachRequest, BeginRunRequest, ControlError, DaemonSessions, LaunchSession, SessionHandle,
    };
    use crate::exit;

    #[derive(Default)]
    struct FakeControl {
        stopped: Vec<String>,
        attached: u32,
    }

    impl DaemonSessions for FakeControl {
        fn begin_run(&mut self, _: &BeginRunRequest) -> Result<LaunchSession, ControlError> {
            Err(ControlError::BadReply {
                detail: "stop must not start a run".to_owned(),
            })
        }

        fn adopt(&mut self, _: &LaunchSession, _: u32) -> Result<(), ControlError> {
            Err(ControlError::BadReply {
                detail: "stop must not adopt".to_owned(),
            })
        }

        fn attach(&mut self, _request: &AttachRequest) -> Result<SessionHandle, ControlError> {
            self.attached += 1;
            Err(ControlError::BadReply {
                detail: "stop must not attach".to_owned(),
            })
        }

        fn stop_monitoring(&mut self, session: &str) -> Result<String, ControlError> {
            self.stopped.push(session.to_owned());
            Ok(session.to_owned())
        }

        fn pin(&mut self, _: &str) -> Result<(), ControlError> {
            Err(ControlError::BadReply {
                detail: "stop must not pin".to_owned(),
            })
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

    #[test]
    fn not_found_is_a_plain_session_error() {
        struct Missing;

        impl DaemonSessions for Missing {
            fn begin_run(&mut self, _: &BeginRunRequest) -> Result<LaunchSession, ControlError> {
                Err(ControlError::BadReply {
                    detail: "not called".to_owned(),
                })
            }

            fn adopt(&mut self, _: &LaunchSession, _: u32) -> Result<(), ControlError> {
                Err(ControlError::BadReply {
                    detail: "not called".to_owned(),
                })
            }

            fn attach(&mut self, _: &AttachRequest) -> Result<SessionHandle, ControlError> {
                Err(ControlError::BadReply {
                    detail: "not called".to_owned(),
                })
            }

            fn stop_monitoring(&mut self, _: &str) -> Result<String, ControlError> {
                Err(ControlError::Status {
                    status: 404,
                    code: None,
                    message: "not_found".to_owned(),
                })
            }

            fn pin(&mut self, _: &str) -> Result<(), ControlError> {
                Err(ControlError::BadReply {
                    detail: "not called".to_owned(),
                })
            }
        }

        let outcome = run("s-missing", false, &mut Missing);
        assert_eq!(outcome.code, exit::USAGE);
        assert_eq!(
            String::from_utf8(outcome.stderr).expect("utf8"),
            "aw: 找不到会话（或它不属于当前账户）\n"
        );
    }
}
