//! `aw stop <SESSION>` (P1-CLI-02).
//!
//! Stops monitoring through the daemon session API. It does not end the watched
//! process. `@last` is forwarded to the daemon, which resolves it to the
//! caller's own newest session; the printed id is the one the daemon stopped.

use serde_json::json;

use crate::exit;
use crate::output::{parse_session, SessionRef};

use super::attach::DaemonSessions;
use super::Outcome;

/// Run `aw stop`.
pub(crate) fn run(
    session: &str,
    owner: Option<&str>,
    json: bool,
    control: &mut dyn DaemonSessions,
) -> Outcome {
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
    match control.stop_monitoring(key, owner) {
        Ok(public_id) => stopped_outcome(&public_id, json),
        Err(error) if error.no_sessions() => super::error_outcome(
            error.exit_code(),
            error.machine_code(),
            "还没有你的会话，@last 无处可指",
            json,
        ),
        Err(error) if error.not_found() => super::error_outcome(
            error.exit_code(),
            error.machine_code(),
            &format!("找不到会话 `{key}`"),
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

        fn record_exit(&mut self, _: &LaunchSession, _: i32) -> Result<(), ControlError> {
            Err(ControlError::BadReply {
                detail: "stop must not record an exit".to_owned(),
            })
        }

        fn attach(&mut self, _request: &AttachRequest) -> Result<SessionHandle, ControlError> {
            self.attached += 1;
            Err(ControlError::BadReply {
                detail: "stop must not attach".to_owned(),
            })
        }

        fn stop_monitoring(
            &mut self,
            session: &str,
            _: Option<&str>,
        ) -> Result<String, ControlError> {
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
        let outcome = run("s-1", None, false, &mut control);
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

            fn record_exit(&mut self, _: &LaunchSession, _: i32) -> Result<(), ControlError> {
                Err(ControlError::BadReply {
                    detail: "not called".to_owned(),
                })
            }

            fn attach(&mut self, _: &AttachRequest) -> Result<SessionHandle, ControlError> {
                Err(ControlError::BadReply {
                    detail: "not called".to_owned(),
                })
            }

            fn stop_monitoring(
                &mut self,
                _: &str,
                _: Option<&str>,
            ) -> Result<String, ControlError> {
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

        let outcome = run("s-missing", None, false, &mut Missing);
        assert_eq!(outcome.code, exit::NOT_FOUND);
        assert_eq!(
            String::from_utf8(outcome.stderr).expect("utf8"),
            "aw: 找不到会话 `s-missing`\n"
        );
    }

    /// `@last` is the daemon's to resolve. The CLI sends the token unchanged
    /// and prints the public id the daemon names back.
    #[test]
    fn stop_sends_at_last_to_the_daemon() {
        use crate::client::{ApiReply, ApiRequest, ClientError, Transport};
        use crate::endpoint::{Endpoint, HttpBase};
        use std::cell::RefCell;
        use std::rc::Rc;

        struct Seen(Rc<RefCell<Vec<String>>>);

        impl Transport for Seen {
            fn exchange(&mut self, request: &ApiRequest) -> Result<ApiReply, ClientError> {
                self.0.borrow_mut().push(request.path.clone());
                Ok(ApiReply {
                    status: 200,
                    body: br#"{"stopped":"@last","id":"s-mine"}"#.to_vec(),
                })
            }
        }

        let seen = Rc::new(RefCell::new(Vec::new()));
        let endpoint = Endpoint::Http {
            base: HttpBase {
                host: "127.0.0.1".to_owned(),
                port: 9,
            },
            token: "test-token".to_owned(),
        };
        let mut control = super::super::attach::HttpDaemonSessions::with_transport(
            endpoint,
            Seen(Rc::clone(&seen)),
        );
        let outcome = run("@last", None, false, &mut control);
        assert_eq!(
            outcome.code,
            exit::OK,
            "{}",
            String::from_utf8_lossy(&outcome.stderr)
        );
        let paths = seen.borrow().clone();
        assert_eq!(paths, vec!["/api/v1/sessions/@last/stop".to_owned()]);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(text.contains("s-mine"), "{text}");
        assert!(!text.contains("@last"), "{text}");
    }

    #[test]
    fn unknown_name_is_one_sentence() {
        struct Unknown;

        impl DaemonSessions for Unknown {
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

            fn stop_monitoring(
                &mut self,
                _: &str,
                _: Option<&str>,
            ) -> Result<String, ControlError> {
                Err(ControlError::Status {
                    status: 404,
                    code: Some("not_found".to_owned()),
                    message: "session not found".to_owned(),
                })
            }

            fn pin(&mut self, _: &str) -> Result<(), ControlError> {
                Err(ControlError::BadReply {
                    detail: "not called".to_owned(),
                })
            }

            fn record_exit(&mut self, _: &LaunchSession, _: i32) -> Result<(), ControlError> {
                Err(ControlError::BadReply {
                    detail: "not called".to_owned(),
                })
            }
        }

        let outcome = run("no-such-name", None, false, &mut Unknown);
        assert_eq!(
            String::from_utf8(outcome.stderr).expect("utf8"),
            "aw: 找不到会话 `no-such-name`\n"
        );
    }
}
