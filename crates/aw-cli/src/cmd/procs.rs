//! `aw procs <S> [--tree]` (P1-CLI-03).
//!
//! The command line column is the pipeline's redacted placeholder. P1 redaction
//! is itself a placeholder, so every row is labeled `P1 脱敏为占位`. Raw argv
//! is not stored on [`super::query::ProcItem`] and is not printed.

use std::io;

use crate::exit;
use crate::output::OutputMode;

use super::query::QuerySource;
use super::render;
use super::sessions::{query_outcome, write_ok};
use super::Outcome;

const FAST_EXIT_NOTE: &str = "这个会话是定时查看进程表来记录的，运行时间很短的程序可能没记下来。";

/// Render the process list or tree.
///
/// # Errors
///
/// A failure to format the outcome.
pub(crate) fn run(
    session: &str,
    tree: bool,
    filter: Option<&str>,
    json: bool,
    source: &dyn QuerySource,
) -> io::Result<Outcome> {
    if session.trim().is_empty() {
        return Ok(super::error_outcome(
            exit::USAGE,
            "usage",
            "会话不能为空",
            json,
        ));
    }
    let mode = OutputMode::from_json_flag(json);
    match source.procs(session, tree, filter) {
        Ok(processes) if processes.scan_pending => {
            if mode == OutputMode::Json {
                let doc = serde_json::json!({
                    "scan_pending": true,
                    "fast_exit_may_be_missed": processes.fast_exit_may_be_missed,
                    "processes": [],
                });
                Ok(Outcome {
                    code: exit::OK,
                    stdout: format!("{doc}\n").into_bytes(),
                    stderr: Vec::new(),
                })
            } else {
                let mut stdout = "正在读取进程…\n".as_bytes().to_vec();
                if processes.fast_exit_may_be_missed {
                    stdout.extend_from_slice(format!("{FAST_EXIT_NOTE}\n").as_bytes());
                }
                Ok(Outcome {
                    code: exit::OK,
                    stdout,
                    stderr: Vec::new(),
                })
            }
        }
        Ok(processes) => {
            let table = render::procs_table(&processes.nodes, tree);
            let mut doc = render::procs_json(&processes.nodes, tree);
            doc["fast_exit_may_be_missed"] =
                serde_json::Value::Bool(processes.fast_exit_may_be_missed);
            let mut outcome = write_ok(mode, &table, &doc)?;
            if mode == OutputMode::Table && processes.fast_exit_may_be_missed {
                outcome
                    .stdout
                    .extend_from_slice(format!("{FAST_EXIT_NOTE}\n").as_bytes());
            }
            Ok(outcome)
        }
        Err(err) => Ok(query_outcome(err, json)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::run;
    use crate::client::{ApiReply, ApiRequest, ClientError, Transport};
    use crate::cmd::http_source::HttpQuerySource;
    use crate::endpoint::{Endpoint, HttpBase};
    use crate::exit;

    struct Script {
        paths: Rc<RefCell<Vec<String>>>,
        replies: RefCell<Vec<(u16, Vec<u8>)>>,
    }

    impl Transport for Script {
        fn exchange(&mut self, request: &ApiRequest) -> Result<ApiReply, ClientError> {
            self.paths.borrow_mut().push(request.path.clone());
            let (status, body) = self.replies.borrow_mut().pop().unwrap_or((
                500,
                br#"{"error":{"code":"empty","message":"no script"}}"#.to_vec(),
            ));
            Ok(ApiReply { status, body })
        }
    }

    fn endpoint() -> Endpoint {
        Endpoint::Http {
            base: HttpBase {
                host: "127.0.0.1".to_owned(),
                port: 9,
            },
            token: "test-token".to_owned(),
        }
    }

    /// A 404 for someone else's session names the id the user typed. The
    /// daemon body does not carry it, so the client must keep it itself.
    #[test]
    fn foreign_session_not_found_names_the_typed_id() {
        let paths = Rc::new(RefCell::new(Vec::new()));
        let script = Script {
            paths: Rc::clone(&paths),
            replies: RefCell::new(vec![(
                404,
                br#"{"error":{"code":"not_found","message":"session not found"}}"#.to_vec(),
            )]),
        };
        let source = HttpQuerySource::with_transport(endpoint(), script);
        let outcome = run("s-someone-else", false, None, false, &source).expect("procs");
        assert_eq!(outcome.code, exit::NOT_FOUND);
        assert_eq!(
            paths.borrow().clone(),
            vec!["/api/v1/sessions/s-someone-else/processes".to_owned()]
        );
        assert_eq!(
            String::from_utf8(outcome.stderr).expect("utf8"),
            "aw: 找不到会话「s-someone-else」\n"
        );
    }

    #[test]
    fn pending_initial_scan_is_not_rendered_as_zero_processes() {
        let paths = Rc::new(RefCell::new(Vec::new()));
        let script = Script {
            paths,
            replies: RefCell::new(vec![(
                200,
                br#"{"processes":[],"scan_pending":true}"#.to_vec(),
            )]),
        };
        let source = HttpQuerySource::with_transport(endpoint(), script);
        let outcome = run("s-pending", false, None, false, &source).expect("procs");
        assert_eq!(outcome.code, exit::OK);
        assert_eq!(
            String::from_utf8(outcome.stdout).expect("utf8"),
            "正在读取进程…\n"
        );
    }

    #[test]
    fn process_output_marks_fast_exits_only_when_the_daemon_says_so() {
        let table_source = HttpQuerySource::with_transport(
            endpoint(),
            Script {
                paths: Rc::new(RefCell::new(Vec::new())),
                replies: RefCell::new(vec![(
                    200,
                    br#"{"processes":[],"fast_exit_may_be_missed":true}"#.to_vec(),
                )]),
            },
        );
        let table = run("s-poll", false, None, false, &table_source).expect("table");
        assert_eq!(table.code, exit::OK);
        assert!(String::from_utf8(table.stdout)
            .expect("utf8")
            .ends_with("这个会话是定时查看进程表来记录的，运行时间很短的程序可能没记下来。\n"));

        let json_source = HttpQuerySource::with_transport(
            endpoint(),
            Script {
                paths: Rc::new(RefCell::new(Vec::new())),
                replies: RefCell::new(vec![(
                    200,
                    br#"{"processes":[],"fast_exit_may_be_missed":true}"#.to_vec(),
                )]),
            },
        );
        let json = run("s-poll", false, None, true, &json_source).expect("json");
        assert_eq!(json.code, exit::OK);
        let body: serde_json::Value = serde_json::from_slice(&json.stdout).expect("json document");
        assert_eq!(body["fast_exit_may_be_missed"], true);
    }
}
