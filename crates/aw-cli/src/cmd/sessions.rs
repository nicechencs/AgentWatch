//! `aw sessions list|show|rename|pin|unpin|delete` (P1-CLI-03).
//!
//! Records come from a [`QuerySource`]. Production passes the daemon client.

use std::io::{self, IsTerminal, Write};

use serde_json::json;

use crate::exit;
use crate::output::OutputMode;

use super::query::{QueryError, QuerySource, SessionQuery};
use super::render::{self, mutation_json};
use super::tree::SessionsCmd;
use super::Outcome;

/// Run one `sessions` subcommand.
///
/// # Errors
///
/// A failure to format the outcome. The process code is [`Outcome::code`].
pub(crate) fn run(
    cmd: &SessionsCmd,
    json: bool,
    source: &mut dyn QuerySource,
) -> io::Result<Outcome> {
    let mode = OutputMode::from_json_flag(json);
    match cmd {
        SessionsCmd::List {
            since,
            agent,
            active,
            limit,
        } => list(
            since.as_deref(),
            agent.clone(),
            *active,
            *limit,
            mode,
            source,
        ),
        SessionsCmd::Show { session } => show(session, mode, source),
        SessionsCmd::Rename { session, name } => rename(session, name, mode, source),
        SessionsCmd::Pin { session } => pin(session, true, mode, source),
        SessionsCmd::Unpin { session } => pin(session, false, mode, source),
        SessionsCmd::Delete { sessions, yes } => delete(sessions, *yes, mode, source),
    }
}

fn list(
    since: Option<&str>,
    agent: Option<String>,
    active: bool,
    limit: Option<u64>,
    mode: OutputMode,
    source: &dyn QuerySource,
) -> io::Result<Outcome> {
    let since_ns = match since {
        Some(text) => match super::query::resolve_time(text, None, 0) {
            Ok(ns) => Some(ns),
            Err(detail) => {
                return Ok(super::error_outcome(
                    exit::USAGE,
                    "usage",
                    &detail,
                    mode == OutputMode::Json,
                ));
            }
        },
        None => None,
    };
    // `--since -10m` is relative to now. This card has no clock injection on the
    // list path beyond `resolve_time(..., now_ns = 0)` for RFC 3339 and `+`.
    // A relative-to-now form cannot be anchored, so refuse it instead of using 0.
    if let Some(text) = since {
        if text.trim().starts_with('-') {
            return Ok(super::error_outcome(
                exit::USAGE,
                "usage",
                "`sessions list --since` 的相对当前时间（-10m）需要此构建没有的时钟；请传入 RFC 3339",
                mode == OutputMode::Json,
            ));
        }
    }
    let query = SessionQuery {
        agent,
        active_only: active,
        since_ns,
        limit,
    };
    match source.list_sessions(&query) {
        Ok(items) => {
            let table = render::session_table(&items);
            let doc = render::session_json(&items);
            Ok(write_ok(mode, &table, &doc)?)
        }
        Err(err) => Ok(query_outcome(err, mode == OutputMode::Json)),
    }
}

fn show(session: &str, mode: OutputMode, source: &dyn QuerySource) -> io::Result<Outcome> {
    match source.show_session(session) {
        Ok(shown) => {
            let table = render::show_table(&shown);
            let doc = render::show_json(&shown);
            Ok(write_ok(mode, &table, &doc)?)
        }
        Err(err) => Ok(query_outcome(err, mode == OutputMode::Json)),
    }
}

fn rename(
    session: &str,
    name: &str,
    mode: OutputMode,
    source: &mut dyn QuerySource,
) -> io::Result<Outcome> {
    if name.trim().is_empty() {
        return Ok(super::error_outcome(
            exit::USAGE,
            "usage",
            "会话名为空",
            mode == OutputMode::Json,
        ));
    }
    match source.rename_session(session, name) {
        Ok(item) => {
            let doc = mutation_json("rename", &render::session_json(std::slice::from_ref(&item)));
            let table = render::session_table(std::slice::from_ref(&item));
            Ok(write_ok(mode, &table, &doc)?)
        }
        Err(err) => Ok(query_outcome(err, mode == OutputMode::Json)),
    }
}

fn pin(
    session: &str,
    pinned: bool,
    mode: OutputMode,
    source: &mut dyn QuerySource,
) -> io::Result<Outcome> {
    match source.set_pinned(session, pinned) {
        Ok(item) => {
            let action = if pinned { "pin" } else { "unpin" };
            let doc = mutation_json(action, &json!({ "id": item.public_id, "pinned": pinned }));
            let table = render::session_table(std::slice::from_ref(&item));
            Ok(write_ok(mode, &table, &doc)?)
        }
        Err(err) => Ok(query_outcome(err, mode == OutputMode::Json)),
    }
}

fn delete(
    sessions: &[String],
    yes: bool,
    mode: OutputMode,
    source: &mut dyn QuerySource,
) -> io::Result<Outcome> {
    if !yes && !confirm_delete(sessions.len()) {
        return Ok(super::error_outcome(
            exit::USAGE,
            "usage",
            "现在不在终端里，没法确认删除。确定要删的话，请加上 `--yes`（删除后无法恢复）",
            mode == OutputMode::Json,
        ));
    }
    match source.delete_sessions(sessions) {
        Ok(removed) => {
            let doc = mutation_json("delete", &json!({ "removed": removed }));
            let table = crate::output::Table {
                headers: vec!["removed".to_owned()],
                rows: vec![crate::output::Row {
                    cells: vec![removed.to_string()],
                    evidence: aw_core::Evidence::E1,
                }],
            };
            Ok(write_ok(mode, &table, &doc)?)
        }
        Err(err) => Ok(query_outcome(err, mode == OutputMode::Json)),
    }
}

/// Ask only on an interactive terminal; redirected input must never block.
fn confirm_delete(count: usize) -> bool {
    if !io::stdin().is_terminal() {
        return false;
    }
    let _ = write!(
        io::stderr(),
        "将删除 {count} 个会话，删除后无法恢复。确定吗？[是/否]"
    );
    let _ = io::stderr().flush();
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).is_ok()
        && matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "是" | "y" | "yes"
        )
}

pub(crate) fn write_ok(
    mode: OutputMode,
    table: &crate::output::Table,
    doc: &serde_json::Value,
) -> io::Result<Outcome> {
    let mut stdout = Vec::new();
    render::write_out(&mut stdout, mode, table, doc)?;
    Ok(Outcome {
        code: exit::OK,
        stdout,
        stderr: Vec::new(),
    })
}

pub(crate) fn query_outcome(err: QueryError, json: bool) -> Outcome {
    let (code, machine) = match &err {
        QueryError::NotFound { .. } => (exit::NOT_FOUND, "not_found"),
        QueryError::NoSessions => (exit::NOT_FOUND, "no_sessions"),
        QueryError::Permission { .. } => (exit::PERMISSION, "permission_denied"),
        QueryError::BadArgument { .. } => (exit::USAGE, "usage"),
        QueryError::Unavailable { .. } => (exit::GENERAL, "not_connected"),
    };
    super::error_outcome(code, machine, &err.to_string(), json)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::run;
    use crate::client::{ApiReply, ApiRequest, ClientError, Transport};
    use crate::cmd::http_source::HttpQuerySource;
    use crate::cmd::tree::SessionsCmd;
    use crate::endpoint::{Endpoint, HttpBase};
    use crate::exit;

    struct Script {
        paths: Rc<RefCell<Vec<String>>>,
        /// Status and body, one per exchange, in order.
        replies: RefCell<Vec<(u16, &'static str)>>,
    }

    impl Transport for Script {
        fn exchange(&mut self, request: &ApiRequest) -> Result<ApiReply, ClientError> {
            self.paths.borrow_mut().push(request.path.clone());
            let (status, body) = self
                .replies
                .borrow_mut()
                .pop()
                .unwrap_or((500, r#"{"error":{"code":"empty","message":"no script"}}"#));
            Ok(ApiReply {
                status,
                body: body.as_bytes().to_vec(),
            })
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

    const SESSION_DOC: &str = r#"{
        "id":"s-mine","name":"demo","mode":"launch","agent":null,
        "started_ns":10,"ended_ns":null,"pinned":false,
        "stats":{"process_count":0,"flow_count":0,"dns_count":0,"gap_count":0}
    }"#;

    /// `@last` goes to the daemon as `@last`. The printed id is the one the
    /// daemon resolved, not the token.
    #[test]
    fn show_sends_at_last_to_the_daemon() {
        let paths = Rc::new(RefCell::new(Vec::new()));
        let script = Script {
            paths: Rc::clone(&paths),
            replies: RefCell::new(vec![(200, SESSION_DOC)]),
        };
        let mut source = HttpQuerySource::with_transport(endpoint(), script);
        let outcome = run(
            &SessionsCmd::Show {
                session: "@last".to_owned(),
            },
            true,
            &mut source,
        )
        .expect("show");
        assert_eq!(
            outcome.code,
            exit::OK,
            "{}",
            String::from_utf8_lossy(&outcome.stderr)
        );
        assert_eq!(
            paths.borrow().clone(),
            vec!["/api/v1/sessions/@last".to_owned()]
        );
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(text.contains("\"s-mine\""), "{text}");
        assert!(!text.contains("@last"), "{text}");
    }

    /// A name the daemon does not list is sent on unchanged, and the 404 names
    /// what was typed — once, not twice.
    #[test]
    fn unknown_name_is_one_sentence() {
        let paths = Rc::new(RefCell::new(Vec::new()));
        let script = Script {
            paths: Rc::clone(&paths),
            replies: RefCell::new(vec![
                (
                    404,
                    r#"{"error":{"code":"not_found","message":"session not found"}}"#,
                ),
                (200, r#"{"sessions":[]}"#),
            ]),
        };
        let mut source = HttpQuerySource::with_transport(endpoint(), script);
        let outcome = run(
            &SessionsCmd::Show {
                session: "no-such-name".to_owned(),
            },
            false,
            &mut source,
        )
        .expect("show");
        assert_eq!(outcome.code, exit::NOT_FOUND);
        assert_eq!(
            paths.borrow().clone(),
            vec![
                "/api/v1/sessions".to_owned(),
                "/api/v1/sessions/no-such-name".to_owned(),
            ]
        );
        assert_eq!(
            String::from_utf8(outcome.stderr).expect("utf8"),
            "aw: 找不到会话「no-such-name」\n"
        );
    }

    /// The store summary omits `pinned` and sends `exit_code: null`. The table
    /// says 没采 for both; JSON keeps the nulls.
    #[test]
    fn show_missing_pinned_and_null_exit_code_are_not_collected() {
        let detail = r#"{
            "id":"s-theirs","name":null,"mode":"launch","agent":null,
            "started_ns":10,"ended_ns":20,"exit_code":null,
            "stats":{"process_count":1,"flow_count":0,"dns_count":0,"gap_count":0}
        }"#;
        let paths = Rc::new(RefCell::new(Vec::new()));
        let script = Script {
            paths: Rc::clone(&paths),
            replies: RefCell::new(vec![(200, detail)]),
        };
        let mut source = HttpQuerySource::with_transport(endpoint(), script);
        let table = run(
            &SessionsCmd::Show {
                session: "s-theirs".to_owned(),
            },
            false,
            &mut source,
        )
        .expect("show");
        assert_eq!(table.code, exit::OK);
        let text = String::from_utf8(table.stdout).expect("utf8");
        assert!(text.contains("没采"), "{text}");
        // An absent pin is not "no", and a null exit code is not 0.
        assert!(
            !text
                .lines()
                .any(|line| line.contains("pinned") && line.contains("no")),
            "{text}"
        );
        assert!(
            !text.lines().any(|line| line.contains("exit_code")
                && line.split_whitespace().any(|cell| cell == "0")),
            "{text}"
        );

        let script = Script {
            paths: Rc::clone(&paths),
            replies: RefCell::new(vec![(200, detail)]),
        };
        let mut source = HttpQuerySource::with_transport(endpoint(), script);
        let json = run(
            &SessionsCmd::Show {
                session: "s-theirs".to_owned(),
            },
            true,
            &mut source,
        )
        .expect("show json");
        let body: serde_json::Value = serde_json::from_slice(&json.stdout).expect("json");
        assert!(body["session"]["pinned"].is_null(), "{body}");
        assert!(body["session"]["exit_code"].is_null(), "{body}");
    }

    /// A collected exit code is printed as that code, including 0.
    #[test]
    fn show_prints_a_collected_exit_code() {
        let detail = r#"{
            "id":"s-mine","name":"demo","mode":"launch","agent":null,
            "started_ns":10,"ended_ns":20,"exit_code":0,"pinned":true,
            "stats":{"process_count":1,"flow_count":0,"dns_count":0,"gap_count":0}
        }"#;
        let paths = Rc::new(RefCell::new(Vec::new()));
        let script = Script {
            paths: Rc::clone(&paths),
            replies: RefCell::new(vec![(200, detail)]),
        };
        let mut source = HttpQuerySource::with_transport(endpoint(), script);
        let outcome = run(
            &SessionsCmd::Show {
                session: "s-mine".to_owned(),
            },
            false,
            &mut source,
        )
        .expect("show");
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        assert!(
            text.lines().any(|line| line.contains("exit_code")
                && line.split_whitespace().any(|cell| cell == "0")),
            "{text}"
        );
        assert!(
            text.lines()
                .any(|line| line.contains("pinned") && line.contains("yes")),
            "{text}"
        );
    }
}
