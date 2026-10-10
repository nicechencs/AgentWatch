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

/// Render the process list or tree.
///
/// # Errors
///
/// A failure to format the outcome.
pub(crate) fn run(
    session: &str,
    tree: bool,
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
    match source.procs(session, tree) {
        Ok(nodes) => {
            let table = render::procs_table(&nodes, tree);
            let doc = render::procs_json(&nodes, tree);
            write_ok(mode, &table, &doc)
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
        let outcome = run("s-someone-else", false, false, &source).expect("procs");
        assert_eq!(outcome.code, exit::GENERAL);
        assert_eq!(
            paths.borrow().clone(),
            vec!["/api/v1/sessions/s-someone-else/processes".to_owned()]
        );
        assert_eq!(
            String::from_utf8(outcome.stderr).expect("utf8"),
            "aw: 找不到会话 `s-someone-else`\n"
        );
    }
}
