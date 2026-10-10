//! Production [`QuerySource`] that talks to a running daemon over loopback HTTP.
//!
//! Tests keep constructing [`super::query::UnavailableSource`] themselves. Only
//! [`crate::cmd::execute_args`] builds this type, and only after `--http` (or the
//! platform default) has resolved to an endpoint.
//!
//! Missing optional JSON fields stay [`Option::None`]. A required field that is
//! absent is [`QueryError::Unavailable`] naming that field — never a guessed `0`
//! or `""`. A 200 with an empty list is a real empty list.
//!
//! `follow` does not poll. The daemon timeline page has `next_cursor` of the form
//! `ts_ns,id`, not an `after` bound, and this client reads one HTTP response then
//! closes the socket, so it cannot consume `GET /sessions/{sid}/live` (SSE).

use aw_core::{Evidence, NaReason};
use serde_json::Value;

use crate::client::{ApiRequest, Client, ClientError, LoopbackHttp};
use crate::endpoint::Endpoint;

use super::query::{
    encode_path_segment, encode_query, AroundItem, AroundPage, AroundQuery, FileItem, FileQuery,
    FindingItem, FindingQuery, FindingRef, FlowItem, GapItem, HttpItem, HttpPage, HttpQuery,
    ProcItem, QueryError, QuerySource, SearchHit, SearchQuery, SessionItem, SessionQuery,
    SessionShow, TimelineBounds, TimelineItem, TimelinePage,
};

/// One resolved daemon endpoint. The token lives inside [`Endpoint`] and is not logged.
pub(crate) struct HttpQuerySource {
    endpoint: Endpoint,
}

impl HttpQuerySource {
    /// Bind to `endpoint`. Does not connect.
    #[must_use]
    pub(crate) fn new(endpoint: Endpoint) -> Self {
        Self { endpoint }
    }

    fn call(&self, request: &ApiRequest) -> Result<Value, QueryError> {
        let transport = LoopbackHttp::new(&self.endpoint).map_err(client_to_query)?;
        let mut client = Client::new(self.endpoint.clone(), transport);
        let reply = client.call(request).map_err(client_to_query)?;
        reply.json().ok_or_else(|| QueryError::Unavailable {
            detail: "daemon returned a non-JSON body".to_owned(),
        })
    }
}

impl QuerySource for HttpQuerySource {
    fn list_sessions(&self, query: &SessionQuery) -> Result<Vec<SessionItem>, QueryError> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        if let Some(agent) = query.agent.as_deref() {
            pairs.push(("agent".to_owned(), agent.to_owned()));
        }
        if query.active_only {
            pairs.push(("active".to_owned(), "1".to_owned()));
        }
        if let Some(since) = query.since_ns {
            pairs.push(("since".to_owned(), since.to_string()));
        }
        if let Some(limit) = query.limit {
            let limit = i64::try_from(limit).unwrap_or(i64::MAX);
            pairs.push(("limit".to_owned(), limit.to_string()));
        }
        let body = self.call(&get_pairs("/api/v1/sessions", &pairs))?;
        let rows = array_field(&body, "sessions")?;
        rows.iter().map(session_item).collect()
    }

    fn show_session(&self, key: &str) -> Result<SessionShow, QueryError> {
        let path = format!("/api/v1/sessions/{}", encode_path_segment(key));
        let body = self.call(&ApiRequest::get(&path))?;
        // The store summary omits `mode` and `pinned`. Do not invent them.
        let mode = required_str(&body, "mode")?;
        let pinned = required_bool(&body, "pinned")?;
        let item = session_from_fields(&body, mode, pinned)?;
        let stats = body.get("stats").cloned().unwrap_or(Value::Null);
        Ok(SessionShow {
            item,
            process_count: opt_i64_field(&stats, "process_count")?,
            flow_count: opt_i64_field(&stats, "flow_count")?,
            dns_count: opt_i64_field(&stats, "dns_count")?,
            gap_count: opt_i64_field(&stats, "gap_count")?,
            bytes_up: opt_i64_field(&stats, "bytes_up")?,
            bytes_down: opt_i64_field(&stats, "bytes_down")?,
            // The session document does not carry a capability snapshot.
            capabilities: Vec::new(),
            gap_summaries: Vec::new(),
        })
    }

    fn rename_session(&mut self, key: &str, name: &str) -> Result<SessionItem, QueryError> {
        let _ = self.patch(key, &serde_json::json!({ "name": name }))?;
        // PATCH answers `{ "id" }` only. Re-read so the printed row is the
        // daemon's row, not a name this process guessed onto a missing session.
        Ok(self.show_session(key)?.item)
    }

    fn set_pinned(&mut self, key: &str, pinned: bool) -> Result<SessionItem, QueryError> {
        let _ = self.patch(key, &serde_json::json!({ "pinned": pinned }))?;
        Ok(self.show_session(key)?.item)
    }

    fn delete_sessions(&mut self, keys: &[String]) -> Result<u64, QueryError> {
        let mut removed = 0u64;
        for key in keys {
            let path = format!("/api/v1/sessions/{}", encode_path_segment(key));
            let request = ApiRequest {
                method: "DELETE".to_owned(),
                path,
                query: String::new(),
                body: Vec::new(),
            };
            let body = self.call(&request)?;
            // A 200 that does not name a deletion is not a success.
            match body.get("deleted") {
                Some(Value::String(_)) => removed = removed.saturating_add(1),
                Some(Value::Bool(true)) => removed = removed.saturating_add(1),
                _ => {
                    return Err(QueryError::Unavailable {
                        detail: "response is missing field `deleted`".to_owned(),
                    });
                }
            }
        }
        Ok(removed)
    }

    fn timeline(&self, key: &str, bounds: &TimelineBounds) -> Result<TimelinePage, QueryError> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        if let Some(filter) = bounds.filter.as_deref() {
            pairs.push(("filter".to_owned(), filter.to_owned()));
        }
        if let Some(from) = bounds.from_ns {
            pairs.push(("from".to_owned(), from.to_string()));
        }
        if let Some(to) = bounds.to_ns {
            pairs.push(("to".to_owned(), to.to_string()));
        }
        if let Some(limit) = bounds.limit {
            let limit = i64::try_from(limit).unwrap_or(i64::MAX);
            pairs.push(("limit".to_owned(), limit.to_string()));
        }
        let path = format!("/api/v1/sessions/{}/timeline", encode_path_segment(key));
        let body = self.call(&get_pairs(&path, &pairs))?;
        let rows = array_field(&body, "rows")?;
        let items = rows
            .iter()
            .map(timeline_item)
            .collect::<Result<Vec<_>, _>>()?;
        let next = match body.get("next_cursor") {
            None | Some(Value::Null) => false,
            Some(Value::String(text)) => !text.is_empty(),
            Some(_) => {
                return Err(QueryError::Unavailable {
                    detail: "field `next_cursor` is not a string".to_owned(),
                });
            }
        };
        Ok(TimelinePage { rows: items, next })
    }

    fn follow(&self, _key: &str, _after_ns: Option<i64>) -> Result<Vec<TimelineItem>, QueryError> {
        // `GET /sessions/{sid}/live` is SSE. LoopbackHttp reads one response and
        // closes. The timeline page's cursor is `ts_ns,id`, not an `after` bound,
        // so polling it would replay the same page. Do not invent a stream.
        Err(QueryError::Unavailable {
            detail: format!(
                "{FOLLOW_NOTE}; real-time /sessions/{{sid}}/live is not subscribed (真实订阅未接通)"
            ),
        })
    }

    fn procs(&self, key: &str, tree: bool) -> Result<Vec<ProcItem>, QueryError> {
        let pairs: Vec<(String, String)> = if tree {
            vec![("tree".to_owned(), "1".to_owned())]
        } else {
            Vec::new()
        };
        let path = format!("/api/v1/sessions/{}/processes", encode_path_segment(key));
        let body = self.call(&get_pairs(&path, &pairs))?;
        let rows = array_field(&body, "processes")?;
        rows.iter().map(|row| proc_item(row, tree)).collect()
    }

    fn flows(
        &self,
        key: &str,
        group_by: Option<&str>,
        sort: Option<&str>,
    ) -> Result<Vec<FlowItem>, QueryError> {
        let mut pairs: Vec<(String, String)> = Vec::new();
        if let Some(group_by) = group_by {
            pairs.push(("group_by".to_owned(), group_by.to_owned()));
        }
        if let Some(sort) = sort {
            pairs.push(("sort".to_owned(), sort.to_owned()));
        }
        let path = format!("/api/v1/sessions/{}/flows", encode_path_segment(key));
        let body = self.call(&get_pairs(&path, &pairs))?;
        let rows = array_field(&body, "flows")?;
        rows.iter().map(flow_item).collect()
    }

    fn gaps(&self, key: &str) -> Result<Vec<GapItem>, QueryError> {
        let path = format!("/api/v1/sessions/{}/gaps", encode_path_segment(key));
        let body = self.call(&ApiRequest::get(&path))?;
        let rows = array_field(&body, "gaps")?;
        rows.iter().map(gap_item).collect()
    }

    fn files(&self, key: &str, query: &FileQuery) -> Result<Vec<FileItem>, QueryError> {
        let request = super::query::files_request(key, query);
        let body = self.call(&request)?;
        // `group_by=dir` answers `{ "roots": [...] }`, which is not a file row.
        // Mapping a root onto FileItem would invent `op` and `first_ns`.
        if body.get("files").is_none() && body.get("roots").is_some() {
            return Err(QueryError::Unavailable {
                detail: "GET /sessions/{sid}/files group_by=dir returns directory roots, not file rows; this command does not invent a file from a directory count".to_owned(),
            });
        }
        let rows = array_field(&body, "files")?;
        rows.iter().map(file_item).collect()
    }

    fn around(&self, key: &str, query: &AroundQuery) -> Result<AroundPage, QueryError> {
        let window = ns_to_window(query.window_ns);
        let request = super::query::around_request(key, &query.reference, &window);
        let body = self.call(&request)?;
        let rows = array_field(&body, "rows")?;
        let items = rows
            .iter()
            .map(|row| around_item(row, &query.reference))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AroundPage { rows: items })
    }

    fn search(&self, query: &SearchQuery) -> Result<Vec<SearchHit>, QueryError> {
        let since = query.since_ns.map(|ns| ns.to_string());
        let request = super::query::search_request(query, since.as_deref());
        let body = self.call(&request)?;
        let rows = array_field(&body, "hits")?;
        // The daemon hit is `{ src, src_id, session_id, public_id }`. A hit
        // needs `summary`, `ts_ns`, and `evidence` to print, and those fields
        // are not in the document. An empty page is a real empty page.
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let _ = search_hit(&rows[0])?;
        Err(QueryError::Unavailable {
            detail: "GET /search hits omit summary, ts_ns, and evidence; this command does not invent them".to_owned(),
        })
    }

    fn http(&self, key: &str, query: &HttpQuery) -> Result<HttpPage, QueryError> {
        let request = super::query::http_request(key, query);
        let body = self.call(&request)?;
        let rows = array_field(&body, "http")?;
        let items = rows.iter().map(http_item).collect::<Result<Vec<_>, _>>()?;
        let reason = match body.get("reason") {
            None | Some(Value::Null) => None,
            Some(Value::String(text)) if text.is_empty() => None,
            Some(Value::String(text)) => Some(text.clone()),
            Some(_) => {
                return Err(QueryError::Unavailable {
                    detail: "field `reason` is not a string".to_owned(),
                });
            }
        };
        Ok(HttpPage {
            rows: items,
            reason,
        })
    }

    fn findings(&self, key: &str, query: &FindingQuery) -> Result<Vec<FindingItem>, QueryError> {
        let request = super::query::findings_request(key, query);
        let body = self.call(&request)?;
        let rows = array_field(&body, "findings")?;
        rows.iter().map(finding_item).collect()
    }
}

impl HttpQuerySource {
    fn patch(&self, key: &str, body: &Value) -> Result<Value, QueryError> {
        let path = format!("/api/v1/sessions/{}", encode_path_segment(key));
        self.call(&ApiRequest::json_method_public("PATCH", &path, body))
    }
}

const FOLLOW_NOTE: &str =
    "daemon timeline has no after cursor this client can poll, and GET /sessions/{sid}/live is an event stream this HTTP client does not keep open";

fn get_pairs(path: &str, pairs: &[(String, String)]) -> ApiRequest {
    let borrowed: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    ApiRequest::get_query(path, encode_query(&borrowed))
}

/// `window_ns` back into a duration the daemon's `window=` parser accepts.
fn ns_to_window(ns: i64) -> String {
    if ns <= 0 {
        return "0ns".to_owned();
    }
    if ns % 1_000_000_000 == 0 {
        return format!("{}s", ns / 1_000_000_000);
    }
    if ns % 1_000_000 == 0 {
        return format!("{}ms", ns / 1_000_000);
    }
    format!("{ns}ns")
}

fn client_to_query(err: ClientError) -> QueryError {
    match err {
        ClientError::Status {
            status: 404,
            message,
        } => QueryError::NotFound {
            session: clip(&message),
        },
        ClientError::Status {
            status: 400 | 422, ..
        } => QueryError::BadArgument {
            detail: clip(&err.to_string()),
        },
        ClientError::Forbidden { .. }
        | ClientError::Status {
            status: 401 | 403, ..
        } => QueryError::Unavailable {
            detail: clip(&format!("auth: {err}")),
        },
        ClientError::Unreachable { .. }
        | ClientError::Transport { .. }
        | ClientError::Status { .. } => QueryError::Unavailable {
            detail: clip(&err.to_string()),
        },
    }
}

fn clip(text: &str) -> String {
    const MAX: usize = 240;
    let mut out: String = text.chars().take(MAX).collect();
    if text.chars().count() > MAX {
        out.push('…');
    }
    out
}

fn session_item(value: &Value) -> Result<SessionItem, QueryError> {
    // Memory-stub rows are `{ id, user_id, name }` with no `mode`. That is not
    // a session record this command can print.
    let mode = required_str(value, "mode")?;
    let pinned = required_bool(value, "pinned")?;
    session_from_fields(value, mode, pinned)
}

fn session_from_fields(
    value: &Value,
    mode: String,
    pinned: bool,
) -> Result<SessionItem, QueryError> {
    let public_id = match value.get("id").and_then(Value::as_str) {
        Some(text) if !text.is_empty() => text.to_owned(),
        _ => {
            return Err(QueryError::Unavailable {
                detail: "response is missing field `id`".to_owned(),
            });
        }
    };
    Ok(SessionItem {
        public_id,
        name: opt_string(value, "name")?,
        mode,
        agent: opt_string(value, "agent")?,
        started_ns: required_i64(value, "started_ns")?,
        ended_ns: opt_i64_field(value, "ended_ns")?,
        pinned,
        // The list and summary documents do not carry an evidence level.
        // A session the daemon returned was observed by the tool.
        evidence: Evidence::E1,
    })
}

fn timeline_item(value: &Value) -> Result<TimelineItem, QueryError> {
    let cat = required_str(value, "cat")?;
    let evidence = evidence_field(value, "evidence")?;
    Ok(TimelineItem {
        ts_ns: required_i64(value, "ts_ns")?,
        cat: cat.clone(),
        id: required_i64(value, "id")?,
        proc_uid: opt_proc_uid(value, "proc_uid")?,
        // The daemon timeline row has no summary text. Printing the category
        // is the field that exists, not an invented description.
        summary: cat.clone(),
        evidence,
        is_gap: cat == "gap",
    })
}

fn proc_item(value: &Value, tree: bool) -> Result<ProcItem, QueryError> {
    let children = if tree {
        match value.get("children") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(rows)) => rows
                .iter()
                .map(|row| proc_item(row, true))
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(QueryError::Unavailable {
                    detail: "field `children` is not an array".to_owned(),
                });
            }
        }
    } else {
        Vec::new()
    };
    Ok(ProcItem {
        proc_uid: required_proc_uid(value)?,
        pid: required_i64(value, "pid")?,
        parent_uid: opt_proc_uid(value, "parent_uid")?,
        exe_name: opt_string(value, "exe_name")?,
        // Process nodes do not carry argv. Leave it unknown.
        argv_redacted: None,
        evidence: evidence_field(value, "evidence")?,
        children,
    })
}

fn flow_item(value: &Value) -> Result<FlowItem, QueryError> {
    let domain = opt_string(value, "domain")?;
    Ok(FlowItem {
        id: opt_i64_field(value, "id")?,
        proc_uid: opt_proc_uid(value, "proc_uid")?,
        local_port: opt_i64_field(value, "local_port")?,
        remote_port: opt_i64_field(value, "remote_port")?,
        remote_ip: opt_string(value, "remote_ip")?,
        domain,
        domain_source: opt_string(value, "domain_source")?,
        domain_evidence: match value.get("domain_evidence") {
            None | Some(Value::Null) => None,
            Some(_) => Some(evidence_field(value, "domain_evidence")?),
        },
        bytes_up: opt_i64_field(value, "bytes_up")?,
        bytes_down: opt_i64_field(value, "bytes_down")?,
        start_ns: required_i64(value, "start_ns")?,
        evidence: match value.get("evidence") {
            None | Some(Value::Null) => None,
            Some(_) => Some(evidence_field(value, "evidence")?),
        },
        count: value
            .get("count")
            .map(|_| required_i64(value, "count"))
            .transpose()?
            .unwrap_or(1),
    })
}

fn gap_item(value: &Value) -> Result<GapItem, QueryError> {
    let affects = match value.get("affects") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => {
            let mut parts = Vec::new();
            for item in items {
                match item.as_str() {
                    Some(text) => parts.push(text.to_owned()),
                    None => {
                        return Err(QueryError::Unavailable {
                            detail: "field `affects` has a non-string entry".to_owned(),
                        });
                    }
                }
            }
            parts.join(",")
        }
        None | Some(Value::Null) => {
            return Err(QueryError::Unavailable {
                detail: "response is missing field `affects`".to_owned(),
            });
        }
        Some(_) => {
            return Err(QueryError::Unavailable {
                detail: "field `affects` is not a string or array".to_owned(),
            });
        }
    };
    let evidence = match value.get("evidence") {
        None | Some(Value::Null) => Evidence::E1,
        Some(_) => evidence_field(value, "evidence")?,
    };
    Ok(GapItem {
        id: required_i64(value, "id")?,
        collector: required_str(value, "collector")?,
        kind: required_str(value, "kind")?,
        affects,
        from_ns: required_i64(value, "from_ns")?,
        to_ns: required_i64(value, "to_ns")?,
        count: opt_i64_field(value, "count")?,
        detail: opt_string(value, "detail")?,
        evidence,
    })
}

fn file_item(value: &Value) -> Result<FileItem, QueryError> {
    let proc = value.get("proc");
    let (proc_pid, proc_exe) = match proc {
        None | Some(Value::Null) => (None, None),
        Some(obj) => (opt_i64_field(obj, "pid")?, opt_string(obj, "exe_name")?),
    };
    Ok(FileItem {
        id: opt_i64_field(value, "id")?,
        proc_uid: opt_proc_uid(value, "proc_uid")?,
        proc_pid,
        proc_exe,
        op: required_str(value, "op")?,
        path: required_str(value, "path")?,
        path_to: opt_string(value, "path_to")?,
        dir: opt_string(value, "dir")?,
        access: opt_string(value, "access")?,
        first_ns: required_i64(value, "first_ns")?,
        opens: opt_i64_field(value, "opens")?,
        bytes_read: opt_i64_field(value, "bytes_read")?,
        bytes_written: opt_i64_field(value, "bytes_written")?,
        result: opt_i64_field(value, "result")?,
        sensitive_rule: opt_string(value, "sensitive_rule")?,
        evidence: match value.get("evidence") {
            None | Some(Value::Null) => None,
            Some(_) => Some(evidence_field(value, "evidence")?),
        },
        na_reason: opt_string(value, "na_reason")?,
        count: value
            .get("count")
            .map(|_| required_i64(value, "count"))
            .transpose()?
            .unwrap_or(1),
    })
}

fn around_item(value: &Value, anchor_ref: &str) -> Result<AroundItem, QueryError> {
    // `/around` reuses the timeline row. It has no per-row reference. The anchor
    // is the row whose category table and id match `table:id`.
    let cat = required_str(value, "cat")?;
    let id = required_i64(value, "id")?;
    let table = match cat.as_str() {
        "proc" => "processes",
        "net" => "net_flow",
        "dns" => "dns",
        "gap" => "gaps",
        "file" => "file_access",
        other => other,
    };
    let reference = format!("{table}:{id}");
    let anchor = reference == anchor_ref || format!("{cat}:{id}") == anchor_ref;
    Ok(AroundItem {
        reference,
        ts_ns: required_i64(value, "ts_ns")?,
        table: table.to_owned(),
        summary: cat.clone(),
        evidence: evidence_field(value, "evidence")?,
        anchor,
        is_gap: cat == "gap",
        sensitive_rule: opt_string(value, "sensitive_rule")?,
    })
}

fn search_hit(value: &Value) -> Result<SearchHit, QueryError> {
    let src = required_str(value, "src")?;
    let src_id = required_i64(value, "src_id")?;
    let kind = match src.as_str() {
        "file_access" => "file",
        "process_images" | "processes" => "proc",
        "http" => "url",
        other => other,
    };
    let session = match value.get("public_id").and_then(Value::as_str) {
        Some(text) if !text.is_empty() => text.to_owned(),
        _ => {
            return Err(QueryError::Unavailable {
                detail: "response is missing field `public_id`".to_owned(),
            });
        }
    };
    // The search document is `{ src, src_id, session_id, public_id }`. It has
    // no summary, evidence, or timestamp. Those are required to print a hit,
    // and inventing them would mark a guess as a record.
    let summary = match value.get("summary").and_then(Value::as_str) {
        Some(text) if !text.is_empty() => text.to_owned(),
        _ => {
            return Err(QueryError::Unavailable {
                detail: "response is missing field `summary`".to_owned(),
            });
        }
    };
    let evidence = evidence_field(value, "evidence")?;
    let ts_ns = required_i64(value, "ts_ns")?;
    Ok(SearchHit {
        session,
        session_name: opt_string(value, "session_name")?,
        kind: kind.to_owned(),
        reference: format!("{src}:{src_id}"),
        ts_ns,
        summary,
        evidence,
        sensitive_rule: opt_string(value, "sensitive_rule")?,
    })
}

fn http_item(value: &Value) -> Result<HttpItem, QueryError> {
    let proc = value.get("proc");
    let (proc_pid, proc_exe) = match proc {
        None | Some(Value::Null) => (None, None),
        Some(obj) => (opt_i64_field(obj, "pid")?, opt_string(obj, "exe_name")?),
    };
    Ok(HttpItem {
        id: required_i64(value, "id")?,
        ts_ns: required_i64(value, "ts_ns")?,
        proc_uid: opt_proc_uid(value, "proc_uid")?,
        proc_pid,
        proc_exe,
        method: required_str(value, "method")?,
        url: required_str(value, "url")?,
        status: opt_i64_field(value, "status")?,
        req_body_bytes: opt_i64_field(value, "req_body_bytes")?,
        resp_body_bytes: opt_i64_field(value, "resp_body_bytes")?,
        duration_ms: opt_i64_field(value, "duration_ms")?,
        evidence: match value.get("evidence") {
            None | Some(Value::Null) => None,
            Some(_) => Some(evidence_field(value, "evidence")?),
        },
    })
}

fn finding_item(value: &Value) -> Result<FindingItem, QueryError> {
    let params = match value.get("params") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(map)) => map
            .iter()
            .map(|(key, item)| {
                let text = match item {
                    Value::String(text) => text.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(flag) => flag.to_string(),
                    Value::Null => {
                        return Err(QueryError::Unavailable {
                            detail: format!("field `params.{key}` is null"),
                        });
                    }
                    _ => {
                        return Err(QueryError::Unavailable {
                            detail: format!("field `params.{key}` is not a scalar"),
                        });
                    }
                };
                Ok((key.clone(), text))
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                let key = item
                    .get("key")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("name").and_then(Value::as_str));
                let text = item.get("value").and_then(Value::as_str);
                match (key, text) {
                    (Some(key), Some(text)) => Ok((key.to_owned(), text.to_owned())),
                    _ => Err(QueryError::Unavailable {
                        detail: "field `params` entry is missing `key` or `value`".to_owned(),
                    }),
                }
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(QueryError::Unavailable {
                detail: "field `params` is not an object or array".to_owned(),
            });
        }
    };
    let refs = match value.get("refs") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .map(finding_ref)
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(QueryError::Unavailable {
                detail: "field `refs` is not an array".to_owned(),
            });
        }
    };
    Ok(FindingItem {
        id: required_i64(value, "id")?,
        rule_id: required_str(value, "rule_id")?,
        kind: required_str(value, "kind")?,
        evidence: required_str(value, "evidence")?,
        severity: required_str(value, "severity")?,
        wording_id: required_str(value, "wording_id")?,
        params,
        text: opt_string(value, "text")?,
        error: opt_string(value, "error")?,
        count: required_i64(value, "count")?,
        first_ns: required_i64(value, "first_ns")?,
        last_ns: required_i64(value, "last_ns")?,
        refs,
    })
}

fn finding_ref(value: &Value) -> Result<FindingRef, QueryError> {
    if let (Some(table), Some(id)) = (
        value.get("table").and_then(Value::as_str),
        value.get("id").and_then(Value::as_i64),
    ) {
        return Ok(FindingRef {
            table: table.to_owned(),
            id,
        });
    }
    // Stored refs may be `{ "file_access": 1 }` rather than `{ table, id }`.
    if let Some(map) = value.as_object() {
        if let Some((table, id_value)) = map.iter().next() {
            if map.len() == 1 {
                if let Some(id) = id_value.as_i64() {
                    return Ok(FindingRef {
                        table: table.clone(),
                        id,
                    });
                }
            }
        }
    }
    Err(QueryError::Unavailable {
        detail: "field `refs` entry is missing `table` and `id`".to_owned(),
    })
}

fn array_field<'a>(value: &'a Value, name: &str) -> Result<&'a Vec<Value>, QueryError> {
    match value.get(name) {
        Some(Value::Array(rows)) => Ok(rows),
        Some(_) => Err(QueryError::Unavailable {
            detail: format!("field `{name}` is not an array"),
        }),
        None => Err(QueryError::Unavailable {
            detail: format!("response is missing field `{name}`"),
        }),
    }
}

fn required_str(value: &Value, name: &str) -> Result<String, QueryError> {
    match value.get(name) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        Some(Value::String(_)) => Err(QueryError::Unavailable {
            detail: format!("field `{name}` is empty"),
        }),
        Some(Value::Null) | None => Err(QueryError::Unavailable {
            detail: format!("response is missing field `{name}`"),
        }),
        Some(_) => Err(QueryError::Unavailable {
            detail: format!("field `{name}` is not a string"),
        }),
    }
}

fn required_bool(value: &Value, name: &str) -> Result<bool, QueryError> {
    match value.get(name) {
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(Value::Null) | None => Err(QueryError::Unavailable {
            detail: format!("response is missing field `{name}`"),
        }),
        Some(_) => Err(QueryError::Unavailable {
            detail: format!("field `{name}` is not a bool"),
        }),
    }
}

fn required_i64(value: &Value, name: &str) -> Result<i64, QueryError> {
    match value.get(name).and_then(json_i64) {
        Some(n) => Ok(n),
        None => Err(QueryError::Unavailable {
            detail: format!("response is missing field `{name}`"),
        }),
    }
}

fn opt_i64_field(value: &Value, name: &str) -> Result<Option<i64>, QueryError> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(other) => json_i64(other)
            .map(Some)
            .ok_or_else(|| QueryError::Unavailable {
                detail: format!("field `{name}` is not an integer"),
            }),
    }
}

fn opt_string(value: &Value, name: &str) -> Result<Option<String>, QueryError> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.is_empty() => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(QueryError::Unavailable {
            detail: format!("field `{name}` is not a string"),
        }),
    }
}

fn json_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok()))
}

/// Process ids travel as hex strings (`format!("{id:x}")`) or as integers.
fn opt_proc_uid(value: &Value, name: &str) -> Result<Option<i64>, QueryError> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.is_empty() => Ok(None),
        Some(Value::String(text)) => {
            parse_hex_i64(text)
                .map(Some)
                .ok_or_else(|| QueryError::Unavailable {
                    detail: format!("field `{name}` is not a proc uid"),
                })
        }
        Some(other) => json_i64(other)
            .map(Some)
            .ok_or_else(|| QueryError::Unavailable {
                detail: format!("field `{name}` is not a proc uid"),
            }),
    }
}

fn required_proc_uid(value: &Value) -> Result<i64, QueryError> {
    opt_proc_uid(value, "proc_uid")?.ok_or_else(|| QueryError::Unavailable {
        detail: "response is missing field `proc_uid`".to_owned(),
    })
}

fn parse_hex_i64(text: &str) -> Option<i64> {
    let hex = text.strip_prefix("0x").unwrap_or(text);
    u64::from_str_radix(hex, 16).ok().map(|n| n as i64)
}

fn evidence_field(value: &Value, name: &str) -> Result<Evidence, QueryError> {
    let text = match value.get(name) {
        Some(Value::String(text)) => text.as_str(),
        Some(Value::Object(obj)) => return parse_evidence_object(obj),
        Some(Value::Null) | None => {
            return Err(QueryError::Unavailable {
                detail: format!("response is missing field `{name}`"),
            });
        }
        Some(_) => {
            return Err(QueryError::Unavailable {
                detail: format!("field `{name}` is not an evidence code"),
            });
        }
    };
    parse_evidence_code(text).ok_or_else(|| QueryError::Unavailable {
        detail: format!("field `{name}` is not an evidence code"),
    })
}

fn parse_evidence_object(value: &serde_json::Map<String, Value>) -> Result<Evidence, QueryError> {
    let level = value.get("level").and_then(Value::as_str).unwrap_or("");
    if level == "NA" {
        let reason = value
            .get("reason")
            .and_then(Value::as_str)
            .map(parse_na_reason)
            .unwrap_or(NaReason::Unknown);
        return Ok(Evidence::NA(reason));
    }
    parse_evidence_code(level).ok_or_else(|| QueryError::Unavailable {
        detail: "field `evidence` is not an evidence code".to_owned(),
    })
}

fn parse_evidence_code(text: &str) -> Option<Evidence> {
    let (level, reason) = text.split_once('(').unwrap_or((text, ""));
    let level = level.trim();
    match level {
        "E1" => Some(Evidence::E1),
        "E2" => Some(Evidence::E2),
        "E3" => Some(Evidence::E3),
        "S" => Some(Evidence::S),
        "I" => Some(Evidence::I),
        "NA" => {
            let reason = reason.trim().trim_end_matches(')').trim();
            let parsed = if reason.is_empty() {
                NaReason::Unknown
            } else {
                parse_na_reason(reason)
            };
            Some(Evidence::NA(parsed))
        }
        _ => None,
    }
}

fn parse_na_reason(text: &str) -> NaReason {
    match text {
        "es_no_read_event" => NaReason::EsNoReadEvent,
        "mmap_not_observable" => NaReason::MmapNotObservable,
        "tls_no_proxy" => NaReason::TlsNoProxy,
        "direct_bypass_proxy" => NaReason::DirectBypassProxy,
        "cert_pinned" => NaReason::CertPinned,
        "quic" => NaReason::Quic,
        "ech" => NaReason::Ech,
        "no_dns_observed" => NaReason::NoDnsObserved,
        "preexisting" => NaReason::Preexisting,
        "collector_unavailable" => NaReason::CollectorUnavailable,
        "redacted" => NaReason::Redacted,
        "attribution_break" => NaReason::AttributionBreak,
        "partial_client_hello" => NaReason::PartialClientHello,
        "h2_hpack" => NaReason::H2Hpack,
        "too_large" => NaReason::TooLarge,
        "file_changed" => NaReason::FileChanged,
        "peer_unknown" => NaReason::PeerUnknown,
        "protocol_not_observed" => NaReason::ProtocolNotObserved,
        _ => NaReason::Unknown,
    }
}
