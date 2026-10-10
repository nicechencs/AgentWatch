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

use std::cell::RefCell;

use aw_core::{Evidence, NaReason};
use serde_json::Value;

use crate::client::{ApiRequest, Client, ClientError, LoopbackHttp, Transport};
use crate::endpoint::Endpoint;

use super::query::{
    encode_path_segment, encode_query, AroundItem, AroundPage, AroundQuery, FileItem, FileQuery,
    FindingItem, FindingQuery, FindingRef, FlowItem, GapItem, HttpItem, HttpPage, HttpQuery,
    ProcItem, QueryError, QuerySource, SearchHit, SearchQuery, SessionItem, SessionQuery,
    SessionShow, TimelineBounds, TimelineItem, TimelinePage,
};

/// Lends a [`Transport`] to [`Client`], which takes one by value.
struct Passthrough<'a, T>(&'a mut T);

impl<T: Transport> Transport for Passthrough<'_, T> {
    fn exchange(&mut self, request: &ApiRequest) -> Result<crate::client::ApiReply, ClientError> {
        self.0.exchange(request)
    }
}

/// One resolved daemon endpoint. The token lives inside [`Endpoint`] and is not logged.
pub(crate) struct HttpQuerySource<T: Transport = LoopbackHttp> {
    endpoint: Endpoint,
    /// `None` dials per call. Tests pass a scripted transport. Interior
    /// mutability because [`QuerySource`] hands out `&self`.
    transport: Option<RefCell<T>>,
}

impl HttpQuerySource<LoopbackHttp> {
    /// Bind to `endpoint`. Does not connect.
    #[must_use]
    pub(crate) fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            transport: None,
        }
    }
}

impl<T: Transport> HttpQuerySource<T> {
    /// Bind to `endpoint` and answer every call with `transport`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_transport(endpoint: Endpoint, transport: T) -> Self {
        Self {
            endpoint,
            transport: Some(RefCell::new(transport)),
        }
    }

    fn call(&self, request: &ApiRequest) -> Result<Value, QueryError> {
        self.call_session(request, None)
    }

    /// `session` is what the user typed. A 404 names it, instead of the
    /// daemon's English message.
    fn call_session(
        &self,
        request: &ApiRequest,
        session: Option<&str>,
    ) -> Result<Value, QueryError> {
        let reply = match self.transport.as_ref() {
            Some(transport) => {
                let mut transport = transport.borrow_mut();
                let mut client = Client::new(self.endpoint.clone(), Passthrough(&mut *transport));
                client
                    .call(request)
                    .map_err(|err| client_to_query_for(&err, session))?
            }
            None => {
                let transport = LoopbackHttp::new(&self.endpoint).map_err(client_to_query)?;
                let mut client = Client::new(self.endpoint.clone(), transport);
                client
                    .call(request)
                    .map_err(|err| client_to_query_for(&err, session))?
            }
        };
        reply.json().ok_or_else(|| QueryError::Unavailable {
            detail: "后台返回的响应体不是 JSON".to_owned(),
        })
    }
}

impl<T: Transport> QuerySource for HttpQuerySource<T> {
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
        // `@last` is resolved by the daemon against this caller's sessions, so
        // it is sent as-is. A name is resolved here, but only among the
        // sessions the daemon already filtered to this caller.
        let (resolved, fetched) = self.resolve_session_key(key)?;
        let body = match fetched {
            Some(body) => body,
            None => {
                let path = format!("/api/v1/sessions/{}", encode_path_segment(&resolved));
                self.call_session(&ApiRequest::get(&path), Some(key))?
            }
        };
        let item = session_item(&body)?;
        let stats = body.get("stats").cloned().unwrap_or(Value::Null);
        Ok(SessionShow {
            item,
            process_count: opt_i64_field(&stats, "process_count")?,
            flow_count: opt_i64_field(&stats, "flow_count")?,
            dns_count: opt_i64_field(&stats, "dns_count")?,
            gap_count: opt_i64_field(&stats, "gap_count")?,
            // The store summary sends `exit_code` (null when not observed).
            exit_code: opt_i64_field(&body, "exit_code")?,
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
                        detail: missing_field("deleted"),
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
                    detail: "字段 `next_cursor` 不是字符串".to_owned(),
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
            detail: format!("{FOLLOW_NOTE}；没有订阅实时 /sessions/{{sid}}/live（真实订阅未接通）"),
        })
    }

    fn procs(&self, key: &str, tree: bool) -> Result<Vec<ProcItem>, QueryError> {
        let pairs: Vec<(String, String)> = if tree {
            vec![("tree".to_owned(), "1".to_owned())]
        } else {
            Vec::new()
        };
        let path = format!("/api/v1/sessions/{}/processes", encode_path_segment(key));
        // `key` is what the user typed. A 404 must name it; dropping it prints
        // 「找不到会话 ``」.
        let body = self.call_session(&get_pairs(&path, &pairs), Some(key))?;
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
                detail: "GET /sessions/{sid}/files 的 group_by=dir 返回目录根，不是文件行；此命令不会根据目录计数编造文件".to_owned(),
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
        rows.iter().map(search_hit).collect()
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
                    detail: "字段 `reason` 不是字符串".to_owned(),
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

impl<T: Transport> HttpQuerySource<T> {
    /// `@last` and `s-` ids pass through (`None`: the caller still fetches).
    /// Anything else is a name, resolved among the caller's own sessions. One
    /// match returns that row's document, so the caller does not fetch again.
    /// No match returns the key unchanged and the daemon answers 404.
    fn resolve_session_key(&self, key: &str) -> Result<(String, Option<Value>), QueryError> {
        if key == "@last" || key.starts_with("s-") {
            return Ok((key.to_owned(), None));
        }
        let body = self.call(&get_pairs(
            "/api/v1/sessions",
            &[("limit".to_owned(), "500".to_owned())],
        ))?;
        let rows = array_field(&body, "sessions")?;
        let matches: Vec<&Value> = rows
            .iter()
            .filter(|row| row.get("name").and_then(Value::as_str) == Some(key))
            .collect();
        match matches.as_slice() {
            [] => Ok((key.to_owned(), None)),
            [one] => {
                let id = one
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| QueryError::Unavailable {
                        detail: "响应缺少字段 `id`".to_owned(),
                    })?;
                Ok((id.to_owned(), Some((*one).clone())))
            }
            many => Err(QueryError::BadArgument {
                detail: format!(
                    "有 {} 个会话名为 `{key}`；请传入 `aw sessions list` 中的公开 ID",
                    many.len()
                ),
            }),
        }
    }

    fn patch(&self, key: &str, body: &Value) -> Result<Value, QueryError> {
        let path = format!("/api/v1/sessions/{}", encode_path_segment(key));
        self.call(&ApiRequest::json_method_public("PATCH", &path, body))
    }
}

const FOLLOW_NOTE: &str =
    "后台时间线没有可供此客户端轮询的 after 游标，且 GET /sessions/{sid}/live 是此 HTTP 客户端不会保持打开的事件流";

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
    client_to_query_for(&err, None)
}

/// [`client_to_query`], but a 404 names `key` — what the user typed — instead
/// of the daemon's English message.
fn client_to_query_for(err: &ClientError, key: Option<&str>) -> QueryError {
    match err {
        ClientError::Status {
            status: 404,
            code: Some(code),
            ..
        } if code == "no_sessions" => QueryError::NoSessions,
        ClientError::Status { status: 404, .. } => QueryError::NotFound {
            session: key.unwrap_or("").to_owned(),
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
            detail: clip(&format!("认证失败：{err}")),
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
    // `GET /sessions` (store page) sends both. `GET /sessions/{id}` is the store
    // summary, which has `mode` and omits `pinned`. A missing flag is not
    // observed (None → 没采), not an unpinned session.
    // The in-memory stub answers `{ id, user_id, name }` with neither: `mode`
    // stays unknown and is printed as 不可得, not invented.
    let mode = match value.get("mode") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        Some(Value::String(_)) | Some(Value::Null) | None => "不可得".to_owned(),
        Some(_) => {
            return Err(QueryError::Unavailable {
                detail: "字段 `mode` 不是字符串".to_owned(),
            });
        }
    };
    let pinned = optional_bool(value, "pinned")?;
    session_from_fields(value, mode, pinned)
}

fn session_from_fields(
    value: &Value,
    mode: String,
    pinned: Option<bool>,
) -> Result<SessionItem, QueryError> {
    let public_id = match value.get("id").and_then(Value::as_str) {
        Some(text) if !text.is_empty() => text.to_owned(),
        _ => {
            return Err(QueryError::Unavailable {
                detail: missing_field("id"),
            });
        }
    };
    Ok(SessionItem {
        public_id,
        name: opt_string(value, "name")?,
        mode,
        agent: opt_string(value, "agent")?,
        // The store page sends it. The in-memory stub row does not; a missing
        // start stays unknown rather than failing the whole list.
        started_ns: opt_i64_field(value, "started_ns")?,
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
                    detail: "字段 `children` 不是数组".to_owned(),
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
        exit_code: opt_i64_field(value, "exit_code")?,
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
                            detail: "字段 `affects` 有非字符串条目".to_owned(),
                        });
                    }
                }
            }
            parts.join(",")
        }
        None | Some(Value::Null) => {
            return Err(QueryError::Unavailable {
                detail: missing_field("affects"),
            });
        }
        Some(_) => {
            return Err(QueryError::Unavailable {
                detail: "字段 `affects` 不是字符串或数组".to_owned(),
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
    // The daemon hit is `{ src, src_id, session_id, public_id, text, ts_ns,
    // evidence, session_name }`. `text` is the stored row (file path or
    // executable path); the page calls that the summary. A field the daemon
    // left null stays unknown: time prints 不可得, evidence prints NA.
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
                detail: missing_field("public_id"),
            });
        }
    };
    let summary = match value.get("summary").and_then(Value::as_str) {
        Some(text) if !text.is_empty() => text.to_owned(),
        _ => match value.get("text").and_then(Value::as_str) {
            Some(text) if !text.is_empty() => text.to_owned(),
            _ => "不可得".to_owned(),
        },
    };
    let evidence = match value.get("evidence") {
        None | Some(Value::Null) => Evidence::NA(NaReason::Unknown),
        Some(_) => evidence_field(value, "evidence")?,
    };
    // Absent time stays unknown. `0` would be the epoch, which was not observed.
    let ts_ns = opt_i64_field(value, "ts_ns")?;
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
                            detail: format!("字段 `params.{key}` 为 null"),
                        });
                    }
                    _ => {
                        return Err(QueryError::Unavailable {
                            detail: format!("字段 `params.{key}` 不是标量"),
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
                        detail: "字段 `params` 的条目缺少 `key` 或 `value`".to_owned(),
                    }),
                }
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(QueryError::Unavailable {
                detail: "字段 `params` 不是对象或数组".to_owned(),
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
                detail: "字段 `refs` 不是数组".to_owned(),
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
        detail: "字段 `refs` 的条目缺少 `table` 和 `id`".to_owned(),
    })
}

/// User-facing text for a JSON field the daemon left out.
fn missing_field(name: &str) -> String {
    format!("后台返回的数据缺少字段 `{name}`")
}

fn array_field<'a>(value: &'a Value, name: &str) -> Result<&'a Vec<Value>, QueryError> {
    match value.get(name) {
        Some(Value::Array(rows)) => Ok(rows),
        Some(_) => Err(QueryError::Unavailable {
            detail: format!("字段 `{name}` 不是数组"),
        }),
        None => Err(QueryError::Unavailable {
            detail: missing_field(name),
        }),
    }
}

fn required_str(value: &Value, name: &str) -> Result<String, QueryError> {
    match value.get(name) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        Some(Value::String(_)) => Err(QueryError::Unavailable {
            detail: format!("字段 `{name}` 为空"),
        }),
        Some(Value::Null) | None => Err(QueryError::Unavailable {
            detail: missing_field(name),
        }),
        Some(_) => Err(QueryError::Unavailable {
            detail: format!("字段 `{name}` 不是字符串"),
        }),
    }
}

/// A bool the daemon may omit. `None` is "not sent", distinct from `Some(false)`.
fn optional_bool(value: &Value, name: &str) -> Result<Option<bool>, QueryError> {
    match value.get(name) {
        Some(Value::Bool(flag)) => Ok(Some(*flag)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(QueryError::Unavailable {
            detail: format!("字段 `{name}` 不是布尔值"),
        }),
    }
}

fn required_i64(value: &Value, name: &str) -> Result<i64, QueryError> {
    match value.get(name).and_then(json_i64) {
        Some(n) => Ok(n),
        None => Err(QueryError::Unavailable {
            detail: missing_field(name),
        }),
    }
}

fn opt_i64_field(value: &Value, name: &str) -> Result<Option<i64>, QueryError> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(other) => json_i64(other)
            .map(Some)
            .ok_or_else(|| QueryError::Unavailable {
                detail: format!("字段 `{name}` 不是整数"),
            }),
    }
}

fn opt_string(value: &Value, name: &str) -> Result<Option<String>, QueryError> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.is_empty() => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(QueryError::Unavailable {
            detail: format!("字段 `{name}` 不是字符串"),
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
                    detail: format!("字段 `{name}` 不是进程 UID"),
                })
        }
        Some(other) => json_i64(other)
            .map(Some)
            .ok_or_else(|| QueryError::Unavailable {
                detail: format!("字段 `{name}` 不是进程 UID"),
            }),
    }
}

fn required_proc_uid(value: &Value) -> Result<i64, QueryError> {
    opt_proc_uid(value, "proc_uid")?.ok_or_else(|| QueryError::Unavailable {
        detail: missing_field("proc_uid"),
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
                detail: missing_field(name),
            });
        }
        Some(_) => {
            return Err(QueryError::Unavailable {
                detail: format!("字段 `{name}` 不是证据代码"),
            });
        }
    };
    parse_evidence_code(text).ok_or_else(|| QueryError::Unavailable {
        detail: format!("字段 `{name}` 不是证据代码"),
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
        detail: "字段 `evidence` 不是证据代码".to_owned(),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{gap_item, search_hit, session_item};
    use crate::cmd::query::SessionShow;
    use crate::cmd::render;
    use crate::output::OutputMode;
    use aw_core::Evidence;

    /// `GET /sessions/{id}` as the daemon builds it: the store summary, which
    /// has `mode` and `stats` and no `pinned`.
    const SESSION_DETAIL: &str = r#"{
        "id": "s-7k2m",
        "session_id": 4,
        "name": "demo",
        "agent": "example-agent",
        "started_ns": 1700000000000000000,
        "ended_ns": null,
        "mode": "launch",
        "collectors": [],
        "argv": null,
        "stats": {
            "process_count": 2,
            "flow_count": 1,
            "dns_count": 0,
            "gap_count": 0,
            "bytes_up": null,
            "bytes_down": null,
            "finding_count": null
        }
    }"#;

    /// The show page `aw sessions show` prints, built the same way
    /// `HttpQuerySource::show_session` builds it.
    fn shown(body: &str) -> SessionShow {
        let value: serde_json::Value = serde_json::from_str(body).expect("json");
        let item = session_item(&value).expect("parse");
        let stats = value
            .get("stats")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        SessionShow {
            item,
            process_count: super::opt_i64_field(&stats, "process_count").expect("count"),
            flow_count: super::opt_i64_field(&stats, "flow_count").expect("count"),
            dns_count: super::opt_i64_field(&stats, "dns_count").expect("count"),
            gap_count: super::opt_i64_field(&stats, "gap_count").expect("count"),
            exit_code: super::opt_i64_field(&value, "exit_code").expect("exit"),
            bytes_up: super::opt_i64_field(&stats, "bytes_up").expect("count"),
            bytes_down: super::opt_i64_field(&stats, "bytes_down").expect("count"),
            capabilities: Vec::new(),
            gap_summaries: Vec::new(),
        }
    }

    #[test]
    fn session_detail_without_pinned_parses_and_renders() {
        let shown = shown(SESSION_DETAIL);
        // The store summary omits `pinned`. That is not observed, not unpinned.
        assert_eq!(shown.item.pinned, None);
        // No `exit_code` in this fixture stays unknown; it is not printed as 0.
        assert_eq!(shown.exit_code, None);
        assert_eq!(shown.item.public_id, "s-7k2m");
        assert_eq!(shown.item.mode, "launch");
        assert_eq!(shown.item.started_ns, Some(1_700_000_000_000_000_000));
        assert_eq!(shown.process_count, Some(2));
        // A null byte count stays unknown; it is not printed as 0.
        assert_eq!(shown.bytes_up, None);

        let mut buf = Vec::new();
        render::write_out(
            &mut buf,
            OutputMode::Table,
            &render::show_table(&shown),
            &render::show_json(&shown),
        )
        .expect("render");
        let text = String::from_utf8(buf).expect("utf8");
        assert!(text.contains("demo"), "{text}");
        assert!(text.contains("launch"), "{text}");
        assert!(text.contains("没采"), "{text}");
        assert!(!text.contains("no"), "{text}");
    }

    /// A list row the stub serves has no `mode` and no `pinned`. Both are
    /// optional: pinned stays unknown, mode is reported as unknown.
    #[test]
    fn session_list_row_without_mode_or_pinned_parses() {
        let value = serde_json::json!({ "id": "s-1", "user_id": "u", "name": "n" });
        let item = session_item(&value).expect("parse");
        assert_eq!(item.pinned, None);
        assert_eq!(item.mode, "不可得");
        assert_eq!(item.name.as_deref(), Some("n"));
    }

    /// `GET /search` hit as `search_hit_json` builds it: the row's stored text
    /// stands in for a summary, and a null time stays unknown.
    #[test]
    fn search_hit_uses_text_and_keeps_a_missing_time_unknown() {
        let value = serde_json::json!({
            "src": "file_access",
            "src_id": 3,
            "session_id": 1,
            "public_id": "s-7k2m",
            "text": "/tmp/notes.txt",
            "ts_ns": null,
            "evidence": null,
            "session_name": null,
        });
        let hit = search_hit(&value).expect("parse");
        assert_eq!(hit.kind, "file");
        assert_eq!(hit.reference, "file_access:3");
        assert_eq!(hit.summary, "/tmp/notes.txt");
        assert_eq!(hit.ts_ns, None);
        assert!(matches!(hit.evidence, Evidence::NA(_)));
    }

    /// `gap_json` sends `affects` as the stored JSON array, not one string.
    #[test]
    fn gap_affects_array_is_joined() {
        let value = serde_json::json!({
            "id": 7,
            "collector": "poll",
            "kind": "dropped",
            "affects": ["proc", "net"],
            "from_ns": 10,
            "to_ns": 20,
            "count": null,
            "detail": null,
        });
        let gap = gap_item(&value).expect("parse");
        assert_eq!(gap.affects, "proc,net");
        assert!(matches!(gap.evidence, Evidence::E1));
    }

    #[test]
    fn missing_field_is_named_in_chinese() {
        let value = serde_json::json!({ "name": "demo" });
        let err = session_item(&value).expect_err("no id");
        let text = err.to_string();
        assert!(text.contains("后台返回的数据缺少字段 `id`"), "{text}");
        assert!(!text.contains("response is missing"), "{text}");
    }
}
