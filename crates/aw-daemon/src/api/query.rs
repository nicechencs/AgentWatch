//! Read boundary between the HTTP API and `aw-store`.
//!
//! P2-DAEMON-02. `aw-store` is owned by another card and is not edited here.
//! [`SessionQuery`] is what the routes call. [`StoreQuery`] is the default. It
//! calls the functions that crate exports: the reads (`list_sessions`,
//! `session_summary`, `timeline`, `timeline_histogram`, `process_tree`,
//! `process_detail`, `flows`, `flow_buckets`, `traffic`, `dns_events`, `gaps`,
//! `files`, `around`, `search`), the session writes (`patch_session`,
//! `stop_session`, `delete_session`), and [`aw_store::Retention`] for stats and
//! purge. `db_vacuum` and `db_migrate` go through the same store.
//!
//! This module does not name `rusqlite`. A second copy of that crate would not
//! match the `Connection` `aw-store` returns, and root `Cargo.toml` cannot grow
//! a workspace dependency to dedupe it. SQL stays inside `aw-store`.
//!
//! `public_id` resolution: functions take the integer `sessions.id`. [`IdMap`]
//! is filled by the session layer when it creates a row, and by
//! [`aw_store::session_by_public_id`] when a later request names an id this
//! process has not seen. An unknown public id is "not found", not a guessed id.

use rusqlite::OptionalExtension;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use aw_store::{
    around, delete_session, dns_events, files, flow_buckets, flows, gaps, list_sessions,
    patch_session, process_detail, process_tree, search, session_by_public_id, session_summary,
    stop_session, timeline, timeline_histogram, traffic, CompileCtx, Cursor, FileGroupBy,
    FileQuery, FlowQuery, FtsMode, ProcessNode, PurgeScope, QueryError, Retention, RetentionConfig,
    SessionFilter, SessionListItem, SessionSummary, Store, StoreError, StoreExpr, TimelinePage,
    TimelineQuery,
};

// Every method calls a function `aw-store` exports. A filter string is parsed
// by `aw_core` and folded into the store AST, which has the same shape. An
// unknown public id is resolved with `session_by_public_id` and remembered;
// `None` from that lookup is "not found", not a guessed id.

/// One page, plus the cursor the client sends back as `?cursor=`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// Rows in this page. Never more than the requested limit.
    pub rows: Vec<T>,
    /// Present when another row exists after this page.
    pub next_cursor: Option<String>,
}

/// Why a query did not return rows.
#[derive(Debug)]
pub enum QueryBackendError {
    /// Filter text did not parse, or a field is unknown. `offset` is a byte index.
    Filter {
        /// Byte offset into the filter, when the backend reported one.
        offset: Option<usize>,
        /// Message safe to show. Does not echo argv, URLs, or headers.
        message: String,
    },
    /// `group_by`, `sort`, `limit`, or another argument is not in the documented set.
    BadArgument {
        /// Argument name.
        name: String,
        /// Allowed tokens.
        expected: String,
    },
    /// The session is not visible to this user. Routes map this to 404.
    NotFound,
    /// The backing function is not exported by this build of `aw-store`.
    Unimplemented {
        /// Short name, for the 501 body. Not a SQL statement.
        what: &'static str,
    },
    /// SQLite or the store rejected the call. Display text only.
    Store(String),
}

impl std::fmt::Display for QueryBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Filter { offset, message } => match offset {
                Some(offset) => write!(f, "filter at {offset}: {message}"),
                None => write!(f, "filter: {message}"),
            },
            Self::BadArgument { name, expected } => {
                write!(f, "bad {name}: expected {expected}")
            }
            Self::NotFound => write!(f, "session not found"),
            Self::Unimplemented { what } => write!(f, "{what} is not available"),
            Self::Store(msg) => write!(f, "{msg}"),
        }
    }
}

/// Shared list / time-range knobs. Absent fields are "no constraint", not zero.
#[derive(Debug, Clone, Default)]
pub struct ListQuery {
    /// Filter expression. `None` matches everything the endpoint allows.
    pub filter: Option<String>,
    /// Inclusive lower bound, unix nanoseconds.
    pub from_ns: Option<i64>,
    /// Inclusive upper bound, unix nanoseconds.
    pub to_ns: Option<i64>,
    /// Category list (`cats=`), already split. Empty means all categories.
    pub cats: Vec<String>,
    /// `group_by` token.
    pub group_by: Option<String>,
    /// `sort` token.
    pub sort: Option<String>,
    /// Page size. The route caps this at [`crate::api::auth::MAX_PAGE`].
    pub limit: i64,
    /// Opaque cursor from a previous page.
    pub cursor: Option<String>,
    /// Free-text `q`.
    pub q: Option<String>,
    /// `kind` for search.
    pub kind: Option<String>,
    /// `since` already parsed to unix nanoseconds.
    pub since_ns: Option<i64>,
    /// `until` already parsed to unix nanoseconds.
    pub until_ns: Option<i64>,
    /// Agent id filter.
    pub agent: Option<String>,
    /// Only sessions that have not ended.
    pub active_only: bool,
    /// Histogram bucket count.
    pub buckets: Option<i64>,
    /// `?tree=1`.
    pub tree: bool,
    /// `ref=table:id` for `/around`.
    pub reference: Option<String>,
    /// Window such as `10s`. Parsing belongs to the filter layer.
    pub window: Option<String>,
    /// Traffic step.
    pub step: Option<String>,
}

/// `public_id` → integer `sessions.id`, remembered when a session is created
/// through this process. Not a substitute for an `aw-store` lookup.
#[derive(Debug, Default)]
pub struct IdMap {
    by_public: HashMap<String, i64>,
}

impl IdMap {
    /// Remember one mapping. Later calls with the same public id overwrite.
    pub fn insert(&mut self, public_id: &str, id: i64) {
        self.by_public.insert(public_id.to_owned(), id);
    }

    /// Integer id previously inserted, if any.
    #[must_use]
    pub fn get(&self, public_id: &str) -> Option<i64> {
        self.by_public.get(public_id).copied()
    }
}

/// What the routes need from storage.
///
/// Every method is backed by a function `aw-store` exports. A session the
/// caller cannot see is `Ok(None)`, which the route turns into 404.
pub trait SessionQuery {
    /// `GET /sessions`.
    fn list_sessions(
        &self,
        user_id: &str,
        query: &ListQuery,
    ) -> Result<Page<SessionListItem>, QueryBackendError>;

    /// `GET /sessions/{sid}` plus stats. `None` when the caller cannot see it.
    fn session_detail(
        &self,
        user_id: &str,
        sid: &str,
    ) -> Result<Option<SessionSummary>, QueryBackendError>;

    /// `GET /sessions/{sid}/summary`.
    fn session_summary(
        &self,
        user_id: &str,
        sid: &str,
    ) -> Result<Option<SessionSummary>, QueryBackendError>;

    /// `PATCH /sessions/{sid}`.
    fn patch_session(
        &self,
        user_id: &str,
        sid: &str,
        name: Option<&str>,
        pinned: Option<bool>,
    ) -> Result<Option<()>, QueryBackendError>;

    /// `DELETE /sessions/{sid}`.
    fn delete_session(&self, user_id: &str, sid: &str) -> Result<Option<()>, QueryBackendError>;

    /// `POST /sessions/{sid}/stop`.
    fn stop_session(&self, user_id: &str, sid: &str) -> Result<Option<()>, QueryBackendError>;

    /// `GET /sessions/{sid}/timeline`.
    fn timeline(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<TimelinePage>, QueryBackendError>;

    /// `GET /sessions/{sid}/timeline/histogram`.
    fn histogram(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError>;

    /// `GET /sessions/{sid}/processes`.
    fn processes(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError>;

    /// `GET /sessions/{sid}/processes/{proc_uid}` where `proc_uid` is hex.
    fn process_detail(
        &self,
        user_id: &str,
        sid: &str,
        proc_uid_hex: &str,
    ) -> Result<Option<serde_json::Value>, QueryBackendError>;

    /// `GET /sessions/{sid}/files`.
    fn files(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError>;

    /// `GET /sessions/{sid}/flows`.
    fn flows(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError>;

    /// `GET /sessions/{sid}/flows/{id}/buckets`.
    fn flow_buckets(
        &self,
        user_id: &str,
        sid: &str,
        flow_id: i64,
    ) -> Result<Option<serde_json::Value>, QueryBackendError>;

    /// `GET /sessions/{sid}/traffic`.
    fn traffic(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError>;

    /// `GET /sessions/{sid}/dns`.
    fn dns(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError>;

    /// `GET /sessions/{sid}/gaps`.
    fn gaps(
        &self,
        user_id: &str,
        sid: &str,
    ) -> Result<Option<serde_json::Value>, QueryBackendError>;

    /// `GET /sessions/{sid}/around`.
    fn around(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError>;

    /// `GET /search`.
    fn search(
        &self,
        user_id: &str,
        query: &ListQuery,
    ) -> Result<serde_json::Value, QueryBackendError>;

    /// `GET /db/stats`.
    fn db_stats(&self, user_id: &str, admin: bool) -> Result<serde_json::Value, QueryBackendError>;

    /// `POST /db/purge`. Admin only; the route has already checked that.
    fn db_purge(
        &self,
        user_id: &str,
        admin: bool,
        older_than_ns: Option<i64>,
        all: bool,
        dry_run: bool,
    ) -> Result<serde_json::Value, QueryBackendError>;

    /// `POST /db/vacuum`. Admin only.
    fn db_vacuum(&self, user_id: &str, admin: bool)
        -> Result<serde_json::Value, QueryBackendError>;

    /// `POST /db/migrate`. Admin only.
    fn db_migrate(
        &self,
        user_id: &str,
        admin: bool,
    ) -> Result<serde_json::Value, QueryBackendError>;

    /// `POST /api/v1/agent/hook`. Writes one bounded self-report, or one gap when
    /// the hook says the report was dropped. Does not store a prompt or a body.
    fn ingest_self_report(&self, report: &HookReport) -> Result<HookIngest, QueryBackendError>;
}

/// One hook post, already split by the route. Fields are the whitelist only.
///
/// Not `Debug`: `command`, `path`, `url`, and `query` have the same shape as
/// argv and request targets.
#[derive(Clone)]
pub struct HookReport {
    /// Public session id, or unknown. An unknown id is stored as NULL, not 0.
    pub session: Option<String>,
    /// Agent id from the hook argument.
    pub agent: String,
    /// `agent.<id>/hook`.
    pub source: String,
    /// Tool name, or unknown.
    pub tool: Option<String>,
    /// `pre` / `post` / `unknown`.
    pub phase: Option<String>,
    /// Adapter call id, or unknown.
    pub call_id: Option<String>,
    /// Structured command, or unknown.
    pub command: Option<String>,
    /// Structured path, or unknown.
    pub path: Option<String>,
    /// Structured URL, already redacted, or unknown.
    pub url: Option<String>,
    /// Structured query, or unknown.
    pub query: Option<String>,
    /// Bounded summary JSON, or unknown. Not logged.
    pub summary_json: Option<String>,
    /// `E3` for a kept report, `NA` for a drop.
    pub evidence: String,
    /// Field evidence JSON, or none.
    pub field_evidence: Option<String>,
    /// NA reason, or none.
    pub na_reason: Option<String>,
    /// `true` when the CLI abandoned the real report. No tool-call row is written.
    pub dropped: bool,
    /// Why it was dropped: `timeout`, `send_failed`. Not a payload.
    pub drop_reason: Option<String>,
}

/// What the store did with one hook post.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookIngest {
    /// The row is in `agent_events`.
    Stored,
    /// The database is not configured. The row was not written.
    NoDatabase,
    /// `dropped: true` became a `self_report_dropped` gap. No tool-call row.
    Gap,
}

/// Default backend. Opens a short-lived [`Store`] per call so the writer is
/// not borrowed across requests. `None` path means no database: lists are
/// empty and session reads are "not found".
pub struct StoreQuery {
    /// `agentwatch.db` inside the data directory.
    pub db_path: Option<PathBuf>,
    /// public_id → id, filled by whoever inserts a session in this process.
    ids: Mutex<IdMap>,
}

impl StoreQuery {
    /// No database.
    #[must_use]
    pub fn disconnected() -> Self {
        Self {
            db_path: None,
            ids: Mutex::new(IdMap::default()),
        }
    }

    /// Point at a database file. The file is not opened until a request.
    #[must_use]
    pub fn open_path(path: PathBuf) -> Self {
        Self {
            db_path: Some(path),
            ids: Mutex::new(IdMap::default()),
        }
    }

    /// Record `public_id` → `id` so later requests can call id-keyed queries.
    pub fn remember(&self, public_id: &str, id: i64) {
        let mut guard = match self.ids.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(public_id, id);
    }

    fn open(&self) -> Result<Option<Store>, QueryBackendError> {
        let Some(path) = &self.db_path else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        Store::open(path).map(Some).map_err(map_store)
    }

    /// Integer id already remembered for `sid`. A numeric `sid` is the id itself.
    ///
    /// A miss is `Ok(None)`, not an error: the caller has a connection and asks
    /// `aw-store` before deciding the session is absent.
    fn remembered(&self, sid: &str) -> Option<i64> {
        if let Ok(id) = sid.parse::<i64>() {
            return Some(id);
        }
        let guard = match self.ids.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.get(sid)
    }

    /// Integer id for `sid`. A public id that is not in [`IdMap`] is looked up
    /// and remembered. `Ok(None)` when the store has no such session for this
    /// user — that is "not found", not a guessed id.
    fn resolve_id(
        &self,
        store: &Store,
        user_id: &str,
        sid: &str,
    ) -> Result<Option<i64>, QueryBackendError> {
        // A remembered or numeric id is only a shortcut for the lookup; the
        // row must still belong to the caller (peer identity). Without this
        // check a numeric id, or a public id another account resolved first,
        // opened that account's session.
        if let Some(id) = self.remembered(sid) {
            let owner: Option<String> = store
                .connection()
                .query_row("SELECT user_id FROM sessions WHERE id = ?1", [id], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(|err| QueryBackendError::Store(format!("session owner: {err}")))?;
            return Ok((owner.as_deref() == Some(user_id)).then_some(id));
        }
        let found = session_by_public_id(store.connection(), user_id, sid).map_err(map_query)?;
        if let Some(id) = found {
            self.remember(sid, id);
        }
        Ok(found)
    }
}

impl SessionQuery for StoreQuery {
    fn list_sessions(
        &self,
        user_id: &str,
        query: &ListQuery,
    ) -> Result<Page<SessionListItem>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(Page {
                rows: Vec::new(),
                next_cursor: None,
            });
        };
        let cursor = parse_cursor(query.cursor.as_deref())?;
        let ask = query.limit.saturating_add(1);
        let filter = SessionFilter {
            agent: query.agent.clone(),
            active_only: query.active_only,
            since_ns: query.since_ns,
            until_ns: query.until_ns,
            expr: query.filter.clone(),
            limit: Some(ask),
            cursor,
        };
        let mut rows = list_sessions(store.connection(), user_id, &filter).map_err(map_query)?;
        let next_cursor = if rows.len() as i64 > query.limit {
            rows.truncate(query.limit as usize);
            rows.last()
                .map(|row| format!("{},{}", row.started_ns, row.id))
        } else {
            None
        };
        let mut guard = match self.ids.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        for row in &rows {
            guard.insert(&row.public_id, row.id);
        }
        drop(guard);
        Ok(Page { rows, next_cursor })
    }

    fn session_detail(
        &self,
        user_id: &str,
        sid: &str,
    ) -> Result<Option<SessionSummary>, QueryBackendError> {
        self.session_summary(user_id, sid)
    }

    fn session_summary(
        &self,
        user_id: &str,
        sid: &str,
    ) -> Result<Option<SessionSummary>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        session_summary(store.connection(), user_id, id).map_err(map_query)
    }

    fn patch_session(
        &self,
        user_id: &str,
        sid: &str,
        name: Option<&str>,
        pinned: Option<bool>,
    ) -> Result<Option<()>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        patch_session(store.connection(), user_id, id, name, pinned).map_err(map_query)
    }

    fn delete_session(&self, user_id: &str, sid: &str) -> Result<Option<()>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        delete_session(store.connection(), user_id, id).map_err(map_query)
    }

    fn stop_session(&self, user_id: &str, sid: &str) -> Result<Option<()>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        // Wall clock of the user action, not an observation time.
        let ended_ns = unix_now_ns();
        stop_session(store.connection(), user_id, id, ended_ns).map_err(map_query)
    }

    fn timeline(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<TimelinePage>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        let cursor = parse_cursor(query.cursor.as_deref())?;
        let q = TimelineQuery {
            filter: query.filter.as_deref(),
            from: query.from_ns,
            to: query.to_ns,
            limit: Some(query.limit),
            cursor,
        };
        timeline(store.connection(), user_id, id, q).map_err(map_query)
    }

    fn histogram(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        let buckets = query.buckets.unwrap_or(60).max(1);
        let rows = timeline_histogram(
            store.connection(),
            user_id,
            id,
            query.from_ns,
            query.to_ns,
            buckets,
        )
        .map_err(map_query)?;
        Ok(rows.map(|rows| {
            serde_json::json!({
                "buckets": rows.iter().map(|bucket| serde_json::json!({
                    "start_ns": bucket.start_ns,
                    "end_ns": bucket.end_ns,
                    "count": bucket.count,
                    "gap": bucket.gap,
                })).collect::<Vec<_>>(),
            })
        }))
    }

    fn processes(
        &self,
        user_id: &str,
        sid: &str,
        _query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        let tree = process_tree(store.connection(), user_id, id).map_err(map_query)?;
        Ok(tree.map(|nodes| serde_json::json!({ "processes": nodes_json(&nodes) })))
    }

    fn process_detail(
        &self,
        user_id: &str,
        sid: &str,
        proc_uid_hex: &str,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        let proc_uid = parse_proc_uid(proc_uid_hex)?;
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        let detail =
            process_detail(store.connection(), user_id, id, proc_uid).map_err(map_query)?;
        let Some(detail) = detail else {
            return Ok(None);
        };
        // `children` on the detail is a list of uids. The UI reads
        // `ProcessNode[]`, so each child is taken from the session tree.
        let tree = process_tree(store.connection(), user_id, id).map_err(map_query)?;
        let children = match tree {
            Some(nodes) => child_nodes(&nodes, &detail.children),
            None => Vec::new(),
        };
        Ok(Some(process_detail_json(&detail, &children)))
    }

    fn files(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        let group_by = match query.group_by.as_deref() {
            None | Some("") | Some("none") => FileGroupBy::None,
            Some("path") => FileGroupBy::Path,
            Some("dir") => FileGroupBy::Dir,
            Some("proc") => FileGroupBy::Proc,
            Some(_) => {
                return Err(QueryBackendError::BadArgument {
                    name: "group_by".to_owned(),
                    expected: "path|dir|proc".to_owned(),
                })
            }
        };
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        let expr = store_expr(query.filter.as_deref())?;
        let cursor = parse_cursor(query.cursor.as_deref())?;
        let q = FileQuery {
            expr,
            group_by,
            from_ns: query.from_ns,
            to_ns: query.to_ns,
            limit: Some(query.limit),
            cursor,
            ctx: CompileCtx::default(),
        };
        let page = files(store.connection(), user_id, id, &q).map_err(map_query)?;
        Ok(page.map(|page| file_page_json(&page, group_by)))
    }

    fn flows(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        let q = FlowQuery {
            filter: query.filter.as_deref(),
            group_by: query.group_by.as_deref(),
            sort: query.sort.as_deref(),
        };
        let rows = flows(store.connection(), user_id, id, q).map_err(map_query)?;
        Ok(rows.map(
            |rows| serde_json::json!({ "flows": rows.iter().map(flow_json).collect::<Vec<_>>() }),
        ))
    }

    fn flow_buckets(
        &self,
        user_id: &str,
        sid: &str,
        flow_id: i64,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        let rows = flow_buckets(store.connection(), user_id, id, flow_id).map_err(map_query)?;
        Ok(rows.map(|rows| {
            serde_json::json!({
                "buckets": rows.iter().map(|bucket| serde_json::json!({
                    "bucket_ns": bucket.bucket_ns,
                    "bytes_up": bucket.bytes_up,
                    "bytes_down": bucket.bytes_down,
                    "evidence": bucket.evidence,
                })).collect::<Vec<_>>(),
            })
        }))
    }

    fn traffic(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        // `step` is a duration. Absent means 5s, the same default the store uses
        // when the step is zero.
        let step_ns = match query.step.as_deref() {
            None => 5_000_000_000,
            Some(_) => parse_step_ns(query.step.as_deref())?,
        };
        let rows = traffic(
            store.connection(),
            user_id,
            id,
            query.from_ns,
            query.to_ns,
            step_ns,
        )
        .map_err(map_query)?;
        Ok(rows.map(traffic_json))
    }

    fn dns(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        let cursor = parse_cursor(query.cursor.as_deref())?;
        let page = dns_events(
            store.connection(),
            user_id,
            id,
            query.from_ns,
            query.to_ns,
            Some(query.limit),
            cursor,
        )
        .map_err(map_query)?;
        Ok(page.map(|page| {
            let next_cursor = page.next.as_ref().map(|c| format!("{},{}", c.ts_ns, c.id));
            serde_json::json!({
                "dns": page.rows.iter().map(dns_json).collect::<Vec<_>>(),
                "next_cursor": next_cursor,
            })
        }))
    }

    fn gaps(
        &self,
        user_id: &str,
        sid: &str,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        let rows = gaps(store.connection(), user_id, id).map_err(map_query)?;
        Ok(rows.map(
            |rows| serde_json::json!({ "gaps": rows.iter().map(gap_json).collect::<Vec<_>>() }),
        ))
    }

    fn around(
        &self,
        user_id: &str,
        sid: &str,
        query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        let reference = query.reference.as_deref().unwrap_or("");
        let Some((table, id_text)) = reference.split_once(':') else {
            return Err(QueryBackendError::BadArgument {
                name: "ref".to_owned(),
                expected: "<table>:<id>".to_owned(),
            });
        };
        let ref_id = id_text
            .parse::<i64>()
            .map_err(|_| QueryBackendError::BadArgument {
                name: "ref".to_owned(),
                expected: "<table>:<id>".to_owned(),
            })?;
        let window_ns = parse_window_ns(query.window.as_deref())?;
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.resolve_id(&store, user_id, sid)? else {
            return Ok(None);
        };
        let page = around(
            store.connection(),
            user_id,
            id,
            table,
            ref_id,
            window_ns,
            Some(query.limit),
        )
        .map_err(map_query)?;
        Ok(page.map(|page| timeline_page_json(&page)))
    }

    fn search(
        &self,
        user_id: &str,
        query: &ListQuery,
    ) -> Result<serde_json::Value, QueryBackendError> {
        let needle = query.q.as_deref().unwrap_or("");
        if needle.is_empty() {
            return Err(QueryBackendError::BadArgument {
                name: "q".to_owned(),
                expected: "non-empty text".to_owned(),
            });
        }
        let Some(store) = self.open()? else {
            return Ok(serde_json::json!({ "hits": [], "fts_enabled": false }));
        };
        // `kind` narrows which source table a hit may come from. `aw-store`'s
        // search takes the text only, so the narrowing happens on the rows it
        // returns. An unknown kind is a 400, not a silent full search.
        let kind = match query.kind.as_deref() {
            None | Some("") => None,
            Some("file") => Some("file_access"),
            Some("proc") => Some("process_images"),
            Some("url") => Some("http"),
            Some(_) => {
                return Err(QueryBackendError::BadArgument {
                    name: "kind".to_owned(),
                    expected: "file|proc|url".to_owned(),
                })
            }
        };
        // Absent meta key reads as on. A database this build cannot read the
        // flag from reports the index as off rather than guessing it is on.
        let fts = aw_store::read_fts_mode(store.connection())
            .map(FtsMode::enabled)
            .unwrap_or(false);
        let hits = search(
            store.connection(),
            user_id,
            needle,
            fts,
            query.since_ns,
            Some(query.limit),
        )
        .map_err(map_query)?;
        let hits: Vec<_> = hits
            .iter()
            .filter(|hit| kind.is_none_or(|src| hit.src == src))
            .map(search_hit_json)
            .collect();
        Ok(serde_json::json!({ "hits": hits, "fts_enabled": fts }))
    }

    fn db_stats(
        &self,
        _user_id: &str,
        admin: bool,
    ) -> Result<serde_json::Value, QueryBackendError> {
        let Some(path) = self.db_path.clone() else {
            return Ok(serde_json::json!({
                "db_bytes": null,
                "tables": [],
                "oldest_session": null,
                "scope": "unconfigured",
            }));
        };
        if !path.exists() {
            return Ok(serde_json::json!({
                "db_bytes": null,
                "tables": [],
                "oldest_session": null,
                "scope": "missing",
            }));
        }
        // `Retention::stats` counts every table. A non-admin must not see
        // another user's row counts, and this crate cannot add a filtered
        // stats function. Non-admins get an explicit unavailable scope.
        if !admin {
            return Ok(serde_json::json!({
                "scope": "caller",
                "available": false,
                "reason": "per-user db stats is not exported by aw-store",
            }));
        }
        let mut store = Store::open(&path).map_err(map_store)?;
        let retention = Retention::new(&mut store, &path, RetentionConfig::default());
        let stats = retention.stats().map_err(map_store)?;
        Ok(serde_json::json!({
            "scope": "all",
            "db_bytes": stats.db_bytes,
            "page_bytes": stats.page_bytes,
            "wal_bytes": stats.wal_bytes,
            "tables": stats.tables.iter().map(|t| serde_json::json!({
                "table": t.table,
                "rows": t.rows,
            })).collect::<Vec<_>>(),
            "oldest_session": stats.oldest_session.as_ref().map(|s| serde_json::json!({
                "id": s.id,
                "public_id": s.public_id,
                "started_ns": s.started_ns,
                "ended_ns": s.ended_ns,
                "pinned": s.pinned,
            })),
        }))
    }

    fn db_purge(
        &self,
        _user_id: &str,
        admin: bool,
        older_than_ns: Option<i64>,
        all: bool,
        dry_run: bool,
    ) -> Result<serde_json::Value, QueryBackendError> {
        if !admin {
            return Err(QueryBackendError::BadArgument {
                name: "caller".to_owned(),
                expected: "an administrator".to_owned(),
            });
        }
        // The route rejects a body that names neither. Both together is `all`:
        // it is the wider of the two and does not silently narrow.
        let scope = if all {
            PurgeScope::All
        } else if let Some(ended_before_ns) = older_than_ns {
            PurgeScope::OlderThan { ended_before_ns }
        } else {
            return Err(QueryBackendError::BadArgument {
                name: "body".to_owned(),
                expected: "older_than or all".to_owned(),
            });
        };
        let mut store = self.open_mut()?;
        let path = self.db_path.clone().ok_or_else(missing_db)?;
        let mut retention = Retention::new(&mut store, &path, RetentionConfig::default());
        if dry_run {
            let candidates = retention.purge_candidates(scope).map_err(map_store)?;
            return Ok(serde_json::json!({
                "dry_run": true,
                "would_purge": candidates.iter().map(|(id, public_id)| serde_json::json!({
                    "public_id": public_id,
                    "session_id": id,
                })).collect::<Vec<_>>(),
            }));
        }
        let reports = retention.purge(scope).map_err(map_store)?;
        Ok(serde_json::json!({
            "purged": reports.iter().map(|report| serde_json::json!({
                "public_id": report.public_id,
                "session_id": report.session_id,
                "reason": purge_reason(report.reason),
                "deleted_ns": report.deleted_ns,
            })).collect::<Vec<_>>(),
        }))
    }

    fn db_vacuum(
        &self,
        _user_id: &str,
        admin: bool,
    ) -> Result<serde_json::Value, QueryBackendError> {
        if !admin {
            return Err(QueryBackendError::BadArgument {
                name: "caller".to_owned(),
                expected: "an administrator".to_owned(),
            });
        }
        let mut store = self.open_mut()?;
        let path = self.db_path.clone().ok_or_else(missing_db)?;
        // Deletes nothing: `vacuum` only returns already-freed pages and
        // truncates the WAL. This crate does not name `rusqlite`, so the
        // pragma runs inside `aw-store`.
        let mut retention = Retention::new(&mut store, &path, RetentionConfig::default());
        retention.vacuum().map_err(map_store)?;
        Ok(serde_json::json!({ "ok": true }))
    }

    fn db_migrate(
        &self,
        _user_id: &str,
        admin: bool,
    ) -> Result<serde_json::Value, QueryBackendError> {
        if !admin {
            return Err(QueryBackendError::BadArgument {
                name: "caller".to_owned(),
                expected: "an administrator".to_owned(),
            });
        }
        let mut store = self.open_mut()?;
        aw_store::apply_file_schema(&mut store).map_err(map_store)?;
        // 0006/0007 are not inside `apply_file_schema`: that function returns as
        // soon as `file_access` exists, so a database already at version 5 would
        // never reach `http` and `findings`.
        aw_store::apply_http_schema(&mut store).map_err(map_store)?;
        // 0008 and 0009 are optional past `http`: a database that never recorded a
        // proxy URL or a self-report stays where it was. `db_migrate` is the
        // operator asking for every script, so both run here.
        aw_store::apply_proxy_schema(&mut store).map_err(map_store)?;
        aw_store::apply_agent_schema(&mut store).map_err(map_store)?;
        Ok(serde_json::json!({
            "file_schema_version": aw_store::FILE_SCHEMA_VERSION,
            "http_schema_version": aw_store::HTTP_SCHEMA_VERSION,
            "proxy_schema_version": aw_store::PROXY_SCHEMA_VERSION,
            "agent_schema_version": aw_store::AGENT_SCHEMA_VERSION,
        }))
    }

    fn ingest_self_report(&self, report: &HookReport) -> Result<HookIngest, QueryBackendError> {
        if self.db_path.is_none() {
            return Ok(HookIngest::NoDatabase);
        }
        let mut store = self.open_mut()?;
        let now = unix_now_ns();
        // No user id: a hook is not an HTTP caller. A miss stays NULL.
        let session_id = match report.session.as_deref().filter(|sid| !sid.is_empty()) {
            Some(sid) => {
                aw_store::session_id_by_public(store.connection(), sid).map_err(map_store)?
            }
            None => None,
        };
        if report.dropped {
            // The hook timed out or could not deliver the report. One gap, no
            // tool-call row: a dropped report is not a successful call.
            let detail = report
                .drop_reason
                .as_deref()
                .filter(|text| !text.is_empty())
                .unwrap_or("self_report_dropped");
            aw_store::insert_self_report_gap(store.connection(), session_id, now, detail)
                .map_err(map_store)?;
            return Ok(HookIngest::Gap);
        }
        let row = aw_store::AgentEventInsert {
            session_id,
            ts_ns: now,
            agent: report.agent.clone(),
            tool: report.tool.clone(),
            phase: report.phase.clone(),
            call_id: report.call_id.clone(),
            command: report.command.clone(),
            path: report.path.clone(),
            url: report.url.clone(),
            query: report.query.clone(),
            summary_json: report.summary_json.clone(),
            evidence: report.evidence.clone(),
            source: report.source.clone(),
            field_evidence: report.field_evidence.clone(),
            na_reason: if session_id.is_none() && report.session.is_some() {
                Some("unknown_session".to_owned())
            } else {
                report.na_reason.clone()
            },
        };
        aw_store::store_agent_event(&mut store, &row).map_err(map_store)?;
        Ok(HookIngest::Stored)
    }
}

impl StoreQuery {
    /// Open the database for a write. A missing file is created by `Store::open`,
    /// unlike [`StoreQuery::open`], which treats absence as "no database".
    fn open_mut(&self) -> Result<Store, QueryBackendError> {
        let path = self.db_path.as_ref().ok_or_else(missing_db)?;
        Store::open(path).map_err(map_store)
    }
}

fn missing_db() -> QueryBackendError {
    QueryBackendError::Store("no database configured".to_owned())
}

fn purge_reason(reason: aw_store::PurgeReason) -> &'static str {
    match reason {
        aw_store::PurgeReason::Age => "age",
        aw_store::PurgeReason::Size => "size",
        aw_store::PurgeReason::OlderThan => "older_than",
        aw_store::PurgeReason::All => "all",
    }
}

fn unix_now_ns() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

fn map_query(err: QueryError) -> QueryBackendError {
    match err {
        QueryError::Parse { offset, message } => QueryBackendError::Filter {
            offset: Some(offset),
            message: message.to_owned(),
        },
        QueryError::UnsupportedField { field } | QueryError::UnknownField { field } => {
            QueryBackendError::Filter {
                offset: None,
                message: format!("unknown or unsupported field `{field}`"),
            }
        }
        QueryError::BadOperator { field, op } => QueryBackendError::Filter {
            offset: None,
            message: format!("operator `{op}` is not valid for `{field}`"),
        },
        QueryError::BadValue { field, message } => QueryBackendError::Filter {
            offset: None,
            message: format!("bad value for `{field}`: {message}"),
        },
        QueryError::BadField { field, message } => QueryBackendError::Filter {
            offset: None,
            message: format!("bad value for `{field}`: {message}"),
        },
        QueryError::BadArgument { name, expected } => QueryBackendError::BadArgument {
            name: name.to_owned(),
            expected: expected.to_owned(),
        },
        QueryError::Sqlite { op, source } => QueryBackendError::Store(format!("{op}: {source}")),
    }
}

fn map_store(err: StoreError) -> QueryBackendError {
    QueryBackendError::Store(err.to_string())
}

/// `step` uses the same `<n>`, `<n>s`, `<n>ms`, `<n>ns` forms as `window`.
fn parse_step_ns(raw: Option<&str>) -> Result<i64, QueryBackendError> {
    parse_duration_ns(raw, "step")
}

fn parse_window_ns(raw: Option<&str>) -> Result<i64, QueryBackendError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        // api-and-cli default window is 10s.
        return Ok(10 * 1_000_000_000);
    };
    parse_duration_ns(Some(raw), "window")
}

fn parse_duration_ns(raw: Option<&str>, name: &str) -> Result<i64, QueryBackendError> {
    let bad = || QueryBackendError::BadArgument {
        name: name.to_owned(),
        expected: "<n>s|<n>ms|<n>ns".to_owned(),
    };
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Err(bad());
    };
    let split = raw
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(raw.len());
    let (num, unit) = raw.split_at(split);
    let n = num.parse::<i64>().map_err(|_| bad())?;
    if n < 0 {
        return Err(bad());
    }
    let scale: i64 = match unit {
        "" | "s" => 1_000_000_000,
        "ms" => 1_000_000,
        "ns" => 1,
        _ => return Err(bad()),
    };
    Ok(n.saturating_mul(scale))
}

fn parse_cursor(raw: Option<&str>) -> Result<Option<Cursor>, QueryBackendError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let Some((ts, id)) = raw.split_once(',') else {
        return Err(QueryBackendError::BadArgument {
            name: "cursor".to_owned(),
            expected: "<ts_ns>,<id>".to_owned(),
        });
    };
    let ts_ns = ts
        .parse::<i64>()
        .map_err(|_| QueryBackendError::BadArgument {
            name: "cursor".to_owned(),
            expected: "<ts_ns>,<id>".to_owned(),
        })?;
    let id = id
        .parse::<i64>()
        .map_err(|_| QueryBackendError::BadArgument {
            name: "cursor".to_owned(),
            expected: "<ts_ns>,<id>".to_owned(),
        })?;
    Ok(Some(Cursor { ts_ns, id }))
}

/// Hex `proc_uid`. A bad string is a 400, not a lookup of uid 0.
fn parse_proc_uid(hex: &str) -> Result<i64, QueryBackendError> {
    let text = hex.trim();
    let text = text.strip_prefix("0x").unwrap_or(text);
    if text.is_empty() {
        return Err(QueryBackendError::BadArgument {
            name: "proc_uid".to_owned(),
            expected: "hex proc uid".to_owned(),
        });
    }
    u64::from_str_radix(text, 16)
        .map(|uid| uid as i64)
        .map_err(|_| QueryBackendError::BadArgument {
            name: "proc_uid".to_owned(),
            expected: "hex proc uid".to_owned(),
        })
}

/// Direct children of `detail`, as the tree already shaped them.
fn child_nodes(nodes: &[ProcessNode], child_uids: &[i64]) -> Vec<ProcessNode> {
    let mut out = Vec::with_capacity(child_uids.len());
    for uid in child_uids {
        if let Some(node) = find_node(nodes, *uid) {
            out.push(node.clone());
        }
    }
    out
}

fn find_node(nodes: &[ProcessNode], proc_uid: i64) -> Option<&ProcessNode> {
    for node in nodes {
        if node.proc_uid == proc_uid {
            return Some(node);
        }
        if let Some(found) = find_node(&node.children, proc_uid) {
            return Some(found);
        }
    }
    None
}

fn process_detail_json(
    detail: &aw_store::ProcessDetail,
    children: &[ProcessNode],
) -> serde_json::Value {
    serde_json::json!({
        "proc_uid": format!("{:x}", detail.proc_uid as u64),
        "pid": detail.pid,
        "parent_uid": detail.parent_uid.map(|id| format!("{id:x}")),
        "ppid": detail.ppid,
        "depth": detail.depth,
        "start_ns": detail.start_ns,
        "exit_ns": detail.exit_ns,
        "exit_code": detail.exit_code,
        "exit_signal": detail.exit_signal,
        "how": detail.how,
        "user_id": detail.user_id,
        "signer": detail.signer,
        "evidence": detail.evidence,
        "field_evidence": detail.field_evidence,
        "source": detail.source,
        "agent": detail.agent,
        "images": detail.images.iter().map(process_image_json).collect::<Vec<_>>(),
        "children": nodes_json(children),
    })
}

fn process_image_json(image: &aw_store::ProcessImage) -> serde_json::Value {
    serde_json::json!({
        "seq": image.seq,
        "ts_ns": image.ts_ns,
        "exe": image.exe,
        "argv": image.argv,
        "cwd": image.cwd,
        "evidence": image.evidence,
        "source": image.source,
    })
}

/// `TrafficSeries`: one label per window, each direction a one-element array.
/// A NULL sum stays NULL inside that array; it is not rewritten as 0.
fn traffic_json(buckets: Vec<aw_store::TrafficBucket>) -> serde_json::Value {
    let labels: Vec<String> = buckets
        .iter()
        .map(|bucket| bucket.bucket_ns.to_string())
        .collect();
    let points: Vec<serde_json::Value> = buckets
        .iter()
        .map(|bucket| {
            serde_json::json!({
                "start_ns": bucket.bucket_ns,
                "values_up": [bucket.bytes_up],
                "values_down": [bucket.bytes_down],
            })
        })
        .collect();
    serde_json::json!({
        "labels": labels,
        "buckets": points,
        "approximate": false,
    })
}

fn dns_json(row: &aw_store::DnsEvent) -> serde_json::Value {
    serde_json::json!({
        "id": row.id,
        "ts_ns": row.ts_ns,
        "proc_uid": row.proc_uid.map(|id| format!("{id:x}")),
        "qname": row.qname,
        "qtype": row.qtype,
        "rcode": row.rcode,
        "answers": row.answers,
        "evidence": row.evidence,
        "source": row.source,
    })
}

fn nodes_json(nodes: &[aw_store::ProcessNode]) -> Vec<serde_json::Value> {
    nodes.iter().map(node_json).collect()
}

fn node_json(node: &aw_store::ProcessNode) -> serde_json::Value {
    serde_json::json!({
        "proc_uid": format!("{:x}", node.proc_uid as u64),
        "pid": node.pid,
        "parent_uid": node.parent_uid.map(|id| format!("{id:x}")),
        "depth": node.depth,
        "start_ns": node.start_ns,
        "exit_ns": node.exit_ns,
        "exit_code": node.exit_code,
        "evidence": node.evidence,
        "exe_name": node.exe_name,
        "proc": { "pid": node.pid, "exe_name": node.exe_name },
        "children": nodes_json(&node.children),
    })
}

fn flow_json(row: &aw_store::FlowRow) -> serde_json::Value {
    serde_json::json!({
        "id": row.id,
        "proc_uid": row.proc_uid.map(|id| format!("{id:x}")),
        "domain": row.domain,
        "remote_ip": row.remote_ip,
        "remote_port": row.remote_port,
        "bytes_up": row.bytes_up,
        "bytes_down": row.bytes_down,
        "start_ns": row.start_ns,
        "evidence": row.evidence,
        "count": row.count,
    })
}

fn file_page_json(page: &aw_store::FilePage, group_by: FileGroupBy) -> serde_json::Value {
    let next_cursor = page.next.as_ref().map(|c| format!("{},{}", c.ts_ns, c.id));
    if group_by == FileGroupBy::Dir {
        // The UI folds a flat directory list into a tree itself. Counts come
        // from the rows in this page; a byte total that was not observed stays
        // absent rather than becoming zero.
        return serde_json::json!({
            "roots": dir_roots(&page.rows),
            "warnings": page.warnings,
        });
    }
    serde_json::json!({
        "files": page.rows.iter().map(file_row_json).collect::<Vec<_>>(),
        "next_cursor": next_cursor,
        "warnings": page.warnings,
    })
}

fn file_row_json(row: &aw_store::FileRow) -> serde_json::Value {
    serde_json::json!({
        "id": row.id,
        "session_id": row.session_id,
        "proc_uid": format!("{:x}", row.proc_uid as u64),
        "op": row.op,
        "path": row.path,
        "first_ns": row.first_ns,
        "evidence": row.evidence,
        "bytes_read": row.bytes_read,
        "bytes_written": row.bytes_written,
        "sensitive_rule": row.sensitive_rule,
    })
}

/// One entry per parent directory: how many rows, and how many of those wrote.
fn dir_roots(rows: &[aw_store::FileRow]) -> Vec<serde_json::Value> {
    let mut order: Vec<String> = Vec::new();
    let mut counts: std::collections::BTreeMap<String, (u64, u64)> =
        std::collections::BTreeMap::new();
    for row in rows {
        let dir = parent_dir(&row.path);
        let entry = counts.entry(dir.clone()).or_insert_with(|| {
            order.push(dir);
            (0, 0)
        });
        entry.0 = entry.0.saturating_add(1);
        let wrote = row.bytes_written.is_some_and(|n| n > 0) || row.op != "access";
        if wrote {
            entry.1 = entry.1.saturating_add(1);
        }
    }
    order
        .into_iter()
        .filter_map(|dir| {
            counts.get(&dir).map(|(count, writes)| {
                serde_json::json!({ "path": dir, "count": count, "writes": writes })
            })
        })
        .collect()
}

fn parent_dir(path: &str) -> String {
    match path.rfind(['/', '\\']) {
        Some(index) if index > 0 => path[..index].to_owned(),
        _ => path.to_owned(),
    }
}

fn timeline_page_json(page: &aw_store::TimelinePage) -> serde_json::Value {
    let next_cursor = page.next.as_ref().map(|c| format!("{},{}", c.ts_ns, c.id));
    serde_json::json!({
        "rows": page.rows.iter().map(timeline_row_json).collect::<Vec<_>>(),
        "next_cursor": next_cursor,
    })
}

fn timeline_row_json(row: &aw_store::TimelineRow) -> serde_json::Value {
    serde_json::json!({
        "session_id": row.session_id,
        "ts_ns": row.ts_ns,
        "cat": row.cat,
        "id": row.id,
        "proc_uid": row.proc_uid.map(|id| format!("{id:x}")),
        "evidence": row.evidence,
        "pre_existing": row.pre_existing,
    })
}

fn search_hit_json(hit: &aw_store::SearchHit) -> serde_json::Value {
    serde_json::json!({
        "src": hit.src,
        "src_id": hit.src_id,
        "session_id": hit.session_id,
        "public_id": hit.public_id,
        "text": hit.text,
        "ts_ns": hit.ts_ns,
        "evidence": hit.evidence,
        "session_name": session_label(hit.session_name.as_deref(), hit.session_argv.as_deref()),
    })
}

/// `sessions.argv` (a JSON array of strings, redacted when stored) as JSON.
/// Null when absent or not an array of strings; never a guess.
pub(crate) fn argv_value(raw: Option<&str>) -> serde_json::Value {
    raw.and_then(|text| serde_json::from_str::<Vec<String>>(text).ok())
        .map_or(serde_json::Value::Null, |argv| serde_json::json!(argv))
}

/// What to call a session: its name, else its command line, else nothing
/// (the page then shows the public id once).
pub(crate) fn session_label(name: Option<&str>, argv: Option<&str>) -> Option<String> {
    if let Some(name) = name.map(str::trim).filter(|name| !name.is_empty()) {
        return Some(name.to_owned());
    }
    argv.and_then(|text| serde_json::from_str::<Vec<String>>(text).ok())
        .filter(|argv| !argv.is_empty())
        .map(|argv| argv.join(" "))
}

/// Parse a filter string with the shared grammar and fold it into the store AST.
///
/// `None` and an empty string are no constraint. The two ASTs have the same
/// shape; only the field representation differs, and that is a name lookup.
fn store_expr(filter: Option<&str>) -> Result<Option<StoreExpr>, QueryBackendError> {
    let Some(text) = filter.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let parsed = aw_core::parse_filter(text).map_err(|err| QueryBackendError::Filter {
        offset: Some(err.offset()),
        message: err.to_string(),
    })?;
    Ok(Some(fold_expr(&parsed)))
}

fn fold_expr(expr: &aw_core::Expr) -> StoreExpr {
    match expr {
        aw_core::Expr::True => StoreExpr::True,
        aw_core::Expr::And(left, right) => {
            StoreExpr::And(Box::new(fold_expr(left)), Box::new(fold_expr(right)))
        }
        aw_core::Expr::Or(left, right) => {
            StoreExpr::Or(Box::new(fold_expr(left)), Box::new(fold_expr(right)))
        }
        aw_core::Expr::Not(inner) => StoreExpr::Not(Box::new(fold_expr(inner))),
        aw_core::Expr::Term(term) => StoreExpr::Term(aw_store::StoreTerm {
            field: fold_field(term.field.name()),
            op: fold_op(term.op),
            values: term.values.iter().map(fold_value).collect(),
            offset: term.offset,
        }),
    }
}

fn fold_field(name: &str) -> aw_store::StoreField {
    use aw_store::StoreField::{
        Access, Agent, Argv, Bare, BytesDown, BytesRead, BytesUp, BytesWritten, Channel, Cwd, Dir,
        Direct, Domain, Evidence, Exe, FileOp, Host, Ip, IpcKind, Kind, LocalPort, Method, Other,
        Path, Peer, Pid, Port, Proc, ProcUid, Proto, Qname, Qtype, Rcode, RemoteIp, RemotePort,
        ReqBytes, RespBytes, Rule, Severity, Source, Status, Subtree, Tag, Target, Time, Tool, Url,
        ViaProxy,
    };
    match name {
        "" => Bare,
        "kind" => Kind,
        "time" => Time,
        "evidence" => Evidence,
        "source" => Source,
        "proc" => Proc,
        "pid" => Pid,
        "proc_uid" => ProcUid,
        "subtree" => Subtree,
        "tag" => Tag,
        "exe" => Exe,
        "argv" => Argv,
        "cwd" => Cwd,
        "path" => Path,
        "dir" => Dir,
        "op" => FileOp,
        "access" => Access,
        "bytes_read" => BytesRead,
        "bytes_written" => BytesWritten,
        "domain" => Domain,
        "ip" => Ip,
        "port" => Port,
        "remote.ip" => RemoteIp,
        "remote.port" => RemotePort,
        "local.port" => LocalPort,
        "proto" => Proto,
        "bytes_up" => BytesUp,
        "bytes_down" => BytesDown,
        "direct" => Direct,
        "via_proxy" => ViaProxy,
        "qname" => Qname,
        "qtype" => Qtype,
        "rcode" => Rcode,
        "method" => Method,
        "url" => Url,
        "host" => Host,
        "status" => Status,
        "req_bytes" => ReqBytes,
        "resp_bytes" => RespBytes,
        "tool" => Tool,
        "agent" => Agent,
        "ipc_kind" => IpcKind,
        "peer" => Peer,
        "channel" => Channel,
        "target" => Target,
        "rule" => Rule,
        "severity" => Severity,
        other => Other(other.to_owned()),
    }
}

fn fold_op(op: aw_core::Op) -> aw_store::StoreOp {
    match op {
        aw_core::Op::Match => aw_store::StoreOp::Match,
        aw_core::Op::Eq => aw_store::StoreOp::Eq,
        aw_core::Op::Ne => aw_store::StoreOp::Ne,
        aw_core::Op::Gt => aw_store::StoreOp::Gt,
        aw_core::Op::Ge => aw_store::StoreOp::Ge,
        aw_core::Op::Lt => aw_store::StoreOp::Lt,
        aw_core::Op::Le => aw_store::StoreOp::Le,
        aw_core::Op::Contains => aw_store::StoreOp::Contains,
        aw_core::Op::In => aw_store::StoreOp::In,
    }
}

fn fold_value(value: &aw_core::Value) -> aw_store::StoreValue {
    match value {
        aw_core::Value::Text(text) => aw_store::StoreValue::Text(text.clone()),
        aw_core::Value::Number(n) => aw_store::StoreValue::Number(*n),
        aw_core::Value::RelativeTime {
            from_session_start,
            nanos,
        } => aw_store::StoreValue::RelativeTime {
            from_session_start: *from_session_start,
            nanos: *nanos,
        },
        aw_core::Value::Bool(b) => aw_store::StoreValue::Bool(*b),
    }
}

fn gap_json(row: &aw_store::GapItem) -> serde_json::Value {
    serde_json::json!({
        "id": row.id,
        "collector": row.collector,
        "kind": row.kind,
        "affects": row.affects,
        "from_ns": row.from_ns,
        "to_ns": row.to_ns,
        "count": row.count,
        "detail": row.detail,
    })
}

#[cfg(test)]
mod label_tests {
    use super::{argv_value, session_label};

    /// UI re-review #144 new-5: a session started with 「启动程序」 was listed
    /// as `s-31988513fa4a`; with no name, the command is the label.
    #[test]
    fn unnamed_session_is_labelled_by_its_command() {
        assert_eq!(
            session_label(None, Some(r#"["sleep","90"]"#)).as_deref(),
            Some("sleep 90")
        );
        assert_eq!(
            session_label(Some("refactor"), Some(r#"["sleep","90"]"#)).as_deref(),
            Some("refactor")
        );
        assert_eq!(session_label(Some("  "), None), None);
        assert_eq!(session_label(None, Some("not json")), None);
        assert_eq!(
            argv_value(Some(r#"["sleep","90"]"#)),
            serde_json::json!(["sleep", "90"])
        );
        assert!(argv_value(None).is_null());
    }
}
