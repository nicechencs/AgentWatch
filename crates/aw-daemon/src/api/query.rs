//! Read boundary between the HTTP API and `aw-store`.
//!
//! P2-DAEMON-02. `aw-store` is owned by another card and is not edited here.
//! [`SessionQuery`] is what the routes call. [`StoreQuery`] is the default: it
//! calls only the functions that crate already exports (`list_sessions`,
//! `session_summary`, `timeline`, `process_tree`, `flows`, `gaps`,
//! [`aw_store::Retention::stats`]).
//!
//! This module does not name `rusqlite`. A second copy of that crate would not
//! match the `Connection` `aw-store` returns, and root `Cargo.toml` cannot grow
//! a workspace dependency to dedupe it. Lookups and updates that have no
//! exported function are [`QueryBackendError::Unimplemented`]. The trait docs
//! name the signature a later `aw-store` card should add.
//!
//! `public_id` resolution is the one lookup those functions do not offer (they
//! take the integer `sessions.id`). [`IdMap`] is filled by the session layer
//! when it creates a row. An unknown public id is "not found", not a guessed id.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use aw_store::{
    around, files, flows, gaps, list_sessions, process_tree, search, session_summary, timeline,
    CompileCtx, Cursor, FileGroupBy, FileQuery, FlowQuery, FtsMode, QueryError, Retention,
    RetentionConfig, SessionFilter, SessionListItem, SessionSummary, Store, StoreError, StoreExpr,
    TimelinePage, TimelineQuery,
};

// `files`, `around`, and `search` call the functions `aw-store` exports. A
// filter string is parsed by `aw_core` and folded into the store AST, which
// has the same shape. Lookups that crate does not export (public_id,
// histogram, process detail, flow buckets, traffic, dns, patch, delete, stop)
// stay [`QueryBackendError::Unimplemented`] and the route answers 501.

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
/// Read methods that `aw-store` already exports are implemented. The rest
/// return [`QueryBackendError::Unimplemented`] until that crate grows them.
/// Assumed signatures (not called today):
///
/// - `session_by_public_id(conn, user_id, public_id) -> Option<i64>`
/// - `patch_session(conn, user_id, session_id, name, pinned)`
/// - `delete_session(conn, user_id, session_id)`
/// - `stop_session(conn, user_id, session_id, ended_ns)`
/// - `timeline_histogram(conn, user_id, session_id, filter, from, to, buckets) -> Vec<Bucket>`
/// - `process_detail(conn, user_id, session_id, proc_uid) -> Row`
/// - `flow_buckets(conn, user_id, session_id, flow_id) -> Vec<Bucket>`
/// - `traffic(conn, user_id, session_id, group_by, from, to, step) -> Series`
/// - `dns_events(conn, user_id, session_id, filter, cursor, limit) -> Page`
/// - `timeline_histogram(conn, user_id, session_id, filter, from, to, buckets) -> Vec<Bucket>`
/// - `process_detail(conn, user_id, session_id, proc_uid) -> Row`
///
/// `files`, `around`, and `search` are wired to the functions `aw-store` exports.
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

    /// `PATCH /sessions/{sid}`. No exported update function yet.
    fn patch_session(
        &self,
        user_id: &str,
        sid: &str,
        name: Option<&str>,
        pinned: Option<bool>,
    ) -> Result<Option<()>, QueryBackendError>;

    /// `DELETE /sessions/{sid}`. No exported delete function yet.
    fn delete_session(&self, user_id: &str, sid: &str) -> Result<Option<()>, QueryBackendError>;

    /// `POST /sessions/{sid}/stop`. No exported stop function yet.
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
    fn gaps(&self, user_id: &str, sid: &str)
        -> Result<Option<serde_json::Value>, QueryBackendError>;

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

    fn session_id(&self, sid: &str) -> Result<Option<i64>, QueryBackendError> {
        if let Ok(id) = sid.parse::<i64>() {
            return Ok(Some(id));
        }
        let guard = match self.ids.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        Ok(guard.get(sid))
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
        let Some(id) = self.session_id(sid)? else {
            // No exported public_id lookup. Do not guess.
            return Err(missing("session_by_public_id"));
        };
        session_summary(store.connection(), user_id, id).map_err(map_query)
    }

    fn patch_session(
        &self,
        _user_id: &str,
        _sid: &str,
        _name: Option<&str>,
        _pinned: Option<bool>,
    ) -> Result<Option<()>, QueryBackendError> {
        Err(missing("patch_session"))
    }

    fn delete_session(&self, _user_id: &str, _sid: &str) -> Result<Option<()>, QueryBackendError> {
        Err(missing("delete_session"))
    }

    fn stop_session(&self, _user_id: &str, _sid: &str) -> Result<Option<()>, QueryBackendError> {
        Err(missing("stop_session"))
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
        let Some(id) = self.session_id(sid)? else {
            return Err(missing("session_by_public_id"));
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
        _user_id: &str,
        _sid: &str,
        _query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        Err(missing("timeline_histogram"))
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
        let Some(id) = self.session_id(sid)? else {
            return Err(missing("session_by_public_id"));
        };
        let tree = process_tree(store.connection(), user_id, id).map_err(map_query)?;
        Ok(tree.map(|nodes| serde_json::json!({ "processes": nodes_json(&nodes) })))
    }

    fn process_detail(
        &self,
        _user_id: &str,
        _sid: &str,
        _proc_uid_hex: &str,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        Err(missing("process_detail"))
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
        let Some(id) = self.session_id(sid)? else {
            return Err(missing("session_by_public_id"));
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
        let Some(id) = self.session_id(sid)? else {
            return Err(missing("session_by_public_id"));
        };
        let q = FlowQuery {
            filter: query.filter.as_deref(),
            group_by: query.group_by.as_deref(),
            sort: query.sort.as_deref(),
        };
        let rows = flows(store.connection(), user_id, id, q).map_err(map_query)?;
        Ok(rows.map(|rows| {
            serde_json::json!({ "flows": rows.iter().map(flow_json).collect::<Vec<_>>() })
        }))
    }

    fn flow_buckets(
        &self,
        _user_id: &str,
        _sid: &str,
        _flow_id: i64,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        Err(missing("flow_buckets"))
    }

    fn traffic(
        &self,
        _user_id: &str,
        _sid: &str,
        _query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        Err(missing("traffic"))
    }

    fn dns(
        &self,
        _user_id: &str,
        _sid: &str,
        _query: &ListQuery,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        Err(missing("dns_events"))
    }

    fn gaps(
        &self,
        user_id: &str,
        sid: &str,
    ) -> Result<Option<serde_json::Value>, QueryBackendError> {
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.session_id(sid)? else {
            return Err(missing("session_by_public_id"));
        };
        let rows = gaps(store.connection(), user_id, id).map_err(map_query)?;
        Ok(rows.map(|rows| {
            serde_json::json!({ "gaps": rows.iter().map(gap_json).collect::<Vec<_>>() })
        }))
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
        let ref_id = id_text.parse::<i64>().map_err(|_| QueryBackendError::BadArgument {
            name: "ref".to_owned(),
            expected: "<table>:<id>".to_owned(),
        })?;
        let window_ns = parse_window_ns(query.window.as_deref())?;
        let Some(store) = self.open()? else {
            return Ok(None);
        };
        let Some(id) = self.session_id(sid)? else {
            return Err(missing("session_by_public_id"));
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

    fn db_stats(&self, _user_id: &str, admin: bool) -> Result<serde_json::Value, QueryBackendError> {
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
}

fn missing(what: &'static str) -> QueryBackendError {
    QueryBackendError::Unimplemented { what }
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

fn parse_window_ns(raw: Option<&str>) -> Result<i64, QueryBackendError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        // api-and-cli default window is 10s.
        return Ok(10 * 1_000_000_000);
    };
    let (num, unit) = raw.split_at(raw.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(raw.len()));
    let n = num.parse::<i64>().map_err(|_| QueryBackendError::BadArgument {
        name: "window".to_owned(),
        expected: "<n>s|<n>ms|<n>ns".to_owned(),
    })?;
    let scale: i64 = match unit {
        "" | "s" => 1_000_000_000,
        "ms" => 1_000_000,
        "ns" => 1,
        _ => {
            return Err(QueryBackendError::BadArgument {
                name: "window".to_owned(),
                expected: "<n>s|<n>ms|<n>ns".to_owned(),
            })
        }
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
    let ts_ns = ts.parse::<i64>().map_err(|_| QueryBackendError::BadArgument {
        name: "cursor".to_owned(),
        expected: "<ts_ns>,<id>".to_owned(),
    })?;
    let id = id.parse::<i64>().map_err(|_| QueryBackendError::BadArgument {
        name: "cursor".to_owned(),
        expected: "<ts_ns>,<id>".to_owned(),
    })?;
    Ok(Some(Cursor { ts_ns, id }))
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
    })
}

fn search_hit_json(hit: &aw_store::SearchHit) -> serde_json::Value {
    serde_json::json!({
        "src": hit.src,
        "src_id": hit.src_id,
        "session_id": hit.session_id,
        "public_id": hit.public_id,
    })
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
        Access, Agent, Argv, Bare, BytesDown, BytesRead, BytesUp, BytesWritten, Channel, Cwd,
        Direct, Dir, Domain, Evidence, Exe, FileOp, Host, Ip, IpcKind, Kind, LocalPort, Method,
        Other, Path, Peer, Pid, Port, Proc, ProcUid, Proto, Qname, Qtype, Rcode, RemoteIp,
        RemotePort, ReqBytes, RespBytes, Rule, Severity, Source, Status, Subtree, Tag, Target,
        Time, Tool, Url, ViaProxy,
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
        aw_core::Value::RelativeTime { from_session_start, nanos } => {
            aw_store::StoreValue::RelativeTime {
                from_session_start: *from_session_start,
                nanos: *nanos,
            }
        }
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
