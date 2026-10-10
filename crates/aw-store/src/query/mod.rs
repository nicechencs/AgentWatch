//! Read-only queries for P1 tables.
//!
//! Every function takes `user_id` and adds `sessions.user_id = ?` itself.
//! Callers do not get to omit that predicate. Unknown SQL values stay
//! [`Option::None`]; they are not turned into `0` or `""`.
//!
//! Pagination is a keyset on `(ts_ns, id)`. There is no `OFFSET`.
//!
//! The connection is borrowed. This module does not open one and does not
//! start a transaction. [`ensure_timeline`] runs the view DDL once; that is
//! one statement, not a long transaction. Set `PRAGMA query_only` on a
//! connection you own before lending it if you want SQLite to reject writes.

mod ast;
mod compile;
mod error;
mod filter;
mod sql;

use std::collections::BTreeMap;

use rusqlite::{params_from_iter, Connection, OptionalExtension, Row};

use crate::query::filter::{parse, Expr};
// `pub(crate)` so `export` can compile a filter without copying the SQL builder.
pub(crate) use sql::{compile, Param, Target};

pub use ast::{
    Expr as StoreExpr, Field as StoreField, Op as StoreOp, Term as StoreTerm, Value as StoreValue,
};
pub use compile::{
    around_sql, compile as compile_store_expr, compile_predicate, keyset_suffix, search_sql,
    search_sql_instr, CompileCtx, Compiled, Param as StoreParam, Target as StoreTarget,
};
pub use error::QueryError;
#[allow(unused_imports)]
pub use filter::{parse as parse_filter, Expr as FilterExpr};

const TIMELINE_SQL: &str = include_str!("../../migrations/0002_timeline_view.sql");

/// How many rows `timeline` returns when the caller passes `None`.
pub const DEFAULT_TIMELINE_LIMIT: i64 = 100;

/// Hard cap so a caller cannot ask for an unbounded page.
pub const MAX_TIMELINE_LIMIT: i64 = 1000;

/// Page cap from api-and-cli: a single response holds at most this many rows.
pub const MAX_PAGE_LIMIT: i64 = 2000;

/// Create the `timeline` view if this connection does not already have it.
///
/// The migrator in this crate only applies `0001_init.sql` (see the module
/// comment there). The view script is idempotent: a second call is a no-op
/// when the view exists. This is not a schema migration and does not touch
/// `schema_meta`.
pub fn ensure_timeline(conn: &Connection) -> Result<(), QueryError> {
    let exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'view' AND name = 'timeline'",
            [],
            |row| row.get(0),
        )
        .map_err(|err| QueryError::sqlite("timeline_view_probe", err))?;
    if exists > 0 {
        return Ok(());
    }
    conn.execute_batch(TIMELINE_SQL)
        .map_err(|err| QueryError::sqlite("timeline_view", err))
}

/// Optional constraints for [`list_sessions`].
#[derive(Debug, Clone, Default)]
pub struct SessionFilter {
    /// Only sessions whose `agent` equals this string.
    pub agent: Option<String>,
    /// `true` keeps sessions with `ended_ns IS NULL`.
    pub active_only: bool,
    /// Inclusive lower bound on `started_ns`. `None` means no bound.
    pub since_ns: Option<i64>,
    /// Inclusive upper bound on `started_ns`.
    pub until_ns: Option<i64>,
    /// Filter expression. Only `time` is meaningful; other fields are an error.
    pub expr: Option<String>,
    /// Page size. `None` means no SQL limit (the table is sessions, not events).
    pub limit: Option<i64>,
    /// Resume after this `(started_ns, id)`.
    pub cursor: Option<Cursor>,
}

/// One session the caller is allowed to see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionListItem {
    /// `sessions.id`.
    pub id: i64,
    /// Public id. Not a hostname.
    pub public_id: String,
    /// User label, or unknown.
    pub name: Option<String>,
    /// `launch` or `attach`.
    pub mode: String,
    /// Agent profile, or unknown.
    pub agent: Option<String>,
    /// Start, Unix nanoseconds.
    pub started_ns: i64,
    /// End, or still running.
    pub ended_ns: Option<i64>,
    /// `1` when excluded from retention.
    pub pinned: i64,
    /// `sessions.collectors`: JSON array of collector names, as stored.
    pub collectors: String,
    /// The same counts the overview reads ([`session_counts`]), so the list
    /// and the overview never disagree.
    pub counts: SessionCounts,
}

/// Row counts for one session, shared by the session list and the overview.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionCounts {
    /// Process rows.
    pub process_count: i64,
    /// Flow rows.
    pub flow_count: i64,
    /// DNS rows.
    pub dns_count: i64,
    /// Gap rows.
    pub gap_count: i64,
    /// Sum of `bytes_up`. `None` when every flow left the column NULL.
    pub bytes_up: Option<i64>,
    /// Sum of `bytes_down`. `None` when every flow left the column NULL.
    pub bytes_down: Option<i64>,
    /// Finding rows. `None` when the database has no `findings` table yet
    /// (unknown, not zero).
    pub finding_count: Option<i64>,
}

/// Counts for `session_id`. The caller has already checked visibility.
pub fn session_counts(conn: &Connection, session_id: i64) -> Result<SessionCounts, QueryError> {
    let mut counts = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM processes p WHERE p.session_id = ?1), \
                    (SELECT COUNT(*) FROM net_flows f WHERE f.session_id = ?1), \
                    (SELECT COUNT(*) FROM dns d WHERE d.session_id = ?1), \
                    (SELECT COUNT(*) FROM gaps g WHERE g.session_id = ?1), \
                    (SELECT SUM(bytes_up) FROM net_flows f WHERE f.session_id = ?1), \
                    (SELECT SUM(bytes_down) FROM net_flows f WHERE f.session_id = ?1)",
            rusqlite::params![session_id],
            |row| {
                Ok(SessionCounts {
                    process_count: row.get(0)?,
                    flow_count: row.get(1)?,
                    dns_count: row.get(2)?,
                    gap_count: row.get(3)?,
                    bytes_up: row.get(4)?,
                    bytes_down: row.get(5)?,
                    finding_count: None,
                })
            },
        )
        .map_err(|err| QueryError::sqlite("session_counts", err))?;
    let findings_table: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'findings'",
            [],
            |row| row.get(0),
        )
        .map_err(|err| QueryError::sqlite("session_counts", err))?;
    if findings_table > 0 {
        counts.finding_count = Some(
            conn.query_row(
                "SELECT COUNT(*) FROM findings WHERE session_id = ?",
                rusqlite::params![session_id],
                |row| row.get(0),
            )
            .map_err(|err| QueryError::sqlite("session_counts", err))?,
        );
    }
    Ok(counts)
}

/// Counts for one session. Missing counts stay `None` only when the session
/// itself is missing; a real zero is a zero because `COUNT(*)` observed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    /// Session id.
    pub id: i64,
    /// Public id.
    pub public_id: String,
    /// User label, or unknown.
    pub name: Option<String>,
    /// Agent profile, or unknown.
    pub agent: Option<String>,
    /// Start, Unix nanoseconds.
    pub started_ns: i64,
    /// End, or still running.
    pub ended_ns: Option<i64>,
    /// Process rows.
    pub process_count: i64,
    /// Flow rows.
    pub flow_count: i64,
    /// DNS rows.
    pub dns_count: i64,
    /// Gap rows.
    pub gap_count: i64,
    /// Sum of `bytes_up`. `None` when every flow left the column NULL.
    pub bytes_up: Option<i64>,
    /// Sum of `bytes_down`. `None` when every flow left the column NULL.
    pub bytes_down: Option<i64>,
    /// `launch` or `attach`.
    pub mode: String,
    /// `sessions.collectors`: JSON array of collector names, as stored.
    pub collectors: String,
    /// Finding rows; see [`SessionCounts::finding_count`].
    pub finding_count: Option<i64>,
}

/// One process in a session tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessNode {
    /// `ProcUid` bit-cast to `i64`.
    pub proc_uid: i64,
    /// OS pid.
    pub pid: i64,
    /// Parent `ProcUid`, or unknown (a root, or a parent that was not observed).
    pub parent_uid: Option<i64>,
    /// Distance from the session root, as stored. Not invented here.
    pub depth: i64,
    /// Start, Unix nanoseconds.
    pub start_ns: i64,
    /// Exit, or still running.
    pub exit_ns: Option<i64>,
    /// Evidence label.
    pub evidence: String,
    /// Latest image basename, or unknown.
    pub exe_name: Option<String>,
    /// Children, ordered by `(start_ns, proc_uid)`.
    pub children: Vec<ProcessNode>,
}

/// How [`flows`] groups rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowGroupBy {
    /// One row per flow.
    None,
    /// By `domain`. NULL domains stay in their own group and are not labeled `""`.
    Domain,
    /// By remote ip.
    Ip,
    /// By remote port.
    Port,
    /// By `proc_uid`.
    Proc,
}

/// Sort for [`flows`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowSort {
    /// `start_ns`, then `id`.
    Time,
    /// Sum of `bytes_up`. NULL sums sort last.
    Up,
    /// Sum of `bytes_down`. NULL sums sort last.
    Down,
    /// Sum of both directions, treating a NULL side as absent (not zero)
    /// unless the other side is present, in which case the NULL side adds nothing
    /// only when both are NULL. See [`flows`].
    Total,
}

/// A flow or a flow group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRow {
    /// Flow id when ungrouped. `None` for a group.
    pub id: Option<i64>,
    /// `proc_uid` when ungrouped or grouped by proc.
    pub proc_uid: Option<i64>,
    /// Domain, or the group key. `None` when unknown, never `""`.
    pub domain: Option<String>,
    /// Remote ip, or the group key.
    pub remote_ip: Option<String>,
    /// Remote port, or the group key.
    pub remote_port: Option<i64>,
    /// Bytes up. `None` when the stored value is NULL (ungrouped) or every
    /// member of the group is NULL.
    pub bytes_up: Option<i64>,
    /// Bytes down. Same NULL rule as `bytes_up`.
    pub bytes_down: Option<i64>,
    /// Start, Unix nanoseconds. For a group, the earliest `start_ns`.
    pub start_ns: i64,
    /// Evidence of the flow. For a group, `None` (members can differ).
    pub evidence: Option<String>,
    /// Rows in the group. `1` when ungrouped.
    pub count: i64,
}

/// One timeline row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineRow {
    /// Session id.
    pub session_id: i64,
    /// Event time, Unix nanoseconds.
    pub ts_ns: i64,
    /// `proc`, `net`, `dns`, or `gap`.
    pub cat: String,
    /// Branch id. For `proc` this is `proc_uid`, not a surrogate.
    pub id: i64,
    /// Process, or unknown (gaps, and DNS that could not be attributed).
    pub proc_uid: Option<i64>,
    /// Evidence label. Gaps are `E1` as stored by the view.
    pub evidence: String,
}

/// Resume token. The next page is strictly after this pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    /// Time component.
    pub ts_ns: i64,
    /// Id component.
    pub id: i64,
}

/// A page of timeline rows plus the cursor for the following page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelinePage {
    /// Rows, ordered by `(ts_ns, id)`.
    pub rows: Vec<TimelineRow>,
    /// Present when another row exists after this page.
    pub next: Option<Cursor>,
}

/// One gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapItem {
    /// Row id.
    pub id: i64,
    /// Collector name.
    pub collector: String,
    /// Gap kind.
    pub kind: String,
    /// JSON array of affected categories.
    pub affects: String,
    /// Start, Unix nanoseconds.
    pub from_ns: i64,
    /// End, Unix nanoseconds.
    pub to_ns: i64,
    /// Lost-event count, or unknown.
    pub count: Option<i64>,
    /// Redacted detail, or unknown.
    pub detail: Option<String>,
}

/// Sessions owned by `user_id`, newest start first.
pub fn list_sessions(
    conn: &Connection,
    user_id: &str,
    filter: &SessionFilter,
) -> Result<Vec<SessionListItem>, QueryError> {
    let pred = compile_optional(filter.expr.as_deref(), Target::Sessions, None, None)?;
    let mut sql = String::from(
        "SELECT id, public_id, name, mode, agent, started_ns, ended_ns, pinned, collectors \
         FROM sessions WHERE user_id = ?",
    );
    let mut bind: Vec<Param> = vec![Param::Text(user_id.to_string())];
    if let Some(agent) = &filter.agent {
        sql.push_str(" AND agent = ?");
        bind.push(Param::Text(agent.clone()));
    }
    if filter.active_only {
        sql.push_str(" AND ended_ns IS NULL");
    }
    if let Some(since) = filter.since_ns {
        sql.push_str(" AND started_ns >= ?");
        bind.push(Param::Int(since));
    }
    if let Some(until) = filter.until_ns {
        sql.push_str(" AND started_ns <= ?");
        bind.push(Param::Int(until));
    }
    sql.push_str(" AND (");
    sql.push_str(&pred.sql);
    sql.push(')');
    bind.extend(pred.params);
    if let Some(cursor) = filter.cursor {
        // Newest first: the next page is strictly older than the cursor.
        sql.push_str(" AND (started_ns < ? OR (started_ns = ? AND id < ?))");
        bind.push(Param::Int(cursor.ts_ns));
        bind.push(Param::Int(cursor.ts_ns));
        bind.push(Param::Int(cursor.id));
    }
    sql.push_str(" ORDER BY started_ns DESC, id DESC");
    if let Some(limit) = filter.limit {
        sql.push_str(" LIMIT ?");
        bind.push(Param::Int(limit));
    }
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| QueryError::sqlite("list_sessions", err))?;
    let rows = stmt
        .query_map(params_from_iter(bind.iter().map(Param::to_sql)), |row| {
            Ok(SessionListItem {
                id: row.get(0)?,
                public_id: row.get(1)?,
                name: row.get(2)?,
                mode: row.get(3)?,
                agent: row.get(4)?,
                started_ns: row.get(5)?,
                ended_ns: row.get(6)?,
                pinned: row.get(7)?,
                collectors: row.get(8)?,
                counts: SessionCounts::default(),
            })
        })
        .map_err(|err| QueryError::sqlite("list_sessions", err))?;
    let mut items: Vec<SessionListItem> = collect_rows(rows)?;
    for item in &mut items {
        item.counts = session_counts(conn, item.id)?;
    }
    Ok(items)
}

/// Overview counts for one session. `None` when it is not owned by `user_id`.
pub fn session_summary(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
) -> Result<Option<SessionSummary>, QueryError> {
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    let head = conn
        .query_row(
            "SELECT s.id, s.public_id, s.name, s.agent, s.started_ns, s.ended_ns, \
                    s.mode, s.collectors \
             FROM sessions s WHERE s.id = ? AND s.user_id = ?",
            rusqlite::params![session_id, user_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|err| QueryError::sqlite("session_summary", err))?;
    let Some((id, public_id, name, agent, started_ns, ended_ns, mode, collectors)) = head else {
        return Ok(None);
    };
    // Same function as the session list: one source for both pages.
    let counts = session_counts(conn, id)?;
    let summary = Some(SessionSummary {
        id,
        public_id,
        name,
        agent,
        started_ns,
        ended_ns,
        process_count: counts.process_count,
        flow_count: counts.flow_count,
        dns_count: counts.dns_count,
        gap_count: counts.gap_count,
        bytes_up: counts.bytes_up,
        bytes_down: counts.bytes_down,
        mode,
        collectors,
        finding_count: counts.finding_count,
    });
    Ok(summary)
}

/// Process tree for a session owned by `user_id`.
///
/// Processes whose parent is missing or outside the session become roots.
/// `None` when the session is not visible. An empty tree is `Some(vec![])`.
pub fn process_tree(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
) -> Result<Option<Vec<ProcessNode>>, QueryError> {
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    let mut stmt = conn
        .prepare(
            "SELECT p.proc_uid, p.pid, p.parent_uid, p.depth, p.start_ns, p.exit_ns, p.evidence, \
                    (SELECT CASE \
                        WHEN exe IS NULL THEN NULL \
                        ELSE replace(exe, rtrim(exe, replace(replace(exe, char(92), char(47)), char(47), '')), '') \
                     END \
                     FROM process_images i \
                     WHERE i.session_id = p.session_id AND i.proc_uid = p.proc_uid \
                     ORDER BY i.ts_ns DESC LIMIT 1) \
             FROM processes p \
             WHERE p.session_id = ? \
             ORDER BY p.start_ns, p.proc_uid",
        )
        .map_err(|err| QueryError::sqlite("process_tree", err))?;
    let flat = stmt
        .query_map(rusqlite::params![session_id], |row| {
            Ok(FlatProc {
                proc_uid: row.get(0)?,
                pid: row.get(1)?,
                parent_uid: row.get(2)?,
                depth: row.get(3)?,
                start_ns: row.get(4)?,
                exit_ns: row.get(5)?,
                evidence: row.get(6)?,
                exe_name: row.get(7)?,
            })
        })
        .map_err(|err| QueryError::sqlite("process_tree", err))?;
    let flat = collect_rows(flat)?;
    Ok(Some(build_tree(flat)))
}

/// Filter, grouping, and sort for [`flows`].
#[derive(Debug, Clone, Copy, Default)]
pub struct FlowQuery<'a> {
    /// Filter expression. `None` or `""` matches every flow.
    pub filter: Option<&'a str>,
    /// `domain`, `ip`, `proc`, `port`, or `None` for one row per flow.
    pub group_by: Option<&'a str>,
    /// `up`, `down`, `total`, `time`, or `None` (time).
    pub sort: Option<&'a str>,
}

/// Flows for a session, optionally grouped.
///
/// `group_by` accepts `None`, `"domain"`, `"ip"`, `"proc"`, `"port"`.
/// `sort` accepts `None` (time), `"up"`, `"down"`, `"total"`, `"time"`.
pub fn flows(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
    query: FlowQuery<'_>,
) -> Result<Option<Vec<FlowRow>>, QueryError> {
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    let started = session_started(conn, session_id)?;
    let pred = compile_optional(query.filter, Target::Flows, started, None)?;
    let group = parse_group(query.group_by)?;
    let sort = parse_sort(query.sort)?;
    let mut sql = String::from(
        "SELECT net_flows.id, net_flows.proc_uid, net_flows.domain, net_flows.remote_ip, \
                net_flows.remote_port, net_flows.bytes_up, net_flows.bytes_down, \
                net_flows.start_ns, net_flows.evidence \
         FROM net_flows \
         JOIN sessions ON sessions.id = net_flows.session_id \
         WHERE net_flows.session_id = ? AND sessions.user_id = ? AND (",
    );
    sql.push_str(&pred.sql);
    sql.push(')');
    let mut bind = vec![Param::Int(session_id), Param::Text(user_id.to_string())];
    bind.extend(pred.params);
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| QueryError::sqlite("flows", err))?;
    let rows = stmt
        .query_map(params_from_iter(bind.iter().map(Param::to_sql)), read_flow)
        .map_err(|err| QueryError::sqlite("flows", err))?;
    let mut rows = collect_rows(rows)?;
    if group != FlowGroupBy::None {
        rows = group_flows(rows, group);
    }
    sort_flows(&mut rows, sort);
    Ok(Some(rows))
}

/// Bounds and page size for [`timeline`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TimelineQuery<'a> {
    /// Filter expression. `None` or `""` matches every row in range.
    pub filter: Option<&'a str>,
    /// Inclusive lower bound on `ts_ns`.
    pub from: Option<i64>,
    /// Inclusive upper bound on `ts_ns`.
    pub to: Option<i64>,
    /// Page size. `None` is [`DEFAULT_TIMELINE_LIMIT`].
    pub limit: Option<i64>,
    /// Resume after this `(ts_ns, id)`.
    pub cursor: Option<Cursor>,
}

/// Timeline page for a session.
///
/// `from` / `to` are inclusive bounds on `ts_ns`. `cursor` skips `(ts_ns, id)`
/// pairs at or before the cursor. `limit` defaults to [`DEFAULT_TIMELINE_LIMIT`].
pub fn timeline(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
    query: TimelineQuery<'_>,
) -> Result<Option<TimelinePage>, QueryError> {
    ensure_timeline(conn)?;
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    let started = session_started(conn, session_id)?;
    let pred = compile_optional(query.filter, Target::Timeline, started, None)?;
    let mut sql = String::from(
        "SELECT timeline.session_id, timeline.ts_ns, timeline.cat, timeline.id, \
                timeline.proc_uid, timeline.evidence \
         FROM timeline \
         JOIN sessions ON sessions.id = timeline.session_id \
         WHERE timeline.session_id = ? AND sessions.user_id = ? AND (",
    );
    sql.push_str(&pred.sql);
    sql.push(')');
    let mut bind = vec![Param::Int(session_id), Param::Text(user_id.to_string())];
    bind.extend(pred.params);
    if let Some(from) = query.from {
        sql.push_str(" AND timeline.ts_ns >= ?");
        bind.push(Param::Int(from));
    }
    if let Some(to) = query.to {
        sql.push_str(" AND timeline.ts_ns <= ?");
        bind.push(Param::Int(to));
    }
    if let Some(cursor) = query.cursor {
        sql.push_str(" AND (timeline.ts_ns > ? OR (timeline.ts_ns = ? AND timeline.id > ?))");
        bind.push(Param::Int(cursor.ts_ns));
        bind.push(Param::Int(cursor.ts_ns));
        bind.push(Param::Int(cursor.id));
    }
    sql.push_str(" ORDER BY timeline.ts_ns, timeline.id");
    let page = query.limit.unwrap_or(DEFAULT_TIMELINE_LIMIT);
    if !(0..=MAX_TIMELINE_LIMIT).contains(&page) {
        return Err(QueryError::BadArgument {
            name: "limit",
            expected: "0..=1000",
        });
    }
    // Fetch one extra row to know whether `next` should be set.
    sql.push_str(" LIMIT ?");
    bind.push(Param::Int(page.saturating_add(1)));
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| QueryError::sqlite("timeline", err))?;
    let rows = stmt
        .query_map(params_from_iter(bind.iter().map(Param::to_sql)), |row| {
            Ok(TimelineRow {
                session_id: row.get(0)?,
                ts_ns: row.get(1)?,
                cat: row.get(2)?,
                id: row.get(3)?,
                proc_uid: row.get(4)?,
                evidence: row.get(5)?,
            })
        })
        .map_err(|err| QueryError::sqlite("timeline", err))?;
    let mut rows = collect_rows(rows)?;
    let next = if rows.len() as i64 > page {
        rows.truncate(page as usize);
        rows.last().map(|row| Cursor {
            ts_ns: row.ts_ns,
            id: row.id,
        })
    } else {
        None
    };
    Ok(Some(TimelinePage { rows, next }))
}

/// Gaps recorded against a session owned by `user_id`.
///
/// Global gaps (`session_id IS NULL`) are not included: they are not owned
/// by the user. `None` when the session is not visible.
pub fn gaps(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
) -> Result<Option<Vec<GapItem>>, QueryError> {
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    let mut stmt = conn
        .prepare(
            "SELECT g.id, g.collector, g.kind, g.affects, g.from_ns, g.to_ns, g.count, g.detail \
             FROM gaps g \
             JOIN sessions s ON s.id = g.session_id \
             WHERE g.session_id = ? AND s.user_id = ? \
             ORDER BY g.from_ns, g.id",
        )
        .map_err(|err| QueryError::sqlite("gaps", err))?;
    let rows = stmt
        .query_map(rusqlite::params![session_id, user_id], |row| {
            Ok(GapItem {
                id: row.get(0)?,
                collector: row.get(1)?,
                kind: row.get(2)?,
                affects: row.get(3)?,
                from_ns: row.get(4)?,
                to_ns: row.get(5)?,
                count: row.get(6)?,
                detail: row.get(7)?,
            })
        })
        .map_err(|err| QueryError::sqlite("gaps", err))?;
    Ok(Some(collect_rows(rows)?))
}

/// One `file_access` row returned by [`files`].
///
/// Byte counts stay [`Option`]: NULL is "not observed", not zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    /// `file_access.id`.
    pub id: i64,
    /// Session id.
    pub session_id: i64,
    /// `ProcUid` bit-cast to `i64`.
    pub proc_uid: i64,
    /// `access` / `create` / `delete` / `rename` / `exec`.
    pub op: String,
    /// Stored path. Already redacted at write time.
    pub path: String,
    /// First observation, Unix nanoseconds.
    pub first_ns: i64,
    /// Evidence label.
    pub evidence: String,
    /// Bytes read. `None` when the column is NULL.
    pub bytes_read: Option<i64>,
    /// Bytes written. `None` when the column is NULL.
    pub bytes_written: Option<i64>,
    /// Sensitive-path rule id, or none.
    pub sensitive_rule: Option<String>,
}

/// How [`files`] groups rows. Grouping is done in process, after the indexed read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileGroupBy {
    /// One row per access.
    None,
    /// By full path.
    Path,
    /// By parent directory. A path with no separator is its own group.
    Dir,
    /// By `proc_uid`.
    Proc,
}

/// Filter and page for [`files`].
#[derive(Debug, Clone)]
pub struct FileQuery {
    /// P2 AST. `None` matches every file row in the session.
    pub expr: Option<StoreExpr>,
    /// Grouping. Default is one row per access.
    pub group_by: FileGroupBy,
    /// Inclusive lower bound on `first_ns`.
    pub from_ns: Option<i64>,
    /// Inclusive upper bound on `first_ns`.
    pub to_ns: Option<i64>,
    /// Page size. `None` is [`DEFAULT_TIMELINE_LIMIT`]. Capped at [`MAX_PAGE_LIMIT`].
    pub limit: Option<i64>,
    /// Resume after this `(first_ns, id)`.
    pub cursor: Option<Cursor>,
    /// See [`CompileCtx`].
    pub ctx: CompileCtx,
}

impl Default for FileQuery {
    fn default() -> Self {
        Self {
            expr: None,
            group_by: FileGroupBy::None,
            from_ns: None,
            to_ns: None,
            limit: None,
            cursor: None,
            ctx: CompileCtx::default(),
        }
    }
}

/// A page of file rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePage {
    /// Rows. Ungrouped pages are ordered by `(first_ns, id)`.
    pub rows: Vec<FileRow>,
    /// Set when another row exists after this page. Absent for grouped results:
    /// grouping consumes the filtered set for the requested page only.
    pub next: Option<Cursor>,
    /// Field/kind mismatches from the compiler. Empty when every field applied.
    pub warnings: Vec<String>,
}

/// File rows for a session owned by `user_id`.
///
/// `None` when the session is not visible. Requires `file_access` (migrations
/// 0003–0005). A connection that has not applied them gets a SQLite error
/// naming the missing table; this function does not migrate, because the
/// connection may be read-only.
pub fn files(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
    query: &FileQuery,
) -> Result<Option<FilePage>, QueryError> {
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    let expr = query.expr.clone().unwrap_or(StoreExpr::True);
    let compiled = compile_predicate(&expr, StoreTarget::Files, &query.ctx)?;
    let mut sql = String::from(
        "SELECT file_access.id, file_access.session_id, file_access.proc_uid, \
         file_access.op, file_access.path, file_access.first_ns, file_access.evidence, \
         file_access.bytes_read, file_access.bytes_written, file_access.sensitive_rule \
         FROM file_access \
         JOIN sessions ON sessions.id = file_access.session_id \
         WHERE file_access.session_id = ? AND sessions.user_id = ? AND (",
    );
    sql.push_str(&compiled.sql);
    sql.push(')');
    let mut bind = vec![
        StoreParam::Int(session_id),
        StoreParam::Text(user_id.to_string()),
    ];
    bind.extend(compiled.params);
    if let Some(from) = query.from_ns {
        sql.push_str(" AND file_access.first_ns >= ?");
        bind.push(StoreParam::Int(from));
    }
    if let Some(to) = query.to_ns {
        sql.push_str(" AND file_access.first_ns <= ?");
        bind.push(StoreParam::Int(to));
    }
    if let Some(cursor) = query.cursor {
        sql.push_str(&keyset_suffix("file_access.first_ns", "file_access.id"));
        bind.push(StoreParam::Int(cursor.ts_ns));
        bind.push(StoreParam::Int(cursor.ts_ns));
        bind.push(StoreParam::Int(cursor.id));
    } else {
        sql.push_str(" ORDER BY file_access.first_ns, file_access.id LIMIT ?");
    }
    let page = clamp_page(query.limit)?;
    bind.push(StoreParam::Int(page.saturating_add(1)));
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| QueryError::sqlite("files", err))?;
    let rows = stmt
        .query_map(
            params_from_iter(bind.iter().map(store_param_to_sql)),
            read_file,
        )
        .map_err(|err| QueryError::sqlite("files", err))?;
    let mut rows = collect_rows(rows)?;
    let next = if query.group_by == FileGroupBy::None && rows.len() as i64 > page {
        rows.truncate(page as usize);
        rows.last().map(|row| Cursor {
            ts_ns: row.first_ns,
            id: row.id,
        })
    } else {
        if rows.len() as i64 > page {
            rows.truncate(page as usize);
        }
        None
    };
    let rows = group_files(rows, query.group_by);
    Ok(Some(FilePage {
        rows,
        next,
        warnings: compiled.warnings,
    }))
}

/// One timeline row from [`around`].
pub type AroundRow = TimelineRow;

/// Events within `window_ns` of `ref_table`:`ref_id`, both sides.
///
/// `ref_table` is one of `file_access`, `net_flows`, `dns`, `http`,
/// `processes`, `gaps`, `process_images`. The reference id is bound. `None`
/// when the session is not visible. An unknown reference yields an empty page,
/// not an error: the id may have been purged.
pub fn around(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
    ref_table: &str,
    ref_id: i64,
    window_ns: i64,
    limit: Option<i64>,
) -> Result<Option<TimelinePage>, QueryError> {
    ensure_timeline(conn)?;
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    let sql = around_sql(ref_table)?;
    let page = clamp_page(limit)?;
    let bind = [
        StoreParam::Int(ref_id),
        StoreParam::Int(session_id),
        StoreParam::Int(session_id),
        StoreParam::Int(window_ns),
        StoreParam::Int(window_ns),
        StoreParam::Int(page),
    ];
    // The SQL joins through the reference row, which is already constrained to
    // this session. Ownership was checked above. Re-checking `user_id` in the
    // statement would need another placeholder the helper does not reserve.
    let _ = user_id;
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| QueryError::sqlite("around", err))?;
    let rows = stmt
        .query_map(
            params_from_iter(bind.iter().map(store_param_to_sql)),
            |row| {
                Ok(TimelineRow {
                    session_id: row.get(0)?,
                    ts_ns: row.get(1)?,
                    cat: row.get(2)?,
                    id: row.get(3)?,
                    proc_uid: row.get(4)?,
                    evidence: row.get(5)?,
                })
            },
        )
        .map_err(|err| QueryError::sqlite("around", err))?;
    let rows = collect_rows(rows)?;
    Ok(Some(TimelinePage { rows, next: None }))
}

/// One cross-session search hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// `file_access` or `process_images`.
    pub src: String,
    /// Source row id.
    pub src_id: i64,
    /// Owning session.
    pub session_id: i64,
    /// Public session id.
    pub public_id: String,
    /// What the hit is, as stored: the file path, or the executable path
    /// (argv when the path is unknown). `None` when the row has neither.
    pub text: Option<String>,
    /// When: `file_access.first_ns` or `process_images.ts_ns`.
    pub ts_ns: Option<i64>,
    /// Record evidence of the source row.
    pub evidence: Option<String>,
}

/// Substring search across the caller's sessions.
///
/// `fts` selects the FTS5 statement or the `instr` fallback. The needle is
/// bound either way. `since_ns` is not part of the FTS statement (the index
/// has no time column); when it is `Some`, hits are dropped unless the source
/// row is at or after that instant. Dropping is a post-filter, not a string
/// concatenated into SQL.
pub fn search(
    conn: &Connection,
    user_id: &str,
    needle: &str,
    fts: bool,
    since_ns: Option<i64>,
    limit: Option<i64>,
) -> Result<Vec<SearchHit>, QueryError> {
    let page = clamp_page(limit)?;
    let needle_param = if fts {
        StoreParam::Text(crate::fts::match_query(needle))
    } else {
        StoreParam::Text(needle.to_lowercase())
    };
    let sql = if fts {
        search_sql()
    } else {
        search_sql_instr()
    };
    let bind = [
        StoreParam::Text(user_id.to_string()),
        needle_param.clone(),
        StoreParam::Text(user_id.to_string()),
        needle_param,
        StoreParam::Int(page),
    ];
    let mut stmt = conn
        .prepare(sql)
        .map_err(|err| QueryError::sqlite("search", err))?;
    let rows = stmt
        .query_map(
            params_from_iter(bind.iter().map(store_param_to_sql)),
            |row| {
                Ok(SearchHit {
                    src: row.get(0)?,
                    src_id: row.get(1)?,
                    session_id: row.get(2)?,
                    public_id: row.get(3)?,
                    text: None,
                    ts_ns: None,
                    evidence: None,
                })
            },
        )
        .map_err(|err| QueryError::sqlite("search", err))?;
    let mut hits: Vec<SearchHit> = collect_rows(rows)?;
    // The id alone left the page printing 「记录 #id」; each hit now carries
    // the text and time of its row.
    for hit in &mut hits {
        if let Some((text, ts_ns, evidence)) = hit_detail(conn, hit)? {
            hit.text = text;
            hit.ts_ns = ts_ns;
            hit.evidence = evidence;
        }
    }
    if let Some(since) = since_ns {
        hits.retain(|hit| hit.ts_ns.unwrap_or(i64::MIN) >= since);
    }
    Ok(hits)
}

/// Integer `sessions.id` for `public_id`, when that session belongs to `user_id`.
///
/// `None` when no session with that public id is owned by this user. Another
/// user's id is not returned.
pub fn session_by_public_id(
    conn: &Connection,
    user_id: &str,
    public_id: &str,
) -> Result<Option<i64>, QueryError> {
    conn.query_row(
        "SELECT id FROM sessions WHERE public_id = ? AND user_id = ?",
        rusqlite::params![public_id, user_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(|err| QueryError::sqlite("session_by_public_id", err))
}

/// Set `name` and/or `pinned` on a session owned by `user_id`.
///
/// A `None` argument leaves that column as it is. It does not write NULL.
/// `Ok(None)` when the session is not visible.
pub fn patch_session(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
    name: Option<&str>,
    pinned: Option<bool>,
) -> Result<Option<()>, QueryError> {
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    // Both arguments absent is a no-op, not an UPDATE that would touch the row.
    if name.is_none() && pinned.is_none() {
        return Ok(Some(()));
    }
    let mut sql = String::from("UPDATE sessions SET ");
    let mut bind: Vec<Param> = Vec::new();
    if let Some(name) = name {
        sql.push_str("name = ?");
        bind.push(Param::Text(name.to_string()));
    }
    if let Some(pinned) = pinned {
        if !bind.is_empty() {
            sql.push_str(", ");
        }
        sql.push_str("pinned = ?");
        bind.push(Param::Int(i64::from(pinned)));
    }
    sql.push_str(" WHERE id = ? AND user_id = ?");
    bind.push(Param::Int(session_id));
    bind.push(Param::Text(user_id.to_string()));
    conn.execute(&sql, params_from_iter(bind.iter().map(Param::to_sql)))
        .map_err(|err| QueryError::sqlite("patch_session", err))?;
    Ok(Some(()))
}

/// Mark a session stopped at `ended_ns`.
///
/// Writes `ended_ns` and `end_reason = 'stopped'` only while the session is
/// still active. An already-ended session is left as it was, including its
/// original end time, and still returns `Ok(Some(()))`. `Ok(None)` when the
/// session is not visible.
pub fn stop_session(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
    ended_ns: i64,
) -> Result<Option<()>, QueryError> {
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    conn.execute(
        "UPDATE sessions SET ended_ns = ?, end_reason = 'stopped' \
         WHERE id = ? AND user_id = ? AND ended_ns IS NULL",
        rusqlite::params![ended_ns, session_id, user_id],
    )
    .map_err(|err| QueryError::sqlite("stop_session", err))?;
    Ok(Some(()))
}

/// Delete one ended, unpinned session owned by `user_id`.
///
/// Children are removed in the same order and with the same statements as
/// retention's purge, so the FTS delete triggers on `file_access` and
/// `process_images` fire. The session row goes last. `Ok(None)` when the
/// session is not visible. A session that is still active or pinned is an
/// error and is not deleted.
pub fn delete_session(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
) -> Result<Option<()>, QueryError> {
    let state = session_delete_state(conn, user_id, session_id)?;
    let Some((public_id, ended, pinned)) = state else {
        return Ok(None);
    };
    if ended.is_none() {
        return Err(QueryError::BadArgument {
            name: "session",
            expected: "an ended session; this one is still active",
        });
    }
    if pinned {
        return Err(QueryError::BadArgument {
            name: "session",
            expected: "an unpinned session",
        });
    }
    delete_session_rows(conn, session_id, &public_id)
}

/// One histogram bucket. `count` is a real row count: `0` means the bucket had
/// no timeline rows, not that the count is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistBucket {
    /// Inclusive start, Unix nanoseconds.
    pub start_ns: i64,
    /// End of the bucket. Exclusive for every bucket but the last, which also
    /// holds a row whose `ts_ns` equals the span end.
    pub end_ns: i64,
    /// Timeline rows in this bucket.
    pub count: i64,
    /// `true` when any `gaps` row for the session overlaps this bucket.
    pub gap: bool,
}

/// Timeline counts in `buckets` equal-width slices of the span.
///
/// The span runs from `from_ns` (or the session's `started_ns`) to `to_ns` (or
/// the session's `ended_ns`, or the latest timeline `ts_ns` while the session
/// is still active). `buckets` is clamped to `1..=360`. Empty buckets are
/// included. A bucket that overlaps any gap has `gap: true`. `Ok(None)` when
/// the session is not visible.
pub fn timeline_histogram(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
    from_ns: Option<i64>,
    to_ns: Option<i64>,
    buckets: i64,
) -> Result<Option<Vec<HistBucket>>, QueryError> {
    ensure_timeline(conn)?;
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    let bounds = session_span(conn, session_id)?;
    let Some((started, ended)) = bounds else {
        return Ok(None);
    };
    let start = from_ns.unwrap_or(started);
    let end = match to_ns {
        Some(to) => to,
        None => match ended {
            Some(ended) => ended,
            None => latest_timeline_ts(conn, session_id)?.unwrap_or(started),
        },
    };
    let requested = buckets.clamp(1, 360);
    let (start, end) = if end < start {
        (end, start)
    } else {
        (start, end)
    };
    // A span shorter than `requested` nanoseconds cannot be split into that
    // many non-empty slices. Cap the count so every bucket has a real range,
    // and let the last bucket absorb the remainder of the integer division.
    let span = end.saturating_sub(start);
    let n = if span <= 0 {
        1
    } else {
        requested.min(span).max(1)
    };
    let width = if span <= 0 || n <= 1 { 1 } else { span / n };
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let bucket_start = if i == 0 {
            start
        } else {
            start.saturating_add(width.saturating_mul(i))
        };
        let bucket_end = if i + 1 == n {
            end
        } else {
            start.saturating_add(width.saturating_mul(i + 1))
        };
        out.push(HistBucket {
            start_ns: bucket_start,
            end_ns: bucket_end,
            count: 0,
            gap: false,
        });
    }
    fill_histogram_counts(conn, session_id, start, end, width, &mut out)?;
    fill_histogram_gaps(conn, session_id, start, end, width, &mut out)?;
    Ok(Some(out))
}

/// One `process_images` row attached to a [`ProcessDetail`].
///
/// `argv` is the stored text, already redacted by the writer. This type has no
/// `Debug` impl so a log of the struct cannot print it.
#[derive(Clone, PartialEq, Eq)]
pub struct ProcessImage {
    /// Sequence within the process.
    pub seq: i64,
    /// Observation time, Unix nanoseconds.
    pub ts_ns: i64,
    /// Executable path, or unknown.
    pub exe: Option<String>,
    /// Redacted argv, or unknown. Never rewritten here.
    pub argv: Option<String>,
    /// Working directory, or unknown.
    pub cwd: Option<String>,
    /// Evidence label.
    pub evidence: String,
    /// Collector source string.
    pub source: String,
}

/// One `processes` row plus its images and child `proc_uid`s.
///
/// No `Debug`: `images` carries argv.
#[derive(Clone, PartialEq, Eq)]
pub struct ProcessDetail {
    /// `ProcUid` bit-cast to `i64`.
    pub proc_uid: i64,
    /// OS pid.
    pub pid: i64,
    /// Parent `ProcUid`, or unknown.
    pub parent_uid: Option<i64>,
    /// Parent pid, or unknown.
    pub ppid: Option<i64>,
    /// Distance from the session root, as stored.
    pub depth: i64,
    /// Start, Unix nanoseconds.
    pub start_ns: i64,
    /// Exit, or still running.
    pub exit_ns: Option<i64>,
    /// Exit code, or unknown.
    pub exit_code: Option<i64>,
    /// Exit signal, or unknown.
    pub exit_signal: Option<i64>,
    /// How the process was observed.
    pub how: String,
    /// OS user of the process, or unknown.
    pub user_id: Option<String>,
    /// Signer, or unknown.
    pub signer: Option<String>,
    /// Evidence label.
    pub evidence: String,
    /// JSON field evidence, or unknown.
    pub field_evidence: Option<String>,
    /// Collector source string.
    pub source: String,
    /// Agent profile, or unknown.
    pub agent: Option<String>,
    /// Images, ordered by `seq`.
    pub images: Vec<ProcessImage>,
    /// Child `proc_uid`s in this session, ordered by `(start_ns, proc_uid)`.
    pub children: Vec<i64>,
}

/// One process in a session owned by `user_id`.
///
/// `Ok(None)` when the session is not visible or the process is not in it.
pub fn process_detail(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
    proc_uid: i64,
) -> Result<Option<ProcessDetail>, QueryError> {
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    let detail = conn
        .query_row(
            "SELECT proc_uid, pid, parent_uid, ppid, depth, start_ns, exit_ns, exit_code, \
                    exit_signal, how, user_id, signer, evidence, field_evidence, source, agent \
             FROM processes \
             WHERE session_id = ? AND proc_uid = ?",
            rusqlite::params![session_id, proc_uid],
            |row| {
                Ok(ProcessDetail {
                    proc_uid: row.get(0)?,
                    pid: row.get(1)?,
                    parent_uid: row.get(2)?,
                    ppid: row.get(3)?,
                    depth: row.get(4)?,
                    start_ns: row.get(5)?,
                    exit_ns: row.get(6)?,
                    exit_code: row.get(7)?,
                    exit_signal: row.get(8)?,
                    how: row.get(9)?,
                    user_id: row.get(10)?,
                    signer: row.get(11)?,
                    evidence: row.get(12)?,
                    field_evidence: row.get(13)?,
                    source: row.get(14)?,
                    agent: row.get(15)?,
                    images: Vec::new(),
                    children: Vec::new(),
                })
            },
        )
        .optional()
        .map_err(|err| QueryError::sqlite("process_detail", err))?;
    let Some(mut detail) = detail else {
        return Ok(None);
    };
    detail.images = process_images(conn, session_id, proc_uid)?;
    detail.children = process_children(conn, session_id, proc_uid)?;
    Ok(Some(detail))
}

/// One `net_flow_buckets` row. The byte columns are `NOT NULL`, so `0` is a
/// stored accumulator, not a stand-in for unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowBucket {
    /// Bucket start, Unix nanoseconds.
    pub bucket_ns: i64,
    /// Bytes up accumulated in this bucket.
    pub bytes_up: i64,
    /// Bytes down accumulated in this bucket.
    pub bytes_down: i64,
    /// Evidence label.
    pub evidence: String,
}

/// Buckets for one flow, when that flow belongs to a session owned by `user_id`.
///
/// `Ok(None)` when the session is not visible or the flow is not in it.
pub fn flow_buckets(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
    flow_id: i64,
) -> Result<Option<Vec<FlowBucket>>, QueryError> {
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    let owned: Option<i64> = conn
        .query_row(
            "SELECT id FROM net_flows WHERE id = ? AND session_id = ?",
            rusqlite::params![flow_id, session_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| QueryError::sqlite("flow_buckets", err))?;
    if owned.is_none() {
        return Ok(None);
    }
    let mut stmt = conn
        .prepare(
            "SELECT bucket_ns, bytes_up, bytes_down, evidence \
             FROM net_flow_buckets \
             WHERE flow_id = ? AND session_id = ? \
             ORDER BY bucket_ns",
        )
        .map_err(|err| QueryError::sqlite("flow_buckets", err))?;
    let rows = stmt
        .query_map(rusqlite::params![flow_id, session_id], |row| {
            Ok(FlowBucket {
                bucket_ns: row.get(0)?,
                bytes_up: row.get(1)?,
                bytes_down: row.get(2)?,
                evidence: row.get(3)?,
            })
        })
        .map_err(|err| QueryError::sqlite("flow_buckets", err))?;
    Ok(Some(collect_rows(rows)?))
}

/// Bytes summed from `net_flow_buckets` over one `step_ns` window.
///
/// Both sums are `Some`: the source columns are `NOT NULL`, so the sum is a
/// real total. A window with no rows is omitted rather than emitted as zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficBucket {
    /// Window start, Unix nanoseconds. Aligned down to `step_ns`.
    pub bucket_ns: i64,
    /// Sum of `bytes_up` in the window.
    pub bytes_up: Option<i64>,
    /// Sum of `bytes_down` in the window.
    pub bytes_down: Option<i64>,
}

/// Session traffic rolled into `step_ns`-wide buckets.
///
/// `step_ns` of `0` is read as 5 seconds. Only windows that contain at least
/// one bucket row are returned. `from_ns` / `to_ns` are inclusive bounds on
/// `bucket_ns`. `Ok(None)` when the session is not visible.
pub fn traffic(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
    from_ns: Option<i64>,
    to_ns: Option<i64>,
    step_ns: i64,
) -> Result<Option<Vec<TrafficBucket>>, QueryError> {
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    let step = if step_ns == 0 { 5_000_000_000 } else { step_ns };
    if step < 0 {
        return Err(QueryError::BadArgument {
            name: "step_ns",
            expected: "a non-negative step in nanoseconds",
        });
    }
    let mut sql = String::from(
        "SELECT (bucket_ns / ?) * ? AS win, SUM(bytes_up), SUM(bytes_down) \
         FROM net_flow_buckets \
         WHERE session_id = ?",
    );
    let mut bind = vec![Param::Int(step), Param::Int(step), Param::Int(session_id)];
    if let Some(from) = from_ns {
        sql.push_str(" AND bucket_ns >= ?");
        bind.push(Param::Int(from));
    }
    if let Some(to) = to_ns {
        sql.push_str(" AND bucket_ns <= ?");
        bind.push(Param::Int(to));
    }
    sql.push_str(" GROUP BY win ORDER BY win");
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| QueryError::sqlite("traffic", err))?;
    let rows = stmt
        .query_map(params_from_iter(bind.iter().map(Param::to_sql)), |row| {
            Ok(TrafficBucket {
                bucket_ns: row.get(0)?,
                bytes_up: row.get(1)?,
                bytes_down: row.get(2)?,
            })
        })
        .map_err(|err| QueryError::sqlite("traffic", err))?;
    Ok(Some(collect_rows(rows)?))
}

/// One `dns` row. `rcode` and `answers` stay `None` when the column is NULL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEvent {
    /// Row id.
    pub id: i64,
    /// Observation time, Unix nanoseconds.
    pub ts_ns: i64,
    /// Asking process, or unknown.
    pub proc_uid: Option<i64>,
    /// Query name.
    pub qname: String,
    /// Query type, as stored.
    pub qtype: i64,
    /// Response code, or unknown.
    pub rcode: Option<i64>,
    /// JSON answers, or unknown.
    pub answers: Option<String>,
    /// Evidence label.
    pub evidence: String,
    /// Collector source string.
    pub source: String,
}

/// A page of DNS rows plus the cursor for the following page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPage {
    /// Rows, ordered by `(ts_ns, id)`.
    pub rows: Vec<DnsEvent>,
    /// Present when another row exists after this page.
    pub next: Option<Cursor>,
}

/// DNS rows for a session, paged the same way as [`timeline`].
///
/// `from_ns` / `to_ns` are inclusive bounds on `ts_ns`. `cursor` skips pairs at
/// or before it. `limit` defaults to [`DEFAULT_TIMELINE_LIMIT`] and is capped
/// at [`MAX_TIMELINE_LIMIT`]. `Ok(None)` when the session is not visible.
pub fn dns_events(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
    from_ns: Option<i64>,
    to_ns: Option<i64>,
    limit: Option<i64>,
    cursor: Option<Cursor>,
) -> Result<Option<DnsPage>, QueryError> {
    if !session_visible(conn, user_id, session_id)? {
        return Ok(None);
    }
    let page = limit.unwrap_or(DEFAULT_TIMELINE_LIMIT);
    if !(0..=MAX_TIMELINE_LIMIT).contains(&page) {
        return Err(QueryError::BadArgument {
            name: "limit",
            expected: "0..=1000",
        });
    }
    let mut sql = String::from(
        "SELECT dns.id, dns.ts_ns, dns.proc_uid, dns.qname, dns.qtype, dns.rcode, \
                dns.answers, dns.evidence, dns.source \
         FROM dns \
         JOIN sessions ON sessions.id = dns.session_id \
         WHERE dns.session_id = ? AND sessions.user_id = ?",
    );
    let mut bind = vec![Param::Int(session_id), Param::Text(user_id.to_string())];
    if let Some(from) = from_ns {
        sql.push_str(" AND dns.ts_ns >= ?");
        bind.push(Param::Int(from));
    }
    if let Some(to) = to_ns {
        sql.push_str(" AND dns.ts_ns <= ?");
        bind.push(Param::Int(to));
    }
    if let Some(cursor) = cursor {
        sql.push_str(" AND (dns.ts_ns > ? OR (dns.ts_ns = ? AND dns.id > ?))");
        bind.push(Param::Int(cursor.ts_ns));
        bind.push(Param::Int(cursor.ts_ns));
        bind.push(Param::Int(cursor.id));
    }
    sql.push_str(" ORDER BY dns.ts_ns, dns.id LIMIT ?");
    bind.push(Param::Int(page.saturating_add(1)));
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| QueryError::sqlite("dns_events", err))?;
    let rows = stmt
        .query_map(params_from_iter(bind.iter().map(Param::to_sql)), |row| {
            Ok(DnsEvent {
                id: row.get(0)?,
                ts_ns: row.get(1)?,
                proc_uid: row.get(2)?,
                qname: row.get(3)?,
                qtype: row.get(4)?,
                rcode: row.get(5)?,
                answers: row.get(6)?,
                evidence: row.get(7)?,
                source: row.get(8)?,
            })
        })
        .map_err(|err| QueryError::sqlite("dns_events", err))?;
    let mut rows = collect_rows(rows)?;
    let next = if rows.len() as i64 > page {
        rows.truncate(page as usize);
        rows.last().map(|row| Cursor {
            ts_ns: row.ts_ns,
            id: row.id,
        })
    } else {
        None
    };
    Ok(Some(DnsPage { rows, next }))
}

/// `(public_id, ended_ns, pinned)`. `None` when the session is not this user's.
fn session_delete_state(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
) -> Result<Option<(String, Option<i64>, bool)>, QueryError> {
    conn.query_row(
        "SELECT public_id, ended_ns, pinned FROM sessions WHERE id = ? AND user_id = ?",
        rusqlite::params![session_id, user_id],
        |row| {
            let pinned: i64 = row.get(2)?;
            Ok((row.get(0)?, row.get(1)?, pinned != 0))
        },
    )
    .optional()
    .map_err(|err| QueryError::sqlite("session_delete_state", err))
}

/// Child tables, in the order retention deletes them. Names and keys are this
/// const list, never caller input. `net_flow_buckets` precedes `net_flows`
/// because it references `net_flows.id`. FTS rows are removed by the
/// BEFORE DELETE triggers, so `fts_text` is not deleted from here.
const DELETE_CHILDREN: &[(&str, &str)] = &[
    ("file_access", "id"),
    ("net_flow_buckets", "flow_id, bucket_ns"),
    ("processes", "session_id, proc_uid"),
    ("process_images", "id"),
    ("net_flows", "id"),
    ("dns", "id"),
    ("gaps", "id"),
];

/// Rows removed per statement. Same batch size retention uses.
const DELETE_BATCH_ROWS: i64 = 5000;

fn delete_session_rows(
    conn: &Connection,
    session_id: i64,
    public_id: &str,
) -> Result<Option<()>, QueryError> {
    for (name, key) in DELETE_CHILDREN {
        if !query_table_exists(conn, name)? {
            continue;
        }
        let sql = format!(
            "DELETE FROM {name} WHERE ({key}) IN \
             (SELECT {key} FROM {name} WHERE session_id = ?1 LIMIT {DELETE_BATCH_ROWS})"
        );
        loop {
            let n = conn
                .execute(&sql, rusqlite::params![session_id])
                .map_err(|err| QueryError::sqlite("delete_session", err))?;
            if n == 0 {
                break;
            }
        }
    }
    conn.execute(
        "DELETE FROM sessions WHERE id = ?1",
        rusqlite::params![session_id],
    )
    .map_err(|err| QueryError::sqlite("delete_session", err))?;
    // Same audit row retention writes: `purged:<public_id>` → `<ns>,user`.
    let deleted_ns = unix_now_ns();
    let key = format!("purged:{public_id}");
    let value = format!("{deleted_ns},user");
    conn.execute(
        "INSERT INTO schema_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        rusqlite::params![key, value],
    )
    .map_err(|err| QueryError::sqlite("delete_session_audit", err))?;
    Ok(Some(()))
}

fn query_table_exists(conn: &Connection, name: &str) -> Result<bool, QueryError> {
    let found: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            rusqlite::params![name],
            |row| row.get(0),
        )
        .map_err(|err| QueryError::sqlite("table_exists", err))?;
    Ok(found > 0)
}

fn unix_now_ns() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// `(started_ns, ended_ns)`. `ended_ns` stays `None` while the session is active.
fn session_span(
    conn: &Connection,
    session_id: i64,
) -> Result<Option<(i64, Option<i64>)>, QueryError> {
    conn.query_row(
        "SELECT started_ns, ended_ns FROM sessions WHERE id = ?",
        rusqlite::params![session_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(|err| QueryError::sqlite("session_span", err))
}

fn latest_timeline_ts(conn: &Connection, session_id: i64) -> Result<Option<i64>, QueryError> {
    conn.query_row(
        "SELECT MAX(ts_ns) FROM timeline WHERE session_id = ?",
        rusqlite::params![session_id],
        |row| row.get(0),
    )
    .map_err(|err| QueryError::sqlite("timeline_latest", err))
}

fn fill_histogram_counts(
    conn: &Connection,
    session_id: i64,
    start: i64,
    end: i64,
    width: i64,
    out: &mut [HistBucket],
) -> Result<(), QueryError> {
    let n = out.len() as i64;
    // The last bucket is closed on the right so a row at exactly `end` counts.
    let mut stmt = conn
        .prepare(
            "SELECT ts_ns FROM timeline \
             WHERE session_id = ? AND ts_ns >= ? AND ts_ns <= ?",
        )
        .map_err(|err| QueryError::sqlite("timeline_histogram", err))?;
    let rows = stmt
        .query_map(rusqlite::params![session_id, start, end], |row| row.get(0))
        .map_err(|err| QueryError::sqlite("timeline_histogram", err))?;
    for row in rows {
        let ts: i64 = row.map_err(|err| QueryError::sqlite("timeline_histogram", err))?;
        let idx = bucket_index(ts, start, end, width, n);
        out[idx].count = out[idx].count.saturating_add(1);
    }
    Ok(())
}

fn fill_histogram_gaps(
    conn: &Connection,
    session_id: i64,
    start: i64,
    end: i64,
    width: i64,
    out: &mut [HistBucket],
) -> Result<(), QueryError> {
    let n = out.len() as i64;
    let mut stmt = conn
        .prepare(
            "SELECT from_ns, to_ns FROM gaps \
             WHERE session_id = ? AND to_ns >= ? AND from_ns <= ?",
        )
        .map_err(|err| QueryError::sqlite("timeline_histogram_gaps", err))?;
    let rows = stmt
        .query_map(rusqlite::params![session_id, start, end], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(|err| QueryError::sqlite("timeline_histogram_gaps", err))?;
    for row in rows {
        let (from_ns, to_ns): (i64, i64) =
            row.map_err(|err| QueryError::sqlite("timeline_histogram_gaps", err))?;
        let mut first = bucket_index(from_ns.max(start), start, end, width, n);
        let mut last = bucket_index(to_ns.min(end), start, end, width, n);
        if first > last {
            std::mem::swap(&mut first, &mut last);
        }
        for bucket in &mut out[first..=last] {
            bucket.gap = true;
        }
    }
    Ok(())
}

/// Bucket index for `ts`. A timestamp at exactly `end` lands in the last bucket.
fn bucket_index(ts: i64, start: i64, end: i64, width: i64, buckets: i64) -> usize {
    if ts >= end || width <= 0 {
        return (buckets - 1).max(0) as usize;
    }
    let offset = ts.saturating_sub(start);
    let idx = if width == 1 && offset >= buckets {
        buckets - 1
    } else {
        offset / width
    };
    idx.clamp(0, buckets - 1) as usize
}

fn process_images(
    conn: &Connection,
    session_id: i64,
    proc_uid: i64,
) -> Result<Vec<ProcessImage>, QueryError> {
    let mut stmt = conn
        .prepare(
            "SELECT seq, ts_ns, exe, argv, cwd, evidence, source \
             FROM process_images \
             WHERE session_id = ? AND proc_uid = ? \
             ORDER BY seq",
        )
        .map_err(|err| QueryError::sqlite("process_images", err))?;
    let rows = stmt
        .query_map(rusqlite::params![session_id, proc_uid], |row| {
            Ok(ProcessImage {
                seq: row.get(0)?,
                ts_ns: row.get(1)?,
                exe: row.get(2)?,
                argv: row.get(3)?,
                cwd: row.get(4)?,
                evidence: row.get(5)?,
                source: row.get(6)?,
            })
        })
        .map_err(|err| QueryError::sqlite("process_images", err))?;
    collect_rows(rows)
}

fn process_children(
    conn: &Connection,
    session_id: i64,
    proc_uid: i64,
) -> Result<Vec<i64>, QueryError> {
    let mut stmt = conn
        .prepare(
            "SELECT proc_uid FROM processes \
             WHERE session_id = ? AND parent_uid = ? \
             ORDER BY start_ns, proc_uid",
        )
        .map_err(|err| QueryError::sqlite("process_children", err))?;
    let rows = stmt
        .query_map(rusqlite::params![session_id, proc_uid], |row| row.get(0))
        .map_err(|err| QueryError::sqlite("process_children", err))?;
    collect_rows(rows)
}

/// Text, time and evidence of a hit's source row.
type HitDetail = (Option<String>, Option<i64>, Option<String>);

fn hit_detail(conn: &Connection, hit: &SearchHit) -> Result<Option<HitDetail>, QueryError> {
    let sql = match hit.src.as_str() {
        "file_access" => "SELECT path, first_ns, evidence FROM file_access WHERE id = ?",
        "process_images" => {
            "SELECT coalesce(exe, argv), ts_ns, evidence FROM process_images WHERE id = ?"
        }
        _ => return Ok(None),
    };
    conn.query_row(sql, rusqlite::params![hit.src_id], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })
    .optional()
    .map_err(|err| QueryError::sqlite("search_detail", err))
}

fn clamp_page(limit: Option<i64>) -> Result<i64, QueryError> {
    let page = limit.unwrap_or(DEFAULT_TIMELINE_LIMIT);
    if !(0..=MAX_PAGE_LIMIT).contains(&page) {
        return Err(QueryError::BadArgument {
            name: "limit",
            expected: "0..=2000",
        });
    }
    Ok(page)
}

fn read_file(row: &Row<'_>) -> rusqlite::Result<FileRow> {
    Ok(FileRow {
        id: row.get(0)?,
        session_id: row.get(1)?,
        proc_uid: row.get(2)?,
        op: row.get(3)?,
        path: row.get(4)?,
        first_ns: row.get(5)?,
        evidence: row.get(6)?,
        bytes_read: row.get(7)?,
        bytes_written: row.get(8)?,
        sensitive_rule: row.get(9)?,
    })
}

fn group_files(rows: Vec<FileRow>, by: FileGroupBy) -> Vec<FileRow> {
    if by == FileGroupBy::None {
        return rows;
    }
    let mut groups: BTreeMap<String, FileRow> = BTreeMap::new();
    for row in rows {
        let key = match by {
            FileGroupBy::None => String::new(),
            FileGroupBy::Path => row.path.clone(),
            FileGroupBy::Dir => parent_dir(&row.path),
            FileGroupBy::Proc => row.proc_uid.to_string(),
        };
        groups
            .entry(key)
            .and_modify(|acc| {
                acc.bytes_read = add_opt(acc.bytes_read, row.bytes_read);
                acc.bytes_written = add_opt(acc.bytes_written, row.bytes_written);
                if row.first_ns < acc.first_ns {
                    acc.first_ns = row.first_ns;
                    acc.id = row.id;
                }
            })
            .or_insert(row);
    }
    let mut out: Vec<FileRow> = groups.into_values().collect();
    out.sort_by_key(|row| (row.first_ns, row.id));
    out
}

/// Parent directory of `path`. `/a/b` → `/a`. A path with no separator is unchanged.
fn parent_dir(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut split = None;
    for (i, byte) in bytes.iter().enumerate().rev() {
        if *byte == b'/' || *byte == b'\\' {
            split = Some(i);
            break;
        }
    }
    match split {
        Some(0) => path[..1].to_string(),
        Some(i) => path[..i].to_string(),
        None => path.to_string(),
    }
}

fn store_param_to_sql(param: &StoreParam) -> rusqlite::types::Value {
    match param {
        StoreParam::Text(s) => rusqlite::types::Value::Text(s.clone()),
        StoreParam::Int(n) => rusqlite::types::Value::Integer(*n),
    }
}

fn session_visible(conn: &Connection, user_id: &str, session_id: i64) -> Result<bool, QueryError> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT id FROM sessions WHERE id = ? AND user_id = ?",
            rusqlite::params![session_id, user_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| QueryError::sqlite("session_owner", err))?;
    Ok(found.is_some())
}

fn session_started(conn: &Connection, session_id: i64) -> Result<Option<i64>, QueryError> {
    conn.query_row(
        "SELECT started_ns FROM sessions WHERE id = ?",
        rusqlite::params![session_id],
        |row| row.get(0),
    )
    .optional()
    .map_err(|err| QueryError::sqlite("session_started", err))
}

fn compile_optional(
    filter: Option<&str>,
    target: Target,
    session_start_ns: Option<i64>,
    now_ns: Option<i64>,
) -> Result<sql::Predicate, QueryError> {
    let expr = match filter {
        None | Some("") => Expr::True,
        Some(text) => parse(text)?,
    };
    compile(&expr, target, session_start_ns, now_ns)
}

fn parse_group(raw: Option<&str>) -> Result<FlowGroupBy, QueryError> {
    match raw {
        None | Some("") | Some("none") => Ok(FlowGroupBy::None),
        Some("domain") => Ok(FlowGroupBy::Domain),
        Some("ip") => Ok(FlowGroupBy::Ip),
        Some("port") => Ok(FlowGroupBy::Port),
        Some("proc") => Ok(FlowGroupBy::Proc),
        Some(_) => Err(QueryError::BadArgument {
            name: "group_by",
            expected: "domain|ip|proc|port",
        }),
    }
}

fn parse_sort(raw: Option<&str>) -> Result<FlowSort, QueryError> {
    match raw {
        None | Some("") | Some("time") => Ok(FlowSort::Time),
        Some("up") => Ok(FlowSort::Up),
        Some("down") => Ok(FlowSort::Down),
        Some("total") => Ok(FlowSort::Total),
        Some(_) => Err(QueryError::BadArgument {
            name: "sort",
            expected: "up|down|total|time",
        }),
    }
}

fn read_flow(row: &Row<'_>) -> rusqlite::Result<FlowRow> {
    Ok(FlowRow {
        id: Some(row.get(0)?),
        proc_uid: Some(row.get(1)?),
        domain: row.get(2)?,
        remote_ip: Some(row.get(3)?),
        remote_port: Some(row.get(4)?),
        bytes_up: row.get(5)?,
        bytes_down: row.get(6)?,
        start_ns: row.get(7)?,
        evidence: Some(row.get(8)?),
        count: 1,
    })
}

fn group_flows(rows: Vec<FlowRow>, by: FlowGroupBy) -> Vec<FlowRow> {
    let mut groups: BTreeMap<String, FlowRow> = BTreeMap::new();
    for row in rows {
        let key = match by {
            FlowGroupBy::None => String::new(),
            FlowGroupBy::Domain => match &row.domain {
                Some(d) => format!("d:{d}"),
                None => "d:\u{0}".to_string(),
            },
            FlowGroupBy::Ip => match &row.remote_ip {
                Some(ip) => format!("i:{ip}"),
                None => "i:\u{0}".to_string(),
            },
            FlowGroupBy::Port => row
                .remote_port
                .map(|p| format!("p:{p}"))
                .unwrap_or_else(|| "p:\u{0}".to_string()),
            FlowGroupBy::Proc => row
                .proc_uid
                .map(|p| format!("u:{p}"))
                .unwrap_or_else(|| "u:\u{0}".to_string()),
        };
        groups
            .entry(key)
            .and_modify(|acc| {
                acc.bytes_up = add_opt(acc.bytes_up, row.bytes_up);
                acc.bytes_down = add_opt(acc.bytes_down, row.bytes_down);
                if row.start_ns < acc.start_ns {
                    acc.start_ns = row.start_ns;
                }
                acc.count += row.count;
            })
            .or_insert_with(|| FlowRow {
                id: None,
                proc_uid: if by == FlowGroupBy::Proc {
                    row.proc_uid
                } else {
                    None
                },
                domain: if by == FlowGroupBy::Domain {
                    row.domain.clone()
                } else {
                    None
                },
                remote_ip: if by == FlowGroupBy::Ip {
                    row.remote_ip.clone()
                } else {
                    None
                },
                remote_port: if by == FlowGroupBy::Port {
                    row.remote_port
                } else {
                    None
                },
                bytes_up: row.bytes_up,
                bytes_down: row.bytes_down,
                start_ns: row.start_ns,
                evidence: None,
                count: row.count,
            });
    }
    groups.into_values().collect()
}

/// `None + None = None`. A known side plus an unknown side keeps the known
/// side: the unknown observation is not treated as zero, and it is not dropped.
fn add_opt(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (None, None) => None,
        (Some(a), None) | (None, Some(a)) => Some(a),
        (Some(a), Some(b)) => Some(a.saturating_add(b)),
    }
}

fn sort_flows(rows: &mut [FlowRow], sort: FlowSort) {
    match sort {
        FlowSort::Time => rows.sort_by_key(|row| (row.start_ns, row.id.unwrap_or(0))),
        FlowSort::Up => rows.sort_by(|a, b| cmp_bytes(a.bytes_up, b.bytes_up).reverse()),
        FlowSort::Down => rows.sort_by(|a, b| cmp_bytes(a.bytes_down, b.bytes_down).reverse()),
        FlowSort::Total => rows.sort_by(|a, b| {
            cmp_bytes(total_bytes(a), total_bytes(b))
                .reverse()
                .then_with(|| a.start_ns.cmp(&b.start_ns))
        }),
    }
}

fn total_bytes(row: &FlowRow) -> Option<i64> {
    add_opt(row.bytes_up, row.bytes_down)
}

/// Known values sort before unknown ones. Unknown is not zero.
fn cmp_bytes(left: Option<i64>, right: Option<i64>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

struct FlatProc {
    proc_uid: i64,
    pid: i64,
    parent_uid: Option<i64>,
    depth: i64,
    start_ns: i64,
    exit_ns: Option<i64>,
    evidence: String,
    exe_name: Option<String>,
}

fn build_tree(flat: Vec<FlatProc>) -> Vec<ProcessNode> {
    let ids: std::collections::BTreeSet<i64> = flat.iter().map(|row| row.proc_uid).collect();
    let mut children: BTreeMap<i64, Vec<ProcessNode>> = BTreeMap::new();
    let mut roots = Vec::new();
    for row in flat {
        let node = ProcessNode {
            proc_uid: row.proc_uid,
            pid: row.pid,
            parent_uid: row.parent_uid,
            depth: row.depth,
            start_ns: row.start_ns,
            exit_ns: row.exit_ns,
            evidence: row.evidence,
            exe_name: row.exe_name,
            children: Vec::new(),
        };
        match row.parent_uid {
            Some(parent) if ids.contains(&parent) && parent != row.proc_uid => {
                children.entry(parent).or_default().push(node);
            }
            _ => roots.push(node),
        }
    }
    fn attach(nodes: &mut [ProcessNode], kids: &BTreeMap<i64, Vec<ProcessNode>>) {
        for node in nodes.iter_mut() {
            if let Some(more) = kids.get(&node.proc_uid) {
                node.children = more.clone();
                attach(&mut node.children, kids);
            }
        }
    }
    attach(&mut roots, &children);
    roots
}

fn collect_rows<T, I>(rows: I) -> Result<Vec<T>, QueryError>
where
    I: Iterator<Item = rusqlite::Result<T>>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|err| QueryError::sqlite("read_row", err))?);
    }
    Ok(out)
}

impl Param {
    pub(crate) fn to_sql(&self) -> rusqlite::types::Value {
        match self {
            Param::Text(s) => rusqlite::types::Value::Text(s.clone()),
            Param::Int(n) => rusqlite::types::Value::Integer(*n),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(include_str!("../../migrations/0001_init.sql"))
            .unwrap();
        conn.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1')",
            [],
        )
        .unwrap();
        ensure_timeline(&conn).unwrap();
        conn
    }

    fn session(conn: &Connection, id: i64, user: &str, started: i64) {
        conn.execute(
            "INSERT INTO sessions (id, public_id, mode, user_id, started_ns, platform, collectors) \
             VALUES (?1, ?2, 'launch', ?3, ?4, 'windows', '[]')",
            rusqlite::params![id, format!("s{id}"), user, started],
        )
        .unwrap();
    }

    fn proc_row(
        conn: &Connection,
        session: i64,
        uid: i64,
        pid: i64,
        parent: Option<i64>,
        start: i64,
    ) {
        conn.execute(
            "INSERT INTO processes (session_id, proc_uid, pid, parent_uid, depth, start_ns, how, evidence, source) \
             VALUES (?1, ?2, ?3, ?4, 0, ?5, 'spawn', 'E1', 'test')",
            rusqlite::params![session, uid, pid, parent, start],
        )
        .unwrap();
    }

    fn image(conn: &Connection, session: i64, uid: i64, ts: i64, exe: Option<&str>) {
        conn.execute(
            "INSERT INTO process_images (session_id, proc_uid, seq, ts_ns, exe, evidence, source) \
             VALUES (?1, ?2, 0, ?3, ?4, 'E1', 'test')",
            rusqlite::params![session, uid, ts, exe],
        )
        .unwrap();
    }

    struct FlowSeed<'a> {
        id: i64,
        session: i64,
        uid: i64,
        domain: Option<&'a str>,
        ip: &'a str,
        port: i64,
        start: i64,
        up: Option<i64>,
        down: Option<i64>,
    }

    fn flow(conn: &Connection, seed: FlowSeed<'_>) {
        let FlowSeed {
            id,
            session,
            uid,
            domain,
            ip,
            port,
            start,
            up,
            down,
        } = seed;
        conn.execute(
            "INSERT INTO net_flows (
                id, session_id, proc_uid, proto, direction, local_ip, local_port,
                remote_ip, remote_port, domain, start_ns, bytes_up, bytes_down, evidence, source
             ) VALUES (?1, ?2, ?3, 'tcp', 'outbound', '127.0.0.1', 1, ?4, ?5, ?6, ?7, ?8, ?9, 'E1', 'test')",
            rusqlite::params![id, session, uid, ip, port, domain, start, up, down],
        )
        .unwrap();
    }

    #[test]
    fn user_a_cannot_see_user_b() {
        let conn = conn();
        session(&conn, 1, "user-a", 10);
        session(&conn, 2, "user-b", 20);
        let a = list_sessions(&conn, "user-a", &SessionFilter::default()).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].id, 1);
        assert!(session_summary(&conn, "user-a", 2).unwrap().is_none());
        assert!(process_tree(&conn, "user-a", 2).unwrap().is_none());
        assert!(flows(&conn, "user-a", 2, FlowQuery::default())
            .unwrap()
            .is_none());
        assert!(timeline(&conn, "user-a", 2, TimelineQuery::default())
            .unwrap()
            .is_none());
        assert!(gaps(&conn, "user-a", 2).unwrap().is_none());
    }

    #[test]
    fn injection_does_not_match_both_rows() {
        let conn = conn();
        session(&conn, 1, "user-a", 1);
        proc_row(&conn, 1, 7, 100, None, 1);
        flow(
            &conn,
            FlowSeed {
                id: 1,
                session: 1,
                uid: 7,
                domain: Some("x' OR 1=1 --"),
                ip: "1.1.1.1",
                port: 443,
                start: 10,
                up: Some(1),
                down: Some(1),
            },
        );
        flow(
            &conn,
            FlowSeed {
                id: 2,
                session: 1,
                uid: 7,
                domain: Some("other.example"),
                ip: "2.2.2.2",
                port: 80,
                start: 20,
                up: Some(1),
                down: Some(1),
            },
        );
        let rows = flows(
            &conn,
            "user-a",
            1,
            FlowQuery {
                filter: Some(r#"domain:"x' OR 1=1 --""#),
                ..FlowQuery::default()
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(rows.len(), 1, "injected text must not return every row");
        assert_eq!(rows[0].id, Some(1));
        assert_eq!(rows[0].domain.as_deref(), Some("x' OR 1=1 --"));
    }

    #[test]
    fn timeline_filter_glob_and_cursor() {
        let conn = conn();
        session(&conn, 1, "user-a", 1);
        proc_row(&conn, 1, 7, 100, None, 5);
        flow(
            &conn,
            FlowSeed {
                id: 1,
                session: 1,
                uid: 7,
                domain: Some("a.example.com"),
                ip: "9.9.9.9",
                port: 443,
                start: 10,
                up: Some(5),
                down: None,
            },
        );
        flow(
            &conn,
            FlowSeed {
                id: 2,
                session: 1,
                uid: 7,
                domain: Some("b.other.net"),
                ip: "8.8.8.8",
                port: 443,
                start: 30,
                up: Some(9),
                down: Some(1),
            },
        );
        conn.execute(
            "INSERT INTO dns (id, session_id, proc_uid, ts_ns, qname, qtype, evidence, source) \
             VALUES (3, 1, NULL, 20, 'a.example.com', 1, 'E1', 'test')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO gaps (id, session_id, collector, kind, affects, from_ns, to_ns, count) \
             VALUES (4, 1, 'poll', 'dropped', '[\"net\"]', 40, 41, NULL)",
            [],
        )
        .unwrap();
        let page = timeline(
            &conn,
            "user-a",
            1,
            TimelineQuery {
                filter: Some("kind:net domain:*.example.com"),
                limit: Some(10),
                ..TimelineQuery::default()
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].cat, "net");
        assert_eq!(page.rows[0].id, 1);
        let all = timeline(
            &conn,
            "user-a",
            1,
            TimelineQuery {
                limit: Some(2),
                ..TimelineQuery::default()
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(all.rows.len(), 2);
        let next = all.next.expect("more rows");
        let rest = timeline(
            &conn,
            "user-a",
            1,
            TimelineQuery {
                limit: Some(10),
                cursor: Some(next),
                ..TimelineQuery::default()
            },
        )
        .unwrap()
        .unwrap();
        assert!(rest
            .rows
            .iter()
            .all(|row| (row.ts_ns, row.id) > (next.ts_ns, next.id)));
        assert!(rest.next.is_none());
        let gap = rest.rows.iter().find(|row| row.cat == "gap");
        if let Some(gap) = gap {
            assert_eq!(gap.proc_uid, None);
            assert_eq!(gap.evidence, "E1");
        }
    }

    #[test]
    fn null_bytes_stay_none_and_tree_nests() {
        let conn = conn();
        session(&conn, 1, "user-a", 1);
        proc_row(&conn, 1, 1, 10, None, 1);
        proc_row(&conn, 1, 2, 11, Some(1), 2);
        image(&conn, 1, 2, 2, Some("/usr/bin/node"));
        flow(
            &conn,
            FlowSeed {
                id: 1,
                session: 1,
                uid: 2,
                domain: None,
                ip: "1.2.3.4",
                port: 443,
                start: 5,
                up: None,
                down: None,
            },
        );
        let summary = session_summary(&conn, "user-a", 1).unwrap().unwrap();
        assert_eq!(summary.bytes_up, None);
        assert_eq!(summary.bytes_down, None);
        assert_eq!(summary.flow_count, 1);
        let tree = process_tree(&conn, "user-a", 1).unwrap().unwrap();
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].proc_uid, 1);
        assert_eq!(tree[0].children.len(), 1);
        assert_eq!(tree[0].children[0].exe_name.as_deref(), Some("node"));
        let grouped = flows(
            &conn,
            "user-a",
            1,
            FlowQuery {
                group_by: Some("domain"),
                sort: Some("up"),
                ..FlowQuery::default()
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].domain, None);
        assert_eq!(grouped[0].bytes_up, None);
    }

    #[test]
    fn gaps_keep_null_count() {
        let conn = conn();
        session(&conn, 1, "user-a", 1);
        conn.execute(
            "INSERT INTO gaps (session_id, collector, kind, affects, from_ns, to_ns, count, detail) \
             VALUES (1, 'poll', 'dropped', '[]', 1, 2, NULL, NULL)",
            [],
        )
        .unwrap();
        let rows = gaps(&conn, "user-a", 1).unwrap().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].count, None);
        assert_eq!(rows[0].detail, None);
    }

    #[test]
    fn proc_filter_uses_basename() {
        let conn = conn();
        session(&conn, 1, "user-a", 1);
        proc_row(&conn, 1, 7, 100, None, 1);
        image(&conn, 1, 7, 1, Some("C:\\tools\\node.exe"));
        flow(
            &conn,
            FlowSeed {
                id: 1,
                session: 1,
                uid: 7,
                domain: Some("example.com"),
                ip: "1.1.1.1",
                port: 443,
                start: 10,
                up: Some(3),
                down: Some(4),
            },
        );
        let rows = flows(
            &conn,
            "user-a",
            1,
            FlowQuery {
                filter: Some("proc:node.exe"),
                ..FlowQuery::default()
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(rows.len(), 1);
        let none = flows(
            &conn,
            "user-a",
            1,
            FlowQuery {
                filter: Some("proc:curl"),
                ..FlowQuery::default()
            },
        )
        .unwrap()
        .unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn explain_uses_session_time_index() {
        let conn = conn();
        session(&conn, 1, "user-a", 1);
        let sql = "EXPLAIN QUERY PLAN \
                   SELECT id FROM timeline \
                   WHERE session_id = 1 AND ts_ns >= 0 AND ts_ns <= 100 \
                   ORDER BY ts_ns, id LIMIT 10";
        let mut stmt = conn.prepare(sql).unwrap();
        let plan: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let joined = plan.join("\n");
        assert!(
            joined.contains("idx_nf_session_ts")
                || joined.contains("idx_dns_session_ts")
                || joined.contains("idx_gaps_session_ts")
                || joined.contains("USING INDEX"),
            "plan did not name an index:\n{joined}"
        );
    }

    /// 20_000 flows, not the card's 1_000_000. The plan must use `idx_nf_session_ts`,
    /// and the filtered page must finish. The 1e6 p95 is not measured here.
    #[test]
    fn timeline_20k_uses_session_index() {
        let conn = conn();
        session(&conn, 1, "user-a", 1);
        proc_row(&conn, 1, 7, 100, None, 1);
        let tx = conn.unchecked_transaction().unwrap();
        for i in 0..20_000_i64 {
            let domain = if i % 50 == 0 {
                "hit.example.com"
            } else {
                "other.net"
            };
            tx.execute(
                "INSERT INTO net_flows (
                    id, session_id, proc_uid, proto, direction, local_ip, local_port,
                    remote_ip, remote_port, domain, start_ns, evidence, source
                 ) VALUES (?1, 1, 7, 'tcp', 'outbound', '127.0.0.1', 1, '9.9.9.9', 443, ?2, ?3, 'E1', 'test')",
                rusqlite::params![i + 1, domain, i],
            )
            .unwrap();
        }
        tx.commit().unwrap();
        let plan_sql = "EXPLAIN QUERY PLAN \
            SELECT timeline.id FROM timeline \
            JOIN sessions ON sessions.id = timeline.session_id \
            WHERE timeline.session_id = ? AND sessions.user_id = ? \
              AND timeline.ts_ns >= ? AND cat = 'net' \
              AND (CASE cat WHEN 'net' THEN (SELECT domain FROM net_flows WHERE net_flows.id = timeline.id) ELSE NULL END) GLOB ? \
            ORDER BY timeline.ts_ns, timeline.id LIMIT 100";
        let mut stmt = conn.prepare(plan_sql).unwrap();
        let plan: Vec<String> = stmt
            .query_map(
                rusqlite::params![1_i64, "user-a", 0_i64, "*.example.com"],
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let joined = plan.join("\n");
        assert!(
            joined.contains("idx_nf_session_ts"),
            "net branch did not use idx_nf_session_ts:\n{joined}"
        );
        let started = std::time::Instant::now();
        let page = timeline(
            &conn,
            "user-a",
            1,
            TimelineQuery {
                filter: Some("kind:net domain:*.example.com"),
                from: Some(0),
                limit: Some(100),
                ..TimelineQuery::default()
            },
        )
        .unwrap()
        .unwrap();
        let elapsed = started.elapsed();
        assert!(!page.rows.is_empty());
        assert!(
            elapsed.as_millis() < 3_000,
            "20k filtered timeline took {elapsed:?}"
        );
    }

    /// UI review of #143: a hit carried only its row id, so the search page
    /// printed 「记录 #id」. It now carries the row's text, time and evidence,
    /// and the executable path is matched when argv is unknown.
    #[test]
    fn search_hit_carries_text_and_time() {
        let conn = conn();
        conn.execute_batch(include_str!("../../migrations/0003_file_access.sql"))
            .unwrap();
        session(&conn, 1, "u", 10);
        image(&conn, 1, 7, 1_000, Some("/usr/bin/node"));
        let hits = search(&conn, "u", "NODE", false, None, None).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text.as_deref(), Some("/usr/bin/node"));
        assert_eq!(hits[0].ts_ns, Some(1_000));
        assert_eq!(hits[0].evidence.as_deref(), Some("E1"));
        assert!(search(&conn, "u", "node", false, Some(2_000), None)
            .unwrap()
            .is_empty());
        assert!(search(&conn, "other", "node", false, None, None)
            .unwrap()
            .is_empty());
    }

    /// UI review of #143, detail 7: the list said 「不可得」 where the
    /// overview had numbers. Both now read [`session_counts`].
    #[test]
    fn session_list_carries_the_overview_counts() {
        let conn = conn();
        session(&conn, 1, "u", 10);
        proc_row(&conn, 1, 7, 70, None, 11);
        proc_row(&conn, 1, 8, 80, Some(7), 12);
        let items = list_sessions(&conn, "u", &SessionFilter::default()).unwrap();
        assert_eq!(items.len(), 1);
        let summary = session_summary(&conn, "u", 1).unwrap().unwrap();
        assert_eq!(items[0].counts.process_count, 2);
        assert_eq!(items[0].counts.process_count, summary.process_count);
        assert_eq!(items[0].counts.gap_count, summary.gap_count);
        assert_eq!(items[0].counts.bytes_up, summary.bytes_up);
        // No findings table in this schema: unknown, not zero.
        assert_eq!(items[0].counts.finding_count, None);
        assert_eq!(summary.finding_count, None);
        assert_eq!(items[0].collectors, "[]");
    }
}
