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

mod error;
mod filter;
mod sql;

use std::collections::BTreeMap;

use rusqlite::{params_from_iter, Connection, OptionalExtension, Row};

use crate::query::filter::{parse, Expr};
use crate::query::sql::{compile, Param, Target};

pub use error::QueryError;
#[allow(unused_imports)]
pub use filter::{parse as parse_filter, Expr as FilterExpr};

const TIMELINE_SQL: &str = include_str!("../../migrations/0002_timeline_view.sql");

/// How many rows `timeline` returns when the caller passes `None`.
pub const DEFAULT_TIMELINE_LIMIT: i64 = 100;

/// Hard cap so a caller cannot ask for an unbounded page.
pub const MAX_TIMELINE_LIMIT: i64 = 1000;

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
        "SELECT id, public_id, name, mode, agent, started_ns, ended_ns, pinned \
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
            })
        })
        .map_err(|err| QueryError::sqlite("list_sessions", err))?;
    collect_rows(rows)
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
    let summary = conn
        .query_row(
            "SELECT s.id, s.public_id, s.name, s.agent, s.started_ns, s.ended_ns, \
                    (SELECT COUNT(*) FROM processes p WHERE p.session_id = s.id), \
                    (SELECT COUNT(*) FROM net_flows f WHERE f.session_id = s.id), \
                    (SELECT COUNT(*) FROM dns d WHERE d.session_id = s.id), \
                    (SELECT COUNT(*) FROM gaps g WHERE g.session_id = s.id), \
                    (SELECT SUM(bytes_up) FROM net_flows f WHERE f.session_id = s.id), \
                    (SELECT SUM(bytes_down) FROM net_flows f WHERE f.session_id = s.id) \
             FROM sessions s WHERE s.id = ? AND s.user_id = ?",
            rusqlite::params![session_id, user_id],
            |row| {
                Ok(SessionSummary {
                    id: row.get(0)?,
                    public_id: row.get(1)?,
                    name: row.get(2)?,
                    agent: row.get(3)?,
                    started_ns: row.get(4)?,
                    ended_ns: row.get(5)?,
                    process_count: row.get(6)?,
                    flow_count: row.get(7)?,
                    dns_count: row.get(8)?,
                    gap_count: row.get(9)?,
                    bytes_up: row.get(10)?,
                    bytes_down: row.get(11)?,
                })
            },
        )
        .optional()
        .map_err(|err| QueryError::sqlite("session_summary", err))?;
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
    fn to_sql(&self) -> rusqlite::types::Value {
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
}
