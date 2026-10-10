//! SQLite page source. One page of timeline rows is loaded, joined back to
//! the table, and returned. The timeline rows are dropped before the page is
//! returned to the writer, so the writer holds one page of records.

use rusqlite::{params_from_iter, Connection, OptionalExtension, Row};

use crate::export::records::{
    CollectorGaps, DnsRecord, ExportRecord, GapRecord, GapsSummary, NetFlowRecord, Page,
    ProcessRecord, SessionHeader,
};
use crate::export::{ExportError, ExportOptions};
use crate::query::{compile, ensure_timeline, parse_filter, Param, QueryError, Target};

/// Flags copied out of [`ExportOptions`] so a page source does not borrow them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redact {
    /// `--redact-paths`.
    pub paths: bool,
    /// `--redact-hosts`.
    pub hosts: bool,
}

impl Redact {
    pub(crate) fn off() -> Self {
        Self {
            paths: false,
            hosts: false,
        }
    }

    pub(crate) fn from_options(options: &ExportOptions<'_>) -> Self {
        Self {
            paths: options.redact_paths,
            hosts: options.redact_hosts,
        }
    }
}

pub(crate) struct SessionExport {
    pub(crate) header: SessionHeader,
    pub(crate) gaps: GapsSummary,
    pub(crate) redact: Redact,
}

pub(crate) fn load_session(
    conn: &Connection,
    options: &ExportOptions<'_>,
) -> Result<SessionExport, ExportError> {
    let page = options
        .page_size
        .unwrap_or(crate::query::MAX_TIMELINE_LIMIT);
    if !(1..=crate::query::MAX_TIMELINE_LIMIT).contains(&page) {
        return Err(ExportError::BadPageSize);
    }
    if let Some(filter) = options.filter {
        if !filter.is_empty() {
            let _ = parse_filter(filter)?;
        }
    }
    ensure_timeline(conn)?;
    let header = load_header(conn, options.user_id, options.session_id)?;
    let gaps = load_gaps_summary(conn, options.session_id)?;
    Ok(SessionExport {
        header,
        gaps,
        redact: Redact::from_options(options),
    })
}

fn load_header(
    conn: &Connection,
    user_id: &str,
    session_id: i64,
) -> Result<SessionHeader, ExportError> {
    let row = conn
        .query_row(
            "SELECT id, public_id, name, mode, agent, started_ns, ended_ns, platform, user_id, collectors \
             FROM sessions WHERE id = ? AND user_id = ?",
            rusqlite::params![session_id, user_id],
            |row| {
                Ok(SessionHeader {
                    id: row.get(0)?,
                    public_id: row.get(1)?,
                    name: row.get(2)?,
                    mode: row.get(3)?,
                    agent: row.get(4)?,
                    started_ns: row.get(5)?,
                    ended_ns: row.get(6)?,
                    platform: row.get(7)?,
                    user_id: row.get(8)?,
                    collectors_json: row.get(9)?,
                })
            },
        )
        .optional()
        .map_err(|err| QueryError::sqlite("export_session", err))?;
    row.ok_or(ExportError::NotFound { session_id })
}

fn load_gaps_summary(conn: &Connection, session_id: i64) -> Result<GapsSummary, ExportError> {
    let (rows, unknown_count, lost) = conn
        .query_row(
            "SELECT COUNT(*), \
                    COALESCE(SUM(CASE WHEN count IS NULL THEN 1 ELSE 0 END), 0), \
                    SUM(count) \
             FROM gaps WHERE session_id = ?",
            rusqlite::params![session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|err| QueryError::sqlite("export_gaps_summary", err))?;
    let mut stmt = conn
        .prepare(
            "SELECT collector, COUNT(*), \
                    COALESCE(SUM(CASE WHEN count IS NULL THEN 1 ELSE 0 END), 0), \
                    SUM(count) \
             FROM gaps WHERE session_id = ? \
             GROUP BY collector ORDER BY collector",
        )
        .map_err(|err| QueryError::sqlite("export_gaps_by_collector", err))?;
    let mapped = stmt
        .query_map(rusqlite::params![session_id], |row| {
            Ok(CollectorGaps {
                collector: row.get(0)?,
                rows: row.get(1)?,
                unknown_count: row.get(2)?,
                lost: row.get(3)?,
            })
        })
        .map_err(|err| QueryError::sqlite("export_gaps_by_collector", err))?;
    let mut by_collector = Vec::new();
    for item in mapped {
        by_collector.push(item.map_err(|err| QueryError::sqlite("export_gaps_by_collector", err))?);
    }
    Ok(GapsSummary {
        rows,
        unknown_count,
        lost,
        by_collector,
    })
}

struct Thin {
    cat: String,
    id: i64,
}

/// Pages the timeline in `(ts_ns, type, id)` order and loads table rows for each page.
pub(crate) struct SqlitePages<'a> {
    conn: &'a Connection,
    user_id: String,
    session_id: i64,
    filter_sql: String,
    filter_params: Vec<Param>,
    page_size: i64,
    /// When set, only this `timeline.cat` is paged. CSV uses one category per file.
    only_cat: Option<&'static str>,
    cursor: Option<SortKey>,
    done: bool,
}

struct SortKey {
    ts_ns: i64,
    /// Table name (`processes`, `net_flows`, `dns`, `gaps`). Bound as `timeline.cat`
    /// through [`cat_of`]. Do not store the short cat here.
    type_name: &'static str,
    id: i64,
}

impl<'a> SqlitePages<'a> {
    pub(crate) fn new(
        conn: &'a Connection,
        options: &ExportOptions<'_>,
        started_ns: i64,
    ) -> Result<Self, ExportError> {
        let page_size = options
            .page_size
            .unwrap_or(crate::query::MAX_TIMELINE_LIMIT);
        let expr = match options.filter {
            None | Some("") => crate::query::FilterExpr::True,
            Some(text) => parse_filter(text)?,
        };
        let pred = compile(&expr, Target::Timeline, Some(started_ns), options.now_ns)?;
        Ok(Self {
            conn,
            user_id: options.user_id.to_string(),
            session_id: options.session_id,
            filter_sql: pred.sql,
            filter_params: pred.params,
            page_size,
            only_cat: None,
            cursor: None,
            done: false,
        })
    }

    /// Restrict later pages to one timeline category (`proc`, `net`, `dns`, `gap`).
    pub(crate) fn only(&mut self, cat: &'static str) {
        self.only_cat = Some(cat);
    }

    fn fetch_thin(&mut self) -> Result<Vec<Thin>, ExportError> {
        let mut sql = String::from(
            "SELECT timeline.ts_ns, timeline.cat, timeline.id \
             FROM timeline \
             JOIN sessions ON sessions.id = timeline.session_id \
             WHERE timeline.session_id = ? AND sessions.user_id = ? AND (",
        );
        sql.push_str(&self.filter_sql);
        sql.push(')');
        let mut bind = vec![
            Param::Int(self.session_id),
            Param::Text(self.user_id.clone()),
        ];
        bind.extend(self.filter_params.iter().cloned());
        if let Some(cat) = self.only_cat {
            sql.push_str(" AND timeline.cat = ?");
            bind.push(Param::Text(cat.to_string()));
        }
        if let Some(cursor) = &self.cursor {
            sql.push_str(
                " AND (timeline.ts_ns > ? OR (timeline.ts_ns = ? AND timeline.cat > ?) \
                 OR (timeline.ts_ns = ? AND timeline.cat = ? AND timeline.id > ?))",
            );
            bind.push(Param::Int(cursor.ts_ns));
            bind.push(Param::Int(cursor.ts_ns));
            bind.push(Param::Text(cat_of(cursor.type_name).to_string()));
            bind.push(Param::Int(cursor.ts_ns));
            bind.push(Param::Text(cat_of(cursor.type_name).to_string()));
            bind.push(Param::Int(cursor.id));
        }
        sql.push_str(" ORDER BY timeline.ts_ns, timeline.cat, timeline.id LIMIT ?");
        bind.push(Param::Int(self.page_size));
        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|err| QueryError::sqlite("export_timeline", err))?;
        let rows = stmt
            .query_map(params_from_iter(bind.iter().map(Param::to_sql)), |row| {
                Ok(Thin {
                    cat: row.get(1)?,
                    id: row.get(2)?,
                })
            })
            .map_err(|err| QueryError::sqlite("export_timeline", err))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|err| QueryError::sqlite("export_timeline", err))?);
        }
        Ok(out)
    }
}

impl crate::export::PageSource for SqlitePages<'_> {
    fn next_page(&mut self) -> Result<Option<Page>, ExportError> {
        if self.done {
            return Ok(None);
        }
        let thin = self.fetch_thin()?;
        if thin.is_empty() {
            self.done = true;
            return Ok(None);
        }
        let records = hydrate(self.conn, self.session_id, &thin)?;
        if let Some(last) = records.last() {
            self.cursor = Some(SortKey {
                ts_ns: time_of(last),
                type_name: last.table(),
                id: id_of(last),
            });
        }
        drop(thin);
        if records.len() < self.page_size as usize {
            self.done = true;
        }
        Ok(Some(Page::from_records(records)))
    }
}

fn time_of(record: &ExportRecord) -> i64 {
    match record {
        ExportRecord::Process(row) => row.start_ns,
        ExportRecord::Net(row) => row.start_ns,
        ExportRecord::Dns(row) => row.ts_ns,
        ExportRecord::Gap(row) => row.from_ns,
    }
}

fn id_of(record: &ExportRecord) -> i64 {
    match record {
        ExportRecord::Process(row) => row.proc_uid,
        ExportRecord::Net(row) => row.id,
        ExportRecord::Dns(row) => row.id,
        ExportRecord::Gap(row) => row.id,
    }
}

/// Timeline `cat` for a table name. The view uses short names.
fn cat_of(type_name: &str) -> &'static str {
    match type_name {
        "processes" => "proc",
        "net_flows" => "net",
        "dns" => "dns",
        _ => "gap",
    }
}

fn hydrate(
    conn: &Connection,
    session_id: i64,
    thin: &[Thin],
) -> Result<Vec<ExportRecord>, ExportError> {
    let mut records = Vec::with_capacity(thin.len());
    // Group ids per category but emit in timeline order, so look up after the fetch.
    let mut procs = Vec::new();
    let mut nets = Vec::new();
    let mut dns = Vec::new();
    let mut gaps = Vec::new();
    for row in thin {
        match row.cat.as_str() {
            "proc" => procs.push(row.id),
            "net" => nets.push(row.id),
            "dns" => dns.push(row.id),
            "gap" => gaps.push(row.id),
            _ => {
                return Err(ExportError::MissingRow {
                    table: "timeline",
                    id: row.id,
                });
            }
        }
    }
    let proc_rows = load_processes(conn, session_id, &procs)?;
    let net_rows = load_nets(conn, session_id, &nets)?;
    let dns_rows = load_dns(conn, session_id, &dns)?;
    let gap_rows = load_gaps(conn, session_id, &gaps)?;
    for row in thin {
        let record = match row.cat.as_str() {
            "proc" => ExportRecord::Process(
                proc_rows
                    .iter()
                    .find(|item| item.proc_uid == row.id)
                    .cloned()
                    .ok_or(ExportError::MissingRow {
                        table: "processes",
                        id: row.id,
                    })?,
            ),
            "net" => ExportRecord::Net(
                net_rows
                    .iter()
                    .find(|item| item.id == row.id)
                    .cloned()
                    .ok_or(ExportError::MissingRow {
                        table: "net_flows",
                        id: row.id,
                    })?,
            ),
            "dns" => ExportRecord::Dns(
                dns_rows
                    .iter()
                    .find(|item| item.id == row.id)
                    .cloned()
                    .ok_or(ExportError::MissingRow {
                        table: "dns",
                        id: row.id,
                    })?,
            ),
            "gap" => ExportRecord::Gap(
                gap_rows
                    .iter()
                    .find(|item| item.id == row.id)
                    .cloned()
                    .ok_or(ExportError::MissingRow {
                        table: "gaps",
                        id: row.id,
                    })?,
            ),
            _ => {
                return Err(ExportError::MissingRow {
                    table: "timeline",
                    id: row.id,
                });
            }
        };
        records.push(record);
    }
    Ok(records)
}

fn in_clause(prefix: &str, n: usize) -> String {
    let mut sql = String::from(prefix);
    sql.push('(');
    for i in 0..n {
        if i > 0 {
            sql.push(',');
        }
        sql.push('?');
    }
    sql.push(')');
    sql
}

fn load_processes(
    conn: &Connection,
    session_id: i64,
    ids: &[i64],
) -> Result<Vec<ProcessRecord>, ExportError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = in_clause(
        "SELECT session_id, proc_uid, pid, parent_uid, ppid, depth, start_ns, exit_ns, \
         exit_code, exit_signal, how, user_id, signer, evidence, field_evidence, source, agent, \
         (SELECT CASE WHEN i.exe IS NULL THEN NULL \
                 ELSE replace(i.exe, rtrim(i.exe, replace(replace(i.exe, char(92), char(47)), char(47), '')), '') END \
          FROM process_images i \
          WHERE i.session_id = processes.session_id AND i.proc_uid = processes.proc_uid \
          ORDER BY i.ts_ns DESC LIMIT 1) \
         FROM processes WHERE session_id = ? AND proc_uid IN ",
        ids.len(),
    );
    let mut bind: Vec<rusqlite::types::Value> = Vec::with_capacity(ids.len() + 1);
    bind.push(rusqlite::types::Value::Integer(session_id));
    for id in ids {
        bind.push(rusqlite::types::Value::Integer(*id));
    }
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| QueryError::sqlite("export_processes", err))?;
    let rows = stmt
        .query_map(params_from_iter(bind), read_process)
        .map_err(|err| QueryError::sqlite("export_processes", err))?;
    collect(rows, "export_processes")
}

fn read_process(row: &Row<'_>) -> rusqlite::Result<ProcessRecord> {
    Ok(ProcessRecord {
        session_id: row.get(0)?,
        proc_uid: row.get(1)?,
        pid: row.get(2)?,
        parent_uid: row.get(3)?,
        ppid: row.get(4)?,
        depth: row.get(5)?,
        start_ns: row.get(6)?,
        exit_ns: row.get(7)?,
        exit_code: row.get(8)?,
        exit_signal: row.get(9)?,
        how: row.get(10)?,
        user_id: row.get(11)?,
        signer: row.get(12)?,
        evidence: row.get(13)?,
        field_evidence: row.get(14)?,
        source: row.get(15)?,
        agent: row.get(16)?,
        exe_name: row.get(17)?,
    })
}

fn load_nets(
    conn: &Connection,
    session_id: i64,
    ids: &[i64],
) -> Result<Vec<NetFlowRecord>, ExportError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = in_clause(
        "SELECT id, session_id, proc_uid, proto, direction, local_ip, local_port, remote_ip, \
         remote_port, domain, domain_source, domain_alts, sni, alpn, start_ns, end_ns, \
         bytes_up, bytes_down, via_proxy, direct, preexisting, is_loopback, result, \
         platform_total_up, platform_total_down, evidence, na_reason, field_evidence, source \
         FROM net_flows WHERE session_id = ? AND id IN ",
        ids.len(),
    );
    let mut bind: Vec<rusqlite::types::Value> = Vec::with_capacity(ids.len() + 1);
    bind.push(rusqlite::types::Value::Integer(session_id));
    for id in ids {
        bind.push(rusqlite::types::Value::Integer(*id));
    }
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| QueryError::sqlite("export_net_flows", err))?;
    let rows = stmt
        .query_map(params_from_iter(bind), read_net)
        .map_err(|err| QueryError::sqlite("export_net_flows", err))?;
    collect(rows, "export_net_flows")
}

fn read_net(row: &Row<'_>) -> rusqlite::Result<NetFlowRecord> {
    Ok(NetFlowRecord {
        id: row.get(0)?,
        session_id: row.get(1)?,
        proc_uid: row.get(2)?,
        proto: row.get(3)?,
        direction: row.get(4)?,
        local_ip: row.get(5)?,
        local_port: row.get(6)?,
        remote_ip: row.get(7)?,
        remote_port: row.get(8)?,
        domain: row.get(9)?,
        domain_source: row.get(10)?,
        domain_alts: row.get(11)?,
        sni: row.get(12)?,
        alpn: row.get(13)?,
        start_ns: row.get(14)?,
        end_ns: row.get(15)?,
        bytes_up: row.get(16)?,
        bytes_down: row.get(17)?,
        via_proxy: row.get(18)?,
        direct: row.get(19)?,
        preexisting: row.get(20)?,
        is_loopback: row.get(21)?,
        result: row.get(22)?,
        platform_total_up: row.get(23)?,
        platform_total_down: row.get(24)?,
        evidence: row.get(25)?,
        na_reason: row.get(26)?,
        field_evidence: row.get(27)?,
        source: row.get(28)?,
    })
}

fn load_dns(
    conn: &Connection,
    session_id: i64,
    ids: &[i64],
) -> Result<Vec<DnsRecord>, ExportError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = in_clause(
        "SELECT id, session_id, proc_uid, ts_ns, qname, qtype, rcode, answers, ttl_min, \
         server, evidence, source FROM dns WHERE session_id = ? AND id IN ",
        ids.len(),
    );
    let mut bind: Vec<rusqlite::types::Value> = Vec::with_capacity(ids.len() + 1);
    bind.push(rusqlite::types::Value::Integer(session_id));
    for id in ids {
        bind.push(rusqlite::types::Value::Integer(*id));
    }
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| QueryError::sqlite("export_dns", err))?;
    let rows = stmt
        .query_map(params_from_iter(bind), |row| {
            Ok(DnsRecord {
                id: row.get(0)?,
                session_id: row.get(1)?,
                proc_uid: row.get(2)?,
                ts_ns: row.get(3)?,
                qname: row.get(4)?,
                qtype: row.get(5)?,
                rcode: row.get(6)?,
                answers: row.get(7)?,
                ttl_min: row.get(8)?,
                server: row.get(9)?,
                evidence: row.get(10)?,
                source: row.get(11)?,
            })
        })
        .map_err(|err| QueryError::sqlite("export_dns", err))?;
    collect(rows, "export_dns")
}

fn load_gaps(
    conn: &Connection,
    session_id: i64,
    ids: &[i64],
) -> Result<Vec<GapRecord>, ExportError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let sql = in_clause(
        "SELECT id, session_id, collector, kind, affects, from_ns, to_ns, count, detail \
         FROM gaps WHERE session_id = ? AND id IN ",
        ids.len(),
    );
    let mut bind: Vec<rusqlite::types::Value> = Vec::with_capacity(ids.len() + 1);
    bind.push(rusqlite::types::Value::Integer(session_id));
    for id in ids {
        bind.push(rusqlite::types::Value::Integer(*id));
    }
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|err| QueryError::sqlite("export_gaps", err))?;
    let rows = stmt
        .query_map(params_from_iter(bind), |row| {
            Ok(GapRecord {
                id: row.get(0)?,
                session_id: row.get(1)?,
                collector: row.get(2)?,
                kind: row.get(3)?,
                affects: row.get(4)?,
                from_ns: row.get(5)?,
                to_ns: row.get(6)?,
                count: row.get(7)?,
                detail: row.get(8)?,
            })
        })
        .map_err(|err| QueryError::sqlite("export_gaps", err))?;
    collect(rows, "export_gaps")
}

fn collect<T, I>(rows: I, op: &'static str) -> Result<Vec<T>, ExportError>
where
    I: Iterator<Item = rusqlite::Result<T>>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|err| QueryError::sqlite(op, err))?);
    }
    Ok(out)
}
