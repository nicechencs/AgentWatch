//! Compile a [`Expr`] into parameterized SQL.
//!
//! User text never enters the SQL string. The string contains fixed column
//! names, `?` placeholders, and SQL keywords. Globs become a prefix range
//! (so `idx_fa_path` can seek) plus a bound `GLOB`. `~` uses FTS5 trigram
//! when the caller says the index is on, and `instr` otherwise.
//!
//! `kind:` selects the table. With no `kind`, the target is [`Target::Timeline`].
//! A field that does not exist on that table compiles to `0` and is recorded
//! in [`Compiled::warnings`]: api-and-cli §4.3 says `kind:file domain:x`
//! yields no rows plus a warning, not a silent ignore and not a hard error.
//!
//! No new index is created here.

use super::ast::{Expr, Field, Op, Term, Value};
use super::error::QueryError;
use crate::fts;

/// Which table the statement reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `timeline` view. Used when the filter does not pin a single `kind`.
    Timeline,
    /// `file_access`.
    Files,
    /// `net_flows`.
    Flows,
    /// `dns`.
    Dns,
    /// `http`. The table is not migrated in P2; the SQL is still well-formed
    /// for a later migration. Running it before that returns a SQLite error
    /// at execute time, not at compile time.
    Http,
    /// `processes` joined to the latest `process_images` row.
    Procs,
    /// `sessions`. Only `time` and `agent` apply.
    Sessions,
}

/// One bound parameter, in placeholder order.
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    /// Text, including glob patterns and FTS phrases.
    Text(String),
    /// Integer. Times are absolute nanoseconds by the time they are bound.
    Int(i64),
}

/// `compile`'s output.
#[derive(Debug, Clone, PartialEq)]
pub struct Compiled {
    /// `SELECT` statement, or just the predicate when [`Target`] is used
    /// through [`compile_predicate`].
    pub sql: String,
    /// Bound values. Same order as `?` in `sql`.
    pub params: Vec<Param>,
    /// Table the statement reads.
    pub target: Target,
    /// Field/kind mismatches. The SQL still runs; mismatched fields are `0`.
    pub warnings: Vec<String>,
}

/// Clock and index flags the compiler cannot know on its own.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompileCtx {
    /// Session start, for `time:+…`. `None` rejects a `+` relative time
    /// instead of using zero.
    pub session_start_ns: Option<i64>,
    /// Wall clock, for `time:-…`. `None` rejects a `-` relative time.
    pub now_ns: Option<i64>,
    /// `true` when `fts_text` exists and `storage.fts` is on.
    ///
    /// `~` then uses `fts_text MATCH ?`. Otherwise it uses `instr`.
    pub fts: bool,
    /// `true` on a Windows session: `path` and `dir` compare case-insensitively.
    pub case_insensitive_paths: bool,
}

/// Compile `expr` to a `SELECT` plus its predicate.
///
/// `kind:` with one value picks the table. Several kinds, or no kind, use
/// [`Target::Timeline`] and keep `kind` as a `cat` predicate. The statement
/// does not add `LIMIT` or a cursor; callers append those.
pub fn compile(expr: &Expr, ctx: &CompileCtx) -> Result<Compiled, QueryError> {
    let target = target_of(expr);
    let mut params = Vec::new();
    let mut warnings = Vec::new();
    let pred = compile_expr(expr, target, ctx, &mut params, &mut warnings, true)?;
    let sql = format!("{} WHERE ({pred})", select_head(target));
    Ok(Compiled {
        sql,
        params,
        target,
        warnings,
    })
}

/// The boolean predicate alone, for a caller that already has a `SELECT`.
///
/// `target` is the caller's table, not the one `kind:` would pick. A `kind:`
/// term is still compiled (against `cat` on the timeline, or as `0` plus a
/// warning on a concrete table that is a different kind).
pub fn compile_predicate(
    expr: &Expr,
    target: Target,
    ctx: &CompileCtx,
) -> Result<Compiled, QueryError> {
    let mut params = Vec::new();
    let mut warnings = Vec::new();
    let sql = compile_expr(expr, target, ctx, &mut params, &mut warnings, false)?;
    Ok(Compiled {
        sql,
        params,
        target,
        warnings,
    })
}

/// Keyset page: rows strictly after `(ts, id)`, ordered by that pair, plus one.
///
/// Appended SQL uses `?` only. `limit` is the caller's page size; this function
/// does not clamp it.
pub fn keyset_suffix(ts_column: &str, id_column: &str) -> String {
    format!(
        " AND ({ts_column} > ? OR ({ts_column} = ? AND {id_column} > ?)) \
         ORDER BY {ts_column}, {id_column} LIMIT ?"
    )
}

fn target_of(expr: &Expr) -> Target {
    match sole_kind(expr) {
        Some("file") => Target::Files,
        Some("net") => Target::Flows,
        Some("dns") => Target::Dns,
        Some("http") => Target::Http,
        Some("proc") => Target::Procs,
        _ => Target::Timeline,
    }
}

/// A single positive `kind:` value, if the expression is exactly that kind
/// (possibly AND-ed with other terms). An OR of two kinds is not a single table.
fn sole_kind(expr: &Expr) -> Option<&str> {
    let mut found: Option<&str> = None;
    if !walk_kind(expr, &mut found) {
        return None;
    }
    found
}

/// `false` when a kind term is negated or OR-ed, so the caller must not pin a table.
fn walk_kind<'a>(expr: &'a Expr, found: &mut Option<&'a str>) -> bool {
    match expr {
        Expr::True => true,
        Expr::And(left, right) => walk_kind(left, found) && walk_kind(right, found),
        Expr::Or(_, _) | Expr::Not(_) => !contains_kind(expr),
        Expr::Term(term) => {
            if term.field != Field::Kind {
                return true;
            }
            if term.values.len() != 1 {
                return false;
            }
            let text = match &term.values[0] {
                Value::Text(s) => s.as_str(),
                _ => return false,
            };
            match found {
                None => {
                    *found = Some(text);
                    true
                }
                Some(prev) if *prev == text => true,
                Some(_) => false,
            }
        }
    }
}

fn contains_kind(expr: &Expr) -> bool {
    match expr {
        Expr::True => false,
        Expr::Term(term) => term.field == Field::Kind,
        Expr::And(a, b) | Expr::Or(a, b) => contains_kind(a) || contains_kind(b),
        Expr::Not(inner) => contains_kind(inner),
    }
}

fn select_head(target: Target) -> &'static str {
    match target {
        Target::Timeline => {
            "SELECT timeline.session_id, timeline.ts_ns, timeline.cat, timeline.id, \
             timeline.proc_uid, timeline.evidence FROM timeline"
        }
        Target::Files => {
            "SELECT file_access.id, file_access.session_id, file_access.proc_uid, \
             file_access.op, file_access.path, file_access.first_ns, file_access.evidence \
             FROM file_access"
        }
        Target::Flows => {
            "SELECT net_flows.id, net_flows.session_id, net_flows.proc_uid, \
             net_flows.domain, net_flows.start_ns, net_flows.evidence FROM net_flows"
        }
        Target::Dns => {
            "SELECT dns.id, dns.session_id, dns.proc_uid, dns.qname, dns.ts_ns, dns.evidence \
             FROM dns"
        }
        Target::Http => {
            "SELECT http.id, http.session_id, http.proc_uid, http.url, http.ts_ns, http.evidence \
             FROM http"
        }
        Target::Procs => {
            "SELECT processes.proc_uid, processes.session_id, processes.pid, \
             processes.start_ns, processes.evidence FROM processes"
        }
        Target::Sessions => {
            "SELECT sessions.id, sessions.public_id, sessions.started_ns FROM sessions"
        }
    }
}

fn compile_expr(
    expr: &Expr,
    target: Target,
    ctx: &CompileCtx,
    params: &mut Vec<Param>,
    warnings: &mut Vec<String>,
    drop_pinned_kind: bool,
) -> Result<String, QueryError> {
    match expr {
        Expr::True => Ok("1".to_string()),
        Expr::Not(inner) => {
            let sql = compile_expr(inner, target, ctx, params, warnings, false)?;
            Ok(format!("NOT ({sql})"))
        }
        Expr::And(left, right) => {
            let a = compile_expr(left, target, ctx, params, warnings, drop_pinned_kind)?;
            let b = compile_expr(right, target, ctx, params, warnings, drop_pinned_kind)?;
            Ok(format!("({a}) AND ({b})"))
        }
        Expr::Or(left, right) => {
            let a = compile_expr(left, target, ctx, params, warnings, false)?;
            let b = compile_expr(right, target, ctx, params, warnings, false)?;
            Ok(format!("({a}) OR ({b})"))
        }
        Expr::Term(term) => {
            if drop_pinned_kind && term.field == Field::Kind && pins_this_target(term, target) {
                // The table choice already applied this kind. Emitting `cat = ?`
                // would be wrong on file_access, which has no `cat`.
                return Ok("1".to_string());
            }
            compile_term(term, target, ctx, params, warnings)
        }
    }
}

fn pins_this_target(term: &Term, target: Target) -> bool {
    let Some(Value::Text(text)) = term.values.first() else {
        return false;
    };
    if term.values.len() != 1 {
        return false;
    }
    matches!(
        (target, text.as_str()),
        (Target::Files, "file")
            | (Target::Flows, "net")
            | (Target::Dns, "dns")
            | (Target::Http, "http")
            | (Target::Procs, "proc")
    )
}

fn compile_term(
    term: &Term,
    target: Target,
    ctx: &CompileCtx,
    params: &mut Vec<Param>,
    warnings: &mut Vec<String>,
) -> Result<String, QueryError> {
    if matches!(term.field, Field::Other(_)) {
        return Err(QueryError::UnknownField {
            field: term.field.name().to_string(),
        });
    }
    if term.values.is_empty() {
        return Err(QueryError::BadField {
            field: term.field.name().to_string(),
            message: "missing value",
        });
    }
    if term.field == Field::Subtree {
        return subtree_sql(term, target, params);
    }
    if term.field == Field::Bare {
        return bare_sql(term, target, ctx, params);
    }
    let Some(column) = column_for(&term.field, target) else {
        warnings.push(format!(
            "{} does not apply to {}",
            term.field.name(),
            target_name(target)
        ));
        return Ok("0".to_string());
    };
    match column {
        Col::Text(sql) => string_term(sql, term, ctx, params),
        Col::Int(sql) => int_term(sql, term, ctx, params),
        Col::Bool(sql) => bool_term(sql, term, params),
        Col::Path { sql, dir } => path_term(sql, term, ctx, params, dir),
    }
}

enum Col {
    Text(&'static str),
    Int(&'static str),
    Bool(&'static str),
    Path { sql: &'static str, dir: bool },
}

fn column_for(field: &Field, target: Target) -> Option<Col> {
    use Col::{Bool, Int, Path, Text};
    let file = matches!(target, Target::Files | Target::Timeline);
    let net = matches!(target, Target::Flows | Target::Timeline);
    let dns = matches!(target, Target::Dns | Target::Timeline);
    let http = matches!(target, Target::Http | Target::Timeline);
    let proc = matches!(target, Target::Procs | Target::Timeline);
    Some(match (field, target) {
        (Field::Kind, Target::Timeline) => Text("cat"),
        (Field::Time, Target::Timeline) => Int("ts_ns"),
        (Field::Time, Target::Files) => Int("first_ns"),
        (Field::Time, Target::Flows) => Int("start_ns"),
        (Field::Time, Target::Dns | Target::Http) => Int("ts_ns"),
        (Field::Time, Target::Procs) => Int("start_ns"),
        (Field::Time, Target::Sessions) => Int("started_ns"),
        (Field::Evidence, Target::Sessions) => return None,
        (Field::Evidence, _) => Text("evidence"),
        (Field::Source, Target::Sessions) => return None,
        (Field::Source, _) => Text("source"),
        (Field::Proc, _) if proc || net || file || dns || http => Text(proc_basename(target)),
        (Field::Pid, _) if proc || net || file || dns || http => Int(pid_column(target)),
        (Field::ProcUid, Target::Timeline) => Int("proc_uid"),
        (Field::ProcUid, Target::Files | Target::Flows | Target::Dns | Target::Http) => {
            Int("proc_uid")
        }
        (Field::ProcUid, Target::Procs) => Int("proc_uid"),
        (Field::Tag, Target::Files) => Text("sensitive_rule"),
        (Field::Tag, Target::Timeline) => Text(tag_column()),
        (Field::Exe, _) if proc => Text(exe_column(target)),
        (Field::Argv, _) if proc => Text(argv_column(target)),
        (Field::Cwd, _) if proc => Text(cwd_column(target)),
        (Field::Path, _) if file => Path {
            sql: path_column(target),
            dir: false,
        },
        (Field::Dir, _) if file => Path {
            sql: path_column(target),
            dir: true,
        },
        (Field::FileOp, Target::Files) => Text("op"),
        (Field::FileOp, Target::Timeline) => Text(file_scalar("op")),
        (Field::Access, _) if file => Text(file_text("access", target)),
        (Field::BytesRead, _) if file => Int(file_int("bytes_read", target)),
        (Field::BytesWritten, _) if file => Int(file_int("bytes_written", target)),
        (Field::Domain, Target::Flows) => Text("domain"),
        (Field::Domain, Target::Dns) => Text("qname"),
        (Field::Domain, Target::Timeline) => Text(domain_case()),
        (Field::Ip | Field::RemoteIp, _) if net => Text(flow_text("remote_ip", target)),
        (Field::Port | Field::RemotePort, _) if net => Int(flow_int("remote_port", target)),
        (Field::LocalPort, _) if net => Int(flow_int("local_port", target)),
        (Field::Proto, _) if net => Text(flow_text("proto", target)),
        (Field::BytesUp, _) if net => Int(flow_int("bytes_up", target)),
        (Field::BytesDown, _) if net => Int(flow_int("bytes_down", target)),
        (Field::Direct, _) if net => Bool(flow_int("direct", target)),
        (Field::ViaProxy, _) if net => Bool(flow_int("via_proxy", target)),
        (Field::Qname, _) if dns => Text(dns_text("qname", target)),
        (Field::Qtype, _) if dns => Int(dns_int("qtype", target)),
        (Field::Rcode, _) if dns => Int(dns_int("rcode", target)),
        (Field::Method, _) if http => Text(http_text("method", target)),
        (Field::Url, _) if http => Text(http_text("url", target)),
        (Field::Host, _) if http => Text(http_text("host", target)),
        (Field::Status, _) if http => Int(http_int("status", target)),
        (Field::ReqBytes, _) if http => Int(http_int("req_body_bytes", target)),
        (Field::RespBytes, _) if http => Int(http_int("resp_body_bytes", target)),
        (Field::Agent, Target::Sessions) => Text("agent"),
        _ => return None,
    })
}

fn target_name(target: Target) -> &'static str {
    match target {
        Target::Timeline => "timeline",
        Target::Files => "file",
        Target::Flows => "net",
        Target::Dns => "dns",
        Target::Http => "http",
        Target::Procs => "proc",
        Target::Sessions => "sessions",
    }
}

fn proc_basename(target: Target) -> &'static str {
    match target {
        Target::Procs => {
            "(SELECT CASE WHEN exe IS NULL THEN NULL \
             ELSE replace(exe, rtrim(exe, replace(replace(exe, char(92), char(47)), char(47), '')), '') END \
             FROM process_images WHERE process_images.session_id = processes.session_id \
               AND process_images.proc_uid = processes.proc_uid \
             ORDER BY process_images.ts_ns DESC LIMIT 1)"
        }
        Target::Files => image_basename("file_access.session_id", "file_access.proc_uid", "file_access.first_ns"),
        Target::Flows => image_basename("net_flows.session_id", "net_flows.proc_uid", "net_flows.start_ns"),
        Target::Dns => image_basename("dns.session_id", "dns.proc_uid", "dns.ts_ns"),
        Target::Http => image_basename("http.session_id", "http.proc_uid", "http.ts_ns"),
        Target::Timeline => image_basename("timeline.session_id", "timeline.proc_uid", "timeline.ts_ns"),
        Target::Sessions => "NULL",
    }
}

fn image_basename(session: &str, proc: &str, ts: &str) -> &'static str {
    // The SQL is one of a fixed set. Matching on the three identifiers keeps
    // the result `'static` without formatting user input into it.
    match (session, proc, ts) {
        ("file_access.session_id", "file_access.proc_uid", "file_access.first_ns") => {
            "(SELECT CASE WHEN exe IS NULL THEN NULL \
             ELSE replace(exe, rtrim(exe, replace(replace(exe, char(92), char(47)), char(47), '')), '') END \
             FROM process_images WHERE process_images.session_id = file_access.session_id \
               AND process_images.proc_uid = file_access.proc_uid \
               AND process_images.ts_ns <= file_access.first_ns \
             ORDER BY process_images.ts_ns DESC LIMIT 1)"
        }
        ("net_flows.session_id", "net_flows.proc_uid", "net_flows.start_ns") => {
            "(SELECT CASE WHEN exe IS NULL THEN NULL \
             ELSE replace(exe, rtrim(exe, replace(replace(exe, char(92), char(47)), char(47), '')), '') END \
             FROM process_images WHERE process_images.session_id = net_flows.session_id \
               AND process_images.proc_uid = net_flows.proc_uid \
               AND process_images.ts_ns <= net_flows.start_ns \
             ORDER BY process_images.ts_ns DESC LIMIT 1)"
        }
        ("dns.session_id", "dns.proc_uid", "dns.ts_ns") => {
            "(SELECT CASE WHEN exe IS NULL THEN NULL \
             ELSE replace(exe, rtrim(exe, replace(replace(exe, char(92), char(47)), char(47), '')), '') END \
             FROM process_images WHERE process_images.session_id = dns.session_id \
               AND process_images.proc_uid = dns.proc_uid \
               AND process_images.ts_ns <= dns.ts_ns \
             ORDER BY process_images.ts_ns DESC LIMIT 1)"
        }
        ("http.session_id", "http.proc_uid", "http.ts_ns") => {
            "(SELECT CASE WHEN exe IS NULL THEN NULL \
             ELSE replace(exe, rtrim(exe, replace(replace(exe, char(92), char(47)), char(47), '')), '') END \
             FROM process_images WHERE process_images.session_id = http.session_id \
               AND process_images.proc_uid = http.proc_uid \
               AND process_images.ts_ns <= http.ts_ns \
             ORDER BY process_images.ts_ns DESC LIMIT 1)"
        }
        _ => {
            "(SELECT CASE WHEN exe IS NULL THEN NULL \
             ELSE replace(exe, rtrim(exe, replace(replace(exe, char(92), char(47)), char(47), '')), '') END \
             FROM process_images WHERE process_images.session_id = timeline.session_id \
               AND process_images.proc_uid = timeline.proc_uid \
               AND process_images.ts_ns <= timeline.ts_ns \
             ORDER BY process_images.ts_ns DESC LIMIT 1)"
        }
    }
}

fn pid_column(target: Target) -> &'static str {
    match target {
        Target::Procs => "pid",
        Target::Files => {
            "(SELECT pid FROM processes WHERE processes.session_id = file_access.session_id \
             AND processes.proc_uid = file_access.proc_uid)"
        }
        Target::Flows => {
            "(SELECT pid FROM processes WHERE processes.session_id = net_flows.session_id \
             AND processes.proc_uid = net_flows.proc_uid)"
        }
        Target::Dns => {
            "(SELECT pid FROM processes WHERE processes.session_id = dns.session_id \
             AND processes.proc_uid = dns.proc_uid)"
        }
        Target::Http => {
            "(SELECT pid FROM processes WHERE processes.session_id = http.session_id \
             AND processes.proc_uid = http.proc_uid)"
        }
        Target::Timeline => {
            "(SELECT pid FROM processes WHERE processes.session_id = timeline.session_id \
             AND processes.proc_uid = timeline.proc_uid)"
        }
        Target::Sessions => "NULL",
    }
}

fn tag_column() -> &'static str {
    "CASE cat WHEN 'file' THEN (SELECT sensitive_rule FROM file_access WHERE file_access.id = timeline.id) \
     ELSE NULL END"
}

fn exe_column(target: Target) -> &'static str {
    match target {
        Target::Procs => {
            "(SELECT exe FROM process_images WHERE process_images.session_id = processes.session_id \
             AND process_images.proc_uid = processes.proc_uid ORDER BY ts_ns DESC LIMIT 1)"
        }
        _ => {
            "(SELECT exe FROM process_images WHERE process_images.session_id = timeline.session_id \
             AND process_images.proc_uid = timeline.proc_uid AND process_images.ts_ns <= timeline.ts_ns \
             ORDER BY ts_ns DESC LIMIT 1)"
        }
    }
}

fn argv_column(target: Target) -> &'static str {
    match target {
        Target::Procs => {
            "(SELECT argv FROM process_images WHERE process_images.session_id = processes.session_id \
             AND process_images.proc_uid = processes.proc_uid ORDER BY ts_ns DESC LIMIT 1)"
        }
        _ => {
            "(SELECT argv FROM process_images WHERE process_images.session_id = timeline.session_id \
             AND process_images.proc_uid = timeline.proc_uid AND process_images.ts_ns <= timeline.ts_ns \
             ORDER BY ts_ns DESC LIMIT 1)"
        }
    }
}

fn cwd_column(target: Target) -> &'static str {
    match target {
        Target::Procs => {
            "(SELECT cwd FROM process_images WHERE process_images.session_id = processes.session_id \
             AND process_images.proc_uid = processes.proc_uid ORDER BY ts_ns DESC LIMIT 1)"
        }
        _ => {
            "(SELECT cwd FROM process_images WHERE process_images.session_id = timeline.session_id \
             AND process_images.proc_uid = timeline.proc_uid AND process_images.ts_ns <= timeline.ts_ns \
             ORDER BY ts_ns DESC LIMIT 1)"
        }
    }
}

fn path_column(target: Target) -> &'static str {
    match target {
        Target::Files => "path",
        _ => "(SELECT path FROM file_access WHERE file_access.id = timeline.id AND cat = 'file')",
    }
}

fn file_scalar(col: &str) -> &'static str {
    match col {
        "op" => "CASE cat WHEN 'file' THEN (SELECT op FROM file_access WHERE file_access.id = timeline.id) ELSE NULL END",
        _ => "NULL",
    }
}

fn file_text(col: &str, target: Target) -> &'static str {
    match (col, target) {
        ("access", Target::Files) => "access",
        ("access", _) => {
            "CASE cat WHEN 'file' THEN (SELECT access FROM file_access WHERE file_access.id = timeline.id) ELSE NULL END"
        }
        _ => "NULL",
    }
}

fn file_int(col: &str, target: Target) -> &'static str {
    match (col, target) {
        ("bytes_read", Target::Files) => "bytes_read",
        ("bytes_written", Target::Files) => "bytes_written",
        ("bytes_read", _) => {
            "CASE cat WHEN 'file' THEN (SELECT bytes_read FROM file_access WHERE file_access.id = timeline.id) ELSE NULL END"
        }
        ("bytes_written", _) => {
            "CASE cat WHEN 'file' THEN (SELECT bytes_written FROM file_access WHERE file_access.id = timeline.id) ELSE NULL END"
        }
        _ => "NULL",
    }
}

fn domain_case() -> &'static str {
    "CASE cat \
     WHEN 'net' THEN (SELECT domain FROM net_flows WHERE net_flows.id = timeline.id) \
     WHEN 'dns' THEN (SELECT qname FROM dns WHERE dns.id = timeline.id) \
     ELSE NULL END"
}

fn flow_text(col: &str, target: Target) -> &'static str {
    match (col, target) {
        ("remote_ip", Target::Flows) => "remote_ip",
        ("proto", Target::Flows) => "proto",
        ("domain", Target::Flows) => "domain",
        ("remote_ip", _) => {
            "CASE cat WHEN 'net' THEN (SELECT remote_ip FROM net_flows WHERE net_flows.id = timeline.id) ELSE NULL END"
        }
        ("proto", _) => {
            "CASE cat WHEN 'net' THEN (SELECT proto FROM net_flows WHERE net_flows.id = timeline.id) ELSE NULL END"
        }
        _ => "NULL",
    }
}

fn flow_int(col: &str, target: Target) -> &'static str {
    match (col, target) {
        ("remote_port", Target::Flows) => "remote_port",
        ("local_port", Target::Flows) => "local_port",
        ("bytes_up", Target::Flows) => "bytes_up",
        ("bytes_down", Target::Flows) => "bytes_down",
        ("direct", Target::Flows) => "direct",
        ("via_proxy", Target::Flows) => "via_proxy",
        ("remote_port", _) => {
            "CASE cat WHEN 'net' THEN (SELECT remote_port FROM net_flows WHERE net_flows.id = timeline.id) ELSE NULL END"
        }
        ("local_port", _) => {
            "CASE cat WHEN 'net' THEN (SELECT local_port FROM net_flows WHERE net_flows.id = timeline.id) ELSE NULL END"
        }
        ("bytes_up", _) => {
            "CASE cat WHEN 'net' THEN (SELECT bytes_up FROM net_flows WHERE net_flows.id = timeline.id) ELSE NULL END"
        }
        ("bytes_down", _) => {
            "CASE cat WHEN 'net' THEN (SELECT bytes_down FROM net_flows WHERE net_flows.id = timeline.id) ELSE NULL END"
        }
        ("direct", _) => {
            "CASE cat WHEN 'net' THEN (SELECT direct FROM net_flows WHERE net_flows.id = timeline.id) ELSE NULL END"
        }
        ("via_proxy", _) => {
            "CASE cat WHEN 'net' THEN (SELECT via_proxy FROM net_flows WHERE net_flows.id = timeline.id) ELSE NULL END"
        }
        _ => "NULL",
    }
}

fn dns_text(col: &str, target: Target) -> &'static str {
    match (col, target) {
        ("qname", Target::Dns) => "qname",
        ("qname", _) => {
            "CASE cat WHEN 'dns' THEN (SELECT qname FROM dns WHERE dns.id = timeline.id) ELSE NULL END"
        }
        _ => "NULL",
    }
}

fn dns_int(col: &str, target: Target) -> &'static str {
    match (col, target) {
        ("qtype", Target::Dns) => "qtype",
        ("rcode", Target::Dns) => "rcode",
        ("qtype", _) => {
            "CASE cat WHEN 'dns' THEN (SELECT qtype FROM dns WHERE dns.id = timeline.id) ELSE NULL END"
        }
        ("rcode", _) => {
            "CASE cat WHEN 'dns' THEN (SELECT rcode FROM dns WHERE dns.id = timeline.id) ELSE NULL END"
        }
        _ => "NULL",
    }
}

fn http_text(col: &str, target: Target) -> &'static str {
    match (col, target) {
        ("method", Target::Http) => "method",
        ("url", Target::Http) => "url",
        ("host", Target::Http) => "host",
        ("method", _) => {
            "CASE cat WHEN 'http' THEN (SELECT method FROM http WHERE http.id = timeline.id) ELSE NULL END"
        }
        ("url", _) => {
            "CASE cat WHEN 'http' THEN (SELECT url FROM http WHERE http.id = timeline.id) ELSE NULL END"
        }
        ("host", _) => {
            "CASE cat WHEN 'http' THEN (SELECT host FROM http WHERE http.id = timeline.id) ELSE NULL END"
        }
        _ => "NULL",
    }
}

fn http_int(col: &str, target: Target) -> &'static str {
    match (col, target) {
        ("status", Target::Http) => "status",
        ("req_body_bytes", Target::Http) => "req_body_bytes",
        ("resp_body_bytes", Target::Http) => "resp_body_bytes",
        ("status", _) => {
            "CASE cat WHEN 'http' THEN (SELECT status FROM http WHERE http.id = timeline.id) ELSE NULL END"
        }
        ("req_body_bytes", _) => {
            "CASE cat WHEN 'http' THEN (SELECT req_body_bytes FROM http WHERE http.id = timeline.id) ELSE NULL END"
        }
        ("resp_body_bytes", _) => {
            "CASE cat WHEN 'http' THEN (SELECT resp_body_bytes FROM http WHERE http.id = timeline.id) ELSE NULL END"
        }
        _ => "NULL",
    }
}

fn subtree_sql(term: &Term, target: Target, params: &mut Vec<Param>) -> Result<String, QueryError> {
    if term.values.len() != 1 {
        return Err(QueryError::BadOperator {
            field: "subtree",
            op: ":",
        });
    }
    let uid = expect_int(&term.values[0], "subtree")?;
    params.push(Param::Int(uid));
    params.push(Param::Int(uid));
    let (session_col, proc_col) = match target {
        Target::Files => ("file_access.session_id", "file_access.proc_uid"),
        Target::Flows => ("net_flows.session_id", "net_flows.proc_uid"),
        Target::Dns => ("dns.session_id", "dns.proc_uid"),
        Target::Http => ("http.session_id", "http.proc_uid"),
        Target::Procs => ("processes.session_id", "processes.proc_uid"),
        Target::Timeline => ("timeline.session_id", "timeline.proc_uid"),
        Target::Sessions => {
            return Err(QueryError::BadOperator {
                field: "subtree",
                op: "on sessions",
            });
        }
    };
    // The root id is bound twice: once as the seed, once so a row whose
    // proc_uid equals the root matches even when `processes` has no parent
    // chain yet. Descendants come from the recursive CTE. User input is only
    // the bound integer.
    Ok(format!(
        "({proc_col} = ? OR {proc_col} IN (
            WITH RECURSIVE subtree(proc_uid) AS (
                SELECT proc_uid FROM processes
                WHERE session_id = {session_col} AND proc_uid = ?
                UNION
                SELECT p.proc_uid FROM processes p
                JOIN subtree s ON p.parent_uid = s.proc_uid
                WHERE p.session_id = {session_col}
            )
            SELECT proc_uid FROM subtree))"
    ))
}

fn bare_sql(
    term: &Term,
    target: Target,
    ctx: &CompileCtx,
    params: &mut Vec<Param>,
) -> Result<String, QueryError> {
    if term.values.len() != 1 {
        return Err(QueryError::BadOperator {
            field: "bare",
            op: "~",
        });
    }
    let text = expect_text(&term.values[0], "bare")?;
    // A bare word is a substring over path, argv, url, and domain (§4.2).
    let mut parts = Vec::new();
    if let Some(Col::Path { sql, .. }) = column_for(&Field::Path, target) {
        parts.push(contains_sql(sql, &text, ctx, params, FtsSourceHint::File)?);
    }
    if let Some(Col::Text(sql)) = column_for(&Field::Domain, target) {
        parts.push(contains_sql(sql, &text, ctx, params, FtsSourceHint::None)?);
    }
    if let Some(Col::Text(sql)) = column_for(&Field::Argv, target) {
        parts.push(contains_sql(sql, &text, ctx, params, FtsSourceHint::Image)?);
    }
    if let Some(Col::Text(sql)) = column_for(&Field::Url, target) {
        parts.push(contains_sql(sql, &text, ctx, params, FtsSourceHint::Http)?);
    }
    if parts.is_empty() {
        return Ok("0".to_string());
    }
    Ok(format!("({})", parts.join(" OR ")))
}

#[derive(Clone, Copy)]
enum FtsSourceHint {
    File,
    Image,
    Http,
    None,
}

fn string_term(
    column: &str,
    term: &Term,
    ctx: &CompileCtx,
    params: &mut Vec<Param>,
) -> Result<String, QueryError> {
    match term.op {
        Op::Contains => {
            if term.values.len() != 1 {
                return Err(QueryError::BadOperator {
                    field: "value",
                    op: "~",
                });
            }
            let text = expect_text(&term.values[0], term.field.name())?;
            contains_sql(column, &text, ctx, params, FtsSourceHint::None)
        }
        Op::Match | Op::Eq | Op::In => any_of_text(column, term, params, false),
        Op::Ne => {
            let inner = any_of_text(column, term, params, false)?;
            Ok(format!("NOT ({inner})"))
        }
        Op::Gt | Op::Ge | Op::Lt | Op::Le => Err(QueryError::BadOperator {
            field: "value",
            op: op_text(term.op),
        }),
    }
}

fn path_term(
    column: &str,
    term: &Term,
    ctx: &CompileCtx,
    params: &mut Vec<Param>,
    dir: bool,
) -> Result<String, QueryError> {
    match term.op {
        Op::Contains => {
            if term.values.len() != 1 {
                return Err(QueryError::BadOperator {
                    field: "path",
                    op: "~",
                });
            }
            let text = expect_text(&term.values[0], term.field.name())?;
            contains_sql(column, &text, ctx, params, FtsSourceHint::File)
        }
        Op::Match | Op::Eq | Op::In => any_of_text(column, term, params, dir),
        Op::Ne => {
            let inner = any_of_text(column, term, params, dir)?;
            Ok(format!("NOT ({inner})"))
        }
        Op::Gt | Op::Ge | Op::Lt | Op::Le => Err(QueryError::BadOperator {
            field: "value",
            op: op_text(term.op),
        }),
    }
}

fn contains_sql(
    column: &str,
    text: &str,
    ctx: &CompileCtx,
    params: &mut Vec<Param>,
    hint: FtsSourceHint,
) -> Result<String, QueryError> {
    if ctx.fts {
        if let Some(src) = hint_src(hint) {
            // Correlated: the outer row's id must be the FTS src_id. The phrase
            // is a bound parameter (quotes inside the text are doubled by
            // `match_query`, which is FTS syntax, not SQL).
            params.push(Param::Text(fts::match_query(text)));
            let id_col = match hint {
                FtsSourceHint::File => "file_access.id",
                FtsSourceHint::Image => "process_images.id",
                FtsSourceHint::Http => "http.id",
                FtsSourceHint::None => "file_access.id",
            };
            // On the timeline the id column is not `file_access.id`. Fall back
            // to instr there: a correlated FTS lookup against the wrong id
            // would silently miss. The concrete-table form is the indexed path.
            if column_is_bare_path(column) || matches!(hint, FtsSourceHint::Image | FtsSourceHint::Http)
            {
                return Ok(format!(
                    "EXISTS (SELECT 1 FROM fts_text WHERE fts_text.src = '{src}' \
                     AND fts_text.src_id = {id_col} AND fts_text MATCH ?)"
                ));
            }
            params.pop();
        }
    }
    params.push(Param::Text(text.to_lowercase()));
    Ok(format!("(instr(lower({column}), ?) > 0 AND {column} IS NOT NULL)"))
}

fn column_is_bare_path(column: &str) -> bool {
    column == "path"
}

fn hint_src(hint: FtsSourceHint) -> Option<&'static str> {
    match hint {
        FtsSourceHint::File => Some("file_access"),
        FtsSourceHint::Image => Some("process_images"),
        FtsSourceHint::Http => Some("http"),
        FtsSourceHint::None => None,
    }
}

fn any_of_text(
    column: &str,
    term: &Term,
    params: &mut Vec<Param>,
    force_dir: bool,
) -> Result<String, QueryError> {
    let fold = matches!(term.field, Field::Path | Field::Dir);
    let mut parts = Vec::with_capacity(term.values.len());
    for value in &term.values {
        let mut text = expect_text(value, term.field.name())?;
        if force_dir && !text.ends_with("/**") && !text.ends_with("/*") {
            // `dir:X` is `path:X/**` (§4.3). A trailing slash is not doubled.
            if text.ends_with('/') || text.ends_with('\\') {
                text.push_str("**");
            } else {
                text.push_str("/**");
            }
        }
        if term.op == Op::Eq || !is_glob(&text) {
            let cmp = if fold {
                params.push(Param::Text(text.to_lowercase()));
                format!("lower({column}) = ?")
            } else {
                params.push(Param::Text(text));
                format!("{column} = ?")
            };
            parts.push(cmp);
        } else if let Some(prefix) = glob_prefix(&text) {
            // Prefix range so an index on the column can seek, plus GLOB for
            // the rest of the pattern. Both bounds are parameters.
            //
            // `*` in the middle still needs GLOB: the range only excludes
            // rows that cannot match. It does not replace the pattern.
            let (low, high) = prefix_bounds(&prefix);
            params.push(Param::Text(low));
            params.push(Param::Text(high));
            params.push(Param::Text(glob_pattern(&text)));
            let col = if fold {
                format!("lower({column})")
            } else {
                column.to_string()
            };
            parts.push(format!(
                "({col} >= ? AND {col} < ? AND {col} GLOB ?)"
            ));
        } else {
            params.push(Param::Text(glob_pattern(&text)));
            let col = if fold {
                format!("lower({column})")
            } else {
                column.to_string()
            };
            parts.push(format!("{col} GLOB ?"));
        }
    }
    Ok(format!("({})", parts.join(" OR ")))
}

fn int_term(
    column: &str,
    term: &Term,
    ctx: &CompileCtx,
    params: &mut Vec<Param>,
) -> Result<String, QueryError> {
    if matches!(term.op, Op::Contains) {
        return Err(QueryError::BadOperator {
            field: "value",
            op: "~",
        });
    }
    let sql_op = match term.op {
        Op::Match | Op::Eq | Op::In => "=",
        Op::Ne => "!=",
        Op::Gt => ">",
        Op::Ge => ">=",
        Op::Lt => "<",
        Op::Le => "<=",
        Op::Contains => "~",
    };
    if matches!(term.op, Op::Gt | Op::Ge | Op::Lt | Op::Le) && term.values.len() != 1 {
        return Err(QueryError::BadOperator {
            field: "value",
            op: sql_op,
        });
    }
    let mut parts = Vec::with_capacity(term.values.len());
    for value in &term.values {
        let n = resolve_number(value, term, ctx)?;
        params.push(Param::Int(n));
        parts.push(format!("{column} {sql_op} ?"));
    }
    Ok(format!("({})", parts.join(" OR ")))
}

fn bool_term(column: &str, term: &Term, params: &mut Vec<Param>) -> Result<String, QueryError> {
    if !matches!(term.op, Op::Match | Op::Eq | Op::Ne) {
        return Err(QueryError::BadOperator {
            field: "value",
            op: op_text(term.op),
        });
    }
    if term.values.len() != 1 {
        return Err(QueryError::BadOperator {
            field: "value",
            op: ":",
        });
    }
    let flag = match &term.values[0] {
        Value::Bool(b) => {
            if *b {
                1
            } else {
                0
            }
        }
        Value::Number(n) => {
            if *n == 0 {
                0
            } else {
                1
            }
        }
        Value::Text(s) if s == "true" => 1,
        Value::Text(s) if s == "false" => 0,
        _ => {
            return Err(QueryError::BadField {
                field: term.field.name().to_string(),
                message: "expected true or false",
            });
        }
    };
    let op = if term.op == Op::Ne { "!=" } else { "=" };
    params.push(Param::Int(flag));
    Ok(format!("{column} {op} ?"))
}

fn resolve_number(value: &Value, term: &Term, ctx: &CompileCtx) -> Result<i64, QueryError> {
    match value {
        Value::Number(n) => Ok(*n),
        Value::RelativeTime {
            from_session_start,
            nanos,
        } => {
            if term.field != Field::Time {
                return Err(QueryError::BadField {
                    field: term.field.name().to_string(),
                    message: "relative time is only valid for time",
                });
            }
            let base = if *from_session_start {
                ctx.session_start_ns.ok_or(QueryError::BadValue {
                    field: "time",
                    message: "session start is unknown",
                })?
            } else {
                ctx.now_ns.ok_or(QueryError::BadValue {
                    field: "time",
                    message: "current time is unknown",
                })?
            };
            let abs = if *from_session_start {
                base.checked_add(*nanos)
            } else {
                base.checked_sub(*nanos)
            };
            abs.ok_or(QueryError::BadValue {
                field: "time",
                message: "time is out of range",
            })
        }
        Value::Text(s) => s.parse::<i64>().map_err(|_| QueryError::BadField {
            field: term.field.name().to_string(),
            message: "expected an integer",
        }),
        Value::Bool(_) => Err(QueryError::BadField {
            field: term.field.name().to_string(),
            message: "expected an integer",
        }),
    }
}

fn expect_text(value: &Value, field: &str) -> Result<String, QueryError> {
    match value {
        Value::Text(s) => Ok(s.clone()),
        Value::Number(_) | Value::RelativeTime { .. } | Value::Bool(_) => Err(QueryError::BadField {
            field: field.to_string(),
            message: "expected text",
        }),
    }
}

fn expect_int(value: &Value, field: &'static str) -> Result<i64, QueryError> {
    match value {
        Value::Number(n) => Ok(*n),
        Value::Text(s) => s.parse::<i64>().map_err(|_| QueryError::BadValue {
            field,
            message: "expected an integer",
        }),
        Value::RelativeTime { .. } | Value::Bool(_) => Err(QueryError::BadValue {
            field,
            message: "expected an integer",
        }),
    }
}

fn op_text(op: Op) -> &'static str {
    match op {
        Op::Match => ":",
        Op::Eq => "=",
        Op::Ne => "!=",
        Op::Gt => ">",
        Op::Ge => ">=",
        Op::Lt => "<",
        Op::Le => "<=",
        Op::Contains => "~",
        Op::In => "in",
    }
}

fn is_glob(text: &str) -> bool {
    text.contains('*') || text.contains('?')
}

/// Literal prefix before the first wildcard. Empty when the pattern starts
/// with `*` or `?`, in which case a range seek cannot help.
fn glob_prefix(text: &str) -> Option<String> {
    let mut out = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' | '?' | '[' => break,
            other => out.push(other),
        }
        i += 1;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Inclusive lower bound and exclusive upper bound for `column >= ? AND column < ?`.
///
/// The upper bound is the prefix with its last byte incremented, so it covers
/// every string that starts with the prefix and nothing past that run. A prefix
/// of all `0xFF` bytes has no upper bound the type can express; the caller
/// then gets a `GLOB` without a range (see [`glob_prefix`] — that case still
/// returns `Some`, and this function uses a bound that only the `GLOB` filters).
fn prefix_bounds(prefix: &str) -> (String, String) {
    let low = prefix.to_string();
    let mut bytes = prefix.as_bytes().to_vec();
    let mut carry = true;
    for byte in bytes.iter_mut().rev() {
        if *byte == 0xFF {
            *byte = 0;
        } else {
            *byte += 1;
            carry = false;
            break;
        }
    }
    if carry {
        // Prefix is all 0xFF. No exclusive upper bound fits in a string that
        // sorts after every extension. Use the prefix itself as the lower
        // bound and a value that sorts first as a dummy; the GLOB still applies.
        // Binding the same prefix twice would exclude longer matches (`>= p AND < p`).
        return (low, "\u{10FFFF}".to_string());
    }
    let high = String::from_utf8_lossy(&bytes).into_owned();
    (low, high)
}

/// SQLite `GLOB` pattern. `**` is `*` (crosses separators). A single `*` is
/// left as `*`: SQLite `GLOB` cannot express "does not cross `/`", so the
/// range predicate is what keeps the seek honest and the pattern is the
/// documented approximation. The task forbids a new index to close that gap.
fn glob_pattern(glob: &str) -> String {
    let mut out = String::new();
    let chars: Vec<char> = glob.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '*' && chars.get(i + 1) == Some(&'*') {
            out.push('*');
            i += 2;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// `around`: rows in `[center - window, center + window]` on one session.
///
/// `ref_table` is a fixed set (`file_access`, `net_flows`, `dns`, `processes`,
/// `gaps`). Anything else is [`QueryError::BadArgument`]. Placeholders, in
/// order: `session_id`, reference id, window nanoseconds, window nanoseconds,
/// `limit`. The reference instant is one scalar subquery, so the id is bound
/// once. This does not use `OFFSET`.
///
/// `processes` has no surrogate `id`. The reference column there is `proc_uid`.
pub fn around_sql(ref_table: &str) -> Result<String, QueryError> {
    let (ts, id_col) = match ref_table {
        "file_access" => ("first_ns", "id"),
        "net_flows" => ("start_ns", "id"),
        "dns" | "http" | "process_images" => ("ts_ns", "id"),
        "processes" => ("start_ns", "proc_uid"),
        "gaps" => ("from_ns", "id"),
        _ => {
            return Err(QueryError::BadArgument {
                name: "ref",
                expected: "file_access|net_flows|dns|http|processes|gaps|process_images",
            });
        }
    };
    Ok(format!(
        "SELECT timeline.session_id, timeline.ts_ns, timeline.cat, timeline.id, \
         timeline.proc_uid, timeline.evidence \
         FROM timeline, \
           (SELECT {ts} AS center_ns FROM {ref_table} \
            WHERE {id_col} = ? AND session_id = ?) AS ref \
         WHERE timeline.session_id = ? \
           AND timeline.ts_ns BETWEEN ref.center_ns - ? AND ref.center_ns + ? \
         ORDER BY timeline.ts_ns, timeline.id \
         LIMIT ?"
    ))
}

/// Cross-session substring search over `fts_text` when FTS is on.
///
/// The phrase is one bound parameter. `user_id` is bound by the caller as the
/// first parameter; this SQL adds the phrase as the second. Sessions the user
/// does not own are excluded by the join, not by filtering after the fact.
pub fn search_sql() -> &'static str {
    "SELECT fts_text.src, fts_text.src_id, sessions.id, sessions.public_id \
     FROM fts_text \
     JOIN file_access ON fts_text.src = 'file_access' AND file_access.id = fts_text.src_id \
     JOIN sessions ON sessions.id = file_access.session_id \
     WHERE sessions.user_id = ? AND fts_text MATCH ? \
     UNION ALL \
     SELECT fts_text.src, fts_text.src_id, sessions.id, sessions.public_id \
     FROM fts_text \
     JOIN process_images ON fts_text.src = 'process_images' AND process_images.id = fts_text.src_id \
     JOIN sessions ON sessions.id = process_images.session_id \
     WHERE sessions.user_id = ? AND fts_text MATCH ? \
     LIMIT ?"
}

/// Same search without FTS: `instr` on `file_access.path` and `process_images.argv`.
///
/// Three bound parameters before the limit: `user_id`, needle, `user_id`, needle.
pub fn search_sql_instr() -> &'static str {
    "SELECT 'file_access', file_access.id, sessions.id, sessions.public_id \
     FROM file_access \
     JOIN sessions ON sessions.id = file_access.session_id \
     WHERE sessions.user_id = ? AND instr(lower(file_access.path), ?) > 0 \
     UNION ALL \
     SELECT 'process_images', process_images.id, sessions.id, sessions.public_id \
     FROM process_images \
     JOIN sessions ON sessions.id = process_images.session_id \
     WHERE sessions.user_id = ? AND process_images.argv IS NOT NULL \
       AND instr(lower(process_images.argv), ?) > 0 \
     LIMIT ?"
}
