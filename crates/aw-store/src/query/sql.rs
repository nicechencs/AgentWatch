//! Translate a filter AST into a parameterized predicate.
//!
//! Every user string is a bound parameter. Nothing from the filter is formatted
//! into the SQL text. The SQL text only contains fixed column names and `?`.

use crate::query::error::QueryError;
use crate::query::filter::{Expr, Field, Op, Term, Value};

/// Which row shape the predicate is compiled against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `timeline` view: `cat`, `ts_ns`, `id`, `proc_uid`, `evidence`.
    Timeline,
    /// `net_flows` joined to `processes` for `proc` / `pid`.
    Flows,
    /// `sessions` list. Only `time` applies, against `started_ns`.
    Sessions,
}

/// One bound parameter.
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    /// Text bound as-is. Globs are converted to LIKE patterns before binding.
    Text(String),
    /// Integer.
    Int(i64),
}

/// A SQL fragment and its parameters, in placeholder order.
#[derive(Debug, Clone, PartialEq)]
pub struct Predicate {
    /// Boolean SQL, or `1` when the filter is empty.
    pub sql: String,
    /// Bound values. Same length as the `?` placeholders in `sql`.
    pub params: Vec<Param>,
}

/// Compile `expr` for `target`.
///
/// `session_start_ns` resolves `time:+…`. `now_ns` resolves `time:-…`.
/// Both stay `None` when the caller has not supplied a clock; a relative
/// time then returns [`QueryError::BadValue`] instead of inventing zero.
pub fn compile(
    expr: &Expr,
    target: Target,
    session_start_ns: Option<i64>,
    now_ns: Option<i64>,
) -> Result<Predicate, QueryError> {
    let mut params = Vec::new();
    let sql = compile_expr(expr, target, session_start_ns, now_ns, &mut params)?;
    Ok(Predicate { sql, params })
}

fn compile_expr(
    expr: &Expr,
    target: Target,
    session_start_ns: Option<i64>,
    now_ns: Option<i64>,
    params: &mut Vec<Param>,
) -> Result<String, QueryError> {
    match expr {
        Expr::True => Ok("1".to_string()),
        Expr::Not(inner) => {
            let sql = compile_expr(inner, target, session_start_ns, now_ns, params)?;
            Ok(format!("NOT ({sql})"))
        }
        Expr::And(left, right) => {
            let a = compile_expr(left, target, session_start_ns, now_ns, params)?;
            let b = compile_expr(right, target, session_start_ns, now_ns, params)?;
            Ok(format!("({a}) AND ({b})"))
        }
        Expr::Or(left, right) => {
            let a = compile_expr(left, target, session_start_ns, now_ns, params)?;
            let b = compile_expr(right, target, session_start_ns, now_ns, params)?;
            Ok(format!("({a}) OR ({b})"))
        }
        Expr::Term(term) => compile_term(term, target, session_start_ns, now_ns, params),
    }
}

fn compile_term(
    term: &Term,
    target: Target,
    session_start_ns: Option<i64>,
    now_ns: Option<i64>,
    params: &mut Vec<Param>,
) -> Result<String, QueryError> {
    if term.values.is_empty() {
        return Err(QueryError::BadValue {
            field: field_name(term.field),
            message: "missing value",
        });
    }
    if target == Target::Sessions && term.field != Field::Time {
        return Err(QueryError::BadOperator {
            field: field_name(term.field),
            op: "on sessions",
        });
    }
    match term.field {
        Field::Kind => string_term("cat", term, params),
        Field::Evidence => string_term(evidence_sql(target)?, term, params),
        Field::Proc => string_term(proc_sql(target)?, term, params),
        Field::Domain => string_term(domain_sql(target)?, term, params),
        Field::Ip => string_term(ip_sql(target)?, term, params),
        Field::Pid => int_term(pid_sql(target)?, term, params),
        Field::Port => int_term(port_sql(target)?, term, params),
        Field::Time => time_term(term, target, session_start_ns, now_ns, params),
    }
}

fn field_name(field: Field) -> &'static str {
    match field {
        Field::Kind => "kind",
        Field::Proc => "proc",
        Field::Pid => "pid",
        Field::Domain => "domain",
        Field::Ip => "ip",
        Field::Port => "port",
        Field::Evidence => "evidence",
        Field::Time => "time",
    }
}

fn evidence_sql(target: Target) -> Result<&'static str, QueryError> {
    match target {
        Target::Timeline => Ok("evidence"),
        Target::Flows => Ok("net_flows.evidence"),
        Target::Sessions => Err(QueryError::BadOperator {
            field: "evidence",
            op: "on sessions",
        }),
    }
}

fn proc_sql(target: Target) -> Result<&'static str, QueryError> {
    match target {
        // Latest image at or before the row. An unknown exe does not match.
        Target::Timeline => Ok(
            "(SELECT CASE \
                WHEN exe IS NULL THEN NULL \
                ELSE replace(exe, rtrim(exe, replace(replace(exe, char(92), char(47)), char(47), '')), '') \
             END \
             FROM process_images \
             WHERE process_images.session_id = timeline.session_id \
               AND process_images.proc_uid = timeline.proc_uid \
               AND process_images.ts_ns <= timeline.ts_ns \
             ORDER BY process_images.ts_ns DESC LIMIT 1)",
        ),
        Target::Flows => Ok(
            "(SELECT CASE \
                WHEN exe IS NULL THEN NULL \
                ELSE replace(exe, rtrim(exe, replace(replace(exe, char(92), char(47)), char(47), '')), '') \
             END \
             FROM process_images \
             WHERE process_images.session_id = net_flows.session_id \
               AND process_images.proc_uid = net_flows.proc_uid \
             ORDER BY process_images.ts_ns DESC LIMIT 1)",
        ),
        Target::Sessions => Err(QueryError::BadOperator {
            field: "proc",
            op: "on sessions",
        }),
    }
}

fn domain_sql(target: Target) -> Result<&'static str, QueryError> {
    match target {
        // dns rows have no domain column; qname is the name. net rows use domain.
        // A proc or gap row has neither, so the predicate is NULL and does not match.
        Target::Timeline => Ok(
            "CASE cat WHEN 'net' THEN (SELECT domain FROM net_flows WHERE net_flows.id = timeline.id) \
             WHEN 'dns' THEN (SELECT qname FROM dns WHERE dns.id = timeline.id) \
             ELSE NULL END",
        ),
        Target::Flows => Ok("net_flows.domain"),
        Target::Sessions => Err(QueryError::BadOperator {
            field: "domain",
            op: "on sessions",
        }),
    }
}

fn ip_sql(target: Target) -> Result<&'static str, QueryError> {
    match target {
        Target::Timeline => Ok(
            "CASE cat WHEN 'net' THEN (SELECT remote_ip FROM net_flows WHERE net_flows.id = timeline.id) \
             ELSE NULL END",
        ),
        Target::Flows => Ok("net_flows.remote_ip"),
        Target::Sessions => Err(QueryError::BadOperator {
            field: "ip",
            op: "on sessions",
        }),
    }
}

fn pid_sql(target: Target) -> Result<&'static str, QueryError> {
    match target {
        Target::Timeline => Ok("(SELECT pid FROM processes \
              WHERE processes.session_id = timeline.session_id \
                AND processes.proc_uid = timeline.proc_uid)"),
        Target::Flows => Ok("(SELECT pid FROM processes \
              WHERE processes.session_id = net_flows.session_id \
                AND processes.proc_uid = net_flows.proc_uid)"),
        Target::Sessions => Err(QueryError::BadOperator {
            field: "pid",
            op: "on sessions",
        }),
    }
}

fn port_sql(target: Target) -> Result<&'static str, QueryError> {
    match target {
        Target::Timeline => Ok(
            "CASE cat WHEN 'net' THEN (SELECT remote_port FROM net_flows WHERE net_flows.id = timeline.id) \
             ELSE NULL END",
        ),
        Target::Flows => Ok("net_flows.remote_port"),
        Target::Sessions => Err(QueryError::BadOperator {
            field: "port",
            op: "on sessions",
        }),
    }
}

fn time_column(target: Target) -> &'static str {
    match target {
        Target::Timeline => "ts_ns",
        Target::Flows => "net_flows.start_ns",
        Target::Sessions => "sessions.started_ns",
    }
}

fn string_term(column: &str, term: &Term, params: &mut Vec<Param>) -> Result<String, QueryError> {
    match term.op {
        Op::Contains => {
            if term.values.len() != 1 {
                return Err(QueryError::BadOperator {
                    field: field_name(term.field),
                    op: "~",
                });
            }
            let text = expect_text(&term.values[0], term.field)?;
            // Bound as a literal substring. `instr` does not treat `%` or `_`
            // as wildcards, so the text is not rewritten into a LIKE pattern.
            params.push(Param::Text(text.to_lowercase()));
            Ok(format!(
                "(instr(lower({column}), ?) > 0 AND {column} IS NOT NULL)"
            ))
        }
        Op::Match | Op::Eq => any_of(column, term, params),
        Op::Ne => {
            let inner = any_of(column, term, params)?;
            Ok(format!("NOT ({inner})"))
        }
        Op::Gt | Op::Ge | Op::Lt | Op::Le => Err(QueryError::BadOperator {
            field: field_name(term.field),
            op: op_text(term.op),
        }),
    }
}

fn any_of(column: &str, term: &Term, params: &mut Vec<Param>) -> Result<String, QueryError> {
    let mut parts = Vec::with_capacity(term.values.len());
    for value in &term.values {
        let text = expect_text(value, term.field)?;
        if term.op == Op::Eq || !is_glob(&text) {
            params.push(Param::Text(text));
            parts.push(format!("{column} = ?"));
        } else {
            // SQLite GLOB: `*` is any string, `?` is one character. The pattern
            // is a bound parameter, never interpolated. A single `*` crosses
            // `/` here; P1 `domain` and `proc` (a basename) do not contain `/`.
            params.push(Param::Text(glob_pattern(&text)));
            parts.push(format!("{column} GLOB ?"));
        }
    }
    Ok(format!("({})", parts.join(" OR ")))
}

fn int_term(column: &str, term: &Term, params: &mut Vec<Param>) -> Result<String, QueryError> {
    if matches!(term.op, Op::Contains) {
        return Err(QueryError::BadOperator {
            field: field_name(term.field),
            op: "~",
        });
    }
    let mut parts = Vec::with_capacity(term.values.len());
    let sql_op = match term.op {
        Op::Match | Op::Eq => "=",
        Op::Ne => "!=",
        Op::Gt => ">",
        Op::Ge => ">=",
        Op::Lt => "<",
        Op::Le => "<=",
        Op::Contains => "~",
    };
    if matches!(term.op, Op::Gt | Op::Ge | Op::Lt | Op::Le) && term.values.len() != 1 {
        return Err(QueryError::BadOperator {
            field: field_name(term.field),
            op: sql_op,
        });
    }
    for value in &term.values {
        let n = expect_int(value, term.field)?;
        params.push(Param::Int(n));
        parts.push(format!("{column} {sql_op} ?"));
    }
    Ok(format!("({})", parts.join(" OR ")))
}

fn time_term(
    term: &Term,
    target: Target,
    session_start_ns: Option<i64>,
    now_ns: Option<i64>,
    params: &mut Vec<Param>,
) -> Result<String, QueryError> {
    let column = time_column(target);
    let mut resolved = Vec::with_capacity(term.values.len());
    for value in &term.values {
        resolved.push(resolve_time(value, session_start_ns, now_ns)?);
    }
    let rewritten = Term {
        field: Field::Time,
        op: term.op,
        values: resolved,
    };
    int_term(column, &rewritten, params)
}

fn resolve_time(
    value: &Value,
    session_start_ns: Option<i64>,
    now_ns: Option<i64>,
) -> Result<Value, QueryError> {
    match value {
        Value::Number(_) => Ok(value.clone()),
        Value::RelativeTime {
            from_session_start,
            nanos,
        } => {
            let base = if *from_session_start {
                session_start_ns.ok_or(QueryError::BadValue {
                    field: "time",
                    message: "session start is unknown",
                })?
            } else {
                now_ns.ok_or(QueryError::BadValue {
                    field: "time",
                    message: "current time is unknown",
                })?
            };
            let abs = if *from_session_start {
                base.checked_add(*nanos)
            } else {
                base.checked_sub(*nanos)
            };
            let abs = abs.ok_or(QueryError::BadValue {
                field: "time",
                message: "time is out of range",
            })?;
            Ok(Value::Number(abs))
        }
        Value::Text(_) | Value::Bool(_) => Err(QueryError::BadValue {
            field: "time",
            message: "expected a number or a relative time",
        }),
    }
}

fn expect_text(value: &Value, field: Field) -> Result<String, QueryError> {
    match value {
        Value::Text(s) => Ok(s.clone()),
        Value::Number(_) | Value::RelativeTime { .. } | Value::Bool(_) => {
            Err(QueryError::BadValue {
                field: field_name(field),
                message: "expected text",
            })
        }
    }
}

fn expect_int(value: &Value, field: Field) -> Result<i64, QueryError> {
    match value {
        Value::Number(n) => Ok(*n),
        Value::Text(s) => s.parse::<i64>().map_err(|_| QueryError::BadValue {
            field: field_name(field),
            message: "expected an integer",
        }),
        Value::RelativeTime { .. } | Value::Bool(_) => Err(QueryError::BadValue {
            field: field_name(field),
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
    }
}

fn is_glob(text: &str) -> bool {
    text.contains('*') || text.contains('?')
}

/// Bound operand for `column GLOB ?`. `**` collapses to `*`. SQLite GLOB
/// cannot escape a literal `*`, `?`, `[`, or `]`; those characters are the
/// wildcards in this grammar, not data the user can quote separately.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::query::filter::parse;

    #[test]
    fn injection_text_is_a_bound_parameter() {
        let expr = parse(r#"domain:"x' OR 1=1 --""#).unwrap();
        let pred = compile(&expr, Target::Flows, None, None).unwrap();
        assert!(
            !pred.sql.contains("OR 1=1"),
            "user text leaked into SQL: {}",
            pred.sql
        );
        assert!(pred.sql.contains('?'));
        assert_eq!(pred.params, vec![Param::Text("x' OR 1=1 --".to_string())]);
    }

    #[test]
    fn glob_domain_is_bound() {
        let expr = parse("domain:*.example.com").unwrap();
        let pred = compile(&expr, Target::Flows, None, None).unwrap();
        assert!(
            pred.sql.contains("GLOB ?") || pred.sql.contains("LIKE ?"),
            "{}",
            pred.sql
        );
        assert!(matches!(&pred.params[0], Param::Text(s) if s.contains("example.com")));
        assert!(!pred.sql.contains("example.com"));
    }

    #[test]
    fn relative_time_uses_session_start() {
        let expr = parse("time>+5m").unwrap();
        let pred = compile(&expr, Target::Timeline, Some(1_000), None).unwrap();
        assert_eq!(
            pred.params,
            vec![Param::Int(1_000 + 5 * 60 * 1_000_000_000)]
        );
    }
}
