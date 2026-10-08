//! The filter AST shared by the CLI, the API, the UI, and the rule engine.
//!
//! [`Expr::to_predicate`] evaluates a record in memory. Compiling to SQL is
//! P2-STORE-03 and lives in `aw-store`, not here.

use super::registry::{FieldInfo, FieldType};

/// A parsed filter. The empty query is [`Expr::True`].
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// No constraint.
    True,
    /// One comparison, or a bare word.
    Term(Term),
    /// Both sides. A space in the source is this node.
    And(Box<Expr>, Box<Expr>),
    /// Either side.
    Or(Box<Expr>, Box<Expr>),
    /// `not`, `!`, or a leading `-`.
    Not(Box<Expr>),
}

/// One comparison.
#[derive(Debug, Clone, PartialEq)]
pub struct Term {
    /// The field, or [`FieldRef::Bare`] for a word with no field.
    pub field: FieldRef,
    /// The operator.
    pub op: Op,
    /// One or more values. `:` and `in` with several values mean any-of.
    pub values: Vec<Value>,
    /// Byte offset of the field in the source.
    pub offset: usize,
}

/// A field reference carried on a [`Term`].
#[derive(Debug, Clone)]
pub enum FieldRef {
    /// A word with no field: substring over path, argv, url, and domain.
    Bare,
    /// A registered field.
    Named(&'static FieldInfo),
}

impl PartialEq for FieldRef {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bare, Self::Bare) => true,
            (Self::Named(a), Self::Named(b)) => a.name == b.name,
            _ => false,
        }
    }
}

impl Eq for FieldRef {}

impl FieldRef {
    /// Canonical name. Empty for [`FieldRef::Bare`].
    pub fn name(&self) -> &str {
        match self {
            Self::Bare => "",
            Self::Named(info) => info.name,
        }
    }
}

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `:` — glob on text, equality on numbers, any-of when multi-valued.
    Match,
    /// `=`.
    Eq,
    /// `!=`.
    Ne,
    /// `>`.
    Gt,
    /// `>=`.
    Ge,
    /// `<`.
    Lt,
    /// `<=`.
    Le,
    /// `~` — case-insensitive substring. Never a regular expression.
    Contains,
    /// `in` — any-of, with the same matching rules as [`Op::Match`].
    In,
}

/// A literal. Units and durations are already reduced to integers.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Quoted text or a glob, exactly as written.
    Text(String),
    /// An integer. `1MB` is `1_000_000`; `1MiB` is `1_048_576`.
    Number(i64),
    /// `+` counts from the session start, `-` counts back from now.
    RelativeTime {
        /// `true` for `+` (session start), `false` for `-` (now).
        from_session_start: bool,
        /// The duration in nanoseconds.
        nanos: i64,
    },
    /// `true` or `false`.
    Bool(bool),
}

/// What [`Expr::to_predicate`] reads from one record.
///
/// Callers project their own record type onto this. A missing field is `None`,
/// which never compares equal: an absent value is not zero and not an empty
/// string.
pub trait RecordView {
    /// Text of a field, already lowercased where the session is case-insensitive.
    fn text(&self, field: &str) -> Option<&str>;
    /// Integer value of a field, in its stored unit (bytes, nanoseconds, raw).
    fn number(&self, field: &str) -> Option<i64>;
    /// Boolean value of a field.
    fn bool_value(&self, field: &str) -> Option<bool>;
    /// Whether `proc_uid` is the named process or one of its descendants.
    fn in_subtree(&self, proc_uid: &str) -> bool;
}

/// The clock and platform a predicate is evaluated against.
#[derive(Debug, Clone, Copy)]
pub struct EvalCtx {
    /// Session start, nanoseconds. `+5m` is measured from here.
    pub session_start_ns: i64,
    /// Current time, nanoseconds. `-10m` is measured from here.
    pub now_ns: i64,
    /// `path` and `dir` compare case-insensitively on a Windows session.
    pub case_insensitive_paths: bool,
}

impl Expr {
    /// Fold this expression into an in-memory predicate.
    ///
    /// `~` is a substring test and never a regular expression. Globs follow
    /// §4.2: `*` stops at a separator, `**` crosses them.
    pub fn to_predicate<'a>(&'a self, ctx: EvalCtx) -> impl Fn(&dyn RecordView) -> bool + 'a {
        move |record| eval(self, record, &ctx)
    }
}

fn eval(expr: &Expr, record: &dyn RecordView, ctx: &EvalCtx) -> bool {
    match expr {
        Expr::True => true,
        Expr::And(left, right) => eval(left, record, ctx) && eval(right, record, ctx),
        Expr::Or(left, right) => eval(left, record, ctx) || eval(right, record, ctx),
        Expr::Not(inner) => !eval(inner, record, ctx),
        Expr::Term(term) => eval_term(term, record, ctx),
    }
}

fn eval_term(term: &Term, record: &dyn RecordView, ctx: &EvalCtx) -> bool {
    if matches!(term.field, FieldRef::Bare) {
        return bare_match(term, record);
    }
    let name = term.field.name();
    if name == "subtree" {
        return term
            .values
            .iter()
            .any(|v| text_of(v).is_some_and(|id| record.in_subtree(id)));
    }
    let ty = match &term.field {
        FieldRef::Named(info) => info.ty,
        FieldRef::Bare => return false,
    };
    let any_of = matches!(term.op, Op::Match | Op::In);
    let results = term.values.iter().map(|value| match ty {
        FieldType::Number | FieldType::Bytes | FieldType::Duration | FieldType::Time => {
            compare_number(name, term.op, value, record, ctx)
        }
        FieldType::Bool => compare_bool(name, term.op, value, record),
        FieldType::String | FieldType::Glob | FieldType::Enum => {
            compare_text(name, term.op, value, record, ctx)
        }
    });
    if any_of {
        results.into_iter().any(|hit| hit)
    } else {
        results.into_iter().all(|hit| hit)
    }
}

/// A bare word matches when any of path, argv, url, or domain contains it.
fn bare_match(term: &Term, record: &dyn RecordView) -> bool {
    let needle = term
        .values
        .first()
        .and_then(text_of)
        .unwrap_or_default()
        .to_lowercase();
    ["path", "argv", "url", "domain"]
        .iter()
        .any(|field| contains_ci(record.text(field).unwrap_or_default(), &needle))
}

fn compare_text(
    field: &str,
    op: Op,
    value: &Value,
    record: &dyn RecordView,
    ctx: &EvalCtx,
) -> bool {
    let Some(haystack) = record.text(field) else {
        return false;
    };
    let Some(needle) = text_of(value) else {
        return false;
    };
    let folded = case_fold(field, ctx.case_insensitive_paths);
    let (haystack, needle) = if folded {
        (haystack.to_lowercase(), needle.to_lowercase())
    } else {
        (haystack.to_owned(), needle.to_owned())
    };
    match op {
        Op::Match | Op::In => glob_match(&needle, &haystack),
        Op::Eq => haystack == needle,
        Op::Ne => haystack != needle,
        Op::Contains => haystack.contains(&needle),
        Op::Gt | Op::Ge | Op::Lt | Op::Le => false,
    }
}

fn compare_number(
    field: &str,
    op: Op,
    value: &Value,
    record: &dyn RecordView,
    ctx: &EvalCtx,
) -> bool {
    let Some(actual) = record.number(field) else {
        return false;
    };
    let Some(expected) = number_of(value, ctx) else {
        return false;
    };
    match op {
        Op::Match | Op::Eq | Op::In => actual == expected,
        Op::Ne => actual != expected,
        Op::Gt => actual > expected,
        Op::Ge => actual >= expected,
        Op::Lt => actual < expected,
        Op::Le => actual <= expected,
        Op::Contains => false,
    }
}

fn compare_bool(field: &str, op: Op, value: &Value, record: &dyn RecordView) -> bool {
    let (Some(actual), Value::Bool(expected)) = (record.bool_value(field), value) else {
        return false;
    };
    match op {
        Op::Match | Op::Eq | Op::In => actual == *expected,
        Op::Ne => actual != *expected,
        _ => false,
    }
}

fn text_of(value: &Value) -> Option<&str> {
    match value {
        Value::Text(text) => Some(text),
        _ => None,
    }
}

fn number_of(value: &Value, ctx: &EvalCtx) -> Option<i64> {
    match value {
        Value::Number(n) => Some(*n),
        Value::RelativeTime { from_session_start, nanos } => Some(if *from_session_start {
            ctx.session_start_ns.saturating_add(*nanos)
        } else {
            ctx.now_ns.saturating_sub(*nanos)
        }),
        _ => None,
    }
}

/// `path` and `dir` fold case only on a Windows session.
fn case_fold(field: &str, case_insensitive_paths: bool) -> bool {
    match field {
        "path" | "dir" => case_insensitive_paths,
        _ => true,
    }
}

fn contains_ci(haystack: &str, needle_lower: &str) -> bool {
    haystack.to_lowercase().contains(needle_lower)
}

/// Glob match. `*` stops at `/` or `\`; `**` crosses them; `?` is one
/// non-separator byte.
///
/// A leading `~/` is left as written: expanding the session user's home
/// directory happens before a value reaches the AST.
fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(pattern: &[u8], text: &[u8]) -> bool {
        if pattern.is_empty() {
            return text.is_empty();
        }
        if pattern[0] == b'*' {
            let crossing = pattern.len() > 1 && pattern[1] == b'*';
            let rest = if crossing { &pattern[2..] } else { &pattern[1..] };
            if rec(rest, text) {
                return true;
            }
            if let Some((first, tail)) = text.split_first() {
                if crossing || !is_sep(*first) {
                    return rec(pattern, tail);
                }
            }
            return false;
        }
        match text.split_first() {
            Some((first, tail)) if pattern[0] == *first => rec(&pattern[1..], tail),
            Some((first, tail)) if pattern[0] == b'?' && !is_sep(*first) => rec(&pattern[1..], tail),
            _ => false,
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}

fn is_sep(byte: u8) -> bool {
    byte == b'/' || byte == b'\\'
}
