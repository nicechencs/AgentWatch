//! Filter AST consumed by the P2 SQL compiler.
//!
//! This is the shape P2-CORE-01 describes (`crates/aw-core/src/filter/`,
//! `Expr`). That module did not exist when this file was written, and this
//! crate is not allowed to add it. [`Expr`] here is the store-side view of
//! that AST: same node kinds, no parser, no `to_predicate`.
//!
//! When `aw_core::filter::Expr` lands, map it onto this enum at the query
//! boundary (or replace this module with a re-export). Field names and the
//! `:` / `~` / comparison operators follow api-and-cli §4.2 and §4.3.
//!
//! Nothing in this module builds SQL. Values stay as data.

/// A parsed filter. The empty query is [`Expr::True`].
///
/// Binary nodes are boxed so a large expression does not bloat every variant.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// No constraint. Compiles to `1`.
    True,
    /// One `field op values` comparison, or a bare substring.
    Term(Term),
    /// Both sides. A space in the source grammar is this node.
    And(Box<Expr>, Box<Expr>),
    /// Either side.
    Or(Box<Expr>, Box<Expr>),
    /// Negation (`not`, `!`, or a leading `-` on a primary).
    Not(Box<Expr>),
}

/// One comparison. `values` is empty only for a programming error; the
/// compiler rejects it instead of matching every row.
#[derive(Debug, Clone, PartialEq)]
pub struct Term {
    /// Field, or [`Field::Bare`] for a word with no field.
    pub field: Field,
    /// Operator. [`Op::Match`] is `:`.
    pub op: Op,
    /// One or more values. `:` with several values means any-of.
    pub values: Vec<Value>,
    /// Byte offset of the field in the source, for error text.
    ///
    /// `0` when the caller did not track positions. The compiler does not
    /// invent a column number.
    pub offset: usize,
}

/// Comparison operator. Text matches §4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `:` — glob on strings, equality on numbers, any-of when multi-valued.
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
    /// `~` — case-insensitive substring. Not a regular expression.
    Contains,
    /// `in` — same matching rules as [`Op::Match`], always any-of.
    In,
}

/// A field from api-and-cli §4.3, plus [`Field::Bare`].
///
/// Dotted names (`remote.ip`, `remote.port`, `local.port`) are their own
/// variants. An unknown name is not a variant: the parser (P2-CORE-01) reports
/// it before an [`Expr`] is built. This compiler still returns
/// [`super::QueryError::UnknownField`] if a caller builds [`Field::Other`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    /// No field. Substring over path, argv, url, and domain.
    Bare,
    /// Timeline category.
    Kind,
    /// Record time.
    Time,
    /// Evidence label.
    Evidence,
    /// Collector source string.
    Source,
    /// Executable basename.
    Proc,
    /// OS pid.
    Pid,
    /// `ProcUid` bit-cast to `i64`.
    ProcUid,
    /// This process and its descendants.
    Subtree,
    /// Tag (`sensitive`, `sensitive.<rule>`, …).
    Tag,
    /// Full executable path.
    Exe,
    /// Redacted argv JSON.
    Argv,
    /// Working directory.
    Cwd,
    /// File path.
    Path,
    /// Directory prefix. `dir:X` is `path:X/**`.
    Dir,
    /// File op.
    FileOp,
    /// Open access mode.
    Access,
    /// Bytes read.
    BytesRead,
    /// Bytes written.
    BytesWritten,
    /// Flow or DNS name.
    Domain,
    /// Remote IP (`ip`).
    Ip,
    /// Remote port (`port`).
    Port,
    /// `remote.ip`.
    RemoteIp,
    /// `remote.port`.
    RemotePort,
    /// `local.port`.
    LocalPort,
    /// `tcp` / `udp`.
    Proto,
    /// Bytes sent.
    BytesUp,
    /// Bytes received.
    BytesDown,
    /// Proxy bypass.
    Direct,
    /// Flow went through the proxy.
    ViaProxy,
    /// DNS query name.
    Qname,
    /// DNS query type.
    Qtype,
    /// DNS response code.
    Rcode,
    /// HTTP method.
    Method,
    /// Redacted URL.
    Url,
    /// HTTP host.
    Host,
    /// HTTP status.
    Status,
    /// Request body length.
    ReqBytes,
    /// Response body length.
    RespBytes,
    /// Agent tool name.
    Tool,
    /// Agent profile id.
    Agent,
    /// IPC channel kind.
    IpcKind,
    /// IPC peer.
    Peer,
    /// IPC channel name.
    Channel,
    /// RPC target (tool name / resource).
    Target,
    /// Finding rule id.
    Rule,
    /// Finding severity.
    Severity,
    /// A name this compiler does not know. Reported, not ignored.
    Other(String),
}

/// A literal. Units and durations are already reduced to integers by the parser.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Quoted text or a glob token, as written (no SQL escaping applied).
    Text(String),
    /// Integer. Byte units are already multiplied (`1MB` = 1_000_000).
    Number(i64),
    /// `+` is relative to the session start; `-` is relative to now.
    RelativeTime {
        /// `true` means `+` (session start). `false` means `-` (now).
        from_session_start: bool,
        /// Duration in nanoseconds. Not a sentinel for "unknown".
        nanos: i64,
    },
    /// `true` or `false`.
    Bool(bool),
}

impl Expr {
    /// `field:value` with no recorded source offset.
    pub fn term(field: Field, op: Op, values: Vec<Value>) -> Self {
        Self::Term(Term {
            field,
            op,
            values,
            offset: 0,
        })
    }
}

impl Field {
    /// Stable name used in errors. Not a SQL identifier.
    pub fn name(&self) -> &str {
        match self {
            Self::Bare => "",
            Self::Kind => "kind",
            Self::Time => "time",
            Self::Evidence => "evidence",
            Self::Source => "source",
            Self::Proc => "proc",
            Self::Pid => "pid",
            Self::ProcUid => "proc_uid",
            Self::Subtree => "subtree",
            Self::Tag => "tag",
            Self::Exe => "exe",
            Self::Argv => "argv",
            Self::Cwd => "cwd",
            Self::Path => "path",
            Self::Dir => "dir",
            Self::FileOp => "op",
            Self::Access => "access",
            Self::BytesRead => "bytes_read",
            Self::BytesWritten => "bytes_written",
            Self::Domain => "domain",
            Self::Ip => "ip",
            Self::Port => "port",
            Self::RemoteIp => "remote.ip",
            Self::RemotePort => "remote.port",
            Self::LocalPort => "local.port",
            Self::Proto => "proto",
            Self::BytesUp => "bytes_up",
            Self::BytesDown => "bytes_down",
            Self::Direct => "direct",
            Self::ViaProxy => "via_proxy",
            Self::Qname => "qname",
            Self::Qtype => "qtype",
            Self::Rcode => "rcode",
            Self::Method => "method",
            Self::Url => "url",
            Self::Host => "host",
            Self::Status => "status",
            Self::ReqBytes => "req_bytes",
            Self::RespBytes => "resp_bytes",
            Self::Tool => "tool",
            Self::Agent => "agent",
            Self::IpcKind => "ipc_kind",
            Self::Peer => "peer",
            Self::Channel => "channel",
            Self::Target => "target",
            Self::Rule => "rule",
            Self::Severity => "severity",
            Self::Other(name) => name.as_str(),
        }
    }
}
