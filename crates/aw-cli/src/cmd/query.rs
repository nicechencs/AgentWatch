//! Injected read model for `sessions`, `timeline`, `procs`, `flows`, `gaps`,
//! `files`, `around`, and `search`.
//!
//! The daemon's HTTP API is still a stub (`aw-daemon` `api/routes.rs` answers
//! `/health` and does not serve these paths). These commands therefore do not
//! dial it. A [`QuerySource`] supplies the records. Production uses
//! [`UnavailableSource`], which reports that the daemon query API is not
//! connected. Tests use an in-memory source. `aw-cli` does not depend on
//! `aw-store`; the shapes here mirror the `file_access` columns in storage.md
//! and the `/files`, `/around`, and `/search` responses in api-and-cli §3
//! without importing the store.
//!
//! The request each command would send, once the daemon serves it:
//!
//! - `GET /api/v1/sessions/{sid}/files?filter&group_by&sort&cursor&limit`
//! - `GET /api/v1/sessions/{sid}/around?ref=<table>:<id>&window=<dur>`
//! - `GET /api/v1/search?q&kind&since&limit`
//!
//! [`files_request`], [`around_request`], and [`search_request`] build those
//! calls. Nothing in this module opens a socket.
//!
//! Unknown values stay [`Option::None`]. Renderers print `不可得`, never `0`
//! or an empty string.

use std::time::Duration;

use aw_core::Evidence;
#[cfg(test)]
use aw_core::NaReason;

/// Why a query did not return records.
///
/// `NotFound` and `BadArgument` are produced by the in-memory source, which is
/// test-only. The production source only returns `Unavailable`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum QueryError {
    /// The session id or name is not in this source.
    NotFound { session: String },
    /// `@last` for a caller who has no sessions.
    NoSessions,
    /// `--group-by` / `--sort` / a time bound the command refused.
    BadArgument { detail: String },
    /// No live query API is wired. The message says so; it is not a fake empty list.
    Unavailable { detail: String },
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound { session } => write!(f, "找不到会话 `{session}`"),
            Self::NoSessions => write!(f, "还没有你的会话，@last 无处可指"),
            Self::BadArgument { detail } => write!(f, "{detail}"),
            Self::Unavailable { detail } => write!(f, "{detail}"),
        }
    }
}

/// One session row for `sessions list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionItem {
    /// Public id. Not a hostname.
    pub public_id: String,
    /// User label, or unknown.
    pub name: Option<String>,
    /// `launch` or `attach`.
    pub mode: String,
    /// Agent profile, or unknown.
    pub agent: Option<String>,
    /// Start, Unix nanoseconds. `None` when the answer did not carry one (the
    /// in-memory stub row is `{ id, user_id, name }`); printed as 不可得, never `0`.
    pub started_ns: Option<i64>,
    /// End, or still running.
    pub ended_ns: Option<i64>,
    /// Excluded from retention. `None` when the reply did not carry `pinned`
    /// (the store summary omits it); printed as 没采, never as unpinned.
    pub pinned: Option<bool>,
    /// Record evidence. A session the user created is E1 (the tool observed it).
    pub evidence: Evidence,
}

/// Counts and the capability snapshot for `sessions show`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionShow {
    /// The list row.
    pub item: SessionItem,
    /// Process rows. A counted zero is `Some(0)`; unknown is `None`.
    pub process_count: Option<i64>,
    /// Flow rows.
    pub flow_count: Option<i64>,
    /// DNS rows.
    pub dns_count: Option<i64>,
    /// Gap rows.
    pub gap_count: Option<i64>,
    /// The watched process's exit code. `None` when the reply omitted it or
    /// sent null — not observed, never printed as `0`.
    pub exit_code: Option<i64>,
    /// Sum of `bytes_up`. `None` when every flow left the column unknown.
    pub bytes_up: Option<i64>,
    /// Sum of `bytes_down`.
    pub bytes_down: Option<i64>,
    /// One line per capability actually used in this session.
    pub capabilities: Vec<CapabilityFact>,
    /// Short gap lines. The full list is `gaps`.
    pub gap_summaries: Vec<String>,
}

/// Actual source and level for one capability class (capability-matrix row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CapabilityFact {
    /// Category, such as `CAP-PROC` or `CAP-NET`.
    pub category: String,
    /// Collector that produced the records, or unknown.
    pub source: Option<String>,
    /// Level those records carry.
    pub evidence: Evidence,
}

/// Constraints for [`QuerySource::list_sessions`].
///
/// Fields are read by the in-memory source. The production source ignores them
/// and returns [`QueryError::Unavailable`].
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub(crate) struct SessionQuery {
    /// Keep sessions whose `agent` equals this string.
    pub agent: Option<String>,
    /// Keep sessions that have not ended.
    pub active_only: bool,
    /// Inclusive lower bound on `started_ns`, when the caller could resolve `--since`.
    pub since_ns: Option<i64>,
    /// Page size. `None` means every matching session.
    pub limit: Option<u64>,
}

/// One timeline row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TimelineItem {
    /// Unix nanoseconds.
    pub ts_ns: i64,
    /// `proc`, `net`, `dns`, or `gap`.
    pub cat: String,
    /// Branch id.
    pub id: i64,
    /// Process, or unknown.
    pub proc_uid: Option<i64>,
    /// One-line summary already safe to print. No raw argv, URL, or header.
    pub summary: String,
    /// Record evidence.
    pub evidence: Evidence,
    /// `true` for a gap row. The renderer marks it even when color is off.
    pub is_gap: bool,
}

/// Page of timeline rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TimelinePage {
    /// Rows, oldest first.
    pub rows: Vec<TimelineItem>,
    /// Present when another row exists after this page.
    pub next: bool,
}

/// Bounds for one timeline page.
///
/// Fields are read by the in-memory source. The production source ignores them.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub(crate) struct TimelineBounds {
    /// Filter text. Applied by the source. `None` matches everything.
    pub filter: Option<String>,
    /// Inclusive lower bound on `ts_ns`.
    pub from_ns: Option<i64>,
    /// Inclusive upper bound on `ts_ns`.
    pub to_ns: Option<i64>,
    /// Page size. `None` uses the source default.
    pub limit: Option<u64>,
}

/// One process. Children are filled when the caller asked for a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcItem {
    /// `ProcUid` bit-cast.
    pub proc_uid: i64,
    /// OS pid.
    pub pid: i64,
    /// Parent, or unknown.
    pub parent_uid: Option<i64>,
    /// Image basename, or unknown.
    pub exe_name: Option<String>,
    /// Command line after the pipeline redaction placeholder.
    ///
    /// P1 redaction is a placeholder. The text stored here is already the
    /// placeholder (or `None` when argv was not observed). The renderer always
    /// labels the column as redacted, so a stored string is not treated as the
    /// original argv.
    pub argv_redacted: Option<String>,
    /// Exit code, or not observed.
    pub exit_code: Option<i64>,
    /// Record evidence.
    pub evidence: Evidence,
    /// Children, parent before child. Empty for a flat listing.
    pub children: Vec<ProcItem>,
}

/// One flow, or one group of flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlowItem {
    /// Flow id when ungrouped.
    pub id: Option<i64>,
    /// `proc_uid` when ungrouped or grouped by proc.
    pub proc_uid: Option<i64>,
    /// Local port, or unknown. Cleared when the group key is not the flow itself.
    pub local_port: Option<i64>,
    /// Remote port.
    pub remote_port: Option<i64>,
    /// Remote ip.
    pub remote_ip: Option<String>,
    /// Domain. `None` is unknown, never `""`.
    pub domain: Option<String>,
    /// How `domain` was chosen (`dns`, `sni`, …), or unknown.
    pub domain_source: Option<String>,
    /// Evidence of `domain` specifically. `None` when there is no domain.
    pub domain_evidence: Option<Evidence>,
    /// Bytes sent. `None` means not observed.
    pub bytes_up: Option<i64>,
    /// Bytes received.
    pub bytes_down: Option<i64>,
    /// Start, Unix nanoseconds. For a group, the earliest start.
    pub start_ns: i64,
    /// Record evidence. `None` for a group whose members differ.
    pub evidence: Option<Evidence>,
    /// Rows in the group. `1` when ungrouped.
    pub count: i64,
}

/// One gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GapItem {
    /// Row id.
    pub id: i64,
    /// Collector name.
    pub collector: String,
    /// Gap kind.
    pub kind: String,
    /// Affected categories, already joined for display.
    pub affects: String,
    /// Start, Unix nanoseconds.
    pub from_ns: i64,
    /// End, Unix nanoseconds.
    pub to_ns: i64,
    /// Lost-event count, or unknown.
    pub count: Option<i64>,
    /// Redacted detail, or unknown. Must not contain argv, URLs, or headers.
    pub detail: Option<String>,
    /// Gaps are system observations of a collector failure. Always E1 unless the
    /// source says otherwise.
    pub evidence: Evidence,
}

/// Read API the five commands share. Implementations must not log argv or tokens.
pub(crate) trait QuerySource {
    /// Sessions, newest start first.
    ///
    /// # Errors
    ///
    /// [`QueryError::Unavailable`] when nothing is connected.
    fn list_sessions(&self, query: &SessionQuery) -> Result<Vec<SessionItem>, QueryError>;

    /// One session by public id or name.
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`] when `key` matches neither.
    fn show_session(&self, key: &str) -> Result<SessionShow, QueryError>;

    /// Rename. Returns the new name.
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`].
    fn rename_session(&mut self, key: &str, name: &str) -> Result<SessionItem, QueryError>;

    /// Set or clear the pin.
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`].
    fn set_pinned(&mut self, key: &str, pinned: bool) -> Result<SessionItem, QueryError>;

    /// Delete. Returns how many were removed.
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`] naming the first missing key. Earlier keys in the
    /// same call are not removed (all-or-nothing).
    fn delete_sessions(&mut self, keys: &[String]) -> Result<u64, QueryError>;

    /// One timeline page.
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`].
    fn timeline(&self, key: &str, bounds: &TimelineBounds) -> Result<TimelinePage, QueryError>;

    /// Events that arrived after `after_ns` (exclusive). Used by `--follow`.
    ///
    /// The live `/sessions/{sid}/live` stream is not connected. A source that
    /// cannot subscribe returns [`QueryError::Unavailable`]. The memory source
    /// returns whatever it was given, so tests can check the rendered lines.
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`] or [`QueryError::Unavailable`].
    fn follow(&self, key: &str, after_ns: Option<i64>) -> Result<Vec<TimelineItem>, QueryError>;

    /// Processes. `tree` asks the source to fill [`ProcItem::children`].
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`].
    fn procs(&self, key: &str, tree: bool) -> Result<Vec<ProcItem>, QueryError>;

    /// Flows, already grouped and sorted by the source.
    ///
    /// `group_by` is `domain`, `ip`, `proc`, `port`, or `None`.
    /// `sort` is `up`, `down`, `total`, or `None` (time).
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`] or [`QueryError::BadArgument`].
    fn flows(
        &self,
        key: &str,
        group_by: Option<&str>,
        sort: Option<&str>,
    ) -> Result<Vec<FlowItem>, QueryError>;

    /// Gaps for one session.
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`].
    fn gaps(&self, key: &str) -> Result<Vec<GapItem>, QueryError>;

    /// File-access rows for one session (`GET /sessions/{sid}/files`).
    ///
    /// `group_by` is `path`, `dir`, `proc`, or `None`. `sort` is a column name
    /// the command already checked, or `None` (time).
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`] or [`QueryError::BadArgument`].
    fn files(&self, key: &str, query: &FileQuery) -> Result<Vec<FileItem>, QueryError>;

    /// Events around one record (`GET /sessions/{sid}/around`).
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`] when the session or the reference is missing.
    /// [`QueryError::BadArgument`] when `reference` is not `<table>:<id>`.
    fn around(&self, key: &str, query: &AroundQuery) -> Result<AroundPage, QueryError>;

    /// Cross-session search (`GET /search`).
    ///
    /// # Errors
    ///
    /// [`QueryError::BadArgument`] for an unknown `kind`.
    /// [`QueryError::Unavailable`] when nothing is connected.
    fn search(&self, query: &SearchQuery) -> Result<Vec<SearchHit>, QueryError>;

    /// HTTP rows for one session (`GET /sessions/{sid}/http`).
    ///
    /// `reason` is `Some("no_proxy")` when the session exists and the proxy was
    /// off. That is an empty list with a reason, not a missing session.
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`] when the session is missing.
    /// [`QueryError::Unavailable`] when nothing is connected. An unwired source
    /// must not return an empty page: that would claim the session had no HTTP.
    fn http(&self, key: &str, query: &HttpQuery) -> Result<HttpPage, QueryError>;

    /// Findings for one session (`GET /sessions/{sid}/findings`).
    ///
    /// `text` is the wording the source already rendered. `None` means rendering
    /// failed; the row still carries `wording_id` and `params`.
    ///
    /// # Errors
    ///
    /// [`QueryError::NotFound`] when the session is missing.
    /// [`QueryError::Unavailable`] when nothing is connected.
    fn findings(&self, key: &str, query: &FindingQuery) -> Result<Vec<FindingItem>, QueryError>;
}

/// One `file_access` row, or one group of them.
///
/// Byte columns are [`Option`]. `None` means the platform did not observe the
/// count (storage.md: NULL). It is not zero. A sensitive hit keeps the rule id
/// so the renderer can highlight the row; the path text is already redacted by
/// the pipeline and is printed as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileItem {
    /// Row id when ungrouped.
    pub id: Option<i64>,
    /// Process. Hex text when the API sent a string; the numeric form is the
    /// store's signed integer. `None` when the group key is not the process.
    pub proc_uid: Option<i64>,
    /// `proc: {pid, exe_name}` from the API. Both sides stay optional.
    pub proc_pid: Option<i64>,
    /// Image basename. Not a path.
    pub proc_exe: Option<String>,
    /// `access`, `create`, `delete`, `rename`, or `exec`.
    pub op: String,
    /// Already-redacted path.
    pub path: String,
    /// Rename target, or unknown.
    pub path_to: Option<String>,
    /// Parent directory used when grouping by `dir`. `None` when unknown.
    pub dir: Option<String>,
    /// `read` / `write` / `read_write` / `exec` / `unknown`, or unknown.
    pub access: Option<String>,
    /// First observation, Unix nanoseconds.
    pub first_ns: i64,
    /// Open count. A counted zero is `Some(0)`; unknown is `None`.
    pub opens: Option<i64>,
    /// Bytes read. `None` is not observed.
    pub bytes_read: Option<i64>,
    /// Bytes written. `None` is not observed.
    pub bytes_written: Option<i64>,
    /// Open failed (errno / NTSTATUS). `None` means success or unknown result
    /// was not reported; the renderer prints `不可得` only when the field is
    /// absent, and `0` only when the API sent a literal zero.
    pub result: Option<i64>,
    /// Sensitive-path rule id. `None` means no rule matched.
    pub sensitive_rule: Option<String>,
    /// Record evidence. `None` for a group whose members differ.
    pub evidence: Option<Evidence>,
    /// Why a field is NA, when the row itself is NA.
    pub na_reason: Option<String>,
    /// Rows in the group. `1` when ungrouped.
    pub count: i64,
}

/// Constraints for [`QuerySource::files`].
#[derive(Debug, Clone, Default)]
pub(crate) struct FileQuery {
    /// Filter expression, forwarded as `filter=`. Not compiled here.
    pub filter: Option<String>,
    /// `path`, `dir`, `proc`, or `None`.
    pub group_by: Option<String>,
    /// Sort field, or `None` for time order.
    pub sort: Option<String>,
}

/// One row in an `around` window. The shape is a timeline event plus the
/// table it came from, which is what `/around` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AroundItem {
    /// `<table>:<id>` of this neighbour, or of the anchor itself.
    pub reference: String,
    /// Unix nanoseconds.
    pub ts_ns: i64,
    /// Table name (`file_access`, `processes`, …).
    pub table: String,
    /// One-line summary already safe to print.
    pub summary: String,
    /// Record evidence.
    pub evidence: Evidence,
    /// `true` when this row is the record the user named.
    pub anchor: bool,
    /// `true` for a gap row.
    pub is_gap: bool,
    /// Sensitive-path rule id, when this neighbour is a file hit.
    pub sensitive_rule: Option<String>,
}

/// The anchor plus its neighbours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AroundPage {
    /// Rows ordered by time. The anchor is included.
    pub rows: Vec<AroundItem>,
}

/// Constraints for [`QuerySource::around`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AroundQuery {
    /// `<table>:<id>`, as in `file_access:123`.
    pub reference: String,
    /// Window half-width in nanoseconds. The API query is `window=<dur>`.
    pub window_ns: i64,
}

/// One cross-session hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SearchHit {
    /// Session public id.
    pub session: String,
    /// Session label, or unknown.
    pub session_name: Option<String>,
    /// `file`, `proc`, or `url`.
    pub kind: String,
    /// `<table>:<id>` so `aw around` can open it.
    pub reference: String,
    /// Unix nanoseconds. `None` when the hit carried no time; the renderer
    /// prints 不可得, never `0`.
    pub ts_ns: Option<i64>,
    /// One-line summary already safe to print. No raw argv or URL.
    pub summary: String,
    /// Record evidence.
    pub evidence: Evidence,
    /// Sensitive-path rule id, when the hit is a file rule match.
    pub sensitive_rule: Option<String>,
}

/// One HTTP row. The URL and header text are already redacted by the pipeline.
///
/// Byte and duration columns are [`Option`]. `None` means the proxy did not
/// observe them. It is not zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpItem {
    /// Row id.
    pub id: i64,
    /// Unix nanoseconds.
    pub ts_ns: i64,
    /// Process, when the request was attributed.
    pub proc_uid: Option<i64>,
    /// `proc.pid` from the API summary. Not invented here.
    pub proc_pid: Option<i64>,
    /// Image basename. Not a path.
    pub proc_exe: Option<String>,
    /// Method (`GET`, `POST`, …).
    pub method: String,
    /// Already-redacted URL. Never a raw query string from the process.
    pub url: String,
    /// Response status. `None` when the exchange did not complete.
    pub status: Option<i64>,
    /// Request body length. `None` is not observed.
    pub req_body_bytes: Option<i64>,
    /// Response body length. `None` is not observed.
    pub resp_body_bytes: Option<i64>,
    /// Round-trip time in milliseconds. `None` is not observed.
    pub duration_ms: Option<i64>,
    /// Record evidence. HTTP through the proxy is E2; unknown stays `None`.
    pub evidence: Option<Evidence>,
}

/// One page of HTTP rows, plus the reason an empty page is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HttpPage {
    /// Rows, oldest first.
    pub rows: Vec<HttpItem>,
    /// `no_proxy` when the session did not enable the proxy. `None` otherwise.
    ///
    /// An empty `rows` with `reason: None` means the proxy ran and recorded
    /// nothing. `Some("no_proxy")` means URLs were not available.
    pub reason: Option<String>,
}

/// Constraints for [`QuerySource::http`].
#[derive(Debug, Clone, Default)]
pub(crate) struct HttpQuery {
    /// Filter expression, forwarded as `filter=`. Not compiled here.
    pub filter: Option<String>,
}

/// One finding the CLI can print.
///
/// `text` is the rendered sentence. `None` means the wording catalog refused
/// it; the command prints that as unavailable and does not invent a sentence.
/// `refs` is only included in `--json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingItem {
    /// Row id.
    pub id: i64,
    /// Rule that fired.
    pub rule_id: String,
    /// `fact`, `fact_conjunction`, `inference`, or `content_match`.
    pub kind: String,
    /// Evidence string as stored (`E1`, `I`, `content_match`, …).
    pub evidence: String,
    /// `info`, `notice`, or `warn`.
    pub severity: String,
    /// Wording template id.
    pub wording_id: String,
    /// Template parameters, already safe to print.
    pub params: Vec<(String, String)>,
    /// Rendered sentence, or `None` when rendering failed.
    pub text: Option<String>,
    /// Why `text` is missing. Not a substitute sentence.
    pub error: Option<String>,
    /// How many times this key fired.
    pub count: i64,
    /// First observation, Unix nanoseconds.
    pub first_ns: i64,
    /// Last observation, Unix nanoseconds.
    pub last_ns: i64,
    /// Cited rows. Printed only with `--json`.
    pub refs: Vec<FindingRef>,
}

/// One cited row: a table name plus the id inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FindingRef {
    /// Table name (`file_access`, `net_flow`, `http`).
    pub table: String,
    /// Row id inside `table`.
    pub id: i64,
}

/// Constraints for [`QuerySource::findings`].
#[derive(Debug, Clone, Default)]
pub(crate) struct FindingQuery {
    /// `info`, `notice`, or `warn`. The source drops anything below this.
    pub min_severity: Option<String>,
    /// Evidence tokens, or `content_match` (matched on `kind`).
    pub evidence: Vec<String>,
    /// `zh` or `en`. The source renders `text` in this language.
    pub lang: Option<String>,
}

/// Constraints for [`QuerySource::search`].
#[derive(Debug, Clone, Default)]
pub(crate) struct SearchQuery {
    /// Free text or a filter expression. Sent as `q`.
    pub text: String,
    /// Inclusive lower bound, Unix nanoseconds, when `--since` resolved.
    ///
    /// The memory source reads this. Production never builds a source, so the
    /// field looks unused to the bin target.
    #[allow(dead_code)]
    pub since_ns: Option<i64>,
    /// `file`, `proc`, `url`, or `None` for every kind.
    pub kind: Option<String>,
}

/// `GET /api/v1/sessions/{sid}/files` with the documented query keys.
///
/// `sid` is percent-encoded. Filter text is encoded too, so a space stays a
/// space in the value and does not split the query.
#[must_use]
pub(crate) fn files_request(session: &str, query: &FileQuery) -> crate::client::ApiRequest {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    if let Some(filter) = query.filter.as_deref() {
        pairs.push(("filter", filter));
    }
    if let Some(group_by) = query.group_by.as_deref() {
        pairs.push(("group_by", group_by));
    }
    if let Some(sort) = query.sort.as_deref() {
        pairs.push(("sort", sort));
    }
    crate::client::ApiRequest::get_query(
        &format!("/api/v1/sessions/{}/files", encode_path_segment(session)),
        encode_query(&pairs),
    )
}

/// `GET /api/v1/sessions/{sid}/around?ref=<table>:<id>&window=<dur>`.
#[must_use]
pub(crate) fn around_request(
    session: &str,
    reference: &str,
    window: &str,
) -> crate::client::ApiRequest {
    crate::client::ApiRequest::get_query(
        &format!("/api/v1/sessions/{}/around", encode_path_segment(session)),
        encode_query(&[("ref", reference), ("window", window)]),
    )
}

/// `GET /api/v1/search?q&kind&since`.
#[must_use]
pub(crate) fn search_request(
    query: &SearchQuery,
    since: Option<&str>,
) -> crate::client::ApiRequest {
    let mut pairs: Vec<(&str, &str)> = vec![("q", query.text.as_str())];
    if let Some(kind) = query.kind.as_deref() {
        pairs.push(("kind", kind));
    }
    if let Some(since) = since {
        pairs.push(("since", since));
    }
    crate::client::ApiRequest::get_query("/api/v1/search", encode_query(&pairs))
}

/// `GET /api/v1/sessions/{sid}/http?filter=`.
///
/// The filter is forwarded, not compiled. A session with the proxy off is still
/// this same request: the response carries `reason: no_proxy`.
#[must_use]
pub(crate) fn http_request(session: &str, query: &HttpQuery) -> crate::client::ApiRequest {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    if let Some(filter) = query.filter.as_deref() {
        pairs.push(("filter", filter));
    }
    crate::client::ApiRequest::get_query(
        &format!("/api/v1/sessions/{}/http", encode_path_segment(session)),
        encode_query(&pairs),
    )
}

/// `GET /api/v1/sessions/{sid}/findings?lang&min_severity&evidence`.
#[must_use]
pub(crate) fn findings_request(session: &str, query: &FindingQuery) -> crate::client::ApiRequest {
    let evidence = query.evidence.join(",");
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    if let Some(lang) = query.lang.as_deref() {
        pairs.push(("lang", lang));
    }
    if let Some(min_severity) = query.min_severity.as_deref() {
        pairs.push(("min_severity", min_severity));
    }
    if !evidence.is_empty() {
        pairs.push(("evidence", &evidence));
    }
    crate::client::ApiRequest::get_query(
        &format!("/api/v1/sessions/{}/findings", encode_path_segment(session)),
        encode_query(&pairs),
    )
}

/// Percent-encode one path segment. `@` in `@last` is left as-is: it is
/// unreserved enough for this API and the daemon matches the literal.
pub(crate) fn encode_path_segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'@' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// `k=v&k=v` with both sides percent-encoded.
pub(crate) fn encode_query(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (index, (key, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        out.push_str(&encode_path_segment(key));
        out.push('=');
        // Space becomes %20, not '+'. Filter expressions contain spaces.
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char);
                }
                other => out.push_str(&format!("%{other:02X}")),
            }
        }
    }
    out
}

/// Production source. Every method says the daemon query API is not connected.
///
/// This is not an empty success: printing zero rows would claim the session had
/// no events.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct UnavailableSource;

const UNAVAILABLE: &str = "后台查询 API 未接通；/sessions 仍是占位实现，所以此命令没有可显示的记录";

impl QuerySource for UnavailableSource {
    fn list_sessions(&self, _: &SessionQuery) -> Result<Vec<SessionItem>, QueryError> {
        Err(QueryError::Unavailable {
            detail: UNAVAILABLE.to_owned(),
        })
    }

    fn show_session(&self, _: &str) -> Result<SessionShow, QueryError> {
        Err(QueryError::Unavailable {
            detail: UNAVAILABLE.to_owned(),
        })
    }

    fn rename_session(&mut self, _: &str, _: &str) -> Result<SessionItem, QueryError> {
        Err(QueryError::Unavailable {
            detail: UNAVAILABLE.to_owned(),
        })
    }

    fn set_pinned(&mut self, _: &str, _: bool) -> Result<SessionItem, QueryError> {
        Err(QueryError::Unavailable {
            detail: UNAVAILABLE.to_owned(),
        })
    }

    fn delete_sessions(&mut self, _: &[String]) -> Result<u64, QueryError> {
        Err(QueryError::Unavailable {
            detail: UNAVAILABLE.to_owned(),
        })
    }

    fn timeline(&self, _: &str, _: &TimelineBounds) -> Result<TimelinePage, QueryError> {
        Err(QueryError::Unavailable {
            detail: UNAVAILABLE.to_owned(),
        })
    }

    fn follow(&self, _: &str, _: Option<i64>) -> Result<Vec<TimelineItem>, QueryError> {
        Err(QueryError::Unavailable {
            detail: format!("{UNAVAILABLE}；没有订阅实时 /sessions/{{sid}}/live（真实订阅未接通）"),
        })
    }

    fn procs(&self, _: &str, _: bool) -> Result<Vec<ProcItem>, QueryError> {
        Err(QueryError::Unavailable {
            detail: UNAVAILABLE.to_owned(),
        })
    }

    fn flows(
        &self,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<Vec<FlowItem>, QueryError> {
        Err(QueryError::Unavailable {
            detail: UNAVAILABLE.to_owned(),
        })
    }

    fn gaps(&self, _: &str) -> Result<Vec<GapItem>, QueryError> {
        Err(QueryError::Unavailable {
            detail: UNAVAILABLE.to_owned(),
        })
    }

    fn files(&self, _: &str, _: &FileQuery) -> Result<Vec<FileItem>, QueryError> {
        Err(QueryError::Unavailable {
            detail: format!("{UNAVAILABLE}；尚未提供 GET /sessions/{{sid}}/files"),
        })
    }

    fn around(&self, _: &str, _: &AroundQuery) -> Result<AroundPage, QueryError> {
        Err(QueryError::Unavailable {
            detail: format!("{UNAVAILABLE}；尚未提供 GET /sessions/{{sid}}/around"),
        })
    }

    fn search(&self, _: &SearchQuery) -> Result<Vec<SearchHit>, QueryError> {
        Err(QueryError::Unavailable {
            detail: format!("{UNAVAILABLE}；尚未提供 GET /search"),
        })
    }

    fn http(&self, _: &str, _: &HttpQuery) -> Result<HttpPage, QueryError> {
        Err(QueryError::Unavailable {
            detail: format!(
                "{UNAVAILABLE}；尚未提供 GET /sessions/{{sid}}/http，所以此命令不会编造空列表"
            ),
        })
    }

    fn findings(&self, _: &str, _: &FindingQuery) -> Result<Vec<FindingItem>, QueryError> {
        Err(QueryError::Unavailable {
            detail: format!(
                "{UNAVAILABLE}；尚未提供 GET /sessions/{{sid}}/findings，所以此命令不会编造空列表"
            ),
        })
    }
}

/// In-memory sessions for tests. Mutations are visible to later calls on the
/// same value, which is what `rename` / `pin` / `delete` need.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct MemorySource {
    sessions: Vec<MemorySession>,
}

/// One stored session plus the records the five commands print.
#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct MemorySession {
    /// List / show identity.
    pub item: SessionItem,
    /// Capability rows for `show`.
    pub capabilities: Vec<CapabilityFact>,
    /// Timeline, oldest first. Also the follow buffer.
    pub timeline: Vec<TimelineItem>,
    /// Processes in tree form (children filled). A flat listing walks this.
    pub procs: Vec<ProcItem>,
    /// Ungrouped flows. Grouping happens in [`MemorySource::flows`].
    pub flows: Vec<FlowItem>,
    /// Gaps.
    pub gaps: Vec<GapItem>,
    /// File-access rows. Grouping happens in [`MemorySource::files`].
    pub files: Vec<FileItem>,
    /// Neighbours `around` can return. The anchor is whichever row's reference matches.
    pub around: Vec<AroundItem>,
    /// Hits this session contributes to `search`.
    pub search: Vec<SearchHit>,
    /// HTTP rows. `reason` is set when the session had no proxy.
    pub http: HttpPage,
    /// Findings, already rendered. Filtering happens in [`MemorySource::findings`].
    pub findings: Vec<FindingItem>,
}

#[cfg(test)]
impl MemorySource {
    /// Empty. `@last` is not found.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            sessions: Vec::new(),
        }
    }

    /// Append a session. Order is insertion order; `@last` is the last one.
    pub(crate) fn push(&mut self, session: MemorySession) {
        self.sessions.push(session);
    }

    fn find(&self, key: &str) -> Result<usize, QueryError> {
        if key == "@last" {
            return self
                .sessions
                .len()
                .checked_sub(1)
                .ok_or_else(|| QueryError::NotFound {
                    session: "@last".to_owned(),
                });
        }
        self.sessions
            .iter()
            .position(|session| {
                session.item.public_id == key || session.item.name.as_deref() == Some(key)
            })
            .ok_or_else(|| QueryError::NotFound {
                session: key.to_owned(),
            })
    }
}

#[cfg(test)]
impl Default for MemorySource {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl QuerySource for MemorySource {
    fn list_sessions(&self, query: &SessionQuery) -> Result<Vec<SessionItem>, QueryError> {
        let mut rows: Vec<&SessionItem> = self
            .sessions
            .iter()
            .map(|session| &session.item)
            .filter(|item| match &query.agent {
                Some(agent) => item.agent.as_deref() == Some(agent.as_str()),
                None => true,
            })
            .filter(|item| !query.active_only || item.ended_ns.is_none())
            .filter(|item| match query.since_ns {
                // No recorded start cannot be shown to fall inside the window.
                Some(since) => item.started_ns.is_some_and(|ts| ts >= since),
                None => true,
            })
            .collect();
        rows.sort_by(|a, b| {
            b.started_ns
                .cmp(&a.started_ns)
                .then_with(|| b.public_id.cmp(&a.public_id))
        });
        if let Some(limit) = query.limit {
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            rows.truncate(limit);
        }
        Ok(rows.into_iter().cloned().collect())
    }

    fn show_session(&self, key: &str) -> Result<SessionShow, QueryError> {
        let index = self.find(key)?;
        let session = &self.sessions[index];
        let (bytes_up, bytes_down) = sum_flow_bytes(&session.flows);
        Ok(SessionShow {
            item: session.item.clone(),
            process_count: Some(count_procs(&session.procs)),
            flow_count: Some(i64::try_from(session.flows.len()).unwrap_or(i64::MAX)),
            dns_count: Some(
                session
                    .timeline
                    .iter()
                    .filter(|row| row.cat == "dns")
                    .count() as i64,
            ),
            gap_count: Some(i64::try_from(session.gaps.len()).unwrap_or(i64::MAX)),
            // The in-memory fixture has no session-level exit code.
            exit_code: None,
            bytes_up,
            bytes_down,
            capabilities: session.capabilities.clone(),
            gap_summaries: session
                .gaps
                .iter()
                .map(|gap| {
                    format!(
                        "{} {} {}–{}",
                        gap.collector, gap.kind, gap.from_ns, gap.to_ns
                    )
                })
                .collect(),
        })
    }

    fn rename_session(&mut self, key: &str, name: &str) -> Result<SessionItem, QueryError> {
        let index = self.find(key)?;
        self.sessions[index].item.name = Some(name.to_owned());
        Ok(self.sessions[index].item.clone())
    }

    fn set_pinned(&mut self, key: &str, pinned: bool) -> Result<SessionItem, QueryError> {
        let index = self.find(key)?;
        self.sessions[index].item.pinned = Some(pinned);
        Ok(self.sessions[index].item.clone())
    }

    fn delete_sessions(&mut self, keys: &[String]) -> Result<u64, QueryError> {
        let mut indexes = Vec::with_capacity(keys.len());
        for key in keys {
            indexes.push(self.find(key)?);
        }
        indexes.sort_unstable();
        indexes.dedup();
        let removed = indexes.len() as u64;
        for index in indexes.into_iter().rev() {
            self.sessions.remove(index);
        }
        Ok(removed)
    }

    fn timeline(&self, key: &str, bounds: &TimelineBounds) -> Result<TimelinePage, QueryError> {
        let index = self.find(key)?;
        let mut rows: Vec<TimelineItem> = self.sessions[index]
            .timeline
            .iter()
            .filter(|row| match bounds.from_ns {
                Some(from) => row.ts_ns >= from,
                None => true,
            })
            .filter(|row| match bounds.to_ns {
                Some(to) => row.ts_ns <= to,
                None => true,
            })
            .filter(|row| match &bounds.filter {
                Some(text) if !text.is_empty() => row_matches_filter(row, text),
                _ => true,
            })
            .cloned()
            .collect();
        let limit = bounds.limit.unwrap_or(100);
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let next = rows.len() > limit;
        rows.truncate(limit);
        Ok(TimelinePage { rows, next })
    }

    fn follow(&self, key: &str, after_ns: Option<i64>) -> Result<Vec<TimelineItem>, QueryError> {
        // The memory source is the test stand-in for `/live`. It does not open
        // a socket. Callers that need the real stream still see UnavailableSource.
        let index = self.find(key)?;
        Ok(self.sessions[index]
            .timeline
            .iter()
            .filter(|row| match after_ns {
                Some(after) => row.ts_ns > after,
                None => true,
            })
            .cloned()
            .collect())
    }

    fn procs(&self, key: &str, tree: bool) -> Result<Vec<ProcItem>, QueryError> {
        let index = self.find(key)?;
        let roots = self.sessions[index].procs.clone();
        if tree {
            Ok(roots)
        } else {
            let mut flat = Vec::new();
            flatten_procs(&roots, &mut flat);
            Ok(flat)
        }
    }

    fn flows(
        &self,
        key: &str,
        group_by: Option<&str>,
        sort: Option<&str>,
    ) -> Result<Vec<FlowItem>, QueryError> {
        let index = self.find(key)?;
        let mut rows = group_flow_rows(&self.sessions[index].flows, group_by)?;
        sort_flow_rows(&mut rows, sort)?;
        Ok(rows)
    }

    fn gaps(&self, key: &str) -> Result<Vec<GapItem>, QueryError> {
        let index = self.find(key)?;
        Ok(self.sessions[index].gaps.clone())
    }

    fn files(&self, key: &str, query: &FileQuery) -> Result<Vec<FileItem>, QueryError> {
        let index = self.find(key)?;
        let mut rows = group_file_rows(&self.sessions[index].files, query.group_by.as_deref())?;
        if let Some(filter) = query.filter.as_deref() {
            if !filter.is_empty() {
                rows.retain(|row| file_matches_filter(row, filter));
            }
        }
        sort_file_rows(&mut rows, query.sort.as_deref())?;
        Ok(rows)
    }

    fn around(&self, key: &str, query: &AroundQuery) -> Result<AroundPage, QueryError> {
        let index = self.find(key)?;
        let (table, id) = split_reference(&query.reference)?;
        let _ = (table, id);
        let rows = &self.sessions[index].around;
        let anchor = rows.iter().find(|row| row.reference == query.reference);
        let Some(anchor) = anchor else {
            return Err(QueryError::NotFound {
                session: format!("{key} {}", query.reference),
            });
        };
        let start = anchor.ts_ns.saturating_sub(query.window_ns);
        let end = anchor.ts_ns.saturating_add(query.window_ns);
        let mut kept: Vec<AroundItem> = rows
            .iter()
            .filter(|row| row.ts_ns >= start && row.ts_ns <= end)
            .cloned()
            .collect();
        kept.sort_by_key(|row| (row.ts_ns, row.reference.clone()));
        Ok(AroundPage { rows: kept })
    }

    fn search(&self, query: &SearchQuery) -> Result<Vec<SearchHit>, QueryError> {
        if let Some(kind) = query.kind.as_deref() {
            if !matches!(kind, "file" | "proc" | "url") {
                return Err(QueryError::BadArgument {
                    detail: format!("--kind `{kind}` is not file, proc, or url"),
                });
            }
        }
        let needle = query.text.to_ascii_lowercase();
        let mut hits = Vec::new();
        for session in &self.sessions {
            for hit in &session.search {
                if let Some(kind) = query.kind.as_deref() {
                    if hit.kind != kind {
                        continue;
                    }
                }
                if let Some(since) = query.since_ns {
                    // A hit with no timestamp cannot be shown to fall inside the
                    // window, so it is left out rather than treated as the epoch.
                    if hit.ts_ns.is_none_or(|ts| ts < since) {
                        continue;
                    }
                }
                if !needle.is_empty()
                    && !hit.summary.to_ascii_lowercase().contains(&needle)
                    && hit.reference.to_ascii_lowercase() != needle
                {
                    continue;
                }
                hits.push(hit.clone());
            }
        }
        hits.sort_by(|a, b| {
            b.ts_ns
                .cmp(&a.ts_ns)
                .then_with(|| a.session.cmp(&b.session))
        });
        Ok(hits)
    }

    fn http(&self, key: &str, query: &HttpQuery) -> Result<HttpPage, QueryError> {
        let index = self.find(key)?;
        let page = &self.sessions[index].http;
        let mut rows = page.rows.clone();
        if let Some(filter) = query.filter.as_deref() {
            if !filter.is_empty() {
                let needle = filter.to_ascii_lowercase();
                rows.retain(|row| {
                    row.method.to_ascii_lowercase().contains(&needle)
                        || row.url.to_ascii_lowercase().contains(&needle)
                });
            }
        }
        rows.sort_by_key(|row| (row.ts_ns, row.id));
        Ok(HttpPage {
            rows,
            reason: page.reason.clone(),
        })
    }

    fn findings(&self, key: &str, query: &FindingQuery) -> Result<Vec<FindingItem>, QueryError> {
        let index = self.find(key)?;
        let floor = severity_rank(query.min_severity.as_deref());
        let mut rows: Vec<FindingItem> = self.sessions[index]
            .findings
            .iter()
            .filter(|row| severity_rank(Some(row.severity.as_str())) >= floor)
            .filter(|row| evidence_selected(row, &query.evidence))
            .cloned()
            .collect();
        rows.sort_by_key(|row| (row.first_ns, row.id));
        Ok(rows)
    }
}

/// `info` < `notice` < `warn`. An unknown token sorts below `info`.
#[cfg(test)]
fn severity_rank(value: Option<&str>) -> u8 {
    match value {
        Some("warn") => 3,
        Some("notice") => 2,
        Some("info") => 1,
        _ => 0,
    }
}

/// `content_match` matches `kind`. Every other token matches `evidence`.
#[cfg(test)]
fn evidence_selected(row: &FindingItem, wanted: &[String]) -> bool {
    if wanted.is_empty() {
        return true;
    }
    wanted.iter().any(|token| {
        if token == "content_match" {
            row.kind == "content_match" || row.evidence == "content_match"
        } else {
            row.evidence == *token
        }
    })
}

/// `<table>:<id>`. The id is numeric. Anything else is a usage error, not a lookup.
pub(crate) fn split_reference(reference: &str) -> Result<(&str, i64), QueryError> {
    let (table, id) = reference
        .split_once(':')
        .ok_or_else(|| QueryError::BadArgument {
            detail: format!("`{reference}` is not <table>:<id>"),
        })?;
    if table.is_empty()
        || !table
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(QueryError::BadArgument {
            detail: format!("`{reference}` has an empty or illegal table name"),
        });
    }
    let id = id.parse::<i64>().map_err(|_| QueryError::BadArgument {
        detail: format!("`{reference}` has an id that is not an integer"),
    })?;
    Ok((table, id))
}

#[cfg(test)]
fn group_file_rows(rows: &[FileItem], group_by: Option<&str>) -> Result<Vec<FileItem>, QueryError> {
    let by = match group_by {
        None | Some("") | Some("none") => return Ok(rows.to_vec()),
        Some("path") => FileGroup::Path,
        Some("dir") => FileGroup::Dir,
        Some("proc") => FileGroup::Proc,
        Some(other) => {
            return Err(QueryError::BadArgument {
                detail: format!("--group-by `{other}` is not path, dir, or proc"),
            });
        }
    };
    let mut grouped: Vec<(String, FileItem)> = Vec::new();
    for row in rows {
        let key = match by {
            FileGroup::Path => format!("p:{}", row.path),
            FileGroup::Dir => match &row.dir {
                Some(dir) => format!("d:{dir}"),
                None => "d:\u{0}".to_owned(),
            },
            FileGroup::Proc => row
                .proc_uid
                .map(|uid| format!("u:{uid}"))
                .unwrap_or_else(|| "u:\u{0}".to_owned()),
        };
        if let Some((_, acc)) = grouped.iter_mut().find(|(existing, _)| existing == &key) {
            acc.bytes_read = add_opt(acc.bytes_read, row.bytes_read);
            acc.bytes_written = add_opt(acc.bytes_written, row.bytes_written);
            acc.opens = add_opt(acc.opens, row.opens);
            if row.first_ns < acc.first_ns {
                acc.first_ns = row.first_ns;
            }
            acc.count = acc.count.saturating_add(row.count);
            if acc.evidence != row.evidence {
                acc.evidence = None;
            }
            if acc.sensitive_rule.is_none() {
                acc.sensitive_rule.clone_from(&row.sensitive_rule);
            }
        } else {
            grouped.push((
                key,
                FileItem {
                    id: None,
                    proc_uid: if by == FileGroup::Proc {
                        row.proc_uid
                    } else {
                        None
                    },
                    proc_pid: if by == FileGroup::Proc {
                        row.proc_pid
                    } else {
                        None
                    },
                    proc_exe: if by == FileGroup::Proc {
                        row.proc_exe.clone()
                    } else {
                        None
                    },
                    op: row.op.clone(),
                    path: if by == FileGroup::Dir {
                        row.dir.clone().unwrap_or_default()
                    } else {
                        row.path.clone()
                    },
                    path_to: None,
                    dir: row.dir.clone(),
                    access: None,
                    first_ns: row.first_ns,
                    opens: row.opens,
                    bytes_read: row.bytes_read,
                    bytes_written: row.bytes_written,
                    result: None,
                    sensitive_rule: row.sensitive_rule.clone(),
                    evidence: row.evidence.clone(),
                    na_reason: row.na_reason.clone(),
                    count: row.count,
                },
            ));
        }
    }
    Ok(grouped.into_iter().map(|(_, row)| row).collect())
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
enum FileGroup {
    Path,
    Dir,
    Proc,
}

#[cfg(test)]
fn sort_file_rows(rows: &mut [FileItem], sort: Option<&str>) -> Result<(), QueryError> {
    match sort {
        None | Some("") | Some("time") => {
            rows.sort_by_key(|row| (row.first_ns, row.id.unwrap_or(0)));
        }
        Some("bytes_read") | Some("read") => {
            rows.sort_by(|a, b| cmp_bytes(a.bytes_read, b.bytes_read).reverse());
        }
        Some("bytes_written") | Some("write") => {
            rows.sort_by(|a, b| cmp_bytes(a.bytes_written, b.bytes_written).reverse());
        }
        Some("opens") => rows.sort_by(|a, b| cmp_bytes(a.opens, b.opens).reverse()),
        Some("path") => rows.sort_by(|a, b| a.path.cmp(&b.path)),
        Some(other) => {
            return Err(QueryError::BadArgument {
                detail: format!(
                    "--sort `{other}` is not time, path, opens, bytes_read, or bytes_written"
                ),
            });
        }
    }
    Ok(())
}

/// Substring match on path, op, and the sensitive rule id. Not the filter compiler.
#[cfg(test)]
fn file_matches_filter(row: &FileItem, filter: &str) -> bool {
    let needle = filter.to_ascii_lowercase();
    if needle.contains("tag:sensitive") || needle == "sensitive" {
        return row.sensitive_rule.is_some();
    }
    row.path.to_ascii_lowercase().contains(&needle)
        || row.op.to_ascii_lowercase().contains(&needle)
        || row
            .sensitive_rule
            .as_deref()
            .is_some_and(|rule| rule.to_ascii_lowercase().contains(&needle))
}

#[cfg(test)]
fn count_procs(nodes: &[ProcItem]) -> i64 {
    let mut n = 0_i64;
    for node in nodes {
        n = n.saturating_add(1);
        n = n.saturating_add(count_procs(&node.children));
    }
    n
}

#[cfg(test)]
fn flatten_procs(nodes: &[ProcItem], out: &mut Vec<ProcItem>) {
    for node in nodes {
        let mut flat = node.clone();
        let children = std::mem::take(&mut flat.children);
        out.push(flat);
        flatten_procs(&children, out);
    }
}

/// `None + None = None`. A known side plus an unknown side keeps the known side.
pub(crate) fn add_opt(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (None, None) => None,
        (Some(a), None) | (None, Some(a)) => Some(a),
        (Some(a), Some(b)) => Some(a.saturating_add(b)),
    }
}

#[cfg(test)]
fn sum_flow_bytes(rows: &[FlowItem]) -> (Option<i64>, Option<i64>) {
    let mut up = None;
    let mut down = None;
    for row in rows {
        up = add_opt(up, row.bytes_up);
        down = add_opt(down, row.bytes_down);
    }
    (up, down)
}

#[cfg(test)]
fn group_flow_rows(rows: &[FlowItem], group_by: Option<&str>) -> Result<Vec<FlowItem>, QueryError> {
    let by = match group_by {
        None | Some("") | Some("none") => return Ok(rows.to_vec()),
        Some("domain") => GroupKey::Domain,
        Some("ip") => GroupKey::Ip,
        Some("port") => GroupKey::Port,
        Some("proc") => GroupKey::Proc,
        Some(other) => {
            return Err(QueryError::BadArgument {
                detail: format!("--group-by `{other}` is not domain, ip, proc, or port"),
            });
        }
    };
    let mut grouped: Vec<(String, FlowItem)> = Vec::new();
    for row in rows {
        let key = match by {
            GroupKey::Domain => match &row.domain {
                Some(domain) => format!("d:{domain}"),
                None => "d:\u{0}".to_owned(),
            },
            GroupKey::Ip => match &row.remote_ip {
                Some(ip) => format!("i:{ip}"),
                None => "i:\u{0}".to_owned(),
            },
            GroupKey::Port => row
                .remote_port
                .map(|port| format!("p:{port}"))
                .unwrap_or_else(|| "p:\u{0}".to_owned()),
            GroupKey::Proc => row
                .proc_uid
                .map(|uid| format!("u:{uid}"))
                .unwrap_or_else(|| "u:\u{0}".to_owned()),
        };
        if let Some((_, acc)) = grouped.iter_mut().find(|(existing, _)| existing == &key) {
            acc.bytes_up = add_opt(acc.bytes_up, row.bytes_up);
            acc.bytes_down = add_opt(acc.bytes_down, row.bytes_down);
            if row.start_ns < acc.start_ns {
                acc.start_ns = row.start_ns;
            }
            acc.count = acc.count.saturating_add(row.count);
            if acc.evidence != row.evidence {
                acc.evidence = None;
            }
            if acc.domain_evidence != row.domain_evidence {
                acc.domain_evidence = None;
            }
        } else {
            grouped.push((
                key,
                FlowItem {
                    id: None,
                    proc_uid: if by == GroupKey::Proc {
                        row.proc_uid
                    } else {
                        None
                    },
                    local_port: None,
                    remote_port: if by == GroupKey::Port {
                        row.remote_port
                    } else {
                        None
                    },
                    remote_ip: if by == GroupKey::Ip {
                        row.remote_ip.clone()
                    } else {
                        None
                    },
                    domain: if by == GroupKey::Domain {
                        row.domain.clone()
                    } else {
                        None
                    },
                    domain_source: if by == GroupKey::Domain {
                        row.domain_source.clone()
                    } else {
                        None
                    },
                    domain_evidence: if by == GroupKey::Domain {
                        row.domain_evidence.clone()
                    } else {
                        None
                    },
                    bytes_up: row.bytes_up,
                    bytes_down: row.bytes_down,
                    start_ns: row.start_ns,
                    evidence: row.evidence.clone(),
                    count: row.count,
                },
            ));
        }
    }
    Ok(grouped.into_iter().map(|(_, row)| row).collect())
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
enum GroupKey {
    Domain,
    Ip,
    Port,
    Proc,
}

#[cfg(test)]
fn sort_flow_rows(rows: &mut [FlowItem], sort: Option<&str>) -> Result<(), QueryError> {
    match sort {
        None | Some("") | Some("time") => {
            rows.sort_by_key(|row| (row.start_ns, row.id.unwrap_or(0)));
        }
        Some("up") => rows.sort_by(|a, b| cmp_bytes(a.bytes_up, b.bytes_up).reverse()),
        Some("down") => rows.sort_by(|a, b| cmp_bytes(a.bytes_down, b.bytes_down).reverse()),
        Some("total") => rows.sort_by(|a, b| {
            cmp_bytes(
                add_opt(a.bytes_up, a.bytes_down),
                add_opt(b.bytes_up, b.bytes_down),
            )
            .reverse()
            .then_with(|| a.start_ns.cmp(&b.start_ns))
        }),
        Some(other) => {
            return Err(QueryError::BadArgument {
                detail: format!("--sort `{other}` is not up, down, or total"),
            });
        }
    }
    Ok(())
}

/// Known values sort before unknown ones. Unknown is not zero.
#[cfg(test)]
fn cmp_bytes(left: Option<i64>, right: Option<i64>) -> std::cmp::Ordering {
    match (left, right) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

/// Substring match on the summary and the category. Not a full filter compiler:
/// the shared parser lives in `aw-store`, which this crate does not depend on.
#[cfg(test)]
fn row_matches_filter(row: &TimelineItem, filter: &str) -> bool {
    let needle = filter.to_ascii_lowercase();
    row.summary.to_ascii_lowercase().contains(&needle)
        || row.cat.to_ascii_lowercase().contains(&needle)
        || evidence_name(&row.evidence)
            .to_ascii_lowercase()
            .contains(&needle)
}

#[cfg(test)]
fn evidence_name(evidence: &Evidence) -> &'static str {
    match evidence {
        Evidence::E1 => "E1",
        Evidence::E2 => "E2",
        Evidence::E3 => "E3",
        Evidence::S => "S",
        Evidence::I => "I",
        Evidence::NA(_) => "NA",
    }
}

/// Sum of known byte sides across `rows`. Unknown sides are not treated as zero
/// when every side is unknown (`None`). A mix keeps the known total.
#[must_use]
#[cfg(test)]
pub(crate) fn total_bytes(rows: &[FlowItem]) -> Option<i64> {
    let (up, down) = sum_flow_bytes(rows);
    add_opt(up, down)
}

/// Cell text. `None` is `不可得`, never an empty string or `0`.
#[must_use]
pub(crate) fn opt_text(value: Option<&str>) -> String {
    match value {
        Some(text) if !text.is_empty() => text.to_owned(),
        Some(_) | None => "不可得".to_owned(),
    }
}

/// Integer cell. `None` is `不可得`.
#[must_use]
pub(crate) fn opt_i64(value: Option<i64>) -> String {
    match value {
        Some(n) => n.to_string(),
        None => "不可得".to_owned(),
    }
}

/// `--from` / `--to` as an absolute nanosecond, or a session-relative `+30s`
/// measured from `started_ns`. `-10m` is relative to `now_ns`.
///
/// # Errors
///
/// A string when `text` is not a form [`crate::output::parse_time`] accepts,
/// or when a relative form has no anchor.
pub(crate) fn resolve_time(
    text: &str,
    started_ns: Option<i64>,
    now_ns: i64,
) -> Result<i64, String> {
    match crate::output::parse_time(text)? {
        crate::output::TimeArg::Rfc3339(raw) => rfc3339_to_ns(&raw),
        crate::output::TimeArg::BeforeNow(duration) => {
            let delta = duration_ns(duration)?;
            Ok(now_ns.saturating_sub(delta))
        }
        crate::output::TimeArg::FromSessionStart(duration) => {
            let start =
                started_ns.ok_or_else(|| "相对会话的时间需要已知的会话开始时间".to_owned())?;
            let delta = duration_ns(duration)?;
            Ok(start.saturating_add(delta))
        }
    }
}

fn duration_ns(duration: crate::output::DurationArg) -> Result<i64, String> {
    let count = i64::try_from(duration.count).map_err(|_| "时长超出 i64 范围".to_owned())?;
    let unit: i64 = match duration.unit {
        crate::output::TimeUnit::Millis => 1_000_000,
        crate::output::TimeUnit::Seconds => 1_000_000_000,
        crate::output::TimeUnit::Minutes => 60 * 1_000_000_000,
        crate::output::TimeUnit::Hours => 3_600 * 1_000_000_000,
        crate::output::TimeUnit::Days => 86_400 * 1_000_000_000,
    };
    count
        .checked_mul(unit)
        .ok_or_else(|| "时长换算为纳秒时溢出".to_owned())
}

/// `YYYY-MM-DDThh:mm:ss` plus optional fraction and `Z` or `±hh:mm`.
/// Enough for the CLI time forms. Not a general date library.
fn rfc3339_to_ns(text: &str) -> Result<i64, String> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 {
        return Err(format!("时间 `{text}` 不是 RFC 3339"));
    }
    let year: i64 = parse_fixed(&text[0..4])?;
    let month: i64 = parse_fixed(&text[5..7])?;
    let day: i64 = parse_fixed(&text[8..10])?;
    let hour: i64 = parse_fixed(&text[11..13])?;
    let minute: i64 = parse_fixed(&text[14..16])?;
    let second: i64 = parse_fixed(&text[17..19])?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(format!("时间 `{text}` 的字段超出范围"));
    }
    let mut rest = &text[19..];
    let mut frac_ns: i64 = 0;
    if let Some(stripped) = rest.strip_prefix('.') {
        let digits: String = stripped
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect();
        if digits.is_empty() {
            return Err(format!("时间 `{text}` 的小数部分为空"));
        }
        let mut padded = digits.clone();
        if padded.len() > 9 {
            padded.truncate(9);
        }
        while padded.len() < 9 {
            padded.push('0');
        }
        frac_ns = parse_fixed(&padded)?;
        rest = &stripped[digits.len()..];
    }
    let offset = if rest == "Z" || rest.is_empty() {
        0
    } else if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) {
        let sign: i64 = if rest.starts_with('-') { -1 } else { 1 };
        let oh: i64 = parse_fixed(&rest[1..3])?;
        let om: i64 = parse_fixed(&rest[4..6])?;
        sign * (oh * 3600 + om * 60)
    } else {
        return Err(format!("时间 `{text}` 的时区偏移不受支持"));
    };
    let days = days_from_civil(year, month, day)?;
    let epoch_days = days - days_from_civil(1970, 1, 1)?;
    let secs = epoch_days
        .checked_mul(86_400)
        .and_then(|d| d.checked_add(hour * 3600 + minute * 60 + second))
        .and_then(|s| s.checked_sub(offset))
        .ok_or_else(|| format!("时间 `{text}` 溢出"))?;
    secs.checked_mul(1_000_000_000)
        .and_then(|ns| ns.checked_add(frac_ns))
        .ok_or_else(|| format!("时间 `{text}` 换算为纳秒时溢出"))
}

fn parse_fixed(text: &str) -> Result<i64, String> {
    text.parse::<i64>()
        .map_err(|_| format!("`{text}` 不是整数"))
}

/// Howard Hinnant civil-from-days, inverted. Days before 1970 are negative.
fn days_from_civil(year: i64, month: i64, day: i64) -> Result<i64, String> {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(era * 146_097 + doe - 719_468)
}

/// How long `--follow` waits between polls of the source. The acceptance bound
/// is under 2 s against a live daemon; this interval is what the stub uses so
/// a test does not sleep.
#[must_use]
pub(crate) fn follow_poll_interval() -> Duration {
    Duration::from_millis(200)
}

/// Marker printed on a gap line. ANSI red is added only when `color` is set.
#[must_use]
pub(crate) fn gap_marker(color: bool) -> String {
    if color {
        "\u{1b}[31m[采集缺口]\u{1b}[0m".to_owned()
    } else {
        "[采集缺口]".to_owned()
    }
}

/// Sample used by the snapshot tests. Synthetic. No real argv, host, or user.
#[cfg(test)]
#[must_use]
pub(crate) fn sample_source() -> MemorySource {
    let mut source = MemorySource::new();
    source.push(MemorySession {
        item: SessionItem {
            public_id: "s-7k2m".to_owned(),
            name: Some("demo".to_owned()),
            mode: "launch".to_owned(),
            agent: Some("example-agent".to_owned()),
            started_ns: Some(1_700_000_000_000_000_000),
            ended_ns: Some(1_700_000_060_000_000_000),
            pinned: Some(false),
            evidence: Evidence::E1,
        },
        capabilities: vec![
            CapabilityFact {
                category: "CAP-PROC".to_owned(),
                source: Some("fixture.proc".to_owned()),
                evidence: Evidence::E1,
            },
            CapabilityFact {
                category: "CAP-NET".to_owned(),
                source: Some("fixture.net".to_owned()),
                evidence: Evidence::E1,
            },
            CapabilityFact {
                category: "CAP-DNS".to_owned(),
                source: None,
                evidence: Evidence::NA(NaReason::NoDnsObserved),
            },
        ],
        timeline: vec![
            TimelineItem {
                ts_ns: 1_700_000_000_000_000_000,
                cat: "proc".to_owned(),
                id: 1,
                proc_uid: Some(10),
                summary: "start pid 100 exe demo".to_owned(),
                evidence: Evidence::E1,
                is_gap: false,
            },
            TimelineItem {
                ts_ns: 1_700_000_001_000_000_000,
                cat: "net".to_owned(),
                id: 2,
                proc_uid: Some(11),
                summary: "connect 203.0.113.10:443".to_owned(),
                evidence: Evidence::E1,
                is_gap: false,
            },
            TimelineItem {
                ts_ns: 1_700_000_002_000_000_000,
                cat: "gap".to_owned(),
                id: 3,
                proc_uid: None,
                summary: "collector dropped events".to_owned(),
                evidence: Evidence::E1,
                is_gap: true,
            },
        ],
        procs: vec![ProcItem {
            proc_uid: 10,
            pid: 100,
            parent_uid: None,
            exe_name: Some("demo".to_owned()),
            argv_redacted: Some("<redacted>".to_owned()),
            exit_code: Some(7),
            evidence: Evidence::E1,
            children: vec![ProcItem {
                proc_uid: 11,
                pid: 101,
                parent_uid: Some(10),
                exe_name: Some("helper".to_owned()),
                argv_redacted: None,
                exit_code: None,
                evidence: Evidence::S,
                children: Vec::new(),
            }],
        }],
        flows: vec![
            FlowItem {
                id: Some(1),
                proc_uid: Some(11),
                local_port: Some(40_000),
                remote_port: Some(443),
                remote_ip: Some("203.0.113.10".to_owned()),
                domain: Some("example.test".to_owned()),
                domain_source: Some("dns".to_owned()),
                domain_evidence: Some(Evidence::E1),
                bytes_up: Some(100),
                bytes_down: Some(400),
                start_ns: 1_700_000_001_000_000_000,
                evidence: Some(Evidence::E1),
                count: 1,
            },
            FlowItem {
                id: Some(2),
                proc_uid: Some(11),
                local_port: Some(40_001),
                remote_port: Some(443),
                remote_ip: Some("203.0.113.10".to_owned()),
                domain: Some("example.test".to_owned()),
                domain_source: Some("sni".to_owned()),
                domain_evidence: Some(Evidence::E1),
                bytes_up: Some(50),
                bytes_down: None,
                start_ns: 1_700_000_003_000_000_000,
                evidence: Some(Evidence::E2),
                count: 1,
            },
            FlowItem {
                id: Some(3),
                proc_uid: Some(10),
                local_port: None,
                remote_port: Some(53),
                remote_ip: Some("203.0.113.53".to_owned()),
                domain: None,
                domain_source: None,
                domain_evidence: None,
                bytes_up: None,
                bytes_down: Some(20),
                start_ns: 1_700_000_004_000_000_000,
                evidence: Some(Evidence::S),
                count: 1,
            },
        ],
        gaps: vec![GapItem {
            id: 7,
            collector: "fixture.proc".to_owned(),
            kind: "overflow".to_owned(),
            affects: "proc".to_owned(),
            from_ns: 1_700_000_002_000_000_000,
            to_ns: 1_700_000_002_500_000_000,
            count: None,
            detail: Some("ring full".to_owned()),
            evidence: Evidence::E1,
        }],
        files: Vec::new(),
        around: Vec::new(),
        search: Vec::new(),
        http: HttpPage {
            rows: Vec::new(),
            reason: None,
        },
        findings: Vec::new(),
    });
    source
}

/// `sessions list --since` with a relative-to-now form is refused. RFC 3339 is
/// converted. `now_ns` is not used for the RFC path.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{sample_source, total_bytes, MemorySource, QuerySource};
    use crate::cmd::flows;
    use crate::cmd::gaps;
    use crate::cmd::procs;
    use crate::cmd::sessions;
    use crate::cmd::timeline::{self, TimelineArgs};
    use crate::cmd::tree::SessionsCmd;
    use crate::exit;
    use aw_core::Evidence;

    fn text(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    fn assert_evidence_column(table: &str) {
        assert!(
            table
                .lines()
                .next()
                .is_some_and(|line| line.contains("evidence")),
            "table header missing evidence:\n{table}"
        );
        let body: Vec<&str> = table
            .lines()
            .skip(1)
            .filter(|line| !line.is_empty())
            .collect();
        assert!(!body.is_empty(), "table has no rows:\n{table}");
        for line in body {
            assert!(
                line.contains("E1 系统")
                    || line.contains("E2 协议")
                    || line.contains("E3 自报")
                    || line.contains("S 采样")
                    || line.contains("推测")
                    || line.contains("不可得"),
                "row missing an evidence badge:\n{line}"
            );
        }
    }

    fn assert_json_evidence(body: &str) {
        let value: serde_json::Value = serde_json::from_str(body).expect("json");
        assert!(
            body.contains("\"level\""),
            "json missing evidence level:\n{body}"
        );
        let _ = value;
    }

    #[test]
    fn sessions_list_table_and_json_carry_evidence() {
        let mut source = sample_source();
        let table = sessions::run(
            &SessionsCmd::List {
                since: None,
                agent: None,
                active: false,
                limit: None,
            },
            false,
            &mut source,
        )
        .expect("run");
        assert_eq!(table.code, exit::OK);
        let rendered = text(&table.stdout);
        assert_evidence_column(&rendered);
        assert!(rendered.contains("s-7k2m"), "{rendered}");
        insta::assert_snapshot!("sessions_list_table", rendered);

        let json = sessions::run(
            &SessionsCmd::List {
                since: None,
                agent: None,
                active: false,
                limit: None,
            },
            true,
            &mut source,
        )
        .expect("run");
        let body = text(&json.stdout);
        assert_json_evidence(&body);
        assert!(body.contains("\"level\": \"E1\""), "{body}");
        insta::assert_snapshot!("sessions_list_json", body);
    }

    #[test]
    fn sessions_show_includes_stats_gaps_and_capabilities() {
        let mut source = sample_source();
        let outcome = sessions::run(
            &SessionsCmd::Show {
                session: "s-7k2m".to_owned(),
            },
            false,
            &mut source,
        )
        .expect("run");
        assert_eq!(outcome.code, exit::OK);
        let rendered = text(&outcome.stdout);
        assert_evidence_column(&rendered);
        assert!(rendered.contains("CAP-PROC"), "{rendered}");
        assert!(rendered.contains("CAP-DNS"), "{rendered}");
        assert!(rendered.contains("不可得"), "{rendered}");
        insta::assert_snapshot!("sessions_show_table", rendered);

        let json = sessions::run(
            &SessionsCmd::Show {
                session: "@last".to_owned(),
            },
            true,
            &mut source,
        )
        .expect("run");
        let body = text(&json.stdout);
        assert!(body.contains("no_dns_observed"), "{body}");
        assert!(body.contains("gap_summaries"), "{body}");
        insta::assert_snapshot!("sessions_show_json", body);
    }

    #[test]
    fn rename_pin_and_delete_round_trip() {
        let mut source = sample_source();
        let renamed = sessions::run(
            &SessionsCmd::Rename {
                session: "s-7k2m".to_owned(),
                name: "kept".to_owned(),
            },
            true,
            &mut source,
        )
        .expect("rename");
        assert_eq!(renamed.code, exit::OK);
        assert!(text(&renamed.stdout).contains("kept"));

        let pinned = sessions::run(
            &SessionsCmd::Pin {
                session: "kept".to_owned(),
            },
            false,
            &mut source,
        )
        .expect("pin");
        assert_eq!(pinned.code, exit::OK);
        assert!(
            text(&pinned.stdout).contains("yes"),
            "{}",
            text(&pinned.stdout)
        );

        let refused = sessions::run(
            &SessionsCmd::Delete {
                sessions: vec!["kept".to_owned()],
                yes: false,
            },
            false,
            &mut source,
        )
        .expect("delete");
        assert_eq!(refused.code, exit::USAGE);

        let deleted = sessions::run(
            &SessionsCmd::Delete {
                sessions: vec!["kept".to_owned()],
                yes: true,
            },
            true,
            &mut source,
        )
        .expect("delete");
        assert_eq!(deleted.code, exit::OK);
        assert!(text(&deleted.stdout).contains("\"removed\": 1"));
        let missing = source.show_session("kept");
        assert!(missing.is_err());
    }

    #[test]
    fn timeline_table_marks_gaps_and_json_carries_evidence() {
        let source = sample_source();
        let outcome = timeline::run(
            TimelineArgs {
                session: "s-7k2m",
                filter: None,
                from: None,
                to: None,
                follow: false,
                limit: Some(10),
                json: false,
                color: false,
            },
            &source,
        )
        .expect("timeline");
        assert_eq!(outcome.code, exit::OK);
        let rendered = text(&outcome.stdout);
        assert_evidence_column(&rendered);
        assert!(rendered.contains("[采集缺口]"), "{rendered}");
        assert!(!rendered.contains('\u{1b}'), "snapshot color is off");
        insta::assert_snapshot!("timeline_table", rendered);

        let json = timeline::run(
            TimelineArgs {
                session: "@last",
                filter: None,
                from: None,
                to: None,
                follow: false,
                limit: None,
                json: true,
                color: false,
            },
            &source,
        )
        .expect("timeline");
        let body = text(&json.stdout);
        assert_json_evidence(&body);
        assert!(body.contains("\"gap\": true"), "{body}");
        insta::assert_snapshot!("timeline_json", body);
    }

    #[test]
    fn timeline_follow_renders_the_stub_format() {
        // Real `/live` is not connected. The memory source stands in so the
        // line format (gap marker, evidence column) can be checked. Delay
        // under 2 s is not measured.
        let source = sample_source();
        let outcome = timeline::run(
            TimelineArgs {
                session: "s-7k2m",
                filter: None,
                from: None,
                to: None,
                follow: true,
                limit: None,
                json: true,
                color: false,
            },
            &source,
        )
        .expect("follow");
        assert_eq!(outcome.code, exit::OK);
        let body = text(&outcome.stdout);
        assert!(body.contains("真实订阅未接通"), "{body}");
        assert!(body.contains("\"live_connected\": false"), "{body}");
        assert!(body.contains("\"level\": \"E1\""), "{body}");
        insta::assert_snapshot!("timeline_follow_json", body);
    }

    #[test]
    fn procs_tree_labels_placeholder_redaction() {
        let source = sample_source();
        let outcome = procs::run("s-7k2m", true, false, &source).expect("procs");
        assert_eq!(outcome.code, exit::OK);
        let rendered = text(&outcome.stdout);
        assert_evidence_column(&rendered);
        assert!(rendered.contains("P1 脱敏为占位"), "{rendered}");
        assert!(rendered.contains("不可得"), "{rendered}");
        assert!(rendered.contains("退出码"), "{rendered}");
        assert!(rendered.contains("7"), "{rendered}");
        assert!(rendered.contains("没采"), "{rendered}");
        // The placeholder text is what was stored. No raw argv is in the sample.
        assert!(!rendered.contains("--token"), "{rendered}");
        insta::assert_snapshot!("procs_tree_table", rendered);

        let json = procs::run("@last", true, true, &source).expect("procs");
        let body = text(&json.stdout);
        assert!(body.contains("P1 脱敏为占位"), "{body}");
        assert!(body.contains("\"exit_code\": 7"), "{body}");
        assert!(body.contains("\"exit_code\": null"), "{body}");
        assert_json_evidence(&body);
        insta::assert_snapshot!("procs_tree_json", body);
    }

    #[test]
    fn flows_group_by_domain_json_totals_match_members() {
        let source = sample_source();
        let ungrouped = source.flows("s-7k2m", None, None).expect("flows");
        let expected = total_bytes(&ungrouped);
        let outcome =
            flows::run("s-7k2m", Some("domain"), Some("total"), true, &source).expect("flows");
        assert_eq!(outcome.code, exit::OK);
        let body = text(&outcome.stdout);
        let value: serde_json::Value = serde_json::from_str(&body).expect("json");
        let grouped_total = value.get("bytes_total").cloned();
        let expected_json = match expected {
            Some(n) => serde_json::Value::from(n),
            None => serde_json::Value::Null,
        };
        assert_eq!(grouped_total, Some(expected_json), "{body}");
        // Member sides: 100+50 up, 400+20 down. The unknown down on the second
        // flow is not a zero, and the unknown up on the third is not a zero.
        // add_opt keeps the known sides, so the total is 100+50+400+20 = 570.
        assert_eq!(expected, Some(570));
        let flows_json = value
            .get("flows")
            .and_then(|v| v.as_array())
            .expect("flows");
        let mut side = 0_i64;
        for row in flows_json {
            if let Some(up) = row.get("bytes_up").and_then(|v| v.as_i64()) {
                side += up;
            }
            if let Some(down) = row.get("bytes_down").and_then(|v| v.as_i64()) {
                side += down;
            }
            assert!(row.get("evidence").is_some() || row.get("domain").is_some());
        }
        assert_eq!(side, 570, "{body}");
        assert!(body.contains("example.test"), "{body}");
        assert!(
            body.contains("\"level\": \"E1\"") || body.contains("\"level\": \"E2\""),
            "{body}"
        );
        insta::assert_snapshot!("flows_group_domain_json", body);

        let table = flows::run("@last", Some("domain"), None, false, &source).expect("flows");
        let rendered = text(&table.stdout);
        assert_evidence_column(&rendered);
        assert!(rendered.contains("不可得"), "{rendered}");
        insta::assert_snapshot!("flows_group_domain_table", rendered);
    }

    #[test]
    fn gaps_table_and_json_keep_unknown_count() {
        let source = sample_source();
        let outcome = gaps::run("s-7k2m", false, &source).expect("gaps");
        assert_eq!(outcome.code, exit::OK);
        let rendered = text(&outcome.stdout);
        assert_evidence_column(&rendered);
        assert!(
            rendered
                .lines()
                .any(|line| line.contains("不可得") && line.contains("overflow")),
            "{rendered}"
        );
        insta::assert_snapshot!("gaps_table", rendered);

        let json = gaps::run("@last", true, &source).expect("gaps");
        let body = text(&json.stdout);
        assert!(body.contains("\"count\": null"), "{body}");
        assert_json_evidence(&body);
        insta::assert_snapshot!("gaps_json", body);
    }

    #[test]
    fn unknown_group_by_is_usage() {
        let source = sample_source();
        let outcome = flows::run("s-7k2m", Some("host"), None, false, &source).expect("flows");
        assert_eq!(outcome.code, exit::USAGE, "{}", text(&outcome.stderr));
    }

    #[test]
    fn missing_session_is_not_an_empty_table() {
        let source = MemorySource::new();
        let outcome = gaps::run("missing", false, &source).expect("gaps");
        assert_eq!(outcome.code, exit::GENERAL);
        assert!(text(&outcome.stderr).contains("找不到会话"));
        assert!(outcome.stdout.is_empty());
    }

    #[test]
    fn evidence_badges_cover_each_level() {
        // The sample uses E1, E2, S, and NA. I is rendered by the shared helper.
        assert_eq!(crate::output::evidence_badge(&Evidence::I), "推测");
    }
}
