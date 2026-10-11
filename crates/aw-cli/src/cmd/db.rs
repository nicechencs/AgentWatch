//! `aw db` (P1-CLI-04, extended by P2-CLI-02).
//!
//! The CLI does not open SQLite. P1 kept a [`DbStore`] so tests could record
//! stats, vacuum, migrate, and purge without a daemon. P2 sends those same
//! operations to the daemon:
//!
//! - `GET /api/v1/db/stats`
//! - `POST /api/v1/db/vacuum`
//! - `POST /api/v1/db/migrate` with `{ "dry_run": bool }`
//! - `POST /api/v1/db/purge` with `{ "older_than"?, "all", "confirm": true }`
//!
//! [`DbApi`] is that boundary. Production uses [`HttpDbApi`]. [`UnwiredApi`] is
//! the test stand-in: every call is exit 3, not an empty success that would
//! claim the database was vacuumed or purged.
//!
//! `purge --all` needs an administrator ([`super::daemon::Privilege`]) and
//! exits 4 otherwise. `purge --older-than` does not. Pinned sessions are never
//! counted as removed. `vacuum` and `purge` are destructive: without a
//! confirmation ([`Confirm`]) they exit 2, and a non-TTY with no `--yes`
//! refuses rather than prompting.

use std::io::{self, IsTerminal, Write};

use serde_json::json;

use crate::exit;
use crate::output::{parse_time, DurationArg, TimeArg, TimeUnit};

use super::daemon::Privilege;
use super::Outcome;

/// `db stats` numbers. Read by [`run_store`], which the P1 tests call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct DbStats {
    /// Logical database size. `None` when the store has no file.
    pub db_bytes: Option<u64>,
    /// Sessions that are not pinned.
    pub sessions: u64,
    /// Pinned sessions. Reported separately so a purge can leave them.
    pub pinned_sessions: u64,
}

/// What purge asked the store to do. The API path sends [`PurgeBody`] instead.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum PurgeRequest {
    /// `ended_ns` strictly before this instant. `None` duration is not used:
    /// the caller parses `--older-than` first.
    OlderThan {
        /// Cutoff, Unix nanoseconds.
        ended_before_ns: i64,
    },
    /// Every ended, unpinned session.
    All,
}

/// Result of a purge. Pinned and active sessions stay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PurgeResult {
    /// Public ids that were removed.
    pub removed: Vec<String>,
    /// Public ids that were left because they are pinned or still active.
    pub kept: Vec<String>,
}

/// Store operations. Implementations must not delete on any method other than
/// [`purge`](Self::purge). Kept for the P1 tests; production uses [`DbApi`].
#[allow(dead_code)]
pub(crate) trait DbStore {
    /// Current counts.
    fn stats(&self) -> DbStats;

    /// Compact. Returns a one-line note.
    ///
    /// # Errors
    ///
    /// A store failure. No path with a username.
    fn vacuum(&mut self) -> Result<String, String>;

    /// Apply migrations. `dry_run` lists them and writes nothing.
    ///
    /// # Errors
    ///
    /// A store failure.
    fn migrate(&mut self, dry_run: bool) -> Result<String, String>;

    /// Remove sessions selected by `request`. Pinned and active rows stay.
    ///
    /// # Errors
    ///
    /// A store failure.
    fn purge(&mut self, request: &PurgeRequest) -> Result<PurgeResult, String>;
}

/// Empty store. Every mutating call is a no-op note.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct EmptyDb;

impl DbStore for EmptyDb {
    fn stats(&self) -> DbStats {
        DbStats {
            db_bytes: None,
            sessions: 0,
            pinned_sessions: 0,
        }
    }

    fn vacuum(&mut self) -> Result<String, String> {
        Ok("已记录 vacuum；未打开数据库".to_owned())
    }

    fn migrate(&mut self, dry_run: bool) -> Result<String, String> {
        if dry_run {
            Ok("migrate --dry-run：没有待执行的迁移".to_owned())
        } else {
            Ok("已记录 migrate；未打开数据库".to_owned())
        }
    }

    fn purge(&mut self, _request: &PurgeRequest) -> Result<PurgeResult, String> {
        Ok(PurgeResult {
            removed: Vec::new(),
            kept: Vec::new(),
        })
    }
}

/// Clock used to turn `--older-than 0s` into a cutoff. Tests pass a fixed value.
pub(crate) trait Clock {
    /// Unix nanoseconds.
    fn now_ns(&self) -> i64;
}

/// A fixed instant. Not the wall clock.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FixedClock(pub i64);

impl Clock for FixedClock {
    fn now_ns(&self) -> i64 {
        self.0
    }
}

/// Which `db` subcommand to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DbOp {
    /// `stats`.
    Stats,
    /// `vacuum`. `yes` skips the terminal confirmation.
    Vacuum { yes: bool },
    /// `migrate`.
    Migrate {
        /// `--dry-run`.
        dry_run: bool,
    },
    /// `purge`.
    Purge {
        /// `--older-than`, raw text. Parsed here.
        older_than: Option<String>,
        /// `--all`.
        all: bool,
        /// `--yes`. Required for a purge that would delete.
        yes: bool,
    },
}

/// Whether the user confirmed a destructive `db` command.
///
/// A TTY implementation may prompt. [`NotInteractive`] never prompts: the
/// command must already carry `--yes` (purge) or it is refused. `vacuum` has
/// no `--yes` flag in the command tree, so a non-TTY vacuum is refused until
/// a caller passes [`Confirmed`].
pub(crate) trait Confirm {
    /// `true` when the operator agreed. Must not print argv, paths, or tokens.
    fn confirm(&mut self, prompt: &str) -> bool;
}

/// Production confirmation. There is no TTY on this path, so the answer is no.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct NotInteractive;

impl Confirm for NotInteractive {
    fn confirm(&mut self, _prompt: &str) -> bool {
        false
    }
}

/// Production confirmation. It prompts only when stdin is a terminal, so a
/// redirected invocation cannot hang or accept an accidental default answer.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct StdinConfirm;

impl Confirm for StdinConfirm {
    fn confirm(&mut self, prompt: &str) -> bool {
        if !io::stdin().is_terminal() {
            return false;
        }
        let _ = write!(io::stderr(), "{prompt}");
        let _ = io::stderr().flush();
        let mut answer = String::new();
        io::stdin().read_line(&mut answer).is_ok()
            && matches!(
                answer.trim().to_ascii_lowercase().as_str(),
                "是" | "y" | "yes"
            )
    }
}

/// A caller that already agreed. Tests and a future `--yes` on vacuum use this.
#[derive(Debug, Default, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct Confirmed;

impl Confirm for Confirmed {
    fn confirm(&mut self, _prompt: &str) -> bool {
        true
    }
}

/// Daemon calls for `aw db`. Implementations must not open SQLite.
pub(crate) trait DbApi {
    /// `GET /api/v1/db/stats`.
    ///
    /// # Errors
    ///
    /// A daemon or transport failure. No path with a username.
    fn stats(&mut self) -> Result<DbStatsView, DbApiError>;

    /// `POST /api/v1/db/vacuum`.
    ///
    /// # Errors
    ///
    /// A daemon or transport failure.
    fn vacuum(&mut self) -> Result<String, DbApiError>;

    /// `POST /api/v1/db/migrate`. `dry_run` lists pending migrations.
    ///
    /// # Errors
    ///
    /// A daemon or transport failure.
    fn migrate(&mut self, dry_run: bool) -> Result<MigrateReport, DbApiError>;

    /// `POST /api/v1/db/purge`.
    ///
    /// # Errors
    ///
    /// A daemon or transport failure. The daemon, not this trait, decides
    /// which sessions the caller may delete.
    fn purge(&mut self, body: &PurgeBody) -> Result<PurgeResult, DbApiError>;
}

/// Why a `db` call did not return a document.
///
/// `Failed` and `Forbidden` are returned by a live client. [`UnwiredApi`] only
/// returns `Unreachable`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum DbApiError {
    /// Nothing is listening, or this build has no client.
    Unreachable { detail: String },
    /// The daemon answered, but not with the expected document.
    Failed { detail: String },
    /// Authenticated and refused. Exit 4.
    Forbidden { detail: String },
    /// The local channel could not establish a trustworthy peer identity.
    /// This preserves the fixed IPC failure wording. Exit 4.
    IdentityFailure { detail: String, code: &'static str },
}

impl std::fmt::Display for DbApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable { detail } => write!(f, "{detail}"),
            Self::Failed { detail } => write!(f, "{detail}"),
            Self::Forbidden { detail } => write!(f, "{detail}"),
            Self::IdentityFailure { detail, .. } => write!(f, "{detail}"),
        }
    }
}

/// `GET /db/stats` body. Unknown numbers stay `None`, not zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DbStatsView {
    /// Logical size of the database file plus WAL, bytes.
    pub db_bytes: Option<u64>,
    /// WAL size, when the daemon reported it separately.
    pub wal_bytes: Option<u64>,
    /// Row counts keyed by table name. Absent tables are not invented.
    pub tables: Vec<(String, u64)>,
    /// Public id of the oldest ended session, or unknown.
    pub oldest_session: Option<String>,
    /// When that session ended, Unix nanoseconds.
    pub oldest_ended_ns: Option<i64>,
    /// `retention.max_age_days`.
    pub max_age_days: Option<u64>,
    /// `retention.max_db_bytes` (or the size-mb key converted by the daemon).
    pub max_db_bytes: Option<u64>,
    /// Sessions that are not pinned. Kept so the P1 counts still render.
    ///
    /// `None` when the daemon did not split pinned from unpinned. The text
    /// renderer prints `不可得`; it is not zero.
    pub sessions: Option<u64>,
    /// Pinned sessions. `None` when the daemon did not report the split.
    pub pinned_sessions: Option<u64>,
}

/// One pending or applied migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MigrationStep {
    /// `NNNN` prefix.
    pub version: String,
    /// File name without the directory.
    pub name: String,
    /// `true` when this call did not apply it.
    pub dry_run: bool,
}

/// `POST /db/migrate` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MigrateReport {
    /// Steps, in apply order.
    pub steps: Vec<MigrationStep>,
    /// One-line note when the daemon sent one.
    pub detail: Option<String>,
}

/// JSON body of `POST /db/purge`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PurgeBody {
    /// Duration text, forwarded as the user typed it. `None` for `--all`.
    pub older_than: Option<String>,
    /// `--all`.
    pub all: bool,
}

/// Test client. No socket is opened, and an empty success would claim a vacuum
/// happened. Production uses [`HttpDbApi`].
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct UnwiredApi;

const UNWIRED: &str = "后台数据库 API 未接通；GET /api/v1/db/stats 仍是占位实现，所以此命令不会打开数据库。请先运行 `aw daemon start`，或加 --no-daemon（本地轮询采集，证据 S）";

impl DbApi for UnwiredApi {
    fn stats(&mut self) -> Result<DbStatsView, DbApiError> {
        Err(DbApiError::Unreachable {
            detail: UNWIRED.to_owned(),
        })
    }

    fn vacuum(&mut self) -> Result<String, DbApiError> {
        Err(DbApiError::Unreachable {
            detail: UNWIRED.to_owned(),
        })
    }

    fn migrate(&mut self, _: bool) -> Result<MigrateReport, DbApiError> {
        Err(DbApiError::Unreachable {
            detail: UNWIRED.to_owned(),
        })
    }

    fn purge(&mut self, _: &PurgeBody) -> Result<PurgeResult, DbApiError> {
        Err(DbApiError::Unreachable {
            detail: UNWIRED.to_owned(),
        })
    }
}

/// Production client. `GET /api/v1/db/stats`, `POST /api/v1/db/vacuum`,
/// `POST /api/v1/db/migrate`, `POST /api/v1/db/purge`.
///
/// [`UnwiredApi`] stays for tests. This type is what `execute_args` builds.
pub(crate) struct HttpDbApi {
    endpoint: crate::endpoint::Endpoint,
}

impl HttpDbApi {
    /// Bind to `endpoint`. Does not connect.
    #[must_use]
    pub(crate) fn new(endpoint: crate::endpoint::Endpoint) -> Self {
        Self { endpoint }
    }

    fn call(&self, request: &crate::client::ApiRequest) -> Result<serde_json::Value, DbApiError> {
        let transport = crate::client::LoopbackHttp::new(&self.endpoint).map_err(client_to_db)?;
        let mut client = crate::client::Client::new(self.endpoint.clone(), transport);
        let reply = client.call(request).map_err(client_to_db)?;
        reply.json().ok_or_else(|| DbApiError::Failed {
            detail: "后台返回的响应体不是 JSON".to_owned(),
        })
    }
}

impl DbApi for HttpDbApi {
    fn stats(&mut self) -> Result<DbStatsView, DbApiError> {
        let body = self.call(&crate::client::ApiRequest::get("/api/v1/db/stats"))?;
        if body.get("available") == Some(&serde_json::Value::Bool(false)) {
            let reason = body
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("此调用者无法取得数据库统计");
            return Err(DbApiError::Failed {
                detail: clip_db(reason),
            });
        }
        let tables = match body.get("tables") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(rows)) => rows
                .iter()
                .map(table_count)
                .collect::<Result<Vec<_>, _>>()?,
            Some(_) => {
                return Err(DbApiError::Failed {
                    detail: "字段 `tables` 不是数组".to_owned(),
                });
            }
        };
        let oldest = body.get("oldest_session");
        let (oldest_session, oldest_ended_ns) = match oldest {
            None | Some(serde_json::Value::Null) => (None, None),
            Some(value) => (
                opt_db_string(value, "public_id")?,
                opt_db_i64(value, "ended_ns")?,
            ),
        };
        let retention = body.get("retention");
        let (max_age_days, max_db_bytes) = match retention {
            None | Some(serde_json::Value::Null) => (None, None),
            Some(value) => (
                opt_db_u64(value, "max_age_days")?,
                opt_db_u64(value, "max_db_bytes")?,
            ),
        };
        // The daemon's `sessions` table count is the only count it currently
        // exports. It is a real total even though it is not split by pin state.
        let sessions = tables
            .iter()
            .find(|(name, _)| name == "sessions")
            .map(|(_, rows)| *rows);
        Ok(DbStatsView {
            db_bytes: opt_db_u64(&body, "db_bytes")?,
            wal_bytes: opt_db_u64(&body, "wal_bytes")?,
            tables,
            oldest_session,
            oldest_ended_ns,
            max_age_days,
            max_db_bytes,
            sessions,
            pinned_sessions: None,
        })
    }

    fn vacuum(&mut self) -> Result<String, DbApiError> {
        let body = self.call(&crate::client::ApiRequest::post_json(
            "/api/v1/db/vacuum",
            &json!({}),
        ))?;
        Ok(body
            .get("ok")
            .map(|_| "已记录 vacuum".to_owned())
            .unwrap_or_else(|| "vacuum 响应没有字段 `ok`".to_owned()))
    }

    fn migrate(&mut self, dry_run: bool) -> Result<MigrateReport, DbApiError> {
        let body = self.call(&crate::client::ApiRequest::post_json(
            "/api/v1/db/migrate",
            &json!({ "dry_run": dry_run }),
        ))?;
        // The daemon applies the schema and returns version numbers, not a step
        // list. A missing version is not reported as "no pending migration".
        let mut steps = Vec::new();
        for (key, name) in [
            ("file_schema_version", "file"),
            ("http_schema_version", "http"),
            ("proxy_schema_version", "proxy"),
            ("agent_schema_version", "agent"),
        ] {
            if let Some(version) = body.get(key) {
                let text = match version {
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::String(text) => text.clone(),
                    _ => {
                        return Err(DbApiError::Failed {
                            detail: format!("字段 `{key}` 不是版本号"),
                        });
                    }
                };
                steps.push(MigrationStep {
                    version: text,
                    name: name.to_owned(),
                    dry_run,
                });
            }
        }
        if steps.is_empty() && body.get("steps").is_none() {
            return Err(DbApiError::Failed {
                detail: "后台返回的数据缺少字段 `file_schema_version`".to_owned(),
            });
        }
        Ok(MigrateReport {
            steps,
            detail: opt_db_string(&body, "detail")?,
        })
    }

    fn purge(&mut self, body: &PurgeBody) -> Result<PurgeResult, DbApiError> {
        // The CLI has already confirmed (`--yes` or the prompt); the daemon
        // refuses a purge without `confirm: true`.
        let payload = json!({
            "older_than": body.older_than,
            "all": body.all,
            "confirm": true,
        });
        let value = self.call(&crate::client::ApiRequest::post_json(
            "/api/v1/db/purge",
            &payload,
        ))?;
        let rows = match value.get("purged") {
            Some(serde_json::Value::Array(rows)) => rows,
            Some(_) => {
                return Err(DbApiError::Failed {
                    detail: "字段 `purged` 不是数组".to_owned(),
                });
            }
            None => {
                return Err(DbApiError::Failed {
                    detail: "后台返回的数据缺少字段 `purged`".to_owned(),
                });
            }
        };
        let mut removed = Vec::new();
        for row in rows {
            match row.get("public_id").and_then(serde_json::Value::as_str) {
                Some(text) if !text.is_empty() => removed.push(text.to_owned()),
                _ => {
                    return Err(DbApiError::Failed {
                        detail: "字段 `purged` 的条目缺少 `public_id`".to_owned(),
                    });
                }
            }
        }
        Ok(PurgeResult {
            removed,
            // The daemon does not list the sessions it kept.
            kept: Vec::new(),
        })
    }
}

fn table_count(value: &serde_json::Value) -> Result<(String, u64), DbApiError> {
    let name = value
        .get("table")
        .and_then(serde_json::Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| DbApiError::Failed {
            detail: "字段 `tables` 的条目缺少 `table`".to_owned(),
        })?;
    let rows = opt_db_u64(value, "rows")?.ok_or_else(|| DbApiError::Failed {
        detail: "字段 `tables` 的条目缺少 `rows`".to_owned(),
    })?;
    Ok((name.to_owned(), rows))
}

fn opt_db_string(value: &serde_json::Value, name: &str) -> Result<Option<String>, DbApiError> {
    match value.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) if text.is_empty() => Ok(None),
        Some(serde_json::Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(DbApiError::Failed {
            detail: format!("字段 `{name}` 不是字符串"),
        }),
    }
}

fn opt_db_i64(value: &serde_json::Value, name: &str) -> Result<Option<i64>, DbApiError> {
    match value.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(other) => other.as_i64().map(Some).ok_or_else(|| DbApiError::Failed {
            detail: format!("字段 `{name}` 不是整数"),
        }),
    }
}

fn opt_db_u64(value: &serde_json::Value, name: &str) -> Result<Option<u64>, DbApiError> {
    match value.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(other) => other.as_u64().map(Some).ok_or_else(|| DbApiError::Failed {
            detail: format!("字段 `{name}` 不是整数"),
        }),
    }
}

fn client_to_db(err: crate::client::ClientError) -> DbApiError {
    if let Some(code) = err.identity_failure_code() {
        return DbApiError::IdentityFailure {
            detail: clip_db(&err.to_string()),
            code,
        };
    }
    match &err {
        crate::client::ClientError::Unreachable { .. } => DbApiError::Unreachable {
            detail: clip_db(&err.to_string()),
        },
        crate::client::ClientError::Forbidden { .. }
        | crate::client::ClientError::UntrustedServer { .. }
        | crate::client::ClientError::Status {
            status: 401 | 403, ..
        } => DbApiError::Forbidden {
            detail: clip_db(&err.to_string()),
        },
        crate::client::ClientError::Status { .. }
        | crate::client::ClientError::Transport { .. } => DbApiError::Failed {
            detail: clip_db(&err.to_string()),
        },
    }
}

fn clip_db(text: &str) -> String {
    let mut out: String = text.chars().take(240).collect();
    if text.chars().count() > 240 {
        out.push('…');
    }
    out
}

/// Run one `db` subcommand against the daemon API.
pub(crate) fn run(
    op: DbOp,
    json: bool,
    privilege: &dyn Privilege,
    clock: &dyn Clock,
    api: &mut dyn DbApi,
    confirm: &mut dyn Confirm,
) -> Outcome {
    match op {
        DbOp::Stats => match api.stats() {
            Ok(view) => stats_view_outcome(&view, json),
            Err(err) => api_error(err, json),
        },
        DbOp::Vacuum { yes } => {
            if !yes && !confirm.confirm("将压缩数据库，可能耗时很久。确定吗？[是/否]")
            {
                return super::error_outcome(
                    exit::USAGE,
                    "usage",
                    "现在不在终端里，没法确认删除。确定要删的话，请加上 `--yes`（删除后无法恢复）",
                    json,
                );
            }
            match api.vacuum() {
                Ok(detail) => note("vacuum", &detail, json),
                Err(err) => api_error(err, json),
            }
        }
        DbOp::Migrate { dry_run } => match api.migrate(dry_run) {
            Ok(report) => migrate_outcome(&report, json),
            Err(DbApiError::Forbidden { .. }) => super::error_outcome(
                exit::PERMISSION,
                "permission",
                "需要管理员权限才能迁移数据库",
                json,
            ),
            Err(err) => api_error(err, json),
        },
        DbOp::Purge {
            older_than,
            all,
            yes,
        } => purge_api(
            PurgeArgs {
                older_than: older_than.as_deref(),
                all,
                yes,
                json,
                privilege,
                clock,
            },
            api,
            confirm,
        ),
    }
}

struct PurgeArgs<'a> {
    older_than: Option<&'a str>,
    all: bool,
    yes: bool,
    json: bool,
    privilege: &'a dyn Privilege,
    clock: &'a dyn Clock,
}

fn purge_api(args: PurgeArgs<'_>, api: &mut dyn DbApi, confirm: &mut dyn Confirm) -> Outcome {
    let PurgeArgs {
        older_than,
        all,
        yes,
        json,
        privilege,
        clock,
    } = args;
    if all && older_than.is_some() {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "`db purge` 只能传入 --older-than 或 --all，不能同时传入",
            json,
        );
    }
    if !all && older_than.is_none() {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "`db purge` 需要 --older-than <dur> 或 --all",
            json,
        );
    }
    if let Some(text) = older_than {
        // Validate before asking. A bad duration must not look like a refusal to confirm.
        if let Err(detail) = older_than_cutoff(text, clock.now_ns()) {
            return super::error_outcome(exit::USAGE, "usage", &detail, json);
        }
    }
    if all && !privilege.is_admin() {
        return super::error_outcome(
            exit::PERMISSION,
            "permission",
            "`db purge --all` 需要管理员权限；请在管理员终端或使用 sudo 重新运行",
            json,
        );
    }
    let confirmed = yes || confirm.confirm("将删除 N 个会话，删除后无法恢复。确定吗？[是/否]");
    if !confirmed {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "现在不在终端里，没法确认删除。确定要删的话，请加上 `--yes`（删除后无法恢复）",
            json,
        );
    }
    let body = PurgeBody {
        older_than: older_than.map(str::to_owned),
        all,
    };
    match api.purge(&body) {
        Ok(result) => purge_outcome(&result, json),
        Err(err) => api_error(err, json),
    }
}

fn api_error(err: DbApiError, json: bool) -> Outcome {
    let (code, machine) = match &err {
        DbApiError::Unreachable { .. } => (exit::UNREACHABLE, "unreachable"),
        DbApiError::Forbidden { .. } => (exit::PERMISSION, "permission"),
        DbApiError::IdentityFailure { code, .. } => (exit::PERMISSION, *code),
        DbApiError::Failed { .. } => (exit::GENERAL, "db"),
    };
    super::error_outcome(code, machine, &err.to_string(), json)
}

fn stats_view_outcome(view: &DbStatsView, json: bool) -> Outcome {
    let text = if json {
        let tables: serde_json::Map<String, serde_json::Value> = view
            .tables
            .iter()
            .map(|(name, count)| (name.clone(), serde_json::Value::from(*count)))
            .collect();
        format!(
            "{}\n",
            json!({
                "db_bytes": view.db_bytes,
                "wal_bytes": view.wal_bytes,
                "tables": tables,
                "oldest_session": view.oldest_session,
                "oldest_ended_ns": view.oldest_ended_ns,
                "retention": {
                    "max_age_days": view.max_age_days,
                    "max_db_bytes": view.max_db_bytes,
                },
                "sessions": view.sessions,
                "pinned_sessions": view.pinned_sessions,
            })
        )
    } else {
        let bytes = match view.db_bytes {
            Some(bytes) => bytes.to_string(),
            None => "不可得".to_owned(),
        };
        let sessions = match view.sessions {
            Some(n) => n.to_string(),
            None => "不可得".to_owned(),
        };
        let pinned = match view.pinned_sessions {
            Some(n) => n.to_string(),
            None => "不可得".to_owned(),
        };
        let mut lines =
            format!("db_bytes {bytes}\nsessions {sessions}\npinned_sessions {pinned}\n");
        for (name, count) in &view.tables {
            lines.push_str(&format!("table {name} {count}\n"));
        }
        let oldest = view.oldest_session.as_deref().unwrap_or("不可得");
        lines.push_str(&format!("oldest_session {oldest}\n"));
        let age = match view.max_age_days {
            Some(days) => days.to_string(),
            None => "不可得".to_owned(),
        };
        lines.push_str(&format!("retention.max_age_days {age}\n"));
        lines
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn migrate_outcome(report: &MigrateReport, json: bool) -> Outcome {
    let text = if json {
        format!(
            "{}\n",
            json!({
                "op": "migrate",
                "steps": report.steps.iter().map(|step| json!({
                    "version": step.version,
                    "name": step.name,
                    "dry_run": step.dry_run,
                })).collect::<Vec<_>>(),
                "detail": report.detail,
            })
        )
    } else if report.steps.is_empty() {
        let detail = report.detail.as_deref().unwrap_or("没有待执行的迁移");
        format!("{detail}\n")
    } else {
        let mut lines = String::new();
        for step in &report.steps {
            let mark = if step.dry_run { "pending" } else { "applied" };
            lines.push_str(&format!("{mark} {} {}\n", step.version, step.name));
        }
        lines
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

/// Run one `db` subcommand against a [`DbStore`].
///
/// P1 tests call this. It confirms vacuum itself (the store trait has no
/// prompt) and still requires `--yes` for purge, matching those tests.
#[allow(dead_code)]
pub(crate) fn run_store(
    op: DbOp,
    json: bool,
    privilege: &dyn Privilege,
    clock: &dyn Clock,
    store: &mut dyn DbStore,
) -> Outcome {
    match op {
        DbOp::Stats => stats_outcome(&store.stats(), json),
        DbOp::Vacuum { .. } => match store.vacuum() {
            Ok(detail) => note("vacuum", &detail, json),
            Err(detail) => super::error_outcome(exit::GENERAL, "db", &detail, json),
        },
        DbOp::Migrate { dry_run } => match store.migrate(dry_run) {
            Ok(detail) => note("migrate", &detail, json),
            Err(detail) => super::error_outcome(exit::GENERAL, "db", &detail, json),
        },
        DbOp::Purge {
            older_than,
            all,
            yes,
        } => purge(
            older_than.as_deref(),
            all,
            yes,
            json,
            privilege,
            clock,
            store,
        ),
    }
}

#[allow(dead_code)]
fn purge(
    older_than: Option<&str>,
    all: bool,
    yes: bool,
    json: bool,
    privilege: &dyn Privilege,
    clock: &dyn Clock,
    store: &mut dyn DbStore,
) -> Outcome {
    if all && older_than.is_some() {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "`db purge` 只能传入 --older-than 或 --all，不能同时传入",
            json,
        );
    }
    if !all && older_than.is_none() {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "`db purge` 需要 --older-than <dur> 或 --all",
            json,
        );
    }
    if !yes {
        return super::error_outcome(exit::USAGE, "usage", "`db purge` 需要 --yes", json);
    }
    if all && !privilege.is_admin() {
        return super::error_outcome(
            exit::PERMISSION,
            "permission",
            "`db purge --all` 需要管理员权限；请在管理员终端或使用 sudo 重新运行",
            json,
        );
    }
    let request = if all {
        PurgeRequest::All
    } else {
        let Some(text) = older_than else {
            return super::error_outcome(
                exit::USAGE,
                "usage",
                "`db purge` 需要 --older-than <dur> 或 --all",
                json,
            );
        };
        let cutoff = match older_than_cutoff(text, clock.now_ns()) {
            Ok(cutoff) => cutoff,
            Err(detail) => return super::error_outcome(exit::USAGE, "usage", &detail, json),
        };
        PurgeRequest::OlderThan {
            ended_before_ns: cutoff,
        }
    };
    match store.purge(&request) {
        Ok(result) => purge_outcome(&result, json),
        Err(detail) => super::error_outcome(exit::GENERAL, "db", &detail, json),
    }
}

/// Cutoff for `--older-than`. The store drops rows with `ended_ns <= cutoff`.
/// `0s` is `now_ns + 1`, so a session that ended at this instant is included
/// and one that ends later is not. A still-running session has no `ended_ns`
/// and is never selected. A longer duration is subtracted from `now_ns`, then
/// the same one nanosecond is added. An RFC 3339 value is not converted (this
/// crate has no time parser that yields nanoseconds) and is rejected rather
/// than treated as zero.
pub(crate) fn older_than_cutoff(text: &str, now_ns: i64) -> Result<i64, String> {
    let arg = parse_time(text)?;
    match arg {
        TimeArg::BeforeNow(duration) | TimeArg::FromSessionStart(duration) => {
            let delta = duration_ns(duration)?;
            Ok(now_ns.saturating_sub(delta).saturating_add(1))
        }
        TimeArg::Rfc3339(_) => {
            Err("`--older-than` 需要 0s 或 30d 这样的时长，不能是绝对时间".to_owned())
        }
    }
}

fn duration_ns(duration: DurationArg) -> Result<i64, String> {
    let count = i64::try_from(duration.count).map_err(|_| "时长超出 i64 范围".to_owned())?;
    let unit: i64 = match duration.unit {
        TimeUnit::Millis => 1_000_000,
        TimeUnit::Seconds => 1_000_000_000,
        TimeUnit::Minutes => 60 * 1_000_000_000,
        TimeUnit::Hours => 60 * 60 * 1_000_000_000,
        TimeUnit::Days => 24 * 60 * 60 * 1_000_000_000,
    };
    count
        .checked_mul(unit)
        .ok_or_else(|| "时长换算为纳秒时溢出".to_owned())
}

#[allow(dead_code)]
fn stats_outcome(stats: &DbStats, json: bool) -> Outcome {
    let text = if json {
        format!(
            "{}\n",
            json!({
                "db_bytes": stats.db_bytes,
                "sessions": stats.sessions,
                "pinned_sessions": stats.pinned_sessions,
            })
        )
    } else {
        let bytes = match stats.db_bytes {
            Some(bytes) => bytes.to_string(),
            None => "不可得".to_owned(),
        };
        format!(
            "db_bytes {bytes}\nsessions {}\npinned_sessions {}\n",
            stats.sessions, stats.pinned_sessions
        )
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn purge_outcome(result: &PurgeResult, json: bool) -> Outcome {
    let text = if json {
        format!(
            "{}\n",
            json!({
                "removed": result.removed,
                "kept": result.kept,
                "sessions": result.kept.iter().filter(|_| true).count(),
            })
        )
    } else {
        format!(
            "removed {}\nkept {}\n",
            result.removed.len(),
            result.kept.len()
        )
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

fn note(op: &str, detail: &str, json: bool) -> Outcome {
    let text = if json {
        format!("{}\n", json!({ "op": op, "detail": detail }))
    } else {
        format!("{detail}\n")
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{run_store, Clock, DbOp, DbStats, DbStore, FixedClock, PurgeRequest, PurgeResult};
    use crate::cmd::daemon::Privilege;
    use crate::exit;

    /// One session the stub store knows about. No username, no hostname.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct SessionRow {
        /// Public id.
        public_id: String,
        /// Ended, Unix nanoseconds. `None` means still active.
        ended_ns: Option<i64>,
        /// Pinned sessions are excluded from purge.
        pinned: bool,
    }

    /// Apply a purge to an in-memory session list. Pinned and active rows stay.
    fn purge_rows(rows: &mut Vec<SessionRow>, request: &PurgeRequest) -> PurgeResult {
        let mut removed = Vec::new();
        let mut kept = Vec::new();
        let mut next = Vec::new();
        for row in rows.drain(..) {
            let drop_it = match request {
                PurgeRequest::All => row.ended_ns.is_some() && !row.pinned,
                PurgeRequest::OlderThan { ended_before_ns } => {
                    // Inclusive. `0s` is `now`, and a session that ended at exactly
                    // now is already over. `ended_ns: None` is still running, not
                    // zero, and stays.
                    matches!(row.ended_ns, Some(ended) if ended <= *ended_before_ns) && !row.pinned
                }
            };
            if drop_it {
                removed.push(row.public_id);
            } else {
                kept.push(row.public_id.clone());
                next.push(row);
            }
        }
        *rows = next;
        PurgeResult { removed, kept }
    }

    /// In-memory store. Tests use this to assert purge arguments and the remaining
    /// session count.
    #[derive(Debug, Clone)]
    struct MemoryDb {
        /// Sessions currently stored.
        sessions: Vec<SessionRow>,
        /// Purge requests in call order.
        purges: Vec<PurgeRequest>,
        /// Logical size. `None` means unknown, not zero.
        db_bytes: Option<u64>,
    }

    impl MemoryDb {
        /// Store `sessions` and no size.
        fn with_sessions(sessions: Vec<SessionRow>) -> Self {
            Self {
                sessions,
                purges: Vec::new(),
                db_bytes: None,
            }
        }

        /// Counts after the last purge.
        fn counts(&self) -> DbStats {
            let pinned_sessions = self.sessions.iter().filter(|row| row.pinned).count() as u64;
            let sessions = (self.sessions.len() as u64).saturating_sub(pinned_sessions);
            DbStats {
                db_bytes: self.db_bytes,
                sessions,
                pinned_sessions,
            }
        }
    }

    impl DbStore for MemoryDb {
        fn stats(&self) -> DbStats {
            self.counts()
        }

        fn vacuum(&mut self) -> Result<String, String> {
            Ok("vacuum recorded".to_owned())
        }

        fn migrate(&mut self, dry_run: bool) -> Result<String, String> {
            if dry_run {
                Ok("migrate --dry-run recorded; nothing written".to_owned())
            } else {
                Ok("migrate recorded".to_owned())
            }
        }

        fn purge(&mut self, request: &PurgeRequest) -> Result<PurgeResult, String> {
            self.purges.push(request.clone());
            Ok(purge_rows(&mut self.sessions, request))
        }
    }

    struct Admin(bool);

    impl Privilege for Admin {
        fn is_admin(&self) -> bool {
            self.0
        }
    }

    fn clock() -> FixedClock {
        FixedClock(1_000_000_000_000)
    }

    fn sample() -> MemoryDb {
        MemoryDb::with_sessions(vec![
            SessionRow {
                public_id: "s-old".to_owned(),
                ended_ns: Some(1),
                pinned: false,
            },
            SessionRow {
                public_id: "s-new".to_owned(),
                ended_ns: Some(clock().now_ns().saturating_add(1)),
                pinned: false,
            },
            SessionRow {
                public_id: "s-pin".to_owned(),
                ended_ns: Some(1),
                pinned: true,
            },
            SessionRow {
                public_id: "s-live".to_owned(),
                ended_ns: None,
                pinned: false,
            },
        ])
    }

    #[test]
    fn purge_older_than_zero_drops_ended_and_keeps_pinned() {
        let mut store = sample();
        let outcome = run_store(
            DbOp::Purge {
                older_than: Some("0s".to_owned()),
                all: false,
                yes: true,
            },
            true,
            &Admin(false),
            &clock(),
            &mut store,
        );
        assert_eq!(
            outcome.code,
            exit::OK,
            "{}",
            String::from_utf8_lossy(&outcome.stderr)
        );
        assert_eq!(
            store.purges,
            vec![PurgeRequest::OlderThan {
                ended_before_ns: clock().now_ns().saturating_add(1),
            }]
        );
        let stats = store.stats();
        assert_eq!(stats.sessions, 1, "only the still-active session remains");
        assert_eq!(stats.pinned_sessions, 1);
        let ids: Vec<_> = store
            .sessions
            .iter()
            .map(|row| row.public_id.as_str())
            .collect();
        assert!(ids.contains(&"s-pin"));
        assert!(ids.contains(&"s-live"));
        assert!(!ids.contains(&"s-old"));
        assert!(!ids.contains(&"s-new"));
    }

    #[test]
    fn purge_all_without_admin_is_exit_4() {
        let mut store = sample();
        let outcome = run_store(
            DbOp::Purge {
                older_than: None,
                all: true,
                yes: true,
            },
            false,
            &Admin(false),
            &clock(),
            &mut store,
        );
        assert_eq!(outcome.code, exit::PERMISSION);
        let err = String::from_utf8(outcome.stderr).expect("utf8");
        assert!(
            err.contains("sudo") || err.contains("administrator"),
            "{err}"
        );
        assert!(store.purges.is_empty());
        assert_eq!(store.sessions.len(), 4);
    }

    #[test]
    fn purge_all_with_admin_leaves_only_pinned_and_active() {
        let mut store = sample();
        let outcome = run_store(
            DbOp::Purge {
                older_than: None,
                all: true,
                yes: true,
            },
            false,
            &Admin(true),
            &clock(),
            &mut store,
        );
        assert_eq!(outcome.code, exit::OK);
        assert_eq!(store.purges, vec![PurgeRequest::All]);
        assert_eq!(store.stats().sessions, 1);
        assert_eq!(store.stats().pinned_sessions, 1);
    }

    #[test]
    fn stats_reports_the_stub_counts() {
        let mut store = MemoryDb::with_sessions(vec![SessionRow {
            public_id: "s-pin".to_owned(),
            ended_ns: Some(1),
            pinned: true,
        }]);
        let outcome = run_store(DbOp::Stats, true, &Admin(false), &clock(), &mut store);
        assert_eq!(outcome.code, exit::OK);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        let value: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert_eq!(value["sessions"], 0);
        assert_eq!(value["pinned_sessions"], 1);
        assert!(value["db_bytes"].is_null());
    }
}
