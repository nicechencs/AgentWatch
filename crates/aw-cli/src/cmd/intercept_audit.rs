//! Deliver one intercept audit record (P5-SEC-01, design §5.4).
//!
//! Order: a local jsonl line, then `POST /api/v1/agent/intercept`. The local
//! file is `AW_INTERCEPT_AUDIT` when that variable is set, otherwise
//! `<session dir>/intercept-audit.jsonl`. The session directory is
//! `<state home>/agentwatch/sessions/<id>`: Linux and macOS use
//! `XDG_STATE_HOME` or `$HOME/.local/state`, Windows uses `LOCALAPPDATA`.
//! With no path at all the delivery is [`Delivered::Dropped`].
//!
//! The jsonl line is the redacted record. It does not contain the original
//! command or URL. The file is created mode `0o600` on Unix.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use aw_pipeline::{Action, AuditRecord, Decision, Delivered, Layer, Subject};
use serde_json::{json, Value};

use crate::client::{ApiRequest, Client, LoopbackHttp};
use crate::endpoint::Endpoint;

/// `AW_INTERCEPT_AUDIT`. A file path, not a directory.
pub(crate) const AUDIT_ENV: &str = "AW_INTERCEPT_AUDIT";

/// Process-local salt used when the caller has no session id.
///
/// A session id is the salt when one exists, so two processes auditing the
/// same session hash the same command the same way. With no session, a fixed
/// salt would let anyone with the binary dictionary-match `before_hash`.
/// This value is 32 random bytes, generated once per process. It is not
/// written next to the hash. Restarting the process changes it, so hashes
/// from two runs without a session are not comparable. That is the point.
pub(crate) fn process_salt() -> &'static [u8] {
    static SALT: OnceLock<[u8; 32]> = OnceLock::new();
    SALT.get_or_init(|| {
        let mut bytes = [0_u8; 32];
        fill_random(&mut bytes);
        bytes
    })
}

fn fill_random(bytes: &mut [u8]) {
    if read_urandom(bytes) {
        return;
    }
    // Windows has no `/dev/urandom`. `RandomState` takes its seed from the OS
    // random source on every platform the standard library supports. The clock
    // and pid are mixed in so two seeds that happened to match still differ.
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let ticks = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mixed = ticks ^ (u128::from(std::process::id()) << 64);
    for (index, chunk) in bytes.chunks_mut(8).enumerate() {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u128(mixed);
        hasher.write_usize(index);
        let word = hasher.finish().to_le_bytes();
        let n = chunk.len().min(word.len());
        chunk[..n].copy_from_slice(&word[..n]);
    }
}

/// `true` when `/dev/urandom` filled `bytes`. A short read is a failure.
fn read_urandom(bytes: &mut [u8]) -> bool {
    let Ok(mut file) = fs::File::open("/dev/urandom") else {
        return false;
    };
    use std::io::Read;
    file.read_exact(bytes).is_ok()
}

/// Where a record went, and whether a rewrite must be downgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuditDelivery {
    pub delivered: Delivered,
    /// The daemon answered `stored: true` for the row as posted.
    ///
    /// Distinct from [`Delivered::Daemon`]: a local backup that also reached
    /// the daemon is `Daemon` too, and this says the database has the row.
    /// A later downgrade has to correct that row, because it says the rewrite
    /// happened. `stored: false` (no database) leaves this false.
    pub daemon_stored: bool,
    /// The client did not see a `stored: true` before its own deadline.
    ///
    /// The daemon may still have the row: a slow write answers after the
    /// client gave up. A rewrite is refused in that case, and the row that
    /// says `rewrite` needs [`correct_delivered`].
    pub client_unconfirmed: bool,
}

impl AuditDelivery {
    /// A rewrite whose audit could not be stored becomes a deny (design §5.3).
    #[must_use]
    pub fn downgrade_rewrite(self, decision: &Decision) -> Decision {
        if self.delivered != Delivered::Dropped || decision.effective != Action::Rewrite {
            return decision.clone();
        }
        let mut next = decision.clone();
        next.effective = Action::Deny;
        next.downgraded = true;
        next.fields.clear();
        let extra = "审计写不进去，改写已改为拒绝";
        next.reason = Some(match decision.reason.as_deref() {
            Some(text) if !text.is_empty() => format!("{text}（{extra}）"),
            _ => extra.to_owned(),
        });
        next
    }
}

/// Write the local backup first, then try the daemon.
///
/// The hook has 200 ms. A daemon that is not listening must not eat that
/// budget and then fail the backup too: a rewrite with nowhere to record
/// becomes a deny. The local line is the durable copy. A later daemon post
/// is best-effort and, when it works, is what the operator queries. Both
/// copies existing is one decision recorded twice only if a collector later
/// ingests the file; step 1 does not ingest the file back. `delivered` on
/// the daemon row is `daemon` when the post worked, otherwise the backup
/// line says `local_backup`.
///
/// `endpoint` `None` skips the daemon attempt.
pub(crate) fn deliver(
    endpoint: Option<&Endpoint>,
    backup: Option<&Path>,
    record: &mut AuditRecord,
    timeout: Duration,
) -> AuditDelivery {
    let backed_up = backup.is_some_and(|path| append_backup(path, record));
    if let Some(endpoint) = endpoint {
        if post_daemon(endpoint, record, timeout) {
            record.delivered = Some(Delivered::Daemon);
            return AuditDelivery {
                delivered: Delivered::Daemon,
                daemon_stored: true,
                client_unconfirmed: false,
            };
        }
    }
    if backed_up {
        record.delivered = Some(Delivered::LocalBackup);
        return AuditDelivery {
            delivered: Delivered::LocalBackup,
            daemon_stored: false,
            // The local line is stored (design §5.3). A daemon that did not
            // confirm does not un-store it, so the rewrite still runs.
            client_unconfirmed: false,
        };
    }
    record.delivered = Some(Delivered::Dropped);
    AuditDelivery {
        delivered: Delivered::Dropped,
        daemon_stored: false,
        client_unconfirmed: endpoint.is_some(),
    }
}

/// The caller stored `posted` and then could not perform it.
///
/// A rewrite whose audit post timed out, or whose fields could not be written
/// back, is refused. The row already in the daemon (or the local line) still
/// says `effective_action = rewrite`, which is not what ran. Append one line
/// for the decision that did run. A reader that takes the last line for this
/// decision sees the refusal.
///
/// Posted again, once. The first post is what ran out of time, and the row it
/// left says `rewrite`. This one says what ran. A slow daemon can miss it too;
/// the local line is the copy that does not depend on that. `true` when either
/// copy was written.
pub(crate) fn correct_delivered(
    backup: Option<&Path>,
    endpoint: Option<&Endpoint>,
    posted: &AuditRecord,
    actual: &Decision,
) -> bool {
    // Keep the posted row's subject, summary, and hash. Rebuilding them would
    // hash an empty string and disagree with the row already stored. A
    // downgraded rewrite has no `after`: nothing was rewritten.
    let mut corrected = posted.clone();
    corrected.action = actual.action.as_str().to_owned();
    corrected.effective_action = actual.effective.as_str().to_owned();
    corrected.downgraded = actual.downgraded;
    corrected.reason = actual.reason.clone();
    corrected.after_summary = None;
    corrected.after_hash = None;
    let local = backup.is_some_and(|path| append_backup(path, &corrected));
    let daemon = endpoint
        .is_some_and(|endpoint| post_daemon(endpoint, &corrected, Duration::from_millis(50)));
    local || daemon
}

/// Backup path: `AW_INTERCEPT_AUDIT`, else `<session_dir>/intercept-audit.jsonl`.
pub(crate) fn backup_path(env_path: Option<&Path>, session_dir: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = env_path {
        if !path.as_os_str().is_empty() {
            return Some(path.to_path_buf());
        }
    }
    session_dir.map(|dir| dir.join("intercept-audit.jsonl"))
}

/// State directory for one platform.
///
/// Linux and macOS use `XDG_STATE_HOME` when it is non-empty, otherwise
/// `$HOME/.local/state`. Windows uses `LOCALAPPDATA` only. An empty input is
/// unset. This does not create the directory.
pub(crate) fn state_home(
    os: &str,
    local_app_data: Option<&Path>,
    xdg_state: Option<&Path>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    fn nonempty(path: Option<&Path>) -> Option<&Path> {
        path.filter(|path| !path.as_os_str().is_empty())
    }
    if os == "windows" {
        return nonempty(local_app_data).map(Path::to_path_buf);
    }
    if let Some(state) = nonempty(xdg_state) {
        return Some(state.to_path_buf());
    }
    nonempty(home).map(|dir| dir.join(".local").join("state"))
}

/// `<state home>/agentwatch/sessions/<id>`, or `None` when there is no session
/// or the id is not a single path component.
///
/// `.`, `..`, a separator, or a NUL would write the backup outside the session
/// directory. Those ids are refused. Anything else is one component, including
/// a public id that contains `-`.
pub(crate) fn session_audit_dir(
    session: Option<&str>,
    state_home: Option<&Path>,
) -> Option<PathBuf> {
    let state = state_home.filter(|path| !path.as_os_str().is_empty())?;
    let id = session.map(str::trim).filter(|id| !id.is_empty())?;
    if id == "." || id == ".." || id.bytes().any(|byte| byte == b'/' || byte == b'\\' || byte == 0)
    {
        return None;
    }
    Some(state.join("agentwatch").join("sessions").join(id))
}

/// Session directory for this process: [`session_audit_dir`] plus the
/// platform's state home from the environment.
pub(crate) fn current_session_dir(session: Option<&str>) -> Option<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let xdg = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    session_audit_dir(
        session,
        state_home(
            std::env::consts::OS,
            local.as_deref(),
            xdg.as_deref(),
            home.as_deref(),
        )
        .as_deref(),
    )
}

fn post_daemon(endpoint: &Endpoint, record: &AuditRecord, timeout: Duration) -> bool {
    let Ok(mut transport) = LoopbackHttp::new(endpoint) else {
        return false;
    };
    transport.set_timeout(timeout);
    let body = record_json(record, Delivered::Daemon);
    let request = ApiRequest::post_json("/api/v1/agent/intercept", &body);
    let mut client = Client::new(endpoint.clone(), transport);
    match client.call(&request) {
        Ok(reply) => body_says_stored(&reply.body),
        Err(_) => false,
    }
}

/// `true` when the daemon's body says the row was written.
///
/// A 200 with `{"stored": false}` means the database is not open. The status
/// alone used to count as delivered, so a rewrite went ahead with nothing
/// stored. A body that is not JSON, or that omits `stored`, is also not a
/// stored row: this route's success body always says `stored: true`.
fn body_says_stored(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("stored").and_then(Value::as_bool))
        == Some(true)
}

fn append_backup(path: &Path, record: &AuditRecord) -> bool {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && fs::create_dir_all(parent).is_err() {
            return false;
        }
    }
    let mut file = match OpenOptions::new().create(true).append(true).open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }
    let mut line = match serde_json::to_vec(&record_json(record, Delivered::LocalBackup)) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    line.push(b'\n');
    file.write_all(&line).is_ok()
}

fn record_json(record: &AuditRecord, delivered: Delivered) -> Value {
    json!({
        "session": record.session,
        "agent": record.agent,
        "layer": record.layer,
        "event": record.event,
        "rule_id": record.rule_id,
        "action": record.action,
        "effective_action": record.effective_action,
        "tool": record.tool,
        "host": record.host,
        "mcp_method": record.mcp_method,
        "before_summary": record.before_summary,
        "before_hash": record.before_hash,
        "after_summary": record.after_summary,
        "after_hash": record.after_hash,
        "reason": record.reason,
        "evidence": record.evidence,
        "source": record.source,
        "delivered": delivered.as_str(),
        "downgraded": record.downgraded,
    })
}

/// Build the record the design asks for. `session` is filled by the caller
/// because [`aw_pipeline::audit_record`] does not know it.
pub(crate) fn record_for(
    subject: &Subject,
    decision: &Decision,
    salt: &[u8],
    original: &str,
    rewritten: Option<&str>,
    session: Option<&str>,
) -> AuditRecord {
    let mut record = aw_pipeline::audit_record(subject, decision, salt, original, rewritten);
    record.session = session.map(str::to_owned);
    let _ = Layer::Hook;
    record
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aw_pipeline::{Action, Decision, Layer, Phase};

    fn decision(action: Action) -> Decision {
        Decision {
            rule_id: Some("r".to_owned()),
            action,
            effective: action,
            downgraded: false,
            reason: Some("原因".to_owned()),
            fields: vec![("command".to_owned(), "terraform plan".to_owned())],
        }
    }

    #[test]
    fn process_salt_is_not_zero_and_differs_from_an_empty_salt() {
        let salt = process_salt();
        assert_eq!(salt.len(), 32);
        assert!(salt.iter().any(|byte| *byte != 0), "salt is all zeros");
        let subject = Subject {
            layer: Layer::Hook,
            agent: Some("claude-code".to_owned()),
            tool: Some("Bash".to_owned()),
            phase: Phase::Pre,
            ..Subject::default()
        };
        let original = "rm -rf /tmp/x";
        let with_salt = record_for(
            &subject,
            &decision(Action::Deny),
            salt,
            original,
            None,
            None,
        );
        let empty = record_for(&subject, &decision(Action::Deny), b"", original, None, None);
        assert_ne!(with_salt.before_hash, empty.before_hash);
        assert_eq!(
            empty.before_hash,
            aw_pipeline::hash_original(b"", original.as_bytes())
        );
    }

    /// The daemon answered 200 and `stored: false` (no database). That used to
    /// count as delivered, so the rewrite ran with no row. It is a drop.
    #[test]
    fn stored_false_is_not_delivered() {
        assert!(!body_says_stored(
            br#"{"stored":false,"storage":"not_ready"}"#
        ));
        assert!(!body_says_stored(br#"{"accepted":0}"#));
        assert!(!body_says_stored(b"not json"));
        assert!(body_says_stored(br#"{"stored":true}"#));
    }

    /// A rewrite the daemon did store, which the caller then had to refuse
    /// (the post outran the hook budget, or the bytes could not be written
    /// back). The row already says `rewrite`. Appending the downgraded record
    /// is what a later reader sees last, and it says `deny`.
    #[test]
    fn downgraded_rewrite_appends_a_deny_line() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("audit-tests")
            .join(format!("downgrade-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("intercept-audit.jsonl");
        let subject = Subject {
            layer: Layer::Hook,
            agent: Some("claude-code".to_owned()),
            tool: Some("Bash".to_owned()),
            event: Some("PreToolUse".to_owned()),
            command: Some("terraform apply".to_owned()),
            phase: Phase::Pre,
            ..Subject::default()
        };
        let mut record = record_for(
            &subject,
            &decision(Action::Rewrite),
            b"salt",
            "terraform apply",
            Some("terraform plan"),
            Some("s-1"),
        );
        // Pretend the daemon post already landed this rewrite. The caller then
        // finds it cannot perform the rewrite and downgrades.
        record.delivered = Some(Delivered::Daemon);
        let downgraded = AuditDelivery {
            delivered: Delivered::Dropped,
            daemon_stored: true,
            client_unconfirmed: true,
        }
        .downgrade_rewrite(&decision(Action::Rewrite));
        assert!(correct_delivered(
            Some(path.as_path()),
            None,
            &record,
            &downgraded
        ));
        let text = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
        assert_eq!(lines.len(), 1, "{text}");
        let row: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(row["effective_action"], json!("deny"), "{row}");
        assert_eq!(row["action"], json!("rewrite"), "{row}");
        assert_eq!(row["downgraded"], json!(true), "{row}");
        assert_eq!(row["delivered"], json!("local_backup"), "{row}");
        assert!(row["after_summary"].is_null(), "{row}");
        assert_eq!(row["session"], json!("s-1"), "{row}");
        let _ = fs::remove_dir_all(&dir);
    }

    /// No `AW_INTERCEPT_AUDIT`: the backup is
    /// `<state>/agentwatch/sessions/<id>/intercept-audit.jsonl`.
    ///
    /// Linux and macOS take `XDG_STATE_HOME`, else `$HOME/.local/state`.
    /// Windows takes `LOCALAPPDATA` and ignores the other two. A session id
    /// that is empty, `.`, `..`, or contains a separator is not a directory.
    #[test]
    fn session_backup_lands_in_the_session_directory() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target");
        let state = root.join("audit-tests").join("state-home");
        let home = root.join("audit-tests").join("home");
        let local = root.join("audit-tests").join("local-app");

        assert_eq!(
            state_home("linux", None, Some(&state), Some(&home)).as_deref(),
            Some(state.as_path())
        );
        assert_eq!(
            state_home("macos", None, None, Some(&home)).as_deref(),
            Some(home.join(".local").join("state").as_path())
        );
        assert_eq!(
            state_home("windows", Some(&local), Some(&state), Some(&home)).as_deref(),
            Some(local.as_path())
        );
        assert!(state_home("windows", None, Some(&state), Some(&home)).is_none());
        assert_eq!(
            state_home("linux", None, Some(Path::new("")), Some(&home)).as_deref(),
            Some(home.join(".local").join("state").as_path()),
            "an empty XDG_STATE_HOME is unset and falls back to HOME"
        );
        assert!(state_home("linux", None, None, None).is_none());

        let dir = session_audit_dir(Some("s-public"), Some(&state)).expect("session dir");
        assert_eq!(
            dir,
            state.join("agentwatch").join("sessions").join("s-public")
        );
        assert_eq!(
            backup_path(None, Some(&dir)).as_deref(),
            Some(dir.join("intercept-audit.jsonl").as_path())
        );
        for bad in ["", ".", "..", "../x", "a/b", "a\\b", "a\0b"] {
            assert!(
                session_audit_dir(Some(bad), Some(&state)).is_none(),
                "session id {bad:?} was accepted"
            );
        }
        assert!(session_audit_dir(None, Some(&state)).is_none());
        assert!(session_audit_dir(Some("s-public"), None).is_none());

        let scratch = root.join("audit-tests").join(format!(
            "mode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&scratch);
        let out = scratch.join("intercept-audit.jsonl");
        let subject = Subject {
            layer: Layer::Hook,
            agent: Some("claude-code".to_owned()),
            tool: Some("Bash".to_owned()),
            phase: Phase::Pre,
            ..Subject::default()
        };
        let mut record = record_for(
            &subject,
            &decision(Action::Deny),
            b"salt",
            "true",
            None,
            Some("s-public"),
        );
        let delivery = deliver(None, Some(&out), &mut record, Duration::from_millis(10));
        assert_eq!(delivery.delivered, Delivered::LocalBackup);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&out).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "backup file mode is {mode:o}");
        }
        let _ = fs::remove_dir_all(&scratch);
    }

    #[test]
    fn dropped_rewrite_becomes_deny() {
        let delivery = AuditDelivery {
            delivered: Delivered::Dropped,
            daemon_stored: false,
            client_unconfirmed: true,
        };
        let next = delivery.downgrade_rewrite(&decision(Action::Rewrite));
        assert_eq!(next.effective, Action::Deny);
        assert!(next.downgraded);
        assert!(next.fields.is_empty());
        assert!(next.reason.unwrap().contains("拒绝"));
    }

    #[test]
    fn backup_keeps_redacted_text_only() {
        let dir = std::env::temp_dir().join(format!("aw-audit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("intercept-audit.jsonl");
        let subject = Subject {
            layer: Layer::Hook,
            agent: Some("claude-code".to_owned()),
            tool: Some("Bash".to_owned()),
            event: Some("PreToolUse".to_owned()),
            command: Some("echo sk-abcdefghijklmnopqrstuvwxyz".to_owned()),
            phase: Phase::Pre,
            ..Subject::default()
        };
        let original = "echo sk-abcdefghijklmnopqrstuvwxyz";
        let mut record = record_for(
            &subject,
            &decision(Action::Deny),
            b"salt",
            original,
            None,
            Some("s-1"),
        );
        let delivery = deliver(None, Some(&path), &mut record, Duration::from_millis(10));
        assert_eq!(delivery.delivered, Delivered::LocalBackup);
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("sk-abcdefghijklmnopqrstuvwxyz"));
        assert!(text.contains("redacted"));
        assert!(text.contains("\"delivered\":\"local_backup\""));
        let _ = fs::remove_dir_all(&dir);
    }
}
