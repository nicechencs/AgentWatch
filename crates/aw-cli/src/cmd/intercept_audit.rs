//! Deliver one intercept audit record (P5-SEC-01, design §5.4).
//!
//! Order: `POST /api/v1/agent/intercept`, then a local jsonl line. The local
//! file is `AW_INTERCEPT_AUDIT` when that variable is set, otherwise
//! `<session dir>/intercept-audit.jsonl` when the caller has a session
//! directory, otherwise a file next to the policy is not invented: with no
//! path at all the delivery is [`Delivered::Dropped`].
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
    if let Ok(mut file) = fs::File::open("/dev/urandom") {
        use std::io::Read;
        if file.read_exact(bytes).is_ok() {
            return;
        }
    }
    // No urandom (or a short read). Mix the clock and the pid. Weaker than
    // urandom, still not a compile-time constant.
    let ticks = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mixed = ticks ^ (u128::from(std::process::id()) << 64);
    for (index, byte) in bytes.iter_mut().enumerate() {
        let shift = (index % 16) * 8;
        *byte = (mixed >> shift) as u8 ^ (index as u8).wrapping_mul(31);
    }
}

/// Where a record went, and whether a rewrite must be downgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuditDelivery {
    pub delivered: Delivered,
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
            };
        }
    }
    if backed_up {
        record.delivered = Some(Delivered::LocalBackup);
        return AuditDelivery {
            delivered: Delivered::LocalBackup,
        };
    }
    record.delivered = Some(Delivered::Dropped);
    AuditDelivery {
        delivered: Delivered::Dropped,
    }
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

fn post_daemon(endpoint: &Endpoint, record: &AuditRecord, timeout: Duration) -> bool {
    let Ok(mut transport) = LoopbackHttp::new(endpoint) else {
        return false;
    };
    transport.set_timeout(timeout);
    let body = record_json(record, Delivered::Daemon);
    let request = ApiRequest::post_json("/api/v1/agent/intercept", &body);
    let mut client = Client::new(endpoint.clone(), transport);
    client.call(&request).is_ok()
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
    fn dropped_rewrite_becomes_deny() {
        let delivery = AuditDelivery {
            delivered: Delivered::Dropped,
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
