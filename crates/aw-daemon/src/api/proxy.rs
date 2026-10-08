//! Proxy CA routes (P3-PROXY-01).
//!
//! The handler does not hold a private key. It formats a [`aw_proxy::CaInfo`]
//! the caller already produced. `trust` returns the plan and a schema_meta
//! record; it does not install a certificate.

use serde_json::{json, Value};

use aw_proxy::CaInfo;

/// JSON for `GET /api/v1/proxy/ca`. Fingerprint and times only.
#[must_use]
pub fn ca_info_body(info: &CaInfo) -> Value {
    json!({
        "fingerprint": info.fingerprint.as_str(),
        "not_before_unix": info.not_before_unix,
        "not_after_unix": info.not_after_unix,
        "protected": info.protected,
        "unprotected_reason": info.unprotected_reason,
        "retired_in_use": info.retired_in_use,
    })
}

/// One row the store would put in `schema_meta` after a confirmed trust action.
///
/// This module does not open the database. The caller persists `record`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRecord {
    /// `proxy.ca.trust` or `proxy.ca.untrust`.
    pub key: &'static str,
    /// `user`.
    pub scope: &'static str,
    /// SHA-256 fingerprint, when the caller has one. `None` if no CA is loaded.
    pub fingerprint: Option<String>,
}

/// Plan returned by `POST /api/v1/proxy/trust`. `installed` is always false.
pub fn trust_plan(
    user: bool,
    confirm: bool,
    fingerprint: Option<&str>,
) -> Result<(Value, TrustRecord), &'static str> {
    if !user {
        return Err("trust requires scope=user; the system store is not a target");
    }
    if !confirm {
        return Err("trust requires confirm=true; no certificate store is modified");
    }
    let record = TrustRecord {
        key: "proxy.ca.trust",
        scope: "user",
        fingerprint: fingerprint.map(str::to_owned),
    };
    let body = json!({
        "action": "trust",
        "scope": "user",
        "installed": false,
        "schema_meta": {
            "key": record.key,
            "fingerprint": record.fingerprint,
        },
        "note": "recorded only; certutil, security, and update-ca-certificates are not invoked",
    });
    Ok((body, record))
}

/// Plan for `POST /api/v1/proxy/untrust`. Same rule: confirm, then record.
pub fn untrust_plan(
    confirm: bool,
    fingerprint: Option<&str>,
) -> Result<(Value, TrustRecord), &'static str> {
    if !confirm {
        return Err("untrust requires confirm=true; no certificate store is modified");
    }
    let record = TrustRecord {
        key: "proxy.ca.untrust",
        scope: "user",
        fingerprint: fingerprint.map(str::to_owned),
    };
    let body = json!({
        "action": "untrust",
        "scope": "user",
        "installed": false,
        "schema_meta": {
            "key": record.key,
            "fingerprint": record.fingerprint,
        },
    });
    Ok((body, record))
}

/// `aw daemon uninstall` step: delete the CA directory and list trust records
/// the operator once confirmed. This function does not delete files. The caller
/// passes the records it loaded and receives the same list back as the cleanup
/// set. An empty list means nothing was installed by a confirmed `trust`.
#[must_use]
pub fn uninstall_cleanup(records: &[TrustRecord]) -> Vec<TrustRecord> {
    records
        .iter()
        .filter(|row| row.key == "proxy.ca.trust")
        .cloned()
        .collect()
}
