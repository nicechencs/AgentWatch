//! Explicit MITM proxy (P3-PROXY-01..03).
//!
//! The CA, the per-session loopback listener, and the environment injection are
//! real. The TLS intercept is not: `hudsucker`, `hyper`, and `tokio` are not in
//! the lock file, so [`server::ProxyBackend`] is the seam a later backend fills.
//! [`server::MetadataBackend`] records one HTTP request line and closes.

#![forbid(unsafe_code)]

pub mod ca;
pub mod hash;
pub mod inject;
pub mod record;
pub mod server;

pub use ca::{
    platform_protector, remove_session_material, unix_now, write_session_material, CaError, CaInfo,
    CaStore, Fingerprint, KeyProtector, LeafCert, SessionMaterial, UnixFileProtector,
    WindowsDpapiPlaceholder,
};
pub use inject::{
    hint_for_exe, plan_injection, refuse_attach_proxy, ExeHint, Injection, Overwrite,
    ProxyOnReject, ATTACH_REFUSES_PROXY, EXE_HINTS,
};
pub use record::{
    filter_headers, record_exchange, redact_url, to_events, RecordedExchange, RequestMeta,
    ResponseMeta, UrlGap, WsCounts, REDACTED_HEADER, REDACTED_QUERY, SOURCE_MITM,
};
pub use server::{
    AcceptError, BackendError, BackendOutput, MetadataBackend, ProxyBackend, ProxyServer,
};

/// Empty marker so the daemon can name this crate before real types exist.
pub struct Placeholder;

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
