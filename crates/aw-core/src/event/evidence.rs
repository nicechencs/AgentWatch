//! Evidence levels and the reason a field could not be observed.
//!
//! Levels are defined in evidence-model §2. Reason codes are evidence-model §3.
//! `Unknown` is the compatible-change sink for a reason this build has not seen yet.

use serde::{Deserialize, Serialize};

/// How a record or a single field is known.
///
/// `NA` always carries a reason. A bare "not available" with no reason is not representable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "level", content = "reason")]
pub enum Evidence {
    /// Kernel or OS event attributed to a process at the moment it happened.
    E1,
    /// Cleartext protocol metadata (proxy or TLS uprobe).
    E2,
    /// Self-report from the observed program. Never sufficient on its own.
    E3,
    /// Periodic snapshot. May miss short-lived activity.
    S,
    /// Inference produced by a correlation rule. Never a fact.
    I,
    /// The field or event cannot be observed in this mode. `reason` says why.
    NA(NaReason),
}

impl Evidence {
    pub const fn is_na(&self) -> bool {
        matches!(self, Self::NA(_))
    }
}

/// Why a field is [`Evidence::NA`].
///
/// Snake_case on the wire matches evidence-model §3. New codes are a compatible
/// change, so an unrecognized code deserializes as [`NaReason::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NaReason {
    /// macOS Endpoint Security has no per-read event.
    EsNoReadEvent,
    /// The file was mapped; read/write byte counts are not emitted.
    MmapNotObservable,
    /// TLS and the session has no proxy, so the URL is not visible.
    TlsNoProxy,
    /// A proxy is on, but this connection did not use it.
    DirectBypassProxy,
    /// The client refused the proxy certificate.
    CertPinned,
    /// QUIC / HTTP3 does not pass through the HTTP proxy.
    Quic,
    /// Encrypted ClientHello hid the SNI.
    Ech,
    /// No DNS answer was observed for this destination.
    NoDnsObserved,
    /// The object already existed when observation started.
    Preexisting,
    /// This platform or privilege set has no collector for the field.
    CollectorUnavailable,
    /// Removed by a redaction rule.
    Redacted,
    /// A process outside the session performed the action.
    AttributionBreak,
    /// The ClientHello was split or spanned iovecs and could not be parsed.
    PartialClientHello,
    /// HTTP/2 headers were HPACK-compressed; the uprobe saw only a fragment.
    H2Hpack,
    /// Larger than the content-hash size cap.
    TooLarge,
    /// The file changed or disappeared before it could be hashed.
    FileChanged,
    /// The other end of an IPC channel could not be identified.
    PeerUnknown,
    /// mcp-tap / proxy was not enabled, so the protocol is not visible.
    ProtocolNotObserved,
    /// A reason code this build does not know. Kept so old readers tolerate new codes.
    #[serde(other)]
    Unknown,
}
