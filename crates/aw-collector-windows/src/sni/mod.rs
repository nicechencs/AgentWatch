//! Windows SNI extraction skeleton (P3-WIN-01).
//!
//! pktmon (`Microsoft-Windows-PktMon`) is named in windows.md §2.6 as a possible
//! source of the first TLS payload. That capability is still 【待验证】: nobody
//! has confirmed on this machine, or in CI, that a real-time ETW subscription
//! yields packet bytes, or that those bytes can be filtered by a 5-tuple.
//!
//! Until that is measured on a privileged CI runner or a VM, this module does
//! not open an ETW session, does not call `pktmon` / `logman` / `netsh`, and
//! does not install a filter. [`PktmonSni::start`] returns
//! [`SniError::Unverified`] and stops. The only live code is [`extract_sni`],
//! which classifies a buffer the caller already has.
//!
//! The switch is off unless a config value says otherwise
//! ([`sni_enabled`]). `None` is off, matching `collectors.windows.sni = false`.
//!
//! WinDivert is not linked. It is LGPL/GPL (ADR-0008) and must not ship in the
//! default package. This module does not load it.

use std::fmt;

/// `collectors.windows.sni`. Absent config is off.
///
/// `Some(true)` is the only value that reports the switch as on. `None` and
/// `Some(false)` are off. Turning the switch on does not by itself start a
/// capture: [`PktmonSni::start`] still refuses until pktmon is verified.
#[must_use]
pub fn sni_enabled(config_value: Option<bool>) -> bool {
    matches!(config_value, Some(true))
}

/// What [`extract_sni`] could say about one buffer.
///
/// A failure is not a parsed name. [`SniExtract::Truncated`] and
/// [`SniExtract::NotHandshake`] are distinct from [`SniExtract::Parsed`], and
/// [`SniExtract::Parsed`] carries the host name the ClientHello actually had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniExtract {
    /// `parse_client_hello` succeeded. `sni` is the first host_name, or `None`
    /// when the handshake had no host_name (including ECH, where the inner
    /// name is hidden). `None` here is "parsed, no name", not "parse failed".
    Parsed { sni: Option<String> },
    /// The parser returned `Incomplete`: the buffer ended inside a
    /// length-prefixed field. Retry with more bytes, or record the name as
    /// unavailable. Do not treat this as a hostname.
    Truncated,
    /// The buffer is not a TLS handshake record (`content_type != 22`), or it
    /// is not a ClientHello this parser accepts. Not a hostname.
    NotHandshake,
}

/// Pull an SNI classification out of one captured payload.
///
/// `payload` is the bytes a capture would have handed over, starting at the
/// TLS record header. This function does not read the network itself.
///
/// The call into `aw_core::tls::parse_client_hello` is isolated in
/// [`parse_client_hello`]. That item exists only once `aw-core` exports `tls`
/// (P3-PIPE-02). Before that export lands, every buffer is [`SniExtract::NotHandshake`]
/// rather than a guessed name.
#[must_use]
pub fn extract_sni(payload: &[u8]) -> SniExtract {
    match parse_client_hello(payload) {
        Ok(sni) => SniExtract::Parsed { sni },
        Err(ClientHelloFailure::Incomplete) => SniExtract::Truncated,
        Err(ClientHelloFailure::NotHandshake | ClientHelloFailure::Malformed) => {
            SniExtract::NotHandshake
        }
    }
}

/// Outcome of the P3-PIPE-02 ClientHello parser, reduced to what [`extract_sni`]
/// needs. Kept local so this module does not depend on `aw_core::tls` types
/// until that module is public.
enum ClientHelloFailure {
    Incomplete,
    NotHandshake,
    Malformed,
}

/// Isolate the `aw_core::tls::parse_client_hello` call (P3-PIPE-02).
///
/// `Incomplete` stays a truncation: the caller records `NA(partial_client_hello)`
/// rather than a name. `Malformed` maps to the same bucket as `NotHandshake`
/// because neither one yields a hostname, and this collector does not guess.
fn parse_client_hello(payload: &[u8]) -> Result<Option<String>, ClientHelloFailure> {
    match aw_core::tls::parse_client_hello(payload) {
        Ok(info) => Ok(info.sni),
        Err(aw_core::tls::ParseError::Incomplete) => Err(ClientHelloFailure::Incomplete),
        Err(aw_core::tls::ParseError::NotHandshake) => Err(ClientHelloFailure::NotHandshake),
        Err(aw_core::tls::ParseError::Malformed) => Err(ClientHelloFailure::Malformed),
    }
}

/// Why [`PktmonSni`] did not start a capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniError {
    /// pktmon's real-time payload is still 【待验证】 (windows.md §2.6).
    ///
    /// Starting would mean subscribing to `Microsoft-Windows-PktMon` and
    /// possibly installing a filter. That is refused until a privileged CI run
    /// or a VM records whether the provider actually delivers packet bytes.
    Unverified,
}

impl fmt::Display for SniError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unverified => f.write_str(
                "pktmon real-time packet payload is unverified; SNI capture refused to start",
            ),
        }
    }
}

impl std::error::Error for SniError {}

/// Placeholder for a pktmon SNI subscription.
///
/// Fields describe the capture the task card would run once §2.6 is measured.
/// They are not applied to the system. [`Self::start`] does not open a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PktmonSni {
    /// `collectors.windows.sni` as resolved by [`sni_enabled`].
    enabled: bool,
}

impl PktmonSni {
    /// Build a subscription handle. Does not talk to ETW.
    ///
    /// `config_value` is the raw `collectors.windows.sni` setting. `None` keeps
    /// the capture off.
    #[must_use]
    pub fn new(config_value: Option<bool>) -> Self {
        Self {
            enabled: sni_enabled(config_value),
        }
    }

    /// Whether config asked for SNI. Independent of [`Self::start`], which
    /// refuses either way until pktmon is verified.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Refuse to subscribe.
    ///
    /// pktmon 能否提供包内容尚未验证 (windows.md §2.6, 【待验证】). A verified
    /// provider would subscribe to `Microsoft-Windows-PktMon`, match the first
    /// outbound TCP payload of an in-session 5-tuple, and pass those bytes to
    /// [`extract_sni`], with `source = windows.pktmon/sni` and evidence E1.
    /// That subscription is not implemented. The filter-cleanup rule (do not
    /// touch the global pktmon config; remove only filters this tool added)
    /// has nothing to undo because nothing is installed.
    ///
    /// # Errors
    ///
    /// Always [`SniError::Unverified`]. The `enabled` flag does not bypass it.
    pub fn start(&self) -> Result<(), SniError> {
        let _ = self.enabled;
        Err(SniError::Unverified)
    }
}
