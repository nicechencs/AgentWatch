//! macOS collector tier selection (P4-MAC-06, ADR-0009).
//!
//! The decision is a pure function of a [`Probe`] the caller already ran. This
//! module does not create an Endpoint Security client and does not talk to a
//! Network Extension. Tests on Linux pass a scripted probe.
//!
//! Three tiers:
//!
//! | tier | collectors | net evidence |
//! |---|---|---|
//! | [`Tier::M1`] | eslogger + nettop + pktap | [`Evidence::S`] |
//! | [`Tier::M2Es`] | native ES + nettop | [`Evidence::S`] |
//! | [`Tier::M2Full`] | native ES + NE | [`Evidence::E1`] |
//!
//! `macos.tier = auto` tries native ES first, then NE. A forced higher tier that
//! the probe cannot support is [`TierError`]. It is not silently lowered.
//! Losing a capability mid-session ([`TierChange`]) produces a [`Gap`] and names
//! the tier that is still available. Existing M1 collectors are not touched.

use std::fmt;

use aw_core::{Capability, CapabilitySet, Evidence, Gap, GapKind, NaReason, Source};

/// One running macOS collector tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// eslogger + nettop + pktap. Needs root and Full Disk Access, no entitlement.
    M1,
    /// Native Endpoint Security plus nettop. Network stays sampled.
    M2Es,
    /// Native Endpoint Security plus a connected Network Extension.
    M2Full,
}

impl Tier {
    /// Stable name stored in `sessions.collector_profile` and shown by `aw doctor`.
    ///
    /// Config tokens (`m1`, `m2-es`, `m2-full`) stay lowercase. The profile value
    /// matches the task card's `aw doctor --json` example: `M1`, `M2-es`, `M2-full`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::M1 => "M1",
            Self::M2Es => "M2-es",
            Self::M2Full => "M2-full",
        }
    }

    /// Config token accepted by [`parse_tier_config`].
    pub const fn config_token(self) -> &'static str {
        match self {
            Self::M1 => "m1",
            Self::M2Es => "m2-es",
            Self::M2Full => "m2-full",
        }
    }

    /// Evidence stamped on network byte events at this tier.
    ///
    /// M1 and M2-es sample with nettop ([`Evidence::S`]). M2-full counts bytes in
    /// the Network Extension ([`Evidence::E1`]). Process and file events stay E1
    /// on every tier; that is not this function.
    pub const fn net_evidence(self) -> Evidence {
        match self {
            Self::M1 | Self::M2Es => Evidence::S,
            Self::M2Full => Evidence::E1,
        }
    }

    /// `true` when the tier creates a native ES client instead of spawning eslogger.
    pub const fn uses_native_es(self) -> bool {
        matches!(self, Self::M2Es | Self::M2Full)
    }

    /// `true` when the tier reads flow bytes from the Network Extension.
    pub const fn uses_network_extension(self) -> bool {
        matches!(self, Self::M2Full)
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the operator wrote as `macos.tier`.
///
/// Default is [`TierConfig::Auto`]. A forced tier is honored only when the probe
/// says that tier's capabilities are present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TierConfig {
    /// Probe native ES, then NE, and pick the highest tier both support.
    #[default]
    Auto,
    /// Stay on this tier. Do not drop to a lower one when it is unavailable.
    Force(Tier),
}

impl TierConfig {
    /// `auto`. Used when the config file does not set `macos.tier`.
    pub const fn auto() -> Self {
        Self::Auto
    }
}

/// Result of the probes this module does not perform itself.
///
/// `es_client` is whether `es_new_client` would succeed. `network_extension` is
/// whether the system extension's XPC connection is up. Neither flag is inferred
/// from a config file that claims an entitlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// A native Endpoint Security client can be created.
    pub es_client: bool,
    /// The Network Extension is connected to the daemon.
    pub network_extension: bool,
}

impl Probe {
    /// Neither native ES nor NE is available. Auto selects [`Tier::M1`].
    pub const fn none() -> Self {
        Self {
            es_client: false,
            network_extension: false,
        }
    }

    /// Native ES is available and the extension is not connected.
    pub const fn es_only() -> Self {
        Self {
            es_client: true,
            network_extension: false,
        }
    }

    /// Both native ES and the Network Extension are available.
    pub const fn full() -> Self {
        Self {
            es_client: true,
            network_extension: true,
        }
    }
}

/// Why a requested tier cannot run on this probe.
///
/// Returned instead of picking a lower tier. Auto never produces this error:
/// M1 does not require either probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TierError {
    /// `m2-es` or `m2-full` was forced and a native ES client cannot be created.
    EsUnavailable {
        /// Tier the operator forced.
        requested: Tier,
    },
    /// `m2-full` was forced, ES is available, and the extension is not connected.
    NetworkExtensionUnavailable {
        /// Always [`Tier::M2Full`].
        requested: Tier,
    },
    /// `macos.tier` was not `auto`, `m1`, `m2-es`, or `m2-full`.
    UnknownConfig {
        /// The token that was rejected.
        token: String,
    },
}

impl fmt::Display for TierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EsUnavailable { requested } => write!(
                f,
                "macos.tier = {token} requires a native Endpoint Security client, and the probe could not create one",
                token = requested.config_token(),
            ),
            Self::NetworkExtensionUnavailable { requested } => write!(
                f,
                "macos.tier = {token} requires a connected Network Extension, and the probe reports it is not connected",
                token = requested.config_token(),
            ),
            Self::UnknownConfig { token } => write!(
                f,
                "unknown macos.tier '{token}'; expected auto, m1, m2-es, or m2-full"
            ),
        }
    }
}

impl std::error::Error for TierError {}

/// Chosen tier. `collector_profile` is what storage writes on the session row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierChoice {
    /// Tier the collector should run.
    pub tier: Tier,
    /// Value for `sessions.collector_profile`. Same text as [`Tier::as_str`].
    pub collector_profile: &'static str,
}

impl TierChoice {
    fn new(tier: Tier) -> Self {
        Self {
            tier,
            collector_profile: tier.as_str(),
        }
    }
}

/// A capability disappeared or appeared while a tier was already running.
///
/// The gap covers the stretch between the last good observation and the moment
/// the probe changed. `count` is `None`: a tier change is not a counted loss.
/// `switched_to` is the tier [`select_tier`] would pick for the same config
/// against `now`. A forced tier that the new probe cannot support leaves
/// `switched_to` as `None` and still emits the gap — the caller must stop rather
/// than silently drop a tier the operator forced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierChange {
    /// Tier that was running.
    pub from: Tier,
    /// Tier to run now. `None` when the configured tier is no longer available.
    pub switched_to: Option<Tier>,
    /// Probe that replaced the one used to select `from`.
    pub now: Probe,
    /// Why the tier moved. Also copied into [`Gap::detail`].
    pub reason: String,
    /// Gap the pipeline should record. Evidence of the gap itself is E1 by kind.
    pub gap: Gap,
}

/// Parse `macos.tier`. Absent config is [`TierConfig::Auto`], not a parse.
///
/// Accepts `auto`, `m1`, `m2-es`, and `m2-full`. Anything else is
/// [`TierError::UnknownConfig`]. No alias is invented.
pub fn parse_tier_config(value: &str) -> Result<TierConfig, TierError> {
    match value {
        "auto" => Ok(TierConfig::Auto),
        "m1" => Ok(TierConfig::Force(Tier::M1)),
        "m2-es" => Ok(TierConfig::Force(Tier::M2Es)),
        "m2-full" => Ok(TierConfig::Force(Tier::M2Full)),
        other => Err(TierError::UnknownConfig {
            token: other.to_string(),
        }),
    }
}

/// Pick a tier from a probe the caller already ran.
///
/// Auto order is native ES, then NE:
///
/// * both available → [`Tier::M2Full`]
/// * ES only → [`Tier::M2Es`]
/// * no ES → [`Tier::M1`], even if the extension is connected (NE without ES is
///   not a defined tier)
///
/// A forced tier whose probe flag is missing returns [`TierError`]. M1 never
/// fails this way: it does not use either capability.
pub fn select_tier(config: TierConfig, probe: Probe) -> Result<TierChoice, TierError> {
    let tier = match config {
        TierConfig::Auto => auto_tier(probe),
        TierConfig::Force(tier) => {
            ensure_available(tier, probe)?;
            tier
        }
    };
    Ok(TierChoice::new(tier))
}

/// Capabilities `aw doctor` and the UI show for `tier`.
///
/// Process and file are E1 on every tier (eslogger or native ES). Network is
/// [`Tier::net_evidence`]. DNS and SNI stay E1 via pktap on every tier; the
/// extension does not replace pktap. URL is `NA(collector_unavailable)` because
/// a URL still needs the proxy, which is not a macOS tier. Scope is E1 via the
/// process tree.
pub fn capabilities(tier: Tier) -> CapabilitySet {
    let net_note = match tier {
        Tier::M1 | Tier::M2Es => "nettop sample",
        Tier::M2Full => "network extension",
    };
    CapabilitySet::new(
        cap_available(Evidence::E1, "endpoint security"),
        cap_available(Evidence::E1, "endpoint security"),
        cap_available(tier.net_evidence(), net_note),
        cap_available(Evidence::E1, "pktap"),
        Capability::unavailable(NaReason::CollectorUnavailable),
        cap_available(Evidence::E1, "process tree"),
    )
}

/// Describe a mid-session probe change.
///
/// `previous` is the probe that selected `running`. When `now` still supports
/// `running`, this returns `Ok(None)`: nothing moved, and no gap is invented.
/// When it does not, the returned [`TierChange`] carries one [`Gap`] with
/// [`GapKind::CollectorDisconnected`]. `config` is re-applied to `now` to decide
/// `switched_to`; a forced tier that `now` cannot run sets `switched_to` to
/// `None` and does not substitute a lower tier.
pub fn tier_changed(
    config: TierConfig,
    running: Tier,
    previous: Probe,
    now: Probe,
    at_mono_ns: u64,
) -> Result<Option<TierChange>, TierError> {
    if probe_supports(running, now) {
        return Ok(None);
    }
    let switched_to = match select_tier(config, now) {
        Ok(choice) => Some(choice.tier),
        Err(TierError::EsUnavailable { .. } | TierError::NetworkExtensionUnavailable { .. }) => {
            None
        }
        Err(err) => return Err(err),
    };
    let reason = change_reason(running, switched_to, previous, now);
    let gap = Gap::new(
        Source::new(gap_source(running)),
        GapKind::CollectorDisconnected,
        affects_for(running, now),
        at_mono_ns,
        at_mono_ns,
        None,
        Some(reason.clone()),
    );
    Ok(Some(TierChange {
        from: running,
        switched_to,
        now,
        reason,
        gap,
    }))
}

fn auto_tier(probe: Probe) -> Tier {
    if probe.es_client && probe.network_extension {
        Tier::M2Full
    } else if probe.es_client {
        Tier::M2Es
    } else {
        Tier::M1
    }
}

fn ensure_available(tier: Tier, probe: Probe) -> Result<(), TierError> {
    if tier.uses_native_es() && !probe.es_client {
        return Err(TierError::EsUnavailable { requested: tier });
    }
    if tier.uses_network_extension() && !probe.network_extension {
        return Err(TierError::NetworkExtensionUnavailable { requested: tier });
    }
    Ok(())
}

fn probe_supports(tier: Tier, probe: Probe) -> bool {
    ensure_available(tier, probe).is_ok()
}

fn gap_source(running: Tier) -> &'static str {
    match running {
        Tier::M2Full => "macos.ne/flow",
        Tier::M2Es => "macos.es",
        Tier::M1 => "macos.eslogger",
    }
}

fn affects_for(running: Tier, now: Probe) -> Vec<String> {
    let mut affects = Vec::new();
    if running.uses_native_es() && !now.es_client {
        affects.push("proc".to_string());
        affects.push("file".to_string());
    }
    if running.uses_network_extension() && !now.network_extension {
        affects.push("net".to_string());
    }
    if affects.is_empty() {
        affects.push("net".to_string());
    }
    affects
}

fn change_reason(from: Tier, switched_to: Option<Tier>, previous: Probe, now: Probe) -> String {
    let lost = lost_capabilities(previous, now);
    match switched_to {
        Some(next) => format!(
            "collector tier changed from {from} to {next}: {lost} no longer available"
        ),
        None => format!(
            "collector tier {from} lost {lost}; configured tier is not available and was not lowered"
        ),
    }
}

fn lost_capabilities(previous: Probe, now: Probe) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if previous.es_client && !now.es_client {
        parts.push("native Endpoint Security");
    }
    if previous.network_extension && !now.network_extension {
        parts.push("Network Extension");
    }
    if parts.is_empty() {
        return "a required capability".to_string();
    }
    parts.join(" and ")
}

fn cap_available(evidence: Evidence, note: &str) -> Capability {
    match Capability::available(evidence) {
        Ok(cap) => cap.with_note(note),
        // `evidence` is E1 or S. `NA` is not passed here.
        Err(_) => Capability::unavailable(NaReason::CollectorUnavailable),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn auto_selects_the_highest_tier_the_probe_supports() {
        let full = select_tier(TierConfig::Auto, Probe::full()).expect("full");
        assert_eq!(full.tier, Tier::M2Full);
        assert_eq!(full.collector_profile, "M2-full");

        let es = select_tier(TierConfig::Auto, Probe::es_only()).expect("es");
        assert_eq!(es.tier, Tier::M2Es);
        assert_eq!(es.collector_profile, "M2-es");

        let m1 = select_tier(TierConfig::Auto, Probe::none()).expect("m1");
        assert_eq!(m1.tier, Tier::M1);
        assert_eq!(m1.collector_profile, "M1");

        // NE without a native ES client is not a tier. Auto stays on M1.
        let extension_only = select_tier(
            TierConfig::Auto,
            Probe {
                es_client: false,
                network_extension: true,
            },
        )
        .expect("extension only");
        assert_eq!(extension_only.tier, Tier::M1);
    }

    #[test]
    fn auto_is_the_default_config() {
        assert_eq!(TierConfig::default(), TierConfig::Auto);
        assert_eq!(parse_tier_config("auto").expect("auto"), TierConfig::Auto);
    }

    #[test]
    fn forced_tier_errors_when_the_probe_cannot_provide_it() {
        let err = select_tier(TierConfig::Force(Tier::M2Full), Probe::none())
            .expect_err("m2-full needs both");
        assert!(matches!(
            err,
            TierError::EsUnavailable {
                requested: Tier::M2Full
            }
        ));

        let err =
            select_tier(TierConfig::Force(Tier::M2Es), Probe::none()).expect_err("m2-es needs ES");
        assert!(matches!(
            err,
            TierError::EsUnavailable {
                requested: Tier::M2Es
            }
        ));

        let err = select_tier(TierConfig::Force(Tier::M2Full), Probe::es_only())
            .expect_err("m2-full needs NE");
        assert!(matches!(
            err,
            TierError::NetworkExtensionUnavailable {
                requested: Tier::M2Full
            }
        ));

        // Forcing M1 never consults the probe and never drops further.
        let stay = select_tier(TierConfig::Force(Tier::M1), Probe::full()).expect("m1");
        assert_eq!(stay.tier, Tier::M1);
    }

    #[test]
    fn forced_tier_is_kept_when_the_probe_has_it() {
        let choice = select_tier(TierConfig::Force(Tier::M2Es), Probe::full()).expect("es");
        assert_eq!(choice.tier, Tier::M2Es);
        let choice = select_tier(TierConfig::Force(Tier::M2Full), Probe::full()).expect("full");
        assert_eq!(choice.tier, Tier::M2Full);
    }

    #[test]
    fn unknown_config_token_is_rejected() {
        let err = parse_tier_config("m2").expect_err("no alias");
        match err {
            TierError::UnknownConfig { token } => assert_eq!(token, "m2"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn mid_session_loss_of_the_extension_emits_a_gap_and_steps_down() {
        let change = tier_changed(
            TierConfig::Auto,
            Tier::M2Full,
            Probe::full(),
            Probe::es_only(),
            50,
        )
        .expect("change")
        .expect("gap");
        assert_eq!(change.from, Tier::M2Full);
        assert_eq!(change.switched_to, Some(Tier::M2Es));
        assert_eq!(change.gap.gap_kind, GapKind::CollectorDisconnected);
        assert_eq!(change.gap.collector.as_str(), "macos.ne/flow");
        assert_eq!(change.gap.affects, vec!["net".to_string()]);
        assert!(change.gap.count.is_none());
        assert_eq!(change.gap.from_mono_ns, 50);
        assert!(change.reason.contains("M2-full"));
        assert!(change.reason.contains("M2-es"));
        assert!(change.reason.contains("Network Extension"));
        assert_eq!(change.gap.detail.as_deref(), Some(change.reason.as_str()));
    }

    #[test]
    fn mid_session_loss_of_es_on_auto_falls_to_m1() {
        let change = tier_changed(
            TierConfig::Auto,
            Tier::M2Full,
            Probe::full(),
            Probe::none(),
            9,
        )
        .expect("change")
        .expect("gap");
        assert_eq!(change.switched_to, Some(Tier::M1));
        assert_eq!(
            change.gap.affects,
            vec!["proc".to_string(), "file".to_string(), "net".to_string()]
        );
        assert_eq!(change.gap.gap_kind, GapKind::CollectorDisconnected);
    }

    #[test]
    fn forced_tier_is_not_lowered_when_it_disappears() {
        let change = tier_changed(
            TierConfig::Force(Tier::M2Full),
            Tier::M2Full,
            Probe::full(),
            Probe::es_only(),
            1,
        )
        .expect("reported")
        .expect("gap");
        assert_eq!(change.switched_to, None);
        assert!(change.reason.contains("not lowered"));
        assert_eq!(change.gap.gap_kind, GapKind::CollectorDisconnected);
    }

    #[test]
    fn unchanged_probe_emits_no_gap() {
        let same = tier_changed(
            TierConfig::Auto,
            Tier::M2Full,
            Probe::full(),
            Probe::full(),
            0,
        )
        .expect("ok");
        assert!(same.is_none());
        let still_es = tier_changed(
            TierConfig::Auto,
            Tier::M2Es,
            Probe::es_only(),
            Probe::es_only(),
            0,
        )
        .expect("ok");
        assert!(still_es.is_none());
    }

    #[test]
    fn capabilities_mark_network_s_until_the_extension_is_the_source() {
        let m1 = capabilities(Tier::M1);
        assert_eq!(
            m1.get(aw_core::CapabilityCategory::Proc).evidence,
            Evidence::E1
        );
        assert_eq!(
            m1.get(aw_core::CapabilityCategory::File).evidence,
            Evidence::E1
        );
        assert_eq!(
            m1.get(aw_core::CapabilityCategory::Net).evidence,
            Evidence::S
        );
        assert_eq!(
            m1.get(aw_core::CapabilityCategory::Dns).evidence,
            Evidence::E1
        );
        assert!(m1.get(aw_core::CapabilityCategory::Url).evidence.is_na());

        let es = capabilities(Tier::M2Es);
        assert_eq!(
            es.get(aw_core::CapabilityCategory::Net).evidence,
            Evidence::S
        );

        let full = capabilities(Tier::M2Full);
        assert_eq!(
            full.get(aw_core::CapabilityCategory::Net).evidence,
            Evidence::E1
        );
        assert_eq!(Tier::M1.net_evidence(), Evidence::S);
        assert_eq!(Tier::M2Es.net_evidence(), Evidence::S);
        assert_eq!(Tier::M2Full.net_evidence(), Evidence::E1);
    }
}
