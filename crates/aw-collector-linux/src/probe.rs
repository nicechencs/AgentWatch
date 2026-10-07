//! Collector tier selection.
//!
//! The decision is a pure function of probe mount results (linux §1). Attaching
//! a probe is someone else's job: on Linux a later task implements [`ProbeHost`]
//! with Aya; tests pass a [`ScriptedHost`]. This module never loads BPF.

use aw_core::{Evidence, Gap, GapKind, Source};

/// One running tier. `poll` is the unprivileged floor and is not an eBPF tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Kernel ≥ 5.8, BTF, and the full probe set (fentry / LSM where present).
    EbpfFull,
    /// BTF, but no fentry or LSM. Tracepoint + kprobe only.
    EbpfLite,
    /// No BTF or kernel < 5.8. proc connector + fanotify + sock_diag.
    Legacy,
    /// No privilege. Userspace polling only.
    Poll,
}

impl Tier {
    /// Stable name used by `--collector` and by `aw doctor`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EbpfFull => "ebpf-full",
            Self::EbpfLite => "ebpf-lite",
            Self::Legacy => "legacy",
            Self::Poll => "poll",
        }
    }

    /// Highest evidence this tier stamps on the events it can see.
    ///
    /// Poll is S. The eBPF tiers and legacy are E1 for the events they cover;
    /// fields a tier cannot see stay `NA` on the event, not a lower tier.
    pub const fn evidence(self) -> Evidence {
        match self {
            Self::Poll => Evidence::S,
            Self::EbpfFull | Self::EbpfLite | Self::Legacy => Evidence::E1,
        }
    }
}

impl core::fmt::Display for Tier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A probe the tier probe tries, in the order linux §1 names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeId {
    /// fentry / fexit (ebpf-full only).
    Fentry,
    /// BPF LSM (ebpf-full, optional; a miss does not by itself drop the tier).
    Lsm,
    /// Tracepoints such as `sched_process_exec` (ebpf-full and ebpf-lite).
    Tracepoint,
    /// kprobe (ebpf-lite, and the full tier's fallback for inlined functions).
    Kprobe,
    /// proc connector (legacy).
    ProcConnector,
    /// fanotify (legacy).
    Fanotify,
    /// `NETLINK_INET_DIAG` (legacy).
    SockDiag,
}

impl ProbeId {
    /// Which tier this probe belongs to. A failed mount blackens that tier.
    pub const fn tier(self) -> Tier {
        match self {
            Self::Fentry | Self::Lsm => Tier::EbpfFull,
            Self::Tracepoint | Self::Kprobe => Tier::EbpfLite,
            Self::ProcConnector | Self::Fanotify | Self::SockDiag => Tier::Legacy,
        }
    }

    /// Event classes this probe would have covered. Used as `Gap.affects`.
    pub const fn affects(self) -> &'static [&'static str] {
        match self {
            Self::Fentry | Self::Lsm => &["file", "net"],
            Self::Tracepoint => &["proc", "file", "net"],
            Self::Kprobe => &["net"],
            Self::ProcConnector => &["proc"],
            Self::Fanotify => &["file"],
            Self::SockDiag => &["net"],
        }
    }

    /// Source string stamped on the gap for a failed mount.
    pub const fn source(self) -> &'static str {
        match self {
            Self::Fentry => "linux.ebpf/fentry",
            Self::Lsm => "linux.ebpf/lsm",
            Self::Tracepoint => "linux.ebpf/tracepoint",
            Self::Kprobe => "linux.ebpf/kprobe",
            Self::ProcConnector => "linux.legacy/proc_connector",
            Self::Fanotify => "linux.legacy/fanotify",
            Self::SockDiag => "linux.legacy/sock_diag",
        }
    }

    const fn all() -> [Self; 7] {
        [
            Self::Fentry,
            Self::Lsm,
            Self::Tracepoint,
            Self::Kprobe,
            Self::ProcConnector,
            Self::Fanotify,
            Self::SockDiag,
        ]
    }
}

/// Why one probe did not attach. Stored on the gap's `detail`, not upgraded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountFailure {
    /// Kernel or BTF rejected the program.
    Unsupported,
    /// The caller lacks root or the needed capability.
    Permission,
    /// The helper returned an error we do not classify further.
    Other,
}

impl MountFailure {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Permission => "permission",
            Self::Other => "other",
        }
    }

    const fn gap_kind(self) -> GapKind {
        match self {
            Self::Unsupported | Self::Other => GapKind::Unsupported,
            Self::Permission => GapKind::Permission,
        }
    }
}

/// Result of trying one probe. The host reports this; selection does not retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountResult {
    /// The probe is attached.
    Attached,
    /// The probe did not attach. The tier falls through.
    Failed(MountFailure),
}

/// What the process is allowed to do, before any probe is tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// Root or the capabilities linux §5 lists.
    Privileged,
    /// No privilege. eBPF and legacy both need it, so the only tier is poll.
    Unprivileged,
}

/// What the operator asked for on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TierRequest {
    /// Try ebpf-full, then ebpf-lite, then legacy, then poll.
    Auto,
    /// Stay on this tier. A privileged tier still falls to poll when unprivileged.
    Force(Tier),
}

/// Chosen tier plus one gap per probe that did not attach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierDecision {
    /// Tier the collector should run.
    pub tier: Tier,
    /// Gaps for probes that failed. Empty when every required probe attached,
    /// and empty for the unprivileged poll path (that path has its own error).
    pub gaps: Vec<Gap>,
    /// Set when a forced privileged tier was refused for lack of privilege.
    pub permission_error: Option<PermissionError>,
}

/// Told to the operator when a privileged tier was requested without privilege.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionError {
    /// Tier the operator asked for.
    pub requested: Tier,
    /// Always [`Tier::Poll`]: that is the only tier available without privilege.
    pub fell_back_to: Tier,
    /// Fixed text. Names the missing privilege and the fallback. Not a guess
    /// about what the target process did.
    pub message: String,
}

impl PermissionError {
    fn new(requested: Tier) -> Self {
        Self {
            requested,
            fell_back_to: Tier::Poll,
            message: format!(
                "permission required for collector tier {requested}; falling back to poll"
            ),
        }
    }
}

/// Something that can try to attach one probe.
///
/// The Linux loader implements this later, behind `cfg(target_os = "linux")`.
/// Tests use [`ScriptedHost`]. Selection calls `mount` at most once per probe.
pub trait ProbeHost {
    /// Try to attach `probe`. Must not panic, and must not attach a different probe.
    fn mount(&mut self, probe: ProbeId) -> MountResult;
}

/// Host whose answers are fixed up front. Used by tests and by `--probe-only`
/// dry runs that already know the results.
#[derive(Debug, Clone)]
pub struct ScriptedHost {
    results: Vec<(ProbeId, MountResult)>,
}

impl ScriptedHost {
    /// Build a host. A probe missing from `results` is treated as unsupported,
    /// so a test cannot accidentally count an unmentioned probe as attached.
    pub fn new(results: impl IntoIterator<Item = (ProbeId, MountResult)>) -> Self {
        Self {
            results: results.into_iter().collect(),
        }
    }
}

impl ProbeHost for ScriptedHost {
    fn mount(&mut self, probe: ProbeId) -> MountResult {
        self.results
            .iter()
            .find(|(id, _)| *id == probe)
            .map(|(_, result)| *result)
            .unwrap_or(MountResult::Failed(MountFailure::Unsupported))
    }
}

/// Probes a tier needs before it can be selected.
///
/// LSM is optional on ebpf-full (linux §1: many distros ship it off). A miss
/// still produces a gap, but does not drop the tier when fentry attached.
fn required(tier: Tier) -> &'static [ProbeId] {
    match tier {
        Tier::EbpfFull => &[ProbeId::Fentry],
        Tier::EbpfLite => &[ProbeId::Tracepoint, ProbeId::Kprobe],
        Tier::Legacy => &[ProbeId::ProcConnector, ProbeId::Fanotify, ProbeId::SockDiag],
        Tier::Poll => &[],
    }
}

/// Optional probes. Tried, recorded, and never required for the tier.
fn optional(tier: Tier) -> &'static [ProbeId] {
    match tier {
        Tier::EbpfFull => &[ProbeId::Lsm],
        _ => &[],
    }
}

/// Pick a tier from mount results.
///
/// Order is ebpf-full, then ebpf-lite, then legacy. Poll is the result only
/// when nothing privileged attached, or when the caller has no privilege.
/// Each failed mount becomes a `Gap` with `GapKind::Unsupported` (or
/// `Permission`). The count is `None`: a failed mount is not a counted loss.
pub fn select_tier(host: &mut dyn ProbeHost, request: TierRequest, privilege: Privilege) -> TierDecision {
    if privilege == Privilege::Unprivileged {
        let requested = match request {
            TierRequest::Force(Tier::Poll) | TierRequest::Auto => None,
            TierRequest::Force(tier) => Some(tier),
        };
        return TierDecision {
            tier: Tier::Poll,
            gaps: Vec::new(),
            permission_error: requested.map(PermissionError::new),
        };
    }

    let candidates: &[Tier] = match request {
        TierRequest::Auto => &[Tier::EbpfFull, Tier::EbpfLite, Tier::Legacy],
        TierRequest::Force(Tier::Poll) => {
            return TierDecision {
                tier: Tier::Poll,
                gaps: Vec::new(),
                permission_error: None,
            };
        }
        TierRequest::Force(Tier::EbpfFull) => &[Tier::EbpfFull],
        TierRequest::Force(Tier::EbpfLite) => &[Tier::EbpfLite],
        TierRequest::Force(Tier::Legacy) => &[Tier::Legacy],
    };

    let mut gaps = Vec::new();
    for tier in candidates {
        let mut tier_ok = true;
        for probe in required(*tier).iter().chain(optional(*tier)) {
            match host.mount(*probe) {
                MountResult::Attached => {}
                MountResult::Failed(failure) => {
                    if required(*tier).contains(probe) {
                        tier_ok = false;
                    }
                    gaps.push(mount_gap(*probe, failure));
                }
            }
        }
        if tier_ok {
            return TierDecision {
                tier: *tier,
                gaps,
                permission_error: None,
            };
        }
    }

    TierDecision {
        tier: Tier::Poll,
        gaps,
        permission_error: None,
    }
}

fn mount_gap(probe: ProbeId, failure: MountFailure) -> Gap {
    Gap::new(
        Source::new(probe.source()),
        failure.gap_kind(),
        probe.affects().iter().map(|s| (*s).to_string()).collect(),
        0,
        0,
        None,
        Some(format!(
            "probe {} failed to mount ({})",
            probe.source(),
            failure.as_str()
        )),
    )
}

/// Parse `--collector <tier>`.
///
/// Accepts `ebpf-full`, `ebpf-lite`, `legacy`, `poll`, and `auto`.
/// Anything else is an error that names the bad token. No default is invented.
pub fn parse_collector_arg(value: &str) -> Result<TierRequest, String> {
    match value {
        "auto" => Ok(TierRequest::Auto),
        "ebpf-full" => Ok(TierRequest::Force(Tier::EbpfFull)),
        "ebpf-lite" => Ok(TierRequest::Force(Tier::EbpfLite)),
        "legacy" => Ok(TierRequest::Force(Tier::Legacy)),
        "poll" => Ok(TierRequest::Force(Tier::Poll)),
        other => Err(format!(
            "unknown collector tier '{other}'; expected ebpf-full, ebpf-lite, legacy, poll, or auto"
        )),
    }
}

/// Every probe id, for tests that want to script a complete host.
pub fn all_probes() -> [ProbeId; 7] {
    ProbeId::all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aw_core::GapKind;

    fn ok(id: ProbeId) -> (ProbeId, MountResult) {
        (id, MountResult::Attached)
    }

    fn fail(id: ProbeId) -> (ProbeId, MountResult) {
        (id, MountResult::Failed(MountFailure::Unsupported))
    }

    fn decision(
        results: &[(ProbeId, MountResult)],
        request: TierRequest,
        privilege: Privilege,
    ) -> TierDecision {
        let mut host = ScriptedHost::new(results.iter().copied());
        select_tier(&mut host, request, privilege)
    }

    #[test]
    fn full_when_fentry_attaches() {
        let d = decision(
            &[ok(ProbeId::Fentry), ok(ProbeId::Lsm)],
            TierRequest::Auto,
            Privilege::Privileged,
        );
        assert_eq!(d.tier, Tier::EbpfFull);
        assert!(d.gaps.is_empty());
        assert!(d.permission_error.is_none());
    }

    #[test]
    fn lsm_miss_stays_on_full_and_records_a_gap() {
        let d = decision(
            &[ok(ProbeId::Fentry), fail(ProbeId::Lsm)],
            TierRequest::Auto,
            Privilege::Privileged,
        );
        assert_eq!(d.tier, Tier::EbpfFull);
        assert_eq!(d.gaps.len(), 1);
        assert_eq!(d.gaps[0].gap_kind, GapKind::Unsupported);
        assert_eq!(d.gaps[0].collector.as_str(), "linux.ebpf/lsm");
        assert!(d.gaps[0].count.is_none());
    }

    #[test]
    fn fentry_miss_falls_to_lite() {
        let d = decision(
            &[
                fail(ProbeId::Fentry),
                fail(ProbeId::Lsm),
                ok(ProbeId::Tracepoint),
                ok(ProbeId::Kprobe),
            ],
            TierRequest::Auto,
            Privilege::Privileged,
        );
        assert_eq!(d.tier, Tier::EbpfLite);
        assert!(d.gaps.iter().any(|g| g.gap_kind == GapKind::Unsupported));
        assert!(d.gaps.len() >= 2);
    }

    #[test]
    fn no_bpf_falls_to_legacy() {
        let d = decision(
            &[
                fail(ProbeId::Fentry),
                fail(ProbeId::Lsm),
                fail(ProbeId::Tracepoint),
                fail(ProbeId::Kprobe),
                ok(ProbeId::ProcConnector),
                ok(ProbeId::Fanotify),
                ok(ProbeId::SockDiag),
            ],
            TierRequest::Auto,
            Privilege::Privileged,
        );
        assert_eq!(d.tier, Tier::Legacy);
    }

    #[test]
    fn nothing_attaches_falls_to_poll() {
        let d = decision(&[], TierRequest::Auto, Privilege::Privileged);
        assert_eq!(d.tier, Tier::Poll);
        assert!(!d.gaps.is_empty());
        assert!(d.gaps.iter().all(|g| g.gap_kind == GapKind::Unsupported));
    }

    #[test]
    fn unprivileged_auto_is_poll_without_a_permission_error() {
        let d = decision(&[], TierRequest::Auto, Privilege::Unprivileged);
        assert_eq!(d.tier, Tier::Poll);
        assert!(d.gaps.is_empty());
        assert!(d.permission_error.is_none());
    }

    #[test]
    fn unprivileged_forced_tier_falls_back_with_an_explicit_error() {
        let d = decision(
            &[ok(ProbeId::Fentry)],
            TierRequest::Force(Tier::EbpfFull),
            Privilege::Unprivileged,
        );
        assert_eq!(d.tier, Tier::Poll);
        let Some(err) = d.permission_error.as_ref() else {
            panic!("permission error");
        };
        assert_eq!(err.requested, Tier::EbpfFull);
        assert_eq!(err.fell_back_to, Tier::Poll);
        assert!(err.message.contains("permission required"));
        assert!(err.message.contains("ebpf-full"));
        assert!(err.message.contains("poll"));
    }

    #[test]
    fn forced_legacy_does_not_try_ebpf() {
        let d = decision(
            &[
                ok(ProbeId::Fentry),
                ok(ProbeId::ProcConnector),
                ok(ProbeId::Fanotify),
                ok(ProbeId::SockDiag),
            ],
            TierRequest::Force(Tier::Legacy),
            Privilege::Privileged,
        );
        assert_eq!(d.tier, Tier::Legacy);
        assert!(d.gaps.is_empty());
    }

    #[test]
    fn parse_collector_arg_accepts_the_four_tiers_and_auto() {
        assert_eq!(must_parse("auto"), TierRequest::Auto);
        assert_eq!(must_parse("ebpf-full"), TierRequest::Force(Tier::EbpfFull));
        assert_eq!(must_parse("ebpf-lite"), TierRequest::Force(Tier::EbpfLite));
        assert_eq!(must_parse("legacy"), TierRequest::Force(Tier::Legacy));
        assert_eq!(must_parse("poll"), TierRequest::Force(Tier::Poll));
    }

    #[test]
    fn parse_collector_arg_rejects_unknown_tokens() {
        let Err(err) = parse_collector_arg("ebpf") else {
            panic!("ebpf is not a tier name");
        };
        assert!(err.contains("ebpf"));
        assert!(err.contains("ebpf-full"));
        assert!(parse_collector_arg("").is_err());
    }

    fn must_parse(value: &str) -> TierRequest {
        match parse_collector_arg(value) {
            Ok(request) => request,
            Err(err) => panic!("parse {value}: {err}"),
        }
    }
}
