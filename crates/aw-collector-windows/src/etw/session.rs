//! Real-time ETW session: name, buffers, scope filter, loss accounting, clock.
//!
//! This module is the logic SPIKE-02 has not measured yet. Nothing here opens a
//! session, calls `ControlTrace`, or reads the host clock. Those live in
//! [`super::trace`] and only run when an elevated process asks for them.
//!
//! Buffer sizes are the starting numbers from `docs/02-platforms/windows.md` §6.
//! They are **not** measured values. SPIKE-02 has not been run elevated, so the
//! constants below are marked as the documented initial values.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use aw_core::{EventKind, Evidence, Gap, GapKind, RawEvent, RawEventParts, Source, SCHEMA_VERSION};

/// Session name prefix. The boot id is appended so two boots never share a name.
pub const SESSION_PREFIX: &str = "AgentWatch";

/// How often a running session re-reads `EventsLost` and `RealTimeBuffersLost`.
pub const LOSS_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// `source` of a gap this session emits. Matches the `windows.etw` prefix in
/// event-schema §2.1. The probe half is `session`, not a provider.
pub const SESSION_SOURCE: &str = "windows.etw/session";

/// NT Kernel Logger session name. Never used. One such session may exist on
/// older Windows, and ADR-0008 forbids taking it. Kept here so a caller can
/// refuse it by name instead of discovering the rule in a comment elsewhere.
pub const NT_KERNEL_LOGGER: &str = "NT Kernel Logger";

/// Microsoft-Windows-Kernel-Process `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`.
///
/// GUID and keyword bit are copied from windows.md §2.1 and are 【待验证 SPIKE-02】.
pub const KERNEL_PROCESS_GUID: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";

/// `WINEVENT_KEYWORD_PROCESS` (0x10). Image-load (0x40) is not enabled in P1.
pub const KERNEL_PROCESS_KEYWORD: u64 = 0x10;

/// Microsoft-Windows-Kernel-Network `{7DD42A49-5329-4832-8DFD-43D979153A88}`.
///
/// Copied from windows.md §2.3. 【待验证 SPIKE-02】.
pub const KERNEL_NETWORK_GUID: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";

/// Microsoft-Windows-DNS-Client `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`.
///
/// Copied from windows.md §2.4. 【待验证 SPIKE-02】.
pub const DNS_CLIENT_GUID: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";

/// Microsoft-Windows-Kernel-File `{EDD08927-9CC4-4E65-B970-C2560FB5C289}`.
///
/// P1 does not enable this provider (task card restriction). The GUID is named
/// so a config that asks for it can be rejected by identity, not by a typo.
pub const KERNEL_FILE_GUID: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";

/// `EVENT_TRACE_PROPERTIES.BufferSize`, in kilobytes.
///
/// 待 SPIKE-02 实测，当前为文档初始值（windows.md §6: `BufferSize=256KB`）。
pub const BUFFER_SIZE_KB: u32 = 256;

/// `EVENT_TRACE_PROPERTIES.MinimumBuffers`.
///
/// 待 SPIKE-02 实测，当前为文档初始值（windows.md §6: `MinimumBuffers=64`）。
pub const MINIMUM_BUFFERS: u32 = 64;

/// `EVENT_TRACE_PROPERTIES.MaximumBuffers`.
///
/// 待 SPIKE-02 实测，当前为文档初始值（windows.md §6: `MaximumBuffers=1024`）。
pub const MAXIMUM_BUFFERS: u32 = 1024;

/// `Wnode.ClientContext = 1` asks the session for the QPC clock.
///
/// ferrisetw's own `EventTraceProperties::new` hard-codes the same value, and
/// event-schema §4 says a Windows session uses QPC. FILETIME (`ClientContext = 2`)
/// is not requested. Whether `EventRecord::raw_timestamp` then arrives already
/// converted to FILETIME is 【待验证 SPIKE-02】: ferrisetw opens the trace
/// *without* `PROCESS_TRACE_MODE_RAW_TIMESTAMP`, and its own docs say that makes
/// the header timestamp system time. [`EtwStamp::from_raw`] therefore branches
/// on [`EtwClockMode`] instead of assuming one answer.
pub const QPC_CLIENT_CONTEXT: u32 = 1;

/// FILETIME 100-ns ticks between 1601-01-01 and the Unix epoch.
const FILETIME_UNIX_EPOCH_TICKS: i128 = 11_644_473_600 * 10_000_000;

/// One provider the session may enable. Config-driven; see [`SessionConfig::p1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderSpec {
    /// Stable name used in diagnostics. Not a display sentence.
    pub name: &'static str,
    /// Provider GUID, `{XXXXXXXX-...}` form, uppercase hex.
    pub guid: &'static str,
    /// `MatchAnyKeyword`. `0` means "provider default" (ferrisetw passes it through).
    pub any_keyword: u64,
}

impl ProviderSpec {
    /// Kernel-Process, process keyword only. No image-load keyword.
    pub const fn kernel_process() -> Self {
        Self {
            name: "kernel_process",
            guid: KERNEL_PROCESS_GUID,
            any_keyword: KERNEL_PROCESS_KEYWORD,
        }
    }

    /// Kernel-Network. Keyword mask is not pinned: windows.md §2.3 lists none.
    pub const fn kernel_network() -> Self {
        Self {
            name: "kernel_network",
            guid: KERNEL_NETWORK_GUID,
            any_keyword: 0,
        }
    }

    /// DNS-Client.
    pub const fn dns_client() -> Self {
        Self {
            name: "dns_client",
            guid: DNS_CLIENT_GUID,
            any_keyword: 0,
        }
    }
}

/// What P1 is allowed to turn on, and what it must refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderClass {
    /// Kernel-Process, Kernel-Network, or DNS-Client.
    P1,
    /// Kernel-File. Deferred to P2. Enabling it is a config error, not a skip.
    KernelFile,
    /// A GUID this build does not know. Not silently enabled.
    Unknown,
}

/// Classify `guid`. Comparison is case-insensitive and ignores surrounding braces.
pub fn classify_provider(guid: &str) -> ProviderClass {
    let g = normalize_guid(guid);
    if g == normalize_guid(KERNEL_PROCESS_GUID)
        || g == normalize_guid(KERNEL_NETWORK_GUID)
        || g == normalize_guid(DNS_CLIENT_GUID)
    {
        ProviderClass::P1
    } else if g == normalize_guid(KERNEL_FILE_GUID) {
        ProviderClass::KernelFile
    } else {
        ProviderClass::Unknown
    }
}

fn normalize_guid(guid: &str) -> String {
    guid.trim()
        .trim_matches(|c| c == '{' || c == '}')
        .to_ascii_uppercase()
}

/// Why a [`SessionConfig`] was rejected. Carries no path, argv, or hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// `AgentWatch-<boot>` could not be built. `reason` names the rule, not the input.
    BadBootId,
    /// The name is `NT Kernel Logger`, which this crate never opens.
    NtKernelLoggerForbidden,
    /// Kernel-File was requested. P1 does not enable it.
    KernelFileForbidden,
    /// A GUID outside the P1 set was requested.
    UnknownProvider,
    /// The provider list is empty. An empty list is not "watch nothing"; it is
    /// a missing config. Callers that want a probe with no providers say so
    /// through [`SessionConfig::probe_only`].
    NoProviders,
    /// Buffer sizes that cannot describe a session (`buffer_kb == 0`, or
    /// `min_buffers > max_buffers` with `max_buffers != 0`).
    BadBuffers,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadBootId => f.write_str("boot id is empty or not a single path segment"),
            Self::NtKernelLoggerForbidden => {
                f.write_str("NT Kernel Logger is not used; open a named user session")
            }
            Self::KernelFileForbidden => f.write_str("Kernel-File is not enabled in P1"),
            Self::UnknownProvider => f.write_str("provider is not in the P1 set"),
            Self::NoProviders => f.write_str("session config enables no provider"),
            Self::BadBuffers => f.write_str("buffer parameters cannot describe a session"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Buffers, providers, and the session name. Pure data; opening it is [`super::trace`]'s job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    name: String,
    buffer_size_kb: u32,
    min_buffers: u32,
    max_buffers: u32,
    providers: Vec<ProviderSpec>,
}

impl SessionConfig {
    /// P1 session: Kernel-Process, Kernel-Network, DNS-Client, documented buffers.
    ///
    /// `boot_id` becomes the suffix of `AgentWatch-<boot>`. It must be a single
    /// non-empty token (no `\`, `/`, or NUL) so the name cannot escape into a path.
    pub fn p1(boot_id: &str) -> Result<Self, ConfigError> {
        Self::build(
            boot_id,
            BUFFER_SIZE_KB,
            MINIMUM_BUFFERS,
            MAXIMUM_BUFFERS,
            vec![
                ProviderSpec::kernel_process(),
                ProviderSpec::kernel_network(),
                ProviderSpec::dns_client(),
            ],
        )
    }

    /// Same shape as [`Self::p1`], but the caller picks providers and buffers.
    ///
    /// Kernel-File and any GUID outside the P1 set are [`ConfigError`], not dropped.
    /// An empty `providers` is [`ConfigError::NoProviders`].
    pub fn from_parts(
        boot_id: &str,
        buffer_size_kb: u32,
        min_buffers: u32,
        max_buffers: u32,
        providers: Vec<ProviderSpec>,
    ) -> Result<Self, ConfigError> {
        if providers.is_empty() {
            return Err(ConfigError::NoProviders);
        }
        for provider in &providers {
            match classify_provider(provider.guid) {
                ProviderClass::P1 => {}
                ProviderClass::KernelFile => return Err(ConfigError::KernelFileForbidden),
                ProviderClass::Unknown => return Err(ConfigError::UnknownProvider),
            }
        }
        Self::build(boot_id, buffer_size_kb, min_buffers, max_buffers, providers)
    }

    fn build(
        boot_id: &str,
        buffer_size_kb: u32,
        min_buffers: u32,
        max_buffers: u32,
        providers: Vec<ProviderSpec>,
    ) -> Result<Self, ConfigError> {
        let name = session_name(boot_id)?;
        if buffer_size_kb == 0 || (max_buffers != 0 && min_buffers > max_buffers) {
            return Err(ConfigError::BadBuffers);
        }
        Ok(Self {
            name,
            buffer_size_kb,
            min_buffers,
            max_buffers,
            providers,
        })
    }

    /// `AgentWatch-<boot>`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `BufferSize` in KB.
    pub fn buffer_size_kb(&self) -> u32 {
        self.buffer_size_kb
    }

    /// `MinimumBuffers`.
    pub fn min_buffers(&self) -> u32 {
        self.min_buffers
    }

    /// `MaximumBuffers`.
    pub fn max_buffers(&self) -> u32 {
        self.max_buffers
    }

    /// Providers that will be enabled, in config order.
    pub fn providers(&self) -> &[ProviderSpec] {
        &self.providers
    }
}

/// `AgentWatch-<boot>`. Refuses an empty boot id, a separator, or the NT Kernel Logger name.
///
/// A boot id is an opaque token (a boot counter, a hex string). It is not a path
/// and it is not echoed back in the error.
pub fn session_name(boot_id: &str) -> Result<String, ConfigError> {
    if boot_id.is_empty() || boot_id.contains(['\\', '/', '\0', ' ']) || boot_id.contains("..") {
        return Err(ConfigError::BadBootId);
    }
    let name = format!("{SESSION_PREFIX}-{boot_id}");
    if name.eq_ignore_ascii_case(NT_KERNEL_LOGGER) {
        return Err(ConfigError::NtKernelLoggerForbidden);
    }
    Ok(name)
}

/// Whether `name` is one this collector would have opened.
///
/// Used at startup to decide which leftover session to stop. Anything that does
/// not start with `AgentWatch-` is left alone, including `NT Kernel Logger` and
/// another product's session. The comparison is case-insensitive because ETW
/// session names are.
pub fn is_agentwatch_session(name: &str) -> bool {
    let prefix = format!("{SESSION_PREFIX}-");
    name.len() > prefix.len() && name[..prefix.len()].eq_ignore_ascii_case(&prefix)
}

/// PIDs the callback keeps. Everything else is dropped before any property parse.
///
/// The set is swapped as a whole (`ArcSwap<HashSet<_>>`). A callback loads the
/// current `Arc` and returns; it never takes a lock and never parses an event
/// whose header PID is absent. An empty set keeps nothing: "no scope yet" is
/// not "watch the machine".
///
/// Lock-free reads are the point of `arc-swap` (MIT/Apache-2.0). SPIKE-02 has
/// not confirmed that ferrisetw exposes the header PID without a schema lookup;
/// [`crate::EventRecord::process_id`] does, and this filter uses only that.
#[derive(Debug, Default)]
pub struct ScopeFilter {
    pids: ArcSwap<HashSet<u32>>,
}

impl ScopeFilter {
    /// Empty filter. No PID passes.
    pub fn new() -> Self {
        Self {
            pids: ArcSwap::from_pointee(HashSet::new()),
        }
    }

    /// Replace the whole set. The previous set stays alive until in-flight
    /// callbacks drop their `Arc`.
    pub fn replace(&self, pids: impl IntoIterator<Item = u32>) {
        let set: HashSet<u32> = pids.into_iter().collect();
        self.pids.store(Arc::new(set));
    }

    /// `true` when `pid` is in the current set.
    ///
    /// The caller must invoke this before touching event properties. A `false`
    /// result means "return from the callback now".
    pub fn contains(&self, pid: u32) -> bool {
        self.pids.load().contains(&pid)
    }
}

/// One `ControlTrace(QUERY)` reading. Both counters are cumulative since the
/// session was created, not since the previous poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossReading {
    /// `EVENT_TRACE_PROPERTIES.EventsLost`.
    pub events_lost: u32,
    /// `EVENT_TRACE_PROPERTIES.RealTimeBuffersLost`.
    pub realtime_buffers_lost: u32,
}

/// How many events and realtime buffers were lost since the previous reading.
///
/// `None` for a counter that did not move, including a counter that went
/// backwards (a new session, a wrap). A backwards counter is not reported as a
/// huge loss: the caller resets its baseline instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossDelta {
    /// New `EventsLost` since the baseline. `None` when the counter did not grow.
    pub events: Option<u64>,
    /// New `RealTimeBuffersLost` since the baseline. `None` when it did not grow.
    pub realtime_buffers: Option<u64>,
}

impl LossDelta {
    /// `true` when at least one counter grew.
    pub fn any(&self) -> bool {
        self.events.is_some() || self.realtime_buffers.is_some()
    }
}

/// Diff two QUERY readings.
///
/// The first call has no baseline: pass `previous = None` and this returns a
/// delta of `None`s while still telling the caller (via [`LossState`]) to store
/// `current` as the baseline. A counter that jumps on the first sample is the
/// session's starting value, not a loss we observed.
pub fn loss_delta(previous: Option<LossReading>, current: LossReading) -> LossDelta {
    let Some(previous) = previous else {
        return LossDelta {
            events: None,
            realtime_buffers: None,
        };
    };
    LossDelta {
        events: counter_delta(previous.events_lost, current.events_lost),
        realtime_buffers: counter_delta(
            previous.realtime_buffers_lost,
            current.realtime_buffers_lost,
        ),
    }
}

fn counter_delta(previous: u32, current: u32) -> Option<u64> {
    let grown = current.checked_sub(previous)?;
    if grown == 0 {
        None
    } else {
        Some(u64::from(grown))
    }
}

/// Baseline plus the decision of whether this poll should emit a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossPoll {
    /// Reading to store as the next baseline. Always `current`, even when a
    /// counter went backwards: the next poll diffs against the new session.
    pub baseline: LossReading,
    /// `Some` only when a counter grew past the previous baseline.
    pub delta: Option<LossDelta>,
}

/// Fold one QUERY sample into the running baseline.
pub fn poll_loss(previous: Option<LossReading>, current: LossReading) -> LossPoll {
    let delta = loss_delta(previous, current);
    LossPoll {
        baseline: current,
        delta: if delta.any() { Some(delta) } else { None },
    }
}

/// Which clock `EventRecord::raw_timestamp` is expressed in.
///
/// event-schema §4: the session uses QPC and converts with
/// `QueryPerformanceFrequency`. ferrisetw 1.2.0 sets `ClientContext = 1` (QPC)
/// but opens the trace *without* `PROCESS_TRACE_MODE_RAW_TIMESTAMP`, and its
/// own comment says the header then carries system time (FILETIME). SPIKE-02
/// has not measured which one a real callback sees. The conversion is split so
/// a later measurement picks a mode without rewriting the arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtwClockMode {
    /// Header timestamp is a raw QPC value. Convert with the frequency.
    Qpc,
    /// Header timestamp is FILETIME (100-ns ticks since 1601-01-01).
    ///
    /// This is what ferrisetw's `timestamp()` feature assumes, and what
    /// `ProcessTrace` produces unless `PROCESS_TRACE_MODE_RAW_TIMESTAMP` is set.
    FileTime,
}

/// QPC frequency and one paired `(qpc, wall)` sample taken at startup.
///
/// The pair is the Windows equivalent of event-schema §4's
/// `(MONOTONIC, REALTIME)` sample: `mono = qpc * 1e9 / frequency`, and the
/// wall reading of the same instant anchors `ts_wall_ns`. Re-calibration (the
/// Linux side does it every 60 s) is not done here; the pair is whatever the
/// caller sampled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QpcClock {
    /// `QueryPerformanceFrequency`, counts per second. Never zero.
    pub frequency: u64,
    /// `QueryPerformanceCounter` at the sample instant.
    pub qpc_at_sample: u64,
    /// Unix epoch nanoseconds at the same instant. Not a sentinel: the caller
    /// only builds this when it actually read the wall clock.
    pub wall_at_sample_ns: i64,
}

impl QpcClock {
    /// `None` when `frequency` is 0. A zero frequency is a broken clock, not a
    /// reason to invent a conversion.
    pub fn new(frequency: u64, qpc_at_sample: u64, wall_at_sample_ns: i64) -> Option<Self> {
        if frequency == 0 {
            return None;
        }
        Some(Self {
            frequency,
            qpc_at_sample,
            wall_at_sample_ns,
        })
    }

    /// QPC counts to monotonic nanoseconds. Saturates instead of wrapping.
    pub fn qpc_to_mono_ns(&self, qpc: u64) -> u64 {
        qpc_to_ns(qpc, self.frequency)
    }

    /// Wall nanoseconds for a QPC reading, using the sampled pair as the anchor.
    ///
    /// `None` when the subtraction overflows `i64`. That is "this reading has
    /// no wall time", not the unix epoch.
    pub fn qpc_to_wall_ns(&self, qpc: u64) -> Option<i64> {
        let mono = self.qpc_to_mono_ns(qpc) as i128;
        let anchor = self.qpc_to_mono_ns(self.qpc_at_sample) as i128;
        let wall = (self.wall_at_sample_ns as i128).checked_add(mono.checked_sub(anchor)?)?;
        i64::try_from(wall).ok()
    }
}

/// `qpc * 1_000_000_000 / frequency`, saturating, without overflowing `u128`'s
/// practical range. `frequency == 0` yields `0` and is not a real conversion;
/// [`QpcClock::new`] already refuses that frequency.
fn qpc_to_ns(qpc: u64, frequency: u64) -> u64 {
    if frequency == 0 {
        return 0;
    }
    let ns = (u128::from(qpc)).saturating_mul(1_000_000_000) / u128::from(frequency);
    u64::try_from(ns).unwrap_or(u64::MAX)
}

/// FILETIME (100-ns ticks since 1601-01-01) to Unix epoch nanoseconds.
///
/// `None` when the value is not a FILETIME this function can place on the Unix
/// timeline (before 1601, or past `i64::MAX` nanoseconds). A `None` is unknown
/// wall time. It is not zero.
pub fn filetime_to_unix_ns(filetime_ticks: i64) -> Option<i64> {
    if filetime_ticks < 0 {
        return None;
    }
    let ticks = i128::from(filetime_ticks);
    let unix_ticks = ticks.checked_sub(FILETIME_UNIX_EPOCH_TICKS)?;
    let ns = unix_ticks.checked_mul(100)?;
    i64::try_from(ns).ok()
}

/// Both timestamps an event needs, after conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtwStamp {
    /// Monotonic nanoseconds. For QPC this is `qpc * 1e9 / frequency`. For
    /// FILETIME it is the same number as [`Self::ts_wall_ns`] shifted to be
    /// non-negative, because a FILETIME header has no separate monotonic clock.
    pub ts_mono_ns: u64,
    /// Unix epoch nanoseconds. `None` when the conversion could not name a wall
    /// time. Callers must not substitute `0`.
    pub ts_wall_ns: Option<i64>,
}

impl EtwStamp {
    /// Convert one header timestamp.
    ///
    /// `raw` is `EventRecord::raw_timestamp()`. `clock` is required for
    /// [`EtwClockMode::Qpc`] and ignored for [`EtwClockMode::FileTime`].
    /// `None` means the mode needs a clock the caller does not have, or the
    /// raw value is not a timestamp (negative FILETIME).
    pub fn from_raw(mode: EtwClockMode, raw: i64, clock: Option<&QpcClock>) -> Option<Self> {
        match mode {
            EtwClockMode::Qpc => {
                let clock = clock?;
                let qpc = u64::try_from(raw).ok()?;
                Some(Self {
                    ts_mono_ns: clock.qpc_to_mono_ns(qpc),
                    ts_wall_ns: clock.qpc_to_wall_ns(qpc),
                })
            }
            EtwClockMode::FileTime => {
                let wall = filetime_to_unix_ns(raw)?;
                let mono = u64::try_from(wall).ok()?;
                Some(Self {
                    ts_mono_ns: mono,
                    ts_wall_ns: Some(wall),
                })
            }
        }
    }
}

/// One observed OS-level loss, already shaped as an [`aw_core::Gap`].
///
/// `count` is `EventsLost`'s growth when that counter moved, otherwise the
/// `RealTimeBuffersLost` growth. A buffer loss is not an event count; when both
/// grow, the event count wins and the buffer count is only in `detail`.
/// `detail` names the counters (`events_lost`, `realtime_buffers_lost`) and
/// never a payload.
pub fn gap_for_loss(delta: LossDelta, from_mono_ns: u64, to_mono_ns: u64) -> Gap {
    let (count, detail) = match (delta.events, delta.realtime_buffers) {
        (Some(events), Some(buffers)) => (
            Some(events),
            Some(format!(
                "events_lost +{events}; realtime_buffers_lost +{buffers}"
            )),
        ),
        (Some(events), None) => (Some(events), Some(format!("events_lost +{events}"))),
        (None, Some(buffers)) => (
            Some(buffers),
            Some(format!("realtime_buffers_lost +{buffers}")),
        ),
        (None, None) => (None, None),
    };
    Gap::new(
        Source::new(SESSION_SOURCE),
        GapKind::LostByOs,
        vec!["proc".to_owned(), "net".to_owned(), "dns".to_owned()],
        from_mono_ns,
        to_mono_ns,
        count,
        detail,
    )
}

/// Wrap [`gap_for_loss`] in a [`RawEvent`].
///
/// `ts_wall_ns` stays `0` only when the caller passes `None`: this function
/// does not invent a wall time, and [`RawEvent::ts_wall_ns`] is an `i64` with
/// no `Option`. The `0` is therefore "wall time was not supplied", and `seq`
/// is whatever counter the caller owns. `evidence` is [`Evidence::E1`] because
/// a gap is itself a fact (event-schema §3).
pub fn raw_gap_for_loss(
    delta: LossDelta,
    seq: u64,
    from_mono_ns: u64,
    to_mono_ns: u64,
    ts_wall_ns: Option<i64>,
) -> RawEvent {
    let gap = gap_for_loss(delta, from_mono_ns, to_mono_ns);
    let source = Source::new(SESSION_SOURCE);
    let wall = ts_wall_ns.unwrap_or(0);
    match RawEvent::try_new(RawEventParts {
        seq,
        ts_mono_ns: to_mono_ns,
        ts_wall_ns: wall,
        session_id: None,
        proc: None,
        source,
        evidence: Evidence::E1,
        kind: EventKind::Gap(gap),
    }) {
        Ok(event) => event,
        // `try_new` rejects a required `None` without an NA entry. `Gap` has
        // none, so this arm does not run. If a later schema change makes it
        // fail, the event is still built directly: a lost counter must stay
        // visible, and panicking in the poll thread would hide it.
        Err(_) => raw_gap_for_loss_direct(delta, seq, from_mono_ns, to_mono_ns, wall),
    }
}

fn raw_gap_for_loss_direct(
    delta: LossDelta,
    seq: u64,
    from_mono_ns: u64,
    to_mono_ns: u64,
    ts_wall_ns: i64,
) -> RawEvent {
    let source = Source::new(SESSION_SOURCE);
    RawEvent {
        v: SCHEMA_VERSION,
        seq,
        ts_mono_ns: to_mono_ns,
        ts_wall_ns,
        session_id: None,
        proc: None,
        source: source.clone(),
        evidence: Evidence::E1,
        field_evidence: std::collections::BTreeMap::new(),
        kind: EventKind::Gap(gap_for_loss(delta, from_mono_ns, to_mono_ns)),
    }
}

/// What [`super::trace::probe`] reports. No session is held open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    /// `true` when a session was created and stopped during the probe.
    pub session_creatable: bool,
    /// Providers the probe was able to enable. Empty when the session itself
    /// could not be created; a provider that fails does not fail the others.
    pub providers: Vec<ProviderSpec>,
}

/// Why a session or a probe failed. Text only; no argv, no URL, no path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// ETW returned access denied (Win32 error 5). The process is not
    /// Administrator, not in Performance Log Users, and not SYSTEM.
    AccessDenied,
    /// A session with this name is already running and could not be stopped.
    AlreadyExists,
    /// `ControlTrace`, `StartTrace`, or `EnableTraceEx2` failed. `code` is the
    /// Win32 error. `op` is `start`, `stop`, `query`, or `enable`.
    Etw { op: &'static str, code: i32 },
    /// The config itself is unusable. Raised before any ETW call.
    Config(ConfigError),
    /// The bounded channel is disconnected. The callback used `try_send` and
    /// the receiver is gone. Not a drop: the caller records it.
    ChannelClosed,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessDenied => f.write_str(
                "access denied creating an ETW session; an elevated token is required \
                 (Administrator, Performance Log Users, or SYSTEM). this process does not elevate itself",
            ),
            Self::AlreadyExists => {
                f.write_str("an ETW session with this name already exists and was not stopped")
            }
            Self::Etw { op, code } => write!(f, "ETW {op} failed with Win32 error {code}"),
            Self::Config(err) => write!(f, "session config: {err}"),
            Self::ChannelClosed => f.write_str("event channel is closed"),
        }
    }
}

impl std::error::Error for SessionError {}

impl SessionError {
    /// Win32 `ERROR_ACCESS_DENIED` is 5. `ERROR_ALREADY_EXISTS` is 183.
    ///
    /// ferrisetw reports `windows::core::Error::code().0`, which is an HRESULT:
    /// `5` arrives as `-2147024891` (`0x80070005`). Both forms are recognized.
    /// A code this function does not know stays [`SessionError::Etw`] with the
    /// number unchanged, so the diagnostic still names what ETW returned.
    pub fn from_win32(op: &'static str, code: i32) -> Self {
        match win32_error_code(code) {
            5 => Self::AccessDenied,
            183 => Self::AlreadyExists,
            _ => Self::Etw { op, code },
        }
    }
}

/// `0x8007xxxx` is a Win32 error packed into an HRESULT. The low 16 bits are
/// the Win32 code. Anything else is already a Win32 code (or not an error).
fn win32_error_code(code: i32) -> i32 {
    let packed = code as u32;
    if packed & 0xFFFF_0000 == 0x8007_0000 {
        (packed & 0xFFFF) as i32
    } else {
        code
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn session_name_uses_the_boot_suffix_and_rejects_a_bad_token() {
        assert_eq!(session_name("1").unwrap(), "AgentWatch-1");
        assert_eq!(session_name("boot-abc").unwrap(), "AgentWatch-boot-abc");
        assert!(session_name("").is_err());
        assert!(session_name("a/b").is_err());
        assert!(session_name("a\\b").is_err());
        assert!(session_name("a b").is_err());
        assert!(session_name("..").is_err());
        assert!(session_name("has\0nul").is_err());
    }

    #[test]
    fn leftover_detection_only_matches_our_prefix() {
        assert!(is_agentwatch_session("AgentWatch-1"));
        assert!(is_agentwatch_session("agentwatch-42"));
        assert!(!is_agentwatch_session("AgentWatch"));
        assert!(!is_agentwatch_session("AgentWatch-"));
        assert!(!is_agentwatch_session("NT Kernel Logger"));
        assert!(!is_agentwatch_session("SomethingElse-1"));
    }

    #[test]
    fn p1_config_enables_three_providers_and_refuses_kernel_file() {
        let config = SessionConfig::p1("7").unwrap();
        assert_eq!(config.name(), "AgentWatch-7");
        assert_eq!(config.buffer_size_kb(), 256);
        assert_eq!(config.min_buffers(), 64);
        assert_eq!(config.max_buffers(), 1024);
        let names: Vec<_> = config.providers().iter().map(|p| p.name).collect();
        assert_eq!(
            names,
            vec!["kernel_process", "kernel_network", "dns_client"]
        );
        assert!(config
            .providers()
            .iter()
            .all(|p| classify_provider(p.guid) == ProviderClass::P1));

        let file = ProviderSpec {
            name: "kernel_file",
            guid: KERNEL_FILE_GUID,
            any_keyword: 0,
        };
        assert_eq!(
            SessionConfig::from_parts("7", 256, 64, 1024, vec![file]).unwrap_err(),
            ConfigError::KernelFileForbidden
        );
        assert_eq!(
            SessionConfig::from_parts("7", 256, 64, 1024, vec![]).unwrap_err(),
            ConfigError::NoProviders
        );
        assert_eq!(
            SessionConfig::from_parts("7", 0, 1, 1, vec![ProviderSpec::dns_client()]).unwrap_err(),
            ConfigError::BadBuffers
        );
        assert_eq!(
            SessionConfig::from_parts("7", 64, 8, 4, vec![ProviderSpec::dns_client()]).unwrap_err(),
            ConfigError::BadBuffers
        );
    }

    #[test]
    fn scope_filter_drops_pids_outside_the_set_without_a_lock() {
        let filter = ScopeFilter::new();
        assert!(!filter.contains(4));
        filter.replace([10, 20, 20]);
        assert!(filter.contains(10));
        assert!(filter.contains(20));
        assert!(!filter.contains(4));
        assert!(!filter.contains(0));
        filter.replace([]);
        assert!(!filter.contains(10));
    }

    #[test]
    fn loss_delta_counts_growth_and_ignores_the_first_sample() {
        let first = LossReading {
            events_lost: 5,
            realtime_buffers_lost: 1,
        };
        let opened = poll_loss(None, first);
        assert_eq!(opened.delta, None);
        assert_eq!(opened.baseline, first);

        let same = poll_loss(Some(first), first);
        assert_eq!(same.delta, None);

        let grown = LossReading {
            events_lost: 8,
            realtime_buffers_lost: 1,
        };
        let step = poll_loss(Some(first), grown);
        assert_eq!(
            step.delta,
            Some(LossDelta {
                events: Some(3),
                realtime_buffers: None,
            })
        );

        let both = LossReading {
            events_lost: 8,
            realtime_buffers_lost: 4,
        };
        let step = poll_loss(Some(grown), both).delta.unwrap();
        assert_eq!(step.events, None);
        assert_eq!(step.realtime_buffers, Some(3));

        // A counter that resets (new session, or a wrap) is not a huge loss.
        let reset = LossReading {
            events_lost: 0,
            realtime_buffers_lost: 0,
        };
        let step = poll_loss(Some(both), reset);
        assert_eq!(step.delta, None);
        assert_eq!(step.baseline, reset);
    }

    #[test]
    fn loss_becomes_a_lost_by_os_gap() {
        let delta = LossDelta {
            events: Some(3),
            realtime_buffers: Some(1),
        };
        let event = raw_gap_for_loss(delta, 9, 1_000, 2_000, Some(50));
        assert_eq!(event.seq, 9);
        assert_eq!(event.ts_mono_ns, 2_000);
        assert_eq!(event.ts_wall_ns, 50);
        assert_eq!(event.evidence, Evidence::E1);
        assert_eq!(event.source.as_str(), SESSION_SOURCE);
        match &event.kind {
            EventKind::Gap(gap) => {
                assert_eq!(gap.gap_kind, GapKind::LostByOs);
                assert_eq!(gap.count, Some(3));
                assert_eq!(gap.from_mono_ns, 1_000);
                assert_eq!(gap.to_mono_ns, 2_000);
                let detail = gap.detail.as_deref().unwrap();
                assert!(detail.contains("events_lost +3"));
                assert!(detail.contains("realtime_buffers_lost +1"));
                assert!(!detail.contains("argv"));
            }
            other => panic!("expected a gap, got {other:?}"),
        }

        let buffers_only = LossDelta {
            events: None,
            realtime_buffers: Some(2),
        };
        let event = raw_gap_for_loss(buffers_only, 1, 0, 5, None);
        match &event.kind {
            EventKind::Gap(gap) => {
                assert_eq!(gap.count, Some(2));
                assert_eq!(event.ts_wall_ns, 0);
            }
            other => panic!("expected a gap, got {other:?}"),
        }
    }

    #[test]
    fn qpc_conversion_uses_the_frequency_and_the_sampled_pair() {
        // 10 MHz counter. 1 count = 100 ns.
        let clock = QpcClock::new(10_000_000, 1_000, 5_000_000_000).unwrap();
        assert_eq!(clock.qpc_to_mono_ns(1_000), 100_000);
        assert_eq!(clock.qpc_to_wall_ns(1_000), Some(5_000_000_000));
        // 500 counts later = 50_000 ns later.
        assert_eq!(clock.qpc_to_mono_ns(1_500), 150_000);
        assert_eq!(clock.qpc_to_wall_ns(1_500), Some(5_000_050_000));

        let stamp = EtwStamp::from_raw(EtwClockMode::Qpc, 1_500, Some(&clock)).unwrap();
        assert_eq!(stamp.ts_mono_ns, 150_000);
        assert_eq!(stamp.ts_wall_ns, Some(5_000_050_000));
        assert!(EtwStamp::from_raw(EtwClockMode::Qpc, 1, None).is_none());
        assert!(QpcClock::new(0, 0, 0).is_none());
    }

    #[test]
    fn filetime_conversion_lands_on_the_unix_epoch() {
        // 100-ns ticks. The constant is the 1601→1970 offset, so that exact
        // value is unix nanosecond 0.
        let epoch_ticks = 11_644_473_600 * 10_000_000;
        assert_eq!(filetime_to_unix_ns(epoch_ticks), Some(0));
        // One second later.
        assert_eq!(
            filetime_to_unix_ns(epoch_ticks + 10_000_000),
            Some(1_000_000_000)
        );
        assert_eq!(filetime_to_unix_ns(-1), None);
        assert_eq!(filetime_to_unix_ns(0), None);

        let stamp =
            EtwStamp::from_raw(EtwClockMode::FileTime, epoch_ticks + 10_000_000, None).unwrap();
        assert_eq!(stamp.ts_wall_ns, Some(1_000_000_000));
        assert_eq!(stamp.ts_mono_ns, 1_000_000_000);
    }

    #[test]
    fn access_denied_is_a_distinct_error_and_does_not_panic() {
        let err = SessionError::from_win32("start", 5);
        assert_eq!(err, SessionError::AccessDenied);
        let text = err.to_string();
        assert!(text.contains("elevated"));
        assert!(!text.contains("argv"));
        assert_eq!(
            SessionError::from_win32("stop", 183),
            SessionError::AlreadyExists
        );
        assert_eq!(
            SessionError::from_win32("query", 87),
            SessionError::Etw {
                op: "query",
                code: 87
            }
        );
        // ferrisetw forwards `Error::code().0`, an HRESULT. 0x80070005 is
        // ERROR_ACCESS_DENIED and 0x800700B7 is ERROR_ALREADY_EXISTS.
        assert_eq!(
            SessionError::from_win32("start", -2147024891),
            SessionError::AccessDenied
        );
        assert_eq!(
            SessionError::from_win32("start", -2147024713),
            SessionError::AlreadyExists
        );
        // An unrecognized HRESULT keeps the original number, not the low 16 bits.
        assert_eq!(
            SessionError::from_win32("start", -2147024894),
            SessionError::Etw {
                op: "start",
                code: -2147024894
            }
        );
    }
}
