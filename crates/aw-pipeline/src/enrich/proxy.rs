//! Loopback-to-proxy rewrite and direct-bypass marks (P3-PIPE-01).
//!
//! Network-attribution §5.3 and ADR-0006. With the explicit proxy on, the kernel
//! sees `process → 127.0.0.1:<proxy port>`. The daemon opens the upstream
//! connection. This module rewrites the loopback flow's remote onto the upstream
//! target the caller supplies, sets `via_proxy`, and keeps the kernel's byte
//! counts. It never copies a proxy body length into `bytes_up` / `bytes_down`.
//!
//! The proxy's own upstream flows are excluded from session network stats. They
//! are still named in [`ProxyPlan::http`]: those rows belong in the `http` table
//! and nowhere else. This module does not write that table.
//!
//! Attribution is the client source port of a loopback connection the kernel
//! collector already reported. That port selects the flow, and the flow already
//! carries the PID and [`ProcUid`]. `http.flow_id` is then the rewritten flow's id.
//!
//! A TCP or UDP connect to a non-loopback address while the proxy is on is
//! `direct`. UDP to port 443 is also `quic`. The URL field of those flows is
//! [`Evidence::NA`] with `direct_bypass_proxy` or `quic`. The proxy process
//! itself is not in the session, so its connects are not marked.
//!
//! There is no hudsucker client here. [`ProxyObservation`] is what a later
//! caller fills in. A field the observation does not carry stays [`None`], and
//! the URL evidence says why. `0` and `""` are not used for "unknown".
//!
//! Nothing in this module reads a clock, opens a socket, or logs a URL, a
//! header, or argv.

use std::collections::BTreeMap;
use std::net::IpAddr;

use aw_core::{Evidence, NaReason, ProcUid, SessionId};

use crate::output::NetFlowRec;

/// `field_evidence` key for the URL, which `net_flows` does not store as a column.
///
/// Direct and QUIC flows have no URL. The reason lives here, not in an empty string.
pub const URL_FIELD: &str = "url";

/// UDP port that means QUIC when the flow did not go through the proxy.
///
/// Network-attribution §5.3: "UDP/443 另标 `quic`".
pub const QUIC_PORT: u16 = 443;

/// `domain_source` written when the remote was rewritten from a proxy upstream target.
pub const DOMAIN_SOURCE_PROXY: &str = "proxy";

/// What one proxied exchange looked like, as far as attribution needs.
///
/// Filled by whoever talks to the proxy. This module does not parse HTTP and
/// does not read a body. `req_body_bytes` / `resp_body_bytes` are the proxy's
/// own counts; they are copied onto [`HttpAttribution`] and never onto a flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyObservation {
    /// Session the proxy was started for.
    pub session_id: SessionId,
    /// Client source port of the loopback connection, when the proxy reported one.
    ///
    /// `None` means the port was not observed. The flow is then not matched, and
    /// `http.flow_id` stays `None` with `NA(attribution_break)`. It is not `0`.
    pub client_src_port: Option<u16>,
    /// Upstream host the proxy connected to. Already a name or an address, not a URL.
    ///
    /// `None` when the proxy did not report a target. The loopback remote is left
    /// as the kernel saw it.
    pub upstream_host: Option<String>,
    /// Upstream port. `None` when not observed. Not defaulted to 80 or 443.
    pub upstream_port: Option<u16>,
    /// Upstream IP, when the proxy resolved one. A name is not turned into an address here.
    pub upstream_ip: Option<IpAddr>,
    /// Request time, monotonic nanoseconds, on the same clock as the flow.
    pub ts_ns: u64,
    /// HTTP method. `None` when the exchange was a tunnel with no request line.
    pub method: Option<String>,
    /// Redacted URL. `None` when the proxy did not see one (tunnel, pin, QUIC).
    ///
    /// Absence is not `""`. The reason is [`Self::url_na`].
    pub url: Option<String>,
    /// Why `url` is absent. Ignored when `url` is `Some`.
    ///
    /// `None` together with `url: None` is `NA(tls_no_proxy)` only if the caller
    /// sets it. This module does not invent a reason the caller did not give,
    /// except the direct and QUIC marks on flows, which §5.3 fixes.
    pub url_na: Option<NaReason>,
    /// Proxy-observed request body length. Not a substitute for `bytes_up`.
    pub req_body_bytes: Option<u64>,
    /// Proxy-observed response body length. Not a substitute for `bytes_down`.
    pub resp_body_bytes: Option<u64>,
}

/// A flow the kernel collector reported, reduced to what matching needs.
///
/// Built from a [`NetFlowRec`]. `flow_id` is the id aggregate assigned; `None`
/// means this flow cannot be pointed at from `http.flow_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackFlow {
    /// Aggregate flow id. `None` when the record was not built by that stage.
    pub flow_id: Option<u64>,
    /// Session the flow was scoped into.
    pub session_id: Option<SessionId>,
    /// Process that owns the socket. Already resolved from the PID.
    pub proc_uid: Option<ProcUid>,
    /// OS pid, when the caller still has it. Not stored on [`NetFlowRec`].
    ///
    /// `None` is "not passed in", not pid 0.
    pub pid: Option<u32>,
    /// `tcp` or `udp`. `None` when the flow record did not say.
    pub proto: Option<String>,
    /// Client address. Loopback is decided from this and [`Self::remote_ip`].
    pub local_ip: Option<IpAddr>,
    /// Client source port. The match key.
    pub local_port: Option<u16>,
    /// What the kernel called the remote address.
    pub remote_ip: Option<IpAddr>,
    /// What the kernel called the remote port.
    pub remote_port: Option<u16>,
    /// Kernel-observed bytes sent. Left untouched by the rewrite.
    pub bytes_up: Option<u64>,
    /// Kernel-observed bytes received. Left untouched by the rewrite.
    pub bytes_down: Option<u64>,
    /// Record evidence. Not raised.
    pub evidence: Evidence,
}

impl LoopbackFlow {
    /// Copy the fields a [`NetFlowRec`] actually has.
    ///
    /// Address text that is not an IP stays `None` and is not parsed into a
    /// guess. `pid` is not on the record, so it stays `None`.
    pub fn from_rec(rec: &NetFlowRec) -> Self {
        Self {
            flow_id: rec.flow_id,
            session_id: rec.session_id,
            proc_uid: rec.proc_uid,
            pid: None,
            proto: rec.proto.clone(),
            local_ip: rec.local_ip.as_deref().and_then(parse_ip),
            local_port: rec.local_port,
            remote_ip: rec.remote_ip.as_deref().and_then(parse_ip),
            remote_port: rec.remote_port,
            bytes_up: rec.bytes_up,
            bytes_down: rec.bytes_down,
            evidence: rec.evidence.clone(),
        }
    }
}

/// Which flows belong to the proxy process and must not enter session totals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySelf {
    /// `ProcUid` of the daemon side that dials upstream. `None` when the caller
    /// has not identified it: nothing is then excluded, rather than excluding pid 0.
    pub proc_uid: Option<ProcUid>,
}

/// One session's proxy, plus the observations the caller has so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySession {
    /// Session that was started with `--proxy`.
    pub session_id: SessionId,
    /// Listen port. A loopback remote of this port is a candidate for rewrite.
    pub listen_port: u16,
    /// Proxy process, when known.
    pub proxy: ProxySelf,
    /// Exchanges the proxy reported. Order is the caller's order.
    pub observations: Vec<ProxyObservation>,
}

/// What to do with one flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowMark {
    /// Not a proxy-session flow, or the proxy is not involved. Leave it.
    Unchanged,
    /// Loopback connect to the proxy port, rewritten onto the upstream target.
    ViaProxy(ViaProxy),
    /// The proxy process's own upstream dial. Keep it out of session net stats.
    ProxyUpstream,
    /// A session process dialed a non-loopback address while the proxy was on.
    Direct(DirectMark),
}

/// Rewrite of `net_flows.remote`. Bytes are the kernel's, not the proxy's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViaProxy {
    /// Flow id the matching observation should store in `http.flow_id`.
    pub flow_id: Option<u64>,
    /// Process the kernel attributed the loopback socket to.
    pub proc_uid: Option<ProcUid>,
    /// OS pid, when [`LoopbackFlow::pid`] had one.
    pub pid: Option<u32>,
    /// Client source port that selected this flow.
    pub client_src_port: u16,
    /// Upstream host, when the observation carried one.
    pub remote_host: Option<String>,
    /// Upstream IP text, when the observation carried an address.
    ///
    /// `None` leaves the stored remote IP as the kernel reported it: this module
    /// does not invent an address from a hostname.
    pub remote_ip: Option<IpAddr>,
    /// Upstream port, when observed.
    pub remote_port: Option<u16>,
    /// Kernel `bytes_up`. Copied through, including `None`.
    pub bytes_up: Option<u64>,
    /// Kernel `bytes_down`. Copied through, including `None`.
    pub bytes_down: Option<u64>,
}

/// A connect that did not use the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectMark {
    /// `true` when the flow is UDP to [`QUIC_PORT`].
    pub quic: bool,
    /// Why the URL is absent. `quic` wins when both apply: QUIC is the more specific reason.
    pub url_na: NaReason,
}

/// `http` row attribution. Not an `http` insert.
///
/// `flow_id` points at the rewritten flow. Body lengths are the proxy's and are
/// not the flow's byte columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAttribution {
    /// Session of the observation.
    pub session_id: SessionId,
    /// Process of the matched loopback flow. `None` when no flow matched.
    pub proc_uid: Option<ProcUid>,
    /// OS pid of that process, when the flow carried one.
    pub pid: Option<u32>,
    /// Rewritten flow's id. `None` when the source port matched nothing.
    pub flow_id: Option<u64>,
    /// Why `flow_id` is absent. `None` when it is present.
    pub flow_na: Option<NaReason>,
    /// Request time from the observation.
    pub ts_ns: u64,
    /// Method, when the proxy saw a request line.
    pub method: Option<String>,
    /// Redacted URL, when the proxy saw one.
    pub url: Option<String>,
    /// Why `url` is absent. `None` when `url` is present.
    pub url_na: Option<NaReason>,
    /// Proxy request-body length. Not kernel `bytes_up`.
    pub req_body_bytes: Option<u64>,
    /// Proxy response-body length. Not kernel `bytes_down`.
    pub resp_body_bytes: Option<u64>,
    /// Evidence of the attribution. E2 when the proxy reported the exchange and
    /// a flow matched. Not raised above what the flow and the observation support.
    pub evidence: Evidence,
}

/// Rewrite, exclusion, and direct marks for one session's flows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyPlan {
    /// One entry per input flow, in the same order.
    pub flows: Vec<FlowMark>,
    /// One entry per observation, in the same order. These go to `http` only.
    pub http: Vec<HttpAttribution>,
    /// Flow indexes (into [`Self::flows`]) whose bytes must not be added to the
    /// session's network totals. Proxy upstream only.
    pub excluded_from_session_stats: Vec<usize>,
}

/// Apply §5.3 to `flows` for one proxy session.
///
/// `flows` is every flow the caller is considering, including other sessions:
/// a flow whose session is not [`ProxySession::session_id`] is [`FlowMark::Unchanged`].
/// Matching consumes each observation at most once, in order, against the first
/// still-unmatched loopback flow with the same client source port.
pub fn plan(session: &ProxySession, flows: &[LoopbackFlow]) -> ProxyPlan {
    let mut marks = Vec::with_capacity(flows.len());
    let mut claimed = vec![false; flows.len()];
    let mut http = Vec::with_capacity(session.observations.len());

    for obs in &session.observations {
        if obs.session_id != session.session_id {
            http.push(unmatched(obs, NaReason::AttributionBreak));
            continue;
        }
        match find_loopback(session, flows, &claimed, obs.client_src_port) {
            Some(index) => {
                claimed[index] = true;
                http.push(matched(obs, &flows[index]));
            }
            None => http.push(unmatched(obs, na_for_unmatched(obs))),
        }
    }

    let mut excluded = Vec::new();
    for (index, flow) in flows.iter().enumerate() {
        let mark = mark_flow(session, flow, claimed[index]);
        if matches!(mark, FlowMark::ProxyUpstream) {
            excluded.push(index);
        }
        marks.push(mark);
    }

    ProxyPlan {
        flows: marks,
        http,
        excluded_from_session_stats: excluded,
    }
}

/// Write a [`ViaProxy`] onto `rec`.
///
/// `remote_ip` / `remote_port` / `domain` change only when the rewrite carried
/// that field. `bytes_up` and `bytes_down` are not assigned. `via_proxy` becomes
/// `true`. Returns `false` when `mark` is not a rewrite, and then changes nothing.
pub fn apply_via_proxy(rec: &mut NetFlowRec, mark: &FlowMark) -> bool {
    let FlowMark::ViaProxy(via) = mark else {
        return false;
    };
    if let Some(ip) = via.remote_ip {
        rec.remote_ip = Some(ip.to_string());
    }
    if let Some(port) = via.remote_port {
        rec.remote_port = Some(port);
    }
    if let Some(host) = via.remote_host.clone() {
        rec.domain = Some(host);
        rec.domain_source = Some(DOMAIN_SOURCE_PROXY.to_owned());
    }
    rec.via_proxy = true;
    // `via.bytes_up` / `via.bytes_down` are the kernel counts already on `rec`.
    // They are not assigned from the proxy observation. See network-attribution §5.3.
    true
}

/// URL evidence for a flow mark.
///
/// Direct and QUIC return the §5.3 reason. Anything else returns `None`: this
/// function does not decide that a normal flow's URL is missing.
pub fn url_evidence(mark: &FlowMark) -> Option<Evidence> {
    match mark {
        FlowMark::Direct(direct) => Some(Evidence::NA(direct.url_na.clone())),
        FlowMark::ViaProxy(_) | FlowMark::ProxyUpstream | FlowMark::Unchanged => None,
    }
}

/// Insert `url → NA(reason)` for a direct or QUIC flow.
///
/// Existing keys are left in place. A direct flow that already has URL evidence
/// keeps it: this does not upgrade and does not overwrite.
pub fn note_url_na(field_evidence: &mut BTreeMap<String, Evidence>, mark: &FlowMark) {
    let Some(evidence) = url_evidence(mark) else {
        return;
    };
    field_evidence
        .entry(URL_FIELD.to_owned())
        .or_insert(evidence);
}

fn mark_flow(session: &ProxySession, flow: &LoopbackFlow, claimed: bool) -> FlowMark {
    if flow.session_id != Some(session.session_id) {
        return FlowMark::Unchanged;
    }
    if is_proxy_self(session, flow) {
        return FlowMark::ProxyUpstream;
    }
    if claimed {
        // `claimed` only happens after a source-port match, so this is Some.
        // A flow that lost its port between the match and here is left alone
        // rather than stored with port 0.
        return via_from(session, flow).map_or(FlowMark::Unchanged, FlowMark::ViaProxy);
    }
    if is_loopback_to_proxy(session, flow) {
        // The kernel saw the session hit the proxy, but no observation named
        // this source port. Still `via_proxy`: the remote stays the loopback
        // address because there is no upstream target to write. Bytes stay.
        // A missing source port is not rewritten into 0; there is nothing to match.
        let Some(client_src_port) = flow.local_port else {
            return FlowMark::Unchanged;
        };
        return FlowMark::ViaProxy(ViaProxy {
            flow_id: flow.flow_id,
            proc_uid: flow.proc_uid,
            pid: flow.pid,
            client_src_port,
            remote_host: None,
            remote_ip: None,
            remote_port: None,
            bytes_up: flow.bytes_up,
            bytes_down: flow.bytes_down,
        });
    }
    if is_direct(flow) {
        let quic = is_quic(flow);
        return FlowMark::Direct(DirectMark {
            quic,
            url_na: if quic {
                NaReason::Quic
            } else {
                NaReason::DirectBypassProxy
            },
        });
    }
    FlowMark::Unchanged
}

/// `via_proxy` for a flow an observation already claimed.
///
/// The upstream target comes from the observation whose client port is this
/// flow's source port. [`plan`] claims a flow once, so a later observation
/// with the same port does not get a second rewrite. `None` when the flow has
/// no source port: that is not rewritten into port 0.
fn via_from(session: &ProxySession, flow: &LoopbackFlow) -> Option<ViaProxy> {
    let client_src_port = flow.local_port?;
    let obs = session
        .observations
        .iter()
        .find(|obs| obs.client_src_port == Some(client_src_port));
    Some(ViaProxy {
        flow_id: flow.flow_id,
        proc_uid: flow.proc_uid,
        pid: flow.pid,
        client_src_port,
        remote_host: obs.and_then(|obs| obs.upstream_host.clone()),
        remote_ip: obs.and_then(|obs| obs.upstream_ip),
        remote_port: obs.and_then(|obs| obs.upstream_port),
        bytes_up: flow.bytes_up,
        bytes_down: flow.bytes_down,
    })
}

fn find_loopback(
    session: &ProxySession,
    flows: &[LoopbackFlow],
    claimed: &[bool],
    port: Option<u16>,
) -> Option<usize> {
    let port = port?;
    flows.iter().enumerate().find_map(|(index, flow)| {
        if claimed[index] {
            return None;
        }
        if flow.session_id != Some(session.session_id) {
            return None;
        }
        if is_proxy_self(session, flow) {
            return None;
        }
        if flow.local_port != Some(port) {
            return None;
        }
        if !is_loopback_to_proxy(session, flow) {
            return None;
        }
        Some(index)
    })
}

fn is_proxy_self(session: &ProxySession, flow: &LoopbackFlow) -> bool {
    match session.proxy.proc_uid {
        Some(uid) => flow.proc_uid == Some(uid),
        None => false,
    }
}

fn is_loopback_to_proxy(session: &ProxySession, flow: &LoopbackFlow) -> bool {
    let Some(remote) = flow.remote_ip else {
        return false;
    };
    remote.is_loopback() && flow.remote_port == Some(session.listen_port)
}

/// Non-loopback TCP/UDP. A flow with no remote address is not called direct:
/// "unknown destination" is not "bypassed the proxy".
fn is_direct(flow: &LoopbackFlow) -> bool {
    let Some(remote) = flow.remote_ip else {
        return false;
    };
    if remote.is_loopback() {
        return false;
    }
    matches!(flow.proto.as_deref(), Some("tcp" | "udp"))
}

fn is_quic(flow: &LoopbackFlow) -> bool {
    flow.proto.as_deref() == Some("udp") && flow.remote_port == Some(QUIC_PORT)
}

fn matched(obs: &ProxyObservation, flow: &LoopbackFlow) -> HttpAttribution {
    HttpAttribution {
        session_id: obs.session_id,
        proc_uid: flow.proc_uid,
        pid: flow.pid,
        flow_id: flow.flow_id,
        flow_na: flow
            .flow_id
            .map(|_| None)
            .unwrap_or(Some(NaReason::AttributionBreak)),
        ts_ns: obs.ts_ns,
        method: obs.method.clone(),
        url: obs.url.clone(),
        url_na: url_na(obs),
        req_body_bytes: obs.req_body_bytes,
        resp_body_bytes: obs.resp_body_bytes,
        evidence: Evidence::E2,
    }
}

fn unmatched(obs: &ProxyObservation, reason: NaReason) -> HttpAttribution {
    HttpAttribution {
        session_id: obs.session_id,
        proc_uid: None,
        pid: None,
        flow_id: None,
        flow_na: Some(reason),
        ts_ns: obs.ts_ns,
        method: obs.method.clone(),
        url: obs.url.clone(),
        url_na: url_na(obs),
        req_body_bytes: obs.req_body_bytes,
        resp_body_bytes: obs.resp_body_bytes,
        evidence: Evidence::NA(NaReason::AttributionBreak),
    }
}

fn na_for_unmatched(_obs: &ProxyObservation) -> NaReason {
    // No source port, or a port no loopback flow carried. Either way the
    // exchange cannot be tied to a PID. Same reason; the port is not invented.
    NaReason::AttributionBreak
}

fn url_na(obs: &ProxyObservation) -> Option<NaReason> {
    if obs.url.is_some() {
        None
    } else {
        obs.url_na.clone()
    }
}

fn parse_ip(text: &str) -> Option<IpAddr> {
    text.parse().ok()
}
