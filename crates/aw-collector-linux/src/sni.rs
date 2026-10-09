//! First-write TLS ClientHello extraction (P3-LNX-01).
//!
//! The kernel side is [`bpf/sni.bpf.c`](bpf/sni.bpf.c). That file is not built:
//! Aya is not a dependency of this crate (see the crate-root note), and nothing
//! here attaches a kprobe, opens a ring buffer, or calls `bpf_probe_read_user`.
//!
//! What does run is [`SniExtractor`]. It takes the first-write prefix a probe
//! would already have copied (at most [`SNI_PREFIX_CAP`] bytes) and turns it
//! into one `tls_sni` event. The bytes are borrowed; this module does not keep
//! them, and it does not read anything past that prefix.
//!
//! When the kernel cannot read user memory at `tcp_sendmsg`, [`SniAttach::attach`]
//! returns [`SniError::FallbackNeeded`]. [`SniAttach::start`] is the collector
//! entry that records that refusal as a [`aw_core::Gap`]: Aya is not linked and
//! `sni.bpf.c` is not built, so `tcp_sendmsg` was not attached. The gap is
//! `GapKind::Unsupported` (the existing "this collector cannot do this" variant)
//! with `detail` `sni_attach_unavailable`. It is not a `tls_sni` event and it is
//! not evidence that a hostname was seen.
//!
//! AF_PACKET is not opened here. `socket(AF_PACKET)` needs `CAP_NET_RAW` and a
//! libc binding this crate does not have, and a failed open on a non-Linux host
//! would be a different fact from "the privileged runtime has not been written".
//! The fallback stays with the privileged runtime. [`SniExtractor`] still accepts
//! a prefix the caller already copied and stamps `linux.afpacket/sni` on it.
//! This module never invents an empty prefix to stand in for a packet it did
//! not read.
//!
//! Only a process the caller has already placed in the session is accepted.
//! A prefix whose tgid is not in that set produces nothing.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use aw_core::{
    tls::{parse_client_hello, ClientHelloInfo, ParseError},
    EventKind, Evidence, FlowKey, Gap, GapKind, L4Proto, NaReason, ProcRef, ProcUid, RawEvent,
    SessionId, Source, TlsSni, SCHEMA_VERSION,
};

/// `linux.ebpf/tcp_sendmsg_sni`. The task card names this string.
pub const SOURCE_EBPF_SNI: &str = "linux.ebpf/tcp_sendmsg_sni";

/// `linux.afpacket/sni`. Used only when the caller takes the fallback path.
/// This module never opens the socket that would produce it.
pub const SOURCE_AFPACKET_SNI: &str = "linux.afpacket/sni";

/// `linux.ebpf/tcp_sendmsg_sni` stamped on the attach gap.
///
/// The probe name is the one that was *not* attached. The event kind is `gap`,
/// so this source does not claim a ClientHello was observed.
pub const SOURCE_SNI_GAP: &str = SOURCE_EBPF_SNI;

/// `Gap.detail` when [`SniAttach::start`] cannot load the probe.
///
/// Aya is not linked and `sni.bpf.c` is not compiled, so `tcp_sendmsg` is not
/// attached. This is a collector limitation ([`GapKind::Unsupported`]), not a
/// hostname that happened to be missing. A later privileged runtime that
/// actually calls `socket(AF_PACKET)` and fails records a *different* detail,
/// `afpacket_unavailable`. This crate does not open that socket, so it does
/// not emit that string.
pub const SNI_ATTACH_UNAVAILABLE: &str = "sni_attach_unavailable";

/// Bytes the probe is allowed to copy from the first write. linux.md §2.3.
pub const SNI_PREFIX_CAP: usize = 1024;

/// First byte of a TLS handshake record (RFC 8446 §5.1, content type 22).
const TLS_HANDSHAKE: u8 = 0x16;

/// `collectors.linux` has no `sni` key. Absent config is off, matching the
/// Windows switch: only an explicit `Some(true)` turns extraction on.
///
/// Turning the switch on does not attach anything. [`SniAttach::attach`] still
/// refuses until a later task links a loader.
#[must_use]
pub fn sni_enabled(config_value: Option<bool>) -> bool {
    matches!(config_value, Some(true))
}

/// Which capture the caller is feeding into [`SniExtractor`].
///
/// The extractor stamps this onto the event. It does not open either source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniSource {
    /// Prefix copied by the `tcp_sendmsg` probe.
    Ebpf,
    /// Prefix copied by the AF_PACKET fallback the caller opened.
    AfPacket,
}

impl SniSource {
    /// The `source` string for an event produced from this capture.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ebpf => SOURCE_EBPF_SNI,
            Self::AfPacket => SOURCE_AFPACKET_SNI,
        }
    }
}

/// Why the first-write prefix did not become a hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniError {
    /// `bpf_probe_read_user` is not available at this attach point.
    ///
    /// [`SniAttach::start`] turns this into a [`aw_core::Gap`]. A caller that
    /// already holds a copied prefix can still feed it back with
    /// [`SniSource::AfPacket`]. This variant carries no bytes and does not name
    /// a process. Opening `AF_PACKET` is not this crate's job.
    FallbackNeeded {
        /// Why the kernel read was refused, as reported by the loader.
        reason: String,
    },
    /// The prefix begins a handshake record but stops before the ClientHello
    /// finishes. The name is `NA(partial_client_hello)`, not an empty string.
    Partial,
    /// The prefix is not a TLS handshake record, or it is not a ClientHello
    /// this parser accepts. Not a hostname.
    NotHandshake,
}

impl fmt::Display for SniError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FallbackNeeded { reason } => {
                write!(f, "kernel user-memory read is unavailable: {reason}")
            }
            Self::Partial => f.write_str("ClientHello prefix is incomplete"),
            Self::NotHandshake => f.write_str("first write is not a TLS ClientHello"),
        }
    }
}

impl std::error::Error for SniError {}

/// One socket's first write, already copied out of the kernel.
///
/// `prefix` is at most [`SNI_PREFIX_CAP`] bytes starting at the TLS record
/// header. Bytes past that cap are ignored, not stored. The tuple is what the
/// caller already knows about the socket; a missing address stays missing and
/// is marked `NA(collector_unavailable)` on the event.
#[derive(Debug, Clone, Copy)]
pub struct FirstWrite<'a> {
    /// Host tgid. Must be in the session set passed to [`SniExtractor::extract`].
    pub tgid: u32,
    /// Host tid, when the probe read one.
    pub tid: Option<u32>,
    /// `hash(pid, start_time, boot_id)`. `None` leaves `proc` as `NA`: a
    /// `ProcUid` of 0 would be a guess.
    pub proc_uid: Option<u64>,
    /// `sock` pointer. Becomes `FlowKey::sock_id`.
    pub sock: u64,
    /// Local address. `None` when the probe had not read it yet.
    pub local: Option<SocketAddr>,
    /// Remote address. `None` when the probe had not read it yet.
    pub remote: Option<SocketAddr>,
    /// `bpf_ktime_get_ns`.
    pub ts_mono_ns: u64,
    /// Wall clock the caller converted. `None` is `NA`, not epoch 0.
    pub ts_wall_ns: Option<i64>,
    /// Session this write belongs to, if the caller has one.
    pub session_id: Option<u64>,
    /// The copied prefix. Not retained after [`SniExtractor::extract`] returns.
    pub prefix: &'a [u8],
}

/// Userspace half of the first-write SNI path.
///
/// It holds no payload and no map. [`Self::extract`] borrows the prefix, parses
/// it, and drops it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniExtractor {
    /// `collectors.linux` SNI switch, as resolved by [`sni_enabled`].
    enabled: bool,
    source: SniSource,
}

impl SniExtractor {
    /// Build an extractor. Does not attach a probe and does not open a socket.
    ///
    /// `config_value` is the raw switch. `None` keeps extraction off.
    #[must_use]
    pub fn new(config_value: Option<bool>, source: SniSource) -> Self {
        Self {
            enabled: sni_enabled(config_value),
            source,
        }
    }

    /// Whether config asked for SNI. Independent of [`SniAttach::attach`].
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// `source` stamped on events this extractor emits.
    #[must_use]
    pub fn source(&self) -> SniSource {
        self.source
    }

    /// Classify one already-copied first write.
    ///
    /// Returns `Ok(None)` when the switch is off, or when `write.tgid` is not in
    /// `session_tgids`. A bystander's prefix is not parsed and not retained.
    ///
    /// `Ok(Some)` is a `tls_sni` event at E1. A handshake that the parser could
    /// not finish is still an event: `sni` is empty and `field_evidence["sni"]`
    /// is `NA(partial_client_hello)`. An empty name without that entry would
    /// read as "the server name was observed and it was empty".
    ///
    /// # Errors
    ///
    /// [`SniError::NotHandshake`] when the prefix is not a ClientHello.
    /// [`SniError::Partial`] is not returned from here: a short handshake is an
    /// event with the field marked unavailable, so the caller still has a record.
    pub fn extract(
        &self,
        write: FirstWrite<'_>,
        session_tgids: &BTreeSet<u32>,
        seq: u64,
    ) -> Result<Option<RawEvent>, SniError> {
        if !self.enabled || !session_tgids.contains(&write.tgid) {
            return Ok(None);
        }
        let prefix = clamp_prefix(write.prefix);
        match classify(prefix) {
            Classified::NotHandshake => Err(SniError::NotHandshake),
            Classified::Hello(info) => Ok(Some(self.event(write, seq, HelloName::Parsed(info)))),
            Classified::Partial => Ok(Some(self.event(write, seq, HelloName::Partial))),
        }
    }

    fn event(&self, write: FirstWrite<'_>, seq: u64, name: HelloName) -> RawEvent {
        let (sni, alpn, partial, ech) = match name {
            HelloName::Parsed(info) => {
                let ech = info.ech.is_some() && info.sni.is_none();
                (info.sni.unwrap_or_default(), info.alpn, false, ech)
            }
            HelloName::Partial => (String::new(), Vec::new(), true, false),
        };
        let local_missing = write.local.is_none();
        let remote_missing = write.remote.is_none();
        let flow = FlowKey::new(
            L4Proto::Tcp,
            write.local.unwrap_or_else(unspec),
            write.remote.unwrap_or_else(unspec),
            Some(write.sock),
        );
        let proc = write.proc_uid.map(|uid| ProcRef {
            uid: ProcUid(uid),
            pid: write.tgid,
            tid: write.tid,
        });
        let proc_missing = proc.is_none();
        let wall_missing = write.ts_wall_ns.is_none();
        let mut event = RawEvent {
            v: SCHEMA_VERSION,
            seq,
            ts_mono_ns: write.ts_mono_ns,
            ts_wall_ns: write.ts_wall_ns.unwrap_or(0),
            session_id: write.session_id.map(SessionId),
            proc,
            source: Source::new(self.source.as_str()),
            evidence: Evidence::E1,
            field_evidence: std::collections::BTreeMap::new(),
            kind: EventKind::TlsSni(TlsSni::new(flow, sni, alpn)),
        };
        if partial {
            event.mark_na("sni", NaReason::PartialClientHello);
        } else if ech {
            // The parser dropped the inner name because the ECH extension was
            // present. That is a known reason, not a truncated read.
            event.mark_na("sni", NaReason::Ech);
        }
        if local_missing {
            event.mark_na("local", NaReason::CollectorUnavailable);
        }
        if remote_missing {
            event.mark_na("remote", NaReason::CollectorUnavailable);
        }
        if wall_missing {
            event.mark_na("ts_wall_ns", NaReason::CollectorUnavailable);
        }
        if proc_missing {
            event.mark_na("proc", NaReason::CollectorUnavailable);
        }
        let _ = event.check();
        event
    }
}

/// What [`classify`] decided about one prefix.
enum Classified {
    /// A ClientHello the shared parser accepted.
    Hello(ClientHelloInfo),
    /// The handshake started and did not finish inside the prefix.
    Partial,
    /// Not a handshake record, or not a ClientHello.
    NotHandshake,
}

/// A name to stamp, or the absence of one.
enum HelloName {
    Parsed(ClientHelloInfo),
    Partial,
}

/// Keep at most [`SNI_PREFIX_CAP`] bytes. The rest of a larger buffer is not read.
fn clamp_prefix(prefix: &[u8]) -> &[u8] {
    let end = prefix.len().min(SNI_PREFIX_CAP);
    &prefix[..end]
}

/// Run [`parse_client_hello`] on one prefix.
///
/// `Incomplete` is a partial hello only when the prefix actually opened with the
/// handshake content type. Any other first byte is [`Classified::NotHandshake`]:
/// the probe is supposed to have skipped those, and a slipped byte is not a
/// truncated ClientHello.
fn classify(prefix: &[u8]) -> Classified {
    let handshake = prefix.first().copied() == Some(TLS_HANDSHAKE);
    match parse_client_hello(prefix) {
        Ok(info) => Classified::Hello(info),
        Err(ParseError::Incomplete) if handshake => Classified::Partial,
        Err(ParseError::Incomplete | ParseError::NotHandshake | ParseError::Malformed) => {
            Classified::NotHandshake
        }
    }
}

fn unspec() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

/// Stand-in for the kprobe this task does not attach.
///
/// [`Self::attach`] never loads `sni.bpf.c`. Aya is not linked, and the crate's
/// [`crate::loader::BpfLoader`] stub refuses every attach. [`Self::start`] is
/// what the collector calls: it turns that refusal into one [`aw_core::Gap`]
/// instead of leaving the missing SNI silent.
///
/// AF_PACKET is intentionally not attempted. The socket needs `CAP_NET_RAW`
/// and a libc binding, neither of which belongs in this unprivileged crate.
/// A privileged runtime that later opens the socket and fails must record its
/// own gap with detail `afpacket_unavailable`, distinct from
/// [`SNI_ATTACH_UNAVAILABLE`]. It must not invent an empty first-write to look
/// like a packet was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniAttach {
    enabled: bool,
}

impl SniAttach {
    /// Build the handle. Does not talk to the kernel.
    #[must_use]
    pub fn new(config_value: Option<bool>) -> Self {
        Self {
            enabled: sni_enabled(config_value),
        }
    }

    /// Whether config asked for the probe.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Refuse to attach, and tell the caller the fallback is required.
    ///
    /// The switch does not change the outcome. An enabled probe still cannot be
    /// loaded: there is no Aya dependency and no embedded object. The reason
    /// string names that, and nothing else — no process, no address, no payload.
    ///
    /// # Errors
    ///
    /// Always [`SniError::FallbackNeeded`].
    pub fn attach(&self) -> Result<(), SniError> {
        let _ = self.enabled;
        Err(SniError::FallbackNeeded {
            reason: "Aya is not linked and sni.bpf.c is not built; tcp_sendmsg was not attached"
                .to_owned(),
        })
    }

    /// Collector entry for the SNI probe.
    ///
    /// Config off (`None` or `Some(false)`) returns nothing: SNI was not asked
    /// for, so there is no silent loss to record.
    ///
    /// Config on always returns one gap. [`Self::attach`] cannot succeed in
    /// this crate, and the refusal is `GapKind::Unsupported` with detail
    /// [`SNI_ATTACH_UNAVAILABLE`]. The event evidence is E1 because the gap
    /// itself was observed. The hostname was not: there is no `tls_sni` event,
    /// and nothing here is stamped E1 as a seen name.
    ///
    /// `seq` is the caller's next sequence number. `mono_ns` is the collector
    /// clock at the refusal; `wall_ns` is `None` when the caller has no wall
    /// clock, and the field is then `NA(collector_unavailable)` rather than
    /// epoch 0 presented as a real time.
    ///
    /// This does not open an `AF_PACKET` socket. See the type-level note.
    #[must_use]
    pub fn start(&self, seq: u64, mono_ns: u64, wall_ns: Option<i64>) -> Option<RawEvent> {
        if !self.enabled {
            return None;
        }
        let Err(SniError::FallbackNeeded { reason }) = self.attach() else {
            // `attach` is infallibly `FallbackNeeded` today. A later task that
            // makes it succeed must not report a gap for a probe that loaded.
            return None;
        };
        Some(attach_gap(seq, mono_ns, wall_ns, &reason))
    }
}

/// One gap for a probe that was not attached.
///
/// `reason` is the loader text from [`SniError::FallbackNeeded`]. It is folded
/// into `detail` after the stable token [`SNI_ATTACH_UNAVAILABLE`], so a reader
/// can match the token without parsing the sentence. The count is `None`: no
/// event was counted, and `0` would mean "we counted zero losses".
fn attach_gap(seq: u64, mono_ns: u64, wall_ns: Option<i64>, reason: &str) -> RawEvent {
    let wall_missing = wall_ns.is_none();
    let source = Source::new(SOURCE_SNI_GAP);
    let gap = Gap::new(
        source.clone(),
        GapKind::Unsupported,
        vec!["net".to_owned()],
        mono_ns,
        mono_ns,
        None,
        Some(format!("{SNI_ATTACH_UNAVAILABLE}: {reason}")),
    );
    let mut event = RawEvent {
        v: SCHEMA_VERSION,
        seq,
        ts_mono_ns: mono_ns,
        ts_wall_ns: wall_ns.unwrap_or(0),
        session_id: None,
        proc: None,
        source,
        // The gap is a fact about the collector. It is not a fact about a hostname.
        evidence: Evidence::E1,
        field_evidence: std::collections::BTreeMap::new(),
        kind: EventKind::Gap(gap),
    };
    event.mark_na("proc", NaReason::CollectorUnavailable);
    event.mark_na("count", NaReason::CollectorUnavailable);
    if wall_missing {
        event.mark_na("ts_wall_ns", NaReason::CollectorUnavailable);
    }
    let _ = event.check();
    event
}
