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
//! returns [`SniError::FallbackNeeded`]. The caller then either switches to
//! AF_PACKET (`source = linux.afpacket/sni`) or records a gap. This module does
//! neither: it does not open a packet socket.
//!
//! Only a process the caller has already placed in the session is accepted.
//! A prefix whose tgid is not in that set produces nothing.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use aw_core::{
    tls::{parse_client_hello, ClientHelloInfo, ParseError},
    EventKind, Evidence, FlowKey, L4Proto, NaReason, ProcRef, ProcUid, RawEvent, SessionId, Source,
    TlsSni, SCHEMA_VERSION,
};

/// `linux.ebpf/tcp_sendmsg_sni`. The task card names this string.
pub const SOURCE_EBPF_SNI: &str = "linux.ebpf/tcp_sendmsg_sni";

/// `linux.afpacket/sni`. Used only when the caller takes the fallback path.
/// This module never opens the socket that would produce it.
pub const SOURCE_AFPACKET_SNI: &str = "linux.afpacket/sni";

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
    /// The caller decides what happens next: open an AF_PACKET socket and feed
    /// its first payload back with [`SniSource::AfPacket`], or write a gap.
    /// This variant carries no bytes and does not name a process.
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
/// [`crate::loader::BpfLoader`] stub refuses every attach. Calling this reports
/// [`SniError::FallbackNeeded`] so the caller can choose AF_PACKET or a gap.
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
}
