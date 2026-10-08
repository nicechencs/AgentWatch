//! pktap TLS ClientHello capture (P3-MAC-01).
//!
//! macOS DNS is sent by `mDNSResponder`, so a DNS answer cannot be attributed to
//! the process that asked. pktap labels each packet with a pid. This module
//! keeps the pieces that turn that label into an SNI observation:
//!
//! - [`handshake_sni`] reads one captured payload and returns the host name, or
//!   a distinct error when the payload is a handshake that was cut short.
//! - [`pid_in_session`] decides whether the pktap pid belongs to the session.
//! - [`unattributed_dns`] describes a DNS answer that can only be charged to
//!   `mDNSResponder`.
//! - [`PktapSni`] (macOS only) owns the `tcpdump` child. When that child exits
//!   it counts the restart and returns a [`GapNote`]. It does not write a
//!   database row and it does not build an `aw_core::Gap`.
//!
//! Nothing here stores a pcap. The child writes to stdout (`-w -`) and the
//! caller consumes that stream. A payload that is not a ClientHello is
//! [`SniError`]-free `Ok(None)`, not a gap.

use std::collections::BTreeSet;
use std::fmt;
#[cfg(target_os = "macos")]
use std::io;

/// `macos.pktap/sni`. The task card names this string.
pub const SOURCE_PKTAP_SNI: &str = "macos.pktap/sni";

/// Process the system resolver runs as. A DNS answer from this process has no
/// original requester (macos.md §1.3, CAP-DNS-02).
pub const MDNS_RESPONDER: &str = "mDNSResponder";

/// `domain_source` for a name learned from an answer that could not be
/// attributed past `mDNSResponder`.
pub const DNS_UNATTRIBUTED: &str = "dns_unattributed";

/// Evidence level string for [`UnattributedDns`].
///
/// The task card says this mapping is backfilled at I. The string is stored
/// here so this crate does not have to name `aw_core::Evidence` — that type is
/// owned by another task, and a cross-crate change is out of scope.
pub const EVIDENCE_INFERRED: &str = "I";

/// Why an answer attributed to `mDNSResponder` is not a per-process mapping.
pub const UNATTRIBUTED_REASON: &str =
    "pktap attributes this DNS answer to mDNSResponder; the process that asked is not on the packet";

/// `tcpdump` argv, not including argv0.
///
/// `tcp[((tcp[12]&0xf0)>>2)]=0x16` keeps only TCP segments whose first payload
/// byte is a TLS handshake record. `-w -` writes the capture to stdout, so no
/// pcap file is created.
pub const TCPDUMP_ARGS: &[&str] = &[
    "-i",
    "pktap,all",
    "-k",
    "NP",
    "-w",
    "-",
    "tcp[((tcp[12]&0xf0)>>2)]=0x16",
];

/// Binary the child is started from. Absolute, so `PATH` cannot redirect it.
pub const TCPDUMP_BIN: &str = "/usr/sbin/tcpdump";

/// What [`handshake_sni`] can refuse.
///
/// `Ok(None)` is reserved for "this buffer is not a ClientHello". A handshake
/// that ends before its declared length is [`SniError::Truncated`], never
/// `None` and never an empty name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniError {
    /// The buffer starts a TLS handshake record but stops before the record or
    /// the handshake message finishes.
    Truncated,
    /// The buffer is a complete handshake record, but it is not a ClientHello
    /// this parser accepts (wrong handshake type, bad length, or a non-UTF-8
    /// name).
    Malformed,
}

impl fmt::Display for SniError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("TLS handshake payload is truncated"),
            Self::Malformed => f.write_str("TLS handshake payload is not a ClientHello"),
        }
    }
}

impl std::error::Error for SniError {}

/// Host name from one captured TLS handshake payload.
///
/// * `Ok(Some(name))` — a ClientHello carried a host_name.
/// * `Ok(None)` — the buffer is not a ClientHello (wrong content type, empty,
///   or a ClientHello with no host_name and no encrypted-ClientHello stand-in).
///   Absence of a name is not an error.
/// * `Err(SniError::Truncated)` — a handshake record began and did not finish.
/// * `Err(SniError::Malformed)` — the record is complete and still not usable.
///
/// The actual parse is [`parse_client_hello`]. That function is the only place
/// that names `aw_core::tls::parse_client_hello` (P3-PIPE-02). A missing
/// re-export breaks that function alone.
pub fn handshake_sni(payload: &[u8]) -> Result<Option<String>, SniError> {
    if !looks_like_tls_handshake(payload) {
        return Ok(None);
    }
    match parse_client_hello(payload) {
        Ok(ParsedHello {
            sni: Some(name), ..
        }) => Ok(Some(name)),
        Ok(ParsedHello {
            sni: None,
            ech_public_name: Some(name),
            ..
        }) => Ok(Some(name)),
        Ok(ParsedHello { sni: None, .. }) => Ok(None),
        Err(HelloFault::Incomplete) => Err(SniError::Truncated),
        Err(HelloFault::NotHello) => Ok(None),
        Err(HelloFault::Malformed) => Err(SniError::Malformed),
    }
}

/// True when `pid` is one of the pids the session is watching.
///
/// pktap prints the pid the kernel put on the packet. Membership is the whole
/// test: this function does not look up a process start time and does not
/// treat a missing pid as `0`. The caller passes `None` for a header that had
/// no pid, and that is not in the session.
pub fn pid_in_session(pid: Option<u32>, session_pids: &BTreeSet<u32>) -> bool {
    match pid {
        Some(pid) => session_pids.contains(&pid),
        None => false,
    }
}

/// A DNS answer pktap could only attribute to `mDNSResponder`.
///
/// `domain_source` is [`DNS_UNATTRIBUTED`] and `evidence` is [`EVIDENCE_INFERRED`]
/// (`"I"`). Both are plain strings so this crate does not construct
/// `aw_core::Evidence`. The caller copies them into `field_evidence`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnattributedDns {
    /// Always [`DNS_UNATTRIBUTED`].
    pub domain_source: &'static str,
    /// Why the name is not attributed to the process that asked.
    pub reason: &'static str,
    /// Always [`EVIDENCE_INFERRED`] (`"I"`).
    pub evidence: &'static str,
    /// Pid pktap printed. This is `mDNSResponder`'s pid, not the requester.
    pub responder_pid: Option<u32>,
    /// Process name pktap printed. Kept so the caller can show what was seen.
    pub process_name: String,
}

/// Describe a DNS answer that belongs to `mDNSResponder`.
///
/// `process_name` is compared to [`MDNS_RESPONDER`] as ASCII, ignoring case.
/// A different name returns `None`: that answer is not this function's case,
/// and it is not rewritten into an unattributed record.
pub fn unattributed_dns(process_name: &str, pid: Option<u32>) -> Option<UnattributedDns> {
    if !process_name.eq_ignore_ascii_case(MDNS_RESPONDER) {
        return None;
    }
    Some(UnattributedDns {
        domain_source: DNS_UNATTRIBUTED,
        reason: UNATTRIBUTED_REASON,
        evidence: EVIDENCE_INFERRED,
        responder_pid: pid,
        process_name: process_name.to_owned(),
    })
}

/// A child exit the caller should record as a gap.
///
/// This is a note, not an event. The collector that owns the session turns it
/// into a `Gap`. Doing that here would pull storage and `aw_core::Gap` into a
/// crate whose only job is the capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapNote {
    /// Why the child is not running.
    pub reason: GapReason,
    /// How many times this supervisor has started the child, including the
    /// start that just ended. The first exit is `1`.
    pub restart_count: u64,
}

/// Why [`PktapSni`] stopped seeing a live child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GapReason {
    /// `tcpdump` exited. `status` is the raw wait status when the host
    /// reported one.
    ChildExited { status: Option<i32> },
    /// The supervisor could not spawn the binary.
    SpawnFailed { message: String },
}

impl fmt::Display for GapReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChildExited { status: Some(code) } => {
                write!(f, "tcpdump exited (status {code})")
            }
            Self::ChildExited { status: None } => f.write_str("tcpdump exited"),
            Self::SpawnFailed { message } => write!(f, "tcpdump could not be started: {message}"),
        }
    }
}

/// First byte of a TLS handshake record (RFC 8446 §5.1, content type 22).
const TLS_HANDSHAKE: u8 = 0x16;

/// Record header is five bytes: type, version, length.
const TLS_RECORD_HEADER: usize = 5;

/// True when the buffer opens with a TLS handshake content type.
///
/// An empty buffer or any other first byte is not a ClientHello. That is
/// `Ok(None)` upstream, not a truncation: the capture filter is supposed to
/// pass only handshake segments, and a non-matching byte means the filter
/// slipped, not that a hello was cut off.
fn looks_like_tls_handshake(payload: &[u8]) -> bool {
    payload.first().copied() == Some(TLS_HANDSHAKE)
}

/// Fields [`handshake_sni`] needs from the shared parser.
struct ParsedHello {
    sni: Option<String>,
    ech_public_name: Option<String>,
}

/// Failure of [`parse_client_hello`], mapped from `aw_core::tls::ParseError`.
enum HelloFault {
    Incomplete,
    NotHello,
    Malformed,
}

/// Call `aw_core::tls::parse_client_hello`.
///
/// This is the only function in the crate that names that parser. P3-PIPE-02
/// owns it (`parse_client_hello(&[u8]) -> Result<ClientHelloInfo, ParseError>`,
/// with `Incomplete` for a short buffer) and re-exports it from the `aw_core`
/// crate root. Keeping the call here means a missing re-export breaks this
/// function alone, not [`handshake_sni`]'s callers.
///
/// A buffer shorter than the five-byte record header is
/// [`HelloFault::Incomplete`] before the parser runs. The caller has already
/// required the first byte to be the handshake content type, so a shorter
/// slice is a cut-off record, not "not a ClientHello".
fn parse_client_hello(payload: &[u8]) -> Result<ParsedHello, HelloFault> {
    if payload.len() < TLS_RECORD_HEADER {
        return Err(HelloFault::Incomplete);
    }
    match aw_core::tls::parse_client_hello(payload) {
        Ok(info) => Ok(ParsedHello {
            sni: info.sni,
            ech_public_name: info.ech.and_then(|ech| ech.public_name),
        }),
        Err(aw_core::tls::ParseError::Incomplete) => Err(HelloFault::Incomplete),
        Err(aw_core::tls::ParseError::NotHandshake) => Err(HelloFault::NotHello),
        Err(aw_core::tls::ParseError::Malformed) => Err(HelloFault::Malformed),
    }
}

/// Owns the pktap `tcpdump` child. Compiled only on macOS: the binary and the
/// pktap interface do not exist elsewhere, and a Windows build of this crate
/// must not contain the spawn.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct PktapSni {
    child: Option<std::process::Child>,
    /// Starts at 0. Incremented on every successful spawn.
    starts: u64,
}

#[cfg(target_os = "macos")]
impl PktapSni {
    /// No child yet. Call [`Self::start`] to spawn one.
    pub fn new() -> Self {
        Self {
            child: None,
            starts: 0,
        }
    }

    /// How many times a child has been spawned.
    pub fn restart_count(&self) -> u64 {
        self.starts
    }

    /// Spawn `tcpdump` with [`TCPDUMP_ARGS`].
    ///
    /// A child that is still running is left alone and this returns `Ok(None)`.
    /// A child that has already exited is reaped, counted, and replaced; the
    /// returned [`GapNote`] describes the exit the caller must record.
    /// A spawn that fails returns `Err` and does not increment the count:
    /// nothing started. The [`GapNote`] for that failure is [`Self::start_or_note`].
    pub fn start(&mut self) -> io::Result<Option<GapNote>> {
        let prior = self.take_exit()?;
        if self.child.is_some() {
            return Ok(None);
        }
        match std::process::Command::new(TCPDUMP_BIN)
            .args(TCPDUMP_ARGS)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => {
                self.starts = self.starts.saturating_add(1);
                self.child = Some(child);
                Ok(prior)
            }
            Err(err) => Err(err),
        }
    }

    /// Start, and on failure return a [`GapNote`] instead of an `io::Error`.
    ///
    /// The note's `restart_count` is the number of children that have actually
    /// started. A failed spawn leaves it unchanged.
    pub fn start_or_note(&mut self) -> Result<Option<GapNote>, GapNote> {
        self.start().map_err(|err| GapNote {
            reason: GapReason::SpawnFailed {
                message: err.to_string(),
            },
            restart_count: self.starts,
        })
    }

    /// Reap the child if it has exited.
    ///
    /// `Ok(None)` means it is still running, or it was never started. `Ok(Some)`
    /// is the gap the caller records; the next [`Self::start`] spawns a
    /// replacement. `Err` is a `try_wait` failure and is not counted as an exit.
    pub fn poll(&mut self) -> io::Result<Option<GapNote>> {
        self.take_exit()
    }

    /// Stop the child without producing a gap. Used when the session ends and
    /// the exit is expected. A child that already exited is reaped and dropped.
    pub fn stop(&mut self) -> io::Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        match child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => child.kill().and_then(|_| child.wait().map(|_| ())),
            Err(err) => Err(err),
        }
    }

    /// Stdout of the live child, if it was spawned with a pipe and not yet taken.
    pub fn stdout(&mut self) -> Option<&mut std::process::ChildStdout> {
        self.child.as_mut().and_then(|child| child.stdout.as_mut())
    }

    fn take_exit(&mut self) -> io::Result<Option<GapNote>> {
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        let status = match child.try_wait() {
            Ok(Some(status)) => status,
            Ok(None) => return Ok(None),
            // Leave the child in place. A wait failure is not an exit and must
            // not be counted as a restart.
            Err(err) => return Err(err),
        };
        self.child = None;
        Ok(Some(GapNote {
            reason: GapReason::ChildExited {
                status: status.code(),
            },
            restart_count: self.starts,
        }))
    }
}

#[cfg(target_os = "macos")]
impl Default for PktapSni {
    fn default() -> Self {
        Self::new()
    }
}
