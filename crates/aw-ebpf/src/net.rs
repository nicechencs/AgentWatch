//! TCP/UDP byte probes and the DNS payload copy (linux §2.3, P1-LNX-03).
//!
//! This file does not attach anything and does not call Aya. SPIKE-01 has not
//! landed, and this crate is a `no_std` placeholder that must stay free of a BPF
//! toolchain (see `main.rs`). What it does fix is the record layout the probes
//! will write and the userspace decoder in `aw-collector-linux` already reads.
//!
//! Every integer is little-endian. Every struct is `#[repr(C)]` with explicit
//! padding so a later CO-RE program and the Windows-tested decoder agree on
//! offsets without sharing a crate (this package is not a workspace member).
//!
//! # Probes
//!
//! | probe | hook | what it writes |
//! |---|---|---|
//! | `tcp_connect` | `fexit/tcp_connect`, else `kprobe/tcp_connect` | one [`ConnRecord`], `direction = outbound` |
//! | `inet_csk_accept` | `fexit/inet_csk_accept` | one [`ConnRecord`], `direction = inbound` |
//! | `inet_sock_set_state` | tracepoint `sock:inet_sock_set_state` | one [`StateRecord`]. Userspace emits `NetClose` only when `newstate` is `TCP_CLOSE` |
//! | `tcp_sendmsg` | `fexit/tcp_sendmsg` | adds the return value (bytes queued) into `sock_stats`. Not one event per call |
//! | `tcp_cleanup_rbuf` | `kprobe/tcp_cleanup_rbuf` | adds `copied` into `sock_stats` |
//! | `udp_sendmsg` | `kprobe/udp_sendmsg` | adds the length into `sock_stats`. Port 53 also copies the first 512 B |
//! | `udpv6_sendmsg` | `kprobe/udpv6_sendmsg` | same, IPv6 |
//! | `udp_recvmsg` | `fexit/udp_recvmsg` | adds the copied length into `sock_stats`. Port 53 also copies the first 512 B |
//!
//! A function that is inlined or renamed fails its attach on its own. The loader
//! records a `Gap` for that probe and keeps the others. The fallback list is
//! [`PROBE_NAMES`] in order; there is no second symbol per probe in this layout.
//!
//! # Scope
//!
//! Each probe returns immediately when `bpf_get_current_cgroup_id()` is not in
//! `scope_cgroups` and the tgid is not in `scope_pids`. It does not write
//! `sock_stats` and it does not reserve a ringbuf slot. Userspace repeats the
//! check, because a record can be decoded from a capture that was not filtered.
//!
//! # `sock_stats`
//!
//! Hash map keyed by the `sock` pointer. Value is [`SockStats`]. `tcp_sendmsg`,
//! `tcp_cleanup_rbuf`, `udp_sendmsg`, `udpv6_sendmsg`, and `udp_recvmsg` only
//! add to it. Once a second, userspace walks the map and emits one
//! [`SockStatsDelta`] per socket whose `tx_bytes` or `rx_bytes` moved. The
//! record carries the new totals and the previous totals; the decoder subtracts.
//! A walk that cannot read a socket writes a delta with `read_error` set and
//! does not invent a zero delta.
//!
//! Byte meaning: application bytes queued (`tcp_sendmsg` return) or copied to
//! userspace (`copied`). That includes TLS record overhead and excludes the
//! TCP/IP headers and retransmissions. SPIKE-01 has not measured this; the
//! decoder labels the source, it does not claim the calibration.
//!
//! # DNS
//!
//! When the remote port (`udp_sendmsg` / `udpv6_sendmsg`) or the local port
//! (`udp_recvmsg`) is 53, the probe also reserves a ringbuf slot and copies the
//! first [`DNS_PAYLOAD_CAP`] bytes of the datagram into [`DnsPayload`]. The
//! copy is for parsing only. Userspace parses it and drops the bytes. A payload
//! shorter than the cap is not padded with zeroes that would be parsed; `len`
//! is the real datagram length, which may be greater than the cap.
//!
//! A query sent to `127.0.0.53` (systemd-resolved) keeps the calling process.
//! resolved's own upstream query is a different process and stays out of the
//! session unless that process is in scope.
//!
//! # What is not here
//!
//! SNI (`tcp_sendmsg` first write) is P3. This layout has no field for it.
//!
//! # Map
//!
//! `sock_stats` is owned by this probe set. The four maps in
//! `aw-collector-linux`'s `maps` module (`scope_cgroups`, `scope_pids`,
//! `events`, `lost`) stay as they are; a full ringbuf is counted in `lost` and
//! is not dropped silently.

#![allow(dead_code)]

/// First bytes of a DNS datagram copied into the ring buffer. The parser never
/// sees past this, even when the datagram is longer.
pub const DNS_PAYLOAD_CAP: usize = 512;

/// Remote port that triggers the DNS copy on send, and local port on recv.
pub const DNS_PORT: u16 = 53;

/// `sock_stats` map name. Not one of the four shared maps from P1-LNX-01.
pub const SOCK_STATS_MAP: &str = "sock_stats";

/// How often userspace walks `sock_stats`.
pub const SOCK_STATS_SCAN_NS: u64 = 1_000_000_000;

/// Probe names, in the order linux §2.3 lists them. `source` is
/// `linux.ebpf/<name>`.
pub const PROBE_NAMES: [&str; 8] = [
    "tcp_connect",
    "inet_csk_accept",
    "inet_sock_set_state",
    "tcp_sendmsg",
    "tcp_cleanup_rbuf",
    "udp_sendmsg",
    "udpv6_sendmsg",
    "udp_recvmsg",
];

/// `events` ringbuf record tags. A reader branches on the first `u32`.
pub const RECORD_CONN: u32 = 1;
pub const RECORD_STATE: u32 = 2;
pub const RECORD_STATS: u32 = 3;
pub const RECORD_DNS: u32 = 4;

/// Address family. `0` is not a stand-in for "unknown"; an unreadable family
/// sets [`ConnRecord::family_known`] to `0` and leaves this field unused.
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;

/// `FlowDirection` as a `u8`, matching `aw-core`.
pub const DIR_OUTBOUND: u8 = 1;
pub const DIR_INBOUND: u8 = 2;

/// Linux `TCP_CLOSE`. The only `newstate` userspace turns into `NetClose`.
pub const TCP_CLOSE: u8 = 7;

/// Transport of a [`SockStats`] row.
pub const PROTO_TCP: u8 = 1;
pub const PROTO_UDP: u8 = 2;

/// IPv4 address, network order, as four bytes. Not an integer, so endianness
/// of the address itself cannot be confused with the record's little-endian
/// integers.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv4Bytes {
    pub octets: [u8; 4],
}

/// IPv6 address, network order.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv6Bytes {
    pub octets: [u8; 16],
}

/// One address the probe managed to read. Unused bytes are zero and ignored.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AddrBytes {
    pub v4: Ipv4Bytes,
    pub v6: Ipv6Bytes,
}

/// Connection observed at `tcp_connect` or `inet_csk_accept`.
///
/// 80 bytes. The local port is often still 0 on `tcp_connect`; userspace must
/// not invent one. `inet_sock_set_state` later carries the port that was
/// chosen, and that record is a separate event, not a patch of this one.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnRecord {
    /// [`RECORD_CONN`].
    pub tag: u32,
    /// `bpf_ktime_get_ns`.
    pub ts_mono_ns: u64,
    /// Host pid (tgid), not a pid-namespace pid.
    pub tgid: u32,
    /// Host tid.
    pub pid: u32,
    /// `sock` pointer. Becomes `FlowKey.sock_id`.
    pub sock: u64,
    /// [`DIR_OUTBOUND`] for `tcp_connect`, [`DIR_INBOUND`] for `inet_csk_accept`.
    pub direction: u8,
    /// [`AF_INET`] or [`AF_INET6`]. Meaningful only when `family_known` is 1.
    pub family: u8,
    /// `1` when `family` was read.
    pub family_known: u8,
    /// `1` when `local` was read.
    pub local_known: u8,
    /// `1` when `remote` was read.
    pub remote_known: u8,
    /// `1` when `local_port` was read. A read port of 0 stays 0 and is still known.
    pub local_port_known: u8,
    /// `1` when `remote_port` was read.
    pub remote_port_known: u8,
    pub _pad0: u8,
    /// Host byte order.
    pub local_port: u16,
    /// Host byte order.
    pub remote_port: u16,
    pub local: AddrBytes,
    pub remote: AddrBytes,
}

/// `sock:inet_sock_set_state` sample.
///
/// Userspace emits `NetClose` only for `newstate == TCP_CLOSE`. Other states
/// (including `TCP_ESTABLISHED`, which is where the local port becomes known)
/// produce no event: the totals are reported by the `sock_stats` scan, and
/// this record does not carry byte counters. Inventing a `NetConnect` from
/// `TCP_ESTABLISHED` would double-count `tcp_connect`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StateRecord {
    /// [`RECORD_STATE`].
    pub tag: u32,
    pub ts_mono_ns: u64,
    pub tgid: u32,
    pub pid: u32,
    pub sock: u64,
    /// Previous TCP state. Linux numbering. `0` with `oldstate_known == 0`
    /// means the tracepoint field was not read, not `TCP_ESTABLISHED`.
    pub oldstate: u8,
    /// New TCP state.
    pub newstate: u8,
    pub oldstate_known: u8,
    pub newstate_known: u8,
    pub family: u8,
    pub family_known: u8,
    pub local_known: u8,
    pub remote_known: u8,
    pub local_port_known: u8,
    pub remote_port_known: u8,
    pub _pad0: u8,
    pub local_port: u16,
    pub remote_port: u16,
    pub local: AddrBytes,
    pub remote: AddrBytes,
}

/// Value stored in the `sock_stats` hash map. The key is the `sock` pointer
/// and is not repeated here.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockStats {
    /// Bytes queued by `tcp_sendmsg` / handed to UDP send.
    pub tx_bytes: u64,
    /// Bytes copied out by `tcp_cleanup_rbuf` / UDP recv.
    pub rx_bytes: u64,
    /// Send calls that contributed to `tx_bytes`.
    pub tx_segments: u64,
    /// Recv calls that contributed to `rx_bytes`.
    pub rx_segments: u64,
    pub tgid: u32,
    pub pid: u32,
    /// [`PROTO_TCP`] or [`PROTO_UDP`].
    pub proto: u8,
    pub family: u8,
    pub family_known: u8,
    pub local_known: u8,
    pub remote_known: u8,
    pub local_port_known: u8,
    pub remote_port_known: u8,
    /// `1` when this row was created by an inbound accept.
    pub inbound: u8,
    pub local_port: u16,
    pub remote_port: u16,
    pub local: AddrBytes,
    pub remote: AddrBytes,
}

/// One socket whose counters moved since the previous scan.
///
/// Userspace builds this; the kernel never writes it. `prev_*` is the totals
/// from the previous scan (0 if the socket is new). The decoder emits `NetSend`
/// / `NetRecv` for the difference and does not emit a direction whose delta is
/// 0. `read_error` set means the walk could not read the row: no event, the
/// caller records a gap itself.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockStatsDelta {
    /// [`RECORD_STATS`].
    pub tag: u32,
    /// Monotonic time of the scan, not of the individual send.
    pub ts_mono_ns: u64,
    pub sock: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub prev_tx_bytes: u64,
    pub prev_rx_bytes: u64,
    pub tgid: u32,
    pub pid: u32,
    pub proto: u8,
    pub family: u8,
    pub family_known: u8,
    pub local_known: u8,
    pub remote_known: u8,
    pub local_port_known: u8,
    pub remote_port_known: u8,
    pub inbound: u8,
    /// `1` when this scan could not read the map value.
    pub read_error: u8,
    pub _pad0: u8,
    pub local_port: u16,
    pub remote_port: u16,
    pub local: AddrBytes,
    pub remote: AddrBytes,
}

/// DNS datagram prefix. Not retained after parsing.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsPayload {
    /// [`RECORD_DNS`].
    pub tag: u32,
    pub ts_mono_ns: u64,
    pub tgid: u32,
    pub pid: u32,
    pub sock: u64,
    /// `1` for `udp_recvmsg` (answer direction), `0` for send (query direction).
    /// The QR bit inside the payload is what the parser trusts; this flag only
    /// says which hook copied the bytes.
    pub recv: u8,
    pub family: u8,
    pub family_known: u8,
    pub local_known: u8,
    pub remote_known: u8,
    pub local_port_known: u8,
    pub remote_port_known: u8,
    /// `1` when `len` is the real datagram length. `0` means the probe could
    /// not read the length and `payload` must not be parsed.
    pub len_known: u8,
    /// Datagram length before truncation. May be greater than [`DNS_PAYLOAD_CAP`].
    pub len: u16,
    pub local_port: u16,
    pub remote_port: u16,
    pub local: AddrBytes,
    pub remote: AddrBytes,
    /// First `min(len, DNS_PAYLOAD_CAP)` bytes. Bytes past `len` are zero and
    /// are not part of the message.
    pub payload: [u8; DNS_PAYLOAD_CAP],
}

const _: () = {
    // Keep the documented sizes honest. A field inserted in the middle without
    // updating the userspace mirror should fail this crate, not mis-decode.
    assert!(core::mem::size_of::<ConnRecord>() == 80);
    assert!(core::mem::size_of::<StateRecord>() == 80);
    assert!(core::mem::size_of::<SockStats>() == 80);
    assert!(core::mem::size_of::<SockStatsDelta>() == 104);
    assert!(core::mem::size_of::<DnsPayload>() == 568);
};

/// Fallback attach points, first choice first (linux §2.3).
///
/// The loader tries them in order. This table is documentation for that
/// loader; nothing here attaches.
pub const ATTACH_FALLBACKS: &[(&str, &[&str])] = &[
    ("tcp_connect", &["fexit/tcp_connect", "kprobe/tcp_connect"]),
    ("inet_csk_accept", &["fexit/inet_csk_accept", "kprobe/inet_csk_accept"]),
    ("inet_sock_set_state", &["tracepoint/sock/inet_sock_set_state"]),
    ("tcp_sendmsg", &["fexit/tcp_sendmsg", "kprobe/tcp_sendmsg"]),
    ("tcp_cleanup_rbuf", &["kprobe/tcp_cleanup_rbuf"]),
    ("udp_sendmsg", &["kprobe/udp_sendmsg"]),
    ("udpv6_sendmsg", &["kprobe/udpv6_sendmsg"]),
    (
        "udp_recvmsg",
        &["fexit/udp_recvmsg", "kprobe/udp_recvmsg"],
    ),
];
