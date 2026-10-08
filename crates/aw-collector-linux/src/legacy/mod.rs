//! Legacy tier: proc connector, sock_diag, AF_PACKET.
//!
//! The decode in [`decode`] is pure and runs on every target, including Windows
//! CI. Opening a netlink socket does not. [`LegacySource`] is the seam a Linux
//! machine fills in later; [`UnavailableLegacy`] is the only implementation in
//! this tree, and it returns [`LegacyError::UnsupportedOnHost`] instead of
//! pretending a sample was taken.
//!
//! Kernel attach for P1-LNX-05 (proc connector subscription, `NETLINK_INET_DIAG`
//! dump, `AF_PACKET` + BPF port-53 filter) is intentionally not written here.
//! This development host is Windows and has no netlink, so that code could not
//! be compiled or checked. It stays behind the trait until a Linux tree lands it.

mod decode;

pub use decode::{
    attribute_dns, counter_evidence, decode_proc, decode_sock_delta, diff_sock, inode_na,
    lookup_inode, pid_for_inode, CounterStep, DnsPacket, InodeLookup, InodeOwner, KnownSocket,
    ProcConnectorEvent, ProcSkip, ProcWhat, SockDelta, SockSample, FIELD_ARGV, FIELD_PROC,
    SOURCE_AF_PACKET, SOURCE_PROC_CONNECTOR, SOURCE_SOCK_DIAG,
};

/// Why the legacy source produced nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyError {
    /// This build has no netlink. The message says so; it is not an empty sample.
    UnsupportedOnHost(&'static str),
}

impl std::fmt::Display for LegacyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedOnHost(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for LegacyError {}

/// Where proc-connector events, sock_diag rows, and DNS packets come from.
///
/// Implementors perform the actual reads. [`decode`] turns the records into
/// events. A poll that fails must return [`LegacyError`], not an empty `Vec`:
/// an empty vec means "the kernel reported nothing", which is a different fact.
pub trait LegacySource {
    /// Next proc-connector records already parsed out of the netlink datagram.
    fn poll_proc(&mut self) -> Result<Vec<ProcConnectorEvent>, LegacyError>;

    /// One sock_diag dump. The caller diffs it against the previous dump.
    fn poll_sock(&mut self) -> Result<Vec<SockSample>, LegacyError>;

    /// DNS packets captured on `AF_PACKET` since the previous poll.
    fn poll_dns(&mut self) -> Result<Vec<DnsPacket>, LegacyError>;

    /// inode → pid rows from `/proc/<pid>/fd`. A missing inode is not an error;
    /// [`lookup_inode`] returns [`InodeLookup::NotFound`] for those.
    fn poll_inodes(&mut self) -> Result<Vec<InodeOwner>, LegacyError>;
}

/// Shown wherever a caller asks this build to open the legacy collectors.
pub const LEGACY_UNAVAILABLE: &str =
    "legacy collection is Linux-only; this build has no netlink (P1-LNX-05 kernel attach is not implemented on this host)";

/// Source that refuses every poll.
///
/// On Linux this is the P1-LNX-05 stub: the trait is in place, the sockets are
/// not. On every other target it is the whole platform body. Either way the
/// error is explicit, so a caller cannot mistake it for an idle system.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableLegacy;

impl LegacySource for UnavailableLegacy {
    fn poll_proc(&mut self) -> Result<Vec<ProcConnectorEvent>, LegacyError> {
        Err(LegacyError::UnsupportedOnHost(LEGACY_UNAVAILABLE))
    }

    fn poll_sock(&mut self) -> Result<Vec<SockSample>, LegacyError> {
        Err(LegacyError::UnsupportedOnHost(LEGACY_UNAVAILABLE))
    }

    fn poll_dns(&mut self) -> Result<Vec<DnsPacket>, LegacyError> {
        Err(LegacyError::UnsupportedOnHost(LEGACY_UNAVAILABLE))
    }

    fn poll_inodes(&mut self) -> Result<Vec<InodeOwner>, LegacyError> {
        Err(LegacyError::UnsupportedOnHost(LEGACY_UNAVAILABLE))
    }
}

/// The legacy source this build can construct.
///
/// Non-Linux returns the error immediately: there is no netlink to open.
/// Linux compiles [`linux_stub`], which is the P1-LNX-05 attach point and also
/// refuses, because the sockets are not written in this tree.
pub fn open_legacy() -> Result<UnavailableLegacy, LegacyError> {
    #[cfg(target_os = "linux")]
    {
        linux_stub::open()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(LegacyError::UnsupportedOnHost(LEGACY_UNAVAILABLE))
    }
}

/// Linux-only attach point.
///
/// P1-LNX-05 kernel wiring (proc connector subscription, `NETLINK_INET_DIAG`
/// dump, `AF_PACKET` with a port-53 filter) belongs in this module and nowhere
/// else. It is a stub: this crate is developed on Windows, where that code
/// cannot be compiled, so nothing here opens a socket. A Linux tree replaces
/// `open` with a real [`LegacySource`] and leaves [`decode`] unchanged.
#[cfg(target_os = "linux")]
mod linux_stub {
    use super::{LegacyError, UnavailableLegacy, LEGACY_UNAVAILABLE};

    pub(super) fn open() -> Result<UnavailableLegacy, LegacyError> {
        Err(LegacyError::UnsupportedOnHost(LEGACY_UNAVAILABLE))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn opening_legacy_on_this_host_is_an_error_not_an_empty_source() {
        let err = open_legacy().expect_err("no netlink on this build");
        let LegacyError::UnsupportedOnHost(text) = err;
        assert!(text.contains("Linux-only") || text.contains("Linux"));
        assert!(text.contains("netlink") || text.contains("P1-LNX-05"));
    }

    #[test]
    fn unavailable_source_refuses_every_poll() {
        let mut src = UnavailableLegacy;
        assert!(src.poll_proc().is_err());
        assert!(src.poll_sock().is_err());
        assert!(src.poll_dns().is_err());
        assert!(src.poll_inodes().is_err());
    }
}
