//! Connection byte counts.
//!
//! This crate does not call the platform counters. They stay unavailable, and the
//! events that would have carried them are not emitted with `0`.
//!
//! A later platform task fills this in:
//! * Windows: `GetPerTcpConnectionEStats` (enabling the stats needs an administrator;
//!   this crate does not call it and does not elevate).
//! * Linux: sock_diag `tcp_info` (may need extra privileges; this crate does not
//!   open a netlink socket).
//! * macOS: `nettop` (needs root; this crate does not spawn it).

use aw_core::NaReason;

/// Byte counters for one connection, or why they cannot be read.
///
/// The only implementation today returns [`NaReason::CollectorUnavailable`].
/// Callers must keep `total_sent` / `total_recv` as `None` and must not emit
/// `NetSend` or `NetRecv`: those kinds require a real `u64` byte count, and `0`
/// would mean "zero bytes were transferred".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteCounts {
    /// Bytes sent on this connection, if a later platform filler observed them.
    pub sent: Option<u64>,
    /// Bytes received on this connection, if a later platform filler observed them.
    pub recv: Option<u64>,
    /// Why `sent` or `recv` is `None`. `None` only when both counters are present.
    pub unavailable: Option<NaReason>,
}

/// Connection byte counts for the current platform.
///
/// Always unavailable. See the module comment for which API fills this later.
/// The function takes no connection key on purpose: there is no per-flow query
/// to make, so a caller cannot accidentally pass a live table into it.
pub fn connection_byte_counts() -> ByteCounts {
    ByteCounts {
        sent: None,
        recv: None,
        unavailable: Some(NaReason::CollectorUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::connection_byte_counts;
    use aw_core::NaReason;

    #[test]
    fn bytes_are_unavailable_not_zero() {
        let counts = connection_byte_counts();
        assert_eq!(counts.sent, None);
        assert_eq!(counts.recv, None);
        assert_eq!(counts.unavailable, Some(NaReason::CollectorUnavailable));
    }
}
