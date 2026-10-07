//! Parse `netstat -ano` text. This module does not run `netstat`.
//!
//! Windows localizes the state column (`LISTENING`, `ESTABLISHED`, and the
//! header). The parser therefore ignores any line that does not start with
//! `TCP` or `UDP`, and it does not look at the state word. A remote endpoint
//! of `*:*` or port `0` is a listener, not a flow.
//!
//! An empty string or a header-only string is an empty table (`Ok`), not a
//! parse error. A line that claims to be TCP or UDP but does not contain two
//! endpoints is [`SourceError`] so the collector records a [`aw_core::Gap`]
//! instead of dropping that line.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use aw_core::{FlowDirection, L4Proto};

use crate::source::{ConnectionRow, ConnectionSnapshot, SourceError};

/// Parse one `netstat -ano` listing into connection rows.
///
/// # Errors
///
/// [`SourceError::parse`] when a TCP or UDP line cannot be read as two endpoints.
/// The error carries no text from the listing.
pub fn parse_netstat_ano(text: &str) -> Result<ConnectionSnapshot, SourceError> {
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(proto_word) = parts.next() else {
            continue;
        };
        let Some(proto) = proto_of(proto_word) else {
            continue;
        };
        let Some(local_word) = parts.next() else {
            return Err(SourceError::parse());
        };
        let Some(remote_word) = parts.next() else {
            return Err(SourceError::parse());
        };
        let Some(local) = parse_endpoint(local_word) else {
            return Err(SourceError::parse());
        };
        let Some(remote) = parse_endpoint(remote_word) else {
            return Err(SourceError::parse());
        };
        // The last integer token is the pid. A localized state word sits between
        // the remote endpoint and the pid on TCP rows, and is ignored.
        let mut pid = None;
        for token in parts {
            if let Ok(value) = token.parse::<u32>() {
                pid = Some(value);
            }
        }
        let listening = remote.port() == 0;
        rows.push(ConnectionRow {
            pid,
            proto,
            local,
            remote: if listening { None } else { Some(remote) },
            direction: FlowDirection::Unknown,
            sock_id: None,
            listening,
        });
    }
    Ok(ConnectionSnapshot::new(rows))
}

fn proto_of(word: &str) -> Option<L4Proto> {
    if word.eq_ignore_ascii_case("TCP") {
        Some(L4Proto::Tcp)
    } else if word.eq_ignore_ascii_case("UDP") {
        Some(L4Proto::Udp)
    } else {
        None
    }
}

/// `ip:port`, `[ipv6]:port`, or the listener wildcard `*:*` (port 0).
fn parse_endpoint(word: &str) -> Option<SocketAddr> {
    if word == "*:*" || word == "*" {
        return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    }
    if let Some(rest) = word.strip_prefix('[') {
        let (addr, port) = rest.split_once("]:")?;
        let ip = addr.parse::<Ipv6Addr>().ok()?;
        let port = port.parse::<u16>().ok()?;
        return Some(SocketAddr::new(IpAddr::V6(ip), port));
    }
    let (addr, port) = word.rsplit_once(':')?;
    if addr == "*" {
        let port = port.parse::<u16>().ok()?;
        return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    }
    let ip = addr.parse::<Ipv4Addr>().ok()?;
    let port = port.parse::<u16>().ok()?;
    Some(SocketAddr::new(IpAddr::V4(ip), port))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::parse_netstat_ano;
    use aw_core::{FlowDirection, L4Proto};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    const FIXTURE: &str = "\
\u{6d3b}\u{52a8}\u{8fde}\u{63a5}\n\n  \u{534f}\u{8bae}    \u{672c}\u{5730}\u{5730}\u{5740}          \u{5916}\u{90e8}\u{5730}\u{5740}        \u{72b6}\u{6001}           PID\n  TCP    127.0.0.1:443        127.0.0.1:51000      \u{5df2}\u{5efa}\u{7acb}           4242\n  TCP    0.0.0.0:80           0.0.0.0:0            \u{6b63}\u{5728}\u{4fa6}\u{542c}           7\n  TCP    [::1]:9              [::1]:51001          ESTABLISHED     99\n  UDP    127.0.0.1:53         *:*                                  53\n  TCP    127.0.0.1:1\n";

    #[test]
    fn parses_localized_listing_and_rejects_a_broken_line() {
        let err = parse_netstat_ano(FIXTURE);
        assert!(
            err.is_err(),
            "a truncated TCP line is a parse gap, not a skip"
        );
    }

    #[test]
    fn parses_established_and_skips_listeners() {
        let text = "\
Active Connections\n\n  Proto  Local Address          Foreign Address        State           PID\n  TCP    127.0.0.1:443          127.0.0.1:51000        ESTABLISHED     4242\n  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       7\n  TCP    [::1]:9                [::1]:51001            \u{5df2}\u{5efa}\u{7acb}           99\n  UDP    127.0.0.1:53           *:*                                    53\n";
        let snap = parse_netstat_ano(text).expect("fixture");
        assert_eq!(snap.rows.len(), 4);

        let established = &snap.rows[0];
        assert_eq!(established.proto, L4Proto::Tcp);
        assert_eq!(established.pid, Some(4242));
        assert!(!established.listening);
        assert_eq!(established.direction, FlowDirection::Unknown);
        assert_eq!(established.sock_id, None);
        assert_eq!(
            established.local,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443)
        );
        assert_eq!(
            established.remote,
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                51000
            ))
        );

        assert!(snap.rows[1].listening);
        assert!(snap.rows[1].remote.is_none());

        let v6 = &snap.rows[2];
        assert_eq!(v6.pid, Some(99));
        assert_eq!(
            v6.local,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9)
        );

        let udp = &snap.rows[3];
        assert_eq!(udp.proto, L4Proto::Udp);
        assert!(udp.listening);
        assert_eq!(udp.pid, Some(53));
    }

    #[test]
    fn header_only_is_an_empty_table() {
        let snap = parse_netstat_ano("Active Connections\n\n  Proto Local Foreign State PID\n")
            .expect("header");
        assert!(snap.rows.is_empty());
    }
}
