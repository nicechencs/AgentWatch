//! Identity newtypes shared by every event: session, process, source, address.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Current major schema version written into every [`super::RawEvent::v`].
///
/// Compatible additions (optional fields, new `NaReason` / `GapKind` / `source`
/// names) do not bump this. Incompatible changes do. See event-schema §6.
pub const SCHEMA_VERSION: u16 = 1;

/// Session the event belongs to. Storage keeps the integer; displays use a short form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u64);

impl Serialize for SessionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for SessionId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(u64::deserialize(deserializer)?))
    }
}

/// Stable process identity: `hash(pid, start_time_ns, boot_id)`.
///
/// Serialized as a `0x` + 16 hex digit string so JSON consumers that only have
/// 53-bit integers (JavaScript) do not truncate it. See event-schema §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcUid(pub u64);

impl Serialize for ProcUid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{:016x}", self.0))
    }
}

impl<'de> Deserialize<'de> for ProcUid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ProcUidVisitor;

        impl Visitor<'_> for ProcUidVisitor {
            type Value = ProcUid;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 0x-prefixed 64-bit hex string or an integer")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                let hex = v
                    .strip_prefix("0x")
                    .or_else(|| v.strip_prefix("0X"))
                    .unwrap_or(v);
                u64::from_str_radix(hex, 16)
                    .map(ProcUid)
                    .map_err(|_| E::custom(format!("invalid ProcUid `{v}`")))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(ProcUid(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                u64::try_from(v)
                    .map(ProcUid)
                    .map_err(|_| E::custom("ProcUid integer out of range"))
            }
        }

        deserializer.deserialize_any(ProcUidVisitor)
    }
}

/// The process an event is about. `None` on the parent event means "not a process event".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcRef {
    pub uid: ProcUid,
    pub pid: u32,
    /// Thread id when the platform provides one.
    pub tid: Option<u32>,
}

/// Collector that produced the event, `"<collector>/<probe>"` (event-schema §2.1).
///
/// The newtype exists so call sites pass a source explicitly (ADR-0004) and so
/// `Debug` can later redact a probe name without touching every event.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Source(pub String);

impl Source {
    pub fn new(collector_and_probe: impl Into<String>) -> Self {
        Self(collector_and_probe.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Source").field(&self.0).finish()
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for Source {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for Source {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// IP or socket address, serialized the way fixtures write it (event-schema §5):
/// IPv4 `ip:port`, IPv6 `[ip]:port`. Bare IPs stay bare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketAddr {
    Ip(IpAddr),
    Socket(std::net::SocketAddr),
}

impl SocketAddr {
    pub fn socket(addr: std::net::SocketAddr) -> Self {
        Self::Socket(addr)
    }

    pub fn ip(addr: IpAddr) -> Self {
        Self::Ip(addr)
    }
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Socket(addr) => write!(f, "{addr}"),
        }
    }
}

impl From<std::net::SocketAddr> for SocketAddr {
    fn from(value: std::net::SocketAddr) -> Self {
        Self::Socket(value)
    }
}

impl From<IpAddr> for SocketAddr {
    fn from(value: IpAddr) -> Self {
        Self::Ip(value)
    }
}

impl Serialize for SocketAddr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SocketAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        parse_socket_addr(&raw).map_err(de::Error::custom)
    }
}

fn parse_socket_addr(raw: &str) -> Result<SocketAddr, String> {
    if let Ok(sock) = std::net::SocketAddr::from_str(raw) {
        return Ok(SocketAddr::Socket(sock));
    }
    if let Ok(ip) = IpAddr::from_str(raw) {
        return Ok(SocketAddr::Ip(ip));
    }
    Err(format!("invalid socket or ip address `{raw}`"))
}

/// Unix uid or Windows SID. `name` is optional and may itself be unavailable.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRef {
    pub id: String,
    pub name: Option<String>,
}

impl fmt::Debug for UserRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserRef")
            .field("id", &"<redacted>")
            .field("name", &self.name.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Reference to a chunk-hash set. The digest itself is not content (ADR-0004 / evidence-model §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyDigestRef {
    pub chunks: u32,
    pub digest_set_id: u64,
}
