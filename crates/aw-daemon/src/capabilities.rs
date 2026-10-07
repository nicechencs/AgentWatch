//! Per-class capability choice for a session.
//!
//! fallback-poll §4: at start the daemon probes native, then legacy, then poll.
//! Each class (PROC, NET, DNS) picks its own source. Mixing is allowed. The
//! choice is data the caller stores on a session. This module does not write
//! SQLite and does not call a platform API.
//!
//! `aw_core::Collector` has `capabilities()` and `update_scope()`, but no
//! `probe()`. The probe used here is therefore a daemon-side question
//! ([`crate::supervisor::Supervised::probe`]), not a method on `aw-core`.

// Same as `supervisor.rs`: the bin target has no session caller yet, and
// dead-code does not count this crate's `#[cfg(test)]` uses.
#![allow(dead_code)]

use aw_core::{Evidence, NaReason};

/// Observation class the supervisor selects a source for.
///
/// Only PROC, NET, and DNS are chosen here. File, URL, and scope stay on the
/// collector's own [`aw_core::CapabilitySet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityClass {
    /// Process start and exit.
    Proc,
    /// Connect, send, recv, and close.
    Net,
    /// DNS questions and answers.
    Dns,
}

impl CapabilityClass {
    /// The three classes, in probe order.
    pub const ALL: [Self; 3] = [Self::Proc, Self::Net, Self::Dns];

    /// Wire name stored with the choice (`"proc"`, `"net"`, `"dns"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proc => "proc",
            Self::Net => "net",
            Self::Dns => "dns",
        }
    }
}

impl std::fmt::Display for CapabilityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Priority of a collector tier. Lower is tried first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceTier {
    /// Platform-native collector (ETW, eBPF, Endpoint Security, …).
    Native = 0,
    /// Older platform path, tried when native cannot provide a class.
    Legacy = 1,
    /// Sampling collector. Events from this tier are evidence [`Evidence::S`].
    Poll = 2,
}

impl SourceTier {
    /// Stable source label used in a [`CapabilityChoice`] and in doctor output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Legacy => "legacy",
            Self::Poll => "poll",
        }
    }

    /// The tier after this one. Poll has no successor.
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::Native => Some(Self::Legacy),
            Self::Legacy => Some(Self::Poll),
            Self::Poll => None,
        }
    }
}

impl std::fmt::Display for SourceTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What one probe said about one class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassProbe {
    /// Class this answer is about.
    pub class: CapabilityClass,
    /// Highest evidence the collector will stamp, or `NA` when it cannot see the class.
    pub evidence: Evidence,
}

impl ClassProbe {
    /// Class is observable at `evidence`. `NA` is rejected: use [`unavailable`].
    ///
    /// [`unavailable`]: Self::unavailable
    pub fn available(class: CapabilityClass, evidence: Evidence) -> Option<Self> {
        if evidence.is_na() {
            return None;
        }
        Some(Self { class, evidence })
    }

    /// Class cannot be observed. The reason is stored inside [`Evidence::NA`].
    pub fn unavailable(class: CapabilityClass, reason: NaReason) -> Self {
        Self {
            class,
            evidence: Evidence::NA(reason),
        }
    }

    /// `true` when this answer can be chosen as a source.
    pub fn is_available(&self) -> bool {
        !self.evidence.is_na()
    }
}

/// One class's chosen source, evidence, and NA reason when nothing provides it.
///
/// `source` is `None` only together with [`Evidence::NA`]. A chosen source never
/// carries a silent empty name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityChoice {
    /// Class this row describes.
    pub class: CapabilityClass,
    /// Tier label (`"native"`, `"legacy"`, `"poll"`), or `None` when unavailable.
    pub source: Option<String>,
    /// Evidence the chosen source will stamp. [`Evidence::NA`] when `source` is `None`.
    pub evidence: Evidence,
}

impl CapabilityChoice {
    /// A tier offered this class at `evidence`.
    pub fn from_tier(class: CapabilityClass, tier: SourceTier, evidence: Evidence) -> Self {
        Self {
            class,
            source: Some(tier.as_str().to_owned()),
            evidence,
        }
    }

    /// No tier can observe `class`. `reason` is the real [`NaReason`], not a free string.
    pub fn unavailable(class: CapabilityClass, reason: NaReason) -> Self {
        Self {
            class,
            source: None,
            evidence: Evidence::NA(reason),
        }
    }

    /// Borrowed source name. `None` when the class is unavailable.
    pub fn source_name(&self) -> Option<&str> {
        self.source.as_deref()
    }
}

/// PROC, NET, and DNS after the startup probe. Caller-owned; not written here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    proc: CapabilityChoice,
    net: CapabilityChoice,
    dns: CapabilityChoice,
}

impl CapabilityReport {
    /// Assemble the three rows. Each row's class must match its slot.
    pub fn new(
        proc: CapabilityChoice,
        net: CapabilityChoice,
        dns: CapabilityChoice,
    ) -> Result<Self, ReportError> {
        check_class(CapabilityClass::Proc, &proc)?;
        check_class(CapabilityClass::Net, &net)?;
        check_class(CapabilityClass::Dns, &dns)?;
        Ok(Self { proc, net, dns })
    }

    /// Choice for `class`.
    pub fn get(&self, class: CapabilityClass) -> &CapabilityChoice {
        match class {
            CapabilityClass::Proc => &self.proc,
            CapabilityClass::Net => &self.net,
            CapabilityClass::Dns => &self.dns,
        }
    }

    /// Replace one row after a demotion. The row's class must match `class`.
    pub fn set(
        &mut self,
        class: CapabilityClass,
        choice: CapabilityChoice,
    ) -> Result<(), ReportError> {
        check_class(class, &choice)?;
        match class {
            CapabilityClass::Proc => self.proc = choice,
            CapabilityClass::Net => self.net = choice,
            CapabilityClass::Dns => self.dns = choice,
        }
        Ok(())
    }
}

fn check_class(expected: CapabilityClass, choice: &CapabilityChoice) -> Result<(), ReportError> {
    if choice.class != expected {
        return Err(ReportError::ClassMismatch {
            expected,
            found: choice.class,
        });
    }
    match (&choice.source, choice.evidence.is_na()) {
        (None, false) => Err(ReportError::SourceWithoutEvidence),
        (Some(_), true) => Err(ReportError::NamedUnavailable),
        _ => Ok(()),
    }
}

/// Why a [`CapabilityReport`] could not be built or updated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    /// A row was placed in the wrong class slot.
    ClassMismatch {
        /// Slot the caller named.
        expected: CapabilityClass,
        /// Class stored on the row.
        found: CapabilityClass,
    },
    /// Available evidence with no source name. Empty is not a stand-in.
    SourceWithoutEvidence,
    /// A source name paired with [`Evidence::NA`]. Unavailable rows have no source.
    NamedUnavailable,
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClassMismatch { expected, found } => {
                write!(f, "capability row is {found}, expected {expected}")
            }
            Self::SourceWithoutEvidence => f.write_str("available capability has no source name"),
            Self::NamedUnavailable => f.write_str("unavailable capability must not name a source"),
        }
    }
}

impl std::error::Error for ReportError {}
