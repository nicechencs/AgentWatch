//! macOS collector.
//!
//! The crate root is not wrapped in `#![cfg(target_os = "macos")]`. That
//! attribute would compile the JSON decoder out on Windows and Linux, and
//! P1-MAC-01's decode tests have to run there. `endpoint_security` is gated
//! with `cfg(target_os = "macos")` as a whole. That is the module that will
//! spawn `/usr/bin/eslogger`. The gate is not removed to make tests compile.
//!
//! JSON decoding, sequence-gap detection, and the pre-parse PID filter live in
//! [`eslogger`] and have no macOS API.

#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

mod eslogger;

#[cfg(target_os = "macos")]
mod endpoint_security;

#[cfg(target_os = "macos")]
pub use endpoint_security::MacosCollector;

pub use eslogger::{
    decode_line, pid_in_scope, AuditToken, EsEvent, LineAction, LineDecoder, LossDetector,
    PidFilter, ProbeError, ResponsibleToken, SequenceKind, SequenceLoss,
};
