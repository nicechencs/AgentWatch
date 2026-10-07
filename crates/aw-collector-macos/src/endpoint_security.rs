//! macOS collector body. Compiled only on macOS.
//!
//! Spawning `/usr/bin/eslogger` is not implemented here yet: this crate is built
//! and tested on hosts that do not have that binary. The process that will own
//! the child, the exponential restart, and the TCC probe belongs in this module
//! so it cannot be compiled into a Windows or Linux test. Decoding itself is
//! [`crate::eslogger`], which has no macOS API.

/// Placeholder type. Real Endpoint Security collection starts in a later task.
///
/// P1-MAC-01 keeps the name `MacosCollector` because `aw-daemon` refers to it
/// under `cfg(target_os = "macos")`. The child-process loop is intentionally
/// absent until a macOS CI job can run `eslogger`.
pub struct MacosCollector;
