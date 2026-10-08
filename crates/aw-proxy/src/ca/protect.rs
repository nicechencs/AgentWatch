//! Private-key wrapping.
//!
//! The workspace forbids `unsafe`, so this crate does not call DPAPI. Windows
//! gets a placeholder that stores the PKCS#8 bytes unchanged and reports
//! `protected = false`. Unix callers set mode `0o600` on the file that holds
//! those bytes; the mode is not a cryptographic wrap.

use std::fmt;

use zeroize::Zeroizing;

/// Turns private-key bytes into the bytes written to `ca.key`, and back.
pub trait KeyProtector {
    /// Protect `pkcs8`. The returned buffer is what `ca.key` stores.
    ///
    /// # Errors
    ///
    /// The platform wrap failed. The message must not contain key bytes.
    fn protect(&self, pkcs8: &[u8]) -> Result<ProtectedKey, String>;

    /// Recover PKCS#8 bytes. The caller wipes them.
    ///
    /// # Errors
    ///
    /// The stored bytes cannot be unwrapped.
    fn unprotect(&self, stored: &[u8]) -> Result<Zeroizing<Vec<u8>>, String>;

    /// `true` only when the bytes are actually encrypted for this machine.
    fn is_protected(&self) -> bool;

    /// Why [`Self::is_protected`] is false, when it is. `None` when it is true.
    fn unprotected_reason(&self) -> Option<&'static str>;
}

/// Bytes destined for `ca.key`. `Debug` prints the length, never the bytes.
pub struct ProtectedKey {
    bytes: Vec<u8>,
}

impl ProtectedKey {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the stored form. Do not log it.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ProtectedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedKey")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Unix file permissions are the protection. The bytes themselves are PKCS#8.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnixFileProtector;

impl KeyProtector for UnixFileProtector {
    fn protect(&self, pkcs8: &[u8]) -> Result<ProtectedKey, String> {
        Ok(ProtectedKey::new(pkcs8.to_vec()))
    }

    fn unprotect(&self, stored: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        Ok(Zeroizing::new(stored.to_vec()))
    }

    fn is_protected(&self) -> bool {
        // Mode 0600 is a permission, not encryption. Callers still set the mode.
        false
    }

    fn unprotected_reason(&self) -> Option<&'static str> {
        Some("unix: key file is mode 0600, not encrypted")
    }
}

/// Windows placeholder.
///
/// DPAPI (machine scope) is the design (security-privacy §5). Calling it needs
/// FFI, and this workspace forbids `unsafe`. The bytes are stored as-is.
/// [`KeyProtector::is_protected`] is `false` and the reason says so. A later
/// change can replace this type without changing [`super::CaStore`].
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsDpapiPlaceholder;

impl KeyProtector for WindowsDpapiPlaceholder {
    fn protect(&self, pkcs8: &[u8]) -> Result<ProtectedKey, String> {
        Ok(ProtectedKey::new(pkcs8.to_vec()))
    }

    fn unprotect(&self, stored: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        Ok(Zeroizing::new(stored.to_vec()))
    }

    fn is_protected(&self) -> bool {
        false
    }

    fn unprotected_reason(&self) -> Option<&'static str> {
        Some(
            "windows: DPAPI machine-scope wrap is not linked (no unsafe FFI); ca.key bytes are not encrypted",
        )
    }
}

/// Protector for the crate's target. Unix sets `0o600`; Windows is the placeholder.
#[must_use]
pub fn platform_protector() -> Box<dyn KeyProtector> {
    #[cfg(unix)]
    {
        Box::new(UnixFileProtector)
    }
    #[cfg(windows)]
    {
        Box::new(WindowsDpapiPlaceholder)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Box::new(UnixFileProtector)
    }
}
