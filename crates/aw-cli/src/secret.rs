//! Bearer token and UI ticket values the CLI holds.
//!
//! [`Secret`] exists so a token cannot leak through formatting. [`Debug`] and
//! [`Display`] always print `<redacted>`: no length, no prefix, no fragment.
//! The bytes are available only through [`Secret::expose`], and only the code
//! that writes the `Authorization` header calls it.

use std::fmt;

/// A bearer token or one-time ticket. Never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap `value`. An empty string is still a secret: printing it as empty
    /// would tell a reader the token was blank.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The raw secret. Call this only to put the bytes on the wire.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_and_display_redact_with_no_length_or_prefix() {
        let secret = Secret::new("bad-ticket-value-XYZ");
        let debug = format!("{secret:?}");
        let display = secret.to_string();
        assert_eq!(debug, "<redacted>");
        assert_eq!(display, "<redacted>");
        for rendered in [debug.as_str(), display.as_str()] {
            assert!(!rendered.contains("bad"), "{rendered}");
            assert!(!rendered.contains("XYZ"), "{rendered}");
            assert!(!rendered.contains("len="), "{rendered}");
            assert!(!rendered.contains("ticket"), "{rendered}");
            assert!(!rendered.contains("token"), "{rendered}");
        }
        assert_eq!(secret.expose(), "bad-ticket-value-XYZ");
    }
}
