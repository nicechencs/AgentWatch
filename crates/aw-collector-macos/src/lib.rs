//! macOS collector. Non-macOS targets compile this crate as an empty shell.

#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "macos"), allow(unused))]

#[cfg(target_os = "macos")]
mod endpoint_security;

#[cfg(target_os = "macos")]
pub use endpoint_security::MacosCollector;

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
