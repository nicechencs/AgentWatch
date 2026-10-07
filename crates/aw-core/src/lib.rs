//! Shared types for AgentWatch. Empty until P0-CORE-01.
//!
//! This crate must not depend on tokio, platform crates, or database crates.

#![forbid(unsafe_code)]

/// Empty marker so downstream crates can name this crate before real types exist.
pub struct Placeholder;

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
