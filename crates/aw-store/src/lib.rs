//! Storage. Empty until a later task fills it in.

#![forbid(unsafe_code)]

/// Empty marker so the daemon can name this crate before real types exist.
pub struct Placeholder;

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
