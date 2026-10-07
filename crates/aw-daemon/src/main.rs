//! agentwatchd entry point. No behavior yet.

#![forbid(unsafe_code)]

fn main() {
    // Collector assembly lives in collectors.rs so other files stay free of target_os.
    let _ = collectors::wired();
}

mod collectors;

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
