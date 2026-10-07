//! `aw` entry point. No commands yet.

#![forbid(unsafe_code)]

fn main() {
    let _ = aw_core::Placeholder;
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
