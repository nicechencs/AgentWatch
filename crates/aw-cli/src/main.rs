//! `aw` entry point. No commands yet.

#![forbid(unsafe_code)]

fn main() {
    // P0-CORE-01 replaced the stub type. Touch the event model so the
    // dependency stays live until real commands exist.
    let _ = std::any::type_name::<aw_core::RawEvent>();
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
