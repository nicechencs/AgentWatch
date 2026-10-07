//! Linux collector. Non-Linux targets compile this crate as an empty shell.

#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "linux"), allow(unused))]

#[cfg(target_os = "linux")]
mod collector;

#[cfg(target_os = "linux")]
pub use collector::LinuxCollector;

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
