//! Windows collector. Non-Windows targets compile this crate as an empty shell.

#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "windows"), allow(unused))]

#[cfg(target_os = "windows")]
mod etw;

#[cfg(target_os = "windows")]
pub use etw::WindowsCollector;

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder() {
        assert_eq!(1 + 1, 2);
    }
}
