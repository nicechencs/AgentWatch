//! LOCAL TIMING PROBE (aw-xplat-prove only, never committed).
use std::cell::RefCell;
use std::time::Instant;
thread_local!(static MARKS: RefCell<Vec<(String, f64)>> = RefCell::new(Vec::new()));
pub fn begin() { MARKS.with(|m| m.borrow_mut().clear()); }
pub fn mark(label: &str, since: Instant) {
    let ms = since.elapsed().as_secs_f64() * 1000.0;
    MARKS.with(|m| m.borrow_mut().push((label.to_owned(), ms)));
}
pub fn flush() {
    MARKS.with(|m| {
        let m = m.borrow();
        if m.iter().any(|(l, _)| l == "check_pid_owner") {
            let line: Vec<String> = m.iter().map(|(l, ms)| format!("{l}={ms:.1}")).collect();
            eprintln!("AWT {}", line.join(" | "));
        }
    });
}
