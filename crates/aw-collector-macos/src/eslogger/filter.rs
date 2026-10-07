//! Drop an eslogger line before JSON parse when its subject PID is out of scope.
//!
//! macos.md §1.1: eslogger cannot filter by process, so the collector finds
//! `"pid":` with a byte search and discards the line. `fork` is the exception
//! named by the task: a child whose parent is in scope must still be parsed,
//! because the child's own pid is not a member yet.
//!
//! The search uses `memchr` on the first byte of `"pid":`, then checks the rest
//! of the needle. That is the pre-parse filter macos.md §1.1 asks for.

/// Which lines to keep. An empty member set keeps nothing (including forks):
/// "watch nobody" is not a scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidFilter {
    members: Vec<u32>,
}

impl PidFilter {
    /// Filter that accepts `members`. Duplicates are kept once, in first-seen order.
    pub fn new(members: impl IntoIterator<Item = u32>) -> Self {
        let mut members: Vec<u32> = members.into_iter().collect();
        let mut seen = Vec::with_capacity(members.len());
        members.retain(|pid| {
            if seen.contains(pid) {
                false
            } else {
                seen.push(*pid);
                true
            }
        });
        Self { members }
    }

    /// PIDs currently in scope, in insertion order.
    pub fn members(&self) -> &[u32] {
        &self.members
    }

    /// `true` when `pid` is a current member.
    pub fn contains(&self, pid: u32) -> bool {
        self.members.contains(&pid)
    }

    /// Decide from the raw line, without parsing JSON.
    ///
    /// Looks for the first `"pid":` integer. A `fork` line (the substring
    /// `"event_type":"fork"` or `"event":"fork"`) is kept when *either* that pid
    /// or the first `"ppid":` integer is a member. Anything else is kept only
    /// when the subject pid is a member.
    ///
    /// A line with no `"pid":` integer is not kept. Dropping it here is not a
    /// silent loss of a process event: the caller still sees [`LineAction::Drop`]
    /// and can count it. A line that is not JSON at all never reaches the decoder.
    pub fn classify(&self, line: &str) -> LineAction {
        let bytes = line.as_bytes();
        let Some(pid) = first_u32_after(bytes, b"\"pid\":") else {
            return LineAction::Drop;
        };
        if self.contains(pid) {
            return LineAction::Keep;
        }
        if is_fork_line(bytes) {
            if let Some(ppid) = first_u32_after(bytes, b"\"ppid\":") {
                if self.contains(ppid) {
                    return LineAction::Keep;
                }
            }
        }
        LineAction::Drop
    }
}

/// What to do with one raw eslogger line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineAction {
    /// Parse the line.
    Keep,
    /// Subject (and, for a fork, parent) is outside the scope. Do not parse.
    Drop,
}

/// `true` when the first `"pid":` integer is inside `members`.
///
/// This is the fast path the task asks for. It does not special-case `fork`;
/// callers that must keep a child of an in-scope parent use [`PidFilter`].
pub fn pid_in_scope(line: &str, members: &[u32]) -> bool {
    let Some(pid) = first_u32_after(line.as_bytes(), b"\"pid\":") else {
        return false;
    };
    members.contains(&pid)
}

fn is_fork_line(bytes: &[u8]) -> bool {
    find_subsequence(bytes, b"\"event_type\":\"fork\"").is_some()
        || find_subsequence(bytes, b"\"event\":\"fork\"").is_some()
}

/// First unsigned integer after `needle`, skipping ASCII space.
///
/// `needle` includes the colon (`"pid":`). A match that is not followed by a
/// digit is ignored and the scan continues, so a string that merely contains
/// the letters does not count. Returns `None` when no such integer exists.
/// Overflow of `u32` is `None`: a pid that does not fit is not a pid we can filter on.
fn first_u32_after(haystack: &[u8], needle: &[u8]) -> Option<u32> {
    let mut rest = haystack;
    while let Some(at) = find_subsequence(rest, needle) {
        let after = &rest[at + needle.len()..];
        let mut i = 0;
        while i < after.len() && after[i] == b' ' {
            i += 1;
        }
        if i < after.len() && after[i].is_ascii_digit() {
            let mut value: u32 = 0;
            let mut saw = false;
            while i < after.len() && after[i].is_ascii_digit() {
                let digit = u32::from(after[i] - b'0');
                value = value.checked_mul(10)?.checked_add(digit)?;
                saw = true;
                i += 1;
            }
            if saw {
                return Some(value);
            }
        }
        // No integer here. Step one byte past this match and keep looking.
        let next = at.saturating_add(1);
        if next >= rest.len() {
            break;
        }
        rest = &rest[next..];
    }
    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let rest = &needle[1..];
    let mut from = 0;
    while let Some(hit) = memchr::memchr(first, &haystack[from..]) {
        let at = from + hit;
        let end = at + needle.len();
        if end <= haystack.len() && &haystack[at + 1..end] == rest {
            return Some(at);
        }
        from = at.saturating_add(1);
        if from >= haystack.len() {
            break;
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn subject_pid_outside_the_set_is_dropped_without_claiming_a_parse() {
        let filter = PidFilter::new([10, 20]);
        let line = r#"{"event":"exec","process":{"pid": 99},"seq_num":1}"#;
        assert_eq!(filter.classify(line), LineAction::Drop);
        assert!(!pid_in_scope(line, filter.members()));
    }

    #[test]
    fn subject_pid_inside_the_set_is_kept() {
        let filter = PidFilter::new([10]);
        let line = r#"{"event":"exec","process":{"audit_token":{"pid":10}}}"#;
        assert_eq!(filter.classify(line), LineAction::Keep);
    }

    #[test]
    fn fork_with_in_scope_parent_is_kept_even_when_child_pid_is_not() {
        let filter = PidFilter::new([10]);
        let line = r#"{"event":"fork","process":{"pid":40,"ppid":10},"event_type":"fork"}"#;
        assert_eq!(filter.classify(line), LineAction::Keep);
        assert!(!pid_in_scope(line, filter.members()));
    }

    #[test]
    fn fork_whose_parent_is_also_outside_is_dropped() {
        let filter = PidFilter::new([10]);
        let line = r#"{"event_type":"fork","process":{"pid":40,"ppid":11}}"#;
        assert_eq!(filter.classify(line), LineAction::Drop);
    }

    #[test]
    fn missing_pid_is_dropped() {
        let filter = PidFilter::new([1]);
        assert_eq!(
            filter.classify(r#"{"event":"exec","seq_num":1}"#),
            LineAction::Drop
        );
    }
}
