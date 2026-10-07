//! P1 stand-ins for `--redact-paths` and `--redact-hosts`.
//!
//! This is not the P2 redaction module. It does not hash, and it does not
//! rewrite a general path grammar (no UNC, no `\\?\`, no `~`).
//!
//! # Paths
//!
//! [`redact_user_paths`] replaces the user-name segment with the fixed token
//! `<user>` (six characters, whatever the original name's length was):
//!
//! - `/Users/<name>` and `/home/<name>` (case-sensitive, POSIX)
//! - `<drive>:\Users\<name>` and `<drive>:/Users/<name>` (`Users` is
//!   case-insensitive; the drive letter is one ASCII letter)
//!
//! `<name>` runs until the next `/` or `\`, or until the end. `.` and `..`
//! are left alone. The original separator characters are kept.
//!
//! # Hosts
//!
//! A hostname label is ASCII: one alphanumeric, then up to 61 of
//! `[A-Za-z0-9-]`, ending in an alphanumeric when longer than one character.
//!
//! [`redact_host_field`] is for a column that is itself a name (`domain`,
//! `sni`, `qname`, `server`):
//!
//! - IPv4 (four dotted decimal octets) and anything containing `:` are unchanged.
//! - A name ending in `.local`, `.lan`, `.home`, `.internal`, or `.localdomain`
//!   (suffix match is case-insensitive) has its leftmost label replaced with
//!   `<host>`. The rest of the name, including the suffix, is kept as stored.
//! - A single label that matches the hostname rule is replaced with `<host>`.
//! - Any other name, including a public multi-label name such as `example.com`,
//!   is unchanged.
//!
//! [`redact_host_text`] is for free text (`gaps.detail`). It only replaces
//! tokens that have one of those intranet suffixes. A bare word is not a host.

const USER_TOKEN: &str = "<user>";
const HOST_TOKEN: &str = "<host>";

const INTRANET_SUFFIXES: &[&str] = &[".local", ".lan", ".home", ".internal", ".localdomain"];

/// Replace user-name path segments with `<user>`.
pub fn redact_user_paths(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if let Some(end) = match_users(bytes, i) {
            let mut name_start = end;
            while name_start > i && bytes[name_start - 1] != b'/' && bytes[name_start - 1] != b'\\'
            {
                name_start -= 1;
            }
            if let Ok(prefix) = std::str::from_utf8(&bytes[i..name_start]) {
                out.push_str(prefix);
                out.push_str(USER_TOKEN);
                i = end;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\u{FFFD}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Replace a hostname column. See the module comment.
pub fn redact_host_field(input: &str) -> String {
    if input.is_empty() || looks_like_ip(input) {
        return input.to_string();
    }
    if let Some((body, suffix)) = strip_intranet(input) {
        if let Some(replaced) = replace_left_label(body, suffix) {
            return replaced;
        }
        return input.to_string();
    }
    if !input.contains('.') && is_hostname_label(input) {
        return HOST_TOKEN.to_string();
    }
    input.to_string()
}

/// Replace intranet-suffixed names inside free text. Bare words stay.
pub fn redact_host_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while !rest.is_empty() {
        let start = rest
            .char_indices()
            .find(|(_, ch)| is_token_char(*ch))
            .map(|(idx, _)| idx);
        let Some(start) = start else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let end = tail
            .char_indices()
            .find(|(_, ch)| !is_token_char(*ch))
            .map(|(idx, _)| idx)
            .unwrap_or(tail.len());
        let token = &tail[..end];
        if strip_intranet(token).is_some() {
            out.push_str(&redact_host_field(token));
        } else {
            out.push_str(token);
        }
        rest = &tail[end..];
    }
    out
}

fn match_users(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes[i..].starts_with(b"/Users/") {
        return name_end(bytes, i + "/Users/".len());
    }
    if bytes[i..].starts_with(b"/home/") {
        return name_end(bytes, i + "/home/".len());
    }
    // "C:\Users\" or "C:/Users/" — `Users` compared case-insensitively.
    if i + 9 < bytes.len()
        && bytes[i].is_ascii_alphabetic()
        && bytes[i + 1] == b':'
        && (bytes[i + 2] == b'\\' || bytes[i + 2] == b'/')
        && bytes[i + 3..].len() >= 6
        && bytes[i + 3..i + 8].eq_ignore_ascii_case(b"Users")
        && (bytes[i + 8] == b'\\' || bytes[i + 8] == b'/')
    {
        return name_end(bytes, i + 9);
    }
    None
}

/// End index of a user-name segment, or `None` when the segment is empty, `.`,
/// or `..`. The returned index is the first separator after the name, or
/// `bytes.len()`.
fn name_end(bytes: &[u8], start: usize) -> Option<usize> {
    if start > bytes.len() {
        return None;
    }
    let mut end = start;
    while end < bytes.len() && bytes[end] != b'/' && bytes[end] != b'\\' {
        end += 1;
    }
    let name = &bytes[start..end];
    if name.is_empty() || name == b"." || name == b".." {
        return None;
    }
    Some(end)
}

/// `(name without the intranet suffix, suffix as stored including the dot)`.
fn strip_intranet(input: &str) -> Option<(&str, &str)> {
    let lower = input.to_ascii_lowercase();
    for suffix in INTRANET_SUFFIXES {
        if lower.ends_with(suffix) && input.len() > suffix.len() {
            let cut = input.len() - suffix.len();
            return Some((&input[..cut], &input[cut..]));
        }
    }
    None
}

/// `<host>` plus everything after the leftmost label, including the suffix.
/// `None` when the leftmost label is not a hostname label.
fn replace_left_label(without_suffix: &str, suffix: &str) -> Option<String> {
    let left = without_suffix.split('.').next().unwrap_or(without_suffix);
    if !is_hostname_label(left) {
        return None;
    }
    let mut out = String::from(HOST_TOKEN);
    out.push_str(&without_suffix[left.len()..]);
    out.push_str(suffix);
    Some(out)
}

fn looks_like_ip(input: &str) -> bool {
    if input.contains(':') {
        return true;
    }
    let mut parts = input.split('.');
    let mut count = 0;
    for part in parts.by_ref() {
        count += 1;
        if count > 4 || part.is_empty() || part.len() > 3 {
            return false;
        }
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if part.len() > 1 && part.starts_with('0') {
            return false;
        }
        let Ok(n) = part.parse::<u16>() else {
            return false;
        };
        if n > 255 {
            return false;
        }
    }
    count == 4
}

fn is_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '-' || ch == '.'
}

fn is_hostname_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() {
        return false;
    }
    if bytes.len() == 1 {
        return true;
    }
    if !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes[1..bytes.len() - 1]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn user_segment_is_fixed_width() {
        assert_eq!(redact_user_paths("/Users/alice/proj"), "/Users/<user>/proj");
        assert_eq!(redact_user_paths("/home/bob"), "/home/<user>");
        assert_eq!(
            redact_user_paths(r"C:\Users\Carol\file"),
            r"C:\Users\<user>\file"
        );
        assert_eq!(
            redact_user_paths("C:/Users/Carol/file"),
            "C:/Users/<user>/file"
        );
        assert_eq!(redact_user_paths(r"d:\users\ALICE\a"), r"d:\users\<user>\a");
        assert_eq!(redact_user_paths("/Users/../etc"), "/Users/../etc");
        assert_eq!(redact_user_paths("/opt/data"), "/opt/data");
        assert_eq!(
            redact_user_paths("/Users/alice/x and /home/bob/y"),
            "/Users/<user>/x and /home/<user>/y"
        );
        assert_eq!(USER_TOKEN.len(), 6);
    }

    #[test]
    fn host_field_rules() {
        assert_eq!(redact_host_field("pc.local"), "<host>.local");
        assert_eq!(redact_host_field("PC.LOCAL"), "<host>.LOCAL");
        assert_eq!(redact_host_field("a.b.lan"), "<host>.b.lan");
        assert_eq!(redact_host_field("laptop"), "<host>");
        assert_eq!(redact_host_field("example.com"), "example.com");
        assert_eq!(redact_host_field("a.example.com"), "a.example.com");
        assert_eq!(redact_host_field("192.168.1.1"), "192.168.1.1");
        assert_eq!(redact_host_field("::1"), "::1");
        assert_eq!(redact_host_field("my_pc"), "my_pc");
        assert_eq!(redact_host_field("-bad.local"), "-bad.local");
        assert_eq!(HOST_TOKEN.len(), 6);
    }

    #[test]
    fn host_text_ignores_bare_words() {
        assert_eq!(redact_host_text("see pc.local now"), "see <host>.local now");
        assert_eq!(
            redact_host_text("dropped example.com"),
            "dropped example.com"
        );
        assert_eq!(redact_host_text("laptop"), "laptop");
    }
}
