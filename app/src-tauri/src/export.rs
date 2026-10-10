//! Export to a file the user picks (`aw_save_export`).
//!
//! The page used to save the bytes through a webview download link. In the
//! desktop window that link wrote the file, unasked, into whatever directory
//! the app was launched from. Now the shell fetches the export over the
//! internal channel, asks with the native "Save As" dialog, writes the bytes
//! there, and tells the page the path. A browser keeps its normal download.
//!
//! The pure parts (target, file name, write) are here so they can be tested
//! without a window; the dialog call itself needs a real window.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::channel::Failure;

/// Formats the daemon exports: (query value, default extension, filter label).
const FORMATS: &[(&str, &str, &str)] = &[
    ("jsonl", "jsonl", "JSON Lines"),
    ("csv", "csv.zip", "CSV (zip)"),
    ("md", "md", "Markdown"),
];

/// Extension and dialog filter label for `format`.
fn format_info(format: &str) -> Option<(&'static str, &'static str)> {
    FORMATS
        .iter()
        .find(|(name, _, _)| *name == format)
        .map(|(_, ext, label)| (*ext, *label))
}

/// Percent-encode a session id for the request path. Public ids are
/// `[A-Za-z0-9-_]`; anything else is encoded rather than passed through.
fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// `/api/v1/sessions/{sid}/export?format=…`.
///
/// # Errors
///
/// `refused` for an empty session id or a format the daemon does not export.
pub fn target(sid: &str, format: &str) -> Result<String, Failure> {
    if sid.is_empty() {
        return Err(Failure::refused("empty session id"));
    }
    if format_info(format).is_none() {
        return Err(Failure::refused(&format!("export format {format}")));
    }
    Ok(format!(
        "/api/v1/sessions/{}/export?format={format}",
        encode_segment(sid)
    ))
}

/// File name offered in the dialog: the daemon's `content-disposition`
/// name when present, else `{sid}.{ext}`. Never a path: separators and
/// leading dots are removed, so the dialog cannot be pointed elsewhere.
#[must_use]
pub fn file_name(sid: &str, format: &str, disposition: Option<&str>) -> String {
    let from_header = disposition.and_then(|value| {
        let start = value.find("filename=")? + "filename=".len();
        let rest = value[start..].trim_start_matches('"');
        let end = rest.find(['"', ';']).unwrap_or(rest.len());
        Some(rest[..end].to_owned())
    });
    let ext = format_info(format).map_or("bin", |(ext, _)| ext);
    let raw = from_header.unwrap_or_else(|| format!("{sid}.{ext}"));
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if matches!(c, '/' | '\\' | ':' | '\0') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim_start_matches('.').trim().to_owned();
    if cleaned.is_empty() {
        format!("agentwatch-export.{ext}")
    } else {
        cleaned
    }
}

/// Dialog filter for `format`: (label, extensions without the dot).
#[must_use]
pub fn filter(format: &str) -> Option<(&'static str, Vec<&'static str>)> {
    let (ext, label) = format_info(format)?;
    // GTK matches the last extension segment; `csv.zip` is offered as `zip`.
    let last = ext.rsplit('.').next().unwrap_or(ext);
    Some((label, vec![last]))
}

/// Write `bytes` to `path`, replacing it. The user chose the path in the
/// dialog (which already asked about overwriting).
///
/// # Errors
///
/// `write_failed` with the OS reason.
pub fn write(path: &Path, bytes: &[u8]) -> Result<PathBuf, Failure> {
    std::fs::write(path, bytes)
        .map_err(|err| write_failed(&format!("could not write {}: {err}", path.display())))?;
    Ok(path.to_path_buf())
}

/// The file could not be written where the user chose.
#[must_use]
pub fn write_failed(detail: &str) -> Failure {
    Failure {
        code: "write_failed".to_owned(),
        message: "没能把导出文件写到所选位置，请换一个位置再试。".to_owned(),
        detail: detail.to_owned(),
    }
}

/// What `aw_save_export` tells the page.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Saved {
    /// HTTP status of the export request. Not 2xx: nothing was written and
    /// `error_body` holds the daemon's JSON error.
    pub status: u16,
    /// Where the file was written. `None` when cancelled or failed.
    pub path: Option<String>,
    /// The user closed the dialog without choosing a file.
    pub cancelled: bool,
    /// The daemon's error body when `status` is not 2xx.
    pub error_body: Option<String>,
    /// Bytes written.
    pub bytes: u64,
}

/// A daemon error answer (not 2xx): nothing to save, show the error.
#[must_use]
pub fn daemon_error(response: &aw_channel::Response) -> Option<Saved> {
    if (200..300).contains(&response.status) {
        return None;
    }
    Some(Saved {
        status: response.status,
        path: None,
        cancelled: false,
        error_body: Some(String::from_utf8_lossy(&response.body).into_owned()),
        bytes: 0,
    })
}

/// After the dialog: `None` is a cancel (nothing written), otherwise the
/// exact response bytes go to the chosen path.
///
/// # Errors
///
/// `write_failed` when the file cannot be written.
pub fn finish(response: &aw_channel::Response, chosen: Option<PathBuf>) -> Result<Saved, Failure> {
    let Some(chosen) = chosen else {
        return Ok(Saved {
            status: response.status,
            path: None,
            cancelled: true,
            error_body: None,
            bytes: 0,
        });
    };
    let written = write(&chosen, &response.body)?;
    Ok(Saved {
        status: response.status,
        path: Some(written.display().to_string()),
        cancelled: false,
        error_body: None,
        bytes: u64::try_from(response.body.len()).unwrap_or(u64::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::{daemon_error, file_name, filter, finish, target, write};

    fn response(status: u16, body: &[u8]) -> aw_channel::Response {
        aw_channel::Response {
            status,
            headers: vec![(
                "content-disposition".to_owned(),
                r#"attachment; filename="s-1.md""#.to_owned(),
            )],
            body: body.to_vec(),
        }
    }

    #[test]
    fn a_daemon_error_opens_no_dialog_and_carries_the_body() {
        let body = br#"{"error":{"code":"not_found","message":"session not found"}}"#;
        let saved = daemon_error(&response(404, body));
        assert_eq!(saved.as_ref().map(|s| s.status), Some(404));
        assert!(saved
            .as_ref()
            .is_some_and(|s| s.path.is_none() && !s.cancelled));
        assert!(saved
            .and_then(|s| s.error_body)
            .is_some_and(|b| b.contains("not_found")));
        assert!(daemon_error(&response(200, b"# report")).is_none());
    }

    #[test]
    fn cancel_writes_nothing_and_a_choice_gets_the_exact_bytes() {
        let ok = response(200, b"# report\n");
        let cancelled = finish(&ok, None).ok();
        assert_eq!(cancelled.as_ref().map(|s| s.cancelled), Some(true));
        assert_eq!(cancelled.and_then(|s| s.path), None);

        let dir = std::env::temp_dir().join(format!("aw-finish-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let chosen = dir.join("chosen.md");
        let saved = finish(&ok, Some(chosen.clone())).ok();
        assert_eq!(
            saved.as_ref().and_then(|s| s.path.clone()),
            Some(chosen.display().to_string())
        );
        assert_eq!(saved.map(|s| s.bytes), Some(9));
        assert_eq!(std::fs::read(&chosen).ok(), Some(b"# report\n".to_vec()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn target_encodes_the_session_and_checks_the_format() {
        assert_eq!(
            target("s-215d0b338ce3", "md").ok().as_deref(),
            Some("/api/v1/sessions/s-215d0b338ce3/export?format=md")
        );
        assert_eq!(
            target("a b/c", "csv").ok().as_deref(),
            Some("/api/v1/sessions/a%20b%2Fc/export?format=csv")
        );
        assert!(target("", "md").is_err());
        assert!(target("s-1", "pdf").is_err());
    }

    #[test]
    fn file_name_prefers_the_daemon_name_and_never_a_path() {
        assert_eq!(
            file_name("s-1", "csv", Some(r#"attachment; filename="s-1.csv.zip""#)),
            "s-1.csv.zip"
        );
        assert_eq!(file_name("s-1", "md", None), "s-1.md");
        assert_eq!(
            file_name(
                "s-1",
                "jsonl",
                Some(r#"attachment; filename="../../etc/x""#)
            ),
            "_.._etc_x"
        );
        assert_eq!(
            file_name("", "md", Some("filename=\"\"")),
            "agentwatch-export.md"
        );
    }

    #[test]
    fn csv_is_offered_as_a_zip() {
        assert_eq!(filter("csv"), Some(("CSV (zip)", vec!["zip"])));
        assert_eq!(filter("md"), Some(("Markdown", vec!["md"])));
        assert_eq!(filter("pdf"), None);
    }

    #[test]
    fn write_puts_the_exact_bytes_at_the_chosen_path() {
        let dir = std::env::temp_dir().join(format!("aw-export-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("out.csv.zip");
        let bytes = [0x50_u8, 0x4b, 0x03, 0x04, 0x00, 0xff];
        let written = write(&path, &bytes);
        assert_eq!(written.ok(), Some(path.clone()));
        assert_eq!(std::fs::read(&path).ok(), Some(bytes.to_vec()));
        let missing = write(&dir.join("no/such/dir/out.md"), b"x");
        assert_eq!(
            missing.err().map(|f| f.code),
            Some("write_failed".to_owned())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
