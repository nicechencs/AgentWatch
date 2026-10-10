//! `GET`/`POST /sessions/{sid}/export?format=jsonl|csv`.
//!
//! The rows, redaction, and file layout are `aw-store`'s
//! ([`aw_store::write_jsonl`], [`aw_store::write_csv_zip`]), the same writers
//! `aw export` uses. This module only opens the caller's session and frames
//! the bytes as an HTTP response. Nothing is written to disk.

use std::collections::BTreeMap;

use aw_store::ExportOptions;

use crate::api::share::{
    error_response, flag_on, open_owned, query_pairs, ApiResponse, ApiState, Caller,
};

/// Export formats this module answers. Markdown is [`super::markdown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataFormat {
    /// One JSON object per line: header, then records.
    Jsonl,
    /// A zip of one CSV per table.
    CsvZip,
}

impl DataFormat {
    /// `format=jsonl` or `format=csv`. Anything else is not this module's.
    pub(crate) fn from_query(raw_query: &str) -> Option<Self> {
        match query_pairs(raw_query).get("format").map(String::as_str) {
            Some("jsonl") => Some(Self::Jsonl),
            Some("csv") => Some(Self::CsvZip),
            _ => None,
        }
    }

    fn content_type(self) -> &'static str {
        match self {
            Self::Jsonl => "application/x-ndjson",
            Self::CsvZip => "application/zip",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::CsvZip => "csv.zip",
        }
    }
}

/// Build the export for `sid`, owned by `caller`. Another user's session is 404.
pub(crate) fn export_data(
    state: &ApiState,
    caller: &Caller,
    sid: &str,
    raw_query: &str,
    format: DataFormat,
) -> ApiResponse {
    let pairs = query_pairs(raw_query);
    let (store, session_id) = match open_owned(state, &caller.user_id, sid) {
        Ok(Some(pair)) => pair,
        Ok(None) => return error_response(404, "not_found", "session not found"),
        Err(response) => return response,
    };
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_nanos()).ok());
    let options = ExportOptions {
        user_id: &caller.user_id,
        session_id,
        filter: pairs
            .get("filter")
            .map(String::as_str)
            .filter(|f| !f.is_empty()),
        now_ns,
        redact_paths: flag_on(pairs.get("redact_paths").map(String::as_str)),
        redact_hosts: flag_on(pairs.get("redact_hosts").map(String::as_str)),
        page_size: None,
    };
    let mut body = Vec::new();
    let written = match format {
        DataFormat::Jsonl => aw_store::write_jsonl(store.connection(), &options, &mut body),
        DataFormat::CsvZip => aw_store::write_csv_zip(store.connection(), &options, &mut body),
    };
    if let Err(err) = written {
        // The store error names the query, not row contents.
        return error_response(500, "export", &err.to_string());
    }
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_owned(), format.content_type().to_owned());
    headers.insert(
        "content-disposition".to_owned(),
        format!(
            "attachment; filename=\"agentwatch-{}.{}\"",
            safe_name(sid),
            format.extension()
        ),
    );
    ApiResponse {
        status: 200,
        headers,
        body,
    }
}

/// Session ids are short tokens; anything else becomes `_` in a file name.
pub(crate) fn safe_name(sid: &str) -> String {
    sid.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{safe_name, DataFormat};

    #[test]
    fn format_selection() {
        assert_eq!(
            DataFormat::from_query("format=jsonl"),
            Some(DataFormat::Jsonl)
        );
        assert_eq!(
            DataFormat::from_query("x=1&format=csv"),
            Some(DataFormat::CsvZip)
        );
        assert_eq!(DataFormat::from_query("format=md"), None);
        assert_eq!(safe_name("a/../b\"c"), "a____b_c");
    }
}
