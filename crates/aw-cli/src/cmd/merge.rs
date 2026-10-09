//! `aw merge a.jsonl b.jsonl -o merged.db` (P6-STORE-02).
//!
//! Offline only. The two paths are local JSONL exports. A URL is refused
//! before any file is opened. `--nat` is an optional text or JSON map; when
//! it is absent, no rewrite is applied and nothing is read from the host.

use std::path::Path;

use aw_store::{merge_exports, MergeRequest};

use crate::exit;

use super::Outcome;

/// Arguments clap already parsed. `nat` is absent when the flag was omitted.
pub(crate) struct MergeArgs<'a> {
    /// First export.
    pub a: &'a str,
    /// Second export.
    pub b: &'a str,
    /// Output database. Required; clap allows it to be missing so the usage
    /// path can name the flag.
    pub output: Option<&'a str>,
    /// NAT map path.
    pub nat: Option<&'a str>,
    /// `--json`.
    pub json: bool,
}

/// Import both files and write remote edges.
///
/// Success prints the paired and unpaired counts. It does not print a rate.
/// Skew is printed only when a median was computed; it is omitted when unknown,
/// never as `0`.
pub(crate) fn run(args: MergeArgs<'_>) -> Outcome {
    let Some(output) = args.output else {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "`aw merge` needs -o <merged.db>",
            args.json,
        );
    };
    if looks_like_url(args.a) || looks_like_url(args.b) || looks_like_url(output) {
        return super::error_outcome(
            exit::USAGE,
            "usage",
            "merge reads local files only and refuses a URL",
            args.json,
        );
    }
    if let Some(nat) = args.nat {
        if looks_like_url(nat) {
            return super::error_outcome(
                exit::USAGE,
                "usage",
                "merge reads local files only and refuses a URL",
                args.json,
            );
        }
    }

    let request = MergeRequest {
        side_a: Path::new(args.a),
        side_b: Path::new(args.b),
        output: Path::new(output),
        nat: args.nat.map(Path::new),
    };
    match merge_exports(&request) {
        Ok(report) => {
            let skew = match report.skew_ns {
                Some(ns) => format!(" skew_b_minus_a_ns={ns}"),
                None => String::new(),
            };
            let text = format!(
                "paired={} unpaired={}{skew}\n",
                report.paired, report.unpaired
            );
            let stdout = if args.json {
                let skew_json = match report.skew_ns {
                    Some(ns) => ns.to_string(),
                    None => "null".to_owned(),
                };
                format!(
                    "{{\"paired\":{},\"unpaired\":{},\"skew_b_minus_a_ns\":{skew_json}}}\n",
                    report.paired, report.unpaired
                )
            } else {
                text
            };
            Outcome {
                code: exit::OK,
                stdout: stdout.into_bytes(),
                stderr: Vec::new(),
            }
        }
        Err(err) => super::error_outcome(exit::GENERAL, "merge", &err.to_string(), args.json),
    }
}

fn looks_like_url(text: &str) -> bool {
    let lower = text.trim().to_ascii_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.starts_with("file://")
}
