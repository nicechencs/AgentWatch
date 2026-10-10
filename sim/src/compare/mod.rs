//! `sim compare` — score a live (or injected) session against a sim truth log.
//!
//! # Usage
//!
//!   sim compare --truth truth.jsonl --session <SESSION_ID> [--base-url http://127.0.0.1:7456]
//!               [--token <BEARER>] [--json-out out.json] [--md-out out.md]
//!
//! # Design
//!
//! The fetcher is a trait (`SessionFetcher`) so unit tests inject a fake
//! without touching network or daemon. The scorer reads truth lines, calls
//! the fetcher, computes recall and byte error per action type, and writes a
//! Markdown table plus JSON summary.
//!
//! ## NA handling
//!
//! Fields with JSON `null` or absent in the session response are counted as NA
//! rather than byte-error 0.  NA fields do not count toward the mean absolute
//! error; instead they are tallied in a separate `na_fields` counter per row.
//!
//! ## Action types scored
//!
//! | truth action          | session record kind   | byte field     |
//! |-----------------------|-----------------------|----------------|
//! | read_file             | file_access (access)  | bytes_read     |
//! | write_file / create   | file_access (create)  | bytes_written  |
//! | delete                | file_access (delete)  | —              |
//! | rename                | file_access (rename)  | —              |
//! | exec                  | process_start         | —              |
//! | http_upload           | net_flow / http       | bytes_up       |
//! | http_download         | net_flow / http       | bytes_down     |

pub mod fetch;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;

use fetch::SessionFetcher;

/// Run `sim compare` from parsed CLI arguments.
pub fn run(args: Vec<String>) -> Result<(), String> {
    let opts = parse_args(args)?;
    let truth = load_truth(&opts.truth_path)?;

    let fetcher: Box<dyn SessionFetcher> = Box::new(fetch::HttpFetcher::new(
        opts.base_url.clone(),
        opts.token.clone(),
        opts.session.clone(),
    ));

    let session_rows = fetcher.fetch_files()?;
    let session_procs = fetcher.fetch_processes()?;
    let session_flows = fetcher.fetch_flows()?;

    let report = score(&truth, &session_rows, &session_procs, &session_flows);

    let md = report.to_markdown();
    let json = report.to_json().map_err(|e| format!("encode json: {e}"))?;

    if let Some(p) = &opts.md_out {
        std::fs::write(p, &md).map_err(|e| format!("write md: {e}"))?;
    }
    if let Some(p) = &opts.json_out {
        std::fs::write(p, &json).map_err(|e| format!("write json: {e}"))?;
    }

    print!("{md}");
    if opts.json_out.is_none() {
        println!("{json}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI parsing
// ---------------------------------------------------------------------------

struct Opts {
    truth_path: PathBuf,
    session: String,
    base_url: String,
    token: Option<String>,
    json_out: Option<PathBuf>,
    md_out: Option<PathBuf>,
}

fn parse_args(args: Vec<String>) -> Result<Opts, String> {
    let mut truth = None;
    let mut session = None;
    let mut base_url = "http://127.0.0.1:7456".to_string();
    let mut token = None;
    let mut json_out = None;
    let mut md_out = None;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let next = |flag: &str, it: &mut std::vec::IntoIter<String>| -> Result<String, String> {
            it.next().ok_or_else(|| format!("{flag} needs a value"))
        };
        match arg.as_str() {
            "--truth" => truth = Some(PathBuf::from(next("--truth", &mut iter)?)),
            "--session" => session = Some(next("--session", &mut iter)?),
            "--base-url" => base_url = next("--base-url", &mut iter)?,
            "--token" => token = Some(next("--token", &mut iter)?),
            "--json-out" => json_out = Some(PathBuf::from(next("--json-out", &mut iter)?)),
            "--md-out" => md_out = Some(PathBuf::from(next("--md-out", &mut iter)?)),
            "-h" | "--help" => {
                return Err(
                    "usage: sim compare --truth truth.jsonl --session <SESSION_ID> \
                     [--base-url http://127.0.0.1:7456] [--token <BEARER>] \
                     [--json-out out.json] [--md-out out.md]"
                        .to_string(),
                )
            }
            other => return Err(format!("unknown compare flag `{other}`")),
        }
    }
    Ok(Opts {
        truth_path: truth.ok_or("missing --truth")?,
        session: session.ok_or("missing --session")?,
        base_url,
        token,
        json_out,
        md_out,
    })
}

// ---------------------------------------------------------------------------
// Truth loading
// ---------------------------------------------------------------------------

/// One truth entry relevant to the compare scorer.
#[derive(Debug, Clone)]
pub struct TruthEntry {
    pub action: String,
    pub path: Option<String>,
    #[allow(dead_code)]
    pub from: Option<String>,
    #[allow(dead_code)]
    pub to: Option<String>,
    pub bytes: Option<u64>,
    pub pid: Option<u64>,
    pub argv: Option<Vec<String>>,
    #[allow(dead_code)]
    pub ok: bool,
}

pub fn load_truth(path: &Path) -> Result<Vec<TruthEntry>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("read truth {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let action = match v.get("action").and_then(|x| x.as_str()) {
            Some(a) => a.to_string(),
            None => continue,
        };
        // Skip meta lines (run, server, setup_file, cleanup, spawn_enter, repeat)
        match action.as_str() {
            "run" | "server" | "setup_file" | "cleanup" | "spawn_enter" | "repeat"
            | "short_lived" | "sleep" | "dns_lookup" | "udp_send" | "long_conn" | "spawn" => {
                continue
            }
            _ => {}
        }
        let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
        // Only score successful truth rows.
        if !ok {
            continue;
        }
        let argv = v.get("argv").and_then(|x| x.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        });
        out.push(TruthEntry {
            action,
            path: v.get("path").and_then(|x| x.as_str()).map(str::to_string),
            from: v.get("from").and_then(|x| x.as_str()).map(str::to_string),
            to: v.get("to").and_then(|x| x.as_str()).map(str::to_string),
            bytes: v.get("bytes").and_then(|x| x.as_u64()),
            pid: v.get("pid").and_then(|x| x.as_u64()),
            argv,
            ok,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// Aggregate metrics for one action category.
#[derive(Debug, Default, Serialize, Clone)]
pub struct CategoryScore {
    pub action: String,
    /// Number of truth rows in this category.
    pub truth_total: u64,
    /// How many were found in the session.
    pub matched: u64,
    /// Total byte delta (|session_bytes - truth_bytes|) across matched rows
    /// that had both values.
    pub byte_error_sum: u64,
    /// Number of byte comparisons actually made (both sides non-NA).
    pub byte_comparisons: u64,
    /// Number of field slots that were NA on the session side.
    pub na_fields: u64,
}

impl CategoryScore {
    pub fn recall(&self) -> f64 {
        if self.truth_total == 0 {
            1.0
        } else {
            self.matched as f64 / self.truth_total as f64
        }
    }

    pub fn mean_byte_error(&self) -> Option<f64> {
        if self.byte_comparisons == 0 {
            None
        } else {
            Some(self.byte_error_sum as f64 / self.byte_comparisons as f64)
        }
    }
}

/// Full compare report.
#[derive(Debug, Serialize)]
pub struct CompareReport {
    pub categories: Vec<CategoryScore>,
    /// Unmatched session-side rows (false positives / extra).
    pub session_only: u64,
}

impl CompareReport {
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("## sim compare\n\n");
        out.push_str("| action | truth | matched | recall | mean_byte_err | na_fields |\n");
        out.push_str("|--------|------:|--------:|-------:|--------------:|----------:|\n");
        for cat in &self.categories {
            let recall = format!("{:.1}%", cat.recall() * 100.0);
            let mbe = cat
                .mean_byte_error()
                .map(|v| format!("{v:.0}"))
                .unwrap_or_else(|| "—".to_string());
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                cat.action, cat.truth_total, cat.matched, recall, mbe, cat.na_fields,
            ));
        }
        out.push_str(&format!(
            "\nsession_only (extra rows): {}\n",
            self.session_only
        ));
        out
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Score truth entries against session data.
pub fn score(
    truth: &[TruthEntry],
    session_files: &[Value],
    session_procs: &[Value],
    session_flows: &[Value],
) -> CompareReport {
    let mut cats: HashMap<String, CategoryScore> = HashMap::new();

    for entry in truth {
        let cat_key = canonical_action(&entry.action);
        let cat = cats
            .entry(cat_key.clone())
            .or_insert_with(|| CategoryScore {
                action: cat_key.clone(),
                ..Default::default()
            });
        cat.truth_total += 1;

        match cat_key.as_str() {
            "read_file" | "write_file" | "delete" | "rename" => {
                let matched = match_file_row(entry, session_files);
                if let Some(row) = matched {
                    cat.matched += 1;
                    score_bytes(cat, entry, row, &cat_key);
                }
            }
            "exec" => {
                if match_proc_row(entry, session_procs) {
                    cat.matched += 1;
                }
            }
            "http_upload" | "http_download" if match_flow_row(entry, session_flows) => {
                cat.matched += 1;
            }
            _ => {
                // Unrecognized action: count truth but no matching attempted.
            }
        }
    }

    // Count session-side file rows that had no matching truth entry.
    let truth_paths: std::collections::HashSet<String> = truth
        .iter()
        .filter_map(|e| e.path.as_ref())
        .map(|p| basename(p))
        .collect();
    let session_only = session_files
        .iter()
        .filter(|row| {
            let path = row.get("path").and_then(|x| x.as_str()).unwrap_or("");
            !truth_paths.contains(&basename(path))
        })
        .count() as u64;

    let mut categories: Vec<CategoryScore> = cats.into_values().collect();
    categories.sort_by(|a, b| a.action.cmp(&b.action));
    CompareReport {
        categories,
        session_only,
    }
}

fn canonical_action(action: &str) -> String {
    match action {
        "create" => "write_file".to_string(),
        other => other.to_string(),
    }
}

/// True when a session file row matches the truth entry.
fn match_file_row<'a>(entry: &TruthEntry, rows: &'a [Value]) -> Option<&'a Value> {
    let want = entry.path.as_deref().map(basename)?;
    rows.iter().find(|row| {
        let got = row
            .get("path")
            .and_then(|x| x.as_str())
            .map(basename)
            .unwrap_or_default();
        got == want
    })
}

fn match_proc_row(entry: &TruthEntry, rows: &[Value]) -> bool {
    // Match on pid when available; fall back to exe name from argv[0].
    if let Some(pid) = entry.pid {
        if rows
            .iter()
            .any(|r| r.get("pid").and_then(|x| x.as_u64()) == Some(pid))
        {
            return true;
        }
    }
    if let Some(argv) = &entry.argv {
        if let Some(exe0) = argv.first() {
            let exe_name = basename(exe0);
            return rows.iter().any(|r| {
                r.get("exe")
                    .and_then(|x| x.as_str())
                    .map(basename)
                    .unwrap_or_default()
                    == exe_name
            });
        }
    }
    false
}

fn match_flow_row(entry: &TruthEntry, rows: &[Value]) -> bool {
    // Flows have no direct path; match by byte direction if present.
    let want_bytes = entry.bytes.unwrap_or(0);
    rows.iter().any(|r| {
        let up = r.get("bytes_up").and_then(|x| x.as_u64()).unwrap_or(0);
        let down = r.get("bytes_down").and_then(|x| x.as_u64()).unwrap_or(0);
        up == want_bytes || down == want_bytes
    })
}

fn score_bytes(cat: &mut CategoryScore, entry: &TruthEntry, row: &Value, action: &str) {
    let byte_field = match action {
        "read_file" => "bytes_read",
        "write_file" => "bytes_written",
        _ => return,
    };
    let truth_bytes = match entry.bytes {
        Some(b) => b,
        None => return,
    };
    match row.get(byte_field) {
        Some(Value::Null) | None => {
            cat.na_fields += 1;
        }
        Some(v) => {
            if let Some(got) = v.as_u64() {
                cat.byte_error_sum += truth_bytes.abs_diff(got);
                cat.byte_comparisons += 1;
            } else {
                cat.na_fields += 1;
            }
        }
    }
}

fn basename(path: &str) -> String {
    path.rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_lowercase()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fetch::MockFetcher;

    /// Build a truth entry for tests.
    fn t(action: &str, path: Option<&str>, bytes: Option<u64>, ok: bool) -> TruthEntry {
        TruthEntry {
            action: action.to_string(),
            path: path.map(str::to_string),
            from: None,
            to: None,
            bytes,
            pid: None,
            argv: None,
            ok,
        }
    }

    /// Build a minimal file_access JSON row.
    fn file_row(path: &str, bytes_read: Option<u64>, bytes_written: Option<u64>) -> Value {
        let mut m = serde_json::json!({ "path": path });
        if let Some(b) = bytes_read {
            m["bytes_read"] = serde_json::json!(b);
        } else {
            m["bytes_read"] = Value::Null;
        }
        if let Some(b) = bytes_written {
            m["bytes_written"] = serde_json::json!(b);
        } else {
            m["bytes_written"] = Value::Null;
        }
        m
    }

    #[test]
    fn perfect_recall_exact_bytes() {
        let truth = vec![
            t(
                "read_file",
                Some("/tmp/x/home/.ssh/id_rsa"),
                Some(412),
                true,
            ),
            t("read_file", Some("/tmp/x/work/data.bin"), Some(4096), true),
        ];
        let files = vec![
            file_row("/session/home/.ssh/id_rsa", Some(412), None),
            file_row("/session/work/data.bin", Some(4096), None),
        ];
        let report = score(&truth, &files, &[], &[]);
        let cat = report
            .categories
            .iter()
            .find(|c| c.action == "read_file")
            .unwrap();
        assert_eq!(cat.truth_total, 2);
        assert_eq!(cat.matched, 2);
        assert!((cat.recall() - 1.0).abs() < 1e-6);
        assert_eq!(cat.byte_error_sum, 0);
        assert_eq!(cat.byte_comparisons, 2);
        assert_eq!(cat.na_fields, 0);
    }

    #[test]
    fn partial_recall() {
        let truth = vec![
            t("read_file", Some("/tmp/a.txt"), Some(100), true),
            t("read_file", Some("/tmp/b.txt"), Some(200), true),
            t("read_file", Some("/tmp/c.txt"), Some(300), true),
        ];
        // Session only has a.txt and c.txt
        let files = vec![
            file_row("/session/a.txt", Some(100), None),
            file_row("/session/c.txt", Some(350), None), // 50 byte error
        ];
        let report = score(&truth, &files, &[], &[]);
        let cat = report
            .categories
            .iter()
            .find(|c| c.action == "read_file")
            .unwrap();
        assert_eq!(cat.truth_total, 3);
        assert_eq!(cat.matched, 2);
        assert!((cat.recall() - 2.0 / 3.0).abs() < 1e-6);
        assert_eq!(cat.byte_error_sum, 50); // only c.txt had error
        assert_eq!(cat.byte_comparisons, 2);
    }

    #[test]
    fn na_fields_counted_separately() {
        let truth = vec![t("read_file", Some("/tmp/x.bin"), Some(1024), true)];
        // bytes_read is null => NA
        let files = vec![file_row("/session/x.bin", None, None)];
        let report = score(&truth, &files, &[], &[]);
        let cat = report
            .categories
            .iter()
            .find(|c| c.action == "read_file")
            .unwrap();
        assert_eq!(cat.matched, 1);
        assert_eq!(cat.byte_comparisons, 0); // no actual comparison
        assert_eq!(cat.na_fields, 1); // bytes_read was NA
    }

    #[test]
    fn mock_fetcher_returns_injected_data() {
        let rows = vec![file_row("/path/test.bin", Some(100), None)];
        let fetcher = MockFetcher {
            files: rows.clone(),
            processes: vec![],
            flows: vec![],
        };
        let got = fetcher.fetch_files().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].get("path").and_then(|x| x.as_str()),
            Some("/path/test.bin")
        );
    }

    #[test]
    fn zero_truth_returns_empty_report() {
        let report = score(&[], &[], &[], &[]);
        assert!(report.categories.is_empty());
        assert_eq!(report.session_only, 0);
    }

    #[test]
    fn report_renders_markdown_table() {
        let truth = vec![t("read_file", Some("/tmp/a.bin"), Some(512), true)];
        let files = vec![file_row("/session/a.bin", Some(512), None)];
        let report = score(&truth, &files, &[], &[]);
        let md = report.to_markdown();
        assert!(md.contains("| read_file |"));
        assert!(md.contains("100.0%"));
        assert!(md.contains("session_only"));
    }

    #[test]
    fn report_serializes_to_json() {
        let report = score(&[], &[], &[], &[]);
        let json = report.to_json().unwrap();
        let v: Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("categories").is_some());
    }
}
