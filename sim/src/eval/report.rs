//! Markdown (for a PR) and JSON (for CI) renderings of one eval run.
//!
//! Wording stays descriptive. The report never claims a process "uploaded",
//! "leaked", or "stole" anything; it only counts matches and byte differences.

use std::collections::BTreeMap;

use serde::Serialize;

use super::Category;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EvalReport {
    pub platform: String,
    pub tier: String,
    /// `false` when an asserted threshold was missed. S-tier is always `true`.
    pub passed: bool,
    pub categories: Vec<CategoryScore>,
    pub connections: Vec<ConnectionError>,
    /// `|sum(collected) - sum(truth)| / sum(truth)` over connections that have
    /// a truth byte count. `None` when the truth total is 0.
    pub session_byte_error: Option<f64>,
    pub evidence: BTreeMap<String, u64>,
    pub gaps: Vec<GapItem>,
    pub unmatched_truth: Vec<String>,
    pub unmatched_export: Vec<String>,
    /// Export lines that were not JSON.
    pub unparsed_export: u64,
    pub failures: Vec<String>,
    /// Short-lived processes that were reported and not asserted.
    pub short_lived_reported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CategoryScore {
    pub category: String,
    pub truth: u64,
    /// Truth rows that had a match and were in the asserted denominator.
    pub hit: u64,
    /// Truth rows excluded from the denominator (short-lived under S).
    pub reported_only: u64,
    /// `None` when `truth` is 0.
    pub recall: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConnectionError {
    pub label: String,
    pub local_port: u16,
    pub remote_port: u16,
    pub truth_up: Option<u64>,
    pub truth_down: Option<u64>,
    pub got_up: Option<u64>,
    pub got_down: Option<u64>,
    /// Per-direction `|got - truth| / truth`. `None` when that side has no truth bytes.
    pub err_up: Option<f64>,
    pub err_down: Option<f64>,
    pub matched: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GapItem {
    pub gap_kind: String,
    pub affects: Vec<String>,
    pub detail: Option<String>,
}

impl EvalReport {
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "platform: {}  tier: {}\n",
            self.platform, self.tier
        ));
        out.push_str("session: not read (export file only; --session is not implemented)\n");
        out.push_str("| category | truth | hit | recall | reported only |\n");
        out.push_str("|---|---:|---:|---:|---:|\n");
        for row in &self.categories {
            let recall = match row.recall {
                Some(value) => format!("{:.1}%", value * 100.0),
                None => "—".to_string(),
            };
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                row.category, row.truth, row.hit, recall, row.reported_only
            ));
        }
        let session = match self.session_byte_error {
            Some(value) => format!("{:.1}%", value * 100.0),
            None => "—".to_string(),
        };
        out.push_str(&format!("bytes: session err {session}\n"));
        if !self.connections.is_empty() {
            out.push_str("| connection | up truth | up got | up err | down truth | down got | down err |\n");
            out.push_str("|---|---:|---:|---:|---:|---:|---:|\n");
            for row in &self.connections {
                out.push_str(&format!(
                    "| {} | {} | {} | {} | {} | {} | {} |\n",
                    row.label,
                    opt_u64(row.truth_up),
                    opt_u64(row.got_up),
                    opt_pct(row.err_up),
                    opt_u64(row.truth_down),
                    opt_u64(row.got_down),
                    opt_pct(row.err_down),
                ));
            }
        }
        if self.evidence.is_empty() {
            out.push_str("evidence: (none)\n");
        } else {
            let parts: Vec<String> = self
                .evidence
                .iter()
                .map(|(level, n)| format!("{level}={n}"))
                .collect();
            out.push_str(&format!("evidence: {}\n", parts.join(" ")));
        }
        out.push_str(&format!("gaps: {}\n", self.gaps.len()));
        for gap in &self.gaps {
            out.push_str(&format!(
                "- gap {}: affects [{}] {}\n",
                gap.gap_kind,
                gap.affects.join(","),
                gap.detail.as_deref().unwrap_or("")
            ));
        }
        out.push_str(&format!(
            "unmatched truth: {}\n",
            self.unmatched_truth.len()
        ));
        for item in &self.unmatched_truth {
            out.push_str(&format!("- {item}\n"));
        }
        out.push_str(&format!(
            "unmatched export: {}\n",
            self.unmatched_export.len()
        ));
        for item in &self.unmatched_export {
            out.push_str(&format!("- {item}\n"));
        }
        if !self.short_lived_reported.is_empty() {
            out.push_str("short-lived (reported, not asserted under S):\n");
            for item in &self.short_lived_reported {
                out.push_str(&format!("- {item}\n"));
            }
        }
        if self.unparsed_export > 0 {
            out.push_str(&format!("unparsed export lines: {}\n", self.unparsed_export));
        }
        for failure in &self.failures {
            out.push_str(&format!("FAIL: {failure}\n"));
        }
        out.push_str(if self.passed {
            "RESULT: PASS\n"
        } else {
            "RESULT: FAIL\n"
        });
        out
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

fn opt_u64(value: Option<u64>) -> String {
    match value {
        Some(n) => n.to_string(),
        None => "—".to_string(),
    }
}

fn opt_pct(value: Option<f64>) -> String {
    match value {
        Some(n) => format!("{:.1}%", n * 100.0),
        None => "—".to_string(),
    }
}

impl CategoryScore {
    pub fn new(category: Category, truth: u64, hit: u64, reported_only: u64) -> Self {
        let recall = if truth == 0 {
            None
        } else {
            Some(hit as f64 / truth as f64)
        };
        Self {
            category: category.as_str().to_string(),
            truth,
            hit,
            reported_only,
            recall,
        }
    }
}
