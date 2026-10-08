//! `aw doctor` (P1-CLI-04).
//!
//! Categories follow capability-matrix sections 1–7 and `aw-core`'s
//! [`CapabilityCategory`]: PROC, FILE, NET, DNS, URL, SCOPE, plus PRIV
//! (permissions and install). IPC is section 10 and is not a P1 doctor row.
//!
//! Probe results come from a [`DoctorSource`]. The default source does not
//! call a platform API: it reports every collector as not probed and every
//! category as `NA(collector_unavailable)`, with a fix hint. Tests inject a
//! fixed report and parse `--json`.

use serde_json::{json, Value};

use aw_core::{Evidence, NaReason};

use crate::exit;
use crate::output::{evidence_badge, evidence_code};

use super::Outcome;

/// One collector's `probe()` answer. Text only: this crate does not call probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CollectorProbe {
    /// Collector name (`etw`, `ebpf`, `poll`, …).
    pub name: String,
    /// `ok` when the probe ran, `unavailable` when it could not.
    pub status: String,
    /// Why, when `status` is not `ok`. `None` when the probe succeeded.
    pub detail: Option<String>,
}

/// One capability-matrix category as `aw doctor` prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CategoryRow {
    /// `proc`, `file`, `net`, `dns`, `url`, `scope`, `priv`.
    pub category: String,
    /// Source label (`native`, `poll`, …). `None` when the category is NA.
    pub source: Option<String>,
    /// Evidence the source will stamp.
    pub evidence: Evidence,
    /// What the operator can do. Present for NA rows; optional otherwise.
    pub fix: Option<String>,
}

/// Machine facts the report shows beside the matrix. No username, no hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostFacts {
    /// `linux` / `windows` / `macos`.
    pub os: String,
    /// Kernel or OS version string. Not a hostname.
    pub version: String,
    /// Whether this process holds the privilege a native collector needs.
    pub privileged: bool,
}

/// Full doctor report. Tests build this and parse the JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DoctorReport {
    /// OS and privilege.
    pub host: HostFacts,
    /// One row per collector that was asked.
    pub collectors: Vec<CollectorProbe>,
    /// One row per matrix category, in display order.
    pub categories: Vec<CategoryRow>,
}

/// Where the report comes from.
pub(crate) trait DoctorSource {
    /// Build the report. Must not include a username, hostname, or token.
    fn report(&mut self) -> DoctorReport;
}

/// Default source: nothing was probed. Every category is NA with a reason.
#[derive(Debug, Default)]
pub(crate) struct Unprobed;

impl DoctorSource for Unprobed {
    fn report(&mut self) -> DoctorReport {
        DoctorReport {
            host: HostFacts {
                os: std::env::consts::OS.to_owned(),
                version: "unknown".to_owned(),
                privileged: false,
            },
            collectors: vec![CollectorProbe {
                name: "none".to_owned(),
                status: "unavailable".to_owned(),
                detail: Some("no collector was probed in this build".to_owned()),
            }],
            categories: default_categories(),
        }
    }
}

/// Categories in capability-matrix order, all unavailable.
fn default_categories() -> Vec<CategoryRow> {
    CATEGORIES
        .iter()
        .map(|name| CategoryRow {
            category: (*name).to_owned(),
            source: None,
            evidence: Evidence::NA(NaReason::CollectorUnavailable),
            fix: Some(fix_for(name).to_owned()),
        })
        .collect()
}

/// Matrix categories this card prints. PROC/FILE/NET/DNS/URL/SCOPE match
/// [`aw_core::CapabilityCategory`]. PRIV is capability-matrix §7.
pub(crate) const CATEGORIES: [&str; 7] = ["proc", "file", "net", "dns", "url", "scope", "priv"];

fn fix_for(category: &str) -> &'static str {
    match category {
        "proc" | "file" | "net" | "dns" => {
            "run the daemon as administrator (Windows), root (Linux/macOS), or use --no-daemon (evidence S)"
        }
        "url" => "URL needs the explicit proxy (P3); without it the field is NA(tls_no_proxy)",
        "scope" => "launch mode needs a job, cgroup, or process-tree scope; attach is evidence S before the attach point",
        "priv" => "install and uninstall need an administrator terminal or sudo",
        _ => "no fix is known for this category",
    }
}

/// JSON document for `--json`. Field names are stable for the schema test.
pub(crate) fn report_json(report: &DoctorReport) -> Value {
    let categories: Vec<Value> = report
        .categories
        .iter()
        .map(|row| {
            json!({
                "category": row.category,
                "source": row.source,
                "evidence": evidence_code(&row.evidence),
                "na_reason": na_reason(&row.evidence),
                "fix": row.fix,
            })
        })
        .collect();
    let collectors: Vec<Value> = report
        .collectors
        .iter()
        .map(|probe| {
            json!({
                "name": probe.name,
                "status": probe.status,
                "detail": probe.detail,
            })
        })
        .collect();
    json!({
        "os": report.host.os,
        "version": report.host.version,
        "privileged": report.host.privileged,
        "collectors": collectors,
        "categories": categories,
    })
}

fn na_reason(evidence: &Evidence) -> Option<&'static str> {
    match evidence {
        Evidence::NA(reason) => Some(reason_code(reason)),
        _ => None,
    }
}

fn reason_code(reason: &NaReason) -> &'static str {
    match reason {
        NaReason::EsNoReadEvent => "es_no_read_event",
        NaReason::MmapNotObservable => "mmap_not_observable",
        NaReason::TlsNoProxy => "tls_no_proxy",
        NaReason::DirectBypassProxy => "direct_bypass_proxy",
        NaReason::CertPinned => "cert_pinned",
        NaReason::Quic => "quic",
        NaReason::Ech => "ech",
        NaReason::NoDnsObserved => "no_dns_observed",
        NaReason::Preexisting => "preexisting",
        NaReason::CollectorUnavailable => "collector_unavailable",
        NaReason::Redacted => "redacted",
        NaReason::AttributionBreak => "attribution_break",
        NaReason::PartialClientHello => "partial_client_hello",
        NaReason::H2Hpack => "h2_hpack",
        NaReason::TooLarge => "too_large",
        NaReason::FileChanged => "file_changed",
        NaReason::PeerUnknown => "peer_unknown",
        NaReason::ProtocolNotObserved => "protocol_not_observed",
        NaReason::Unknown => "unknown",
    }
}

fn report_text(report: &DoctorReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "os {} {} privileged={}\n",
        report.host.os, report.host.version, report.host.privileged
    ));
    out.push_str("collectors\n");
    for probe in &report.collectors {
        match &probe.detail {
            Some(detail) => {
                out.push_str(&format!("  {} {} ({detail})\n", probe.name, probe.status));
            }
            None => out.push_str(&format!("  {} {}\n", probe.name, probe.status)),
        }
    }
    out.push_str("category  source  evidence  fix\n");
    for row in &report.categories {
        let source = row.source.as_deref().unwrap_or("-");
        let fix = row.fix.as_deref().unwrap_or("-");
        out.push_str(&format!(
            "{}  {}  {}  {}\n",
            row.category,
            source,
            evidence_badge(&row.evidence),
            fix
        ));
    }
    out
}

/// Run `aw doctor`. `--perf` is P2 and exits 2 without calling `source`.
pub(crate) fn run(perf: bool, json: bool, source: &mut dyn DoctorSource) -> Outcome {
    if perf {
        return super::error_outcome(
            exit::USAGE,
            "not_implemented",
            "`aw doctor --perf` is not implemented (P2)",
            json,
        );
    }
    let report = source.report();
    let text = if json {
        format!("{}\n", report_json(&report))
    } else {
        report_text(&report)
    };
    Outcome {
        code: exit::OK,
        stdout: text.into_bytes(),
        stderr: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{
        report_json, run, CategoryRow, CollectorProbe, DoctorReport, DoctorSource, HostFacts,
        CATEGORIES,
    };
    use crate::exit;
    use aw_core::{Evidence, NaReason};

    struct Fixed;

    impl DoctorSource for Fixed {
        fn report(&mut self) -> DoctorReport {
            DoctorReport {
                host: HostFacts {
                    os: "linux".to_owned(),
                    version: "6.6".to_owned(),
                    privileged: false,
                },
                collectors: vec![
                    CollectorProbe {
                        name: "ebpf".to_owned(),
                        status: "unavailable".to_owned(),
                        detail: Some("no BTF; demoted to legacy".to_owned()),
                    },
                    CollectorProbe {
                        name: "poll".to_owned(),
                        status: "ok".to_owned(),
                        detail: None,
                    },
                ],
                categories: vec![
                    CategoryRow {
                        category: "proc".to_owned(),
                        source: Some("poll".to_owned()),
                        evidence: Evidence::S,
                        fix: None,
                    },
                    CategoryRow {
                        category: "file".to_owned(),
                        source: None,
                        evidence: Evidence::NA(NaReason::CollectorUnavailable),
                        fix: Some("file events need a native collector".to_owned()),
                    },
                    CategoryRow {
                        category: "net".to_owned(),
                        source: Some("poll".to_owned()),
                        evidence: Evidence::S,
                        fix: None,
                    },
                    CategoryRow {
                        category: "dns".to_owned(),
                        source: None,
                        evidence: Evidence::NA(NaReason::CollectorUnavailable),
                        fix: Some("DNS needs a native collector".to_owned()),
                    },
                    CategoryRow {
                        category: "url".to_owned(),
                        source: None,
                        evidence: Evidence::NA(NaReason::TlsNoProxy),
                        fix: Some("enable the explicit proxy".to_owned()),
                    },
                    CategoryRow {
                        category: "scope".to_owned(),
                        source: Some("poll".to_owned()),
                        evidence: Evidence::S,
                        fix: None,
                    },
                    CategoryRow {
                        category: "priv".to_owned(),
                        source: None,
                        evidence: Evidence::NA(NaReason::CollectorUnavailable),
                        fix: Some("run as root".to_owned()),
                    },
                ],
            }
        }
    }

    #[test]
    fn json_covers_every_matrix_category() {
        let outcome = run(false, true, &mut Fixed);
        assert_eq!(outcome.code, exit::OK);
        let text = String::from_utf8(outcome.stdout).expect("utf8");
        let value: serde_json::Value = serde_json::from_str(&text).expect("json");
        let rows = value["categories"].as_array().expect("categories");
        let names: Vec<&str> = rows
            .iter()
            .map(|row| row["category"].as_str().unwrap())
            .collect();
        assert_eq!(names, CATEGORIES);
        // `aw_core::CapabilityCategory` has no `ALL` in this build. The six
        // names are spelled here so a renamed variant fails this test. `priv`
        // is capability-matrix §7 and is not an `aw-core` category.
        let core = [
            aw_core::CapabilityCategory::Proc,
            aw_core::CapabilityCategory::File,
            aw_core::CapabilityCategory::Net,
            aw_core::CapabilityCategory::Dns,
            aw_core::CapabilityCategory::Url,
            aw_core::CapabilityCategory::Scope,
        ]
        .map(aw_core::CapabilityCategory::as_str);
        assert!(
            core.iter().all(|name| names.contains(name)),
            "doctor rows {names:?} are missing an aw-core category from {core:?}"
        );
        for row in rows {
            assert!(row.get("source").is_some(), "{row}");
            assert!(row.get("evidence").is_some(), "{row}");
            assert!(
                row.get("na_reason").is_some() || row["evidence"] != "NA",
                "{row}"
            );
            assert!(row.get("fix").is_some(), "{row}");
        }
        assert_eq!(value["categories"][1]["na_reason"], "collector_unavailable");
        assert_eq!(value["categories"][4]["na_reason"], "tls_no_proxy");
        assert_eq!(
            value["collectors"][0]["detail"],
            "no BTF; demoted to legacy"
        );
        assert_eq!(value["privileged"], false);
        let again = report_json(&Fixed.report());
        assert_eq!(again["categories"].as_array().unwrap().len(), 7);
    }

    #[test]
    fn perf_is_refused_as_p2() {
        let outcome = run(true, false, &mut Fixed);
        assert_eq!(outcome.code, exit::USAGE);
        let err = String::from_utf8(outcome.stderr).expect("utf8");
        assert!(err.contains("P2"), "{err}");
        assert!(outcome.stdout.is_empty());
    }
}
