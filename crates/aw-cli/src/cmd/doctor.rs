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
    ///
    /// `false` when the daemon did not say. That is this machine's report, not
    /// a claim that the daemon probed and found the process unprivileged. The
    /// collector row carries the daemon's reason.
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
                version: "不可得".to_owned(),
                privileged: false,
            },
            collectors: vec![CollectorProbe {
                name: "无".to_owned(),
                status: "没采".to_owned(),
                detail: Some("此构建没有探测采集器".to_owned()),
            }],
            categories: default_categories(),
        }
    }
}

/// Production source. `GET /api/v1/doctor` says the request path does not probe
/// collectors. That is mapped onto the same NA categories [`Unprobed`] prints,
/// with the daemon's reason on the collector row. Categories the daemon does
/// not list stay NA; they are not dropped.
///
/// [`Unprobed`] stays for tests and for a daemon this process could not reach.
/// A failed call does not invent an "ok" collector.
pub(crate) struct HttpDoctor {
    endpoint: crate::endpoint::Endpoint,
}

impl HttpDoctor {
    /// Bind to `endpoint`. Does not connect.
    #[must_use]
    pub(crate) fn new(endpoint: crate::endpoint::Endpoint) -> Self {
        Self { endpoint }
    }
}

impl DoctorSource for HttpDoctor {
    fn report(&mut self) -> DoctorReport {
        let fetched = (|| {
            let transport = crate::client::LoopbackHttp::new(&self.endpoint)?;
            let mut client = crate::client::Client::new(self.endpoint.clone(), transport);
            let reply = client.call(&crate::client::ApiRequest::get("/api/v1/doctor"))?;
            reply
                .json()
                .ok_or_else(|| crate::client::ClientError::Transport {
                    detail: "后台返回的响应体不是 JSON".to_owned(),
                })
        })();
        match fetched {
            Ok(body) => report_from_doctor_json(&body),
            Err(err) => {
                let mut report = Unprobed.report();
                let detail = clip_doctor(&err.to_string());
                if let Some(probe) = report.collectors.first_mut() {
                    probe.detail = Some(detail);
                }
                report
            }
        }
    }
}

fn report_from_doctor_json(body: &Value) -> DoctorReport {
    let probed = body.get("probed").and_then(Value::as_bool).unwrap_or(false);
    let reason = body
        .get("reason")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned);
    let mut collectors = match body.get("collectors") {
        Some(Value::Array(rows)) => rows.iter().filter_map(collector_from_json).collect(),
        _ => Vec::new(),
    };
    if collectors.is_empty() {
        collectors.push(CollectorProbe {
            name: "无".to_owned(),
            status: if probed {
                "可用".to_owned()
            } else {
                "没采".to_owned()
            },
            detail: reason.or_else(|| Some("后台 doctor 没有列出采集器".to_owned())),
        });
    }
    let mut categories = default_categories();
    if let Some(Value::Array(rows)) = body.get("categories") {
        for row in rows {
            let Some(name) = row.get("category").and_then(Value::as_str) else {
                continue;
            };
            let Some(slot) = categories.iter_mut().find(|item| item.category == name) else {
                // Unknown categories are not added: the report's row set is the
                // matrix this command prints. Leaving them out is NA-by-absence
                // of a slot, not a dropped known row.
                continue;
            };
            slot.source = row
                .get("source")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(str::to_owned);
            if let Some(code) = row.get("evidence").and_then(Value::as_str) {
                if let Some(evidence) = evidence_from_code(code) {
                    slot.evidence = evidence;
                }
            }
            if let Some(fix) = row.get("fix").and_then(Value::as_str) {
                if !fix.is_empty() {
                    slot.fix = Some(fix.to_owned());
                }
            }
        }
    }
    let host = body.get("host").unwrap_or(body);
    DoctorReport {
        host: HostFacts {
            os: host
                .get("os")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| std::env::consts::OS.to_owned()),
            version: host
                .get("version")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| "不可得".to_owned()),
            privileged: host
                .get("privileged")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        },
        collectors,
        categories,
    }
}

fn collector_from_json(value: &Value) -> Option<CollectorProbe> {
    let name = value.get("name").and_then(Value::as_str)?;
    if name.is_empty() {
        return None;
    }
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .unwrap_or("没采");
    let detail = value
        .get("detail")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned);
    Some(CollectorProbe {
        name: name.to_owned(),
        status: status.to_owned(),
        detail,
    })
}

fn evidence_from_code(text: &str) -> Option<Evidence> {
    let (level, reason) = text.split_once('(').unwrap_or((text, ""));
    match level.trim() {
        "E1" => Some(Evidence::E1),
        "E2" => Some(Evidence::E2),
        "E3" => Some(Evidence::E3),
        "S" => Some(Evidence::S),
        "I" => Some(Evidence::I),
        "NA" => {
            let reason = reason.trim().trim_end_matches(')').trim();
            let parsed = if reason.is_empty() {
                NaReason::CollectorUnavailable
            } else {
                parse_na(reason)
            };
            Some(Evidence::NA(parsed))
        }
        _ => None,
    }
}

fn parse_na(text: &str) -> NaReason {
    match text {
        "collector_unavailable" => NaReason::CollectorUnavailable,
        "tls_no_proxy" => NaReason::TlsNoProxy,
        _ => NaReason::Unknown,
    }
}

fn clip_doctor(text: &str) -> String {
    let mut out: String = text.chars().take(240).collect();
    if text.chars().count() > 240 {
        out.push('…');
    }
    out
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
            "请以管理员权限（Windows）或 root（Linux/macOS）运行后台，或使用 --no-daemon（证据 S）"
        }
        "url" => "URL 需要显式代理（P3）；否则字段为 NA(tls_no_proxy)",
        "scope" => "启动模式需要 Job、cgroup 或进程树范围；附着点之前为证据 S",
        "priv" => "install 和 uninstall 需要管理员终端或 sudo",
        _ => "此类别没有已知修复方法",
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
            "`aw doctor --perf` 尚未实现（P2）",
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
