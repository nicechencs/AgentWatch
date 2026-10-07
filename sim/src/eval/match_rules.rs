//! Match truth actions to export events and apply the platform threshold.
//!
//! Recall is `|matched truth in the denominator| / |truth in the denominator|`.
//! Short-lived processes are removed from that denominator only when the
//! platform tier is S, or when the export's process observations are all
//! S-tier. Otherwise a miss counts.

use std::collections::BTreeMap;

use super::report::{CategoryScore, ConnectionError, EvalReport, GapItem};
use super::thresholds::{ActiveThreshold, Tier};
use super::{Category, ExportEvent, ExportKind, TruthAction};

const START_SLOP_NS: u128 = 1_000_000_000;

pub fn score_with(
    truth: &[TruthAction],
    export: &[ExportEvent],
    active: &ActiveThreshold,
    unparsed_export: u64,
) -> EvalReport {
    let s_sources = export_processes_are_s(export);
    let short_not_asserted = active.tier == Tier::S || s_sources;

    let mut proc_used = vec![false; export.len()];
    let mut net_used = vec![false; export.len()];
    let mut dns_used = vec![false; export.len()];

    let mut unmatched_truth = Vec::new();
    let mut short_lived_reported = Vec::new();
    let mut connections = Vec::new();

    let mut proc_truth = 0u64;
    let mut proc_hit = 0u64;
    let mut proc_reported = 0u64;
    let mut net_truth = 0u64;
    let mut net_hit = 0u64;
    let mut dns_truth = 0u64;
    let mut dns_hit = 0u64;

    let mut session_truth: u128 = 0;
    let mut session_got: u128 = 0;
    let mut session_comparable = false;

    for action in truth {
        match action.category {
            Category::Proc => {
                if let Some(index) = find_proc(action, export, &proc_used) {
                    proc_used[index] = true;
                    if action.short_lived && short_not_asserted {
                        proc_reported += 1;
                        short_lived_reported.push(format!("{} hit (not asserted)", action.label));
                    } else {
                        proc_truth += 1;
                        proc_hit += 1;
                    }
                } else if action.short_lived && short_not_asserted {
                    proc_reported += 1;
                    short_lived_reported.push(format!("{} miss (not asserted)", action.label));
                } else {
                    proc_truth += 1;
                    unmatched_truth.push(action.label.clone());
                }
            }
            Category::Net => {
                net_truth += 1;
                match find_conn(action, export, &net_used) {
                    Some(index) => {
                        net_used[index] = true;
                        net_hit += 1;
                        let err = connection_error(action, &export[index]);
                        accumulate(&mut session_truth, &mut session_got, &mut session_comparable, &err);
                        connections.push(err);
                    }
                    None => {
                        unmatched_truth.push(action.label.clone());
                        let err = connection_error(action, &ExportEvent::missing_conn());
                        accumulate(&mut session_truth, &mut session_got, &mut session_comparable, &err);
                        connections.push(err);
                    }
                }
            }
            Category::Dns => {
                dns_truth += 1;
                if let Some(index) = find_dns(action, export, &dns_used) {
                    dns_used[index] = true;
                    dns_hit += 1;
                } else {
                    unmatched_truth.push(action.label.clone());
                }
            }
        }
    }

    let mut unmatched_export = Vec::new();
    for (index, event) in export.iter().enumerate() {
        let used = match event.kind {
            ExportKind::ProcessStart => proc_used[index],
            ExportKind::NetConnect | ExportKind::NetClose => net_used[index],
            ExportKind::DnsQuery => dns_used[index],
            ExportKind::Gap | ExportKind::Other => true,
        };
        if !used {
            unmatched_export.push(describe_export(event));
        }
    }

    let gaps = export
        .iter()
        .filter(|event| event.kind == ExportKind::Gap)
        .map(|event| GapItem {
            gap_kind: event.gap_kind.clone().unwrap_or_else(|| "unspecified".to_string()),
            affects: event.gap_affects.clone(),
            detail: event.gap_detail.clone(),
        })
        .collect();

    let mut evidence = BTreeMap::new();
    for event in export {
        if let Some(level) = &event.evidence {
            *evidence.entry(level.clone()).or_insert(0) += 1;
        }
    }

    let session_byte_error = if session_comparable && session_truth > 0 {
        let diff = session_got.abs_diff(session_truth);
        Some(diff as f64 / session_truth as f64)
    } else {
        None
    };

    let categories = vec![
        CategoryScore::new(Category::Proc, proc_truth, proc_hit, proc_reported),
        CategoryScore::new(Category::Net, net_truth, net_hit, 0),
        CategoryScore::new(Category::Dns, dns_truth, dns_hit, 0),
    ];

    let mut failures = Vec::new();
    if active.tier == Tier::E1 {
        for row in &categories {
            if let Some(recall) = row.recall {
                if recall + f64::EPSILON < active.recall_min {
                    failures.push(format!(
                        "{} recall {:.1}% < {:.1}%",
                        row.category,
                        recall * 100.0,
                        active.recall_min * 100.0
                    ));
                }
            }
        }
        if let Some(err) = session_byte_error {
            if err + f64::EPSILON >= active.byte_error_max {
                failures.push(format!(
                    "session byte error {:.1}% >= {:.1}%",
                    err * 100.0,
                    active.byte_error_max * 100.0
                ));
            }
        }
        for row in &connections {
            for (side, err) in [("up", row.err_up), ("down", row.err_down)] {
                if let Some(err) = err {
                    if err + f64::EPSILON >= active.byte_error_max {
                        failures.push(format!(
                            "{} {side} byte error {:.1}% >= {:.1}%",
                            row.label,
                            err * 100.0,
                            active.byte_error_max * 100.0
                        ));
                    }
                }
            }
        }
    }

    EvalReport {
        platform: active.platform.clone(),
        tier: match active.tier {
            Tier::E1 => "E1",
            Tier::S => "S",
        }
        .to_string(),
        passed: failures.is_empty(),
        categories,
        connections,
        session_byte_error,
        evidence,
        gaps,
        unmatched_truth,
        unmatched_export,
        unparsed_export,
        failures,
        short_lived_reported,
    }
}

fn export_processes_are_s(export: &[ExportEvent]) -> bool {
    let starts: Vec<&ExportEvent> = export
        .iter()
        .filter(|event| event.kind == ExportKind::ProcessStart)
        .collect();
    !starts.is_empty() && starts.iter().all(|event| event.is_s_tier())
}

fn find_proc(action: &TruthAction, export: &[ExportEvent], used: &[bool]) -> Option<usize> {
    export.iter().enumerate().find_map(|(index, event)| {
        if used[index] || event.kind != ExportKind::ProcessStart {
            return None;
        }
        if event.pid != Some(action.pid) {
            return None;
        }
        if !exe_match(action.exe.as_deref(), event.exe.as_deref()) {
            return None;
        }
        if !time_match(action.t_wall_ns, event.ts_wall_ns) {
            return None;
        }
        Some(index)
    })
}

fn exe_match(truth: Option<&str>, export: Option<&str>) -> bool {
    match (truth, export) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(left), Some(right)) => exe_key(left) == exe_key(right),
    }
}

fn exe_key(path: &str) -> String {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path);
    name.to_ascii_lowercase()
}

fn time_match(truth_ns: u128, export_ns: Option<i64>) -> bool {
    let Some(export_ns) = export_ns else {
        return true;
    };
    if export_ns < 0 {
        return false;
    }
    let export_ns = export_ns as u128;
    truth_ns.abs_diff(export_ns) <= START_SLOP_NS
}

fn find_conn(action: &TruthAction, export: &[ExportEvent], used: &[bool]) -> Option<usize> {
    let (local, remote) = (action.local_port?, action.remote_port?);
    let close = export.iter().enumerate().find_map(|(index, event)| {
        if used[index] || event.kind != ExportKind::NetClose {
            return None;
        }
        if event.local_port == Some(local) && event.remote_port == Some(remote) {
            Some(index)
        } else {
            None
        }
    });
    if close.is_some() {
        return close;
    }
    export.iter().enumerate().find_map(|(index, event)| {
        if used[index] || event.kind != ExportKind::NetConnect {
            return None;
        }
        if event.local_port == Some(local) && event.remote_port == Some(remote) {
            Some(index)
        } else {
            None
        }
    })
}

fn find_dns(action: &TruthAction, export: &[ExportEvent], used: &[bool]) -> Option<usize> {
    let qname = action.qname.as_deref()?;
    export.iter().enumerate().find_map(|(index, event)| {
        if used[index] || event.kind != ExportKind::DnsQuery {
            return None;
        }
        let got = event.qname.as_deref()?;
        if qname_key(qname) == qname_key(got) {
            Some(index)
        } else {
            None
        }
    })
}

fn qname_key(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn connection_error(action: &TruthAction, event: &ExportEvent) -> ConnectionError {
    let (local_port, remote_port) = (action.local_port.unwrap_or(0), action.remote_port.unwrap_or(0));
    let matched = event.kind == ExportKind::NetClose || event.kind == ExportKind::NetConnect;
    // A side with no truth bytes is not scored, so the collected count is not
    // shown either. `0` would read as a measurement of a transfer that did not happen.
    let got_up = if event.kind == ExportKind::NetClose && action.bytes_up.is_some() {
        event.bytes_sent
    } else {
        None
    };
    let got_down = if event.kind == ExportKind::NetClose && action.bytes_down.is_some() {
        event.bytes_recv
    } else {
        None
    };
    ConnectionError {
        label: action.label.clone(),
        local_port,
        remote_port,
        truth_up: action.bytes_up,
        truth_down: action.bytes_down,
        got_up,
        got_down,
        err_up: rel_err(action.bytes_up, got_up),
        err_down: rel_err(action.bytes_down, got_down),
        matched,
    }
}

/// `|got - truth| / truth`. A missing observation counts as 0 collected bytes,
/// so a dropped connection is a 100% error rather than "no data".
fn rel_err(truth: Option<u64>, got: Option<u64>) -> Option<f64> {
    let truth = truth.filter(|n| *n > 0)?;
    let got = got.unwrap_or(0);
    Some(got.abs_diff(truth) as f64 / truth as f64)
}

fn accumulate(truth: &mut u128, got: &mut u128, comparable: &mut bool, err: &ConnectionError) {
    if let Some(n) = err.truth_up {
        *truth += u128::from(n);
        *got += u128::from(err.got_up.unwrap_or(0));
        *comparable = true;
    }
    if let Some(n) = err.truth_down {
        *truth += u128::from(n);
        *got += u128::from(err.got_down.unwrap_or(0));
        *comparable = true;
    }
}

fn describe_export(event: &ExportEvent) -> String {
    match event.kind {
        ExportKind::ProcessStart => format!(
            "process_start pid={} exe={}",
            event.pid.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
            event.exe.as_deref().unwrap_or("-")
        ),
        ExportKind::NetConnect => format!(
            "net_connect {}:{}",
            event.local_port.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
            event.remote_port.map(|n| n.to_string()).unwrap_or_else(|| "-".into())
        ),
        ExportKind::NetClose => format!(
            "net_close {}:{}",
            event.local_port.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
            event.remote_port.map(|n| n.to_string()).unwrap_or_else(|| "-".into())
        ),
        ExportKind::DnsQuery => format!("dns_query {}", event.qname.as_deref().unwrap_or("-")),
        ExportKind::Gap | ExportKind::Other => "export".to_string(),
    }
}

impl ExportEvent {
    fn missing_conn() -> Self {
        Self {
            kind: ExportKind::Other,
            evidence: None,
            source: None,
            pid: None,
            exe: None,
            ts_wall_ns: None,
            local_port: None,
            remote_port: None,
            qname: None,
            bytes_sent: None,
            bytes_recv: None,
            lifetime_ms: None,
            gap_kind: None,
            gap_affects: Vec::new(),
            gap_detail: None,
        }
    }
}
