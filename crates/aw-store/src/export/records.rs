//! Row shapes written by the exporters.
//!
//! Fields mirror `0001_init.sql`. `None` is SQL NULL. There is no `Debug`
//! impl: `detail` and `field_evidence` can carry paths and names.

use std::io::Write;

use crate::export::jsontext::{self, JsonWrite};
use crate::export::redact::{redact_host_field, redact_host_text, redact_user_paths};
use crate::export::{io_err, ExportError, Redact};

/// Header `session` object. See the `export` module comment for the field list.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionHeader {
    /// `sessions.id`.
    pub id: i64,
    /// Public id. Not a hostname.
    pub public_id: String,
    /// User label, or unknown.
    pub name: Option<String>,
    /// `launch` or `attach`.
    pub mode: String,
    /// Agent profile, or unknown.
    pub agent: Option<String>,
    /// Start, Unix nanoseconds.
    pub started_ns: i64,
    /// End, or still running.
    pub ended_ns: Option<i64>,
    /// `linux` / `windows` / `macos`.
    pub platform: String,
    /// OS user id of the person who started the session.
    pub user_id: String,
    /// `sessions.collectors`, one JSON value.
    pub collectors_json: String,
}

/// One collector line inside `gaps_summary.by_collector`.
#[derive(Clone, PartialEq, Eq)]
pub struct CollectorGaps {
    /// `gaps.collector`.
    pub collector: String,
    /// Rows for this collector.
    pub rows: i64,
    /// Rows whose `count` is NULL.
    pub unknown_count: i64,
    /// `SUM(count)`. `None` when every `count` is NULL.
    pub lost: Option<i64>,
}

/// `gaps_summary`. Counts are the whole session; `--filter` does not apply.
#[derive(Clone, PartialEq, Eq)]
pub struct GapsSummary {
    /// Gap rows in the session.
    pub rows: i64,
    /// Rows whose `count` is NULL.
    pub unknown_count: i64,
    /// `SUM(count)` over the session. `None` when that sum is NULL.
    pub lost: Option<i64>,
    /// Per collector, ordered by collector name.
    pub by_collector: Vec<CollectorGaps>,
}

/// One `processes` row.
#[derive(Clone, PartialEq, Eq)]
pub struct ProcessRecord {
    /// Owning session.
    pub session_id: i64,
    /// `ProcUid` bit-cast to `i64`. Also the export `id`.
    pub proc_uid: i64,
    /// OS pid.
    pub pid: i64,
    /// Parent `ProcUid`, or unknown.
    pub parent_uid: Option<i64>,
    /// Parent pid, or unknown.
    pub ppid: Option<i64>,
    /// Distance from the session root, as stored.
    pub depth: i64,
    /// Start, Unix nanoseconds. Sort time for this record.
    pub start_ns: i64,
    /// Exit, or still running.
    pub exit_ns: Option<i64>,
    /// Exit code, or unknown.
    pub exit_code: Option<i64>,
    /// Exit signal, or unknown.
    pub exit_signal: Option<i64>,
    /// `fork` / `exec` / `spawn` / `snapshot` / `unknown`.
    pub how: String,
    /// OS user of the process, or unknown.
    pub user_id: Option<String>,
    /// Signer identity, or unknown.
    pub signer: Option<String>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// JSON field evidence, or unknown.
    pub field_evidence: Option<String>,
    /// Collector source string.
    pub source: String,
    /// Recognized agent id, or unknown.
    pub agent: Option<String>,
}

/// One `net_flows` row.
#[derive(Clone, PartialEq, Eq)]
pub struct NetFlowRecord {
    /// Flow id.
    pub id: i64,
    /// Owning session.
    pub session_id: i64,
    /// `ProcUid` bit-cast to `i64`.
    pub proc_uid: i64,
    /// `tcp` or `udp`.
    pub proto: String,
    /// `outbound` / `inbound` / `unknown`.
    pub direction: String,
    /// Local address.
    pub local_ip: String,
    /// Local port.
    pub local_port: i64,
    /// Remote address.
    pub remote_ip: String,
    /// Remote port.
    pub remote_port: i64,
    /// Best domain, or unknown.
    pub domain: Option<String>,
    /// How `domain` was chosen, or unknown.
    pub domain_source: Option<String>,
    /// JSON array of other candidates, or unknown.
    pub domain_alts: Option<String>,
    /// TLS SNI, or unknown.
    pub sni: Option<String>,
    /// ALPN, or unknown.
    pub alpn: Option<String>,
    /// Start, Unix nanoseconds. Sort time for this record.
    pub start_ns: i64,
    /// End, or still open.
    pub end_ns: Option<i64>,
    /// Bytes sent. `None` is not observed, not zero.
    pub bytes_up: Option<i64>,
    /// Bytes received. `None` is not observed, not zero.
    pub bytes_down: Option<i64>,
    /// `1` when the flow went through the explicit proxy.
    pub via_proxy: i64,
    /// `1` when a proxied session bypassed the proxy.
    pub direct: i64,
    /// `1` when the flow already existed at attach.
    pub preexisting: i64,
    /// `1` when the remote address is loopback.
    pub is_loopback: i64,
    /// Close result, or unknown.
    pub result: Option<i64>,
    /// Platform cumulative bytes up, or unknown.
    pub platform_total_up: Option<i64>,
    /// Platform cumulative bytes down, or unknown.
    pub platform_total_down: Option<i64>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// Why the record is `NA`, or unknown.
    pub na_reason: Option<String>,
    /// JSON field evidence, or unknown.
    pub field_evidence: Option<String>,
    /// Collector source string.
    pub source: String,
}

/// One `dns` row.
#[derive(Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Row id.
    pub id: i64,
    /// Owning session.
    pub session_id: i64,
    /// Asking process, or unknown.
    pub proc_uid: Option<i64>,
    /// Query time, Unix nanoseconds. Sort time for this record.
    pub ts_ns: i64,
    /// Query name.
    pub qname: String,
    /// Query type.
    pub qtype: i64,
    /// Response code, or unknown.
    pub rcode: Option<i64>,
    /// JSON answers, or unknown.
    pub answers: Option<String>,
    /// Minimum TTL, or unknown.
    pub ttl_min: Option<i64>,
    /// Server address, or unknown.
    pub server: Option<String>,
    /// `E1|E2|E3|S|I|NA`.
    pub evidence: String,
    /// Collector source string.
    pub source: String,
}

/// One `gaps` row. Evidence is not stored on the table; writers emit `E1`.
#[derive(Clone, PartialEq, Eq)]
pub struct GapRecord {
    /// Row id.
    pub id: i64,
    /// Session, or unknown for a global gap that was still selected.
    pub session_id: Option<i64>,
    /// Collector name.
    pub collector: String,
    /// Gap kind.
    pub kind: String,
    /// JSON array of affected categories.
    pub affects: String,
    /// Start, Unix nanoseconds. Sort time for this record.
    pub from_ns: i64,
    /// End, Unix nanoseconds.
    pub to_ns: i64,
    /// Lost-event count, or unknown.
    pub count: Option<i64>,
    /// Redacted detail, or unknown.
    pub detail: Option<String>,
}

/// One exportable record.
#[derive(Clone, PartialEq, Eq)]
pub enum ExportRecord {
    /// A `processes` row.
    Process(ProcessRecord),
    /// A `net_flows` row.
    Net(NetFlowRecord),
    /// A `dns` row.
    Dns(DnsRecord),
    /// A `gaps` row.
    Gap(GapRecord),
}

impl ExportRecord {
    /// Timeline category used as the tie-break `type` sort key's table name.
    pub fn table(&self) -> &'static str {
        match self {
            Self::Process(_) => "processes",
            Self::Net(_) => "net_flows",
            Self::Dns(_) => "dns",
            Self::Gap(_) => "gaps",
        }
    }

    /// Evidence label that will be written. Gaps are the literal `E1`.
    pub fn evidence(&self) -> &str {
        match self {
            Self::Process(row) => &row.evidence,
            Self::Net(row) => &row.evidence,
            Self::Dns(row) => &row.evidence,
            Self::Gap(_) => "E1",
        }
    }
}

/// Which CSV entry a page belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsvTable {
    /// `processes.csv`.
    Processes,
    /// `net_flows.csv`.
    NetFlows,
    /// `dns.csv`.
    Dns,
    /// `gaps.csv`.
    Gaps,
}

impl CsvTable {
    pub(crate) const ALL: [CsvTable; 4] = [
        CsvTable::Processes,
        CsvTable::NetFlows,
        CsvTable::Dns,
        CsvTable::Gaps,
    ];

    pub(crate) fn file_name(self) -> &'static str {
        match self {
            Self::Processes => "processes.csv",
            Self::NetFlows => "net_flows.csv",
            Self::Dns => "dns.csv",
            Self::Gaps => "gaps.csv",
        }
    }

    /// `timeline.cat` for this file. Short names, not the table names.
    pub(crate) fn timeline_cat(self) -> &'static str {
        match self {
            Self::Processes => "proc",
            Self::NetFlows => "net",
            Self::Dns => "dns",
            Self::Gaps => "gap",
        }
    }
}

/// One page of records. Drop it before asking the source for the next page.
///
/// `on_drop` runs when the page is dropped. The streaming test uses it to
/// prove the writer does not keep an earlier page alive.
pub struct Page {
    /// Records in this page, already in export order.
    pub records: Vec<ExportRecord>,
    on_drop: Option<Box<dyn FnOnce()>>,
}

impl Page {
    /// A page with no drop hook.
    pub fn from_records(records: Vec<ExportRecord>) -> Self {
        Self {
            records,
            on_drop: None,
        }
    }

    /// A page that runs `on_drop` when dropped.
    pub fn from_records_with_drop(records: Vec<ExportRecord>, on_drop: Box<dyn FnOnce()>) -> Self {
        Self {
            records,
            on_drop: Some(on_drop),
        }
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        if let Some(hook) = self.on_drop.take() {
            hook();
        }
    }
}

/// Yields pages. `None` means there are no further rows.
///
/// An empty `Some` page is not used. The writer drops each page before it
/// calls [`PageSource::next_page`] again.
pub trait PageSource {
    /// Next page, or `None` at the end.
    fn next_page(&mut self) -> Result<Option<Page>, ExportError>;
}

pub(crate) fn write_header<W: Write>(
    out: &mut W,
    session: &SessionHeader,
    gaps: &GapsSummary,
) -> Result<(), ExportError> {
    out.write_all(b"{\"type\":\"header\",\"export_version\":1,\"session\":")
        .map_err(|err| io_err("write_jsonl", err))?;
    write_session(out, session)?;
    out.write_all(b",\"collectors\":")
        .map_err(|err| io_err("write_jsonl", err))?;
    jsontext::write_embedded(out, "collectors", &session.collectors_json)?;
    out.write_all(b",\"gaps_summary\":")
        .map_err(|err| io_err("write_jsonl", err))?;
    write_gaps_summary(out, gaps)?;
    out.write_all(b"}\n")
        .map_err(|err| io_err("write_jsonl", err))?;
    Ok(())
}

fn write_session<W: Write>(out: &mut W, session: &SessionHeader) -> Result<(), ExportError> {
    let mut w = JsonWrite::new(out);
    w.begin_object()?;
    w.key("id")?;
    w.i64(session.id)?;
    w.key("public_id")?;
    w.string(&session.public_id)?;
    w.key("name")?;
    w.opt_string(session.name.as_deref())?;
    w.key("mode")?;
    w.string(&session.mode)?;
    w.key("agent")?;
    w.opt_string(session.agent.as_deref())?;
    w.key("started_ns")?;
    w.i64(session.started_ns)?;
    w.key("ended_ns")?;
    w.opt_i64(session.ended_ns)?;
    w.key("platform")?;
    w.string(&session.platform)?;
    w.key("user_id")?;
    w.string(&session.user_id)?;
    w.end_object()?;
    Ok(())
}

fn write_gaps_summary<W: Write>(out: &mut W, gaps: &GapsSummary) -> Result<(), ExportError> {
    let mut w = JsonWrite::new(out);
    w.begin_object()?;
    w.key("rows")?;
    w.i64(gaps.rows)?;
    w.key("unknown_count")?;
    w.i64(gaps.unknown_count)?;
    w.key("lost")?;
    w.opt_i64(gaps.lost)?;
    w.key("by_collector")?;
    w.begin_array()?;
    for item in &gaps.by_collector {
        w.begin_object()?;
        w.key("collector")?;
        w.string(&item.collector)?;
        w.key("rows")?;
        w.i64(item.rows)?;
        w.key("unknown_count")?;
        w.i64(item.unknown_count)?;
        w.key("lost")?;
        w.opt_i64(item.lost)?;
        w.end_object()?;
    }
    w.end_array()?;
    w.end_object()?;
    Ok(())
}

pub(crate) fn write_record<W: Write>(
    out: &mut W,
    record: &ExportRecord,
    redact: Redact,
) -> Result<(), ExportError> {
    match record {
        ExportRecord::Process(row) => write_process(out, row, redact),
        ExportRecord::Net(row) => write_net(out, row, redact),
        ExportRecord::Dns(row) => write_dns(out, row, redact),
        ExportRecord::Gap(row) => write_gap(out, row, redact),
    }
}

fn write_process<W: Write>(
    out: &mut W,
    row: &ProcessRecord,
    redact: Redact,
) -> Result<(), ExportError> {
    let mut w = JsonWrite::new(out);
    w.begin_object()?;
    w.key("type")?;
    w.string("processes")?;
    w.key("session_id")?;
    w.i64(row.session_id)?;
    w.key("proc_uid")?;
    w.i64(row.proc_uid)?;
    w.key("pid")?;
    w.i64(row.pid)?;
    w.key("parent_uid")?;
    w.opt_i64(row.parent_uid)?;
    w.key("ppid")?;
    w.opt_i64(row.ppid)?;
    w.key("depth")?;
    w.i64(row.depth)?;
    w.key("start_ns")?;
    w.i64(row.start_ns)?;
    w.key("exit_ns")?;
    w.opt_i64(row.exit_ns)?;
    w.key("exit_code")?;
    w.opt_i64(row.exit_code)?;
    w.key("exit_signal")?;
    w.opt_i64(row.exit_signal)?;
    w.key("how")?;
    w.string(&row.how)?;
    w.key("user_id")?;
    w.opt_string(row.user_id.as_deref())?;
    w.key("signer")?;
    w.opt_string(row.signer.as_deref())?;
    w.key("evidence")?;
    w.string(&row.evidence)?;
    w.key("field_evidence")?;
    write_json_column(
        &mut w,
        "field_evidence",
        row.field_evidence.as_deref(),
        redact,
    )?;
    w.key("source")?;
    w.string(&row.source)?;
    w.key("agent")?;
    w.opt_string(row.agent.as_deref())?;
    w.end_object()?;
    out.write_all(b"\n")
        .map_err(|err| io_err("write_jsonl", err))?;
    Ok(())
}

fn write_net<W: Write>(
    out: &mut W,
    row: &NetFlowRecord,
    redact: Redact,
) -> Result<(), ExportError> {
    let domain = redact_opt(row.domain.as_deref(), redact_host_field, redact.hosts);
    let sni = redact_opt(row.sni.as_deref(), redact_host_field, redact.hosts);
    let mut w = JsonWrite::new(out);
    w.begin_object()?;
    w.key("type")?;
    w.string("net_flows")?;
    w.key("id")?;
    w.i64(row.id)?;
    w.key("session_id")?;
    w.i64(row.session_id)?;
    w.key("proc_uid")?;
    w.i64(row.proc_uid)?;
    w.key("proto")?;
    w.string(&row.proto)?;
    w.key("direction")?;
    w.string(&row.direction)?;
    w.key("local_ip")?;
    w.string(&row.local_ip)?;
    w.key("local_port")?;
    w.i64(row.local_port)?;
    w.key("remote_ip")?;
    w.string(&row.remote_ip)?;
    w.key("remote_port")?;
    w.i64(row.remote_port)?;
    w.key("domain")?;
    w.opt_string(domain.as_deref())?;
    w.key("domain_source")?;
    w.opt_string(row.domain_source.as_deref())?;
    w.key("domain_alts")?;
    write_json_column(
        &mut w,
        "domain_alts",
        row.domain_alts.as_deref(),
        Redact::off(),
    )?;
    w.key("sni")?;
    w.opt_string(sni.as_deref())?;
    w.key("alpn")?;
    w.opt_string(row.alpn.as_deref())?;
    w.key("start_ns")?;
    w.i64(row.start_ns)?;
    w.key("end_ns")?;
    w.opt_i64(row.end_ns)?;
    w.key("bytes_up")?;
    w.opt_i64(row.bytes_up)?;
    w.key("bytes_down")?;
    w.opt_i64(row.bytes_down)?;
    w.key("via_proxy")?;
    w.i64(row.via_proxy)?;
    w.key("direct")?;
    w.i64(row.direct)?;
    w.key("preexisting")?;
    w.i64(row.preexisting)?;
    w.key("is_loopback")?;
    w.i64(row.is_loopback)?;
    w.key("result")?;
    w.opt_i64(row.result)?;
    w.key("platform_total_up")?;
    w.opt_i64(row.platform_total_up)?;
    w.key("platform_total_down")?;
    w.opt_i64(row.platform_total_down)?;
    w.key("evidence")?;
    w.string(&row.evidence)?;
    w.key("na_reason")?;
    w.opt_string(row.na_reason.as_deref())?;
    w.key("field_evidence")?;
    write_json_column(
        &mut w,
        "field_evidence",
        row.field_evidence.as_deref(),
        Redact::off(),
    )?;
    w.key("source")?;
    w.string(&row.source)?;
    w.end_object()?;
    out.write_all(b"\n")
        .map_err(|err| io_err("write_jsonl", err))?;
    Ok(())
}

fn write_dns<W: Write>(out: &mut W, row: &DnsRecord, redact: Redact) -> Result<(), ExportError> {
    let qname = if redact.hosts {
        redact_host_field(&row.qname)
    } else {
        row.qname.clone()
    };
    let server = redact_opt(row.server.as_deref(), redact_host_field, redact.hosts);
    let mut w = JsonWrite::new(out);
    w.begin_object()?;
    w.key("type")?;
    w.string("dns")?;
    w.key("id")?;
    w.i64(row.id)?;
    w.key("session_id")?;
    w.i64(row.session_id)?;
    w.key("proc_uid")?;
    w.opt_i64(row.proc_uid)?;
    w.key("ts_ns")?;
    w.i64(row.ts_ns)?;
    w.key("qname")?;
    w.string(&qname)?;
    w.key("qtype")?;
    w.i64(row.qtype)?;
    w.key("rcode")?;
    w.opt_i64(row.rcode)?;
    w.key("answers")?;
    write_json_column(&mut w, "answers", row.answers.as_deref(), Redact::off())?;
    w.key("ttl_min")?;
    w.opt_i64(row.ttl_min)?;
    w.key("server")?;
    w.opt_string(server.as_deref())?;
    w.key("evidence")?;
    w.string(&row.evidence)?;
    w.key("source")?;
    w.string(&row.source)?;
    w.end_object()?;
    out.write_all(b"\n")
        .map_err(|err| io_err("write_jsonl", err))?;
    Ok(())
}

fn write_gap<W: Write>(out: &mut W, row: &GapRecord, redact: Redact) -> Result<(), ExportError> {
    let detail = redact_detail(row.detail.as_deref(), redact);
    let mut w = JsonWrite::new(out);
    w.begin_object()?;
    w.key("type")?;
    w.string("gaps")?;
    w.key("id")?;
    w.i64(row.id)?;
    w.key("session_id")?;
    w.opt_i64(row.session_id)?;
    w.key("collector")?;
    w.string(&row.collector)?;
    w.key("kind")?;
    w.string(&row.kind)?;
    w.key("affects")?;
    write_json_column(&mut w, "affects", Some(&row.affects), Redact::off())?;
    w.key("from_ns")?;
    w.i64(row.from_ns)?;
    w.key("to_ns")?;
    w.i64(row.to_ns)?;
    w.key("count")?;
    w.opt_i64(row.count)?;
    w.key("detail")?;
    w.opt_string(detail.as_deref())?;
    w.key("evidence")?;
    w.string("E1")?;
    w.key("field_evidence")?;
    w.null()?;
    w.end_object()?;
    out.write_all(b"\n")
        .map_err(|err| io_err("write_jsonl", err))?;
    Ok(())
}

fn write_json_column<W: Write>(
    w: &mut JsonWrite<'_, W>,
    column: &'static str,
    value: Option<&str>,
    redact: Redact,
) -> Result<(), ExportError> {
    match value {
        None => w.null(),
        Some(text) => {
            let owned;
            let text = if redact.paths {
                owned = redact_user_paths(text);
                owned.as_str()
            } else {
                text
            };
            w.embed(column, text)
        }
    }
}

fn redact_opt(value: Option<&str>, map: fn(&str) -> String, enabled: bool) -> Option<String> {
    value.map(|text| if enabled { map(text) } else { text.to_string() })
}

fn redact_detail(value: Option<&str>, redact: Redact) -> Option<String> {
    value.map(|text| {
        let step = if redact.paths {
            redact_user_paths(text)
        } else {
            text.to_string()
        };
        if redact.hosts {
            redact_host_text(&step)
        } else {
            step
        }
    })
}

pub(crate) fn csv_header(table: CsvTable) -> &'static str {
    match table {
        CsvTable::Processes => {
            "session_id,proc_uid,pid,parent_uid,ppid,depth,start_ns,exit_ns,exit_code,exit_signal,how,user_id,signer,evidence,field_evidence,source,agent\n"
        }
        CsvTable::NetFlows => {
            "id,session_id,proc_uid,proto,direction,local_ip,local_port,remote_ip,remote_port,domain,domain_source,domain_alts,sni,alpn,start_ns,end_ns,bytes_up,bytes_down,via_proxy,direct,preexisting,is_loopback,result,platform_total_up,platform_total_down,evidence,na_reason,field_evidence,source\n"
        }
        CsvTable::Dns => {
            "id,session_id,proc_uid,ts_ns,qname,qtype,rcode,answers,ttl_min,server,evidence,source\n"
        }
        CsvTable::Gaps => {
            "id,session_id,collector,kind,affects,from_ns,to_ns,count,detail,evidence\n"
        }
    }
}

pub(crate) fn write_csv_row<W: Write>(
    out: &mut W,
    table: CsvTable,
    record: &ExportRecord,
    redact: Redact,
) -> Result<(), ExportError> {
    match (table, record) {
        (CsvTable::Processes, ExportRecord::Process(row)) => write_process_csv(out, row),
        (CsvTable::NetFlows, ExportRecord::Net(row)) => write_net_csv(out, row, redact),
        (CsvTable::Dns, ExportRecord::Dns(row)) => write_dns_csv(out, row, redact),
        (CsvTable::Gaps, ExportRecord::Gap(row)) => write_gap_csv(out, row, redact),
        _ => Err(ExportError::MissingRow {
            table: table.file_name(),
            id: 0,
        }),
    }
}

fn write_process_csv<W: Write>(out: &mut W, row: &ProcessRecord) -> Result<(), ExportError> {
    let mut csv = CsvRow::new(out);
    csv.i64(row.session_id)?;
    csv.i64(row.proc_uid)?;
    csv.i64(row.pid)?;
    csv.opt_i64(row.parent_uid)?;
    csv.opt_i64(row.ppid)?;
    csv.i64(row.depth)?;
    csv.i64(row.start_ns)?;
    csv.opt_i64(row.exit_ns)?;
    csv.opt_i64(row.exit_code)?;
    csv.opt_i64(row.exit_signal)?;
    csv.text(&row.how)?;
    csv.opt_text(row.user_id.as_deref())?;
    csv.opt_text(row.signer.as_deref())?;
    csv.text(&row.evidence)?;
    csv.opt_text(row.field_evidence.as_deref())?;
    csv.text(&row.source)?;
    csv.opt_text(row.agent.as_deref())?;
    csv.finish()
}

fn write_net_csv<W: Write>(
    out: &mut W,
    row: &NetFlowRecord,
    redact: Redact,
) -> Result<(), ExportError> {
    let domain = redact_opt(row.domain.as_deref(), redact_host_field, redact.hosts);
    let sni = redact_opt(row.sni.as_deref(), redact_host_field, redact.hosts);
    let mut csv = CsvRow::new(out);
    csv.i64(row.id)?;
    csv.i64(row.session_id)?;
    csv.i64(row.proc_uid)?;
    csv.text(&row.proto)?;
    csv.text(&row.direction)?;
    csv.text(&row.local_ip)?;
    csv.i64(row.local_port)?;
    csv.text(&row.remote_ip)?;
    csv.i64(row.remote_port)?;
    csv.opt_text(domain.as_deref())?;
    csv.opt_text(row.domain_source.as_deref())?;
    csv.opt_text(row.domain_alts.as_deref())?;
    csv.opt_text(sni.as_deref())?;
    csv.opt_text(row.alpn.as_deref())?;
    csv.i64(row.start_ns)?;
    csv.opt_i64(row.end_ns)?;
    csv.opt_i64(row.bytes_up)?;
    csv.opt_i64(row.bytes_down)?;
    csv.i64(row.via_proxy)?;
    csv.i64(row.direct)?;
    csv.i64(row.preexisting)?;
    csv.i64(row.is_loopback)?;
    csv.opt_i64(row.result)?;
    csv.opt_i64(row.platform_total_up)?;
    csv.opt_i64(row.platform_total_down)?;
    csv.text(&row.evidence)?;
    csv.opt_text(row.na_reason.as_deref())?;
    csv.opt_text(row.field_evidence.as_deref())?;
    csv.text(&row.source)?;
    csv.finish()
}

fn write_dns_csv<W: Write>(
    out: &mut W,
    row: &DnsRecord,
    redact: Redact,
) -> Result<(), ExportError> {
    let qname = if redact.hosts {
        redact_host_field(&row.qname)
    } else {
        row.qname.clone()
    };
    let server = redact_opt(row.server.as_deref(), redact_host_field, redact.hosts);
    let mut csv = CsvRow::new(out);
    csv.i64(row.id)?;
    csv.i64(row.session_id)?;
    csv.opt_i64(row.proc_uid)?;
    csv.i64(row.ts_ns)?;
    csv.text(&qname)?;
    csv.i64(row.qtype)?;
    csv.opt_i64(row.rcode)?;
    csv.opt_text(row.answers.as_deref())?;
    csv.opt_i64(row.ttl_min)?;
    csv.opt_text(server.as_deref())?;
    csv.text(&row.evidence)?;
    csv.text(&row.source)?;
    csv.finish()
}

fn write_gap_csv<W: Write>(
    out: &mut W,
    row: &GapRecord,
    redact: Redact,
) -> Result<(), ExportError> {
    let detail = redact_detail(row.detail.as_deref(), redact);
    let mut csv = CsvRow::new(out);
    csv.i64(row.id)?;
    csv.opt_i64(row.session_id)?;
    csv.text(&row.collector)?;
    csv.text(&row.kind)?;
    csv.text(&row.affects)?;
    csv.i64(row.from_ns)?;
    csv.i64(row.to_ns)?;
    csv.opt_i64(row.count)?;
    csv.opt_text(detail.as_deref())?;
    csv.text("E1")?;
    csv.finish()
}

struct CsvRow<'a, W> {
    out: &'a mut W,
    first: bool,
}

impl<'a, W: Write> CsvRow<'a, W> {
    fn new(out: &'a mut W) -> Self {
        Self { out, first: true }
    }

    fn comma(&mut self) -> Result<(), ExportError> {
        if self.first {
            self.first = false;
            return Ok(());
        }
        self.out
            .write_all(b",")
            .map_err(|err| io_err("write_csv", err))
    }

    fn i64(&mut self, value: i64) -> Result<(), ExportError> {
        self.comma()?;
        write!(self.out, "{value}").map_err(|err| io_err("write_csv", err))
    }

    fn opt_i64(&mut self, value: Option<i64>) -> Result<(), ExportError> {
        self.comma()?;
        match value {
            Some(value) => write!(self.out, "{value}").map_err(|err| io_err("write_csv", err)),
            None => Ok(()),
        }
    }

    fn text(&mut self, value: &str) -> Result<(), ExportError> {
        self.comma()?;
        write_csv_text(self.out, value)
    }

    fn opt_text(&mut self, value: Option<&str>) -> Result<(), ExportError> {
        self.comma()?;
        match value {
            Some(value) => write_csv_text(self.out, value),
            None => Ok(()),
        }
    }

    fn finish(self) -> Result<(), ExportError> {
        self.out
            .write_all(b"\n")
            .map_err(|err| io_err("write_csv", err))
    }
}

/// Quoted CSV field. NULL is not passed here: the caller writes nothing between
/// commas, so an empty unquoted field stays distinct from `""`.
fn write_csv_text<W: Write>(out: &mut W, value: &str) -> Result<(), ExportError> {
    out.write_all(b"\"")
        .map_err(|err| io_err("write_csv", err))?;
    let mut start = 0;
    for (idx, ch) in value.char_indices() {
        if ch == '"' {
            out.write_all(&value.as_bytes()[start..idx])
                .map_err(|err| io_err("write_csv", err))?;
            out.write_all(b"\"\"")
                .map_err(|err| io_err("write_csv", err))?;
            start = idx + 1;
        }
    }
    out.write_all(&value.as_bytes()[start..])
        .map_err(|err| io_err("write_csv", err))?;
    out.write_all(b"\"")
        .map_err(|err| io_err("write_csv", err))?;
    Ok(())
}

pub(crate) const README: &str = "\
AgentWatch session export (P1 CSV)\n\
\n\
Files: processes.csv, net_flows.csv, dns.csv, gaps.csv.\n\
process_images is not included. exe and argv are not in processes.csv.\n\
\n\
Time columns (*_ns) are Unix epoch nanoseconds.\n\
\n\
Byte columns bytes_up, bytes_down, platform_total_up, and platform_total_down\n\
count octets. An empty unquoted field means SQL NULL: the count was not\n\
observed. It does not mean zero octets. A quoted empty field (\"\") is an\n\
empty string, which these columns do not use.\n\
\n\
gaps.evidence is the literal E1. The gaps table has no evidence column;\n\
the timeline view uses the same literal. field_evidence is not a gaps column\n\
and is absent here. In JSONL it is null.\n\
\n\
gaps.count empty means the lost-event count is unknown, not zero.\n\
\n\
--redact-paths replaces the user-name segment of /Users/<name>, /home/<name>,\n\
and <drive>:\\Users\\<name> with the fixed token <user>.\n\
--redact-hosts replaces a hostname-shaped label with the fixed token <host>.\n\
Public multi-label names such as example.com are left unchanged.\n\
Neither flag is the later redaction module.\n\
";
