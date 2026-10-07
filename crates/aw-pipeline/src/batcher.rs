//! Batch writer. Flushes on row count or on the monotonic clock, whichever first.
//!
//! pipeline.md §3.7: a batch goes out at `store.batch_max_rows` (default 1000)
//! or `store.batch_max_ms` (default 100), through [`aw_store::RecordSink`].
//! Process rows are placed in the batch before flow rows. The trait writes them
//! in that order.
//!
//! [`crate::output`] records are not store rows. [`rows_from`] converts them.
//! `None` stays absent. It is not written as `0` or `""`.
//!
//! `processes.depth` is `NOT NULL`. A [`ProcessRec`] whose `depth` is `None`
//! is skipped and counted: passing `0` would claim the process is the session
//! root. The skip becomes a [`GapKind::Unknown`] gap with detail
//! [`crate::gaps::DEPTH_UNOBSERVED_DETAIL`]. The row is not invented.
//!
//! A failed [`aw_store::RecordSink::write_batch`] keeps the batch. Up to
//! [`crate::gaps::DEFAULT_RETRY_BATCHES`] failed batches stay in memory and are
//! retried on the next flush. Past that cap the oldest batch is dropped and one
//! gap is emitted. `aw_core::GapKind` has no `store_failure` variant, so the
//! gap is [`GapKind::Unknown`] with detail [`crate::gaps::STORE_FAILURE_DETAIL`].
//!
//! The clock is [`crate::stage::Stage::tick`]'s `now_ns` and each record's own
//! monotonic timestamp. This module does not read the host clock.

use aw_core::{Evidence, GapKind, ProcUid, SessionId};
use aw_store::{
    DnsRow, GapRow, NetFlowBucketRow, NetFlowRow, ProcessRow, RecordSink, StoreError, WriteBatch,
};

use crate::config::StoreConfig;
use crate::gaps::{self, GapMerger, DEFAULT_RETRY_BATCHES, PIPELINE_COLLECTOR};
use crate::output::{DnsRec, FlowBucketRec, GapRec, NetFlowRec, Output, ProcessRec};

/// Owns the open batch, the retry queue, and the gap merger.
pub struct Batcher<S> {
    sink: S,
    cfg: StoreConfig,
    /// Failed batches kept for retry. Oldest first. Capped at `retry_limit`.
    retry: Vec<WriteBatch>,
    retry_limit: usize,
    open: WriteBatch,
    open_rows: u64,
    /// Monotonic time of the first row in `open`. `None` when `open` is empty.
    open_since_ns: Option<u64>,
    gaps: GapMerger,
    /// Rows in batches dropped past the retry cap, not yet written as a gap.
    /// One number, not one gap per batch: a long outage must not grow a second
    /// queue. The next successful flush writes a single gap with this count.
    pending_store_failure_rows: u64,
    /// Process rows skipped because `depth` was `None`, not yet flushed as a gap.
    depth_skipped: u64,
    depth_from_ns: Option<u64>,
    depth_to_ns: Option<u64>,
}

impl<S> Batcher<S> {
    /// `retry_limit` is how many failed batches stay in memory. `0` drops a
    /// failed batch on the next failed flush (the cap is already exceeded).
    pub fn new(sink: S, cfg: StoreConfig, retry_limit: usize) -> Self {
        Self {
            sink,
            cfg,
            retry: Vec::new(),
            retry_limit,
            open: WriteBatch::default(),
            open_rows: 0,
            open_since_ns: None,
            gaps: GapMerger::new(),
            pending_store_failure_rows: 0,
            depth_skipped: 0,
            depth_from_ns: None,
            depth_to_ns: None,
        }
    }

    /// Same as [`Self::new`] with [`DEFAULT_RETRY_BATCHES`] (4).
    pub fn with_defaults(sink: S, cfg: StoreConfig) -> Self {
        Self::new(sink, cfg, DEFAULT_RETRY_BATCHES)
    }

    /// How many batches are waiting for a successful write.
    pub fn pending_batches(&self) -> usize {
        self.retry.len()
    }

    /// Rows sitting in the open batch, not yet handed to the sink.
    pub fn open_rows(&self) -> u64 {
        self.open_rows
    }
}

impl<S: RecordSink> Batcher<S> {
    /// Append records. Flushes when the open batch reaches `batch_max_rows`.
    ///
    /// `now_ns` is the pipeline clock. A record with no timestamp of its own
    /// uses it for the batch-age check.
    pub fn push_output(&mut self, out: &Output, now_ns: u64) -> Vec<GapRec> {
        self.ingest(out, now_ns);
        let mut emitted = Vec::new();
        if self.should_flush_rows() {
            emitted.extend(self.flush(now_ns));
        }
        emitted
    }

    /// Convert `out` into the open batch. Does not flush.
    pub fn ingest(&mut self, out: &Output, now_ns: u64) {
        for gap in &out.gaps {
            if let Some(closed) = self.gaps.observe(gap.clone()) {
                self.enqueue_gap(&closed, now_ns);
            }
        }
        for proc in &out.processes {
            match process_row(proc) {
                Some(row) => self.push_process(row, proc.start_ns),
                None => self.note_skipped_depth(proc.start_ns),
            }
        }
        for flow in &out.net_flows {
            if let Some(row) = flow_row(flow) {
                self.push_flow(row, flow.start_ns);
            }
        }
        for bucket in &out.flow_buckets {
            if let Some(row) = bucket_row(bucket) {
                self.push_bucket(row, bucket.bucket_ns);
            }
        }
        for dns in &out.dns {
            // `dns.session_id` is NOT NULL. No session means no row, not session 0.
            if let Some(row) = dns_row(dns) {
                self.push_dns(row, dns.ts_ns);
            }
        }
    }

    /// Time-based flush. Uses `now_ns`, not the host clock.
    ///
    /// Also closes gap-merge buckets whose window has ended relative to `now_ns`.
    pub fn tick(&mut self, now_ns: u64) -> Vec<GapRec> {
        let mut emitted = Vec::new();
        if self.should_flush_time(now_ns) || self.should_flush_rows() {
            emitted.extend(self.flush(now_ns));
        }
        emitted
    }

    /// Write the open batch and anything still queued. Returns gaps this flush
    /// created (a dropped batch, a skipped depth). Also returns merged gaps
    /// that were closed by being written — those are inside the batch, not in
    /// the returned vec, unless the write itself was dropped.
    pub fn flush(&mut self, now_ns: u64) -> Vec<GapRec> {
        self.enqueue_depth_gap(now_ns);
        // Close merge windows so a gap that has been open is actually written.
        for gap in self.gaps.flush() {
            self.enqueue_gap(&gap, now_ns);
        }
        if self.open_rows > 0 {
            let batch = std::mem::take(&mut self.open);
            self.open_rows = 0;
            self.open_since_ns = None;
            self.retry.push(batch);
        }
        let mut dropped_gaps = Vec::new();
        while self.retry.len() > self.retry_limit {
            let dropped = self.retry.remove(0);
            let rows = dropped_rows(&dropped);
            dropped_gaps.push(self.store_failure_gap(now_ns, rows));
            self.pending_store_failure_rows = self.pending_store_failure_rows.saturating_add(rows);
        }
        self.write_retry(now_ns);
        // The failure gap is written only after a write succeeds. Putting it
        // into `retry` while the sink is down would either exceed the cap again
        // or be dropped on the next flush. One gap is reported to the caller
        // per dropped batch; the stored copy waits for a successful flush.
        if self.retry.is_empty() {
            self.enqueue_pending_store_failures(now_ns);
            if self.open_rows > 0 {
                let batch = std::mem::take(&mut self.open);
                self.open_rows = 0;
                self.open_since_ns = None;
                if self.sink.write_batch(&batch).is_err() {
                    // The sink died between the data write and the gap write.
                    // Keep the gap batch inside the cap. It is one batch of
                    // gaps, not the dropped data.
                    if self.retry.len() < self.retry_limit {
                        self.retry.push(batch);
                    }
                }
            }
        }
        dropped_gaps
    }

    fn enqueue_pending_store_failures(&mut self, now_ns: u64) {
        if self.pending_store_failure_rows == 0 {
            return;
        }
        let gap = self.store_failure_gap(now_ns, self.pending_store_failure_rows);
        self.pending_store_failure_rows = 0;
        self.enqueue_gap(&gap, now_ns);
    }

    /// Force the open batch out, then retry. Used when the stage is dropped
    /// from a test. Same path as [`Self::flush`].
    pub fn flush_all(&mut self, now_ns: u64) -> Vec<GapRec> {
        self.flush(now_ns)
    }

    fn write_retry(&mut self, now_ns: u64) {
        let mut still = Vec::new();
        for batch in std::mem::take(&mut self.retry) {
            match self.sink.write_batch(&batch) {
                Ok(()) => {}
                Err(_err) => {
                    // The error text can name a path. It is not copied into a
                    // gap. The detail is the fixed string `store_failure`.
                    let _ = now_ns;
                    still.push(batch);
                }
            }
        }
        self.retry = still;
    }

    fn enqueue_gap(&mut self, gap: &GapRec, now_ns: u64) {
        let row = gap_row(gap);
        self.note_time(now_ns);
        self.open.gaps.push(row);
        self.open_rows = self.open_rows.saturating_add(1);
    }

    fn enqueue_depth_gap(&mut self, now_ns: u64) {
        if self.depth_skipped == 0 {
            return;
        }
        let from = self.depth_from_ns.unwrap_or(now_ns);
        let to = self.depth_to_ns.unwrap_or(now_ns);
        let gap = gaps::make_gap(
            PIPELINE_COLLECTOR,
            GapKind::Unknown,
            vec!["process".to_owned()],
            from,
            to,
            Some(self.depth_skipped),
            Some(gaps::DEPTH_UNOBSERVED_DETAIL.to_owned()),
            Evidence::E1,
        );
        self.depth_skipped = 0;
        self.depth_from_ns = None;
        self.depth_to_ns = None;
        if let Some(closed) = self.gaps.observe(gap) {
            self.enqueue_gap(&closed, now_ns);
        }
    }

    fn note_skipped_depth(&mut self, ts_ns: u64) {
        self.depth_skipped = self.depth_skipped.saturating_add(1);
        self.depth_from_ns = Some(self.depth_from_ns.map_or(ts_ns, |have| have.min(ts_ns)));
        self.depth_to_ns = Some(self.depth_to_ns.map_or(ts_ns, |have| have.max(ts_ns)));
    }

    fn push_process(&mut self, row: ProcessRow, ts_ns: u64) {
        self.note_time(ts_ns);
        self.open.processes.push(row);
        self.open_rows = self.open_rows.saturating_add(1);
    }

    fn push_flow(&mut self, row: NetFlowRow, ts_ns: u64) {
        self.note_time(ts_ns);
        self.open.net_flows.push(row);
        self.open_rows = self.open_rows.saturating_add(1);
    }

    fn push_bucket(&mut self, row: NetFlowBucketRow, ts_ns: u64) {
        self.note_time(ts_ns);
        self.open.net_flow_buckets.push(row);
        self.open_rows = self.open_rows.saturating_add(1);
    }

    fn push_dns(&mut self, row: DnsRow, ts_ns: u64) {
        self.note_time(ts_ns);
        self.open.dns.push(row);
        self.open_rows = self.open_rows.saturating_add(1);
    }

    fn note_time(&mut self, ts_ns: u64) {
        if self.open_since_ns.is_none() {
            self.open_since_ns = Some(ts_ns);
        }
    }

    fn should_flush_rows(&self) -> bool {
        let cap = self.cfg.batch_max_rows;
        cap > 0 && self.open_rows >= cap
    }

    fn should_flush_time(&self, now_ns: u64) -> bool {
        let Some(since) = self.open_since_ns else {
            return false;
        };
        let max_ms = self.cfg.batch_max_ms;
        if max_ms == 0 {
            return self.open_rows > 0;
        }
        let max_ns = max_ms.saturating_mul(1_000_000);
        now_ns.saturating_sub(since) >= max_ns
    }

    fn store_failure_gap(&self, now_ns: u64, rows: u64) -> GapRec {
        // GapKind has no store_failure. Unknown + the literal detail is the
        // stand-in. See gaps::STORE_FAILURE_DETAIL.
        gaps::make_gap(
            PIPELINE_COLLECTOR,
            GapKind::Unknown,
            vec!["store".to_owned()],
            now_ns,
            now_ns,
            Some(rows),
            Some(gaps::STORE_FAILURE_DETAIL.to_owned()),
            Evidence::E1,
        )
    }
}

fn dropped_rows(batch: &WriteBatch) -> u64 {
    let n = batch.sessions.len()
        + batch.processes.len()
        + batch.process_images.len()
        + batch.net_flows.len()
        + batch.net_flow_buckets.len()
        + batch.dns.len()
        + batch.gaps.len();
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// `None` when `depth` was not observed. The caller counts that skip.
fn process_row(proc: &ProcessRec) -> Option<ProcessRow> {
    let depth = proc.depth?;
    let session_id = match proc.session_id {
        Some(SessionId(id)) => i64::try_from(id).ok()?,
        // The DDL requires a session. An unscoped process is not a row.
        None => return None,
    };
    Some(ProcessRow {
        session_id,
        proc_uid: uid_bits(proc.proc_uid),
        pid: i64::from(proc.pid),
        parent_uid: proc.parent_uid.map(uid_bits),
        ppid: proc.ppid.map(i64::from),
        depth: i64::from(depth),
        start_ns: i64::try_from(proc.start_ns).unwrap_or(i64::MAX),
        exit_ns: proc.exit_ns.and_then(|ns| i64::try_from(ns).ok()),
        exit_code: proc.exit_code.map(i64::from),
        exit_signal: proc.exit_signal.map(i64::from),
        how: start_how_name(proc.how).to_owned(),
        user_id: proc.user_id.clone(),
        signer: proc.signer.clone(),
        evidence: gaps::evidence_code(&proc.evidence).to_owned(),
        field_evidence: field_evidence_json(&proc.field_evidence),
        source: proc.source.as_str().to_owned(),
        agent: proc.agent.clone(),
    })
}

fn flow_row(flow: &NetFlowRec) -> Option<NetFlowRow> {
    // Required by the DDL. Unknown stays out of the row rather than becoming "".
    let proto = flow.proto.clone()?;
    let direction = flow.direction.clone()?;
    let local_ip = flow.local_ip.clone()?;
    let local_port = flow.local_port?;
    let remote_ip = flow.remote_ip.clone()?;
    let remote_port = flow.remote_port?;
    let session_id = session_i64(flow.session_id)?;
    let proc_uid = flow.proc_uid.map(uid_bits)?;
    Some(NetFlowRow {
        // The in-memory record has no flow id yet. A stable id is the later
        // aggregate stage's job. This conversion uses a hash of the tuple so
        // two identical observations upsert together, and does not invent a
        // counter that would collide with a real id space. Callers that already
        // know an id should not come through this path twice with different
        // tuples. The hash is xxh-free: a simple mix, documented as not a
        // database identity.
        id: flow_id(flow),
        session_id,
        proc_uid,
        proto,
        direction,
        local_ip,
        local_port: i64::from(local_port),
        remote_ip,
        remote_port: i64::from(remote_port),
        domain: flow.domain.clone(),
        domain_source: flow.domain_source.clone(),
        domain_alts: None,
        sni: flow.sni.clone(),
        alpn: None,
        start_ns: i64::try_from(flow.start_ns).unwrap_or(i64::MAX),
        end_ns: flow.end_ns.and_then(|ns| i64::try_from(ns).ok()),
        bytes_up: flow.bytes_up.and_then(|n| i64::try_from(n).ok()),
        bytes_down: flow.bytes_down.and_then(|n| i64::try_from(n).ok()),
        via_proxy: 0,
        direct: 0,
        preexisting: 0,
        is_loopback: 0,
        result: None,
        platform_total_up: None,
        platform_total_down: None,
        evidence: gaps::evidence_code(&flow.evidence).to_owned(),
        na_reason: gaps::na_reason_code(&flow.evidence).map(str::to_owned),
        field_evidence: None,
        source: flow.source.as_str().to_owned(),
    })
}

fn bucket_row(bucket: &FlowBucketRec) -> Option<NetFlowBucketRow> {
    // Both byte columns are accumulators (`NOT NULL`). A bucket that did not
    // measure a direction contributes 0 to that side only when the other side
    // was measured. If neither side was measured there is nothing to add.
    // The DDL says both columns are `NOT NULL` accumulators. A direction that
    // was not measured adds nothing (0) only when the other direction was.
    // Neither direction measured: no row, rather than a zero bucket.
    let (bytes_up, bytes_down) = match (bucket.bytes_up, bucket.bytes_down) {
        (None, None) => return None,
        (Some(up), Some(down)) => (up, down),
        (Some(up), None) => (up, 0),
        (None, Some(down)) => (0, down),
    };
    let flow_id = bucket.flow_id.and_then(|id| i64::try_from(id).ok())?;
    let session_id = session_i64(bucket.session_id)?;
    Some(NetFlowBucketRow {
        flow_id,
        session_id,
        bucket_ns: i64::try_from(bucket.bucket_ns).unwrap_or(i64::MAX),
        bytes_up: i64::try_from(bytes_up).unwrap_or(i64::MAX),
        bytes_down: i64::try_from(bytes_down).unwrap_or(i64::MAX),
        evidence: gaps::evidence_code(&bucket.evidence).to_owned(),
    })
}

fn dns_row(dns: &DnsRec) -> Option<DnsRow> {
    let answers = if dns.answers.is_empty() {
        // An empty answer list is an observation of no answers, not unknown.
        Some("[]".to_owned())
    } else {
        Some(json_string_array(&dns.answers))
    };
    Some(DnsRow {
        id: None,
        session_id: session_i64(dns.session_id)?,
        proc_uid: dns.proc_uid.map(uid_bits),
        ts_ns: i64::try_from(dns.ts_ns).unwrap_or(i64::MAX),
        qname: dns.qname.clone(),
        qtype: i64::from(dns.qtype),
        rcode: dns.rcode.map(i64::from),
        answers,
        ttl_min: dns.ttl_min.map(i64::from),
        server: dns.server.clone(),
        evidence: gaps::evidence_code(&dns.evidence).to_owned(),
        source: dns.source.as_str().to_owned(),
    })
}

fn gap_row(gap: &GapRec) -> GapRow {
    GapRow {
        id: None,
        session_id: gap
            .session_id
            .and_then(|SessionId(id)| i64::try_from(id).ok()),
        collector: gap.collector.as_str().to_owned(),
        kind: gaps::gap_kind_name(gap.gap_kind).to_owned(),
        affects: json_string_array(&gap.affects),
        from_ns: i64::try_from(gap.from_mono_ns).unwrap_or(i64::MAX),
        to_ns: i64::try_from(gap.to_mono_ns).unwrap_or(i64::MAX),
        count: gap.count.and_then(|n| i64::try_from(n).ok()),
        detail: gap.detail.clone(),
    }
}

fn session_i64(id: Option<SessionId>) -> Option<i64> {
    id.and_then(|SessionId(v)| i64::try_from(v).ok())
}

/// Bit-cast. The store documents `ProcUid` as a signed integer with the same bits.
fn uid_bits(uid: ProcUid) -> i64 {
    i64::from_ne_bytes(uid.0.to_ne_bytes())
}

fn start_how_name(how: aw_core::StartHow) -> &'static str {
    match how {
        aw_core::StartHow::Fork => "fork",
        aw_core::StartHow::Exec => "exec",
        aw_core::StartHow::Spawn => "spawn",
        aw_core::StartHow::Snapshot => "snapshot",
        aw_core::StartHow::Unknown => "unknown",
    }
}

fn field_evidence_json(map: &std::collections::BTreeMap<String, Evidence>) -> Option<String> {
    if map.is_empty() {
        return None;
    }
    let mut parts = Vec::with_capacity(map.len());
    for (key, evidence) in map {
        let code = gaps::evidence_code(evidence);
        parts.push(format!("{}:{}", json_string(key), json_string(code)));
    }
    Some(format!("{{{}}}", parts.join(",")))
}

fn json_string_array(items: &[String]) -> String {
    let body = items
        .iter()
        .map(|item| json_string(item))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Mix the tuple into an i64. Not a stored identity from the aggregate stage.
/// Negative ids are fine: SQLite `INTEGER` is signed.
fn flow_id(flow: &NetFlowRec) -> i64 {
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    fn mix(acc: &mut u64, bytes: &[u8]) {
        for byte in bytes {
            *acc = acc
                .wrapping_mul(0x100_0000_01b3)
                .wrapping_add(u64::from(*byte));
        }
    }
    mix(&mut acc, flow.proto.as_deref().unwrap_or("").as_bytes());
    mix(&mut acc, flow.local_ip.as_deref().unwrap_or("").as_bytes());
    mix(&mut acc, &flow.local_port.unwrap_or(0).to_le_bytes());
    mix(&mut acc, flow.remote_ip.as_deref().unwrap_or("").as_bytes());
    mix(&mut acc, &flow.remote_port.unwrap_or(0).to_le_bytes());
    if let Some(ProcUid(uid)) = flow.proc_uid {
        mix(&mut acc, &uid.to_le_bytes());
    }
    i64::from_ne_bytes(acc.to_ne_bytes())
}

/// A sink that fails `fail_times` calls, then succeeds and keeps the batches.
///
/// Not `Debug`: [`WriteBatch`] is deliberately not `Debug` (it can hold argv).
pub struct ScriptedSink {
    /// Remaining failures. Each `write_batch` consumes one.
    pub fail_times: u32,
    /// Batches that committed.
    pub committed: Vec<WriteBatch>,
}

impl ScriptedSink {
    /// Fails the next `fail_times` writes, then accepts.
    pub fn failing(fail_times: u32) -> Self {
        Self {
            fail_times,
            committed: Vec::new(),
        }
    }
}

/// Owns a sink the stage can swap. The trait object itself cannot implement
/// [`RecordSink`] from this crate (orphan rule), so the stage stores this.
pub struct DynSink {
    inner: Box<dyn RecordSink + Send>,
}

impl DynSink {
    /// Box `sink` for [`crate::stage::BatcherStage::set_sink`].
    pub fn new(sink: Box<dyn RecordSink + Send>) -> Self {
        Self { inner: sink }
    }
}

impl RecordSink for DynSink {
    fn write_batch(&mut self, batch: &WriteBatch) -> Result<(), StoreError> {
        self.inner.write_batch(batch)
    }
}

impl RecordSink for ScriptedSink {
    fn write_batch(&mut self, batch: &WriteBatch) -> Result<(), StoreError> {
        if self.fail_times > 0 {
            self.fail_times -= 1;
            return Err(StoreError::ReadOnly);
        }
        self.committed.push(batch.clone());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]
mod tests {
    use super::*;
    use crate::config::PipelineConfig;
    use crate::output::Output;
    use aw_core::{Evidence, GapKind, ProcUid, Source, StartHow};

    fn cfg_rows(rows: u64, ms: u64) -> StoreConfig {
        StoreConfig {
            batch_max_rows: rows,
            batch_max_ms: ms,
        }
    }

    fn process(depth: Option<u32>, start_ns: u64) -> ProcessRec {
        ProcessRec {
            session_id: Some(SessionId(1)),
            proc_uid: ProcUid(9),
            pid: 42,
            parent_uid: None,
            ppid: None,
            depth,
            start_ns,
            exit_ns: None,
            exit_code: None,
            exit_signal: None,
            how: StartHow::Spawn,
            user_id: None,
            signer: None,
            evidence: Evidence::E1,
            field_evidence: std::collections::BTreeMap::new(),
            source: Source::new("test/proc"),
            agent: None,
        }
    }

    fn out_with_processes(n: u64, depth: Option<u32>) -> Output {
        let mut out = Output::empty();
        for i in 0..n {
            let mut row = process(depth, i);
            row.proc_uid = ProcUid(i);
            row.pid = u32::try_from(i).unwrap_or(u32::MAX);
            out.processes.push(row);
        }
        out
    }

    #[test]
    fn flushes_on_row_count_before_time() {
        let mut batcher = Batcher::with_defaults(ScriptedSink::failing(0), cfg_rows(3, 100));
        let gaps = batcher.push_output(&out_with_processes(3, Some(1)), 0);
        assert!(gaps.is_empty());
        assert_eq!(batcher.sink.committed.len(), 1);
        assert_eq!(batcher.sink.committed[0].processes.len(), 3);
        assert_eq!(batcher.open_rows(), 0);
    }

    #[test]
    fn flushes_on_monotonic_age_not_the_host_clock() {
        let mut batcher = Batcher::with_defaults(ScriptedSink::failing(0), cfg_rows(1000, 100));
        batcher.push_output(&out_with_processes(1, Some(1)), 0);
        assert!(batcher.sink.committed.is_empty());
        // 100 ms later on the event clock.
        batcher.tick(100_000_000);
        assert_eq!(batcher.sink.committed.len(), 1);
        assert_eq!(batcher.sink.committed[0].processes.len(), 1);
    }

    #[test]
    fn missing_depth_is_skipped_and_counted() {
        let mut batcher = Batcher::with_defaults(ScriptedSink::failing(0), cfg_rows(1000, 100));
        batcher.push_output(&out_with_processes(2, None), 10);
        batcher.flush(10);
        let committed = &batcher.sink.committed;
        assert_eq!(committed.len(), 1);
        assert!(
            committed[0].processes.is_empty(),
            "a missing depth is not stored as 0"
        );
        let gaps = &committed[0].gaps;
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].kind, "unknown");
        assert_eq!(
            gaps[0].detail.as_deref(),
            Some(gaps::DEPTH_UNOBSERVED_DETAIL)
        );
        assert_eq!(gaps[0].count, Some(2));
    }

    #[test]
    fn none_bytes_stay_absent_on_a_flow() {
        let mut out = Output::empty();
        out.net_flows.push(NetFlowRec {
            session_id: Some(SessionId(1)),
            proc_uid: Some(ProcUid(3)),
            proto: Some("tcp".to_owned()),
            direction: Some("outbound".to_owned()),
            local_ip: Some("127.0.0.1".to_owned()),
            local_port: Some(1),
            remote_ip: Some("127.0.0.1".to_owned()),
            remote_port: Some(9),
            domain: None,
            domain_source: None,
            sni: None,
            bytes_up: None,
            bytes_down: None,
            start_ns: 5,
            end_ns: None,
            evidence: Evidence::S,
            source: Source::new("poll/net"),
        });
        let mut batcher = Batcher::with_defaults(ScriptedSink::failing(0), cfg_rows(10, 100));
        batcher.push_output(&out, 5);
        batcher.flush(5);
        let row = &batcher.sink.committed[0].net_flows[0];
        assert_eq!(row.bytes_up, None);
        assert_eq!(row.bytes_down, None);
        assert_eq!(row.domain, None);
        assert_eq!(row.evidence, "S");
    }

    #[test]
    fn write_errors_retry_then_one_store_failure_gap() {
        // retry_limit = 2. Three flushes each fail. The oldest batch is dropped
        // once the queue would exceed 2, and that drop is one gap.
        let mut batcher = Batcher::new(ScriptedSink::failing(100), cfg_rows(1, 100), 2);
        let mut failure_gaps = Vec::new();
        for i in 0..3 {
            let pushed = batcher.push_output(&out_with_processes(1, Some(1)), i);
            failure_gaps.extend(pushed);
        }
        let store_failures: Vec<_> = failure_gaps
            .iter()
            .filter(|gap| gap.detail.as_deref() == Some(gaps::STORE_FAILURE_DETAIL))
            .collect();
        assert_eq!(
            store_failures.len(),
            1,
            "one drop past the cap, not one per retry"
        );
        assert_eq!(store_failures[0].gap_kind, GapKind::Unknown);
        assert_eq!(store_failures[0].detail.as_deref(), Some("store_failure"));
        assert!(batcher.sink.committed.is_empty(), "every write failed");
        assert!(batcher.pending_batches() <= 2);
    }

    #[test]
    fn a_sink_that_recovers_commits_the_retried_batch() {
        let mut batcher = Batcher::new(ScriptedSink::failing(1), cfg_rows(1, 100), 4);
        let first = batcher.push_output(&out_with_processes(1, Some(2)), 0);
        assert!(first.is_empty(), "one failure is inside the cap");
        assert!(batcher.sink.committed.is_empty());
        assert_eq!(batcher.pending_batches(), 1);
        // Next flush retries. fail_times is now 0, so the write lands.
        batcher.flush(1);
        assert_eq!(batcher.sink.committed.len(), 1);
        assert_eq!(batcher.sink.committed[0].processes.len(), 1);
        assert_eq!(batcher.sink.committed[0].processes[0].depth, 2);
        assert_eq!(batcher.pending_batches(), 0);
    }

    #[test]
    fn default_store_bounds_match_the_config() {
        let cfg = PipelineConfig::default();
        assert_eq!(cfg.store.batch_max_rows, 1000);
        assert_eq!(cfg.store.batch_max_ms, 100);
        assert_eq!(DEFAULT_RETRY_BATCHES, 4);
    }
}
