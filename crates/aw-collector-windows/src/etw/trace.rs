//! Open, filter, and stop one real-time ETW session.
//!
//! ferrisetw drives `StartTrace` / `EnableTraceEx2` / `OpenTrace`. This module
//! adds the three things ferrisetw does not: stopping a leftover session of the
//! same name first, dropping out-of-scope events before any property parse, and
//! polling `EventsLost` without blocking the callback.
//!
//! The callback does two things and returns. It reads the header PID, and on a
//! hit it `try_send`s the header fields into a bounded channel. It never parses
//! properties, never allocates for a rejected PID, and never blocks. A full or
//! disconnected channel is counted; the event is not retried inside the callback
//! because retrying would stall ETW's buffer.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceProperties, UserTrace};
use ferrisetw::EventRecord;

use super::ffi::{self, from_trace_error};
use super::session::{
    self, EtwClockMode, EtwStamp, LossDelta, LossReading, ProviderSpec, QpcClock, ScopeFilter,
    SessionConfig, SessionError,
};

/// What the callback and the loss poller put on the channel.
///
/// Both travel on one bounded channel so a consumer sees them in one order.
/// A loss notice is not an event: it carries no provider, no PID, and no
/// payload. The consumer turns it into a `Gap` with [`gap_from_delta`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMessage {
    /// An in-scope event, header only.
    Header(HeaderEvent),
    /// `EventsLost` or `RealTimeBuffersLost` grew since the previous poll.
    Loss(LossDelta),
}

/// Header fields the callback forwards. No property bytes.
///
/// `raw_timestamp` is the ETW header value unchanged. Conversion to
/// `ts_mono_ns` / `ts_wall_ns` happens on the consumer side, off the callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderEvent {
    /// Provider GUID in ferrisetw's `Display` form.
    pub provider: ProviderId,
    /// `EventHeader.EventDescriptor.Id`.
    pub event_id: u16,
    /// `EventHeader.ProcessId`. This is the only field the filter looked at.
    pub pid: u32,
    /// `EventHeader.ThreadId`.
    pub tid: u32,
    /// `EventRecord::raw_timestamp()`. See [`EtwClockMode`] for the unit.
    pub raw_timestamp: i64,
}

/// Provider GUID split into the fields ferrisetw's `GUID` exposes.
///
/// Stored by value so the callback does not format a string. Formatting is a
/// consumer-side concern; the callback only copies eight bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderId {
    /// `Data1`.
    pub data1: u32,
    /// `Data2`.
    pub data2: u16,
    /// `Data3`.
    pub data3: u16,
    /// `Data4`.
    pub data4: [u8; 8],
}

/// What the callback did with one event. Tested without ETW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackAction {
    /// Header PID was not in the scope set. Properties were not read.
    Dropped,
    /// Header was queued.
    Queued,
    /// The channel was full. The event was not retried and not parsed.
    ChannelFull,
    /// The receiver is gone.
    ChannelClosed,
}

/// Decide what a callback does with one header. No I/O.
pub fn on_header(
    filter: &ScopeFilter,
    tx: &SyncSender<SessionMessage>,
    event: HeaderEvent,
) -> CallbackAction {
    if !filter.contains(event.pid) {
        return CallbackAction::Dropped;
    }
    match tx.try_send(SessionMessage::Header(event)) {
        Ok(()) => CallbackAction::Queued,
        Err(TrySendError::Full(_)) => CallbackAction::ChannelFull,
        Err(TrySendError::Disconnected(_)) => CallbackAction::ChannelClosed,
    }
}

/// A running session plus the channel a consumer reads headers from.
///
/// Drop stops the session. [`Session::stop`] does the same and reports the
/// ETW error instead of swallowing it.
pub struct Session {
    name: String,
    trace: Option<UserTrace>,
    filter: Arc<ScopeFilter>,
    rx: Receiver<SessionMessage>,
    stop_poll: Arc<AtomicBool>,
    poller: Option<JoinHandle<()>>,
    full: Arc<AtomicU64>,
    closed: Arc<AtomicU64>,
    clock: Option<QpcClock>,
    clock_mode: EtwClockMode,
}

/// How many headers the channel holds. A full channel increments
/// [`Session::channel_full`] and the callback returns. The number is a bound,
/// not a drop policy: the loss is counted, and the 5 s poll still emits an
/// OS-loss gap separately.
const CHANNEL_BOUND: usize = 4096;

impl Session {
    /// Stop a leftover `AgentWatch-*` session of this name, then start a new one.
    ///
    /// Provider list and buffer sizes come from `config`. Kernel-File never
    /// appears there: [`SessionConfig`] rejects it before this function runs.
    ///
    /// The loss poller starts immediately and diffs the first QUERY against the
    /// next one, so a counter that is already non-zero at start is a baseline,
    /// not a gap.
    pub fn start(config: &SessionConfig) -> Result<Self, SessionError> {
        // ferrisetw's `stop_trace_by_name` uses the same ControlTrace(STOP) and
        // treats "no such session" as an error. Ours treats it as success.
        match ffi::stop_session_by_name(config.name()) {
            Ok(_) => {}
            Err(SessionError::AccessDenied) => return Err(SessionError::AccessDenied),
            // Any other stop failure is reported. Starting on top of a session
            // we failed to stop would hide the leftover.
            Err(err) => return Err(err),
        }

        let filter = Arc::new(ScopeFilter::new());
        let (tx, rx) = sync_channel::<SessionMessage>(CHANNEL_BOUND);
        let full = Arc::new(AtomicU64::new(0));
        let closed = Arc::new(AtomicU64::new(0));

        let mut builder = UserTrace::new()
            .named(config.name().to_owned())
            .set_trace_properties(buffer_properties(config));
        for provider in config.providers() {
            builder = builder.enable(provider_with_callback(
                provider,
                Arc::clone(&filter),
                tx.clone(),
                Arc::clone(&full),
                Arc::clone(&closed),
            ));
        }
        let trace = builder.start_and_process().map_err(|err| {
            // The session may exist even though enabling a provider failed.
            // Stop it so a retry does not see a leftover of our own making.
            let _ = ffi::stop_session_by_name(config.name());
            from_trace_error("start", &err)
        })?;

        let stop_poll = Arc::new(AtomicBool::new(false));
        let poller = spawn_loss_poller(config.name().to_owned(), Arc::clone(&stop_poll), tx);
        let clock = sample_clock();

        Ok(Self {
            name: config.name().to_owned(),
            trace: Some(trace),
            filter,
            rx,
            stop_poll,
            poller: Some(poller),
            full,
            closed,
            clock,
            // ferrisetw does not set PROCESS_TRACE_MODE_RAW_TIMESTAMP, so the
            // header value is system time. See `EtwClockMode`. SPIKE-02 has not
            // confirmed this on a live session; the QPC path stays available.
            clock_mode: EtwClockMode::FileTime,
        })
    }

    /// Session name actually opened (`AgentWatch-<boot>`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Replace the PID set the callback filters on. Takes effect on the next event.
    pub fn set_scope(&self, pids: impl IntoIterator<Item = u32>) {
        self.filter.replace(pids);
    }

    /// Headers the callback accepted and the consumer has not taken yet.
    pub fn receiver(&self) -> &Receiver<SessionMessage> {
        &self.rx
    }

    /// Events the callback could not queue because the channel was full.
    pub fn channel_full(&self) -> u64 {
        self.full.load(Ordering::Relaxed)
    }

    /// Events the callback could not queue because the receiver was dropped.
    pub fn channel_closed(&self) -> u64 {
        self.closed.load(Ordering::Relaxed)
    }

    /// Clock sampled at start. `None` when QPC or the wall clock could not be read.
    pub fn clock(&self) -> Option<QpcClock> {
        self.clock
    }

    /// How [`Session::stamp`] interprets a header timestamp.
    pub fn clock_mode(&self) -> EtwClockMode {
        self.clock_mode
    }

    /// Convert one header timestamp with the clock sampled at start.
    pub fn stamp(&self, raw_timestamp: i64) -> Option<EtwStamp> {
        EtwStamp::from_raw(self.clock_mode, raw_timestamp, self.clock.as_ref())
    }

    /// One `ControlTrace(QUERY)`. The caller diffs; this does not emit a gap.
    pub fn query_loss(&self) -> Result<LossReading, SessionError> {
        ffi::query_loss(&self.name)
    }

    /// Stop the session and the loss poller.
    ///
    /// A second call is [`SessionError::Etw`] with code 6 (invalid handle):
    /// the trace is already gone. The leftover-stop at the next `start` is
    /// what recovers a session whose owner crashed.
    pub fn stop(mut self) -> Result<(), SessionError> {
        self.shutdown()
    }

    fn shutdown(&mut self) -> Result<(), SessionError> {
        self.stop_poll.store(true, Ordering::Relaxed);
        if let Some(handle) = self.poller.take() {
            let _ = handle.join();
        }
        let trace = self.trace.take();
        match trace {
            Some(trace) => trace.stop().map_err(|err| from_trace_error("stop", &err)),
            None => Ok(()),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn buffer_properties(config: &SessionConfig) -> TraceProperties {
    TraceProperties {
        buffer_size: config.buffer_size_kb(),
        min_buffer: config.min_buffers(),
        max_buffer: config.max_buffers(),
        // ferrisetw rounds this to seconds and rejects 0. One second matches
        // its own default. It is not a measured value.
        flush_timer: Duration::from_secs(1),
        log_file_mode: ferrisetw::trace::LoggingMode::EVENT_TRACE_REAL_TIME_MODE
            | ferrisetw::trace::LoggingMode::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING,
    }
}

fn provider_with_callback(
    spec: &ProviderSpec,
    filter: Arc<ScopeFilter>,
    tx: SyncSender<SessionMessage>,
    full: Arc<AtomicU64>,
    closed: Arc<AtomicU64>,
) -> Provider {
    let callback = move |record: &EventRecord, _locator: &SchemaLocator| {
        // Header PID first. `process_id()` reads `EventHeader.ProcessId` and
        // does not touch the schema locator. A miss returns before the channel.
        let pid = record.process_id();
        if !filter.contains(pid) {
            return;
        }
        let guid = record.provider_id();
        let event = HeaderEvent {
            provider: ProviderId {
                data1: guid.data1,
                data2: guid.data2,
                data3: guid.data3,
                data4: guid.data4,
            },
            event_id: record.event_id(),
            pid,
            tid: record.thread_id(),
            raw_timestamp: record.raw_timestamp(),
        };
        match tx.try_send(SessionMessage::Header(event)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                full.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                closed.fetch_add(1, Ordering::Relaxed);
            }
        }
    };
    let mut builder = Provider::by_guid(spec.guid).add_callback(callback);
    if spec.any_keyword != 0 {
        builder = builder.any(spec.any_keyword);
    }
    builder.build()
}

/// Poll `ControlTrace(QUERY)` every [`session::LOSS_POLL_INTERVAL`].
///
/// A counter that grew is `try_send`ed as [`SessionMessage::Loss`]. The poller
/// does not build the `RawEvent`: the consumer owns `seq` and calls
/// [`gap_from_delta`]. A full channel drops the notice and moves on. The loss
/// is still in the ETW counters, so the next poll reports it again as growth
/// from the baseline this poll already stored — see [`session::poll_loss`],
/// which keeps the baseline even when the caller ignores the delta. That is
/// the wrong trade for a notice we failed to deliver. The baseline is therefore
/// advanced only after a successful send.
fn spawn_loss_poller(
    name: String,
    stop: Arc<AtomicBool>,
    tx: SyncSender<SessionMessage>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut baseline: Option<LossReading> = None;
        while !stop.load(Ordering::Relaxed) {
            if let Ok(reading) = ffi::query_loss(&name) {
                let poll = session::poll_loss(baseline, reading);
                match poll.delta {
                    Some(delta) => {
                        if tx.try_send(SessionMessage::Loss(delta)).is_ok() {
                            baseline = Some(poll.baseline);
                        }
                    }
                    None => baseline = Some(poll.baseline),
                }
            }
            // Sleep in short steps so `stop` is noticed promptly. Five seconds
            // is the QUERY period, not a delay on shutdown.
            let step = Duration::from_millis(200);
            let mut waited = Duration::ZERO;
            while waited < session::LOSS_POLL_INTERVAL && !stop.load(Ordering::Relaxed) {
                thread::sleep(step);
                waited += step;
            }
        }
    })
}

fn sample_clock() -> Option<QpcClock> {
    let (qpc, frequency) = ffi::read_qpc()?;
    let wall = ffi::read_wall_unix_ns()?;
    QpcClock::new(frequency, qpc, wall)
}

/// Check that this process can create a session, then stop it.
///
/// Enables every P1 provider. A provider that fails fails the probe: ferrisetw
/// enables providers inside `start`, and a partial session is stopped before
/// the error returns. The report lists the providers the config asked for when
/// the session came up, which is the P1 set.
///
/// Does not elevate. Access denied is [`SessionError::AccessDenied`].
pub fn probe(boot_id: &str) -> Result<session::ProbeReport, SessionError> {
    let config = SessionConfig::p1(boot_id).map_err(SessionError::Config)?;
    let session = Session::start(&config)?;
    let providers = config.providers().to_vec();
    session.stop()?;
    Ok(session::ProbeReport {
        session_creatable: true,
        providers,
    })
}

/// Stop whatever `AgentWatch-*` session `boot_id` names, if one is still there.
///
/// Exposed so a test can clean up after a crashed run. Returns whether a
/// session was actually stopped.
pub fn stop_leftover(boot_id: &str) -> Result<bool, SessionError> {
    let name = session::session_name(boot_id).map_err(SessionError::Config)?;
    ffi::stop_session_by_name(&name)
}

/// Build the gap a consumer emits when a [`SessionMessage::Loss`] arrives.
pub fn gap_from_delta(
    delta: LossDelta,
    seq: u64,
    from_mono_ns: u64,
    to_mono_ns: u64,
    wall_ns: Option<i64>,
) -> aw_core::RawEvent {
    session::raw_gap_for_loss(delta, seq, from_mono_ns, to_mono_ns, wall_ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_drops_before_send_and_does_not_block_on_a_full_channel() {
        let filter = ScopeFilter::new();
        filter.replace([7]);
        let (tx, rx) = sync_channel::<SessionMessage>(1);
        let event = HeaderEvent {
            provider: ProviderId {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            event_id: 1,
            pid: 7,
            tid: 1,
            raw_timestamp: 0,
        };
        assert_eq!(on_header(&filter, &tx, event), CallbackAction::Queued);
        assert_eq!(on_header(&filter, &tx, event), CallbackAction::ChannelFull);
        let outsider = HeaderEvent { pid: 8, ..event };
        assert_eq!(on_header(&filter, &tx, outsider), CallbackAction::Dropped);
        let queued = rx.try_recv().unwrap_or_else(|_| {
            panic!("the in-scope header was queued");
        });
        match queued {
            SessionMessage::Header(got) => assert_eq!(got.pid, 7),
            SessionMessage::Loss(_) => panic!("a header was queued, not a loss notice"),
        }
        // The outsider was not queued behind the full channel.
        assert!(rx.try_recv().is_err());

        drop(rx);
        assert_eq!(
            on_header(&filter, &tx, event),
            CallbackAction::ChannelClosed
        );
    }
}
