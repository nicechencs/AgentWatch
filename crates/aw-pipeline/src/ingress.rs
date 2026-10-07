//! Bounded ingress from a collector into the pipeline.
//!
//! pipeline.md §2 names `tokio::mpsc` with capacity 65536 and `try_send`. This workspace
//! has no tokio, and replay does not need a runtime, so the queue is
//! [`std::sync::mpsc::sync_channel`]. Capacity, `try_send`-only sends, and the failure
//! counter are unchanged. Turning those failures into `Gap { dropped }` is P1-PIPE-05;
//! this type only counts.
//!
//! A failed send is not a silent drop. [`std::sync::mpsc::TrySendError`] gives the
//! event back, and [`Ingress::emit`] returns it inside [`aw_core::SinkError`].

use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};

use aw_core::{EventSink, RawEvent, SinkError};

/// Default collector → pipeline depth. pipeline.md §2.
pub const DEFAULT_CAPACITY: usize = 65_536;

/// Sending half of the ingress queue. Implements [`EventSink`].
///
/// The only send path is [`SyncSender::try_send`]. A full or disconnected queue
/// increments [`Ingress::failures`] and returns the event.
pub struct Ingress {
    tx: SyncSender<RawEvent>,
    failures: u64,
}

/// Receiving half. The pipeline drains this; collectors never see it.
pub struct IngressRx {
    rx: Receiver<RawEvent>,
}

impl Ingress {
    /// Queue of [`DEFAULT_CAPACITY`].
    pub fn new() -> (Self, IngressRx) {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Queue of `capacity` slots. `0` is a valid bound: the first `emit` fails and
    /// counts, and the event is returned.
    pub fn with_capacity(capacity: usize) -> (Self, IngressRx) {
        let (tx, rx) = mpsc::sync_channel(capacity);
        (Self { tx, failures: 0 }, IngressRx { rx })
    }

    /// How many `emit` calls failed. Includes both a full queue and a disconnected one.
    ///
    /// Each increment corresponds to an event that was returned to the caller, not to
    /// an event that disappeared.
    pub fn failures(&self) -> u64 {
        self.failures
    }
}

impl EventSink for Ingress {
    fn emit(&mut self, event: RawEvent) -> Result<(), SinkError> {
        match self.tx.try_send(event) {
            Ok(()) => Ok(()),
            // `Closed` cannot carry the event. Returning it would drop the payload
            // inside this function. Both failures come back as `Full`, which hands the
            // event to the caller, and both increment `failures`. P1-PIPE-05 turns that
            // counter into `Gap { dropped }`. This card does not.
            Err(TrySendError::Full(event) | TrySendError::Disconnected(event)) => {
                self.failures = self.failures.saturating_add(1);
                Err(SinkError::Full {
                    event: Box::new(event),
                })
            }
        }
    }
}

impl IngressRx {
    /// Next event, or [`None`] if the sender is gone and the queue is empty.
    pub fn try_recv(&self) -> Option<RawEvent> {
        self.rx.try_recv().ok()
    }
}
