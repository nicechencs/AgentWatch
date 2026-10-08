//! Where a session writes events and where it reads them back.
//!
//! The orchestrator does not talk to SQLite. It pushes [`RawEvent`]s here and
//! asks for a flush when a session ends. [`SessionSink`] is the trait; the
//! in-memory impl lives next to the tests that need to read the events.

use aw_core::{RawEvent, SessionId};

use super::orch::SessionSummary;

/// One flush of one session.
#[derive(Debug, Clone, PartialEq)]
pub struct Flushed {
    /// Session that ended.
    pub session: SessionId,
    /// Events delivered for this session, in push order, after the flush.
    pub events: Vec<RawEvent>,
    /// Counts written next to `ended_ns`.
    pub summary: SessionSummary,
}

/// Pipeline stand-in.
///
/// `push` delivers one event to every session that contains its process.
/// `flush` is called once when a session ends, before `ended_ns` is stored.
pub trait SessionSink {
    /// `session` receives later events whose process pid is `pid`.
    fn watch(&mut self, session: SessionId, pid: u32);

    /// Accept `event`. Fan-out is the sink's job when `event.session_id` is
    /// `None` and the process belongs to more than one session.
    fn push(&mut self, event: RawEvent);

    /// Finish the session. Returns the events that belong to it.
    fn flush(&mut self, session: SessionId, summary: &SessionSummary) -> Flushed;
}

/// Records every push and tags an event with each session that holds its pid.
#[derive(Debug, Default)]
pub struct FanoutSink {
    /// Pid → sessions currently watching it, in insertion order.
    watchers: Vec<(u32, Vec<SessionId>)>,
    /// `(session, event)` in arrival order. An event for two sessions is stored twice.
    delivered: Vec<(SessionId, RawEvent)>,
    flushed: Vec<Flushed>,
}

impl FanoutSink {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// `session` should receive events whose process pid is `pid`.
    pub fn watch_pid(&mut self, session: SessionId, pid: u32) {
        if let Some((_, sessions)) = self
            .watchers
            .iter_mut()
            .find(|(watched, _)| *watched == pid)
        {
            if !sessions.contains(&session) {
                sessions.push(session);
            }
            return;
        }
        self.watchers.push((pid, vec![session]));
    }

    /// Events delivered to `session`, in order. Includes copies of shared processes.
    pub fn events_of(&self, session: SessionId) -> Vec<&RawEvent> {
        self.delivered
            .iter()
            .filter(|(id, _)| *id == session)
            .map(|(_, event)| event)
            .collect()
    }

    /// Flushes so far.
    pub fn flushed(&self) -> &[Flushed] {
        &self.flushed
    }
}

impl SessionSink for FanoutSink {
    fn watch(&mut self, session: SessionId, pid: u32) {
        self.watch_pid(session, pid);
    }

    fn push(&mut self, event: RawEvent) {
        let targets = match event.session_id {
            Some(session) => vec![session],
            None => {
                let pid = event.proc.as_ref().map(|proc| proc.pid);
                match pid {
                    Some(pid) => self
                        .watchers
                        .iter()
                        .find(|(watched, _)| *watched == pid)
                        .map(|(_, sessions)| sessions.clone())
                        .unwrap_or_default(),
                    None => Vec::new(),
                }
            }
        };
        if targets.is_empty() {
            // Nobody is watching. Keep the event on a side channel only when it
            // already names a session; an unscoped event with no watcher is not
            // dropped silently — it is stored under no session by not storing it
            // only when there is truly no recipient. Callers that need the gap
            // visible pass `session_id`.
            return;
        }
        for session in targets {
            let mut copy = event.clone();
            copy.session_id = Some(session);
            self.delivered.push((session, copy));
        }
    }

    fn flush(&mut self, session: SessionId, summary: &SessionSummary) -> Flushed {
        let events = self
            .delivered
            .iter()
            .filter(|(id, _)| *id == session)
            .map(|(_, event)| event.clone())
            .collect();
        let flushed = Flushed {
            session,
            events,
            summary: summary.clone(),
        };
        self.flushed.push(flushed.clone());
        flushed
    }
}
