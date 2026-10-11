//! Sessions started from the API: `POST /sessions` (attach or launch),
//! `POST /sessions/run` + `/sessions/{sid}/adopt`, `/sessions/{sid}/attach`.
//!
//! The route inserts the `sessions` row and queues a [`WatchRequest`] on
//! [`crate::api::ApiState`]. The foreground loop drains the queue on each
//! sample tick ([`Watches::tick`]) and runs one [`HostSampler`] per watched
//! root, the same poll collector the daemon-wide sample uses (evidence S).
//!
//! A session ends when its root exits (`exited`, with the exit code when the
//! daemon spawned the root and reaped it), when `POST /sessions/{sid}/stop`
//! asks (`stopped`; the target keeps running), when an adopt does not arrive
//! in time (`adopt_timeout`), or when the daemon stops (`daemon_shutdown`).
//! On start, sessions a previous run left open are closed as
//! `daemon_restart`: nothing is watching them any more.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Child;
use std::sync::{Arc, Mutex};

use crate::api::ApiState;
use crate::sample::{HostSampler, SampleTarget};

use aw_platform::{PlatformError, ReapOutcome, ReleasedChild};

/// How long `POST /sessions/run` waits for `/adopt`. Same as the orchestrator.
pub(crate) const ADOPT_TIMEOUT_NS: i64 = 5_000_000_000;

/// Work queued by a route for the foreground loop.
pub(crate) enum WatchRequest {
    /// Watch `target.root_pid`. `child` is set when the daemon spawned it.
    Start {
        target: Box<SampleTarget>,
        child: Option<Box<dyn ReleasedChild>>,
    },
    /// Stop watching every root of this `sessions.id`. The row was already
    /// marked ended by the route.
    Stop { db_id: i64 },
}

/// A `/sessions/run` waiting for its `/adopt`.
pub(crate) struct PendingLaunch {
    pub ticket: String,
    pub deadline_ns: i64,
    pub target: SampleTarget,
}

struct Running {
    sampler: HostSampler,
    child: Option<Box<dyn ReleasedChild>>,
}

/// Wrap the daemon's already-launched child in the interface-v2 ownership
/// type. The watcher only ever reaps this owned handle, never a PID lookup.
pub(crate) fn released_child(child: Child) -> Box<dyn ReleasedChild> {
    Box::new(DaemonReleasedChild { child })
}

struct DaemonReleasedChild {
    child: Child,
}

fn child_outcome(status: std::process::ExitStatus) -> ReapOutcome {
    match status.code() {
        Some(code) => ReapOutcome::Exited(code),
        #[cfg(unix)]
        None => {
            use std::os::unix::process::ExitStatusExt;
            ReapOutcome::Signaled(status.signal().unwrap_or_default())
        }
        #[cfg(not(unix))]
        None => ReapOutcome::Signaled(0),
    }
}

impl ReleasedChild for DaemonReleasedChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn try_reap(&mut self) -> Result<ReapOutcome, PlatformError> {
        Ok(self
            .child
            .try_wait()?
            .map_or(ReapOutcome::StillRunning, child_outcome))
    }

    fn wait(mut self: Box<Self>) -> Result<ReapOutcome, PlatformError> {
        Ok(child_outcome(self.child.wait()?))
    }
}

/// Samplers for API-started sessions. Owned by the foreground loop.
pub(crate) struct Watches {
    db_path: PathBuf,
    running: Vec<Running>,
}

impl Watches {
    pub(crate) fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            running: Vec::new(),
        }
    }

    /// Close sessions a previous daemon run left open (not the daemon sample).
    pub(crate) fn recover(&self) {
        if let Ok(conn) = rusqlite::Connection::open(&self.db_path) {
            let _ = conn.execute(
                "UPDATE sessions SET ended_ns = ?1, end_reason = 'daemon_restart' \
                 WHERE ended_ns IS NULL AND id <> 1",
                [now_ns()],
            );
        }
    }

    /// Drain the queue, expire adopts, sample every root, end finished ones.
    pub(crate) fn tick(&mut self, shared: &Arc<Mutex<ApiState>>) {
        let (requests, expired) = match shared.lock() {
            Ok(mut state) => {
                let requests = std::mem::take(&mut state.watch_requests);
                let now = now_ns();
                let expired: Vec<i64> = state
                    .pending_launches
                    .iter()
                    .filter(|(_, pending)| pending.deadline_ns <= now)
                    .map(|(_, pending)| pending.target.db_id)
                    .collect();
                state
                    .pending_launches
                    .retain(|_, pending| pending.deadline_ns > now);
                (requests, expired)
            }
            Err(_) => (Vec::new(), Vec::new()),
        };
        for db_id in expired {
            self.end(db_id, "adopt_timeout", None);
        }
        for request in requests {
            match request {
                WatchRequest::Start { target, child } => self.start(*target, child),
                WatchRequest::Stop { db_id } => self.stop_session(db_id),
            }
        }
        let mut finished = Vec::new();
        for (index, running) in self.running.iter_mut().enumerate() {
            running.sampler.tick();
            let exit = running
                .child
                .as_mut()
                .and_then(|child| child.try_reap().ok());
            if exit.is_some_and(|outcome| outcome != ReapOutcome::StillRunning)
                || !running.sampler.root_alive()
            {
                finished.push((index, exit));
            }
        }
        for (index, outcome) in finished.into_iter().rev() {
            let mut running = self.running.remove(index);
            running.sampler.flush();
            running.sampler.stop();
            let db_id = running.sampler.target().db_id;
            // Another root of the same session may still be running.
            if !self
                .running
                .iter()
                .any(|r| r.sampler.target().db_id == db_id)
            {
                // Only the status the daemon reaped. An attached root (no child)
                // and a status with no code stay unknown; they are not written
                // as 0. The poll sampler cannot see a non-child's status, so
                // children are left NULL here too.
                if let Some(ReapOutcome::Exited(code)) = outcome {
                    if let Some(root) = running.sampler.target().root_hint.as_ref() {
                        record_root_exit(&self.db_path, db_id, root, code);
                    } else {
                        tracing::warn!(session = db_id, "root exit had no stored process identity");
                    }
                }
                self.end(
                    db_id,
                    "exited",
                    match outcome {
                        Some(ReapOutcome::Exited(code)) => Some(code),
                        _ => None,
                    },
                );
            }
        }
    }

    /// Flush and close every watched session. Called once at shutdown.
    pub(crate) fn shutdown(&mut self) {
        let ids: Vec<i64> = self
            .running
            .iter()
            .map(|r| r.sampler.target().db_id)
            .collect();
        for running in &mut self.running {
            running.sampler.flush();
            running.sampler.stop();
        }
        self.running.clear();
        for db_id in ids {
            self.end(db_id, "daemon_shutdown", None);
        }
    }

    /// Roots being sampled now, and the newest stored sample among them.
    pub(crate) fn runtime(&self) -> (usize, Option<i64>) {
        let roots = self.running.iter().filter(|r| r.sampler.running()).count();
        let last = self
            .running
            .iter()
            .filter_map(|r| r.sampler.last_sample_ns())
            .max();
        (roots, last)
    }

    /// Number of roots being watched. The tests that read it are Linux-only.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn len(&self) -> usize {
        self.running.len()
    }

    fn start(&mut self, target: SampleTarget, child: Option<Box<dyn ReleasedChild>>) {
        let db_id = target.db_id;
        let pid = target.root_pid;
        let mut sampler = HostSampler::for_target(self.db_path.clone(), target);
        // Adopted root: its row first (from the `/adopt` identity), then poll.
        let hinted = sampler.persist_root_hint();
        if sampler.start() {
            tracing::info!(session = db_id, pid, "watching process");
            self.running.push(Running { sampler, child });
        } else if hinted || sampler.persist_gone_root_hint() {
            // `/adopt` captured this identity while the CLI's pipe gate held
            // it. The target has already gone before the first poll, but the
            // snapshot row was persisted with evidence S and NA fields rather
            // than silently reporting zero processes.
            self.end(db_id, "exited", None);
            if let Some(child) = child {
                reap_launched_child(child);
            }
        } else {
            // The root could not be identified (gone already, or a platform
            // the poll sampler does not read). Not left open as "recording".
            self.end(db_id, "attach_failed", None);
            if let Some(child) = child {
                reap_launched_child(child);
            }
        }
    }

    fn stop_session(&mut self, db_id: i64) {
        let mut index = 0;
        while index < self.running.len() {
            if self.running[index].sampler.target().db_id == db_id {
                let mut running = self.running.remove(index);
                running.sampler.flush();
                running.sampler.stop();
                // `stop` does not kill. The session must not receive any later
                // status updates, but its daemon-launched child remains ours
                // to reap. Move just that handle to a waiter independent of
                // the recording lifecycle.
                if let Some(child) = running.child.take() {
                    reap_launched_child(child);
                }
            } else {
                index += 1;
            }
        }
    }

    fn end(&self, db_id: i64, reason: &str, exit_code: Option<i32>) {
        let Ok(conn) = rusqlite::Connection::open(&self.db_path) else {
            return;
        };
        let _ = conn.execute(
            "UPDATE sessions SET ended_ns = ?1, end_reason = ?2, \
             exit_code = COALESCE(?3, exit_code) WHERE id = ?4 AND ended_ns IS NULL",
            rusqlite::params![now_ns(), reason, exit_code, db_id],
        );
    }
}

/// Reap exactly one daemon-launched child after its recording has stopped.
///
/// The waiter owns the [`Child`] handle, so `wait` can only reap this child;
/// it neither changes SIGCHLD handling nor observes unrelated children. It
/// deliberately has no database access: a user stop is final for recording
/// purposes even if the target exits later.
fn reap_launched_child(child: Box<dyn ReleasedChild>) {
    let _ = std::thread::Builder::new()
        .name("aw-launch-reaper".to_owned())
        .spawn(move || {
            let _ = child.wait();
        });
}

/// Write `code` onto the root's `processes` row, and its `exit_ns` when that
/// is still NULL.
///
/// The row is selected by its pid/start-time identity, not pid alone. The poll
/// sampler records the process but not its status (a non-child's status is not
/// readable), so this is the only place a daemon-spawned root's code is stored.
/// A code already stored is kept: the first observation wins, and `0` is never
/// written in place of an unknown one. Other rows of the session, including
/// children or a reused pid, are not touched.
pub(crate) fn record_root_exit(
    db_path: &std::path::Path,
    db_id: i64,
    root: &crate::sample::RootHint,
    code: i32,
) {
    let Ok(conn) = rusqlite::Connection::open(db_path) else {
        return;
    };
    let code = i64::from(code);
    let root_uid = i64::from_ne_bytes(root.uid.0.to_ne_bytes());
    let Ok(start_ns) = i64::try_from(root.start_ns) else {
        tracing::warn!(
            session = db_id,
            "root exit had an invalid process start time"
        );
        return;
    };
    let Ok(updated) = conn.execute(
        "UPDATE processes SET \
            exit_code = COALESCE(exit_code, ?1), \
            exit_ns = COALESCE(exit_ns, ?2) \
         WHERE session_id = ?3 AND proc_uid = ?4 AND pid = ?5 AND start_ns = ?6 \
           AND exit_code IS NULL",
        rusqlite::params![
            code,
            now_ns(),
            db_id,
            root_uid,
            i64::from(root.pid),
            start_ns
        ],
    ) else {
        return;
    };
    if updated == 0 {
        tracing::warn!(session = db_id, "root exit did not update a process row");
    }
}

/// Unix nanoseconds.
pub(crate) fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Pending launches keyed by public id.
pub(crate) type PendingLaunches = BTreeMap<String, PendingLaunch>;

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::Watches;

    #[test]
    fn startup_recovery_marks_open_sessions_as_daemon_restart() {
        let dir = std::env::temp_dir().join(format!(
            "aw-watch-recover-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp directory");
        let db = dir.join("agentwatch.db");
        let store = aw_store::Store::open(&db).expect("store");
        store
            .connection()
            .execute_batch(
                "INSERT INTO sessions (id, public_id, mode, user_id, started_ns, platform, collectors) VALUES \
                     (1, 'daemon-sample', 'launch', '0', 1, 'linux', '[]'), \
                     (2, 'interrupted', 'launch', 'u', 2, 'linux', '[]'); \
                 INSERT INTO sessions (id, public_id, mode, user_id, started_ns, ended_ns, end_reason, platform, collectors) VALUES \
                     (3, 'already-ended', 'launch', 'u', 3, 4, 'stopped', 'linux', '[]');",
            )
            .expect("seed sessions");

        Watches::new(db.clone()).recover();

        let recovered: (Option<i64>, Option<String>) = store
            .connection()
            .query_row(
                "SELECT ended_ns, end_reason FROM sessions WHERE id = 2",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("recovered session");
        assert!(recovered.0.is_some());
        assert_eq!(recovered.1.as_deref(), Some("daemon_restart"));
        let daemon_sample: Option<i64> = store
            .connection()
            .query_row("SELECT ended_ns FROM sessions WHERE id = 1", [], |row| {
                row.get(0)
            })
            .expect("daemon sample");
        assert_eq!(daemon_sample, None);
        let ended: (Option<i64>, Option<String>) = store
            .connection()
            .query_row(
                "SELECT ended_ns, end_reason FROM sessions WHERE id = 3",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("already ended session");
        assert_eq!(ended, (Some(4), Some("stopped".to_owned())));

        drop(store);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
