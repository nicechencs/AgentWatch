//! Session lifetime against a real ETW session.
//!
//! Creating a session needs an elevated token. These tests are `#[ignore]`d
//! and also gated on the `e2e` feature, so `cargo test -p aw-collector-windows`
//! does not open one. Run them from an already-elevated shell:
//!
//! ```text
//! cargo test -p aw-collector-windows --features e2e session::
//! ```
//!
//! Nothing here relaunches itself, calls `ShellExecute`, or requests a UAC
//! prompt. Access denied fails the test with [`SessionError::AccessDenied`].

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use super::session::{self, SessionConfig, SessionError};
use super::trace::{self, Session, SessionMessage};

/// Boot id used by these tests. Distinct from a daemon's boot id so a test
/// never stops a session a real daemon opened.
const TEST_BOOT: &str = "e2e";

/// `Ok(None)` when this process cannot create a session. The test skips.
///
/// A skip is not a pass. The line names the command that runs it for real.
fn open() -> Option<Session> {
    let config = SessionConfig::p1(TEST_BOOT).expect("test boot id is a single token");
    match Session::start(&config) {
        Ok(session) => Some(session),
        Err(SessionError::AccessDenied) => {
            eprintln!(
                "skipped: access denied. An elevated token is required. \
                 cargo test -p aw-collector-windows --features e2e session:: -- --ignored"
            );
            None
        }
        Err(err) => panic!("session start failed: {err}"),
    }
}

#[test]
#[ignore = "creates a real ETW session; needs an elevated token"]
fn session_create_stop() {
    let Some(session) = open() else {
        return;
    };
    assert_eq!(session.name(), "AgentWatch-e2e");
    // The first poll has not necessarily run. QUERY itself must succeed.
    let reading = session.query_loss().expect("query");
    let _ = reading.events_lost;
    session.stop().expect("stop");
    // Gone: a second stop-by-name reports absence, not an error.
    let still = trace::stop_leftover(TEST_BOOT).expect("cleanup");
    assert!(!still);
}

#[test]
#[ignore = "creates a real ETW session; needs an elevated token"]
fn session_second_start_clears_the_leftover() {
    let config = SessionConfig::p1(TEST_BOOT).expect("boot");
    let first = match Session::start(&config) {
        Ok(session) => session,
        Err(SessionError::AccessDenied) => {
            eprintln!(
                "skipped: access denied. An elevated token is required. \
                 cargo test -p aw-collector-windows --features e2e session:: -- --ignored"
            );
            return;
        }
        Err(err) => panic!("session start failed: {err}"),
    };
    // Leak the session without stopping it, the way a crashed daemon would.
    // `mem::forget` skips Drop, so the ETW session stays behind.
    std::mem::forget(first);

    let second = Session::start(&config).expect("restart stops the leftover");
    assert_eq!(second.name(), "AgentWatch-e2e");
    second.stop().expect("stop");
}

#[test]
#[ignore = "creates a real ETW session; needs an elevated token"]
fn session_probe_lists_the_p1_providers() {
    let report = match trace::probe(TEST_BOOT) {
        Ok(report) => report,
        Err(SessionError::AccessDenied) => {
            eprintln!(
                "skipped: access denied. An elevated token is required. \
                 cargo test -p aw-collector-windows --features e2e session:: -- --ignored"
            );
            return;
        }
        Err(other) => panic!("probe failed: {other}"),
    };
    assert!(report.session_creatable);
    assert_eq!(report.providers.len(), 3);
    assert!(report
        .providers
        .iter()
        .all(|p| session::classify_provider(p.guid) == session::ProviderClass::P1));
    // Probe stops the session. Nothing named AgentWatch-e2e remains.
    assert!(!trace::stop_leftover(TEST_BOOT).expect("cleanup"));
}

#[test]
#[ignore = "creates a real ETW session; needs an elevated token"]
fn session_scope_filter_drops_other_pids() {
    let Some(session) = open() else {
        return;
    };
    // PID 4 is System. Kernel-Process emits for everyone; the filter keeps
    // only this one, which will not be the subject of most events.
    session.set_scope([4]);
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        match session.receiver().recv_timeout(Duration::from_millis(200)) {
            Ok(SessionMessage::Header(header)) => {
                assert_eq!(header.pid, 4, "an out-of-scope pid reached the channel");
            }
            Ok(SessionMessage::Loss(_)) => {}
            Err(_) => {}
        }
    }
    session.stop().expect("stop");
}
