//! Acceptance tests for P1-DAEMON-04. Mock provider only. No process is created.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use aw_core::{EventKind, Evidence, GapKind, NaReason, ProcUid, SessionId, StartHow};

use super::{
    process_exit, process_file_placeholder, AdoptRequest, AttachOptions, EndReason, LaunchRequest,
    MockScope, ScopeAction, ScopeProvider, SessionOrchestrator, SessionStatus, SnapshotProc,
    ADOPT_TIMEOUT_NS,
};

fn launch() -> LaunchRequest {
    LaunchRequest {
        caller: "user-1".to_owned(),
        duration_ns: None,
        until_exit: None,
    }
}

fn proc(
    uid: u64,
    pid: u32,
    ppid: Option<u32>,
    parent: Option<u64>,
    start_ns: Option<u64>,
) -> SnapshotProc {
    SnapshotProc {
        uid: ProcUid(uid),
        pid,
        ppid,
        parent_uid: parent.map(ProcUid),
        exe: Some(format!("bin-{pid}")),
        start_ns,
    }
}

#[test]
fn run_completes_when_the_root_exits() {
    let mut provider = MockScope::new();
    provider.stage_waiting(42, ProcUid(100));
    let mut orch = SessionOrchestrator::new(provider);
    orch.set_now_ns(1_000);

    let started = orch.begin_run(launch()).expect("begin");
    orch.note_launch_pid(started.session, 42).expect("note");
    let adopted = orch
        .adopt(
            started.session,
            AdoptRequest {
                pid: 42,
                ticket: started.ticket,
                uid: Some(ProcUid(100)),
            },
        )
        .expect("adopt");
    assert_eq!(adopted.pid, 42);
    assert_eq!(adopted.uid, ProcUid(100));
    assert!(orch.provider().holds(started.session, 42));

    let exit = process_exit(42, ProcUid(100), 5_000, 9).expect("exit event");
    orch.set_now_ns(5_000);
    orch.ingest(exit).expect("ingest");

    let record = orch.session(started.session).expect("record");
    assert_eq!(record.status, SessionStatus::Ended);
    assert_eq!(record.ended_ns, Some(5_000));
    assert_eq!(record.end_reason, Some(EndReason::RootExited));
    let summary = record.summary.clone().expect("summary");
    assert_eq!(summary.watched_pids, 1);
    assert!(summary.other_events >= 1);
    assert!(orch.provider().released().contains(&started.session));
    // stop is not this path, and the target was not killed: it exited on its own.
    assert!(orch.provider().terminated().is_empty());
    let flushed = orch.sink().flushed();
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].summary.watched_pids, 1);
}

#[test]
fn stop_ends_observation_and_does_not_kill_the_target() {
    let mut provider = MockScope::new();
    provider.stage_waiting(7, ProcUid(7));
    let mut orch = SessionOrchestrator::new(provider);
    let started = orch.begin_run(launch()).expect("begin");
    orch.note_launch_pid(started.session, 7).expect("note");
    orch.adopt(
        started.session,
        AdoptRequest {
            pid: 7,
            ticket: started.ticket,
            uid: None,
        },
    )
    .expect("adopt");
    orch.set_now_ns(50);
    let record = orch.stop(started.session).expect("stop");
    assert_eq!(record.status, SessionStatus::Ended);
    assert_eq!(record.end_reason, Some(EndReason::Stopped));
    assert_eq!(record.ended_ns, Some(50));
    assert!(orch.provider().terminated().is_empty());
    assert!(orch.provider().released().contains(&started.session));
}

#[test]
fn adopt_timeout_terminates_the_target_and_fails_the_session() {
    let mut provider = MockScope::new();
    provider.stage_waiting(99, ProcUid(99));
    let mut orch = SessionOrchestrator::new(provider);
    orch.set_now_ns(0);
    let started = orch.begin_run(launch()).expect("begin");
    orch.note_launch_pid(started.session, 99).expect("note");

    orch.tick(ADOPT_TIMEOUT_NS - 1).expect("not yet");
    assert_eq!(
        orch.session(started.session).expect("live").status,
        SessionStatus::AwaitingAdopt
    );
    assert!(orch.provider().terminated().is_empty());

    orch.tick(ADOPT_TIMEOUT_NS).expect("timeout");
    let record = orch.session(started.session).expect("failed");
    assert_eq!(record.status, SessionStatus::Failed);
    assert_eq!(record.end_reason, Some(EndReason::AdoptTimeout));
    assert_eq!(record.ended_ns, Some(ADOPT_TIMEOUT_NS));
    assert_eq!(orch.provider().terminated(), &[99]);
}

#[test]
fn adopt_timeout_without_a_pid_does_not_invent_one() {
    let mut orch = SessionOrchestrator::new(MockScope::new());
    let started = orch.begin_run(launch()).expect("begin");
    let err = orch.tick(ADOPT_TIMEOUT_NS).expect_err("no pid");
    let message = err.to_string();
    assert!(message.contains("pid"), "{message}");
    assert!(orch.provider().terminated().is_empty());
    let record = orch.session(started.session).expect("failed anyway");
    assert_eq!(record.status, SessionStatus::Failed);
}

#[test]
fn attach_collects_then_snapshots_then_rescans_without_losing_or_duplicating() {
    let mut provider = MockScope::new();
    // Root and one child are visible in the first snapshot.
    provider.add_proc(proc(1, 10, None, None, Some(100)));
    provider.add_proc(proc(2, 11, Some(10), Some(1), Some(200)));
    // A grandchild appears only on the rescan: the race the second scan fills.
    provider.add_proc_on_rescan(proc(3, 12, Some(11), Some(2), Some(300)));
    let mut orch = SessionOrchestrator::new(provider);
    orch.set_now_ns(1_000);
    let record = orch
        .begin_attach(AttachOptions {
            root_pid: 10,
            follow_children: true,
            duration_ns: None,
            until_exit: None,
        })
        .expect("attach");

    let actions: Vec<&ScopeAction> = orch
        .provider()
        .log()
        .iter()
        .filter(|action| {
            matches!(
                action,
                ScopeAction::BeginCollect { .. }
                    | ScopeAction::Snapshot { .. }
                    | ScopeAction::Rescan { .. }
            )
        })
        .collect();
    assert_eq!(
        actions,
        vec![
            &ScopeAction::BeginCollect { session: record.id },
            &ScopeAction::Snapshot {
                session: record.id,
                root_pid: 10,
            },
            &ScopeAction::Rescan {
                session: record.id,
                root_pid: 10,
            },
        ]
    );

    let events = orch.sink().events_of(record.id);
    let starts: Vec<&aw_core::RawEvent> = events
        .iter()
        .copied()
        .filter(|event| matches!(event.kind, EventKind::ProcessStart(_)))
        .collect();
    assert_eq!(starts.len(), 3, "root, child, and the late grandchild");
    let mut pids: Vec<u32> = starts
        .iter()
        .filter_map(|event| event.proc.as_ref().map(|proc| proc.pid))
        .collect();
    pids.sort_unstable();
    assert_eq!(pids, vec![10, 11, 12]);
    for event in &starts {
        assert_eq!(event.evidence, Evidence::S);
        match &event.kind {
            EventKind::ProcessStart(start) => {
                assert_eq!(start.how, StartHow::Snapshot);
                assert!(start.start_time_ns > 0);
                assert!(
                    !event.field_evidence.contains_key("start_time_ns"),
                    "a reported start time is not NA"
                );
            }
            other => panic!("expected process_start, got {other:?}"),
        }
    }

    // The same attach again must not inject a second copy of an already-seen uid.
    // A further rescan is not a public method; ingesting nothing keeps the count.
    assert_eq!(
        orch.session(record.id).expect("record").summary,
        None,
        "still running, no flush yet"
    );
}

#[test]
fn snapshot_without_a_start_time_is_marked_na() {
    let mut provider = MockScope::new();
    provider.add_proc(proc(1, 10, None, None, None));
    let mut orch = SessionOrchestrator::new(provider);
    orch.set_now_ns(5);
    let record = orch
        .begin_attach(AttachOptions {
            root_pid: 10,
            follow_children: true,
            duration_ns: None,
            until_exit: None,
        })
        .expect("attach");
    let event = orch
        .sink()
        .events_of(record.id)
        .into_iter()
        .find(|event| matches!(event.kind, EventKind::ProcessStart(_)))
        .expect("start");
    assert_eq!(
        event.field_evidence.get("start_time_ns"),
        Some(&Evidence::NA(NaReason::Preexisting))
    );
    assert_eq!(event.evidence, Evidence::S);
}

#[test]
fn interleaved_live_event_is_kept_once() {
    let mut provider = MockScope::new();
    provider.add_proc(proc(1, 10, None, None, Some(1)));
    provider.add_proc(proc(2, 11, Some(10), Some(1), Some(2)));
    let mut orch = SessionOrchestrator::new(provider);
    orch.set_now_ns(10);
    let record = orch
        .begin_attach(AttachOptions {
            root_pid: 10,
            follow_children: true,
            duration_ns: None,
            until_exit: None,
        })
        .expect("attach");

    // A live start for the child arrives after the snapshot already injected it.
    // Membership is by uid, so this is a second observation, not a second member.
    // A live start for a *new* pid is not in the snapshot; the sink still delivers
    // it because the parent pid is watched only when the event's own pid is.
    // Watch the child, then send one event, and assert it is delivered once.
    let event = process_file_placeholder(11, ProcUid(2), 20, 50).expect("event");
    orch.set_now_ns(20);
    orch.ingest(event).expect("ingest");

    let delivered = orch.sink().events_of(record.id);
    let for_child = delivered
        .iter()
        .filter(|event| event.proc.as_ref().is_some_and(|proc| proc.pid == 11))
        .count();
    // One snapshot injection plus one live event. Not two live copies.
    assert_eq!(for_child, 2);
    let live = delivered.iter().filter(|event| event.seq == 50).count();
    assert_eq!(live, 1);
}

#[test]
fn recover_marks_open_sessions_interrupted_and_emits_a_restart_gap() {
    let mut provider = MockScope::new();
    provider.stage_waiting(4, ProcUid(4));
    provider.add_proc(proc(8, 8, None, None, Some(1)));
    let mut orch = SessionOrchestrator::new(provider);
    orch.set_now_ns(100);
    let running = orch.begin_run(launch()).expect("run");
    orch.note_launch_pid(running.session, 4).expect("note");
    orch.adopt(
        running.session,
        AdoptRequest {
            pid: 4,
            ticket: running.ticket,
            uid: None,
        },
    )
    .expect("adopt");
    orch.set_now_ns(200);
    let attached = orch
        .begin_attach(AttachOptions {
            root_pid: 8,
            follow_children: true,
            duration_ns: None,
            until_exit: None,
        })
        .expect("attach");

    let recovered = orch.recover(1_000).expect("recover");
    assert_eq!(recovered.len(), 2);
    for record in &recovered {
        assert_eq!(record.status, SessionStatus::Interrupted);
        assert_eq!(record.end_reason, Some(EndReason::Interrupted));
        assert_eq!(record.ended_ns, Some(1_000));
    }
    for id in [running.session, attached.id] {
        let gaps: Vec<_> = orch
            .sink()
            .events_of(id)
            .into_iter()
            .filter(|event| matches!(event.kind, EventKind::Gap(_)))
            .collect();
        assert_eq!(gaps.len(), 1, "one restart gap per session");
        match &gaps[0].kind {
            EventKind::Gap(gap) => {
                assert_eq!(gap.gap_kind, GapKind::Restart);
                assert_eq!(gap.to_mono_ns, 1_000);
                assert!(gap.from_mono_ns <= gap.to_mono_ns);
            }
            other => panic!("expected gap, got {other:?}"),
        }
        assert_eq!(gaps[0].evidence, Evidence::E1);
    }
}

#[test]
fn two_sessions_attached_to_one_process_both_receive_its_events() {
    let mut first = MockScope::new();
    first.add_proc(proc(5, 50, None, None, Some(1)));
    let mut orch = SessionOrchestrator::new(first);
    orch.set_now_ns(1);
    let a = orch
        .begin_attach(AttachOptions {
            root_pid: 50,
            follow_children: true,
            duration_ns: None,
            until_exit: None,
        })
        .expect("a");

    // The second session is a second orchestrator only if the provider is shared.
    // One orchestrator, one provider: stage the same pid again for another attach.
    orch.provider_mut()
        .add_proc(proc(5, 50, None, None, Some(1)));
    let b = orch
        .begin_attach(AttachOptions {
            root_pid: 50,
            follow_children: true,
            duration_ns: None,
            until_exit: None,
        })
        .expect("b");
    assert_ne!(a.id, b.id);

    let event = process_file_placeholder(50, ProcUid(5), 30, 77).expect("event");
    orch.ingest(event).expect("ingest");

    let seqs = |id: SessionId| -> Vec<u64> {
        orch.sink()
            .events_of(id)
            .into_iter()
            .filter(|event| event.seq == 77)
            .map(|event| event.seq)
            .collect()
    };
    assert_eq!(seqs(a.id), vec![77]);
    assert_eq!(seqs(b.id), vec![77]);
    assert_eq!(
        orch.sink()
            .events_of(a.id)
            .iter()
            .filter(|e| e.seq == 77)
            .count(),
        1
    );
    assert_eq!(
        orch.sink()
            .events_of(b.id)
            .iter()
            .filter(|e| e.seq == 77)
            .count(),
        1
    );
}

#[test]
fn duration_ends_the_session_without_killing() {
    let mut provider = MockScope::new();
    provider.stage_waiting(3, ProcUid(3));
    let mut orch = SessionOrchestrator::new(provider);
    orch.set_now_ns(0);
    let started = orch
        .begin_run(LaunchRequest {
            caller: "user-1".to_owned(),
            duration_ns: Some(1_000),
            until_exit: None,
        })
        .expect("begin");
    orch.note_launch_pid(started.session, 3).expect("note");
    orch.adopt(
        started.session,
        AdoptRequest {
            pid: 3,
            ticket: started.ticket,
            uid: None,
        },
    )
    .expect("adopt");
    orch.tick(1_000).expect("duration");
    let record = orch.session(started.session).expect("ended");
    assert_eq!(record.end_reason, Some(EndReason::Duration));
    assert_eq!(record.status, SessionStatus::Ended);
    assert!(orch.provider().terminated().is_empty());
}

#[test]
fn until_exit_ends_the_session_when_that_pid_exits() {
    let mut provider = MockScope::new();
    provider.stage_waiting(3, ProcUid(3));
    let mut orch = SessionOrchestrator::new(provider);
    orch.set_now_ns(10);
    let started = orch
        .begin_run(LaunchRequest {
            caller: "user-1".to_owned(),
            duration_ns: None,
            until_exit: Some(80),
        })
        .expect("begin");
    orch.note_launch_pid(started.session, 3).expect("note");
    orch.adopt(
        started.session,
        AdoptRequest {
            pid: 3,
            ticket: started.ticket,
            uid: None,
        },
    )
    .expect("adopt");
    // 80 is the CLI, not a member. Its exit ends observation and does not kill 3.
    let exit = process_exit(80, ProcUid(80), 40, 4).expect("exit");
    orch.set_now_ns(40);
    orch.ingest(exit).expect("ingest");
    let record = orch.session(started.session).expect("ended");
    assert_eq!(record.end_reason, Some(EndReason::UntilExit));
    assert_eq!(record.status, SessionStatus::Ended);
    assert_eq!(record.ended_ns, Some(40));
    assert!(orch.provider().terminated().is_empty());
}

#[test]
fn empty_ticket_is_an_error() {
    let err = super::LaunchTicket::new("").expect_err("empty");
    assert_eq!(err, super::ProviderError::EmptyTicket);
}

#[test]
fn provider_actions_return_result_not_a_sentinel() {
    let mut provider = MockScope::new();
    let missing = provider.attach(
        SessionId(1),
        1,
        &AttachOptions {
            root_pid: 1,
            follow_children: true,
            duration_ns: None,
            until_exit: None,
        },
    );
    assert!(missing.is_err());
    let killed = provider.terminate(1234);
    assert!(killed.is_err());
}
