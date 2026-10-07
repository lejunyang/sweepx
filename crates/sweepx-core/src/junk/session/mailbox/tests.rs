use super::*;
use std::sync::mpsc::sync_channel;

#[test]
fn backpressure_preserves_errors_and_reserved_terminal() {
    let shared = Arc::new(Shared::new(JunkSessionLimits {
        max_events: 1,
        ..JunkSessionLimits::default()
    }));
    let worker_shared = Arc::clone(&shared);
    let (ready_tx, ready_rx) = sync_channel(1);
    let (done_tx, done_rx) = sync_channel(1);
    let worker = std::thread::spawn(move || {
        let mut writer = Writer::new(
            worker_shared,
            JunkSessionRevision(1),
            CancellationToken::new(),
        );
        writer.failure(JunkSessionFailure::new("first", "first failure"));
        ready_tx.send(()).unwrap();
        writer.failure(JunkSessionFailure::new("second", "second failure"));
        writer.finish(JunkSessionOutcome::Partial, false, 0);
        done_tx.send(()).unwrap();
    });
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    {
        let state = shared.lock();
        assert_eq!(state.queue.len(), 1);
        assert!(state.bytes <= shared.limits.max_event_bytes);
    }
    assert!(done_rx.try_recv().is_err());
    assert!(matches!(
        shared
            .receive(Duration::from_secs(2))
            .unwrap()
            .unwrap()
            .kind,
        JunkSessionEventKind::Error(JunkSessionFailure { code: "first", .. })
    ));
    assert!(matches!(
        shared
            .receive(Duration::from_secs(2))
            .unwrap()
            .unwrap()
            .kind,
        JunkSessionEventKind::Error(JunkSessionFailure { code: "second", .. })
    ));
    let terminal = shared.receive(Duration::from_secs(2)).unwrap().unwrap();
    assert!(matches!(
        terminal.kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Partial,
            error_count: 2,
            ..
        }
    ));
    done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    worker.join().unwrap();
}

#[test]
fn progress_is_coalesced_but_reliable_data_precedes_terminal() {
    let shared = Arc::new(Shared::new(JunkSessionLimits {
        max_events: 1,
        ..JunkSessionLimits::default()
    }));
    let mut writer = Writer::new(
        Arc::clone(&shared),
        JunkSessionRevision(1),
        CancellationToken::new(),
    );
    for observed in 0..10_000 {
        writer.coalesce(JunkSessionEventKind::Progress {
            observed_entries: observed,
            path: PathBuf::from("presentation"),
        });
    }
    writer.failure(JunkSessionFailure::new("retained", "reliable failure"));
    writer.finish(JunkSessionOutcome::Partial, false, 0);
    {
        let state = shared.lock();
        assert_eq!(state.queue.len(), 1);
        assert!(state.progress.is_some() && state.terminal.is_some());
    }
    assert!(matches!(
        shared.pop().unwrap().kind,
        JunkSessionEventKind::Error(_)
    ));
    assert!(matches!(
        shared.pop().unwrap().kind,
        JunkSessionEventKind::Progress {
            observed_entries: 9999,
            ..
        }
    ));
    assert!(matches!(
        shared.pop().unwrap().kind,
        JunkSessionEventKind::Completed { .. }
    ));
    assert!(shared.pop().is_none());
}

#[test]
fn coalesced_paths_share_the_byte_budget_with_reliable_events() {
    let shared = Arc::new(Shared::new(JunkSessionLimits {
        max_event_bytes: 4096,
        ..JunkSessionLimits::default()
    }));
    let mut writer = Writer::new(
        Arc::clone(&shared),
        JunkSessionRevision(1),
        CancellationToken::new(),
    );
    for index in 0..100 {
        writer.coalesce(JunkSessionEventKind::Progress {
            observed_entries: index,
            path: PathBuf::from("p".repeat(3000)),
        });
        assert!(shared.lock().bytes <= 4096);
    }
    // A reliable error evicts lossy progress to fit, without waiting for a consumer.
    writer.failure(JunkSessionFailure::new("kept", "e".repeat(2048)));
    assert!(shared.lock().bytes <= 4096);
    assert!(matches!(
        shared.pop().unwrap().kind,
        JunkSessionEventKind::Error(JunkSessionFailure { code: "kept", .. })
    ));
    assert!(shared.pop().is_none());
    assert_eq!(shared.lock().bytes, 0);
}

#[test]
fn close_releases_a_full_queue_and_overflowing_waits_decline() {
    let shared = Arc::new(Shared::new(JunkSessionLimits {
        max_events: 1,
        ..JunkSessionLimits::default()
    }));
    let worker_shared = Arc::clone(&shared);
    let (ready_tx, ready_rx) = sync_channel(1);
    let (done_tx, done_rx) = sync_channel(1);
    let worker = std::thread::spawn(move || {
        let mut writer = Writer::new(
            worker_shared,
            JunkSessionRevision(1),
            CancellationToken::new(),
        );
        writer
            .send(JunkSessionEventKind::Phase(JunkSessionPhase::Rules))
            .unwrap();
        ready_tx.send(()).unwrap();
        let result = writer.send(JunkSessionEventKind::Phase(JunkSessionPhase::Traversal));
        done_tx.send(result.err().unwrap().code).unwrap();
    });
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    shared.close();
    assert_eq!(
        done_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
        "session_closed"
    );
    worker.join().unwrap();
    assert!(matches!(
        shared.receive(Duration::MAX),
        Err(JunkSessionControlError::ResourceLimit)
    ));
    assert!(matches!(
        shared.wait_exit(Duration::MAX),
        Err(JunkSessionControlError::ResourceLimit)
    ));
}

#[test]
fn revision_cannot_overwrite_undelivered_terminal_and_resets_cancellation() {
    let shared = Arc::new(Shared::new(JunkSessionLimits::default()));
    let mut writer = Writer::new(
        Arc::clone(&shared),
        JunkSessionRevision(1),
        shared.cancel_token(),
    );
    writer
        .send(JunkSessionEventKind::Phase(JunkSessionPhase::Rules))
        .unwrap();
    writer.finish(JunkSessionOutcome::Complete, true, 0);
    let keys = vec![JunkCandidateKey([1; 32])];
    assert!(matches!(
        shared.refresh(keys.clone()),
        Err(JunkSessionControlError::Busy)
    ));
    shared.pop().unwrap();
    assert!(matches!(
        shared.refresh(keys.clone()),
        Err(JunkSessionControlError::Busy)
    ));
    assert!(matches!(
        shared.pop().unwrap().kind,
        JunkSessionEventKind::Completed { .. }
    ));
    shared.cancel_token().cancel();
    assert_eq!(shared.refresh(keys).unwrap(), JunkSessionRevision(2));
    let job = shared.next_job().unwrap();
    assert_eq!(job.revision, JunkSessionRevision(2));
    assert!(!job.cancel.is_cancelled());
}

#[test]
fn operation_pause_admission_is_atomic_and_shared_clones_keep_it_held() {
    let shared = Arc::new(Shared::new(JunkSessionLimits::default()));
    assert!(matches!(
        shared.suspend_auto_refresh(),
        Err(JunkSessionControlError::Busy)
    ));
    let writer = Writer::new(
        Arc::clone(&shared),
        JunkSessionRevision(1),
        shared.cancel_token(),
    );
    writer.finish(JunkSessionOutcome::Complete, true, 0);
    assert!(
        matches!(
            shared.suspend_auto_refresh(),
            Err(JunkSessionControlError::Busy)
        ),
        "undrained terminal must still block operation admission"
    );
    assert!(matches!(
        shared.pop().unwrap().kind,
        JunkSessionEventKind::Completed { .. }
    ));
    let pause = shared.suspend_auto_refresh().unwrap();
    let worker_pause = pause.clone();
    assert!(matches!(
        shared.refresh(Vec::new()),
        Err(JunkSessionControlError::Busy)
    ));
    drop(pause);
    assert!(matches!(
        shared.refresh(Vec::new()),
        Err(JunkSessionControlError::Busy)
    ));
    drop(worker_pause);
    assert_eq!(shared.refresh(Vec::new()).unwrap(), JunkSessionRevision(2));
    shared.close();
}
