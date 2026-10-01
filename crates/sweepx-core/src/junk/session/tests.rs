use super::*;
use std::fs;
use std::sync::Mutex;
use std::time::Instant;

// These tests intentionally exercise the process-wide worker cap; serialize their admission,
// and explicitly observe worker exit so a previous test cannot consume the next one's permit.
static SESSION_TESTS: Mutex<()> = Mutex::new(());

fn fixture_root(fixture: &tempfile::TempDir) -> PathBuf {
    #[cfg(unix)]
    {
        fs::canonicalize(fixture.path()).unwrap()
    }
    #[cfg(not(unix))]
    {
        fixture.path().to_path_buf()
    }
}
fn project(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let project = root.join(name);
    fs::create_dir(&project).unwrap();
    fs::write(project.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    let target = project.join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("payload"), bytes).unwrap();
    target
}
fn drain(session: &JunkSession, revision: JunkSessionRevision) -> Vec<JunkSessionEvent> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut events = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "session did not produce a terminal event"
        );
        let event = session
            .next_event_timeout(remaining.min(Duration::from_secs(1)))
            .unwrap();
        if let Some(event) = event {
            assert_eq!(event.revision, revision);
            let finished = matches!(event.kind, JunkSessionEventKind::Completed { .. });
            events.push(event);
            if finished {
                return events;
            }
        }
    }
}
fn current(events: &[JunkSessionEvent]) -> BTreeMap<JunkCandidateKey, Arc<JunkSessionCandidate>> {
    events
        .iter()
        .filter_map(|event| match &event.kind {
            JunkSessionEventKind::Candidate {
                key,
                state: JunkSessionCandidateState::Current,
                row,
                ..
            } => Some((*key, Arc::clone(row))),
            _ => None,
        })
        .collect()
}
fn shutdown(session: &JunkSession) {
    session.close();
    assert!(
        session
            .wait_for_worker_exit(Duration::from_secs(3))
            .unwrap()
    );
}
fn git(root: &Path, args: &[&str]) -> std::process::Output {
    let mut command = std::process::Command::new("git");
    command.arg("-C").arg(root).args(args);
    for key in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
    ] {
        command.env_remove(key);
    }
    command.output().unwrap()
}

#[test]
fn fresh_sessions_and_selected_refresh_keep_stable_keys_current_git_and_native_accounting() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture_root(&fixture);
    assert!(git(&root, &["init", "--quiet"]).status.success());
    fs::write(root.join(".gitignore"), b"target/\n").unwrap();
    let a = project(&root, "a", b"observed");
    let b = project(&root, "b", b"other-data");
    let mut request = JunkSessionRequest::new(vec![root.clone()]);
    request.limits.max_events = 1; // Exercise backpressure throughout the real native pipeline.
    let session = JunkSession::start(request).unwrap();
    session.set_visible_directory(Some(a.clone())).unwrap();
    let events = drain(&session, JunkSessionRevision(1));
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Complete,
            replaced: true,
            candidate_count: 2,
            ..
        }
    ));
    let rows = current(&events);
    assert_eq!(rows.len(), 2);
    let (a_key, a_row) = rows
        .iter()
        .find(|(_, row)| row.candidate.path == a.display().to_string())
        .unwrap();
    let (b_key, _) = rows
        .iter()
        .find(|(_, row)| row.candidate.path == b.display().to_string())
        .unwrap();
    assert_eq!(a_row.candidate.confidence.as_deref(), Some("high"));
    assert_eq!(
        git(&root, &["check-ignore", "--quiet", "--", "a/target"])
            .status
            .code(),
        Some(0)
    );
    let children: Vec<_> = fs::read_dir(&a).unwrap().map(Result::unwrap).collect();
    assert_eq!(children.len(), 1);
    assert_eq!(fs::symlink_metadata(children[0].path()).unwrap().len(), 8);
    assert_eq!(
        a_row.aggregate.apparent_logical_bytes,
        sweepx_platform::known_u128(8)
    );
    let initial_scan = a_row
        .candidate
        .source_entry
        .as_ref()
        .unwrap()
        .scan_id
        .clone();

    let other = JunkSession::start(JunkSessionRequest::new(vec![root.clone()])).unwrap();
    let other_rows = current(&drain(&other, JunkSessionRevision(1)));
    assert_eq!(
        rows.keys().collect::<Vec<_>>(),
        other_rows.keys().collect::<Vec<_>>()
    );
    assert_ne!(
        initial_scan,
        other_rows[a_key]
            .candidate
            .source_entry
            .as_ref()
            .unwrap()
            .scan_id
    );
    shutdown(&other);

    fs::write(a.join("payload"), b"new-current-data").unwrap();
    fs::write(root.join(".gitignore"), b"").unwrap();
    assert_eq!(
        git(&root, &["check-ignore", "--quiet", "--", "a/target"])
            .status
            .code(),
        Some(1)
    );
    let revision = session.refresh_selected(&[*a_key]).unwrap();
    assert_eq!(revision, JunkSessionRevision(2));
    let refreshed = drain(&session, revision);
    let fresh = current(&refreshed);
    assert_eq!(fresh.keys().copied().collect::<Vec<_>>(), vec![*a_key]);
    assert_eq!(fresh[a_key].candidate.confidence.as_deref(), Some("medium"));
    assert_ne!(
        initial_scan,
        fresh[a_key]
            .candidate
            .source_entry
            .as_ref()
            .unwrap()
            .scan_id
    );
    let native_length = fs::symlink_metadata(a.join("payload")).unwrap().len();
    assert_eq!(native_length, 16);
    assert_eq!(
        fresh[a_key].aggregate.apparent_logical_bytes,
        sweepx_platform::known_u128(native_length.into())
    );
    assert!(
        !refreshed
            .iter()
            .any(|event| matches!(event.kind, JunkSessionEventKind::Removed { .. }))
    );
    assert!(!fresh.contains_key(b_key));

    fs::remove_file(a.parent().unwrap().join("Cargo.toml")).unwrap();
    let revision = session.refresh_selected(&[*a_key]).unwrap();
    let removed = drain(&session, revision);
    assert!(current(&removed).is_empty());
    assert!(
        removed.iter().any(
            |event| matches!(event.kind, JunkSessionEventKind::Removed { key } if key == *a_key)
        )
    );
    assert!(matches!(
        removed.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Complete,
            replaced: true,
            candidate_count: 0,
            ..
        }
    ));
    assert_eq!(fs::read(a.join("payload")).unwrap(), b"new-current-data");
    // An unrelated old binding remains refreshable after the selected scope was replaced.
    let revision = session.refresh_selected(&[*b_key]).unwrap();
    assert_eq!(
        current(&drain(&session, revision))
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![*b_key]
    );
    shutdown(&session);
}

#[test]
fn replacing_a_selected_object_fails_without_removing_old_evidence() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture_root(&fixture);
    let target = project(&root, "project", b"old");
    let session = JunkSession::start(JunkSessionRequest::new(vec![root])).unwrap();
    let rows = current(&drain(&session, JunkSessionRevision(1)));
    let key = *rows.keys().next().unwrap();
    let old_target = target.with_file_name("retained-old-target");
    let unknown = JunkCandidateKey([0; 32]);
    assert_ne!(key, unknown);
    let revision = session.refresh_selected(&[unknown]).unwrap();
    let unknown_events = drain(&session, revision);
    assert!(unknown_events.iter().any(|event| matches!(&event.kind, JunkSessionEventKind::Error(failure) if failure.code == "unknown_candidate")));
    assert!(matches!(
        unknown_events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Failed,
            replaced: false,
            ..
        }
    ));
    assert!(
        !unknown_events
            .iter()
            .any(|event| matches!(event.kind, JunkSessionEventKind::Removed { .. }))
    );
    fs::rename(&target, &old_target).unwrap();
    fs::create_dir(&target).unwrap();
    fs::write(target.join("payload"), b"replacement").unwrap();
    let revision = session.refresh_selected(&[key]).unwrap();
    let events = drain(&session, revision);
    assert!(events.iter().any(|event| matches!(&event.kind, JunkSessionEventKind::Error(failure) if failure.code == "refresh_binding_changed")));
    assert!(!events.iter().any(|event| matches!(
        event.kind,
        JunkSessionEventKind::Removed { .. } | JunkSessionEventKind::Candidate { .. }
    )));
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Failed,
            replaced: false,
            ..
        }
    ));
    assert_eq!(fs::read(old_target.join("payload")).unwrap(), b"old");
    assert_eq!(fs::read(target.join("payload")).unwrap(), b"replacement");
    shutdown(&session);
}

#[test]
fn incomplete_refresh_does_not_remove_old_candidates_when_retained_boundaries_are_empty() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture_root(&fixture);
    let target = project(&root, "project", b"retained");
    let mut request = JunkSessionRequest::new(vec![root.clone()]);
    request.limits.scan.max_classified_metadata_bytes = 128 * 1024;
    request.limits.scan.max_classified_root_metadata_bytes = 128 * 1024;
    request.limits.scan.max_retained_boundaries = 0;
    // Progress overflow itself declares incomplete details. Keep its normal budget so the
    // initial scan is complete, while the later resource boundary cannot survive in summary.
    let session = JunkSession::start(request).unwrap();
    let initial = drain(&session, JunkSessionRevision(1));
    assert!(matches!(
        initial.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Complete,
            ..
        }
    ));
    let key = *current(&initial).keys().next().unwrap();
    fs::remove_file(target.parent().unwrap().join("Cargo.toml")).unwrap();
    // This is genuine metadata pressure, independent of callback queue/log capacities.
    for index in 0..256 {
        fs::create_dir(root.join(format!("extra-{index}"))).unwrap();
    }
    let revision = session.refresh_selected(&[key]).unwrap();
    let events = drain(&session, revision);
    assert!(events.iter().any(|event| matches!(&event.kind, JunkSessionEventKind::Boundary(boundary) if boundary.kind == sweepx_platform::BoundaryKind::ResourceLimit)));
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Partial,
            replaced: false,
            ..
        }
    ));
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.kind, JunkSessionEventKind::Removed { .. }))
    );
    assert_eq!(fs::read(target.join("payload")).unwrap(), b"retained");
    for index in 0..256 {
        fs::remove_dir(root.join(format!("extra-{index}"))).unwrap();
    }
    // The old binding was preserved, so a complete retry can now establish actual disappearance.
    let revision = session.refresh_selected(&[key]).unwrap();
    let events = drain(&session, revision);
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Complete,
            replaced: true,
            ..
        }
    ));
    assert!(events.iter().any(|event| matches!(event.kind, JunkSessionEventKind::Removed { key: removed } if removed == key)));
    shutdown(&session);
}

#[test]
fn cancellation_and_retention_failure_have_explicit_terminals() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture_root(&fixture);
    project(&root, "project", b"untouched");
    let mut request = JunkSessionRequest::new(vec![root.clone()]);
    request.limits.max_events = 1;
    let session = JunkSession::start(request).unwrap();
    // Started occupies the sole reliable slot, so the worker cannot pass Rules before we drain.
    session.cancel();
    let events = drain(&session, JunkSessionRevision(1));
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Cancelled,
            replaced: false,
            ..
        }
    ));
    assert!(current(&events).is_empty());
    shutdown(&session);

    let mut request = JunkSessionRequest::new(vec![root.clone()]);
    request.limits.max_candidate_bytes = 1;
    let limited = JunkSession::start(request).unwrap();
    let events = drain(&limited, JunkSessionRevision(1));
    assert!(events.iter().any(|event| matches!(&event.kind, JunkSessionEventKind::Error(failure) if failure.code == "resource_limit")));
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Failed,
            replaced: false,
            ..
        }
    ));
    assert!(current(&events).is_empty());
    shutdown(&limited);

    let mut request = JunkSessionRequest::new(vec![root]);
    request.project_rule_bytes = b"[]".to_vec();
    let invalid = JunkSession::start(request).unwrap();
    let events = drain(&invalid, JunkSessionRevision(1));
    assert!(events.iter().any(|event| matches!(&event.kind, JunkSessionEventKind::Error(failure) if failure.code == "rules_invalid")));
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Failed,
            ..
        }
    ));
    shutdown(&invalid);
}

#[test]
fn worker_cap_and_closing_an_undrained_session_are_bounded() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture_root(&fixture);
    let sessions: Vec<_> = (0..4)
        .map(|_| {
            let mut request = JunkSessionRequest::new(vec![root.clone()]);
            request.limits.max_events = 1;
            JunkSession::start(request).unwrap()
        })
        .collect();
    assert!(matches!(
        JunkSession::start(JunkSessionRequest::new(vec![root])),
        Err(JunkSessionControlError::ResourceLimit)
    ));
    for session in &sessions {
        shutdown(session);
    }
}

#[cfg(unix)]
#[test]
fn lossy_display_aliases_have_distinct_native_candidate_keys() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture_root(&fixture);
    project(&root, "project", b"payload");
    let session = JunkSession::start(JunkSessionRequest::new(vec![root])).unwrap();
    let rows = current(&drain(&session, JunkSessionRevision(1)));
    // The macOS fixture volume rejects malformed UTF-8 names (host EILSEQ). Exercise the
    // presentation-key codec with controlled model locators instead of claiming native I/O
    // support there. Both rows retain the same object identity, isolating the native path input.
    let original = &rows.values().next().unwrap().candidate;
    let mut cases = Vec::new();
    for byte in [0xfe, 0xff] {
        let mut candidate = original.clone();
        let source = candidate.source_entry.as_mut().unwrap();
        source.native_locator.as_mut().unwrap().parent_reopen_recipe[1].native_basename =
            sweepx_model::NativeName::UnixBytes(vec![b'p', byte]);
        let path = native_path(source).unwrap();
        candidate.path = path.display().to_string();
        cases.push((
            candidate_key(&candidate, &path).unwrap(),
            candidate.path,
            path,
        ));
    }
    assert_eq!(cases[0].1, cases[1].1);
    assert_ne!(cases[0].2, cases[1].2);
    assert_ne!(cases[0].0, cases[1].0);
    shutdown(&session);
}
