use super::*;
use std::fs;
use std::sync::Mutex;
use std::time::Instant;

// These tests intentionally exercise the process-wide worker cap; serialize their admission,
// and explicitly observe worker exit so a previous test cannot consume the next one's permit.
static SESSION_TESTS: Mutex<()> = Mutex::new(());

#[test]
fn native_closed_candidate_reaches_session_mailbox_before_unrelated_subtree() {
    struct Probe<'a> {
        inner: Observer<'a>,
        target: PathBuf,
        unrelated: PathBuf,
        unrelated_seen: bool,
        early: bool,
    }
    impl ClassifiedScanObserver for Probe<'_> {
        fn on_progress(&mut self, root: &Path, event: &ProgressEvent) {
            if let ProgressEvent::EntryObserved { path, .. } = event {
                self.unrelated_seen |= path.starts_with(&self.unrelated) && path != &self.unrelated;
            }
            self.inner.on_progress(root, event);
        }
        fn on_boundary(&mut self, boundary: &sweepx_platform::BoundaryRecord) {
            self.inner.on_boundary(boundary);
        }
        fn on_directory_progress(&mut self, path: &Path, aggregate: &DirectoryAggregate) {
            self.inner.on_directory_progress(path, aggregate);
        }
        fn preferred_directory(&self) -> Option<PathBuf> {
            Some(self.target.clone())
        }
        fn on_candidate(
            &mut self,
            entry: &ScannedEntry,
            rule: &str,
            aggregate: &DirectoryAggregate,
        ) {
            if native_path(entry).as_ref() == Some(&self.target) {
                assert!(
                    !self.unrelated_seen,
                    "candidate must precede unrelated payload traversal"
                );
                assert!(aggregate.coverage.complete);
                self.early = true;
            }
            self.inner.on_candidate(entry, rule, aggregate);
        }
    }
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture_root(&fixture);
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    let target = root.join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("payload"), b"completed subtree").unwrap();
    let unrelated = root.join("unrelated");
    fs::create_dir(&unrelated).unwrap();
    for index in 0..64 {
        fs::write(unrelated.join(format!("file-{index}")), b"later").unwrap();
    }
    // Ordinary native metadata is the independent oracle, including host-created files.
    let logical: u128 = fs::read_dir(&target)
        .unwrap()
        .map(|entry| u128::from(fs::symlink_metadata(entry.unwrap().path()).unwrap().len()))
        .sum();
    let limits = JunkSessionLimits::default();
    let shared = Arc::new(Shared::new(limits));
    let cancel = CancellationToken::new();
    let mut writer = Writer::new(Arc::clone(&shared), JunkSessionRevision(1), cancel.clone());
    let service = JunkService::built_in().unwrap();
    let platform = PlatformJunkSetup::default();
    let mut pending = Rows::new();
    let mut probe = Probe {
        inner: Observer {
            service: &service,
            platform: &platform,
            writer: &mut writer,
            pending: &mut pending,
            paths: None,
            limits,
            retained_bytes: 0,
            retained_rows: 0,
            rules_digest: [0; 32],
            observed: 0,
        },
        target: target.clone(),
        unrelated,
        unrelated_seen: false,
        early: false,
    };
    Scanner::new(
        HostPlatformScanner::new(),
        ScannerOptions {
            max_workers: 1,
            ..Default::default()
        },
    )
    .scan_classified_with_observer(
        &[ScanRoot::new(root).unwrap()],
        &cancel,
        &service.with_platform(&platform.rules, &platform.evidence),
        None,
        &mut probe,
    )
    .unwrap();
    assert!(probe.early && probe.unrelated_seen);
    drop(probe);
    assert!(writer.fault.is_none());
    assert_eq!(pending.len(), 1);
    let session = JunkSession { shared };
    let event = std::iter::from_fn(|| session.try_next_event())
        .find(|event| {
            matches!(
                event.kind,
                JunkSessionEventKind::Candidate {
                    state: JunkSessionCandidateState::Base,
                    ..
                }
            )
        })
        .unwrap();
    let JunkSessionEventKind::Candidate { row, key, .. } = event.kind else {
        unreachable!()
    };
    assert_eq!(row.observed_native_path(), Some(target));
    assert_eq!(row.logical_bytes(), &sweepx_platform::known_u128(logical));
    assert!(row.complete());
    assert!(pending.contains_key(&key));
    session.close();
}

#[test]
fn system_admission_rejects_explicit_roots_and_disabled_platform_rules() {
    let fixture = tempfile::tempdir().unwrap();
    let mut request = JunkSessionRequest::system();
    request.roots.push(fixture_root(&fixture));
    assert!(matches!(
        JunkSession::start(request),
        Err(JunkSessionControlError::InvalidRequest)
    ));
    let mut request = JunkSessionRequest::system();
    request.include_platform_rules = false;
    assert!(matches!(
        JunkSession::start(request),
        Err(JunkSessionControlError::InvalidRequest)
    ));
}

#[test]
fn discovered_root_admission_is_bounded_and_preserves_link_sensitive_spelling() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture_root(&fixture);
    assert_eq!(
        normalize_discovered_roots(Vec::new()).unwrap(),
        Vec::<PathBuf>::new()
    );
    assert!(normalize_discovered_roots(vec![root.clone(); 257]).is_err());
    assert!(normalize_discovered_roots(vec![PathBuf::from("relative")]).is_err());
    assert_eq!(
        normalize_discovered_roots(vec![root.clone(), root.join("nested")]).unwrap(),
        vec![root.clone()]
    );
    let sensitive = root.join("linked/../candidate");
    assert_eq!(
        normalize_discovered_roots(vec![sensitive.clone()]).unwrap(),
        vec![sensitive]
    );
}

#[cfg(target_os = "macos")]
#[test]
fn system_refresh_rediscovers_scope_and_restores_only_newly_discovered_history() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let base = fixture_root(&fixture);
    let a = project(&base, "a", b"a-payload");
    let b = project(&base, "b", b"b-larger-payload");
    let cache = base.join("cache");
    let request = || {
        let mut request = JunkSessionRequest::system();
        request.cache_dir = Some(cache.clone());
        request
    };
    let new_worker = || Worker {
        request: request(),
        session_id: "controlled-system-session".into(),
        current: Rows::new(),
        preview_keys: BTreeSet::new(),
        scan_roots: Vec::new(),
    };
    let run = |worker: &mut Worker, revision, root: PathBuf| {
        // Inject only discovery inventory; native traversal, interpretation, cache publication
        // and replacement are real. No process-global HOME or tool configuration is mutated.
        let shared = Arc::new(Shared::new(worker.request.limits));
        let job = Job {
            revision: JunkSessionRevision(revision),
            selected: None,
            cancel: CancellationToken::new(),
        };
        let mut writer = Writer::new(Arc::clone(&shared), job.revision, job.cancel.clone());
        worker
            .run_with_discovery(&job, &mut writer, |_| {
                Ok((PlatformJunkSetup::default(), vec![root]))
            })
            .unwrap();
        let session = JunkSession { shared };
        let events = drain(&session, job.revision);
        session.close();
        events
    };
    let mut worker = new_worker();
    let first = run(&mut worker, 1, a.parent().unwrap().to_path_buf());
    let rows = current(&first);
    let (&a_key, a_row) = rows.first_key_value().unwrap();
    assert_eq!(a_row.observed_native_path().as_ref(), Some(&a));
    assert_eq!(
        a_row.logical_bytes(),
        &sweepx_platform::known_u128(u128::from(fs::metadata(a.join("payload")).unwrap().len()))
    );
    let second = run(&mut worker, 2, b.parent().unwrap().to_path_buf());
    assert!(
        second.iter().any(
            |event| matches!(event.kind, JunkSessionEventKind::Removed { key } if key == a_key)
        )
    );
    let b_rows = current(&second);
    assert_eq!(
        b_rows
            .values()
            .next()
            .unwrap()
            .observed_native_path()
            .as_ref(),
        Some(&b)
    );
    assert_eq!(worker.scan_roots, vec![b.parent().unwrap().to_path_buf()]);
    assert!(!worker.current.contains_key(&a_key));
    let mut warm = new_worker();
    let events = run(&mut warm, 1, b.parent().unwrap().to_path_buf());
    let history: Vec<_> = events
        .iter()
        .filter_map(|event| match &event.kind {
            JunkSessionEventKind::Candidate {
                state: JunkSessionCandidateState::Historical,
                row,
                ..
            } => row.observed_native_path(),
            _ => None,
        })
        .collect();
    assert_eq!(history, vec![b]);
    let position = |predicate: fn(&JunkSessionEventKind) -> bool| {
        events
            .iter()
            .position(|event| predicate(&event.kind))
            .unwrap()
    };
    assert!(
        position(|kind| matches!(
            kind,
            JunkSessionEventKind::Phase(JunkSessionPhase::Discovery)
        )) < position(|kind| matches!(
            kind,
            JunkSessionEventKind::Candidate {
                state: JunkSessionCandidateState::Historical,
                ..
            }
        ))
    );
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Complete,
            replaced: true,
            ..
        }
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn cached_session_shows_history_before_discovery_then_replaces_with_new_scan_id() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let base = fixture_root(&fixture);
    let root = base.join("projects");
    fs::create_dir(&root).unwrap();
    let target = project(&root, "a", b"initial-payload");
    let cache = base.join("cache");
    let request = || {
        let mut request = JunkSessionRequest::new(vec![root.clone()]);
        request.cache_dir = Some(cache.clone());
        request.limits.max_events = 1;
        request
    };
    let cold = JunkSession::start(request()).unwrap();
    let rows = current(&drain(&cold, JunkSessionRevision(1)));
    let (&key, original) = rows.first_key_value().unwrap();
    shutdown(&cold);
    assert!(
        crate::junk::cache::CacheReader::new(&cache)
            .index(&root)
            .is_some()
    );
    fs::write(
        target.join("payload"),
        b"changed-and-larger-current-payload",
    )
    .unwrap();
    let warm = JunkSession::start(request()).unwrap();
    let events = drain(&warm, JunkSessionRevision(1));
    let preview_position = events
        .iter()
        .position(|event| {
            matches!(
                event.kind,
                JunkSessionEventKind::Candidate {
                    state: JunkSessionCandidateState::Historical,
                    ..
                }
            )
        })
        .unwrap();
    let discovery_position = events
        .iter()
        .position(|event| {
            matches!(
                event.kind,
                JunkSessionEventKind::Phase(JunkSessionPhase::Discovery)
            )
        })
        .unwrap();
    assert!(preview_position < discovery_position);
    let current_rows = current(&events);
    let refreshed = &current_rows[&key];
    assert_ne!(
        original.directory_aggregate().unwrap().scan_id,
        refreshed.directory_aggregate().unwrap().scan_id
    );
    assert_eq!(
        refreshed
            .directory_aggregate()
            .unwrap()
            .apparent_logical_bytes,
        sweepx_model::ByteValue::Known {
            value: sweepx_model::DecimalU128::new(
                fs::symlink_metadata(target.join("payload"))
                    .unwrap()
                    .len()
                    .into()
            )
        }
    );
    assert!(
        !refreshed
            .candidate
            .blockers
            .iter()
            .any(|blocker| blocker == "historical_cache")
    );
    fs::remove_file(root.join("a/Cargo.toml")).unwrap();
    let revision = warm.refresh_all().unwrap();
    let removed = drain(&warm, revision);
    assert!(matches!(
        removed.first().unwrap().kind,
        JunkSessionEventKind::Started {
            scope: JunkSessionScope::All
        }
    ));
    assert!(removed.iter().any(|event| matches!(event.kind,
        JunkSessionEventKind::Removed { key: old } if old == key)));
    shutdown(&warm);
    let last = JunkSession::start(request()).unwrap();
    let final_events = drain(&last, JunkSessionRevision(1));
    assert!(!final_events.iter().any(|event| matches!(
        event.kind,
        JunkSessionEventKind::Candidate {
            state: JunkSessionCandidateState::Historical,
            ..
        }
    )));
    assert!(
        crate::junk::cache::CacheReader::new(&cache)
            .index(&root)
            .is_some()
    );
    shutdown(&last);
}

#[cfg(target_os = "macos")]
#[test]
fn selected_refresh_preserves_full_cache_generation_and_outside_scope_facts() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let base = fixture_root(&fixture);
    let root = base.join("projects");
    fs::create_dir(&root).unwrap();
    let a = project(&root, "a", b"before");
    let b = project(&root, "b", b"unchanged-sibling");
    let cache = base.join("cache");
    let mut request = JunkSessionRequest::new(vec![root.clone()]);
    request.cache_dir = Some(cache.clone());
    let session = JunkSession::start(request).unwrap();
    let first = current(&drain(&session, JunkSessionRevision(1)));
    assert_eq!(first.len(), 2);
    let key = *first
        .iter()
        .find(|(_, row)| row.observed_native_path().as_ref() == Some(&a))
        .unwrap()
        .0;
    // Compare actual published bytes, including the original cursor. LRU atime changes
    // are permitted; no partial listing or candidate report may replace this generation.
    let published = || {
        fs::read_dir(&cache)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .map(|path| {
                (
                    path.file_name().unwrap().to_owned(),
                    fs::read(path).unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    let before = published();
    assert!(!before.is_empty());
    let old_index = crate::junk::cache::CacheReader::new(&cache)
        .index(&root)
        .unwrap();
    let old_index = serde_json::to_value(old_index).unwrap();
    assert_eq!(
        old_index["listings"][b.to_str().unwrap()]["files"]["payload"],
        serde_json::json!(fs::symlink_metadata(b.join("payload")).unwrap().len())
    );
    fs::write(a.join("payload"), b"larger-current-payload").unwrap();
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
    assert_eq!(current(&events).len(), 1);
    assert_eq!(published(), before);

    // Full refresh still validates the old cursor and restores both current subtrees.
    // This asserts current facts, not an immediate FSEvents hit or enumeration order.
    let revision = session.refresh_all().unwrap();
    let events = drain(&session, revision);
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Complete,
            replaced: true,
            ..
        }
    ));
    let fresh = current(&events);
    assert_eq!(fresh.len(), 2);
    let index = crate::junk::cache::CacheReader::new(&cache)
        .index(&root)
        .unwrap();
    let index = serde_json::to_value(index).unwrap();
    for path in [&a, &b] {
        let row = fresh
            .values()
            .find(|row| row.observed_native_path().as_ref() == Some(path))
            .unwrap();
        let expected: u128 = fs::read_dir(path)
            .unwrap()
            .map(|entry| u128::from(fs::symlink_metadata(entry.unwrap().path()).unwrap().len()))
            .sum();
        assert_eq!(row.logical_bytes(), &sweepx_platform::known_u128(expected));
        let payload = path.join("payload");
        assert_eq!(
            index["listings"][path.to_str().unwrap()]["files"]["payload"],
            serde_json::json!(fs::symlink_metadata(payload).unwrap().len())
        );
    }
    shutdown(&session);
}

#[cfg(target_os = "macos")]
#[test]
fn preview_cancellation_preserves_history_until_complete_full_refresh() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let base = fixture_root(&fixture);
    let root = base.join("projects");
    fs::create_dir(&root).unwrap();
    project(&root, "a", b"payload");
    let cache = base.join("cache");
    let request = || {
        let mut request = JunkSessionRequest::new(vec![root.clone()]);
        request.cache_dir = Some(cache.clone());
        request.limits.max_events = 1;
        request
    };
    let cold = JunkSession::start(request()).unwrap();
    drain(&cold, JunkSessionRevision(1));
    shutdown(&cold);
    fs::remove_file(root.join("a/Cargo.toml")).unwrap();
    let session = JunkSession::start(request()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let key = loop {
        assert!(Instant::now() < deadline);
        if let Some(event) = session
            .next_event_timeout(Duration::from_millis(100))
            .unwrap()
        {
            match event.kind {
                JunkSessionEventKind::Candidate {
                    key,
                    state: JunkSessionCandidateState::Historical,
                    ..
                } => {
                    session.cancel();
                    break key;
                }
                JunkSessionEventKind::Completed { .. } => panic!("history missing"),
                _ => {}
            }
        }
    };
    let cancelled = drain(&session, JunkSessionRevision(1));
    assert!(matches!(
        cancelled.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Cancelled,
            replaced: false,
            ..
        }
    ));
    assert!(
        !cancelled
            .iter()
            .any(|event| matches!(event.kind, JunkSessionEventKind::Removed { .. }))
    );
    let revision = session.refresh_all().unwrap();
    let refreshed = drain(&session, revision);
    assert!(refreshed.iter().any(|event| matches!(event.kind,
        JunkSessionEventKind::Removed { key: old } if old == key)));
    shutdown(&session);
}

#[cfg(target_os = "macos")]
#[test]
fn cache_publication_failure_keeps_fresh_scan_complete() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let base = fixture_root(&fixture);
    let root = base.join("projects");
    fs::create_dir(&root).unwrap();
    project(&root, "a", b"payload");
    let cache = base.join("cache-file");
    fs::write(&cache, b"not a directory").unwrap();
    let mut request = JunkSessionRequest::new(vec![root]);
    request.cache_dir = Some(cache.clone());
    let session = JunkSession::start(request).unwrap();
    let events = drain(&session, JunkSessionRevision(1));
    assert!(
        events
            .iter()
            .any(|event| matches!(event.kind, JunkSessionEventKind::CacheWarning(_)))
    );
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Complete,
            replaced: true,
            error_count: 0,
            ..
        }
    ));
    assert_eq!(fs::read(cache).unwrap(), b"not a directory");
    shutdown(&session);
}

#[cfg(target_os = "macos")]
#[test]
fn warm_large_directory_finishes_with_fresh_identity_and_independent_logical_total() {
    check_warm_directory(8192);
}

#[cfg(target_os = "macos")]
#[test]
fn progress_log_cap_does_not_make_large_cold_or_cached_directory_partial() {
    // Exceeds the production progress cap without changing production resource limits.
    check_warm_directory(32768);
}

#[cfg(target_os = "macos")]
fn check_warm_directory(file_count: usize) {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let base = fixture_root(&fixture);
    let root = base.join("projects");
    fs::create_dir(&root).unwrap();
    let target = project(&root, "a", b"payload");
    for index in 0..file_count {
        fs::write(target.join(format!("file-{index:05}")), b"01234567").unwrap();
    }
    let lengths: Vec<_> = fs::read_dir(&target)
        .unwrap()
        .map(|entry| u128::from(fs::symlink_metadata(entry.unwrap().path()).unwrap().len()))
        .collect();
    let expected: u128 = lengths.iter().sum();
    let request = || {
        let mut request = JunkSessionRequest::new(vec![root.clone()]);
        request.cache_dir = Some(base.join("cache"));
        request
    };
    let cold = JunkSession::start(request()).unwrap();
    let cold_events = drain(&cold, JunkSessionRevision(1));
    assert!(matches!(
        cold_events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Complete,
            replaced: true,
            error_count: 0,
            ..
        }
    ));
    let initial = current(&cold_events);
    assert_eq!(initial.len(), 1);
    let aggregate = &initial
        .first_key_value()
        .unwrap()
        .1
        .directory_aggregate()
        .unwrap();
    assert_eq!(
        aggregate.apparent_logical_bytes,
        sweepx_model::ByteValue::Known {
            value: sweepx_model::DecimalU128::new(expected)
        }
    );
    assert_eq!(
        aggregate.direct_child_count,
        sweepx_model::CountValue::Known {
            value: sweepx_model::DecimalU128::new(lengths.len() as u128)
        }
    );
    shutdown(&cold);
    let warm = JunkSession::start(request()).unwrap();
    let events = drain(&warm, JunkSessionRevision(1));
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Complete,
            replaced: true,
            ..
        }
    ));
    assert!(events.iter().any(|event| matches!(
        event.kind,
        JunkSessionEventKind::Candidate {
            state: JunkSessionCandidateState::Historical,
            ..
        }
    )));
    let refreshed = current(&events);
    assert_eq!(
        initial.keys().collect::<Vec<_>>(),
        refreshed.keys().collect::<Vec<_>>()
    );
    let (&key, row) = refreshed.first_key_value().unwrap();
    assert_ne!(
        initial[&key].directory_aggregate().unwrap().scan_id,
        row.directory_aggregate().unwrap().scan_id
    );
    assert_eq!(
        row.directory_aggregate().unwrap().apparent_logical_bytes,
        sweepx_model::ByteValue::Known {
            value: sweepx_model::DecimalU128::new(expected)
        }
    );
    shutdown(&warm);
}

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

#[test]
fn own_layout_markers_are_reobserved_on_selected_and_full_refresh() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let base = fixture_root(&fixture);
    let root = base.join("project");
    let target = root.join(".dart_tool");
    fs::create_dir_all(&target).unwrap();
    fs::write(root.join("pubspec.yaml"), b"name: example\n").unwrap();
    fs::write(
        target.join("package_config.json"),
        b"{\"configVersion\":2,\"packages\":[]}",
    )
    .unwrap();
    fs::write(target.join("payload"), b"retained-user-payload").unwrap();
    let request = JunkSessionRequest::new(vec![root.clone()]);
    #[cfg(target_os = "macos")]
    let request = {
        let mut request = request;
        request.cache_dir = Some(base.join("cache"));
        request
    };
    let session = JunkSession::start(request).unwrap();
    let rows = current(&drain(&session, JunkSessionRevision(1)));
    assert_eq!(rows.len(), 1);
    let key = *rows.keys().next().unwrap();
    assert_eq!(rows[&key].candidate.rule_id, "dart.tool-state");
    // A directory called package_config.json cannot replace the ordinary-file marker.
    fs::remove_file(target.join("package_config.json")).unwrap();
    fs::create_dir(target.join("package_config.json")).unwrap();
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
    assert!(current(&events).is_empty());
    assert!(events.iter().any(|event| matches!(event.kind, JunkSessionEventKind::Removed { key: removed } if removed == key)));
    // A subsequent full scan must invalidate old cached candidate facts, not replay the old row.
    let revision = session.refresh_all().unwrap();
    let events = drain(&session, revision);
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Complete,
            ..
        }
    ));
    assert!(current(&events).is_empty());
    fs::remove_dir(target.join("package_config.json")).unwrap();
    fs::write(
        target.join("package_config.json"),
        b"{\"configVersion\":2,\"packages\":[]}",
    )
    .unwrap();
    let revision = session.refresh_all().unwrap();
    let rows = current(&drain(&session, revision));
    assert_eq!(rows.len(), 1);
    assert_eq!(*rows.keys().next().unwrap(), key);
    #[cfg(unix)]
    {
        fs::remove_file(target.join("package_config.json")).unwrap();
        fs::write(base.join("external-config.json"), b"{}").unwrap();
        std::os::unix::fs::symlink(
            base.join("external-config.json"),
            target.join("package_config.json"),
        )
        .unwrap();
        let revision = session.refresh_selected(&[key]).unwrap();
        let events = drain(&session, revision);
        assert!(current(&events).is_empty());
        assert!(events.iter().any(|event| matches!(event.kind, JunkSessionEventKind::Removed { key: removed } if removed == key)));
    }
    assert_eq!(
        fs::read(target.join("payload")).unwrap(),
        b"retained-user-payload"
    );
    shutdown(&session);
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
        a_row.directory_aggregate().unwrap().apparent_logical_bytes,
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
        fresh[a_key]
            .directory_aggregate()
            .unwrap()
            .apparent_logical_bytes,
        sweepx_platform::known_u128(native_length.into())
    );
    assert!(
        !refreshed
            .iter()
            .any(|event| matches!(event.kind, JunkSessionEventKind::Removed { .. }))
    );
    assert!(!fresh.contains_key(b_key));
    assert!(refreshed.iter().all(|event| !matches!(&event.kind, JunkSessionEventKind::Progress { path, .. } if path.starts_with(b.parent().unwrap()))));
    assert_eq!(
        native_root_path(fresh[a_key].candidate.source_entry.as_ref().unwrap()),
        Some(root.clone())
    );

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
fn selected_refresh_keeps_ancestor_history_and_repeated_native_lineage_without_sibling_work() {
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture_root(&fixture);
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    let ancestor = root.join("target");
    fs::create_dir(&ancestor).unwrap();
    fs::write(ancestor.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    let selected = ancestor.join("target");
    fs::create_dir(&selected).unwrap();
    fs::write(selected.join("payload"), b"before").unwrap();
    let sibling = project(&root, "sibling", b"untouched");
    for index in 0..128 {
        fs::write(sibling.join(format!("noise-{index}")), b"outside scope").unwrap();
    }
    let session = JunkSession::start(JunkSessionRequest::new(vec![root.clone()])).unwrap();
    let initial = drain(&session, JunkSessionRevision(1));
    let rows = current(&initial);
    let key_for = |path: &Path| {
        *rows
            .iter()
            .find(|(_, row)| row.observed_native_path().as_deref() == Some(path))
            .unwrap()
            .0
    };
    let selected_key = key_for(&selected);
    let ancestor_key = key_for(&ancestor);
    let sibling_key = key_for(&sibling);
    for payload in [
        b"after local refresh".as_slice(),
        b"second independent refresh".as_slice(),
    ] {
        fs::write(selected.join("payload"), payload).unwrap();
        let revision = session.refresh_selected(&[selected_key]).unwrap();
        let events = drain(&session, revision);
        assert!(matches!(
            events.last().unwrap().kind,
            JunkSessionEventKind::Completed {
                outcome: JunkSessionOutcome::Complete,
                replaced: true,
                ..
            }
        ));
        assert!(events.iter().any(|event| matches!(event.kind, JunkSessionEventKind::Invalidated { key } if key == ancestor_key)));
        assert!(events.iter().all(|event| !matches!(event.kind, JunkSessionEventKind::Invalidated { key } | JunkSessionEventKind::Removed { key } if key == sibling_key)));
        let fresh = current(&events);
        assert_eq!(
            fresh.keys().copied().collect::<Vec<_>>(),
            vec![selected_key]
        );
        let entry = fresh[&selected_key]
            .candidate
            .source_entry
            .as_ref()
            .unwrap();
        assert_eq!(native_root_path(entry), Some(root.clone()));
        assert!(entry.executable_native_locator().unwrap().is_some());
        let length = fs::read_dir(&selected)
            .unwrap()
            .map(|entry| u128::from(fs::symlink_metadata(entry.unwrap().path()).unwrap().len()))
            .sum();
        assert_eq!(
            fresh[&selected_key].logical_bytes(),
            &sweepx_platform::known_u128(length)
        );
        assert!(events.iter().all(|event| !matches!(&event.kind, JunkSessionEventKind::Progress { path, .. } if path.starts_with(sibling.parent().unwrap()))));
    }
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
    request.limits.scan.max_progress_events = 0;
    // Neither retained log can explain incompleteness; live failure/boundary observations
    // still prevent removing old candidates under genuine metadata pressure.
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
    // Pressure must be inside the selected subtree. Unrelated siblings are deliberately
    // omitted by local refresh and no longer consume its required classification metadata.
    for index in 0..256 {
        fs::create_dir(target.join(format!("extra-{index}"))).unwrap();
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
        fs::remove_dir(target.join(format!("extra-{index}"))).unwrap();
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

#[test]
fn dart_content_is_current_on_selected_refresh_and_never_trash_authority() {
    use crate::junk::format::ProjectFormatStatus;
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    #[cfg(target_os = "linux")]
    let owner = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let owner = tempfile::tempdir().unwrap();
    let base = fixture_root(&owner);
    let root = base.join("project");
    fs::create_dir_all(root.join(".dart_tool")).unwrap();
    fs::write(root.join("pubspec.yaml"), b"name: example\n").unwrap();
    let file = root.join(".dart_tool/package_config.json");
    let body = br#"{"configVersion":2,"packages":[{"name":"example","rootUri":"../","packageUri":"lib/"}],"generator":"pub","generatorVersion":"3.6.0"}"#;
    fs::write(&file, body).unwrap();
    let mut request = JunkSessionRequest::new(vec![root]);
    request.include_platform_rules = false;
    #[cfg(target_os = "macos")]
    {
        request.cache_dir = Some(base.join("cache"));
    }
    let session = JunkSession::start(request).unwrap();
    let events = drain(&session, JunkSessionRevision(1));
    let rows = current(&events);
    assert_eq!(rows.len(), 1);
    let key = *rows.keys().next().unwrap();
    assert!(rows[&key].complete());
    assert_eq!(
        rows[&key].candidate.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Recognized
    );
    assert!(rows[&key].candidate.project_execution_blocker().is_some());
    assert!(events.iter().any(|e| matches!(&e.kind,
        JunkSessionEventKind::Candidate { state: JunkSessionCandidateState::Base, row, .. }
        if row.candidate.project_format.as_ref().is_some_and(|f| f.status == ProjectFormatStatus::NotChecked))));
    fs::write(&file, vec![b'x'; body.len()]).unwrap();
    let revision = session.refresh_selected(&[key]).unwrap();
    let rows = current(&drain(&session, revision));
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[&key].candidate.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Invalid
    );
    assert_eq!(rows[&key].candidate.confidence.as_deref(), Some("low"));
    assert!(rows[&key].complete());
    assert!(rows[&key].candidate.project_execution_blocker().is_some());
    // Full revisions also reread contents, including rows whose filesystem cache is validated.
    fs::write(&file, body).unwrap();
    let revision = session.refresh_all().unwrap();
    let rows = current(&drain(&session, revision));
    assert_eq!(
        rows[&key].candidate.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Recognized
    );
    assert_eq!(fs::read(&file).unwrap(), body);
}

#[test]
fn legacy_svelte_content_changes_are_reobserved_in_selected_and_full_revisions() {
    use crate::junk::format::ProjectFormatStatus;
    use sweepx_fixtures::project_junk::{SVELTEKIT_AMBIENT, SVELTEKIT2_CONFIG};
    let _serial = SESSION_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    #[cfg(target_os = "linux")]
    let owner = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let owner = tempfile::tempdir().unwrap();
    let base = fixture_root(&owner);
    let root = base.join("project");
    fs::create_dir_all(root.join(".svelte-kit")).unwrap();
    fs::write(root.join("svelte.config.js"), "export default {}\n").unwrap();
    let config = root.join(".svelte-kit/tsconfig.json");
    let ambient = root.join(".svelte-kit/ambient.d.ts");
    fs::write(&config, SVELTEKIT2_CONFIG).unwrap();
    fs::write(&ambient, SVELTEKIT_AMBIENT).unwrap();
    let mut request = JunkSessionRequest::new(vec![root]);
    request.include_platform_rules = false;
    #[cfg(target_os = "macos")]
    {
        request.cache_dir = Some(base.join("cache"));
    }
    let session = JunkSession::start(request).unwrap();
    let first = current(&drain(&session, JunkSessionRevision(1)));
    assert_eq!(first.len(), 1);
    let key = *first.keys().next().unwrap();
    assert_eq!(
        first[&key]
            .candidate
            .project_format
            .as_ref()
            .unwrap()
            .status,
        ProjectFormatStatus::Recognized
    );
    assert!(first[&key].candidate.project_execution_blocker().is_some());
    let changed = SVELTEKIT_AMBIENT.replace("$env/static/private", "$env/static/custom_");
    assert_eq!(changed.len(), SVELTEKIT_AMBIENT.len());
    fs::write(&ambient, changed.as_bytes()).unwrap();
    let revision = session.refresh_selected(&[key]).unwrap();
    let rows = current(&drain(&session, revision));
    assert_eq!(rows.len(), 1);
    assert!(rows[&key].complete());
    assert_eq!(
        rows[&key].candidate.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Unknown
    );
    assert_eq!(rows[&key].candidate.confidence.as_deref(), Some("low"));
    fs::write(&ambient, SVELTEKIT_AMBIENT).unwrap();
    let revision = session.refresh_all().unwrap();
    let rows = current(&drain(&session, revision));
    assert_eq!(
        rows[&key].candidate.project_format.as_ref().unwrap().status,
        ProjectFormatStatus::Recognized
    );
    assert!(rows[&key].candidate.project_execution_blocker().is_some());
    assert_eq!(fs::read(config).unwrap(), SVELTEKIT2_CONFIG.as_bytes());
}

#[test]
fn incomplete_tool_discovery_keeps_positive_rows_and_partial_terminal_state() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture_root(&fixture);
    let target = project(&root, "project", b"positive-row");
    let mut request = JunkSessionRequest::new(vec![root.clone()]);
    request.include_platform_rules = true;
    let shared = Arc::new(Shared::new(request.limits));
    let job = Job {
        revision: JunkSessionRevision(1),
        selected: None,
        cancel: CancellationToken::new(),
    };
    let mut writer = Writer::new(Arc::clone(&shared), job.revision, job.cancel.clone());
    let mut worker = Worker {
        request,
        session_id: "controlled-incomplete-tool-discovery".into(),
        current: Rows::new(),
        preview_keys: BTreeSet::new(),
        scan_roots: Vec::new(),
    };
    worker
        .run_with_discovery(&job, &mut writer, |_| {
            let rule = super::super::platform::load_platform_junk_rules()
                .unwrap()
                .into_iter()
                .find(|rule| rule.root_kind == "npm_reported_cache")
                .unwrap();
            let cancel = CancellationToken::new();
            cancel.cancel();
            let evidence = super::super::platform::PlatformJunkEvidence::precompute_with_cancel(
                std::slice::from_ref(&rule),
                cancel,
            );
            assert!(evidence.layout_failure().is_none());
            assert_eq!(
                evidence.tool_discovery_failure(),
                Some(crate::tools::ToolDiscoveryFailure::Cancelled)
            );
            Ok((
                PlatformJunkSetup {
                    rules: vec![rule],
                    evidence,
                },
                Vec::new(),
            ))
        })
        .unwrap();
    let session = JunkSession { shared };
    let events = drain(&session, job.revision);
    assert!(events.iter().any(|event| matches!(&event.kind, JunkSessionEventKind::Error(failure) if failure.code == "discovery_incomplete")));
    assert!(matches!(
        events.last().unwrap().kind,
        JunkSessionEventKind::Completed {
            outcome: JunkSessionOutcome::Partial,
            ..
        }
    ));
    let rows = current(&events);
    assert_eq!(rows.len(), 1);
    let row = rows.values().next().unwrap();
    assert_eq!(row.observed_native_path().as_ref(), Some(&target));
    assert_eq!(
        row.logical_bytes(),
        &sweepx_platform::known_u128(u128::from(
            fs::symlink_metadata(target.join("payload")).unwrap().len()
        ))
    );
    assert_eq!(fs::read(target.join("payload")).unwrap(), b"positive-row");
    session.close();
}
