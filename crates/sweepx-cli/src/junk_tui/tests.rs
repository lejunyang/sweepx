use super::*;
use std::fs;
use std::time::{Duration, Instant};

// These fixtures test row/refresh contracts, not process-wide session admission. Hold this gate
// until each test has explicitly observed worker exit so default harness parallelism cannot
// consume the production four-session allowance or inherit a closing worker from another test.
static SESSION_FIXTURE_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn directory_inspection_drills_native_children_without_promoting_project_trash() {
    use sweepx_tui::{
        BrowserAction, BrowserControl, BrowserModel, BrowserReducer, DetailRescanBrowserReducer,
        DetailRescanProvider, DetailRescanState,
    };
    struct Shared(Arc<dyn DetailRescanProvider>);
    impl DetailRescanProvider for Shared {
        fn prepare_detail_rescan(&self) {
            self.0.prepare_detail_rescan();
        }
        fn rescan_detail(
            &self,
            request: &sweepx_tui::DetailRescanRequest,
        ) -> sweepx_tui::DetailRescanResult {
            self.0.rescan_detail(request)
        }
        fn cancel_detail_rescan(&self) {
            self.0.cancel_detail_rescan();
        }
    }
    fn finish(reducer: &impl BrowserReducer, model: &mut BrowserModel) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            reducer.poll_background(model);
            if matches!(
                model.current_detail_rescan_state(),
                Some(DetailRescanState::Refreshed { .. } | DetailRescanState::Stale { .. })
            ) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!(
            "inspection did not finish: {:?}",
            model.current_detail_rescan_state()
        );
    }
    let _gate = SESSION_FIXTURE_GATE.lock().unwrap();
    let fixture = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = fs::canonicalize(fixture.path()).unwrap();
    #[cfg(windows)]
    let root = fixture.path().to_path_buf();
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    fs::create_dir_all(root.join("target/debug/incremental")).unwrap();
    fs::write(root.join("target/debug/incremental/payload"), b"12345").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("Cargo.toml"), root.join("target/link")).unwrap();
    let mut provider =
        Provider::new(JunkSession::start(JunkSessionRequest::new(vec![root.clone()])).unwrap());
    complete(&mut provider);
    let row = provider
        .rows
        .values()
        .find(|row| row.row.candidate.rule_id == "rust.target")
        .unwrap()
        .clone();
    assert!(!row.report_allows_trash());
    let inspection = provider.inspect(&row.key).unwrap();
    assert_eq!(
        inspection.directory.identity,
        row.row.candidate.source_entry.as_ref().unwrap().identity
    );
    let mut model = BrowserModel::from_progressive_inspection(
        Locale::EnUs,
        inspection.directory,
        HumanSizeUnit::Bytes,
        ScanSort::Path,
    )
    .unwrap();
    let reducer = DetailRescanBrowserReducer::new(Shared(inspection.provider)).unwrap();
    reducer.reduce(&mut model, BrowserAction::EnterDirectory);
    finish(&reducer, &mut model);
    let expected: BTreeSet<_> = fs::read_dir(root.join("target"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let observed: BTreeSet<_> = model
        .visible_rows()
        .iter()
        .map(|row| row.label().to_string())
        .collect();
    assert_eq!(observed, expected);
    #[cfg(unix)]
    assert!(
        !model
            .visible_rows()
            .iter()
            .find(|row| row.label() == "link")
            .unwrap()
            .can_enter()
    );
    assert_eq!(model.selected_row().unwrap().label(), "debug");
    assert_eq!(
        reducer.reduce(&mut model, BrowserAction::TrashSelected),
        BrowserControl::Continue
    );
    reducer.reduce(&mut model, BrowserAction::ToggleReviewPath);
    let review = model.review_paths().map(str::to_owned).collect::<Vec<_>>();
    reducer.reduce(&mut model, BrowserAction::EnterDirectory);
    finish(&reducer, &mut model);
    assert_eq!(model.selected_row().unwrap().label(), "incremental");
    reducer.reduce(&mut model, BrowserAction::EnterDirectory);
    finish(&reducer, &mut model);
    let file = model
        .visible_rows()
        .iter()
        .find(|row| row.label() == "payload")
        .unwrap();
    assert!(!file.can_enter());
    assert_eq!(
        file.entry().logical_bytes,
        sweepx_platform::known_u128(u128::from(
            fs::symlink_metadata(root.join("target/debug/incremental/payload"))
                .unwrap()
                .len()
        ))
    );
    assert_eq!(
        model.review_paths().collect::<Vec<_>>(),
        review.iter().map(String::as_str).collect::<Vec<_>>()
    );
    reducer.reduce(&mut model, BrowserAction::ReturnToParent);
    assert_eq!(
        model.current_directory(),
        Some(root.join("target/debug").to_str().unwrap())
    );
    drop(reducer);
    assert!(
        provider
            .trash(std::slice::from_ref(&row.key))
            .unwrap_err()
            .contains("unverified")
    );
    provider.historical.insert(row.key.clone());
    assert!(provider.inspect(&row.key).is_err());
    provider.historical.clear();
    let inspection = provider.inspect(&row.key).unwrap();
    fs::rename(root.join("target"), root.join("old-target")).unwrap();
    fs::create_dir(root.join("target")).unwrap();
    let mut changed = BrowserModel::from_progressive_inspection(
        Locale::EnUs,
        inspection.directory,
        HumanSizeUnit::Bytes,
        ScanSort::Path,
    )
    .unwrap();
    let reducer = DetailRescanBrowserReducer::new(Shared(inspection.provider)).unwrap();
    reducer.reduce(&mut changed, BrowserAction::EnterDirectory);
    finish(&reducer, &mut changed);
    assert!(matches!(
        changed.current_detail_rescan_state(),
        Some(DetailRescanState::Stale {
            failure: sweepx_tui::DetailRescanFailure::IdentityMismatch,
            ..
        })
    ));
    assert!(changed.visible_rows().is_empty());
    drop(reducer);
    assert_eq!(
        fs::read(root.join("old-target/debug/incremental/payload")).unwrap(),
        b"12345"
    );
    provider.close();
    assert!(
        provider
            .session
            .wait_for_worker_exit(Duration::from_secs(3))
            .unwrap()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn temporary_reports_keep_logical_bytes_and_refuse_generic_trash_then_refresh_all() {
    let _session_guard = SESSION_FIXTURE_GATE.lock().unwrap();
    use sweepx_core::junk::linux_temp::{
        LinuxTempCandidate, LinuxTempDiscovery, LinuxTempMeasurement, report_candidates,
    };
    use sweepx_core::junk::session::JunkSessionFacts;
    let fixture = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(fixture.path()).unwrap();
    let path = root.join("ordinary-temporary-file");
    fs::write(&path, b"preserve-temporary-payload").unwrap();
    let metadata = fs::symlink_metadata(&path).unwrap();
    // This fixture tests report presentation and action routing, not eligibility. Deliberately
    // different allocation evidence prevents logical display from silently using report size.
    let measurement = LinuxTempMeasurement {
        top: metadata.clone(),
        allocated_bytes: 8192,
        logical_bytes: u128::from(metadata.len()),
        entries: BTreeMap::new(),
        fifo_inodes: BTreeSet::new(),
        entry_count: 1,
        last_accessed: metadata.accessed().unwrap(),
        last_modified: metadata.modified().unwrap(),
        last_status_change: metadata.modified().unwrap(),
    };
    let discovery = LinuxTempDiscovery {
        candidates: vec![LinuxTempCandidate {
            path: path.clone(),
            measurement: measurement.clone(),
        }],
        complete: true,
        incomplete_reason: None,
    };
    let rule = sweepx_core::junk::platform::load_platform_junk_rules()
        .unwrap()
        .into_iter()
        .find(|rule| rule.root_kind == "linux_tmp")
        .unwrap();
    let candidate = report_candidates(&rule, &discovery).remove(0);
    let row = Arc::new(JunkSessionCandidate {
        candidate,
        facts: JunkSessionFacts::LinuxTemporary {
            logical_bytes: sweepx_platform::known_u128(u128::from(metadata.len())),
            measurement: Arc::new(measurement),
        },
    });
    assert!(row.complete());
    assert!(row.directory_aggregate().is_none());
    assert_eq!(row.observed_native_path().as_ref(), Some(&path));
    assert_eq!(
        row.logical_bytes(),
        &sweepx_platform::known_u128(u128::from(metadata.len()))
    );
    assert!(
        row.revalidate_native_binding(&CancellationToken::new(), Default::default())
            .is_err()
    );
    assert!(
        crate::trash_command::trash_session_candidate(&row, &CancellationToken::new())
            .unwrap_err()
            .contains("quarantine")
    );
    let session = JunkSession::start(JunkSessionRequest::new(vec![root])).unwrap();
    let mut provider = Provider::new(session);
    complete(&mut provider);
    // Reuse an opaque key from a controlled scan as a fixture. Action routing must inspect the
    // typed facts rather than assuming the key itself supplies directory authority.
    fs::write(
        fixture.path().join("Cargo.toml"),
        b"[workspace]\nmembers=[]\n",
    )
    .unwrap();
    fs::create_dir(fixture.path().join("target")).unwrap();
    provider.refresh(&[]).unwrap();
    complete(&mut provider);
    let native_key = provider.rows.values().next().unwrap().native_key;
    let key = "controlled-temporary-presentation".to_string();
    assert!(matches!(
        provider.admit(Arc::new(Row {
            key: key.clone(),
            native_key,
            revision: provider.revision,
            current: true,
            preview: false,
            row,
        })),
        Some(JunkEvent::Candidate { .. })
    ));
    assert!(
        provider
            .trash(std::slice::from_ref(&key))
            .unwrap_err()
            .contains("quarantine")
    );
    assert!(provider.trash.is_none());
    provider.refresh(std::slice::from_ref(&key)).unwrap();
    let events = complete(&mut provider);
    assert!(matches!(
        events.first().unwrap(),
        JunkEvent::Started { keys: None, .. }
    ));
    assert_eq!(fs::read(path).unwrap(), b"preserve-temporary-payload");
    provider.close();
    assert!(
        provider
            .session
            .wait_for_worker_exit(Duration::from_secs(3))
            .unwrap()
    );
}

fn complete(provider: &mut Provider) -> Vec<JunkEvent> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut events = Vec::new();
    loop {
        assert!(Instant::now() < deadline, "session did not finish");
        if let Some(event) = provider.poll() {
            let done = matches!(event, JunkEvent::Completed { .. });
            events.push(event);
            if done {
                return events;
            }
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn adapter_fixture() -> (tempfile::TempDir, Provider, Vec<Arc<Row>>) {
    let fixture = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = fs::canonicalize(fixture.path()).unwrap();
    #[cfg(not(unix))]
    let root = fixture.path().to_path_buf();
    for name in ["a", "b", "c"] {
        let project = root.join(name);
        fs::create_dir_all(project.join("target")).unwrap();
        fs::write(project.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
        fs::write(
            project.join("target").join("payload"),
            b"preserve adapter payload",
        )
        .unwrap();
    }
    let mut provider =
        Provider::new(JunkSession::start(JunkSessionRequest::new(vec![root])).unwrap());
    complete(&mut provider);
    let rows: Vec<_> = provider.rows.values().cloned().collect();
    assert_eq!(rows.len(), 3);
    for row in &rows {
        assert!(matches!(
            provider.translate_event(
                1,
                JunkSessionEventKind::Removed {
                    key: row.native_key
                }
            ),
            Some(JunkEvent::Removed { .. })
        ));
    }
    assert!(provider.rows.is_empty() && provider.historical.is_empty());
    assert_eq!(provider.retained, 0);
    (fixture, provider, rows)
}

fn candidate_event(row: &Arc<Row>, state: JunkSessionCandidateState) -> JunkSessionEventKind {
    JunkSessionEventKind::Candidate {
        key: row.native_key,
        state,
        rules_digest: [0; 32],
        row: Arc::clone(&row.row),
    }
}

fn terminal_event(outcome: JunkSessionOutcome, replaced: bool) -> JunkSessionEventKind {
    JunkSessionEventKind::Completed {
        outcome,
        replaced,
        candidate_count: 1,
        error_count: 0,
    }
}

fn stop_adapter_fixture(provider: &mut Provider, rows: &[Arc<Row>]) {
    for row in rows {
        assert_eq!(
            fs::read(row.row.observed_native_path().unwrap().join("payload")).unwrap(),
            b"preserve adapter payload"
        );
    }
    provider.close();
    assert_eq!(provider.retained, 0);
    assert!(provider.rows.is_empty() && provider.historical.is_empty());
    assert!(
        provider
            .session
            .wait_for_worker_exit(Duration::from_secs(3))
            .unwrap()
    );
}

#[test]
fn private_registry_keeps_cancelled_rows_under_one_cross_revision_row_budget() {
    let _session_guard = SESSION_FIXTURE_GATE.lock().unwrap();
    let (_fixture, mut provider, rows) = adapter_fixture();
    provider.limits.rows = 1;
    provider.translate_event(
        2,
        JunkSessionEventKind::Started {
            scope: JunkSessionScope::All,
        },
    );
    assert!(matches!(
        provider.translate_event(
            2,
            candidate_event(&rows[0], JunkSessionCandidateState::Base)
        ),
        Some(JunkEvent::Candidate { current: false, .. })
    ));
    provider.translate_event(2, terminal_event(JunkSessionOutcome::Cancelled, false));
    let retained = provider.retained;
    assert!(retained > 0 && provider.historical.contains(&rows[0].key));

    for (revision, row, final_outcome) in [
        (3, &rows[1], JunkSessionOutcome::Complete),
        (4, &rows[2], JunkSessionOutcome::Cancelled),
        (5, &rows[1], JunkSessionOutcome::Failed),
    ] {
        provider.translate_event(
            revision,
            JunkSessionEventKind::Started {
                scope: JunkSessionScope::All,
            },
        );
        assert_eq!(
            provider.retained, retained,
            "Started cannot renew retained-row capacity"
        );
        for attempt in 0..20 {
            let event = provider.translate_event(
                revision,
                candidate_event(row, JunkSessionCandidateState::Base),
            );
            assert_eq!(matches!(event, Some(JunkEvent::Error { .. })), attempt == 0);
            if attempt > 0 {
                assert!(event.is_none());
            }
            provider.translate_event(
                revision,
                JunkSessionEventKind::Invalidated {
                    key: row.native_key,
                },
            );
        }
        let terminal = provider.translate_event(revision, terminal_event(final_outcome, true));
        let expected = match final_outcome {
            JunkSessionOutcome::Complete => JunkOutcome::Partial,
            JunkSessionOutcome::Cancelled => JunkOutcome::Cancelled,
            _ => JunkOutcome::Failed,
        };
        assert!(
            matches!(terminal, Some(JunkEvent::Completed { outcome, replaced: false, .. }) if outcome == expected)
        );
        assert_eq!(provider.rows.len(), 1);
        assert_eq!(provider.retained, retained);
        assert_eq!(provider.historical, BTreeSet::from([rows[0].key.clone()]));
        assert!(provider.rejected && !provider.complete && !provider.busy);
        assert_eq!(
            provider
                .trash(std::slice::from_ref(&rows[0].key))
                .unwrap_err(),
            "complete the scan or refresh first"
        );
        assert!(provider.trash.is_none());
    }
    stop_adapter_fixture(&mut provider, &rows);
}

#[test]
fn replacement_debits_old_bytes_and_rejected_growth_keeps_old_evidence() {
    let _session_guard = SESSION_FIXTURE_GATE.lock().unwrap();
    let (_fixture, mut provider, rows) = adapter_fixture();
    provider.translate_event(
        2,
        JunkSessionEventKind::Started {
            scope: JunkSessionScope::All,
        },
    );
    let mut bulky = (*rows[0].row).clone();
    bulky.candidate.evidence = "bounded old evidence".repeat(1024);
    let key = rows[0].native_key;
    provider.translate_event(
        2,
        JunkSessionEventKind::Candidate {
            key,
            state: JunkSessionCandidateState::Current,
            rules_digest: [0; 32],
            row: Arc::new(bulky),
        },
    );
    let bulky_bytes = provider.retained;
    provider.translate_event(
        2,
        candidate_event(&rows[0], JunkSessionCandidateState::Current),
    );
    let original_bytes = provider.retained;
    assert!(
        original_bytes < bulky_bytes,
        "a smaller replacement must release capacity"
    );
    for _ in 0..20 {
        provider.translate_event(
            2,
            candidate_event(&rows[0], JunkSessionCandidateState::Current),
        );
        assert_eq!(
            provider.retained, original_bytes,
            "same-key replacement is not cumulative"
        );
    }
    provider.translate_event(2, terminal_event(JunkSessionOutcome::Complete, true));
    assert!(provider.complete);
    let old = Arc::clone(&provider.rows[&rows[0].key]);
    provider.limits.bytes = original_bytes + 512;
    provider.translate_event(
        3,
        JunkSessionEventKind::Started {
            scope: JunkSessionScope::All,
        },
    );
    let mut oversized = (*rows[0].row).clone();
    oversized.candidate.evidence = "new larger evidence".repeat(4096);
    assert!(matches!(
        provider.translate_event(
            3,
            JunkSessionEventKind::Candidate {
                key,
                state: JunkSessionCandidateState::Current,
                rules_digest: [0; 32],
                row: Arc::new(oversized),
            }
        ),
        Some(JunkEvent::Error { .. })
    ));
    assert!(Arc::ptr_eq(&old, &provider.rows[&rows[0].key]));
    assert_eq!(provider.retained, original_bytes);
    assert!(provider.historical.contains(&rows[0].key));
    assert!(matches!(
        provider.translate_event(3, terminal_event(JunkSessionOutcome::Complete, true)),
        Some(JunkEvent::Completed {
            outcome: JunkOutcome::Partial,
            replaced: false,
            ..
        })
    ));
    assert!(!provider.complete && provider.trash(std::slice::from_ref(&rows[0].key)).is_err());
    provider.translate_event(3, JunkSessionEventKind::Removed { key });
    assert_eq!(provider.retained, 0);
    assert!(provider.rows.is_empty() && provider.historical.is_empty());
    stop_adapter_fixture(&mut provider, &rows);
}

#[test]
fn cancelled_base_selection_refreshes_all_without_promoting_its_native_key() {
    let _session_guard = SESSION_FIXTURE_GATE.lock().unwrap();
    let fixture = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = fs::canonicalize(fixture.path()).unwrap();
    #[cfg(not(unix))]
    let root = fixture.path().to_path_buf();
    fs::create_dir(root.join("target")).unwrap();
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    fs::write(
        root.join("target").join("payload"),
        b"base remains unmodified",
    )
    .unwrap();
    let mut request = JunkSessionRequest::new(vec![root.clone()]);
    request.limits.max_events = 1;
    let mut provider = Provider::new(JunkSession::start(request).unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    let key = loop {
        assert!(Instant::now() < deadline, "base observation did not arrive");
        match provider.poll() {
            Some(JunkEvent::Candidate {
                current: false,
                historical: false,
                row,
                ..
            }) => {
                break row.key().to_string();
            }
            Some(JunkEvent::Completed { .. }) => {
                panic!("scan finished before its base observation")
            }
            _ => std::thread::sleep(Duration::from_millis(1)),
        }
    };
    // One reliable slot holds Formats or Git before Current can be published. Cancel before
    // draining another phase; no sleep or producer timing is used as completion evidence.
    provider.cancel();
    let events = complete(&mut provider);
    assert!(matches!(
        events.last(),
        Some(JunkEvent::Completed {
            outcome: JunkOutcome::Cancelled,
            replaced: false,
            ..
        })
    ));
    assert!(!provider.rows[&key].current && !provider.rows[&key].preview);
    assert!(provider.trash(std::slice::from_ref(&key)).is_err());
    provider.refresh(std::slice::from_ref(&key)).unwrap();
    let events = complete(&mut provider);
    assert!(matches!(
        events.first(),
        Some(JunkEvent::Started { keys: None, .. })
    ));
    assert!(matches!(
        events.last(),
        Some(JunkEvent::Completed {
            outcome: JunkOutcome::Complete,
            replaced: true,
            ..
        })
    ));
    assert!(provider.rows[&key].current);
    assert_eq!(
        fs::read(root.join("target").join("payload")).unwrap(),
        b"base remains unmodified"
    );
    provider.close();
    assert!(
        provider
            .session
            .wait_for_worker_exit(Duration::from_secs(3))
            .unwrap()
    );
}

#[test]
fn confirmed_moves_remove_descendants_and_invalidate_ancestor_accounting_without_native_mutation() {
    let _session_guard = SESSION_FIXTURE_GATE.lock().unwrap();
    let fixture = tempfile::TempDir::new().unwrap();
    #[cfg(unix)]
    let root = fs::canonicalize(fixture.path()).unwrap();
    #[cfg(not(unix))]
    let root = fixture.path().to_path_buf();
    let outer = root.join("target");
    let selected = outer.join("target");
    let descendant = selected.join("target");
    fs::create_dir_all(&descendant).unwrap();
    for parent in [&root, &outer, &selected] {
        fs::write(parent.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    }
    fs::write(descendant.join("payload"), b"native payload retained").unwrap();
    let mut provider =
        Provider::new(JunkSession::start(JunkSessionRequest::new(vec![root])).unwrap());
    complete(&mut provider);
    let key_for = |path: &std::path::Path| {
        provider
            .rows
            .iter()
            .find(|(_, row)| row.row.observed_native_path().as_deref() == Some(path))
            .map(|(key, _)| key.clone())
            .unwrap()
    };
    let ancestor_key = key_for(&outer);
    let selected_key = key_for(&selected);
    let child_key = key_for(&descendant);
    let ancestor_cost = provider.rows[&ancestor_key].registry_cost();
    provider.confirmed_moves(std::slice::from_ref(&selected_key));
    assert!(!provider.rows.contains_key(&selected_key));
    assert!(!provider.rows.contains_key(&child_key));
    assert!(provider.rows.contains_key(&ancestor_key));
    assert!(provider.historical.contains(&ancestor_key));
    assert_eq!(provider.retained, ancestor_cost);
    assert_eq!(provider.pending.len(), 3);
    assert!(provider.refresh(&[]).is_err(), "drain reconciliation first");
    assert!(provider.trash(std::slice::from_ref(&ancestor_key)).is_err());
    assert!(provider.pending.iter().any(|event| matches!(event, JunkEvent::Candidate { historical: true, row, .. } if row.key() == ancestor_key)));
    for _ in 0..3 {
        assert!(provider.poll().is_some());
    }
    assert!(provider.pending.is_empty());
    assert_eq!(provider.pending.capacity(), 0);
    assert_eq!(provider.retained, ancestor_cost);
    assert_eq!(
        fs::read(descendant.join("payload")).unwrap(),
        b"native payload retained"
    );
    provider.close();
    assert!(
        provider
            .session
            .wait_for_worker_exit(Duration::from_secs(3))
            .unwrap()
    );
}

#[test]
fn local_refresh_keeps_ancestor_bindings_but_requires_refresh_before_trash() {
    let _session_guard = SESSION_FIXTURE_GATE.lock().unwrap();
    let fixture = tempfile::TempDir::new().unwrap();
    #[cfg(unix)]
    let root = fs::canonicalize(fixture.path()).unwrap();
    #[cfg(not(unix))]
    let root = fixture.path().to_path_buf();
    let ancestor = root.join("target");
    let selected = ancestor.join("target");
    fs::create_dir_all(&selected).unwrap();
    for parent in [&root, &ancestor] {
        fs::write(parent.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    }
    fs::write(selected.join("payload"), b"before").unwrap();
    let mut provider =
        Provider::new(JunkSession::start(JunkSessionRequest::new(vec![root])).unwrap());
    complete(&mut provider);
    let key_for = |path: &std::path::Path| {
        provider
            .rows
            .iter()
            .find(|(_, row)| row.row.observed_native_path().as_deref() == Some(path))
            .unwrap()
            .0
            .clone()
    };
    let ancestor_key = key_for(&ancestor);
    let selected_key = key_for(&selected);
    fs::write(selected.join("payload"), b"after local refresh").unwrap();
    provider
        .refresh(std::slice::from_ref(&selected_key))
        .unwrap();
    let events = complete(&mut provider);
    assert!(
        events.iter().any(
            |event| matches!(event, JunkEvent::Invalidated { key, .. } if key == &ancestor_key)
        )
    );
    assert!(provider.historical.contains(&ancestor_key));
    assert!(
        !provider.rows[&ancestor_key].preview,
        "retained bindings differ from unvalidated cache previews"
    );
    assert!(provider.trash(std::slice::from_ref(&ancestor_key)).is_err());
    provider
        .refresh(std::slice::from_ref(&ancestor_key))
        .unwrap();
    let events = complete(&mut provider);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, JunkEvent::Started { keys: Some(_), .. })),
        "refresh the retained ancestor scope, not every original root"
    );
    assert!(!provider.historical.contains(&ancestor_key));
    assert_eq!(
        fs::read(selected.join("payload")).unwrap(),
        b"after local refresh"
    );
    provider.close();
    assert!(
        provider
            .session
            .wait_for_worker_exit(Duration::from_secs(3))
            .unwrap()
    );
}

#[test]
fn bridge_refreshes_current_native_evidence_and_refuses_replaced_object_before_trash() {
    let _session_guard = SESSION_FIXTURE_GATE.lock().unwrap();
    let fixture = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = fs::canonicalize(fixture.path()).unwrap();
    #[cfg(not(unix))]
    let root = fixture.path().to_path_buf();
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    let target = root.join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("payload"), b"original").unwrap();
    let mut provider =
        Provider::new(JunkSession::start(JunkSessionRequest::new(vec![root.clone()])).unwrap());
    let events = complete(&mut provider);
    assert!(matches!(
        events.last().unwrap(),
        JunkEvent::Completed {
            outcome: JunkOutcome::Complete,
            replaced: true,
            ..
        }
    ));
    let key = provider.rows.keys().next().unwrap().clone();
    assert_eq!(
        provider.rows[&key]
            .row
            .directory_aggregate()
            .unwrap()
            .apparent_logical_bytes,
        sweepx_platform::known_u128(8)
    );
    fs::write(target.join("payload"), b"updated-current").unwrap();
    provider.refresh(std::slice::from_ref(&key)).unwrap();
    let events = complete(&mut provider);
    assert!(
        matches!(events.first().unwrap(), JunkEvent::Started { revision: 2, keys: Some(keys) } if keys == std::slice::from_ref(&key))
    );
    assert_eq!(
        provider.rows[&key]
            .row
            .directory_aggregate()
            .unwrap()
            .apparent_logical_bytes,
        sweepx_platform::known_u128(u128::from(
            fs::symlink_metadata(target.join("payload")).unwrap().len()
        ))
    );
    let project_row = provider.rows[&key].row.clone();
    assert!(!provider.rows[&key].report_allows_trash());
    assert_eq!(
        crate::trash_command::trash_session_candidate(&project_row, &CancellationToken::new())
            .unwrap_err(),
        "project_ownership_not_verified"
    );
    // A controlled platform-like row isolates the native preflight contract below the project
    // guard. Both following cases change identity and must reject before a real Trash call.
    let mut old = (*project_row).clone();
    old.candidate.rule_id = "test.native-cache".into();
    // This lower-layer platform-style fixture tests stale native identities, independently of
    // project manifest/ownership requirements. It must not carry the original Rust context.
    old.candidate.project_context = None;
    old.candidate.execution_policy =
        sweepx_core::junk::candidate::JunkExecutionPolicy::NativeRevalidationRequired;
    let old = Arc::new(old);
    fs::rename(&target, root.join("retained-old-target")).unwrap();
    fs::create_dir(&target).unwrap();
    fs::write(target.join("payload"), b"replacement").unwrap();
    // The real native preflight rejects before reaching the host Trash backend, preserving both.
    let failure =
        crate::trash_command::trash_session_candidate(&old, &CancellationToken::new()).unwrap_err();
    assert!(failure.starts_with("refresh_binding_changed:"), "{failure}");
    assert_eq!(fs::read(target.join("payload")).unwrap(), b"replacement");
    assert_eq!(
        fs::read(root.join("retained-old-target/payload")).unwrap(),
        b"updated-current"
    );
    #[cfg(unix)]
    {
        fs::rename(&target, root.join("retained-replacement")).unwrap();
        std::os::unix::fs::symlink(root.join("retained-replacement"), &target).unwrap();
        let failure =
            crate::trash_command::trash_session_candidate(&old, &CancellationToken::new())
                .unwrap_err();
        assert!(failure.starts_with("refresh_binding_changed:"), "{failure}");
        assert_eq!(
            fs::read(root.join("retained-replacement/payload")).unwrap(),
            b"replacement"
        );
    }
    provider.close();
    assert!(
        provider
            .session
            .wait_for_worker_exit(Duration::from_secs(3))
            .unwrap()
    );
}

#[test]
fn changed_directory_scope_marks_existing_descendants_without_affecting_sibling_rows() {
    let _session_guard = SESSION_FIXTURE_GATE.lock().unwrap();
    let (_fixture, mut provider, rows) = adapter_fixture();
    for row in &rows {
        provider.translate_event(2, candidate_event(row, JunkSessionCandidateState::Current));
    }
    provider.historical.clear();
    let path = rows[0].row.observed_native_path().unwrap();
    let expected: BTreeSet<_> = provider
        .rows
        .iter()
        .filter(|(_, row)| {
            row.row
                .observed_native_path()
                .is_some_and(|p| p.starts_with(&path))
        })
        .map(|(key, _)| key.clone())
        .collect();
    let event = provider
        .translate_event(
            3,
            JunkSessionEventKind::Started {
                scope: JunkSessionScope::Directories(vec![path].into()),
            },
        )
        .unwrap();
    let JunkEvent::Started {
        keys: Some(keys), ..
    } = event
    else {
        panic!("directory scope must carry existing affected keys");
    };
    assert_eq!(keys.into_iter().collect::<BTreeSet<_>>(), expected);
    assert_eq!(provider.historical, expected);
    assert!(
        provider
            .rows
            .keys()
            .any(|key| !provider.historical.contains(key))
    );
    stop_adapter_fixture(&mut provider, &rows);
}
