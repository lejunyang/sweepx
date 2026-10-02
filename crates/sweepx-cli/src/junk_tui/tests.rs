use super::*;
use std::fs;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
#[test]
fn temporary_reports_keep_logical_bytes_and_refuse_generic_trash_then_refresh_all() {
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
    provider.rows.insert(
        key.clone(),
        Arc::new(Row {
            key: key.clone(),
            native_key,
            revision: provider.revision,
            current: true,
            preview: false,
            row,
        }),
    );
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

#[test]
fn confirmed_moves_remove_descendants_and_invalidate_ancestor_accounting_without_native_mutation() {
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
    provider.confirmed_moves(std::slice::from_ref(&selected_key));
    assert!(!provider.rows.contains_key(&selected_key));
    assert!(!provider.rows.contains_key(&child_key));
    assert!(provider.rows.contains_key(&ancestor_key));
    assert!(provider.historical.contains(&ancestor_key));
    assert!(provider.pending.iter().any(|event| matches!(event, JunkEvent::Candidate { historical: true, row, .. } if row.key() == ancestor_key)));
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
