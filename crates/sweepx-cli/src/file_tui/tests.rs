use super::*;
use std::fs;
use std::path::Path;
use sweepx_i18n::{LocaleResolution, LocaleSource};

// These tests share the real process-wide native worker quota. The mutex controls fixture
// concurrency, not filesystem ordering or production cancellation behavior.
static TEST_SESSION: Mutex<()> = Mutex::new(());

fn fixture() -> (tempfile::TempDir, PathBuf) {
    #[cfg(target_os = "linux")]
    let fixture = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let fixture = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = fixture.path().canonicalize().unwrap();
    #[cfg(windows)]
    let root = fixture.path().to_path_buf();
    (fixture, root)
}

fn provider(root: PathBuf, options: Options) -> Provider {
    Provider::new(
        CoreContext::new(LocaleResolution::new(Locale::EnUs, LocaleSource::Explicit)),
        ScanRequest {
            roots: vec![root],
            state_dir: None,
        },
        None,
        options,
    )
    .unwrap()
}

fn finish(provider: &mut Provider) -> Vec<JunkEvent> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut events = Vec::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "analysis did not publish a terminal result"
        );
        if let Some(event) = provider.poll() {
            let done = matches!(event, JunkEvent::Completed { .. });
            events.push(event);
            if done {
                return events;
            }
        } else {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

fn duplicate_options() -> Options {
    Options::Duplicates(DuplicateOptions {
        minimum_logical_bytes: 0.into(),
        ..Default::default()
    })
}

fn duplicates(root: &Path) -> Provider {
    fs::write(root.join("one"), b"same payload").unwrap();
    fs::write(root.join("two"), b"same payload").unwrap();
    let mut provider = provider(root.to_path_buf(), duplicate_options());
    let events = finish(&mut provider);
    assert!(provider.complete, "{}", events.len());
    assert_eq!(provider.rows.len(), 2);
    provider
}

#[test]
fn live_ranking_replaces_preview_and_refresh_removes_obsolete_identity() {
    let _guard = TEST_SESSION.lock().unwrap();
    let (_fixture, root) = fixture();
    fs::create_dir(root.join("nested")).unwrap();
    for (name, size) in [("small", 8), ("nested/large", 4096), ("medium", 512)] {
        fs::write(root.join(name), vec![b'x'; size]).unwrap();
    }
    let mut provider = provider(
        root.clone(),
        Options::Large(LargeFileOptions {
            minimum_logical_bytes: 0.into(),
            max_files: 2,
            ..Default::default()
        }),
    );
    assert!(provider.trash(&["arbitrary label".into()]).is_err());
    let events = finish(&mut provider);
    assert!(provider.complete);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, JunkEvent::Candidate { .. }))
    );
    let files: BTreeSet<_> = provider
        .rows
        .values()
        .map(|row| {
            let path = PathBuf::from(row.path());
            let measured = fs::symlink_metadata(&path).unwrap().len();
            assert_eq!(
                row.logical_bytes(),
                &sweepx_platform::known_u128(u128::from(measured))
            );
            assert!(row.complete());
            (path.strip_prefix(&root).unwrap().to_path_buf(), measured)
        })
        .collect();
    assert_eq!(
        files,
        BTreeSet::from([
            (PathBuf::from("medium"), 512),
            (PathBuf::from("nested/large"), 4096)
        ])
    );
    let old = provider
        .rows
        .values()
        .find(|row| PathBuf::from(row.path()).file_name().unwrap() == "large")
        .unwrap()
        .clone();
    // Preserve the old inode so the replacement oracle cannot accidentally reuse its identity.
    fs::rename(root.join("nested/large"), root.join("small-old-object")).unwrap();
    fs::write(root.join("nested/large"), vec![b'z'; 8192]).unwrap();
    fs::remove_file(root.join("medium")).unwrap();
    provider.refresh(std::slice::from_ref(&old.key)).unwrap();
    finish(&mut provider);
    assert!(provider.complete);
    assert!(!provider.rows.contains_key(&old.key));
    assert!(
        provider
            .rows
            .values()
            .any(|row| row.path() == old.path() && row.key != old.key)
    );
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    assert!(
        super::super::trash_command::trash_observed_file(&old.entry, None, None, &cancelled)
            .is_err()
    );
    assert_eq!(
        fs::read(root.join("nested/large")).unwrap(),
        vec![b'z'; 8192]
    );
}

#[test]
fn duplicate_rows_use_full_content_oracle_exclude_aliases_and_require_explicit_keeper() {
    let _guard = TEST_SESSION.lock().unwrap();
    let (_fixture, root) = fixture();
    fs::write(root.join("one"), b"same payload").unwrap();
    fs::write(root.join("two"), b"same payload").unwrap();
    fs::hard_link(root.join("one"), root.join("alias")).unwrap();
    fs::write(root.join("unique"), b"diff payload").unwrap();
    let mut provider = provider(root.clone(), duplicate_options());
    finish(&mut provider);
    assert!(provider.complete);
    assert_eq!(provider.rows.len(), 2);
    let rows: Vec<_> = provider.rows.values().cloned().collect();
    let hash = format!("{:x}", Sha256::digest(fs::read(root.join("one")).unwrap()));
    for row in &rows {
        assert!(row.group.as_ref().unwrap().ends_with(&hash));
        assert!(row.stamp.is_some());
        assert!(!row.keeper);
    }
    assert_eq!(
        fs::read(rows[0].path()).unwrap(),
        fs::read(rows[1].path()).unwrap()
    );
    assert!(
        provider
            .trash(&[rows[0].key.clone()])
            .unwrap_err()
            .contains("keeper")
    );
    provider.toggle_keeper(&rows[1].key).unwrap();
    while provider.poll().is_some() {}
    assert!(provider.rows[&rows[1].key].keeper);
    assert!(!provider.rows[&rows[1].key].report_allows_trash());
    assert!(provider.selected(&[rows[1].key.clone()]).is_err());
    assert!(
        preflight(
            &[rows[0].clone()],
            &[rows[1].clone()],
            &provider.options,
            &CancellationToken::new()
        )
        .is_ok()
    );
    assert!(
        preflight(
            &rows,
            &[rows[1].clone()],
            &provider.options,
            &CancellationToken::new()
        )
        .is_err()
    );
    assert!(preflight(&rows, &[], &provider.options, &CancellationToken::new()).is_err());
    provider.toggle_keeper(&rows[1].key).unwrap();
    while provider.poll().is_some() {}
    assert!(provider.keepers.is_empty());
    assert!(provider.rows.values().all(|row| !row.keeper));
}

#[test]
fn changed_keeper_blocks_content_preflight_and_final_native_trash_validation() {
    let _guard = TEST_SESSION.lock().unwrap();
    let (_fixture, root) = fixture();
    let provider = duplicates(&root);
    let rows: Vec<_> = provider.rows.values().cloned().collect();
    // Same logical length, same inode, different bytes: identity and length alone are insufficient.
    fs::write(rows[1].path(), b"user payload").unwrap();
    assert!(
        preflight(
            &[rows[0].clone()],
            &[rows[1].clone()],
            &provider.options,
            &CancellationToken::new()
        )
        .is_err()
    );
    assert!(
        super::super::trash_command::trash_observed_file(
            &rows[0].entry,
            rows[0].stamp.as_ref(),
            Some((&rows[1].entry, rows[1].stamp.as_ref().unwrap())),
            &CancellationToken::new()
        )
        .is_err()
    );
    assert_eq!(fs::read(rows[0].path()).unwrap(), b"same payload");
    assert_eq!(fs::read(rows[1].path()).unwrap(), b"user payload");
}

#[test]
fn replacing_selected_object_or_parent_refuses_native_action_before_trash() {
    let _guard = TEST_SESSION.lock().unwrap();
    let (_fixture, root) = fixture();
    let provider = duplicates(&root);
    let row = provider.rows.values().next().unwrap();
    let path = PathBuf::from(row.path());
    fs::rename(&path, root.join("original-object")).unwrap();
    fs::write(&path, b"same payload").unwrap();
    assert!(
        super::super::trash_command::trash_observed_file(
            &row.entry,
            None,
            None,
            &CancellationToken::new()
        )
        .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), b"same payload");
    let moved_root = root.with_file_name(format!(
        "{}-retained",
        root.file_name().unwrap().to_string_lossy()
    ));
    fs::rename(&root, &moved_root).unwrap();
    fs::create_dir(&root).unwrap();
    fs::write(&path, b"user payload").unwrap();
    let result = super::super::trash_command::trash_observed_file(
        &row.entry,
        None,
        None,
        &CancellationToken::new(),
    );
    // Always restore fixture ownership, including a failed assertion's payload.
    fs::remove_dir_all(&root).unwrap();
    fs::rename(&moved_root, &root).unwrap();
    assert!(result.is_err());
}

#[test]
fn cancelled_session_reports_terminal_state_and_never_enables_actions() {
    let _guard = TEST_SESSION.lock().unwrap();
    let (_fixture, root) = fixture();
    fs::write(root.join("one"), b"same payload").unwrap();
    let mut provider = provider(root, duplicate_options());
    provider.cancel();
    let events = finish(&mut provider);
    assert!(!provider.complete);
    assert!(events.iter().any(|event| matches!(
        event,
        JunkEvent::Completed {
            outcome: JunkOutcome::Cancelled,
            ..
        }
    )));
    assert!(provider.trash(&["one".into()]).is_err());
}

#[test]
fn refresh_preserves_native_keys_but_clears_keeper_authority_and_loaded_stamps() {
    let _guard = TEST_SESSION.lock().unwrap();
    let (_fixture, root) = fixture();
    let mut provider = duplicates(&root);
    let rows: Vec<_> = provider.rows.values().cloned().collect();
    provider.toggle_keeper(&rows[0].key).unwrap();
    assert!(
        provider.toggle_keeper(&rows[1].key).is_err(),
        "updates must drain before another owned batch"
    );
    while provider.poll().is_some() {}
    provider.refresh(&[]).unwrap();
    finish(&mut provider);
    assert_eq!(
        provider.live_keys,
        rows.iter().map(|row| row.key.clone()).collect()
    );
    assert!(provider.keepers.is_empty());
    assert!(provider.rows.values().all(|row| !row.keeper));
    let group = DuplicateGroup {
        sha256: rows[0]
            .group
            .as_ref()
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .into(),
        logical_bytes: 12.into(),
        files: rows.iter().map(|row| (*row.entry).clone()).collect(),
        live_observations: Vec::new(),
    };
    let loaded = Row::new(&group.files[0], Some((&group, 0)), true, Locale::ZhCn);
    assert!(
        !loaded.complete(),
        "JSON-restored hashes lack live execution stamps"
    );
    assert!(loaded.evidence().contains("内容相同"));
}

#[test]
fn resource_gaps_stay_partial_and_repeated_retention_failures_keep_one_error() {
    let _guard = TEST_SESSION.lock().unwrap();
    let (_fixture, root) = fixture();
    fs::write(root.join("one"), b"same payload").unwrap();
    fs::write(root.join("two"), b"same payload").unwrap();
    let mut limited = provider(
        root.clone(),
        Options::Duplicates(DuplicateOptions {
            minimum_logical_bytes: 0.into(),
            max_read_bytes: 1,
            ..Default::default()
        }),
    );
    let events = finish(&mut limited);
    assert!(!limited.complete);
    assert!(events.iter().any(|event| matches!(
        event,
        JunkEvent::Completed {
            outcome: JunkOutcome::Partial,
            ..
        }
    )));
    assert!(limited.trash(&["untrusted path".into()]).is_err());
    drop(limited);
    let mut provider = duplicates(&root);
    let mut row = (**provider.rows.values().next().unwrap()).clone();
    row.key = "budget-refused-row".into();
    let row = Arc::new(row);
    provider.retained = MAX_BYTES;
    provider.complete = false;
    provider.busy = true;
    for _ in 0..100 {
        provider.admit(row.clone());
    }
    assert_eq!(provider.pending.len(), 1);
    assert!(provider.rejected && provider.cancel.is_cancelled());
    assert!(!provider.rows.contains_key(&row.key));
    assert_eq!(fs::read(root.join("one")).unwrap(), b"same payload");
}

#[test]
fn closing_releases_a_backpressured_sender_and_progress_keeps_utf8_bounds() {
    let (sender, receiver) = sync_channel(1);
    let closed = Arc::new(AtomicBool::new(false));
    let progress = Arc::new(Mutex::new(None));
    let mut sink = Sink {
        sender,
        closed: closed.clone(),
        progress: progress.clone(),
        preview: Arc::new(Mutex::new(None)),
        last_progress: None,
        cancel: CancellationToken::new(),
        rejected: false,
        locale: Locale::ZhCn,
    };
    sink.on_progress("content", 8, &"中文".repeat(2000));
    let value = progress.lock().unwrap().take().unwrap();
    assert!(value.path.len() <= 2048);
    assert!(value.path.chars().all(|ch| ch == '中' || ch == '文'));
    sink.send(Packet::Large(Vec::new()));
    let (started, ready) = sync_channel(1);
    let (done, returned) = sync_channel(1);
    let worker = std::thread::spawn(move || {
        started.send(()).unwrap();
        sink.send(Packet::Group(Vec::new()));
        done.send(()).unwrap();
    });
    ready.recv_timeout(Duration::from_secs(1)).unwrap();
    closed.store(true, Ordering::Release);
    returned.recv_timeout(Duration::from_secs(1)).unwrap();
    worker.join().unwrap();
    assert!(matches!(receiver.try_recv(), Ok(Packet::Large(_))));
}

#[test]
fn ranking_snapshots_coalesce_without_occupying_the_reliable_final_result_slot() {
    let _guard = TEST_SESSION.lock().unwrap();
    let (_fixture, root) = fixture();
    let provider = duplicates(&root);
    let entry = (*provider.rows.values().next().unwrap().entry).clone();
    let (sender, receiver) = sync_channel(1);
    let preview = Arc::new(Mutex::new(None));
    let mut sink = Sink {
        sender,
        closed: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(Mutex::new(None)),
        preview: preview.clone(),
        last_progress: None,
        cancel: CancellationToken::new(),
        rejected: false,
        locale: Locale::EnUs,
    };
    let mut report = LargeFileReport {
        options: LargeFileOptions::default(),
        files: vec![entry],
        observed_files: 1.into(),
        qualifying_files: 1.into(),
        unknown_logical_files: 0.into(),
        top_k_limited: false,
        complete: false,
        incomplete_reasons: Vec::new(),
    };
    for ordinal in 0..100 {
        report.files[0].display_path = format!("display-only-{ordinal}");
        sink.on_large_files(&report);
    }
    assert!(matches!(
        receiver.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    assert_eq!(
        preview.lock().unwrap().as_ref().unwrap()[0].path(),
        "display-only-99"
    );
    report.complete = true;
    sink.on_large_files_final(&report);
    let Packet::Large(rows) = receiver.try_recv().unwrap() else {
        panic!("reliable final ranking missing")
    };
    assert!(rows[0].complete());
    assert_eq!(rows[0].path(), "display-only-99");
}
