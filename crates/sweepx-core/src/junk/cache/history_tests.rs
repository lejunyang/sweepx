use super::*;
use crate::junk::JunkService;
use std::fs;
use sweepx_platform::{CancellationToken, ScanRoot};
use sweepx_scanner::{HostPlatformScanner, Scanner, ScannerOptions};

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    #[cfg(target_os = "linux")]
    let guard = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let guard = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let base = guard.path().canonicalize().unwrap();
    #[cfg(windows)]
    let base = guard.path().to_path_buf();
    let root = base.join("project");
    fs::create_dir_all(root.join("target")).unwrap();
    fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
    fs::write(root.join("target/payload"), b"original").unwrap();
    (guard, root, base.join("cache"))
}

fn capture(root: &Path) -> StoredJunkRoot {
    let service = JunkService::built_in().unwrap();
    let scan = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
        .scan_classified(
            &[ScanRoot::new(root.to_path_buf()).unwrap()],
            &CancellationToken::new(),
            &service,
            None,
        )
        .unwrap();
    let aggregates = scan
        .summary
        .aggregates
        .iter()
        .map(|aggregate| (aggregate.directory_identity.as_str(), aggregate))
        .collect::<BTreeMap<_, _>>();
    let candidates = scan
        .summary
        .entries
        .iter()
        .filter_map(|entry| {
            let id = &entry.validated_identity().unwrap()?.entry_id;
            let candidate = service.interpret(
                scan.decisions.get(id)?,
                entry,
                &aggregates,
                &[],
                &Default::default(),
            )?;
            let mut stored = StoredJunkCandidate::from_candidate(&candidate);
            stored.aggregate = aggregates
                .get(id.as_str())
                .map(|aggregate| (*aggregate).clone());
            Some(stored)
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.len(), 1);
    let mut record = StoredJunkRoot::capture_historical_with_rule_bytes(
        &scan.observed_roots[0],
        candidates,
        None,
        super::super::PROJECT_RULES_JSON.as_bytes(),
        super::super::platform::PLATFORM_JUNK_RULES_JSON.as_bytes(),
    )
    .unwrap();
    record.bind_scope(&[root.to_path_buf()]);
    record
}

#[test]
fn explicit_state_history_refuses_growth_and_preserves_old_record() {
    let (_guard, root, cache) = fixture();
    let state_path = cache.with_file_name("state");
    let state = Directory::open(&state_path, true).unwrap();
    let record = capture(&root);
    write_in_state(&state_path, &record).unwrap();
    let filename = state_path.join("junk-cache").join(record_file_name(&root));
    let previous = fs::read(&filename).unwrap();
    state
        .write_synced_bytes("protected-record", b"keep", 4)
        .unwrap();
    let accounted = sweepx_cache::state_directory::StateWriteSession::capture(&state)
        .unwrap()
        .usage()
        .bytes;
    fs::OpenOptions::new()
        .write(true)
        .open(state_path.join("protected-record"))
        .unwrap()
        .set_len(503_316_480 - (accounted - 4))
        .unwrap();
    let error = write_in_state(&state_path, &record).unwrap_err();
    assert_eq!(
        sweepx_cache::state_directory::resource_limit(&error)
            .unwrap()
            .resource,
        "state_bytes"
    );
    assert_eq!(fs::read(filename).unwrap(), previous);
    assert_eq!(
        fs::metadata(state_path.join("protected-record"))
            .unwrap()
            .len(),
        503_316_480 - (accounted - 4)
    );
    let mut reader = CacheReader::new(&state_path.join("junk-cache"));
    assert!(
        reader
            .historical_roots(std::slice::from_ref(&root))
            .pop()
            .flatten()
            .is_some()
    );
}

#[test]
fn history_preserves_native_facts_but_absent_cursor_and_context_never_become_zero() {
    let (_guard, root, cache) = fixture();
    let record = capture(&root);
    let encoded = serde_json::to_value(&record).unwrap();
    assert!(encoded["since_event_id"].is_null());
    assert!(encoded["classification_context"].is_null());
    assert_eq!(encoded["preview_only"], true);
    assert_eq!(encoded["root_platform"], host_platform());
    let historical = record.candidates[0].clone();
    write(&cache, &record).unwrap();
    let mut reader = CacheReader::new(&cache);
    let loaded = reader
        .historical_roots(std::slice::from_ref(&root))
        .pop()
        .flatten()
        .unwrap();
    assert_eq!(loaded.candidates, record.candidates);
    // An ordinary walk/stat supplies the independent recursive logical-size oracle.
    let length: u128 = fs::read_dir(root.join("target"))
        .unwrap()
        .map(|entry| u128::from(entry.unwrap().metadata().unwrap().len()))
        .sum();
    assert_eq!(
        historical
            .aggregate
            .as_ref()
            .unwrap()
            .apparent_logical_bytes,
        sweepx_platform::known_u128(length)
    );
    fs::write(
        root.join("target/payload"),
        b"a different and much longer payload",
    )
    .unwrap();
    let loaded = CacheReader::new(&cache)
        .historical_roots(std::slice::from_ref(&root))
        .pop()
        .flatten()
        .unwrap();
    assert_eq!(loaded.candidates, record.candidates); // history, never a claim of unchanged contents
    let restored = loaded.into_candidates().pop().unwrap().into_candidate();
    assert_eq!(
        restored.execution_policy,
        super::super::candidate::JunkExecutionPolicy::NotChecked
    );
    assert!(
        restored.activity.is_none() && restored.git.is_none() && restored.project_context.is_none()
    );
    #[cfg(target_os = "macos")]
    {
        assert!(
            CacheReader::new(&cache).roots(std::slice::from_ref(&root), Some(&[0; 32]))[0]
                .is_none()
        );
        let mut contradictory = record;
        contradictory.preview_only = false;
        contradictory.classification_context = Some([0; 32]);
        write(&cache, &contradictory).unwrap();
        assert!(CacheReader::new(&cache).roots(&[root], Some(&[0; 32]))[0].is_none());
    }
}

#[test]
fn rule_platform_scope_replacement_and_linked_ancestors_refuse_history() {
    let (_guard, root, cache) = fixture();
    let record = capture(&root);
    write(&cache, &record).unwrap();
    let edited = format!("{}\n", super::super::PROJECT_RULES_JSON);
    assert!(
        CacheReader::with_rule_bytes(
            &cache,
            edited.as_bytes(),
            super::super::platform::PLATFORM_JUNK_RULES_JSON.as_bytes()
        )
        .historical_roots(std::slice::from_ref(&root))[0]
            .is_none()
    );
    let mut foreign = record.clone();
    foreign.root_platform = if host_platform() == "macos" {
        "linux"
    } else {
        "macos"
    }
    .into();
    write(&cache, &foreign).unwrap();
    assert!(CacheReader::new(&cache).historical_roots(std::slice::from_ref(&root))[0].is_none());
    let mut other_mount = record.clone();
    other_mount.root_mount = u128::MAX.to_string();
    write(&cache, &other_mount).unwrap();
    assert!(CacheReader::new(&cache).historical_roots(std::slice::from_ref(&root))[0].is_none());
    let mut legacy = record.clone();
    legacy.schema = "sweepx.junk-cache/v9".into();
    write(&cache, &legacy).unwrap();
    assert!(CacheReader::new(&cache).historical_roots(std::slice::from_ref(&root))[0].is_none());
    let mut missing_mount = serde_json::to_value(&record).unwrap();
    missing_mount.as_object_mut().unwrap().remove("root_mount");
    assert!(serde_json::from_value::<StoredJunkRoot>(missing_mount).is_err());
    write(&cache, &record).unwrap();
    let nested = root.join("target");
    assert!(CacheReader::new(&cache).historical_roots(&[root.clone(), nested])[0].is_none());
    let original = root.with_file_name("original");
    fs::rename(&root, &original).unwrap();
    fs::create_dir(&root).unwrap();
    assert!(CacheReader::new(&cache).historical_roots(std::slice::from_ref(&root))[0].is_none());
    #[cfg(unix)]
    {
        fs::remove_dir(&root).unwrap();
        std::os::unix::fs::symlink(&original, &root).unwrap();
        assert!(
            CacheReader::new(&cache).historical_roots(std::slice::from_ref(&root))[0].is_none()
        );
        // A linked ancestor can reach the original inode; native admission must still reject it.
        let link = root.with_file_name("alias-parent");
        std::os::unix::fs::symlink(original.parent().unwrap(), &link).unwrap();
        let aliased = link.join("original");
        let mut alias_record = record;
        alias_record.root = aliased.to_str().unwrap().into();
        write(&cache, &alias_record).unwrap();
        assert!(CacheReader::new(&cache).historical_roots(&[aliased])[0].is_none());
    }
}

#[test]
fn root_without_mount_evidence_cannot_publish_history() {
    let (_guard, root, _cache) = fixture();
    let scan = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
        .scan_classified(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
            &JunkService::built_in().unwrap(),
            None,
        )
        .unwrap();
    let mut source = scan.observed_roots[0].clone();
    let unknown =
        sweepx_model::IdentityEvidence::unknown(sweepx_model::ReasonCode::UnknownIdentity);
    source.identity.as_mut().unwrap().volume_or_mount_identity = unknown.clone();
    let locator = source.native_locator.as_mut().unwrap();
    locator.entry.volume_or_mount_identity = unknown.clone();
    locator.scan_root.volume_or_mount_identity = unknown;
    assert!(source.validated_identity().unwrap().is_some());
    assert_eq!(super::super::git::native_path(&source), Some(root));
    assert!(
        StoredJunkRoot::capture_historical_with_rule_bytes(
            &source,
            Vec::new(),
            None,
            super::super::PROJECT_RULES_JSON.as_bytes(),
            super::super::platform::PLATFORM_JUNK_RULES_JSON.as_bytes(),
        )
        .is_err()
    );
}

#[test]
fn cancellation_stops_history_reads_without_charging_the_input_budget() {
    let (_guard, root, cache) = fixture();
    write(&cache, &capture(&root)).unwrap();
    let mut reader = CacheReader::new(&cache);
    let before = reader.remaining_retained_bytes();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(
        reader.historical_roots_scoped_with_cancel(
            std::slice::from_ref(&root),
            std::slice::from_ref(&root),
            &cancel
        )[0]
        .is_none()
    );
    assert_eq!(reader.remaining_retained_bytes(), before);
}
