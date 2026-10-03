use super::*;
use std::fs;
use sweepx_platform::ScanResourceLimits;

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
fn context() -> CoreContext {
    CoreContext::new(LocaleResolution::new(
        Locale::EnUs,
        sweepx_i18n::LocaleSource::Explicit,
    ))
}
fn options() -> DuplicateOptions {
    DuplicateOptions {
        minimum_logical_bytes: 0.into(),
        ..Default::default()
    }
}
fn scan(
    roots: Vec<PathBuf>,
    limits: ScanResourceLimits,
    options: &DuplicateOptions,
    cancel: &CancellationToken,
) -> ScanSuccess {
    scan_with_store_options(
        &context(),
        &ScanRequest {
            roots,
            state_dir: None,
        },
        Option::<&MemorySnapshotStore>::None,
        ScannerOptions {
            resource_limits: limits,
            ..Default::default()
        },
        None,
        None,
        None,
        Some(FileAnalysisObservation {
            options: FileAnalysisOptions::Duplicates(options),
            cancel,
            sink: None,
        }),
        ScanProjection::Materialized,
    )
    .unwrap()
    .scan
}
fn report(result: &ScanSuccess) -> DuplicateReport {
    let mut value = result.output.data["duplicates"].clone();
    for group in value["groups"].as_array_mut().unwrap() {
        group["files"] = decamelize_json_keys(group["files"].take());
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn observer_streams_verified_groups_but_cancelled_scope_and_json_have_no_live_authority() {
    struct Sink {
        cancel: CancellationToken,
        groups: Vec<DuplicateGroup>,
    }
    impl FileAnalysisSink for Sink {
        fn on_duplicate_group(&mut self, group: &DuplicateGroup) {
            self.groups.push(group.clone());
            self.cancel.cancel();
        }
    }
    let (_fixture, root) = fixture();
    fs::write(root.join("one"), b"same payload").unwrap();
    fs::write(root.join("two"), b"same payload").unwrap();
    let cancel = CancellationToken::new();
    let mut sink = Sink {
        cancel: cancel.clone(),
        groups: Vec::new(),
    };
    let result = scan_file_analysis_with_observer(
        &context(),
        &ScanRequest {
            roots: vec![root.clone()],
            state_dir: None,
        },
        Option::<&MemorySnapshotStore>::None,
        FileAnalysisOptions::Duplicates(&options()),
        &cancel,
        &mut sink,
    )
    .unwrap();
    assert_eq!(result.output.status, OutputStatus::Cancelled);
    assert_eq!(sink.groups.len(), 1);
    let group = &sink.groups[0];
    assert_eq!(group.files.len(), group.live_observations.len());
    let expected_hash = format!("{:x}", Sha256::digest(fs::read(root.join("one")).unwrap()));
    assert_eq!(group.sha256, expected_hash);
    assert!(
        group
            .live_observations
            .iter()
            .all(|stamp| stamp.logical_bytes.0 == 12)
    );
    assert!(
        result.output.data["duplicates"]["groups"][0]
            .get("liveObservations")
            .is_none()
    );
    let restored = report(&result);
    assert!(restored.groups[0].live_observations.is_empty());
    assert_eq!(restored.groups[0].files, group.files);
    assert!(!restored.complete);
}

#[test]
fn native_duplicates_use_all_observations_before_listing_limits_and_full_bytes_after_sample_collisions()
 {
    let (_fixture, root) = fixture();
    let payload = vec![b'x'; 16_101];
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("one"), &payload).unwrap();
    fs::write(root.join("nested/two"), &payload).unwrap();
    fs::hard_link(root.join("one"), root.join("alias")).unwrap();
    let mut different = payload.clone();
    different[8192] = b'y';
    fs::write(root.join("collision"), &different).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("one"), root.join("link")).unwrap();
    let result = scan(
        vec![root.clone()],
        ScanResourceLimits {
            max_retained_entries: 1,
            max_progress_events: 0,
            max_retained_boundaries: 0,
            ..Default::default()
        },
        &options(),
        &CancellationToken::new(),
    );
    assert_eq!(
        result.output.status,
        OutputStatus::Partial,
        "ordinary listing limit remains separate"
    );
    let report = report(&result);
    assert!(
        report.complete,
        "{:?}; aggregates={:?}; errors={:?}",
        report.incomplete_reasons, result.summary.aggregates, result.summary.boundaries
    );
    assert_eq!(report.groups.len(), 1);
    assert_eq!(report.groups[0].files.len(), 2);
    assert_eq!(report.hard_link_aliases_excluded.0, 1);
    let objects: BTreeSet<_> = report.groups[0]
        .files
        .iter()
        .map(|file| {
            serde_json::to_string(&file.identity.as_ref().unwrap().platform_file_identity).unwrap()
        })
        .collect();
    assert_eq!(objects.len(), 2);
    for file in &report.groups[0].files {
        assert_eq!(fs::read(&file.display_path).unwrap(), payload);
    }
    assert!(
        report.groups[0]
            .files
            .iter()
            .all(|file| !file.display_path.ends_with("collision"))
    );
    assert!(
        report.read_budget_charged_bytes.0 >= 3 * payload.len() as u128,
        "same samples require complete content reads"
    );
    assert_eq!(fs::read(root.join("collision")).unwrap(), different);
}

#[test]
fn native_duplicate_budget_cancellation_and_traversal_gaps_remain_explicit() {
    let (_fixture, root) = fixture();
    fs::write(root.join("one"), b"abc").unwrap();
    fs::write(root.join("two"), b"abc").unwrap();
    let limited = scan(
        vec![root.clone()],
        ScanResourceLimits::default(),
        &DuplicateOptions {
            max_read_bytes: 1,
            ..options()
        },
        &CancellationToken::new(),
    );
    assert_eq!(limited.output.status, OutputStatus::Partial);
    let limited = report(&limited);
    assert!(limited.groups.is_empty());
    assert!(
        limited
            .incomplete_reasons
            .contains(&sweepx_analysis::DuplicateIncompleteReason::ReadLimit)
    );
    assert_eq!(limited.read_operations.0, 0);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let cancelled = scan(
        vec![root.clone()],
        ScanResourceLimits::default(),
        &options(),
        &cancel,
    );
    assert_eq!(cancelled.output.status, OutputStatus::Cancelled);
    assert!(
        report(&cancelled)
            .incomplete_reasons
            .contains(&sweepx_analysis::DuplicateIncompleteReason::Cancelled)
    );
    let truncated = scan(
        vec![root],
        ScanResourceLimits {
            max_directory_entries: 1,
            max_progress_events: 0,
            max_retained_boundaries: 0,
            ..Default::default()
        },
        &options(),
        &CancellationToken::new(),
    );
    assert!(
        report(&truncated)
            .incomplete_reasons
            .contains(&sweepx_analysis::DuplicateIncompleteReason::TraversalIncomplete)
    );
}

#[test]
fn duplicate_groups_span_original_roots_and_public_options_fail_before_admission() {
    let (_fixture, root) = fixture();
    fs::create_dir(root.join("a")).unwrap();
    fs::create_dir(root.join("b")).unwrap();
    fs::write(root.join("a/one"), b"abc").unwrap();
    fs::write(root.join("b/two"), b"abc").unwrap();
    let result = scan_duplicates_with_store(
        &context(),
        &ScanRequest {
            roots: vec![root.join("a"), root.join("b")],
            state_dir: None,
        },
        Option::<&MemorySnapshotStore>::None,
        &options(),
        &CancellationToken::new(),
    )
    .unwrap();
    let report = report(&result);
    assert!(report.complete);
    assert_eq!(report.groups.len(), 1);
    assert_eq!(
        report.groups[0].sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(matches!(
        scan_duplicates_with_store(
            &context(),
            &ScanRequest {
                roots: vec![PathBuf::from("relative")],
                state_dir: None
            },
            Option::<&MemorySnapshotStore>::None,
            &DuplicateOptions {
                max_files: 0,
                ..options()
            },
            &CancellationToken::new()
        ),
        Err(CoreError::InvalidDuplicateOptions(_))
    ));
}
