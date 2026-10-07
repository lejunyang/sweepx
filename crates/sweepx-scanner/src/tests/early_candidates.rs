//! Controlled stream order, independent expected totals, and conservative custom evaluators.

use super::*;

fn enable_fixture_file_lengths(platform: &mut FakePlatform) {
    platform.file_length_proposals = Some(
        platform
            .walk_entries
            .iter()
            .filter_map(|(path, entry)| match entry {
                WalkEntry::File(metadata) => Some((
                    path.clone(),
                    sweepx_platform::CachedFileEntry {
                        path: path.clone(),
                        file_name: metadata.file_name.clone(),
                        logical_bytes: extract_known_u128(&metadata.logical_bytes).unwrap(),
                    },
                )),
                _ => None,
            })
            .collect(),
    );
}

#[test]
fn classified_live_lengths_keep_markers_git_lineage_and_totals_without_file_index() {
    let fixture = |fast| {
        let (mut platform, root, target) = marker_fixture(true);
        let git = root.join(".git");
        platform
            .entries_by_capability
            .get_mut(&1)
            .unwrap()
            .push(DirectoryEntryRecord {
                path: git.clone(),
                file_name: test_native_name(".git"),
            });
        let mut metadata = test_metadata(git.clone(), ".git", EntryKind::File, Some(1));
        metadata.logical_bytes = known_u128(9);
        platform.walk_entries.insert(git, WalkEntry::File(metadata));
        if fast {
            enable_fixture_file_lengths(&mut platform);
        }
        (platform, root, target)
    };
    let classifier = ParentMarker {
        negative: false,
        local: true,
    };
    let (cold_platform, root, target) = fixture(false);
    let cold_calls = Arc::clone(&cold_platform.inspect_calls);
    let cold = Scanner::new(cold_platform, ScannerOptions::default())
        .scan_classified(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
            &classifier,
            None,
        )
        .unwrap();
    let (fast_platform, _, _) = fixture(true);
    let fast_calls = Arc::clone(&fast_platform.inspect_calls);
    let hook_calls = Arc::clone(&fast_platform.file_length_calls);
    let fast = Scanner::new(
        fast_platform,
        ScannerOptions {
            retain_file_index: false,
            ..Default::default()
        },
    )
    .scan_classified(
        &[ScanRoot::new(root.clone()).unwrap()],
        &CancellationToken::new(),
        &classifier,
        None,
    )
    .unwrap();
    assert_eq!(cold_calls.load(Ordering::SeqCst), 6);
    assert_eq!(
        fast_calls.load(Ordering::SeqCst),
        3,
        "two directories and native gitfile only"
    );
    assert_eq!(
        hook_calls.load(Ordering::SeqCst),
        5,
        "gitfile never enters the length hook"
    );
    assert_eq!(fast.decisions, cold.decisions);
    assert_eq!(fast.directory_markers, cold.directory_markers);
    assert_eq!(fast.coverages, cold.coverages);
    assert_eq!(fast.covered_paths, cold.covered_paths);
    assert_eq!(fast.observed_roots, cold.observed_roots);
    assert!(fast.dir_listings.is_empty());
    assert!(!cold.dir_listings.is_empty());
    let cold_aggregate = aggregate_for_path(&cold.summary, &target);
    let fast_aggregate = aggregate_for_path(&fast.summary, &target);
    assert_eq!(fast_aggregate.apparent_logical_bytes, known_u128(17));
    assert_eq!(fast_aggregate.direct_child_count, known_count(1));
    assert_eq!(fast_aggregate.recursive_entry_count, known_count(1));
    assert_eq!(
        fast_aggregate.apparent_logical_bytes,
        cold_aggregate.apparent_logical_bytes
    );
    assert_eq!(fast_aggregate.coverage, cold_aggregate.coverage);
    let gitfile = fast
        .summary
        .entries
        .iter()
        .find(|entry| entry.display_path == root.join(".git").to_string_lossy())
        .unwrap();
    assert_eq!(gitfile.logical_bytes, known_u128(9));
    assert!(gitfile.identity.is_some() && gitfile.native_locator.is_some());
}

#[test]
fn ordinary_scans_and_full_file_observers_bypass_live_length_hook() {
    let (mut platform, root, _) = marker_fixture(true);
    enable_fixture_file_lengths(&mut platform);
    let hook_calls = Arc::clone(&platform.file_length_calls);
    let scanner = Scanner::new(platform, ScannerOptions::default());
    let roots = [ScanRoot::new(root).unwrap()];
    let ordinary = scanner.scan(&roots, &CancellationToken::new()).unwrap();
    assert_eq!(
        ordinary
            .entries
            .iter()
            .filter(|entry| entry.object_type == ObjectType::File)
            .count(),
        3
    );
    assert_eq!(hook_calls.load(Ordering::SeqCst), 0);

    #[derive(Default)]
    struct Files(Vec<ScannedEntry>);
    impl ClassifiedScanObserver for Files {
        fn wants_file_observations(&self) -> bool {
            true
        }
        fn on_entry(&mut self, entry: &ScannedEntry) {
            if entry.object_type == ObjectType::File {
                self.0.push(entry.clone());
            }
        }
    }
    let mut files = Files::default();
    scanner
        .scan_classified_with_observer(
            &roots,
            &CancellationToken::new(),
            &ParentMarker {
                negative: false,
                local: true,
            },
            None,
            &mut files,
        )
        .unwrap();
    assert_eq!(files.0.len(), 3);
    assert!(
        files
            .0
            .iter()
            .all(|entry| entry.identity.is_some() && entry.native_locator.is_some())
    );
    assert_eq!(hook_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn malformed_live_length_proposals_fall_back_to_bound_inspection() {
    let (mut platform, root, target) = marker_fixture(true);
    enable_fixture_file_lengths(&mut platform);
    let proposals = platform.file_length_proposals.as_mut().unwrap();
    let marker = proposals.get_mut(&root.join("Cargo.toml")).unwrap();
    marker.path = root.join("wrong-marker");
    let payload = proposals.get_mut(&target.join("payload")).unwrap();
    payload.file_name = test_native_name("wrong-payload");
    payload.logical_bytes = 999;
    let calls = Arc::clone(&platform.inspect_calls);
    let scan = Scanner::new(platform, ScannerOptions::default())
        .scan_classified(
            &[ScanRoot::new(root).unwrap()],
            &CancellationToken::new(),
            &ParentMarker {
                negative: false,
                local: true,
            },
            None,
        )
        .unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        4,
        "two directories and two invalid proposals"
    );
    assert_eq!(
        scan.decisions.len(),
        1,
        "live fallback preserves required marker"
    );
    assert_eq!(
        aggregate_for_path(&scan.summary, &target).apparent_logical_bytes,
        known_u128(17)
    );
}

#[test]
fn current_file_observer_bypasses_length_only_reuse_and_sees_unretained_files() {
    struct RefusedPlan;
    impl SubtreeReuse for RefusedPlan {
        fn plan_entries(
            &self,
            _dir: &Path,
            _children: &[sweepx_platform::DirectoryEntryRecord],
        ) -> Option<Vec<PlannedEntry>> {
            panic!("file observer requires native observations, not a logical-length-only plan")
        }
    }
    #[derive(Default)]
    struct Files {
        entries: Vec<ScannedEntry>,
        coverage: Vec<(PathBuf, bool)>,
    }
    impl ClassifiedScanObserver for Files {
        fn wants_file_observations(&self) -> bool {
            true
        }
        fn wants_directory_progress(&self) -> bool {
            false
        }
        fn on_entry(&mut self, entry: &ScannedEntry) {
            if entry.object_type == ObjectType::File {
                self.entries.push(entry.clone());
            }
        }
        fn on_directory_coverage(&mut self, path: &Path, coverage: &Coverage) {
            self.coverage.push((path.into(), coverage.complete));
        }
    }
    let (platform, root, _) = marker_fixture(false);
    let mut files = Files::default();
    let result = Scanner::new(platform, ScannerOptions::default())
        .scan_classified_with_observer(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
            &ParentMarker {
                negative: false,
                local: true,
            },
            Some(&RefusedPlan),
            &mut files,
        )
        .unwrap();
    assert!(
        result.summary.entries.is_empty(),
        "no Cargo marker, hence no retained candidates"
    );
    let observed: BTreeSet<_> = files
        .entries
        .iter()
        .map(|entry| PathBuf::from(&entry.display_path))
        .collect();
    assert_eq!(
        observed,
        BTreeSet::from([root.join("target/payload"), root.join("other/payload")])
    );
    assert!(
        files
            .entries
            .iter()
            .all(|entry| entry.logical_bytes == known_u128(17)
                && entry.identity.is_some()
                && entry.native_locator.is_some())
    );
    assert!(files.coverage.contains(&(root, true)));
}

struct LocalBranches;
impl JunkClassifier for LocalBranches {
    fn uses_only_local_markers(&self) -> bool {
        true
    }
    fn classify(
        &self,
        entry: &ScannedEntry,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<String> {
        ObservedBranches.classify(entry, markers)
    }
}

#[derive(Default)]
struct EarlyLog {
    observations: ObservationLog,
    seen: BTreeSet<PathBuf>,
    first_candidate_seen: Option<BTreeSet<PathBuf>>,
    preference: Option<PathBuf>,
    cancel_on_candidate: Option<CancellationToken>,
}
impl ClassifiedScanObserver for EarlyLog {
    fn on_progress(&mut self, root: &Path, event: &ProgressEvent) {
        if let ProgressEvent::EntryObserved { path, .. } = event {
            self.seen.insert(path.clone());
        }
        self.observations.on_progress(root, event);
    }
    fn on_boundary(&mut self, boundary: &BoundaryRecord) {
        self.observations.on_boundary(boundary);
    }
    fn on_directory_progress(&mut self, path: &Path, aggregate: &DirectoryAggregate) {
        self.observations.on_directory_progress(path, aggregate);
    }
    fn on_candidate(&mut self, entry: &ScannedEntry, rule: &str, aggregate: &DirectoryAggregate) {
        self.first_candidate_seen
            .get_or_insert_with(|| self.seen.clone());
        self.observations.on_candidate(entry, rule, aggregate);
        if let Some(cancel) = &self.cancel_on_candidate {
            cancel.cancel();
        }
    }
    fn preferred_directory(&self) -> Option<PathBuf> {
        self.preference.clone()
    }
}

#[test]
fn completed_branch_arrives_before_other_payloads_and_survives_cancellation() {
    let platform = NestedFanOutPlatform::new(8);
    let roots = [ScanRoot::new(platform.root.clone()).unwrap()];
    let cancel = CancellationToken::new();
    let mut log = EarlyLog {
        cancel_on_candidate: Some(cancel.clone()),
        ..Default::default()
    };
    let result = Scanner::new(
        platform,
        ScannerOptions {
            max_workers: 1,
            ..Default::default()
        },
    )
    .scan_classified_with_observer(&roots, &cancel, &LocalBranches, None, &mut log)
    .unwrap();
    assert!(cancel.is_cancelled());
    // Root-end fallback still reports admitted but unvisited candidates as incomplete after
    // cancellation. Only the branch delivered before cancellation is recursively complete.
    assert_eq!(
        log.observations
            .candidates
            .iter()
            .filter(|(_, _, aggregate)| aggregate.coverage.complete)
            .count(),
        1
    );
    let (_, _, aggregate) = &log.observations.candidates[0];
    assert!(aggregate.coverage.complete);
    // This fixture has one 1,024-byte ordinary file and one leaf under each branch.
    assert_eq!(aggregate.apparent_logical_bytes, known_u128(1024));
    assert_eq!(aggregate.recursive_entry_count, known_count(2));
    assert_eq!(
        log.first_candidate_seen
            .as_ref()
            .unwrap()
            .iter()
            .filter(|path| path.file_name() == Some(std::ffi::OsStr::new("payload.bin")))
            .count(),
        1
    );
    assert!(result.summary.aggregates.contains(aggregate));
    assert!(result.summary.progress_retention.cancelled);
}

#[test]
fn local_final_results_match_root_end_classification_without_duplicate_callbacks() {
    let scanner = Scanner::new(NestedFanOutPlatform::new(8), ScannerOptions::default());
    let roots = [ScanRoot::new(scanner.platform.root.clone()).unwrap()];
    let ordinary = scanner
        .scan_classified(&roots, &CancellationToken::new(), &ObservedBranches, None)
        .unwrap();
    let mut log = EarlyLog::default();
    let live = scanner
        .scan_classified_with_observer(
            &roots,
            &CancellationToken::new(),
            &LocalBranches,
            None,
            &mut log,
        )
        .unwrap();
    assert_eq!(live.decisions, ordinary.decisions);
    assert_eq!(live.coverages, ordinary.coverages);
    assert_eq!(live.directory_markers, ordinary.directory_markers);
    assert_eq!(live.covered_paths, ordinary.covered_paths);
    assert_eq!(live.dir_listings, ordinary.dir_listings);
    assert_eq!(live.summary.progress, ordinary.summary.progress);
    assert_eq!(live.summary.boundaries, ordinary.summary.boundaries);
    let by_id = |scan: &ClassifiedScan| {
        scan.summary
            .aggregates
            .iter()
            .map(|aggregate| (aggregate.directory_identity.clone(), aggregate.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(by_id(&live), by_id(&ordinary));
    assert_eq!(log.observations.candidates.len(), 8);
    assert!(log.first_candidate_seen.unwrap().len() < log.seen.len());
}

fn marker_fixture(marker: bool) -> (FakePlatform, PathBuf, PathBuf) {
    let root = test_path("marker-root");
    let target = root.join("target");
    let other = root.join("other");
    let record = |path: &Path| DirectoryEntryRecord {
        path: path.to_path_buf(),
        file_name: test_native_name(path.file_name().unwrap().to_str().unwrap()),
    };
    let mut entries = vec![record(&target), record(&other)];
    let mut walks = BTreeMap::new();
    let mut by_capability = BTreeMap::new();
    for (path, capability) in [(&target, 2), (&other, 3)] {
        let mut metadata = test_metadata(
            path.clone(),
            path.file_name().unwrap().to_str().unwrap(),
            EntryKind::Directory,
            Some(1),
        );
        metadata.identity = Some(EntryIdentity::from_unix(1, capability));
        walks.insert(
            path.clone(),
            WalkEntry::Directory(sweepx_platform::OpenedDirectory {
                metadata,
                handle: FakeDirectoryHandle {
                    path: path.clone(),
                    capability_id: capability,
                    cursor: 0,
                },
            }),
        );
        let payload = path.join("payload");
        let mut metadata = test_metadata(payload.clone(), "payload", EntryKind::File, Some(1));
        metadata.logical_bytes = known_u128(17);
        metadata.identity = Some(EntryIdentity::from_unix(1, capability + 10));
        by_capability.insert(capability, vec![record(&payload)]);
        walks.insert(payload, WalkEntry::File(metadata));
    }
    if marker {
        let path = root.join("Cargo.toml");
        entries.push(record(&path));
        walks.insert(
            path.clone(),
            WalkEntry::File(test_metadata(path, "Cargo.toml", EntryKind::File, Some(1))),
        );
    }
    let mut platform = FakePlatform::new(root.clone(), entries, walks).with_batch_size(1);
    platform.entries_by_capability.extend(by_capability);
    (platform, root, target)
}

struct ParentMarker {
    negative: bool,
    local: bool,
}
impl JunkClassifier for ParentMarker {
    fn needs_file_marker(&self, name: &NativeName) -> bool {
        native_basename_marker(name).as_deref() == Some("Cargo.toml")
    }
    fn uses_only_local_markers(&self) -> bool {
        self.local
    }
    fn classify(
        &self,
        entry: &ScannedEntry,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<String> {
        if native_basename_marker(&entry.native_basename).as_deref() != Some("target") {
            return None;
        }
        let parent = entry.identity.as_ref()?.parent_id.as_ref()?;
        let present = markers
            .get(parent)
            .is_some_and(|names| names.contains("Cargo.toml"));
        (present != self.negative).then(|| "parent-marker".into())
    }
}

#[test]
fn late_parent_marker_prevents_premature_negative_decisions_and_preserves_positive_match() {
    for negative in [false, true] {
        let (platform, root, target) = marker_fixture(true);
        let mut log = EarlyLog {
            preference: Some(target),
            ..Default::default()
        };
        let scan = Scanner::new(
            platform,
            ScannerOptions {
                max_workers: 1,
                ..Default::default()
            },
        )
        .scan_classified_with_observer(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
            &ParentMarker {
                negative,
                local: true,
            },
            None,
            &mut log,
        )
        .unwrap();
        assert_eq!(scan.decisions.len(), usize::from(!negative));
        if !negative {
            let seen = log.first_candidate_seen.unwrap();
            assert!(seen.contains(&root.join("target/payload")));
            assert!(seen.contains(&root.join("Cargo.toml")));
            assert!(!seen.contains(&root.join("other/payload")));
            assert_eq!(
                log.observations.candidates[0].2.apparent_logical_bytes,
                known_u128(17)
            );
        } else {
            assert!(log.observations.candidates.is_empty());
        }
    }
}

#[test]
fn true_parent_marker_absence_is_decided_only_after_parent_enumeration() {
    let (platform, root, target) = marker_fixture(false);
    let mut log = EarlyLog {
        preference: Some(target),
        ..Default::default()
    };
    Scanner::new(
        platform,
        ScannerOptions {
            max_workers: 1,
            ..Default::default()
        },
    )
    .scan_classified_with_observer(
        &[ScanRoot::new(root.clone()).unwrap()],
        &CancellationToken::new(),
        &ParentMarker {
            negative: true,
            local: true,
        },
        None,
        &mut log,
    )
    .unwrap();
    let seen = log.first_candidate_seen.unwrap();
    assert!(
        seen.contains(&root.join("other")),
        "the last parent batch must have committed"
    );
    assert!(
        !seen.contains(&root.join("other/payload")),
        "unrelated subtree remains pending"
    );
}

#[test]
fn custom_evaluator_defaults_to_full_root_markers() {
    let (platform, root, target) = marker_fixture(true);
    let mut log = EarlyLog {
        preference: Some(target),
        ..Default::default()
    };
    Scanner::new(
        platform,
        ScannerOptions {
            max_workers: 1,
            ..Default::default()
        },
    )
    .scan_classified_with_observer(
        &[ScanRoot::new(root.clone()).unwrap()],
        &CancellationToken::new(),
        &ParentMarker {
            negative: false,
            local: false,
        },
        None,
        &mut log,
    )
    .unwrap();
    assert!(
        log.first_candidate_seen
            .unwrap()
            .contains(&root.join("other/payload"))
    );
}

#[test]
fn exhausted_marker_budget_never_grants_local_absence_classification() {
    let (platform, root, target) = marker_fixture(true);
    let mut log = EarlyLog {
        preference: Some(target),
        ..Default::default()
    };
    let result = Scanner::new(
        platform,
        ScannerOptions {
            max_workers: 1,
            resource_limits: ScanResourceLimits {
                max_classified_metadata_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .scan_classified_with_observer(
        &[ScanRoot::new(root).unwrap()],
        &CancellationToken::new(),
        &ParentMarker {
            negative: true,
            local: true,
        },
        None,
        &mut log,
    )
    .unwrap();
    assert!(result.decisions.is_empty());
    assert!(log.observations.candidates.is_empty());
    assert!(
        log.observations
            .boundaries
            .iter()
            .any(|boundary| boundary.kind == BoundaryKind::ResourceLimit)
    );
}

#[test]
fn scoped_walk_preserves_parent_markers_and_native_lineage_without_inspecting_siblings() {
    let (platform, root, target) = marker_fixture(true);
    let calls = Arc::clone(&platform.inspect_calls);
    let scanner = Scanner::new(
        platform,
        ScannerOptions {
            max_workers: 1,
            ..Default::default()
        },
    );
    let classifier = ParentMarker {
        negative: false,
        local: true,
    };
    let mut log = EarlyLog {
        preference: Some(target.clone()),
        ..Default::default()
    };
    let result = scanner
        .scan_classified_subtrees_with_observer(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
            &classifier,
            None,
            std::slice::from_ref(&target),
            &mut log,
        )
        .unwrap();
    // One selected directory, its payload, and the late parent marker; no other directory/file.
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(result.subtree_coverage_complete, Some(true));
    assert_eq!(log.observations.candidates.len(), 1);
    let (entry, _, aggregate) = &log.observations.candidates[0];
    assert_eq!(aggregate.apparent_logical_bytes, known_u128(17));
    assert!(aggregate.coverage.complete);
    assert_eq!(
        entry
            .validated_native_locator()
            .unwrap()
            .unwrap()
            .scan_root_absolute_path
            .as_ref()
            .unwrap()
            .equals_path(&root),
        Ok(true)
    );
    assert!(result.coverages.values().any(|coverage| !coverage.complete));
    assert!(!log.seen.contains(&root.join("other")));
    assert!(!log.seen.contains(&root.join("other/payload")));
}

#[test]
fn scoped_marker_directories_are_observed_shallowly_for_git_lineage() {
    let (mut platform, root, target) = marker_fixture(true);
    let git = root.join(".git");
    platform
        .entries_by_capability
        .get_mut(&1)
        .unwrap()
        .push(DirectoryEntryRecord {
            path: git.clone(),
            file_name: test_native_name(".git"),
        });
    let mut metadata = test_metadata(git.clone(), ".git", EntryKind::Directory, Some(1));
    metadata.identity = Some(EntryIdentity::from_unix(1, 4));
    platform.walk_entries.insert(
        git.clone(),
        WalkEntry::Directory(sweepx_platform::OpenedDirectory {
            metadata,
            handle: FakeDirectoryHandle {
                path: git.clone(),
                capability_id: 4,
                cursor: 0,
            },
        }),
    );
    // Descending this deliberately unmapped child would fail. The scoped walk must only
    // preserve the native .git directory marker, without enumerating its contents.
    platform.entries_by_capability.insert(
        4,
        vec![DirectoryEntryRecord {
            path: git.join("unexpected"),
            file_name: test_native_name("unexpected"),
        }],
    );
    let mut log = EarlyLog::default();
    let result = Scanner::new(
        platform,
        ScannerOptions {
            max_workers: 1,
            ..Default::default()
        },
    )
    .scan_classified_subtrees_with_observer(
        &[ScanRoot::new(root).unwrap()],
        &CancellationToken::new(),
        &ParentMarker {
            negative: false,
            local: true,
        },
        None,
        &[target],
        &mut log,
    )
    .unwrap();
    assert_eq!(result.subtree_coverage_complete, Some(true));
    assert!(
        result
            .directory_markers
            .values()
            .any(|children| children.contains_key(".git"))
    );
    assert!(log.seen.contains(&git));
    assert!(!log.seen.contains(&git.join("unexpected")));
}

#[test]
fn scoped_negative_predicate_refuses_truncated_parent_markers() {
    let (platform, root, target) = marker_fixture(true);
    let mut log = EarlyLog {
        preference: Some(target.clone()),
        ..Default::default()
    };
    let result = Scanner::new(
        platform,
        ScannerOptions {
            max_workers: 1,
            resource_limits: ScanResourceLimits {
                max_directory_entries: 2,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .scan_classified_subtrees_with_observer(
        &[ScanRoot::new(root).unwrap()],
        &CancellationToken::new(),
        &ParentMarker {
            negative: true,
            local: true,
        },
        None,
        &[target],
        &mut log,
    )
    .unwrap();
    assert!(result.decisions.is_empty());
    assert!(log.observations.candidates.is_empty());
    assert!(
        log.observations
            .boundaries
            .iter()
            .any(|boundary| boundary.kind == BoundaryKind::ResourceLimit)
    );
}

#[test]
fn unvisited_scoped_path_never_reports_complete_coverage() {
    let (platform, root, _) = marker_fixture(true);
    let result = Scanner::new(platform, ScannerOptions::default())
        .scan_classified_subtrees_with_observer(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
            &ParentMarker {
                negative: false,
                local: true,
            },
            None,
            &[root.join("missing")],
            &mut EarlyLog::default(),
        )
        .unwrap();
    assert_eq!(result.subtree_coverage_complete, Some(false));
}

#[test]
fn scoped_walk_rejects_global_evaluators_and_outside_paths_before_observation() {
    let (platform, root, target) = marker_fixture(true);
    let calls = Arc::clone(&platform.inspect_calls);
    let scanner = Scanner::new(platform, ScannerOptions::default());
    let roots = [ScanRoot::new(root).unwrap()];
    assert!(
        scanner
            .scan_classified_subtrees_with_observer(
                &roots,
                &CancellationToken::new(),
                &ParentMarker {
                    negative: false,
                    local: false
                },
                None,
                &[target],
                &mut EarlyLog::default()
            )
            .is_err()
    );
    assert!(
        scanner
            .scan_classified_subtrees_with_observer(
                &roots,
                &CancellationToken::new(),
                &ParentMarker {
                    negative: false,
                    local: true
                },
                None,
                &[test_path("outside")],
                &mut EarlyLog::default()
            )
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn scoped_omission_cannot_hide_malformed_backend_paths() {
    let (mut platform, root, target) = marker_fixture(true);
    platform
        .entries_by_capability
        .get_mut(&1)
        .unwrap()
        .push(DirectoryEntryRecord {
            path: test_path("escaped/ignored"),
            file_name: test_native_name("ignored"),
        });
    assert!(
        Scanner::new(platform, ScannerOptions::default())
            .scan_classified_subtrees_with_observer(
                &[ScanRoot::new(root).unwrap()],
                &CancellationToken::new(),
                &ParentMarker {
                    negative: false,
                    local: true
                },
                None,
                &[target],
                &mut EarlyLog::default()
            )
            .is_err()
    );
}
