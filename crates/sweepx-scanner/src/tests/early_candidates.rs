//! Controlled stream order, independent expected totals, and conservative custom evaluators.

use super::*;

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
