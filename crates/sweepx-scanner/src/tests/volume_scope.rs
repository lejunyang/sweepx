//! Controlled two-volume namespaces exercise the shared ordinary and classified traversal.
//! Native metadata identifies aliases; path names alone never establish duplicate accounting.

use super::*;
use crate::volume_scope::VolumeScope;

struct MountedPlatform(FakePlatform);

impl PlatformScanner for MountedPlatform {
    type DirectoryHandle = FakeDirectoryHandle;

    fn platform_name(&self) -> &'static str {
        "controlled-volumes"
    }

    fn supports_file_length_observation(&self) -> bool {
        self.0.supports_file_length_observation()
    }

    fn observe_file_length(
        &self,
        parent: &Self::DirectoryHandle,
        child: &DirectoryEntryRecord,
    ) -> Option<sweepx_platform::CachedFileEntry> {
        self.0.observe_file_length(parent, child)
    }

    fn admit_root(
        &self,
        root: &ScanRoot,
        cancel: &CancellationToken,
    ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
        self.0.admit_root(root, cancel)
    }

    fn enumerate_children(
        &self,
        directory: &mut Self::DirectoryHandle,
        cancel: &CancellationToken,
        limits: DirectoryReadLimits,
    ) -> Result<DirectoryEntryBatch, PlatformError> {
        self.0.enumerate_children(directory, cancel, limits)
    }

    fn inspect_child(
        &self,
        parent: &Self::DirectoryHandle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
    ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
        self.0.inspect_child(parent, child, cancel)
    }

    fn inspect_child_with_directory_admission(
        &self,
        parent: &Self::DirectoryHandle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
        admission: DirectoryHandleAdmission,
    ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
        self.0
            .inspect_child_with_directory_admission(parent, child, cancel, admission)
    }

    fn is_same_mount(
        &self,
        root: &EntryMetadata,
        entry: &EntryMetadata,
    ) -> Result<bool, PlatformError> {
        Ok(root.filesystem_identity == entry.filesystem_identity
            && root.mount_identity == entry.mount_identity)
    }
}

struct Fixture {
    scanner: Scanner<MountedPlatform>,
    root: PathBuf,
    logical: PathBuf,
    data: PathBuf,
    alias: PathBuf,
    files: BTreeSet<String>,
}

fn metadata(path: &Path, kind: EntryKind, device: u64, inode: u64, mount: u64) -> EntryMetadata {
    let mut value = test_metadata(
        path.to_path_buf(),
        path.file_name().unwrap().to_str().unwrap(),
        kind,
        Some(mount),
    );
    value.identity = Some(EntryIdentity::from_unix(device, inode));
    value.filesystem_identity = Some(FilesystemIdentity { device });
    value
}

fn directory(value: EntryMetadata, capability_id: u64) -> WalkEntry<FakeDirectoryHandle> {
    WalkEntry::Directory(sweepx_platform::OpenedDirectory {
        handle: FakeDirectoryHandle {
            path: value.path.clone(),
            capability_id,
            cursor: 0,
        },
        metadata: value,
    })
}

fn fixture(live_lengths: bool) -> Fixture {
    let root = test_path("volume-root");
    let logical = root.join("Users");
    let data = root.join("Data");
    let alias = data.join("Users");
    let logical_metadata = metadata(&logical, EntryKind::Directory, 2, 20, 100);
    let data_metadata = metadata(&data, EntryKind::Directory, 2, 10, 100);
    let mut alias_metadata = logical_metadata.clone();
    alias_metadata.path = alias.clone();
    let mut walked = BTreeMap::from([
        (logical.clone(), directory(logical_metadata.clone(), 2)),
        (data.clone(), directory(data_metadata.clone(), 3)),
        (alias.clone(), directory(alias_metadata, 4)),
    ]);
    // These four independent payload lengths make the accounting oracle explicit: an ordinary
    // namespace walk would see 38 bytes; a verified two-entrance walk must see 7 + 11 + 13 = 31.
    let payloads = [
        (logical.join("user-file"), 2, 21, 100, 7),
        (data.join("unique"), 2, 22, 100, 11),
        (root.join("system-file"), 1, 3, 1, 13),
        (alias.join("user-file"), 2, 21, 100, 7),
    ];
    let files = payloads[..3]
        .iter()
        .map(|(path, ..)| path.display().to_string())
        .collect();
    for (path, device, inode, mount, length) in &payloads {
        let mut value = metadata(path, EntryKind::File, *device, *inode, *mount);
        value.logical_bytes = known_u128(*length);
        value.allocated_bytes = known_u128(*length);
        walked.insert(path.clone(), WalkEntry::File(value));
    }
    let mut platform = FakePlatform::new(root.clone(), Vec::new(), walked);
    platform.entries_by_capability = [
        (1, vec!["Users", "Data", "system-file"], &root),
        (2, vec!["user-file"], &logical),
        (3, vec!["Users", "unique"], &data),
        (4, vec!["user-file"], &alias),
    ]
    .into_iter()
    .map(|(capability, names, parent)| {
        (
            capability,
            names
                .into_iter()
                .map(|name| test_entry(parent, name))
                .collect(),
        )
    })
    .collect();
    if live_lengths {
        platform.file_length_proposals = Some(
            payloads
                .iter()
                .map(|(path, _, _, _, length)| {
                    (
                        path.clone(),
                        sweepx_platform::CachedFileEntry {
                            path: path.clone(),
                            file_name: test_native_name(
                                path.file_name().unwrap().to_str().unwrap(),
                            ),
                            logical_bytes: *length,
                        },
                    )
                })
                .collect(),
        );
    }
    let mut scanner = Scanner::new(MountedPlatform(platform), ScannerOptions::default());
    scanner.scope_override = Some(VolumeScope {
        data: Some(data_metadata),
        aliases: [(alias.clone(), logical_metadata)].into_iter().collect(),
        unverified_logical: Default::default(),
    });
    Fixture {
        scanner,
        root,
        logical,
        data,
        alias,
        files,
    }
}

#[test]
fn ordinary_scan_includes_data_and_counts_verified_firmlink_content_once() {
    let fixture = fixture(false);
    let summary = fixture
        .scanner
        .scan(
            &[ScanRoot::new(&fixture.root).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(summary.boundaries.is_empty());
    let root = aggregate_for_path(&summary, &fixture.root);
    assert_eq!(root.apparent_logical_bytes, known_u128(31));
    assert!(root.coverage.complete);
    assert_eq!(
        aggregate_for_path(&summary, &fixture.data).apparent_logical_bytes,
        known_u128(11)
    );
    let files: BTreeSet<_> = summary
        .entries
        .iter()
        .filter(|entry| entry.object_type == ObjectType::File)
        .map(|entry| entry.display_path.clone())
        .collect();
    assert_eq!(files, fixture.files);
    assert!(summary.entries.iter().any(|entry| {
        entry.display_path == fixture.alias.display().to_string()
            && matches!(entry.logical_bytes, EvidenceValue::NotChecked { .. })
    }));
}

struct LocalCandidate;
impl JunkClassifier for LocalCandidate {
    fn uses_only_local_markers(&self) -> bool {
        true
    }
    fn needs_file_marker(&self, name: &NativeName) -> bool {
        name == &test_native_name("user-file") || name == &test_native_name("unique")
    }
    fn classify(
        &self,
        entry: &ScannedEntry,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<String> {
        let identity = entry.identity.as_ref()?;
        let names = markers.get(&identity.entry_id)?;
        names
            .iter()
            .any(|name| name == "user-file" || name == "unique")
            .then(|| "controlled-candidate".into())
    }
}

#[test]
fn compact_local_classification_keeps_data_markers_and_suppresses_alias_candidates() {
    let mut fixture = fixture(true);
    fixture.scanner.options.retain_directory_index = false;
    fixture.scanner.options.retain_file_index = false;
    let result = fixture
        .scanner
        .scan_classified(
            &[ScanRoot::new(&fixture.root).unwrap()],
            &CancellationToken::new(),
            &LocalCandidate,
            None,
        )
        .unwrap();
    assert!(result.summary.boundaries.is_empty());
    assert_eq!(result.decisions.len(), 2);
    let paths: BTreeSet<_> = result
        .summary
        .entries
        .iter()
        .map(|entry| entry.display_path.clone())
        .collect();
    assert_eq!(
        paths,
        [
            fixture.logical.display().to_string(),
            fixture.data.display().to_string()
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        aggregate_for_path(&result.summary, &fixture.logical).apparent_logical_bytes,
        known_u128(7)
    );
    assert_eq!(
        aggregate_for_path(&result.summary, &fixture.data).apparent_logical_bytes,
        known_u128(11)
    );
}

#[derive(Default)]
struct Files(BTreeSet<String>);
impl ClassifiedScanObserver for Files {
    fn wants_file_observations(&self) -> bool {
        true
    }
    fn on_entry(&mut self, entry: &ScannedEntry) {
        if entry.object_type == ObjectType::File {
            assert!(
                self.0.insert(entry.display_path.clone()),
                "file observed twice"
            );
            assert!(entry.validated_native_locator().unwrap().is_some());
        }
    }
}

#[test]
fn file_analysis_observer_receives_data_files_once_before_optional_row_retention() {
    let mut fixture = fixture(true);
    fixture.scanner.options.resource_limits.max_retained_entries = 1;
    let mut observer = Files::default();
    let summary = fixture
        .scanner
        .scan_with_observer(
            &[ScanRoot::new(&fixture.root).unwrap()],
            &CancellationToken::new(),
            &mut observer,
        )
        .unwrap();
    assert_eq!(observer.0, fixture.files);
    assert!(summary.entries.len() <= 1);
}

#[test]
fn selected_physical_alias_is_observed_when_logical_entrance_is_outside_refresh_scope() {
    let fixture = fixture(true);
    let mut observer = Files::default();
    let result = fixture
        .scanner
        .scan_classified_subtrees_with_observer(
            &[ScanRoot::new(&fixture.root).unwrap()],
            &CancellationToken::new(),
            &LocalCandidate,
            None,
            std::slice::from_ref(&fixture.alias),
            &mut observer,
        )
        .unwrap();
    // The current unique marker also identifies the shallowly observed Data ancestor. Its
    // incomplete aggregate cannot replace the selected physical entrance's complete subtree.
    assert_eq!(result.decisions.len(), 2);
    assert_eq!(
        result
            .summary
            .entries
            .iter()
            .map(|entry| entry.display_path.clone())
            .collect::<BTreeSet<_>>(),
        [
            fixture.data.display().to_string(),
            fixture.alias.display().to_string()
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        aggregate_for_path(&result.summary, &fixture.alias).apparent_logical_bytes,
        known_u128(7)
    );
    assert!(
        aggregate_for_path(&result.summary, &fixture.alias)
            .coverage
            .complete
    );
    assert!(
        !aggregate_for_path(&result.summary, &fixture.data)
            .coverage
            .complete
    );
    assert!(
        observer
            .0
            .contains(&fixture.alias.join("user-file").display().to_string())
    );
    assert!(
        !observer
            .0
            .contains(&fixture.logical.join("user-file").display().to_string())
    );
}

#[test]
fn mixed_logical_and_physical_selections_do_not_skip_a_different_alias_subtree() {
    struct Payload;
    impl JunkClassifier for Payload {
        fn uses_only_local_markers(&self) -> bool {
            true
        }
        fn needs_file_marker(&self, name: &NativeName) -> bool {
            name == &test_native_name("payload")
        }
        fn classify(
            &self,
            entry: &ScannedEntry,
            markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
        ) -> Option<String> {
            markers
                .get(&entry.identity.as_ref()?.entry_id)?
                .contains("payload")
                .then(|| "payload-directory".into())
        }
    }
    let mut fixture = fixture(false);
    let logical_a = fixture.logical.join("A");
    let logical_b = fixture.logical.join("B");
    let physical_a = fixture.alias.join("A");
    let physical_b = fixture.alias.join("B");
    for (capability, parent) in [(2, &fixture.logical), (4, &fixture.alias)] {
        fixture
            .scanner
            .platform
            .0
            .entries_by_capability
            .get_mut(&capability)
            .unwrap()
            .extend([test_entry(parent, "A"), test_entry(parent, "B")]);
    }
    // Both entrances model the same complete namespace. Selecting A through the logical
    // entrance and B through the physical entrance requires both independently complete facts;
    // shallow observation of their common logical ancestor cannot prove B was counted there.
    for (path, capability, object, length) in [
        (&logical_a, 5, 201, 3),
        (&logical_b, 6, 202, 5),
        (&physical_a, 7, 201, 3),
        (&physical_b, 8, 202, 5),
    ] {
        fixture.scanner.platform.0.walk_entries.insert(
            path.clone(),
            directory(
                metadata(path, EntryKind::Directory, 2, object, 100),
                capability,
            ),
        );
        fixture
            .scanner
            .platform
            .0
            .entries_by_capability
            .insert(capability, vec![test_entry(path, "payload")]);
        let file = path.join("payload");
        let mut value = metadata(&file, EntryKind::File, 2, object + 100, 100);
        value.logical_bytes = known_u128(length);
        fixture
            .scanner
            .platform
            .0
            .walk_entries
            .insert(file, WalkEntry::File(value));
    }
    let mut observer = Files::default();
    let result = fixture
        .scanner
        .scan_classified_subtrees_with_observer(
            &[ScanRoot::new(&fixture.root).unwrap()],
            &CancellationToken::new(),
            &Payload,
            None,
            &[logical_a.clone(), physical_b.clone()],
            &mut observer,
        )
        .unwrap();
    assert_eq!(result.decisions.len(), 2);
    assert_eq!(
        result
            .summary
            .entries
            .iter()
            .map(|entry| entry.display_path.clone())
            .collect::<BTreeSet<_>>(),
        [
            logical_a.display().to_string(),
            physical_b.display().to_string()
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        observer.0,
        [
            logical_a.join("payload").display().to_string(),
            physical_b.join("payload").display().to_string()
        ]
        .into_iter()
        .collect()
    );
    for (path, length) in [(&logical_a, 3), (&physical_b, 5)] {
        let aggregate = aggregate_for_path(&result.summary, path);
        assert_eq!(aggregate.apparent_logical_bytes, known_u128(length));
        assert!(aggregate.coverage.complete);
    }
}

#[test]
fn alias_native_identity_change_fails_closed_before_duplicate_content_is_observed() {
    for component in ["object", "filesystem", "mount"] {
        let mut fixture = fixture(false);
        let WalkEntry::Directory(alias) = fixture
            .scanner
            .platform
            .0
            .walk_entries
            .get_mut(&fixture.alias)
            .unwrap()
        else {
            unreachable!()
        };
        match component {
            "object" => alias.metadata.identity = Some(EntryIdentity::from_unix(2, 999)),
            "filesystem" => {
                alias.metadata.filesystem_identity = Some(FilesystemIdentity { device: 3 })
            }
            "mount" => alias.metadata.mount_identity = Some(MountIdentity { value: 200 }),
            _ => unreachable!(),
        }
        let mut observer = Files::default();
        let result = fixture.scanner.scan_with_observer(
            &[ScanRoot::new(&fixture.root).unwrap()],
            &CancellationToken::new(),
            &mut observer,
        );
        assert!(
            matches!(
                result,
                Err(ScanError::Platform(
                    PlatformError::InvalidDirectoryEntry { .. }
                ))
            ),
            "changed {component} must invalidate captured alias admission"
        );
        assert!(
            !observer
                .0
                .contains(&fixture.alias.join("user-file").display().to_string())
        );
    }
}

#[test]
fn verified_volume_and_firmlink_entrance_type_changes_fail_closed() {
    for kind in [EntryKind::File, EntryKind::Symlink] {
        for entrance in ["alias", "logical", "data"] {
            let mut fixture = fixture(false);
            let path = match entrance {
                "alias" => &fixture.alias,
                "logical" => &fixture.logical,
                "data" => &fixture.data,
                _ => unreachable!(),
            };
            let WalkEntry::Directory(opened) =
                fixture.scanner.platform.0.walk_entries.get(path).unwrap()
            else {
                unreachable!()
            };
            let mut changed = opened.metadata.clone();
            changed.kind = kind.clone();
            changed.logical_bytes = known_u128(999);
            let walked = if kind == EntryKind::File {
                WalkEntry::File(changed)
            } else {
                WalkEntry::Link(changed)
            };
            fixture
                .scanner
                .platform
                .0
                .walk_entries
                .insert(path.clone(), walked);
            let result = fixture.scanner.scan(
                &[ScanRoot::new(&fixture.root).unwrap()],
                &CancellationToken::new(),
            );
            assert!(
                matches!(
                    result,
                    Err(ScanError::Platform(
                        PlatformError::InvalidDirectoryEntry { .. }
                    ))
                ),
                "changed {entrance} entrance kind {kind:?} must invalidate captured volume facts"
            );
        }
    }
}

#[test]
fn live_length_proposal_cannot_hide_firmlink_entrance_replaced_by_file() {
    let mut fixture = fixture(true);
    let WalkEntry::Directory(opened) = fixture
        .scanner
        .platform
        .0
        .walk_entries
        .get(&fixture.alias)
        .unwrap()
    else {
        unreachable!()
    };
    let mut changed = opened.metadata.clone();
    changed.kind = EntryKind::File;
    changed.logical_bytes = known_u128(999);
    fixture
        .scanner
        .platform
        .0
        .walk_entries
        .insert(fixture.alias.clone(), WalkEntry::File(changed));
    fixture
        .scanner
        .platform
        .0
        .file_length_proposals
        .as_mut()
        .unwrap()
        .insert(
            fixture.alias.clone(),
            sweepx_platform::CachedFileEntry {
                path: fixture.alias.clone(),
                file_name: test_native_name("Users"),
                logical_bytes: 999,
            },
        );
    let result = fixture.scanner.scan_classified(
        &[ScanRoot::new(&fixture.root).unwrap()],
        &CancellationToken::new(),
        &LocalCandidate,
        None,
    );
    assert!(matches!(
        result,
        Err(ScanError::Platform(
            PlatformError::InvalidDirectoryEntry { .. }
        ))
    ));
}

#[test]
fn unadmitted_and_unknown_mounts_remain_visible_without_descendant_accounting() {
    let mut fixture = fixture(false);
    let outside = fixture.root.join("external");
    let unknown = fixture.root.join("unknown");
    for (path, mount, capability) in [(&outside, Some(200), 5), (&unknown, None, 6)] {
        fixture
            .scanner
            .platform
            .0
            .entries_by_capability
            .get_mut(&1)
            .unwrap()
            .push(test_entry(
                &fixture.root,
                path.file_name().unwrap().to_str().unwrap(),
            ));
        let mut value = metadata(path, EntryKind::Directory, 3, capability, 200);
        value.mount_identity = mount.map(|value| MountIdentity { value });
        fixture
            .scanner
            .platform
            .0
            .walk_entries
            .insert(path.clone(), directory(value, capability));
        // Missing synthetic child observations would fail the test if either excluded directory
        // were accidentally enumerated. Visible boundaries must precede descendant traversal.
        fixture
            .scanner
            .platform
            .0
            .entries_by_capability
            .insert(capability, vec![test_entry(path, "excluded")]);
    }
    let summary = fixture
        .scanner
        .scan(
            &[ScanRoot::new(&fixture.root).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();
    for (path, reason) in [
        (&outside, ReasonCode::UnsupportedFilesystem),
        (&unknown, ReasonCode::UnknownIdentity),
    ] {
        assert!(summary.boundaries.iter().any(|boundary| {
            boundary.path == *path
                && boundary.kind == BoundaryKind::Mount
                && boundary.reason == reason
        }));
    }
    let total = aggregate_for_path(&summary, &fixture.root);
    assert_eq!(
        total.apparent_logical_bytes,
        lower_bound_u128(31, ReasonCode::IncompleteStreamCoverage)
    );
    assert!(!total.coverage.complete);
}

fn assert_cancelled_root(summary: &ScanSummary, root: &Path) {
    assert_eq!(summary.roots.len(), 1);
    assert!(summary.entries.is_empty());
    assert_eq!(summary.error_count(), 0);
    assert!(summary.progress_retention.cancelled);
    assert!(summary.progress_retention.finished);
    let aggregate = aggregate_for_path(summary, root);
    assert_eq!(
        aggregate.apparent_logical_bytes,
        lower_bound_u128(0, ReasonCode::IncompleteStreamCoverage)
    );
    assert!(!aggregate.coverage.complete);
    assert_eq!(
        aggregate.directory_identity,
        summary.roots[0]
            .identity
            .as_ref()
            .unwrap()
            .entry_id
            .as_str()
    );
    assert!(
        summary
            .progress
            .iter()
            .any(|event| { matches!(event, ProgressEvent::Cancelled { path } if path == root) })
    );
}

#[test]
fn observer_cancel_at_root_acceptance_preserves_cancelled_summary_and_root_identity() {
    struct CancelAtRoot(CancellationToken, usize);
    impl ClassifiedScanObserver for CancelAtRoot {
        fn on_progress(&mut self, _: &Path, event: &ProgressEvent) {
            if matches!(event, ProgressEvent::RootAccepted { .. }) {
                self.1 += 1;
                self.0.cancel();
            }
        }
    }
    let mut fixture = fixture(false);
    // Exercise the actual scope-preparation seam, rather than bypassing it with a test scope.
    fixture.scanner.scope_override = None;
    let cancel = CancellationToken::new();
    let mut observer = CancelAtRoot(cancel.clone(), 0);
    let summary = fixture
        .scanner
        .scan_with_observer(
            &[ScanRoot::new(&fixture.root).unwrap()],
            &cancel,
            &mut observer,
        )
        .expect("cooperative cancellation during admission must not become scan_failed");
    assert_eq!(observer.1, 1);
    assert_cancelled_root(&summary, &fixture.root);
    assert_eq!(
        fixture
            .scanner
            .platform
            .0
            .inspect_calls
            .load(Ordering::SeqCst),
        0
    );
}

#[test]
fn sink_cancel_at_root_acceptance_preserves_cancelled_summary_and_root_identity() {
    struct CancelAtRoot {
        cancel: CancellationToken,
        inner: CollectingScanSink<'static>,
    }
    impl ScanSink for CancelAtRoot {
        fn push_root(&mut self, root: &Path, entry: ScannedEntry) -> Result<(), ScanError> {
            self.inner.push_root(root, entry)
        }
        fn push_entry(&mut self, root: &Path, entry: ScannedEntry) -> Result<(), ScanError> {
            self.inner.push_entry(root, entry)
        }
        fn push_boundary(
            &mut self,
            root: &Path,
            boundary: BoundaryRecord,
        ) -> Result<(), ScanError> {
            self.inner.push_boundary(root, boundary)
        }
        fn push_progress(&mut self, root: &Path, event: ProgressEvent) -> Result<(), ScanError> {
            if matches!(event, ProgressEvent::RootAccepted { .. }) {
                self.cancel.cancel();
            }
            self.inner.push_progress(root, event)
        }
        fn push_aggregate(
            &mut self,
            root: &Path,
            aggregate: DirectoryAggregate,
        ) -> Result<(), ScanError> {
            self.inner.push_aggregate(root, aggregate)
        }
    }
    let mut fixture = fixture(false);
    fixture.scanner.scope_override = None;
    let cancel = CancellationToken::new();
    let mut sink = CancelAtRoot {
        cancel: cancel.clone(),
        inner: CollectingScanSink::new(ScanResourceLimits::default()),
    };
    fixture
        .scanner
        .scan_with_sink(
            &[ScanRoot::new(&fixture.root).unwrap()],
            &cancel,
            None,
            &mut sink,
        )
        .expect("sink cancellation during admission must not become scan_failed");
    assert_cancelled_root(&sink.inner.finish(), &fixture.root);
    assert_eq!(
        fixture
            .scanner
            .platform
            .0
            .inspect_calls
            .load(Ordering::SeqCst),
        0
    );
}
