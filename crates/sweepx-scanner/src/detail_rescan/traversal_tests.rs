//! Native fixtures and ordinary-walk accounting, independent of the detail traversal.
use super::*;
use crate::{HostPlatformScanner, Scanner, ScannerOptions};
use std::fs;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use sweepx_platform::{DirectoryEntryBatch, OpenedDirectory, known_u128};

type NativeHandle = <HostPlatformScanner as PlatformScanner>::DirectoryHandle;
#[derive(Default)]
struct Probe {
    live: AtomicUsize,
    peak: AtomicUsize,
    roots: AtomicUsize,
    denied: AtomicUsize,
    native_lengths: AtomicUsize,
    boundary_descendants: AtomicUsize,
    #[cfg(unix)]
    directories: BTreeSet<(u64, u64)>,
    #[cfg(unix)]
    fd_peak: AtomicUsize,
}
struct Lease(Arc<Probe>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}
struct Handle {
    // Native owner closes before test instrumentation counts a released capability.
    native: NativeHandle,
    path: PathBuf,
    _lease: Lease,
}
struct ProbedPlatform {
    native: HostPlatformScanner,
    probe: Arc<Probe>,
    bad_batch: bool,
    mount_boundaries: BTreeSet<PathBuf>,
    changed_root_mount: bool,
    force_full_file_observations: bool,
    unavailable_mount_comparison: bool,
    child_io_errors: std::collections::BTreeMap<PathBuf, std::io::ErrorKind>,
    enumeration_io_errors: std::collections::BTreeMap<PathBuf, std::io::ErrorKind>,
}
impl ProbedPlatform {
    fn new(probe: Arc<Probe>) -> Self {
        Self {
            native: HostPlatformScanner::new(),
            probe,
            bad_batch: false,
            mount_boundaries: BTreeSet::new(),
            changed_root_mount: false,
            force_full_file_observations: false,
            unavailable_mount_comparison: false,
            child_io_errors: std::collections::BTreeMap::new(),
            enumeration_io_errors: std::collections::BTreeMap::new(),
        }
    }
    fn handle(&self, native: NativeHandle, path: PathBuf) -> Handle {
        let live = self.probe.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.probe.peak.fetch_max(live, Ordering::SeqCst);
        let handle = Handle {
            native,
            path,
            _lease: Lease(Arc::clone(&self.probe)),
        };
        self.observe();
        handle
    }
    fn observed(&self, entry: WalkEntry<NativeHandle>) -> WalkEntry<Handle> {
        let entry = match entry {
            WalkEntry::Directory(opened) => WalkEntry::Directory(OpenedDirectory {
                handle: self.handle(opened.handle, opened.metadata.path.clone()),
                metadata: opened.metadata,
            }),
            WalkEntry::File(value) => WalkEntry::File(value),
            WalkEntry::Link(value) => WalkEntry::Link(value),
            WalkEntry::Boundary(value) => WalkEntry::Boundary(value),
            WalkEntry::Error(value) => WalkEntry::Error(value),
            WalkEntry::CachedFile(value) => WalkEntry::CachedFile(value),
        };
        self.observe();
        entry
    }
    fn observe(&self) {
        #[cfg(unix)]
        self.probe
            .fd_peak
            .fetch_max(self.probe.descriptors(), Ordering::SeqCst);
    }
}
impl PlatformScanner for ProbedPlatform {
    type DirectoryHandle = Handle;
    fn platform_name(&self) -> &'static str {
        self.native.platform_name()
    }
    fn admit_root(
        &self,
        root: &ScanRoot,
        cancel: &CancellationToken,
    ) -> Result<RootAdmission<Handle>, PlatformError> {
        self.probe.roots.fetch_add(1, Ordering::SeqCst);
        let mut opened = self.native.admit_root(root, cancel)?;
        if self.changed_root_mount {
            let mount = opened.metadata.mount_identity.as_mut().unwrap();
            mount.value = mount.value.wrapping_add(1);
        }
        Ok(RootAdmission::new(
            opened.root,
            opened.metadata,
            self.handle(opened.directory, root.path().to_path_buf()),
            opened.root_locator,
        ))
    }
    fn enumerate_children(
        &self,
        directory: &mut Handle,
        cancel: &CancellationToken,
        limits: DirectoryReadLimits,
    ) -> Result<DirectoryEntryBatch, PlatformError> {
        if let Some(kind) = self.enumeration_io_errors.get(&directory.path) {
            return Err(PlatformError::Io {
                path: directory.path.clone(),
                detail: "fixture enumeration denied or removed".into(),
                io_kind: Some(*kind),
            });
        }
        if self.bad_batch {
            return Ok(DirectoryEntryBatch {
                entries: Vec::new(),
                end_of_directory: false,
            });
        }
        let batch = self
            .native
            .enumerate_children(&mut directory.native, cancel, limits)?;
        for child in &batch.entries {
            if self
                .mount_boundaries
                .iter()
                .any(|path| child.path != *path && child.path.starts_with(path))
            {
                self.probe
                    .boundary_descendants
                    .fetch_add(1, Ordering::SeqCst);
            }
        }
        self.observe();
        Ok(batch)
    }
    fn inspect_child(
        &self,
        parent: &Handle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
    ) -> Result<WalkEntry<Handle>, PlatformError> {
        self.native
            .inspect_child(&parent.native, child, cancel)
            .map(|entry| self.observed(entry))
    }
    fn inspect_child_with_directory_admission(
        &self,
        parent: &Handle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
        admission: DirectoryHandleAdmission,
    ) -> Result<WalkEntry<Handle>, PlatformError> {
        self.native
            .inspect_child_with_directory_admission(&parent.native, child, cancel, admission)
            .map(|entry| self.observed(entry))
    }
    fn inspect_child_with_mount_identity(
        &self,
        parent: &Handle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
    ) -> Result<WalkEntry<Handle>, PlatformError> {
        self.native
            .inspect_child_with_mount_identity(&parent.native, child, cancel)
            .map(|entry| self.observed(entry))
    }
    fn inspect_child_with_mount_identity_and_directory_admission(
        &self,
        parent: &Handle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
        admission: DirectoryHandleAdmission,
    ) -> Result<WalkEntry<Handle>, PlatformError> {
        if admission == DirectoryHandleAdmission::Deny {
            self.probe.denied.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(kind) = self.child_io_errors.get(&child.path) {
            return Err(PlatformError::Io {
                path: child.path.clone(),
                detail: "fixture child denied or removed".into(),
                io_kind: Some(*kind),
            });
        }
        self.native
            .inspect_child_with_mount_identity_and_directory_admission(
                &parent.native,
                child,
                cancel,
                admission,
            )
            .map(|entry| self.observed(entry))
    }
    fn observe_file_length(
        &self,
        parent: &Handle,
        child: &DirectoryEntryRecord,
    ) -> Option<sweepx_platform::CachedFileEntry> {
        if self.force_full_file_observations
            || self.mount_boundaries.contains(&child.path)
            || self.child_io_errors.contains_key(&child.path)
        {
            // Model the native fast path's refusal of a file on a different mount.
            return None;
        }
        let file = self.native.observe_file_length(&parent.native, child)?;
        self.probe.native_lengths.fetch_add(1, Ordering::SeqCst);
        Some(file)
    }
    fn is_same_mount(
        &self,
        root: &EntryMetadata,
        entry: &EntryMetadata,
    ) -> Result<bool, PlatformError> {
        if self.unavailable_mount_comparison {
            return Err(PlatformError::Unsupported(
                "mount comparison unavailable".into(),
            ));
        }
        if self.mount_boundaries.contains(&entry.path) {
            return Ok(false);
        }
        self.native.is_same_mount(root, entry)
    }
}

#[cfg(unix)]
impl Probe {
    fn descriptors(&self) -> usize {
        use std::os::unix::fs::MetadataExt;
        #[cfg(target_os = "linux")]
        let namespace = Path::new("/proc/self/fd");
        #[cfg(not(target_os = "linux"))]
        let namespace = Path::new("/dev/fd");
        // Snapshot descriptor names before opening ordinary /dev/fd aliases for fstat metadata;
        // the oracle's later transient duplicates are not included in that snapshot. No private
        // backend fields, production counter or enumeration of a reporting fixture path is used.
        let names = fs::read_dir(namespace)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        names
            .into_iter()
            .filter_map(|path| fs::File::open(path).ok()?.metadata().ok())
            .filter(|meta| self.directories.contains(&(meta.dev(), meta.ino())))
            .count()
    }
}

#[derive(Default)]
struct Oracle {
    logical: u128,
    unique: u128,
    entries: u128,
    direct: u128,
    #[cfg(unix)]
    allocated: u128,
    #[cfg(unix)]
    files: BTreeSet<(u64, u64)>,
    #[cfg(unix)]
    directories: BTreeSet<(u64, u64)>,
}
impl Oracle {
    fn walk(&mut self, root: &Path, top: bool) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(root).unwrap();
            self.directories.insert((meta.dev(), meta.ino()));
        }
        for entry in fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            let meta = fs::symlink_metadata(entry.path()).unwrap();
            self.entries += 1;
            self.direct += u128::from(top);
            if meta.is_dir() {
                self.walk(&entry.path(), false);
            } else if meta.is_file() {
                self.logical += u128::from(meta.len());
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if self.files.insert((meta.dev(), meta.ino())) {
                        self.unique += u128::from(meta.len());
                        self.allocated += u128::from(meta.blocks()) * 512;
                    }
                }
                #[cfg(not(unix))]
                {
                    self.unique += u128::from(meta.len());
                }
            }
        }
    }
    fn probe(&self) -> Arc<Probe> {
        Arc::new(Probe {
            #[cfg(unix)]
            directories: self.directories.clone(),
            ..Probe::default()
        })
    }
}
fn source(root: &Path) -> (ScanId, ScannedEntry) {
    let scan_id = ScanId::new("detail-native-dfs");
    let summary = Scanner::new(
        HostPlatformScanner::new(),
        ScannerOptions {
            scan_id: scan_id.clone(),
            ..ScannerOptions::default()
        },
    )
    .scan(
        &[ScanRoot::new(root.to_path_buf()).unwrap()],
        &CancellationToken::new(),
    )
    .unwrap();
    (scan_id, summary.roots.into_iter().next().unwrap())
}
fn request<'a>(scan_id: &'a ScanId, root: &'a ScannedEntry) -> DetailRescanRequest<'a> {
    DetailRescanRequest {
        source_scan_id: scan_id,
        source_root_identity: root.identity.as_ref().unwrap(),
        source_directory_identity: root.identity.as_ref().unwrap(),
        directory_locator: root.executable_native_locator().unwrap().unwrap(),
        revision: DecimalU128::new(3),
        max_rows: 1024,
    }
}
fn fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let parent = temp.path().canonicalize().unwrap();
    #[cfg(windows)]
    let parent = temp.path().to_path_buf();
    let root = parent.join("root");
    fs::create_dir(&root).unwrap();
    (temp, root)
}
fn limits() -> ScanResourceLimits {
    ScanResourceLimits {
        max_frontier_entries: 3,
        max_directory_batch_entries: 2,
        ..ScanResourceLimits::default()
    }
}
fn released(probe: &Probe) {
    assert_eq!(probe.live.load(Ordering::SeqCst), 0);
    #[cfg(unix)]
    assert_eq!(probe.descriptors(), 0);
}

#[test]
fn wide_native_detail_is_complete_with_three_capabilities_and_independent_totals() {
    let (_temp, root) = fixture();
    for ordinal in 0..160 {
        let direct = root.join(format!("shard-{ordinal:03}"));
        let nested = direct.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(direct.join("a"), vec![1; 17]).unwrap();
        fs::write(nested.join("b"), vec![2; 31]).unwrap();
    }
    #[cfg(unix)]
    fs::hard_link(root.join("shard-000/a"), root.join("shard-001/alias")).unwrap();
    let mut oracle = Oracle::default();
    oracle.walk(&root, true);
    let probe = oracle.probe();
    let (scan_id, observed) = source(&root);
    let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();
    let mut updates = Vec::new();
    let result = DetailRescanner::new(ProbedPlatform::new(Arc::clone(&probe)), limits())
        .rescan_with_progress(
            request(&scan_id, &observed),
            &mut ids,
            &CancellationToken::new(),
            |update| updates.push((Instant::now(), update)),
        )
        .unwrap();
    assert!(result.aggregate.coverage.complete);
    assert_eq!(
        result.aggregate.apparent_logical_bytes,
        known_u128(oracle.logical)
    );
    assert_eq!(
        result.aggregate.unique_logical_bytes,
        known_u128(oracle.unique)
    );
    assert_eq!(
        result.aggregate.recursive_entry_count,
        known_count(oracle.entries)
    );
    assert_eq!(
        result.aggregate.direct_child_count,
        known_count(oracle.direct)
    );
    #[cfg(target_os = "linux")]
    assert_eq!(
        result.aggregate.filesystem_reported_allocated_bytes,
        known_u128(oracle.allocated)
    );
    #[cfg(target_os = "macos")]
    {
        // The ordinary fixture reports nonzero allocation, but this backend deliberately has
        // no accepted allocated-byte claim. Preserve unknown rather than manufacture zero or
        // broaden production evidence just to satisfy the independent accounting test.
        assert!(oracle.allocated > 0);
        assert_eq!(
            result.aggregate.filesystem_reported_allocated_bytes,
            EvidenceValue::Unknown {
                reason: ReasonCode::UnknownIdentity
            }
        );
    }
    let expected = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap().path().display().to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        result
            .rows
            .iter()
            .map(|row| row.display_path.clone())
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(probe.peak.load(Ordering::SeqCst), 3);
    // At the deepest frame, directory admission is denied; ordinary files must still receive
    // native mount observations and contribute exact bytes without another directory owner.
    assert!(probe.denied.load(Ordering::SeqCst) > 0);
    #[cfg(target_os = "macos")]
    assert_eq!(probe.fd_peak.load(Ordering::SeqCst), 3);
    #[cfg(target_os = "linux")]
    assert!(probe.fd_peak.load(Ordering::SeqCst) <= 6);
    assert!(!updates.is_empty());
    // Literal policy expectation, independently timed at callback entry. The last flush can be
    // earlier; no percentile or performance inference is made from this functional check.
    for pair in updates.windows(2).take(updates.len().saturating_sub(2)) {
        assert!(pair[1].0.duration_since(pair[0].0) >= Duration::from_millis(120));
    }
    for (_, update) in updates {
        assert!(!update.aggregate.coverage.complete);
        assert!(update.rows.iter().all(|row| !row.coverage.complete));
        assert!(result.rows.iter().any(|row| {
            update
                .rows
                .iter()
                .any(|changed| row.identity == changed.identity)
        }));
    }
    for row in &result.rows {
        if row.object_type == ObjectType::Directory {
            assert!(row.coverage.complete);
            let mut child_oracle = Oracle::default();
            child_oracle.walk(Path::new(&row.display_path), true);
            assert_eq!(row.logical_bytes, known_u128(child_oracle.logical));
        }
    }
    released(&probe);
}

#[test]
fn native_detail_refusal_cancellation_and_invalid_batch_release_all_capabilities() {
    let (_temp, root) = fixture();
    fs::create_dir_all(root.join("a/b")).unwrap();
    fs::write(root.join("a/b/file"), b"content").unwrap();
    let mut oracle = Oracle::default();
    oracle.walk(&root, true);
    let (scan_id, observed) = source(&root);
    for mode in ["depth", "zero", "aggregate", "cancel", "batch"] {
        let probe = oracle.probe();
        let mut platform = ProbedPlatform::new(Arc::clone(&probe));
        let mut config = limits();
        match mode {
            "depth" => config.max_frontier_entries = 2,
            "zero" => config.max_frontier_entries = 0,
            "aggregate" => config.max_retained_aggregates = 1,
            "batch" => platform.bad_batch = true,
            _ => {}
        }
        let cancel = CancellationToken::new();
        let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();
        let result = DetailRescanner::new(platform, config).rescan_with_progress(
            request(&scan_id, &observed),
            &mut ids,
            &cancel,
            |_| {
                if mode == "cancel" {
                    cancel.cancel();
                }
            },
        );
        assert_eq!(
            result.unwrap_err(),
            match mode {
                "cancel" => DetailRescanError::Cancelled,
                "batch" => DetailRescanError::Unavailable,
                _ => DetailRescanError::ResourceLimit,
            }
        );
        if mode == "zero" {
            assert_eq!(probe.roots.load(Ordering::SeqCst), 0);
        }
        if mode == "depth" {
            assert_eq!(probe.peak.load(Ordering::SeqCst), 2);
            assert!(probe.denied.load(Ordering::SeqCst) > 0);
        }
        released(&probe);
    }
}

#[test]
fn logical_usage_matches_independent_walk_after_mutations_and_does_not_invent_allocation() {
    let (_temp, root) = fixture();
    for directory in ["first/deep", "second/deep"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    fs::write(root.join("direct"), b"123").unwrap();
    fs::write(root.join("first/deep/file"), b"12345").unwrap();
    fs::hard_link(root.join("first/deep/file"), root.join("second/deep/link")).unwrap();
    fs::write(root.join("second/deep/removed"), b"old").unwrap();
    let (scan_id, source) = source(&root);
    // The new traversal must observe mutations rather than replay source-scan totals.
    fs::write(root.join("first/deep/file"), b"123456789").unwrap();
    fs::remove_file(root.join("second/deep/removed")).unwrap();
    fs::write(root.join("second/deep/added"), b"1234").unwrap();
    let mut oracle = Oracle::default();
    oracle.walk(&root, true);
    let probe = oracle.probe();
    let scanner = DetailRescanner::new(ProbedPlatform::new(Arc::clone(&probe)), limits());
    let mut updates = Vec::new();
    let fast = scanner
        .rescan_logical_with_progress(
            request(&scan_id, &source),
            &mut DetailEntryIdAllocator::new(scan_id.clone()).unwrap(),
            &CancellationToken::new(),
            |update| updates.push(update),
        )
        .unwrap();
    let full = scanner
        .rescan_with_progress(
            request(&scan_id, &source),
            &mut DetailEntryIdAllocator::new(scan_id.clone()).unwrap(),
            &CancellationToken::new(),
            |_| {},
        )
        .unwrap();
    assert!(fast.aggregate.coverage.complete);
    assert_eq!(
        fast.aggregate.apparent_logical_bytes,
        known_u128(oracle.logical)
    );
    assert_eq!(
        fast.aggregate.recursive_entry_count,
        known_count(oracle.entries)
    );
    assert_eq!(
        fast.aggregate.apparent_logical_bytes,
        full.aggregate.apparent_logical_bytes
    );
    assert_eq!(
        fast.aggregate.recursive_entry_count,
        full.aggregate.recursive_entry_count
    );
    assert_eq!(probe.native_lengths.load(Ordering::SeqCst), 3);
    assert!(matches!(
        fast.aggregate.unique_logical_bytes,
        EvidenceValue::Unknown { .. }
    ));
    assert!(matches!(
        fast.aggregate.filesystem_reported_allocated_bytes,
        EvidenceValue::Unknown { .. }
    ));
    assert!(matches!(
        fast.aggregate.potentially_reclaimable_bytes,
        EvidenceValue::Unknown { .. }
    ));
    let update = updates.last().unwrap();
    assert_eq!(update.native_file_lengths, 3);
    assert_eq!(update.rows.len(), 2);
    assert!(update.current_path.starts_with(&root));
    for row in &fast.rows {
        assert!(row.validated_identity().unwrap().is_some());
        assert!(row.executable_native_locator().unwrap().is_some());
        if row.object_type == ObjectType::Directory {
            let mut child_oracle = Oracle::default();
            child_oracle.walk(Path::new(&row.display_path), true);
            assert_eq!(row.logical_bytes, known_u128(child_oracle.logical));
        }
    }
    released(&probe);
}

#[test]
fn logical_usage_honors_cancellation_in_final_progress_callback() {
    let (_temp, root) = fixture();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/file"), b"123").unwrap();
    let (scan_id, source) = source(&root);
    let cancel = CancellationToken::new();
    let result = DetailRescanner::new(HostPlatformScanner::new(), limits())
        .rescan_logical_with_progress(
            request(&scan_id, &source),
            &mut DetailEntryIdAllocator::new(scan_id.clone()).unwrap(),
            &cancel,
            |_| cancel.cancel(),
        );
    assert_eq!(result, Err(DetailRescanError::Cancelled));
}

#[test]
fn child_mount_boundaries_keep_safe_siblings_and_lower_bound_totals() {
    for nested in [false, true] {
        for directory in [false, true] {
            let (_temp, root) = fixture();
            fs::create_dir(root.join("safe")).unwrap();
            fs::write(root.join("safe/file"), b"1234567").unwrap();
            fs::write(root.join("direct"), b"123").unwrap();
            let excluded = if nested {
                root.join("safe/mount")
            } else {
                root.join("mount")
            };
            if directory {
                fs::create_dir(&excluded).unwrap();
                fs::write(excluded.join("never-visit"), vec![9; 1024]).unwrap();
            } else {
                fs::write(&excluded, vec![9; 1024]).unwrap();
            }
            // Independent ordinary metadata gives the admitted file total. Excluded data must
            // contribute neither bytes nor descendant observations, regardless of row ordering.
            let expected = u128::from(fs::metadata(root.join("direct")).unwrap().len())
                + u128::from(fs::metadata(root.join("safe/file")).unwrap().len());
            let (scan_id, observed) = source(&root);
            for mode in ["listing", "full", "size", "strict"] {
                let probe = Arc::new(Probe::default());
                let mut platform = ProbedPlatform::new(Arc::clone(&probe));
                platform.mount_boundaries.insert(excluded.clone());
                let scanner = DetailRescanner::new(platform, limits());
                let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();
                let cancel = CancellationToken::new();
                if mode == "strict" {
                    let result = scanner.observe_direct_children(
                        request(&scan_id, &observed),
                        &mut ids,
                        &cancel,
                    );
                    if nested {
                        assert!(result.is_ok());
                    } else {
                        assert_eq!(result.unwrap_err(), DetailRescanError::MountChanged);
                    }
                } else {
                    let result = match mode {
                        "listing" => scanner.rescan_direct_children(
                            request(&scan_id, &observed),
                            &mut ids,
                            &cancel,
                        ),
                        "size" => scanner.rescan_logical_with_progress(
                            request(&scan_id, &observed),
                            &mut ids,
                            &cancel,
                            |_| {},
                        ),
                        _ => scanner.rescan(request(&scan_id, &observed), &mut ids, &cancel),
                    }
                    .unwrap();
                    let expected_rows = [root.join("safe"), root.join("direct")]
                        .into_iter()
                        .map(|path| path.display().to_string())
                        .collect::<BTreeSet<_>>();
                    assert_eq!(
                        result
                            .rows
                            .iter()
                            .map(|row| row.display_path.clone())
                            .collect::<BTreeSet<_>>(),
                        expected_rows
                    );
                    assert_eq!(result.aggregate.direct_child_count, known_count(2));
                    assert!(!result.aggregate.coverage.complete);
                    if mode != "listing" {
                        assert!(
                            result
                                .aggregate
                                .coverage
                                .incomplete_reasons
                                .contains(&ReasonCode::UnsupportedFilesystem)
                        );
                        assert_eq!(
                            result.aggregate.apparent_logical_bytes,
                            EvidenceValue::LowerBound {
                                value: DecimalU128::new(expected),
                                reason: ReasonCode::IncompleteStreamCoverage,
                            }
                        );
                        let safe = result
                            .rows
                            .iter()
                            .find(|row| row.display_path == root.join("safe").display().to_string())
                            .unwrap();
                        assert_eq!(safe.coverage.complete, !nested);
                        assert_eq!(
                            result.aggregate.recursive_entry_count,
                            known_count(if nested { 4 } else { 3 })
                        );
                    }
                }
                assert_eq!(probe.boundary_descendants.load(Ordering::SeqCst), 0);
                released(&probe);
            }
        }
    }
}

#[test]
fn detail_target_mount_change_and_uncertain_child_mount_still_fail_closed() {
    let (_temp, root) = fixture();
    fs::write(root.join("file"), b"123").unwrap();
    let (scan_id, observed) = source(&root);
    for changed_root in [false, true] {
        let probe = Arc::new(Probe::default());
        let mut platform = ProbedPlatform::new(Arc::clone(&probe));
        platform.changed_root_mount = changed_root;
        platform.unavailable_mount_comparison = !changed_root;
        let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();
        let result = DetailRescanner::new(platform, limits()).rescan_direct_children(
            request(&scan_id, &observed),
            &mut ids,
            &CancellationToken::new(),
        );
        assert_eq!(
            result.unwrap_err(),
            if changed_root {
                DetailRescanError::MountChanged
            } else {
                DetailRescanError::IdentityUnavailable
            }
        );
        released(&probe);
    }
}

#[test]
fn denied_or_disappearing_children_keep_siblings_without_claiming_complete_totals() {
    for io_kind in [
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::NotFound,
    ] {
        for scenario in ["direct", "nested", "enumeration"] {
            let (_temp, root) = fixture();
            fs::create_dir(root.join("safe")).unwrap();
            fs::write(root.join("safe/file"), b"1234567").unwrap();
            fs::write(root.join("direct"), b"123").unwrap();
            let excluded = if scenario == "nested" {
                root.join("safe/excluded")
            } else {
                root.join("excluded")
            };
            if scenario == "enumeration" {
                fs::create_dir(&excluded).unwrap();
                fs::write(excluded.join("never-read"), vec![9; 1024]).unwrap();
            } else {
                fs::write(&excluded, vec![9; 1024]).unwrap();
            }
            let expected = u128::from(fs::metadata(root.join("direct")).unwrap().len())
                + u128::from(fs::metadata(root.join("safe/file")).unwrap().len());
            let (scan_id, observed) = source(&root);
            for mode in ["full", "size", "listing", "strict"] {
                let probe = Arc::new(Probe::default());
                let mut platform = ProbedPlatform::new(Arc::clone(&probe));
                if scenario == "enumeration" {
                    platform
                        .enumeration_io_errors
                        .insert(excluded.clone(), io_kind);
                } else {
                    platform.child_io_errors.insert(excluded.clone(), io_kind);
                }
                let scanner = DetailRescanner::new(platform, limits());
                let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();
                let cancel = CancellationToken::new();
                if mode == "strict" {
                    let result = scanner.observe_direct_children(
                        request(&scan_id, &observed),
                        &mut ids,
                        &cancel,
                    );
                    if scenario == "direct" {
                        assert_eq!(
                            result.unwrap_err(),
                            if io_kind == std::io::ErrorKind::PermissionDenied {
                                DetailRescanError::IdentityUnavailable
                            } else {
                                DetailRescanError::IdentityMismatch
                            }
                        );
                    } else {
                        assert!(result.is_ok());
                    }
                } else {
                    let result = match mode {
                        "listing" => scanner.rescan_direct_children(
                            request(&scan_id, &observed),
                            &mut ids,
                            &cancel,
                        ),
                        "size" => scanner.rescan_logical_with_progress(
                            request(&scan_id, &observed),
                            &mut ids,
                            &cancel,
                            |_| {},
                        ),
                        _ => scanner.rescan(request(&scan_id, &observed), &mut ids, &cancel),
                    }
                    .unwrap();
                    let mut expected_rows = [root.join("safe"), root.join("direct")]
                        .into_iter()
                        .map(|path| path.display().to_string())
                        .collect::<BTreeSet<_>>();
                    if scenario == "enumeration" {
                        expected_rows.insert(excluded.display().to_string());
                    }
                    assert_eq!(
                        result
                            .rows
                            .iter()
                            .map(|row| row.display_path.clone())
                            .collect::<BTreeSet<_>>(),
                        expected_rows
                    );
                    assert_eq!(
                        result.aggregate.direct_child_count,
                        known_count(expected_rows.len() as u128)
                    );
                    assert!(!result.aggregate.coverage.complete);
                    if mode != "listing" {
                        assert_eq!(
                            result.aggregate.apparent_logical_bytes,
                            EvidenceValue::LowerBound {
                                value: DecimalU128::new(expected),
                                reason: ReasonCode::IncompleteStreamCoverage,
                            }
                        );
                        assert!(
                            result
                                .aggregate
                                .coverage
                                .incomplete_reasons
                                .contains(&if io_kind == std::io::ErrorKind::PermissionDenied {
                                    ReasonCode::StrictReadOnly
                                } else {
                                    ReasonCode::UnknownIdentity
                                })
                        );
                        let safe = result
                            .rows
                            .iter()
                            .find(|row| row.display_path == root.join("safe").display().to_string())
                            .unwrap();
                        assert_eq!(safe.coverage.complete, scenario != "nested");
                    }
                }
                released(&probe);
            }
        }
    }
}

#[test]
fn denied_target_enumeration_is_still_a_failure() {
    let (_temp, root) = fixture();
    let (scan_id, observed) = source(&root);
    let probe = Arc::new(Probe::default());
    let mut platform = ProbedPlatform::new(Arc::clone(&probe));
    platform
        .enumeration_io_errors
        .insert(root, std::io::ErrorKind::PermissionDenied);
    let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();
    let result = DetailRescanner::new(platform, limits()).rescan(
        request(&scan_id, &observed),
        &mut ids,
        &CancellationToken::new(),
    );
    assert_eq!(result.unwrap_err(), DetailRescanError::IdentityUnavailable);
    released(&probe);
}

#[test]
fn streamed_fallback_file_facts_keep_size_without_hard_link_or_allocation_claims() {
    let (_temp, root) = fixture();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/file"), b"12345").unwrap();
    fs::hard_link(root.join("nested/file"), root.join("nested/alias")).unwrap();
    let mut oracle = Oracle::default();
    oracle.walk(&root, true);
    let (scan_id, observed) = source(&root);
    let probe = oracle.probe();
    let mut platform = ProbedPlatform::new(Arc::clone(&probe));
    platform.force_full_file_observations = true;
    let result = DetailRescanner::new(platform, limits())
        .rescan_logical_with_progress(
            request(&scan_id, &observed),
            &mut DetailEntryIdAllocator::new(scan_id.clone()).unwrap(),
            &CancellationToken::new(),
            |_| {},
        )
        .unwrap();
    assert!(result.aggregate.coverage.complete);
    assert_eq!(
        result.aggregate.apparent_logical_bytes,
        known_u128(oracle.logical)
    );
    assert_eq!(
        result.aggregate.recursive_entry_count,
        known_count(oracle.entries)
    );
    assert!(matches!(
        result.aggregate.unique_logical_bytes,
        EvidenceValue::Unknown { .. }
    ));
    assert!(matches!(
        result.aggregate.filesystem_reported_allocated_bytes,
        EvidenceValue::Unknown { .. }
    ));
    assert!(matches!(
        result.aggregate.potentially_reclaimable_bytes,
        EvidenceValue::Unknown { .. }
    ));
    assert_eq!(probe.native_lengths.load(Ordering::SeqCst), 0);
    assert_eq!(result.rows.len(), 1);
    released(&probe);
}
