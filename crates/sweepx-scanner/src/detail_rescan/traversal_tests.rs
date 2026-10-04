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
    _lease: Lease,
}
struct ProbedPlatform {
    native: HostPlatformScanner,
    probe: Arc<Probe>,
    bad_batch: bool,
}
impl ProbedPlatform {
    fn new(probe: Arc<Probe>) -> Self {
        Self {
            native: HostPlatformScanner::new(),
            probe,
            bad_batch: false,
        }
    }
    fn handle(&self, native: NativeHandle) -> Handle {
        let live = self.probe.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.probe.peak.fetch_max(live, Ordering::SeqCst);
        let handle = Handle {
            native,
            _lease: Lease(Arc::clone(&self.probe)),
        };
        self.observe();
        handle
    }
    fn observed(&self, entry: WalkEntry<NativeHandle>) -> WalkEntry<Handle> {
        let entry = match entry {
            WalkEntry::Directory(opened) => WalkEntry::Directory(OpenedDirectory {
                metadata: opened.metadata,
                handle: self.handle(opened.handle),
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
        let opened = self.native.admit_root(root, cancel)?;
        Ok(RootAdmission::new(
            opened.root,
            opened.metadata,
            self.handle(opened.directory),
            opened.root_locator,
        ))
    }
    fn enumerate_children(
        &self,
        directory: &mut Handle,
        cancel: &CancellationToken,
        limits: DirectoryReadLimits,
    ) -> Result<DirectoryEntryBatch, PlatformError> {
        if self.bad_batch {
            return Ok(DirectoryEntryBatch {
                entries: Vec::new(),
                end_of_directory: false,
            });
        }
        let batch = self
            .native
            .enumerate_children(&mut directory.native, cancel, limits)?;
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
        self.native
            .inspect_child_with_mount_identity_and_directory_admission(
                &parent.native,
                child,
                cancel,
                admission,
            )
            .map(|entry| self.observed(entry))
    }
    fn is_same_mount(
        &self,
        root: &EntryMetadata,
        entry: &EntryMetadata,
    ) -> Result<bool, PlatformError> {
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
        assert!(!update.row.coverage.complete);
        assert!(
            result
                .rows
                .iter()
                .any(|row| row.identity == update.row.identity)
        );
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
