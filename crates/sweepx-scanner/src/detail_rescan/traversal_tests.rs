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
    inspection_batch: Vec<DirectoryEntryRecord>,
    _lease: Lease,
}
struct ProbedPlatform {
    native: HostPlatformScanner,
    probe: Arc<Probe>,
    bad_batch: bool,
    require_enumerated_inspection: bool,
    mount_boundaries: BTreeSet<PathBuf>,
    changed_root_mount: bool,
    force_full_file_observations: bool,
    unavailable_mount_comparison: bool,
    child_io_errors: std::collections::BTreeMap<PathBuf, std::io::ErrorKind>,
    enumeration_io_errors: std::collections::BTreeMap<PathBuf, std::io::ErrorKind>,
    file_delay: Duration,
    volume_prefixes: std::collections::BTreeMap<PathBuf, u64>,
    aliases: std::collections::BTreeMap<PathBuf, EntryMetadata>,
}
impl ProbedPlatform {
    fn new(probe: Arc<Probe>) -> Self {
        Self {
            native: HostPlatformScanner::new(),
            probe,
            bad_batch: false,
            require_enumerated_inspection: false,
            mount_boundaries: BTreeSet::new(),
            changed_root_mount: false,
            force_full_file_observations: false,
            unavailable_mount_comparison: false,
            child_io_errors: std::collections::BTreeMap::new(),
            enumeration_io_errors: std::collections::BTreeMap::new(),
            file_delay: Duration::ZERO,
            volume_prefixes: Default::default(),
            aliases: Default::default(),
        }
    }
    fn handle(&self, native: NativeHandle, path: PathBuf) -> Handle {
        let live = self.probe.live.fetch_add(1, Ordering::SeqCst) + 1;
        self.probe.peak.fetch_max(live, Ordering::SeqCst);
        let handle = Handle {
            native,
            path,
            inspection_batch: Vec::new(),
            _lease: Lease(Arc::clone(&self.probe)),
        };
        self.observe();
        handle
    }
    fn check_child(
        &self,
        parent: &Handle,
        child: &DirectoryEntryRecord,
    ) -> Result<(), PlatformError> {
        if self.require_enumerated_inspection && !parent.inspection_batch.contains(child) {
            return Err(PlatformError::InvalidDirectoryEntry {
                parent: parent.path.clone(),
                detail: "child was not in this handle's current enumeration batch".into(),
            });
        }
        Ok(())
    }
    fn observed(&self, mut entry: WalkEntry<NativeHandle>) -> WalkEntry<Handle> {
        match &mut entry {
            WalkEntry::Directory(opened) => self.scope_metadata(&mut opened.metadata),
            WalkEntry::File(metadata) | WalkEntry::Link(metadata) => self.scope_metadata(metadata),
            _ => {}
        }
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
    fn scope_metadata(&self, metadata: &mut EntryMetadata) {
        if let Some((_, mount)) = self
            .volume_prefixes
            .iter()
            .rev()
            .find(|(prefix, _)| metadata.path.starts_with(prefix))
        {
            metadata.mount_identity = Some(sweepx_platform::MountIdentity { value: *mount });
        }
        if let Some(alias) = self.aliases.get(&metadata.path) {
            metadata.identity = alias.identity.clone();
            metadata.filesystem_identity = alias.filesystem_identity.clone();
            metadata.mount_identity = alias.mount_identity.clone();
        }
    }
}
impl PlatformScanner for ProbedPlatform {
    type DirectoryHandle = Handle;
    fn platform_name(&self) -> &'static str {
        self.native.platform_name()
    }
    fn child_inspection_requires_enumeration(&self) -> bool {
        self.require_enumerated_inspection || self.native.child_inspection_requires_enumeration()
    }

    fn admit_root(
        &self,
        root: &ScanRoot,
        cancel: &CancellationToken,
    ) -> Result<RootAdmission<Handle>, PlatformError> {
        self.probe.roots.fetch_add(1, Ordering::SeqCst);
        let mut opened = self.native.admit_root(root, cancel)?;
        self.scope_metadata(&mut opened.metadata);
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
        directory.inspection_batch = batch.entries.clone();
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
        self.check_child(parent, child)?;
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
        self.check_child(parent, child)?;
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
        self.check_child(parent, child)?;
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
        self.check_child(parent, child)?;
        if !self.file_delay.is_zero()
            && fs::symlink_metadata(&child.path).is_ok_and(|metadata| metadata.is_file())
        {
            std::thread::sleep(self.file_delay);
        }
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
        if !self.file_delay.is_zero() {
            std::thread::sleep(self.file_delay);
        }
        self.probe.native_lengths.fetch_add(1, Ordering::SeqCst);
        Some(file)
    }
    fn stream_regular_file_relative(
        &self,
        parent: &Handle,
        request: &sweepx_platform::RegularFileStreamRequest,
        cancel: &CancellationToken,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), sweepx_platform::BoundedRegularFileReadError>,
    ) -> Result<
        sweepx_platform::RegularFileStreamResult,
        sweepx_platform::BoundedRegularFileReadError,
    > {
        self.native
            .stream_regular_file_relative(&parent.native, request, cancel, consume)
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
fn named_reopens_obtain_current_batch_evidence_for_details_content_and_manifests() {
    use crate::{CargoConfigMemberObservation, LocatorReadLimits, LocatorReader};

    let (_temp, root) = fixture();
    let nested = root.join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("payload"), b"abcde").unwrap();
    fs::write(nested.join("manifest.json"), b"{}").unwrap();
    fs::create_dir(root.join(".cargo")).unwrap();
    fs::write(root.join(".cargo/config.toml"), b"[build]\n").unwrap();
    let cancel = CancellationToken::new();
    let summary = Scanner::new(
        HostPlatformScanner::new(),
        ScannerOptions {
            accelerated_preview: false,
            ..ScannerOptions::default()
        },
    )
    .scan(&[ScanRoot::new(&root).unwrap()], &cancel)
    .unwrap();
    let directory = summary
        .entries
        .iter()
        .find(|row| Path::new(&row.display_path) == nested)
        .unwrap();
    let file = summary
        .entries
        .iter()
        .find(|row| Path::new(&row.display_path) == nested.join("payload"))
        .unwrap();
    let request = DetailRescanRequest {
        source_scan_id: &directory.scan_id,
        source_root_identity: summary.roots[0].identity.as_ref().unwrap(),
        source_directory_identity: directory.identity.as_ref().unwrap(),
        directory_locator: directory.executable_native_locator().unwrap().unwrap(),
        revision: 1.into(),
        max_rows: 20,
    };
    let platform = || {
        let mut platform = ProbedPlatform::new(Arc::default());
        // Model Windows' strict native contract even on Unix CI. The wrapper refuses fabricated
        // tokens, so this exercises the caller/backend mismatch rather than trusting a flag.
        platform.require_enumerated_inspection = true;
        platform
    };
    let strict = platform();
    let admitted = strict
        .admit_root(&ScanRoot::new(&root).unwrap(), &cancel)
        .unwrap();
    let fabricated =
        DirectoryEntryRecord::from_parent_and_name(&root, directory.native_basename.clone())
            .unwrap();
    assert!(matches!(
        sweepx_platform::inspect_bound_child(
            &strict,
            &admitted.directory,
            &root,
            &fabricated,
            &cancel,
        ),
        Err(PlatformError::InvalidDirectoryEntry { .. })
    ));
    drop(admitted);
    let limits = ScanResourceLimits {
        max_directory_batch_entries: 1,
        ..limits()
    };
    let reader = DetailRescanner::new(platform(), limits);
    let mut ids = DetailEntryIdAllocator::new(directory.scan_id.clone()).unwrap();
    let observed = reader
        .observe_child(request, &file.native_basename, &mut ids, &cancel)
        .unwrap();
    assert_eq!(observed.logical_bytes, known_u128(5));
    let mut payload = Vec::new();
    reader
        .stream_file(
            FileContentRequest {
                entry: file,
                offset: 0,
                max_bytes: 5,
                previous: None,
            },
            &cancel,
            &mut |bytes| {
                payload.extend_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(payload, fs::read(nested.join("payload")).unwrap());
    fs::write(nested.join("payload"), b"updated-current").unwrap();
    let refreshed = reader.rescan(request, &mut ids, &cancel).unwrap();
    assert!(refreshed.aggregate.coverage.complete);
    assert_eq!(refreshed.aggregate.apparent_logical_bytes, known_u128(17));

    let locator = LocatorReader::new(
        platform(),
        LocatorReadLimits {
            max_components_per_request: 64,
            max_total_components: 128,
            max_directory_batch_entries: 1,
            ..LocatorReadLimits::default()
        },
    );
    let captured = locator.capture_directory_identity(&root, &cancel).unwrap();
    let captured_child = locator
        .capture_child_directory(&captured, &directory.native_basename, &cancel)
        .unwrap();
    let manifest = summary
        .entries
        .iter()
        .find(|row| Path::new(&row.display_path) == nested.join("manifest.json"))
        .unwrap();
    let bytes = locator.read_cargo_config_include_in_captured_directory(
        &captured_child,
        &manifest.native_basename,
        &cancel,
    );
    assert_eq!(bytes.observed_bytes().unwrap(), b"{}");
    let pair = locator
        .read_cargo_config_pair_in_captured_directory(&captured, true, &cancel)
        .unwrap();
    assert_eq!(pair.config_toml.observed_bytes().unwrap(), b"[build]\n");
    assert_eq!(
        pair.config,
        CargoConfigMemberObservation::AbsentDuringEnumeration
    );

    let limited_locator = LocatorReader::new(
        platform(),
        LocatorReadLimits {
            max_components_per_request: 64,
            max_total_components: 128,
            max_directory_entries: 0,
            ..LocatorReadLimits::default()
        },
    );
    assert_eq!(
        limited_locator.capture_child_directory(&captured, &directory.native_basename, &cancel),
        Err(crate::LocatorDirectoryLookupFailure::Read(
            crate::LocatorReadFailure::ResourceLimit
        ))
    );
    let pair = limited_locator
        .read_cargo_config_pair_in_captured_directory(&captured, true, &cancel)
        .unwrap();
    assert_eq!(
        pair.config,
        CargoConfigMemberObservation::Failed(crate::LocatorReadFailure::ResourceLimit)
    );
    assert_eq!(pair.config_toml, pair.config);

    // Resource refusal and a replaced parent remain failures, never accepted content or rows.
    let limited = DetailRescanner::new(
        platform(),
        ScanResourceLimits {
            max_directory_entries: 0,
            ..limits
        },
    );
    assert!(matches!(
        limited.rescan(request, &mut ids, &cancel),
        Err(DetailRescanError::ResourceLimit)
    ));
    let mut malformed = platform();
    malformed.bad_batch = true;
    assert!(matches!(
        DetailRescanner::new(malformed, ScanResourceLimits::default())
            .rescan(request, &mut ids, &cancel),
        Err(DetailRescanError::Unavailable)
    ));
    fs::rename(&nested, root.join("original")).unwrap();
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("payload"), b"abcde").unwrap();
    assert!(matches!(
        reader.rescan(request, &mut ids, &cancel),
        Err(DetailRescanError::IdentityMismatch)
    ));
}

#[test]
fn captured_cargo_lookup_rejects_case_alias_when_enumeration_is_required() {
    use crate::{
        CargoConfigMemberObservation, LocatorReadFailure, LocatorReadLimits, LocatorReader,
    };

    let (_temp, root) = fixture();
    fs::create_dir(root.join(".CARGO")).unwrap();
    fs::write(root.join(".CARGO/config.toml"), b"[build]\n").unwrap();
    let mut platform = ProbedPlatform::new(Arc::default());
    platform.require_enumerated_inspection = true;
    let reader = LocatorReader::new(
        platform,
        LocatorReadLimits {
            max_components_per_request: 64,
            max_total_components: 128,
            max_directory_batch_entries: 1,
            ..LocatorReadLimits::default()
        },
    );
    let cancel = CancellationToken::new();
    let captured = reader.capture_directory_identity(&root, &cancel).unwrap();
    let pair = reader
        .read_cargo_config_pair_in_captured_directory(&captured, true, &cancel)
        .unwrap();
    assert_eq!(
        pair.config,
        CargoConfigMemberObservation::Failed(LocatorReadFailure::AmbiguousAlias)
    );
    assert_eq!(pair.config_toml, pair.config);
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
fn completed_directory_observations_match_each_independent_subtree_walk() {
    let (_temp, root) = fixture();
    let directories = [
        root.clone(),
        root.join("first"),
        root.join("first/deep"),
        root.join("second"),
        root.join("empty"),
    ];
    for directory in &directories {
        fs::create_dir_all(directory).unwrap();
    }
    fs::write(root.join("direct"), b"123").unwrap();
    fs::write(root.join("first/a"), b"12345").unwrap();
    fs::write(root.join("first/deep/b"), b"1234567").unwrap();
    fs::hard_link(root.join("first/a"), root.join("second/alias")).unwrap();
    let (scan_id, observed) = source(&root);
    let mut sizes = Vec::new();
    let result = DetailRescanner::new(HostPlatformScanner::new(), limits())
        .rescan_logical_with_directory_observations(
            request(&scan_id, &observed),
            &mut DetailEntryIdAllocator::new(scan_id.clone()).unwrap(),
            &CancellationToken::new(),
            |_| {},
            |size| sizes.push(size),
        )
        .unwrap();
    assert_eq!(sizes.len(), directories.len());
    for directory in directories {
        let (_, native) = source(&directory);
        let identity = native.identity.unwrap();
        let size = sizes
            .iter()
            .find(|size| size.identity.platform_file_identity == identity.platform_file_identity)
            .unwrap();
        let mut oracle = Oracle::default();
        oracle.walk(&directory, true);
        assert_eq!(
            size.aggregate.apparent_logical_bytes,
            known_u128(oracle.logical)
        );
        assert_eq!(
            size.aggregate.recursive_entry_count,
            known_count(oracle.entries)
        );
        assert_eq!(
            size.aggregate.direct_child_count,
            known_count(oracle.direct)
        );
        assert!(size.aggregate.coverage.complete);
        if directory != root {
            assert!(matches!(
                size.aggregate.filesystem_reported_allocated_bytes,
                EvidenceValue::Unknown { .. }
            ));
            assert!(matches!(
                size.aggregate.unique_logical_bytes,
                EvidenceValue::Unknown { .. }
            ));
        }
    }
    assert_eq!(sizes.last().unwrap().aggregate, result.aggregate);
}

#[test]
fn active_nested_progress_includes_unfinished_descendants_without_double_counting() {
    let (_temp, root) = fixture();
    fs::create_dir_all(root.join("child/deep")).unwrap();
    fs::write(root.join("child/deep/a"), b"1234567").unwrap();
    fs::write(root.join("child/deep/b"), b"123456789").unwrap();
    let mut oracle = Oracle::default();
    oracle.walk(&root, true);
    let (scan_id, observed) = source(&root);
    let (_, child) = source(&root.join("child"));
    let (_, deep) = source(&root.join("child/deep"));
    let probe = Arc::new(Probe::default());
    let mut platform = ProbedPlatform::new(Arc::clone(&probe));
    // A controlled native file observation exceeds the measured 120 ms presentation interval.
    // Neither the expected byte values nor this delay are derived from the implementation constant.
    platform.file_delay = Duration::from_millis(200);
    let mut updates = Vec::new();
    let result = DetailRescanner::new(platform, limits())
        .rescan_logical_with_directory_observations(
            request(&scan_id, &observed),
            &mut DetailEntryIdAllocator::new(scan_id.clone()).unwrap(),
            &CancellationToken::new(),
            |progress| updates.push(progress),
            |_| {},
        )
        .unwrap();
    let intermediate = updates.iter().find(|progress| {
        progress.directory_sizes.iter().any(|size| {
            size.identity.platform_file_identity == deep.identity.as_ref().unwrap().platform_file_identity
                && matches!(size.aggregate.apparent_logical_bytes, EvidenceValue::LowerBound {value, ..} if value.0 > 0 && value.0 < oracle.logical)
        })
    }).expect("unfinished nested file contribution was not streamed");
    let parent = intermediate
        .directory_sizes
        .iter()
        .find(|size| {
            size.identity.platform_file_identity
                == child.identity.as_ref().unwrap().platform_file_identity
        })
        .unwrap();
    let leaf = intermediate
        .directory_sizes
        .iter()
        .find(|size| {
            size.identity.platform_file_identity
                == deep.identity.as_ref().unwrap().platform_file_identity
        })
        .unwrap();
    assert_eq!(
        parent.aggregate.apparent_logical_bytes,
        leaf.aggregate.apparent_logical_bytes
    );
    assert!(!parent.aggregate.coverage.complete && !leaf.aggregate.coverage.complete);
    assert!(
        updates
            .iter()
            .all(|progress| progress.directory_sizes.len() <= 2)
    );
    assert_eq!(
        result.aggregate.apparent_logical_bytes,
        known_u128(oracle.logical)
    );
    assert_eq!(
        result.aggregate.recursive_entry_count,
        known_count(oracle.entries)
    );
    released(&probe);
}

#[test]
fn final_directory_observation_cancellation_never_publishes_success() {
    let (_temp, root) = fixture();
    fs::create_dir_all(root.join("nested/deep")).unwrap();
    fs::write(root.join("nested/deep/file"), b"123").unwrap();
    let (scan_id, observed) = source(&root);
    let cancel = CancellationToken::new();
    let result = DetailRescanner::new(HostPlatformScanner::new(), limits())
        .rescan_logical_with_directory_observations(
            request(&scan_id, &observed),
            &mut DetailEntryIdAllocator::new(scan_id.clone()).unwrap(),
            &cancel,
            |_| {},
            |size| {
                if size.identity == *observed.identity.as_ref().unwrap() {
                    cancel.cancel();
                }
            },
        );
    assert_eq!(result, Err(DetailRescanError::Cancelled));
}

#[test]
fn nested_size_snapshot_inventory_matches_direct_listing_across_excluded_children() {
    for denied in [false, true] {
        let (_temp, root) = fixture();
        fs::create_dir(root.join("child")).unwrap();
        fs::write(root.join("child/file"), b"1234567").unwrap();
        fs::create_dir(root.join("child/excluded")).unwrap();
        fs::write(root.join("child/excluded/never-read"), vec![9; 1024]).unwrap();
        let (scan_id, observed) = source(&root);
        let probe = Arc::new(Probe::default());
        let mut platform = ProbedPlatform::new(Arc::clone(&probe));
        let excluded = root.join("child/excluded");
        if denied {
            platform
                .child_io_errors
                .insert(excluded.clone(), std::io::ErrorKind::PermissionDenied);
        } else {
            platform.mount_boundaries.insert(excluded.clone());
        }
        let scanner = DetailRescanner::new(platform, limits());
        let mut sizes = Vec::new();
        let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();
        let detail = scanner
            .rescan_logical_with_directory_observations(
                request(&scan_id, &observed),
                &mut ids,
                &CancellationToken::new(),
                |_| {},
                |size| sizes.push(size),
            )
            .unwrap();
        let child = detail
            .rows
            .iter()
            .find(|row| row.object_type == ObjectType::Directory)
            .unwrap();
        let snapshot = sizes
            .iter()
            .find(|size| size.identity.entry_id == child.identity.as_ref().unwrap().entry_id)
            .unwrap();
        let listing = scanner
            .rescan_direct_children(
                DetailRescanRequest {
                    source_directory_identity: child.identity.as_ref().unwrap(),
                    directory_locator: child.executable_native_locator().unwrap().unwrap(),
                    ..request(&scan_id, &observed)
                },
                &mut ids,
                &CancellationToken::new(),
            )
            .unwrap();
        let admitted = fs::read_dir(root.join("child"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path != &excluded)
            .collect::<Vec<_>>();
        assert_eq!(listing.rows.len(), admitted.len());
        assert_eq!(
            snapshot.aggregate.direct_child_count,
            known_count(admitted.len() as u128)
        );
        assert_eq!(
            snapshot.aggregate.direct_child_count,
            listing.aggregate.direct_child_count
        );
        assert!(!snapshot.aggregate.coverage.complete);
        assert!(!listing.aggregate.coverage.complete);
        assert_eq!(
            snapshot.aggregate.apparent_logical_bytes,
            EvidenceValue::LowerBound {
                value: DecimalU128::new(
                    fs::metadata(root.join("child/file")).unwrap().len() as u128
                ),
                reason: ReasonCode::IncompleteStreamCoverage,
            }
        );
        released(&probe);
    }
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
                                DetailRescanError::AccessDenied
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
    assert_eq!(result.unwrap_err(), DetailRescanError::AccessDenied);
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

#[test]
fn all_detail_modes_share_two_volume_admission_and_alias_deduplication() {
    let (_temp, root) = fixture();
    let logical = root.join("Users");
    let data = root.join("Data");
    let alias = data.join("Users");
    let outside = root.join("external");
    for path in [&logical, &data, &alias, &outside] {
        fs::create_dir(path).unwrap();
    }
    fs::write(logical.join("user-file"), b"1234567").unwrap();
    // A controlled namespace fixture models two firmlink entrances to one native directory.
    // The alternate entrance has the same content and native identity; its traversal must stop.
    fs::write(alias.join("user-file"), b"1234567").unwrap();
    fs::write(data.join("unique"), b"12345678901").unwrap();
    fs::write(root.join("system-file"), b"1234567890123").unwrap();
    fs::write(outside.join("excluded-file"), vec![0; 1000]).unwrap();
    let denied = root.join("denied");
    fs::create_dir(&denied).unwrap();
    let expected = [
        &logical.join("user-file"),
        &data.join("unique"),
        &root.join("system-file"),
    ]
    .into_iter()
    .map(|p| u128::from(fs::metadata(p).unwrap().len()))
    .sum::<u128>();
    assert_eq!(expected, 31);
    let (scan_id, observed) = source(&root);
    let probe = Arc::new(Probe::default());
    let mut platform = ProbedPlatform::new(Arc::clone(&probe));
    platform.volume_prefixes.insert(logical.clone(), 100);
    platform.volume_prefixes.insert(data.clone(), 100);
    platform.volume_prefixes.insert(outside.clone(), 200);
    platform
        .child_io_errors
        .insert(denied.clone(), std::io::ErrorKind::PermissionDenied);
    let cancel = CancellationToken::new();
    let logical_metadata = platform
        .admit_root(&ScanRoot::new(&logical).unwrap(), &cancel)
        .unwrap()
        .metadata;
    let data_metadata = platform
        .admit_root(&ScanRoot::new(&data).unwrap(), &cancel)
        .unwrap()
        .metadata;
    platform
        .aliases
        .insert(alias.clone(), logical_metadata.clone());
    let mut scanner = DetailRescanner::new(
        platform,
        ScanResourceLimits {
            max_frontier_entries: 8,
            ..limits()
        },
    )
    .with_size_browser();
    scanner.scope_override = Some(volume_scope::VolumeScope {
        data: Some(data_metadata),
        aliases: [(alias.clone(), logical_metadata)].into_iter().collect(),
        unverified_logical: Default::default(),
    });
    let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();
    let listing = scanner
        .rescan_direct_children(request(&scan_id, &observed), &mut ids, &cancel)
        .unwrap();
    assert_eq!(listing.rows.len(), fs::read_dir(&root).unwrap().count());
    for (path, reason) in [
        (&outside, ReasonCode::UnsupportedFilesystem),
        (&denied, ReasonCode::StrictReadOnly),
    ] {
        let row = listing
            .rows
            .iter()
            .find(|row| row.display_path == path.display().to_string())
            .unwrap();
        assert_eq!(row.logical_bytes, EvidenceValue::Unknown { reason });
        assert!(row.executable_native_locator().unwrap().is_none());
    }
    let mut observations = Vec::new();
    let complete = scanner
        .rescan_logical_with_directory_observations(
            request(&scan_id, &observed),
            &mut ids,
            &cancel,
            |_| {},
            |o| observations.push(o),
        )
        .unwrap();
    assert_eq!(
        complete.aggregate.apparent_logical_bytes,
        EvidenceValue::LowerBound {
            value: DecimalU128::new(expected),
            reason: ReasonCode::IncompleteStreamCoverage
        }
    );
    let data_row = complete
        .rows
        .iter()
        .find(|row| row.display_path == data.display().to_string())
        .unwrap();
    assert_eq!(data_row.logical_bytes, known_u128(11));
    let users = complete
        .rows
        .iter()
        .find(|row| row.display_path == logical.display().to_string())
        .unwrap();
    assert_eq!(users.logical_bytes, known_u128(7));
    let subrequest = DetailRescanRequest {
        source_directory_identity: users.identity.as_ref().unwrap(),
        directory_locator: users.executable_native_locator().unwrap().unwrap(),
        ..request(&scan_id, &observed)
    };
    assert_eq!(
        scanner
            .rescan_direct_children(subrequest, &mut ids, &cancel)
            .unwrap()
            .rows
            .len(),
        1
    );
    // Strict inventory has the same volume scope, while retaining every native direct row.
    let strict = scanner
        .observe_direct_children(subrequest, &mut ids, &cancel)
        .unwrap();
    assert_eq!(strict.len(), 1);
    assert_eq!(strict[0].logical_bytes, known_u128(7));
    assert!(strict[0].executable_native_locator().unwrap().is_some());
    scanner.revalidate_directory(subrequest, &cancel).unwrap();
    #[cfg(unix)]
    let child_name = sweepx_model::NativeName::unix(b"user-file".to_vec());
    #[cfg(windows)]
    let child_name =
        sweepx_model::NativeName::windows_utf16("user-file".encode_utf16().collect::<Vec<_>>());
    let child = scanner
        .observe_child(subrequest, &child_name, &mut ids, &cancel)
        .unwrap();
    assert_eq!(child.logical_bytes, known_u128(7));
    let data_request = DetailRescanRequest {
        source_directory_identity: data_row.identity.as_ref().unwrap(),
        directory_locator: data_row.executable_native_locator().unwrap().unwrap(),
        ..request(&scan_id, &observed)
    };
    let data_listing = scanner
        .rescan_direct_children(data_request, &mut ids, &cancel)
        .unwrap();
    let alias_row = data_listing
        .rows
        .iter()
        .find(|row| row.display_path == alias.display().to_string())
        .unwrap();
    assert!(!matches!(
        alias_row.logical_bytes,
        EvidenceValue::NotChecked { .. }
    ));
    assert!(alias_row.executable_native_locator().unwrap().is_some());
    let expected_data = u128::from(fs::metadata(data.join("unique")).unwrap().len())
        + u128::from(fs::metadata(alias.join("user-file")).unwrap().len());
    assert_eq!(expected_data, 18);
    let data_detail = scanner.rescan(data_request, &mut ids, &cancel).unwrap();
    assert_eq!(
        data_detail.aggregate.apparent_logical_bytes,
        known_u128(expected_data)
    );
    let measured_alias = data_detail
        .rows
        .iter()
        .find(|row| row.display_path == alias.display().to_string())
        .unwrap();
    assert_eq!(measured_alias.logical_bytes, known_u128(7));
    assert!(
        observations
            .iter()
            .any(|o| o.identity == *users.identity.as_ref().unwrap())
    );
    // Full-fact junk breakdowns and logical aggregation use the same admitted and deduplicated
    // native objects even without the size browser's visible-exclusion presentation option.
    scanner.size_browser = false;
    for logical_only in [false, true] {
        let measured = if logical_only {
            scanner.rescan_logical_with_progress(
                request(&scan_id, &observed),
                &mut ids,
                &cancel,
                |_| {},
            )
        } else {
            scanner.rescan(request(&scan_id, &observed), &mut ids, &cancel)
        }
        .unwrap();
        assert_eq!(
            measured.aggregate.apparent_logical_bytes,
            EvidenceValue::LowerBound {
                value: DecimalU128::new(expected),
                reason: ReasonCode::IncompleteStreamCoverage,
            }
        );
        assert!(
            measured
                .rows
                .iter()
                .any(|row| row.display_path == logical.display().to_string())
        );
        assert!(
            measured
                .rows
                .iter()
                .any(|row| row.display_path == data.display().to_string())
        );
        assert!(
            !measured
                .rows
                .iter()
                .any(|row| row.display_path == outside.display().to_string())
        );
    }
    released(&probe);
}

#[test]
fn verified_alias_replacement_or_missing_identity_fails_closed() {
    let (_temp, root) = fixture();
    let cancel = CancellationToken::new();
    let platform = HostPlatformScanner::new();
    let metadata = platform
        .admit_root(&ScanRoot::new(&root).unwrap(), &cancel)
        .unwrap()
        .metadata;
    let scope = volume_scope::VolumeScope {
        aliases: [(root.clone(), metadata.clone())].into_iter().collect(),
        ..Default::default()
    };
    assert!(scope.is_counted_alias(&metadata).unwrap());
    for change in ["object", "filesystem", "mount", "kind", "changed_mount"] {
        let mut changed = metadata.clone();
        match change {
            "object" => changed.identity = None,
            "filesystem" => changed.filesystem_identity = None,
            "mount" => changed.mount_identity = None,
            "kind" => changed.kind = EntryKind::File,
            "changed_mount" => {
                let mount = changed.mount_identity.as_mut().unwrap();
                mount.value = mount.value.wrapping_add(1);
            }
            _ => unreachable!(),
        }
        assert_eq!(
            scope.is_counted_alias(&changed),
            Err(VolumeScopeError::IdentityMismatch),
            "{change} must not turn the captured alias into uncounted coverage",
        );
    }
}

#[test]
fn logical_firmlink_or_data_root_replacement_on_the_same_mount_fails_closed() {
    for replace_data in [false, true] {
        let (_temp, root) = fixture();
        let logical = root.join("Users");
        let data = root.join("Data");
        let physical = data.join("Users");
        for path in [&logical, &data, &physical] {
            fs::create_dir(path).unwrap();
        }
        fs::write(logical.join("old-content"), b"old logical bytes").unwrap();
        fs::write(physical.join("old-content"), b"old logical bytes").unwrap();
        let (scan_id, observed) = source(&root);
        let probe = Arc::new(Probe::default());
        let mut platform = ProbedPlatform::new(Arc::clone(&probe));
        platform.volume_prefixes.insert(logical.clone(), 100);
        platform.volume_prefixes.insert(data.clone(), 100);
        let cancel = CancellationToken::new();
        let logical_metadata = platform
            .admit_root(&ScanRoot::new(&logical).unwrap(), &cancel)
            .unwrap()
            .metadata;
        let data_metadata = platform
            .admit_root(&ScanRoot::new(&data).unwrap(), &cancel)
            .unwrap()
            .metadata;
        platform
            .aliases
            .insert(physical.clone(), logical_metadata.clone());
        let mut scanner = DetailRescanner::new(platform, limits());
        scanner.scope_override = Some(volume_scope::VolumeScope {
            data: Some(data_metadata),
            aliases: [(physical, logical_metadata)].into_iter().collect(),
            unverified_logical: Default::default(),
        });
        let replaced = if replace_data { &data } else { &logical };
        fs::rename(replaced, root.join("preserved-original")).unwrap();
        fs::create_dir(replaced).unwrap();
        fs::write(replaced.join("new-content"), b"new bytes").unwrap();
        assert_eq!(
            scanner.rescan(
                request(&scan_id, &observed),
                &mut DetailEntryIdAllocator::new(scan_id.clone()).unwrap(),
                &cancel,
            ),
            Err(DetailRescanError::IdentityMismatch),
            "same-mount replacement must not justify dropping the original alias",
        );
        assert_eq!(
            fs::read(root.join("preserved-original/old-content")).unwrap_or_else(|_| {
                fs::read(root.join("preserved-original/Users/old-content")).unwrap()
            }),
            b"old logical bytes",
        );
        released(&probe);
    }
}

#[test]
fn logical_file_length_shortcut_cannot_accept_a_tracked_directory_replaced_by_file() {
    let (_temp, root) = fixture();
    let logical = root.join("Users");
    let data = root.join("Data");
    let physical = data.join("Users");
    for path in [&logical, &data, &physical] {
        fs::create_dir(path).unwrap();
    }
    let (scan_id, observed) = source(&root);
    let probe = Arc::new(Probe::default());
    let mut platform = ProbedPlatform::new(Arc::clone(&probe));
    platform.volume_prefixes.insert(logical.clone(), 100);
    platform.volume_prefixes.insert(data.clone(), 100);
    let cancel = CancellationToken::new();
    let logical_metadata = platform
        .admit_root(&ScanRoot::new(&logical).unwrap(), &cancel)
        .unwrap()
        .metadata;
    let data_metadata = platform
        .admit_root(&ScanRoot::new(&data).unwrap(), &cancel)
        .unwrap()
        .metadata;
    platform
        .aliases
        .insert(physical.clone(), logical_metadata.clone());
    let mut scanner = DetailRescanner::new(platform, limits());
    scanner.scope_override = Some(volume_scope::VolumeScope {
        data: Some(data_metadata),
        aliases: [(physical.clone(), logical_metadata)].into_iter().collect(),
        unverified_logical: Default::default(),
    });
    fs::rename(&physical, data.join("preserved-directory")).unwrap();
    fs::write(
        &physical,
        b"ordinary file must not inherit the directory admission",
    )
    .unwrap();
    assert_eq!(
        scanner.rescan_logical_with_progress(
            request(&scan_id, &observed),
            &mut DetailEntryIdAllocator::new(scan_id.clone()).unwrap(),
            &cancel,
            |_| {},
        ),
        Err(DetailRescanError::IdentityMismatch),
    );
    assert!(data.join("preserved-directory").is_dir());
    released(&probe);
}

#[cfg(unix)]
#[test]
fn native_socket_exclusion_does_not_claim_a_foreign_volume() {
    use std::os::unix::{fs::FileTypeExt, net::UnixListener};
    let (_temp, root) = fixture();
    let socket = root.join("socket");
    let _listener = UnixListener::bind(&socket).unwrap();
    assert!(
        fs::symlink_metadata(&socket)
            .unwrap()
            .file_type()
            .is_socket()
    );
    let (scan_id, source) = source(&root);
    let detail = DetailRescanner::new(HostPlatformScanner::new(), limits())
        .with_size_browser()
        .rescan_direct_children(
            request(&scan_id, &source),
            &mut DetailEntryIdAllocator::new(scan_id.clone()).unwrap(),
            &CancellationToken::new(),
        )
        .unwrap();
    let row = detail
        .rows
        .iter()
        .find(|row| row.display_path == socket.display().to_string())
        .unwrap();
    assert_eq!(
        row.logical_bytes,
        EvidenceValue::Unknown {
            reason: ReasonCode::AdapterCapabilityAbsent
        }
    );
    assert!(row.executable_native_locator().unwrap().is_none());
}
