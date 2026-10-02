use super::*;
use crate::{HostPlatformScanner, Scanner, ScannerOptions};
use std::sync::atomic::{AtomicUsize, Ordering};
use sweepx_platform::{DirectoryEntryBatch, RegularFileStreamResult};

fn native(name: &str) -> NativeName {
    #[cfg(unix)]
    {
        NativeName::UnixBytes(name.as_bytes().to_vec())
    }
    #[cfg(windows)]
    {
        NativeName::WindowsUtf16(name.encode_utf16().collect())
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf, ScannedEntry) {
    // Explicit content reads reject unknown/FUSE/overlay providers on Linux.
    #[cfg(target_os = "linux")]
    let owner = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let owner = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = owner.path().canonicalize().unwrap();
    #[cfg(windows)]
    let root = owner.path().to_path_buf();
    let directory = root.join("captured");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("config.json"), b"{\"version\":2}").unwrap();
    let summary = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
        .scan(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();
    let captured = summary
        .entries
        .into_iter()
        .find(|entry| entry.native_basename == native("captured"))
        .unwrap();
    (owner, directory, captured)
}

struct ProbeScanner {
    inner: HostPlatformScanner,
    streams: AtomicUsize,
    mutation: Option<PathBuf>,
}

impl PlatformScanner for ProbeScanner {
    type DirectoryHandle = <HostPlatformScanner as PlatformScanner>::DirectoryHandle;
    fn platform_name(&self) -> &'static str {
        self.inner.platform_name()
    }
    fn admit_root(
        &self,
        root: &ScanRoot,
        cancel: &CancellationToken,
    ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
        self.inner.admit_root(root, cancel)
    }
    fn enumerate_children(
        &self,
        directory: &mut Self::DirectoryHandle,
        cancel: &CancellationToken,
        limits: DirectoryReadLimits,
    ) -> Result<DirectoryEntryBatch, PlatformError> {
        self.inner.enumerate_children(directory, cancel, limits)
    }
    fn inspect_child(
        &self,
        parent: &Self::DirectoryHandle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
    ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
        self.inner.inspect_child(parent, child, cancel)
    }
    fn inspect_child_with_directory_admission(
        &self,
        parent: &Self::DirectoryHandle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
        admission: DirectoryHandleAdmission,
    ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
        self.inner
            .inspect_child_with_directory_admission(parent, child, cancel, admission)
    }
    fn is_same_mount(
        &self,
        root: &sweepx_platform::EntryMetadata,
        entry: &sweepx_platform::EntryMetadata,
    ) -> Result<bool, PlatformError> {
        self.inner.is_same_mount(root, entry)
    }
    fn stream_regular_file_relative(
        &self,
        parent: &Self::DirectoryHandle,
        request: &RegularFileStreamRequest,
        cancel: &CancellationToken,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), BoundedRegularFileReadError>,
    ) -> Result<RegularFileStreamResult, BoundedRegularFileReadError> {
        let number = self.streams.fetch_add(1, Ordering::SeqCst);
        let result = self
            .inner
            .stream_regular_file_relative(parent, request, cancel, consume)?;
        if number == 0
            && let Some(path) = &self.mutation
        {
            assert_eq!(request.max_bytes(), 0);
            std::fs::write(path, b"{\"version\":2,\"new\":true}").unwrap();
        }
        Ok(result)
    }
}

fn new_reader(limits: LocatorReadLimits, mutation: Option<PathBuf>) -> LocatorReader<ProbeScanner> {
    LocatorReader::new(
        ProbeScanner {
            inner: HostPlatformScanner::new(),
            streams: AtomicUsize::new(0),
            mutation,
        },
        limits,
    )
}

#[test]
fn captured_ancestor_content_uses_full_lineage_and_never_display_parents() {
    let (_owner, directory, _captured) = fixture();
    let root = directory.parent().unwrap();
    let nested = directory.join("nested");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(root.join("manifest.toml"), b"root context").unwrap();
    std::fs::write(directory.join("manifest.toml"), b"parent context").unwrap();
    let summary = Scanner::new(HostPlatformScanner::new(), ScannerOptions::default())
        .scan(
            &[ScanRoot::new(root.to_path_buf()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();
    let mut captured = summary
        .entries
        .into_iter()
        .find(|entry| entry.native_basename == native("nested"))
        .unwrap();
    captured.display_path = "/invented/display/parent/nested".into();
    let reader = new_reader(LocatorReadLimits::default(), None);
    for (levels, path) in [(1, &directory), (2, &root.to_path_buf())] {
        let read = reader
            .read_captured_ancestor_regular_file(
                &captured,
                levels,
                &native("manifest.toml"),
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            read.bytes,
            std::fs::read(path.join("manifest.toml")).unwrap()
        );
        assert_eq!(read.observed_before, read.observed_after);
    }
    assert_eq!(reader.platform.streams.load(Ordering::SeqCst), 4);
    assert_eq!(
        reader.read_captured_ancestor_regular_file(
            &captured,
            3,
            &native("manifest.toml"),
            &CancellationToken::new()
        ),
        Err(LocatorReadFailure::InvalidBinding)
    );
    assert_eq!(reader.platform.streams.load(Ordering::SeqCst), 4);
    // Even a root-context read must budget the complete nested candidate validation.
    let limited = new_reader(
        LocatorReadLimits {
            max_total_components: 3,
            ..LocatorReadLimits::default()
        },
        None,
    );
    assert_eq!(
        limited.read_captured_ancestor_regular_file(
            &captured,
            2,
            &native("manifest.toml"),
            &CancellationToken::new()
        ),
        Err(LocatorReadFailure::ResourceLimit)
    );
    assert_eq!(limited.platform.streams.load(Ordering::SeqCst), 0);

    std::fs::rename(&nested, directory.join("retained-nested")).unwrap();
    std::fs::create_dir(&nested).unwrap();
    assert_eq!(
        reader.read_captured_ancestor_regular_file(
            &captured,
            1,
            &native("manifest.toml"),
            &CancellationToken::new()
        ),
        Err(LocatorReadFailure::IdentityMismatch)
    );
    assert_eq!(reader.platform.streams.load(Ordering::SeqCst), 4);
}

#[test]
fn ancestor_content_preserves_cancellation_read_bounds_and_probe_binding() {
    let (_owner, directory, captured) = fixture();
    let path = directory.parent().unwrap().join("manifest.toml");
    std::fs::write(&path, b"context").unwrap();
    let reader = new_reader(LocatorReadLimits::default(), Some(path.clone()));
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        reader.read_captured_ancestor_regular_file(&captured, 1, &native("manifest.toml"), &cancel),
        Err(LocatorReadFailure::Cancelled)
    );
    assert_eq!(reader.platform.streams.load(Ordering::SeqCst), 0);
    assert_eq!(
        reader.read_captured_ancestor_regular_file(
            &captured,
            1,
            &native("manifest.toml"),
            &CancellationToken::new()
        ),
        Err(LocatorReadFailure::ReadFailed)
    );
    let limited = new_reader(
        LocatorReadLimits {
            max_file_bytes: 1,
            ..LocatorReadLimits::default()
        },
        None,
    );
    assert_eq!(
        limited.read_captured_ancestor_regular_file(
            &captured,
            1,
            &native("manifest.toml"),
            &CancellationToken::new()
        ),
        Err(LocatorReadFailure::ResourceLimit)
    );
    assert_eq!(limited.platform.streams.load(Ordering::SeqCst), 1);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("manifest.toml", path.with_file_name("linked.toml")).unwrap();
        assert!(matches!(
            reader.read_captured_ancestor_regular_file(
                &captured,
                1,
                &native("linked.toml"),
                &CancellationToken::new()
            ),
            Err(LocatorReadFailure::SymlinkOrReparse | LocatorReadFailure::NotRegular)
        ));
    }
}

#[test]
fn captured_content_is_complete_bounded_and_independent_of_display_paths() {
    let (_owner, directory, mut captured) = fixture();
    captured.display_path = "forged display path".into();
    let oracle = std::fs::read(directory.join("config.json")).unwrap();
    let limits = LocatorReadLimits {
        max_file_bytes: oracle.len(),
        ..LocatorReadLimits::default()
    };
    let reader = new_reader(limits, None);
    let read = reader
        .read_captured_regular_file(&captured, &native("config.json"), &CancellationToken::new())
        .unwrap();
    assert_eq!(read.bytes, oracle);
    assert_eq!(read.observed_before, read.observed_after);
    assert_eq!(
        read.observed_after.logical_bytes.0,
        u128::from(
            std::fs::symlink_metadata(directory.join("config.json"))
                .unwrap()
                .len()
        )
    );
    assert_eq!(reader.platform.streams.load(Ordering::SeqCst), 2);
    std::fs::write(directory.join("empty"), []).unwrap();
    assert!(
        reader
            .read_captured_regular_file(&captured, &native("empty"), &CancellationToken::new())
            .unwrap()
            .bytes
            .is_empty()
    );
    let capped = new_reader(
        LocatorReadLimits {
            max_file_bytes: oracle.len() - 1,
            ..limits
        },
        None,
    );
    assert_eq!(
        capped.read_captured_regular_file(
            &captured,
            &native("config.json"),
            &CancellationToken::new()
        ),
        Err(LocatorReadFailure::ResourceLimit)
    );
    // Only the zero-payload probe ran: no truncated content was returned as a full file.
    assert_eq!(capped.platform.streams.load(Ordering::SeqCst), 1);
}

#[test]
fn captured_content_rejects_changes_links_replaced_parents_and_invalid_requests() {
    let (_owner, directory, captured) = fixture();
    let changing = new_reader(
        LocatorReadLimits::default(),
        Some(directory.join("config.json")),
    );
    assert_eq!(
        changing.read_captured_regular_file(
            &captured,
            &native("config.json"),
            &CancellationToken::new()
        ),
        Err(LocatorReadFailure::ReadFailed)
    );
    let normal = new_reader(LocatorReadLimits::default(), None);
    for name in ["../config.json", "a/b", "", ".", ".."] {
        assert_eq!(
            normal.read_captured_regular_file(&captured, &native(name), &CancellationToken::new()),
            Err(LocatorReadFailure::InvalidBinding)
        );
    }
    assert_eq!(normal.platform.streams.load(Ordering::SeqCst), 0);
    for limits in [
        LocatorReadLimits {
            max_requests: 1,
            ..LocatorReadLimits::default()
        },
        LocatorReadLimits {
            max_components_per_request: 0,
            ..LocatorReadLimits::default()
        },
        // This fixture needs root + captured directory + final filename (three components).
        LocatorReadLimits {
            max_components_per_request: 2,
            ..LocatorReadLimits::default()
        },
        LocatorReadLimits {
            max_total_components: 2,
            ..LocatorReadLimits::default()
        },
        LocatorReadLimits {
            max_directory_batch_bytes: 0,
            ..LocatorReadLimits::default()
        },
    ] {
        let limited = new_reader(limits, None);
        assert_eq!(
            limited.read_captured_regular_file(
                &captured,
                &native("config.json"),
                &CancellationToken::new()
            ),
            Err(LocatorReadFailure::ResourceLimit)
        );
        assert_eq!(limited.platform.streams.load(Ordering::SeqCst), 0);
    }
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        normal.read_captured_regular_file(&captured, &native("config.json"), &cancel),
        Err(LocatorReadFailure::Cancelled)
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("config.json", directory.join("linked")).unwrap();
        assert!(matches!(
            normal.read_captured_regular_file(
                &captured,
                &native("linked"),
                &CancellationToken::new()
            ),
            Err(LocatorReadFailure::SymlinkOrReparse | LocatorReadFailure::NotRegular)
        ));
    }
    std::fs::create_dir(directory.join("not-file")).unwrap();
    assert_eq!(
        normal.read_captured_regular_file(
            &captured,
            &native("not-file"),
            &CancellationToken::new()
        ),
        Err(LocatorReadFailure::NotRegular)
    );
    assert!(
        normal
            .read_captured_regular_file(&captured, &native("absent"), &CancellationToken::new())
            .is_err()
    );
    std::fs::rename(&directory, directory.with_file_name("retained-old-parent")).unwrap();
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("config.json"), b"replacement").unwrap();
    assert_eq!(
        normal.read_captured_regular_file(
            &captured,
            &native("config.json"),
            &CancellationToken::new()
        ),
        Err(LocatorReadFailure::IdentityMismatch)
    );
}
