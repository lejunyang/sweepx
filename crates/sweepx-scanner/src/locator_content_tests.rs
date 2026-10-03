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
    deny_stream: bool,
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
    fn inspect_child_with_mount_identity(
        &self,
        parent: &Self::DirectoryHandle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
    ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
        self.inner
            .inspect_child_with_mount_identity(parent, child, cancel)
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
        if self.deny_stream {
            return Err(BoundedRegularFileReadError::ProviderOrOffline(
                "controlled provider refusal".into(),
            ));
        }
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
            deny_stream: false,
        },
        limits,
    )
}

#[test]
fn captured_include_reads_match_ordinary_bytes_and_refuse_probe_races_and_provider_reads() {
    let (_owner, directory, _) = fixture();
    let path = directory.join("input.toml");
    std::fs::write(&path, b"[build]\ntarget-dir='ordinary'\n").unwrap();
    let reader = new_reader(Default::default(), None);
    let cancel = CancellationToken::new();
    let captured = reader
        .capture_directory_identity(&directory, &cancel)
        .unwrap();
    let CargoConfigMemberObservation::Present(read) = reader
        .read_cargo_config_include_in_captured_directory(&captured, &native("input.toml"), &cancel)
    else {
        panic!("complete ordinary include missing");
    };
    assert_eq!(read.bytes, std::fs::read(&path).unwrap());
    assert_eq!(
        read.observed_after.logical_bytes.to_string(),
        std::fs::metadata(&path).unwrap().len().to_string()
    );
    assert_eq!(reader.platform.streams.load(Ordering::SeqCst), 2);

    let mut denied = new_reader(Default::default(), None);
    denied.platform.deny_stream = true;
    assert!(matches!(
        denied.read_cargo_config_include_in_captured_directory(
            &captured,
            &native("input.toml"),
            &cancel
        ),
        CargoConfigMemberObservation::Failed(LocatorReadFailure::ProviderOrOffline)
    ));
    assert_eq!(denied.platform.streams.load(Ordering::SeqCst), 1);
    let changed = new_reader(Default::default(), Some(path));
    assert!(matches!(
        changed.read_cargo_config_include_in_captured_directory(
            &captured,
            &native("input.toml"),
            &cancel
        ),
        CargoConfigMemberObservation::Failed(_)
    ));
}

#[test]
fn captured_include_admission_and_absence_do_not_bypass_native_read_limits() {
    let (_owner, directory, _) = fixture();
    let reader = new_reader(Default::default(), None);
    let cancel = CancellationToken::new();
    let captured = reader
        .capture_directory_identity(&directory, &cancel)
        .unwrap();
    assert_eq!(
        reader.read_cargo_config_include_in_captured_directory(
            &captured,
            &native("missing.toml"),
            &cancel
        ),
        CargoConfigMemberObservation::AbsentDuringLookup
    );
    let invalid = new_reader(Default::default(), None);
    assert_eq!(
        invalid.read_cargo_config_include_in_captured_directory(
            &captured,
            &native("../other.toml"),
            &cancel
        ),
        CargoConfigMemberObservation::Failed(LocatorReadFailure::InvalidBinding)
    );
    assert_eq!(invalid.platform.streams.load(Ordering::SeqCst), 0);
    let limited = new_reader(
        LocatorReadLimits {
            max_requests: 1,
            ..Default::default()
        },
        None,
    );
    assert_eq!(
        limited.read_cargo_config_include_in_captured_directory(
            &captured,
            &native("input.toml"),
            &cancel
        ),
        CargoConfigMemberObservation::Failed(LocatorReadFailure::ResourceLimit)
    );
    assert_eq!(limited.platform.streams.load(Ordering::SeqCst), 0);
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        reader.read_cargo_config_include_in_captured_directory(
            &captured,
            &native("missing.toml"),
            &cancel
        ),
        CargoConfigMemberObservation::Failed(LocatorReadFailure::Cancelled)
    );
    #[cfg(unix)]
    {
        let cancel = CancellationToken::new();
        std::os::unix::fs::symlink("config.json", directory.join("linked.toml")).unwrap();
        assert_eq!(
            reader.read_cargo_config_include_in_captured_directory(
                &captured,
                &native("linked.toml"),
                &cancel
            ),
            CargoConfigMemberObservation::Failed(LocatorReadFailure::SymlinkOrReparse)
        );
    }
}

#[test]
fn include_parent_normalizes_the_complete_spelling_before_native_lookup() {
    let (_owner, directory, _) = fixture();
    std::fs::write(directory.join("input.toml"), "[build]\n").unwrap();
    // Absolute admission walks the full host temporary path, unlike a fixed basename read.
    // Match the production Cargo observer's path bounds rather than relying on tmp depth.
    let reader = new_reader(
        LocatorReadLimits {
            max_components_per_request: 64,
            max_total_components: 129,
            ..Default::default()
        },
        None,
    );
    let cancel = CancellationToken::new();
    let captured = reader
        .capture_directory_identity(&directory, &cancel)
        .unwrap();
    assert!(!directory.join("missing").exists());
    let (observed, name) = reader
        .observe_cargo_config_include_parent(&captured, Path::new("missing/../input.toml"), &cancel)
        .unwrap();
    let DirectoryPathObservation::Present(parent) = observed else {
        panic!("normalized parent missing");
    };
    assert_eq!(parent, captured);
    assert_eq!(name, native("input.toml"));
    let dotted = reader
        .capture_directory_identity(&directory.join("."), &cancel)
        .unwrap();
    let (observed, name) = reader
        .observe_cargo_config_include_parent(&dotted, Path::new("input.toml"), &cancel)
        .unwrap();
    assert_eq!(observed, DirectoryPathObservation::Present(parent));
    assert_eq!(name, native("input.toml"));
    assert!(!directory.join("missing").exists());
}

#[test]
fn ancestor_cargo_pair_preserves_native_binding_and_reports_both_current_files() {
    let (_owner, directory, mut captured) = fixture();
    let cargo = directory.parent().unwrap().join(".cargo");
    std::fs::create_dir(&cargo).unwrap();
    std::fs::write(cargo.join("config"), b"[build]\ntarget-dir='legacy'\n").unwrap();
    std::fs::write(cargo.join("config.toml"), b"[build]\ntarget-dir='modern'\n").unwrap();
    captured.display_path = "/forged/candidate".into();
    let reader = new_reader(Default::default(), None);
    let pair = reader
        .observe_cargo_config_pair_at_captured_ancestor(&captured, 1, &CancellationToken::new())
        .unwrap();
    assert_eq!(pair.consistency, CargoConfigPairConsistency::NonAtomic);
    assert!(pair.config.observed_bytes().is_some(), "{pair:?}");
    assert_eq!(
        pair.config.observed_bytes().unwrap(),
        std::fs::read(cargo.join("config")).unwrap()
    );
    assert_eq!(
        pair.config_toml.observed_bytes().unwrap(),
        std::fs::read(cargo.join("config.toml")).unwrap()
    );
    assert_eq!(
        pair.total_bytes,
        pair.config.observed_bytes().unwrap().len()
            + pair.config_toml.observed_bytes().unwrap().len()
    );
    assert_eq!(reader.platform.streams.load(Ordering::SeqCst), 4);
    for limits in [
        LocatorReadLimits {
            max_requests: 4,
            ..Default::default()
        },
        // Complete captured root/candidate plus .cargo and two names costs 11 components.
        LocatorReadLimits {
            max_total_components: 10,
            ..Default::default()
        },
    ] {
        let limited = new_reader(limits, None);
        assert_eq!(
            limited.observe_cargo_config_pair_at_captured_ancestor(
                &captured,
                1,
                &CancellationToken::new()
            ),
            Err(LocatorReadError::ResourceLimit)
        );
        assert_eq!(limited.platform.streams.load(Ordering::SeqCst), 0);
    }
    assert_eq!(
        reader.observe_cargo_config_pair_at_captured_ancestor(
            &captured,
            2,
            &CancellationToken::new()
        ),
        Err(LocatorReadError::InvalidRequest)
    );
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        reader.observe_cargo_config_pair_at_captured_ancestor(&captured, 1, &cancel),
        Err(LocatorReadError::Cancelled)
    );
    std::fs::rename(&directory, directory.with_file_name("retained-original")).unwrap();
    std::fs::create_dir(&directory).unwrap();
    let replaced = new_reader(Default::default(), None);
    assert_eq!(
        replaced.observe_cargo_config_pair_at_captured_ancestor(
            &captured,
            1,
            &CancellationToken::new()
        ),
        Err(LocatorReadError::InvalidRequest)
    );
    assert_eq!(replaced.platform.streams.load(Ordering::SeqCst), 0);
}

#[test]
fn cargo_pair_streams_refuse_provider_changes_and_oversize_before_payload() {
    let (_owner, directory, captured) = fixture();
    let cargo = directory.parent().unwrap().join(".cargo");
    std::fs::create_dir(&cargo).unwrap();
    let path = cargo.join("config");
    std::fs::write(&path, b"[build]\ntarget-dir='private'\n").unwrap();
    let mut provider = new_reader(Default::default(), None);
    provider.platform.deny_stream = true;
    let refused = provider
        .observe_cargo_config_pair_at_captured_ancestor(&captured, 1, &CancellationToken::new())
        .unwrap();
    assert!(
        matches!(
            refused.config,
            CargoConfigMemberObservation::Failed(LocatorReadFailure::ProviderOrOffline)
        ),
        "{refused:?}"
    );
    assert_eq!(provider.platform.streams.load(Ordering::SeqCst), 1);
    let limited = new_reader(
        LocatorReadLimits {
            max_file_bytes: 1,
            ..Default::default()
        },
        None,
    );
    let refused = limited
        .observe_cargo_config_pair_at_captured_ancestor(&captured, 1, &CancellationToken::new())
        .unwrap();
    assert!(matches!(
        refused.config,
        CargoConfigMemberObservation::Failed(LocatorReadFailure::ResourceLimit)
    ));
    assert_eq!(limited.platform.streams.load(Ordering::SeqCst), 1);
    let changing = new_reader(Default::default(), Some(path.clone()));
    let refused = changing
        .observe_cargo_config_pair_at_captured_ancestor(&captured, 1, &CancellationToken::new())
        .unwrap();
    assert!(matches!(
        refused.config,
        CargoConfigMemberObservation::Failed(LocatorReadFailure::ReadFailed)
    ));
    let plain = new_reader(Default::default(), None);
    std::fs::remove_file(&path).unwrap();
    let missing = plain
        .observe_cargo_config_pair_at_captured_ancestor(&captured, 1, &CancellationToken::new())
        .unwrap();
    assert_eq!(missing.consistency, CargoConfigPairConsistency::NonAtomic);
    assert!(matches!(
        missing.config,
        CargoConfigMemberObservation::AbsentDuringEnumeration
    ));
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(directory.join("config.json"), &path).unwrap();
        let linked = plain
            .observe_cargo_config_pair_at_captured_ancestor(&captured, 1, &CancellationToken::new())
            .unwrap();
        assert!(matches!(
            linked.config,
            CargoConfigMemberObservation::Failed(LocatorReadFailure::SymlinkOrReparse)
        ));
        assert_eq!(plain.platform.streams.load(Ordering::SeqCst), 0);
    }
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

#[test]
fn independently_captured_cargo_sources_read_contents_and_reject_provider_or_replacement() {
    let (_owner, directory, _) = fixture();
    let cargo = directory.join(".cargo");
    std::fs::create_dir(&cargo).unwrap();
    let legacy = b"[build]\ntarget-dir='legacy'\n";
    let modern = b"[build]\ntarget-dir='../shared'\n";
    std::fs::write(cargo.join("config"), legacy).unwrap();
    std::fs::write(cargo.join("config.toml"), modern).unwrap();
    let normal = new_reader(Default::default(), None);
    let captured = normal
        .capture_directory_identity(&directory, &CancellationToken::new())
        .unwrap();
    let pair = normal
        .read_cargo_config_pair_in_captured_directory(&captured, true, &CancellationToken::new())
        .unwrap();
    assert_eq!(pair.config.observed_bytes(), Some(legacy.as_slice()));
    assert_eq!(pair.config_toml.observed_bytes(), Some(modern.as_slice()));
    assert_eq!(std::fs::read(cargo.join("config")).unwrap(), legacy);
    assert_eq!(std::fs::read(cargo.join("config.toml")).unwrap(), modern);
    let home = normal
        .capture_directory_identity(&cargo, &CancellationToken::new())
        .unwrap();
    let direct = normal
        .read_cargo_config_pair_in_captured_directory(&home, false, &CancellationToken::new())
        .unwrap();
    assert_eq!(direct.config.observed_bytes(), pair.config.observed_bytes());
    assert_eq!(
        direct.config_toml.observed_bytes(),
        pair.config_toml.observed_bytes()
    );
    let mut denied = new_reader(Default::default(), None);
    denied.platform.deny_stream = true;
    let pair = denied
        .read_cargo_config_pair_in_captured_directory(&home, false, &CancellationToken::new())
        .unwrap();
    assert!(matches!(
        pair.config,
        CargoConfigMemberObservation::Failed(LocatorReadFailure::ProviderOrOffline)
    ));
    let moved = directory.with_extension("moved");
    std::fs::rename(&directory, &moved).unwrap();
    std::fs::create_dir(&directory).unwrap();
    assert_eq!(
        normal.read_cargo_config_pair_in_captured_directory(
            &captured,
            true,
            &CancellationToken::new()
        ),
        Err(LocatorReadError::InvalidRequest)
    );
}

#[test]
fn captured_ancestor_and_configured_spelling_require_native_lineage_and_bounded_inputs() {
    let (_owner, directory, mut entry) = fixture();
    entry.display_path = "/forged/report/location".into();
    let reader = new_reader(Default::default(), None);
    let captured = reader
        .capture_scanned_ancestor_directory(&entry, 0, &CancellationToken::new())
        .unwrap();
    let parent = reader
        .capture_scanned_ancestor_directory(&entry, 1, &CancellationToken::new())
        .unwrap();
    let independently_admitted = reader
        .capture_parent_directory(&captured, &CancellationToken::new())
        .unwrap()
        .unwrap();
    assert_eq!(parent, independently_admitted);
    assert_eq!(
        reader.capture_scanned_ancestor_directory(&entry, 2, &CancellationToken::new()),
        Err(LocatorReadError::InvalidRequest)
    );
    assert_eq!(
        reader.compare_scanned_directory_to_configured_path(
            &entry,
            &parent,
            Path::new("captured"),
            &CancellationToken::new()
        ),
        Ok(true)
    );
    assert_eq!(
        reader.compare_scanned_directory_to_configured_path(
            &entry,
            &parent,
            Path::new("different"),
            &CancellationToken::new()
        ),
        Ok(false)
    );
    assert_eq!(
        reader.compare_scanned_directory_to_configured_path(
            &entry,
            &parent,
            Path::new("../captured"),
            &CancellationToken::new()
        ),
        Err(LocatorReadError::InvalidRequest)
    );
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert_eq!(
        reader.capture_parent_directory(&captured, &cancel),
        Err(LocatorReadError::Cancelled)
    );
    let capped = new_reader(
        LocatorReadLimits {
            max_requests: 3,
            ..Default::default()
        },
        None,
    );
    assert_eq!(
        capped.read_cargo_config_pair_in_captured_directory(
            &captured,
            false,
            &CancellationToken::new()
        ),
        Err(LocatorReadError::ResourceLimit)
    );
    let moved = directory.with_extension("moved");
    std::fs::rename(&directory, &moved).unwrap();
    std::fs::create_dir(&directory).unwrap();
    assert_eq!(
        reader.capture_scanned_ancestor_directory(&entry, 1, &CancellationToken::new()),
        Err(LocatorReadError::InvalidRequest)
    );
}

#[test]
fn fixed_cargo_lookup_does_not_need_unrelated_enumeration_or_convert_a_read_gap_to_absence() {
    let (_owner, directory, _) = fixture();
    let reader = new_reader(
        LocatorReadLimits {
            max_directory_entries: 0,
            max_directory_bytes: 0,
            ..Default::default()
        },
        None,
    );
    let captured = reader
        .capture_directory_identity(&directory, &CancellationToken::new())
        .unwrap();
    let absent = reader
        .read_cargo_config_pair_in_captured_directory(&captured, true, &CancellationToken::new())
        .unwrap();
    assert!(matches!(
        absent.config,
        CargoConfigMemberObservation::AbsentDuringLookup
    ));
    assert!(matches!(
        absent.config_toml,
        CargoConfigMemberObservation::AbsentDuringLookup
    ));
    assert_eq!(reader.platform.streams.load(Ordering::SeqCst), 0);
    std::fs::create_dir(directory.join(".cargo")).unwrap();
    let captured = reader
        .capture_directory_identity(&directory, &CancellationToken::new())
        .unwrap();
    let incomplete = reader
        .read_cargo_config_pair_in_captured_directory(&captured, true, &CancellationToken::new())
        .unwrap();
    assert!(matches!(
        incomplete.config,
        CargoConfigMemberObservation::Failed(LocatorReadFailure::ResourceLimit)
    ));
    assert!(matches!(
        incomplete.config_toml,
        CargoConfigMemberObservation::Failed(LocatorReadFailure::ResourceLimit)
    ));
}
