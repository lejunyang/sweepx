//! A selected native Data fixture exercises captured `/` lineage without a whole-disk scan.
#![cfg(all(target_os = "macos", feature = "platform-macos"))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use sweepx_model::{
    ByteValue, CountValue, DecimalU128, NativeAbsolutePath, NativeName, ObjectType, ScanEntryId,
    ScanObjectIdentity, ScannedEntry,
};
use sweepx_platform::{CancellationToken, ScanResourceLimits, ScanRoot};
use sweepx_scanner::{
    ClassifiedScanObserver, DetailEntryIdAllocator, DetailRescanError, DetailRescanRequest,
    DetailRescanner, FileContentRequest, HostPlatformScanner, JunkClassifier, LocatorReadFailure,
    LocatorReadLimits, LocatorReader, Scanner, ScannerOptions,
};

const MARKER: &str = ".sweepx-test-marker";

struct GeneratedDirectory;

impl JunkClassifier for GeneratedDirectory {
    fn uses_only_local_markers(&self) -> bool {
        true
    }

    fn needs_file_marker(&self, name: &NativeName) -> bool {
        name == &NativeName::unix(MARKER.as_bytes())
    }

    fn classify(
        &self,
        entry: &ScannedEntry,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<String> {
        let identity = entry.identity.as_ref()?;
        (entry.native_basename == NativeName::unix(b"generated")
            && markers
                .get(&identity.entry_id)
                .is_some_and(|names| names.contains(MARKER)))
        .then(|| "native-system-data-fixture".into())
    }
}

struct FixtureFiles<'a> {
    root: PathBuf,
    files: BTreeMap<PathBuf, ScannedEntry>,
    cancel: &'a CancellationToken,
    deadline: Instant,
}

impl ClassifiedScanObserver for FixtureFiles<'_> {
    fn wants_file_observations(&self) -> bool {
        true
    }

    fn wants_directory_progress(&self) -> bool {
        false
    }

    fn on_entry(&mut self, entry: &ScannedEntry) {
        let path = PathBuf::from(&entry.display_path);
        if entry.object_type == ObjectType::File && path.starts_with(&self.root) {
            assert!(self.files.insert(path, entry.clone()).is_none());
        }
    }

    fn on_progress(&mut self, _: &Path, _: &sweepx_scanner::ProgressEvent) {
        if Instant::now() >= self.deadline {
            self.cancel.cancel();
        }
    }
}

// Independent no-follow metadata accounting includes any host-created ordinary files, rather
// than manufacturing the expected sum from the scanner or its retained marker set.
fn ordinary_facts(path: &Path) -> (u128, u128) {
    let mut logical = 0;
    let mut entries = 0;
    for child in std::fs::read_dir(path).unwrap() {
        let child = child.unwrap();
        let metadata = std::fs::symlink_metadata(child.path()).unwrap();
        assert!(!metadata.file_type().is_symlink());
        entries += 1;
        if metadata.is_dir() {
            let nested = ordinary_facts(&child.path());
            logical += nested.0;
            entries += nested.1;
        } else if metadata.is_file() {
            logical += u128::from(metadata.len());
        } else {
            panic!("unexpected native fixture type");
        }
    }
    (logical, entries)
}

fn root_identity(entry: &ScannedEntry) -> ScanObjectIdentity {
    let locator = entry.executable_native_locator().unwrap().unwrap();
    ScanObjectIdentity {
        entry_id: locator.scan_root.entry_id.clone(),
        scan_root_id: locator.scan_root.entry_id.clone(),
        parent_id: None,
        platform_file_identity: locator.scan_root.platform_file_identity.clone(),
        filesystem_object_domain_identity: locator
            .scan_root
            .filesystem_object_domain_identity
            .clone(),
        volume_or_mount_identity: locator.scan_root.volume_or_mount_identity.clone(),
    }
}

fn exercise_selected_data_candidate(physical_entrance: bool) {
    // `/tmp` has a linked ancestor on macOS. Keep fixture ownership while using its canonical
    // `/private/tmp` entrance for native no-follow scanning and ordinary metadata comparisons.
    let owner = tempfile::tempdir_in("/private/tmp").unwrap();
    let logical_fixture = owner.path().canonicalize().unwrap();
    let fixture = if physical_entrance {
        Path::new("/System/Volumes/Data").join(logical_fixture.strip_prefix("/").unwrap())
    } else {
        logical_fixture
    };
    let candidate_path = fixture.join("generated");
    std::fs::create_dir_all(candidate_path.join("nested")).unwrap();
    std::fs::write(candidate_path.join(MARKER), b"current marker\n").unwrap();
    std::fs::write(candidate_path.join("payload"), b"native Data payload\n").unwrap();
    std::fs::write(candidate_path.join("nested/deep"), b"recursive payload\n").unwrap();
    let expected = ordinary_facts(&candidate_path);

    let cancel = CancellationToken::new();
    let mut observer = FixtureFiles {
        root: candidate_path.clone(),
        files: BTreeMap::new(),
        cancel: &cancel,
        deadline: Instant::now() + Duration::from_secs(15),
    };
    let scan = Scanner::new(
        HostPlatformScanner::new(),
        ScannerOptions {
            retain_directory_index: false,
            retain_file_index: false,
            ..Default::default()
        },
    )
    .scan_classified_subtrees_with_observer(
        &[ScanRoot::new("/").unwrap()],
        &cancel,
        &GeneratedDirectory,
        None,
        std::slice::from_ref(&candidate_path),
        &mut observer,
    )
    .unwrap();
    assert!(
        !cancel.is_cancelled(),
        "selected scan exceeded its deadline"
    );
    assert_eq!(scan.subtree_coverage_complete, Some(true));
    let candidate = scan
        .summary
        .entries
        .iter()
        .find(|entry| entry.native_basename == NativeName::unix(b"generated"))
        .expect("the selected Data directory must classify under captured `/` lineage");
    let identity = candidate.validated_identity().unwrap().unwrap();
    let locator = candidate.executable_native_locator().unwrap().unwrap();
    assert_eq!(
        locator.scan_root_absolute_path,
        Some(NativeAbsolutePath::unix(b"/"))
    );
    assert_ne!(
        locator.scan_root.volume_or_mount_identity,
        identity.volume_or_mount_identity
    );
    let aggregate = scan
        .summary
        .aggregates
        .iter()
        .find(|aggregate| aggregate.directory_identity == identity.entry_id.as_str())
        .unwrap();
    assert!(aggregate.coverage.complete && !aggregate.coverage.details_lost);
    assert_eq!(
        aggregate.apparent_logical_bytes,
        ByteValue::Known {
            value: DecimalU128(expected.0)
        }
    );
    assert_eq!(
        aggregate.recursive_entry_count,
        CountValue::Known {
            value: DecimalU128(expected.1)
        }
    );

    let source_root = root_identity(candidate);
    let request = DetailRescanRequest {
        source_scan_id: &candidate.scan_id,
        source_root_identity: &source_root,
        source_directory_identity: identity,
        directory_locator: locator,
        revision: 1.into(),
        max_rows: 16,
    };
    // Use default strict detail mode: the former browser-only opt-in must not be needed for
    // a fresh Data candidate's current binding, recursive facts or payload reads.
    let detail = DetailRescanner::new(HostPlatformScanner::new(), ScanResourceLimits::default());
    let (_, revalidated) = detail.revalidate_directory(request, &cancel).unwrap();
    assert_eq!(revalidated.identity, candidate.identity);
    let mut ids = DetailEntryIdAllocator::new(candidate.scan_id.clone()).unwrap();
    let refreshed = detail.rescan(request, &mut ids, &cancel).unwrap();
    assert!(refreshed.aggregate.coverage.complete);
    assert_eq!(
        refreshed.aggregate.apparent_logical_bytes,
        aggregate.apparent_logical_bytes
    );
    assert_eq!(
        refreshed.aggregate.recursive_entry_count,
        aggregate.recursive_entry_count
    );
    let payload = detail
        .observe_child(request, &NativeName::unix(b"payload"), &mut ids, &cancel)
        .unwrap();
    let original_payload = &observer.files[&candidate_path.join("payload")];
    assert_eq!(
        payload.identity.as_ref().unwrap().platform_file_identity,
        original_payload
            .identity
            .as_ref()
            .unwrap()
            .platform_file_identity
    );

    let reader = LocatorReader::new(
        HostPlatformScanner::new(),
        LocatorReadLimits {
            max_components_per_request: 32,
            max_total_components: 64,
            ..Default::default()
        },
    );
    let marker = reader
        .read_captured_regular_file(candidate, &NativeName::unix(MARKER.as_bytes()), &cancel)
        .unwrap();
    assert_eq!(
        marker.bytes,
        std::fs::read(candidate_path.join(MARKER)).unwrap()
    );
    let mut bytes = Vec::new();
    detail
        .stream_file(
            FileContentRequest {
                entry: original_payload,
                offset: 0,
                max_bytes: 1024,
                previous: None,
            },
            &cancel,
            &mut |chunk| {
                bytes.extend_from_slice(chunk);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        bytes,
        std::fs::read(candidate_path.join("payload")).unwrap()
    );
    assert_eq!(ordinary_facts(&candidate_path), expected);

    // Joining the two admitted volumes must not authorize a replacement at an old candidate's
    // native spelling. Keep the old bytes under another fixture name to expose mistaken reads.
    let retained = fixture.join("retained-original");
    std::fs::rename(&candidate_path, &retained).unwrap();
    std::fs::create_dir(&candidate_path).unwrap();
    std::fs::write(candidate_path.join(MARKER), b"replacement marker\n").unwrap();
    assert_eq!(
        detail.revalidate_directory(request, &cancel),
        Err(DetailRescanError::IdentityMismatch)
    );
    assert_eq!(
        reader.read_captured_regular_file(candidate, &NativeName::unix(MARKER.as_bytes()), &cancel),
        Err(LocatorReadFailure::IdentityMismatch)
    );
    assert_eq!(ordinary_facts(&retained), expected);
}

#[test]
fn logical_data_candidate_reopens_reads_and_rescans_from_system_root() {
    exercise_selected_data_candidate(false);
}

#[test]
fn physical_data_candidate_reopens_reads_and_rescans_from_system_root() {
    exercise_selected_data_candidate(true);
}
