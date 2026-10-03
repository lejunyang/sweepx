use super::*;
use crate::HostPlatformScanner;

fn fixture() -> (tempfile::TempDir, PathBuf) {
    #[cfg(target_os = "linux")]
    let owner = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let owner = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = owner.path().canonicalize().unwrap();
    #[cfg(windows)]
    let root = owner.path().to_path_buf();
    (owner, root)
}

fn reader() -> LocatorReader<HostPlatformScanner> {
    LocatorReader::new(
        HostPlatformScanner::new(),
        LocatorReadLimits {
            max_components_per_request: 64,
            max_total_components: 129,
            max_requests: 64,
            ..Default::default()
        },
    )
}

#[test]
fn fixed_manifest_preserves_present_missing_and_refused_objects() {
    let (_owner, root) = fixture();
    let cancel = CancellationToken::new();
    let reader = reader();
    let captured = reader.capture_directory_identity(&root, &cancel).unwrap();
    assert_eq!(
        reader.read_cargo_manifest_in_captured_directory(&captured, &cancel),
        CargoManifestObservation::AbsentDuringLookup
    );
    let bytes = b"[package]\nname='independent'\nversion='0.1.0'\n";
    std::fs::write(root.join("Cargo.toml"), bytes).unwrap();
    let captured = reader.capture_directory_identity(&root, &cancel).unwrap();
    let observed = reader.read_cargo_manifest_in_captured_directory(&captured, &cancel);
    assert_eq!(
        observed.observed_bytes().unwrap(),
        std::fs::read(root.join("Cargo.toml")).unwrap()
    );
    std::fs::remove_file(root.join("Cargo.toml")).unwrap();
    std::fs::create_dir(root.join("Cargo.toml")).unwrap();
    let captured = reader.capture_directory_identity(&root, &cancel).unwrap();
    assert!(matches!(
        reader.read_cargo_manifest_in_captured_directory(&captured, &cancel),
        CargoManifestObservation::Failed(_)
    ));
}

#[test]
fn directory_enumeration_and_component_walk_match_ordinary_tree() {
    let (_owner, root) = fixture();
    for name in ["a", "b", "包"] {
        std::fs::create_dir(root.join(name)).unwrap();
    }
    std::fs::write(root.join("ordinary"), b"personal").unwrap();
    let reader = reader();
    let cancel = CancellationToken::new();
    let captured = reader.capture_directory_identity(&root, &cancel).unwrap();
    let actual: Vec<_> = reader
        .captured_directory_child_names(&captured, &cancel)
        .unwrap()
        .into_iter()
        .collect();
    let mut expected: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .map(|entry| {
            let name = entry.unwrap().file_name();
            #[cfg(unix)]
            {
                NativeName::UnixBytes(name.into_vec())
            }
            #[cfg(windows)]
            {
                use std::os::windows::ffi::OsStrExt;
                NativeName::WindowsUtf16(name.encode_wide().collect())
            }
        })
        .collect();
    expected.sort_unstable_by(native_name_order);
    assert_eq!(actual, expected);
    let b = reader
        .capture_relative_directory(&captured, Path::new("a/./../b"), &cancel)
        .unwrap();
    let independent = reader
        .capture_directory_identity(&root.join("b"), &cancel)
        .unwrap();
    assert!(
        reader
            .captured_directories_same_native_object(&b, &independent, &cancel)
            .unwrap()
    );
    assert_eq!(
        reader
            .captured_directory_relative_components(&b, &captured, &cancel)
            .unwrap(),
        Some(vec![fixed_native_name("b")])
    );
    assert!(
        reader
            .captured_directory_matches_declared_prefix(&b, &captured, Path::new("b"), &cancel)
            .unwrap()
    );
    assert!(
        !reader
            .captured_directory_matches_declared_prefix(&b, &captured, Path::new("a/../b"), &cancel)
            .unwrap()
    );
    assert!(
        reader
            .captured_directory_matches_declared_prefix(&b, &captured, &root.join("b"), &cancel)
            .unwrap()
    );
    assert!(matches!(
        reader.capture_relative_directory(&captured, Path::new("missing/../b"), &cancel),
        Err(LocatorDirectoryLookupFailure::NotFoundDuringLookup)
    ));
    assert_eq!(std::fs::read(root.join("ordinary")).unwrap(), b"personal");
}

#[test]
fn directory_replacement_rejects_old_capture_and_cancel_limits_stay_failures() {
    let (_owner, root) = fixture();
    std::fs::create_dir(root.join("old")).unwrap();
    std::fs::write(root.join("old/Cargo.toml"), b"[workspace]").unwrap();
    let reader = reader();
    let cancel = CancellationToken::new();
    let old = reader
        .capture_directory_identity(&root.join("old"), &cancel)
        .unwrap();
    // Retain the old object to make replacement independent of inode reuse.
    std::fs::rename(root.join("old"), root.join("retained")).unwrap();
    std::fs::create_dir(root.join("old")).unwrap();
    assert!(matches!(
        reader.read_cargo_manifest_in_captured_directory(&old, &cancel),
        CargoManifestObservation::Failed(LocatorReadFailure::IdentityMismatch)
    ));
    assert!(
        reader
            .captured_directory_child_names(&old, &cancel)
            .is_err()
    );
    let current = reader.capture_directory_identity(&root, &cancel).unwrap();
    let limited = LocatorReader::new(
        HostPlatformScanner::new(),
        LocatorReadLimits {
            max_directory_entries: 1,
            ..Default::default()
        },
    );
    assert!(matches!(
        limited.captured_directory_child_names(&current, &cancel),
        Err(LocatorDirectoryLookupFailure::Read(
            LocatorReadFailure::ResourceLimit
        ))
    ));
    cancel.cancel();
    assert!(matches!(
        reader.read_cargo_manifest_in_captured_directory(&current, &cancel),
        CargoManifestObservation::Failed(LocatorReadFailure::Cancelled)
    ));
    assert!(
        reader
            .capture_relative_directory(&current, Path::new("old"), &cancel)
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn linked_manifest_and_linked_intermediate_never_follow_targets() {
    let (_owner, root) = fixture();
    std::fs::create_dir(root.join("real")).unwrap();
    std::fs::write(root.join("personal"), b"preserved").unwrap();
    std::os::unix::fs::symlink("personal", root.join("Cargo.toml")).unwrap();
    std::os::unix::fs::symlink("real", root.join("alias")).unwrap();
    let reader = reader();
    let cancel = CancellationToken::new();
    let captured = reader.capture_directory_identity(&root, &cancel).unwrap();
    assert!(matches!(
        reader.read_cargo_manifest_in_captured_directory(&captured, &cancel),
        CargoManifestObservation::Failed(LocatorReadFailure::SymlinkOrReparse)
    ));
    assert!(matches!(
        reader.capture_relative_directory(&captured, Path::new("alias/../real"), &cancel),
        Err(LocatorDirectoryLookupFailure::Read(
            LocatorReadFailure::SymlinkOrReparse
        ))
    ));
    assert_eq!(std::fs::read(root.join("personal")).unwrap(), b"preserved");
}

#[test]
fn configured_home_lookup_distinguishes_missing_components_and_current_directories() {
    let (_owner, root) = fixture();
    std::fs::create_dir(root.join("home")).unwrap();
    std::fs::write(root.join("ordinary"), b"personal").unwrap();
    let reader = reader();
    let cancel = CancellationToken::new();
    let cwd = reader.capture_directory_identity(&root, &cancel).unwrap();
    for path in [
        root.join("missing/deep"),
        PathBuf::from("missing/../home"),
        PathBuf::from("ordinary/config"),
    ] {
        assert!(
            matches!(
                reader.observe_directory_path(&cwd, &path, &cancel).unwrap(),
                DirectoryPathObservation::AbsentDuringLookup(_)
            ),
            "{path:?}"
        );
    }
    let before = reader
        .observe_directory_path(&cwd, Path::new("missing/deep"), &cancel)
        .unwrap();
    std::fs::create_dir_all(root.join("missing/deep")).unwrap();
    // Directory mutations require a fresh cwd snapshot, independent of the old absent result.
    let cwd = reader.capture_directory_identity(&root, &cancel).unwrap();
    let after = reader
        .observe_directory_path(&cwd, Path::new("missing/deep"), &cancel)
        .unwrap();
    assert_ne!(before, after);
    let DirectoryPathObservation::Present(after) = after else {
        panic!("new directory was not observed")
    };
    let ordinary = reader
        .capture_directory_identity(&root.join("missing/deep"), &cancel)
        .unwrap();
    assert!(
        reader
            .captured_directories_same_native_object(&after, &ordinary, &cancel)
            .unwrap()
    );
    assert_eq!(std::fs::read(root.join("ordinary")).unwrap(), b"personal");
}

#[test]
fn cargo_home_output_base_preserves_lexical_parent_before_native_resolution() {
    let (_owner, root) = fixture();
    std::fs::create_dir_all(root.join("project/home")).unwrap();
    let reader = reader();
    let cancel = CancellationToken::new();
    let cwd = reader
        .capture_directory_identity(&root.join("project"), &cancel)
        .unwrap();
    for (input, expected, comparable) in [
        ("home", root.join("project"), true),
        (".", root.clone(), true),
        ("home/..", root.join("project/home"), true),
        ("../home", root.clone(), false),
    ] {
        let (base, actual_comparable) = reader
            .observe_cargo_home_output_base(&cwd, Path::new(input), &cancel)
            .unwrap();
        assert_eq!(actual_comparable, comparable, "{input}");
        let DirectoryPathObservation::Present(base) = base else {
            panic!("base missing: {input}")
        };
        let independent = reader
            .capture_directory_identity(&expected, &cancel)
            .unwrap();
        assert!(
            reader
                .captured_directories_same_native_object(&base, &independent, &cancel)
                .unwrap(),
            "{input}"
        );
    }
    assert!(!root.join("project/home/target").exists());
}

#[test]
fn configured_home_lookup_keeps_cancellation_and_resource_refusal_distinct_from_absence() {
    let (_owner, root) = fixture();
    let reader = reader();
    let cancel = CancellationToken::new();
    let cwd = reader.capture_directory_identity(&root, &cancel).unwrap();
    let limited = LocatorReader::new(
        HostPlatformScanner::new(),
        LocatorReadLimits {
            max_requests: 2,
            ..Default::default()
        },
    );
    assert!(matches!(
        limited.observe_directory_path(&cwd, &root.join("a/b/c"), &cancel),
        Err(LocatorDirectoryLookupFailure::Read(
            LocatorReadFailure::ResourceLimit
        ))
    ));
    cancel.cancel();
    assert!(matches!(
        reader.observe_directory_path(&cwd, Path::new("missing"), &cancel),
        Err(LocatorDirectoryLookupFailure::Read(
            LocatorReadFailure::Cancelled
        ))
    ));
}

#[cfg(unix)]
#[test]
fn configured_home_lookup_rejects_linked_and_dangling_ancestors() {
    let (_owner, root) = fixture();
    std::fs::create_dir(root.join("home")).unwrap();
    std::os::unix::fs::symlink("home", root.join("linked")).unwrap();
    std::os::unix::fs::symlink("unavailable", root.join("dangling")).unwrap();
    let reader = reader();
    let cancel = CancellationToken::new();
    let cwd = reader.capture_directory_identity(&root, &cancel).unwrap();
    for path in [
        root.join("linked/missing"),
        root.join("dangling/config"),
        PathBuf::from("linked/../home"),
    ] {
        assert!(
            matches!(
                reader.observe_directory_path(&cwd, &path, &cancel),
                Err(LocatorDirectoryLookupFailure::Read(
                    LocatorReadFailure::SymlinkOrReparse
                ))
            ),
            "{path:?}"
        );
    }
}
