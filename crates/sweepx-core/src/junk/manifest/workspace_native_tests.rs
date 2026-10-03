use super::super::workspace::resolve_workspace;
use super::*;
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use sweepx_scanner::{HostPlatformScanner, LocatorReadLimits};

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
            max_requests: 64,
            max_components_per_request: 64,
            max_total_components: 129,
            max_file_bytes: 256 * 1024,
            ..Default::default()
        },
    )
}

fn budget(reserved: &mut usize) -> ScopeBudget<'_> {
    ScopeBudget {
        reserved_bytes: reserved,
        max_reserved_bytes: 32 * 1024 * 1024,
        file_bytes: 256 * 1024,
        started: Instant::now(),
        timeout: Duration::from_secs(5),
    }
}

#[test]
fn native_workspace_matches_raw_cargo_root_members_and_cwd_defaults_for_all_53_cases() {
    let oracle: Value =
        serde_json::from_str(sweepx_fixtures::project_junk::CARGO_WORKSPACE_ORACLE).unwrap();
    assert_eq!(oracle["complete"], true);
    let records = oracle["records"].as_array().unwrap();
    assert_eq!(records.len(), 53);
    for record in records {
        let (_owner, root) = fixture();
        let mut originals = Vec::new();
        for input in record["inputs"].as_array().unwrap() {
            let path = root.join(input["path"].as_str().unwrap());
            let bytes = input["utf8"].as_str().unwrap().as_bytes();
            assert_eq!(hex_digest(bytes), input["sha256"].as_str().unwrap());
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
            originals.push((path, bytes.to_vec()));
        }
        let reader = reader();
        let cancel = CancellationToken::new();
        let cwd = root.join(record["fixtureRelativeCwd"].as_str().unwrap());
        let project = reader.capture_directory_identity(&cwd, &cancel).unwrap();
        let mut inputs = WorkspaceInputs::default();
        let mut reserved = 0;
        let mut budget = budget(&mut reserved);
        let mut source = NativeWorkspaceSource::new(&reader, &cancel, &mut budget, &mut inputs);
        let project_id = source.intern(project).unwrap();
        let actual = resolve_workspace(&mut source, &project_id);
        let cargo = &record["cargo"];
        assert!(cargo["boundedFailure"].is_null());
        let name = record["name"].as_str().unwrap();
        if cargo["status"] == 101 {
            assert!(
                matches!(actual, Err(WorkspaceError::Invalid(_))),
                "{name}: {actual:?}"
            );
        } else {
            assert_eq!(cargo["status"], 0);
            let actual = actual.unwrap_or_else(|error| panic!("{name}: {error:?}"));
            source
                .finish()
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
            let metadata: Value = serde_json::from_str(cargo["stdout"].as_str().unwrap()).unwrap();
            let suffix = format!("/{}", record["fixtureRelativeCwd"].as_str().unwrap());
            let prefix = format!(
                "{}/",
                record["cwd"]
                    .as_str()
                    .unwrap()
                    .strip_suffix(&suffix)
                    .unwrap()
            );
            let expected_root = root.join(
                metadata["workspace_root"]
                    .as_str()
                    .unwrap()
                    .strip_prefix(&prefix)
                    .unwrap(),
            );
            let expected_root = reader
                .capture_directory_identity(&expected_root, &cancel)
                .unwrap();
            assert!(
                reader
                    .captured_directories_same_native_object(
                        source.directory(actual.root),
                        &expected_root,
                        &cancel
                    )
                    .unwrap(),
                "{name}"
            );
            for (field, actual_ids) in [
                ("workspace_members", &actual.members),
                ("workspace_default_members", &actual.default_members),
            ] {
                let mut expected_ids = BTreeSet::new();
                for id in metadata[field].as_array().unwrap() {
                    let package = metadata["packages"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|p| p["id"] == *id)
                        .unwrap();
                    let relative = package["manifest_path"]
                        .as_str()
                        .unwrap()
                        .strip_prefix(&prefix)
                        .unwrap()
                        .strip_suffix("/Cargo.toml")
                        .unwrap();
                    let native = reader
                        .capture_directory_identity(&root.join(relative), &cancel)
                        .unwrap();
                    let matched = actual_ids
                        .iter()
                        .find(|id| source.directory(**id).same_captured_native_object(&native))
                        .unwrap_or_else(|| panic!("{name}: missing {relative} in {field}"));
                    assert!(expected_ids.insert(*matched));
                }
                assert_eq!(
                    expected_ids,
                    actual_ids.iter().copied().collect(),
                    "{name}: {field}"
                );
            }
        }
        for (path, original) in originals {
            assert_eq!(std::fs::read(path).unwrap(), original, "{name}");
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn final_revalidation_rejects_changed_manifest_and_keeps_budget_cancel_distinct() {
    let (_owner, root) = fixture();
    let path = root.join("Cargo.toml");
    std::fs::write(&path, b"[package]\nname='before'\nversion='0.1.0'\n").unwrap();
    let reader = reader();
    let cancel = CancellationToken::new();
    let mut inputs = WorkspaceInputs::default();
    let mut reserved = 0;
    let mut budget = budget(&mut reserved);
    let mut source = NativeWorkspaceSource::new(&reader, &cancel, &mut budget, &mut inputs);
    let id = source
        .intern(reader.capture_directory_identity(&root, &cancel).unwrap())
        .unwrap();
    resolve_workspace(&mut source, &id).unwrap();
    // Equal-length valid contents exercise bytes/change-stamp revalidation, without changing
    // a directory's entry list or relying on filesystem timestamp resolution.
    std::fs::write(&path, b"[package]\nname='after_'\nversion='0.1.0'\n").unwrap();
    assert_eq!(
        source.finish(),
        Err(WorkspaceError::Unavailable("workspace_manifest_changed"))
    );
    source.budget.max_reserved_bytes = *source.budget.reserved_bytes;
    assert_eq!(
        source.finish(),
        Err(WorkspaceError::Unavailable("resource_limit"))
    );
    cancel.cancel();
    assert_eq!(
        source.finish(),
        Err(WorkspaceError::Unavailable("cancelled"))
    );
    assert_eq!(
        std::fs::read(path).unwrap(),
        b"[package]\nname='after_'\nversion='0.1.0'\n"
    );
}

#[cfg(unix)]
#[test]
fn linked_member_remains_unavailable_even_when_cargo_can_follow_it() {
    let (_owner, root) = fixture();
    std::fs::create_dir(root.join("real")).unwrap();
    std::fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=['alias']").unwrap();
    std::fs::write(
        root.join("real/Cargo.toml"),
        b"[package]\nname='real'\nversion='0.1.0'",
    )
    .unwrap();
    std::os::unix::fs::symlink("real", root.join("alias")).unwrap();
    let reader = reader();
    let cancel = CancellationToken::new();
    let mut inputs = WorkspaceInputs::default();
    let mut reserved = 0;
    let mut budget = budget(&mut reserved);
    let mut source = NativeWorkspaceSource::new(&reader, &cancel, &mut budget, &mut inputs);
    let id = source
        .intern(reader.capture_directory_identity(&root, &cancel).unwrap())
        .unwrap();
    assert_eq!(
        resolve_workspace(&mut source, &id).unwrap_err(),
        WorkspaceError::Unavailable("linked_file")
    );
    assert!(root.join("real/Cargo.toml").is_file());
}
