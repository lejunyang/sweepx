use super::*;
use std::fs;
fn fixture() -> (tempfile::TempDir, PathBuf) {
    #[cfg(target_os = "linux")]
    let temp = tempfile::tempdir_in("/dev/shm").unwrap();
    #[cfg(not(target_os = "linux"))]
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    let root = temp.path().canonicalize().unwrap();
    #[cfg(windows)]
    let root = temp.path().to_path_buf();
    (temp, root)
}
fn slot(root: &Path, id: &str, version: &str) {
    let path = root.join(id);
    fs::create_dir_all(path.join("node_modules/@test/tool")).unwrap();
    fs::write(
        path.join("package.json"),
        r#"{"dependencies":{"@test/tool":"^1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        path.join("node_modules/@test/tool/package.json"),
        format!(r#"{{"name":"@test/tool","version":"{version}"}}"#),
    )
    .unwrap();
    fs::write(path.join("node_modules/@test/tool/content"), [1u8; 17]).unwrap();
}
fn oracle(root: &Path) -> u128 {
    fs::read_dir(root)
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                oracle(&p)
            } else if m.is_file() {
                u128::from(m.len())
            } else {
                0
            }
        })
        .sum()
}
#[test]
fn actual_versions_sizes_and_semver_order_are_independent_of_requested_ranges() {
    let (_temp, root) = fixture();
    slot(&root, "0123456789abcdef", "1.10.0");
    slot(&root, "abcdef0123456789", "1.9.0");
    let inv = inventory(&root, &CancellationToken::new());
    assert!(inv.complete, "{:?}", inv);
    assert_eq!(
        inv.bytes.as_deref().unwrap().parse::<u128>().unwrap(),
        oracle(&root)
    );
    for row in &inv.entries {
        assert_eq!(
            row.bytes.as_deref().unwrap().parse::<u128>().unwrap(),
            oracle(&row.path)
        );
    }
    assert_eq!(
        inv.entries
            .iter()
            .filter(|r| r.older_version)
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        vec!["abcdef0123456789"]
    );
    assert_eq!(inv.entries[0].packages[0].requested, "^1.0.0");
}
#[test]
fn changed_manifest_and_replaced_directory_are_rejected() {
    let (_temp, root) = fixture();
    slot(&root, "0123456789abcdef", "1.0.0");
    let inv = inventory(&root, &CancellationToken::new());
    let row = &inv.entries[0];
    row.revalidate(&CancellationToken::new()).unwrap();
    fs::write(
        row.path.join("node_modules/@test/tool/package.json"),
        r#"{"name":"@test/tool","version":"2.0.0"}"#,
    )
    .unwrap();
    assert!(row.revalidate(&CancellationToken::new()).is_err());
    fs::rename(&row.path, root.join("moved")).unwrap();
    slot(&root, "0123456789abcdef", "1.0.0");
    assert!(row.revalidate(&CancellationToken::new()).is_err());
}
#[test]
fn malformed_names_unknown_versions_and_multi_package_slots_are_not_old_plans() {
    assert!(package_parts("../outside").is_none());
    assert!(package_parts("@scope/../outside").is_none());
    assert!(package_parts("bad\\path").is_none());
    let (_temp, root) = fixture();
    slot(&root, "0123456789abcdef", "custom");
    slot(&root, "abcdef0123456789", "2.0.0");
    let path = root.join("0123456789abcdef/package.json");
    fs::write(path, r#"{"dependencies":{"@test/tool":"*","other":"*"}}"#).unwrap();
    let inv = inventory(&root, &CancellationToken::new());
    assert!(!inv.complete);
    assert!(inv.entries.iter().all(|r| !r.older_version));
}
#[test]
fn sibling_removal_does_not_turn_an_unchanged_slot_into_missing_native_authority() {
    let (_temp, root) = fixture();
    slot(&root, "0123456789abcdef", "1.0.0");
    slot(&root, "abcdef0123456789", "2.0.0");
    let inv = inventory(&root, &CancellationToken::new());
    let row = inv
        .entries
        .iter()
        .find(|r| r.id == "abcdef0123456789")
        .unwrap();
    fs::remove_dir_all(root.join("0123456789abcdef")).unwrap();
    row.revalidate(&CancellationToken::new()).unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(row.revalidate(&cancel).is_err());
}
#[cfg(unix)]
#[test]
fn linked_package_manifest_is_visible_as_unknown_not_a_deletion_plan() {
    let (_temp, root) = fixture();
    slot(&root, "0123456789abcdef", "1.0.0");
    let path = root.join("0123456789abcdef/node_modules/@test/tool/package.json");
    fs::rename(&path, root.join("outside.json")).unwrap();
    std::os::unix::fs::symlink(root.join("outside.json"), path).unwrap();
    let inv = inventory(&root, &CancellationToken::new());
    assert!(!inv.entries[0].complete);
    assert!(!inv.entries[0].older_version);
}

#[test]
fn build_metadata_and_incomplete_coverage_do_not_make_old_version_plans() {
    let (_temp, root) = fixture();
    slot(&root, "0123456789abcdef", "1.0.0+build1");
    slot(&root, "abcdef0123456789", "1.0.0+build2");
    let inv = inventory(&root, &CancellationToken::new());
    assert!(inv.complete);
    assert!(inv.entries.iter().all(|r| !r.older_version));
    fs::create_dir(root.join("unknown")).unwrap();
    let inv = inventory(&root, &CancellationToken::new());
    assert!(!inv.complete);
    assert!(inv.entries.iter().all(|r| !r.older_version));
}

#[cfg(unix)]
#[test]
fn a_known_linked_local_package_only_excludes_its_own_version_group() {
    let (_temp, root) = fixture();
    slot(&root, "0123456789abcdef", "1.0.0");
    slot(&root, "abcdef0123456789", "2.0.0");
    let local = root.join("1234567890abcdef");
    fs::create_dir_all(local.join("node_modules")).unwrap();
    fs::write(
        local.join("package.json"),
        r#"{"dependencies":{"local-tool":"file:../../../project"}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&root, local.join("node_modules/local-tool")).unwrap();
    let inv = inventory(&root, &CancellationToken::new());
    assert!(!inv.complete);
    assert_eq!(
        inv.entries
            .iter()
            .filter(|r| r.older_version)
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        vec!["0123456789abcdef"]
    );
    let unknown = inv
        .entries
        .iter()
        .find(|r| r.id == "1234567890abcdef")
        .unwrap();
    assert_eq!(unknown.packages[0].name, "local-tool");
    assert!(!unknown.complete);
}
