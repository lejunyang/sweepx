use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::symlink;

use sweepx_fixtures::{
    FixtureEntry, FixtureEntryKind, FixtureError, Receipt, TaggedValue, contract_manifest_path,
    contract_receipt_path, default_p0_p1_manifest, generate_from_contract_files,
    generate_from_manifest, host_supports_fixture_symlinks, load_receipt_contract,
    oracle_from_contract_files, oracle_from_manifest,
};
use tempfile::tempdir;

// The Linux P4 Trash qualification surface only exists on Linux hosts, so its
// imports are gated with the tests that exercise it.
#[cfg(target_os = "linux")]
use sha2::Digest;
#[cfg(target_os = "linux")]
use sweepx_fixtures::{
    ContentPattern, LINUX_P4_TRASH_TARGET_ENTRY_ID, P4BarrierName, P4EvidenceBundle,
    contract_p4_evidence_bundle_path, linux_p4_trash_manifest,
};

/// Skips a symlink-dependent fixture when the host cannot create symlinks at all.
///
/// The default P0/P1 manifest contains a relative symlink, and Windows refuses
/// symlink creation to an unprivileged process unless Developer Mode is on. The
/// capability is probed against the real filesystem rather than assumed from the
/// target OS, and a skip is announced so it can never be mistaken for a pass of the
/// symlink behavior itself.
macro_rules! require_symlink_support {
    ($probe_dir:expr, $test_name:literal) => {
        if !host_supports_fixture_symlinks($probe_dir) {
            eprintln!(
                "SKIP {}: host cannot create symlinks (on Windows this needs Developer Mode \
                 or elevation); the symlink fixture behavior is NOT verified here",
                $test_name
            );
            return;
        }
    };
}

#[test]
fn minimal_contract_generation_matches_full_expected_receipt() {
    let root = tempdir().expect("tempdir");
    let generated = generate_from_contract_files(root.path(), contract_manifest_path("minimal"))
        .expect("generate minimal fixture");
    let expected =
        load_receipt_contract(contract_receipt_path("minimal")).expect("receipt contract");
    assert_eq!(generated.receipt, expected);
}

#[test]
fn generation_receipt_is_byte_for_byte_reproducible_from_seed() {
    let manifest = default_p0_p1_manifest();
    let root_a = tempdir().expect("tempdir a");
    let root_b = tempdir().expect("tempdir b");
    require_symlink_support!(
        root_a.path(),
        "generation_receipt_is_byte_for_byte_reproducible_from_seed"
    );

    let generated_a = generate_from_manifest(root_a.path(), &manifest).expect("generate a");
    let generated_b = generate_from_manifest(root_b.path(), &manifest).expect("generate b");

    let receipt_a = serde_json::to_vec_pretty(&generated_a.receipt).expect("serialize receipt a");
    let receipt_b = serde_json::to_vec_pretty(&generated_b.receipt).expect("serialize receipt b");
    assert_eq!(receipt_a, receipt_b);

    let alpha_a = generated_a.fixture_dir.join("alpha.txt");
    let alpha_b = generated_b.fixture_dir.join("alpha.txt");
    assert_eq!(
        fs::read(alpha_a).expect("alpha a"),
        fs::read(alpha_b).expect("alpha b")
    );
}

#[test]
fn generation_refuses_nonempty_root_and_filesystem_root() {
    let manifest = default_p0_p1_manifest();

    let root = tempdir().expect("tempdir");
    fs::write(root.path().join("occupied"), b"x").expect("write blocker");
    let err =
        generate_from_manifest(root.path(), &manifest).expect_err("must reject nonempty root");
    assert!(matches!(err, FixtureError::FixtureRootNotEmpty { .. }));

    // A volume root must be refused on every host. `/` is the Unix filesystem root;
    // on Windows the equivalent is a drive root, which still has no `Normal` path
    // component even though it does carry a `Prefix`.
    for filesystem_root in filesystem_roots() {
        let err =
            generate_from_manifest(&filesystem_root, &manifest).expect_err("must reject fs root");
        assert!(
            matches!(err, FixtureError::FixtureRootIsFilesystemRoot { .. }),
            "{} must be refused as a filesystem root, got {err:?}",
            filesystem_root.display()
        );
    }
}

/// Returns host filesystem/volume roots that fixture generation must always refuse.
fn filesystem_roots() -> Vec<std::path::PathBuf> {
    #[cfg(windows)]
    {
        let mut roots = vec![std::path::PathBuf::from(r"C:\")];
        // The drive holding this checkout is covered too, so the assertion is not
        // limited to whichever volume happens to be C:.
        if let Ok(current) = std::env::current_dir() {
            let mut components = current.components();
            if let (Some(prefix), Some(root)) = (components.next(), components.next()) {
                let drive_root: std::path::PathBuf = [prefix, root].iter().collect();
                if !roots.contains(&drive_root) {
                    roots.push(drive_root);
                }
            }
        }
        roots
    }
    #[cfg(not(windows))]
    {
        vec![std::path::PathBuf::from("/")]
    }
}

// Creating a symlink is unprivileged on Unix but requires elevation or Developer
// Mode on Windows, so the symlink-root rejection is asserted only where the test
// can actually build the link. A skipped assertion is preferable to a fixture that
// silently proves nothing.
#[cfg(unix)]
#[test]
fn generation_refuses_symlink_fixture_root_and_canonicalizes_root() {
    let manifest = default_p0_p1_manifest();
    let holder = tempdir().expect("holder");
    let real_root = holder.path().join("real-root");
    fs::create_dir(&real_root).expect("create real root");
    let symlink_root = holder.path().join("root-link");
    symlink(&real_root, &symlink_root).expect("create symlink root");

    let err =
        generate_from_manifest(&symlink_root, &manifest).expect_err("must reject symlink root");
    assert!(matches!(err, FixtureError::FixtureRootIsSymlink { .. }));

    let generated = generate_from_manifest(&real_root, &manifest).expect("generate real root");
    let oracle = oracle_from_manifest(&real_root, &manifest).expect("oracle");
    assert_eq!(generated.receipt.root_path, "/NORMALIZED/p1-deterministic");
    assert_eq!(generated.receipt.root_path, oracle.receipt.root_path);
}

/// Asserts root canonicalization on hosts where the symlink half cannot be built.
#[cfg(not(unix))]
#[test]
fn generation_canonicalizes_root() {
    let manifest = default_p0_p1_manifest();
    let holder = tempdir().expect("holder");
    require_symlink_support!(holder.path(), "generation_canonicalizes_root");
    let real_root = holder.path().join("real-root");
    fs::create_dir(&real_root).expect("create real root");

    let generated = generate_from_manifest(&real_root, &manifest).expect("generate real root");
    let oracle = oracle_from_manifest(&real_root, &manifest).expect("oracle");
    assert_eq!(generated.receipt.root_path, "/NORMALIZED/p1-deterministic");
    assert_eq!(generated.receipt.root_path, oracle.receipt.root_path);
}

#[test]
fn generation_refuses_symlink_escape_outside_fixture_root() {
    // No symlink is ever created here: the escape must be refused during manifest
    // validation, before any mutation, so this runs on every host.
    let mut manifest = default_p0_p1_manifest();
    let symlink = manifest
        .entries
        .iter_mut()
        .find(|entry| entry.kind == FixtureEntryKind::Symlink)
        .expect("symlink entry");
    symlink.link_target = Some(vec![
        "..".into(),
        "..".into(),
        "outside-root".into(),
        "escape".into(),
    ]);

    let root = tempdir().expect("tempdir");
    let err =
        generate_from_manifest(root.path(), &manifest).expect_err("must reject escaping symlink");
    assert!(matches!(
        err,
        FixtureError::SymlinkTargetEscapesFixtureRoot { .. }
    ));
    assert!(
        fs::read_dir(root.path())
            .expect("root listing")
            .next()
            .is_none()
    );
}

#[test]
fn invalid_hardlink_manifest_is_rejected_before_mutation() {
    let mut manifest = default_p0_p1_manifest();
    let hardlink = manifest
        .entries
        .iter_mut()
        .find(|entry| entry.kind == FixtureEntryKind::Hardlink)
        .expect("hardlink entry");
    hardlink.hardlink_to = Some(vec![
        "p1-deterministic".into(),
        "nested".into(),
        "missing.bin".into(),
    ]);

    let root = tempdir().expect("tempdir");
    let err = generate_from_manifest(root.path(), &manifest)
        .expect_err("must reject missing hardlink target");
    assert!(matches!(err, FixtureError::HardlinkTargetMissing { .. }));
    assert!(
        fs::read_dir(root.path())
            .expect("root listing")
            .next()
            .is_none()
    );
}

#[test]
fn self_referential_hardlink_is_rejected_before_mutation() {
    let mut manifest = default_p0_p1_manifest();
    let hardlink = manifest
        .entries
        .iter_mut()
        .find(|entry| entry.kind == FixtureEntryKind::Hardlink)
        .expect("hardlink entry");
    hardlink.hardlink_to = Some(hardlink.path.clone());

    let root = tempdir().expect("tempdir");
    let err = generate_from_manifest(root.path(), &manifest)
        .expect_err("must reject self-referential hardlink");
    assert!(matches!(err, FixtureError::HardlinkCycle { .. }));
    assert!(
        fs::read_dir(root.path())
            .expect("root listing")
            .next()
            .is_none()
    );
}

#[test]
fn multi_node_hardlink_cycle_is_rejected_before_mutation() {
    let mut manifest = default_p0_p1_manifest();
    let first_path = vec![
        "p1-deterministic".into(),
        "nested".into(),
        "alpha-hard.txt".into(),
    ];
    let second_path = vec![
        "p1-deterministic".into(),
        "nested".into(),
        "beta-hard.txt".into(),
    ];
    manifest
        .entries
        .iter_mut()
        .find(|entry| entry.path == first_path)
        .expect("first hardlink entry")
        .hardlink_to = Some(second_path.clone());
    manifest.entries.push(FixtureEntry {
        entry_id: "beta-hardlink".into(),
        path: second_path,
        kind: FixtureEntryKind::Hardlink,
        bytes: None,
        mode: None,
        content_pattern: None,
        link_target: None,
        hardlink_to: Some(first_path),
        notes: vec![],
    });

    let root = tempdir().expect("tempdir");
    let err = generate_from_manifest(root.path(), &manifest)
        .expect_err("must reject multi-node hardlink cycle");
    assert!(matches!(err, FixtureError::HardlinkCycle { .. }));
    assert!(
        fs::read_dir(root.path())
            .expect("root listing")
            .next()
            .is_none()
    );
}

#[test]
fn oracle_reports_independent_identity_boundaries_and_hardlink_group() {
    let manifest = default_p0_p1_manifest();
    let root = tempdir().expect("tempdir");
    require_symlink_support!(
        root.path(),
        "oracle_reports_independent_identity_boundaries_and_hardlink_group"
    );
    let generated = generate_from_manifest(root.path(), &manifest).expect("generate");

    let oracle = oracle_from_manifest(root.path(), &manifest).expect("oracle");
    assert_eq!(oracle.receipt.root_path, "/NORMALIZED/p1-deterministic");
    assert!(
        oracle
            .boundaries
            .contains("kind:p1-deterministic/nested/alpha-link.txt:symlink")
    );

    let alpha = oracle
        .identities
        .get(&vec!["p1-deterministic".into(), "alpha.txt".into()])
        .expect("alpha identity");
    let hard = oracle
        .identities
        .get(&vec![
            "p1-deterministic".into(),
            "nested".into(),
            "alpha-hard.txt".into(),
        ])
        .expect("hardlink identity");
    let link = oracle
        .identities
        .get(&vec![
            "p1-deterministic".into(),
            "nested".into(),
            "alpha-link.txt".into(),
        ])
        .expect("symlink identity");

    assert_eq!(alpha.digest, hard.digest);
    assert_eq!(alpha.hardlink_group, hard.hardlink_group);
    assert_eq!(
        alpha.hardlink_group.as_deref(),
        Some("hardlink:p1-deterministic/alpha.txt")
    );
    assert_eq!(
        link.link_target,
        Some(vec!["..".into(), "alpha.txt".into()])
    );
    assert_eq!(
        oracle.receipt.totals.apparent_logical_bytes,
        TaggedValue::Known {
            value: "55".parse().expect("decimal")
        }
    );
    assert_eq!(
        oracle.receipt.totals.unique_logical_bytes,
        TaggedValue::Known {
            value: "38".parse().expect("decimal")
        }
    );

    assert_same_native_file(
        &generated.fixture_dir.join("alpha.txt"),
        &generated.fixture_dir.join("nested/alpha-hard.txt"),
    );
}

/// Asserts that two paths name the same native file object, not merely equal bytes.
///
/// The hardlink group in the oracle is a manifest-derived claim, so it is checked
/// against the live filesystem. Unix compares `(dev, ino)` directly. Windows has no
/// stable `Metadata` accessor for the file ID (`file_index` is still unstable), so
/// the shared-inode property is observed behaviorally: a write through one name must
/// be visible through the other. Two distinct files with identical content fail that
/// write half, so this cannot pass by content coincidence.
fn assert_same_native_file(left: &Path, right: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let left_meta = fs::metadata(left).expect("left metadata");
        let right_meta = fs::metadata(right).expect("right metadata");
        assert_eq!(left_meta.dev(), right_meta.dev());
        assert_eq!(left_meta.ino(), right_meta.ino());
    }
    #[cfg(not(unix))]
    {
        let original = fs::read(left).expect("read left");
        assert_eq!(original, fs::read(right).expect("read right"));

        let probe = b"hardlink-identity-probe".to_vec();
        fs::write(left, &probe).expect("write through left name");
        assert_eq!(
            fs::read(right).expect("read right after write"),
            probe,
            "a write through one hardlink name must be visible through the other"
        );
        assert_eq!(
            fs::metadata(left).expect("left metadata").len(),
            fs::metadata(right).expect("right metadata").len()
        );

        // Restore the generated content so later assertions still see the fixture
        // exactly as the manifest describes it.
        fs::write(left, &original).expect("restore left");
        assert_eq!(fs::read(right).expect("read right after restore"), original);
    }
}

#[test]
fn oracle_from_contract_files_reads_contract_and_generated_tree() {
    let root = tempdir().expect("tempdir");
    generate_from_contract_files(root.path(), contract_manifest_path("minimal")).expect("generate");
    let oracle = oracle_from_contract_files(root.path(), contract_manifest_path("minimal"))
        .expect("oracle contract");

    assert_eq!(oracle.receipt.entries.len(), 2);
    assert_eq!(
        oracle.receipt.entries[1].digest.as_deref(),
        Some("sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    );
    assert_eq!(
        oracle.receipt.totals.logical_bytes,
        TaggedValue::Known {
            value: "5".parse().expect("decimal")
        }
    );
    assert_eq!(
        oracle.receipt.totals.apparent_logical_bytes,
        TaggedValue::Known {
            value: "5".parse().expect("decimal")
        }
    );
    assert_eq!(
        oracle.receipt.totals.unique_logical_bytes,
        TaggedValue::Known {
            value: "5".parse().expect("decimal")
        }
    );
}

#[test]
fn receipt_json_roundtrip_keeps_contract_shape() {
    let receipt: Receipt = load_receipt_contract(contract_receipt_path("minimal")).expect("load");
    let json = serde_json::to_value(&receipt).expect("serialize");
    assert_eq!(
        json.get("schema").and_then(|v| v.as_str()),
        Some("sweepx.receipt/v1")
    );
    assert_eq!(json["entries"][1]["kind"], "file");
}

#[test]
fn receipt_comparison_is_independent_of_generation_root() {
    let manifest = default_p0_p1_manifest();
    let root_a = tempdir().expect("root a");
    let root_b = tempdir().expect("root b");
    require_symlink_support!(
        root_a.path(),
        "receipt_comparison_is_independent_of_generation_root"
    );

    let receipt_a = generate_from_manifest(root_a.path(), &manifest)
        .expect("generate a")
        .receipt;
    let receipt_b = generate_from_manifest(root_b.path(), &manifest)
        .expect("generate b")
        .receipt;

    assert_eq!(receipt_a, receipt_b);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_p4_manifest_selects_one_private_path_by_entry_id() {
    let manifest = linux_p4_trash_manifest("ext4");
    assert_eq!(manifest.platform_profile.os_family, "linux");
    assert_eq!(manifest.platform_profile.filesystem, "ext4");
    assert_eq!(
        manifest.platform_profile.native_mutation_phase,
        "P4-trash-only"
    );
    assert_eq!(
        manifest
            .entries
            .iter()
            .filter(|entry| entry.kind == FixtureEntryKind::File)
            .count(),
        1
    );

    let root = tempdir().expect("tempdir");
    let generated = generate_from_manifest(root.path(), &manifest).expect("generate");
    let selected = generated
        .select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID)
        .expect("select target");

    assert_eq!(selected.entry_id(), LINUX_P4_TRASH_TARGET_ENTRY_ID);
    assert_eq!(selected.expected_filesystem(), "ext4");
    let authoritative_digest = selected.manifest_digest().to_string();
    assert_eq!(generated.top_dir(), generated.fixture_dir);
    assert!(
        selected.matches_manifest_derived_target(&generated.fixture_dir.join("trash-target.txt"))
    );
    assert!(!selected.matches_manifest_derived_target(&generated.fixture_dir));
    assert!(!selected.matches_manifest_derived_target(
        &generated.fixture_dir.join(".").join("trash-target.txt")
    ));
    let debug = format!("{selected:?}");
    assert!(!debug.contains(generated.fixture_dir.to_string_lossy().as_ref()));
    assert!(!debug.contains("trash-target.txt"));
    selected.verify_unchanged().expect("unchanged");
    selected
        .verify_source_unchanged()
        .expect("source unchanged alias");
    assert!(matches!(
        generated.select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID),
        Err(FixtureError::LinuxTrashTargetAlreadyIssued)
    ));
    let public_digest = format!(
        "sha256:{:x}",
        sha2::Sha256::digest(serde_json::to_vec(&generated.manifest).unwrap())
    );
    assert_eq!(authoritative_digest, public_digest);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_p4_selection_rejects_profile_mismatches() {
    for (manifest, expected) in [
        (
            {
                let mut manifest = linux_p4_trash_manifest("ext4");
                manifest.platform_profile.os_family = "macos".into();
                manifest
            },
            "os",
        ),
        (
            {
                let mut manifest = linux_p4_trash_manifest("ext4");
                manifest.platform_profile.native_mutation_phase = "P5-qualified".into();
                manifest
            },
            "phase",
        ),
    ] {
        let root = tempdir().expect("tempdir");
        let generated = generate_from_manifest(root.path(), &manifest).expect("generate");
        let error = generated
            .select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID)
            .expect_err("profile mismatch");
        match expected {
            "os" => assert!(matches!(
                error,
                FixtureError::LinuxTrashOsFamilyMismatch { .. }
            )),
            "phase" => assert!(matches!(
                error,
                FixtureError::LinuxTrashMutationPhaseMismatch { .. }
            )),
            _ => unreachable!(),
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_p4_selection_rejects_absent_duplicate_and_non_file_entry_ids() {
    let root = tempdir().expect("tempdir");
    let generated =
        generate_from_manifest(root.path(), &linux_p4_trash_manifest("ext4")).expect("generate");
    assert!(matches!(
        generated.select_linux_trash_target("missing"),
        Err(FixtureError::LinuxTrashEntryIdAbsent { .. })
    ));
    assert!(matches!(
        generated.select_linux_trash_target("linux-trash-root"),
        Err(FixtureError::LinuxTrashManifestTargetNotFile { .. })
    ));

    let mut duplicate = linux_p4_trash_manifest("ext4");
    duplicate.entries.push(FixtureEntry {
        entry_id: LINUX_P4_TRASH_TARGET_ENTRY_ID.into(),
        path: vec!["linux-p4-trash".into(), "second.txt".into()],
        kind: FixtureEntryKind::File,
        bytes: Some(1u128.into()),
        mode: Some("0644".into()),
        content_pattern: Some(ContentPattern::Zeroes),
        link_target: None,
        hardlink_to: None,
        notes: vec![],
    });
    let root = tempdir().expect("duplicate tempdir");
    let generated = generate_from_manifest(root.path(), &duplicate).expect("generate duplicate");
    assert!(matches!(
        generated.select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID),
        Err(FixtureError::LinuxTrashEntryIdDuplicate { .. })
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_p4_selection_uses_private_generation_snapshot() {
    let root = tempdir().expect("tempdir");
    let authoritative_manifest = linux_p4_trash_manifest("ext4");
    let authoritative_digest = format!(
        "sha256:{:x}",
        sha2::Sha256::digest(serde_json::to_vec(&authoritative_manifest).unwrap())
    );
    let mut generated =
        generate_from_manifest(root.path(), &authoritative_manifest).expect("generate");
    generated.manifest.platform_profile.os_family = "windows".into();
    generated.manifest.entries[1].entry_id = "redirected-entry".into();
    generated.fixture_dir = root.path().join("caller-substituted");

    let selected = generated
        .select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID)
        .expect("public diagnostic fields cannot redirect selection");
    assert_eq!(selected.entry_id(), LINUX_P4_TRASH_TARGET_ENTRY_ID);
    assert_eq!(selected.manifest_digest(), authoritative_digest);
    assert!(
        selected
            .matches_manifest_derived_target(&root.path().join("linux-p4-trash/trash-target.txt"))
    );
    assert!(
        !selected.matches_manifest_derived_target(&generated.fixture_dir.join("trash-target.txt"))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_p4_selection_rejects_symlink_directory_and_hardlink_targets() {
    let mut directory_manifest = linux_p4_trash_manifest("ext4");
    directory_manifest.entries.push(FixtureEntry {
        entry_id: "trash-directory".into(),
        path: vec!["linux-p4-trash".into(), "trash-directory".into()],
        kind: FixtureEntryKind::Directory,
        bytes: None,
        mode: None,
        content_pattern: None,
        link_target: None,
        hardlink_to: None,
        notes: vec![],
    });
    let root = tempdir().expect("manifest directory tempdir");
    let generated =
        generate_from_manifest(root.path(), &directory_manifest).expect("generate directory entry");
    assert!(matches!(
        generated.select_linux_trash_target("trash-directory"),
        Err(FixtureError::LinuxTrashManifestTargetNotFile { .. })
    ));

    let mut symlink_manifest = linux_p4_trash_manifest("ext4");
    symlink_manifest.entries.push(FixtureEntry {
        entry_id: "trash-symlink".into(),
        path: vec!["linux-p4-trash".into(), "trash-link".into()],
        kind: FixtureEntryKind::Symlink,
        bytes: None,
        mode: None,
        content_pattern: None,
        link_target: Some(vec!["trash-target.txt".into()]),
        hardlink_to: None,
        notes: vec![],
    });
    let root = tempdir().expect("symlink tempdir");
    let generated =
        generate_from_manifest(root.path(), &symlink_manifest).expect("generate symlink");
    assert!(matches!(
        generated.select_linux_trash_target("trash-symlink"),
        Err(FixtureError::LinuxTrashManifestTargetNotFile { .. })
    ));

    let mut hardlink_manifest = linux_p4_trash_manifest("ext4");
    hardlink_manifest.entries.push(FixtureEntry {
        entry_id: "trash-hardlink".into(),
        path: vec!["linux-p4-trash".into(), "trash-hardlink.txt".into()],
        kind: FixtureEntryKind::Hardlink,
        bytes: None,
        mode: None,
        content_pattern: None,
        link_target: None,
        hardlink_to: Some(vec!["linux-p4-trash".into(), "trash-target.txt".into()]),
        notes: vec![],
    });
    let root = tempdir().expect("manifest hardlink tempdir");
    let generated =
        generate_from_manifest(root.path(), &hardlink_manifest).expect("generate hardlink entry");
    assert!(matches!(
        generated.select_linux_trash_target("trash-hardlink"),
        Err(FixtureError::LinuxTrashManifestTargetNotFile { .. })
    ));

    let root = tempdir().expect("runtime symlink tempdir");
    let generated = generate_from_manifest(root.path(), &linux_p4_trash_manifest("ext4"))
        .expect("generate runtime symlink");
    fs::remove_file(generated.fixture_dir.join("trash-target.txt")).expect("remove target");
    symlink(
        "replacement",
        generated.fixture_dir.join("trash-target.txt"),
    )
    .expect("replace with symlink");
    assert!(matches!(
        generated.select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID),
        Err(FixtureError::LinuxTrashRuntimeTargetNotFile { .. })
    ));

    let root = tempdir().expect("hardlink tempdir");
    let generated = generate_from_manifest(root.path(), &linux_p4_trash_manifest("ext4"))
        .expect("generate hardlink");
    fs::hard_link(
        generated.fixture_dir.join("trash-target.txt"),
        generated.fixture_dir.join("extra-hardlink.txt"),
    )
    .expect("create hardlink");
    assert!(matches!(
        generated.select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID),
        Err(FixtureError::LinuxTrashRuntimeTargetHasMultipleLinks { .. })
    ));

    let root = tempdir().expect("runtime directory tempdir");
    let generated = generate_from_manifest(root.path(), &linux_p4_trash_manifest("ext4"))
        .expect("generate runtime directory");
    fs::remove_file(generated.fixture_dir.join("trash-target.txt")).expect("remove target");
    fs::create_dir(generated.fixture_dir.join("trash-target.txt")).expect("replace with directory");
    assert!(matches!(
        generated.select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID),
        Err(FixtureError::LinuxTrashRuntimeTargetNotFile { .. })
    ));

    let root = tempdir().expect("missing runtime target tempdir");
    let generated = generate_from_manifest(root.path(), &linux_p4_trash_manifest("ext4"))
        .expect("generate missing runtime target");
    fs::remove_file(generated.fixture_dir.join("trash-target.txt")).expect("remove target");
    assert!(matches!(
        generated.select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID),
        Err(FixtureError::LinuxTrashFixtureChanged)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_p4_final_recheck_detects_target_sibling_and_unexpected_tree_changes() {
    let root = tempdir().expect("preselection tempdir");
    let generated = generate_from_manifest(root.path(), &linux_p4_trash_manifest("ext4"))
        .expect("generate preselection");
    fs::write(generated.fixture_dir.join("trash-target.txt"), b"changed")
        .expect("change before selection");
    assert!(matches!(
        generated.select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID),
        Err(FixtureError::LinuxTrashFixtureChanged)
    ));

    let root = tempdir().expect("target tempdir");
    let generated = generate_from_manifest(root.path(), &linux_p4_trash_manifest("ext4"))
        .expect("generate target");
    let selected = generated
        .select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID)
        .expect("select target");
    fs::write(generated.fixture_dir.join("trash-target.txt"), b"changed").expect("change target");
    assert!(matches!(
        selected.verify_unchanged(),
        Err(FixtureError::LinuxTrashFixtureChanged)
    ));

    let mut manifest = linux_p4_trash_manifest("ext4");
    manifest.entries.push(FixtureEntry {
        entry_id: "sibling-file".into(),
        path: vec!["linux-p4-trash".into(), "sibling.txt".into()],
        kind: FixtureEntryKind::File,
        bytes: Some(4u128.into()),
        mode: Some("0644".into()),
        content_pattern: Some(ContentPattern::Zeroes),
        link_target: None,
        hardlink_to: None,
        notes: vec![],
    });
    let root = tempdir().expect("sibling tempdir");
    let generated = generate_from_manifest(root.path(), &manifest).expect("generate sibling");
    let selected = generated
        .select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID)
        .expect("select target");
    fs::write(generated.fixture_dir.join("sibling.txt"), b"changed").expect("change sibling");
    assert!(matches!(
        selected.verify_unchanged(),
        Err(FixtureError::LinuxTrashFixtureChanged)
    ));

    let root = tempdir().expect("unexpected tempdir");
    let generated = generate_from_manifest(root.path(), &linux_p4_trash_manifest("ext4"))
        .expect("generate unexpected");
    let selected = generated
        .select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID)
        .expect("select target");
    fs::write(generated.fixture_dir.join("unexpected"), b"x").expect("add entry");
    assert!(matches!(
        selected.verify_unchanged(),
        Err(FixtureError::LinuxTrashUnexpectedEntry)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_p4_post_action_recheck_allows_only_target_removal() {
    let mut manifest = linux_p4_trash_manifest("ext4");
    manifest.entries.push(FixtureEntry {
        entry_id: "sibling-file".into(),
        path: vec!["linux-p4-trash".into(), "sibling.txt".into()],
        kind: FixtureEntryKind::File,
        bytes: Some(4u128.into()),
        mode: Some("0644".into()),
        content_pattern: Some(ContentPattern::Zeroes),
        link_target: None,
        hardlink_to: None,
        notes: vec![],
    });

    let root = tempdir().expect("success tempdir");
    let generated = generate_from_manifest(root.path(), &manifest).expect("generate success");
    let selected = generated
        .select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID)
        .expect("select target");
    assert!(matches!(
        selected.verify_target_removed_and_rest_unchanged(),
        Err(FixtureError::LinuxTrashTargetStillExists { .. })
    ));
    fs::remove_file(generated.fixture_dir.join("trash-target.txt"))
        .expect("remove selected target");
    selected
        .verify_target_removed_and_rest_unchanged()
        .expect("only target removed");

    let mut nested_manifest = linux_p4_trash_manifest("ext4");
    nested_manifest.entries.insert(
        1,
        FixtureEntry {
            entry_id: "target-parent".into(),
            path: vec!["linux-p4-trash".into(), "nested".into()],
            kind: FixtureEntryKind::Directory,
            bytes: None,
            mode: None,
            content_pattern: None,
            link_target: None,
            hardlink_to: None,
            notes: vec![],
        },
    );
    nested_manifest.entries[2].path = vec![
        "linux-p4-trash".into(),
        "nested".into(),
        "trash-target.txt".into(),
    ];
    let root = tempdir().expect("nested tempdir");
    let generated = generate_from_manifest(root.path(), &nested_manifest).expect("generate nested");
    let selected = generated
        .select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID)
        .expect("select nested target");
    fs::remove_file(generated.fixture_dir.join("nested/trash-target.txt"))
        .expect("remove nested target");
    selected
        .verify_target_removed_and_rest_unchanged()
        .expect("only nested target removed");

    let root = tempdir().expect("changed sibling tempdir");
    let generated = generate_from_manifest(root.path(), &manifest).expect("generate changed");
    let selected = generated
        .select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID)
        .expect("select target");
    fs::remove_file(generated.fixture_dir.join("trash-target.txt"))
        .expect("remove selected target");
    fs::write(generated.fixture_dir.join("sibling.txt"), b"changed").expect("change sibling");
    assert!(matches!(
        selected.verify_target_removed_and_rest_unchanged(),
        Err(FixtureError::LinuxTrashFixtureChanged)
    ));

    let root = tempdir().expect("unexpected tempdir");
    let generated = generate_from_manifest(root.path(), &manifest).expect("generate unexpected");
    let selected = generated
        .select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID)
        .expect("select target");
    fs::remove_file(generated.fixture_dir.join("trash-target.txt"))
        .expect("remove selected target");
    fs::write(generated.fixture_dir.join("unexpected"), b"x").expect("add entry");
    assert!(matches!(
        selected.verify_target_removed_and_rest_unchanged(),
        Err(FixtureError::LinuxTrashUnexpectedEntry)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_p4_named_evidence_trace_and_bundle_are_deterministic() {
    let root = tempdir().expect("evidence tempdir");
    let generated = generate_from_manifest(root.path(), &linux_p4_trash_manifest("ext4"))
        .expect("generate evidence fixture");
    let selected = generated
        .select_linux_trash_target(LINUX_P4_TRASH_TARGET_ENTRY_ID)
        .expect("select target");

    let barriers = [
        P4BarrierName::BeforeIntent,
        P4BarrierName::AfterIntentSync,
        P4BarrierName::AfterSubmit,
        P4BarrierName::BeforeOutcomeSync,
        P4BarrierName::DuringReconcile,
    ];
    for barrier in barriers {
        let trace = selected
            .evidence_trace(barrier, "linux-trash-backend", "native_ok")
            .expect("trace");
        assert_eq!(trace.schema, "sweepx.p4_evidence_trace/v1");
        assert_eq!(trace.barrier, barrier);
        assert_eq!(trace.seed, "44".parse().expect("seed"));
        assert_eq!(trace.fixture_manifest_id, "fixture-linux-p4-trash");
        assert_eq!(trace.os_family, "linux");
        assert_eq!(trace.filesystem, "ext4");
        assert_eq!(trace.backend, "linux-trash-backend");
        assert_eq!(trace.native_result, "native_ok");
        assert_eq!(trace.expires_at, "2026-08-28T06:00:00Z");
        assert!(!trace.limitations.is_empty());
    }

    let bundle = selected
        .evidence_bundle(
            P4BarrierName::AfterSubmit,
            "linux-trash-backend",
            "native_ok",
        )
        .expect("bundle");
    let expected = load_p4_evidence_bundle(contract_p4_evidence_bundle_path(
        "linux-p4-trash-after-submit",
    ))
    .expect("golden bundle");
    assert_eq!(
        bundle.trace.fixture_manifest_digest,
        "sha256:49a8824cb0d8c7d567941d580402ca3cdfbe6acdab05be6a6b67b7f1698af4cf"
    );
    assert_eq!(
        bundle.trace.oracle_receipt_digest,
        "sha256:d7df63f4132e2d84f8def197e8b6e66c38733346b64c6b6fb1c2520815ad8a4f"
    );
    assert_eq!(
        bundle.trace.oracle_receipt_digest,
        selected.oracle_receipt_digest()
    );
    assert_eq!(bundle, expected);
}

#[cfg(target_os = "linux")]
fn load_p4_evidence_bundle(path: impl AsRef<Path>) -> Result<P4EvidenceBundle, serde_json::Error> {
    let bytes = std::fs::read(path).expect("read p4 evidence bundle contract");
    serde_json::from_slice(&bytes)
}
