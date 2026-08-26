use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use sweepx_fixtures::{
    FixtureEntryKind, FixtureError, Receipt, TaggedValue, contract_manifest_path,
    contract_receipt_path, default_p0_p1_manifest, generate_from_contract_files,
    generate_from_manifest, load_receipt_contract, oracle_from_contract_files,
    oracle_from_manifest,
};
use tempfile::tempdir;

#[test]
fn minimal_contract_generation_matches_expected_receipt_shape() {
    let root = tempdir().expect("tempdir");
    let generated = generate_from_contract_files(root.path(), contract_manifest_path("minimal"))
        .expect("generate minimal fixture");
    let expected =
        load_receipt_contract(contract_receipt_path("minimal")).expect("receipt contract");
    assert_eq!(
        normalized_receipt(generated.receipt),
        normalized_receipt(expected)
    );
}

#[test]
fn generation_is_deterministic_and_reproducible() {
    let manifest = default_p0_p1_manifest();
    let root_a = tempdir().expect("tempdir a");
    let root_b = tempdir().expect("tempdir b");

    let generated_a = generate_from_manifest(root_a.path(), &manifest).expect("generate a");
    let generated_b = generate_from_manifest(root_b.path(), &manifest).expect("generate b");

    assert_eq!(
        generated_a.receipt.generated_at,
        generated_b.receipt.generated_at
    );
    assert_eq!(generated_a.receipt.entries, generated_b.receipt.entries);
    assert_eq!(generated_a.receipt.totals, generated_b.receipt.totals);

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

    let err = generate_from_manifest(Path::new("/"), &manifest).expect_err("must reject fs root");
    assert!(matches!(
        err,
        FixtureError::FixtureRootIsFilesystemRoot { .. }
    ));
}

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
    assert_eq!(
        generated.receipt.root_path,
        real_root.join("p1-deterministic").display().to_string()
    );
    assert_eq!(generated.receipt.root_path, oracle.receipt.root_path);
}

#[test]
fn generation_refuses_symlink_escape_outside_fixture_root() {
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
fn oracle_reports_independent_identity_boundaries_and_hardlink_group() {
    let manifest = default_p0_p1_manifest();
    let root = tempdir().expect("tempdir");
    let generated = generate_from_manifest(root.path(), &manifest).expect("generate");

    let oracle = oracle_from_manifest(root.path(), &manifest).expect("oracle");
    assert_eq!(
        oracle.receipt.root_path,
        generated.fixture_dir.display().to_string()
    );
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

    let alpha_meta = fs::metadata(generated.fixture_dir.join("alpha.txt")).expect("alpha meta");
    let hard_meta =
        fs::metadata(generated.fixture_dir.join("nested/alpha-hard.txt")).expect("hard meta");
    assert_eq!(alpha_meta.ino(), hard_meta.ino());
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
fn normalized_receipt_comparison_ignores_root_path_variance() {
    let manifest = default_p0_p1_manifest();
    let root_a = tempdir().expect("root a");
    let root_b = tempdir().expect("root b");

    let receipt_a = generate_from_manifest(root_a.path(), &manifest)
        .expect("generate a")
        .receipt;
    let receipt_b = generate_from_manifest(root_b.path(), &manifest)
        .expect("generate b")
        .receipt;

    assert_eq!(normalized_receipt(receipt_a), normalized_receipt(receipt_b));
}

fn normalized_receipt(mut receipt: Receipt) -> Receipt {
    receipt.root_path = normalize_root_path(&receipt.root_path);
    receipt.receipt_id = normalize_receipt_id(&receipt.receipt_id, &receipt.manifest_id);
    receipt
        .entries
        .sort_by(|left, right| left.path.cmp(&right.path));
    for entry in &mut receipt.entries {
        match entry.kind {
            FixtureEntryKind::Directory => {
                entry.allocated_bytes = Some(TaggedValue::Unknown {
                    reason: "directory_allocation_platform_specific".into(),
                });
                entry.notes.clear();
            }
            FixtureEntryKind::File => {
                if let Some(allocated) = entry.allocated_bytes.take() {
                    entry.allocated_bytes = Some(normalize_file_allocated(allocated));
                }
                entry.notes.clear();
            }
            FixtureEntryKind::Symlink => {
                if let Some(allocated) = entry.allocated_bytes.take() {
                    entry.allocated_bytes = Some(normalize_symlink_allocated(allocated));
                }
            }
            FixtureEntryKind::Hardlink | FixtureEntryKind::Special => {}
        }
    }
    receipt.totals.allocated_bytes = normalize_file_allocated(receipt.totals.allocated_bytes);
    receipt.totals.logical_bytes = normalize_numeric_tagged(receipt.totals.logical_bytes);
    receipt.totals.apparent_logical_bytes =
        normalize_numeric_tagged(receipt.totals.apparent_logical_bytes);
    receipt.totals.unique_logical_bytes =
        normalize_numeric_tagged(receipt.totals.unique_logical_bytes);
    receipt
}

fn normalize_root_path(path: &str) -> String {
    let path = PathBuf::from(path);
    let name = path
        .file_name()
        .expect("fixture dirname")
        .to_string_lossy()
        .into_owned();
    format!("/NORMALIZED/{name}")
}

fn normalize_receipt_id(receipt_id: &str, manifest_id: &str) -> String {
    if receipt_id == format!("receipt-{manifest_id}") {
        receipt_id.to_string()
    } else {
        format!("receipt-{manifest_id}")
    }
}

fn normalize_file_allocated(value: TaggedValue) -> TaggedValue {
    match value {
        TaggedValue::Known { .. } | TaggedValue::LowerBound { .. } => TaggedValue::LowerBound {
            value: "5".parse().expect("decimal"),
            reason: "cross_platform_block_size_unknown".into(),
        },
        other => other,
    }
}

fn normalize_symlink_allocated(value: TaggedValue) -> TaggedValue {
    match value {
        TaggedValue::Known { value } | TaggedValue::LowerBound { value, .. } => {
            TaggedValue::LowerBound {
                value,
                reason: "symlink_target_length".into(),
            }
        }
        other => other,
    }
}

fn normalize_numeric_tagged(value: TaggedValue) -> TaggedValue {
    match value {
        TaggedValue::Known { value } | TaggedValue::LowerBound { value, .. } => {
            TaggedValue::Known { value }
        }
        other => other,
    }
}
