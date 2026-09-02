//! Acceptance tests for development-time cleaner signing.
//!
//! These use the real built-in package as the fixture, copied into a temporary
//! directory, so they exercise the same shapes the repository actually ships rather
//! than a hand-built minimal package that could diverge from it.

use std::fs;
use std::path::{Path, PathBuf};

use sweepx_catalog::{ExplicitPublisherKey, load_package_bytes, load_package_bytes_with_key};
use sweepx_cleaner_sign::{DEVELOPMENT_KEY_MARKER, SigningKeyFile, sign_package};
use tempfile::TempDir;
use time::OffsetDateTime;

/// The package used as a fixture; it carries a rule, evidence, and a manifest.
const FIXTURE_PACKAGE: &str = "org.sweepx.cargo-target";

fn repo_package_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../sweepx-catalog/resources/cleaners")
        .join(FIXTURE_PACKAGE)
}

/// Copies the shipped package into a temporary directory so tests never mutate the
/// repository. Signing rewrites files in place, so operating on the real directory
/// would corrupt the checked-in package.
fn staged_package() -> (TempDir, PathBuf) {
    let temp = TempDir::new().expect("temp dir");
    let destination = temp.path().join("pkg");
    copy_tree(&repo_package_dir(), &destination);
    (temp, destination)
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("create dir");
    for entry in fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("dir entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("copy file");
        }
    }
}

fn dev_key(temp: &TempDir, now: OffsetDateTime) -> (SigningKeyFile, PathBuf) {
    let path = temp.path().join("dev-key.json");
    let key = SigningKeyFile::generate("sweepx-dev-key-test", "org.sweepx", now).expect("generate");
    key.write(&path).expect("write key");
    (key, path)
}

fn explicit(key: &SigningKeyFile) -> ExplicitPublisherKey {
    ExplicitPublisherKey {
        key_id: key.key_id.clone(),
        publisher_id: key.publisher_id.clone(),
        public_key_b64u: key.public_key_b64u.clone(),
        valid_from: key.valid_from.clone(),
        valid_until: key.valid_until.clone(),
    }
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).expect("read file")
}

/// Loads a package straight off disk through the caller-key admission path.
fn load_from_disk(
    package: &Path,
    key: &SigningKeyFile,
    now: OffsetDateTime,
) -> Result<(), sweepx_catalog::CatalogError> {
    let manifest = read(&package.join("cleaner.json"));
    let signature = read(&package.join("SIGNATURE"));
    let rule = read(&package.join("rules/cargo-target.json"));
    let evidence = read(&package.join("evidence/README.md"));
    load_package_bytes_with_key(
        &manifest,
        &signature,
        &[("rules/cargo-target.json", &rule)],
        &[("evidence/README.md", &evidence)],
        &explicit(key),
        now,
    )
    .map(|_| ())
}

/// The workflow that was impossible before this tool existed: edit a rule on any
/// machine, re-sign, and have the package load again.
#[test]
fn a_locally_edited_rule_can_be_resigned_and_loads_again() {
    let now = OffsetDateTime::now_utc();
    let (temp, package) = staged_package();
    let (key, key_path) = dev_key(&temp, now);

    let first = sign_package(&package, &key_path, now).expect("initial signing");
    load_from_disk(&package, &key, now).expect("freshly signed package must load");

    let rule_path = package.join("rules/cargo-target.json");
    let original_rule = read(&rule_path);
    let edited = String::from_utf8(original_rule.clone())
        .expect("utf-8 rule")
        .replace(
            "\"cargo-clean-official-docs@accessed-2026-08-26\"",
            "\"cargo-clean-official-docs@accessed-2026-08-26\",\n    \
             \"local-edit@accessed-2026-09-01\"",
        );
    assert_ne!(
        edited.as_bytes(),
        original_rule.as_slice(),
        "the test edit must actually change the rule file, or it proves nothing"
    );
    fs::write(&rule_path, edited.as_bytes()).expect("write edited rule");

    // The edit must break the existing signature: if it did not, the digest would not
    // be covering rule content and tampering would go unnoticed.
    let stale = load_from_disk(&package, &key, now);
    assert!(
        stale.is_err(),
        "editing a rule must invalidate the existing signature, got {stale:?}"
    );

    let second = sign_package(&package, &key_path, now).expect("re-signing after edit");
    assert_ne!(
        first.package_digest, second.package_digest,
        "the package digest must track rule content"
    );
    load_from_disk(&package, &key, now).expect("re-signed package must load");
}

/// Signing twice without touching anything must not rewrite files.
///
/// If it did, every signing run would produce a diff, and contributors could not tell a
/// real change from signing noise.
#[test]
fn signing_an_unchanged_package_is_idempotent() {
    let now = OffsetDateTime::now_utc();
    let (temp, package) = staged_package();
    let (_key, key_path) = dev_key(&temp, now);

    let first = sign_package(&package, &key_path, now).expect("initial signing");
    let manifest_after_first = read(&package.join("cleaner.json"));
    let signature_after_first = read(&package.join("SIGNATURE"));

    let second = sign_package(&package, &key_path, now).expect("second signing");
    assert_eq!(first.package_digest, second.package_digest);
    assert!(
        !second.manifest_updated,
        "an unchanged package must not rewrite cleaner.json"
    );
    assert!(
        !second.publisher_rekeyed,
        "the publisher block is already correct after the first run"
    );
    assert_eq!(manifest_after_first, read(&package.join("cleaner.json")));
    assert_eq!(signature_after_first, read(&package.join("SIGNATURE")));
}

/// A development signature must not be accepted by the shipped trust store.
///
/// This is the guard that keeps the tool from becoming a way to inject packages into a
/// released binary: the package is internally valid, yet still refused.
#[test]
fn a_development_signature_is_refused_by_the_builtin_trust_store() {
    let now = OffsetDateTime::now_utc();
    let (temp, package) = staged_package();
    let (key, key_path) = dev_key(&temp, now);

    let outcome = sign_package(&package, &key_path, now).expect("signing");
    assert!(
        !outcome.key_is_builtin_trusted,
        "a generated development key must never already be a shipped anchor"
    );
    load_from_disk(&package, &key, now).expect("valid against its own key");

    let manifest = read(&package.join("cleaner.json"));
    let signature = read(&package.join("SIGNATURE"));
    let rule = read(&package.join("rules/cargo-target.json"));
    let evidence = read(&package.join("evidence/README.md"));
    let shipped = load_package_bytes(
        &manifest,
        &signature,
        &[("rules/cargo-target.json", &rule)],
        &[("evidence/README.md", &evidence)],
    );
    assert!(
        matches!(
            shipped,
            Err(sweepx_catalog::CatalogError::UnknownKey { .. })
        ),
        "the shipped trust store must reject a development key, got {shipped:?}"
    );
}

/// Rule digests recorded in the manifest are refreshed from the files on disk.
#[test]
fn manifest_rule_digests_are_recomputed_from_disk() {
    let now = OffsetDateTime::now_utc();
    let (temp, package) = staged_package();
    let (_key, key_path) = dev_key(&temp, now);

    let manifest_path = package.join("cleaner.json");
    let corrupted = String::from_utf8(read(&manifest_path))
        .expect("utf-8 manifest")
        .replace(
            "\"sha256\": \"364e73c3e666dec371582c683f499b1e0fedaf497ab829ef2a3dbbe3c6473eb3\"",
            "\"sha256\": \"0000000000000000000000000000000000000000000000000000000000000000\"",
        );
    fs::write(&manifest_path, corrupted.as_bytes()).expect("write manifest");

    sign_package(&package, &key_path, now).expect("signing must repair the recorded digest");
    let repaired = String::from_utf8(read(&manifest_path)).expect("utf-8 manifest");
    assert!(
        repaired.contains("364e73c3e666dec371582c683f499b1e0fedaf497ab829ef2a3dbbe3c6473eb3"),
        "the recorded rule digest must be recomputed from the rule file on disk"
    );
}

/// Signing must refuse a manifest that names a rule the package does not contain.
#[test]
fn a_manifest_referencing_a_missing_rule_is_refused() {
    let now = OffsetDateTime::now_utc();
    let (temp, package) = staged_package();
    let (_key, key_path) = dev_key(&temp, now);

    fs::remove_file(package.join("rules/cargo-target.json")).expect("remove rule");
    let error = sign_package(&package, &key_path, now).expect_err("must refuse");
    assert!(
        error.to_string().contains("not in the package"),
        "expected a missing-rule diagnosis, got: {error}"
    );
}

/// Keys without the development marker are refused at both generation and load.
#[test]
fn only_development_key_ids_are_accepted() {
    let now = OffsetDateTime::now_utc();
    let temp = TempDir::new().expect("temp dir");

    let generated = SigningKeyFile::generate("release-signing-key-2026", "org.sweepx", now);
    assert!(
        generated.is_err(),
        "a key id without {DEVELOPMENT_KEY_MARKER:?} must be refused"
    );

    // A key file edited by hand to drop the marker must also be refused on read, or the
    // generation-time check would be trivially bypassable.
    let path = temp.path().join("smuggled.json");
    let mut key = SigningKeyFile::generate("sweepx-dev-key-test", "org.sweepx", now).expect("key");
    key.write(&path).expect("write");
    key.key_id = "release-signing-key-2026".to_owned();
    let raw = serde_json::to_vec_pretty(&key).expect("serialize");
    fs::write(&path, raw).expect("write smuggled");
    assert!(
        SigningKeyFile::read(&path).is_err(),
        "reading a non-development key id must be refused"
    );
}

/// A key file whose public key does not match its secret key is refused.
///
/// Signing with it would emit a signature that nothing can verify, and the mismatch
/// would surface far from its cause.
#[test]
fn an_inconsistent_key_file_is_refused_before_signing() {
    let now = OffsetDateTime::now_utc();
    let (temp, package) = staged_package();
    let (mut key, key_path) = dev_key(&temp, now);

    let other = SigningKeyFile::generate("sweepx-dev-key-other", "org.sweepx", now).expect("key");
    key.public_key_b64u = other.public_key_b64u;
    let raw = serde_json::to_vec_pretty(&key).expect("serialize");
    fs::write(&key_path, raw).expect("write inconsistent key");

    let error = sign_package(&package, &key_path, now).expect_err("must refuse");
    assert!(
        error.to_string().contains("does not match the secret key"),
        "expected a key-consistency diagnosis, got: {error}"
    );
}
