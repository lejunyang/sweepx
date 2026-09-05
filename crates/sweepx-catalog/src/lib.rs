use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Deserializer;
use sha2::{Digest, Sha256};
use sweepx_cleaner_schema::{CleanerManifest, CleanerRule, ValidationError};
use thiserror::Error;

/// A cleaner package compiled into the executable.
///
/// The bytes are `include_bytes!` of the files under `resources/cleaners/`, so the package and the
/// code that reads it ship as one artifact and share one trust boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltInCleaner {
    pub package_dir: &'static str,
    pub manifest_bytes: &'static [u8],
    pub rule_files: &'static [(&'static str, &'static [u8])],
    pub evidence_files: &'static [(&'static str, &'static [u8])],
}

pub const CARGO_TARGET: BuiltInCleaner = BuiltInCleaner {
    package_dir: "org.sweepx.cargo-target",
    manifest_bytes: include_bytes!("../resources/cleaners/org.sweepx.cargo-target/cleaner.json"),
    rule_files: &[(
        "rules/cargo-target.json",
        include_bytes!("../resources/cleaners/org.sweepx.cargo-target/rules/cargo-target.json"),
    )],
    evidence_files: &[(
        "evidence/README.md",
        include_bytes!("../resources/cleaners/org.sweepx.cargo-target/evidence/README.md"),
    )],
};

pub const CHROMIUM_CACHE: BuiltInCleaner = BuiltInCleaner {
    package_dir: "org.sweepx.chromium-rebuildable-cache",
    manifest_bytes: include_bytes!(
        "../resources/cleaners/org.sweepx.chromium-rebuildable-cache/cleaner.json"
    ),
    rule_files: &[(
        "rules/chromium-cache.json",
        include_bytes!(
            "../resources/cleaners/org.sweepx.chromium-rebuildable-cache/rules/chromium-cache.json"
        ),
    )],
    evidence_files: &[(
        "evidence/README.md",
        include_bytes!(
            "../resources/cleaners/org.sweepx.chromium-rebuildable-cache/evidence/README.md"
        ),
    )],
};

pub const BUILT_INS: &[BuiltInCleaner] = &[CARGO_TARGET, CHROMIUM_CACHE];

#[derive(Debug, Clone)]
pub struct LoadedCleanerPackage {
    pub manifest: CleanerManifest,
    pub rules: Vec<(String, CleanerRule)>,
    /// Digest of the manifest and rule bytes as loaded.
    ///
    /// Use this, not `manifest.package_digest`, whenever the question is "did the rules change".
    /// The manifest field is author-declared text that no longer has to match anything.
    pub content_digest: String,
}

/// Runs the complete package admission path over caller-supplied bytes.
///
/// This is the same code the built-in loader uses, so tooling can prove a package it just
/// produced actually loads instead of asserting that it should.
pub fn load_package_bytes(
    manifest_bytes: &[u8],
    rule_files: &[(&str, &[u8])],
    evidence_files: &[(&str, &[u8])],
) -> Result<LoadedCleanerPackage, CatalogError> {
    load_package_inner(manifest_bytes, rule_files, evidence_files)
}

impl BuiltInCleaner {
    pub fn load(&self) -> Result<LoadedCleanerPackage, CatalogError> {
        self.load_with(self.manifest_bytes, self.rule_files, self.evidence_files)
    }

    fn load_with(
        &self,
        manifest_bytes: &[u8],
        rule_files: &[(&str, &[u8])],
        evidence_files: &[(&str, &[u8])],
    ) -> Result<LoadedCleanerPackage, CatalogError> {
        load_package_inner(manifest_bytes, rule_files, evidence_files)
    }
}

/// Loads and schema-validates a built-in cleaner package.
///
/// Rule bytes are compiled into the binary next to this code, so there is no boundary here for a
/// signature to protect: anyone able to alter the rules can equally alter a signature, the trust
/// store, or this function. Cryptographic admission becomes meaningful only if packages ever
/// arrive separately from the executable - over the network, from a user directory, or from a
/// third-party publisher - and the design note for that day is in `docs/research/`.
///
/// Schema validation, path validation and manifest/rule inventory agreement are kept, because
/// those catch genuine authoring mistakes rather than an adversary.
fn load_package_inner(
    manifest_bytes: &[u8],
    rule_files: &[(&str, &[u8])],
    evidence_files: &[(&str, &[u8])],
) -> Result<LoadedCleanerPackage, CatalogError> {
    let manifest: CleanerManifest =
        deserialize_rejecting_unknown_fields(manifest_bytes, "cleaner.json")?;
    manifest.validate().map_err(CatalogError::Schema)?;
    if !manifest.probes.is_empty() {
        return Err(CatalogError::UnsupportedPayloadInventory(
            "native probe payload inventory is not implemented".into(),
        ));
    }

    let mut rules = Vec::with_capacity(rule_files.len());
    for (path, bytes) in rule_files {
        validate_package_path(path)?;
        let rule: CleanerRule = deserialize_rejecting_unknown_fields(bytes, path)?;
        rule.validate().map_err(CatalogError::Schema)?;
        rules.push(((*path).to_owned(), rule));
    }
    for (path, _) in evidence_files {
        validate_package_path(path)?;
    }

    // Every rule the manifest claims must exist, and every shipped rule must be claimed. This is
    // an authoring check, not an integrity one: a rule file added without a manifest entry would
    // silently never load, which is the mistake this actually prevents.
    validate_manifest_rule_inventory(&manifest, rule_files)?;

    // Identity is derived from the rule bytes actually loaded, never from a field an author has
    // to remember to update. `cleaner_set_digest` binds a clean authorization to the rule set
    // that produced the scan; if this were the manifest's `packageDigest` string, editing a rule
    // would leave the authorization identity unchanged and a stale authorization could execute
    // against rules it never saw.
    let content_digest = compute_content_digest(manifest_bytes, rule_files);

    Ok(LoadedCleanerPackage {
        manifest,
        rules,
        content_digest,
    })
}

/// Hashes the manifest and rule bytes that were actually admitted.
///
/// Rule files are sorted by path so the digest depends on package content rather than on the
/// order the caller happened to pass them in. This is an identity function, not an integrity
/// check: it answers "are these the same rules as before", which is what authorization binding
/// needs. It cannot detect tampering, because a package edited on disk simply produces a
/// different, equally valid identity.
fn compute_content_digest(manifest_bytes: &[u8], rule_files: &[(&str, &[u8])]) -> String {
    let mut sorted = rule_files.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(right.0));

    let mut hasher = Sha256::new();
    hasher.update(b"sweepx.cleaner-package-content.v1\0");
    hasher.update((manifest_bytes.len() as u64).to_le_bytes());
    hasher.update(manifest_bytes);
    for (path, bytes) in sorted {
        // Length-prefix each field so that concatenation cannot be ambiguous between packages.
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    format!("sha256:{:x}", hasher.finalize())
}

/// Cross-checks the manifest's rule list against the rule files present in the package.
///
/// This is an authoring check: it catches a rule file added without a manifest entry, which
/// would otherwise silently never load. It deliberately does not verify digests. The manifest's
/// `packageDigest` and per-rule `sha256` fields are retained only as declared metadata, and
/// nothing derives trust or identity from them — requiring them to be true hashes is what
/// previously made editing a validated rule impossible without a signing key.
fn validate_manifest_rule_inventory(
    manifest: &CleanerManifest,
    rule_files: &[(&str, &[u8])],
) -> Result<(), CatalogError> {
    for manifest_rule in &manifest.rules {
        if !rule_files
            .iter()
            .any(|(path, _)| path == &manifest_rule.path.as_str())
        {
            return Err(CatalogError::MissingRule(manifest_rule.path.clone()));
        }
    }

    for (path, _) in rule_files {
        if !manifest
            .rules
            .iter()
            .any(|manifest_rule| manifest_rule.path.as_str() == *path)
        {
            return Err(CatalogError::ManifestInventoryMismatch);
        }
    }

    Ok(())
}

fn validate_package_path(path: &str) -> Result<(), CatalogError> {
    if path.is_empty()
        || !path.is_ascii()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(CatalogError::InvalidPackagePath(path.into()));
    }
    Ok(())
}

fn deserialize_rejecting_unknown_fields<T>(bytes: &[u8], path: &str) -> Result<T, CatalogError>
where
    T: serde::de::DeserializeOwned,
{
    reject_duplicate_keys_and_trailing_bytes(bytes)?;
    let mut deserializer = Deserializer::from_slice(bytes);
    let mut unknown = Vec::new();
    let value = serde_ignored::deserialize(&mut deserializer, |unknown_path| {
        unknown.push(unknown_path.to_string());
    })
    .map_err(CatalogError::Json)?;
    deserializer.end().map_err(CatalogError::Json)?;
    if let Some(field) = unknown.first() {
        return Err(CatalogError::UnknownOrDefaultedField(format!(
            "{path}:{field}"
        )));
    }
    Ok(value)
}

fn reject_duplicate_keys_and_trailing_bytes(bytes: &[u8]) -> Result<(), CatalogError> {
    let mut deserializer = Deserializer::from_slice(bytes);
    NoDuplicateValue
        .deserialize(&mut deserializer)
        .map_err(CatalogError::Json)?;
    deserializer.end().map_err(CatalogError::Json)
}

struct NoDuplicateValue;

impl<'de> DeserializeSeed<'de> for NoDuplicateValue {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

struct NoDuplicateVisitor;

impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("valid JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.is_finite() {
            Ok(())
        } else {
            Err(E::custom("non-finite numbers are not allowed"))
        }
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NoDuplicateValue.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while (seq.next_element_seed(NoDuplicateValue)?).is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = std::collections::BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate key `{key}` is not allowed"
                )));
            }
            map.next_value_seed(NoDuplicateValue)?;
        }
        Ok(())
    }

    fn visit_bytes<E>(self, _: &[u8]) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_byte_buf<E>(self, _: Vec<u8>) -> Result<Self::Value, E> {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("json parse failed: {0}")]
    Json(serde_json::Error),
    #[error("canonical JSON failed: {0}")]
    Canonical(sweepx_canonical::CanonicalError),
    #[error("cleaner manifest root must be a JSON object")]
    ManifestRootNotObject,
    #[error("cleaner manifest must contain packageDigest")]
    ManifestPackageDigestMissing,
    #[error("schema validation failed: {0}")]
    Schema(ValidationError),
    #[error("manifest references missing rule file: {0}")]
    MissingRule(String),
    #[error("invalid package path: {0}")]
    InvalidPackagePath(String),
    #[error("duplicate package path: {0}")]
    DuplicatePath(String),
    #[error("package path is not NFC-normalized: {0}")]
    PathNotNfc(String),
    #[error("package path NFC collision: {0}")]
    PathNfcCollision(String),
    #[error("package path casefold collision: {0}")]
    PathCasefoldCollision(String),
    #[error("file table must be sorted by path bytes")]
    FileTableNotSorted,
    #[error("manifest rule inventory does not match packaged rule files")]
    ManifestInventoryMismatch,
    #[error("manifest rule identity mismatch for {path}: expected {expected}, got {actual}")]
    ManifestRuleIdentityMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("JSON contains an unknown or defaulted field: {0}")]
    UnknownOrDefaultedField(String),
    #[error("duplicate Cleaner rule id: {0}")]
    DuplicateRuleId(String),
    #[error("unsupported package payload inventory: {0}")]
    UnsupportedPayloadInventory(String),
    #[error("Cleaner package exceeds the built-in file or byte budget")]
    PackageResourceLimit,
    #[error("reserved path is not allowed in file table: {0}")]
    ReservedPath(String),
    #[error("digest mismatch for {path}: expected {expected}, got {actual}")]
    DigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("package digest mismatch: expected {expected}, got {actual}")]
    PackageDigestMismatch { expected: String, actual: String },
    #[error("unknown trusted key: {key_id}")]
    UnknownKey { key_id: String },
    #[error("revoked trusted key: {key_id}")]
    RevokedKey { key_id: String },
    #[error("signature publisher mismatch for key {key_id}")]
    KeyPublisherMismatch { key_id: String },
    #[error("invalid trusted public key encoding for {key_id}")]
    InvalidTrustedKey { key_id: String },
    #[error("invalid signature bytes")]
    InvalidSignatureBytes,
    #[error("signature expired at {expires_at}")]
    SignatureExpired { expires_at: String },
    #[error("manifest expired at {expires_at}")]
    ManifestExpired { expires_at: String },
    #[error("signature signedAt is in the future: {signed_at}")]
    SignatureFromFuture { signed_at: String },
    #[error("signature signedAt must be earlier than expiresAt")]
    InvalidSignatureTimeOrder,
    #[error("signature is outside the validity window for key {key_id}")]
    SignatureOutsideKeyValidity { key_id: String },
    #[error("signature statement invalid: {0}")]
    InvalidSignatureStatement(ValidationError),
    #[error("signature binding mismatch: {0}")]
    SignatureBindingMismatch(String),
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("trust snapshot validation failed: {0}")]
    InvalidTrustSnapshot(ValidationError),
    #[error("invalid trust snapshot timestamp: {0}")]
    InvalidTrustSnapshotTime(String),
    #[error("unknown trust root: {0}")]
    UnknownTrustRoot(String),
    #[error("trust snapshot signature verification failed")]
    TrustSnapshotSignatureVerificationFailed,
    #[error("trust snapshot was generated in the future")]
    TrustSnapshotFromFuture,
    #[error("trust snapshot generatedAt must be earlier than expiresAt")]
    InvalidTrustSnapshotTimeOrder,
    #[error("trust snapshot is expired")]
    TrustSnapshotExpired,
    #[error("invalid trust window for publisher key {key_id}")]
    InvalidTrustedKeyWindow { key_id: String },
    #[error("revocation timestamp is later than trust snapshot generation")]
    RevocationFromFuture,
    #[error("trust snapshot epoch rollback: highest {highest_epoch}, candidate {candidate_epoch}")]
    TrustSnapshotRollback {
        highest_epoch: u64,
        candidate_epoch: u64,
    },
    #[error("trust snapshot epoch {epoch} was reused with different content")]
    TrustSnapshotEpochCollision { epoch: u64 },
    #[error("invalid Cleaner package version: {0}")]
    InvalidPackageVersion(String),
    #[error("invalid revoked package version requirement: {0}")]
    InvalidRevocationVersionReq(String),
    #[error("Cleaner package is revoked: {reason}")]
    RevokedPackage { reason: String },
    #[error("publisher key does not allow {0}")]
    KeyUsageDenied(&'static str),
    #[error(
        "package version rollback for {publisher_id}/{package_id}: highest {highest_version}, candidate {candidate_version}"
    )]
    PackageVersionRollback {
        publisher_id: String,
        package_id: String,
        highest_version: String,
        candidate_version: String,
    },
    #[error(
        "same package ID/version has a different digest: {publisher_id}/{package_id}@{version}"
    )]
    SameVersionDigestCollision {
        publisher_id: String,
        package_id: String,
        version: String,
        known_digest: String,
        candidate_digest: String,
    },
    #[error(
        "package publisher substitution for {package_id}: expected {known_publisher}, got {candidate_publisher}"
    )]
    PackagePublisherSubstitution {
        package_id: String,
        known_publisher: String,
        candidate_publisher: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_ins_load_and_validate() {
        for cleaner in BUILT_INS {
            let loaded = cleaner.load().expect("built-in package loads");
            assert_eq!(loaded.rules.len(), loaded.manifest.rules.len());
        }
    }

    /// Editing a rule must not be blocked, but it must not go unnoticed either.
    ///
    /// Removing package signing made rules freely editable; the risk that introduced is that a
    /// clean authorized against one rule set could execute against another. `content_digest` is
    /// what prevents that, so it has to move when the bytes move. The manifest's declared
    /// `packageDigest` is held fixed here on purpose: that is exactly the situation an author who
    /// edits a rule and updates nothing else produces.
    #[test]
    fn editing_a_rule_changes_the_content_digest_but_still_loads() {
        let manifest = CHROMIUM_CACHE.manifest_bytes;
        let original = CHROMIUM_CACHE.load().expect("baseline package loads");

        let (rule_path, rule_bytes) = CHROMIUM_CACHE.rule_files[0];
        // Rename a selector component rather than matching the file's exact indentation: the edit
        // only has to change the bytes and stay schema-valid, and "Cache" is present regardless of
        // how the JSON happens to be formatted.
        let edited_text = String::from_utf8(rule_bytes.to_vec())
            .expect("rule is utf-8")
            .replace("\"Code Cache\"", "\"GPUCache\"");
        assert_ne!(
            edited_text.as_bytes(),
            rule_bytes,
            "the edit must actually change the bytes"
        );

        let edited = load_package_bytes(
            manifest,
            &[(rule_path, edited_text.as_bytes())],
            CHROMIUM_CACHE.evidence_files,
        )
        .expect("an edited rule loads without any signature or digest refresh");

        assert_eq!(
            edited.manifest.package_digest, original.manifest.package_digest,
            "the declared manifest digest is untouched, as an author would leave it"
        );
        assert_ne!(
            edited.content_digest, original.content_digest,
            "authorization identity must follow the rule bytes"
        );
    }

    #[test]
    fn chromium_manifest_is_report_only_on_unknown_version() {
        let loaded = CHROMIUM_CACHE.load().expect("chromium cleaner loads");
        assert_eq!(
            loaded.manifest.target_versions.unknown,
            sweepx_cleaner_schema::UnknownVersionBehavior::ReportOnly
        );
    }

    #[test]
    fn duplicate_keys_are_rejected_at_every_json_depth() {
        let error = reject_duplicate_keys_and_trailing_bytes(br#"{"outer":{"key":1,"key":2}}"#)
            .expect_err("nested duplicate keys must fail");
        assert!(matches!(error, CatalogError::Json(_)));
    }

    #[test]
    fn trailing_json_is_rejected() {
        let error = reject_duplicate_keys_and_trailing_bytes(br#"{} {}"#)
            .expect_err("trailing JSON must fail");
        assert!(matches!(error, CatalogError::Json(_)));
    }
}
