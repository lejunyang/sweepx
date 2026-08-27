use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Deserializer;
use sha2::{Digest, Sha256};
use sweepx_cleaner_schema::{
    CLEANER_MANIFEST_SCHEMA, CleanerManifest, CleanerRule, CleanerSignatureEnvelope,
    PackageDigestEntry, ValidationError, canonical_signature_payload, compute_package_digest,
};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use unicode_normalization::UnicodeNormalization;

const MAX_BUILTIN_PACKAGE_FILES: usize = 4_096;
const MAX_BUILTIN_SINGLE_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_BUILTIN_PACKAGE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltInCleaner {
    pub package_dir: &'static str,
    pub manifest_bytes: &'static [u8],
    pub signature_bytes: &'static [u8],
    pub rule_files: &'static [(&'static str, &'static [u8])],
    pub evidence_files: &'static [(&'static str, &'static [u8])],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustedKey {
    key_id: &'static str,
    publisher_id: &'static str,
    public_key_b64u: &'static str,
    valid_from: &'static str,
    valid_until: &'static str,
    revoked: bool,
}

const BUILTIN_TRUST_STORE: &[TrustedKey] = &[TrustedKey {
    key_id: "builtin-cleaner-key-2026",
    publisher_id: "org.sweepx",
    public_key_b64u: "bqB4tpOIibLAwawWg455kwXbfGIsbgj7X6gotTL1S_w",
    valid_from: "2026-08-27T00:00:00Z",
    valid_until: "2027-08-27T00:00:00Z",
    revoked: false,
}];

pub const CARGO_TARGET: BuiltInCleaner = BuiltInCleaner {
    package_dir: "org.sweepx.cargo-target",
    manifest_bytes: include_bytes!("../resources/cleaners/org.sweepx.cargo-target/cleaner.json"),
    signature_bytes: include_bytes!("../resources/cleaners/org.sweepx.cargo-target/SIGNATURE"),
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
    signature_bytes: include_bytes!(
        "../resources/cleaners/org.sweepx.chromium-rebuildable-cache/SIGNATURE"
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
    pub signature: CleanerSignatureEnvelope,
    pub rules: Vec<(String, CleanerRule)>,
}

impl BuiltInCleaner {
    pub fn load(&self) -> Result<LoadedCleanerPackage, CatalogError> {
        self.load_with(
            self.manifest_bytes,
            self.signature_bytes,
            self.rule_files,
            self.evidence_files,
        )
    }

    fn load_with(
        &self,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
        rule_files: &[(&str, &[u8])],
        evidence_files: &[(&str, &[u8])],
    ) -> Result<LoadedCleanerPackage, CatalogError> {
        let manifest_value = parse_strict_json_value(manifest_bytes)?;
        let manifest: CleanerManifest =
            deserialize_rejecting_unknown_fields(manifest_bytes, "cleaner.json")?;
        manifest.validate().map_err(CatalogError::Schema)?;
        if !manifest.probes.is_empty() {
            return Err(CatalogError::UnsupportedPayloadInventory(
                "native probe payload inventory is not implemented".into(),
            ));
        }

        let signature: CleanerSignatureEnvelope =
            deserialize_rejecting_unknown_fields(signature_bytes, "SIGNATURE")?;
        signature
            .validate()
            .map_err(CatalogError::InvalidSignatureStatement)?;

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

        let file_table = build_file_table(&manifest_value, rule_files, evidence_files)?;
        validate_manifest_inventory(&manifest, &file_table, &rules)?;

        for manifest_rule in &manifest.rules {
            let Some((_, bytes)) = rule_files
                .iter()
                .find(|(path, _)| path == &manifest_rule.path.as_str())
            else {
                return Err(CatalogError::MissingRule(manifest_rule.path.clone()));
            };

            let actual = sha256_hex(bytes);
            if actual != manifest_rule.sha256 {
                return Err(CatalogError::DigestMismatch {
                    path: manifest_rule.path.clone(),
                    expected: manifest_rule.sha256.clone(),
                    actual,
                });
            }
        }

        let actual_package_digest =
            compute_package_digest(&file_table).map_err(CatalogError::Schema)?;
        if actual_package_digest != manifest.package_digest {
            return Err(CatalogError::PackageDigestMismatch {
                expected: manifest.package_digest.clone(),
                actual: actual_package_digest,
            });
        }

        verify_signature(&manifest, &signature, &file_table)?;

        Ok(LoadedCleanerPackage {
            manifest,
            signature,
            rules,
        })
    }
}

fn verify_signature_with_store(
    manifest: &CleanerManifest,
    signature: &CleanerSignatureEnvelope,
    file_table: &[PackageDigestEntry],
    trust_store: &[TrustedKey],
    now: OffsetDateTime,
) -> Result<(), CatalogError> {
    let trusted = trust_store
        .iter()
        .find(|entry| entry.key_id == signature.key_id)
        .ok_or_else(|| CatalogError::UnknownKey {
            key_id: signature.key_id.clone(),
        })?;

    if trusted.revoked {
        return Err(CatalogError::RevokedKey {
            key_id: trusted.key_id.to_owned(),
        });
    }
    if trusted.publisher_id != signature.publisher_id {
        return Err(CatalogError::KeyPublisherMismatch {
            key_id: trusted.key_id.to_owned(),
        });
    }
    if signature.publisher_id != manifest.publisher.id {
        return Err(CatalogError::SignatureBindingMismatch(
            "publisherId does not match manifest.publisher.id".into(),
        ));
    }
    if signature.key_id != manifest.publisher.key_id {
        return Err(CatalogError::SignatureBindingMismatch(
            "keyId does not match manifest.publisher.keyId".into(),
        ));
    }
    if signature.package_id != manifest.id {
        return Err(CatalogError::SignatureBindingMismatch(
            "packageId does not match manifest.id".into(),
        ));
    }
    if signature.package_version != manifest.version {
        return Err(CatalogError::SignatureBindingMismatch(
            "packageVersion does not match manifest.version".into(),
        ));
    }
    if signature.manifest_schema != CLEANER_MANIFEST_SCHEMA {
        return Err(CatalogError::SignatureBindingMismatch(
            "manifestSchema does not match cleaner manifest schema".into(),
        ));
    }
    let actual_package_digest =
        compute_package_digest(file_table).map_err(CatalogError::InvalidSignatureStatement)?;
    if signature.package_digest != actual_package_digest
        || manifest.package_digest != actual_package_digest
    {
        return Err(CatalogError::PackageDigestMismatch {
            expected: manifest.package_digest.clone(),
            actual: actual_package_digest,
        });
    }

    let signed_at = OffsetDateTime::parse(&signature.signed_at, &Rfc3339).map_err(|_| {
        CatalogError::InvalidSignatureStatement(ValidationError::UnsupportedFeature(
            "invalid signature signedAt".into(),
        ))
    })?;
    if signed_at > now {
        return Err(CatalogError::SignatureFromFuture {
            signed_at: signature.signed_at.clone(),
        });
    }
    let manifest_expires_at =
        OffsetDateTime::parse(&manifest.expires_at, &Rfc3339).map_err(|_| {
            CatalogError::InvalidSignatureStatement(ValidationError::UnsupportedFeature(
                "invalid manifest expiresAt".into(),
            ))
        })?;
    if manifest_expires_at <= now {
        return Err(CatalogError::ManifestExpired {
            expires_at: manifest.expires_at.clone(),
        });
    }
    if signed_at >= manifest_expires_at {
        return Err(CatalogError::InvalidSignatureTimeOrder);
    }
    let key_valid_from = OffsetDateTime::parse(trusted.valid_from, &Rfc3339).map_err(|_| {
        CatalogError::InvalidTrustedKey {
            key_id: trusted.key_id.to_owned(),
        }
    })?;
    let key_valid_until = OffsetDateTime::parse(trusted.valid_until, &Rfc3339).map_err(|_| {
        CatalogError::InvalidTrustedKey {
            key_id: trusted.key_id.to_owned(),
        }
    })?;
    if signed_at < key_valid_from || signed_at >= key_valid_until {
        return Err(CatalogError::SignatureOutsideKeyValidity {
            key_id: trusted.key_id.to_owned(),
        });
    }

    if let Some(expires_at_value) = &signature.expires_at {
        let expires_at = OffsetDateTime::parse(expires_at_value, &Rfc3339).map_err(|_| {
            CatalogError::InvalidSignatureStatement(ValidationError::UnsupportedFeature(
                "invalid signature expiresAt".into(),
            ))
        })?;
        if signed_at >= expires_at {
            return Err(CatalogError::InvalidSignatureTimeOrder);
        }
        if expires_at <= now {
            return Err(CatalogError::SignatureExpired {
                expires_at: expires_at_value.clone(),
            });
        }
    }

    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(trusted.public_key_b64u)
        .map_err(|_| CatalogError::InvalidTrustedKey {
            key_id: trusted.key_id.to_owned(),
        })?;
    let public_key =
        VerifyingKey::from_bytes(public_key_bytes.as_slice().try_into().map_err(|_| {
            CatalogError::InvalidTrustedKey {
                key_id: trusted.key_id.to_owned(),
            }
        })?)
        .map_err(|_| CatalogError::InvalidTrustedKey {
            key_id: trusted.key_id.to_owned(),
        })?;
    if public_key.is_weak() {
        return Err(CatalogError::InvalidTrustedKey {
            key_id: trusted.key_id.to_owned(),
        });
    }

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&signature.signature)
        .map_err(|_| CatalogError::InvalidSignatureBytes)?;
    let ed25519_signature =
        Signature::from_slice(&signature_bytes).map_err(|_| CatalogError::InvalidSignatureBytes)?;
    let payload =
        canonical_signature_payload(signature).map_err(CatalogError::InvalidSignatureStatement)?;
    public_key
        .verify_strict(&payload, &ed25519_signature)
        .map_err(|_| CatalogError::SignatureVerificationFailed)
}

fn build_file_table(
    manifest_value: &serde_json::Value,
    rule_files: &[(&str, &[u8])],
    evidence_files: &[(&str, &[u8])],
) -> Result<Vec<PackageDigestEntry>, CatalogError> {
    let payload_file_count = 1usize
        .checked_add(rule_files.len())
        .and_then(|count| count.checked_add(evidence_files.len()))
        .ok_or(CatalogError::PackageResourceLimit)?;
    if payload_file_count > MAX_BUILTIN_PACKAGE_FILES {
        return Err(CatalogError::PackageResourceLimit);
    }
    let manifest_without_digest = canonical_manifest_without_digest(manifest_value)?;
    let mut total_bytes = manifest_without_digest.len();
    if total_bytes > MAX_BUILTIN_SINGLE_FILE_BYTES {
        return Err(CatalogError::PackageResourceLimit);
    }
    let mut entries = Vec::with_capacity(rule_files.len() + evidence_files.len() + 1);
    entries.push(PackageDigestEntry {
        path: "cleaner.json".to_owned(),
        bytes: manifest_without_digest.len().to_string(),
        sha256: sha256_hex(&manifest_without_digest),
    });
    for (path, bytes) in rule_files {
        if bytes.len() > MAX_BUILTIN_SINGLE_FILE_BYTES {
            return Err(CatalogError::PackageResourceLimit);
        }
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or(CatalogError::PackageResourceLimit)?;
        entries.push(PackageDigestEntry {
            path: (*path).to_owned(),
            bytes: bytes.len().to_string(),
            sha256: sha256_hex(bytes),
        });
    }
    for (path, bytes) in evidence_files {
        if bytes.len() > MAX_BUILTIN_SINGLE_FILE_BYTES {
            return Err(CatalogError::PackageResourceLimit);
        }
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or(CatalogError::PackageResourceLimit)?;
        entries.push(PackageDigestEntry {
            path: (*path).to_owned(),
            bytes: bytes.len().to_string(),
            sha256: sha256_hex(bytes),
        });
    }
    if total_bytes > MAX_BUILTIN_PACKAGE_BYTES {
        return Err(CatalogError::PackageResourceLimit);
    }
    entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    validate_file_table(&entries)?;
    Ok(entries)
}

fn validate_file_table(entries: &[PackageDigestEntry]) -> Result<(), CatalogError> {
    let mut seen_exact = std::collections::BTreeSet::new();
    let mut seen_nfc = std::collections::BTreeSet::new();
    let mut seen_casefold = std::collections::BTreeSet::new();
    let mut previous_path: Option<&str> = None;
    for entry in entries {
        validate_package_path(&entry.path)?;
        sweepx_cleaner_schema::validate_decimal_string(&entry.bytes, "fileTable[].bytes")
            .map_err(CatalogError::Schema)?;
        if entry.path == "SIGNATURE" {
            return Err(CatalogError::ReservedPath("SIGNATURE".into()));
        }
        if !seen_exact.insert(entry.path.clone()) {
            return Err(CatalogError::DuplicatePath(entry.path.clone()));
        }
        let nfc = entry.path.nfc().collect::<String>();
        if nfc != entry.path {
            return Err(CatalogError::PathNotNfc(entry.path.clone()));
        }
        if !seen_nfc.insert(nfc.clone()) {
            return Err(CatalogError::PathNfcCollision(entry.path.clone()));
        }
        // Built-in v1 package paths are ASCII-only, so this exactly covers the admitted
        // Windows case-insensitive namespace. Widening to Unicode requires a versioned Windows
        // upcase-table implementation in the future archive loader.
        let casefold = nfc.to_ascii_uppercase();
        if !seen_casefold.insert(casefold) {
            return Err(CatalogError::PathCasefoldCollision(entry.path.clone()));
        }
        if let Some(previous) = previous_path {
            let out_of_order = previous.as_bytes() >= entry.path.as_bytes();
            if out_of_order {
                return Err(CatalogError::FileTableNotSorted);
            }
        }
        previous_path = Some(&entry.path);
    }
    Ok(())
}

fn validate_manifest_inventory(
    manifest: &CleanerManifest,
    file_table: &[PackageDigestEntry],
    loaded_rules: &[(String, CleanerRule)],
) -> Result<(), CatalogError> {
    let manifest_rule_paths = manifest
        .rules
        .iter()
        .map(|rule| rule.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let rule_paths = file_table
        .iter()
        .filter_map(|entry| {
            entry
                .path
                .strip_prefix("rules/")
                .map(|_| entry.path.as_str())
        })
        .collect::<std::collections::BTreeSet<_>>();
    if manifest_rule_paths != rule_paths {
        return Err(CatalogError::ManifestInventoryMismatch);
    }
    for manifest_rule in &manifest.rules {
        let loaded = loaded_rules
            .iter()
            .find(|(path, _)| path == &manifest_rule.path)
            .ok_or(CatalogError::ManifestInventoryMismatch)?;
        if loaded.1.id != manifest_rule.id {
            return Err(CatalogError::ManifestRuleIdentityMismatch {
                path: manifest_rule.path.clone(),
                expected: manifest_rule.id.clone(),
                actual: loaded.1.id.clone(),
            });
        }
    }
    let mut manifest_ids = std::collections::BTreeSet::new();
    for rule in &manifest.rules {
        if !manifest_ids.insert(rule.id.as_str()) {
            return Err(CatalogError::DuplicateRuleId(rule.id.clone()));
        }
    }
    let mut loaded_ids = std::collections::BTreeSet::new();
    for (_, rule) in loaded_rules {
        if !loaded_ids.insert(rule.id.as_str()) {
            return Err(CatalogError::DuplicateRuleId(rule.id.clone()));
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

fn canonical_manifest_without_digest(
    manifest_value: &serde_json::Value,
) -> Result<Vec<u8>, CatalogError> {
    let mut object = manifest_value
        .as_object()
        .cloned()
        .ok_or(CatalogError::ManifestRootNotObject)?;
    if object.remove("packageDigest").is_none() {
        return Err(CatalogError::ManifestPackageDigestMissing);
    }
    sweepx_canonical::canonicalize_value(&serde_json::Value::Object(object))
        .map_err(CatalogError::Canonical)
}

fn parse_strict_json_value(bytes: &[u8]) -> Result<serde_json::Value, CatalogError> {
    reject_duplicate_keys_and_trailing_bytes(bytes)?;
    serde_json::from_slice(bytes).map_err(CatalogError::Json)
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

#[cfg(test)]
fn built_in_manifest_and_table(
    cleaner: &BuiltInCleaner,
) -> (CleanerManifest, Vec<PackageDigestEntry>) {
    let value = parse_strict_json_value(cleaner.manifest_bytes).expect("manifest value");
    let manifest: CleanerManifest =
        deserialize_rejecting_unknown_fields(cleaner.manifest_bytes, "cleaner.json")
            .expect("manifest model");
    let table =
        build_file_table(&value, cleaner.rule_files, cleaner.evidence_files).expect("file table");
    (manifest, table)
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

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
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
}

fn verify_signature(
    manifest: &CleanerManifest,
    signature: &CleanerSignatureEnvelope,
    file_table: &[PackageDigestEntry],
) -> Result<(), CatalogError> {
    verify_signature_with_store(
        manifest,
        signature,
        file_table,
        BUILTIN_TRUST_STORE,
        OffsetDateTime::now_utc(),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, from_slice, to_vec};

    use super::*;

    #[test]
    fn built_ins_load_and_validate() {
        for cleaner in BUILT_INS {
            let loaded = cleaner.load().expect("built-in package loads");
            assert_eq!(loaded.rules.len(), loaded.manifest.rules.len());
        }
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
    fn tampered_rule_fails_load() {
        let mut bytes = CARGO_TARGET.rule_files[0].1.to_vec();
        bytes[10] ^= 1;
        let err = CARGO_TARGET
            .load_with(
                CARGO_TARGET.manifest_bytes,
                CARGO_TARGET.signature_bytes,
                &[("rules/cargo-target.json", &bytes)],
                CARGO_TARGET.evidence_files,
            )
            .expect_err("tampered rule must fail");
        assert!(matches!(
            err,
            CatalogError::DigestMismatch { .. } | CatalogError::Json(_)
        ));
    }

    #[test]
    fn tampered_evidence_fails_load() {
        let mut evidence = CARGO_TARGET.evidence_files[0].1.to_vec();
        evidence.extend_from_slice(b"\nTAMPER\n");
        let err = CARGO_TARGET
            .load_with(
                CARGO_TARGET.manifest_bytes,
                CARGO_TARGET.signature_bytes,
                CARGO_TARGET.rule_files,
                &[("evidence/README.md", &evidence)],
            )
            .expect_err("tampered evidence must fail");
        assert!(matches!(err, CatalogError::PackageDigestMismatch { .. }));
    }

    #[test]
    fn tampered_manifest_fails_load() {
        let mut manifest: Value = from_slice(CARGO_TARGET.manifest_bytes).expect("manifest json");
        manifest["description"] = Value::String("tampered".into());
        let manifest_bytes = to_vec(&manifest).expect("serialize manifest");
        let err = CARGO_TARGET
            .load_with(
                &manifest_bytes,
                CARGO_TARGET.signature_bytes,
                CARGO_TARGET.rule_files,
                CARGO_TARGET.evidence_files,
            )
            .expect_err("tampered manifest must fail");
        assert!(matches!(err, CatalogError::PackageDigestMismatch { .. }));
    }

    #[test]
    fn unknown_key_fails_closed() {
        let (manifest, file_table) = built_in_manifest_and_table(&CARGO_TARGET);
        let mut signature: CleanerSignatureEnvelope =
            from_slice(CARGO_TARGET.signature_bytes).expect("signature json");
        signature.key_id = "unknown-key".into();

        let err = verify_signature_with_store(
            &manifest,
            &signature,
            &file_table,
            BUILTIN_TRUST_STORE,
            OffsetDateTime::parse("2026-08-27T12:00:00Z", &Rfc3339).expect("time"),
        )
        .expect_err("unknown key must fail");
        assert!(matches!(err, CatalogError::UnknownKey { .. }));
    }

    #[test]
    fn expired_signature_fails_closed() {
        let (manifest, file_table) = built_in_manifest_and_table(&CARGO_TARGET);
        let signature: CleanerSignatureEnvelope =
            from_slice(CARGO_TARGET.signature_bytes).expect("signature json");

        let err = verify_signature_with_store(
            &manifest,
            &signature,
            &file_table,
            BUILTIN_TRUST_STORE,
            OffsetDateTime::parse("2028-08-27T12:00:00Z", &Rfc3339).expect("time"),
        )
        .expect_err("expired manifest/signature must fail");
        assert!(matches!(
            err,
            CatalogError::ManifestExpired { .. } | CatalogError::SignatureExpired { .. }
        ));
    }

    #[test]
    fn revoked_key_fails_closed() {
        let (manifest, file_table) = built_in_manifest_and_table(&CARGO_TARGET);
        let signature: CleanerSignatureEnvelope =
            from_slice(CARGO_TARGET.signature_bytes).expect("signature json");
        let revoked_store = [TrustedKey {
            key_id: "builtin-cleaner-key-2026",
            publisher_id: "org.sweepx",
            public_key_b64u: "bqB4tpOIibLAwawWg455kwXbfGIsbgj7X6gotTL1S_w",
            valid_from: "2026-08-27T00:00:00Z",
            valid_until: "2027-08-27T00:00:00Z",
            revoked: true,
        }];
        let err = verify_signature_with_store(
            &manifest,
            &signature,
            &file_table,
            &revoked_store,
            OffsetDateTime::parse("2026-08-27T12:00:00Z", &Rfc3339).expect("time"),
        )
        .expect_err("revoked key must fail");
        assert!(matches!(err, CatalogError::RevokedKey { .. }));
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

    #[test]
    fn unknown_manifest_fields_are_rejected() {
        let mut manifest: Value = from_slice(CARGO_TARGET.manifest_bytes).unwrap();
        manifest["unexpectedField"] = Value::Bool(true);
        let manifest_bytes = to_vec(&manifest).unwrap();
        assert!(matches!(
            CARGO_TARGET.load_with(
                &manifest_bytes,
                CARGO_TARGET.signature_bytes,
                CARGO_TARGET.rule_files,
                CARGO_TARGET.evidence_files
            ),
            Err(CatalogError::UnknownOrDefaultedField(path))
                if path.starts_with("cleaner.json:")
        ));
    }

    #[test]
    fn unknown_nested_rule_and_signature_fields_are_rejected() {
        let mut rule: Value = from_slice(CARGO_TARGET.rule_files[0].1).unwrap();
        rule["analysis"]["unexpectedField"] = Value::Bool(true);
        let rule_bytes = to_vec(&rule).unwrap();
        assert!(matches!(
            CARGO_TARGET.load_with(
                CARGO_TARGET.manifest_bytes,
                CARGO_TARGET.signature_bytes,
                &[("rules/cargo-target.json", &rule_bytes)],
                CARGO_TARGET.evidence_files
            ),
            Err(CatalogError::UnknownOrDefaultedField(path))
                if path.starts_with("rules/cargo-target.json:")
        ));

        let mut signature: Value = from_slice(CARGO_TARGET.signature_bytes).unwrap();
        signature["unexpectedField"] = Value::Bool(true);
        let signature_bytes = to_vec(&signature).unwrap();
        assert!(matches!(
            CARGO_TARGET.load_with(
                CARGO_TARGET.manifest_bytes,
                &signature_bytes,
                CARGO_TARGET.rule_files,
                CARGO_TARGET.evidence_files
            ),
            Err(CatalogError::Json(_)) | Err(CatalogError::UnknownOrDefaultedField(_))
        ));
    }

    #[test]
    fn file_table_includes_canonical_manifest_and_excludes_signature() {
        let (manifest, table) = built_in_manifest_and_table(&CARGO_TARGET);

        assert_eq!(table.first().unwrap().path, "cleaner.json");
        assert!(table.iter().all(|entry| entry.path != "SIGNATURE"));
        assert_eq!(
            table
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            [
                "cleaner.json",
                "evidence/README.md",
                "rules/cargo-target.json"
            ]
        );
        assert_eq!(
            compute_package_digest(&table).unwrap(),
            manifest.package_digest
        );
    }

    #[test]
    fn signature_time_rules_fail_closed_before_crypto() {
        let (manifest, file_table) = built_in_manifest_and_table(&CARGO_TARGET);
        let signature: CleanerSignatureEnvelope =
            from_slice(CARGO_TARGET.signature_bytes).expect("signature json");

        let future_now = OffsetDateTime::parse("2026-08-26T00:00:00Z", &Rfc3339).expect("time");
        assert!(matches!(
            verify_signature_with_store(
                &manifest,
                &signature,
                &file_table,
                BUILTIN_TRUST_STORE,
                future_now
            ),
            Err(CatalogError::SignatureFromFuture { .. })
        ));

        let mut invalid_order = signature;
        invalid_order.expires_at = Some(invalid_order.signed_at.clone());
        let now = OffsetDateTime::parse("2026-08-27T00:00:00Z", &Rfc3339).expect("time");
        assert!(matches!(
            verify_signature_with_store(
                &manifest,
                &invalid_order,
                &file_table,
                BUILTIN_TRUST_STORE,
                now
            ),
            Err(CatalogError::InvalidSignatureTimeOrder)
        ));
    }
}
