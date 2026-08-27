use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use semver::{Version, VersionReq};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::Deserializer;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use sweepx_cleaner_schema::{
    CLEANER_MANIFEST_SCHEMA, CleanerManifest, CleanerRevocationTarget, CleanerRule,
    CleanerSignatureEnvelope, CleanerTrustSnapshot, PackageDigestEntry, TrustKeyUsage,
    TrustedPublisherKey, ValidationError, canonical_signature_payload,
    canonical_trust_snapshot_payload, compute_package_digest,
};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use unicode_normalization::UnicodeNormalization;

const MAX_BUILTIN_PACKAGE_FILES: usize = 4_096;
const MAX_BUILTIN_SINGLE_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_BUILTIN_PACKAGE_BYTES: usize = 64 * 1024 * 1024;
const TRUST_SNAPSHOT_MAX_AGE: time::Duration = time::Duration::days(7);
const TRUST_SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"SweepX cleaner trust snapshot digest v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRootAnchor {
    pub key_id: String,
    pub public_key_b64u: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltInCleaner {
    pub package_dir: &'static str,
    pub manifest_bytes: &'static [u8],
    pub signature_bytes: &'static [u8],
    pub rule_files: &'static [(&'static str, &'static [u8])],
    pub evidence_files: &'static [(&'static str, &'static [u8])],
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustFreshness {
    Current,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageTrustDisposition {
    Trusted,
    ReportOnly,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageTrustDecision {
    pub epoch: u64,
    pub snapshot_digest: String,
    pub freshness: TrustFreshness,
    pub disposition: PackageTrustDisposition,
}

#[derive(Debug, Clone)]
pub struct VerifiedTrustSnapshot {
    snapshot: CleanerTrustSnapshot,
    digest: String,
    freshness: TrustFreshness,
}

impl VerifiedTrustSnapshot {
    pub fn epoch(&self) -> u64 {
        self.snapshot.epoch
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn freshness(&self) -> TrustFreshness {
        self.freshness
    }

    fn publisher_key(&self, key_id: &str) -> Option<&TrustedPublisherKey> {
        self.snapshot.keys.iter().find(|key| key.key_id == key_id)
    }
}

pub fn verify_trust_snapshot(
    snapshot_bytes: &[u8],
    root_keys: &[TrustRootAnchor],
    now: OffsetDateTime,
    history: &mut TrustHistory,
) -> Result<VerifiedTrustSnapshot, CatalogError> {
    reject_duplicate_keys_and_trailing_bytes(snapshot_bytes)?;
    let snapshot: CleanerTrustSnapshot =
        deserialize_rejecting_unknown_fields(snapshot_bytes, "trust-snapshot.json")?;
    snapshot
        .validate()
        .map_err(CatalogError::InvalidTrustSnapshot)?;

    let generated_at = parse_trust_time(&snapshot.generated_at)?;
    let expires_at = parse_trust_time(&snapshot.expires_at)?;
    if generated_at > now {
        return Err(CatalogError::TrustSnapshotFromFuture);
    }
    if generated_at >= expires_at {
        return Err(CatalogError::InvalidTrustSnapshotTimeOrder);
    }
    if now >= expires_at {
        return Err(CatalogError::TrustSnapshotExpired);
    }
    for key in &snapshot.keys {
        let valid_from = parse_trust_time(&key.valid_from)?;
        let valid_until = parse_trust_time(&key.valid_until)?;
        if valid_from >= valid_until {
            return Err(CatalogError::InvalidTrustedKeyWindow {
                key_id: key.key_id.clone(),
            });
        }
    }
    for revocation in &snapshot.revocations {
        if parse_trust_time(&revocation.revoked_at)? > generated_at {
            return Err(CatalogError::RevocationFromFuture);
        }
    }

    let root = root_keys
        .iter()
        .find(|root| root.key_id == snapshot.root_key_id)
        .ok_or_else(|| CatalogError::UnknownTrustRoot(snapshot.root_key_id.clone()))?;
    verify_ed25519(
        &root.public_key_b64u,
        &canonical_trust_snapshot_payload(&snapshot).map_err(CatalogError::InvalidTrustSnapshot)?,
        &snapshot.signature,
    )
    .map_err(|_| CatalogError::TrustSnapshotSignatureVerificationFailed)?;

    let payload =
        canonical_trust_snapshot_payload(&snapshot).map_err(CatalogError::InvalidTrustSnapshot)?;
    let mut hasher = Sha256::new();
    hasher.update(TRUST_SNAPSHOT_DIGEST_DOMAIN);
    hasher.update(payload);
    let freshness = if now - generated_at <= TRUST_SNAPSHOT_MAX_AGE {
        TrustFreshness::Current
    } else {
        TrustFreshness::Stale
    };
    let verified = VerifiedTrustSnapshot {
        snapshot,
        digest: format!("sha256:{:x}", hasher.finalize()),
        freshness,
    };
    history.check_snapshot(&verified)?;
    history.record_snapshot(&verified);
    Ok(verified)
}

pub fn evaluate_package_trust(
    manifest: &CleanerManifest,
    signature: &CleanerSignatureEnvelope,
    file_table: &[PackageDigestEntry],
    trust: &VerifiedTrustSnapshot,
    now: OffsetDateTime,
    history: &mut TrustHistory,
) -> Result<PackageTrustDecision, CatalogError> {
    history.check_snapshot(trust)?;
    history.check_package(manifest)?;
    let trusted =
        trust
            .publisher_key(&signature.key_id)
            .ok_or_else(|| CatalogError::UnknownKey {
                key_id: signature.key_id.clone(),
            })?;
    verify_package_signature(manifest, signature, file_table, trusted, now)?;
    enforce_revocations(manifest, trusted, trust)?;

    let disposition = package_disposition(manifest, trusted, trust.freshness)?;

    history.record_snapshot(trust);
    history.record_package(manifest)?;
    Ok(PackageTrustDecision {
        epoch: trust.epoch(),
        snapshot_digest: trust.digest().to_owned(),
        freshness: trust.freshness(),
        disposition,
    })
}

fn package_disposition(
    manifest: &CleanerManifest,
    trusted: &TrustedPublisherKey,
    freshness: TrustFreshness,
) -> Result<PackageTrustDisposition, CatalogError> {
    let has_native_probe = !manifest.probes.is_empty();
    let has_official_command = !manifest.official_commands.is_empty();
    if !trusted.usages.contains(&TrustKeyUsage::DeclarativePackage) {
        return Err(CatalogError::KeyUsageDenied("declarative_package"));
    }
    if has_native_probe && !trusted.usages.contains(&TrustKeyUsage::NativeProbe) {
        return Err(CatalogError::KeyUsageDenied("native_probe"));
    }
    if has_official_command && !trusted.usages.contains(&TrustKeyUsage::OfficialCommand) {
        return Err(CatalogError::KeyUsageDenied("official_command"));
    }
    let disposition = if freshness == TrustFreshness::Current {
        PackageTrustDisposition::Trusted
    } else if has_native_probe || has_official_command {
        PackageTrustDisposition::Disabled
    } else {
        PackageTrustDisposition::ReportOnly
    };

    Ok(disposition)
}

fn enforce_revocations(
    manifest: &CleanerManifest,
    key: &TrustedPublisherKey,
    trust: &VerifiedTrustSnapshot,
) -> Result<(), CatalogError> {
    let version = Version::parse(&manifest.version)
        .map_err(|_| CatalogError::InvalidPackageVersion(manifest.version.clone()))?;
    let probe_digests = manifest
        .probes
        .iter()
        .flat_map(|probe| probe.artifacts.iter())
        .map(|artifact| format!("sha256:{}", artifact.sha256))
        .collect::<BTreeSet<_>>();
    for revocation in &trust.snapshot.revocations {
        let matches = match &revocation.target {
            CleanerRevocationTarget::PublisherKey {
                publisher_id,
                key_id,
            } => publisher_id == &key.publisher_id && key_id == &key.key_id,
            CleanerRevocationTarget::PackageDigest { package_digest } => {
                package_digest == &manifest.package_digest
            }
            CleanerRevocationTarget::PackageVersion {
                publisher_id,
                package_id,
                version_req,
            } => {
                publisher_id == &manifest.publisher.id
                    && package_id == &manifest.id
                    && VersionReq::parse(version_req)
                        .map_err(|_| {
                            CatalogError::InvalidRevocationVersionReq(version_req.clone())
                        })?
                        .matches(&version)
            }
            CleanerRevocationTarget::ProbeDigest { probe_digest } => {
                probe_digests.contains(probe_digest)
            }
        };
        if matches {
            return Err(CatalogError::RevokedPackage {
                reason: revocation.reason.clone(),
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustHistory {
    highest_epoch: Option<u64>,
    snapshot_digest: Option<String>,
    package_digests: BTreeMap<(String, semver::Version), String>,
    highest_versions: BTreeMap<String, semver::Version>,
    package_publishers: BTreeMap<String, String>,
}

impl TrustHistory {
    pub fn highest_epoch(&self) -> Option<u64> {
        self.highest_epoch
    }

    /// Applies the monotonic package identity rules to a previously authenticated package.
    /// The caller must invoke this only after package digest and signature verification.
    pub fn observe_package_identity(
        &mut self,
        publisher_id: &str,
        package_id: &str,
        package_version: &str,
        package_digest: &str,
    ) -> Result<(), CatalogError> {
        let manifest = PackageHistoryIdentity {
            publisher_id,
            package_id,
            package_version,
            package_digest,
        };
        self.check_package_identity(&manifest)?;
        self.record_package_identity(&manifest)
    }

    fn check_snapshot(&self, snapshot: &VerifiedTrustSnapshot) -> Result<(), CatalogError> {
        if let Some(highest_epoch) = self.highest_epoch {
            if snapshot.epoch() < highest_epoch {
                return Err(CatalogError::TrustSnapshotRollback {
                    highest_epoch,
                    candidate_epoch: snapshot.epoch(),
                });
            }
            if snapshot.epoch() == highest_epoch
                && self.snapshot_digest.as_deref() != Some(snapshot.digest())
            {
                return Err(CatalogError::TrustSnapshotEpochCollision {
                    epoch: snapshot.epoch(),
                });
            }
        }
        Ok(())
    }

    fn record_snapshot(&mut self, snapshot: &VerifiedTrustSnapshot) {
        if self
            .highest_epoch
            .is_none_or(|epoch| snapshot.epoch() >= epoch)
        {
            self.highest_epoch = Some(snapshot.epoch());
            self.snapshot_digest = Some(snapshot.digest().to_owned());
        }
    }

    fn check_package(&self, manifest: &CleanerManifest) -> Result<(), CatalogError> {
        self.check_package_identity(&PackageHistoryIdentity {
            publisher_id: &manifest.publisher.id,
            package_id: &manifest.id,
            package_version: &manifest.version,
            package_digest: &manifest.package_digest,
        })
    }

    fn check_package_identity(
        &self,
        identity: &PackageHistoryIdentity<'_>,
    ) -> Result<(), CatalogError> {
        if let Some(known_publisher) = self.package_publishers.get(identity.package_id)
            && known_publisher != identity.publisher_id
        {
            return Err(CatalogError::PackagePublisherSubstitution {
                package_id: identity.package_id.into(),
                known_publisher: known_publisher.clone(),
                candidate_publisher: identity.publisher_id.into(),
            });
        }
        let version = Version::parse(identity.package_version)
            .map_err(|_| CatalogError::InvalidPackageVersion(identity.package_version.into()))?;
        if let Some(highest) = self.highest_versions.get(identity.package_id)
            && &version < highest
        {
            return Err(CatalogError::PackageVersionRollback {
                publisher_id: identity.publisher_id.into(),
                package_id: identity.package_id.into(),
                highest_version: highest.to_string(),
                candidate_version: version.to_string(),
            });
        }
        let version_key = (identity.package_id.into(), version);
        if let Some(known_digest) = self.package_digests.get(&version_key)
            && known_digest != identity.package_digest
        {
            return Err(CatalogError::SameVersionDigestCollision {
                publisher_id: identity.publisher_id.into(),
                package_id: identity.package_id.into(),
                version: identity.package_version.into(),
                known_digest: known_digest.clone(),
                candidate_digest: identity.package_digest.into(),
            });
        }
        Ok(())
    }

    fn record_package(&mut self, manifest: &CleanerManifest) -> Result<(), CatalogError> {
        self.record_package_identity(&PackageHistoryIdentity {
            publisher_id: &manifest.publisher.id,
            package_id: &manifest.id,
            package_version: &manifest.version,
            package_digest: &manifest.package_digest,
        })
    }

    fn record_package_identity(
        &mut self,
        identity: &PackageHistoryIdentity<'_>,
    ) -> Result<(), CatalogError> {
        let version = Version::parse(identity.package_version)
            .map_err(|_| CatalogError::InvalidPackageVersion(identity.package_version.into()))?;
        self.highest_versions
            .entry(identity.package_id.into())
            .and_modify(|highest| {
                if version > *highest {
                    *highest = version.clone();
                }
            })
            .or_insert_with(|| version.clone());
        self.package_publishers
            .entry(identity.package_id.into())
            .or_insert_with(|| identity.publisher_id.into());
        self.package_digests.insert(
            (identity.package_id.into(), version),
            identity.package_digest.into(),
        );
        Ok(())
    }
}

struct PackageHistoryIdentity<'a> {
    publisher_id: &'a str,
    package_id: &'a str,
    package_version: &'a str,
    package_digest: &'a str,
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

fn verify_package_signature(
    manifest: &CleanerManifest,
    signature: &CleanerSignatureEnvelope,
    file_table: &[PackageDigestEntry],
    trusted: &TrustedPublisherKey,
    now: OffsetDateTime,
) -> Result<(), CatalogError> {
    if trusted.publisher_id != signature.publisher_id {
        return Err(CatalogError::KeyPublisherMismatch {
            key_id: trusted.key_id.clone(),
        });
    }
    verify_signature_bindings_and_times(
        manifest,
        signature,
        file_table,
        &trusted.key_id,
        &trusted.publisher_id,
        &trusted.public_key_b64u,
        &trusted.valid_from,
        &trusted.valid_until,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_signature_bindings_and_times(
    manifest: &CleanerManifest,
    signature: &CleanerSignatureEnvelope,
    file_table: &[PackageDigestEntry],
    key_id: &str,
    publisher_id: &str,
    public_key_b64u: &str,
    valid_from: &str,
    valid_until: &str,
    now: OffsetDateTime,
) -> Result<(), CatalogError> {
    if publisher_id != signature.publisher_id {
        return Err(CatalogError::KeyPublisherMismatch {
            key_id: key_id.to_owned(),
        });
    }
    if signature.publisher_id != manifest.publisher.id
        || signature.key_id != manifest.publisher.key_id
        || signature.package_id != manifest.id
        || signature.package_version != manifest.version
        || signature.manifest_schema != CLEANER_MANIFEST_SCHEMA
    {
        return Err(CatalogError::SignatureBindingMismatch(
            "signature does not bind the exact manifest tuple".into(),
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
    let signed_at = parse_signature_time(&signature.signed_at)?;
    let manifest_expires_at = parse_signature_time(&manifest.expires_at)?;
    if signed_at > now {
        return Err(CatalogError::SignatureFromFuture {
            signed_at: signature.signed_at.clone(),
        });
    }
    if manifest_expires_at <= now {
        return Err(CatalogError::ManifestExpired {
            expires_at: manifest.expires_at.clone(),
        });
    }
    if signed_at >= manifest_expires_at {
        return Err(CatalogError::InvalidSignatureTimeOrder);
    }
    let key_valid_from = parse_signature_time(valid_from)?;
    let key_valid_until = parse_signature_time(valid_until)?;
    if signed_at < key_valid_from || signed_at >= key_valid_until {
        return Err(CatalogError::SignatureOutsideKeyValidity {
            key_id: key_id.to_owned(),
        });
    }
    if let Some(expires_at_value) = &signature.expires_at {
        let expires_at = parse_signature_time(expires_at_value)?;
        if signed_at >= expires_at {
            return Err(CatalogError::InvalidSignatureTimeOrder);
        }
        if expires_at <= now {
            return Err(CatalogError::SignatureExpired {
                expires_at: expires_at_value.clone(),
            });
        }
    }
    let payload =
        canonical_signature_payload(signature).map_err(CatalogError::InvalidSignatureStatement)?;
    verify_ed25519(public_key_b64u, &payload, &signature.signature)
}

fn verify_ed25519(
    public_key_b64u: &str,
    payload: &[u8],
    signature: &str,
) -> Result<(), CatalogError> {
    let public_key_bytes = URL_SAFE_NO_PAD
        .decode(public_key_b64u)
        .map_err(|_| CatalogError::InvalidSignatureBytes)?;
    let public_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CatalogError::InvalidSignatureBytes)?,
    )
    .map_err(|_| CatalogError::InvalidSignatureBytes)?;
    if public_key.is_weak() {
        return Err(CatalogError::InvalidSignatureBytes);
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| CatalogError::InvalidSignatureBytes)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| CatalogError::InvalidSignatureBytes)?;
    public_key
        .verify_strict(payload, &signature)
        .map_err(|_| CatalogError::SignatureVerificationFailed)
}

fn parse_signature_time(value: &str) -> Result<OffsetDateTime, CatalogError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        CatalogError::InvalidSignatureStatement(ValidationError::UnsupportedFeature(
            "invalid RFC 3339 timestamp".into(),
        ))
    })
}

fn parse_trust_time(value: &str) -> Result<OffsetDateTime, CatalogError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| CatalogError::InvalidTrustSnapshotTime(value.to_owned()))
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
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, from_slice, to_vec};

    use super::*;
    use sweepx_cleaner_schema::CleanerRevocation;

    const TEST_ROOT_SEED: [u8; 32] = [7; 32];

    fn trust_time(value: &str) -> OffsetDateTime {
        OffsetDateTime::parse(value, &Rfc3339).unwrap()
    }

    fn signed_trust_snapshot(
        epoch: u64,
        generated_at: &str,
        expires_at: &str,
        revocations: Vec<CleanerRevocation>,
    ) -> (Vec<u8>, TrustRootAnchor) {
        let root = SigningKey::from_bytes(&TEST_ROOT_SEED);
        let package_key = BUILTIN_TRUST_STORE[0];
        let mut snapshot = CleanerTrustSnapshot {
            schema: sweepx_cleaner_schema::CLEANER_TRUST_SNAPSHOT_SCHEMA.into(),
            epoch,
            generated_at: generated_at.into(),
            expires_at: expires_at.into(),
            root_key_id: "test-root".into(),
            algorithm: sweepx_cleaner_schema::SignatureAlgorithm::Ed25519,
            keys: vec![TrustedPublisherKey {
                key_id: package_key.key_id.into(),
                publisher_id: package_key.publisher_id.into(),
                public_key_b64u: package_key.public_key_b64u.into(),
                usages: vec![TrustKeyUsage::DeclarativePackage],
                valid_from: package_key.valid_from.into(),
                valid_until: package_key.valid_until.into(),
            }],
            revocations,
            signature: URL_SAFE_NO_PAD.encode([0_u8; 64]),
        };
        let payload = canonical_trust_snapshot_payload(&snapshot).unwrap();
        snapshot.signature = URL_SAFE_NO_PAD.encode(root.sign(&payload).to_bytes());
        let anchor = TrustRootAnchor {
            key_id: "test-root".into(),
            public_key_b64u: URL_SAFE_NO_PAD.encode(root.verifying_key().as_bytes()),
        };
        (serde_json::to_vec(&snapshot).unwrap(), anchor)
    }

    #[test]
    fn trust_snapshot_signature_and_freshness_are_verified() {
        let (bytes, root) =
            signed_trust_snapshot(1, "2026-08-20T00:00:00Z", "2026-09-20T00:00:00Z", vec![]);
        let mut history = TrustHistory::default();
        let current = verify_trust_snapshot(
            &bytes,
            std::slice::from_ref(&root),
            trust_time("2026-08-27T00:00:00Z"),
            &mut history,
        )
        .unwrap();
        assert_eq!(current.freshness(), TrustFreshness::Current);
        assert_eq!(history.highest_epoch(), Some(1));

        let (stale_bytes, _) =
            signed_trust_snapshot(2, "2026-08-19T23:59:59Z", "2026-09-20T00:00:00Z", vec![]);
        let stale = verify_trust_snapshot(
            &stale_bytes,
            &[root],
            trust_time("2026-08-27T00:00:00Z"),
            &mut history,
        )
        .unwrap();
        assert_eq!(stale.freshness(), TrustFreshness::Stale);
    }

    #[test]
    fn verified_snapshot_drives_package_signature_and_stale_declarative_policy() {
        let (manifest, file_table) = built_in_manifest_and_table(&CARGO_TARGET);
        let signature: CleanerSignatureEnvelope = from_slice(CARGO_TARGET.signature_bytes).unwrap();
        let (bytes, root) =
            signed_trust_snapshot(1, "2026-08-20T00:00:00Z", "2026-09-20T00:00:00Z", vec![]);
        let mut history = TrustHistory::default();
        let trust = verify_trust_snapshot(
            &bytes,
            &[root],
            trust_time("2026-08-27T00:00:00Z"),
            &mut history,
        )
        .unwrap();
        let decision = evaluate_package_trust(
            &manifest,
            &signature,
            &file_table,
            &trust,
            trust_time("2026-08-27T00:00:00Z"),
            &mut history,
        )
        .unwrap();
        assert_eq!(decision.disposition, PackageTrustDisposition::Trusted);

        let (stale_bytes, stale_root) =
            signed_trust_snapshot(2, "2026-08-19T23:59:59Z", "2026-09-20T00:00:00Z", vec![]);
        let stale = verify_trust_snapshot(
            &stale_bytes,
            &[stale_root],
            trust_time("2026-08-27T00:00:00Z"),
            &mut history,
        )
        .unwrap();
        let decision = evaluate_package_trust(
            &manifest,
            &signature,
            &file_table,
            &stale,
            trust_time("2026-08-27T00:00:00Z"),
            &mut history,
        )
        .unwrap();
        assert_eq!(decision.disposition, PackageTrustDisposition::ReportOnly);
    }

    #[test]
    fn every_revocation_target_matches_its_exact_subject() {
        let (manifest, _) = built_in_manifest_and_table(&CARGO_TARGET);
        let key = TrustedPublisherKey {
            key_id: manifest.publisher.key_id.clone(),
            publisher_id: manifest.publisher.id.clone(),
            public_key_b64u: BUILTIN_TRUST_STORE[0].public_key_b64u.into(),
            usages: vec![TrustKeyUsage::DeclarativePackage],
            valid_from: BUILTIN_TRUST_STORE[0].valid_from.into(),
            valid_until: BUILTIN_TRUST_STORE[0].valid_until.into(),
        };
        let targets = [
            CleanerRevocationTarget::PublisherKey {
                publisher_id: manifest.publisher.id.clone(),
                key_id: manifest.publisher.key_id.clone(),
            },
            CleanerRevocationTarget::PackageDigest {
                package_digest: manifest.package_digest.clone(),
            },
            CleanerRevocationTarget::PackageVersion {
                publisher_id: manifest.publisher.id.clone(),
                package_id: manifest.id.clone(),
                version_req: format!("={}", manifest.version),
            },
        ];
        for target in targets {
            let snapshot = VerifiedTrustSnapshot {
                snapshot: CleanerTrustSnapshot {
                    schema: sweepx_cleaner_schema::CLEANER_TRUST_SNAPSHOT_SCHEMA.into(),
                    epoch: 1,
                    generated_at: "2026-08-27T00:00:00Z".into(),
                    expires_at: "2026-09-27T00:00:00Z".into(),
                    root_key_id: "root".into(),
                    algorithm: sweepx_cleaner_schema::SignatureAlgorithm::Ed25519,
                    keys: vec![key.clone()],
                    revocations: vec![CleanerRevocation {
                        revoked_at: "2026-08-27T00:00:00Z".into(),
                        reason: "test revocation".into(),
                        target,
                    }],
                    signature: URL_SAFE_NO_PAD.encode([0_u8; 64]),
                },
                digest: "sha256:test".into(),
                freshness: TrustFreshness::Current,
            };
            assert!(matches!(
                enforce_revocations(&manifest, &key, &snapshot),
                Err(CatalogError::RevokedPackage { .. })
            ));
        }

        let mut probe_manifest = manifest.clone();
        probe_manifest
            .probes
            .push(sweepx_cleaner_schema::NativeProbeDescriptor {
                schema: "sweepx.native-probe/v1".into(),
                id: "probe".into(),
                abi_version: 1,
                artifacts: vec![sweepx_cleaner_schema::ProbeArtifact {
                    os: sweepx_cleaner_schema::Os::Linux,
                    arch: sweepx_cleaner_schema::Arch::X86_64,
                    min_os: None,
                    max_tested_os: None,
                    package_relative_path: "probes/helper".into(),
                    sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .into(),
                }],
                input_schema: "in/v1".into(),
                output_schema: "out/v1".into(),
                capabilities: vec![],
                sandbox_profile: "strict".into(),
                network: sweepx_cleaner_schema::DenyPolicy::Deny,
                filesystem_read_scopes: vec![],
                cpu_millis: 1,
                rss_bytes: 1,
                handle_count: 1,
                timeout_millis: 1,
                stdout_bytes: 1,
                stderr_bytes: 1,
            });
        let snapshot = VerifiedTrustSnapshot {
            snapshot: CleanerTrustSnapshot {
                schema: sweepx_cleaner_schema::CLEANER_TRUST_SNAPSHOT_SCHEMA.into(),
                epoch: 1,
                generated_at: "2026-08-27T00:00:00Z".into(),
                expires_at: "2026-09-27T00:00:00Z".into(),
                root_key_id: "root".into(),
                algorithm: sweepx_cleaner_schema::SignatureAlgorithm::Ed25519,
                keys: vec![key.clone()],
                revocations: vec![CleanerRevocation {
                    revoked_at: "2026-08-27T00:00:00Z".into(),
                    reason: "probe revoked".into(),
                    target: CleanerRevocationTarget::ProbeDigest {
                        probe_digest:
                            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                                .into(),
                    },
                }],
                signature: URL_SAFE_NO_PAD.encode([0_u8; 64]),
            },
            digest: "sha256:test".into(),
            freshness: TrustFreshness::Current,
        };
        assert!(matches!(
            enforce_revocations(&probe_manifest, &key, &snapshot),
            Err(CatalogError::RevokedPackage { .. })
        ));
    }

    #[test]
    fn trust_snapshot_tamper_epoch_rollback_and_epoch_reuse_fail_closed() {
        let (bytes, root) =
            signed_trust_snapshot(5, "2026-08-27T00:00:00Z", "2026-09-27T00:00:00Z", vec![]);
        let mut history = TrustHistory::default();
        verify_trust_snapshot(
            &bytes,
            std::slice::from_ref(&root),
            trust_time("2026-08-27T12:00:00Z"),
            &mut history,
        )
        .unwrap();

        let (rollback, _) =
            signed_trust_snapshot(4, "2026-08-27T00:00:00Z", "2026-09-27T00:00:00Z", vec![]);
        assert!(matches!(
            verify_trust_snapshot(
                &rollback,
                std::slice::from_ref(&root),
                trust_time("2026-08-27T12:00:00Z"),
                &mut history
            ),
            Err(CatalogError::TrustSnapshotRollback { .. })
        ));

        let revocation = CleanerRevocation {
            revoked_at: "2026-08-27T00:00:00Z".into(),
            reason: "test".into(),
            target: CleanerRevocationTarget::PackageDigest {
                package_digest:
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            },
        };
        let (reused, _) = signed_trust_snapshot(
            5,
            "2026-08-27T00:00:00Z",
            "2026-09-27T00:00:00Z",
            vec![revocation],
        );
        assert!(matches!(
            verify_trust_snapshot(
                &reused,
                &[root],
                trust_time("2026-08-27T12:00:00Z"),
                &mut history
            ),
            Err(CatalogError::TrustSnapshotEpochCollision { epoch: 5 })
        ));

        let mut tampered: Value = from_slice(&bytes).unwrap();
        tampered["generatedAt"] = Value::String("2026-08-26T00:00:00Z".into());
        let mut fresh_history = TrustHistory::default();
        assert!(matches!(
            verify_trust_snapshot(
                &to_vec(&tampered).unwrap(),
                &[TrustRootAnchor {
                    key_id: "test-root".into(),
                    public_key_b64u: URL_SAFE_NO_PAD.encode(
                        SigningKey::from_bytes(&TEST_ROOT_SEED)
                            .verifying_key()
                            .as_bytes()
                    ),
                }],
                trust_time("2026-08-27T12:00:00Z"),
                &mut fresh_history
            ),
            Err(CatalogError::TrustSnapshotSignatureVerificationFailed)
        ));
    }

    #[test]
    fn package_history_rejects_same_version_substitution_and_rollback() {
        let mut history = TrustHistory::default();
        let first = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let other = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        history
            .observe_package_identity("org.sweepx", "org.sweepx.test", "2.0.0", first)
            .unwrap();
        assert!(matches!(
            history.observe_package_identity("org.sweepx", "org.sweepx.test", "2.0.0", other),
            Err(CatalogError::SameVersionDigestCollision { .. })
        ));
        assert!(matches!(
            history.observe_package_identity("org.sweepx", "org.sweepx.test", "1.9.9", first),
            Err(CatalogError::PackageVersionRollback { .. })
        ));
        assert!(matches!(
            history.observe_package_identity("other.publisher", "org.sweepx.test", "3.0.0", first),
            Err(CatalogError::PackagePublisherSubstitution { .. })
        ));
    }

    #[test]
    fn stale_policy_is_report_only_for_declarative_and_disabled_for_executable_payloads() {
        let mut manifest = built_in_manifest_and_table(&CARGO_TARGET).0;
        let key = TrustedPublisherKey {
            key_id: "key".into(),
            publisher_id: "org.sweepx".into(),
            public_key_b64u: URL_SAFE_NO_PAD.encode([9_u8; 32]),
            usages: vec![
                TrustKeyUsage::DeclarativePackage,
                TrustKeyUsage::NativeProbe,
            ],
            valid_from: "2026-01-01T00:00:00Z".into(),
            valid_until: "2027-01-01T00:00:00Z".into(),
        };
        assert_eq!(
            package_disposition(&manifest, &key, TrustFreshness::Stale).unwrap(),
            PackageTrustDisposition::ReportOnly
        );
        manifest
            .probes
            .push(sweepx_cleaner_schema::NativeProbeDescriptor {
                schema: "sweepx.native-probe/v1".into(),
                id: "probe".into(),
                abi_version: 1,
                artifacts: vec![],
                input_schema: "in/v1".into(),
                output_schema: "out/v1".into(),
                capabilities: vec![],
                sandbox_profile: "strict".into(),
                network: sweepx_cleaner_schema::DenyPolicy::Deny,
                filesystem_read_scopes: vec![],
                cpu_millis: 1,
                rss_bytes: 1,
                handle_count: 1,
                timeout_millis: 1,
                stdout_bytes: 1,
                stderr_bytes: 1,
            });
        assert_eq!(
            package_disposition(&manifest, &key, TrustFreshness::Stale).unwrap(),
            PackageTrustDisposition::Disabled
        );
    }

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
