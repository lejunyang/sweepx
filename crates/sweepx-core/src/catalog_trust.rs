use semver::{Version, VersionReq};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sweepx_canonical::canonicalize_value;
use sweepx_catalog::{
    BUILT_INS, CatalogError, PackageTrustDisposition, TrustFreshness, TrustHistory,
    TrustRootAnchor, evaluate_package_trust, verify_trust_snapshot,
};
use sweepx_cleaner_schema::{PackageDigestEntry, compute_package_digest};
use time::OffsetDateTime;

use crate::{CORE_VERSION, CoreError};

/// Hard input limits for the in-memory production trust boundary.
///
/// Snapshot schema validation is intentionally not treated as a resource bound: an oversized
/// document or anchor set is rejected before JSON parsing or signature verification.
pub const MAX_PRODUCTION_TRUST_SNAPSHOT_BYTES: usize = 1024 * 1024;
pub const MAX_PRODUCTION_TRUST_ROOT_ANCHORS: usize = 32;

const MAX_TRUST_ROOT_KEY_ID_BYTES: usize = 256;
const MAX_TRUST_ROOT_PUBLIC_KEY_BYTES: usize = 128;
const CLEANER_SET_DIGEST_DOMAIN: &[u8] = b"sweepx.cleaner-set-digest.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionTrustFreshness {
    Current,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionTrustDisposition {
    Trusted,
    ReportOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionCatalogDisposition {
    Trusted,
    ReportOnly,
    Disabled,
}

/// A fully verified, read-only view of the release catalog under production trust metadata.
///
/// `trust_disposition` describes only the authenticated snapshot: current is trusted and stale is
/// report-only. `catalog_disposition` also accounts for every shipped package and current Core
/// compatibility, so a current/trusted snapshot can still yield a report-only catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductionCleanerCatalogTrust {
    pub snapshot_digest: String,
    pub epoch: u64,
    pub freshness: ProductionTrustFreshness,
    pub trust_disposition: ProductionTrustDisposition,
    pub catalog_disposition: ProductionCatalogDisposition,
    pub cleaner_set_digest: String,
}

/// Verifies a signed trust snapshot and applies it to every Cleaner shipped in this release.
///
/// This function performs no I/O and does not change the default built-in catalog resolver. The
/// supplied history is updated only after the snapshot and every shipped package pass all checks.
/// Invalid, expired, tampered, unknown-root, revoked, rollback, and same-epoch-collision inputs
/// return an error and cannot yield a usable catalog. Stale trust is accepted only as report-only.
pub fn resolve_production_catalog_trust(
    snapshot_bytes: &[u8],
    root_anchors: &[TrustRootAnchor],
    now: OffsetDateTime,
    history: &mut TrustHistory,
) -> Result<ProductionCleanerCatalogTrust, CoreError> {
    validate_input_bounds(snapshot_bytes, root_anchors)?;

    // Catalog verification records observations as it succeeds. Work on a clone so a later
    // revoked or otherwise invalid package cannot partially advance caller-owned history.
    let mut candidate_history = history.clone();
    let snapshot = verify_trust_snapshot(snapshot_bytes, root_anchors, now, &mut candidate_history)
        .map_err(CoreError::ProductionCatalogTrust)?;

    let mut cleaner_records = Vec::with_capacity(BUILT_INS.len());
    let mut catalog_disposition = ProductionCatalogDisposition::Trusted;
    let current_core = Version::parse(CORE_VERSION).map_err(|_| {
        CoreError::CleanerCatalogTrust(format!("invalid core version: {CORE_VERSION}"))
    })?;

    for cleaner in BUILT_INS {
        let package = cleaner.load().map_err(CoreError::ProductionCatalogTrust)?;
        let file_table = built_in_file_table(cleaner, &package.manifest)?;
        let decision = evaluate_package_trust(
            &package.manifest,
            &package.signature,
            &file_table,
            &snapshot,
            now,
            &mut candidate_history,
        )
        .map_err(CoreError::ProductionCatalogTrust)?;
        let required_core = VersionReq::parse(&package.manifest.requires.core).map_err(|_| {
            CoreError::CleanerCompat {
                cleaner_ref: package.manifest.id.clone(),
                required_core: package.manifest.requires.core.clone(),
                current_core: CORE_VERSION.to_string(),
            }
        })?;
        let compatible = required_core.matches(&current_core);
        let package_disposition = match decision.disposition {
            PackageTrustDisposition::Disabled => ProductionCatalogDisposition::Disabled,
            PackageTrustDisposition::ReportOnly => ProductionCatalogDisposition::ReportOnly,
            PackageTrustDisposition::Trusted if compatible => ProductionCatalogDisposition::Trusted,
            PackageTrustDisposition::Trusted => ProductionCatalogDisposition::ReportOnly,
        };
        catalog_disposition = stricter_disposition(catalog_disposition, package_disposition);
        cleaner_records.push(json!({
            "id": package.manifest.id,
            "version": package.manifest.version,
            "packageDigest": package.manifest.package_digest,
        }));
    }

    let freshness = match snapshot.freshness() {
        TrustFreshness::Current => ProductionTrustFreshness::Current,
        TrustFreshness::Stale => ProductionTrustFreshness::Stale,
    };
    let trust_disposition = match freshness {
        ProductionTrustFreshness::Current => ProductionTrustDisposition::Trusted,
        ProductionTrustFreshness::Stale => ProductionTrustDisposition::ReportOnly,
    };
    let result = ProductionCleanerCatalogTrust {
        snapshot_digest: snapshot.digest().to_owned(),
        epoch: snapshot.epoch(),
        freshness,
        trust_disposition,
        catalog_disposition,
        cleaner_set_digest: cleaner_set_digest(
            cleaner_records,
            snapshot.epoch(),
            snapshot.digest(),
            freshness,
            trust_disposition,
        )?,
    };
    *history = candidate_history;
    Ok(result)
}

fn stricter_disposition(
    left: ProductionCatalogDisposition,
    right: ProductionCatalogDisposition,
) -> ProductionCatalogDisposition {
    use ProductionCatalogDisposition::{Disabled, ReportOnly, Trusted};
    match (left, right) {
        (Disabled, _) | (_, Disabled) => Disabled,
        (ReportOnly, _) | (_, ReportOnly) => ReportOnly,
        (Trusted, Trusted) => Trusted,
    }
}

fn validate_input_bounds(
    snapshot_bytes: &[u8],
    root_anchors: &[TrustRootAnchor],
) -> Result<(), CoreError> {
    if snapshot_bytes.len() > MAX_PRODUCTION_TRUST_SNAPSHOT_BYTES {
        return Err(CoreError::CleanerCatalogTrust(format!(
            "production trust snapshot exceeds byte limit: limit={}, observed={}",
            MAX_PRODUCTION_TRUST_SNAPSHOT_BYTES,
            snapshot_bytes.len()
        )));
    }
    if root_anchors.is_empty() {
        return Err(CoreError::CleanerCatalogTrust(
            "production trust requires at least one root anchor".to_string(),
        ));
    }
    if root_anchors.len() > MAX_PRODUCTION_TRUST_ROOT_ANCHORS {
        return Err(CoreError::CleanerCatalogTrust(format!(
            "production trust root anchor count exceeds limit: limit={}, observed={}",
            MAX_PRODUCTION_TRUST_ROOT_ANCHORS,
            root_anchors.len()
        )));
    }

    let mut key_ids = std::collections::BTreeSet::new();
    for anchor in root_anchors {
        if anchor.key_id.is_empty()
            || anchor.key_id.len() > MAX_TRUST_ROOT_KEY_ID_BYTES
            || anchor.public_key_b64u.is_empty()
            || anchor.public_key_b64u.len() > MAX_TRUST_ROOT_PUBLIC_KEY_BYTES
        {
            return Err(CoreError::CleanerCatalogTrust(
                "production trust root anchor exceeds field bounds".to_string(),
            ));
        }
        if !key_ids.insert(anchor.key_id.as_str()) {
            return Err(CoreError::CleanerCatalogTrust(format!(
                "duplicate production trust root anchor: {}",
                anchor.key_id
            )));
        }
    }
    Ok(())
}

fn built_in_file_table(
    cleaner: &sweepx_catalog::BuiltInCleaner,
    manifest: &sweepx_cleaner_schema::CleanerManifest,
) -> Result<Vec<PackageDigestEntry>, CoreError> {
    let manifest_bytes = manifest
        .canonical_without_package_digest()
        .map_err(CatalogError::Schema)
        .map_err(CoreError::ProductionCatalogTrust)?;
    let mut entries = Vec::with_capacity(
        1usize
            .checked_add(cleaner.rule_files.len())
            .and_then(|count| count.checked_add(cleaner.evidence_files.len()))
            .ok_or_else(|| {
                CoreError::CleanerCatalogTrust(
                    "built-in cleaner file table length overflow".to_string(),
                )
            })?,
    );
    entries.push(digest_entry("cleaner.json", &manifest_bytes));
    entries.extend(
        cleaner
            .rule_files
            .iter()
            .map(|(path, bytes)| digest_entry(path, bytes)),
    );
    entries.extend(
        cleaner
            .evidence_files
            .iter()
            .map(|(path, bytes)| digest_entry(path, bytes)),
    );
    entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));

    let actual = compute_package_digest(&entries)
        .map_err(CatalogError::Schema)
        .map_err(CoreError::ProductionCatalogTrust)?;
    if actual != manifest.package_digest {
        return Err(CoreError::ProductionCatalogTrust(
            CatalogError::PackageDigestMismatch {
                expected: manifest.package_digest.clone(),
                actual,
            },
        ));
    }
    Ok(entries)
}

fn digest_entry(path: &str, bytes: &[u8]) -> PackageDigestEntry {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    PackageDigestEntry {
        path: path.to_owned(),
        bytes: bytes.len().to_string(),
        sha256: format!("{:x}", hasher.finalize()),
    }
}

fn cleaner_set_digest(
    mut cleaner_records: Vec<Value>,
    epoch: u64,
    snapshot_digest: &str,
    freshness: ProductionTrustFreshness,
    trust_disposition: ProductionTrustDisposition,
) -> Result<String, CoreError> {
    cleaner_records.sort_by(|left, right| {
        (
            left["id"].as_str().unwrap_or_default(),
            left["version"].as_str().unwrap_or_default(),
            left["packageDigest"].as_str().unwrap_or_default(),
        )
            .cmp(&(
                right["id"].as_str().unwrap_or_default(),
                right["version"].as_str().unwrap_or_default(),
                right["packageDigest"].as_str().unwrap_or_default(),
            ))
    });
    let trust = json!({
        "source": "production_snapshot",
        "snapshotDigest": snapshot_digest,
        "epoch": epoch,
        "freshness": freshness,
        "disposition": trust_disposition,
    });
    for record in &mut cleaner_records {
        record["catalogTrust"] = trust.clone();
    }
    let payload = canonicalize_value(&Value::Array(cleaner_records)).map_err(|error| {
        CoreError::CleanerCatalogTrust(format!(
            "failed to canonicalize cleaner set digest payload: {error}"
        ))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(CLEANER_SET_DIGEST_DOMAIN);
    hasher.update(payload);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_PUBLIC_KEY: &str = "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw";
    const CURRENT: &[u8] = br#"{"algorithm":"ed25519","epoch":5,"expiresAt":"2026-09-27T00:00:00Z","generatedAt":"2026-08-27T00:00:00Z","keys":[{"keyId":"builtin-cleaner-key-2026","publicKeyB64u":"bqB4tpOIibLAwawWg455kwXbfGIsbgj7X6gotTL1S_w","publisherId":"org.sweepx","usages":["declarative_package"],"validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-12-31T00:00:00Z"}],"revocations":[],"rootKeyId":"test-root","schema":"sweepx.cleaner-trust-snapshot/v1","signature":"13b9DZIxk3nOtPodDM1RfUIkOXOkbOHIp8PNCT-n2cl65AHsSOG0H9flyQRL_3pf1DlvkSqJAyBa47IAFONkAQ"}"#;
    const STALE: &[u8] = br#"{"algorithm":"ed25519","epoch":6,"expiresAt":"2026-09-27T00:00:00Z","generatedAt":"2026-08-19T23:59:59Z","keys":[{"keyId":"builtin-cleaner-key-2026","publicKeyB64u":"bqB4tpOIibLAwawWg455kwXbfGIsbgj7X6gotTL1S_w","publisherId":"org.sweepx","usages":["declarative_package"],"validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-12-31T00:00:00Z"}],"revocations":[],"rootKeyId":"test-root","schema":"sweepx.cleaner-trust-snapshot/v1","signature":"ASehOihB1CDsMqWiqATQP_D6UO-rvIjAt0Wimtb6F90dm3hX73lSBsgCC6EKbnA9DhEkDz-rwq0EUT3tkyhTDA"}"#;
    const ROLLBACK: &[u8] = br#"{"algorithm":"ed25519","epoch":4,"expiresAt":"2026-09-27T00:00:00Z","generatedAt":"2026-08-27T00:00:00Z","keys":[{"keyId":"builtin-cleaner-key-2026","publicKeyB64u":"bqB4tpOIibLAwawWg455kwXbfGIsbgj7X6gotTL1S_w","publisherId":"org.sweepx","usages":["declarative_package"],"validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-12-31T00:00:00Z"}],"revocations":[],"rootKeyId":"test-root","schema":"sweepx.cleaner-trust-snapshot/v1","signature":"vgpSFmvDWy3YLtaqMioxp-HgGXCIt8q1fTYLmPthqAe9WsZgLTIGOVsgUMoYEiloHLO48XRlJ0x1oYdvpVZyDw"}"#;
    const COLLISION: &[u8] = br#"{"algorithm":"ed25519","epoch":5,"expiresAt":"2026-09-27T00:00:00Z","generatedAt":"2026-08-26T00:00:00Z","keys":[{"keyId":"builtin-cleaner-key-2026","publicKeyB64u":"bqB4tpOIibLAwawWg455kwXbfGIsbgj7X6gotTL1S_w","publisherId":"org.sweepx","usages":["declarative_package"],"validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-12-31T00:00:00Z"}],"revocations":[],"rootKeyId":"test-root","schema":"sweepx.cleaner-trust-snapshot/v1","signature":"37yQ6-xF3PnKspgv31_O90YUdy89Xg-21sq4Sk5iyB6-2nc9ZTBsTSnLx6NE_d7INvYNNzmdYavy9yM5bbPbDw"}"#;
    const REVOKED: &[u8] = br#"{"algorithm":"ed25519","epoch":6,"expiresAt":"2026-09-27T00:00:00Z","generatedAt":"2026-08-27T00:00:00Z","keys":[{"keyId":"builtin-cleaner-key-2026","publicKeyB64u":"bqB4tpOIibLAwawWg455kwXbfGIsbgj7X6gotTL1S_w","publisherId":"org.sweepx","usages":["declarative_package"],"validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-12-31T00:00:00Z"}],"revocations":[{"reason":"fixture revocation","revokedAt":"2026-08-27T00:00:00Z","target":{"kind":"package_digest","packageDigest":"sha256:28c58ddcc3dff4fe953ab0c326f2bdc4fd71d51c072737451f8766646db328a7"}}],"rootKeyId":"test-root","schema":"sweepx.cleaner-trust-snapshot/v1","signature":"8n9pjroIvHCNy_TMIi9MO6_dewECrl22rDApA747LkSQDkDb5TGRb_9CEFk7L4XOkoq0v1PfKo-RM9zqUb7BDw"}"#;

    fn root() -> TrustRootAnchor {
        TrustRootAnchor {
            key_id: "test-root".to_string(),
            public_key_b64u: ROOT_PUBLIC_KEY.to_string(),
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse(
            "2026-08-27T12:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
    }

    fn catalog_error(error: &CoreError) -> Option<&CatalogError> {
        match error {
            CoreError::ProductionCatalogTrust(error) => Some(error),
            _ => None,
        }
    }

    #[test]
    fn current_snapshot_verifies_every_builtin_but_core_incompatibility_is_report_only() {
        let mut history = TrustHistory::default();
        let resolved =
            resolve_production_catalog_trust(CURRENT, &[root()], now(), &mut history).unwrap();

        assert_eq!(resolved.epoch, 5);
        assert_eq!(resolved.freshness, ProductionTrustFreshness::Current);
        assert_eq!(
            resolved.trust_disposition,
            ProductionTrustDisposition::Trusted
        );
        assert_eq!(
            resolved.catalog_disposition,
            ProductionCatalogDisposition::ReportOnly,
            "all shipped manifests currently require Core >=1.0.0 while CORE_VERSION is 0.1.0"
        );
        assert_eq!(
            BUILT_INS
                .iter()
                .filter(|cleaner| {
                    let manifest: sweepx_cleaner_schema::CleanerManifest =
                        serde_json::from_slice(cleaner.manifest_bytes).unwrap();
                    !VersionReq::parse(&manifest.requires.core)
                        .unwrap()
                        .matches(&Version::parse(CORE_VERSION).unwrap())
                })
                .count(),
            BUILT_INS.len(),
            "the report-only result must be explained by every shipped manifest"
        );
        assert_eq!(history.highest_epoch(), Some(5));
        assert!(resolved.snapshot_digest.starts_with("sha256:"));
        assert!(resolved.cleaner_set_digest.starts_with("sha256:"));
    }

    #[test]
    fn stale_snapshot_is_report_only_and_changes_cleaner_set_digest() {
        let current = resolve_production_catalog_trust(
            CURRENT,
            &[root()],
            now(),
            &mut TrustHistory::default(),
        )
        .unwrap();
        let stale =
            resolve_production_catalog_trust(STALE, &[root()], now(), &mut TrustHistory::default())
                .unwrap();

        assert_eq!(stale.freshness, ProductionTrustFreshness::Stale);
        assert_eq!(
            stale.trust_disposition,
            ProductionTrustDisposition::ReportOnly
        );
        assert_eq!(
            stale.catalog_disposition,
            ProductionCatalogDisposition::ReportOnly
        );
        assert_ne!(current.cleaner_set_digest, stale.cleaner_set_digest);
    }

    #[test]
    fn invalid_snapshot_classes_fail_closed_without_mutating_history() {
        let mut history = TrustHistory::default();
        resolve_production_catalog_trust(CURRENT, &[root()], now(), &mut history).unwrap();
        let baseline = history.clone();

        let rollback =
            resolve_production_catalog_trust(ROLLBACK, &[root()], now(), &mut history).unwrap_err();
        assert!(matches!(
            catalog_error(&rollback),
            Some(CatalogError::TrustSnapshotRollback { .. })
        ));
        assert_eq!(history, baseline);

        let collision = resolve_production_catalog_trust(COLLISION, &[root()], now(), &mut history)
            .unwrap_err();
        assert!(matches!(
            catalog_error(&collision),
            Some(CatalogError::TrustSnapshotEpochCollision { epoch: 5 })
        ));
        assert_eq!(history, baseline);

        let revoked = resolve_production_catalog_trust(
            REVOKED,
            &[root()],
            now(),
            &mut TrustHistory::default(),
        )
        .unwrap_err();
        assert!(matches!(
            catalog_error(&revoked),
            Some(CatalogError::RevokedPackage { .. })
        ));

        let expired = resolve_production_catalog_trust(
            CURRENT,
            &[root()],
            OffsetDateTime::parse(
                "2026-09-27T00:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap(),
            &mut TrustHistory::default(),
        )
        .unwrap_err();
        assert!(matches!(
            catalog_error(&expired),
            Some(CatalogError::TrustSnapshotExpired)
        ));

        let unknown_root = resolve_production_catalog_trust(
            CURRENT,
            &[TrustRootAnchor {
                key_id: "different-root".to_string(),
                public_key_b64u: ROOT_PUBLIC_KEY.to_string(),
            }],
            now(),
            &mut TrustHistory::default(),
        )
        .unwrap_err();
        assert!(matches!(
            catalog_error(&unknown_root),
            Some(CatalogError::UnknownTrustRoot(_))
        ));

        let mut tampered: Value = serde_json::from_slice(CURRENT).unwrap();
        tampered["generatedAt"] = Value::String("2026-08-26T00:00:00Z".to_string());
        let tampered = serde_json::to_vec(&tampered).unwrap();
        let tampered = resolve_production_catalog_trust(
            &tampered,
            &[root()],
            now(),
            &mut TrustHistory::default(),
        )
        .unwrap_err();
        assert!(matches!(
            catalog_error(&tampered),
            Some(CatalogError::TrustSnapshotSignatureVerificationFailed)
        ));
    }

    #[test]
    fn trust_inputs_are_bounded_before_verification() {
        let oversized = vec![b' '; MAX_PRODUCTION_TRUST_SNAPSHOT_BYTES + 1];
        let error = resolve_production_catalog_trust(
            &oversized,
            &[root()],
            now(),
            &mut TrustHistory::default(),
        )
        .unwrap_err();
        assert!(matches!(error, CoreError::CleanerCatalogTrust(_)));

        let duplicate = root();
        let error = resolve_production_catalog_trust(
            CURRENT,
            &[duplicate.clone(), duplicate],
            now(),
            &mut TrustHistory::default(),
        )
        .unwrap_err();
        assert!(matches!(error, CoreError::CleanerCatalogTrust(_)));
    }
}
