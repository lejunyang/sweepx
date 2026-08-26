use sha2::{Digest, Sha256};
use sweepx_cleaner_schema::{
    CleanerManifest, CleanerRule, PackageDigestEntry, ValidationError, compute_package_digest,
};
use thiserror::Error;

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
        let manifest: CleanerManifest =
            serde_json::from_slice(manifest_bytes).map_err(CatalogError::Json)?;
        manifest.validate().map_err(CatalogError::Schema)?;

        let mut rules = Vec::with_capacity(rule_files.len());
        for (path, bytes) in rule_files {
            let rule: CleanerRule = serde_json::from_slice(bytes).map_err(CatalogError::Json)?;
            rule.validate().map_err(CatalogError::Schema)?;
            rules.push(((*path).to_owned(), rule));
        }

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

        let mut entries = Vec::with_capacity(rule_files.len() + evidence_files.len());
        for (path, bytes) in rule_files {
            entries.push(PackageDigestEntry {
                path: (*path).to_owned(),
                sha256: sha256_hex(bytes),
            });
        }
        for (path, bytes) in evidence_files {
            entries.push(PackageDigestEntry {
                path: (*path).to_owned(),
                sha256: sha256_hex(bytes),
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));

        let actual_package_digest =
            compute_package_digest(&manifest, &entries).map_err(CatalogError::Schema)?;
        if actual_package_digest != manifest.package_digest {
            return Err(CatalogError::PackageDigestMismatch {
                expected: manifest.package_digest.clone(),
                actual: actual_package_digest,
            });
        }

        Ok(LoadedCleanerPackage { manifest, rules })
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
    #[error("schema validation failed: {0}")]
    Schema(ValidationError),
    #[error("manifest references missing rule file: {0}")]
    MissingRule(String),
    #[error("digest mismatch for {path}: expected {expected}, got {actual}")]
    DigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("package digest mismatch: expected {expected}, got {actual}")]
    PackageDigestMismatch { expected: String, actual: String },
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
                CARGO_TARGET.rule_files,
                CARGO_TARGET.evidence_files,
            )
            .expect_err("tampered manifest must fail");
        assert!(matches!(err, CatalogError::PackageDigestMismatch { .. }));
    }
}
