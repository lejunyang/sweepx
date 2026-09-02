//! Development-time signing for SweepX cleaner packages.
//!
//! # Why this exists
//!
//! A cleaner package is admitted only if its `packageDigest` matches the bytes on
//! disk *and* its `SIGNATURE` verifies against a trusted publisher key. That is a
//! supply-chain property, not secrecy: the rules themselves are plain JSON. But it
//! means editing a rule by hand always invalidates the package, so without a signing
//! path in the repository a contributor cannot change a rule on their own machine —
//! which is what `DESIGN.md` R-24 rules out by requiring the build to "generate a
//! real file table/digest/signature".
//!
//! # What it deliberately does not do
//!
//! This tool mints *development* signatures. It does not, and must not, become the
//! release signing path: a release key belongs in a controlled environment, not in a
//! working tree. To keep those apart, the key here is loaded from an explicit path or
//! generated on demand, and the resulting key id is required to carry a development
//! marker (see [`SigningKeyFile::key_id`]). The crate is `publish = false` and is not
//! a dependency of the shipped CLI, so nothing that ships can mint a signature.
//!
//! # Correctness approach
//!
//! Every byte-level decision — canonical JSON form, which manifest fields the digest
//! covers, file-table ordering, the signature payload framing — is delegated to
//! `sweepx-catalog` and `sweepx-cleaner-schema`, the same code that verifies at load
//! time. Reimplementing any of it here would let the two drift apart, producing
//! packages that fail to load for reasons invisible in the JSON. After writing, the
//! package is re-loaded through the real admission path so a successful run proves
//! loadability rather than asserting it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sweepx_catalog::{
    CatalogError, ExplicitPublisherKey, is_builtin_trusted_key, load_package_bytes_with_key,
    package_file_table,
};
use sweepx_cleaner_schema::{
    CLEANER_MANIFEST_SCHEMA, CleanerSignatureEnvelope, SignatureAlgorithm,
    canonical_signature_payload, compute_package_digest,
};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Marker every development key id must contain.
///
/// Makes a development signature self-identifying in any package that carries one, so
/// a locally signed package cannot be mistaken for a released one during review.
pub const DEVELOPMENT_KEY_MARKER: &str = "dev";

/// The subdirectory holding rule documents inside a package.
const RULES_DIR: &str = "rules";
/// The subdirectory holding evidence documents inside a package.
const EVIDENCE_DIR: &str = "evidence";
/// The manifest file name inside a package.
const MANIFEST_FILE: &str = "cleaner.json";
/// The detached signature file name inside a package.
const SIGNATURE_FILE: &str = "SIGNATURE";

/// Failures that can occur while signing a package.
#[derive(Debug, Error)]
pub enum SignError {
    /// A file or directory could not be read or written.
    #[error("io error at {path}: {source}")]
    Io {
        /// The path being accessed.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The manifest is not valid JSON, or is not a JSON object.
    #[error("{path} is not a usable JSON object: {detail}")]
    Manifest {
        /// The offending path.
        path: PathBuf,
        /// What was wrong.
        detail: String,
    },
    /// A package invariant enforced by the loader was violated.
    #[error("package rejected by the catalog loader: {0}")]
    Catalog(#[from] CatalogError),
    /// The signing key file is malformed.
    #[error("signing key at {path} is unusable: {detail}")]
    Key {
        /// The key file path.
        path: PathBuf,
        /// What was wrong.
        detail: String,
    },
    /// The key id does not carry the development marker.
    #[error(
        "key id {key_id:?} must contain {DEVELOPMENT_KEY_MARKER:?}; this tool only mints \
         development signatures"
    )]
    KeyIdNotDevelopment {
        /// The rejected key id.
        key_id: String,
    },
    /// A timestamp could not be produced or parsed.
    #[error("invalid timestamp: {0}")]
    Time(String),
}

/// An ed25519 signing key plus the publisher identity it signs for.
///
/// Stored as JSON so a key can be committed to a developer's own environment or
/// generated ad hoc, and so the trust-store entry can be derived from it mechanically
/// rather than transcribed by hand.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SigningKeyFile {
    /// Key identifier; must contain [`DEVELOPMENT_KEY_MARKER`].
    pub key_id: String,
    /// Publisher this key signs for.
    pub publisher_id: String,
    /// Base64url (unpadded) ed25519 secret scalar seed, 32 bytes.
    pub secret_key_b64u: String,
    /// Base64url (unpadded) ed25519 public key, 32 bytes.
    pub public_key_b64u: String,
    /// Start of the key's validity window, RFC 3339.
    pub valid_from: String,
    /// End of the key's validity window, RFC 3339.
    pub valid_until: String,
}

impl SigningKeyFile {
    /// Generates a fresh development key valid for one year from `now`.
    pub fn generate(
        key_id: impl Into<String>,
        publisher_id: impl Into<String>,
        now: OffsetDateTime,
    ) -> Result<Self, SignError> {
        let key_id = key_id.into();
        if !key_id.contains(DEVELOPMENT_KEY_MARKER) {
            return Err(SignError::KeyIdNotDevelopment { key_id });
        }
        let signing = SigningKey::generate(&mut rand_core::OsRng);
        let valid_until = now
            .checked_add(time::Duration::days(365))
            .ok_or_else(|| SignError::Time("validity window overflows".to_owned()))?;
        Ok(Self {
            key_id,
            publisher_id: publisher_id.into(),
            secret_key_b64u: URL_SAFE_NO_PAD.encode(signing.to_bytes()),
            public_key_b64u: URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes()),
            valid_from: format_time(now)?,
            valid_until: format_time(valid_until)?,
        })
    }

    /// Reads a key file from disk.
    pub fn read(path: &Path) -> Result<Self, SignError> {
        let bytes = fs::read(path).map_err(|source| SignError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let key: Self = serde_json::from_slice(&bytes).map_err(|error| SignError::Key {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
        if !key.key_id.contains(DEVELOPMENT_KEY_MARKER) {
            return Err(SignError::KeyIdNotDevelopment {
                key_id: key.key_id.clone(),
            });
        }
        Ok(key)
    }

    /// Writes the key file, creating parent directories as needed.
    pub fn write(&self, path: &Path) -> Result<(), SignError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| SignError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        // Pretty-printed with a trailing newline and LF endings: this file is read by
        // humans, and the repository normalizes to LF.
        let mut json = serde_json::to_string_pretty(self).map_err(|error| SignError::Key {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
        json.push('\n');
        fs::write(path, json.replace("\r\n", "\n")).map_err(|source| SignError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    fn signing_key(&self, path: &Path) -> Result<SigningKey, SignError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.secret_key_b64u)
            .map_err(|error| SignError::Key {
                path: path.to_path_buf(),
                detail: format!("secretKeyB64u is not base64url: {error}"),
            })?;
        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| SignError::Key {
            path: path.to_path_buf(),
            detail: format!("secretKeyB64u must be 32 bytes, got {}", bytes.len()),
        })?;
        let signing = SigningKey::from_bytes(&seed);
        // A mismatch here means the file was edited inconsistently; signing with it
        // would produce a signature no one can verify, so fail before writing.
        let derived = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
        if derived != self.public_key_b64u {
            return Err(SignError::Key {
                path: path.to_path_buf(),
                detail: "publicKeyB64u does not match the secret key".to_owned(),
            });
        }
        Ok(signing)
    }

    /// Renders the Rust literal for this key's `BUILTIN_TRUST_STORE` entry.
    ///
    /// Emitted rather than applied automatically: adding a trust anchor is a
    /// deliberate act that belongs in a reviewed diff, not a side effect of signing.
    pub fn trust_store_entry(&self) -> String {
        format!(
            "    TrustedKey {{\n        key_id: {:?},\n        publisher_id: {:?},\n        \
             public_key_b64u: {:?},\n        valid_from: {:?},\n        valid_until: {:?},\n        \
             revoked: false,\n    }},",
            self.key_id, self.publisher_id, self.public_key_b64u, self.valid_from, self.valid_until,
        )
    }
}

/// What signing changed in a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignOutcome {
    /// The recomputed package digest.
    pub package_digest: String,
    /// Whether `cleaner.json` had to be rewritten.
    pub manifest_updated: bool,
    /// Whether the manifest's `publisher` block was repointed at the signing key.
    pub publisher_rekeyed: bool,
    /// Whether the signing key is a shipped trust anchor.
    ///
    /// When false, the package verifies against the signing key but the shipped binary
    /// will reject it until the key is added to `BUILTIN_TRUST_STORE`. Surfaced rather
    /// than hidden so a contributor is not left to diagnose that as a mystery failure.
    pub key_is_builtin_trusted: bool,
    /// Package-relative paths covered by the signature, in signed order.
    pub signed_paths: Vec<String>,
}

/// Signs the cleaner package rooted at `package_dir` in place.
///
/// Repoints the manifest's publisher block at the signing key, refreshes every recorded
/// rule digest and the package digest, writes a fresh `SIGNATURE`, then re-loads the
/// result through the loader's own admission path so a successful return means the
/// package genuinely loads rather than merely having been written.
pub fn sign_package(
    package_dir: &Path,
    key_path: &Path,
    now: OffsetDateTime,
) -> Result<SignOutcome, SignError> {
    let key = SigningKeyFile::read(key_path)?;
    let signing = key.signing_key(key_path)?;

    let manifest_path = package_dir.join(MANIFEST_FILE);
    let manifest_bytes = read_file(&manifest_path)?;
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).map_err(|error| SignError::Manifest {
            path: manifest_path.clone(),
            detail: error.to_string(),
        })?;

    let payload_files = collect_payload_files(package_dir)?;
    let rule_files = borrowed(&payload_files.rules);
    let evidence_files = borrowed(&payload_files.evidence);

    // Per-rule digests recorded in the manifest must be refreshed before the package
    // digest is computed over the manifest, since the manifest's own bytes feed it.
    let manifest_updated_rules =
        refresh_manifest_rule_digests(&mut manifest, &manifest_path, &payload_files.rules)?;

    // The signature must bind the manifest's own publisher tuple, so signing with a
    // different key means the manifest has to name that key. Rewriting it here is what
    // makes local rule edits possible at all; the alternative is asking every
    // contributor to hand-edit two identity fields before every signing run.
    let publisher_rekeyed = set_publisher(&mut manifest, &manifest_path, &key)?;
    let identity = manifest_identity(&manifest, &manifest_path)?;

    // The digest covers the manifest with `packageDigest` removed, so a placeholder is
    // required to exist but its value is irrelevant to the result.
    set_package_digest(&mut manifest, &manifest_path, "sha256:0")?;
    let candidate_bytes = to_manifest_bytes(&manifest, &manifest_path)?;
    let file_table = package_file_table(&candidate_bytes, &rule_files, &evidence_files)?;
    let package_digest =
        compute_package_digest(&file_table).map_err(|error| SignError::Time(error.to_string()))?;

    set_package_digest(&mut manifest, &manifest_path, &package_digest)?;
    let final_manifest_bytes = to_manifest_bytes(&manifest, &manifest_path)?;
    let manifest_updated =
        manifest_updated_rules || publisher_rekeyed || final_manifest_bytes != manifest_bytes;
    if manifest_updated {
        write_file(&manifest_path, &final_manifest_bytes)?;
    }

    // Recompute over the bytes actually written: if rewriting the manifest changed its
    // length or ordering, the earlier table no longer describes the file on disk.
    let written_table = package_file_table(&final_manifest_bytes, &rule_files, &evidence_files)?;
    let written_digest = compute_package_digest(&written_table)
        .map_err(|error| SignError::Time(error.to_string()))?;

    let mut envelope = CleanerSignatureEnvelope {
        schema: sweepx_cleaner_schema::CLEANER_SIGNATURE_SCHEMA.into(),
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: key.key_id.clone(),
        publisher_id: key.publisher_id.clone(),
        package_id: identity.package_id,
        package_version: identity.package_version,
        package_digest: written_digest.clone(),
        manifest_schema: CLEANER_MANIFEST_SCHEMA.into(),
        signed_at: format_time(now)?,
        expires_at: None,
        transparency_proof: None,
        signature: URL_SAFE_NO_PAD.encode([0_u8; 64]),
    };
    let payload = canonical_signature_payload(&envelope)
        .map_err(|error| SignError::Time(error.to_string()))?;
    envelope.signature = URL_SAFE_NO_PAD.encode(signing.sign(&payload).to_bytes());

    let signature_bytes = signature_file_bytes(&envelope, package_dir)?;
    write_file(&package_dir.join(SIGNATURE_FILE), &signature_bytes)?;

    // Proof, not assertion: run the real admission path over what was just written.
    // Verification uses the signing key because a development key is by definition not
    // a shipped trust anchor; every other check is the shipped loader's own.
    load_package_bytes_with_key(
        &final_manifest_bytes,
        &signature_bytes,
        &rule_files,
        &evidence_files,
        &ExplicitPublisherKey {
            key_id: key.key_id.clone(),
            publisher_id: key.publisher_id.clone(),
            public_key_b64u: key.public_key_b64u.clone(),
            valid_from: key.valid_from.clone(),
            valid_until: key.valid_until.clone(),
        },
        now,
    )?;

    Ok(SignOutcome {
        package_digest: written_digest,
        manifest_updated,
        publisher_rekeyed,
        key_is_builtin_trusted: is_builtin_trusted_key(&key.key_id),
        signed_paths: written_table.into_iter().map(|entry| entry.path).collect(),
    })
}

struct PayloadFiles {
    rules: Vec<(String, Vec<u8>)>,
    evidence: Vec<(String, Vec<u8>)>,
}

fn collect_payload_files(package_dir: &Path) -> Result<PayloadFiles, SignError> {
    Ok(PayloadFiles {
        rules: read_dir_files(package_dir, RULES_DIR)?,
        evidence: read_dir_files(package_dir, EVIDENCE_DIR)?,
    })
}

/// Reads every file under `package_dir/subdir`, returning package-relative paths.
///
/// A missing directory yields no entries rather than an error, because a package need
/// not carry evidence. Entries are sorted so the signed inventory is reproducible
/// regardless of directory iteration order.
fn read_dir_files(package_dir: &Path, subdir: &str) -> Result<Vec<(String, Vec<u8>)>, SignError> {
    let dir = package_dir.join(subdir);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut files = BTreeMap::new();
    let mut stack = vec![(dir, String::from(subdir))];
    while let Some((current, prefix)) = stack.pop() {
        let entries = fs::read_dir(&current).map_err(|source| SignError::Io {
            path: current.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| SignError::Io {
                path: current.clone(),
                source,
            })?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = format!("{prefix}/{name}");
            let file_type = entry.file_type().map_err(|source| SignError::Io {
                path: entry.path(),
                source,
            })?;
            if file_type.is_dir() {
                stack.push((entry.path(), relative));
            } else {
                files.insert(relative, read_file(&entry.path())?);
            }
        }
    }
    Ok(files.into_iter().collect())
}

fn borrowed(files: &[(String, Vec<u8>)]) -> Vec<(&str, &[u8])> {
    files
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect()
}

struct ManifestIdentity {
    package_id: String,
    package_version: String,
}

fn manifest_identity(
    manifest: &serde_json::Value,
    path: &Path,
) -> Result<ManifestIdentity, SignError> {
    let missing = |field: &str| SignError::Manifest {
        path: path.to_path_buf(),
        detail: format!("missing or non-string field {field:?}"),
    };
    let text = |value: Option<&serde_json::Value>, field: &str| {
        value
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| missing(field))
    };
    Ok(ManifestIdentity {
        package_id: text(manifest.get("id"), "id")?,
        package_version: text(manifest.get("version"), "version")?,
    })
}

/// Rewrites each `rules[].sha256` to match the rule file on disk.
///
/// Returns whether anything changed. Without this a contributor editing a rule would
/// have to update the digest by hand, which is exactly the manual step that makes
/// local rule changes impractical.
fn refresh_manifest_rule_digests(
    manifest: &mut serde_json::Value,
    path: &Path,
    rules: &[(String, Vec<u8>)],
) -> Result<bool, SignError> {
    let digests: BTreeMap<&str, String> = rules
        .iter()
        .map(|(rule_path, bytes)| (rule_path.as_str(), sha256_hex(bytes)))
        .collect();
    let entries = manifest
        .get_mut("rules")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| SignError::Manifest {
            path: path.to_path_buf(),
            detail: "missing array field \"rules\"".to_owned(),
        })?;
    let mut changed = false;
    for entry in entries {
        let rule_path = entry
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SignError::Manifest {
                path: path.to_path_buf(),
                detail: "a rules[] entry has no string \"path\"".to_owned(),
            })?
            .to_owned();
        let digest = digests.get(rule_path.as_str()).ok_or_else(|| {
            // Failing here beats signing a manifest that references a file the package
            // does not contain; the loader would reject it later with less context.
            SignError::Manifest {
                path: path.to_path_buf(),
                detail: format!("manifest references {rule_path:?}, which is not in the package"),
            }
        })?;
        let object = entry.as_object_mut().ok_or_else(|| SignError::Manifest {
            path: path.to_path_buf(),
            detail: "a rules[] entry is not an object".to_owned(),
        })?;
        if object.get("sha256").and_then(serde_json::Value::as_str) != Some(digest.as_str()) {
            object.insert(
                "sha256".to_owned(),
                serde_json::Value::String(digest.clone()),
            );
            changed = true;
        }
    }
    Ok(changed)
}

/// Repoints the manifest's `publisher` block at the signing key.
///
/// Returns whether anything changed. Preserves any other fields the publisher block
/// carries, so this stays correct if the schema grows.
fn set_publisher(
    manifest: &mut serde_json::Value,
    path: &Path,
    key: &SigningKeyFile,
) -> Result<bool, SignError> {
    let publisher = manifest
        .get_mut("publisher")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| SignError::Manifest {
            path: path.to_path_buf(),
            detail: "missing object field \"publisher\"".to_owned(),
        })?;
    let mut changed = false;
    for (field, value) in [("id", &key.publisher_id), ("keyId", &key.key_id)] {
        if publisher.get(field).and_then(serde_json::Value::as_str) != Some(value.as_str()) {
            publisher.insert(field.to_owned(), serde_json::Value::String(value.clone()));
            changed = true;
        }
    }
    Ok(changed)
}

fn set_package_digest(
    manifest: &mut serde_json::Value,
    path: &Path,
    digest: &str,
) -> Result<(), SignError> {
    let object = manifest
        .as_object_mut()
        .ok_or_else(|| SignError::Manifest {
            path: path.to_path_buf(),
            detail: "root is not a JSON object".to_owned(),
        })?;
    if !object.contains_key("packageDigest") {
        return Err(SignError::Manifest {
            path: path.to_path_buf(),
            detail: "missing field \"packageDigest\"".to_owned(),
        });
    }
    object.insert(
        "packageDigest".to_owned(),
        serde_json::Value::String(digest.to_owned()),
    );
    Ok(())
}

/// Serializes a package JSON document the way the repository stores it.
///
/// Two-space pretty printing with a trailing newline and LF endings. The digest is
/// computed over a canonical form rather than this text, so formatting is free to be
/// human-readable — but it must be *stable*, or every signing run would rewrite the
/// file and produce a spurious diff.
fn to_manifest_bytes(manifest: &serde_json::Value, path: &Path) -> Result<Vec<u8>, SignError> {
    let mut text = serde_json::to_string_pretty(manifest).map_err(|error| SignError::Manifest {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    text.push('\n');
    Ok(text.replace("\r\n", "\n").into_bytes())
}

fn signature_file_bytes(
    envelope: &CleanerSignatureEnvelope,
    package_dir: &Path,
) -> Result<Vec<u8>, SignError> {
    let mut text = serde_json::to_string_pretty(envelope).map_err(|error| SignError::Manifest {
        path: package_dir.join(SIGNATURE_FILE),
        detail: error.to_string(),
    })?;
    text.push('\n');
    Ok(text.replace("\r\n", "\n").into_bytes())
}

fn read_file(path: &Path) -> Result<Vec<u8>, SignError> {
    fs::read(path).map_err(|source| SignError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), SignError> {
    fs::write(path, bytes).map_err(|source| SignError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn format_time(value: OffsetDateTime) -> Result<String, SignError> {
    value
        .format(&Rfc3339)
        .map_err(|error| SignError::Time(error.to_string()))
}
