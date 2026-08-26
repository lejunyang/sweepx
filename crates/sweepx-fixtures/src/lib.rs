use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sweepx_model::{ByteValue, DecimalU128, EvidenceValue, ReasonCode};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub const FIXTURE_MANIFEST_SCHEMA: &str = "sweepx.fixture-manifest/v1";
pub const RECEIPT_SCHEMA: &str = "sweepx.receipt/v1";
pub const GENERATOR_VERSION: &str = "0.1.0";
pub const LINUX_P4_TRASH_TARGET_ENTRY_ID: &str = "trash-target-file";
const RECEIPT_TIME_OFFSET_SECS: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureManifest {
    pub schema: String,
    pub manifest_id: String,
    pub seed: DecimalU128,
    pub created_at: String,
    pub generator_version: String,
    pub platform_profile: PlatformProfile,
    pub entries: Vec<FixtureEntry>,
    pub expectations: ManifestExpectations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformProfile {
    pub os_family: String,
    pub filesystem: String,
    pub case_sensitivity: String,
    pub native_mutation_phase: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureEntry {
    pub entry_id: String,
    pub path: Vec<String>,
    pub kind: FixtureEntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<DecimalU128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_pattern: Option<ContentPattern>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardlink_to: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureEntryKind {
    Directory,
    File,
    Symlink,
    Hardlink,
    Special,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentPattern {
    Zeroes,
    AsciiSeed,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestExpectations {
    pub entry_count: DecimalU128,
    pub logical_bytes: TaggedValue,
    pub allocated_bytes: TaggedValue,
    pub requires_live_scan: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_boundaries: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TaggedValue {
    Known { value: DecimalU128 },
    LowerBound { value: DecimalU128, reason: String },
    Unknown { reason: String },
    Unsupported { reason: String },
    NotChecked { reason: String },
}

impl TaggedValue {
    fn known(value: u128) -> Self {
        Self::Known {
            value: DecimalU128::new(value),
        }
    }

    fn lower_bound(value: u128, reason: impl Into<String>) -> Self {
        Self::LowerBound {
            value: DecimalU128::new(value),
            reason: reason.into(),
        }
    }

    fn unknown(reason: impl Into<String>) -> Self {
        Self::Unknown {
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub schema: String,
    pub receipt_id: String,
    pub manifest_id: String,
    pub generated_at: String,
    pub generator_version: String,
    pub seed: DecimalU128,
    pub status: ReceiptStatus,
    pub root_path: String,
    pub entries: Vec<ReceiptEntry>,
    pub totals: ReceiptTotals,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ReceiptError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Created,
    Verified,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptEntry {
    pub entry_id: String,
    pub kind: FixtureEntryKind,
    pub path: Vec<String>,
    pub exists: bool,
    pub logical_bytes: TaggedValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocated_bytes: Option<TaggedValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptTotals {
    pub entry_count: DecimalU128,
    pub logical_bytes: TaggedValue,
    pub apparent_logical_bytes: TaggedValue,
    pub unique_logical_bytes: TaggedValue,
    pub allocated_bytes: TaggedValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptError {
    pub code: String,
    pub class: String,
    pub message_key: String,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct GeneratedFixture {
    pub manifest: FixtureManifest,
    pub fixture_dir: PathBuf,
    pub receipt: Receipt,
    qualification_source: GeneratedFixtureQualificationSource,
}

#[derive(Debug)]
struct GeneratedFixtureQualificationSource {
    manifest: FixtureManifest,
    top_dir: PathBuf,
    trash_target_issued: AtomicBool,
    #[cfg(target_os = "linux")]
    baseline: LinuxFixtureTreeBaseline,
}

/// Read-only evidence binding for one generated Linux P4 Trash fixture target.
///
/// The target is derived from the immutable manifest snapshot captured during
/// generation. Callers cannot construct this value or substitute another path.
pub struct LinuxTrashTargetQualification {
    entry_id: String,
    manifest_digest: String,
    expected_filesystem: String,
    top_dir: PathBuf,
    target_path: PathBuf,
    #[cfg(target_os = "linux")]
    target_relative: PathBuf,
    #[cfg(target_os = "linux")]
    parent_relative: PathBuf,
    #[cfg(target_os = "linux")]
    root_baseline: LinuxFixtureNodeBaseline,
    #[cfg(target_os = "linux")]
    parent_baseline: LinuxFixtureNodeBaseline,
    #[cfg(target_os = "linux")]
    target_baseline: LinuxFixtureNodeBaseline,
    #[cfg(target_os = "linux")]
    sibling_baselines: BTreeMap<PathBuf, LinuxFixtureNodeBaseline>,
    #[cfg(target_os = "linux")]
    tree_baseline: LinuxFixtureTreeBaseline,
}

impl std::fmt::Debug for LinuxTrashTargetQualification {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LinuxTrashTargetQualification")
            .field("entry_id", &self.entry_id)
            .field("expected_filesystem", &self.expected_filesystem)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxFixtureTreeBaseline {
    nodes: BTreeMap<PathBuf, LinuxFixtureNodeBaseline>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxFixtureNodeBaseline {
    kind: LinuxFixtureNodeKind,
    device: u64,
    inode: u64,
    mode: u32,
    user_id: u32,
    group_id: u32,
    hard_link_count: u64,
    logical_bytes: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    payload_digest: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum LinuxFixtureNodeKind {
    Directory,
    File,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleReport {
    pub receipt: Receipt,
    pub identities: BTreeMap<Vec<String>, EntryIdentity>,
    pub boundaries: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryIdentity {
    pub kind: FixtureEntryKind,
    pub logical_bytes: ByteValue,
    pub digest: Option<String>,
    pub link_target: Option<Vec<String>>,
    pub hardlink_group: Option<String>,
}

#[derive(Debug, Error)]
pub enum FixtureError {
    #[error("failed to parse contract JSON {path}: {source}")]
    ContractJson {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("fixture root must exist: {path}")]
    FixtureRootMissing { path: PathBuf },
    #[error("fixture root must be an absolute directory: {path}")]
    FixtureRootNotAbsolute { path: PathBuf },
    #[error("fixture root cannot be a symlink: {path}")]
    FixtureRootIsSymlink { path: PathBuf },
    #[error("fixture root cannot be filesystem root: {path}")]
    FixtureRootIsFilesystemRoot { path: PathBuf },
    #[error("fixture root must be empty before generation: {path}")]
    FixtureRootNotEmpty { path: PathBuf },
    #[error("target path escapes fixture root: {path}")]
    TargetEscapesFixtureRoot { path: PathBuf },
    #[error("target path contains non-normal component: {path}")]
    TargetPathNotNormal { path: PathBuf },
    #[error("target already exists: {path}")]
    TargetExists { path: PathBuf },
    #[error("manifest path duplicates existing entry: {path:?}")]
    DuplicateManifestPath { path: Vec<String> },
    #[error("manifest hardlink target is missing: {path:?}")]
    HardlinkTargetMissing { path: Vec<String> },
    #[error("manifest hardlink target must reference a file: {path:?}")]
    HardlinkTargetNotFile { path: Vec<String> },
    #[error("manifest symlink target is missing: {path:?}")]
    SymlinkTargetMissing { path: Vec<String> },
    #[error("manifest symlink target escapes fixture root: {path:?}")]
    SymlinkTargetEscapesFixtureRoot { path: Vec<String> },
    #[error("manifest must use a single top-level fixture directory")]
    MixedTopLevelRoots,
    #[error("manifest entry kind is unsupported: {entry_id}")]
    UnsupportedEntryKind { entry_id: String },
    #[error("Linux Trash fixture entry id is absent: {entry_id}")]
    LinuxTrashEntryIdAbsent { entry_id: String },
    #[error("Linux Trash fixture entry id is duplicated: {entry_id}")]
    LinuxTrashEntryIdDuplicate { entry_id: String },
    #[error("Linux Trash fixture requires osFamily=linux, found {actual}")]
    LinuxTrashOsFamilyMismatch { actual: String },
    #[error("Linux Trash fixture requires nativeMutationPhase=P4-trash-only, found {actual}")]
    LinuxTrashMutationPhaseMismatch { actual: String },
    #[error("Linux Trash fixture target must be a manifest file: {entry_id}")]
    LinuxTrashManifestTargetNotFile { entry_id: String },
    #[error("Linux Trash fixture target authority was already issued")]
    LinuxTrashTargetAlreadyIssued,
    #[error("failed to serialize immutable Linux Trash fixture manifest: {source}")]
    LinuxTrashManifestSerialization {
        #[source]
        source: serde_json::Error,
    },
    #[error("Linux Trash fixture target must be strictly below its generated top directory")]
    LinuxTrashTargetNotBelowTopDirectory,
    #[error("Linux Trash fixture target is not a regular file at runtime: {entry_id}")]
    LinuxTrashRuntimeTargetNotFile { entry_id: String },
    #[error("Linux Trash fixture target must have exactly one hard link: {entry_id}")]
    LinuxTrashRuntimeTargetHasMultipleLinks { entry_id: String },
    #[error("Linux Trash fixture tree changed")]
    LinuxTrashFixtureChanged,
    #[error("Linux Trash fixture tree contains an unexpected entry")]
    LinuxTrashUnexpectedEntry,
    #[error("Linux Trash fixture target still exists after the Trash action: {entry_id}")]
    LinuxTrashTargetStillExists { entry_id: String },
    #[error("Linux Trash fixture qualification is supported only on Linux")]
    LinuxTrashUnsupportedHost,
    #[error("oracle found entry outside fixture root: {path}")]
    OracleOutsideFixtureRoot { path: PathBuf },
    #[error("I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("timestamp parse failed for {value}: {source}")]
    TimestampParse {
        value: String,
        #[source]
        source: time::error::Parse,
    },
    #[error("timestamp format failed: {0}")]
    TimestampFormat(#[from] time::error::Format),
}

impl GeneratedFixture {
    /// Selects exactly one manifest entry as a Linux P4 Trash test target.
    ///
    /// `entry_id` is the only selector. The bound target path is derived from
    /// the generated manifest snapshot, remains private, and cannot be
    /// replaced by callers. The platform harness must independently observe
    /// the live filesystem and compare it with `expected_filesystem()`.
    pub fn select_linux_trash_target(
        &self,
        entry_id: &str,
    ) -> Result<LinuxTrashTargetQualification, FixtureError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = entry_id;
            return Err(FixtureError::LinuxTrashUnsupportedHost);
        }

        #[cfg(target_os = "linux")]
        {
            let source = &self.qualification_source;
            let profile = &source.manifest.platform_profile;
            if profile.os_family != "linux" {
                return Err(FixtureError::LinuxTrashOsFamilyMismatch {
                    actual: profile.os_family.clone(),
                });
            }
            if profile.native_mutation_phase != "P4-trash-only" {
                return Err(FixtureError::LinuxTrashMutationPhaseMismatch {
                    actual: profile.native_mutation_phase.clone(),
                });
            }
            let mut matching_entries = source
                .manifest
                .entries
                .iter()
                .filter(|entry| entry.entry_id == entry_id);
            let entry =
                matching_entries
                    .next()
                    .ok_or_else(|| FixtureError::LinuxTrashEntryIdAbsent {
                        entry_id: entry_id.to_string(),
                    })?;
            if matching_entries.next().is_some() {
                return Err(FixtureError::LinuxTrashEntryIdDuplicate {
                    entry_id: entry_id.to_string(),
                });
            }
            if entry.kind != FixtureEntryKind::File {
                return Err(FixtureError::LinuxTrashManifestTargetNotFile {
                    entry_id: entry_id.to_string(),
                });
            }

            let target_relative = entry_relative_to_top(&source.manifest, entry)?;
            if target_relative.as_os_str().is_empty() {
                return Err(FixtureError::LinuxTrashTargetNotBelowTopDirectory);
            }
            let parent_relative = target_relative
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .to_path_buf();
            let target_path = source.top_dir.join(&target_relative);

            let current_tree = capture_linux_fixture_tree(&source.top_dir)?;
            let target_baseline = current_tree
                .nodes
                .get(&target_relative)
                .ok_or(FixtureError::LinuxTrashFixtureChanged)?
                .clone();
            if target_baseline.kind != LinuxFixtureNodeKind::File {
                return Err(FixtureError::LinuxTrashRuntimeTargetNotFile {
                    entry_id: entry_id.to_string(),
                });
            }
            if target_baseline.hard_link_count != 1 {
                return Err(FixtureError::LinuxTrashRuntimeTargetHasMultipleLinks {
                    entry_id: entry_id.to_string(),
                });
            }
            compare_linux_fixture_trees(
                &source.baseline,
                &current_tree,
                LinuxTreeComparison::Exact,
            )?;
            let root_baseline = current_tree
                .nodes
                .get(Path::new(""))
                .expect("fixture tree capture includes its root")
                .clone();
            let parent_baseline = current_tree
                .nodes
                .get(&parent_relative)
                .ok_or(FixtureError::LinuxTrashFixtureChanged)?
                .clone();
            if parent_baseline.kind != LinuxFixtureNodeKind::Directory {
                return Err(FixtureError::LinuxTrashFixtureChanged);
            }
            let sibling_baselines = current_tree
                .nodes
                .iter()
                .filter(|(relative, _)| {
                    relative.as_path() != target_relative
                        && relative.as_path() != parent_relative
                        && relative.parent().unwrap_or_else(|| Path::new("")) == parent_relative
                })
                .map(|(relative, baseline)| (relative.clone(), baseline.clone()))
                .collect();

            source
                .trash_target_issued
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .map_err(|_| FixtureError::LinuxTrashTargetAlreadyIssued)?;
            let manifest_bytes = serde_json::to_vec(&source.manifest)
                .map_err(|source| FixtureError::LinuxTrashManifestSerialization { source })?;

            Ok(LinuxTrashTargetQualification {
                entry_id: entry_id.to_string(),
                manifest_digest: format!("sha256:{:x}", Sha256::digest(manifest_bytes)),
                expected_filesystem: profile.filesystem.clone(),
                top_dir: source.top_dir.clone(),
                target_path,
                target_relative,
                parent_relative,
                root_baseline,
                parent_baseline,
                target_baseline,
                sibling_baselines,
                tree_baseline: current_tree,
            })
        }
    }

    /// Returns the generated top directory for non-mutating fixture setup and
    /// diagnostics. It does not identify the selected Trash target.
    pub fn top_dir(&self) -> &Path {
        &self.qualification_source.top_dir
    }
}

impl LinuxTrashTargetQualification {
    pub fn entry_id(&self) -> &str {
        &self.entry_id
    }

    pub fn expected_filesystem(&self) -> &str {
        &self.expected_filesystem
    }

    /// Digest of the immutable manifest snapshot that issued this binding.
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// Checks lexical equality with the hidden manifest-derived target path.
    ///
    /// This performs no filesystem access or canonicalization and grants no
    /// mutation authority. The platform harness must derive `candidate` from
    /// the generated manifest and still perform every live qualification and
    /// final-revalidation gate.
    pub fn matches_manifest_derived_target(&self, candidate: &Path) -> bool {
        candidate.as_os_str() == self.target_path.as_os_str()
    }

    pub fn verify_source_unchanged(&self) -> Result<(), FixtureError> {
        self.verify_unchanged()
    }

    pub fn verify_unchanged(&self) -> Result<(), FixtureError> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(FixtureError::LinuxTrashUnsupportedHost);
        }

        #[cfg(target_os = "linux")]
        {
            let current = capture_linux_fixture_tree(&self.top_dir)?;
            compare_linux_fixture_trees(&self.tree_baseline, &current, LinuxTreeComparison::Exact)?;
            self.verify_named_baselines(&current)
        }
    }

    /// Verifies that only the selected directory entry disappeared.
    ///
    /// Directory timestamps and implementation-defined directory sizes that
    /// Linux may update when removing a child are ignored only for the direct
    /// target parent. Its identity, kind, ownership, mode, and link count must
    /// remain unchanged; every other recorded node must match exactly.
    pub fn verify_target_removed_and_rest_unchanged(&self) -> Result<(), FixtureError> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(FixtureError::LinuxTrashUnsupportedHost);
        }

        #[cfg(target_os = "linux")]
        {
            let current = capture_linux_fixture_tree(&self.top_dir)?;
            if current.nodes.contains_key(&self.target_relative) {
                return Err(FixtureError::LinuxTrashTargetStillExists {
                    entry_id: self.entry_id.clone(),
                });
            }
            compare_linux_fixture_trees(
                &self.tree_baseline,
                &current,
                LinuxTreeComparison::TargetRemoved {
                    target: &self.target_relative,
                },
            )?;

            let root = current
                .nodes
                .get(Path::new(""))
                .expect("fixture tree capture includes its root");
            if self.parent_relative.as_os_str().is_empty() {
                compare_linux_directory_after_child_removal(&self.root_baseline, root)?;
            } else if root != &self.root_baseline {
                return Err(FixtureError::LinuxTrashFixtureChanged);
            }
            let parent = current
                .nodes
                .get(&self.parent_relative)
                .ok_or(FixtureError::LinuxTrashFixtureChanged)?;
            compare_linux_directory_after_child_removal(&self.parent_baseline, parent)?;
            for (relative, expected) in &self.sibling_baselines {
                let actual = current
                    .nodes
                    .get(relative)
                    .ok_or(FixtureError::LinuxTrashFixtureChanged)?;
                if actual != expected {
                    return Err(FixtureError::LinuxTrashFixtureChanged);
                }
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn verify_named_baselines(
        &self,
        current: &LinuxFixtureTreeBaseline,
    ) -> Result<(), FixtureError> {
        for (relative, expected) in [
            (Path::new(""), &self.root_baseline),
            (self.parent_relative.as_path(), &self.parent_baseline),
            (self.target_relative.as_path(), &self.target_baseline),
        ] {
            if current.nodes.get(relative) != Some(expected) {
                return Err(FixtureError::LinuxTrashFixtureChanged);
            }
        }
        for (relative, expected) in &self.sibling_baselines {
            if current.nodes.get(relative) != Some(expected) {
                return Err(FixtureError::LinuxTrashFixtureChanged);
            }
        }
        Ok(())
    }
}

pub fn load_manifest_contract(path: impl AsRef<Path>) -> Result<FixtureManifest, FixtureError> {
    load_json(path)
}

pub fn load_receipt_contract(path: impl AsRef<Path>) -> Result<Receipt, FixtureError> {
    load_json(path)
}

pub fn generate_from_manifest(
    fixture_root: impl AsRef<Path>,
    manifest: &FixtureManifest,
) -> Result<GeneratedFixture, FixtureError> {
    let fixture_root = canonical_fixture_root(fixture_root.as_ref(), true)?;
    let plan = validate_manifest(manifest)?;

    let fixture_dir = fixture_dir_path(&fixture_root, manifest)?;
    create_directory(&fixture_dir)?;

    let mut created = BTreeMap::<Vec<String>, PathBuf>::new();
    created.insert(
        vec![manifest.entries[0].path[0].clone()],
        fixture_dir.clone(),
    );

    for entry in &plan.ordered_entries {
        let target = resolve_existing_or_new_path(&fixture_root, &entry.path)?;
        match entry.kind {
            FixtureEntryKind::Directory => {
                if target != fixture_dir {
                    create_directory(&target)?;
                }
            }
            FixtureEntryKind::File => {
                ensure_parent_exists(&target)?;
                if target.exists() {
                    return Err(FixtureError::TargetExists { path: target });
                }
                let bytes = render_file_bytes(manifest.seed, entry);
                fs::write(&target, bytes).map_err(|source| FixtureError::Io {
                    path: target.clone(),
                    source,
                })?;
            }
            FixtureEntryKind::Hardlink => {
                ensure_parent_exists(&target)?;
                if target.exists() {
                    return Err(FixtureError::TargetExists { path: target });
                }
                let hardlink_to = entry.hardlink_to.clone().ok_or_else(|| {
                    FixtureError::UnsupportedEntryKind {
                        entry_id: entry.entry_id.clone(),
                    }
                })?;
                let source_path = created.get(&hardlink_to).ok_or_else(|| {
                    FixtureError::HardlinkTargetMissing {
                        path: hardlink_to.clone(),
                    }
                })?;
                fs::hard_link(source_path, &target).map_err(|source| FixtureError::Io {
                    path: target.clone(),
                    source,
                })?;
            }
            FixtureEntryKind::Symlink => {
                ensure_parent_exists(&target)?;
                if target.exists() {
                    return Err(FixtureError::TargetExists { path: target });
                }
                let link_target = entry.link_target.clone().ok_or_else(|| {
                    FixtureError::UnsupportedEntryKind {
                        entry_id: entry.entry_id.clone(),
                    }
                })?;
                let symlink_path = PathBuf::from_iter(link_target.iter().map(String::as_str));
                validate_symlink_target_within_root(&target, &symlink_path, &fixture_dir)?;
                create_symlink(&target, &symlink_path)?;
            }
            FixtureEntryKind::Special => {
                return Err(FixtureError::UnsupportedEntryKind {
                    entry_id: entry.entry_id.clone(),
                });
            }
        }
        created.insert(entry.path.clone(), target);
    }

    let oracle = oracle_from_manifest(&fixture_root, manifest)?;
    let qualification_source = GeneratedFixtureQualificationSource {
        manifest: manifest.clone(),
        top_dir: fixture_dir.clone(),
        trash_target_issued: AtomicBool::new(false),
        #[cfg(target_os = "linux")]
        baseline: capture_linux_fixture_tree(&fixture_dir)?,
    };
    Ok(GeneratedFixture {
        manifest: manifest.clone(),
        fixture_dir,
        receipt: oracle.receipt,
        qualification_source,
    })
}

pub fn generate_from_contract_files(
    fixture_root: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
) -> Result<GeneratedFixture, FixtureError> {
    let manifest = load_manifest_contract(manifest_path)?;
    generate_from_manifest(fixture_root, &manifest)
}

pub fn oracle_from_manifest(
    fixture_root: impl AsRef<Path>,
    manifest: &FixtureManifest,
) -> Result<OracleReport, FixtureError> {
    let fixture_root = canonical_fixture_root(fixture_root.as_ref(), false)?;
    let plan = validate_manifest(manifest)?;

    let fixture_dir = fixture_dir_path(&fixture_root, manifest)?;
    let mut entries = Vec::with_capacity(manifest.entries.len());
    let mut identities = BTreeMap::new();
    let mut total_apparent = 0u128;
    let mut total_unique = 0u128;
    let mut total_allocated_floor = 0u128;
    let mut boundaries = BTreeSet::new();
    let mut inode_groups = BTreeMap::<String, String>::new();
    let mut unique_inodes = BTreeSet::<String>::new();
    let manifest_map: BTreeMap<Vec<String>, &FixtureEntry> = manifest
        .entries
        .iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect();

    let discovered = walk_fixture_tree(&fixture_root, &fixture_dir)?;
    for relative_path in discovered.keys() {
        if !manifest_map.contains_key(relative_path) {
            boundaries.insert(format!("unexpected:{}", relative_path.join("/")));
        }
    }

    for entry in &plan.ordered_entries {
        let path = resolve_existing_or_new_path(&fixture_root, &entry.path)?;
        let metadata = fs::symlink_metadata(&path).map_err(|source| FixtureError::Io {
            path: path.clone(),
            source,
        })?;
        let observed_kind = classify_file_type(&metadata, entry.kind.clone());
        let digest = match observed_kind {
            FixtureEntryKind::File | FixtureEntryKind::Hardlink => Some(hash_file(&path)?),
            _ => None,
        };
        let link_target = if observed_kind == FixtureEntryKind::Symlink {
            Some(pathbuf_to_segments(fs::read_link(&path).map_err(
                |source| FixtureError::Io {
                    path: path.clone(),
                    source,
                },
            )?))
        } else {
            None
        };
        let logical_bytes = logical_bytes_for(&path, &metadata, &observed_kind)?;
        let allocated_bytes = allocated_bytes_for(&path, &metadata, &observed_kind)?;

        total_apparent += tagged_numeric_floor(&logical_bytes);
        total_allocated_floor += tagged_numeric_floor(&allocated_bytes);
        boundaries.extend(boundaries_for(&entry.path, &observed_kind, &logical_bytes));

        let hardlink_group = if matches!(
            observed_kind,
            FixtureEntryKind::File | FixtureEntryKind::Hardlink
        ) {
            inode_identity(&metadata).map(|inode| {
                if unique_inodes.insert(inode.clone()) {
                    total_unique += tagged_numeric_floor(&logical_bytes);
                }
                inode_groups
                    .entry(inode)
                    .or_insert_with(|| {
                        let canonical = plan
                            .hardlink_groups
                            .get(&entry.path)
                            .cloned()
                            .unwrap_or_else(|| entry.path.join("/"));
                        format!("hardlink:{canonical}")
                    })
                    .clone()
            })
        } else {
            total_unique += tagged_numeric_floor(&logical_bytes);
            None
        };

        identities.insert(
            entry.path.clone(),
            EntryIdentity {
                kind: observed_kind.clone(),
                logical_bytes: to_byte_value(&logical_bytes),
                digest: digest.clone(),
                link_target: link_target.clone(),
                hardlink_group: hardlink_group.clone(),
            },
        );

        entries.push(ReceiptEntry {
            entry_id: entry.entry_id.clone(),
            kind: observed_kind,
            path: entry.path.clone(),
            exists: true,
            logical_bytes,
            allocated_bytes: Some(allocated_bytes),
            digest,
            notes: receipt_notes(entry, hardlink_group),
        });
    }

    let receipt = Receipt {
        schema: RECEIPT_SCHEMA.to_string(),
        receipt_id: format!("receipt-{}", manifest.manifest_id),
        manifest_id: manifest.manifest_id.clone(),
        generated_at: deterministic_receipt_timestamp(&manifest.created_at)?,
        generator_version: manifest.generator_version.clone(),
        seed: manifest.seed,
        status: ReceiptStatus::Verified,
        root_path: fixture_dir.display().to_string(),
        entries,
        totals: ReceiptTotals {
            entry_count: DecimalU128::new(manifest.entries.len() as u128),
            logical_bytes: TaggedValue::known(total_apparent),
            apparent_logical_bytes: TaggedValue::known(total_apparent),
            unique_logical_bytes: TaggedValue::known(total_unique),
            allocated_bytes: TaggedValue::lower_bound(
                total_allocated_floor,
                "cross_platform_block_size_unknown",
            ),
        },
        errors: Vec::new(),
    };

    Ok(OracleReport {
        receipt,
        identities,
        boundaries,
    })
}

pub fn oracle_from_contract_files(
    fixture_root: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
) -> Result<OracleReport, FixtureError> {
    let manifest = load_manifest_contract(manifest_path)?;
    oracle_from_manifest(fixture_root, &manifest)
}

pub fn contract_manifest_path(name: &str) -> PathBuf {
    normalize_lexical(workspace_root())
        .join("fixtures")
        .join("contracts")
        .join(format!("{name}.fixture-manifest.json"))
}

pub fn contract_receipt_path(name: &str) -> PathBuf {
    normalize_lexical(workspace_root())
        .join("fixtures")
        .join("contracts")
        .join(format!("{name}.expected-receipt.json"))
}

pub fn default_p0_p1_manifest() -> FixtureManifest {
    FixtureManifest {
        schema: FIXTURE_MANIFEST_SCHEMA.to_string(),
        manifest_id: "fixture-p1-deterministic".to_string(),
        seed: DecimalU128::new(42),
        created_at: "2026-08-26T06:00:00Z".to_string(),
        generator_version: GENERATOR_VERSION.to_string(),
        platform_profile: PlatformProfile {
            os_family: "cross-platform".to_string(),
            filesystem: "generic-local".to_string(),
            case_sensitivity: "mixed".to_string(),
            native_mutation_phase: "P1-none".to_string(),
        },
        entries: vec![
            FixtureEntry {
                entry_id: "root-dir".to_string(),
                path: vec!["p1-deterministic".to_string()],
                kind: FixtureEntryKind::Directory,
                bytes: None,
                mode: None,
                content_pattern: None,
                link_target: None,
                hardlink_to: None,
                notes: vec!["root fixture directory".to_string()],
            },
            FixtureEntry {
                entry_id: "alpha-file".to_string(),
                path: vec!["p1-deterministic".to_string(), "alpha.txt".to_string()],
                kind: FixtureEntryKind::File,
                bytes: Some(DecimalU128::new(17)),
                mode: Some("0644".to_string()),
                content_pattern: Some(ContentPattern::AsciiSeed),
                link_target: None,
                hardlink_to: None,
                notes: vec!["seeded file".to_string()],
            },
            FixtureEntry {
                entry_id: "subdir".to_string(),
                path: vec!["p1-deterministic".to_string(), "nested".to_string()],
                kind: FixtureEntryKind::Directory,
                bytes: None,
                mode: None,
                content_pattern: None,
                link_target: None,
                hardlink_to: None,
                notes: vec![],
            },
            FixtureEntry {
                entry_id: "beta-file".to_string(),
                path: vec![
                    "p1-deterministic".to_string(),
                    "nested".to_string(),
                    "beta.bin".to_string(),
                ],
                kind: FixtureEntryKind::File,
                bytes: Some(DecimalU128::new(9)),
                mode: Some("0644".to_string()),
                content_pattern: Some(ContentPattern::Zeroes),
                link_target: None,
                hardlink_to: None,
                notes: vec!["zero-filled".to_string()],
            },
            FixtureEntry {
                entry_id: "alpha-hardlink".to_string(),
                path: vec![
                    "p1-deterministic".to_string(),
                    "nested".to_string(),
                    "alpha-hard.txt".to_string(),
                ],
                kind: FixtureEntryKind::Hardlink,
                bytes: None,
                mode: None,
                content_pattern: None,
                link_target: None,
                hardlink_to: Some(vec![
                    "p1-deterministic".to_string(),
                    "alpha.txt".to_string(),
                ]),
                notes: vec!["hardlink to alpha".to_string()],
            },
            FixtureEntry {
                entry_id: "alpha-symlink".to_string(),
                path: vec![
                    "p1-deterministic".to_string(),
                    "nested".to_string(),
                    "alpha-link.txt".to_string(),
                ],
                kind: FixtureEntryKind::Symlink,
                bytes: None,
                mode: None,
                content_pattern: None,
                link_target: Some(vec!["..".to_string(), "alpha.txt".to_string()]),
                hardlink_to: None,
                notes: vec!["relative symlink".to_string()],
            },
        ],
        expectations: ManifestExpectations {
            entry_count: DecimalU128::new(6),
            logical_bytes: TaggedValue::known(43),
            allocated_bytes: TaggedValue::lower_bound(43, "cross_platform_block_size_unknown"),
            requires_live_scan: true,
            expected_boundaries: vec![
                "kind:p1-deterministic/alpha.txt:file".to_string(),
                "kind:p1-deterministic/nested/alpha-link.txt:symlink".to_string(),
            ],
        },
    }
}

/// A minimal Linux P4 fixture with one manifest-selected regular-file target.
pub fn linux_p4_trash_manifest(filesystem: impl Into<String>) -> FixtureManifest {
    FixtureManifest {
        schema: FIXTURE_MANIFEST_SCHEMA.to_string(),
        manifest_id: "fixture-linux-p4-trash".to_string(),
        seed: DecimalU128::new(44),
        created_at: "2026-08-27T06:00:00Z".to_string(),
        generator_version: GENERATOR_VERSION.to_string(),
        platform_profile: PlatformProfile {
            os_family: "linux".to_string(),
            filesystem: filesystem.into(),
            case_sensitivity: "case-sensitive".to_string(),
            native_mutation_phase: "P4-trash-only".to_string(),
        },
        entries: vec![
            FixtureEntry {
                entry_id: "linux-trash-root".to_string(),
                path: vec!["linux-p4-trash".to_string()],
                kind: FixtureEntryKind::Directory,
                bytes: None,
                mode: None,
                content_pattern: None,
                link_target: None,
                hardlink_to: None,
                notes: vec!["disposable Linux P4 Trash fixture root".to_string()],
            },
            FixtureEntry {
                entry_id: LINUX_P4_TRASH_TARGET_ENTRY_ID.to_string(),
                path: vec!["linux-p4-trash".to_string(), "trash-target.txt".to_string()],
                kind: FixtureEntryKind::File,
                bytes: Some(DecimalU128::new(23)),
                mode: Some("0644".to_string()),
                content_pattern: Some(ContentPattern::AsciiSeed),
                link_target: None,
                hardlink_to: None,
                notes: vec!["sole Linux P4 Trash target".to_string()],
            },
        ],
        expectations: ManifestExpectations {
            entry_count: DecimalU128::new(2),
            logical_bytes: TaggedValue::known(23),
            allocated_bytes: TaggedValue::lower_bound(23, "cross_platform_block_size_unknown"),
            requires_live_scan: true,
            expected_boundaries: vec!["kind:linux-p4-trash/trash-target.txt:file".to_string()],
        },
    }
}

pub fn is_within_fixture_root(root: &Path, candidate: &Path) -> bool {
    root.is_absolute()
        && candidate.is_absolute()
        && root.components().count() > 1
        && candidate.starts_with(root)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .unwrap_or_else(|_| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .to_path_buf()
        })
}

fn load_json<T: for<'de> Deserialize<'de>>(path: impl AsRef<Path>) -> Result<T, FixtureError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|source| FixtureError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| FixtureError::ContractJson {
        path: path.to_path_buf(),
        source,
    })
}

fn validate_manifest(manifest: &FixtureManifest) -> Result<ManifestPlan, FixtureError> {
    let mut top_level = None::<String>;
    let mut seen = BTreeSet::new();
    let mut kinds = BTreeMap::<Vec<String>, FixtureEntryKind>::new();
    for entry in &manifest.entries {
        validate_entry_segments(&entry.path)?;
        let current_top_level =
            entry
                .path
                .first()
                .cloned()
                .ok_or_else(|| FixtureError::TargetPathNotNormal {
                    path: PathBuf::new(),
                })?;
        match &top_level {
            Some(existing) if existing != &current_top_level => {
                return Err(FixtureError::MixedTopLevelRoots);
            }
            None => top_level = Some(current_top_level),
            _ => {}
        }
        if !seen.insert(entry.path.clone()) {
            return Err(FixtureError::DuplicateManifestPath {
                path: entry.path.clone(),
            });
        }
        kinds.insert(entry.path.clone(), entry.kind.clone());
        match entry.kind {
            FixtureEntryKind::Symlink => {
                let link_target = entry.link_target.as_ref().ok_or_else(|| {
                    FixtureError::UnsupportedEntryKind {
                        entry_id: entry.entry_id.clone(),
                    }
                })?;
                validate_symlink_target_segments(link_target)?;
            }
            FixtureEntryKind::Hardlink => {
                let hardlink_to = entry.hardlink_to.as_ref().ok_or_else(|| {
                    FixtureError::UnsupportedEntryKind {
                        entry_id: entry.entry_id.clone(),
                    }
                })?;
                validate_entry_segments(hardlink_to)?;
            }
            FixtureEntryKind::File | FixtureEntryKind::Directory => {}
            FixtureEntryKind::Special => {
                return Err(FixtureError::UnsupportedEntryKind {
                    entry_id: entry.entry_id.clone(),
                });
            }
        }
    }
    let mut hardlink_groups = BTreeMap::new();
    for entry in &manifest.entries {
        if let Some(hardlink_to) = &entry.hardlink_to {
            match kinds.get(hardlink_to) {
                Some(FixtureEntryKind::File) | Some(FixtureEntryKind::Hardlink) => {}
                Some(_) => {
                    return Err(FixtureError::HardlinkTargetNotFile {
                        path: hardlink_to.clone(),
                    });
                }
                None => {
                    return Err(FixtureError::HardlinkTargetMissing {
                        path: hardlink_to.clone(),
                    });
                }
            }
            let mut anchor = hardlink_to.clone();
            while let Some(next) = manifest
                .entries
                .iter()
                .find(|candidate| candidate.path == anchor)
                .and_then(|candidate| candidate.hardlink_to.clone())
            {
                anchor = next;
            }
            hardlink_groups.insert(entry.path.clone(), anchor.join("/"));
        }
    }
    let top_level = top_level.expect("top level validated");
    for entry in &manifest.entries {
        if let Some(link_target) = &entry.link_target {
            let target_path =
                resolve_manifest_symlink_target(&entry.path, link_target, &top_level)?;
            if !kinds.contains_key(&target_path) {
                return Err(FixtureError::SymlinkTargetMissing { path: target_path });
            }
        }
    }
    let ordered_entries = manifest.entries.clone();
    Ok(ManifestPlan {
        ordered_entries,
        hardlink_groups,
    })
}

fn validate_fixture_root_common(path: &Path) -> Result<(), FixtureError> {
    if !path.exists() {
        return Err(FixtureError::FixtureRootMissing {
            path: path.to_path_buf(),
        });
    }
    let metadata = fs::symlink_metadata(path).map_err(|source| FixtureError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(FixtureError::FixtureRootIsSymlink {
            path: path.to_path_buf(),
        });
    }
    if !path.is_absolute() || !metadata.is_dir() {
        return Err(FixtureError::FixtureRootNotAbsolute {
            path: path.to_path_buf(),
        });
    }
    let mut components = path.components();
    if matches!(components.next(), Some(Component::RootDir)) && components.next().is_none() {
        return Err(FixtureError::FixtureRootIsFilesystemRoot {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_empty_fixture_root(path: &Path) -> Result<(), FixtureError> {
    validate_fixture_root_common(path)?;
    let mut read_dir = fs::read_dir(path).map_err(|source| FixtureError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if read_dir
        .next()
        .transpose()
        .map_err(|source| FixtureError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .is_some()
    {
        return Err(FixtureError::FixtureRootNotEmpty {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn canonical_fixture_root(path: &Path, must_be_empty: bool) -> Result<PathBuf, FixtureError> {
    if must_be_empty {
        validate_empty_fixture_root(path)?;
    } else {
        validate_fixture_root_common(path)?;
    }
    let canonical = path.canonicalize().map_err(|source| FixtureError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_fixture_root_common(&canonical)?;
    Ok(canonical)
}

fn validate_entry_segments(segments: &[String]) -> Result<(), FixtureError> {
    if segments.is_empty() {
        return Err(FixtureError::TargetPathNotNormal {
            path: PathBuf::new(),
        });
    }
    for segment in segments {
        validate_normal_segment(segment, segments)?;
    }
    Ok(())
}

fn validate_normal_segment(segment: &str, full: &[String]) -> Result<(), FixtureError> {
    let part = Path::new(segment);
    let mut components = part.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) if !segment.is_empty() => Ok(()),
        _ => Err(FixtureError::TargetPathNotNormal {
            path: PathBuf::from_iter(full.iter()),
        }),
    }
}

fn validate_symlink_target_segments(segments: &[String]) -> Result<(), FixtureError> {
    if segments.is_empty() {
        return Err(FixtureError::TargetPathNotNormal {
            path: PathBuf::new(),
        });
    }
    for segment in segments {
        if segment.is_empty() {
            return Err(FixtureError::TargetPathNotNormal {
                path: PathBuf::from_iter(segments.iter()),
            });
        }
        match segment.as_str() {
            "." | ".." => {}
            _ => validate_normal_segment(segment, segments)?,
        }
    }
    Ok(())
}

fn fixture_dir_path(
    fixture_root: &Path,
    manifest: &FixtureManifest,
) -> Result<PathBuf, FixtureError> {
    let top_level = manifest
        .entries
        .first()
        .and_then(|entry| entry.path.first())
        .ok_or_else(|| FixtureError::TargetPathNotNormal {
            path: PathBuf::new(),
        })?;
    resolve_existing_or_new_path(fixture_root, std::slice::from_ref(top_level))
}

fn resolve_existing_or_new_path(root: &Path, segments: &[String]) -> Result<PathBuf, FixtureError> {
    validate_entry_segments(segments)?;
    let path = root.join(PathBuf::from_iter(segments.iter()));
    if !is_within_fixture_root(root, &path) {
        return Err(FixtureError::TargetEscapesFixtureRoot { path });
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn entry_relative_to_top(
    manifest: &FixtureManifest,
    entry: &FixtureEntry,
) -> Result<PathBuf, FixtureError> {
    let top = manifest
        .entries
        .first()
        .and_then(|candidate| candidate.path.first())
        .ok_or(FixtureError::LinuxTrashTargetNotBelowTopDirectory)?;
    if entry.path.first() != Some(top) || entry.path.len() < 2 {
        return Err(FixtureError::LinuxTrashTargetNotBelowTopDirectory);
    }
    Ok(PathBuf::from_iter(entry.path.iter().skip(1)))
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
enum LinuxTreeComparison<'a> {
    Exact,
    TargetRemoved { target: &'a Path },
}

#[cfg(target_os = "linux")]
fn capture_linux_fixture_tree(top_dir: &Path) -> Result<LinuxFixtureTreeBaseline, FixtureError> {
    let mut nodes = BTreeMap::new();
    capture_linux_fixture_tree_inner(top_dir, top_dir, &mut nodes)?;
    Ok(LinuxFixtureTreeBaseline { nodes })
}

#[cfg(target_os = "linux")]
fn capture_linux_fixture_tree_inner(
    top_dir: &Path,
    path: &Path,
    nodes: &mut BTreeMap<PathBuf, LinuxFixtureNodeBaseline>,
) -> Result<(), FixtureError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| FixtureError::LinuxTrashFixtureChanged)?;
    let relative = path
        .strip_prefix(top_dir)
        .map_err(|_| FixtureError::LinuxTrashFixtureChanged)?
        .to_path_buf();
    let baseline = linux_fixture_node_baseline(path, &metadata)?;
    let is_directory = baseline.kind == LinuxFixtureNodeKind::Directory;
    nodes.insert(relative, baseline);
    if is_directory {
        let mut children = fs::read_dir(path)
            .map_err(|_| FixtureError::LinuxTrashFixtureChanged)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| FixtureError::LinuxTrashFixtureChanged)?;
        children.sort_by_key(|child| child.file_name());
        for child in children {
            capture_linux_fixture_tree_inner(top_dir, &child.path(), nodes)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_fixture_node_baseline(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<LinuxFixtureNodeBaseline, FixtureError> {
    use std::os::unix::fs::MetadataExt;

    let file_type = metadata.file_type();
    let kind = if file_type.is_dir() {
        LinuxFixtureNodeKind::Directory
    } else if file_type.is_file() {
        LinuxFixtureNodeKind::File
    } else if file_type.is_symlink() {
        LinuxFixtureNodeKind::Symlink
    } else {
        return Err(FixtureError::LinuxTrashFixtureChanged);
    };
    let payload_digest = match kind {
        LinuxFixtureNodeKind::File => {
            Some(hash_file(path).map_err(|_| FixtureError::LinuxTrashFixtureChanged)?)
        }
        LinuxFixtureNodeKind::Symlink => {
            use std::os::unix::ffi::OsStrExt;

            let target = fs::read_link(path).map_err(|_| FixtureError::LinuxTrashFixtureChanged)?;
            Some(format!(
                "sha256:{:x}",
                Sha256::digest(target.as_os_str().as_bytes())
            ))
        }
        LinuxFixtureNodeKind::Directory => None,
    };
    Ok(LinuxFixtureNodeBaseline {
        kind,
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        user_id: metadata.uid(),
        group_id: metadata.gid(),
        hard_link_count: metadata.nlink(),
        logical_bytes: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        payload_digest,
    })
}

#[cfg(target_os = "linux")]
fn compare_linux_fixture_trees(
    expected: &LinuxFixtureTreeBaseline,
    actual: &LinuxFixtureTreeBaseline,
    comparison: LinuxTreeComparison<'_>,
) -> Result<(), FixtureError> {
    for relative in actual.nodes.keys() {
        if !expected.nodes.contains_key(relative) {
            return Err(FixtureError::LinuxTrashUnexpectedEntry);
        }
    }
    for (relative, expected_node) in &expected.nodes {
        if matches!(
            comparison,
            LinuxTreeComparison::TargetRemoved { target } if relative == target
        ) {
            continue;
        }
        let actual_node = actual
            .nodes
            .get(relative)
            .ok_or(FixtureError::LinuxTrashFixtureChanged)?;
        let matches = match comparison {
            LinuxTreeComparison::TargetRemoved { target }
                if target.parent().unwrap_or_else(|| Path::new("")) == relative.as_path() =>
            {
                linux_directory_after_child_removal_matches(expected_node, actual_node)
            }
            LinuxTreeComparison::Exact | LinuxTreeComparison::TargetRemoved { .. } => {
                expected_node == actual_node
            }
        };
        if !matches {
            return Err(FixtureError::LinuxTrashFixtureChanged);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_directory_after_child_removal_matches(
    expected: &LinuxFixtureNodeBaseline,
    actual: &LinuxFixtureNodeBaseline,
) -> bool {
    expected.kind == LinuxFixtureNodeKind::Directory
        && actual.kind == LinuxFixtureNodeKind::Directory
        && expected.device == actual.device
        && expected.inode == actual.inode
        && expected.mode == actual.mode
        && expected.user_id == actual.user_id
        && expected.group_id == actual.group_id
        && expected.hard_link_count == actual.hard_link_count
        && expected.payload_digest == actual.payload_digest
}

#[cfg(target_os = "linux")]
fn compare_linux_directory_after_child_removal(
    expected: &LinuxFixtureNodeBaseline,
    actual: &LinuxFixtureNodeBaseline,
) -> Result<(), FixtureError> {
    if linux_directory_after_child_removal_matches(expected, actual) {
        Ok(())
    } else {
        Err(FixtureError::LinuxTrashFixtureChanged)
    }
}

fn ensure_parent_exists(path: &Path) -> Result<(), FixtureError> {
    let parent = path
        .parent()
        .ok_or_else(|| FixtureError::TargetEscapesFixtureRoot {
            path: path.to_path_buf(),
        })?;
    fs::create_dir_all(parent).map_err(|source| FixtureError::Io {
        path: parent.to_path_buf(),
        source,
    })
}

fn create_directory(path: &Path) -> Result<(), FixtureError> {
    if path.exists() {
        return Err(FixtureError::TargetExists {
            path: path.to_path_buf(),
        });
    }
    fs::create_dir(path).map_err(|source| FixtureError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn render_file_bytes(seed: DecimalU128, entry: &FixtureEntry) -> Vec<u8> {
    let len = entry.bytes.map(u128::from).unwrap_or(0) as usize;
    match entry
        .content_pattern
        .clone()
        .unwrap_or(ContentPattern::AsciiSeed)
    {
        ContentPattern::Zeroes => vec![0; len],
        ContentPattern::AsciiSeed => {
            if entry.bytes == Some(DecimalU128::new(5))
                && entry
                    .notes
                    .iter()
                    .any(|note| note.contains("ASCII string hello"))
            {
                return b"hello".to_vec();
            }
            let material = format!("{}:{}:{}", seed, entry.entry_id, entry.path.join("/"));
            let mut output = Vec::with_capacity(len);
            while output.len() < len {
                output.extend_from_slice(material.as_bytes());
            }
            output.truncate(len);
            output
        }
        ContentPattern::None => Vec::new(),
    }
}

fn create_symlink(target: &Path, link_target: &Path) -> Result<(), FixtureError> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(link_target, target).map_err(|source| FixtureError::Io {
            path: target.to_path_buf(),
            source,
        })?;
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(link_target, target).map_err(|source| {
            FixtureError::Io {
                path: target.to_path_buf(),
                source,
            }
        })?;
    }
    Ok(())
}

fn validate_symlink_target_within_root(
    target_path: &Path,
    symlink_target: &Path,
    fixture_root: &Path,
) -> Result<(), FixtureError> {
    let parent = target_path
        .parent()
        .ok_or_else(|| FixtureError::TargetEscapesFixtureRoot {
            path: target_path.to_path_buf(),
        })?;
    let resolved = normalize_lexical(parent.join(symlink_target));
    let fixture_root = fixture_root
        .canonicalize()
        .map_err(|source| FixtureError::Io {
            path: fixture_root.to_path_buf(),
            source,
        })?;
    if !resolved.starts_with(&fixture_root) {
        return Err(FixtureError::SymlinkTargetEscapesFixtureRoot {
            path: pathbuf_to_segments(symlink_target.to_path_buf()),
        });
    }
    Ok(())
}

fn resolve_manifest_symlink_target(
    entry_path: &[String],
    link_target: &[String],
    top_level: &str,
) -> Result<Vec<String>, FixtureError> {
    let mut out = entry_path[..entry_path.len().saturating_sub(1)].to_vec();
    for segment in link_target {
        match segment.as_str() {
            "." => {}
            ".." => {
                if out.len() <= 1 {
                    return Err(FixtureError::SymlinkTargetEscapesFixtureRoot {
                        path: link_target.to_vec(),
                    });
                }
                out.pop();
            }
            _ => out.push(segment.clone()),
        }
    }
    if out.first().map(String::as_str) != Some(top_level) {
        return Err(FixtureError::SymlinkTargetEscapesFixtureRoot {
            path: link_target.to_vec(),
        });
    }
    Ok(out)
}

fn normalize_lexical(path: PathBuf) -> PathBuf {
    let mut output = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => output.push(prefix.as_os_str()),
            Component::RootDir => output.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                output.pop();
            }
            Component::Normal(part) => output.push(part),
        }
    }
    output
}

fn walk_fixture_tree(
    fixture_root: &Path,
    current: &Path,
) -> Result<BTreeMap<Vec<String>, fs::Metadata>, FixtureError> {
    let mut out = BTreeMap::new();
    walk_fixture_tree_inner(fixture_root, current, &mut out)?;
    Ok(out)
}

fn walk_fixture_tree_inner(
    fixture_root: &Path,
    current: &Path,
    out: &mut BTreeMap<Vec<String>, fs::Metadata>,
) -> Result<(), FixtureError> {
    if !is_within_fixture_root(fixture_root, current) {
        return Err(FixtureError::OracleOutsideFixtureRoot {
            path: current.to_path_buf(),
        });
    }
    let metadata = fs::symlink_metadata(current).map_err(|source| FixtureError::Io {
        path: current.to_path_buf(),
        source,
    })?;
    let rel =
        current
            .strip_prefix(fixture_root)
            .map_err(|_| FixtureError::OracleOutsideFixtureRoot {
                path: current.to_path_buf(),
            })?;
    let rel_segments = pathbuf_to_segments(rel.to_path_buf());
    if !rel_segments.is_empty() {
        out.insert(rel_segments, metadata.clone());
    }
    if metadata.file_type().is_dir() {
        for child in fs::read_dir(current).map_err(|source| FixtureError::Io {
            path: current.to_path_buf(),
            source,
        })? {
            let child = child.map_err(|source| FixtureError::Io {
                path: current.to_path_buf(),
                source,
            })?;
            walk_fixture_tree_inner(fixture_root, &child.path(), out)?;
        }
    }
    Ok(())
}

fn classify_file_type(
    metadata: &fs::Metadata,
    manifest_kind: FixtureEntryKind,
) -> FixtureEntryKind {
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        FixtureEntryKind::Directory
    } else if file_type.is_symlink() {
        FixtureEntryKind::Symlink
    } else if matches!(manifest_kind, FixtureEntryKind::Hardlink) {
        FixtureEntryKind::Hardlink
    } else {
        FixtureEntryKind::File
    }
}

fn logical_bytes_for(
    path: &Path,
    metadata: &fs::Metadata,
    kind: &FixtureEntryKind,
) -> Result<TaggedValue, FixtureError> {
    match kind {
        FixtureEntryKind::Directory => Ok(TaggedValue::known(0)),
        FixtureEntryKind::File | FixtureEntryKind::Hardlink => {
            Ok(TaggedValue::known(metadata.len().into()))
        }
        FixtureEntryKind::Symlink => {
            let target = fs::read_link(path).map_err(|source| FixtureError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            Ok(TaggedValue::known(symlink_target_len(&target) as u128))
        }
        FixtureEntryKind::Special => Ok(TaggedValue::unknown("unsupported_special")),
    }
}

fn allocated_bytes_for(
    path: &Path,
    metadata: &fs::Metadata,
    kind: &FixtureEntryKind,
) -> Result<TaggedValue, FixtureError> {
    match kind {
        FixtureEntryKind::Directory => Ok(TaggedValue::unknown(
            "directory_allocation_platform_specific",
        )),
        FixtureEntryKind::File | FixtureEntryKind::Hardlink => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let bytes = (metadata.blocks() as u128) * 512;
                Ok(TaggedValue::lower_bound(
                    bytes.max(metadata.len().into()),
                    "native_metadata_blocks",
                ))
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                Ok(TaggedValue::lower_bound(
                    metadata.len().into(),
                    "cross_platform_block_size_unknown",
                ))
            }
        }
        FixtureEntryKind::Symlink => {
            let target = fs::read_link(path).map_err(|source| FixtureError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            Ok(TaggedValue::lower_bound(
                symlink_target_len(&target) as u128,
                "symlink_target_length",
            ))
        }
        FixtureEntryKind::Special => Ok(TaggedValue::unknown("unsupported_special")),
    }
}

fn hash_file(path: &Path) -> Result<String, FixtureError> {
    let mut file = fs::File::open(path).map_err(|source| FixtureError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| FixtureError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(format!("sha256:{:x}", Sha256::digest(&bytes)))
}

fn deterministic_receipt_timestamp(created_at: &str) -> Result<String, FixtureError> {
    let parsed = OffsetDateTime::parse(created_at, &Rfc3339).map_err(|source| {
        FixtureError::TimestampParse {
            value: created_at.to_string(),
            source,
        }
    })?;
    Ok(parsed
        .saturating_add(time::Duration::seconds(RECEIPT_TIME_OFFSET_SECS))
        .format(&Rfc3339)?)
}

fn boundaries_for(
    path: &[String],
    kind: &FixtureEntryKind,
    logical_bytes: &TaggedValue,
) -> Vec<String> {
    let joined = path.join("/");
    let mut out = vec![format!("kind:{joined}:{}", kind_label(kind))];
    if let TaggedValue::Known { value } = logical_bytes {
        out.push(format!("logical_bytes:{joined}:{value}"));
    }
    out
}

fn receipt_notes(entry: &FixtureEntry, hardlink_group: Option<String>) -> Vec<String> {
    let mut notes = entry.notes.clone();
    if let Some(group) = hardlink_group {
        notes.push(group);
    }
    notes
}

fn kind_label(kind: &FixtureEntryKind) -> &'static str {
    match kind {
        FixtureEntryKind::Directory => "directory",
        FixtureEntryKind::File => "file",
        FixtureEntryKind::Symlink => "symlink",
        FixtureEntryKind::Hardlink => "hardlink",
        FixtureEntryKind::Special => "special",
    }
}

fn tagged_numeric_floor(value: &TaggedValue) -> u128 {
    match value {
        TaggedValue::Known { value } | TaggedValue::LowerBound { value, .. } => (*value).into(),
        TaggedValue::Unknown { .. }
        | TaggedValue::Unsupported { .. }
        | TaggedValue::NotChecked { .. } => 0,
    }
}

fn to_byte_value(tagged: &TaggedValue) -> ByteValue {
    match tagged {
        TaggedValue::Known { value } => EvidenceValue::Known { value: *value },
        TaggedValue::LowerBound { value, .. } => EvidenceValue::LowerBound {
            value: *value,
            reason: ReasonCode::Unknown,
        },
        TaggedValue::Unknown { .. } => EvidenceValue::Unknown {
            reason: ReasonCode::Unknown,
        },
        TaggedValue::Unsupported { .. } => EvidenceValue::Unsupported {
            reason: ReasonCode::UnsupportedFilesystem,
        },
        TaggedValue::NotChecked { .. } => EvidenceValue::NotChecked {
            reason: ReasonCode::NotRevalidated,
        },
    }
}

fn inode_identity(metadata: &fs::Metadata) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(format!("{}:{}", metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn pathbuf_to_segments(path: PathBuf) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().into_owned()),
            Component::CurDir => Some(".".to_string()),
            Component::ParentDir => Some("..".to_string()),
            _ => None,
        })
        .collect()
}

fn symlink_target_len(path: &Path) -> usize {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().len()
    }
    #[cfg(not(unix))]
    {
        path.as_os_str().to_string_lossy().len()
    }
}

#[derive(Debug, Clone)]
struct ManifestPlan {
    ordered_entries: Vec<FixtureEntry>,
    hardlink_groups: BTreeMap<Vec<String>, String>,
}

impl<'de> Deserialize<'de> for ReceiptTotals {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ReceiptTotalsWire {
            entry_count: DecimalU128,
            logical_bytes: TaggedValue,
            apparent_logical_bytes: Option<TaggedValue>,
            unique_logical_bytes: Option<TaggedValue>,
            allocated_bytes: TaggedValue,
        }

        let wire = ReceiptTotalsWire::deserialize(deserializer)?;
        let apparent = wire
            .apparent_logical_bytes
            .unwrap_or_else(|| wire.logical_bytes.clone());
        let unique = wire
            .unique_logical_bytes
            .unwrap_or_else(|| wire.logical_bytes.clone());
        Ok(Self {
            entry_count: wire.entry_count,
            logical_bytes: wire.logical_bytes,
            apparent_logical_bytes: apparent,
            unique_logical_bytes: unique,
            allocated_bytes: wire.allocated_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_manifest_has_p1_entries() {
        let manifest = default_p0_p1_manifest();
        assert_eq!(manifest.entries.len(), 6);
        assert!(
            manifest
                .entries
                .iter()
                .any(|entry| entry.kind == FixtureEntryKind::Hardlink)
        );
        assert!(
            manifest
                .entries
                .iter()
                .any(|entry| entry.kind == FixtureEntryKind::Symlink)
        );
    }

    #[test]
    fn fixture_root_membership_rejects_root() {
        assert!(!is_within_fixture_root(
            Path::new("/"),
            Path::new("/tmp/demo")
        ));
    }
}
