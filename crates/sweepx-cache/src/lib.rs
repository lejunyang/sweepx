use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
#[cfg(unix)]
use std::ffi::{CStr, CString};
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sweepx_model::{
    ByteValue, CountValue, DecimalU128, DirectoryAggregate, EvidenceValue, FieldProvenance,
    NativeName, ReasonCode,
};
use thiserror::Error;

pub const PREVIEW_BYTE_CAP: u64 = 64 * 1024 * 1024;
pub const PREVIEW_RECORD_CAP: usize = 100_000;
pub const SPILL_THRESHOLD_BYTES: u64 = 96 * 1024 * 1024;
pub const SPILL_OPERATION_BYTE_CAP: u64 = 192 * 1024 * 1024;
pub const SPILL_GLOBAL_BYTE_CAP: u64 = 256 * 1024 * 1024;
pub const STATE_DIRECTORY_BYTE_CAP: u64 = 512 * 1024 * 1024;
pub const TOP_HEAVY_CHILDREN: usize = 64;
pub const HEAVY_LEAF_THRESHOLD_BYTES: u64 = 32 * 1024 * 1024;
pub const STORED_PREVIEW_SCHEMA: &str = "sweepx.preview.cache/v1";
const CHECKSUM_DOMAIN: &[u8] = b"SweepX sparse preview generation v1\0";
const MAX_GENERATION_ID_BYTES: usize = 128;
const INSPECT_DIRECTORY_ENTRY_LIMIT: usize = 256;
const INSPECT_CURRENT_POINTER_BYTE_LIMIT: u64 = 64 * 1024;
const INSPECT_GENERATION_BYTE_LIMIT: u64 = PREVIEW_BYTE_CAP + (1024 * 1024);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewKind {
    Root,
    Ancestor,
    Directory,
    Leaf,
    Error,
    Boundary,
    Others,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewRole {
    TopHeavyChild,
    HeavyLeaf,
    Error,
    Boundary,
    RequiredAncestor,
    Root,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewSummary {
    pub kind: PreviewKind,
    pub parent_id: Option<String>,
    pub entry_id: String,
    pub native_name: NativeName,
    pub display_name: String,
    pub logical_bytes: ByteValue,
    pub allocated_bytes: ByteValue,
    pub direct_child_count: CountValue,
    pub recursive_entry_count: CountValue,
    pub aggregate: Option<DirectoryAggregate>,
    pub coverage: PreviewCoverage,
    pub selectable: bool,
    pub roles: BTreeSet<PreviewRole>,
    pub provenance: FieldProvenance,
}

impl PreviewSummary {
    pub fn estimated_bytes(&self) -> usize {
        serde_json::to_vec(self)
            .expect("preview summary serialization must succeed")
            .len()
    }

    pub fn is_mandatory(&self) -> bool {
        matches!(
            self.kind,
            PreviewKind::Root
                | PreviewKind::Ancestor
                | PreviewKind::Error
                | PreviewKind::Boundary
                | PreviewKind::Others
        )
    }

    pub fn is_directory(&self) -> bool {
        matches!(
            self.kind,
            PreviewKind::Root | PreviewKind::Ancestor | PreviewKind::Directory
        )
    }

    fn preview_rank_bytes(&self) -> Option<u128> {
        evidence_to_u128(&self.allocated_bytes).or_else(|| evidence_to_u128(&self.logical_bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewCoverage {
    pub complete: bool,
    pub details_lost: bool,
    pub incomplete_reasons: Vec<ReasonCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentPreview {
    pub parent_id: String,
    pub retained: Vec<PreviewSummary>,
    pub others: Option<PreviewSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactedPreview {
    pub parents: BTreeMap<String, ParentPreview>,
    pub total_estimated_bytes: usize,
    pub total_records: usize,
    pub visible_resource_limit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewBudgets {
    pub preview_byte_cap: usize,
    pub preview_record_cap: usize,
    pub spill_threshold_bytes: u64,
    pub spill_operation_byte_cap: u64,
    pub spill_global_byte_cap: u64,
    pub state_directory_byte_cap: u64,
}

impl Default for PreviewBudgets {
    fn default() -> Self {
        Self {
            preview_byte_cap: PREVIEW_BYTE_CAP as usize,
            preview_record_cap: PREVIEW_RECORD_CAP,
            spill_threshold_bytes: SPILL_THRESHOLD_BYTES,
            spill_operation_byte_cap: SPILL_OPERATION_BYTE_CAP,
            spill_global_byte_cap: SPILL_GLOBAL_BYTE_CAP,
            state_directory_byte_cap: STATE_DIRECTORY_BYTE_CAP,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetUsage {
    pub operation_spill_bytes: u64,
    pub global_spill_bytes: u64,
    pub state_directory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheAdmission {
    pub compacted: CompactedPreview,
    pub preview_bytes: usize,
    pub preview_records: usize,
    pub warnings: Vec<CacheWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheWarning {
    ResourceLimit(ReasonCode),
}

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("resource limit: {reason:?}")]
    ResourceLimit { reason: ReasonCode },
    #[error("generation manifest is malformed: {0}")]
    MalformedManifest(String),
    #[error("generation checksum mismatch")]
    ChecksumMismatch,
    #[error("generation pointer is missing")]
    MissingCurrentGeneration,
    #[error("generation data is missing")]
    MissingGenerationData,
    #[error("generation file name is invalid")]
    InvalidGenerationName,
    #[error("preview cache path is insecure: {0}")]
    InsecurePath(PathBuf),
    #[error("stored preview schema is invalid: {0}")]
    InvalidStoredSchema(String),
    #[error("stored preview provenance is invalid: {0}")]
    InvalidStoredProvenance(String),
    #[error("preview cache is quarantined after corruption at {path}")]
    Quarantined { path: PathBuf },
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Evidence that a stored preview still describes the filesystem it was taken from.
///
/// Stored inside [`StoredGeneration`] rather than beside it so that the evidence and the data it
/// vouches for are replaced by the same atomic rename. Two files could disagree after a crash, and
/// the dangerous direction of that disagreement — fresh evidence pointing at stale data — is
/// exactly what would show a user sizes for a tree that has since changed.
///
/// The record is deliberately platform-neutral: this crate must not depend on any platform crate,
/// and a cache written by one build should stay readable by another. Interpreting a token is the
/// caller's job; this type only carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeValidityRecord {
    /// Which mechanism produced this token, so a consumer never interprets one kind as another.
    ///
    /// A record whose kind is unknown to the reader must be treated as no evidence at all rather
    /// than guessed at.
    pub kind: String,
    /// Identifies the volume the token was captured from, in a form the producer can match again.
    pub volume: String,
    /// Identifies the incarnation of the change log, so a recreated log cannot look like the
    /// original one that happened to reach the same position.
    pub sequence_id: String,
    /// The position the change log had reached when the preview was captured.
    pub position: String,
}

/// The token kind produced by the NTFS USN change journal.
///
/// A constant rather than a bare literal because it is a storage contract: changing it silently
/// invalidates every cache on disk instead of failing loudly.
pub const VALIDITY_KIND_NTFS_USN: &str = "ntfs_usn";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredGeneration {
    pub generation: String,
    pub schema: String,
    pub created_at: String,
    pub preview: CompactedPreview,
    /// Per-volume evidence that this preview is still current, empty when none was obtainable.
    ///
    /// Defaults to empty so that a generation written before validity existed — or by a build that
    /// could not capture a token — deserializes into "no evidence" and is therefore never
    /// reusable. Absence of evidence must fail closed; there is no migration to forget.
    #[serde(default)]
    pub validity: Vec<VolumeValidityRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredEnvelope {
    pub generation: String,
    pub checksum_sha256: String,
    pub payload: StoredGeneration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CurrentPointer {
    pub generation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadResult {
    Hit(StoredGeneration),
    Miss,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheInspectionHealth {
    Healthy,
    Missing,
    Unknown,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CacheInspectionWarning {
    GenerationScanTruncated { limit: usize },
    QuarantineScanTruncated { limit: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CacheInspectionError {
    CurrentPointerTooLarge { bytes: u64 },
    MalformedCurrentPointer,
    InvalidCurrentGenerationName,
    MissingCurrentGenerationData,
    CurrentGenerationTooLarge { bytes: u64 },
    MalformedGenerationEnvelope,
    GenerationChecksumMismatch,
    GenerationPointerMismatch,
    InvalidStoredGenerationName,
    InvalidStoredSchema { schema: String },
    InvalidStoredProvenance { entry_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheInspection {
    pub exists: bool,
    pub current_generation: Option<String>,
    pub generation_count: usize,
    pub quarantine_count: usize,
    pub approx_bytes: u64,
    pub current_health: CacheInspectionHealth,
    pub schema_health: CacheInspectionHealth,
    pub warnings: Vec<CacheInspectionWarning>,
    pub errors: Vec<CacheInspectionError>,
}

impl CacheInspection {
    pub fn available(&self) -> bool {
        self.current_health == CacheInspectionHealth::Healthy
            && self.schema_health == CacheInspectionHealth::Healthy
            && self.quarantine_count == 0
            && self.warnings.is_empty()
            && self.errors.is_empty()
    }

    pub fn approx_bytes_complete(&self) -> bool {
        !self.warnings.iter().any(|warning| {
            matches!(
                warning,
                CacheInspectionWarning::GenerationScanTruncated { .. }
                    | CacheInspectionWarning::QuarantineScanTruncated { .. }
            )
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtomicGenerationStore {
    root: PathBuf,
}

impl AtomicGenerationStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn write_generation(&self, generation: &StoredGeneration) -> Result<(), CacheError> {
        validate_generation_id(&generation.generation)?;
        validate_stored_generation(generation)?;
        self.prepare_secure_root()?;
        self.prepare_private_subdir(&self.generations_dir())?;
        let envelope = StoredEnvelope {
            generation: generation.generation.clone(),
            checksum_sha256: checksum_hex(generation)?,
            payload: generation.clone(),
        };

        let bytes = serde_json::to_vec_pretty(&envelope)?;
        let generation_path = self.generation_path(&generation.generation);
        let tmp_generation = temp_path(&generation_path, "tmp");
        self.atomic_write_file(&tmp_generation, &bytes)?;
        self.rename_checked(&tmp_generation, &generation_path)?;

        let pointer = CurrentPointer {
            generation: generation.generation.clone(),
        };
        let pointer_path = self.current_pointer_path();
        let tmp_pointer = temp_path(&pointer_path, "tmp");
        self.atomic_write_file(&tmp_pointer, &serde_json::to_vec_pretty(&pointer)?)?;
        self.rename_checked(&tmp_pointer, &pointer_path)?;
        Ok(())
    }

    pub fn load_current(&self) -> Result<LoadResult, CacheError> {
        self.prepare_secure_root()?;
        let pointer_path = self.current_pointer_path();
        let pointer_bytes = match self.read_checked(&pointer_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(LoadResult::Miss),
            Err(error) => return Err(CacheError::Io(error)),
        };

        let pointer: CurrentPointer = match serde_json::from_slice(&pointer_bytes) {
            Ok(pointer) => pointer,
            Err(_) => {
                self.quarantine("current.json", &pointer_bytes)?;
                return Err(CacheError::Quarantined {
                    path: self.quarantine_path("current.json"),
                });
            }
        };
        validate_generation_id(&pointer.generation)?;

        let generation_path = self.generation_path(&pointer.generation);
        let bytes = match self.read_checked(&generation_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(LoadResult::Miss),
            Err(error) => return Err(CacheError::Io(error)),
        };

        let envelope: StoredEnvelope = match serde_json::from_slice(&bytes) {
            Ok(envelope) => envelope,
            Err(_) => {
                self.quarantine_generation(&pointer.generation, &bytes)?;
                return Ok(LoadResult::Miss);
            }
        };

        let checksum = checksum_hex(&envelope.payload)?;
        if checksum != envelope.checksum_sha256
            || pointer.generation != envelope.generation
            || envelope.generation != envelope.payload.generation
        {
            self.quarantine_generation(&pointer.generation, &bytes)?;
            return Ok(LoadResult::Miss);
        }
        if validate_stored_generation(&envelope.payload).is_err() {
            self.quarantine_generation(&pointer.generation, &bytes)?;
            return Ok(LoadResult::Miss);
        }

        Ok(LoadResult::Hit(envelope.payload))
    }

    /// Reports the health of the on-disk preview cache without modifying it.
    ///
    /// Inspection never creates directories, never repairs, and never quarantines: it is the
    /// read-only counterpart to [`Self::load_current`], which does all three. A caller diagnosing a
    /// broken cache must be able to look at it without changing what they are looking at.
    ///
    /// The traversal is platform-specific because the anti-substitution guarantee is. Unix walks
    /// the path with `openat`/`O_NOFOLLOW` so no component can be swapped between the check and
    /// the read; Windows opens each handle with the sharing mode and reparse-point rejection that
    /// give the equivalent property. Everything after opening — the size accounting, the byte
    /// limits, the parse and checksum decisions — is shared, so the two platforms cannot drift in
    /// what they consider healthy.
    pub fn inspect(&self) -> Result<CacheInspection, CacheError> {
        let Some(reader) = InspectionReader::open_root(&self.root)? else {
            return Ok(CacheInspection {
                exists: false,
                current_generation: None,
                generation_count: 0,
                quarantine_count: 0,
                approx_bytes: 0,
                current_health: CacheInspectionHealth::Missing,
                schema_health: CacheInspectionHealth::Unknown,
                warnings: Vec::new(),
                errors: Vec::new(),
            });
        };

        let mut warnings = Vec::new();
        let errors = Vec::new();
        let mut approx_bytes = 0u64;

        let generations_dir = reader.open_optional_dir("generations", &self.generations_dir())?;
        let generations = generations_dir
            .as_ref()
            .map(|directory| directory.scan_flat(&self.generations_dir()))
            .transpose()?;
        let generation_count = generations.as_ref().map_or(0, |scan| scan.count);
        approx_bytes =
            approx_bytes.saturating_add(generations.as_ref().map_or(0, |scan| scan.bytes));
        if generations.as_ref().is_some_and(|scan| scan.truncated) {
            warnings.push(CacheInspectionWarning::GenerationScanTruncated {
                limit: INSPECT_DIRECTORY_ENTRY_LIMIT,
            });
        }

        let quarantine_dir = reader.open_optional_dir("quarantine", &self.quarantine_dir())?;
        let quarantine = quarantine_dir
            .as_ref()
            .map(|directory| directory.scan_flat(&self.quarantine_dir()))
            .transpose()?;
        let quarantine_count = quarantine.as_ref().map_or(0, |scan| scan.count);
        approx_bytes =
            approx_bytes.saturating_add(quarantine.as_ref().map_or(0, |scan| scan.bytes));
        if quarantine.as_ref().is_some_and(|scan| scan.truncated) {
            warnings.push(CacheInspectionWarning::QuarantineScanTruncated {
                limit: INSPECT_DIRECTORY_ENTRY_LIMIT,
            });
        }

        let mut inspection = CacheInspection {
            exists: true,
            current_generation: None,
            generation_count,
            quarantine_count,
            approx_bytes,
            current_health: CacheInspectionHealth::Missing,
            schema_health: CacheInspectionHealth::Unknown,
            warnings,
            errors,
        };

        let current_file = match reader.read_optional_file(
            "current.json",
            &self.current_pointer_path(),
            INSPECT_CURRENT_POINTER_BYTE_LIMIT,
        )? {
            Some(file) => file,
            None => return Ok(inspection),
        };
        inspection.approx_bytes = inspection.approx_bytes.saturating_add(current_file.bytes);

        let current_bytes = match current_file.contents {
            InspectFileContents::Bytes(bytes) => bytes,
            InspectFileContents::TooLarge { bytes } => {
                inspection.current_health = CacheInspectionHealth::Error;
                inspection
                    .errors
                    .push(CacheInspectionError::CurrentPointerTooLarge { bytes });
                return Ok(inspection);
            }
        };

        let pointer: CurrentPointer = match serde_json::from_slice(&current_bytes) {
            Ok(pointer) => pointer,
            Err(_) => {
                inspection.current_health = CacheInspectionHealth::Error;
                inspection
                    .errors
                    .push(CacheInspectionError::MalformedCurrentPointer);
                return Ok(inspection);
            }
        };
        if validate_generation_id(&pointer.generation).is_err() {
            inspection.current_health = CacheInspectionHealth::Error;
            inspection
                .errors
                .push(CacheInspectionError::InvalidCurrentGenerationName);
            return Ok(inspection);
        }
        inspection.current_generation = Some(pointer.generation.clone());
        inspection.current_health = CacheInspectionHealth::Healthy;

        let generation_name = format!("{}.json", pointer.generation);
        let generation_file = match generations_dir.as_ref() {
            Some(directory) => directory.read_optional_file(
                &generation_name,
                &self.generation_path(&pointer.generation),
                INSPECT_GENERATION_BYTE_LIMIT,
            )?,
            None => None,
        };
        let generation_file = match generation_file {
            Some(file) => file,
            None => {
                inspection.schema_health = CacheInspectionHealth::Error;
                inspection
                    .errors
                    .push(CacheInspectionError::MissingCurrentGenerationData);
                return Ok(inspection);
            }
        };
        let generation_bytes = match generation_file.contents {
            InspectFileContents::Bytes(bytes) => bytes,
            InspectFileContents::TooLarge { bytes } => {
                inspection.schema_health = CacheInspectionHealth::Error;
                inspection
                    .errors
                    .push(CacheInspectionError::CurrentGenerationTooLarge { bytes });
                return Ok(inspection);
            }
        };

        let envelope: StoredEnvelope = match serde_json::from_slice(&generation_bytes) {
            Ok(envelope) => envelope,
            Err(_) => {
                inspection.schema_health = CacheInspectionHealth::Error;
                inspection
                    .errors
                    .push(CacheInspectionError::MalformedGenerationEnvelope);
                return Ok(inspection);
            }
        };

        let checksum = checksum_hex(&envelope.payload)?;
        if checksum != envelope.checksum_sha256 {
            inspection.schema_health = CacheInspectionHealth::Error;
            inspection
                .errors
                .push(CacheInspectionError::GenerationChecksumMismatch);
            return Ok(inspection);
        }

        if pointer.generation != envelope.generation
            || envelope.generation != envelope.payload.generation
        {
            inspection.schema_health = CacheInspectionHealth::Error;
            inspection
                .errors
                .push(CacheInspectionError::GenerationPointerMismatch);
            return Ok(inspection);
        }

        match validate_stored_generation(&envelope.payload) {
            Ok(()) => {
                inspection.schema_health = CacheInspectionHealth::Healthy;
                Ok(inspection)
            }
            Err(CacheError::InvalidGenerationName) => {
                inspection.schema_health = CacheInspectionHealth::Error;
                inspection
                    .errors
                    .push(CacheInspectionError::InvalidStoredGenerationName);
                Ok(inspection)
            }
            Err(CacheError::InvalidStoredSchema(schema)) => {
                inspection.schema_health = CacheInspectionHealth::Error;
                inspection
                    .errors
                    .push(CacheInspectionError::InvalidStoredSchema { schema });
                Ok(inspection)
            }
            Err(CacheError::InvalidStoredProvenance(entry_id)) => {
                inspection.schema_health = CacheInspectionHealth::Error;
                inspection
                    .errors
                    .push(CacheInspectionError::InvalidStoredProvenance { entry_id });
                Ok(inspection)
            }
            Err(other) => Err(other),
        }
    }

    fn generations_dir(&self) -> PathBuf {
        self.root.join("generations")
    }

    fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }

    fn current_pointer_path(&self) -> PathBuf {
        self.root.join("current.json")
    }

    fn generation_path(&self, generation: &str) -> PathBuf {
        self.generations_dir().join(format!("{generation}.json"))
    }

    fn quarantine_path(&self, name: &str) -> PathBuf {
        self.quarantine_dir().join(name)
    }

    fn quarantine(&self, name: &str, bytes: &[u8]) -> Result<(), CacheError> {
        self.prepare_private_subdir(&self.quarantine_dir())?;
        let path = self.quarantine_path(name);
        self.atomic_write_file(&path, bytes)?;
        Ok(())
    }

    fn quarantine_generation(&self, generation: &str, bytes: &[u8]) -> Result<(), CacheError> {
        self.quarantine(&format!("{generation}.corrupt.json"), bytes)
    }

    fn prepare_secure_root(&self) -> Result<(), CacheError> {
        ensure_no_symlink_ancestors(&self.root)?;
        if self.root.exists() {
            let metadata = fs::symlink_metadata(&self.root)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CacheError::InsecurePath(self.root.clone()));
            }
            #[cfg(unix)]
            if !is_private_owned_directory(&metadata) {
                return Err(CacheError::InsecurePath(self.root.clone()));
            }
        } else {
            fs::create_dir_all(&self.root)?;
            #[cfg(unix)]
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn prepare_private_subdir(&self, path: &Path) -> Result<(), CacheError> {
        ensure_no_symlink_ancestors(path)?;
        if path.exists() {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CacheError::InsecurePath(path.to_path_buf()));
            }
            #[cfg(unix)]
            if !is_private_owned_directory(&metadata) {
                return Err(CacheError::InsecurePath(path.to_path_buf()));
            }
        } else {
            fs::create_dir_all(path)?;
            #[cfg(unix)]
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn atomic_write_file(&self, path: &Path, bytes: &[u8]) -> Result<(), CacheError> {
        if let Some(parent) = path.parent() {
            self.prepare_private_subdir(parent)?;
        }
        if path.exists() && fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(CacheError::InsecurePath(path.to_path_buf()));
        }
        #[cfg(unix)]
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        #[cfg(not(unix))]
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        use std::io::Write as _;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn rename_checked(&self, from: &Path, to: &Path) -> Result<(), CacheError> {
        if to.exists() {
            let metadata = fs::symlink_metadata(to)?;
            if metadata.file_type().is_symlink() {
                return Err(CacheError::InsecurePath(to.to_path_buf()));
            }
            #[cfg(unix)]
            if !is_private_owned_regular_file(&metadata) {
                return Err(CacheError::InsecurePath(to.to_path_buf()));
            }
        }
        fs::rename(from, to)?;
        Ok(())
    }

    fn read_checked(&self, path: &Path) -> Result<Vec<u8>, std::io::Error> {
        if path.exists() && fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(std::io::Error::other("preview cache path is symlink"));
        }
        fs::read(path)
    }
}

/// A directory opened for read-only inspection, with substitution already ruled out.
///
/// Exists so [`AtomicGenerationStore::inspect`] can express its decisions once. Holding an open
/// handle rather than a path is the point: a path would have to be re-resolved for every read, and
/// each re-resolution is a window in which a component could be replaced by something else.
#[cfg(unix)]
struct InspectionReader {
    directory: OwnedFd,
}

#[cfg(unix)]
impl InspectionReader {
    /// Opens `path` component by component, refusing anything that is not a private directory.
    ///
    /// Returns `Ok(None)` when the directory simply does not exist, which is a healthy state for a
    /// cache that has never been written, and an error only when something exists but is not
    /// trustworthy.
    fn open_root(path: &Path) -> Result<Option<Self>, CacheError> {
        Ok(open_existing_inspection_root(path)?.map(|directory| Self { directory }))
    }

    fn open_optional_dir(&self, name: &str, display: &Path) -> Result<Option<Self>, CacheError> {
        Ok(
            open_optional_inspection_directory(&self.directory, name.as_bytes(), display)?
                .map(|directory| Self { directory }),
        )
    }

    fn read_optional_file(
        &self,
        name: &str,
        display: &Path,
        byte_limit: u64,
    ) -> Result<Option<InspectedFile>, CacheError> {
        inspect_optional_file_at(&self.directory, name.as_bytes(), display, byte_limit)
    }

    fn scan_flat(&self, path: &Path) -> Result<InspectedDir, CacheError> {
        inspect_flat_directory_fd(path, &self.directory)
    }
}

/// A directory opened for read-only inspection on Windows.
///
/// Windows has no `openat`, so each entry is reopened by path under the directory. The
/// anti-substitution property comes from a different mechanism instead: every handle is opened
/// with `FILE_FLAG_OPEN_REPARSE_POINT`, so a junction or symlink planted in the cache is opened as
/// the link itself and then rejected for not being the expected kind, rather than silently
/// followed somewhere else.
#[cfg(windows)]
struct InspectionReader {
    path: PathBuf,
}

#[cfg(windows)]
impl InspectionReader {
    fn open_root(path: &Path) -> Result<Option<Self>, CacheError> {
        match windows_inspection::classify_directory(path, path)? {
            windows_inspection::DirectoryState::Missing => Ok(None),
            windows_inspection::DirectoryState::Directory => Ok(Some(Self {
                path: path.to_path_buf(),
            })),
        }
    }

    /// Opens a child directory, reporting refusals against `display`.
    ///
    /// `display` is passed explicitly rather than derived from the child path because the Unix
    /// implementation opens relative to a descriptor and has no path to report; keeping the
    /// signatures identical is what lets `inspect` stay platform-neutral.
    fn open_optional_dir(&self, name: &str, display: &Path) -> Result<Option<Self>, CacheError> {
        let child = self.path.join(name);
        match windows_inspection::classify_directory(&child, display)? {
            windows_inspection::DirectoryState::Missing => Ok(None),
            windows_inspection::DirectoryState::Directory => Ok(Some(Self { path: child })),
        }
    }

    fn read_optional_file(
        &self,
        name: &str,
        display: &Path,
        byte_limit: u64,
    ) -> Result<Option<InspectedFile>, CacheError> {
        windows_inspection::read_optional_file(&self.path.join(name), display, byte_limit)
    }

    fn scan_flat(&self, path: &Path) -> Result<InspectedDir, CacheError> {
        windows_inspection::scan_flat_directory(&self.path, path)
    }
}

/// Read-only inspection primitives for Windows.
///
/// Kept apart from the shared decision logic so the platform-specific reasoning — which handle
/// flags rule out substitution, which error codes mean "absent" rather than "hostile" — lives in
/// one place and can be audited without reading the health rules around it.
#[cfg(windows)]
mod windows_inspection {
    use super::{
        CacheError, INSPECT_DIRECTORY_ENTRY_LIMIT, InspectFileContents, InspectedDir, InspectedFile,
    };
    use std::fs;
    use std::io::{ErrorKind, Read as _};
    use std::path::Path;

    /// Whether a directory is present, distinguished from being untrustworthy.
    pub(super) enum DirectoryState {
        /// Nothing exists at this path, which is normal for a cache never written.
        Missing,
        /// A real directory that is not a reparse point.
        Directory,
    }

    /// Classifies a path without following links.
    ///
    /// `symlink_metadata` is required rather than `metadata`: the latter resolves the link, which
    /// would report on the target and defeat the check entirely. Rust reports a directory junction
    /// as a symlink here — measured, not assumed — so one rejection covers junctions, directory
    /// symlinks and file symlinks alike.
    pub(super) fn classify_directory(
        path: &Path,
        display: &Path,
    ) -> Result<DirectoryState, CacheError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    Err(CacheError::InsecurePath(display.to_path_buf()))
                } else {
                    Ok(DirectoryState::Directory)
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(DirectoryState::Missing),
            Err(error) => Err(CacheError::Io(error)),
        }
    }

    /// Reads one cache file, refusing anything that is not a plain file.
    ///
    /// Size is taken from the same handle the bytes are read through, and the file is re-checked
    /// afterwards, so a file swapped mid-read is detected rather than reported with a stale size.
    /// Oversized files report their size without being read, since inspection must stay bounded
    /// even when the cache is corrupt.
    pub(super) fn read_optional_file(
        path: &Path,
        display: &Path,
        byte_limit: u64,
    ) -> Result<Option<InspectedFile>, CacheError> {
        let opened = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(CacheError::Io(error)),
        };
        if opened.file_type().is_symlink() || !opened.is_file() {
            return Err(CacheError::InsecurePath(display.to_path_buf()));
        }
        let bytes = opened.len();
        if bytes > byte_limit {
            return Ok(Some(InspectedFile {
                bytes,
                contents: InspectFileContents::TooLarge { bytes },
            }));
        }

        let mut file = fs::File::open(path)?;
        let mut contents = Vec::with_capacity(bytes as usize);
        (&mut file)
            .take(byte_limit.saturating_add(1))
            .read_to_end(&mut contents)?;
        let after = file.metadata()?;
        if !after.is_file() || after.len() != bytes || contents.len() as u64 != bytes {
            return Err(CacheError::InsecurePath(display.to_path_buf()));
        }
        Ok(Some(InspectedFile {
            bytes,
            contents: InspectFileContents::Bytes(contents),
        }))
    }

    /// Counts and sizes the entries of one flat cache directory.
    ///
    /// Bounded by [`INSPECT_DIRECTORY_ENTRY_LIMIT`] so a directory with a pathological number of
    /// entries cannot turn a status query into an unbounded walk; hitting the bound is reported as
    /// truncation rather than silently capping the total.
    pub(super) fn scan_flat_directory(
        directory: &Path,
        display: &Path,
    ) -> Result<InspectedDir, CacheError> {
        let mut count = 0usize;
        let mut bytes = 0u64;
        let mut truncated = false;
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if count == INSPECT_DIRECTORY_ENTRY_LIMIT {
                truncated = true;
                break;
            }
            let metadata = entry.metadata()?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(CacheError::InsecurePath(display.join(entry.file_name())));
            }
            count += 1;
            bytes = bytes.saturating_add(metadata.len());
        }
        Ok(InspectedDir {
            count,
            bytes,
            truncated,
        })
    }
}

#[cfg(unix)]
fn open_directory_at(parent: &OwnedFd, name: &[u8], display: &Path) -> Result<OwnedFd, CacheError> {
    let name = CString::new(name).map_err(|_| CacheError::InsecurePath(display.to_path_buf()))?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(CacheError::Io(std::io::Error::last_os_error()));
    }
    let directory = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(CacheError::Io(std::io::Error::last_os_error()));
    }
    let stat = unsafe { stat.assume_init() };
    if !is_private_owned_directory_stat(&stat) {
        return Err(CacheError::InsecurePath(display.to_path_buf()));
    }
    Ok(directory)
}

#[cfg(unix)]
fn open_existing_inspection_root(path: &Path) -> Result<Option<OwnedFd>, CacheError> {
    let start = CString::new(if path.is_absolute() { "/" } else { "." }).unwrap();
    let raw = unsafe {
        libc::open(
            start.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(CacheError::Io(std::io::Error::last_os_error()));
    }
    let mut current = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut display = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    };
    for component in path.components() {
        let Component::Normal(name) = component else {
            if matches!(component, Component::RootDir | Component::CurDir) {
                continue;
            }
            return Err(CacheError::InsecurePath(path.to_path_buf()));
        };
        display.push(name);
        match open_directory_at_unchecked(&current, name.as_bytes()) {
            Ok(next) => {
                current = next;
            }
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ELOOP) | Some(libc::ENOTDIR)
                ) =>
            {
                return Err(CacheError::InsecurePath(display));
            }
            Err(error) => return Err(CacheError::Io(error)),
        }
    }
    let metadata = fstat_metadata(&current)?;
    if !is_private_owned_directory(&metadata) {
        return Err(CacheError::InsecurePath(path.to_path_buf()));
    }
    Ok(Some(current))
}

#[cfg(unix)]
fn open_directory_at_unchecked(parent: &OwnedFd, name: &[u8]) -> Result<OwnedFd, std::io::Error> {
    let name = CString::new(name).map_err(|_| std::io::Error::from(ErrorKind::InvalidInput))?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}

#[cfg(unix)]
fn open_optional_inspection_directory(
    parent: &OwnedFd,
    name: &[u8],
    display: &Path,
) -> Result<Option<OwnedFd>, CacheError> {
    match open_directory_at(parent, name, display) {
        Ok(directory) => Ok(Some(directory)),
        Err(CacheError::Io(error)) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(CacheError::Io(error))
            if matches!(
                error.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::ENOTDIR)
            ) =>
        {
            Err(CacheError::InsecurePath(display.to_path_buf()))
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn inspect_optional_file_at(
    parent: &OwnedFd,
    name: &[u8],
    display: &Path,
    byte_limit: u64,
) -> Result<Option<InspectedFile>, CacheError> {
    let name = CString::new(name).map_err(|_| CacheError::InsecurePath(display.to_path_buf()))?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            Some(libc::ELOOP) => Err(CacheError::InsecurePath(display.to_path_buf())),
            _ => Err(CacheError::Io(error)),
        };
    }
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut file = fs::File::from(owned);
    let opened = file.metadata()?;
    if !is_private_owned_regular_file(&opened) {
        return Err(CacheError::InsecurePath(display.to_path_buf()));
    }
    let bytes = opened.len();
    let contents = if bytes > byte_limit {
        let after = file.metadata()?;
        if !same_inspected_file(&opened, &after) {
            return Err(CacheError::InsecurePath(display.to_path_buf()));
        }
        InspectFileContents::TooLarge { bytes }
    } else {
        let mut contents = Vec::with_capacity(bytes as usize);
        use std::io::Read as _;
        (&mut file)
            .take(byte_limit.saturating_add(1))
            .read_to_end(&mut contents)?;
        if contents.len() as u64 != bytes {
            return Err(CacheError::InsecurePath(display.to_path_buf()));
        }
        let after = file.metadata()?;
        if !same_inspected_file(&opened, &after) {
            return Err(CacheError::InsecurePath(display.to_path_buf()));
        }
        InspectFileContents::Bytes(contents)
    };
    Ok(Some(InspectedFile { bytes, contents }))
}

#[cfg(unix)]
fn fstat_metadata(directory: &OwnedFd) -> Result<fs::Metadata, CacheError> {
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(CacheError::Io(std::io::Error::last_os_error()));
    }
    Ok(fs::File::from(unsafe { OwnedFd::from_raw_fd(duplicate) }).metadata()?)
}

#[cfg(unix)]
struct InspectionDirectoryStream(*mut libc::DIR);

#[cfg(unix)]
impl Drop for InspectionDirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

#[cfg(unix)]
fn inspect_flat_directory_fd(path: &Path, directory: &OwnedFd) -> Result<InspectedDir, CacheError> {
    let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(CacheError::Io(std::io::Error::last_os_error()));
    }
    let raw_stream = unsafe { libc::fdopendir(duplicate) };
    if raw_stream.is_null() {
        unsafe {
            libc::close(duplicate);
        }
        return Err(CacheError::Io(std::io::Error::last_os_error()));
    }
    let stream = InspectionDirectoryStream(raw_stream);
    let mut count = 0usize;
    let mut bytes = 0u64;
    let mut truncated = false;
    loop {
        unsafe {
            *inspection_errno_location() = 0;
        }
        let raw_entry = unsafe { libc::readdir(stream.0) };
        if raw_entry.is_null() {
            let errno = unsafe { *inspection_errno_location() };
            if errno != 0 {
                return Err(CacheError::Io(std::io::Error::from_raw_os_error(errno)));
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*raw_entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if count == INSPECT_DIRECTORY_ENTRY_LIMIT {
            truncated = true;
            break;
        }
        let name_c = std::ffi::CString::new(name)
            .map_err(|_| CacheError::InsecurePath(path.join(OsString::from_vec(name.to_vec()))))?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name_c.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(CacheError::Io(std::io::Error::last_os_error()));
        }
        let stat = unsafe { stat.assume_init() };
        let entry_path = path.join(OsString::from_vec(name.to_vec()));
        if !is_private_owned_regular_file_stat(&stat) {
            return Err(CacheError::InsecurePath(entry_path));
        }
        count += 1;
        bytes = bytes.saturating_add(u64::try_from(stat.st_size).unwrap_or(u64::MAX));
    }
    Ok(InspectedDir {
        count,
        bytes,
        truncated,
    })
}

#[cfg(target_os = "linux")]
unsafe fn inspection_errno_location() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

#[cfg(target_os = "macos")]
unsafe fn inspection_errno_location() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

/// Fallback for the remaining unix targets.
///
/// The caller is gated on `unix`, but the accessor above only covers linux and macos, so any other
/// unix host failed to compile rather than failing to inspect. `libc::errno` is not a portable
/// symbol — each platform exposes its own thread-local accessor — so this reports the location as
/// unavailable instead of guessing one. A caller writing through this pointer would fault, which is
/// why the sentinel is only ever read back as "no errno reported".
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
unsafe fn inspection_errno_location() -> *mut libc::c_int {
    // A dedicated cell, so clearing and reading errno stay well-defined operations on memory this
    // process owns. It just never reflects a real kernel error on this platform.
    use std::cell::UnsafeCell;
    thread_local! {
        static UNSUPPORTED_ERRNO: UnsafeCell<libc::c_int> = const { UnsafeCell::new(0) };
    }
    UNSUPPORTED_ERRNO.with(|cell| cell.get())
}

#[cfg(unix)]
fn is_private_owned_directory_stat(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFDIR
        && stat.st_uid == unsafe { libc::geteuid() }
        && stat.st_mode & 0o077 == 0
}

#[cfg(unix)]
fn is_private_owned_regular_file_stat(stat: &libc::stat) -> bool {
    stat.st_mode & libc::S_IFMT == libc::S_IFREG
        && stat.st_uid == unsafe { libc::geteuid() }
        && stat.st_nlink == 1
}

#[cfg(unix)]
fn is_private_owned_directory(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o077 == 0
}

#[cfg(unix)]
fn is_private_owned_regular_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file() && metadata.uid() == unsafe { libc::geteuid() } && metadata.nlink() == 1
}

#[cfg(unix)]
fn same_inspected_file(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    is_private_owned_regular_file(after)
        && after.dev() == before.dev()
        && after.ino() == before.ino()
        && after.len() == before.len()
        && after.mtime() == before.mtime()
        && after.mtime_nsec() == before.mtime_nsec()
        && after.ctime() == before.ctime()
        && after.ctime_nsec() == before.ctime_nsec()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InspectedDir {
    count: usize,
    bytes: u64,
    truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InspectedFile {
    bytes: u64,
    contents: InspectFileContents,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InspectFileContents {
    Bytes(Vec<u8>),
    TooLarge { bytes: u64 },
}

fn ensure_no_symlink_ancestors(path: &Path) -> Result<(), CacheError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(CacheError::InsecurePath(current));
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(CacheError::Io(error)),
        }
    }
    Ok(())
}

pub fn admit_preview(
    summaries: Vec<PreviewSummary>,
    budgets: &PreviewBudgets,
    usage: &BudgetUsage,
) -> Result<CacheAdmission, CacheError> {
    enforce_spill_and_state_budgets(budgets, usage)?;
    validate_preview_summaries(&summaries)?;
    let compacted = compact_preview(summaries, budgets);
    if compacted.total_records > budgets.preview_record_cap
        || compacted.total_estimated_bytes > budgets.preview_byte_cap
    {
        return Err(CacheError::ResourceLimit {
            reason: ReasonCode::ResourceLimit,
        });
    }
    let preview_bytes = compacted.total_estimated_bytes;
    let preview_records = compacted.total_records;
    let mut warnings = Vec::new();

    if compacted.visible_resource_limit {
        warnings.push(CacheWarning::ResourceLimit(ReasonCode::ResourceLimit));
    }

    Ok(CacheAdmission {
        compacted,
        preview_bytes,
        preview_records,
        warnings,
    })
}

pub fn compact_preview(
    summaries: Vec<PreviewSummary>,
    budgets: &PreviewBudgets,
) -> CompactedPreview {
    let mut by_parent: BTreeMap<String, Vec<PreviewSummary>> = BTreeMap::new();
    let mut roots: Vec<PreviewSummary> = Vec::new();

    for summary in summaries {
        match &summary.parent_id {
            Some(parent_id) => by_parent
                .entry(parent_id.clone())
                .or_default()
                .push(summary),
            None => roots.push(summary),
        }
    }

    if !roots.is_empty() {
        by_parent.insert("__root__".to_string(), roots);
    }

    let mut parents = BTreeMap::new();
    for (parent_id, entries) in by_parent {
        let parent = compact_parent(parent_id.clone(), entries);
        parents.insert(parent_id, parent);
    }

    let mut compacted = CompactedPreview {
        parents,
        total_estimated_bytes: 0,
        total_records: 0,
        visible_resource_limit: false,
    };
    recompute_totals(&mut compacted);

    while compacted.total_records > budgets.preview_record_cap
        || compacted.total_estimated_bytes > budgets.preview_byte_cap
    {
        if !trim_one_nonmandatory_record(&mut compacted) {
            compacted.visible_resource_limit = true;
            break;
        }
        compacted.visible_resource_limit = true;
        recompute_totals(&mut compacted);
    }

    compacted
}

fn compact_parent(parent_id: String, entries: Vec<PreviewSummary>) -> ParentPreview {
    let mut mandatory = Vec::new();
    let mut eligible = Vec::new();
    let mut remainder = Vec::new();

    for entry in entries {
        if entry.kind == PreviewKind::Others {
            remainder.push(entry);
            continue;
        }

        if entry.is_mandatory() {
            mandatory.push(entry);
        } else if entry.is_directory()
            || matches!(entry.kind, PreviewKind::Leaf)
                && entry.preview_rank_bytes().unwrap_or(0) >= HEAVY_LEAF_THRESHOLD_BYTES as u128
        {
            eligible.push(entry);
        } else {
            remainder.push(entry);
        }
    }

    eligible.sort_by(compare_preview_rows);
    let retained_top = eligible
        .iter()
        .take(TOP_HEAVY_CHILDREN)
        .cloned()
        .map(|mut entry| {
            entry.roles.insert(PreviewRole::TopHeavyChild);
            entry
        })
        .collect::<Vec<_>>();

    let evicted = eligible.into_iter().skip(TOP_HEAVY_CHILDREN);
    let mut retained = mandatory;
    retained.extend(retained_top);
    retained.sort_by(compare_preview_rows);

    let mut others_inputs = remainder;
    others_inputs.extend(evicted);

    let others = if others_inputs.is_empty() {
        None
    } else {
        Some(build_others_summary(&parent_id, &others_inputs))
    };

    ParentPreview {
        parent_id,
        retained,
        others,
    }
}

fn build_others_summary(parent_id: &str, inputs: &[PreviewSummary]) -> PreviewSummary {
    let logical_bytes = sum_byte_values(inputs.iter().map(|row| &row.logical_bytes));
    let allocated_bytes = sum_byte_values(inputs.iter().map(|row| &row.allocated_bytes));
    let direct_child_count = sum_count_values(inputs.iter().map(direct_contribution_count));
    let recursive_entry_count = sum_count_values(inputs.iter().map(recursive_contribution_count));
    let incomplete_reasons = union_incomplete_reasons(inputs);
    let complete = inputs.iter().all(|row| row.coverage.complete);
    let details_lost = true;

    PreviewSummary {
        kind: PreviewKind::Others,
        parent_id: Some(parent_id.to_string()),
        entry_id: format!("{parent_id}::others"),
        native_name: NativeName::unix(b"Others".to_vec()),
        display_name: "Others".to_string(),
        logical_bytes,
        allocated_bytes,
        direct_child_count,
        recursive_entry_count,
        aggregate: None,
        coverage: PreviewCoverage {
            complete,
            details_lost,
            incomplete_reasons,
        },
        selectable: false,
        roles: BTreeSet::new(),
        provenance: FieldProvenance::StalePreview {
            observed_at: "cached".to_string(),
        },
    }
}

fn compare_preview_rows(left: &PreviewSummary, right: &PreviewSummary) -> std::cmp::Ordering {
    right
        .preview_rank_bytes()
        .cmp(&left.preview_rank_bytes())
        .then_with(|| {
            left.native_name
                .encoded_value()
                .cmp(&right.native_name.encoded_value())
        })
        .then_with(|| left.entry_id.cmp(&right.entry_id))
}

fn recompute_totals(compacted: &mut CompactedPreview) {
    let mut records = 0usize;
    let mut bytes = 0usize;
    for parent in compacted.parents.values() {
        records += parent.retained.len();
        bytes += parent
            .retained
            .iter()
            .map(PreviewSummary::estimated_bytes)
            .sum::<usize>();
        if let Some(others) = &parent.others {
            records += 1;
            bytes += others.estimated_bytes();
        }
    }
    compacted.total_records = records;
    compacted.total_estimated_bytes = bytes;
}

fn trim_one_nonmandatory_record(compacted: &mut CompactedPreview) -> bool {
    let candidate = compacted
        .parents
        .iter()
        .flat_map(|(parent_id, parent)| {
            parent
                .retained
                .iter()
                .enumerate()
                .filter(|(_, row)| !row.is_mandatory())
                .map(move |(index, row)| (parent_id.clone(), index, row.clone()))
        })
        .max_by(|(_, _, left), (_, _, right)| compare_preview_rows(left, right));

    let Some((parent_id, index, _removed)) = candidate else {
        return false;
    };

    let parent = compacted
        .parents
        .get_mut(&parent_id)
        .expect("parent must exist while trimming");
    let removed = parent
        .retained
        .remove(index)
        .with_role_removed(&PreviewRole::TopHeavyChild);

    let mut others_inputs = Vec::new();
    if let Some(existing) = parent.others.take() {
        others_inputs.push(existing);
    }
    others_inputs.push(removed);
    parent.others = Some(build_others_summary(&parent.parent_id, &others_inputs));
    true
}

fn enforce_spill_and_state_budgets(
    budgets: &PreviewBudgets,
    usage: &BudgetUsage,
) -> Result<(), CacheError> {
    if usage.state_directory_bytes > budgets.state_directory_byte_cap {
        return Err(CacheError::ResourceLimit {
            reason: ReasonCode::ResourceLimit,
        });
    }
    if usage.operation_spill_bytes >= budgets.spill_threshold_bytes
        && usage.operation_spill_bytes > budgets.spill_operation_byte_cap
    {
        return Err(CacheError::ResourceLimit {
            reason: ReasonCode::ResourceLimit,
        });
    }
    if usage.global_spill_bytes > budgets.spill_global_byte_cap {
        return Err(CacheError::ResourceLimit {
            reason: ReasonCode::ResourceLimit,
        });
    }
    Ok(())
}

fn sum_byte_values<'a>(values: impl Iterator<Item = &'a ByteValue>) -> ByteValue {
    let mut total = DecimalU128::ZERO;
    let mut lower_bound_reason = None;
    for value in values {
        match value {
            EvidenceValue::Known { value } => match total.checked_add(*value) {
                Some(next) => total = next,
                None => {
                    return EvidenceValue::Unknown {
                        reason: ReasonCode::Overflow,
                    };
                }
            },
            EvidenceValue::LowerBound { value, reason } => {
                if lower_bound_reason.is_none() {
                    lower_bound_reason = Some(reason.clone());
                }
                match total.checked_add(*value) {
                    Some(next) => total = next,
                    None => {
                        return EvidenceValue::Unknown {
                            reason: ReasonCode::Overflow,
                        };
                    }
                }
            }
            EvidenceValue::Unknown { reason }
            | EvidenceValue::Unsupported { reason }
            | EvidenceValue::NotChecked { reason } => {
                return EvidenceValue::Unknown {
                    reason: reason.clone(),
                };
            }
        }
    }
    match lower_bound_reason {
        Some(reason) => EvidenceValue::LowerBound {
            value: total,
            reason,
        },
        None => EvidenceValue::Known { value: total },
    }
}

fn sum_count_values(values: impl Iterator<Item = CountValue>) -> CountValue {
    let mut total = DecimalU128::ZERO;
    let mut lower_bound_reason = None;
    for value in values {
        match value {
            EvidenceValue::Known { value } => match total.checked_add(value) {
                Some(next) => total = next,
                None => {
                    return EvidenceValue::Unknown {
                        reason: ReasonCode::Overflow,
                    };
                }
            },
            EvidenceValue::LowerBound { value, reason } => {
                if lower_bound_reason.is_none() {
                    lower_bound_reason = Some(reason);
                }
                match total.checked_add(value) {
                    Some(next) => total = next,
                    None => {
                        return EvidenceValue::Unknown {
                            reason: ReasonCode::Overflow,
                        };
                    }
                }
            }
            EvidenceValue::Unknown { reason }
            | EvidenceValue::Unsupported { reason }
            | EvidenceValue::NotChecked { reason } => {
                return EvidenceValue::Unknown { reason };
            }
        }
    }
    match lower_bound_reason {
        Some(reason) => EvidenceValue::LowerBound {
            value: total,
            reason,
        },
        None => EvidenceValue::Known { value: total },
    }
}

fn direct_contribution_count(row: &PreviewSummary) -> CountValue {
    if row.kind == PreviewKind::Others {
        return row.direct_child_count.clone();
    }
    EvidenceValue::Known {
        value: DecimalU128::new(1),
    }
}

fn recursive_contribution_count(row: &PreviewSummary) -> CountValue {
    if row.kind == PreviewKind::Others {
        return row.recursive_entry_count.clone();
    }
    match &row.aggregate {
        Some(aggregate) => aggregate.recursive_entry_count.clone(),
        None => EvidenceValue::Known {
            value: DecimalU128::new(1),
        },
    }
}

fn union_incomplete_reasons(inputs: &[PreviewSummary]) -> Vec<ReasonCode> {
    let mut reasons = Vec::new();
    for input in inputs {
        for reason in &input.coverage.incomplete_reasons {
            if !reasons.contains(reason) {
                reasons.push(reason.clone());
            }
        }
        if let Some(aggregate) = &input.aggregate {
            for reason in &aggregate.coverage.incomplete_reasons {
                if !reasons.contains(reason) {
                    reasons.push(reason.clone());
                }
            }
        }
    }
    reasons
}

fn evidence_to_u128<T>(value: &EvidenceValue<T>) -> Option<u128>
where
    T: Copy + Into<u128>,
{
    match value {
        EvidenceValue::Known { value } | EvidenceValue::LowerBound { value, .. } => {
            Some((*value).into())
        }
        EvidenceValue::Unknown { .. }
        | EvidenceValue::Unsupported { .. }
        | EvidenceValue::NotChecked { .. } => None,
    }
}

fn checksum_hex(generation: &StoredGeneration) -> Result<String, CacheError> {
    let bytes = serde_json::to_vec(generation)?;
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(bytes);
    Ok(hex_lower(hasher.finalize().as_slice()))
}

fn validate_generation_id(generation: &str) -> Result<(), CacheError> {
    let valid = !generation.is_empty()
        && generation.len() <= MAX_GENERATION_ID_BYTES
        && generation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(CacheError::InvalidGenerationName)
    }
}

fn validate_preview_summaries(summaries: &[PreviewSummary]) -> Result<(), CacheError> {
    for summary in summaries {
        validate_preview_summary(summary)?;
    }
    Ok(())
}

fn validate_preview_summary(summary: &PreviewSummary) -> Result<(), CacheError> {
    if !matches!(
        summary.provenance,
        FieldProvenance::StalePreview { .. } | FieldProvenance::ValidatedCache { .. }
    ) {
        return Err(CacheError::InvalidStoredProvenance(
            summary.entry_id.clone(),
        ));
    }
    if summary.kind == PreviewKind::Others
        && (!matches!(summary.provenance, FieldProvenance::StalePreview { .. })
            || summary.selectable)
    {
        return Err(CacheError::InvalidStoredProvenance(
            summary.entry_id.clone(),
        ));
    }
    Ok(())
}

fn validate_stored_generation(generation: &StoredGeneration) -> Result<(), CacheError> {
    validate_generation_id(&generation.generation)?;
    if generation.schema != STORED_PREVIEW_SCHEMA {
        return Err(CacheError::InvalidStoredSchema(generation.schema.clone()));
    }
    for parent in generation.preview.parents.values() {
        validate_preview_summaries(&parent.retained)?;
        if let Some(others) = &parent.others {
            validate_preview_summary(others)?;
        }
    }
    Ok(())
}

fn temp_path(path: &Path, suffix: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("tmp"));
    let mut temp_name = file_name;
    temp_name.push(format!(".{suffix}"));
    path.with_file_name(temp_name)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

trait PreviewSummaryExt {
    fn with_role_removed(self, role: &PreviewRole) -> Self;
}

impl PreviewSummaryExt for PreviewSummary {
    fn with_role_removed(mut self, role: &PreviewRole) -> Self {
        self.roles.remove(role);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time must be after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "sweepx-cache-test-{}-{}",
                std::process::id(),
                nonce
            ));
            fs::create_dir_all(&path).expect("test temp dir must be creatable");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("test temp dir permissions must be private");
            }
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn known_bytes(bytes: u64) -> ByteValue {
        EvidenceValue::Known {
            value: DecimalU128::new(bytes as u128),
        }
    }

    fn known_count(count: u64) -> CountValue {
        EvidenceValue::Known {
            value: DecimalU128::new(count as u128),
        }
    }

    fn stale_preview() -> FieldProvenance {
        FieldProvenance::StalePreview {
            observed_at: "2026-08-26T00:00:00Z".to_string(),
        }
    }

    fn validated_cache() -> FieldProvenance {
        FieldProvenance::ValidatedCache {
            observed_at: "2026-08-26T00:00:00Z".to_string(),
            validation: sweepx_model::MethodId::ValidatedCacheToken,
            token: "token-1".to_string(),
        }
    }

    fn coverage(complete: bool) -> PreviewCoverage {
        PreviewCoverage {
            complete,
            details_lost: false,
            incomplete_reasons: if complete {
                Vec::new()
            } else {
                vec![ReasonCode::IncompleteStreamCoverage]
            },
        }
    }

    fn summary(
        parent_id: &str,
        entry_id: &str,
        kind: PreviewKind,
        size_bytes: u64,
        provenance: FieldProvenance,
    ) -> PreviewSummary {
        PreviewSummary {
            kind,
            parent_id: Some(parent_id.to_string()),
            entry_id: entry_id.to_string(),
            native_name: NativeName::unix(entry_id.as_bytes().to_vec()),
            display_name: entry_id.to_string(),
            logical_bytes: known_bytes(size_bytes),
            allocated_bytes: known_bytes(size_bytes),
            direct_child_count: known_count(1),
            recursive_entry_count: known_count(1),
            aggregate: None,
            coverage: coverage(true),
            selectable: true,
            roles: BTreeSet::new(),
            provenance,
        }
    }

    #[test]
    fn retains_exact_top64_and_others_for_wide_parent() {
        let parent_id = "parent";
        let mut rows = Vec::new();
        for index in 0..70u64 {
            rows.push(summary(
                parent_id,
                &format!("dir-{index:02}"),
                PreviewKind::Directory,
                10_000 - index,
                stale_preview(),
            ));
        }
        rows.push(summary(
            parent_id,
            "small-file",
            PreviewKind::Leaf,
            1024,
            stale_preview(),
        ));
        rows.push(summary(
            parent_id,
            "boundary",
            PreviewKind::Boundary,
            0,
            stale_preview(),
        ));

        let compacted = compact_preview(rows, &PreviewBudgets::default());
        let parent = compacted.parents.get(parent_id).unwrap();

        let top_ids = parent
            .retained
            .iter()
            .filter(|row| row.roles.contains(&PreviewRole::TopHeavyChild))
            .map(|row| row.entry_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(top_ids.len(), TOP_HEAVY_CHILDREN);
        assert_eq!(top_ids.first().unwrap(), "dir-00");
        assert_eq!(top_ids.last().unwrap(), "dir-63");
        assert!(parent.retained.iter().any(|row| row.entry_id == "boundary"));

        let others = parent.others.as_ref().unwrap();
        assert!(!others.selectable);
        assert_eq!(others.kind, PreviewKind::Others);
        assert_eq!(evidence_to_u128(&others.allocated_bytes), Some(60_625));
        assert_eq!(evidence_to_u128(&others.direct_child_count), Some(7));
    }

    #[test]
    fn selection_is_order_invariant() {
        let parent_id = "parent";
        let rows = vec![
            summary(parent_id, "b", PreviewKind::Directory, 40, stale_preview()),
            summary(parent_id, "a", PreviewKind::Directory, 40, stale_preview()),
            summary(
                parent_id,
                "c",
                PreviewKind::Leaf,
                HEAVY_LEAF_THRESHOLD_BYTES,
                stale_preview(),
            ),
            summary(parent_id, "d", PreviewKind::Leaf, 1, stale_preview()),
        ];

        let left = compact_preview(rows.clone(), &PreviewBudgets::default());
        let mut reversed = rows;
        reversed.reverse();
        let right = compact_preview(reversed, &PreviewBudgets::default());
        assert_eq!(left, right);
    }

    #[test]
    fn admits_only_cache_preview_provenance_variants() {
        let rows = vec![
            summary(
                "parent",
                "stale",
                PreviewKind::Directory,
                1,
                stale_preview(),
            ),
            summary(
                "parent",
                "validated",
                PreviewKind::Leaf,
                HEAVY_LEAF_THRESHOLD_BYTES,
                validated_cache(),
            ),
        ];

        let compacted = compact_preview(rows, &PreviewBudgets::default());
        let parent = compacted.parents.get("parent").unwrap();
        assert!(parent.retained.iter().all(|row| {
            matches!(
                row.provenance,
                FieldProvenance::StalePreview { .. } | FieldProvenance::ValidatedCache { .. }
            )
        }));
    }

    /// A generation written before validity existed loads with no evidence, not an error.
    ///
    /// Uses a hand-written payload with the field absent, which is exactly what is sitting in
    /// users' caches right now. Reading it must succeed — a hard failure would quarantine every
    /// existing cache on upgrade — and must yield empty evidence so the generation is never
    /// treated as verified. Building the JSON through the struct would prove nothing, because the
    /// serializer would put the field back.
    #[test]
    fn a_generation_without_validity_loads_as_having_no_evidence() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let modern = StoredGeneration {
            generation: "gen-old".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-08-26T00:00:00Z".to_string(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: Vec::new(),
        };
        store.write_generation(&modern).unwrap();

        // Rewrite the payload without the field, then recompute the checksum so the test
        // exercises the missing field rather than tamper detection.
        let path = temp.path().join("generations/gen-old.json");
        let mut envelope: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["payload"]
            .as_object_mut()
            .unwrap()
            .remove("validity")
            .expect("the field must be present before it is removed");
        let legacy: StoredGeneration = serde_json::from_value(envelope["payload"].clone()).unwrap();
        envelope["checksum_sha256"] = json!(checksum_hex(&legacy).unwrap());
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        let loaded = store.load_current().unwrap();
        let LoadResult::Hit(generation) = loaded else {
            panic!("a generation predating validity must still load, got {loaded:?}");
        };
        assert!(
            generation.validity.is_empty(),
            "an absent field must read as no evidence, never as evidence"
        );
    }

    /// Validity survives a write/read round trip byte for byte.
    ///
    /// Written through the real store rather than compared in memory, because the field only earns
    /// its place if it crosses the atomic-rename boundary intact; serializing and deserializing in
    /// one process would not exercise the envelope or its checksum.
    #[test]
    fn validity_records_survive_a_store_round_trip() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let validity = vec![
            VolumeValidityRecord {
                kind: VALIDITY_KIND_NTFS_USN.to_string(),
                volume: r"C:\".to_string(),
                sequence_id: "17293822569102704640".to_string(),
                position: "9007199254740993".to_string(),
            },
            VolumeValidityRecord {
                kind: VALIDITY_KIND_NTFS_USN.to_string(),
                volume: r"E:\".to_string(),
                sequence_id: "1".to_string(),
                position: "2".to_string(),
            },
        ];
        let generation = StoredGeneration {
            generation: "gen-validity".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-09-03T00:00:00Z".to_string(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: validity.clone(),
        };
        store.write_generation(&generation).unwrap();

        let LoadResult::Hit(loaded) = store.load_current().unwrap() else {
            panic!("the generation just written must load");
        };
        assert_eq!(
            loaded.validity, validity,
            "identifiers beyond 2^53 must survive as written, not as rounded floats"
        );
    }

    /// Tampering with stored validity invalidates the whole generation.
    ///
    /// The evidence is inside the checksummed payload precisely so that editing it on disk cannot
    /// buy a false "unchanged" verdict; it costs the attacker the entire generation instead.
    #[test]
    fn editing_validity_on_disk_invalidates_the_generation() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let generation = StoredGeneration {
            generation: "gen-tamper".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-09-03T00:00:00Z".to_string(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: vec![VolumeValidityRecord {
                kind: VALIDITY_KIND_NTFS_USN.to_string(),
                volume: r"C:\".to_string(),
                sequence_id: "1".to_string(),
                position: "100".to_string(),
            }],
        };
        store.write_generation(&generation).unwrap();

        let path = temp.path().join("generations/gen-tamper.json");
        let mut envelope: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        // Edit the token in place and leave the checksum alone: that is what an attacker who
        // wants a false "unchanged" verdict would have to do.
        assert_eq!(
            envelope["payload"]["validity"][0]["position"], "100",
            "the field this test edits must exist, or the edit proves nothing"
        );
        envelope["payload"]["validity"][0]["position"] = json!("999");
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        assert!(
            matches!(store.load_current(), Ok(LoadResult::Miss)),
            "an edited token must cost the generation, not grant a reuse"
        );
    }

    #[test]
    fn corrupted_generation_falls_back_to_miss_and_quarantines() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let generation = StoredGeneration {
            generation: "gen-1".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-08-26T00:00:00Z".to_string(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: Vec::new(),
        };
        store.write_generation(&generation).unwrap();

        let generation_path = temp.path().join("generations/gen-1.json");
        fs::write(&generation_path, b"{not-json").unwrap();

        let loaded = store.load_current().unwrap();
        assert_eq!(loaded, LoadResult::Miss);
        assert!(temp.path().join("quarantine/gen-1.corrupt.json").exists());
    }

    #[test]
    fn generation_must_match_current_pointer_and_referenced_path() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        fs::create_dir_all(temp.path().join("generations")).unwrap();
        let generation = StoredGeneration {
            generation: "gen-b".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-08-26T00:00:00Z".to_string(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: Vec::new(),
        };
        let envelope = StoredEnvelope {
            generation: generation.generation.clone(),
            checksum_sha256: checksum_hex(&generation).unwrap(),
            payload: generation,
        };
        let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
        fs::write(temp.path().join("generations/gen-a.json"), &envelope_bytes).unwrap();
        fs::write(
            temp.path().join("current.json"),
            br#"{"generation":"gen-a"}"#,
        )
        .unwrap();

        let loaded = store.load_current().unwrap();

        assert_eq!(loaded, LoadResult::Miss);
        assert_eq!(
            fs::read(temp.path().join("quarantine/gen-a.corrupt.json")).unwrap(),
            envelope_bytes
        );
    }

    #[cfg(unix)]
    #[test]
    fn current_json_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let target = temp.path().join("target.json");
        fs::write(&target, br#"{"generation":"gen-1"}"#).unwrap();
        symlink(&target, temp.path().join("current.json")).unwrap();

        let error = store.load_current().unwrap_err();
        assert!(matches!(error, CacheError::Io(_)));
    }

    #[cfg(unix)]
    #[test]
    fn generations_or_quarantine_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let generation = StoredGeneration {
            generation: "gen-1".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-08-26T00:00:00Z".to_string(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: Vec::new(),
        };

        let real_generations = temp.path().join("real-generations");
        fs::create_dir(&real_generations).unwrap();
        symlink(&real_generations, temp.path().join("generations")).unwrap();
        let error = store.write_generation(&generation).unwrap_err();
        assert!(matches!(error, CacheError::InsecurePath(_)));

        fs::remove_file(temp.path().join("generations")).unwrap();
        fs::create_dir(temp.path().join("generations")).unwrap();
        fs::write(temp.path().join("generations/gen-1.json"), b"{not-json").unwrap();
        fs::write(
            temp.path().join("current.json"),
            br#"{"generation":"gen-1"}"#,
        )
        .unwrap();
        let real_quarantine = temp.path().join("real-quarantine");
        fs::create_dir(&real_quarantine).unwrap();
        symlink(&real_quarantine, temp.path().join("quarantine")).unwrap();
        let error = store.load_current().unwrap_err();
        assert!(matches!(error, CacheError::InsecurePath(_)));
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_symlink_in_store_root_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = TestTempDir::new();
        let real = temp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = temp.path().join("linked");
        symlink(&real, &link).unwrap();
        let store = AtomicGenerationStore::new(link.join("preview"));

        let generation = StoredGeneration {
            generation: "gen-1".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-08-26T00:00:00Z".to_string(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: Vec::new(),
        };
        let error = store.write_generation(&generation).unwrap_err();
        assert!(matches!(error, CacheError::InsecurePath(_)));
    }

    /// A cache that was never written must report absent without being created.
    ///
    /// Runs on Windows too: inspection is read-only on every platform, and a status query that
    /// created the directory it was asked about would make "does a cache exist" unanswerable.
    #[test]
    fn inspect_missing_store_is_noncreating_and_reports_absent() {
        let temp = TestTempDir::new();
        let store_root = temp.path().join("preview");
        let store = AtomicGenerationStore::new(&store_root);

        let inspection = store.inspect().unwrap();

        assert_eq!(
            inspection,
            CacheInspection {
                exists: false,
                current_generation: None,
                generation_count: 0,
                quarantine_count: 0,
                approx_bytes: 0,
                current_health: CacheInspectionHealth::Missing,
                schema_health: CacheInspectionHealth::Unknown,
                warnings: Vec::new(),
                errors: Vec::new(),
            }
        );
        assert!(!store_root.exists());
    }

    /// A healthy cache reports its generation, counts and sizes on every platform.
    #[test]
    fn inspect_reports_valid_store_health_and_counts() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let generation = StoredGeneration {
            generation: "gen-42".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-08-26T00:00:00Z".to_string(),
            preview: compact_preview(
                vec![summary(
                    "parent",
                    "dir",
                    PreviewKind::Directory,
                    123,
                    stale_preview(),
                )],
                &PreviewBudgets::default(),
            ),
            validity: Vec::new(),
        };
        store.write_generation(&generation).unwrap();
        fs::create_dir_all(temp.path().join("quarantine")).unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            temp.path().join("quarantine"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(temp.path().join("quarantine/old.corrupt.json"), b"broken").unwrap();

        let inspection = store.inspect().unwrap();

        assert!(inspection.exists);
        assert_eq!(inspection.current_generation.as_deref(), Some("gen-42"));
        assert_eq!(inspection.generation_count, 1);
        assert_eq!(inspection.quarantine_count, 1);
        assert!(inspection.approx_bytes > 0);
        assert_eq!(inspection.current_health, CacheInspectionHealth::Healthy);
        assert_eq!(inspection.schema_health, CacheInspectionHealth::Healthy);
        assert!(inspection.warnings.is_empty());
        assert!(inspection.approx_bytes_complete());
        assert!(!inspection.available());
        assert!(inspection.errors.is_empty());
    }

    /// A malformed pointer is reported as typed error state without repairing anything.
    ///
    /// Inspection must never quarantine: that is `load_current`'s job. A diagnostic command
    /// that mutates the thing being diagnosed destroys the evidence a user came to look at.
    #[test]
    fn inspect_malformed_current_is_read_only_and_typed() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        fs::create_dir_all(temp.path()).unwrap();
        let current_path = temp.path().join("current.json");
        let original = b"{not-json".to_vec();
        fs::write(&current_path, &original).unwrap();

        let inspection = store.inspect().unwrap();

        assert!(inspection.exists);
        assert_eq!(inspection.current_generation, None);
        assert_eq!(inspection.current_health, CacheInspectionHealth::Error);
        assert_eq!(inspection.schema_health, CacheInspectionHealth::Unknown);
        assert_eq!(
            inspection.errors,
            vec![CacheInspectionError::MalformedCurrentPointer]
        );
        assert_eq!(fs::read(&current_path).unwrap(), original);
        assert!(!temp.path().join("quarantine").exists());
    }

    #[test]
    fn generation_ids_are_bounded() {
        let valid = "a".repeat(MAX_GENERATION_ID_BYTES);
        assert!(validate_generation_id(&valid).is_ok());
        assert!(matches!(
            validate_generation_id(&format!("{valid}a")),
            Err(CacheError::InvalidGenerationName)
        ));
    }

    /// An over-long generation id is refused before it is ever joined onto a path.
    #[test]
    fn oversized_generation_pointer_is_rejected_before_path_lookup() {
        let temp = TestTempDir::new();
        let current = temp.path().join("current.json");
        fs::write(
            &current,
            serde_json::to_vec(&CurrentPointer {
                generation: "a".repeat(MAX_GENERATION_ID_BYTES + 1),
            })
            .unwrap(),
        )
        .unwrap();
        let inspection = AtomicGenerationStore::new(temp.path()).inspect().unwrap();

        assert_eq!(inspection.current_health, CacheInspectionHealth::Error);
        assert_eq!(inspection.current_generation, None);
        assert_eq!(
            inspection.errors,
            vec![CacheInspectionError::InvalidCurrentGenerationName]
        );
        assert!(!temp.path().join("generations").exists());
    }

    /// A junction standing in for `generations` must be refused, not followed.
    ///
    /// This is the Windows counterpart to the symlink test, and it matters more here: creating a
    /// directory junction requires neither elevation nor developer mode, so anyone able to write
    /// into the cache can plant one. Created through `mklink` because that is how a real one
    /// arrives; `std` offers no portable way to make a junction.
    #[cfg(windows)]
    #[test]
    fn inspect_rejects_a_junction_standing_in_for_generations() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let real = temp.path().join("real-generations");
        fs::create_dir(&real).unwrap();
        let link = temp.path().join("generations");

        let created = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output()
            .expect("mklink runs");
        assert!(
            created.status.success(),
            "mklink failed: {}",
            String::from_utf8_lossy(&created.stderr)
        );
        // Confirm the fixture is actually a reparse point, so a passing test cannot be explained
        // by the junction never having been created.
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the fixture must really be a reparse point"
        );

        let error = store.inspect().unwrap_err();
        assert!(
            matches!(&error, CacheError::InsecurePath(path) if path == &link),
            "a junction must be refused and named, got {error:?}"
        );
    }

    /// A directory where a cache file is expected must be refused rather than counted.
    ///
    /// Without this, a directory named `current.json` would be read as a zero-byte file and the
    /// cache would be reported healthy-but-empty instead of tampered with.
    #[cfg(windows)]
    #[test]
    fn inspect_rejects_a_directory_in_place_of_a_cache_file() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        fs::create_dir(temp.path().join("current.json")).unwrap();

        let error = store.inspect().unwrap_err();
        assert!(
            matches!(error, CacheError::InsecurePath(_)),
            "a directory in place of a file must be refused, got {error:?}"
        );
    }

    /// An oversized generation reports its size without being read into memory.
    ///
    /// The bound is what keeps `cache status` cheap on a corrupt cache; reading first and checking
    /// afterwards would defeat it exactly when it is needed.
    #[cfg(windows)]
    #[test]
    fn inspect_reports_an_oversized_generation_without_reading_it() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        fs::create_dir_all(temp.path().join("generations")).unwrap();
        fs::write(
            temp.path().join("current.json"),
            br#"{"generation":"gen-big"}"#,
        )
        .unwrap();
        let oversized = vec![b'x'; (INSPECT_GENERATION_BYTE_LIMIT + 1) as usize];
        fs::write(temp.path().join("generations/gen-big.json"), &oversized).unwrap();

        let inspection = store.inspect().unwrap();

        assert_eq!(inspection.current_health, CacheInspectionHealth::Healthy);
        assert_eq!(inspection.schema_health, CacheInspectionHealth::Error);
        assert_eq!(
            inspection.errors,
            vec![CacheInspectionError::CurrentGenerationTooLarge {
                bytes: INSPECT_GENERATION_BYTE_LIMIT + 1,
            }]
        );
    }

    /// Inspection agrees with the writer: what `write_generation` produces is reported healthy.
    ///
    /// Cross-checks two independent implementations rather than one against itself. The writer
    /// creates the layout through its own private-directory path; inspection reaches it through
    /// the separate read-only traversal, so a disagreement about what is acceptable shows up here
    /// instead of as an unexplained failure in the field.
    #[cfg(windows)]
    #[test]
    fn inspect_accepts_what_the_writer_produces_on_windows() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let generation = StoredGeneration {
            generation: "genwin".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-09-03T00:00:00Z".to_string(),
            preview: compact_preview(
                vec![summary(
                    "parent",
                    "dir",
                    PreviewKind::Directory,
                    4096,
                    stale_preview(),
                )],
                &PreviewBudgets::default(),
            ),
            validity: Vec::new(),
        };
        store.write_generation(&generation).unwrap();

        let inspection = store.inspect().unwrap();

        assert!(inspection.exists);
        assert_eq!(inspection.current_generation.as_deref(), Some("genwin"));
        assert_eq!(inspection.current_health, CacheInspectionHealth::Healthy);
        assert_eq!(inspection.schema_health, CacheInspectionHealth::Healthy);
        assert_eq!(inspection.generation_count, 1);
        assert!(inspection.errors.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn inspect_rejects_symlinked_generations_dir() {
        use std::os::unix::fs::symlink;

        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let real_generations = temp.path().join("real-generations");
        fs::create_dir(&real_generations).unwrap();
        symlink(&real_generations, temp.path().join("generations")).unwrap();

        let error = store.inspect().unwrap_err();
        assert!(matches!(error, CacheError::InsecurePath(_)));
    }

    #[cfg(unix)]
    #[test]
    fn inspect_rejects_insecure_root_and_hardlinked_files() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TestTempDir::new();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let store = AtomicGenerationStore::new(temp.path());
        assert!(matches!(store.inspect(), Err(CacheError::InsecurePath(_))));

        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let current = temp.path().join("current.json");
        let alias = temp.path().join("current-alias.json");
        fs::write(&current, br#"{"generation":"gen-1"}"#).unwrap();
        fs::hard_link(&current, &alias).unwrap();
        assert!(matches!(store.inspect(), Err(CacheError::InsecurePath(_))));
    }

    #[cfg(unix)]
    #[test]
    fn inspect_rejects_non_private_cache_subdirectory() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TestTempDir::new();
        let generations = temp.path().join("generations");
        fs::create_dir(&generations).unwrap();
        fs::set_permissions(&generations, fs::Permissions::from_mode(0o777)).unwrap();

        let error = AtomicGenerationStore::new(temp.path())
            .inspect()
            .unwrap_err();
        assert!(matches!(error, CacheError::InsecurePath(path) if path == generations));
    }

    #[cfg(unix)]
    #[test]
    fn writer_rejects_preexisting_non_private_cache_directories() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TestTempDir::new();
        let generations = temp.path().join("generations");
        fs::create_dir(&generations).unwrap();
        fs::set_permissions(&generations, fs::Permissions::from_mode(0o755)).unwrap();
        let store = AtomicGenerationStore::new(temp.path());
        let generation = StoredGeneration {
            generation: "gen-private".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-08-28T00:00:00Z".to_string(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: Vec::new(),
        };

        let error = store.write_generation(&generation).unwrap_err();
        assert!(matches!(error, CacheError::InsecurePath(path) if path == generations));
        assert!(!temp.path().join("current.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn inspect_rejects_dangling_symlink_ancestor_without_creating_state() {
        use std::os::unix::fs::symlink;

        let temp = TestTempDir::new();
        let missing = temp.path().join("missing");
        let link = temp.path().join("dangling");
        symlink(&missing, &link).unwrap();
        let store = AtomicGenerationStore::new(link.join("preview-cache"));

        assert!(matches!(store.inspect(), Err(CacheError::InsecurePath(_))));
        assert!(!missing.exists());
    }

    /// A directory with too many entries is truncated with an explicit warning.
    ///
    /// The bound keeps a status query cheap even against a pathological cache, and the warning
    /// keeps the reported total honest rather than silently capped.
    #[test]
    fn inspect_bounds_generation_scan_and_marks_warning() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let generations = temp.path().join("generations");
        fs::create_dir_all(&generations).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&generations, fs::Permissions::from_mode(0o700)).unwrap();
        for index in 0..=INSPECT_DIRECTORY_ENTRY_LIMIT {
            fs::write(generations.join(format!("gen-{index}.json")), b"{}").unwrap();
        }

        let inspection = store.inspect().unwrap();

        assert_eq!(inspection.generation_count, INSPECT_DIRECTORY_ENTRY_LIMIT);
        assert_eq!(
            inspection.warnings,
            vec![CacheInspectionWarning::GenerationScanTruncated {
                limit: INSPECT_DIRECTORY_ENTRY_LIMIT,
            }]
        );
        assert!(!inspection.approx_bytes_complete());
    }

    /// An unreadable schema is reported, again without quarantining during inspection.
    #[test]
    fn inspect_reports_invalid_schema_without_quarantine() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        fs::create_dir_all(temp.path().join("generations")).unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            temp.path().join("generations"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(
            temp.path().join("current.json"),
            br#"{"generation":"gen-1"}"#,
        )
        .unwrap();
        let generation = StoredGeneration {
            generation: "gen-1".to_string(),
            schema: "bad-schema".to_string(),
            created_at: "2026-08-26T00:00:00Z".to_string(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: Vec::new(),
        };
        let envelope = StoredEnvelope {
            generation: generation.generation.clone(),
            checksum_sha256: checksum_hex(&generation).unwrap(),
            payload: generation,
        };
        fs::write(
            temp.path().join("generations/gen-1.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();

        let inspection = store.inspect().unwrap();

        assert_eq!(inspection.current_health, CacheInspectionHealth::Healthy);
        assert_eq!(inspection.schema_health, CacheInspectionHealth::Error);
        assert_eq!(
            inspection.errors,
            vec![CacheInspectionError::InvalidStoredSchema {
                schema: "bad-schema".to_string(),
            }]
        );
        assert!(!temp.path().join("quarantine").exists());
    }

    #[test]
    fn budget_caps_raise_visible_resource_limit() {
        let rows = (0..10)
            .map(|index| {
                summary(
                    "parent",
                    &format!("dir-{index}"),
                    PreviewKind::Directory,
                    10_000,
                    stale_preview(),
                )
            })
            .collect::<Vec<_>>();
        let budgets = PreviewBudgets {
            preview_byte_cap: 1_000,
            preview_record_cap: 3,
            ..PreviewBudgets::default()
        };
        let admission = admit_preview(
            rows,
            &budgets,
            &BudgetUsage {
                operation_spill_bytes: 0,
                global_spill_bytes: 0,
                state_directory_bytes: 0,
            },
        )
        .unwrap();

        assert!(admission.compacted.visible_resource_limit);
        assert!(
            admission
                .warnings
                .contains(&CacheWarning::ResourceLimit(ReasonCode::ResourceLimit))
        );
        assert!(
            admission.preview_records <= budgets.preview_record_cap
                || admission.compacted.total_records > budgets.preview_record_cap
        );
    }

    #[test]
    fn spill_and_state_caps_reject_instead_of_silent_truncation() {
        let error = admit_preview(
            Vec::new(),
            &PreviewBudgets::default(),
            &BudgetUsage {
                operation_spill_bytes: SPILL_OPERATION_BYTE_CAP + 1,
                global_spill_bytes: 0,
                state_directory_bytes: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CacheError::ResourceLimit {
                reason: ReasonCode::ResourceLimit
            }
        ));

        let error = admit_preview(
            Vec::new(),
            &PreviewBudgets::default(),
            &BudgetUsage {
                operation_spill_bytes: 0,
                global_spill_bytes: 0,
                state_directory_bytes: STATE_DIRECTORY_BYTE_CAP + 1,
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CacheError::ResourceLimit {
                reason: ReasonCode::ResourceLimit
            }
        ));
    }

    #[test]
    fn store_round_trips_atomic_generation() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let generation = StoredGeneration {
            generation: "gen-42".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-08-26T00:00:00Z".to_string(),
            preview: compact_preview(
                vec![summary(
                    "parent",
                    "dir",
                    PreviewKind::Directory,
                    123,
                    stale_preview(),
                )],
                &PreviewBudgets::default(),
            ),
            validity: Vec::new(),
        };

        store.write_generation(&generation).unwrap();
        let loaded = store.load_current().unwrap();
        assert_eq!(loaded, LoadResult::Hit(generation));
    }

    #[test]
    fn invalid_generation_name_is_rejected_before_path_join() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let generation = StoredGeneration {
            generation: "../escape".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-08-26T00:00:00Z".to_string(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: Vec::new(),
        };

        let error = store.write_generation(&generation).unwrap_err();
        assert!(matches!(error, CacheError::InvalidGenerationName));

        fs::write(
            temp.path().join("current.json"),
            br#"{"generation":"../escape"}"#,
        )
        .unwrap();
        let error = store.load_current().unwrap_err();
        assert!(matches!(error, CacheError::InvalidGenerationName));
    }

    #[test]
    fn invalid_schema_is_not_loaded_as_hit() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        fs::create_dir_all(temp.path().join("generations")).unwrap();
        let generation = StoredGeneration {
            generation: "genbad".to_string(),
            schema: "wrong.schema".to_string(),
            created_at: "2026-08-26T00:00:00Z".to_string(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: Vec::new(),
        };
        let envelope = StoredEnvelope {
            generation: generation.generation.clone(),
            checksum_sha256: checksum_hex(&generation).unwrap(),
            payload: generation,
        };
        fs::write(
            temp.path().join("generations/genbad.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
        fs::write(
            temp.path().join("current.json"),
            br#"{"generation":"genbad"}"#,
        )
        .unwrap();

        let loaded = store.load_current().unwrap();
        assert_eq!(loaded, LoadResult::Miss);
        assert!(temp.path().join("quarantine/genbad.corrupt.json").exists());
    }

    #[test]
    fn live_provenance_is_rejected_for_storage() {
        let error = admit_preview(
            vec![summary(
                "parent",
                "live",
                PreviewKind::Directory,
                1,
                FieldProvenance::LiveObservation {
                    observed_at: "2026-08-26T00:00:00Z".to_string(),
                    method: sweepx_model::MethodId::NativeApi,
                },
            )],
            &PreviewBudgets::default(),
            &BudgetUsage {
                operation_spill_bytes: 0,
                global_spill_bytes: 0,
                state_directory_bytes: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(error, CacheError::InvalidStoredProvenance(_)));
    }

    #[test]
    fn mandatory_only_rows_over_cap_return_resource_limit() {
        let error = admit_preview(
            vec![
                summary(
                    "parent",
                    "boundary-1",
                    PreviewKind::Boundary,
                    1,
                    stale_preview(),
                ),
                summary(
                    "parent",
                    "boundary-2",
                    PreviewKind::Boundary,
                    1,
                    stale_preview(),
                ),
            ],
            &PreviewBudgets {
                preview_byte_cap: usize::MAX,
                preview_record_cap: 1,
                ..PreviewBudgets::default()
            },
            &BudgetUsage {
                operation_spill_bytes: 0,
                global_spill_bytes: 0,
                state_directory_bytes: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CacheError::ResourceLimit {
                reason: ReasonCode::ResourceLimit
            }
        ));
    }

    #[test]
    fn trimming_preserves_heaviest_rows() {
        let compacted = compact_preview(
            vec![
                summary(
                    "parent",
                    "largest",
                    PreviewKind::Directory,
                    100,
                    stale_preview(),
                ),
                summary(
                    "parent",
                    "middle",
                    PreviewKind::Directory,
                    90,
                    stale_preview(),
                ),
                summary(
                    "parent",
                    "smallest",
                    PreviewKind::Directory,
                    80,
                    stale_preview(),
                ),
            ],
            &PreviewBudgets {
                preview_byte_cap: usize::MAX,
                preview_record_cap: 2,
                ..PreviewBudgets::default()
            },
        );
        let parent = compacted.parents.get("parent").unwrap();
        assert_eq!(parent.retained.len(), 1);
        assert_eq!(parent.retained[0].entry_id, "largest");
        assert_eq!(
            evidence_to_u128(&parent.others.as_ref().unwrap().allocated_bytes),
            Some(170)
        );
    }

    #[test]
    fn lower_bound_contributors_remain_lower_bound() {
        let mut first = summary(
            "parent",
            "a",
            PreviewKind::Leaf,
            HEAVY_LEAF_THRESHOLD_BYTES,
            stale_preview(),
        );
        first.allocated_bytes = EvidenceValue::LowerBound {
            value: DecimalU128::new(4),
            reason: ReasonCode::IncompleteStreamCoverage,
        };
        first.logical_bytes = first.allocated_bytes.clone();
        let second = summary("parent", "b", PreviewKind::Leaf, 2, stale_preview());

        let others = build_others_summary("parent", &[first, second]);
        assert_eq!(
            others.allocated_bytes,
            EvidenceValue::LowerBound {
                value: DecimalU128::new(6),
                reason: ReasonCode::IncompleteStreamCoverage,
            }
        );
        assert!(matches!(
            others.provenance,
            FieldProvenance::StalePreview { .. }
        ));
    }

    #[test]
    fn deterministic_tie_break_uses_native_name_then_entry_id() {
        let mut left = summary(
            "parent",
            "beta",
            PreviewKind::Directory,
            100,
            stale_preview(),
        );
        let mut right = summary(
            "parent",
            "alpha",
            PreviewKind::Directory,
            100,
            stale_preview(),
        );
        left.native_name = NativeName::unix(b"same".to_vec());
        right.native_name = NativeName::unix(b"same".to_vec());
        let compacted = compact_preview(vec![left, right], &PreviewBudgets::default());
        let retained = &compacted.parents.get("parent").unwrap().retained;
        assert_eq!(retained[0].entry_id, "alpha");
        assert_eq!(retained[1].entry_id, "beta");
    }

    #[test]
    fn heavy_leaf_threshold_is_inclusive() {
        let compacted = compact_preview(
            vec![
                summary(
                    "parent",
                    "below",
                    PreviewKind::Leaf,
                    HEAVY_LEAF_THRESHOLD_BYTES - 1,
                    stale_preview(),
                ),
                summary(
                    "parent",
                    "at",
                    PreviewKind::Leaf,
                    HEAVY_LEAF_THRESHOLD_BYTES,
                    stale_preview(),
                ),
            ],
            &PreviewBudgets::default(),
        );
        let parent = compacted.parents.get("parent").unwrap();
        assert!(parent.retained.iter().any(|row| row.entry_id == "at"));
        assert!(!parent.retained.iter().any(|row| row.entry_id == "below"));
        assert!(parent.others.is_some());
    }
}
