/// Retained native directory handles and resource admission for private cache namespaces.
#[cfg(any(unix, windows))]
pub mod native;
#[cfg(any(windows, test))]
mod windows_state_policy;
/// Windows state-directory security checks, shared with application state admission.
#[cfg(windows)]
pub mod windows_state_security;

mod generation_state;
mod json_budget;
mod writer_admission;
pub use generation_state::GenerationWriteSession;

use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::ffi::OsString;
#[cfg(test)]
use std::fs;
use std::io::{ErrorKind, Write};
#[cfg(all(test, unix))]
use std::os::unix::fs::PermissionsExt;
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
    /// Counts compact JSON bytes without allocating a serialized row. This is the existing
    /// preview admission measure, not an estimate of allocator overhead or process RSS.
    pub fn estimated_bytes(&self) -> usize {
        serialized_len(self).expect("preview summary serialization must succeed")
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

/// Legacy per-volume journal hints retained for generation wire/checksum compatibility.
///
/// These records do not bind full root scope, native identity or capture ordering. NTFS can
/// also coalesce repeated writes before close, so matching positions do not prove current
/// filesystem facts. Consumers must treat loaded generations as historical and independently
/// observe current facts. The checksum binds these bytes to their generation, not to live state.
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
    /// Legacy captured journal position; its ordering relative to the preview is not encoded.
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
    /// Legacy journal hints, preserved when reading old generations. New core previews write
    /// an empty list; neither presence nor absence establishes current-fact reuse authority.
    #[serde(default)]
    pub validity: Vec<VolumeValidityRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredEnvelope<T = StoredGeneration> {
    pub generation: String,
    pub checksum_sha256: String,
    pub payload: T,
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
    CurrentPointerTooLarge {
        bytes: u64,
    },
    MalformedCurrentPointer,
    InvalidCurrentGenerationName,
    MissingCurrentGenerationData,
    CurrentGenerationTooLarge {
        bytes: u64,
    },
    /// Typed JSON storage reservations exceed the cap; the original cache is retained.
    CurrentGenerationParseLimit {
        /// Deserialization storage reservation cap, excluding encoded input/parser scratch.
        reservation_cap_bytes: usize,
    },
    MalformedGenerationEnvelope,
    GenerationChecksumMismatch,
    GenerationPointerMismatch,
    InvalidStoredGenerationName,
    InvalidStoredSchema {
        schema: String,
    },
    InvalidStoredProvenance {
        entry_id: String,
    },
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

    /// Publishes a bounded generation before advancing its pointer. JSON uses compact encoding;
    /// its payload checksum is compatible with existing generations. Oversized encodings are
    /// refused before creating a generation file. Loader reservations are admitted with
    /// bounded per-fragment scratch, without duplicating the complete preview. Filesystem/IO
    /// failures never publish a partially encoded file through the current pointer. IDs must
    /// be new on the actual volume, including case aliases. Retention may remove noncurrent
    /// cache metadata before publication; the old current generation remains protected.
    pub fn write_generation(&self, generation: &StoredGeneration) -> Result<(), CacheError> {
        self.write_generation_with_limit(generation, INSPECT_GENERATION_BYTE_LIMIT as usize)
    }

    fn write_generation_with_limit(
        &self,
        generation: &StoredGeneration,
        byte_limit: usize,
    ) -> Result<(), CacheError> {
        self.write_generation_with_limits(
            generation,
            byte_limit,
            json_budget::PARSE_RESERVATION_CAP,
        )
    }

    fn write_generation_with_limits(
        &self,
        generation: &StoredGeneration,
        byte_limit: usize,
        parse_cap: usize,
    ) -> Result<(), CacheError> {
        // Keep encoding/parser refusals ahead of storage creation for standalone writers.
        let prepared = PreparedGeneration::new(generation, byte_limit, parse_cap)?;
        let mut session = self.begin_write()?;
        prepared.publish(&mut session)
    }

    /// Loads one bounded historical generation through retained private native directories.
    /// Missing storage stays absent. Oversize or unstable files are refused before parsing;
    /// corruption is copied into the same retained namespace, never a re-resolved display path.
    /// Typed parsing uses a separate 256 MiB storage-reservation ledger. Exhaustion preserves
    /// the original generation rather than quarantining it; this is not a process RSS cap.
    pub fn load_current(&self) -> Result<LoadResult, CacheError> {
        let directory = match native::Directory::open(&self.root, false) {
            Ok(directory) => directory,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(LoadResult::Miss),
            Err(error) => return Err(directory_error(error, &self.root)),
        };
        self.load_from_directory(&directory)
    }

    fn load_from_directory(&self, directory: &native::Directory) -> Result<LoadResult, CacheError> {
        self.load_from_directory_with_parse_cap(directory, json_budget::PARSE_RESERVATION_CAP)
    }

    fn load_from_directory_with_parse_cap(
        &self,
        directory: &native::Directory,
        parse_cap: usize,
    ) -> Result<LoadResult, CacheError> {
        let pointer_bytes = match read_generation_bytes(
            directory,
            "current.json",
            INSPECT_CURRENT_POINTER_BYTE_LIMIT,
        )? {
            Some(bytes) => bytes,
            None => return Ok(LoadResult::Miss),
        };

        let pointer: CurrentPointer = match serde_json::from_slice(&pointer_bytes) {
            Ok(pointer) => pointer,
            Err(_) => {
                self.quarantine(directory, "current.json", &pointer_bytes)?;
                return Err(CacheError::Quarantined {
                    path: self.quarantine_path("current.json"),
                });
            }
        };
        validate_generation_id(&pointer.generation)?;

        let generations = match directory.child("generations") {
            Ok(generations) => generations,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(LoadResult::Miss),
            Err(error) => return Err(directory_error(error, &self.generations_dir())),
        };
        let bytes = match read_generation_bytes(
            &generations,
            &format!("{}.json", pointer.generation),
            INSPECT_GENERATION_BYTE_LIMIT,
        )? {
            Some(bytes) => bytes,
            None => return Ok(LoadResult::Miss),
        };

        let envelope: StoredEnvelope = match json_budget::parse_generation(&bytes, parse_cap) {
            Ok(envelope) => envelope,
            Err(json_budget::ParseError::ResourceLimit) => {
                return Err(CacheError::ResourceLimit {
                    reason: ReasonCode::ResourceLimit,
                });
            }
            Err(json_budget::ParseError::Json) => {
                self.quarantine_generation(directory, &pointer.generation, &bytes)?;
                return Ok(LoadResult::Miss);
            }
        };

        let checksum = checksum_hex(&envelope.payload)?;
        if checksum != envelope.checksum_sha256
            || pointer.generation != envelope.generation
            || envelope.generation != envelope.payload.generation
        {
            self.quarantine_generation(directory, &pointer.generation, &bytes)?;
            return Ok(LoadResult::Miss);
        }
        if validate_stored_generation(&envelope.payload).is_err() {
            self.quarantine_generation(directory, &pointer.generation, &bytes)?;
            return Ok(LoadResult::Miss);
        }

        Ok(LoadResult::Hit(envelope.payload))
    }

    /// Reports the health of the on-disk preview cache without modifying it.
    ///
    /// Inspection never creates directories, never repairs, and never quarantines: it is the
    /// read-only counterpart to [`Self::load_current`], which may quarantine corrupt data. A caller diagnosing a
    /// broken cache must be able to look at it without changing what they are looking at.
    ///
    /// The traversal is platform-specific because the anti-substitution guarantee is. Unix walks
    /// the path with `openat`/`O_NOFOLLOW` so no component can be swapped between the check and
    /// the read; Windows opens each handle with the sharing mode and reparse-point rejection that
    /// give the equivalent property. Everything after opening — the size accounting, the byte
    /// limits, the parse and checksum decisions — is shared, so the two platforms cannot drift in
    /// what they consider healthy.
    /// Parsing shares the loader's storage-reservation budget; exhaustion is a typed diagnostic,
    /// independent of encoded size, malformed JSON or a checksum mismatch.
    pub fn inspect(&self) -> Result<CacheInspection, CacheError> {
        self.inspect_with_parse_cap(json_budget::PARSE_RESERVATION_CAP)
    }

    fn inspect_with_parse_cap(&self, parse_cap: usize) -> Result<CacheInspection, CacheError> {
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

        let envelope: StoredEnvelope =
            match json_budget::parse_generation(&generation_bytes, parse_cap) {
                Ok(envelope) => envelope,
                Err(json_budget::ParseError::ResourceLimit) => {
                    inspection.schema_health = CacheInspectionHealth::Error;
                    inspection
                        .errors
                        .push(CacheInspectionError::CurrentGenerationParseLimit {
                            reservation_cap_bytes: parse_cap,
                        });
                    return Ok(inspection);
                }
                Err(json_budget::ParseError::Json) => {
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

    fn quarantine(
        &self,
        directory: &native::Directory,
        name: &str,
        bytes: &[u8],
    ) -> Result<(), CacheError> {
        GenerationWriteSession::quarantine(self, directory, name, bytes)
    }

    fn quarantine_generation(
        &self,
        directory: &native::Directory,
        generation: &str,
        bytes: &[u8],
    ) -> Result<(), CacheError> {
        self.quarantine(directory, &format!("{generation}.corrupt.json"), bytes)
    }
}

/// Borrowed generation admission; no complete JSON or preview copy is retained.
struct PreparedGeneration<'a> {
    envelope: StoredEnvelope<&'a StoredGeneration>,
    encoded_bytes: u64,
    byte_limit: usize,
    pointer_bytes: Vec<u8>,
}

impl<'a> PreparedGeneration<'a> {
    fn new(
        generation: &'a StoredGeneration,
        byte_limit: usize,
        parse_cap: usize,
    ) -> Result<Self, CacheError> {
        validate_generation_id(&generation.generation)?;
        writer_admission::admit(generation, parse_cap)?;
        validate_stored_generation(generation)?;
        let (checksum_sha256, payload_bytes) = checksum_and_len(generation)?;
        let envelope = StoredEnvelope {
            generation: generation.generation.clone(),
            checksum_sha256,
            payload: generation,
        };
        // Actual encoded length, including the envelope; caller preview counters are not proof.
        // Hashing already counted the payload, so counting this header avoids another full pass.
        let header = StoredEnvelope {
            generation: envelope.generation.clone(),
            checksum_sha256: envelope.checksum_sha256.clone(),
            payload: (),
        };
        let header_bytes = serialized_len(&header)? - serialized_len(&())?;
        if payload_bytes > byte_limit.saturating_sub(header_bytes) || header_bytes > byte_limit {
            return Err(CacheError::ResourceLimit {
                reason: ReasonCode::ResourceLimit,
            });
        }
        let pointer_bytes = serde_json::to_vec_pretty(&CurrentPointer {
            generation: generation.generation.clone(),
        })?;
        Ok(Self {
            envelope,
            encoded_bytes: (payload_bytes + header_bytes) as u64,
            byte_limit,
            pointer_bytes,
        })
    }

    fn publish(self, session: &mut GenerationWriteSession) -> Result<(), CacheError> {
        let name = format!("{}.json", self.envelope.generation);
        // Conservatively reserve coexistence of old data plus the complete generation and
        // pointer temporaries. No quota failure can advance the old current pointer.
        session.reserve(&name, self.encoded_bytes + self.pointer_bytes.len() as u64)?;
        session.bindings()?;
        session.generations().publish(&name, |file| {
            let mut writer = LimitedWriter::new(
                std::io::BufWriter::with_capacity(16 * 1024, &mut *file),
                self.byte_limit,
            );
            serde_json::to_writer(&mut writer, &self.envelope).map_err(std::io::Error::other)?;
            writer.flush()?;
            drop(writer);
            file.sync_all()
        })?;
        // A substituted generations directory must not receive a pointer to data published
        // through our retained original child. An orphan from a failed publication is disposable.
        session.bindings()?;
        session.root().publish("current.json", |file| {
            file.write_all(&self.pointer_bytes)?;
            file.sync_all()
        })?;
        Ok(())
    }
}

fn directory_error(error: std::io::Error, display: &Path) -> CacheError {
    // Admission errors carry no authority. Keep genuine I/O failures distinct from a
    // linked, public or unsupported directory without trying to repair its permissions.
    match error.kind() {
        ErrorKind::Other | ErrorKind::PermissionDenied | ErrorKind::NotADirectory => {
            CacheError::InsecurePath(display.to_path_buf())
        }
        _ => CacheError::Io(error),
    }
}

fn read_generation_bytes(
    directory: &native::Directory,
    name: &str,
    cap: u64,
) -> Result<Option<Vec<u8>>, CacheError> {
    match directory.read_bytes(name, cap) {
        Ok(native::BoundedRead {
            contents: Some(bytes),
            ..
        }) => Ok(Some(bytes)),
        Ok(native::BoundedRead { contents: None, .. }) => Err(CacheError::ResourceLimit {
            reason: ReasonCode::ResourceLimit,
        }),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CacheError::Io(error)),
    }
}

/// Read-only inspection retains the same native authority as generation loading and publication.
struct InspectionReader {
    directory: native::Directory,
}

impl InspectionReader {
    fn open_root(path: &Path) -> Result<Option<Self>, CacheError> {
        match native::Directory::open(path, false) {
            Ok(directory) => Ok(Some(Self { directory })),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(directory_error(error, path)),
        }
    }

    fn open_optional_dir(&self, name: &str, display: &Path) -> Result<Option<Self>, CacheError> {
        match self.directory.child(name) {
            Ok(directory) => Ok(Some(Self { directory })),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(directory_error(error, display)),
        }
    }

    fn read_optional_file(
        &self,
        name: &str,
        display: &Path,
        byte_limit: u64,
    ) -> Result<Option<InspectedFile>, CacheError> {
        match self.directory.read_bytes(name, byte_limit) {
            Ok(native::BoundedRead { bytes, contents }) => Ok(Some(InspectedFile {
                bytes,
                contents: match contents {
                    Some(contents) => InspectFileContents::Bytes(contents),
                    None => InspectFileContents::TooLarge { bytes },
                },
            })),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(directory_error(error, display)),
        }
    }

    fn scan_flat(&self, path: &Path) -> Result<InspectedDir, CacheError> {
        let mut result = InspectedDir {
            count: 0,
            bytes: 0,
            truncated: false,
        };
        let mut insecure = None;
        let scanned = self.directory.entries_all(|name| {
            if result.count == INSPECT_DIRECTORY_ENTRY_LIMIT {
                result.truncated = true;
                return Err(std::io::Error::from(ErrorKind::Interrupted));
            }
            let Some(name) = name else {
                insecure = Some(path.to_path_buf());
                return Err(std::io::Error::other("unrepresentable cache entry"));
            };
            // Read no content during accounting, but still admit the native object as a
            // private regular file. No followed metadata or lossy-name totals.
            let file = self.directory.accounting_metadata(name)?;
            result.count += 1;
            result.bytes = result.bytes.saturating_add(file.bytes);
            Ok(())
        });
        match scanned {
            Ok(()) => Ok(result),
            Err(_) if result.truncated => Ok(result),
            Err(_) if insecure.is_some() => Err(CacheError::InsecurePath(insecure.unwrap())),
            Err(error) => Err(directory_error(error, path)),
        }
    }
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

    trim_to_budgets(compacted, budgets)
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
    let mut retained = mandatory;
    for (index, mut entry) in eligible.into_iter().enumerate() {
        if index < TOP_HEAVY_CHILDREN {
            entry.roles.insert(PreviewRole::TopHeavyChild);
            retained.push(entry);
        } else {
            remainder.push(entry);
        }
    }
    retained.sort_by(compare_preview_rows);

    let others = if remainder.is_empty() {
        None
    } else {
        Some(build_others_summary(&parent_id, &remainder))
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

fn trim_to_budgets(mut compacted: CompactedPreview, budgets: &PreviewBudgets) -> CompactedPreview {
    let over_budget =
        |records, bytes| records > budgets.preview_record_cap || bytes > budgets.preview_byte_cap;
    if !over_budget(compacted.total_records, compacted.total_estimated_bytes) {
        return compacted;
    }
    compacted.visible_resource_limit = true;

    // Rank only integer slots once. Immutable row ranks never change during eviction, and
    // Others/mandatory rows never participate. Tied ranks choose the last parent/row as the
    // old BTreeMap/Vec max_by did. No candidate owns a duplicate name, aggregate or provenance.
    let parents: Vec<_> = compacted.parents.values().collect();
    let mut candidates: Vec<_> = parents
        .iter()
        .enumerate()
        .flat_map(|(parent_index, parent)| {
            parent
                .retained
                .iter()
                .enumerate()
                .filter(|(_, row)| !row.is_mandatory())
                .map(move |(row_index, _)| (parent_index, row_index))
        })
        .collect();
    candidates.sort_unstable_by(|left, right| {
        compare_preview_rows(
            &parents[left.0].retained[left.1],
            &parents[right.0].retained[right.1],
        )
        .then_with(|| left.cmp(right))
    });

    struct Slots {
        key: String,
        parent_id: String,
        retained: Vec<Option<PreviewSummary>>,
        others: Option<PreviewSummary>,
        others_bytes: usize,
    }
    // Vacant slots keep ranking indexes stable while rows move into Others. Both vectors are
    // bounded by the already-owned input/compacted rows; neither retains another payload copy.
    let mut slots: Vec<_> = std::mem::take(&mut compacted.parents)
        .into_iter()
        .map(|(key, parent)| Slots {
            key,
            parent_id: parent.parent_id,
            retained: parent.retained.into_iter().map(Some).collect(),
            others_bytes: parent
                .others
                .as_ref()
                .map_or(0, PreviewSummary::estimated_bytes),
            others: parent.others,
        })
        .collect();
    for (parent_index, row_index) in candidates.into_iter().rev() {
        if !over_budget(compacted.total_records, compacted.total_estimated_bytes) {
            break;
        }
        let parent = &mut slots[parent_index];
        let removed = parent.retained[row_index]
            .take()
            .expect("each ranked slot is evicted once");
        let removed_bytes = removed.estimated_bytes();
        let removed = removed.with_role_removed(&PreviewRole::TopHeavyChild);
        let had_others = parent.others.is_some();
        let others = if let Some(existing) = parent.others.take() {
            // Preserve the original fold order, including reason order and unknown/lower-bound
            // propagation. Merging at most two rows never recreates all previous omitted rows.
            build_others_summary(&parent.parent_id, &[existing, removed])
        } else {
            build_others_summary(&parent.parent_id, std::slice::from_ref(&removed))
        };
        let others_bytes = others.estimated_bytes();
        compacted.total_records = compacted.total_records - 1 + usize::from(!had_others);
        compacted.total_estimated_bytes =
            compacted.total_estimated_bytes - removed_bytes - parent.others_bytes + others_bytes;
        parent.others_bytes = others_bytes;
        parent.others = Some(others);
    }
    compacted.parents = slots
        .into_iter()
        .map(|parent| {
            (
                parent.key,
                ParentPreview {
                    parent_id: parent.parent_id,
                    retained: parent.retained.into_iter().flatten().collect(),
                    others: parent.others,
                },
            )
        })
        .collect();
    compacted
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

struct CountingWriter(usize);
impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialized_len<T: Serialize>(value: &T) -> Result<usize, serde_json::Error> {
    let mut writer = CountingWriter(0);
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.0)
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct LimitedWriter<W> {
    inner: W,
    limit: usize,
    written: usize,
    exhausted: bool,
}
impl<W> LimitedWriter<W> {
    fn new(inner: W, limit: usize) -> Self {
        Self {
            inner,
            limit,
            written: 0,
            exhausted: false,
        }
    }
}
impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.written) {
            self.exhausted = true;
            return Err(std::io::Error::other(
                "preview JSON byte allowance exhausted",
            ));
        }
        let count = self.inner.write(bytes)?;
        self.written += count;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn checksum_hex(generation: &StoredGeneration) -> Result<String, CacheError> {
    checksum_and_len(generation).map(|(checksum, _)| checksum)
}

fn checksum_and_len(generation: &StoredGeneration) -> Result<(String, usize), CacheError> {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    // Small serializer fragments share a fixed buffer before SHA-256; buffering stays bounded
    // and preserves the exact byte sequence/domain used by existing on-disk checksums.
    let mut writer = LimitedWriter::new(
        std::io::BufWriter::with_capacity(16 * 1024, HashWriter(hasher)),
        INSPECT_GENERATION_BYTE_LIMIT as usize,
    );
    let result = serde_json::to_writer(&mut writer, generation);
    if writer.exhausted {
        return Err(CacheError::ResourceLimit {
            reason: ReasonCode::ResourceLimit,
        });
    }
    result?;
    let hash_writer = writer
        .inner
        .into_inner()
        .map_err(|error| error.into_error())?;
    Ok((
        hex_lower(hash_writer.0.finalize().as_slice()),
        writer.written,
    ))
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

    pub(super) struct TestTempDir {
        // Keep the atomically created directory alive for the complete fixture lifetime.
        _directory: tempfile::TempDir,
        path: PathBuf,
    }

    impl TestTempDir {
        pub(super) fn new() -> Self {
            // Wall-clock nanoseconds are not unique across threads. create_dir_all would
            // silently share a colliding fixture, letting another test remove its live files.
            let directory = tempfile::Builder::new()
                .prefix("sweepx-cache-test-")
                .tempdir()
                .expect("test temp dir must be atomically creatable");
            let path = directory.path().to_path_buf();
            #[cfg(windows)]
            let path = {
                let path = path.join("cache");
                native::Directory::open(&path, true).expect("private fixture root");
                path
            };
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("test temp dir permissions must be private");
            }
            // Resolve Unix symlinked temporary ancestors before native no-follow admission.
            //
            // Windows keeps the ordinary absolute drive path; no verbatim canonicalization.
            #[cfg(unix)]
            let path = path
                .canonicalize()
                .expect("test temp dir must be resolvable");
            Self {
                _directory: directory,
                path,
            }
        }

        pub(super) fn path(&self) -> &Path {
            &self.path
        }
    }

    // Deliberately construct private fixtures independently of the production JSON encoder.
    // Unix permissions use the ordinary filesystem API; Windows requires explicit DACL creation.
    pub(super) fn create_fixture_dir(path: impl AsRef<Path>) -> std::io::Result<()> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            fs::create_dir_all(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(windows)]
        {
            native::Directory::open(path, true)?;
        }
        Ok(())
    }

    pub(super) fn write_fixture(
        path: impl AsRef<Path>,
        bytes: impl AsRef<[u8]>,
    ) -> std::io::Result<()> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            fs::write(path, bytes)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(windows)]
        {
            let directory = native::Directory::open(path.parent().unwrap(), false)?;
            directory.publish(path.file_name().unwrap().to_str().unwrap(), |file| {
                file.write_all(bytes.as_ref())
            })?;
        }
        Ok(())
    }

    #[test]
    fn load_missing_cache_stays_absent() {
        let fixture = TestTempDir::new();
        let root = fixture.path().join("missing");
        assert_eq!(
            AtomicGenerationStore::new(&root).load_current().unwrap(),
            LoadResult::Miss
        );
        assert!(!root.exists());
    }

    #[test]
    fn loading_refuses_oversize_files_without_quarantine_or_publication() {
        for pointer in [true, false] {
            let fixture = TestTempDir::new();
            let store = AtomicGenerationStore::new(fixture.path());
            create_fixture_dir(store.generations_dir()).unwrap();
            write_fixture(store.current_pointer_path(), br#"{"generation":"huge"}"#).unwrap();
            let path = if pointer {
                store.current_pointer_path()
            } else {
                store.generation_path("huge")
            };
            if !pointer {
                write_fixture(&path, b"").unwrap();
            }
            let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
            // Literal independent length, well above either documented cap. Sparse set_len
            // avoids allocating or writing a giant fixture, especially on Windows.
            file.set_len(4 * 1024 * 1024 * 1024).unwrap();
            drop(file);
            assert_eq!(fs::metadata(&path).unwrap().len(), 4_294_967_296);
            assert!(matches!(
                store.load_current(),
                Err(CacheError::ResourceLimit { .. })
            ));
            assert!(!store.quarantine_dir().exists());
            assert_eq!(
                fs::read_dir(store.generations_dir()).unwrap().count(),
                usize::from(!pointer)
            );
            let inspection = store.inspect().unwrap();
            assert_eq!(
                inspection.errors,
                if pointer {
                    vec![CacheInspectionError::CurrentPointerTooLarge {
                        bytes: 4_294_967_296,
                    }]
                } else {
                    vec![CacheInspectionError::CurrentGenerationTooLarge {
                        bytes: 4_294_967_296,
                    }]
                }
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn retained_generation_load_and_quarantine_ignore_replaced_display_root() {
        let fixture = TestTempDir::new();
        let root = fixture.path().join("cache");
        let store = AtomicGenerationStore::new(&root);
        let generation = StoredGeneration {
            generation: "original".into(),
            schema: STORED_PREVIEW_SCHEMA.into(),
            created_at: "2026-10-03T00:00:00Z".into(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
            validity: Vec::new(),
        };
        store.write_generation(&generation).unwrap();
        let retained = native::Directory::open(&root, false).unwrap();
        let old = fixture.path().join("retained");
        fs::rename(&root, &old).unwrap();
        create_fixture_dir(&root).unwrap();
        write_fixture(root.join("current.json"), b"replacement sentinel").unwrap();
        assert_eq!(
            store.load_from_directory(&retained).unwrap(),
            LoadResult::Hit(generation)
        );
        // The public path now denotes another object. Corruption must be quarantined into
        // the retained namespace, even when the display path still looks healthy.
        write_fixture(old.join("generations/original.json"), b"broken generation").unwrap();
        assert_eq!(
            store.load_from_directory(&retained).unwrap(),
            LoadResult::Miss
        );
        assert_eq!(
            fs::read(old.join("quarantine/original.corrupt.json")).unwrap(),
            b"broken generation"
        );
        assert!(!root.join("quarantine").exists());
        assert_eq!(
            fs::read(root.join("current.json")).unwrap(),
            b"replacement sentinel"
        );
    }

    // APFS rejects raw invalid UTF-8 filenames with EILSEQ before enumeration. Linux's
    // native byte-name fixture covers this branch; Windows unknown UTF-16 has a portable oracle.
    #[cfg(target_os = "linux")]
    #[test]
    fn inspection_cannot_silently_omit_opaque_native_names() {
        use std::os::unix::ffi::OsStringExt;
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        create_fixture_dir(store.generations_dir()).unwrap();
        let path = store.generations_dir().join(OsString::from_vec(vec![0xff]));
        write_fixture(&path, b"private unknown").unwrap();
        assert!(matches!(store.inspect(), Err(CacheError::InsecurePath(_))));
        assert_eq!(fs::read(path).unwrap(), b"private unknown");
        assert!(!store.quarantine_dir().exists());
    }

    #[cfg(unix)]
    #[test]
    fn loading_refuses_public_aliased_and_special_pointer_files() {
        use std::ffi::CString;
        for case in ["public", "alias", "fifo"] {
            let fixture = TestTempDir::new();
            let store = AtomicGenerationStore::new(fixture.path());
            let path = store.current_pointer_path();
            if case == "fifo" {
                let name = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                // SAFETY: the fixture owns this literal path; no producer is started. Native
                // nonblocking open must reject the type instead of waiting for a writer.
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            } else {
                write_fixture(&path, br#"{"generation":"missing"}"#).unwrap();
                if case == "public" {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                } else {
                    fs::hard_link(&path, fixture.path().join("alias")).unwrap();
                }
            }
            assert!(store.load_current().is_err(), "{case} must not be parsed");
            assert!(fs::symlink_metadata(&path).is_ok());
            assert!(!store.quarantine_dir().exists());
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
        let path = store.generation_path("gen-old");
        let mut envelope: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["payload"]
            .as_object_mut()
            .unwrap()
            .remove("validity")
            .expect("the field must be present before it is removed");
        let legacy: StoredGeneration = serde_json::from_value(envelope["payload"].clone()).unwrap();
        envelope["checksum_sha256"] = json!(checksum_hex(&legacy).unwrap());
        write_fixture(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

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

        let path = store.generation_path("gen-tamper");
        let mut envelope: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        // Edit the token in place and leave the checksum alone: that is what an attacker who
        // wants a false "unchanged" verdict would have to do.
        assert_eq!(
            envelope["payload"]["validity"][0]["position"], "100",
            "the field this test edits must exist, or the edit proves nothing"
        );
        envelope["payload"]["validity"][0]["position"] = json!("999");
        write_fixture(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

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

        let generation_path = store.generation_path("gen-1");
        write_fixture(&generation_path, b"{not-json").unwrap();

        let loaded = store.load_current().unwrap();
        assert_eq!(loaded, LoadResult::Miss);
        assert!(temp.path().join("quarantine/gen-1.corrupt.json").exists());
    }

    #[test]
    fn generation_must_match_current_pointer_and_referenced_path() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        create_fixture_dir(temp.path().join("generations")).unwrap();
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
        write_fixture(temp.path().join("generations/gen-a.json"), &envelope_bytes).unwrap();
        write_fixture(
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
        write_fixture(&target, br#"{"generation":"gen-1"}"#).unwrap();
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
        create_fixture_dir(&real_generations).unwrap();
        let generations = store.generations_dir();
        symlink(&real_generations, &generations).unwrap();
        let error = store.write_generation(&generation).unwrap_err();
        assert!(matches!(error, CacheError::InsecurePath(_)));

        fs::remove_file(store.generations_dir()).unwrap();
        create_fixture_dir(store.generations_dir()).unwrap();
        write_fixture(store.generation_path("gen-1"), b"{not-json").unwrap();
        write_fixture(
            temp.path().join("current.json"),
            br#"{"generation":"gen-1"}"#,
        )
        .unwrap();
        let real_quarantine = temp.path().join("real-quarantine");
        create_fixture_dir(&real_quarantine).unwrap();
        symlink(&real_quarantine, store.quarantine_dir()).unwrap();
        let error = store.load_current().unwrap_err();
        assert!(matches!(error, CacheError::InsecurePath(_)));
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_symlink_in_store_root_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = TestTempDir::new();
        let real = temp.path().join("real");
        create_fixture_dir(&real).unwrap();
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
        create_fixture_dir(temp.path().join("quarantine")).unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            temp.path().join("quarantine"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        write_fixture(temp.path().join("quarantine/old.corrupt.json"), b"broken").unwrap();

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
        create_fixture_dir(temp.path()).unwrap();
        let current_path = temp.path().join("current.json");
        let original = b"{not-json".to_vec();
        write_fixture(&current_path, &original).unwrap();

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
        write_fixture(
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
        create_fixture_dir(&real).unwrap();
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
        create_fixture_dir(temp.path().join("current.json")).unwrap();

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
        create_fixture_dir(temp.path().join("generations")).unwrap();
        write_fixture(
            temp.path().join("current.json"),
            br#"{"generation":"gen-big"}"#,
        )
        .unwrap();
        let oversized = vec![b'x'; (INSPECT_GENERATION_BYTE_LIMIT + 1) as usize];
        write_fixture(temp.path().join("generations/gen-big.json"), &oversized).unwrap();

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
        create_fixture_dir(&real_generations).unwrap();
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
        write_fixture(&current, br#"{"generation":"gen-1"}"#).unwrap();
        fs::hard_link(&current, &alias).unwrap();
        assert!(matches!(store.inspect(), Err(CacheError::InsecurePath(_))));
    }

    #[cfg(unix)]
    #[test]
    fn inspect_rejects_non_private_cache_subdirectory() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TestTempDir::new();
        let generations = temp.path().join("generations");
        create_fixture_dir(&generations).unwrap();
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
        create_fixture_dir(&generations).unwrap();
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
        create_fixture_dir(&generations).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&generations, fs::Permissions::from_mode(0o700)).unwrap();
        for index in 0..=INSPECT_DIRECTORY_ENTRY_LIMIT {
            write_fixture(generations.join(format!("gen-{index}.json")), b"{}").unwrap();
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
        create_fixture_dir(temp.path().join("generations")).unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            temp.path().join("generations"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        write_fixture(
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
        write_fixture(
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
    fn parsed_storage_limit_preserves_generation_and_reports_read_only_diagnostics() {
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path());
        let generation = StoredGeneration {
            generation: "parse-fixture".into(),
            schema: STORED_PREVIEW_SCHEMA.into(),
            created_at: "2026-10-03T00:00:00Z".into(),
            preview: compact_preview(
                vec![summary(
                    "parent",
                    "file",
                    PreviewKind::Directory,
                    1,
                    stale_preview(),
                )],
                &PreviewBudgets::default(),
            ),
            validity: Vec::new(),
        };
        store.write_generation(&generation).unwrap();
        let pointer_before = fs::read(store.root().join("current.json")).unwrap();
        let generation_before = fs::read(store.generation_path("parse-fixture")).unwrap();
        let directory = native::Directory::open(store.root(), false).unwrap();
        // Same production loader/inspector with a controlled cap, without a huge host fixture.
        assert!(matches!(
            store.load_from_directory_with_parse_cap(&directory, 1024),
            Err(CacheError::ResourceLimit { .. })
        ));
        let inspection = store.inspect_with_parse_cap(1024).unwrap();
        assert_eq!(inspection.schema_health, CacheInspectionHealth::Error);
        assert_eq!(
            inspection.errors,
            [CacheInspectionError::CurrentGenerationParseLimit {
                reservation_cap_bytes: 1024
            }]
        );
        assert_eq!(
            fs::read(store.root().join("current.json")).unwrap(),
            pointer_before
        );
        assert_eq!(
            fs::read(store.generation_path("parse-fixture")).unwrap(),
            generation_before
        );
        assert!(!store.quarantine_dir().exists());
        assert_eq!(store.load_current().unwrap(), LoadResult::Hit(generation));
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

        write_fixture(
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
        create_fixture_dir(temp.path().join("generations")).unwrap();
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
        write_fixture(
            temp.path().join("generations/genbad.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
        write_fixture(
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

    #[test]
    fn measured_json_and_streamed_checksum_match_independent_legacy_encoding() {
        let mut row = summary(
            "parent",
            "escaped",
            PreviewKind::Directory,
            3,
            stale_preview(),
        );
        row.display_name = "quote\" slash\\ newline\n中文😀".into();
        row.coverage.incomplete_reasons = vec![ReasonCode::IncompleteStreamCoverage];
        assert_eq!(
            row.estimated_bytes(),
            serde_json::to_vec(&row).unwrap().len()
        );
        let generation = StoredGeneration {
            generation: "streamed_compatible".into(),
            schema: STORED_PREVIEW_SCHEMA.into(),
            created_at: "fixture".into(),
            preview: compact_preview(vec![row], &PreviewBudgets::default()),
            validity: Vec::new(),
        };
        let encoded = serde_json::to_vec(&generation).unwrap();
        let mut oracle = Sha256::new();
        // Literal existing disk contract, independent of the implementation's constant/writer.
        oracle.update(b"SweepX sparse preview generation v1\0");
        oracle.update(&encoded);
        assert_eq!(
            checksum_hex(&generation).unwrap(),
            format!("{:x}", oracle.finalize())
        );
        assert_eq!(serialized_len(&generation).unwrap(), encoded.len());
        let owned = StoredEnvelope {
            generation: generation.generation.clone(),
            checksum_sha256: checksum_hex(&generation).unwrap(),
            payload: generation.clone(),
        };
        let borrowed = StoredEnvelope {
            generation: owned.generation.clone(),
            checksum_sha256: owned.checksum_sha256.clone(),
            payload: &generation,
        };
        assert_eq!(
            serde_json::to_vec(&owned).unwrap(),
            serde_json::to_vec(&borrowed).unwrap()
        );
        let (_, payload_bytes) = checksum_and_len(&generation).unwrap();
        let header = StoredEnvelope {
            generation: owned.generation.clone(),
            checksum_sha256: owned.checksum_sha256.clone(),
            payload: (),
        };
        assert_eq!(
            payload_bytes + serialized_len(&header).unwrap() - serialized_len(&()).unwrap(),
            serde_json::to_vec(&owned).unwrap().len()
        );
    }

    #[test]
    fn limited_writer_caps_actual_bytes_and_keeps_underlying_io_errors_distinct() {
        let mut writer = LimitedWriter::new(Vec::new(), 8);
        writer.write_all(b"12345").unwrap();
        writer.write_all(b"678").unwrap();
        assert!(writer.write_all(b"9").is_err());
        assert!(writer.exhausted);
        assert_eq!(writer.inner, b"12345678");
        struct Failing {
            bytes: Vec<u8>,
        }
        impl Write for Failing {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let available = 3 - self.bytes.len();
                if available == 0 {
                    return Err(std::io::Error::other("controlled write failure"));
                }
                let count = available.min(bytes.len());
                self.bytes.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut writer = LimitedWriter::new(Failing { bytes: Vec::new() }, 64);
        let error = writer.write_all(b"abcdef").unwrap_err();
        assert!(error.to_string().contains("controlled write failure"));
        assert!(!writer.exhausted);
        assert_eq!(writer.written, 3);
        assert_eq!(writer.inner.bytes, b"abc");
    }

    #[test]
    fn rejected_encoded_generation_preserves_pointer_and_creates_no_generation_file() {
        let fixture = TestTempDir::new();
        let store = AtomicGenerationStore::new(fixture.path().join("cache"));
        let mut generation = StoredGeneration {
            generation: "first".into(),
            schema: STORED_PREVIEW_SCHEMA.into(),
            created_at: "fixture".into(),
            preview: compact_preview(
                vec![summary(
                    "parent",
                    "one",
                    PreviewKind::Directory,
                    1,
                    stale_preview(),
                )],
                &PreviewBudgets::default(),
            ),
            validity: Vec::new(),
        };
        store.write_generation(&generation).unwrap();
        let original = fs::read(store.current_pointer_path()).unwrap();
        generation.generation = "too_large".into();
        // Public counters can be forged. Actual encoding remains the admission authority.
        generation.preview.total_estimated_bytes = 0;
        let error = store
            .write_generation_with_limit(&generation, 256)
            .unwrap_err();
        assert!(matches!(error, CacheError::ResourceLimit { .. }));
        assert_eq!(fs::read(store.current_pointer_path()).unwrap(), original);
        let names: BTreeSet<_> = fs::read_dir(store.generations_dir())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, BTreeSet::from([OsString::from("first.json")]));
        let LoadResult::Hit(restored) = store.load_current().unwrap() else {
            panic!("old generation remains")
        };
        assert_eq!(restored.generation, "first");
    }

    #[test]
    fn incremental_trimming_matches_exhaustive_eviction_and_json_size_oracle() {
        use std::cmp::Reverse;
        fn rank(row: &PreviewSummary) -> Option<u128> {
            fn value(value: &ByteValue) -> Option<u128> {
                match value {
                    EvidenceValue::Known { value } | EvidenceValue::LowerBound { value, .. } => {
                        Some(value.0)
                    }
                    _ => None,
                }
            }
            value(&row.allocated_bytes).or_else(|| value(&row.logical_bytes))
        }
        fn recount(preview: &mut CompactedPreview) {
            let rows: Vec<_> = preview
                .parents
                .values()
                .flat_map(|parent| parent.retained.iter().chain(parent.others.iter()))
                .collect();
            preview.total_records = rows.len();
            preview.total_estimated_bytes = rows
                .iter()
                .map(|row| serde_json::to_vec(row).unwrap().len())
                .sum();
        }
        fn oracle(mut full: CompactedPreview, budgets: &PreviewBudgets) -> CompactedPreview {
            while full.total_records > budgets.preview_record_cap
                || full.total_estimated_bytes > budgets.preview_byte_cap
            {
                full.visible_resource_limit = true;
                // Exhaustive search and materialized JSON recount differ from ranked slots and
                // incremental counters. All comparator ties choose the later parent/position.
                let candidate = full
                    .parents
                    .iter()
                    .flat_map(|(parent_key, parent)| {
                        parent
                            .retained
                            .iter()
                            .enumerate()
                            .filter(|(_, row)| !row.is_mandatory())
                            .map(move |(index, row)| {
                                (
                                    (
                                        rank(row),
                                        Reverse(row.native_name.encoded_value()),
                                        Reverse(row.entry_id.as_str()),
                                        Reverse(parent_key.as_str()),
                                        Reverse(index),
                                    ),
                                    parent_key,
                                    index,
                                )
                            })
                    })
                    .min_by(|left, right| left.0.cmp(&right.0))
                    .map(|(_, key, index)| (key.clone(), index));
                let Some((key, index)) = candidate else {
                    break;
                };
                let parent = full.parents.get_mut(&key).unwrap();
                let mut removed = parent.retained.remove(index);
                removed.roles.remove(&PreviewRole::TopHeavyChild);
                let mut inputs = Vec::new();
                inputs.extend(parent.others.take());
                inputs.push(removed);
                parent.others = Some(build_others_summary(&parent.parent_id, &inputs));
                recount(&mut full);
            }
            full
        }
        let mut rows = Vec::new();
        for parent in ["a", "b", "c"] {
            for (name, bytes) in [("same", 4), ("large", 9), ("zero", 0)] {
                rows.push(summary(
                    parent,
                    name,
                    PreviewKind::Directory,
                    bytes,
                    stale_preview(),
                ));
            }
            let mut unknown = summary(
                parent,
                "unknown",
                PreviewKind::Directory,
                0,
                stale_preview(),
            );
            unknown.logical_bytes = EvidenceValue::Unknown {
                reason: ReasonCode::IncompleteStreamCoverage,
            };
            unknown.allocated_bytes = unknown.logical_bytes.clone();
            unknown.coverage = coverage(false);
            rows.push(unknown);
            rows.push(summary(
                parent,
                "boundary",
                PreviewKind::Boundary,
                0,
                stale_preview(),
            ));
            rows.push(summary(
                parent,
                "tiny",
                PreviewKind::Leaf,
                2,
                stale_preview(),
            ));
        }
        let full = compact_preview(
            rows.clone(),
            &PreviewBudgets {
                preview_record_cap: usize::MAX,
                preview_byte_cap: usize::MAX,
                ..Default::default()
            },
        );
        for records in [0, 1, 3, 5, 8, usize::MAX] {
            for bytes in [0, 700, 1400, 5000, usize::MAX] {
                let budgets = PreviewBudgets {
                    preview_record_cap: records,
                    preview_byte_cap: bytes,
                    ..Default::default()
                };
                let result = compact_preview(rows.clone(), &budgets);
                assert_eq!(
                    result,
                    oracle(full.clone(), &budgets),
                    "records={records}, bytes={bytes}"
                );
            }
        }
    }
}
