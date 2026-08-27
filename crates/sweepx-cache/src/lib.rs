use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredGeneration {
    pub generation: String,
    pub schema: String,
    pub created_at: String,
    pub preview: CompactedPreview,
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
        } else {
            fs::create_dir_all(&self.root)?;
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
        } else {
            fs::create_dir_all(path)?;
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
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        use std::io::Write as _;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }

    fn rename_checked(&self, from: &Path, to: &Path) -> Result<(), CacheError> {
        if to.exists() && fs::symlink_metadata(to)?.file_type().is_symlink() {
            return Err(CacheError::InsecurePath(to.to_path_buf()));
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

fn ensure_no_symlink_ancestors(path: &Path) -> Result<(), CacheError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current.exists() {
            let metadata = fs::symlink_metadata(&current)?;
            if metadata.file_type().is_symlink() {
                return Err(CacheError::InsecurePath(current));
            }
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

    #[test]
    fn corrupted_generation_falls_back_to_miss_and_quarantines() {
        let temp = TestTempDir::new();
        let store = AtomicGenerationStore::new(temp.path());
        let generation = StoredGeneration {
            generation: "gen-1".to_string(),
            schema: STORED_PREVIEW_SCHEMA.to_string(),
            created_at: "2026-08-26T00:00:00Z".to_string(),
            preview: compact_preview(Vec::new(), &PreviewBudgets::default()),
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
        };
        let error = store.write_generation(&generation).unwrap_err();
        assert!(matches!(error, CacheError::InsecurePath(_)));
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
