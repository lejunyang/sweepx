mod cargo_cleaner_detect;
mod catalog_trust;

pub use catalog_trust::{
    MAX_PRODUCTION_TRUST_ROOT_ANCHORS, MAX_PRODUCTION_TRUST_SNAPSHOT_BYTES,
    ProductionCatalogDisposition, ProductionCleanerCatalogTrust, ProductionTrustDisposition,
    ProductionTrustFreshness, resolve_production_catalog_trust,
};

use std::collections::BTreeMap;
#[cfg(unix)]
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sweepx_analysis::{
    DirectoryAggregateLink, build_candidates_from_summary_with_links,
    build_explanation_from_candidate,
};
use sweepx_audit::{AuditStore, ProjectionError};
use sweepx_cache::CompactedPreview;
#[cfg(unix)]
use sweepx_cache::{
    AtomicGenerationStore, BudgetUsage, CacheError, LoadResult, PreviewBudgets, PreviewCoverage,
    PreviewKind, PreviewSummary, STORED_PREVIEW_SCHEMA, StoredGeneration, admit_preview,
};
use sweepx_canonical::canonicalize_value;
use sweepx_catalog::{BUILT_INS, LoadedCleanerPackage};
use sweepx_cleaner_vm::{EvaluationContext, evaluate_rule};
use sweepx_i18n::{Catalog, Locale, LocaleResolution, MessageArgs, MessageKey};
#[cfg(unix)]
use sweepx_model::EvidenceValue;
use sweepx_model::{
    CapabilityState, Coverage, CoverageState, DecimalU128, FieldProvenance, ObjectType,
    OperationId, ReasonCode, RequestId, ScanId, ScannedEntry,
};
use sweepx_platform::{BoundaryKind, BoundaryRecord};
use sweepx_protocol::{
    AuditProjectionSnapshot, CapabilityCell, CapabilityEvidence, CapabilityRecordV1,
    CompatSnapshot, EventCheckpoint, EventEnvelope, EventPhase, EventType, EvidenceClass, ExitCode,
    OsFamily, OutputEnvelope, OutputKind, OutputStatus, PlatformAdapterCompat, ProtocolMessage,
    QualificationKey, QualificationScope, QualificationValidity, QualificationValidityStatus,
    RuntimePrivilegeProfile,
};
pub use sweepx_scanner::ScanSummary;
use sweepx_scanner::{ProgressEvent, ScanError};
use sweepx_tui::{
    DetailRescanFailure as TuiDetailRescanFailure, DetailRescanProvider,
    DetailRescanRequest as TuiDetailRescanRequest, DetailRescanResult as TuiDetailRescanResult,
    LoadLimits as TuiLoadLimits, RefreshedDetail, ViewModel, ViewModelError,
};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use sweepx_platform::{CancellationToken, ScanRoot};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use sweepx_scanner::{
    DetailEntryIdAllocator, DetailRescanError, DetailRescanRequest, DetailRescanner,
    HostPlatformScanner,
};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use sweepx_scanner::{Scanner, ScannerOptions};

pub const CORE_VERSION: &str = "0.1.0";
pub const SCANNER_SEMANTICS_VERSION: u32 = 1;
pub const SAFETY_POLICY_VERSION: u32 = 1;
pub const STREAM_ID_PREFIX: &str = "stream-p1";
const SNAPSHOT_SCHEMA: &str = "sweepx.operation-snapshot/v1";
const OPERATION_ID_MAX_LEN: usize = 128;
pub const DEFAULT_ANALYSIS_INPUT_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_HUMAN_SCAN_ROWS: usize = 40;
pub const SCAN_NDJSON_UNAVAILABLE_MESSAGE: &str =
    "scan --format ndjson is disabled until SweepX has a durable event journal and replay support";
#[cfg(unix)]
const PREVIEW_GENERATION_POINTER_DIR: &str = "preview-cache";
const CACHE_LOAD_MODE_MISS: &str = "miss";
#[cfg(unix)]
const CACHE_LOAD_MODE_HIT: &str = "stale_preview";
#[cfg(unix)]
const CACHE_LOAD_MODE_QUARANTINED: &str = "quarantined";
#[cfg(unix)]
const CACHE_STORE_MODE_WRITTEN: &str = "written";
const CACHE_STORE_MODE_SKIPPED: &str = "skipped";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CachePreviewMetadata {
    load_status: &'static str,
    store_status: &'static str,
    loaded_generation: Option<String>,
    written_generation: Option<String>,
    stale_parent_count: DecimalU128,
    stale_record_count: DecimalU128,
    preview_byte_count: DecimalU128,
    resource_limit: bool,
    incomplete: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachePreviewLoad {
    status: &'static str,
    generation: Option<String>,
    preview: Option<CompactedPreview>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachePreviewStoreResult {
    status: &'static str,
    generation: Option<String>,
    preview_bytes: usize,
    resource_limit: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Ndjson,
}

impl OutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Json => "json",
            Self::Ndjson => "ndjson",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Completed,
    Partial,
    Failed,
    Unsupported,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelDisposition {
    NotFound,
    AlreadyTerminal,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationSnapshot {
    pub schema: String,
    pub operation_id: String,
    pub request_id: String,
    pub command: String,
    pub state: OperationState,
    pub status: OutputStatus,
    pub exit_code: u8,
    pub created_at: String,
    pub updated_at: String,
    pub locale: String,
    pub root_paths: Vec<String>,
    pub scan_id: Option<String>,
    pub terminal_event_type: Option<String>,
    pub entry_count: Option<String>,
    pub error_count: Option<String>,
    pub boundary_count: Option<String>,
    pub error: Option<ProtocolMessage>,
}

impl OperationSnapshot {
    pub fn not_found(operation_id: &str, locale: Locale) -> Self {
        let now = timestamp_now();
        Self {
            schema: SNAPSHOT_SCHEMA.to_string(),
            operation_id: operation_id.to_string(),
            request_id: format!("req-status-{operation_id}"),
            command: "status".to_string(),
            state: OperationState::NotFound,
            status: OutputStatus::Failed,
            exit_code: ExitCode::OperationFailed as u8,
            created_at: now.clone(),
            updated_at: now,
            locale: locale.as_bcp47().to_string(),
            root_paths: Vec::new(),
            scan_id: None,
            terminal_event_type: None,
            entry_count: None,
            error_count: None,
            boundary_count: None,
            error: Some(protocol_error(
                "state.not_found",
                "state",
                "operation.snapshot.not_found",
                false,
                [("operationId", operation_id.to_string())],
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicOperationView {
    pub operation_id: String,
    pub command: String,
    pub state: OperationState,
    pub status: OutputStatus,
    pub created_at: String,
    pub updated_at: String,
    pub locale: String,
    pub scan_id: Option<String>,
    pub root_count: DecimalU128,
    pub entry_count: Option<String>,
    pub error_count: Option<String>,
    pub boundary_count: Option<String>,
    pub terminal_event_type: Option<String>,
    pub can_cancel: bool,
}

impl From<&OperationSnapshot> for PublicOperationView {
    fn from(snapshot: &OperationSnapshot) -> Self {
        Self {
            operation_id: snapshot.operation_id.clone(),
            command: snapshot.command.clone(),
            state: snapshot.state,
            status: snapshot.status,
            created_at: snapshot.created_at.clone(),
            updated_at: snapshot.updated_at.clone(),
            locale: snapshot.locale.clone(),
            scan_id: snapshot.scan_id.clone(),
            root_count: DecimalU128::new(snapshot.root_paths.len() as u128),
            entry_count: snapshot.entry_count.clone(),
            error_count: snapshot.error_count.clone(),
            boundary_count: snapshot.boundary_count.clone(),
            terminal_event_type: snapshot.terminal_event_type.clone(),
            can_cancel: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelView {
    pub operation_id: String,
    pub disposition: CancelDisposition,
    pub can_cancel: bool,
    pub operation: Option<PublicOperationView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreContext {
    pub locale_resolution: LocaleResolution,
}

impl CoreContext {
    pub fn new(locale_resolution: LocaleResolution) -> Self {
        Self { locale_resolution }
    }

    pub fn locale(&self) -> Locale {
        self.locale_resolution.locale()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRequest {
    pub roots: Vec<PathBuf>,
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusRequest {
    pub operation_id: String,
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelRequest {
    pub operation_id: String,
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainRequest {
    pub scan_json_path: PathBuf,
    pub candidate_id: Option<String>,
    pub max_input_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanerShowRequest {
    pub cleaner_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanerCargoDetectRequest {
    pub roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TuiReadRequest {
    pub scan_json_path: PathBuf,
    pub page_index: usize,
    pub max_input_bytes: usize,
    pub max_total_rows: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanSuccess {
    pub output: OutputEnvelope,
    pub events: Vec<EventEnvelope>,
    pub snapshot: OperationSnapshot,
    /// The typed, in-memory result of this scan. Interactive clients must use
    /// this snapshot instead of round-tripping through exported JSON.
    pub summary: ScanSummary,
}

impl ScanSuccess {
    /// Split an interactive result into the small values needed after the TUI
    /// exits and the owned scan rows consumed by the browser. This releases
    /// the JSON envelope and retained event stream before terminal setup.
    /// During the scan itself, the typed summary and protocol JSON coexist;
    /// that construction-time peak is bounded by the scanner's resource
    /// limits. The interactive phase does not add another full row copy.
    pub fn into_tui_parts(self) -> TuiScanParts {
        let exit_code = self.output.conservative_exit_code() as u8;
        let status = self.output.status;
        let scan_id = self
            .output
            .summary
            .get("scanId")
            .and_then(Value::as_str)
            .map(str::to_string);
        TuiScanParts {
            status,
            exit_code,
            scan_id,
            summary: self.summary,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TuiScanParts {
    pub status: OutputStatus,
    pub exit_code: u8,
    pub scan_id: Option<String>,
    pub summary: ScanSummary,
}

/// A read-only adapter from the TUI detail protocol to the host scanner's targeted rescan API.
///
/// Construction fails closed when the live summary does not establish one consistent scan-id
/// namespace. The provider never accepts a display path as authority; scanner-side reopening is
/// driven exclusively by the request's lossless native root and no-follow lineage recipe.
pub struct TuiDetailRescanProvider {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    live: Option<LiveTuiDetailRescanProvider>,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
struct LiveTuiDetailRescanProvider {
    scanner: DetailRescanner<HostPlatformScanner>,
    ids: DetailEntryIdAllocator,
    cancel: CancellationToken,
}

pub fn tui_detail_rescan_provider(summary: &ScanSummary) -> TuiDetailRescanProvider {
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let live = live_tui_detail_rescan_provider(summary).ok();
        TuiDetailRescanProvider { live }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = summary;
        TuiDetailRescanProvider {}
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn live_tui_detail_rescan_provider(
    summary: &ScanSummary,
) -> Result<LiveTuiDetailRescanProvider, DetailRescanError> {
    let scan_id = summary
        .roots
        .iter()
        .chain(summary.entries.iter())
        .map(|entry| &entry.scan_id)
        .next()
        .ok_or(DetailRescanError::InvalidRequest)?
        .clone();
    let mut ids = DetailEntryIdAllocator::new(scan_id.clone())?;
    for entry in summary.roots.iter().chain(summary.entries.iter()) {
        if entry.scan_id != scan_id {
            return Err(DetailRescanError::InvalidRequest);
        }
        let identity = entry
            .validated_identity()
            .map_err(|_| DetailRescanError::InvalidRequest)?
            .ok_or(DetailRescanError::InvalidRequest)?;
        ids.reserve(&identity.entry_id)?;
        ids.reserve(&identity.scan_root_id)?;
        if let Some(parent_id) = &identity.parent_id {
            ids.reserve(parent_id)?;
        }
    }
    for aggregate in &summary.aggregates {
        if aggregate.scan_id != scan_id {
            return Err(DetailRescanError::InvalidRequest);
        }
        ids.reserve(
            &aggregate
                .scan_entry_id()
                .map_err(|_| DetailRescanError::InvalidRequest)?,
        )?;
    }
    Ok(LiveTuiDetailRescanProvider {
        scanner: DetailRescanner::new(
            HostPlatformScanner::new(),
            sweepx_platform::ScanResourceLimits::default(),
        ),
        ids,
        cancel: CancellationToken::new(),
    })
}

impl DetailRescanProvider for TuiDetailRescanProvider {
    fn rescan_detail(&mut self, request: &TuiDetailRescanRequest) -> TuiDetailRescanResult {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        if let Some(live) = &mut self.live {
            let binding = request.binding.clone();
            return match live.scanner.rescan(
                DetailRescanRequest {
                    source_scan_id: &request.binding.source_scan_id,
                    source_root_identity: &request.binding.source_root_identity,
                    source_directory_identity: &request.binding.source_directory_identity,
                    directory_locator: &request.directory_locator,
                    revision: request.binding.revision,
                    max_rows: request.max_rows,
                },
                &mut live.ids,
                &live.cancel,
            ) {
                Ok(detail) => TuiDetailRescanResult::Refreshed(Box::new(RefreshedDetail {
                    binding,
                    observed_root: detail.observed_root,
                    observed_directory: detail.observed_directory,
                    rows: detail.rows,
                    aggregate: detail.aggregate,
                })),
                Err(error) => TuiDetailRescanResult::Failed {
                    binding: Box::new(binding),
                    failure: map_tui_detail_rescan_error(error),
                },
            };
        }
        TuiDetailRescanResult::Failed {
            binding: Box::new(request.binding.clone()),
            failure: TuiDetailRescanFailure::Unavailable,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn map_tui_detail_rescan_error(error: DetailRescanError) -> TuiDetailRescanFailure {
    match error {
        DetailRescanError::InvalidRequest => TuiDetailRescanFailure::InvalidResult,
        DetailRescanError::IdentityUnavailable => TuiDetailRescanFailure::IdentityUnavailable,
        DetailRescanError::IdentityMismatch => TuiDetailRescanFailure::IdentityMismatch,
        DetailRescanError::MountChanged => TuiDetailRescanFailure::MountChanged,
        DetailRescanError::SymlinkOrReparse => TuiDetailRescanFailure::SymlinkOrReparse,
        DetailRescanError::Cancelled => TuiDetailRescanFailure::Cancelled,
        DetailRescanError::ResourceLimit => TuiDetailRescanFailure::ResourceLimit,
        DetailRescanError::Unavailable => TuiDetailRescanFailure::Unavailable,
    }
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
mod tui_detail_rescan_provider_tests {
    use super::*;
    use sweepx_model::{
        FilesystemObjectDomainIdentity, IdentityEvidence, NativeAbsolutePath, NativeName,
        NativePathComponent, PlatformFileIdentity, ScanEntryId, ScanObjectIdentity,
        VolumeOrMountIdentity,
    };
    use sweepx_tui::{DetailRescanBinding, DetailRescanReason};

    fn identity(scan_id: &ScanId, ordinal: u128) -> ScanObjectIdentity {
        let entry_id = ScanEntryId::for_scan_ordinal(scan_id, ordinal).unwrap();
        ScanObjectIdentity {
            entry_id: entry_id.clone(),
            scan_root_id: entry_id,
            parent_id: None,
            platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                device: DecimalU128::new(1),
                inode: DecimalU128::new(1),
            }),
            filesystem_object_domain_identity: IdentityEvidence::known(
                FilesystemObjectDomainIdentity {
                    device: DecimalU128::new(1),
                },
            ),
            volume_or_mount_identity: IdentityEvidence::known(VolumeOrMountIdentity {
                value: DecimalU128::new(1),
            }),
        }
    }

    #[test]
    fn empty_summary_constructs_a_fail_closed_unavailable_provider() {
        let scan_id = ScanId::new("missing-live-summary");
        let identity = identity(&scan_id, 1);
        let component = NativePathComponent {
            entry_id: identity.entry_id.clone(),
            parent_id: None,
            native_basename: {
                #[cfg(unix)]
                {
                    NativeName::unix(b"root".to_vec())
                }
                #[cfg(windows)]
                {
                    NativeName::windows_utf16("root".encode_utf16().collect::<Vec<_>>())
                }
            },
            object_type: ObjectType::Directory,
            platform_file_identity: identity.platform_file_identity.clone(),
            filesystem_object_domain_identity: identity.filesystem_object_domain_identity.clone(),
            volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
            metadata_fingerprint: "root".to_string(),
        };
        let locator = sweepx_model::NativeLocatorEvidence {
            scan_root: component.clone(),
            scan_root_absolute_path: Some({
                #[cfg(unix)]
                {
                    NativeAbsolutePath::unix(b"/root".to_vec())
                }
                #[cfg(windows)]
                {
                    NativeAbsolutePath::windows_utf16(r"C:\root".encode_utf16().collect::<Vec<_>>())
                }
            }),
            parent_reopen_recipe: Vec::new(),
            entry: component,
        };
        let mut provider = tui_detail_rescan_provider(&ScanSummary {
            roots: Vec::new(),
            entries: Vec::new(),
            aggregates: Vec::new(),
            boundaries: Vec::new(),
            progress: Vec::new(),
        });
        let request = TuiDetailRescanRequest {
            binding: DetailRescanBinding {
                source_scan_id: scan_id,
                source_root_identity: identity.clone(),
                source_directory_identity: identity,
                base_revision: DecimalU128::new(1),
                revision: DecimalU128::new(2),
            },
            directory_locator: locator,
            reason: DetailRescanReason::Incomplete,
            max_rows: 1,
        };

        assert!(matches!(
            provider.rescan_detail(&request),
            TuiDetailRescanResult::Failed { binding, failure: TuiDetailRescanFailure::Unavailable }
                if *binding == request.binding
        ));
    }

    #[test]
    fn scanner_error_mapping_is_conservative() {
        let cases = [
            (
                DetailRescanError::InvalidRequest,
                TuiDetailRescanFailure::InvalidResult,
            ),
            (
                DetailRescanError::IdentityUnavailable,
                TuiDetailRescanFailure::IdentityUnavailable,
            ),
            (
                DetailRescanError::IdentityMismatch,
                TuiDetailRescanFailure::IdentityMismatch,
            ),
            (
                DetailRescanError::MountChanged,
                TuiDetailRescanFailure::MountChanged,
            ),
            (
                DetailRescanError::SymlinkOrReparse,
                TuiDetailRescanFailure::SymlinkOrReparse,
            ),
            (
                DetailRescanError::Cancelled,
                TuiDetailRescanFailure::Cancelled,
            ),
            (
                DetailRescanError::ResourceLimit,
                TuiDetailRescanFailure::ResourceLimit,
            ),
            (
                DetailRescanError::Unavailable,
                TuiDetailRescanFailure::Unavailable,
            ),
        ];
        for (scanner, tui) in cases {
            assert_eq!(map_tui_detail_rescan_error(scanner), tui);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_provider_echoes_binding_and_returns_complete_direct_detail() {
        let temp = tempfile::TempDir::new().unwrap();
        let root_path = temp.path().join("root");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::write(root_path.join("child"), b"1234").unwrap();
        let context = CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Default,
        ));
        let scan = scan_with_store(
            &context,
            &ScanRequest {
                roots: vec![root_path],
                state_dir: None,
            },
            Option::<&MemorySnapshotStore>::None,
        )
        .unwrap();
        let root = scan.summary.roots[0].clone();
        let root_identity = root.identity.as_ref().unwrap().clone();
        let binding = DetailRescanBinding {
            source_scan_id: root.scan_id.clone(),
            source_root_identity: root_identity.clone(),
            source_directory_identity: root_identity,
            base_revision: DecimalU128::new(1),
            revision: DecimalU128::new(2),
        };
        let request = TuiDetailRescanRequest {
            binding: binding.clone(),
            directory_locator: root.executable_native_locator().unwrap().unwrap().clone(),
            reason: DetailRescanReason::Evicted,
            max_rows: 8,
        };
        let mut provider = tui_detail_rescan_provider(&scan.summary);

        let TuiDetailRescanResult::Refreshed(detail) = provider.rescan_detail(&request) else {
            panic!("live provider unexpectedly failed");
        };
        assert_eq!(detail.binding, binding);
        assert_eq!(detail.rows.len(), 1);
        assert_eq!(detail.aggregate.revision, DecimalU128::new(2));
        assert_eq!(
            detail.aggregate.direct_child_count,
            sweepx_model::EvidenceValue::Known {
                value: DecimalU128::new(1),
            }
        );
        assert!(detail.aggregate.coverage.complete);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CapabilitiesSuccess {
    pub output: OutputEnvelope,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotSuccess {
    pub output: OutputEnvelope,
    pub snapshot: Option<OperationSnapshot>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExplanationSuccess {
    pub output: OutputEnvelope,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CleanerSuccess {
    pub output: OutputEnvelope,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TuiReadSuccess {
    pub output: OutputEnvelope,
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("scan root must be absolute: {0}")]
    NonAbsoluteRoot(PathBuf),
    #[error("at least one scan root is required")]
    MissingRoots,
    #[error("invalid operation id: {0}")]
    InvalidOperationId(String),
    #[error("scan failed: {0}")]
    Scan(#[from] ScanError),
    #[error("state persistence failed: {0}")]
    State(#[from] StateError),
    #[error("analysis input must be a positive bounded byte limit")]
    InvalidAnalysisInputLimit,
    #[error("analysis input path must be absolute: {0}")]
    NonAbsoluteAnalysisInput(PathBuf),
    #[error("analysis input exceeds byte limit: limit={limit}, observed={observed}")]
    AnalysisInputTooLarge { limit: usize, observed: usize },
    #[error("analysis input json is invalid: {0}")]
    AnalysisInputJson(#[from] serde_json::Error),
    #[error("analysis build failed: {0}")]
    AnalysisBuild(#[from] sweepx_analysis::BuildError),
    #[error("candidate not found in analysis input: {0}")]
    CandidateNotFound(String),
    #[error("cleaner catalog failed: {0}")]
    Catalog(#[from] sweepx_catalog::CatalogError),
    #[error("production cleaner catalog trust failed: {0}")]
    ProductionCatalogTrust(#[source] Box<sweepx_catalog::CatalogError>),
    #[error("cleaner rule evaluation failed: {0}")]
    CleanerVm(#[from] sweepx_cleaner_vm::VmError),
    #[error("cleaner reference is invalid: {0}")]
    InvalidCleanerRef(String),
    #[error("cleaner catalog trust is invalid: {0}")]
    CleanerCatalogTrust(String),
    #[error(
        "cleaner is incompatible with this core: {cleaner_ref} requires {required_core}, current={current_core}"
    )]
    CleanerCompat {
        cleaner_ref: String,
        required_core: String,
        current_core: String,
    },
    #[error("unsupported tui input: {0}")]
    TuiInput(String),
    #[error("tui read failed: {0}")]
    TuiRead(String),
    #[error("tui view-model load failed: {0}")]
    TuiViewModel(String),
    #[error(transparent)]
    AuditProjection(#[from] ProjectionError),
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("state directory must be absolute: {0}")]
    NonAbsoluteStateDir(PathBuf),
    #[error(
        "durable state is disabled on Windows until current-user-private ACL and reparse-point checks are implemented"
    )]
    DurableStateUnsupportedOnWindows,
    #[error("state directory must not be a symlink: {0}")]
    SymlinkStateDir(PathBuf),
    #[error("state directory must be a directory: {0}")]
    InvalidStateDir(PathBuf),
    #[error("state directory must be owned by the current user and mode 0700: {0}")]
    InsecureStateDir(PathBuf),
    #[error("invalid operation id: {0}")]
    InvalidOperationId(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Whether the current build can safely persist operation snapshots.
///
/// Windows remains disabled until the store can enforce a current-user-only
/// DACL and reject reparse points for every state-directory component and
/// snapshot file. Returning `false` is intentional fail-closed behavior.
pub const fn durable_state_supported() -> bool {
    cfg!(unix)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedOperationId(String);

impl ValidatedOperationId {
    fn parse(raw: &str) -> Result<Self, StateError> {
        let valid = !raw.is_empty()
            && raw.len() <= OPERATION_ID_MAX_LEN
            && raw
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        if valid {
            Ok(Self(raw.to_string()))
        } else {
            Err(StateError::InvalidOperationId(raw.to_string()))
        }
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

pub trait SnapshotStore {
    fn save(&self, snapshot: &OperationSnapshot) -> Result<(), StateError>;
    fn load(&self, operation_id: &str) -> Result<Option<OperationSnapshot>, StateError>;
}

#[derive(Debug, Clone)]
pub struct DurableSnapshotStore {
    base_dir: PathBuf,
}

impl DurableSnapshotStore {
    pub fn new(base_dir: impl Into<PathBuf>) -> Result<Self, StateError> {
        let base_dir = base_dir.into();
        if !durable_state_supported() {
            return Err(StateError::DurableStateUnsupportedOnWindows);
        }
        validate_or_prepare_state_dir(&base_dir)?;
        Ok(Self { base_dir })
    }

    fn operations_dir(&self) -> Result<PathBuf, StateError> {
        let path = self.base_dir.join("operations");
        validate_or_prepare_private_subdir(&path)?;
        Ok(path)
    }

    fn file_path(&self, operation_id: &ValidatedOperationId) -> Result<PathBuf, StateError> {
        Ok(self
            .operations_dir()?
            .join(format!("{}.json", digest_hex(operation_id.as_str()))))
    }
}

impl SnapshotStore for DurableSnapshotStore {
    fn save(&self, snapshot: &OperationSnapshot) -> Result<(), StateError> {
        let operation_id = ValidatedOperationId::parse(&snapshot.operation_id)?;
        let path = self.file_path(&operation_id)?;
        let bytes = serde_json::to_vec_pretty(snapshot)?;
        atomic_write_private_file(&path, &bytes)?;
        Ok(())
    }

    fn load(&self, operation_id: &str) -> Result<Option<OperationSnapshot>, StateError> {
        let operation_id = ValidatedOperationId::parse(operation_id)?;
        let path = self.file_path(&operation_id)?;
        match fs::read(path) {
            Ok(bytes) => {
                let snapshot: OperationSnapshot = serde_json::from_slice(&bytes)?;
                if snapshot.operation_id == operation_id.as_str() {
                    Ok(Some(snapshot))
                } else {
                    Err(StateError::InvalidOperationId(
                        operation_id.as_str().to_string(),
                    ))
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemorySnapshotStore {
    inner: Arc<Mutex<BTreeMap<String, OperationSnapshot>>>,
}

impl SnapshotStore for MemorySnapshotStore {
    fn save(&self, snapshot: &OperationSnapshot) -> Result<(), StateError> {
        let _ = ValidatedOperationId::parse(&snapshot.operation_id)?;
        self.inner
            .lock()
            .expect("memory snapshot store poisoned")
            .insert(snapshot.operation_id.clone(), snapshot.clone());
        Ok(())
    }

    fn load(&self, operation_id: &str) -> Result<Option<OperationSnapshot>, StateError> {
        let operation_id = ValidatedOperationId::parse(operation_id)?;
        Ok(self
            .inner
            .lock()
            .expect("memory snapshot store poisoned")
            .get(operation_id.as_str())
            .cloned())
    }
}

pub fn durable_store(state_dir: Option<&Path>) -> Result<Option<DurableSnapshotStore>, StateError> {
    if state_dir.is_some() && !durable_state_supported() {
        return Err(StateError::DurableStateUnsupportedOnWindows);
    }

    match state_dir {
        Some(path) => Ok(Some(DurableSnapshotStore::new(path)?)),
        None => Ok(None),
    }
}

pub const fn scan_ndjson_supported() -> bool {
    false
}

pub fn audit_projection(store: &AuditStore) -> Result<AuditProjectionSnapshot, CoreError> {
    Ok(store.projection_snapshot()?)
}

pub fn scan_with_store<S: SnapshotStore>(
    context: &CoreContext,
    request: &ScanRequest,
    store: Option<&S>,
) -> Result<ScanSuccess, CoreError> {
    if request.state_dir.is_some() && !durable_state_supported() {
        return Err(StateError::DurableStateUnsupportedOnWindows.into());
    }
    let normalized_roots = normalize_scan_roots(&request.roots)?;
    if normalized_roots.is_empty() {
        return Err(CoreError::MissingRoots);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let roots: Vec<ScanRoot> = normalized_roots
        .iter()
        .map(|path| {
            ScanRoot::new(path.clone()).map_err(|_| CoreError::NonAbsoluteRoot(path.clone()))
        })
        .collect::<Result<_, _>>()?;

    let ids = fresh_operation_ids("scan", &normalized_roots);
    let started_at = timestamp_now();
    let monotonic = Instant::now();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let output = unsupported_scan_output(context, &normalized_roots, &ids, &started_at);
        let snapshot = snapshot_from_output(&output, "scan", context.locale(), &normalized_roots);
        if let Some(store) = store {
            store.save(&snapshot)?;
        }
        let events = build_scan_events(
            &format!("{STREAM_ID_PREFIX}-{}", digest_hex(ids.operation_id_str())),
            &ids.operation_id,
            &output.compat,
            &normalized_roots,
            None,
            &output,
            &started_at,
            monotonic.elapsed(),
        );
        Ok(ScanSuccess {
            output,
            events,
            snapshot,
            summary: ScanSummary {
                roots: Vec::new(),
                entries: Vec::new(),
                aggregates: Vec::new(),
                boundaries: Vec::new(),
                progress: Vec::new(),
            },
        })
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let scan_id = ScanId::new(format!(
            "scan-{}-{}",
            unix_timestamp_nanos(),
            &digest_hex(ids.operation_id_str())[..12]
        ));
        let compat = compat_snapshot(host_scan_platform());
        #[cfg(unix)]
        let loaded_preview = load_stale_preview(request.state_dir.as_deref());
        #[cfg(windows)]
        let loaded_preview = empty_cache_preview_load();
        let scanner = Scanner::new(
            HostPlatformScanner::new(),
            ScannerOptions {
                scan_id: scan_id.clone(),
                ..ScannerOptions::default()
            },
        );
        let cancel = CancellationToken::new();
        let summary = scanner.scan(&roots, &cancel)?;
        #[cfg(unix)]
        let stored_preview = store_stale_preview(request.state_dir.as_deref(), &scan_id, &summary);
        #[cfg(windows)]
        let stored_preview = empty_cache_preview_store();
        let finished_at = timestamp_now();
        let status = scan_status(&summary);
        let cache_metadata = cache_preview_metadata(&summary, &loaded_preview, &stored_preview);

        let mut output = OutputEnvelope::new(
            OutputKind::ScanResult,
            ids.request_id.clone(),
            ids.operation_id.clone(),
            finished_at,
            status,
            ExitCode::from(status),
            compat.clone(),
        );
        output.summary = json!({
            "scanId": scan_id,
            "rootCount": DecimalU128::new(normalized_roots.len() as u128),
            "entryCount": DecimalU128::new(summary.entries.len() as u128),
            "aggregateCount": DecimalU128::new(summary.aggregates.len() as u128),
            "boundaryCount": DecimalU128::new(summary.boundaries.len() as u128),
            "errorCount": DecimalU128::new(scan_error_count(&summary)),
            "platform": host_scan_platform(),
            "mode": "read_only",
            "cachePreview": camelize_json_keys(serde_json::to_value(&cache_metadata).expect("cache preview metadata serializable"))
        });
        output.data = camelize_json_keys(json!({
            "scanId": scan_id,
            "roots": summary.roots,
            "entries": summary.entries,
            "aggregates": summary.aggregates,
            "boundaries": summary.boundaries.iter().map(|boundary| json!({
                "path": boundary.path.display().to_string(),
                "kind": boundary_label(&boundary.kind),
                "reason": boundary.reason,
                "detail": boundary.detail
            })).collect::<Vec<_>>()
        }));

        if status == OutputStatus::Partial {
            output.warnings.push(protocol_error(
                "scan.partial",
                "scan",
                "scan.partial",
                false,
                [("scanId", scan_id.to_string())],
            ));
        }
        for warning in loaded_preview
            .warnings
            .iter()
            .chain(stored_preview.warnings.iter())
        {
            output
                .warnings
                .push(protocol_error(warning, "cache", warning, false, []));
        }

        let snapshot = snapshot_from_output(&output, "scan", context.locale(), &normalized_roots);
        if let Some(store) = store {
            store.save(&snapshot)?;
        }

        let events = build_scan_events(
            &format!("{STREAM_ID_PREFIX}-{}", digest_hex(ids.operation_id_str())),
            &ids.operation_id,
            &compat,
            &normalized_roots,
            Some(&summary),
            &output,
            &started_at,
            monotonic.elapsed(),
        );

        Ok(ScanSuccess {
            output,
            events,
            snapshot,
            summary,
        })
    }
}

pub fn status_with_store<S: SnapshotStore>(
    context: &CoreContext,
    request: &StatusRequest,
    store: Option<&S>,
) -> Result<SnapshotSuccess, CoreError> {
    let snapshot = load_snapshot(context, &request.operation_id, store)?;
    let output = status_output_from_snapshot(&request.operation_id, snapshot.as_ref());
    Ok(SnapshotSuccess { output, snapshot })
}

pub fn cancel_with_store<S: SnapshotStore>(
    context: &CoreContext,
    request: &CancelRequest,
    store: Option<&S>,
) -> Result<SnapshotSuccess, CoreError> {
    let snapshot = load_snapshot(context, &request.operation_id, store)?;
    let output = cancel_output_from_snapshot(&request.operation_id, snapshot.as_ref());
    Ok(SnapshotSuccess { output, snapshot })
}

pub fn capabilities(_context: &CoreContext) -> Result<CapabilitiesSuccess, CoreError> {
    let ids = fresh_operation_ids("capabilities", &[]);
    let recorded_at = timestamp_now();
    let qualification_expires_at = timestamp_after(&recorded_at, time::Duration::hours(24));
    let current_os = current_os_family();
    let cleaner_catalog = resolve_cleaner_catalog()?;
    let cleaner_state = match cleaner_catalog.trust.disposition {
        CleanerCatalogTrustDisposition::Disabled => CapabilityState::Disabled,
        CleanerCatalogTrustDisposition::ReportOnly => CapabilityState::ReportOnly,
        CleanerCatalogTrustDisposition::Trusted
            if cleaner_catalog
                .cleaners
                .iter()
                .any(|cleaner| !cleaner.compatible) =>
        {
            CapabilityState::ReportOnly
        }
        CleanerCatalogTrustDisposition::Trusted => CapabilityState::Qualified,
    };
    let cleaner_reason = match cleaner_catalog.trust.disposition {
        CleanerCatalogTrustDisposition::Disabled => "BUILTIN_CLEANER_TRUST_DISABLED",
        CleanerCatalogTrustDisposition::ReportOnly => "BUILTIN_CLEANER_TRUST_REPORT_ONLY",
        CleanerCatalogTrustDisposition::Trusted
            if cleaner_catalog
                .cleaners
                .iter()
                .any(|cleaner| !cleaner.compatible) =>
        {
            "BUILTIN_CLEANER_COMPAT_PARTIAL"
        }
        CleanerCatalogTrustDisposition::Trusted => "BUILTIN_CLEANER_REPORTING_SUPPORTED",
    };
    let (status_state, status_reason) = if durable_state_supported() {
        (CapabilityState::Qualified, "STATUS_SNAPSHOT_SUPPORTED")
    } else {
        (
            CapabilityState::Disabled,
            "WINDOWS_DURABLE_STATE_SECURITY_UNIMPLEMENTED",
        )
    };
    let scan_reason = match current_os {
        "linux" => "LINUX_SCANNER_DEVELOPMENT",
        "macos" => "MACOS_SCANNER_DEVELOPMENT",
        "windows" => "WINDOWS_SCANNER_DEVELOPMENT",
        _ => "STUB_COMPILATION_ONLY",
    };
    let mut output = OutputEnvelope::new(
        OutputKind::CapabilitiesResult,
        ids.request_id,
        ids.operation_id,
        recorded_at.clone(),
        OutputStatus::Partial,
        ExitCode::Partial,
        compat_snapshot_with_digest(current_os, cleaner_catalog.cleaner_set_digest.clone()),
    );
    let commands = vec![
        command_record("scan", CapabilityState::Degraded, scan_reason),
        command_record(
            "explain",
            CapabilityState::Qualified,
            "EXPLAIN_FROM_SCAN_JSON_SUPPORTED",
        ),
        command_record("status", status_state, status_reason),
        command_record(
            "cancel",
            CapabilityState::Disabled,
            "CANCEL_LIVE_REGISTRY_ABSENT",
        ),
        command_record("cleaner.list", cleaner_state, cleaner_reason),
        command_record("cleaner.show", cleaner_state, cleaner_reason),
        command_record(
            "capabilities",
            CapabilityState::Qualified,
            "CAPABILITIES_REPORT_SUPPORTED",
        ),
    ];
    let capabilities = vec![
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Linux,
            "scan.local.directory",
            CapabilityState::Degraded,
            "LINUX_SCANNER_DEVELOPMENT",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Linux,
            "scan.ndjson.stream",
            CapabilityState::Disabled,
            "SCAN_NDJSON_DURABLE_JOURNAL_ABSENT",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Linux,
            "operation.snapshot.durable",
            CapabilityState::Qualified,
            "STATUS_SNAPSHOT_SUPPORTED",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Linux,
            "analysis.explain.scan_json",
            CapabilityState::Qualified,
            "EXPLAIN_FROM_SCAN_JSON_SUPPORTED",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Linux,
            "catalog.cleaner.read",
            cleaner_state,
            cleaner_reason,
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Linux,
            "scan.tui.live",
            CapabilityState::Degraded,
            "LINUX_LIVE_TUI_DEVELOPMENT",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Linux,
            "operation.cancel",
            CapabilityState::Disabled,
            "CANCEL_LIVE_REGISTRY_ABSENT",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Macos,
            "scan.local.directory",
            CapabilityState::Degraded,
            "MACOS_SCANNER_DEVELOPMENT",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Macos,
            "scan.ndjson.stream",
            CapabilityState::Disabled,
            "SCAN_NDJSON_DURABLE_JOURNAL_ABSENT",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Macos,
            "operation.snapshot.durable",
            CapabilityState::Qualified,
            "STATUS_SNAPSHOT_SUPPORTED",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Macos,
            "analysis.explain.scan_json",
            CapabilityState::Qualified,
            "EXPLAIN_FROM_SCAN_JSON_SUPPORTED",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Macos,
            "catalog.cleaner.read",
            cleaner_state,
            cleaner_reason,
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Macos,
            "scan.tui.live",
            CapabilityState::Degraded,
            "MACOS_LIVE_TUI_DEVELOPMENT",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Windows,
            "scan.local.directory",
            CapabilityState::Degraded,
            "WINDOWS_SCANNER_DEVELOPMENT",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Windows,
            "scan.ndjson.stream",
            CapabilityState::Disabled,
            "SCAN_NDJSON_DURABLE_JOURNAL_ABSENT",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Windows,
            "operation.snapshot.durable",
            CapabilityState::Disabled,
            "WINDOWS_DURABLE_STATE_SECURITY_UNIMPLEMENTED",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Windows,
            "analysis.explain.scan_json",
            CapabilityState::Qualified,
            "EXPLAIN_FROM_SCAN_JSON_SUPPORTED",
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Windows,
            "catalog.cleaner.read",
            cleaner_state,
            cleaner_reason,
        ),
        capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Windows,
            "scan.tui.live",
            CapabilityState::Degraded,
            "WINDOWS_LIVE_TUI_DEVELOPMENT",
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Linux,
            CapabilityCell::TRASH_LOCAL_FILE,
            "NATIVE_TRASH_QUALIFICATION_ABSENT",
            EvidenceClass::FixtureConformanceOnly,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Linux,
            CapabilityCell::TRASH_LOCAL_DIRECTORY,
            "NATIVE_TRASH_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Linux,
            CapabilityCell::PERMANENT_LOCAL_FILE,
            "PERMANENT_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Linux,
            CapabilityCell::PERMANENT_LOCAL_DIRECTORY,
            "PERMANENT_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Linux,
            CapabilityCell::PERMANENT_LOCAL_LINK,
            "PERMANENT_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Macos,
            CapabilityCell::TRASH_LOCAL_FILE,
            "NATIVE_TRASH_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Macos,
            CapabilityCell::TRASH_LOCAL_DIRECTORY,
            "NATIVE_TRASH_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Macos,
            CapabilityCell::PERMANENT_LOCAL_FILE,
            "PERMANENT_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Macos,
            CapabilityCell::PERMANENT_LOCAL_DIRECTORY,
            "PERMANENT_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Macos,
            CapabilityCell::PERMANENT_LOCAL_LINK,
            "PERMANENT_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Windows,
            CapabilityCell::TRASH_LOCAL_FILE,
            "NATIVE_TRASH_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Windows,
            CapabilityCell::TRASH_LOCAL_DIRECTORY,
            "NATIVE_TRASH_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Windows,
            CapabilityCell::PERMANENT_LOCAL_FILE,
            "PERMANENT_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Windows,
            CapabilityCell::PERMANENT_LOCAL_DIRECTORY,
            "PERMANENT_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
        mutation_capability_record(
            &recorded_at,
            &qualification_expires_at,
            OsFamily::Windows,
            CapabilityCell::PERMANENT_LOCAL_LINK,
            "PERMANENT_QUALIFICATION_ABSENT",
            EvidenceClass::Incomplete,
        ),
    ];
    for capability in &capabilities {
        if capability.state == CapabilityState::Qualified {
            capability
                .validate_at(&recorded_at)
                .expect("qualified capability records must validate before emission");
        } else {
            capability
                .validate()
                .expect("non-qualified capability records must validate before emission");
        }
    }
    output.summary = json!({
        "commandCount": DecimalU128::new(commands.len() as u128),
        "capabilityCount": DecimalU128::new(capabilities.len() as u128),
        "currentPlatform": current_os,
        "cleanerSetDigest": cleaner_catalog.cleaner_set_digest,
    });
    output.data = json!({
        "commands": commands,
        "capabilities": capabilities
    });
    output.warnings.push(protocol_error(
        "capabilities.partial",
        "capabilities",
        "capabilities.partial",
        false,
        [("platform", current_os.to_string())],
    ));
    Ok(CapabilitiesSuccess { output })
}

pub fn explain_from_scan_json(
    _context: &CoreContext,
    request: &ExplainRequest,
) -> Result<ExplanationSuccess, CoreError> {
    let input = read_scan_input_from_path(&request.scan_json_path, request.max_input_bytes)?;
    let summary = scan_summary_from_input(&input);
    let links = directory_links(&summary);
    let candidates = build_candidates_from_summary_with_links(&summary, &links, true)?;

    let selected = if let Some(candidate_id) = request.candidate_id.as_deref() {
        candidates
            .into_iter()
            .filter(|candidate| candidate.candidate_id.to_string() == candidate_id)
            .collect::<Vec<_>>()
    } else {
        candidates
    };

    if let Some(candidate_id) = request.candidate_id.as_ref()
        && selected.is_empty()
    {
        return Err(CoreError::CandidateNotFound(candidate_id.clone()));
    }

    let explanations = selected
        .iter()
        .map(build_explanation_from_candidate)
        .collect::<Result<Vec<_>, _>>()?;
    let ids = fresh_operation_ids("explain", std::slice::from_ref(&request.scan_json_path));
    let mut output = OutputEnvelope::new(
        OutputKind::ExplanationResult,
        ids.request_id,
        ids.operation_id,
        timestamp_now(),
        OutputStatus::Ok,
        ExitCode::Completed,
        compat_snapshot(current_os_family()),
    );
    output.summary = json!({
        "scanId": input.scan_id.clone(),
        "candidateCount": DecimalU128::new(summary.entries.len() as u128),
        "selectedCandidateCount": DecimalU128::new(explanations.len() as u128),
        "inputMode": "scan_json",
    });
    output.data = json!({
        "scanId": input.scan_id.clone(),
        "inputPath": request.scan_json_path.display().to_string(),
        "inputMode": "scan_json",
        "explanations": explanations.iter().zip(selected.iter()).map(|(explanation, candidate)| json!({
            "candidate": camelize_json_keys(serde_json::to_value(candidate).expect("candidate serializable")),
            "explanation": camelize_json_keys(serde_json::to_value(explanation).expect("explanation serializable")),
        })).collect::<Vec<_>>(),
    });
    Ok(ExplanationSuccess { output })
}

pub fn cleaner_list(_context: &CoreContext) -> Result<CleanerSuccess, CoreError> {
    let ids = fresh_operation_ids("cleaner-list", &[]);
    let cleaner_catalog = resolve_cleaner_catalog()?;
    let list = cleaner_catalog
        .cleaners
        .iter()
        .map(|cleaner| cleaner_list_entry(cleaner, &cleaner_catalog.trust))
        .collect::<Vec<_>>();
    let incompatible_count = cleaner_catalog
        .cleaners
        .iter()
        .filter(|cleaner| !cleaner.compatible)
        .count();
    let status = if incompatible_count > 0 {
        OutputStatus::Partial
    } else {
        OutputStatus::Ok
    };
    let mut output = OutputEnvelope::new(
        OutputKind::CleanerResult,
        ids.request_id,
        ids.operation_id,
        timestamp_now(),
        status,
        ExitCode::Completed,
        compat_snapshot_with_digest(
            current_os_family(),
            cleaner_catalog.cleaner_set_digest.clone(),
        ),
    );
    output.summary = json!({
        "command": "cleaner.list",
        "cleanerCount": DecimalU128::new(list.len() as u128),
        "incompatibleCleanerCount": DecimalU128::new(incompatible_count as u128),
        "cleanerSetDigest": cleaner_catalog.cleaner_set_digest,
    });
    output.data = json!({
        "command": "cleaner.list",
        "cleaners": list,
    });
    if incompatible_count > 0 {
        output.warnings.push(protocol_error(
            "cleaner.catalog.compat.partial",
            "cleaner",
            "cleaner.catalog.compat.partial",
            false,
            [("currentCore", CORE_VERSION.to_string())],
        ));
    }
    Ok(CleanerSuccess { output })
}

pub fn cleaner_show(
    _context: &CoreContext,
    request: &CleanerShowRequest,
) -> Result<CleanerSuccess, CoreError> {
    let (id, version) = parse_cleaner_ref(&request.cleaner_ref)?;
    let cleaner_catalog = resolve_cleaner_catalog()?;
    let cleaner = cleaner_catalog
        .cleaners
        .iter()
        .find(|cleaner| {
            cleaner.package.manifest.id == id
                && version
                    .as_ref()
                    .map(|expected| expected == &cleaner.package.manifest.version)
                    .unwrap_or(true)
        })
        .ok_or_else(|| CoreError::InvalidCleanerRef(request.cleaner_ref.clone()))?;
    if !cleaner.compatible {
        return Err(CoreError::CleanerCompat {
            cleaner_ref: request.cleaner_ref.clone(),
            required_core: cleaner.package.manifest.requires.core.clone(),
            current_core: CORE_VERSION.to_string(),
        });
    }
    let entry = cleaner_show_entry(cleaner, &cleaner_catalog.trust)?;
    let ids = fresh_operation_ids("cleaner-show", &[]);
    let mut output = OutputEnvelope::new(
        OutputKind::CleanerResult,
        ids.request_id,
        ids.operation_id,
        timestamp_now(),
        OutputStatus::Ok,
        ExitCode::Completed,
        compat_snapshot_with_digest(
            current_os_family(),
            cleaner_catalog.cleaner_set_digest.clone(),
        ),
    );
    output.summary = json!({
        "command": "cleaner.show",
        "cleanerId": entry["manifest"]["id"].clone(),
        "ruleCount": DecimalU128::new(entry["rules"].as_array().map(|items| items.len()).unwrap_or(0) as u128),
        "cleanerSetDigest": cleaner_catalog.cleaner_set_digest,
    });
    output.data = json!({
        "command": "cleaner.show",
        "cleaner": entry,
    });
    Ok(CleanerSuccess { output })
}

pub fn cleaner_cargo_detect(
    context: &CoreContext,
    request: &CleanerCargoDetectRequest,
) -> Result<CleanerSuccess, CoreError> {
    // Compatibility and trust are admission gates, not annotations on a best-effort result.
    // Resolve them before touching any caller-selected scan root or evaluating package rules.
    let cleaner_catalog = resolve_cleaner_catalog()?;
    let cleaner = cargo_cleaner_detect::cargo_cleaner(&cleaner_catalog.cleaners)?;
    if !cleaner.compatible {
        let ids = fresh_operation_ids("cleaner-cargo-detect", &request.roots);
        let mut output = OutputEnvelope::new(
            OutputKind::CleanerResult,
            ids.request_id,
            ids.operation_id,
            timestamp_now(),
            OutputStatus::Failed,
            ExitCode::CleanerTrustOrCompat,
            compat_snapshot_with_digest(
                current_os_family(),
                cleaner_catalog.cleaner_set_digest.clone(),
            ),
        );
        output.summary = json!({
            "command": "cleaner.cargo-detect",
            "cleanerId": cargo_cleaner_detect::CARGO_CLEANER_ID,
            "experimental": true,
            "liveOnly": true,
            "scanPerformed": false,
            "matchCount": DecimalU128::ZERO,
            "hintCount": DecimalU128::ZERO,
            "rootCount": DecimalU128::new(request.roots.len() as u128),
            "reasonCode": cargo_cleaner_detect::BUILTIN_MANIFEST_INCOMPATIBLE,
            "cleanerSetDigest": cleaner_catalog.cleaner_set_digest,
        });
        output.data = cargo_cleaner_detect::incompatible_cargo_detect_json();
        output.errors.push(protocol_error(
            "cleaner.compatibility",
            "cleaner",
            "cleaner.compatibility",
            false,
            [
                (
                    "cleanerRef",
                    format!(
                        "{}@{}",
                        cleaner.package.manifest.id, cleaner.package.manifest.version
                    ),
                ),
                (
                    "requiredCore",
                    cleaner.package.manifest.requires.core.clone(),
                ),
                ("currentCore", CORE_VERSION.to_string()),
            ],
        ));
        return Ok(CleanerSuccess { output });
    }
    let scan = scan_with_store(
        context,
        &ScanRequest {
            roots: request.roots.clone(),
            state_dir: None,
        },
        Option::<&MemorySnapshotStore>::None,
    )?;
    let source_scan_incomplete = scan.output.status == OutputStatus::Partial;
    let source_scan_warning_count = scan.output.warnings.len();
    let detected = cargo_cleaner_detect::detect_live_cargo_cleaner_candidates(
        &scan.summary,
        cleaner,
        source_scan_incomplete,
        source_scan_warning_count,
    )?;
    let status = if detected.requires_partial_status() {
        OutputStatus::Partial
    } else {
        OutputStatus::Ok
    };
    let exit_code = ExitCode::from(status);
    let reason_code = detected.primary_reason_code();

    let ids = fresh_operation_ids("cleaner-cargo-detect", &request.roots);
    let mut output = OutputEnvelope::new(
        OutputKind::CleanerResult,
        ids.request_id,
        ids.operation_id,
        timestamp_now(),
        status,
        exit_code,
        compat_snapshot_with_digest(
            current_os_family(),
            cleaner_catalog.cleaner_set_digest.clone(),
        ),
    );
    output.summary = json!({
        "command": "cleaner.cargo-detect",
        "cleanerId": cargo_cleaner_detect::CARGO_CLEANER_ID,
        "experimental": true,
        "liveOnly": true,
        "matchCount": DecimalU128::new(detected.matches.len() as u128),
        "hintCount": DecimalU128::new(detected.hints.len() as u128),
        "rootCount": DecimalU128::new(request.roots.len() as u128),
        "reasonCode": reason_code,
        "sourceScanIncomplete": detected.scan.incomplete,
        "sourceScanWarningCount": detected.scan.warning_count,
        "sourceScanErrorCount": detected.scan.error_count,
        "sourceScanBoundaryCount": detected.scan.boundary_count,
        "sourceScanPartialBoundaryCount": detected.scan.partial_boundary_count,
        "sourceScanIncompleteAggregateCount": detected.scan.incomplete_aggregate_count,
        "cleanerSetDigest": cleaner_catalog.cleaner_set_digest,
    });
    output.data = cargo_cleaner_detect::experimental_cargo_detect_json(&detected);
    output.warnings.push(protocol_error(
        "cleaner.cargo_detect.experimental",
        "cleaner",
        "cleaner.cargo_detect.experimental",
        false,
        [("reasonCode", reason_code.to_string())],
    ));
    if source_scan_incomplete {
        output.warnings.push(protocol_error(
            "scan.partial",
            "scan",
            "scan.partial",
            false,
            [(
                "scanId",
                scan.output.summary["scanId"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string(),
            )],
        ));
    }
    Ok(CleanerSuccess { output })
}

pub fn tui_read_from_scan_json(
    context: &CoreContext,
    request: &TuiReadRequest,
) -> Result<TuiReadSuccess, CoreError> {
    if !request.scan_json_path.is_absolute() {
        return Err(CoreError::NonAbsoluteAnalysisInput(
            request.scan_json_path.clone(),
        ));
    }
    if request.max_input_bytes == 0 || request.max_total_rows == 0 {
        return Err(CoreError::InvalidAnalysisInputLimit);
    }
    let view = ViewModel::from_path(
        &request.scan_json_path,
        context.locale(),
        request.page_index,
        TuiLoadLimits {
            max_input_bytes: request.max_input_bytes,
            max_total_rows: request.max_total_rows,
        },
    )
    .map_err(map_tui_view_model_error)?;
    let ids = fresh_operation_ids("tui-read", std::slice::from_ref(&request.scan_json_path));
    let mut output = OutputEnvelope::new(
        OutputKind::StatusResult,
        ids.request_id,
        ids.operation_id,
        timestamp_now(),
        OutputStatus::Ok,
        ExitCode::Completed,
        compat_snapshot(current_os_family()),
    );
    output.summary = json!({
        "command": "tui",
        "scanId": view.scan_id(),
        "loadedPageIndex": DecimalU128::new(view.loaded_page_index() as u128),
        "pageCount": DecimalU128::new(view.page_count() as u128),
        "totalRows": DecimalU128::new(view.row_count() as u128),
        "readOnly": true,
    });
    output.data = json!({
        "command": "tui",
        "mode": "read_only",
        "scanId": view.scan_id(),
        "inputPath": request.scan_json_path.display().to_string(),
        "loadedPageIndex": DecimalU128::new(view.loaded_page_index() as u128),
        "pageCount": DecimalU128::new(view.page_count() as u128),
        "totalRows": DecimalU128::new(view.row_count() as u128),
        "status": status_label(view.status()),
        "title": view.title(),
        "readOnly": true,
    });
    Ok(TuiReadSuccess { output })
}

pub fn render_human_output(context: &CoreContext, output: &OutputEnvelope) -> String {
    if output.kind == OutputKind::ScanResult {
        return render_human_scan_output(context, output, DEFAULT_HUMAN_SCAN_ROWS);
    }
    let catalog = Catalog::new(context.locale());
    if output.kind == OutputKind::ExplanationResult {
        let count = output
            .summary
            .get("selectedCandidateCount")
            .and_then(json_decimal_to_usize)
            .unwrap_or(0);
        let scan_id = output
            .summary
            .get("scanId")
            .and_then(Value::as_str)
            .unwrap_or("-");
        let detail = match context.locale() {
            Locale::ZhCn => format!("已从扫描 {scan_id} 生成 {count} 条解释。"),
            Locale::EnUs => format!("Generated {count} explanations from scan {scan_id}."),
        };
        return [
            format!(
                "{}: {}",
                catalog.render(MessageKey::LabelCommand, &MessageArgs::default()),
                "explain"
            ),
            format!(
                "{}: {}",
                catalog.render(MessageKey::LabelLocale, &MessageArgs::default()),
                context.locale().as_bcp47()
            ),
            detail,
            catalog.render(MessageKey::SafetyReadOnlyNotice, &MessageArgs::default()),
        ]
        .join("\n");
    }
    if output.kind == OutputKind::CleanerResult {
        let count = output
            .summary
            .get("cleanerCount")
            .or_else(|| output.summary.get("ruleCount"))
            .and_then(json_decimal_to_usize)
            .unwrap_or(0);
        let command = output
            .summary
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or("cleaner");
        let detail = match context.locale() {
            Locale::ZhCn => format!("只读 Cleaner 输出已就绪: {command} ({count})."),
            Locale::EnUs => format!("Read-only cleaner output ready: {command} ({count})."),
        };
        return [
            format!(
                "{}: {}",
                catalog.render(MessageKey::LabelCommand, &MessageArgs::default()),
                command
            ),
            format!(
                "{}: {}",
                catalog.render(MessageKey::LabelLocale, &MessageArgs::default()),
                context.locale().as_bcp47()
            ),
            detail,
            catalog.render(MessageKey::SafetyReadOnlyNotice, &MessageArgs::default()),
        ]
        .join("\n");
    }
    let summary_key = match output.kind {
        OutputKind::ScanResult => {
            if output.status == OutputStatus::Ok {
                MessageKey::ScanCompleted
            } else {
                MessageKey::ScanPartial
            }
        }
        OutputKind::StatusResult => MessageKey::StatusSummary,
        OutputKind::CancelResult => MessageKey::ErrorGeneric,
        OutputKind::CapabilitiesResult => MessageKey::CapabilitiesSummary,
        _ => MessageKey::ErrorGeneric,
    };
    let args = MessageArgs {
        command: command_name(&output.kind),
        root: first_root(output),
        items: output
            .summary
            .get("entryCount")
            .and_then(json_decimal_to_usize)
            .unwrap_or(0),
        errors: output
            .summary
            .get("errorCount")
            .and_then(json_decimal_to_usize)
            .unwrap_or(output.errors.len()),
        status: status_label(output.status),
        capabilities: "scan (--tui), explain, status, cancel, cleaner, capabilities",
        detail: output
            .errors
            .first()
            .map(|item| item.code.as_str())
            .unwrap_or("ok"),
    };
    if output.summary.get("command").and_then(Value::as_str) == Some("tui") {
        let detail = match context.locale() {
            Locale::ZhCn => "TUI 只读输入已校验。".to_string(),
            Locale::EnUs => "TUI read-only input validated.".to_string(),
        };
        return [
            format!(
                "{}: {}",
                catalog.render(MessageKey::LabelCommand, &MessageArgs::default()),
                "tui"
            ),
            format!(
                "{}: {}",
                catalog.render(MessageKey::LabelLocale, &MessageArgs::default()),
                context.locale().as_bcp47()
            ),
            detail,
            catalog.render(MessageKey::SafetyReadOnlyNotice, &MessageArgs::default()),
        ]
        .join("\n");
    }

    [
        format!(
            "{}: {}",
            catalog.render(MessageKey::LabelCommand, &MessageArgs::default()),
            args.command
        ),
        format!(
            "{}: {}",
            catalog.render(MessageKey::LabelLocale, &MessageArgs::default()),
            context.locale().as_bcp47()
        ),
        catalog.render(summary_key, &args),
        catalog.render(MessageKey::SafetyReadOnlyNotice, &MessageArgs::default()),
    ]
    .join("\n")
}

fn render_human_scan_output(
    context: &CoreContext,
    output: &OutputEnvelope,
    max_rows: usize,
) -> String {
    let catalog = Catalog::new(context.locale());
    let mut lines = vec![
        format!(
            "{}: scan",
            catalog.render(MessageKey::LabelCommand, &MessageArgs::default())
        ),
        format!(
            "{}: {}",
            catalog.render(MessageKey::LabelLocale, &MessageArgs::default()),
            context.locale().as_bcp47()
        ),
    ];
    let status = status_label(output.status);
    lines.push(match context.locale() {
        Locale::ZhCn => format!("状态: {status}"),
        Locale::EnUs => format!("Status: {status}"),
    });
    let root_count = output
        .summary
        .get("rootCount")
        .and_then(json_decimal_to_usize)
        .unwrap_or(0);
    let entry_count = output
        .summary
        .get("entryCount")
        .and_then(json_decimal_to_usize)
        .unwrap_or(0);
    let aggregate_count = output
        .summary
        .get("aggregateCount")
        .and_then(json_decimal_to_usize)
        .unwrap_or(0);
    let boundary_count = output
        .summary
        .get("boundaryCount")
        .and_then(json_decimal_to_usize)
        .unwrap_or(0);
    let error_count = output
        .summary
        .get("errorCount")
        .and_then(json_decimal_to_usize)
        .unwrap_or(output.errors.len());
    lines.push(match context.locale() {
        Locale::ZhCn => format!(
            "摘要: 根目录 {root_count}，条目 {entry_count}，目录汇总 {aggregate_count}，边界 {boundary_count}，错误 {error_count}"
        ),
        Locale::EnUs => format!(
            "Summary: {root_count} roots, {entry_count} entries, {aggregate_count} directory aggregates, {boundary_count} boundaries, {error_count} errors"
        ),
    });
    append_human_protocol_messages(context.locale(), &mut lines, "warning", &output.warnings);
    append_human_protocol_messages(context.locale(), &mut lines, "error", &output.errors);
    let aggregates: BTreeMap<&str, &Value> = output
        .data
        .get("aggregates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|aggregate| {
            aggregate
                .get("scanEntryId")
                .or_else(|| aggregate.get("directoryIdentity"))
                .and_then(Value::as_str)
                .filter(|identity| !identity.contains('/'))
                .map(|entry_id| (entry_id, aggregate))
        })
        .collect();
    let items = output
        .data
        .get("roots")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            output
                .data
                .get("entries")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
        .fold(BTreeMap::<&str, &Value>::new(), |mut items, item| {
            if let Some(path) = item.get("displayPath").and_then(Value::as_str) {
                items.entry(path).or_insert(item);
            }
            items
        })
        .into_values()
        .collect::<Vec<_>>();
    let headings = match context.locale() {
        Locale::ZhCn => ("路径", "类型", "可回收", "覆盖"),
        Locale::EnUs => ("Path", "Type", "Reclaimable", "Coverage"),
    };
    lines.push(format!(
        "{:<56}  {:<10}  {:>14}  {}",
        headings.0, headings.1, headings.2, headings.3
    ));
    lines.push("-".repeat(100));
    for item in items.iter().take(max_rows) {
        let path = item
            .get("displayPath")
            .and_then(Value::as_str)
            .unwrap_or("-");
        let kind = item
            .get("objectType")
            .and_then(Value::as_str)
            .unwrap_or("root");
        let aggregate = item
            .get("identity")
            .and_then(|identity| identity.get("entryId"))
            .and_then(Value::as_str)
            .and_then(|entry_id| aggregates.get(entry_id))
            .copied();
        let reclaimable = aggregate
            .and_then(|value| value.get("potentiallyReclaimableBytes"))
            .or_else(|| item.get("reclaimableEstimate"))
            .or_else(|| item.get("logicalBytes"))
            .map(render_human_evidence_value)
            .unwrap_or_else(|| "unknown".to_string());
        let coverage = aggregate
            .and_then(|value| value.get("coverage"))
            .or_else(|| item.get("coverage"))
            .and_then(|value| value.get("state"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        lines.push(format!(
            "{:<56}  {:<10}  {:>14}  {}",
            truncate_display(&sanitize_terminal_text(path), 56),
            kind,
            reclaimable,
            coverage
        ));
    }
    if items.len() > max_rows {
        lines.push(match context.locale() {
            Locale::ZhCn => format!(
                "… 另有 {} 行未显示；使用 --format json 获取机器输出。",
                items.len() - max_rows
            ),
            Locale::EnUs => format!(
                "… {} more rows omitted; use --format json for machine output.",
                items.len() - max_rows
            ),
        });
    }
    lines.push(catalog.render(MessageKey::SafetyReadOnlyNotice, &MessageArgs::default()));
    lines.join("\n")
}

fn append_human_protocol_messages(
    locale: Locale,
    lines: &mut Vec<String>,
    kind: &str,
    messages: &[ProtocolMessage],
) {
    if messages.is_empty() {
        return;
    }
    let label = match (locale, kind) {
        (Locale::ZhCn, "warning") => "警告",
        (Locale::ZhCn, _) => "错误",
        (Locale::EnUs, "warning") => "Warnings",
        (Locale::EnUs, _) => "Errors",
    };
    let codes = messages
        .iter()
        .map(|message| sanitize_terminal_text(&message.code))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!("{label}: {codes}"));
}

fn sanitize_terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn render_human_evidence_value(value: &Value) -> String {
    let state = value
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    match state {
        "known" => value
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        "lower_bound" => format!(
            ">= {}",
            value
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ),
        other => other.to_string(),
    }
}

fn truncate_display(value: &str, max_chars: usize) -> String {
    let count = value.chars().count();
    if count <= max_chars {
        return value.to_string();
    }
    let keep = max_chars.saturating_sub(1);
    format!("…{}", value.chars().skip(count - keep).collect::<String>())
}

#[cfg(windows)]
fn empty_cache_preview_load() -> CachePreviewLoad {
    CachePreviewLoad {
        status: CACHE_LOAD_MODE_MISS,
        generation: None,
        preview: None,
        warnings: Vec::new(),
    }
}

#[cfg(windows)]
fn empty_cache_preview_store() -> CachePreviewStoreResult {
    CachePreviewStoreResult {
        status: CACHE_STORE_MODE_SKIPPED,
        generation: None,
        preview_bytes: 0,
        resource_limit: false,
        warnings: Vec::new(),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_stale_preview(state_dir: Option<&Path>) -> CachePreviewLoad {
    let Some(store) = preview_generation_store(state_dir).ok().flatten() else {
        return CachePreviewLoad {
            status: CACHE_LOAD_MODE_MISS,
            generation: None,
            preview: None,
            warnings: Vec::new(),
        };
    };

    match store.load_current() {
        Ok(LoadResult::Hit(generation)) => CachePreviewLoad {
            status: CACHE_LOAD_MODE_HIT,
            generation: Some(generation.generation),
            preview: Some(generation.preview),
            warnings: Vec::new(),
        },
        Ok(LoadResult::Miss) => {
            let quarantined = store.root().join("quarantine").exists();
            CachePreviewLoad {
                status: if quarantined {
                    CACHE_LOAD_MODE_QUARANTINED
                } else {
                    CACHE_LOAD_MODE_MISS
                },
                generation: None,
                preview: None,
                warnings: if quarantined {
                    vec!["cache.preview.quarantined".to_string()]
                } else {
                    Vec::new()
                },
            }
        }
        Err(CacheError::Quarantined { .. }) => CachePreviewLoad {
            status: CACHE_LOAD_MODE_QUARANTINED,
            generation: None,
            preview: None,
            warnings: vec!["cache.preview.quarantined".to_string()],
        },
        Err(_) => CachePreviewLoad {
            status: CACHE_LOAD_MODE_MISS,
            generation: None,
            preview: None,
            warnings: vec!["cache.preview.load_failed".to_string()],
        },
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn store_stale_preview(
    state_dir: Option<&Path>,
    scan_id: &ScanId,
    summary: &ScanSummary,
) -> CachePreviewStoreResult {
    let Some(store) = preview_generation_store(state_dir).ok().flatten() else {
        return CachePreviewStoreResult {
            status: CACHE_STORE_MODE_SKIPPED,
            generation: None,
            preview_bytes: 0,
            resource_limit: false,
            warnings: Vec::new(),
        };
    };

    let generation_id = format!(
        "preview_{}_{}",
        unix_timestamp_nanos(),
        &digest_hex(scan_id.as_ref())[..12]
    );
    let preview_rows = preview_summaries_from_scan(summary);
    let state_directory_bytes = match state_dir_bytes(store.root()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return CachePreviewStoreResult {
                status: CACHE_STORE_MODE_SKIPPED,
                generation: None,
                preview_bytes: 0,
                resource_limit: true,
                warnings: vec!["cache.preview.state_accounting_failed".to_string()],
            };
        }
    };
    let admission = match admit_preview(
        preview_rows,
        &PreviewBudgets::default(),
        &BudgetUsage {
            operation_spill_bytes: 0,
            global_spill_bytes: 0,
            state_directory_bytes,
        },
    ) {
        Ok(admission) => admission,
        Err(CacheError::ResourceLimit { .. }) => {
            return CachePreviewStoreResult {
                status: CACHE_STORE_MODE_SKIPPED,
                generation: None,
                preview_bytes: 0,
                resource_limit: true,
                warnings: vec!["cache.preview.resource_limit".to_string()],
            };
        }
        Err(_) => {
            return CachePreviewStoreResult {
                status: CACHE_STORE_MODE_SKIPPED,
                generation: None,
                preview_bytes: 0,
                resource_limit: false,
                warnings: vec!["cache.preview.store_failed".to_string()],
            };
        }
    };

    let stored = StoredGeneration {
        generation: generation_id.clone(),
        schema: STORED_PREVIEW_SCHEMA.to_string(),
        created_at: timestamp_now(),
        preview: admission.compacted.clone(),
    };
    match store.write_generation(&stored) {
        Ok(()) => CachePreviewStoreResult {
            status: CACHE_STORE_MODE_WRITTEN,
            generation: Some(generation_id),
            preview_bytes: admission.preview_bytes,
            resource_limit: admission
                .warnings
                .iter()
                .any(|warning| matches!(warning, sweepx_cache::CacheWarning::ResourceLimit(_))),
            warnings: admission
                .warnings
                .iter()
                .map(|_| "cache.preview.resource_limit".to_string())
                .collect(),
        },
        Err(CacheError::ResourceLimit { .. }) => CachePreviewStoreResult {
            status: CACHE_STORE_MODE_SKIPPED,
            generation: None,
            preview_bytes: 0,
            resource_limit: true,
            warnings: vec!["cache.preview.resource_limit".to_string()],
        },
        Err(_) => CachePreviewStoreResult {
            status: CACHE_STORE_MODE_SKIPPED,
            generation: None,
            preview_bytes: 0,
            resource_limit: false,
            warnings: vec!["cache.preview.store_failed".to_string()],
        },
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn cache_preview_metadata(
    summary: &ScanSummary,
    loaded: &CachePreviewLoad,
    stored: &CachePreviewStoreResult,
) -> CachePreviewMetadata {
    let stale_parent_count = loaded
        .preview
        .as_ref()
        .map(|preview| DecimalU128::new(preview.parents.len() as u128))
        .unwrap_or_else(|| DecimalU128::new(0));
    let stale_record_count = loaded
        .preview
        .as_ref()
        .map(|preview| DecimalU128::new(preview.total_records as u128))
        .unwrap_or_else(|| DecimalU128::new(0));
    let incomplete = summary
        .aggregates
        .iter()
        .any(|aggregate| !aggregate.coverage.complete)
        || summary
            .boundaries
            .iter()
            .any(|boundary| !is_non_partial_boundary(&boundary.kind));

    CachePreviewMetadata {
        load_status: loaded.status,
        store_status: stored.status,
        loaded_generation: loaded.generation.clone(),
        written_generation: stored.generation.clone(),
        stale_parent_count,
        stale_record_count,
        preview_byte_count: DecimalU128::new(stored.preview_bytes as u128),
        resource_limit: stored.resource_limit,
        incomplete,
        warnings: loaded
            .warnings
            .iter()
            .chain(stored.warnings.iter())
            .cloned()
            .collect(),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn preview_generation_store(
    state_dir: Option<&Path>,
) -> Result<Option<AtomicGenerationStore>, StateError> {
    let Some(path) = state_dir else {
        return Ok(None);
    };
    validate_or_prepare_private_ancestor_chain(path)?;
    validate_or_prepare_state_dir(path)?;
    let preview_root = path.join(PREVIEW_GENERATION_POINTER_DIR);
    validate_or_prepare_private_ancestor_chain(&preview_root)?;
    validate_or_prepare_private_subdir(&preview_root)?;
    Ok(Some(AtomicGenerationStore::new(preview_root)))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn preview_summaries_from_scan(summary: &ScanSummary) -> Vec<PreviewSummary> {
    let aggregate_by_id = summary
        .aggregates
        .iter()
        .filter_map(|aggregate| {
            aggregate
                .scan_entry_id()
                .ok()
                .map(|entry_id| (entry_id.to_string(), aggregate))
        })
        .collect::<BTreeMap<_, _>>();

    let mut rows = Vec::new();
    for entry in summary.roots.iter().chain(summary.entries.iter()) {
        let Some(identity) = entry.identity.as_ref() else {
            continue;
        };
        let kind = match entry.object_type {
            ObjectType::Directory if identity.parent_id.is_none() => PreviewKind::Root,
            ObjectType::Directory => PreviewKind::Directory,
            _ => PreviewKind::Leaf,
        };
        rows.push(PreviewSummary {
            kind,
            parent_id: identity.parent_id.as_ref().map(ToString::to_string),
            entry_id: identity.entry_id.to_string(),
            native_name: entry.native_basename.clone(),
            display_name: entry.display_path.clone(),
            logical_bytes: stale_preview_value(&entry.logical_bytes),
            allocated_bytes: stale_preview_value(&entry.allocated_bytes),
            direct_child_count: aggregate_by_id
                .get(identity.entry_id.as_str())
                .map(|aggregate| stale_preview_count(&aggregate.direct_child_count))
                .unwrap_or_else(|| sweepx_platform::known_count(0)),
            recursive_entry_count: aggregate_by_id
                .get(identity.entry_id.as_str())
                .map(|aggregate| stale_preview_count(&aggregate.recursive_entry_count))
                .unwrap_or_else(|| sweepx_platform::known_count(1)),
            aggregate: aggregate_by_id
                .get(identity.entry_id.as_str())
                .map(|aggregate| stale_preview_aggregate(aggregate)),
            coverage: PreviewCoverage {
                complete: entry.coverage.complete,
                details_lost: !entry.coverage.complete,
                incomplete_reasons: entry.coverage.incomplete_reasons.clone(),
            },
            selectable: false,
            roles: BTreeSet::new(),
            provenance: FieldProvenance::StalePreview {
                observed_at: timestamp_now(),
            },
        });
    }

    for boundary in &summary.boundaries {
        if let Some(native_name) = boundary_native_name(&boundary.path) {
            rows.push(PreviewSummary {
                kind: PreviewKind::Boundary,
                parent_id: None,
                entry_id: format!(
                    "boundary:{}",
                    sanitize_cache_id(&boundary.path.display().to_string())
                ),
                native_name,
                display_name: boundary.path.display().to_string(),
                logical_bytes: EvidenceValue::Unknown {
                    reason: boundary.reason.clone(),
                },
                allocated_bytes: EvidenceValue::Unknown {
                    reason: boundary.reason.clone(),
                },
                direct_child_count: sweepx_platform::known_count(0),
                recursive_entry_count: sweepx_platform::known_count(0),
                aggregate: None,
                coverage: PreviewCoverage {
                    complete: false,
                    details_lost: true,
                    incomplete_reasons: vec![boundary.reason.clone()],
                },
                selectable: false,
                roles: {
                    let mut roles = BTreeSet::new();
                    roles.insert(sweepx_cache::PreviewRole::Boundary);
                    roles
                },
                provenance: FieldProvenance::StalePreview {
                    observed_at: timestamp_now(),
                },
            });
        }
    }

    rows
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stale_preview_value(value: &sweepx_model::ByteValue) -> sweepx_model::ByteValue {
    match value {
        sweepx_model::EvidenceValue::Known { value } => {
            sweepx_model::EvidenceValue::Known { value: *value }
        }
        sweepx_model::EvidenceValue::LowerBound { value, reason } => {
            sweepx_model::EvidenceValue::LowerBound {
                value: *value,
                reason: reason.clone(),
            }
        }
        sweepx_model::EvidenceValue::Unknown { reason }
        | sweepx_model::EvidenceValue::Unsupported { reason }
        | sweepx_model::EvidenceValue::NotChecked { reason } => {
            sweepx_model::EvidenceValue::Unknown {
                reason: reason.clone(),
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stale_preview_count(value: &sweepx_model::CountValue) -> sweepx_model::CountValue {
    match value {
        sweepx_model::EvidenceValue::Known { value } => {
            sweepx_model::EvidenceValue::Known { value: *value }
        }
        sweepx_model::EvidenceValue::LowerBound { value, reason } => {
            sweepx_model::EvidenceValue::LowerBound {
                value: *value,
                reason: reason.clone(),
            }
        }
        sweepx_model::EvidenceValue::Unknown { reason }
        | sweepx_model::EvidenceValue::Unsupported { reason }
        | sweepx_model::EvidenceValue::NotChecked { reason } => {
            sweepx_model::EvidenceValue::Unknown {
                reason: reason.clone(),
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stale_preview_aggregate(
    aggregate: &sweepx_model::DirectoryAggregate,
) -> sweepx_model::DirectoryAggregate {
    let mut aggregate = aggregate.clone();
    aggregate.apparent_logical_bytes = stale_preview_value(&aggregate.apparent_logical_bytes);
    aggregate.unique_logical_bytes = stale_preview_value(&aggregate.unique_logical_bytes);
    aggregate.filesystem_reported_allocated_bytes =
        stale_preview_value(&aggregate.filesystem_reported_allocated_bytes);
    aggregate.potentially_reclaimable_bytes =
        stale_preview_value(&aggregate.potentially_reclaimable_bytes);
    aggregate.direct_child_count = stale_preview_count(&aggregate.direct_child_count);
    aggregate.recursive_entry_count = stale_preview_count(&aggregate.recursive_entry_count);
    aggregate.coverage.provenance = FieldProvenance::StalePreview {
        observed_at: timestamp_now(),
    };
    aggregate
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn state_dir_bytes(path: &Path) -> io::Result<u64> {
    fn visit(path: &Path, total: &mut u64, visited_dirs: &mut usize) -> io::Result<()> {
        const MAX_STATE_DIR_ENTRIES: usize = 16_384;
        *visited_dirs = visited_dirs.saturating_add(1);
        if *visited_dirs > MAX_STATE_DIR_ENTRIES {
            return Err(io::Error::other(
                "preview cache state traversal exceeded bounded entry cap",
            ));
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(io::Error::other("preview cache state contains symlink"));
            }
            if metadata.is_dir() {
                visit(&entry.path(), total, visited_dirs)?;
            } else {
                *total = total.saturating_add(metadata.len());
            }
        }
        Ok(())
    }

    if !path.exists() {
        return Ok(0);
    }
    let mut total = 0;
    let mut visited_dirs = 0;
    visit(path, &mut total, &mut visited_dirs)?;
    Ok(total)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sanitize_cache_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn boundary_native_name(path: &Path) -> Option<sweepx_model::NativeName> {
    let name = path.file_name()?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(sweepx_model::NativeName::unix(name.as_bytes().to_vec()))
    }
    #[cfg(not(unix))]
    {
        let text = name.to_string_lossy().into_owned();
        Some(sweepx_model::NativeName::unix(text.into_bytes()))
    }
}

#[cfg(unix)]
fn validate_or_prepare_private_ancestor_chain(path: &Path) -> Result<(), StateError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current.exists() {
            let meta = fs::symlink_metadata(&current)?;
            if meta.file_type().is_symlink() {
                return Err(StateError::SymlinkStateDir(current));
            }
        }
    }
    Ok(())
}

pub fn serialize_json(output: &OutputEnvelope) -> String {
    serde_json::to_string_pretty(output).expect("output envelope serializable")
}

pub fn serialize_ndjson(events: &[EventEnvelope]) -> String {
    let mut out = String::new();
    for event in events {
        out.push_str(&serde_json::to_string(event).expect("event envelope serializable"));
        out.push('\n');
    }
    out
}

struct ScanInputEnvelope {
    scan_id: Option<ScanId>,
    roots: Vec<ScannedEntry>,
    entries: Vec<ScannedEntry>,
    aggregates: Vec<sweepx_model::DirectoryAggregate>,
    boundaries: Vec<BoundaryRecord>,
}

fn read_scan_input_from_path(
    path: &Path,
    max_input_bytes: usize,
) -> Result<ScanInputEnvelope, CoreError> {
    let envelope = read_json_value_from_path(path, max_input_bytes)?;
    parse_scan_input_from_value(envelope)
}

fn read_json_value_from_path(path: &Path, max_input_bytes: usize) -> Result<Value, CoreError> {
    if !path.is_absolute() {
        return Err(CoreError::NonAbsoluteAnalysisInput(path.to_path_buf()));
    }
    if max_input_bytes == 0 {
        return Err(CoreError::InvalidAnalysisInputLimit);
    }

    let file = File::open(path).map_err(StateError::from)?;
    let mut reader = io::BufReader::new(file);
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = reader.read(&mut chunk).map_err(StateError::from)?;
        if read == 0 {
            break;
        }
        if bytes.len() + read > max_input_bytes {
            return Err(CoreError::AnalysisInputTooLarge {
                limit: max_input_bytes,
                observed: bytes.len() + read,
            });
        }
        bytes.extend_from_slice(&chunk[..read]);
    }

    serde_json::from_slice(&bytes).map_err(CoreError::from)
}

fn parse_scan_input_from_value(envelope: Value) -> Result<ScanInputEnvelope, CoreError> {
    let kind: OutputKind = serde_json::from_value(
        envelope
            .get("kind")
            .cloned()
            .ok_or_else(|| CoreError::TuiInput("missing kind".to_string()))?,
    )?;
    if kind != OutputKind::ScanResult {
        return Err(CoreError::TuiInput(format!(
            "expected scan.result input, got {:?}",
            kind
        )));
    }
    let summary = envelope
        .get("summary")
        .and_then(Value::as_object)
        .ok_or_else(|| CoreError::TuiInput("missing summary".to_string()))?;
    let data = envelope
        .get("data")
        .and_then(Value::as_object)
        .ok_or_else(|| CoreError::TuiInput("missing data".to_string()))?;

    let scan_id = data
        .get("scanId")
        .cloned()
        .or_else(|| summary.get("scanId").cloned())
        .map(serde_json::from_value)
        .transpose()?;

    let mut roots: Vec<ScannedEntry> = serde_json::from_value(decamelize_json_keys(
        data.get("roots").cloned().unwrap_or_else(|| json!([])),
    ))?;
    let mut entries: Vec<ScannedEntry> = serde_json::from_value(decamelize_json_keys(
        data.get("entries").cloned().unwrap_or_else(|| json!([])),
    ))?;
    let mut aggregates: Vec<sweepx_model::DirectoryAggregate> = serde_json::from_value(
        decamelize_json_keys(data.get("aggregates").cloned().unwrap_or_else(|| json!([]))),
    )?;
    roots.iter_mut().for_each(downgrade_imported_entry);
    entries.iter_mut().for_each(downgrade_imported_entry);
    aggregates.iter_mut().for_each(downgrade_imported_aggregate);
    let boundaries = parse_boundaries(data.get("boundaries"))?;

    Ok(ScanInputEnvelope {
        scan_id,
        roots,
        entries,
        aggregates,
        boundaries,
    })
}

fn scan_summary_from_input(input: &ScanInputEnvelope) -> ScanSummary {
    ScanSummary {
        roots: input.roots.clone(),
        entries: input.entries.clone(),
        aggregates: input.aggregates.clone(),
        boundaries: input.boundaries.clone(),
        progress: Vec::new(),
    }
}

fn directory_links(summary: &ScanSummary) -> Vec<DirectoryAggregateLink<'_>> {
    summary
        .entries
        .iter()
        .filter(|entry| entry.object_type == ObjectType::Directory)
        .filter_map(|entry| {
            let identity = entry.validated_identity().ok().flatten()?;
            summary
                .aggregates
                .iter()
                .find(|aggregate| {
                    aggregate.scan_id == entry.scan_id
                        && aggregate
                            .scan_entry_id()
                            .ok()
                            .is_some_and(|aggregate_entry_id| {
                                aggregate_entry_id == identity.entry_id
                            })
                })
                .map(|aggregate| DirectoryAggregateLink {
                    entry,
                    directory_identity: aggregate.directory_identity.as_str(),
                    expected_root_id: Some(identity.scan_root_id.as_str()),
                })
        })
        .collect()
}

fn parse_boundaries(value: Option<&Value>) -> Result<Vec<BoundaryRecord>, CoreError> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut boundaries = Vec::with_capacity(items.len());
    for item in items {
        let reason = item
            .get("reason")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or(sweepx_model::ReasonCode::Unknown);
        boundaries.push(BoundaryRecord {
            path: PathBuf::from(item.get("path").and_then(Value::as_str).unwrap_or_default()),
            kind: boundary_kind_from_str(item.get("kind").and_then(Value::as_str)),
            reason,
            detail: item
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("unknown boundary from imported scan.result")
                .to_string(),
        });
    }
    Ok(boundaries)
}

fn boundary_kind_from_str(kind: Option<&str>) -> BoundaryKind {
    match kind {
        Some("root_symlink") => BoundaryKind::RootSymlink,
        Some("symlink") => BoundaryKind::Symlink,
        Some("reparse_point") => BoundaryKind::ReparsePoint,
        Some("mount") => BoundaryKind::Mount,
        Some("resource_limit") => BoundaryKind::ResourceLimit,
        Some("cancelled") => BoundaryKind::Cancelled,
        Some("other_filesystem") => BoundaryKind::OtherFilesystem,
        _ => BoundaryKind::ResourceLimit,
    }
}

fn decamelize_json_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (to_snake_case(&key), decamelize_json_keys(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(decamelize_json_keys).collect()),
        other => other,
    }
}

fn to_snake_case(input: &str) -> String {
    let mut result = String::with_capacity(input.len() + 4);
    for (index, ch) in input.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                result.push('_');
            }
            result.push(ch.to_ascii_lowercase());
        } else {
            result.push(ch);
        }
    }
    result
}

fn map_tui_view_model_error(error: ViewModelError) -> CoreError {
    match error {
        ViewModelError::UnsupportedOutputKind(kind) => {
            CoreError::TuiInput(format!("expected scan.result input, got {kind:?}"))
        }
        ViewModelError::ResourceLimit {
            kind,
            limit,
            observed,
        } => CoreError::TuiRead(format!(
            "resource limit exceeded for {kind}: limit={limit}, observed={observed}"
        )),
        ViewModelError::Io(source) => CoreError::State(StateError::Io(source)),
        ViewModelError::Json { source } => CoreError::AnalysisInputJson(source),
        ViewModelError::MissingStatus => {
            CoreError::TuiViewModel("missing scan status in input".to_string())
        }
    }
}

fn imported_preview_provenance() -> FieldProvenance {
    FieldProvenance::StalePreview {
        observed_at: "1970-01-01T00:00:00Z".to_string(),
    }
}

fn downgrade_imported_entry(entry: &mut ScannedEntry) {
    entry.provenance = imported_preview_provenance();
    downgrade_imported_coverage(&mut entry.coverage);
}

fn downgrade_imported_aggregate(aggregate: &mut sweepx_model::DirectoryAggregate) {
    downgrade_imported_coverage(&mut aggregate.coverage);
}

fn downgrade_imported_coverage(coverage: &mut Coverage) {
    coverage.state = CoverageState::Incomplete;
    coverage.complete = false;
    coverage.details_lost = false;
    coverage.provenance = imported_preview_provenance();
    if !coverage
        .incomplete_reasons
        .contains(&ReasonCode::IncompleteStreamCoverage)
    {
        coverage
            .incomplete_reasons
            .push(ReasonCode::IncompleteStreamCoverage);
    }
    if !coverage
        .incomplete_reasons
        .contains(&ReasonCode::NotRevalidated)
    {
        coverage.incomplete_reasons.push(ReasonCode::NotRevalidated);
    }
}

fn cleaner_list_entry(
    cleaner: &LoadedBuiltInCleaner,
    trust: &CleanerCatalogTrustResolution,
) -> Value {
    let package = &cleaner.package;
    json!({
        "id": package.manifest.id,
        "version": package.manifest.version,
        "description": package.manifest.description,
        "publisher": package.manifest.publisher,
        "packageDigest": package.manifest.package_digest,
        "riskFloor": package.manifest.risk_floor,
        "supportedActions": package.manifest.supported_actions,
        "platforms": package.manifest.platforms,
        "unknownVersionBehavior": package.manifest.target_versions.unknown,
        "ruleCount": DecimalU128::new(package.rules.len() as u128),
        "catalogTrust": cleaner_catalog_trust_json(trust),
        "compatibility": cleaner_compatibility_json(cleaner),
    })
}

fn cleaner_show_entry(
    cleaner: &LoadedBuiltInCleaner,
    trust: &CleanerCatalogTrustResolution,
) -> Result<Value, CoreError> {
    let package = &cleaner.package;
    let rules = package
        .rules
        .iter()
        .map(|(path, rule)| cleaner_rule_entry(rule, path))
        .collect::<Result<Vec<_>, CoreError>>()?;
    Ok(json!({
        "manifest": package.manifest,
        "catalogTrust": cleaner_catalog_trust_json(trust),
        "compatibility": cleaner_compatibility_json(cleaner),
        "rules": rules,
    }))
}

fn cleaner_rule_entry(
    rule: &sweepx_cleaner_schema::CleanerRule,
    path: &str,
) -> Result<Value, CoreError> {
    let evaluation = evaluate_rule(rule, &synthetic_cleaner_context())?;
    Ok(json!({
        "path": path,
        "rule": rule,
        "vmCheck": {
            "factState": eval_state_label(evaluation.fact_state),
            "inferenceState": eval_state_label(evaluation.inference_state),
            "resolvedRisk": evaluation.resolved_risk.to_string().to_lowercase(),
            "reportOnly": evaluation.report_only,
            "context": "synthetic_read_only_contract_check",
        }
    }))
}

fn synthetic_cleaner_context() -> EvaluationContext {
    EvaluationContext::new()
        .insert("coverage.complete", sweepx_cleaner_vm::VmValue::Bool(true))
        .insert(
            "candidate.relativePath",
            sweepx_cleaner_vm::VmValue::String("target".to_string()),
        )
        .insert(
            "candidate.relativeComponents",
            sweepx_cleaner_vm::VmValue::StringList(vec!["Cache".to_string()]),
        )
        .insert(
            "cargo.targetDir",
            sweepx_cleaner_vm::VmValue::String("target".to_string()),
        )
        .insert(
            "cargo.targetShape",
            sweepx_cleaner_vm::VmValue::String("recognized_generated_structure".to_string()),
        )
        .insert(
            "cargo.workspaceId",
            sweepx_cleaner_vm::VmValue::String("workspace-1".to_string()),
        )
        .insert(
            "exclusiveReclaimableBytes",
            sweepx_cleaner_vm::VmValue::String("known".to_string()),
        )
        .insert(
            "objectType",
            sweepx_cleaner_vm::VmValue::String("Directory".to_string()),
        )
        .insert(
            "sharing.state",
            sweepx_cleaner_vm::VmValue::String("private".to_string()),
        )
        .insert(
            "activity.state",
            sweepx_cleaner_vm::VmValue::String("inactive".to_string()),
        )
        .insert(
            "browser.profileStillness",
            sweepx_cleaner_vm::VmValue::String("verified".to_string()),
        )
        .insert(
            "browser.storageClass",
            sweepx_cleaner_vm::VmValue::String("rebuildable_http_or_code_cache".to_string()),
        )
        .insert(
            "browser.runningState",
            sweepx_cleaner_vm::VmValue::String("stopped".to_string()),
        )
}

fn parse_cleaner_ref(raw: &str) -> Result<(String, Option<String>), CoreError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CoreError::InvalidCleanerRef(raw.to_string()));
    }
    match trimmed.split_once('@') {
        Some((id, version)) if !id.is_empty() && !version.is_empty() => {
            Ok((id.to_string(), Some(version.to_string())))
        }
        Some(_) => Err(CoreError::InvalidCleanerRef(raw.to_string())),
        None => Ok((trimmed.to_string(), None)),
    }
}

fn eval_state_label(state: sweepx_cleaner_vm::EvalState) -> &'static str {
    match state {
        sweepx_cleaner_vm::EvalState::Known(true) => "known_true",
        sweepx_cleaner_vm::EvalState::Known(false) => "known_false",
        sweepx_cleaner_vm::EvalState::Unknown => "unknown",
    }
}

#[allow(clippy::too_many_arguments)]
fn build_scan_events(
    stream_id: &str,
    operation_id: &OperationId,
    compat: &CompatSnapshot,
    roots: &[PathBuf],
    summary: Option<&ScanSummary>,
    output: &OutputEnvelope,
    started_at: &str,
    elapsed: Duration,
) -> Vec<EventEnvelope> {
    let mut sequence = 1u128;
    let mut events = Vec::new();
    events.push(event(
        stream_id,
        operation_id,
        sequence,
        EventType::OperationStarted,
        EventPhase::Detect,
        json!({
            "command": "scan",
            "requestDigest": format!("sha256:{}", digest_hex(&join_display_paths(roots))),
            "compat": compat,
            "rootCount": DecimalU128::new(roots.len() as u128),
            "resumable": false
        }),
        false,
        started_at,
        0,
        false,
        0,
    ));
    sequence += 1;

    if let Some(summary) = summary {
        for progress in &summary.progress {
            let (event_type, payload) = match progress {
                ProgressEvent::RootAccepted { path } => (
                    EventType::ScanRootAdmitted,
                    json!({"displayPath": path.display().to_string()}),
                ),
                ProgressEvent::EntryObserved { path, kind } => (
                    EventType::ScanProgress,
                    json!({
                        "displayPath": path.display().to_string(),
                        "kind": kind,
                        "scanId": output.summary["scanId"].clone(),
                        "processed": DecimalU128::new(sequence),
                        "completeState": "streaming"
                    }),
                ),
                ProgressEvent::Boundary { path, kind } => (
                    EventType::ScanBoundaryObserved,
                    json!({
                        "displayPath": path.display().to_string(),
                        "boundaryKind": boundary_label(kind),
                        "coverageEffect": if is_non_partial_boundary(kind) { "observed" } else { "incomplete" }
                    }),
                ),
                ProgressEvent::Error { path, reason } => (
                    EventType::ScanErrorObserved,
                    json!({
                        "displayPath": path.display().to_string(),
                        "reason": reason,
                        "coverageEffect": "incomplete"
                    }),
                ),
                ProgressEvent::Cancelled { path } => (
                    EventType::OperationCancelTooLate,
                    json!({"displayPath": path.display().to_string()}),
                ),
                ProgressEvent::ResourceLimit { path } => (
                    EventType::ScanBoundaryObserved,
                    json!({
                        "displayPath": path.display().to_string(),
                        "boundaryKind": "resource_limit",
                        "coverageEffect": "incomplete"
                    }),
                ),
                ProgressEvent::Finished => (
                    EventType::ScanRootCompleted,
                    json!({"rootCount": DecimalU128::new(roots.len() as u128)}),
                ),
            };
            events.push(event(
                stream_id,
                operation_id,
                sequence,
                event_type,
                EventPhase::Detect,
                payload,
                false,
                started_at,
                elapsed.as_nanos(),
                false,
                0,
            ));
            sequence += 1;
        }
    }

    events.push(event(
        stream_id,
        operation_id,
        sequence,
        EventType::OperationTerminal,
        EventPhase::Audit,
        json!({
            "status": output.status,
            "exitCode": output.conservative_exit_code(),
            "kind": output.kind,
            "resumable": false
        }),
        true,
        &output.generated_at,
        elapsed.as_nanos(),
        false,
        0,
    ));
    events
}

#[allow(clippy::too_many_arguments)]
fn event(
    stream_id: &str,
    operation_id: &OperationId,
    sequence: u128,
    event_type: EventType,
    phase: EventPhase,
    payload: Value,
    terminal: bool,
    emitted_at: &str,
    monotonic_offset_ns: u128,
    durable: bool,
    last_durable_sequence: u128,
) -> EventEnvelope {
    EventEnvelope {
        schema: sweepx_protocol::EVENT_SCHEMA.to_string(),
        stream_id: stream_id.to_string(),
        operation_id: operation_id.clone(),
        sequence: DecimalU128::new(sequence),
        cursor: format!("{stream_id}:{sequence}"),
        emitted_at: emitted_at.to_string(),
        monotonic_offset_ns: DecimalU128::new(monotonic_offset_ns),
        r#type: event_type,
        phase,
        payload,
        terminal,
        checkpoint: EventCheckpoint {
            durable,
            last_durable_sequence: DecimalU128::new(last_durable_sequence),
        },
    }
}

fn status_output_from_snapshot(
    operation_id: &str,
    snapshot: Option<&OperationSnapshot>,
) -> OutputEnvelope {
    let snapshot = snapshot
        .cloned()
        .unwrap_or_else(|| OperationSnapshot::not_found(operation_id, Locale::EnUs));
    let public = PublicOperationView::from(&snapshot);
    let mut output = OutputEnvelope::new(
        OutputKind::StatusResult,
        RequestId::new(format!("req-status-{operation_id}")),
        OperationId::new(format!("op-status-{}", nonce_tag())),
        timestamp_now(),
        snapshot.status,
        ExitCode::from(snapshot.status),
        compat_snapshot(current_os_family()),
    );
    output.summary = json!({
        "found": snapshot.state != OperationState::NotFound,
        "operationId": snapshot.operation_id,
        "state": snapshot.state
    });
    output.data = serde_json::to_value(public).expect("public operation view serializable");
    if let Some(error) = snapshot.error {
        output.errors.push(error);
    }
    output
}

fn cancel_output_from_snapshot(
    operation_id: &str,
    snapshot: Option<&OperationSnapshot>,
) -> OutputEnvelope {
    let disposition = match snapshot {
        None => CancelDisposition::NotFound,
        Some(_) => CancelDisposition::AlreadyTerminal,
    };
    let status = match disposition {
        CancelDisposition::NotFound => OutputStatus::Failed,
        CancelDisposition::AlreadyTerminal | CancelDisposition::Unsupported => {
            OutputStatus::Unsupported
        }
    };
    let public = snapshot.map(PublicOperationView::from);
    let mut output = OutputEnvelope::new(
        OutputKind::CancelResult,
        RequestId::new(format!("req-cancel-{}", nonce_tag())),
        OperationId::new(format!("op-cancel-{}", nonce_tag())),
        timestamp_now(),
        status,
        ExitCode::from(status),
        compat_snapshot(current_os_family()),
    );
    output.summary = json!({
        "operationId": operation_id,
        "disposition": disposition,
        "canCancel": false
    });
    output.data = serde_json::to_value(CancelView {
        operation_id: operation_id.to_string(),
        disposition,
        can_cancel: false,
        operation: public,
    })
    .expect("cancel view serializable");
    output.errors.push(match disposition {
        CancelDisposition::NotFound => protocol_error(
            "cancel.not_found",
            "cancel",
            "cancel.not_found",
            false,
            [("operationId", operation_id.to_string())],
        ),
        CancelDisposition::AlreadyTerminal => protocol_error(
            "cancel.already_terminal",
            "cancel",
            "cancel.already_terminal",
            false,
            [("operationId", operation_id.to_string())],
        ),
        CancelDisposition::Unsupported => protocol_error(
            "cancel.unsupported",
            "cancel",
            "cancel.unsupported",
            false,
            [("operationId", operation_id.to_string())],
        ),
    });
    output
}

fn load_snapshot<S: SnapshotStore>(
    _context: &CoreContext,
    operation_id: &str,
    store: Option<&S>,
) -> Result<Option<OperationSnapshot>, CoreError> {
    let validated = ValidatedOperationId::parse(operation_id)
        .map_err(|_| CoreError::InvalidOperationId(operation_id.to_string()))?;
    match store {
        Some(store) => Ok(store.load(validated.as_str())?),
        None => Ok(None),
    }
}

fn snapshot_from_output(
    output: &OutputEnvelope,
    command: &str,
    locale: Locale,
    roots: &[PathBuf],
) -> OperationSnapshot {
    OperationSnapshot {
        schema: SNAPSHOT_SCHEMA.to_string(),
        operation_id: output.operation_id.to_string(),
        request_id: output.request_id.to_string(),
        command: command.to_string(),
        state: snapshot_state(output.status),
        status: output.status,
        exit_code: output.conservative_exit_code() as u8,
        created_at: output.generated_at.clone(),
        updated_at: output.generated_at.clone(),
        locale: locale.as_bcp47().to_string(),
        root_paths: roots
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        scan_id: output
            .summary
            .get("scanId")
            .and_then(Value::as_str)
            .map(str::to_string),
        terminal_event_type: Some("operation.terminal".to_string()),
        entry_count: json_to_string(&output.summary["entryCount"]),
        error_count: json_to_string(&output.summary["errorCount"]),
        boundary_count: json_to_string(&output.summary["boundaryCount"]),
        error: output.errors.first().cloned(),
    }
}

fn snapshot_state(status: OutputStatus) -> OperationState {
    match status {
        OutputStatus::Ok => OperationState::Completed,
        OutputStatus::Partial => OperationState::Partial,
        OutputStatus::Unsupported => OperationState::Unsupported,
        OutputStatus::Blocked
        | OutputStatus::AuthorizationRequired
        | OutputStatus::Stale
        | OutputStatus::Failed
        | OutputStatus::NeedsReconciliation
        | OutputStatus::Cancelled => OperationState::Failed,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn unsupported_scan_output(
    context: &CoreContext,
    roots: &[PathBuf],
    ids: &GeneratedIds,
    generated_at: &str,
) -> OutputEnvelope {
    let mut output = OutputEnvelope::new(
        OutputKind::ScanResult,
        ids.request_id.clone(),
        ids.operation_id.clone(),
        generated_at.to_string(),
        OutputStatus::Unsupported,
        ExitCode::Unsupported,
        compat_snapshot(current_os_family()),
    );
    output.summary = json!({
        "rootCount": DecimalU128::new(roots.len() as u128),
        "platform": current_os_family(),
        "mode": "read_only"
    });
    output.data = json!({
        "scanId": Value::Null,
        "roots": [],
        "entries": [],
        "aggregates": [],
        "boundaries": []
    });
    output.errors.push(protocol_error(
        "scan.unsupported_platform",
        "scan",
        "scan.unsupported_platform",
        false,
        [("locale", context.locale().as_bcp47().to_string())],
    ));
    output
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn scan_status(summary: &ScanSummary) -> OutputStatus {
    if scan_error_count(summary) > 0 || scan_partial_boundary_count(summary) > 0 {
        OutputStatus::Partial
    } else {
        OutputStatus::Ok
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn scan_error_count(summary: &ScanSummary) -> u128 {
    summary
        .progress
        .iter()
        .filter(|event| matches!(event, ProgressEvent::Error { .. }))
        .count() as u128
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn scan_partial_boundary_count(summary: &ScanSummary) -> u128 {
    summary
        .boundaries
        .iter()
        .filter(|boundary| !is_non_partial_boundary(&boundary.kind))
        .count() as u128
}

fn is_non_partial_boundary(kind: &BoundaryKind) -> bool {
    matches!(kind, BoundaryKind::Symlink | BoundaryKind::RootSymlink)
}

#[derive(Debug, Clone)]
struct LoadedBuiltInCleaner {
    package: LoadedCleanerPackage,
    compatible: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CleanerCatalogTrustSource {
    LegacyBuiltin,
    ProductionSnapshot,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CleanerCatalogTrustFreshness {
    Current,
    Stale,
    LegacyBuiltin,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CleanerCatalogTrustDisposition {
    Trusted,
    ReportOnly,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanerCatalogTrustResolution {
    source: CleanerCatalogTrustSource,
    snapshot_digest: Option<String>,
    epoch: Option<u64>,
    freshness: CleanerCatalogTrustFreshness,
    disposition: CleanerCatalogTrustDisposition,
}

#[derive(Debug, Clone)]
struct ResolvedCleanerCatalog {
    cleaners: Vec<LoadedBuiltInCleaner>,
    trust: CleanerCatalogTrustResolution,
    cleaner_set_digest: String,
}

fn load_builtin_cleaners() -> Result<Vec<LoadedBuiltInCleaner>, CoreError> {
    BUILT_INS
        .iter()
        .map(|cleaner| {
            let package = cleaner.load()?;
            let compatible = cleaner_is_core_compatible(&package)?;
            Ok(LoadedBuiltInCleaner {
                package,
                compatible,
            })
        })
        .collect()
}

fn resolve_cleaner_catalog() -> Result<ResolvedCleanerCatalog, CoreError> {
    let cleaners = load_builtin_cleaners()?;
    let trust = legacy_builtin_catalog_trust()?;
    let cleaner_set_digest = cleaner_set_digest_with_trust(&cleaners, &trust)?;
    Ok(ResolvedCleanerCatalog {
        cleaners,
        trust,
        cleaner_set_digest,
    })
}

fn legacy_builtin_catalog_trust() -> Result<CleanerCatalogTrustResolution, CoreError> {
    let trust = CleanerCatalogTrustResolution {
        source: CleanerCatalogTrustSource::LegacyBuiltin,
        snapshot_digest: None,
        epoch: None,
        freshness: CleanerCatalogTrustFreshness::LegacyBuiltin,
        disposition: CleanerCatalogTrustDisposition::Trusted,
    };
    validate_catalog_trust(&trust)?;
    Ok(trust)
}

fn validate_catalog_trust(trust: &CleanerCatalogTrustResolution) -> Result<(), CoreError> {
    match trust.source {
        CleanerCatalogTrustSource::LegacyBuiltin => {
            if trust.snapshot_digest.is_some() || trust.epoch.is_some() {
                return Err(CoreError::CleanerCatalogTrust(
                    "legacy builtin catalog trust cannot carry snapshot digest or epoch"
                        .to_string(),
                ));
            }
            if trust.freshness != CleanerCatalogTrustFreshness::LegacyBuiltin {
                return Err(CoreError::CleanerCatalogTrust(
                    "legacy builtin catalog trust must use legacy_builtin freshness".to_string(),
                ));
            }
        }
        CleanerCatalogTrustSource::ProductionSnapshot => {
            if trust.snapshot_digest.is_none() || trust.epoch.is_none() {
                return Err(CoreError::CleanerCatalogTrust(
                    "production snapshot trust requires snapshot digest and epoch".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn cleaner_is_core_compatible(package: &LoadedCleanerPackage) -> Result<bool, CoreError> {
    let current_core = Version::parse(CORE_VERSION).map_err(|_| CoreError::CleanerCompat {
        cleaner_ref: package.manifest.id.clone(),
        required_core: package.manifest.requires.core.clone(),
        current_core: CORE_VERSION.to_string(),
    })?;
    let required = VersionReq::parse(&package.manifest.requires.core).map_err(|_| {
        CoreError::CleanerCompat {
            cleaner_ref: package.manifest.id.clone(),
            required_core: package.manifest.requires.core.clone(),
            current_core: CORE_VERSION.to_string(),
        }
    })?;
    Ok(required.matches(&current_core))
}

fn cleaner_set_digest() -> Result<String, CoreError> {
    let cleaner_catalog = resolve_cleaner_catalog()?;
    Ok(cleaner_catalog.cleaner_set_digest)
}

fn cleaner_set_digest_with_trust(
    cleaners: &[LoadedBuiltInCleaner],
    trust: &CleanerCatalogTrustResolution,
) -> Result<String, CoreError> {
    validate_catalog_trust(trust)?;
    let mut records = cleaners
        .iter()
        .map(|cleaner| {
            json!({
                "id": cleaner.package.manifest.id,
                "version": cleaner.package.manifest.version,
                "packageDigest": cleaner.package.manifest.package_digest,
                "catalogTrust": cleaner_catalog_trust_json(trust),
            })
        })
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        let left_key = (
            left["id"].as_str().unwrap_or_default(),
            left["version"].as_str().unwrap_or_default(),
            left["packageDigest"].as_str().unwrap_or_default(),
            left["catalogTrust"]["source"].as_str().unwrap_or_default(),
            left["catalogTrust"]["snapshotDigest"]
                .as_str()
                .unwrap_or_default(),
            left["catalogTrust"]["epoch"].as_u64().unwrap_or_default(),
            left["catalogTrust"]["freshness"]
                .as_str()
                .unwrap_or_default(),
            left["catalogTrust"]["disposition"]
                .as_str()
                .unwrap_or_default(),
        );
        let right_key = (
            right["id"].as_str().unwrap_or_default(),
            right["version"].as_str().unwrap_or_default(),
            right["packageDigest"].as_str().unwrap_or_default(),
            right["catalogTrust"]["source"].as_str().unwrap_or_default(),
            right["catalogTrust"]["snapshotDigest"]
                .as_str()
                .unwrap_or_default(),
            right["catalogTrust"]["epoch"].as_u64().unwrap_or_default(),
            right["catalogTrust"]["freshness"]
                .as_str()
                .unwrap_or_default(),
            right["catalogTrust"]["disposition"]
                .as_str()
                .unwrap_or_default(),
        );
        left_key.cmp(&right_key)
    });
    let mut hasher = Sha256::new();
    hasher.update(b"sweepx.cleaner-set-digest.v1\0");
    hasher.update(canonicalize_value(&Value::Array(records)).map_err(|error| {
        CoreError::CleanerCatalogTrust(format!(
            "failed to canonicalize cleaner set digest payload: {error}"
        ))
    })?);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn cleaner_catalog_trust_json(trust: &CleanerCatalogTrustResolution) -> Value {
    json!(trust)
}

fn cleaner_compatibility_json(cleaner: &LoadedBuiltInCleaner) -> Value {
    json!({
        "state": if cleaner.compatible { "compatible" } else { "incompatible" },
        "currentCore": CORE_VERSION,
        "requiresCore": cleaner.package.manifest.requires.core,
        "reportOnly": !cleaner.compatible,
    })
}

fn compat_snapshot_with_digest(
    platform_adapter_id: &str,
    cleaner_set_digest: String,
) -> CompatSnapshot {
    CompatSnapshot {
        core_version: CORE_VERSION.to_string(),
        scanner_semantics_version: SCANNER_SEMANTICS_VERSION,
        safety_policy_version: SAFETY_POLICY_VERSION,
        platform_adapter: PlatformAdapterCompat {
            id: platform_adapter_id.to_string(),
            version: CORE_VERSION.to_string(),
        },
        cleaner_set_digest,
        required_features: Vec::new(),
        extensions: Vec::new(),
    }
}

fn compat_snapshot(platform_adapter_id: &str) -> CompatSnapshot {
    compat_snapshot_with_digest(
        platform_adapter_id,
        cleaner_set_digest().unwrap_or_else(|_| "sha256:unavailable".to_string()),
    )
}

fn command_record(id: &str, state: CapabilityState, reason_code: &str) -> Value {
    json!({
        "id": id,
        "state": capability_state_name(state),
        "reasonCode": reason_code,
        "mutating": false
    })
}

fn capability_record(
    recorded_at: &str,
    qualification_expires_at: &str,
    os_family: OsFamily,
    capability: &str,
    state: CapabilityState,
    reason_code: &str,
) -> CapabilityRecordV1 {
    let os_family_name = os_family_name(os_family);
    let qualified = state == CapabilityState::Qualified;
    let qualification_key = QualificationKey {
        scope: QualificationScope::Platform,
        core_version: CORE_VERSION.to_string(),
        scanner_semantics_version: SCANNER_SEMANTICS_VERSION,
        safety_policy_digest: if qualified {
            sha256_label("p1-read-only-policy")
        } else {
            "sha256:p1-read-only-policy".to_string()
        },
        adapter_id: os_family_name.to_string(),
        adapter_digest: if qualified {
            sha256_label(&format!("{os_family_name}-read-only-adapter"))
        } else {
            format!("sha256:{os_family_name}-adapter")
        },
        os_family,
        os_build: if qualified {
            "platform-independent-read-only-contract-v1".to_string()
        } else {
            "development".to_string()
        },
        arch: std::env::consts::ARCH.to_string(),
        filesystem: "local".to_string(),
        filesystem_version: None,
        volume_class: "local".to_string(),
        provider_or_desktop_backend: None,
        runtime_privilege_profile: RuntimePrivilegeProfile::OrdinaryUser,
        cleaner_id: None,
        cleaner_version: None,
        capability: CapabilityCell::new(capability)
            .expect("built-in capability cells must be valid"),
    };
    let evidence = CapabilityEvidence {
        bundle_digest: if qualified {
            sha256_label(&format!(
                "{os_family_name}:{capability}:{reason_code}:development-snapshot"
            ))
        } else {
            format!("sha256:{os_family_name}:{capability}:{reason_code}")
        },
        evidence_class: EvidenceClass::DevelopmentSnapshot,
        reviewed_by: vec!["p1-core-cli".to_string()],
        limitations: vec![
            "read-only CLI only".to_string(),
            "no destructive commands".to_string(),
            "no background daemon".to_string(),
        ],
        invalidates_on: vec![
            "platform-adapter-change".to_string(),
            "policy-change".to_string(),
            "future-mutation-implementation".to_string(),
        ],
        validity: qualified.then(|| QualificationValidity {
            status: QualificationValidityStatus::Current,
            valid_from: Some(recorded_at.to_string()),
            expires_at: Some(qualification_expires_at.to_string()),
            invalidated_at: None,
            invalidation_reason: None,
        }),
    };
    let mut record =
        CapabilityRecordV1::new(recorded_at, qualification_key, state, reason_code, evidence);
    record.reason = Some(capability_reason(reason_code).to_string());
    record
}

fn mutation_capability_record(
    recorded_at: &str,
    qualification_expires_at: &str,
    os_family: OsFamily,
    capability: &str,
    reason_code: &str,
    evidence_class: EvidenceClass,
) -> CapabilityRecordV1 {
    let mut record = capability_record(
        recorded_at,
        qualification_expires_at,
        os_family,
        capability,
        CapabilityState::Disabled,
        reason_code,
    );
    record.evidence.evidence_class = evidence_class;
    record.evidence.reviewed_by = vec!["p4a-capability-integration".to_string()];
    record.evidence.limitations = match evidence_class {
        EvidenceClass::FixtureConformanceOnly => vec![
            "fixture-only fake-adapter evidence is not product qualification".to_string(),
            "no native Trash adapter is exposed".to_string(),
            "no destructive commands are exposed".to_string(),
        ],
        _ => vec![
            "real-OS qualification evidence is incomplete".to_string(),
            "no native mutation adapter is exposed".to_string(),
            "no destructive commands are exposed".to_string(),
        ],
    };
    record.evidence.invalidates_on = vec![
        "real-os-qualification-added".to_string(),
        "platform-adapter-change".to_string(),
        "safety-policy-change".to_string(),
    ];
    record
}

fn os_family_name(os_family: OsFamily) -> &'static str {
    match os_family {
        OsFamily::Windows => "windows",
        OsFamily::Macos => "macos",
        OsFamily::Linux => "linux",
    }
}

fn sha256_label(label: &str) -> String {
    format!("sha256:{}", digest_hex(label))
}

fn capability_state_name(state: CapabilityState) -> &'static str {
    match state {
        CapabilityState::Qualified => "qualified",
        CapabilityState::Degraded => "degraded",
        CapabilityState::ReportOnly => "report_only",
        CapabilityState::Unsupported => "unsupported",
        CapabilityState::Disabled => "disabled",
    }
}

fn capability_reason(reason_code: &str) -> &'static str {
    match reason_code {
        "LINUX_SCANNER_DEVELOPMENT" => {
            "Linux scanning is implemented as a development-grade read-only facade."
        }
        "MACOS_SCANNER_DEVELOPMENT" => {
            "macOS scanning is implemented as a development-grade read-only facade."
        }
        "WINDOWS_SCANNER_DEVELOPMENT" => {
            "Windows scanning is implemented as a development-grade handle-relative read-only facade without durable state."
        }
        "STUB_COMPILATION_ONLY" => {
            "Platform support is currently limited to stub compilation only."
        }
        "NATIVE_TRASH_QUALIFICATION_ABSENT" => {
            "Native Trash is disabled because real-OS qualification is absent for this exact capability cell."
        }
        "PERMANENT_QUALIFICATION_ABSENT" => {
            "Permanent deletion is disabled because independent qualification is absent for this exact capability cell."
        }
        "CANCEL_LIVE_REGISTRY_ABSENT" => {
            "Cancel is disabled because P1 does not maintain a live in-process operation registry."
        }
        "SCAN_NDJSON_DURABLE_JOURNAL_ABSENT" => {
            "Scan NDJSON is disabled until a durable event journal and replay path are implemented."
        }
        "STATUS_SNAPSHOT_SUPPORTED" => "Status reads durable snapshots only.",
        "WINDOWS_DURABLE_STATE_SECURITY_UNIMPLEMENTED" => {
            "Durable snapshots are disabled on Windows until current-user-private ACL and reparse-point checks are implemented."
        }
        "CAPABILITIES_REPORT_SUPPORTED" => "Capabilities reports the current read-only surface.",
        "EXPLAIN_FROM_SCAN_JSON_SUPPORTED" => {
            "Explain reads a bounded scan.result envelope and returns read-only analysis."
        }
        "BUILTIN_CLEANER_COMPAT_PARTIAL" => {
            "Built-in cleaner metadata is readable, but one or more cleaners are incompatible with this core version."
        }
        "BUILTIN_CLEANER_REPORTING_DEGRADED" => {
            "Built-in cleaner reporting is currently degraded because the cleaner catalog could not be loaded."
        }
        "BUILTIN_CLEANER_REPORTING_SUPPORTED" => {
            "Built-in cleaner list and show commands report catalog metadata only."
        }
        "TUI_READ_PATH_SUPPORTED" => {
            "TUI validates a bounded scan.result input and stays read-only."
        }
        "LINUX_LIVE_TUI_DEVELOPMENT" => {
            "The in-process read-only TUI browses the completed live Linux scan snapshot."
        }
        "MACOS_LIVE_TUI_DEVELOPMENT" => {
            "The in-process read-only TUI browses the completed live macOS scan snapshot."
        }
        "WINDOWS_LIVE_TUI_DEVELOPMENT" => {
            "The in-process read-only TUI browses the completed live Windows scan held in memory without durable state."
        }
        "LIVE_TUI_REQUIRES_SUPPORTED_SCANNER" => {
            "The live TUI is unavailable because the host scanner is not implemented."
        }
        _ => "Capability state is intentionally conservative.",
    }
}

fn camelize_json_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (to_camel_case(&key), camelize_json_keys(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(camelize_json_keys).collect()),
        other => other,
    }
}

fn to_camel_case(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut uppercase_next = false;
    for ch in input.chars() {
        if ch == '_' {
            uppercase_next = true;
            continue;
        }
        if uppercase_next {
            result.extend(ch.to_uppercase());
            uppercase_next = false;
        } else {
            result.push(ch);
        }
    }
    result
}

fn protocol_error<const N: usize>(
    code: &str,
    class: &str,
    message_key: &str,
    retryable: bool,
    params: [(&str, String); N],
) -> ProtocolMessage {
    ProtocolMessage {
        code: code.to_string(),
        class: class.to_string(),
        message_key: message_key.to_string(),
        retryable,
        params: params
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    }
}

pub fn core_error_exit_code(error: &CoreError) -> ExitCode {
    match error {
        CoreError::NonAbsoluteRoot(_)
        | CoreError::MissingRoots
        | CoreError::InvalidOperationId(_)
        | CoreError::InvalidAnalysisInputLimit
        | CoreError::NonAbsoluteAnalysisInput(_)
        | CoreError::AnalysisInputTooLarge { .. }
        | CoreError::AnalysisInputJson(_)
        | CoreError::CandidateNotFound(_)
        | CoreError::InvalidCleanerRef(_)
        | CoreError::TuiInput(_) => ExitCode::UsageError,
        CoreError::CleanerCompat { .. }
        | CoreError::CleanerCatalogTrust(_)
        | CoreError::ProductionCatalogTrust(_) => ExitCode::CleanerTrustOrCompat,
        CoreError::State(_) => ExitCode::StateIntegrityUnavailable,
        CoreError::AuditProjection(_) => ExitCode::StateIntegrityUnavailable,
        CoreError::Scan(_)
        | CoreError::AnalysisBuild(_)
        | CoreError::Catalog(_)
        | CoreError::CleanerVm(_)
        | CoreError::TuiRead(_)
        | CoreError::TuiViewModel(_) => ExitCode::OperationFailed,
    }
}

fn boundary_label(kind: &BoundaryKind) -> &'static str {
    match kind {
        BoundaryKind::RootSymlink => "root_symlink",
        BoundaryKind::Symlink => "symlink",
        BoundaryKind::ReparsePoint => "reparse_point",
        BoundaryKind::Mount => "mount",
        BoundaryKind::ResourceLimit => "resource_limit",
        BoundaryKind::Cancelled => "cancelled",
        BoundaryKind::OtherFilesystem => "other_filesystem",
    }
}

fn first_root(output: &OutputEnvelope) -> &str {
    output
        .data
        .get("roots")
        .and_then(Value::as_array)
        .and_then(|roots| roots.first())
        .and_then(|root| root.get("displayPath"))
        .and_then(Value::as_str)
        .unwrap_or("-")
}

fn json_decimal_to_usize(value: &Value) -> Option<usize> {
    value
        .as_str()
        .and_then(|raw| raw.parse::<usize>().ok())
        .or_else(|| value.as_u64().map(|raw| raw as usize))
}

fn json_to_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::to_string)
        .or_else(|| value.as_u64().map(|raw| raw.to_string()))
}

fn status_label(status: OutputStatus) -> &'static str {
    match status {
        OutputStatus::Ok => "ok",
        OutputStatus::Partial => "partial",
        OutputStatus::Blocked => "blocked",
        OutputStatus::AuthorizationRequired => "authorization_required",
        OutputStatus::Stale => "stale",
        OutputStatus::Failed => "failed",
        OutputStatus::NeedsReconciliation => "needs_reconciliation",
        OutputStatus::Cancelled => "cancelled",
        OutputStatus::Unsupported => "unsupported",
    }
}

fn command_name(kind: &OutputKind) -> &'static str {
    match kind {
        OutputKind::ScanResult => "scan",
        OutputKind::StatusResult => "status",
        OutputKind::CancelResult => "cancel",
        OutputKind::CapabilitiesResult => "capabilities",
        _ => "unknown",
    }
}

fn current_os_family() -> &'static str {
    std::env::consts::OS
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn host_scan_platform() -> &'static str {
    current_os_family()
}

#[derive(Debug, Clone)]
struct GeneratedIds {
    request_id: RequestId,
    operation_id: OperationId,
}

impl GeneratedIds {
    fn operation_id_str(&self) -> &str {
        &self.operation_id
    }
}

fn fresh_operation_ids(command: &str, roots: &[PathBuf]) -> GeneratedIds {
    let seed = format!(
        "{}:{}:{}:{}",
        command,
        unix_timestamp_nanos(),
        nonce_tag(),
        digest_hex(&join_display_paths(roots))
    );
    GeneratedIds {
        request_id: RequestId::new(format!(
            "req-{command}-{}",
            digest_hex(&(seed.clone() + ":req"))
        )),
        operation_id: OperationId::new(format!("op-{command}-{}", digest_hex(&(seed + ":op")))),
    }
}

fn join_display_paths(roots: &[PathBuf]) -> String {
    roots
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

fn digest_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}

fn nonce_tag() -> String {
    digest_hex(&format!(
        "{}:{}",
        unix_timestamp_nanos(),
        std::process::id()
    ))[..12]
        .to_string()
}

fn unix_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos()
}

fn timestamp_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    let seconds = now.as_secs() as i64;
    let nanos = now.subsec_nanos();
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .replace_nanosecond(nanos)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339 formatting available")
}

fn timestamp_after(timestamp: &str, duration: time::Duration) -> String {
    time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339)
        .expect("internally generated timestamp must parse")
        .checked_add(duration)
        .expect("capability validity timestamp must remain representable")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339 formatting available")
}

pub fn state_dir_from_explicit_or_default(
    explicit: Option<&Path>,
) -> Result<Option<PathBuf>, StateError> {
    match explicit {
        Some(path) => {
            if !path.is_absolute() {
                return Err(StateError::NonAbsoluteStateDir(path.to_path_buf()));
            }
            Ok(Some(path.to_path_buf()))
        }
        None => Ok(default_state_dir()),
    }
}

#[cfg(target_os = "windows")]
fn default_state_dir() -> Option<PathBuf> {
    None
}

#[cfg(not(target_os = "windows"))]
fn default_state_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".local/state")))?;
    Some(base.join("sweepx"))
}

#[cfg(not(target_os = "windows"))]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

pub fn parse_locale_override(raw: &str) -> Result<Locale, sweepx_i18n::LocaleParseError> {
    raw.parse()
}

pub fn validate_absolute_root(path: &OsStr) -> Result<PathBuf, CoreError> {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(CoreError::NonAbsoluteRoot(path))
    }
}

fn normalize_scan_roots(roots: &[PathBuf]) -> Result<Vec<PathBuf>, CoreError> {
    if roots.is_empty() {
        return Err(CoreError::MissingRoots);
    }
    if let Some(path) = roots.iter().find(|path| !path.is_absolute()) {
        return Err(CoreError::NonAbsoluteRoot(path.clone()));
    }

    // Normalize only syntactic separators and `.` components. Never
    // canonicalize or collapse `..`: doing so could follow an ancestor
    // symlink before the scanner's no-follow admission checks run.
    let mut normalized = roots
        .iter()
        .map(|root| root.components().collect::<PathBuf>())
        .collect::<Vec<_>>();
    normalized.sort_by(|left, right| {
        left.components()
            .count()
            .cmp(&right.components().count())
            .then_with(|| left.cmp(right))
    });
    normalized.dedup();

    let mut retained = Vec::<PathBuf>::new();
    for root in normalized {
        let contains_parent = root
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir));
        if !contains_parent
            && retained.iter().any(|ancestor| {
                !ancestor
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
                    && root.starts_with(ancestor)
            })
        {
            continue;
        }
        retained.push(root);
    }
    retained.sort();
    Ok(retained)
}

fn validate_or_prepare_state_dir(path: &Path) -> Result<(), StateError> {
    if !durable_state_supported() {
        return Err(StateError::DurableStateUnsupportedOnWindows);
    }
    if !path.is_absolute() {
        return Err(StateError::NonAbsoluteStateDir(path.to_path_buf()));
    }
    if path.exists() {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(StateError::SymlinkStateDir(path.to_path_buf()));
        }
        if !meta.is_dir() {
            return Err(StateError::InvalidStateDir(path.to_path_buf()));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    set_private_dir_mode(path)?;
    ensure_private_dir(path)
}

fn validate_or_prepare_private_subdir(path: &Path) -> Result<(), StateError> {
    if !durable_state_supported() {
        return Err(StateError::DurableStateUnsupportedOnWindows);
    }
    if path.exists() {
        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(StateError::SymlinkStateDir(path.to_path_buf()));
        }
        if !meta.is_dir() {
            return Err(StateError::InvalidStateDir(path.to_path_buf()));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    set_private_dir_mode(path)?;
    ensure_private_dir(path)
}

#[cfg(unix)]
fn set_private_dir_mode(path: &Path) -> Result<(), StateError> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir_mode(_path: &Path) -> Result<(), StateError> {
    Err(StateError::DurableStateUnsupportedOnWindows)
}

#[cfg(unix)]
fn ensure_private_dir(path: &Path) -> Result<(), StateError> {
    let meta = fs::symlink_metadata(path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o700 || meta.uid() != current_euid() {
        return Err(StateError::InsecureStateDir(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_dir(_path: &Path) -> Result<(), StateError> {
    Err(StateError::DurableStateUnsupportedOnWindows)
}

#[cfg(unix)]
fn current_euid() -> u32 {
    unsafe { libc::geteuid() }
}

fn atomic_write_private_file(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    let parent = path
        .parent()
        .ok_or_else(|| StateError::InvalidStateDir(path.to_path_buf()))?;
    validate_or_prepare_private_subdir(parent)?;
    let temp_path = parent.join(format!(
        ".{}.{}.tmp",
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("snapshot"),
        nonce_tag()
    ));

    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp_path)?;

    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;

    file.write_all(bytes)?;
    file.sync_all()?;

    #[cfg(unix)]
    fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;

    fs::rename(&temp_path, path)?;
    sync_directory(parent)?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), StateError> {
    let file = File::open(path)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::{Seek, SeekFrom};

    #[cfg(unix)]
    fn empty_audit_store() -> (tempfile::TempDir, AuditStore) {
        use std::os::unix::fs::DirBuilderExt;

        let temp = tempfile::tempdir().unwrap();
        let audit_root = temp.path().join("audit");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&audit_root)
            .unwrap();
        let store = AuditStore::open(audit_root).unwrap();
        (temp, store)
    }

    #[cfg(unix)]
    #[test]
    fn audit_projection_returns_empty_snapshot_for_existing_store() {
        let (_temp, store) = empty_audit_store();

        let snapshot = audit_projection(&store).unwrap();

        assert_eq!(snapshot.schema, sweepx_protocol::AUDIT_PROJECTION_SCHEMA);
        assert!(snapshot.batches.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn audit_projection_propagates_corrupted_header() {
        let (temp, store) = empty_audit_store();
        let audit_root = temp.path().join("audit");
        let mut database = OpenOptions::new()
            .write(true)
            .open(audit_root.join("audit.db"))
            .unwrap();
        database.seek(SeekFrom::Start(68)).unwrap();
        database.write_all(&[0; 4]).unwrap();
        database.sync_all().unwrap();
        drop(database);

        let error = audit_projection(&store).unwrap_err();

        assert!(matches!(
            error,
            CoreError::AuditProjection(ProjectionError::Corruption(_))
        ));
    }

    #[test]
    fn operation_id_validation_rejects_traversal_like_input() {
        assert!(ValidatedOperationId::parse("../etc/passwd").is_err());
        assert!(ValidatedOperationId::parse("op/123").is_err());
        assert!(ValidatedOperationId::parse("op:123").is_err());
    }

    #[test]
    fn durable_state_support_matches_platform_security_implementation() {
        assert_eq!(durable_state_supported(), cfg!(unix));
    }

    #[test]
    fn scan_ndjson_remains_disabled_without_a_durable_journal() {
        assert!(!scan_ndjson_supported());
    }

    #[test]
    fn status_and_cancel_data_use_the_exact_public_views() {
        let snapshot = OperationSnapshot {
            schema: SNAPSHOT_SCHEMA.to_string(),
            operation_id: "op-contract".to_string(),
            request_id: "req-contract".to_string(),
            command: "scan".to_string(),
            state: OperationState::Completed,
            status: OutputStatus::Ok,
            exit_code: 0,
            created_at: "2026-08-27T00:00:00Z".to_string(),
            updated_at: "2026-08-27T00:00:01Z".to_string(),
            locale: "en-US".to_string(),
            root_paths: vec!["/tmp/root".to_string()],
            scan_id: Some("scan-contract".to_string()),
            terminal_event_type: Some("operation.terminal".to_string()),
            entry_count: Some("1".to_string()),
            error_count: Some("0".to_string()),
            boundary_count: Some("0".to_string()),
            error: None,
        };
        let expected_operation =
            serde_json::to_value(PublicOperationView::from(&snapshot)).unwrap();

        let status = status_output_from_snapshot(&snapshot.operation_id, Some(&snapshot));
        assert_eq!(status.data, expected_operation);

        let cancel = cancel_output_from_snapshot(&snapshot.operation_id, Some(&snapshot));
        assert_eq!(cancel.data["operation"], expected_operation);
        assert_eq!(cancel.data["disposition"], "already_terminal");
        assert_eq!(cancel.data["canCancel"], false);

        let missing = cancel_output_from_snapshot("op-missing", None);
        assert_eq!(missing.data["operation"], Value::Null);
        assert_eq!(missing.data["disposition"], "not_found");
    }

    #[cfg(unix)]
    #[test]
    fn durable_store_none_does_not_create_state() {
        assert!(durable_store(None).unwrap().is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_durable_store_fails_before_creating_state() {
        let temp = tempfile::TempDir::new().unwrap();
        let state = temp.path().join("state");

        assert!(matches!(
            DurableSnapshotStore::new(&state),
            Err(StateError::DurableStateUnsupportedOnWindows)
        ));
        assert!(!state.exists());
        assert!(matches!(
            durable_store(Some(&state)),
            Err(StateError::DurableStateUnsupportedOnWindows)
        ));
        assert!(!state.exists());
        assert!(state_dir_from_explicit_or_default(None).unwrap().is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn scan_roots_are_deduplicated_and_ancestor_order_is_stable() {
        let forward = normalize_scan_roots(&[
            PathBuf::from("/tmp/root/child"),
            PathBuf::from("/tmp/root"),
            PathBuf::from("/tmp/root"),
            PathBuf::from("/tmp/root2"),
        ])
        .unwrap();
        let reverse = normalize_scan_roots(&[
            PathBuf::from("/tmp/root2"),
            PathBuf::from("/tmp/root"),
            PathBuf::from("/tmp/root/child"),
        ])
        .unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(
            forward,
            [PathBuf::from("/tmp/root"), PathBuf::from("/tmp/root2")]
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn scan_root_normalization_removes_dot_but_does_not_collapse_parent() {
        let normalized = normalize_scan_roots(&[
            PathBuf::from("/tmp/./root/"),
            PathBuf::from("/tmp/root"),
            PathBuf::from("/tmp/link/../root"),
        ])
        .unwrap();
        assert_eq!(
            normalized,
            [
                PathBuf::from("/tmp/link/../root"),
                PathBuf::from("/tmp/root")
            ]
        );
    }

    #[test]
    fn scan_success_tui_parts_keep_only_small_metadata_and_owned_summary() {
        let output = OutputEnvelope::new(
            OutputKind::ScanResult,
            RequestId::new("req"),
            OperationId::new("op"),
            timestamp_now(),
            OutputStatus::Partial,
            ExitCode::Partial,
            compat_snapshot("linux"),
        );
        let mut output = output;
        output.summary = json!({"scanId": "scan-owned"});
        output.data = json!({"large": ["discarded"]});
        let success = ScanSuccess {
            output,
            events: Vec::new(),
            snapshot: OperationSnapshot::not_found("unused", Locale::EnUs),
            summary: ScanSummary {
                roots: Vec::new(),
                entries: Vec::new(),
                aggregates: Vec::new(),
                boundaries: Vec::new(),
                progress: Vec::new(),
            },
        };

        let parts = success.into_tui_parts();
        assert_eq!(parts.status, OutputStatus::Partial);
        assert_eq!(parts.exit_code, ExitCode::Partial as u8);
        assert_eq!(parts.scan_id.as_deref(), Some("scan-owned"));
    }

    #[test]
    fn human_output_uses_selected_locale_only() {
        let context = CoreContext::new(LocaleResolution::new(
            Locale::ZhCn,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let mut output = OutputEnvelope::new(
            OutputKind::CapabilitiesResult,
            RequestId::new("req"),
            OperationId::new("op"),
            timestamp_now(),
            OutputStatus::Partial,
            ExitCode::Partial,
            compat_snapshot("linux"),
        );
        output.summary = json!({"entryCount": "0", "errorCount": "0"});
        let rendered = render_human_output(&context, &output);
        assert!(rendered.contains("语言"));
        assert!(!rendered.contains("Locale"));
    }

    #[test]
    fn human_scan_output_joins_aggregate_and_deduplicates_directory_row() {
        let context = CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let mut output = OutputEnvelope::new(
            OutputKind::ScanResult,
            RequestId::new("req"),
            OperationId::new("op"),
            timestamp_now(),
            OutputStatus::Partial,
            ExitCode::Partial,
            compat_snapshot("linux"),
        );
        let entry = json!({
            "displayPath": "/tmp/root",
            "identity": {
                "entryId": "scan-1:e:1",
                "scanRootId": "scan-1:e:root"
            },
            "objectType": "directory",
            "reclaimableEstimate": {"state": "known", "value": "0"},
            "coverage": {"state": "incomplete"}
        });
        output.data = json!({
            "roots": [entry.clone()],
            "entries": [entry],
            "aggregates": [{
                "scanEntryId": "scan-1:e:1",
                "directoryIdentity": "scan-1:e:1",
                "potentiallyReclaimableBytes": {"state": "known", "value": "4096"},
                "coverage": {"state": "complete"}
            }]
        });
        output.summary = json!({
            "rootCount": "1",
            "entryCount": "1",
            "aggregateCount": "1",
            "boundaryCount": "2",
            "errorCount": "3"
        });
        output.warnings.push(protocol_error(
            "scan.partial",
            "scan",
            "scan.partial",
            false,
            [("scanId", "scan-1".to_string())],
        ));
        output.errors.push(protocol_error(
            "scan.example_error",
            "scan",
            "scan.example_error",
            false,
            [],
        ));

        let rendered = render_human_output(&context, &output);
        assert_eq!(rendered.matches("/tmp/root").count(), 1);
        assert!(rendered.contains("Status: partial"));
        assert!(rendered.contains("4096"));
        assert!(rendered.contains("complete"));
        assert!(rendered.contains(
            "Summary: 1 roots, 1 entries, 1 directory aggregates, 2 boundaries, 3 errors"
        ));
        assert!(rendered.contains("Warnings: scan.partial"));
        assert!(rendered.contains("Errors: scan.example_error"));
    }

    #[test]
    fn human_scan_output_does_not_associate_legacy_entry_without_identity() {
        let context = CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let mut output = OutputEnvelope::new(
            OutputKind::ScanResult,
            RequestId::new("req"),
            OperationId::new("op"),
            timestamp_now(),
            OutputStatus::Ok,
            ExitCode::Completed,
            compat_snapshot("linux"),
        );
        output.data = json!({
            "roots": [],
            "entries": [{
                "displayPath": "/tmp/root",
                "objectType": "directory",
                "reclaimableEstimate": {"state": "known", "value": "0"},
                "coverage": {"state": "incomplete"}
            }],
            "aggregates": [{
                "scanEntryId": "scan-1:e:1",
                "directoryIdentity": "scan-1:e:1",
                "potentiallyReclaimableBytes": {"state": "known", "value": "4096"},
                "coverage": {"state": "complete"}
            }]
        });

        let rendered = render_human_output(&context, &output);
        assert!(rendered.contains("/tmp/root"));
        assert!(!rendered.contains("4096"));
        assert!(rendered.contains("0"));
        assert!(rendered.contains("incomplete"));
    }

    #[test]
    fn human_scan_output_sanitizes_terminal_control_characters() {
        let context = CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let mut output = OutputEnvelope::new(
            OutputKind::ScanResult,
            RequestId::new("req"),
            OperationId::new("op"),
            timestamp_now(),
            OutputStatus::Ok,
            ExitCode::Completed,
            compat_snapshot("linux"),
        );
        output.data = json!({
            "roots": [],
            "entries": [{
                "displayPath": "/tmp/\u{001b}]52;c;clipboard\u{0007}",
                "objectType": "file",
                "reclaimableEstimate": {"state": "known", "value": "1"},
                "coverage": {"state": "complete"}
            }],
            "aggregates": []
        });

        let rendered = render_human_output(&context, &output);
        assert!(!rendered.contains('\u{001b}'));
        assert!(!rendered.contains('\u{0007}'));
        assert!(rendered.contains('\u{fffd}'));
    }

    #[test]
    fn camelize_json_keys_converts_nested_maps() {
        let value = json!({
            "scan_id": "scan-1",
            "entries": [
                {
                    "display_path": "/tmp/demo",
                    "logical_bytes": {
                        "not_checked": false
                    }
                }
            ]
        });
        let camelized = camelize_json_keys(value);
        assert_eq!(camelized["scanId"], "scan-1");
        assert_eq!(camelized["entries"][0]["displayPath"], "/tmp/demo");
        assert_eq!(camelized["entries"][0]["logicalBytes"]["notChecked"], false);
    }

    #[cfg(unix)]
    #[test]
    fn state_dir_validation_rejects_symlink_and_relative_paths() {
        let temp = tempfile::TempDir::new().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            state_dir_from_explicit_or_default(Some(Path::new("relative"))),
            Err(StateError::NonAbsoluteStateDir(_))
        ));
        assert!(matches!(
            DurableSnapshotStore::new(&link),
            Err(StateError::SymlinkStateDir(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_store_hashes_filenames_and_writes_private_file() {
        let temp = tempfile::TempDir::new().unwrap();
        let store = DurableSnapshotStore::new(temp.path()).unwrap();
        let snapshot = OperationSnapshot {
            schema: SNAPSHOT_SCHEMA.to_string(),
            operation_id: "op_scan_123".to_string(),
            request_id: "req_scan_123".to_string(),
            command: "scan".to_string(),
            state: OperationState::Completed,
            status: OutputStatus::Ok,
            exit_code: 0,
            created_at: timestamp_now(),
            updated_at: timestamp_now(),
            locale: "en-US".to_string(),
            root_paths: vec!["/tmp/demo".to_string()],
            scan_id: Some("scan-1".to_string()),
            terminal_event_type: Some("operation.terminal".to_string()),
            entry_count: Some("1".to_string()),
            error_count: Some("0".to_string()),
            boundary_count: Some("0".to_string()),
            error: None,
        };
        store.save(&snapshot).unwrap();
        let operations_dir = temp.path().join("operations");
        let entry = fs::read_dir(&operations_dir)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert!(
            !entry
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap()
                .contains("op_scan_123")
        );
        let mode = fs::metadata(entry).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn scan_persists_then_loads_stale_preview_without_replacing_live_authority() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("large.bin"), vec![0u8; 4096]).unwrap();
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested").join("small.txt"), b"hello").unwrap();

        let context = CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let store = DurableSnapshotStore::new(temp.path()).unwrap();

        let first = scan_with_store(
            &context,
            &ScanRequest {
                roots: vec![root.clone()],
                state_dir: Some(temp.path().to_path_buf()),
            },
            Some(&store),
        )
        .unwrap();
        assert_eq!(first.output.summary["cachePreview"]["loadStatus"], "miss");
        assert_eq!(
            first.output.summary["cachePreview"]["storeStatus"],
            "written"
        );
        assert!(first.output.data.get("stalePreview").is_none());
        assert!(first.output.data.get("cachePreview").is_none());

        let second = scan_with_store(
            &context,
            &ScanRequest {
                roots: vec![root],
                state_dir: Some(temp.path().to_path_buf()),
            },
            Some(&store),
        )
        .unwrap();
        assert_eq!(
            second.output.summary["cachePreview"]["loadStatus"],
            "stale_preview"
        );
        assert_eq!(second.output.summary["mode"], "read_only");
        assert_eq!(
            second.output.summary["entryCount"],
            DecimalU128::new(second.summary.entries.len() as u128).to_string()
        );
        assert!(
            second.output.summary["cachePreview"]["staleParentCount"]
                .as_str()
                .is_some_and(|count| count != "0")
        );
        assert_eq!(
            second.output.data["entries"]
                .as_array()
                .map(|items| items.len())
                .unwrap_or_default(),
            second.summary.entries.len()
        );
        assert!(
            temp.path()
                .join(PREVIEW_GENERATION_POINTER_DIR)
                .join("current.json")
                .exists()
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn scan_quarantines_corrupt_preview_and_still_returns_live_scan() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("file.txt"), b"content").unwrap();

        let preview_dir = temp.path().join(PREVIEW_GENERATION_POINTER_DIR);
        fs::create_dir_all(preview_dir.join("generations")).unwrap();
        fs::write(
            preview_dir.join("current.json"),
            br#"{"generation":"bad_gen"}"#,
        )
        .unwrap();
        fs::write(preview_dir.join("generations/bad_gen.json"), b"{not-json").unwrap();

        let context = CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let store = DurableSnapshotStore::new(temp.path()).unwrap();
        let scan = scan_with_store(
            &context,
            &ScanRequest {
                roots: vec![root],
                state_dir: Some(temp.path().to_path_buf()),
            },
            Some(&store),
        )
        .unwrap();

        assert_eq!(
            scan.output.summary["cachePreview"]["loadStatus"],
            "quarantined"
        );
        assert!(
            scan.output
                .warnings
                .iter()
                .any(|warning| warning.code == "cache.preview.quarantined")
        );
        assert!(preview_dir.join("quarantine/bad_gen.corrupt.json").exists());
        assert!(
            scan.output.data["entries"]
                .as_array()
                .is_some_and(|entries| !entries.is_empty())
        );
        assert!(scan.output.data.get("stalePreview").is_none());
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn scan_rejects_symlinked_preview_cache_subtree() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("file.txt"), b"content").unwrap();
        let real = temp.path().join("real-preview");
        fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, temp.path().join(PREVIEW_GENERATION_POINTER_DIR))
            .unwrap();

        let context = CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let scan = scan_with_store(
            &context,
            &ScanRequest {
                roots: vec![root],
                state_dir: Some(temp.path().to_path_buf()),
            },
            Option::<&MemorySnapshotStore>::None,
        )
        .unwrap();

        assert_eq!(scan.output.summary["cachePreview"]["loadStatus"], "miss");
        assert_eq!(
            scan.output.summary["cachePreview"]["storeStatus"],
            "skipped"
        );
        assert!(scan.output.data.get("stalePreview").is_none());
        assert!(scan.output.data.get("cachePreview").is_none());
        assert!(
            scan.output.data["entries"]
                .as_array()
                .is_some_and(|entries| !entries.is_empty())
        );
    }

    #[test]
    fn fresh_operation_ids_are_unique() {
        let first = fresh_operation_ids("scan", &[]);
        let second = fresh_operation_ids("scan", &[]);
        assert_ne!(
            first.operation_id.to_string(),
            second.operation_id.to_string()
        );
    }

    #[test]
    fn capabilities_report_macos_and_windows_scan_and_tui_as_degraded() {
        let context = CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let output = capabilities(&context).unwrap().output;
        let capabilities = output.data["capabilities"]
            .as_array()
            .expect("capabilities array");

        let macos_scan = capabilities
            .iter()
            .find(|item| {
                item["qualificationKey"]["osFamily"] == "macos"
                    && item["qualificationKey"]["capability"] == "scan.local.directory"
            })
            .expect("macos scan capability");
        assert_eq!(macos_scan["state"], "degraded");
        assert_eq!(macos_scan["reasonCode"], "MACOS_SCANNER_DEVELOPMENT");

        let macos_tui = capabilities
            .iter()
            .find(|item| {
                item["qualificationKey"]["osFamily"] == "macos"
                    && item["qualificationKey"]["capability"] == "scan.tui.live"
            })
            .expect("macos tui capability");
        assert_eq!(macos_tui["state"], "degraded");
        assert_eq!(macos_tui["reasonCode"], "MACOS_LIVE_TUI_DEVELOPMENT");

        let windows_scan = capabilities
            .iter()
            .find(|item| {
                item["qualificationKey"]["osFamily"] == "windows"
                    && item["qualificationKey"]["capability"] == "scan.local.directory"
            })
            .expect("windows scan capability");
        assert_eq!(windows_scan["state"], "degraded");
        assert_eq!(windows_scan["reasonCode"], "WINDOWS_SCANNER_DEVELOPMENT");

        let windows_tui = capabilities
            .iter()
            .find(|item| {
                item["qualificationKey"]["osFamily"] == "windows"
                    && item["qualificationKey"]["capability"] == "scan.tui.live"
            })
            .expect("windows tui capability");
        assert_eq!(windows_tui["state"], "degraded");
        assert_eq!(windows_tui["reasonCode"], "WINDOWS_LIVE_TUI_DEVELOPMENT");

        let windows_snapshot = capabilities
            .iter()
            .find(|item| {
                item["qualificationKey"]["osFamily"] == "windows"
                    && item["qualificationKey"]["capability"] == "operation.snapshot.durable"
            })
            .expect("windows durable snapshot capability");
        assert_eq!(windows_snapshot["state"], "disabled");
        assert_eq!(
            windows_snapshot["reasonCode"],
            "WINDOWS_DURABLE_STATE_SECURITY_UNIMPLEMENTED"
        );
    }

    #[test]
    fn cleaner_ref_parser_accepts_plain_and_versioned_ids() {
        let plain = parse_cleaner_ref("org.sweepx.cargo-target").unwrap();
        assert_eq!(plain.0, "org.sweepx.cargo-target");
        assert_eq!(plain.1, None);

        let versioned = parse_cleaner_ref("org.sweepx.cargo-target@1.2.3").unwrap();
        assert_eq!(versioned.0, "org.sweepx.cargo-target");
        assert_eq!(versioned.1.as_deref(), Some("1.2.3"));
        assert!(parse_cleaner_ref("@1.2.3").is_err());
    }

    #[test]
    fn synthetic_cleaner_context_supports_rule_evaluation() {
        for cleaner in BUILT_INS {
            let package = cleaner.load().unwrap();
            for (_, rule) in &package.rules {
                let evaluation = evaluate_rule(rule, &synthetic_cleaner_context()).unwrap();
                assert!(matches!(
                    evaluation.fact_state,
                    sweepx_cleaner_vm::EvalState::Known(_) | sweepx_cleaner_vm::EvalState::Unknown
                ));
            }
        }
    }

    #[test]
    fn imported_scan_input_downgrades_live_provenance_and_forces_report_only_candidates() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("scan.json");
        fs::write(&path, sample_scan_json()).unwrap();

        let input = read_scan_input_from_path(&path, DEFAULT_ANALYSIS_INPUT_BYTES).unwrap();
        assert!(matches!(
            input.entries[0].provenance,
            FieldProvenance::StalePreview { .. }
        ));
        assert!(matches!(
            input.entries[0].coverage.provenance,
            FieldProvenance::StalePreview { .. }
        ));
        assert!(!input.entries[0].coverage.complete);
        assert!(
            input.entries[0]
                .coverage
                .incomplete_reasons
                .contains(&ReasonCode::NotRevalidated)
        );

        let summary = scan_summary_from_input(&input);
        let links = directory_links(&summary);
        let candidates = build_candidates_from_summary_with_links(&summary, &links, true).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].source_state,
            sweepx_analysis::CandidateSourceState::Stale
        );
        assert_ne!(
            candidates[0].eligibility.executable,
            sweepx_analysis::ExecutableEligibility::Executable
        );
        assert!(
            candidates[0]
                .eligibility
                .reasons
                .contains(&ReasonCode::NotRevalidated)
        );
    }

    #[test]
    fn cleaner_show_rejects_incompatible_builtin_with_compat_exit_code() {
        let context = CoreContext::new(LocaleResolution::new(
            Locale::EnUs,
            sweepx_i18n::LocaleSource::Default,
        ));
        let error = cleaner_show(
            &context,
            &CleanerShowRequest {
                cleaner_ref: "org.sweepx.cargo-target".to_string(),
            },
        )
        .expect_err("incompatible cleaner should fail");

        assert!(matches!(error, CoreError::CleanerCompat { .. }));
        assert_eq!(core_error_exit_code(&error), ExitCode::CleanerTrustOrCompat);
    }

    #[test]
    fn deterministic_cleaner_set_digest_is_stable() {
        let first = cleaner_set_digest().unwrap();
        let second = cleaner_set_digest().unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("sha256:"));
    }

    #[test]
    fn cleaner_set_digest_is_order_independent_for_same_catalog_and_trust() {
        let mut cleaners = load_builtin_cleaners().unwrap();
        let trust = legacy_builtin_catalog_trust().unwrap();
        let forward = cleaner_set_digest_with_trust(&cleaners, &trust).unwrap();
        cleaners.reverse();
        let reversed = cleaner_set_digest_with_trust(&cleaners, &trust).unwrap();
        assert_eq!(forward, reversed);
    }

    #[test]
    fn cleaner_set_digest_changes_when_catalog_trust_changes() {
        let cleaners = load_builtin_cleaners().unwrap();
        let legacy = legacy_builtin_catalog_trust().unwrap();
        let production = CleanerCatalogTrustResolution {
            source: CleanerCatalogTrustSource::ProductionSnapshot,
            snapshot_digest: Some("sha256:trust-snapshot".to_string()),
            epoch: Some(7),
            freshness: CleanerCatalogTrustFreshness::Current,
            disposition: CleanerCatalogTrustDisposition::Trusted,
        };
        let report_only = CleanerCatalogTrustResolution {
            source: CleanerCatalogTrustSource::ProductionSnapshot,
            snapshot_digest: Some("sha256:trust-snapshot".to_string()),
            epoch: Some(7),
            freshness: CleanerCatalogTrustFreshness::Stale,
            disposition: CleanerCatalogTrustDisposition::ReportOnly,
        };

        let legacy_digest = cleaner_set_digest_with_trust(&cleaners, &legacy).unwrap();
        let production_digest = cleaner_set_digest_with_trust(&cleaners, &production).unwrap();
        let report_only_digest = cleaner_set_digest_with_trust(&cleaners, &report_only).unwrap();

        assert_ne!(legacy_digest, production_digest);
        assert_ne!(production_digest, report_only_digest);
    }

    #[test]
    fn cleaner_set_digest_accepts_disabled_production_trust_shape() {
        let cleaners = load_builtin_cleaners().unwrap();
        let disabled = CleanerCatalogTrustResolution {
            source: CleanerCatalogTrustSource::ProductionSnapshot,
            snapshot_digest: Some("sha256:trust-disabled".to_string()),
            epoch: Some(9),
            freshness: CleanerCatalogTrustFreshness::Stale,
            disposition: CleanerCatalogTrustDisposition::Disabled,
        };
        let digest = cleaner_set_digest_with_trust(&cleaners, &disabled).unwrap();
        assert!(digest.starts_with("sha256:"));
    }

    #[test]
    fn cleaner_catalog_trust_error_maps_to_trust_or_compat_exit_code() {
        assert_eq!(
            core_error_exit_code(&CoreError::CleanerCatalogTrust(
                "trust snapshot invalid".to_string()
            )),
            ExitCode::CleanerTrustOrCompat
        );
    }

    #[test]
    fn directory_links_join_directory_entries_to_matching_aggregates() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("scan.json");
        fs::write(&path, sample_scan_json()).unwrap();
        let input = read_scan_input_from_path(&path, DEFAULT_ANALYSIS_INPUT_BYTES).unwrap();
        let summary = scan_summary_from_input(&input);
        let links = directory_links(&summary);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].entry.display_path, "/tmp/demo");
        assert_eq!(links[0].directory_identity, "scan-entry:v1:c2Nhbi0x:1");
        assert_eq!(links[0].expected_root_id, Some("scan-entry:v1:c2Nhbi0x:2"));
    }

    #[test]
    fn directory_links_skip_legacy_entries_without_identity() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("scan.json");
        let mut envelope: Value = serde_json::from_str(&sample_scan_json()).unwrap();
        envelope["data"]["entries"][0]
            .as_object_mut()
            .expect("entry object")
            .remove("identity");
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        let input = read_scan_input_from_path(&path, DEFAULT_ANALYSIS_INPUT_BYTES).unwrap();
        let summary = scan_summary_from_input(&input);
        let links = directory_links(&summary);
        assert!(links.is_empty());
    }

    #[test]
    fn directory_links_reject_cross_field_invalid_identity() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("scan.json");
        let mut envelope: Value = serde_json::from_str(&sample_scan_json()).unwrap();
        envelope["data"]["entries"][0]["identity"]["parentId"] = Value::Null;
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

        let input = read_scan_input_from_path(&path, DEFAULT_ANALYSIS_INPUT_BYTES).unwrap();
        let summary = scan_summary_from_input(&input);
        assert!(directory_links(&summary).is_empty());
    }

    fn sample_scan_json() -> String {
        serde_json::to_string(&json!({
            "schema": "sweepx.output/v1",
            "kind": "scan.result",
            "requestId": "req-1",
            "operationId": "op-1",
            "generatedAt": "2026-08-26T00:00:00Z",
            "status": "ok",
            "exitCode": 0,
            "compat": {
                "coreVersion": "0.1.0",
                "scannerSemanticsVersion": 1,
                "safetyPolicyVersion": 1,
                "platformAdapter": {
                    "id": "linux",
                    "version": "0.1.0"
                },
                "cleanerSetDigest": "sha256:test",
                "requiredFeatures": [],
                "extensions": []
            },
            "summary": {
                "scanId": "scan-1"
            },
            "data": {
                "scanId": "scan-1",
                "roots": [],
                "entries": [{
                    "scanId": "scan-1",
                    "identity": {
                        "entryId": "scan-entry:v1:c2Nhbi0x:1",
                        "scanRootId": "scan-entry:v1:c2Nhbi0x:2",
                        "parentId": "scan-entry:v1:c2Nhbi0x:2",
                        "platformFileIdentity": {
                            "state": "known",
                            "value": {
                                "device": "1",
                                "inode": "1"
                            }
                        },
                        "filesystemObjectDomainIdentity": {
                            "state": "known",
                            "value": {
                                "device": "1"
                            }
                        },
                        "volumeOrMountIdentity": {
                            "state": "known",
                            "value": {
                                "value": "1"
                            }
                        }
                    },
                    "displayPath": "/tmp/demo",
                    "nativeBasename": {
                        "kind": "unix_bytes_base64_url",
                        "value": "ZGVtbw"
                    },
                    "objectType": "directory",
                    "logicalBytes": {
                        "state": "known",
                        "value": "42"
                    },
                    "allocatedBytes": {
                        "state": "known",
                        "value": "42"
                    },
                    "reclaimableEstimate": {
                        "state": "known",
                        "value": "42"
                    },
                    "metadataFingerprint": "fp-1",
                    "coverage": {
                        "state": "complete",
                        "complete": true,
                        "incompleteReasons": [],
                        "detailsLost": false,
                        "provenance": {
                            "kind": "live_observation",
                            "observed_at": "2026-08-26T00:00:00Z",
                            "method": "native_api"
                        }
                    },
                    "provenance": {
                        "kind": "live_observation",
                        "observed_at": "2026-08-26T00:00:00Z",
                        "method": "native_api"
                    }
                }],
                "aggregates": [{
                    "scanId": "scan-1",
                    "scanEntryId": "scan-entry:v1:c2Nhbi0x:1",
                    "directoryIdentity": "scan-entry:v1:c2Nhbi0x:1",
                    "revision": "1",
                    "apparentLogicalBytes": {
                        "state": "known",
                        "value": "42"
                    },
                    "uniqueLogicalBytes": {
                        "state": "known",
                        "value": "42"
                    },
                    "filesystemReportedAllocatedBytes": {
                        "state": "known",
                        "value": "42"
                    },
                    "potentiallyReclaimableBytes": {
                        "state": "known",
                        "value": "42"
                    },
                    "directChildCount": {
                        "state": "known",
                        "value": "1"
                    },
                    "recursiveEntryCount": {
                        "state": "known",
                        "value": "1"
                    },
                    "coverage": {
                        "state": "complete",
                        "complete": true,
                        "incompleteReasons": [],
                        "detailsLost": false,
                        "provenance": {
                            "kind": "live_observation",
                            "observed_at": "2026-08-26T00:00:00Z",
                            "method": "native_api"
                        }
                    },
                    "arithmeticState": "exact"
                }],
                "boundaries": []
            },
            "warnings": [],
            "errors": []
        }))
        .unwrap()
    }
}
