use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sweepx_i18n::{Catalog, Locale, LocaleResolution, MessageArgs, MessageKey};
use sweepx_model::{CapabilityState, DecimalU128, OperationId, RequestId, ScanId};
use sweepx_platform::{BoundaryKind, CancellationToken, ScanRoot};
use sweepx_protocol::{
    CompatSnapshot, EventCheckpoint, EventEnvelope, EventPhase, EventType, ExitCode,
    OutputEnvelope, OutputKind, OutputStatus, PlatformAdapterCompat, ProtocolMessage,
};
use sweepx_scanner::{ProgressEvent, ScanError, ScanSummary, Scanner, ScannerOptions};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(target_os = "linux")]
use sweepx_scanner::HostPlatformScanner;

pub const CORE_VERSION: &str = "0.1.0";
pub const SCANNER_SEMANTICS_VERSION: u32 = 1;
pub const SAFETY_POLICY_VERSION: u32 = 1;
pub const CLEANER_SET_DIGEST: &str = "sha256:p1-read-only-no-cleaners";
pub const STREAM_ID_PREFIX: &str = "stream-p1";
const SNAPSHOT_SCHEMA: &str = "sweepx.operation-snapshot/v1";
const OPERATION_ID_MAX_LEN: usize = 128;

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

#[derive(Debug, Clone, PartialEq)]
pub struct ScanSuccess {
    pub output: OutputEnvelope,
    pub events: Vec<EventEnvelope>,
    pub snapshot: OperationSnapshot,
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
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("state directory must be absolute: {0}")]
    NonAbsoluteStateDir(PathBuf),
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
    match state_dir {
        Some(path) => Ok(Some(DurableSnapshotStore::new(path)?)),
        None => Ok(None),
    }
}

pub fn scan_with_store<S: SnapshotStore>(
    context: &CoreContext,
    request: &ScanRequest,
    store: Option<&S>,
) -> Result<ScanSuccess, CoreError> {
    if request.roots.is_empty() {
        return Err(CoreError::MissingRoots);
    }
    let roots: Vec<ScanRoot> = request
        .roots
        .iter()
        .map(|path| {
            if !path.is_absolute() {
                return Err(CoreError::NonAbsoluteRoot(path.clone()));
            }
            ScanRoot::new(path.clone()).map_err(|_| CoreError::NonAbsoluteRoot(path.clone()))
        })
        .collect::<Result<_, _>>()?;

    let ids = fresh_operation_ids("scan", &request.roots);
    let started_at = timestamp_now();
    let monotonic = Instant::now();

    #[cfg(not(target_os = "linux"))]
    {
        let output = unsupported_scan_output(context, &request.roots, &ids, &started_at);
        let snapshot = snapshot_from_output(&output, "scan", context.locale(), &request.roots);
        if let Some(store) = store {
            store.save(&snapshot)?;
        }
        let events = build_scan_events(
            &format!("{STREAM_ID_PREFIX}-{}", digest_hex(ids.operation_id_str())),
            &ids.operation_id,
            &output.compat,
            &request.roots,
            None,
            &output,
            &started_at,
            monotonic.elapsed(),
        );
        return Ok(ScanSuccess {
            output,
            events,
            snapshot,
        });
    }

    #[cfg(target_os = "linux")]
    {
        let scan_id = ScanId::new(format!(
            "scan-{}-{}",
            unix_timestamp_nanos(),
            &digest_hex(ids.operation_id_str())[..12]
        ));
        let compat = compat_snapshot("linux");
        let scanner = Scanner::new(
            HostPlatformScanner::new(),
            ScannerOptions {
                scan_id: scan_id.clone(),
                ..ScannerOptions::default()
            },
        );
        let cancel = CancellationToken::new();
        let summary = scanner.scan(&roots, &cancel)?;
        let finished_at = timestamp_now();
        let status = scan_status(&summary);

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
            "rootCount": DecimalU128::new(request.roots.len() as u128),
            "entryCount": DecimalU128::new(summary.entries.len() as u128),
            "aggregateCount": DecimalU128::new(summary.aggregates.len() as u128),
            "boundaryCount": DecimalU128::new(summary.boundaries.len() as u128),
            "errorCount": DecimalU128::new(scan_error_count(&summary)),
            "platform": "linux",
            "mode": "read_only"
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

        let snapshot = snapshot_from_output(&output, "scan", context.locale(), &request.roots);
        if let Some(store) = store {
            store.save(&snapshot)?;
        }

        let events = build_scan_events(
            &format!("{STREAM_ID_PREFIX}-{}", digest_hex(ids.operation_id_str())),
            &ids.operation_id,
            &compat,
            &request.roots,
            Some(&summary),
            &output,
            &started_at,
            monotonic.elapsed(),
        );

        Ok(ScanSuccess {
            output,
            events,
            snapshot,
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

pub fn capabilities(_context: &CoreContext) -> CapabilitiesSuccess {
    let ids = fresh_operation_ids("capabilities", &[]);
    let current_os = current_os_family();
    let mut output = OutputEnvelope::new(
        OutputKind::CapabilitiesResult,
        ids.request_id,
        ids.operation_id,
        timestamp_now(),
        OutputStatus::Partial,
        ExitCode::Partial,
        compat_snapshot(current_os),
    );
    let commands = vec![
        command_record(
            "scan",
            CapabilityState::Degraded,
            "LINUX_SCANNER_DEVELOPMENT",
        ),
        command_record(
            "status",
            CapabilityState::Qualified,
            "STATUS_SNAPSHOT_SUPPORTED",
        ),
        command_record(
            "cancel",
            CapabilityState::Disabled,
            "CANCEL_LIVE_REGISTRY_ABSENT",
        ),
        command_record(
            "capabilities",
            CapabilityState::Qualified,
            "CAPABILITIES_REPORT_SUPPORTED",
        ),
    ];
    let capabilities = vec![
        capability_record(
            "linux",
            "scan.local.directory",
            CapabilityState::Degraded,
            "LINUX_SCANNER_DEVELOPMENT",
        ),
        capability_record(
            "linux",
            "operation.cancel",
            CapabilityState::Disabled,
            "CANCEL_LIVE_REGISTRY_ABSENT",
        ),
        capability_record(
            "linux",
            "mutation.local.any",
            CapabilityState::Disabled,
            "MUTATION_UNAVAILABLE",
        ),
        capability_record(
            "macos",
            "scan.local.directory",
            CapabilityState::Unsupported,
            "STUB_COMPILATION_ONLY",
        ),
        capability_record(
            "windows",
            "scan.local.directory",
            CapabilityState::Unsupported,
            "STUB_COMPILATION_ONLY",
        ),
    ];
    output.summary = json!({
        "commandCount": DecimalU128::new(commands.len() as u128),
        "capabilityCount": DecimalU128::new(capabilities.len() as u128),
        "currentPlatform": current_os
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
    CapabilitiesSuccess { output }
}

pub fn render_human_output(context: &CoreContext, output: &OutputEnvelope) -> String {
    let catalog = Catalog::new(context.locale());
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
        capabilities: "scan, status, cancel, capabilities",
        detail: output
            .errors
            .first()
            .map(|item| item.code.as_str())
            .unwrap_or("ok"),
    };

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

#[cfg(not(target_os = "linux"))]
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

fn scan_status(summary: &ScanSummary) -> OutputStatus {
    if scan_error_count(summary) > 0 || scan_partial_boundary_count(summary) > 0 {
        OutputStatus::Partial
    } else {
        OutputStatus::Ok
    }
}

fn scan_error_count(summary: &ScanSummary) -> u128 {
    summary
        .progress
        .iter()
        .filter(|event| matches!(event, ProgressEvent::Error { .. }))
        .count() as u128
}

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

fn compat_snapshot(platform_adapter_id: &str) -> CompatSnapshot {
    CompatSnapshot {
        core_version: CORE_VERSION.to_string(),
        scanner_semantics_version: SCANNER_SEMANTICS_VERSION,
        safety_policy_version: SAFETY_POLICY_VERSION,
        platform_adapter: PlatformAdapterCompat {
            id: platform_adapter_id.to_string(),
            version: CORE_VERSION.to_string(),
        },
        cleaner_set_digest: CLEANER_SET_DIGEST.to_string(),
        required_features: Vec::new(),
        extensions: Vec::new(),
    }
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
    os_family: &str,
    capability: &str,
    state: CapabilityState,
    reason_code: &str,
) -> Value {
    json!({
        "schema": "sweepx.capability-record/v1",
        "recordedAt": timestamp_now(),
        "qualificationKey": {
            "coreVersion": CORE_VERSION,
            "scannerSemanticsVersion": SCANNER_SEMANTICS_VERSION,
            "safetyPolicyDigest": "sha256:p1-read-only-policy",
            "adapterId": os_family,
            "adapterDigest": format!("sha256:{}-adapter", os_family),
            "osFamily": os_family,
            "osBuild": "development",
            "arch": std::env::consts::ARCH,
            "filesystem": "local",
            "volumeClass": "local",
            "runtimePrivilegeProfile": "ordinary_user",
            "capability": capability
        },
        "state": capability_state_name(state),
        "reasonCode": reason_code,
        "reason": capability_reason(reason_code),
        "evidence": {
            "bundleDigest": format!("sha256:{}:{}:{}", os_family, capability, reason_code),
            "reviewedBy": ["p1-core-cli"],
            "limitations": [
                "read-only CLI only",
                "no destructive commands",
                "no background daemon"
            ],
            "invalidatesOn": [
                "platform-adapter-change",
                "policy-change",
                "future-mutation-implementation"
            ]
        }
    })
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
        "STUB_COMPILATION_ONLY" => {
            "Platform support is currently limited to stub compilation only."
        }
        "MUTATION_UNAVAILABLE" => {
            "Mutation commands and adapters are intentionally unavailable in P1."
        }
        "CANCEL_LIVE_REGISTRY_ABSENT" => {
            "Cancel is disabled because P1 does not maintain a live in-process operation registry."
        }
        "STATUS_SNAPSHOT_SUPPORTED" => "Status reads durable snapshots only.",
        "CAPABILITIES_REPORT_SUPPORTED" => "Capabilities reports the current read-only surface.",
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

fn default_state_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".local/state")))?;
    Some(base.join("sweepx"))
}

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

fn validate_or_prepare_state_dir(path: &Path) -> Result<(), StateError> {
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
    Ok(())
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
    Ok(())
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

    #[test]
    fn operation_id_validation_rejects_traversal_like_input() {
        assert!(ValidatedOperationId::parse("../etc/passwd").is_err());
        assert!(ValidatedOperationId::parse("op/123").is_err());
        assert!(ValidatedOperationId::parse("op:123").is_err());
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

    #[test]
    fn fresh_operation_ids_are_unique() {
        let first = fresh_operation_ids("scan", &[]);
        let second = fresh_operation_ids("scan", &[]);
        assert_ne!(
            first.operation_id.to_string(),
            second.operation_id.to_string()
        );
    }
}
