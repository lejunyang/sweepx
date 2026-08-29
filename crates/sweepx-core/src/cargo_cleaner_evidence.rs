//! Bounded, side-effect-free Cargo Z0 evidence decoding and classification.
//!
//! `Known` in this module means only that caller-provided parsing substrate was decoded or
//! classified without ambiguity. It is not filesystem admission or deletion authority. The
//! crate-private input has deliberately private fields and no production constructor: a future
//! handle-bound reader must construct it in this module before detector wiring is allowed. This
//! module never opens a path, expands an environment variable, starts a process, or produces a
//! cleanup candidate or plan.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sweepx_model::{
    ArithmeticState, CoverageState, FieldProvenance, IdentityEvidence, NativeName, ObjectType,
    ScanEntryId, ScannedEntry,
};
use sweepx_platform::{CancellationToken, PlatformScanner};
use sweepx_scanner::{
    CargoConfigMemberObservation, CargoConfigMemberPresenceObservation, CargoConfigPairConsistency,
    CargoConfigPairObservation, CargoConfigPairPresenceObservation, LocatorBatchReadRequest,
    LocatorDirectoryComparison, LocatorDirectoryComparisonFailure, LocatorDirectoryIdentity,
    LocatorFileRead, LocatorFileRequest, LocatorReadError, LocatorReadFailure, LocatorReadLimits,
    LocatorReader, ProgressEvent, ScanSummary,
};

const CARGO_WORKSPACE_EVIDENCE_SCHEMA: &str = "cargo.workspace.v1";
const CARGO_TARGET_DIR_EVIDENCE_SCHEMA: &str = "cargo.config.target-dir.v1";
const CARGO_CONFIG_SCOPE_EVIDENCE_SCHEMA: &str = "cargo.config-scope.v1";
const CARGO_WORKSPACE_TARGET_DIR_DECLARATION_SCHEMA: &str = "cargo.config.workspace-target-dir.v1";
const CARGO_TARGET_SHAPE_EVIDENCE_SCHEMA: &str = "cargo.target-shape.v1";
const CARGO_CONFIG_DECODER_ID: &str = "cargo-workspace-config-v1";
const MAX_CARGO_INPUT_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CARGO_INPUT_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_TARGET_DIR_BYTES: usize = 4096;
const MAX_TARGET_DIR_COMPONENTS: usize = 64;
const MAX_TARGET_DIR_COMPONENT_BYTES: usize = 255;

const DEFAULT_TARGET_COMPONENT: &str = "target";

pub(crate) const fn cargo_fixed_input_locator_limits() -> LocatorReadLimits {
    LocatorReadLimits {
        max_requests: 3,
        max_components_per_request: 3,
        max_total_components: 8,
        max_file_bytes: MAX_CARGO_INPUT_FILE_BYTES,
        max_total_bytes: MAX_CARGO_INPUT_TOTAL_BYTES,
        max_directory_entries: 4096,
        max_directory_bytes: 4 * 1024 * 1024,
        max_directory_batch_entries: 256,
        max_directory_batch_bytes: 256 * 1024,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum CargoEvidence<T> {
    Known { value: T },
    Unknown { reason: CargoEvidenceReason },
    NotChecked { reason: CargoEvidenceReason },
}

impl<T> CargoEvidence<T> {
    const fn state(&self) -> CargoEvidenceStateProjection {
        match self {
            Self::Known { .. } => CargoEvidenceStateProjection::Known,
            Self::Unknown { .. } => CargoEvidenceStateProjection::Unknown,
            Self::NotChecked { .. } => CargoEvidenceStateProjection::NotChecked,
        }
    }

    fn reason(&self) -> Option<CargoEvidenceReason> {
        match self {
            Self::Known { .. } => None,
            Self::Unknown { reason } | Self::NotChecked { reason } => Some(*reason),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CargoEvidenceStateProjection {
    Known,
    Unknown,
    NotChecked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum CargoEvidenceReason {
    ActivityNotChecked,
    AmbiguousConfig,
    BoundaryPresent,
    Cancelled,
    ConfigReadFailed,
    ConfigScopeNotChecked,
    DuplicateTomlKey,
    IncompleteScan,
    InvalidRelativeTargetDir,
    MalformedToml,
    MissingIdentity,
    MissingManifest,
    ManifestReadFailed,
    MissingTargetAggregate,
    MultipleTargetEntries,
    ResourceLimit,
    SharingNotChecked,
    TargetEntryMissing,
    UnexpectedTargetComponent,
    UnknownObjectType,
    UnsupportedConfigInclude,
    UnsupportedManifestShape,
}

impl CargoEvidenceReason {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::ActivityNotChecked => "activity_not_checked",
            Self::AmbiguousConfig => "ambiguous_config",
            Self::BoundaryPresent => "boundary_present",
            Self::Cancelled => "cancelled",
            Self::ConfigReadFailed => "config_read_failed",
            Self::ConfigScopeNotChecked => "config_scope_not_checked",
            Self::DuplicateTomlKey => "duplicate_toml_key",
            Self::IncompleteScan => "incomplete_scan",
            Self::InvalidRelativeTargetDir => "invalid_relative_target_dir",
            Self::MalformedToml => "malformed_toml",
            Self::MissingIdentity => "missing_identity",
            Self::MissingManifest => "missing_manifest",
            Self::ManifestReadFailed => "manifest_read_failed",
            Self::MissingTargetAggregate => "missing_target_aggregate",
            Self::MultipleTargetEntries => "multiple_target_entries",
            Self::ResourceLimit => "resource_limit",
            Self::SharingNotChecked => "sharing_not_checked",
            Self::TargetEntryMissing => "target_entry_missing",
            Self::UnexpectedTargetComponent => "unexpected_target_component",
            Self::UnknownObjectType => "unknown_object_type",
            Self::UnsupportedConfigInclude => "unsupported_config_include",
            Self::UnsupportedManifestShape => "unsupported_manifest_shape",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CargoManifestKind {
    VirtualWorkspace,
    WorkspacePackage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CargoWorkspaceEvidenceV1 {
    schema: &'static str,
    decoder_id: &'static str,
    workspace_id: String,
    root_entry_id: ScanEntryId,
    manifest_entry_id: ScanEntryId,
    manifest_kind: CargoManifestKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CargoTargetDirSource {
    Default,
    Config,
    ConfigToml,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CargoTargetDirEvidenceV1 {
    schema: &'static str,
    decoder_id: &'static str,
    relative_components: Vec<String>,
    relative_path: String,
    source: CargoTargetDirSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CargoTargetShape {
    RecognizedGeneratedStructure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CargoTargetShapeEvidenceV1 {
    schema: &'static str,
    target_entry_id: ScanEntryId,
    classification: CargoTargetShape,
    observed_top_level_components: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct CargoInputFile<'a> {
    name: &'static str,
    bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
enum CargoConfigFile<'a> {
    Present(&'a [u8]),
    VerifiedAbsent,
    NotChecked,
    ReadFailed(CargoEvidenceReason),
}

#[derive(Debug, Clone, Copy)]
enum CollectedCargoConfigFile<'a> {
    Present(&'a [u8]),
    AbsentDuringEnumeration,
    Failed(CargoEvidenceReason),
}

/// Redacted process-context observations captured by the caller. The decoder deliberately accepts
/// presence only: it cannot inspect, retain, or serialize an environment value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CargoConfigScopeRuntime {
    cargo_target_dir: CargoEnvironmentPresence,
    cargo_build_target_dir: CargoEnvironmentPresence,
    cargo_home: CargoEnvironmentPresence,
}

impl CargoConfigScopeRuntime {
    pub(crate) const fn from_presence(
        cargo_target_dir_present: bool,
        cargo_build_target_dir_present: bool,
        cargo_home_present: bool,
    ) -> Self {
        Self {
            cargo_target_dir: CargoEnvironmentPresence::from_present(cargo_target_dir_present),
            cargo_build_target_dir: CargoEnvironmentPresence::from_present(
                cargo_build_target_dir_present,
            ),
            cargo_home: CargoEnvironmentPresence::from_present(cargo_home_present),
        }
    }
}

/// Process invocation facts that are common to every layout considered by one detector call.
/// The SweepX CLI `cargo-detect` surface has no Cargo `--target-dir` or `--config` options, so that
/// frontend can attest those sources are structurally absent. The cwd path and object identity
/// are captured privately and never serialized. Because SweepX does not retain the process cwd
/// object itself, a successful comparison remains a path-match observation rather than an
/// authority binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CargoInvocationContext {
    runtime: CargoConfigScopeRuntime,
    cwd: Result<LocatorDirectoryIdentity, CargoEvidenceReason>,
    cargo_home_config: CargoHomeConfigCapture,
    cli_overrides_absent: bool,
}

impl CargoInvocationContext {
    pub(crate) fn capture_for_sweepx_cli<P: PlatformScanner>(
        runtime: CargoConfigScopeRuntime,
        explicit_cargo_home: Option<&std::ffi::OsStr>,
        reader: &LocatorReader<P>,
        cancel: &CancellationToken,
    ) -> Self {
        Self::capture(runtime, explicit_cargo_home, true, reader, cancel)
    }

    pub(crate) fn capture_for_unmodeled_caller<P: PlatformScanner>(
        runtime: CargoConfigScopeRuntime,
        explicit_cargo_home: Option<&std::ffi::OsStr>,
        reader: &LocatorReader<P>,
        cancel: &CancellationToken,
    ) -> Self {
        Self::capture(runtime, explicit_cargo_home, false, reader, cancel)
    }

    fn capture<P: PlatformScanner>(
        runtime: CargoConfigScopeRuntime,
        explicit_cargo_home: Option<&std::ffi::OsStr>,
        cli_overrides_absent: bool,
        reader: &LocatorReader<P>,
        cancel: &CancellationToken,
    ) -> Self {
        let cwd = std::env::current_dir()
            .map_err(|_| CargoEvidenceReason::MissingIdentity)
            .and_then(|path| capture_directory_identity(reader, &path, cancel));
        let cargo_home_config = match explicit_cargo_home {
            None => CargoHomeConfigCapture::NotChecked,
            Some(raw_path) => {
                let path = std::path::Path::new(raw_path);
                if !path.is_absolute() {
                    CargoHomeConfigCapture::Failed(CargoEvidenceReason::MissingIdentity)
                } else {
                    match capture_directory_identity(reader, path, cancel) {
                        Ok(identity) => CargoHomeConfigCapture::Captured(identity),
                        Err(reason) => CargoHomeConfigCapture::Failed(reason),
                    }
                }
            }
        };
        Self {
            runtime,
            cwd,
            cargo_home_config,
            cli_overrides_absent,
        }
    }

    #[cfg(test)]
    fn with_cwd_path<P: PlatformScanner>(
        runtime: CargoConfigScopeRuntime,
        cwd: &std::path::Path,
        cli_overrides_absent: bool,
        reader: &LocatorReader<P>,
    ) -> Self {
        Self {
            runtime,
            cwd: capture_directory_identity(reader, cwd, &CancellationToken::new()),
            cargo_home_config: CargoHomeConfigCapture::NotChecked,
            cli_overrides_absent,
        }
    }

    fn unavailable(runtime: CargoConfigScopeRuntime) -> Self {
        Self {
            runtime,
            cwd: Err(CargoEvidenceReason::MissingIdentity),
            cargo_home_config: CargoHomeConfigCapture::NotChecked,
            cli_overrides_absent: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn unavailable_for_sweepx_cli(runtime: CargoConfigScopeRuntime) -> Self {
        Self {
            runtime,
            cwd: Err(CargoEvidenceReason::MissingIdentity),
            cargo_home_config: CargoHomeConfigCapture::NotChecked,
            cli_overrides_absent: true,
        }
    }

    /// Resolves the captured explicit `CARGO_HOME` exactly once after the source scan.
    ///
    /// The directory identity is opaque outside the locator reader. Only this aggregate outcome
    /// is retained; the raw environment value is never serialized, and the presence-only reader
    /// never returns config bytes to Core.
    pub(crate) fn observe_cargo_home_config<P: PlatformScanner>(
        &mut self,
        reader: &LocatorReader<P>,
        cancel: &CancellationToken,
    ) {
        let CargoHomeConfigCapture::Captured(directory) = &self.cargo_home_config else {
            return;
        };
        self.cargo_home_config =
            match reader.observe_cargo_config_pair_in_captured_directory(directory, cancel) {
                Ok(pair) => cargo_config_pair_presence(&pair),
                Err(error) => CargoHomeConfigCapture::Failed(map_locator_batch_error(error)),
            };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CargoHomeConfigCapture {
    /// No explicit `CARGO_HOME` was present at invocation capture time.
    NotChecked,
    /// An explicit absolute directory was captured before the scan and awaits observation.
    Captured(LocatorDirectoryIdentity),
    /// At least one direct config name was observed. No file contents were read.
    PresentRedacted,
    /// The explicit path was invalid, capture failed, or post-scan observation failed.
    Failed(CargoEvidenceReason),
}

impl CargoHomeConfigCapture {
    const fn external_source_input(&self) -> CargoConfigExternalSourceInput {
        match self {
            Self::NotChecked | Self::Captured(_) => CargoConfigExternalSourceInput::NotChecked,
            Self::PresentRedacted => CargoConfigExternalSourceInput::PresentRedacted,
            Self::Failed(reason) => CargoConfigExternalSourceInput::Failed(*reason),
        }
    }
}

fn capture_directory_identity<P: PlatformScanner>(
    reader: &LocatorReader<P>,
    path: &std::path::Path,
    cancel: &CancellationToken,
) -> Result<LocatorDirectoryIdentity, CargoEvidenceReason> {
    reader
        .capture_directory_identity(path, cancel)
        .map_err(map_locator_batch_error)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CargoEnvironmentPresence {
    PresentRedacted,
    VerifiedAbsent,
}

impl CargoEnvironmentPresence {
    const fn from_present(present: bool) -> Self {
        if present {
            Self::PresentRedacted
        } else {
            Self::VerifiedAbsent
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum CargoConfigExternalSourceInput {
    VerifiedAbsent,
    PresentRedacted,
    NotChecked,
    Failed(CargoEvidenceReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum CargoInvocationCwdInput {
    BoundToWorkspaceRoot,
    PathMatchesRevalidatedWorkspaceRoot,
    NotChecked,
    Failed(CargoEvidenceReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CargoWorkspacePairInput {
    StableSnapshot,
    NotChecked,
    Failed(CargoEvidenceReason),
}

#[derive(Debug, Clone, Copy)]
struct CargoConfigScopeInputs {
    runtime: CargoConfigScopeRuntime,
    workspace_pair: CargoWorkspacePairInput,
    ancestor_configs: CargoConfigExternalSourceInput,
    cargo_home_config: CargoConfigExternalSourceInput,
    cli_target_dir: CargoConfigExternalSourceInput,
    cli_config_overrides: CargoConfigExternalSourceInput,
    invocation_cwd: CargoInvocationCwdInput,
}

impl CargoConfigScopeInputs {
    fn production(invocation: &CargoInvocationContext) -> Self {
        let cli_source = if invocation.cli_overrides_absent {
            CargoConfigExternalSourceInput::VerifiedAbsent
        } else {
            CargoConfigExternalSourceInput::NotChecked
        };
        Self {
            runtime: invocation.runtime,
            workspace_pair: CargoWorkspacePairInput::NotChecked,
            ancestor_configs: CargoConfigExternalSourceInput::NotChecked,
            cargo_home_config: invocation.cargo_home_config.external_source_input(),
            cli_target_dir: cli_source,
            cli_config_overrides: cli_source,
            invocation_cwd: CargoInvocationCwdInput::NotChecked,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CargoConfigInputs<'a> {
    config: CargoConfigFile<'a>,
    config_toml: CargoConfigFile<'a>,
    scope: CargoConfigScopeInputs,
}

impl Default for CargoConfigInputs<'_> {
    fn default() -> Self {
        Self {
            config: CargoConfigFile::NotChecked,
            config_toml: CargoConfigFile::NotChecked,
            scope: CargoConfigScopeInputs::production(&CargoInvocationContext::unavailable(
                CargoConfigScopeRuntime::from_presence(false, false, false),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum CargoConfigFileState {
    Present,
    VerifiedAbsent,
    NotChecked { reason_code: CargoEvidenceReason },
    Failed { reason_code: CargoEvidenceReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CargoWorkspaceConfigSelection {
    Config,
    ConfigToml,
    None,
    NotChecked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum CargoWorkspacePairState {
    StableSnapshot,
    NotChecked { reason_code: CargoEvidenceReason },
    Failed { reason_code: CargoEvidenceReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CargoWorkspaceTargetDirDeclarationV1 {
    schema: &'static str,
    decoder_id: &'static str,
    relative_components: Vec<String>,
    relative_path: String,
    source: CargoTargetDirSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum CargoWorkspaceTargetDirDeclaration {
    Known {
        value: CargoWorkspaceTargetDirDeclarationV1,
    },
    VerifiedAbsent,
    NotChecked {
        reason_code: CargoEvidenceReason,
    },
    Unknown {
        reason_code: CargoEvidenceReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CargoWorkspaceConfigScopeEvidence {
    pair_snapshot: CargoWorkspacePairState,
    config: CargoConfigFileState,
    config_toml: CargoConfigFileState,
    selected: CargoWorkspaceConfigSelection,
    target_dir_declaration: CargoWorkspaceTargetDirDeclaration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CargoWorkspaceConfigScopeProjection {
    pair_snapshot: CargoWorkspacePairState,
    config: CargoConfigFileState,
    config_toml: CargoConfigFileState,
    selected: CargoWorkspaceConfigSelection,
    target_dir_declaration: CargoWorkspaceTargetDirDeclarationProjection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum CargoWorkspaceTargetDirDeclarationProjection {
    Known {
        source: CargoTargetDirSource,
        value_redacted: bool,
    },
    VerifiedAbsent,
    NotChecked {
        reason_code: CargoEvidenceReason,
    },
    Unknown {
        reason_code: CargoEvidenceReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum CargoConfigExternalSourceState {
    VerifiedAbsent,
    PresentRedacted,
    NotChecked { reason_code: CargoEvidenceReason },
    Failed { reason_code: CargoEvidenceReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CargoEnvironmentVariableEvidence {
    name: &'static str,
    state: CargoEnvironmentPresence,
    value_redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CargoConfigEnvironmentEvidence {
    cargo_target_dir: CargoEnvironmentVariableEvidence,
    cargo_build_target_dir: CargoEnvironmentVariableEvidence,
    cargo_home: CargoEnvironmentVariableEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CargoConfigCliEvidence {
    target_dir: CargoConfigExternalSourceState,
    config_overrides: CargoConfigExternalSourceState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum CargoInvocationCwdBinding {
    BoundToWorkspaceRoot,
    PathMatchesRevalidatedWorkspaceRoot,
    NotChecked { reason_code: CargoEvidenceReason },
    Failed { reason_code: CargoEvidenceReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum CargoConfigScopeBlocker {
    AncestorConfigsFailed,
    AncestorConfigsNotChecked,
    AncestorConfigsPresentRedacted,
    CargoBuildTargetDirPresentRedacted,
    CargoHomeConfigFailed,
    CargoHomeConfigNotChecked,
    CargoHomeConfigPresentRedacted,
    CargoHomePresentRedacted,
    CargoTargetDirPresentRedacted,
    CliConfigOverridesFailed,
    CliConfigOverridesNotChecked,
    CliTargetDirFailed,
    CliTargetDirNotChecked,
    InvocationCwdBindingFailed,
    InvocationCwdIdentityNotBound,
    InvocationCwdNotBound,
    WorkspaceConfigDuplicateKey,
    WorkspaceConfigIncludeUnsupported,
    WorkspaceConfigMalformed,
    WorkspaceConfigNotChecked,
    WorkspaceConfigPairFailed,
    WorkspaceConfigPairNotStable,
    WorkspaceConfigReadFailed,
    WorkspaceConfigResourceLimit,
    WorkspaceConfigShapeUnsupported,
    WorkspaceTargetDirInvalid,
}

impl CargoConfigScopeBlocker {
    const fn code(self) -> &'static str {
        match self {
            Self::AncestorConfigsFailed => "ancestor_configs_failed",
            Self::AncestorConfigsNotChecked => "ancestor_configs_not_checked",
            Self::AncestorConfigsPresentRedacted => "ancestor_configs_present_redacted",
            Self::CargoBuildTargetDirPresentRedacted => "cargo_build_target_dir_present_redacted",
            Self::CargoHomeConfigFailed => "cargo_home_config_failed",
            Self::CargoHomeConfigNotChecked => "cargo_home_config_not_checked",
            Self::CargoHomeConfigPresentRedacted => "cargo_home_config_present_redacted",
            Self::CargoHomePresentRedacted => "cargo_home_present_redacted",
            Self::CargoTargetDirPresentRedacted => "cargo_target_dir_present_redacted",
            Self::CliConfigOverridesFailed => "cli_config_overrides_failed",
            Self::CliConfigOverridesNotChecked => "cli_config_overrides_not_checked",
            Self::CliTargetDirFailed => "cli_target_dir_failed",
            Self::CliTargetDirNotChecked => "cli_target_dir_not_checked",
            Self::InvocationCwdBindingFailed => "invocation_cwd_binding_failed",
            Self::InvocationCwdIdentityNotBound => "invocation_cwd_identity_not_bound",
            Self::InvocationCwdNotBound => "invocation_cwd_not_bound",
            Self::WorkspaceConfigDuplicateKey => "workspace_config_duplicate_key",
            Self::WorkspaceConfigIncludeUnsupported => "workspace_config_include_unsupported",
            Self::WorkspaceConfigMalformed => "workspace_config_malformed",
            Self::WorkspaceConfigNotChecked => "workspace_config_not_checked",
            Self::WorkspaceConfigPairFailed => "workspace_config_pair_failed",
            Self::WorkspaceConfigPairNotStable => "workspace_config_pair_not_stable",
            Self::WorkspaceConfigReadFailed => "workspace_config_read_failed",
            Self::WorkspaceConfigResourceLimit => "workspace_config_resource_limit",
            Self::WorkspaceConfigShapeUnsupported => "workspace_config_shape_unsupported",
            Self::WorkspaceTargetDirInvalid => "workspace_target_dir_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CargoConfigScopeEvidenceV1 {
    schema: &'static str,
    decoder_id: &'static str,
    workspace: CargoWorkspaceConfigScopeEvidence,
    ancestor_configs: CargoConfigExternalSourceState,
    cargo_home_config: CargoConfigExternalSourceState,
    environment: CargoConfigEnvironmentEvidence,
    cli: CargoConfigCliEvidence,
    invocation_cwd: CargoInvocationCwdBinding,
    precedence_complete: bool,
    blockers: Vec<CargoConfigScopeBlocker>,
}

impl CargoConfigScopeEvidenceV1 {
    pub(crate) fn projected(&self) -> CargoConfigScopeProjectionV1 {
        let pair_is_stable = matches!(
            self.workspace.pair_snapshot,
            CargoWorkspacePairState::StableSnapshot
        );
        let project_file = |state: &CargoConfigFileState| match (pair_is_stable, state) {
            (false, CargoConfigFileState::VerifiedAbsent) => CargoConfigFileState::NotChecked {
                reason_code: CargoEvidenceReason::ConfigScopeNotChecked,
            },
            _ => state.clone(),
        };
        CargoConfigScopeProjectionV1 {
            schema: self.schema,
            decoder_id: self.decoder_id,
            workspace: CargoWorkspaceConfigScopeProjection {
                pair_snapshot: self.workspace.pair_snapshot.clone(),
                config: project_file(&self.workspace.config),
                config_toml: project_file(&self.workspace.config_toml),
                selected: self.workspace.selected,
                target_dir_declaration: match &self.workspace.target_dir_declaration {
                    CargoWorkspaceTargetDirDeclaration::Known { value } => {
                        CargoWorkspaceTargetDirDeclarationProjection::Known {
                            source: value.source,
                            value_redacted: true,
                        }
                    }
                    CargoWorkspaceTargetDirDeclaration::VerifiedAbsent => {
                        CargoWorkspaceTargetDirDeclarationProjection::VerifiedAbsent
                    }
                    CargoWorkspaceTargetDirDeclaration::NotChecked { reason_code } => {
                        CargoWorkspaceTargetDirDeclarationProjection::NotChecked {
                            reason_code: *reason_code,
                        }
                    }
                    CargoWorkspaceTargetDirDeclaration::Unknown { reason_code } => {
                        CargoWorkspaceTargetDirDeclarationProjection::Unknown {
                            reason_code: *reason_code,
                        }
                    }
                },
            },
            ancestor_configs: self.ancestor_configs.clone(),
            cargo_home_config: self.cargo_home_config.clone(),
            environment: self.environment.clone(),
            cli: self.cli.clone(),
            invocation_cwd: self.invocation_cwd.clone(),
            precedence_complete: self.precedence_complete,
            blockers: self
                .blockers
                .iter()
                .copied()
                .map(CargoConfigScopeBlocker::code)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CargoConfigScopeProjectionV1 {
    schema: &'static str,
    decoder_id: &'static str,
    workspace: CargoWorkspaceConfigScopeProjection,
    ancestor_configs: CargoConfigExternalSourceState,
    cargo_home_config: CargoConfigExternalSourceState,
    environment: CargoConfigEnvironmentEvidence,
    cli: CargoConfigCliEvidence,
    invocation_cwd: CargoInvocationCwdBinding,
    precedence_complete: bool,
    blockers: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CargoTypedEvidenceV1 {
    workspace: CargoEvidence<CargoWorkspaceEvidenceV1>,
    config_scope: CargoConfigScopeEvidenceV1,
    target_dir: CargoEvidence<CargoTargetDirEvidenceV1>,
    target_shape: CargoEvidence<CargoTargetShapeEvidenceV1>,
    not_shared: CargoEvidence<()>,
    activity: CargoEvidence<()>,
}

impl CargoTypedEvidenceV1 {
    pub(crate) const fn candidate_allowed(&self) -> bool {
        false
    }

    pub(crate) const fn plan_allowed(&self) -> bool {
        false
    }

    pub(crate) const fn workspace_state(&self) -> CargoEvidenceStateProjection {
        self.workspace.state()
    }

    pub(crate) fn workspace_reason_code(&self) -> Option<&'static str> {
        self.workspace.reason().map(CargoEvidenceReason::code)
    }

    pub(crate) fn workspace_id(&self) -> Option<&str> {
        match &self.workspace {
            CargoEvidence::Known { value } => Some(value.workspace_id.as_str()),
            CargoEvidence::Unknown { .. } | CargoEvidence::NotChecked { .. } => None,
        }
    }

    pub(crate) fn config_scope_projection(&self) -> CargoConfigScopeProjectionV1 {
        self.config_scope.projected()
    }

    pub(crate) const fn target_dir_state(&self) -> CargoEvidenceStateProjection {
        self.target_dir.state()
    }

    pub(crate) fn target_dir_reason_code(&self) -> Option<&'static str> {
        self.target_dir.reason().map(CargoEvidenceReason::code)
    }

    pub(crate) fn target_dir_relative_path(&self) -> Option<&str> {
        match &self.target_dir {
            CargoEvidence::Known { value } => Some(value.relative_path.as_str()),
            CargoEvidence::Unknown { .. } | CargoEvidence::NotChecked { .. } => None,
        }
    }

    pub(crate) const fn target_shape_state(&self) -> CargoEvidenceStateProjection {
        self.target_shape.state()
    }

    pub(crate) fn target_shape_reason_code(&self) -> Option<&'static str> {
        self.target_shape.reason().map(CargoEvidenceReason::code)
    }

    pub(crate) fn target_shape_classification(&self) -> Option<&'static str> {
        match &self.target_shape {
            CargoEvidence::Known { value } => Some(match value.classification {
                CargoTargetShape::RecognizedGeneratedStructure => "recognized_generated_structure",
            }),
            CargoEvidence::Unknown { .. } | CargoEvidence::NotChecked { .. } => None,
        }
    }

    pub(crate) const fn not_shared_state(&self) -> CargoEvidenceStateProjection {
        self.not_shared.state()
    }

    pub(crate) fn not_shared_reason_code(&self) -> Option<&'static str> {
        self.not_shared.reason().map(CargoEvidenceReason::code)
    }

    pub(crate) const fn activity_state(&self) -> CargoEvidenceStateProjection {
        self.activity.state()
    }

    pub(crate) fn activity_reason_code(&self) -> Option<&'static str> {
        self.activity.reason().map(CargoEvidenceReason::code)
    }
}

/// Constructed only after the handle-bound collector reopens the admitted scan identities. Private
/// fields prevent another crate module from pairing arbitrary bytes with trusted scan identities.
pub(crate) struct HandleBoundCargoInputs<'a> {
    root_entry_id: &'a ScanEntryId,
    manifest_entry_id: &'a ScanEntryId,
    manifest_bytes: &'a [u8],
    config_inputs: CargoConfigInputs<'a>,
    target_entry_id: &'a ScanEntryId,
}

/// Produces decoded substrate only. Sharing and activity remain explicitly unchecked, and this
/// result never authorizes a Candidate or Plan.
pub(crate) fn produce_cargo_typed_evidence(
    input: HandleBoundCargoInputs<'_>,
    summary: &ScanSummary,
) -> CargoTypedEvidenceV1 {
    if !summary_identity_graph_is_unique_and_complete(summary) {
        return CargoTypedEvidenceV1 {
            workspace: unknown(CargoEvidenceReason::MissingIdentity),
            config_scope: decode_config_scope(input.config_inputs),
            target_dir: unknown(CargoEvidenceReason::MissingIdentity),
            target_shape: unknown(CargoEvidenceReason::MissingIdentity),
            not_shared: CargoEvidence::NotChecked {
                reason: CargoEvidenceReason::SharingNotChecked,
            },
            activity: CargoEvidence::NotChecked {
                reason: CargoEvidenceReason::ActivityNotChecked,
            },
        };
    }
    let mut files = vec![CargoInputFile {
        name: "Cargo.toml",
        bytes: input.manifest_bytes,
    }];
    if let CargoConfigFile::Present(bytes) = input.config_inputs.config {
        files.push(CargoInputFile {
            name: ".cargo/config",
            bytes,
        });
    }
    if let CargoConfigFile::Present(bytes) = input.config_inputs.config_toml {
        files.push(CargoInputFile {
            name: ".cargo/config.toml",
            bytes,
        });
    }
    let budget = validate_input_budget(files);
    let (workspace, mut config_scope) = match budget {
        Ok(()) => (
            decode_bound_workspace_manifest(
                summary,
                input.root_entry_id,
                input.manifest_entry_id,
                input.manifest_bytes,
            ),
            decode_config_scope(input.config_inputs),
        ),
        Err(reason) => (
            unknown(reason),
            config_scope_for_input_failure(input.config_inputs, reason),
        ),
    };
    normalize_config_scope(&mut config_scope);
    // This milestone records a workspace declaration, but deliberately does not claim an effective
    // target directory until every precedence source and the invocation cwd are bound. Production
    // collection always leaves those sources unresolved.
    let target_dir = if let CargoWorkspaceTargetDirDeclaration::Unknown { reason_code } =
        config_scope.workspace.target_dir_declaration
    {
        unknown(
            if reason_code == CargoEvidenceReason::UnsupportedConfigInclude {
                // Preserve the existing v1 targetDir reason while the additive scope ledger exposes
                // the more precise include-specific blocker.
                CargoEvidenceReason::UnsupportedManifestShape
            } else {
                reason_code
            },
        )
    } else if !matches!(
        config_scope.workspace.pair_snapshot,
        CargoWorkspacePairState::StableSnapshot
    ) {
        CargoEvidence::NotChecked {
            reason: CargoEvidenceReason::ConfigScopeNotChecked,
        }
    } else if matches!(
        (input.config_inputs.config, input.config_inputs.config_toml),
        (CargoConfigFile::Present(_), CargoConfigFile::Present(_))
    ) {
        // Preserve the already-published conservative v1 reason for dual config names. The scope
        // ledger records Cargo's selected extensionless file, but effective resolution remains
        // intentionally unavailable until the invocation context and all higher sources are bound.
        unknown(CargoEvidenceReason::AmbiguousConfig)
    } else if config_scope.precedence_complete {
        decode_effective_target_dir(input.config_inputs, &config_scope)
    } else {
        CargoEvidence::NotChecked {
            reason: CargoEvidenceReason::ConfigScopeNotChecked,
        }
    };
    let target_shape = match (&workspace, &target_dir) {
        (CargoEvidence::Known { value: workspace }, CargoEvidence::Known { value: target_dir }) => {
            classify_bound_target_shape(summary, workspace, target_dir, input.target_entry_id)
        }
        (CargoEvidence::Unknown { reason }, _)
        | (CargoEvidence::NotChecked { reason }, _)
        | (_, CargoEvidence::Unknown { reason })
        | (_, CargoEvidence::NotChecked { reason }) => unknown(*reason),
    };
    CargoTypedEvidenceV1 {
        workspace,
        config_scope,
        target_dir,
        target_shape,
        not_shared: CargoEvidence::NotChecked {
            reason: CargoEvidenceReason::SharingNotChecked,
        },
        activity: CargoEvidence::NotChecked {
            reason: CargoEvidenceReason::ActivityNotChecked,
        },
    }
}

pub(crate) fn collect_and_produce_cargo_typed_evidence<P: PlatformScanner>(
    reader: &LocatorReader<P>,
    summary: &ScanSummary,
    root_entry_id: &ScanEntryId,
    manifest_entry_id: &ScanEntryId,
    target_entry_id: &ScanEntryId,
    invocation: &CargoInvocationContext,
    cancel: &CancellationToken,
) -> CargoTypedEvidenceV1 {
    if !summary_identity_graph_is_unique_and_complete(summary) {
        return fail_closed_cargo_evidence(
            CargoEvidenceReason::MissingIdentity,
            CargoEvidenceReason::MissingIdentity,
            invocation,
        );
    }
    let Some(root) = unique_root_entry(summary, root_entry_id) else {
        return fail_closed_cargo_evidence(
            CargoEvidenceReason::MissingIdentity,
            CargoEvidenceReason::MissingIdentity,
            invocation,
        );
    };
    let Some(manifest) = unique_summary_entry(summary, manifest_entry_id) else {
        return fail_closed_cargo_evidence(
            CargoEvidenceReason::MissingIdentity,
            CargoEvidenceReason::MissingIdentity,
            invocation,
        );
    };
    if unique_summary_entry(summary, target_entry_id).is_none() {
        return fail_closed_cargo_evidence(
            CargoEvidenceReason::MissingIdentity,
            CargoEvidenceReason::MissingIdentity,
            invocation,
        );
    }

    let requests = [LocatorFileRequest::ScannedFile { entry: manifest }];
    let batch = match reader.read_batch(
        LocatorBatchReadRequest {
            base_directory: root,
            files: &requests,
        },
        cancel,
    ) {
        Ok(batch) => batch,
        Err(error) => {
            let reason = map_locator_batch_error(error);
            return fail_closed_cargo_evidence(reason, reason, invocation);
        }
    };

    let manifest_read = batch.files.first().expect("manifest request is present");
    let manifest_bytes = match manifest_read {
        LocatorFileRead::Present(read) => read.bytes.as_slice(),
        LocatorFileRead::VerifiedAbsent => {
            return fail_closed_cargo_evidence(
                CargoEvidenceReason::MissingManifest,
                CargoEvidenceReason::MissingManifest,
                invocation,
            );
        }
        LocatorFileRead::Failed(failure) => {
            let reason = map_manifest_read_failure(failure);
            return fail_closed_cargo_evidence(reason, reason, invocation);
        }
    };
    let invocation_cwd = match &invocation.cwd {
        Ok(cwd) => match reader.compare_base_directory_snapshot(root, cwd, cancel) {
            Ok(LocatorDirectoryComparison::PathAndIdentityMatch) => {
                CargoInvocationCwdInput::PathMatchesRevalidatedWorkspaceRoot
            }
            Ok(LocatorDirectoryComparison::DifferentNativePath) => {
                CargoInvocationCwdInput::NotChecked
            }
            Ok(LocatorDirectoryComparison::Failed(
                LocatorDirectoryComparisonFailure::Cancelled,
            ))
            | Err(LocatorReadError::Cancelled) => {
                CargoInvocationCwdInput::Failed(CargoEvidenceReason::Cancelled)
            }
            Ok(LocatorDirectoryComparison::Failed(
                LocatorDirectoryComparisonFailure::ResourceLimit,
            ))
            | Err(LocatorReadError::ResourceLimit) => {
                CargoInvocationCwdInput::Failed(CargoEvidenceReason::ResourceLimit)
            }
            Ok(LocatorDirectoryComparison::Failed(
                LocatorDirectoryComparisonFailure::RevalidationFailed,
            ))
            | Err(LocatorReadError::InvalidRequest) => {
                CargoInvocationCwdInput::Failed(CargoEvidenceReason::MissingIdentity)
            }
        },
        Err(reason) => CargoInvocationCwdInput::Failed(*reason),
    };
    let config_pair = match reader.observe_cargo_config_pair(root, cancel) {
        Ok(observed) => observed,
        Err(error) => {
            let reason = map_locator_batch_error(error);
            return fail_closed_cargo_evidence_with_cwd(reason, reason, invocation, invocation_cwd);
        }
    };
    let collected_config = map_config_pair_member_read(&config_pair.config);
    let collected_config_toml = map_config_pair_member_read(&config_pair.config_toml);
    let config_failure_reason = [collected_config, collected_config_toml]
        .into_iter()
        .filter_map(|config| match config {
            CollectedCargoConfigFile::Failed(reason) => Some(reason),
            CollectedCargoConfigFile::Present(_)
            | CollectedCargoConfigFile::AbsentDuringEnumeration => None,
        })
        .min_by_key(|reason| cargo_config_failure_precedence(*reason));
    let pair_failure_reason = config_failure_reason.filter(|reason| {
        matches!(
            reason,
            CargoEvidenceReason::AmbiguousConfig
                | CargoEvidenceReason::Cancelled
                | CargoEvidenceReason::ResourceLimit
                | CargoEvidenceReason::ConfigReadFailed
        )
    });
    let input = HandleBoundCargoInputs {
        root_entry_id,
        manifest_entry_id,
        manifest_bytes,
        config_inputs: CargoConfigInputs {
            config: collected_config.into_decode_input(),
            config_toml: collected_config_toml.into_decode_input(),
            scope: cargo_config_scope_inputs(
                invocation,
                cargo_workspace_pair_input(&config_pair, pair_failure_reason),
                invocation_cwd,
            ),
        },
        target_entry_id,
    };
    let mut evidence = produce_cargo_typed_evidence(input, summary);
    if let Some(reason) = config_failure_reason {
        evidence.target_dir = unknown(reason);
        evidence.target_shape = unknown(reason);
    }
    evidence
}

fn fail_closed_cargo_evidence(
    workspace_reason: CargoEvidenceReason,
    target_reason: CargoEvidenceReason,
    invocation: &CargoInvocationContext,
) -> CargoTypedEvidenceV1 {
    let invocation_cwd = match invocation.cwd {
        Ok(_) => CargoInvocationCwdInput::NotChecked,
        Err(reason) => CargoInvocationCwdInput::Failed(reason),
    };
    fail_closed_cargo_evidence_with_cwd(workspace_reason, target_reason, invocation, invocation_cwd)
}

fn fail_closed_cargo_evidence_with_cwd(
    workspace_reason: CargoEvidenceReason,
    target_reason: CargoEvidenceReason,
    invocation: &CargoInvocationContext,
    invocation_cwd: CargoInvocationCwdInput,
) -> CargoTypedEvidenceV1 {
    CargoTypedEvidenceV1 {
        workspace: unknown(workspace_reason),
        config_scope: config_scope_for_failure(target_reason, invocation, invocation_cwd),
        target_dir: unknown(target_reason),
        target_shape: unknown(match target_reason {
            CargoEvidenceReason::ConfigScopeNotChecked => workspace_reason,
            other => other,
        }),
        not_shared: CargoEvidence::NotChecked {
            reason: CargoEvidenceReason::SharingNotChecked,
        },
        activity: CargoEvidence::NotChecked {
            reason: CargoEvidenceReason::ActivityNotChecked,
        },
    }
}

fn unique_root_entry<'a>(
    summary: &'a ScanSummary,
    entry_id: &ScanEntryId,
) -> Option<&'a ScannedEntry> {
    unique_entry(summary.roots.iter(), entry_id)
}

fn unique_summary_entry<'a>(
    summary: &'a ScanSummary,
    entry_id: &ScanEntryId,
) -> Option<&'a ScannedEntry> {
    unique_entry(summary.roots.iter().chain(summary.entries.iter()), entry_id)
}

fn unique_entry<'a>(
    entries: impl IntoIterator<Item = &'a ScannedEntry>,
    entry_id: &ScanEntryId,
) -> Option<&'a ScannedEntry> {
    let mut matches = entries.into_iter().filter(|entry| {
        entry
            .identity
            .as_ref()
            .is_some_and(|identity| &identity.entry_id == entry_id)
    });
    let entry = matches.next()?;
    if matches.next().is_some() {
        None
    } else {
        Some(entry)
    }
}

fn map_locator_batch_error(error: LocatorReadError) -> CargoEvidenceReason {
    match error {
        LocatorReadError::ResourceLimit => CargoEvidenceReason::ResourceLimit,
        LocatorReadError::Cancelled => CargoEvidenceReason::Cancelled,
        LocatorReadError::InvalidRequest => CargoEvidenceReason::MissingIdentity,
    }
}

fn map_manifest_read_failure(failure: &LocatorReadFailure) -> CargoEvidenceReason {
    match failure {
        LocatorReadFailure::Cancelled => CargoEvidenceReason::Cancelled,
        LocatorReadFailure::ResourceLimit => CargoEvidenceReason::ResourceLimit,
        LocatorReadFailure::IdentityMismatch
        | LocatorReadFailure::MountChanged
        | LocatorReadFailure::InvalidBinding
        | LocatorReadFailure::SymlinkOrReparse
        | LocatorReadFailure::NotRegular
        | LocatorReadFailure::AmbiguousAlias => CargoEvidenceReason::MissingManifest,
        LocatorReadFailure::ReadFailed
        | LocatorReadFailure::ProviderOrOffline
        | LocatorReadFailure::Unavailable => CargoEvidenceReason::ManifestReadFailed,
    }
}

impl<'a> CollectedCargoConfigFile<'a> {
    fn into_decode_input(self) -> CargoConfigFile<'a> {
        match self {
            Self::Present(bytes) => CargoConfigFile::Present(bytes),
            Self::AbsentDuringEnumeration => CargoConfigFile::NotChecked,
            Self::Failed(reason) => CargoConfigFile::ReadFailed(reason),
        }
    }
}

fn cargo_workspace_pair_input(
    pair: &CargoConfigPairObservation,
    failure: Option<CargoEvidenceReason>,
) -> CargoWorkspacePairInput {
    match (pair.consistency, failure) {
        (_, Some(reason)) => CargoWorkspacePairInput::Failed(reason),
        (CargoConfigPairConsistency::NonAtomic, None) => CargoWorkspacePairInput::NotChecked,
    }
}

fn cargo_config_pair_presence(pair: &CargoConfigPairPresenceObservation) -> CargoHomeConfigCapture {
    debug_assert_eq!(
        pair.consistency,
        CargoConfigPairConsistency::NonAtomic,
        "Cargo-home absence must never be promoted without a stable pair observation"
    );
    let failure = [&pair.config, &pair.config_toml]
        .into_iter()
        .filter_map(|member| match member {
            CargoConfigMemberPresenceObservation::Failed(failure) => {
                Some(map_config_presence_failure(failure))
            }
            CargoConfigMemberPresenceObservation::Present
            | CargoConfigMemberPresenceObservation::AbsentDuringEnumeration => None,
        })
        .min_by_key(|reason| cargo_config_failure_precedence(*reason));
    if let Some(reason) = failure {
        CargoHomeConfigCapture::Failed(reason)
    } else if matches!(pair.config, CargoConfigMemberPresenceObservation::Present)
        || matches!(
            pair.config_toml,
            CargoConfigMemberPresenceObservation::Present
        )
    {
        CargoHomeConfigCapture::PresentRedacted
    } else {
        // The pair is explicitly non-atomic, so an empty enumeration cannot prove absence.
        CargoHomeConfigCapture::NotChecked
    }
}

fn map_config_presence_failure(failure: &LocatorReadFailure) -> CargoEvidenceReason {
    match failure {
        LocatorReadFailure::Cancelled => CargoEvidenceReason::Cancelled,
        LocatorReadFailure::ResourceLimit => CargoEvidenceReason::ResourceLimit,
        LocatorReadFailure::AmbiguousAlias => CargoEvidenceReason::AmbiguousConfig,
        LocatorReadFailure::IdentityMismatch
        | LocatorReadFailure::MountChanged
        | LocatorReadFailure::InvalidBinding
        | LocatorReadFailure::SymlinkOrReparse
        | LocatorReadFailure::NotRegular
        | LocatorReadFailure::ReadFailed
        | LocatorReadFailure::ProviderOrOffline
        | LocatorReadFailure::Unavailable => CargoEvidenceReason::ConfigReadFailed,
    }
}

fn cargo_config_scope_inputs(
    invocation: &CargoInvocationContext,
    workspace_pair: CargoWorkspacePairInput,
    invocation_cwd: CargoInvocationCwdInput,
) -> CargoConfigScopeInputs {
    CargoConfigScopeInputs {
        runtime: invocation.runtime,
        workspace_pair,
        invocation_cwd,
        ..CargoConfigScopeInputs::production(invocation)
    }
}

fn map_config_pair_member_read(
    read: &CargoConfigMemberObservation,
) -> CollectedCargoConfigFile<'_> {
    match read {
        CargoConfigMemberObservation::Present(_) => CollectedCargoConfigFile::Present(
            read.observed_bytes()
                .expect("present config observation carries bytes"),
        ),
        CargoConfigMemberObservation::AbsentDuringEnumeration => {
            CollectedCargoConfigFile::AbsentDuringEnumeration
        }
        CargoConfigMemberObservation::Failed(failure) => match failure {
            LocatorReadFailure::Cancelled => {
                CollectedCargoConfigFile::Failed(CargoEvidenceReason::Cancelled)
            }
            LocatorReadFailure::ResourceLimit => {
                CollectedCargoConfigFile::Failed(CargoEvidenceReason::ResourceLimit)
            }
            LocatorReadFailure::AmbiguousAlias => {
                CollectedCargoConfigFile::Failed(CargoEvidenceReason::AmbiguousConfig)
            }
            LocatorReadFailure::IdentityMismatch
            | LocatorReadFailure::MountChanged
            | LocatorReadFailure::InvalidBinding
            | LocatorReadFailure::SymlinkOrReparse
            | LocatorReadFailure::NotRegular
            | LocatorReadFailure::ReadFailed
            | LocatorReadFailure::ProviderOrOffline
            | LocatorReadFailure::Unavailable => {
                CollectedCargoConfigFile::Failed(CargoEvidenceReason::ConfigReadFailed)
            }
        },
    }
}

fn decode_bound_workspace_manifest(
    summary: &ScanSummary,
    root_entry_id: &ScanEntryId,
    manifest_entry_id: &ScanEntryId,
    bytes: &[u8],
) -> CargoEvidence<CargoWorkspaceEvidenceV1> {
    // The caller must supply bytes read through this manifest entry's already-admitted native
    // locator. This pure layer validates that locator/identity binding but intentionally does no I/O.
    if !summary_identity_graph_is_unique_and_complete(summary) {
        return unknown(CargoEvidenceReason::MissingIdentity);
    }
    let roots: Vec<_> = summary
        .roots
        .iter()
        .filter(|entry| {
            entry
                .identity
                .as_ref()
                .is_some_and(|identity| &identity.entry_id == root_entry_id)
        })
        .collect();
    let manifests: Vec<_> = summary
        .entries
        .iter()
        .filter(|entry| {
            entry
                .identity
                .as_ref()
                .is_some_and(|identity| &identity.entry_id == manifest_entry_id)
        })
        .collect();
    if roots.len() != 1 || manifests.len() != 1 {
        return unknown(CargoEvidenceReason::MissingIdentity);
    }
    let root = roots[0];
    let manifest = manifests[0];
    let (Some(root_identity), Some(manifest_identity)) = (
        validated_known_identity(root),
        validated_known_identity(manifest),
    ) else {
        return unknown(CargoEvidenceReason::MissingIdentity);
    };
    let (Ok(Some(root_locator)), Ok(Some(manifest_locator))) = (
        root.executable_native_locator(),
        manifest.executable_native_locator(),
    ) else {
        return unknown(CargoEvidenceReason::MissingIdentity);
    };
    if root.object_type != ObjectType::Directory
        || manifest.object_type != ObjectType::File
        || !entry_is_complete_live(root)
        || !entry_is_complete_live(manifest)
        || root_identity.entry_id != root_identity.scan_root_id
        || root_identity.parent_id.is_some()
        || manifest_identity.scan_root_id != root_identity.entry_id
        || manifest_identity.parent_id.as_ref() != Some(root_entry_id)
        || manifest_identity.filesystem_object_domain_identity
            != root_identity.filesystem_object_domain_identity
        || manifest_identity.volume_or_mount_identity != root_identity.volume_or_mount_identity
        || !native_name_equals(&manifest.native_basename, "Cargo.toml")
        || root_locator.scan_root != manifest_locator.scan_root
        || root_locator.scan_root_absolute_path != manifest_locator.scan_root_absolute_path
        || manifest_locator.parent_reopen_recipe.as_slice() != [root_locator.scan_root.clone()]
        || !locator_components_share_scope(root_locator)
        || !locator_components_share_scope(manifest_locator)
    {
        return unknown(CargoEvidenceReason::MissingIdentity);
    }
    decode_workspace_manifest(root_entry_id, manifest_entry_id, bytes)
}

fn classify_bound_target_shape(
    summary: &ScanSummary,
    workspace: &CargoWorkspaceEvidenceV1,
    target_dir: &CargoTargetDirEvidenceV1,
    target_entry_id: &ScanEntryId,
) -> CargoEvidence<CargoTargetShapeEvidenceV1> {
    if !summary_identity_graph_is_unique_and_complete(summary) {
        return unknown(CargoEvidenceReason::MissingIdentity);
    }
    let roots: Vec<_> = summary
        .roots
        .iter()
        .filter(|entry| {
            entry
                .identity
                .as_ref()
                .is_some_and(|identity| identity.entry_id == workspace.root_entry_id)
        })
        .collect();
    let targets: Vec<_> = summary
        .entries
        .iter()
        .filter(|entry| {
            entry
                .identity
                .as_ref()
                .is_some_and(|identity| &identity.entry_id == target_entry_id)
        })
        .collect();
    if roots.len() != 1 || targets.len() != 1 {
        return unknown(CargoEvidenceReason::MissingIdentity);
    }
    let root = roots[0];
    let target = targets[0];
    let (Some(root_identity), Some(target_identity)) = (
        validated_known_identity(root),
        validated_known_identity(target),
    ) else {
        return unknown(CargoEvidenceReason::MissingIdentity);
    };
    let (Ok(Some(root_locator)), Ok(Some(target_locator))) = (
        root.executable_native_locator(),
        target.executable_native_locator(),
    ) else {
        return unknown(CargoEvidenceReason::MissingIdentity);
    };
    let relative_locator_components: Vec<_> = target_locator
        .parent_reopen_recipe
        .iter()
        .skip(1)
        .map(|component| native_name_to_utf8(&component.native_basename))
        .chain(std::iter::once(native_name_to_utf8(
            &target_locator.entry.native_basename,
        )))
        .collect();
    if root_identity.entry_id != root_identity.scan_root_id
        || workspace.schema != CARGO_WORKSPACE_EVIDENCE_SCHEMA
        || workspace.decoder_id != CARGO_CONFIG_DECODER_ID
        || workspace.workspace_id != workspace.root_entry_id.to_string()
        || target_dir.schema != CARGO_TARGET_DIR_EVIDENCE_SCHEMA
        || target_dir.decoder_id != CARGO_CONFIG_DECODER_ID
        || target_dir.relative_path != target_dir.relative_components.join("/")
        || target_identity.scan_root_id != root_identity.entry_id
        || target_identity.filesystem_object_domain_identity
            != root_identity.filesystem_object_domain_identity
        || target_identity.volume_or_mount_identity != root_identity.volume_or_mount_identity
        || root_locator.scan_root != target_locator.scan_root
        || root_locator.scan_root_absolute_path != target_locator.scan_root_absolute_path
        || !locator_components_share_scope(root_locator)
        || !locator_components_share_scope(target_locator)
        || !locator_parents_are_backed_by_summary(summary, target_locator)
        || relative_locator_components.iter().any(Option::is_none)
        || relative_locator_components
            .into_iter()
            .flatten()
            .ne(target_dir.relative_components.iter().cloned())
    {
        return unknown(CargoEvidenceReason::MissingIdentity);
    }
    classify_target_shape(summary, target_entry_id)
}

fn validate_input_budget<'a>(
    files: impl IntoIterator<Item = CargoInputFile<'a>>,
) -> Result<(), CargoEvidenceReason> {
    let mut total = 0usize;
    for file in files {
        if !matches!(
            file.name,
            "Cargo.toml" | "Cargo.lock" | ".cargo/config" | ".cargo/config.toml"
        ) || file.bytes.len() > MAX_CARGO_INPUT_FILE_BYTES
        {
            return Err(CargoEvidenceReason::ResourceLimit);
        }
        total = total
            .checked_add(file.bytes.len())
            .ok_or(CargoEvidenceReason::ResourceLimit)?;
        if total > MAX_CARGO_INPUT_TOTAL_BYTES {
            return Err(CargoEvidenceReason::ResourceLimit);
        }
    }
    Ok(())
}

fn decode_workspace_manifest(
    root_entry_id: &ScanEntryId,
    manifest_entry_id: &ScanEntryId,
    bytes: &[u8],
) -> CargoEvidence<CargoWorkspaceEvidenceV1> {
    if bytes.is_empty() {
        return unknown(CargoEvidenceReason::MissingManifest);
    }
    if bytes.len() > MAX_CARGO_INPUT_FILE_BYTES {
        return unknown(CargoEvidenceReason::ResourceLimit);
    }
    let table = match parse_toml(bytes) {
        Ok(table) => table,
        Err(reason) => return unknown(reason),
    };
    let package = table.get("package");
    let workspace = table.get("workspace");
    if package.is_some_and(|value| !value.is_table())
        || workspace.is_some_and(|value| !value.is_table())
    {
        return unknown(CargoEvidenceReason::UnsupportedManifestShape);
    }
    let manifest_kind = match (package.is_some(), workspace.is_some()) {
        (true, true) => CargoManifestKind::WorkspacePackage,
        (false, true) => CargoManifestKind::VirtualWorkspace,
        (true, false) | (false, false) => {
            return unknown(CargoEvidenceReason::UnsupportedManifestShape);
        }
    };
    if let Some(package) = package {
        let package = package.as_table().expect("package kind requires a table");
        let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
            return unknown(CargoEvidenceReason::UnsupportedManifestShape);
        };
        if name.trim().is_empty() {
            return unknown(CargoEvidenceReason::UnsupportedManifestShape);
        }
        if package.contains_key("workspace") {
            return unknown(CargoEvidenceReason::UnsupportedManifestShape);
        }
    }
    let workspace = workspace
        .and_then(toml::Value::as_table)
        .expect("workspace kind requires a table");
    for key in ["members", "exclude", "default-members"] {
        let Some(value) = workspace.get(key) else {
            continue;
        };
        let Some(values) = value.as_array() else {
            return unknown(CargoEvidenceReason::UnsupportedManifestShape);
        };
        if !values.is_empty()
            || values.iter().any(|member| {
                member
                    .as_str()
                    .is_none_or(|member| member.trim().is_empty())
            })
        {
            return unknown(CargoEvidenceReason::UnsupportedManifestShape);
        }
    }
    if contains_path_dependency(&table) {
        return unknown(CargoEvidenceReason::UnsupportedManifestShape);
    }
    CargoEvidence::Known {
        value: CargoWorkspaceEvidenceV1 {
            schema: CARGO_WORKSPACE_EVIDENCE_SCHEMA,
            decoder_id: CARGO_CONFIG_DECODER_ID,
            workspace_id: root_entry_id.to_string(),
            root_entry_id: root_entry_id.clone(),
            manifest_entry_id: manifest_entry_id.clone(),
            manifest_kind,
        },
    }
}

fn decode_config_scope(inputs: CargoConfigInputs<'_>) -> CargoConfigScopeEvidenceV1 {
    let workspace = decode_workspace_config_scope(
        inputs.config,
        inputs.config_toml,
        inputs.scope.workspace_pair,
    );
    let scope = inputs.scope;
    let environment = CargoConfigEnvironmentEvidence {
        cargo_target_dir: environment_evidence("CARGO_TARGET_DIR", scope.runtime.cargo_target_dir),
        cargo_build_target_dir: environment_evidence(
            "CARGO_BUILD_TARGET_DIR",
            scope.runtime.cargo_build_target_dir,
        ),
        cargo_home: environment_evidence("CARGO_HOME", scope.runtime.cargo_home),
    };
    let mut evidence = CargoConfigScopeEvidenceV1 {
        schema: CARGO_CONFIG_SCOPE_EVIDENCE_SCHEMA,
        decoder_id: CARGO_CONFIG_DECODER_ID,
        workspace,
        ancestor_configs: project_external_source(scope.ancestor_configs),
        cargo_home_config: project_external_source(scope.cargo_home_config),
        environment,
        cli: CargoConfigCliEvidence {
            target_dir: project_external_source(scope.cli_target_dir),
            config_overrides: project_external_source(scope.cli_config_overrides),
        },
        invocation_cwd: project_invocation_cwd(scope.invocation_cwd),
        precedence_complete: false,
        blockers: Vec::new(),
    };
    normalize_config_scope(&mut evidence);
    evidence
}

fn decode_workspace_config_scope(
    config: CargoConfigFile<'_>,
    config_toml: CargoConfigFile<'_>,
    pair_snapshot: CargoWorkspacePairInput,
) -> CargoWorkspaceConfigScopeEvidence {
    let config_state = project_config_file_state(config);
    let config_toml_state = project_config_file_state(config_toml);
    // Production observes both names through one retained directory handle and one bounded cursor,
    // but no platform-sealed directory generation exists yet. The observation therefore cannot
    // exclude create/delete/rename ABA and must not be promoted into a stable selection.
    let pair_is_stable = matches!(pair_snapshot, CargoWorkspacePairInput::StableSnapshot);
    let (selected, selected_file) = match (pair_is_stable, config, config_toml) {
        (true, CargoConfigFile::Present(bytes), _) => (
            CargoWorkspaceConfigSelection::Config,
            Some((CargoTargetDirSource::Config, bytes)),
        ),
        (true, CargoConfigFile::VerifiedAbsent, CargoConfigFile::Present(bytes)) => (
            CargoWorkspaceConfigSelection::ConfigToml,
            Some((CargoTargetDirSource::ConfigToml, bytes)),
        ),
        (true, CargoConfigFile::VerifiedAbsent, CargoConfigFile::VerifiedAbsent) => {
            (CargoWorkspaceConfigSelection::None, None)
        }
        (false, CargoConfigFile::Present(bytes), _) => (
            CargoWorkspaceConfigSelection::NotChecked,
            Some((CargoTargetDirSource::Config, bytes)),
        ),
        (
            false,
            CargoConfigFile::VerifiedAbsent | CargoConfigFile::NotChecked,
            CargoConfigFile::Present(bytes),
        ) => (
            CargoWorkspaceConfigSelection::NotChecked,
            Some((CargoTargetDirSource::ConfigToml, bytes)),
        ),
        _ => (CargoWorkspaceConfigSelection::NotChecked, None),
    };
    let target_dir_declaration = match selected_file {
        Some((source, bytes)) => decode_workspace_target_dir_declaration(source, bytes),
        None if pair_is_stable
            && matches!(
                (config, config_toml),
                (
                    CargoConfigFile::VerifiedAbsent,
                    CargoConfigFile::VerifiedAbsent
                )
            ) =>
        {
            CargoWorkspaceTargetDirDeclaration::VerifiedAbsent
        }
        None if matches!(config, CargoConfigFile::ReadFailed(_))
            || matches!(config_toml, CargoConfigFile::ReadFailed(_)) =>
        {
            CargoWorkspaceTargetDirDeclaration::Unknown {
                reason_code: config_failure_reason(config, config_toml),
            }
        }
        None => CargoWorkspaceTargetDirDeclaration::NotChecked {
            reason_code: CargoEvidenceReason::ConfigScopeNotChecked,
        },
    };
    CargoWorkspaceConfigScopeEvidence {
        pair_snapshot: match pair_snapshot {
            CargoWorkspacePairInput::StableSnapshot => CargoWorkspacePairState::StableSnapshot,
            CargoWorkspacePairInput::NotChecked => CargoWorkspacePairState::NotChecked {
                reason_code: CargoEvidenceReason::ConfigScopeNotChecked,
            },
            CargoWorkspacePairInput::Failed(reason_code) => {
                CargoWorkspacePairState::Failed { reason_code }
            }
        },
        config: config_state,
        config_toml: config_toml_state,
        selected,
        target_dir_declaration,
    }
}

fn project_config_file_state(file: CargoConfigFile<'_>) -> CargoConfigFileState {
    match file {
        CargoConfigFile::Present(_) => CargoConfigFileState::Present,
        CargoConfigFile::VerifiedAbsent => CargoConfigFileState::VerifiedAbsent,
        CargoConfigFile::NotChecked => CargoConfigFileState::NotChecked {
            reason_code: CargoEvidenceReason::ConfigScopeNotChecked,
        },
        CargoConfigFile::ReadFailed(reason_code) => CargoConfigFileState::Failed { reason_code },
    }
}

fn config_failure_reason(
    config: CargoConfigFile<'_>,
    config_toml: CargoConfigFile<'_>,
) -> CargoEvidenceReason {
    [config, config_toml]
        .into_iter()
        .filter_map(|file| match file {
            CargoConfigFile::ReadFailed(reason) => Some(reason),
            CargoConfigFile::Present(_)
            | CargoConfigFile::VerifiedAbsent
            | CargoConfigFile::NotChecked => None,
        })
        .min_by_key(|reason| cargo_config_failure_precedence(*reason))
        .unwrap_or(CargoEvidenceReason::ConfigReadFailed)
}

fn decode_workspace_target_dir_declaration(
    source: CargoTargetDirSource,
    bytes: &[u8],
) -> CargoWorkspaceTargetDirDeclaration {
    if bytes.len() > MAX_CARGO_INPUT_FILE_BYTES {
        return CargoWorkspaceTargetDirDeclaration::Unknown {
            reason_code: CargoEvidenceReason::ResourceLimit,
        };
    }
    let table = match parse_toml(bytes) {
        Ok(table) => table,
        Err(reason) => {
            return CargoWorkspaceTargetDirDeclaration::Unknown {
                reason_code: reason,
            };
        }
    };
    if table.contains_key("include") {
        return CargoWorkspaceTargetDirDeclaration::Unknown {
            reason_code: CargoEvidenceReason::UnsupportedConfigInclude,
        };
    }
    let Some(build) = table.get("build") else {
        return CargoWorkspaceTargetDirDeclaration::VerifiedAbsent;
    };
    let Some(build) = build.as_table() else {
        return CargoWorkspaceTargetDirDeclaration::Unknown {
            reason_code: CargoEvidenceReason::UnsupportedManifestShape,
        };
    };
    let Some(value) = build.get("target-dir") else {
        return CargoWorkspaceTargetDirDeclaration::VerifiedAbsent;
    };
    let Some(value) = value.as_str() else {
        return CargoWorkspaceTargetDirDeclaration::Unknown {
            reason_code: CargoEvidenceReason::UnsupportedManifestShape,
        };
    };
    let relative_components = match validate_relative_target_dir(value) {
        Ok(components) => components,
        Err(reason) => {
            return CargoWorkspaceTargetDirDeclaration::Unknown {
                reason_code: reason,
            };
        }
    };
    CargoWorkspaceTargetDirDeclaration::Known {
        value: CargoWorkspaceTargetDirDeclarationV1 {
            schema: CARGO_WORKSPACE_TARGET_DIR_DECLARATION_SCHEMA,
            decoder_id: CARGO_CONFIG_DECODER_ID,
            relative_path: relative_components.join("/"),
            relative_components,
            source,
        },
    }
}

fn cargo_config_failure_precedence(reason: CargoEvidenceReason) -> u8 {
    match reason {
        CargoEvidenceReason::Cancelled => 0,
        CargoEvidenceReason::ResourceLimit => 1,
        CargoEvidenceReason::ConfigReadFailed => 2,
        _ => 3,
    }
}

fn environment_evidence(
    name: &'static str,
    state: CargoEnvironmentPresence,
) -> CargoEnvironmentVariableEvidence {
    CargoEnvironmentVariableEvidence {
        name,
        state,
        value_redacted: matches!(state, CargoEnvironmentPresence::PresentRedacted),
    }
}

fn project_external_source(
    input: CargoConfigExternalSourceInput,
) -> CargoConfigExternalSourceState {
    match input {
        CargoConfigExternalSourceInput::VerifiedAbsent => {
            CargoConfigExternalSourceState::VerifiedAbsent
        }
        CargoConfigExternalSourceInput::PresentRedacted => {
            CargoConfigExternalSourceState::PresentRedacted
        }
        CargoConfigExternalSourceInput::NotChecked => CargoConfigExternalSourceState::NotChecked {
            reason_code: CargoEvidenceReason::ConfigScopeNotChecked,
        },
        CargoConfigExternalSourceInput::Failed(reason_code) => {
            CargoConfigExternalSourceState::Failed { reason_code }
        }
    }
}

fn project_invocation_cwd(input: CargoInvocationCwdInput) -> CargoInvocationCwdBinding {
    match input {
        CargoInvocationCwdInput::BoundToWorkspaceRoot => {
            CargoInvocationCwdBinding::BoundToWorkspaceRoot
        }
        CargoInvocationCwdInput::PathMatchesRevalidatedWorkspaceRoot => {
            CargoInvocationCwdBinding::PathMatchesRevalidatedWorkspaceRoot
        }
        CargoInvocationCwdInput::NotChecked => CargoInvocationCwdBinding::NotChecked {
            reason_code: CargoEvidenceReason::ConfigScopeNotChecked,
        },
        CargoInvocationCwdInput::Failed(reason_code) => {
            CargoInvocationCwdBinding::Failed { reason_code }
        }
    }
}

fn normalize_config_scope(evidence: &mut CargoConfigScopeEvidenceV1) {
    let mut blockers = config_scope_blockers(evidence);
    sort_and_dedup_blockers(&mut blockers);
    evidence.precedence_complete = blockers.is_empty();
    evidence.blockers = blockers;
}

fn config_scope_blockers(evidence: &CargoConfigScopeEvidenceV1) -> Vec<CargoConfigScopeBlocker> {
    let mut blockers = Vec::new();
    match evidence.workspace.pair_snapshot {
        CargoWorkspacePairState::StableSnapshot => {}
        CargoWorkspacePairState::NotChecked { .. } => {
            blockers.push(CargoConfigScopeBlocker::WorkspaceConfigPairNotStable);
        }
        CargoWorkspacePairState::Failed { .. } => {
            blockers.push(CargoConfigScopeBlocker::WorkspaceConfigPairFailed);
        }
    }
    match (
        &evidence.workspace.pair_snapshot,
        &evidence.workspace.target_dir_declaration,
    ) {
        (
            CargoWorkspacePairState::StableSnapshot,
            CargoWorkspaceTargetDirDeclaration::Known { .. },
        )
        | (
            CargoWorkspacePairState::StableSnapshot,
            CargoWorkspaceTargetDirDeclaration::VerifiedAbsent,
        ) => {}
        (_, CargoWorkspaceTargetDirDeclaration::Unknown { reason_code }) => {
            blockers.push(workspace_config_blocker(*reason_code))
        }
        (CargoWorkspacePairState::StableSnapshot, _) => {
            blockers.push(CargoConfigScopeBlocker::WorkspaceConfigNotChecked);
        }
        _ => {}
    }
    collect_external_blocker(
        &mut blockers,
        &evidence.ancestor_configs,
        CargoConfigScopeBlocker::AncestorConfigsNotChecked,
        CargoConfigScopeBlocker::AncestorConfigsFailed,
        CargoConfigScopeBlocker::AncestorConfigsPresentRedacted,
    );
    collect_external_blocker(
        &mut blockers,
        &evidence.cargo_home_config,
        CargoConfigScopeBlocker::CargoHomeConfigNotChecked,
        CargoConfigScopeBlocker::CargoHomeConfigFailed,
        CargoConfigScopeBlocker::CargoHomeConfigPresentRedacted,
    );
    collect_external_blocker(
        &mut blockers,
        &evidence.cli.target_dir,
        CargoConfigScopeBlocker::CliTargetDirNotChecked,
        CargoConfigScopeBlocker::CliTargetDirFailed,
        CargoConfigScopeBlocker::CliTargetDirNotChecked,
    );
    collect_external_blocker(
        &mut blockers,
        &evidence.cli.config_overrides,
        CargoConfigScopeBlocker::CliConfigOverridesNotChecked,
        CargoConfigScopeBlocker::CliConfigOverridesFailed,
        CargoConfigScopeBlocker::CliConfigOverridesNotChecked,
    );
    match evidence.invocation_cwd {
        CargoInvocationCwdBinding::BoundToWorkspaceRoot => {}
        CargoInvocationCwdBinding::PathMatchesRevalidatedWorkspaceRoot => {
            blockers.push(CargoConfigScopeBlocker::InvocationCwdIdentityNotBound);
        }
        CargoInvocationCwdBinding::NotChecked { .. } => {
            blockers.push(CargoConfigScopeBlocker::InvocationCwdNotBound);
        }
        CargoInvocationCwdBinding::Failed { .. } => {
            blockers.push(CargoConfigScopeBlocker::InvocationCwdBindingFailed);
        }
    }
    if evidence.environment.cargo_target_dir.state == CargoEnvironmentPresence::PresentRedacted {
        blockers.push(CargoConfigScopeBlocker::CargoTargetDirPresentRedacted);
    }
    if evidence.environment.cargo_build_target_dir.state
        == CargoEnvironmentPresence::PresentRedacted
    {
        blockers.push(CargoConfigScopeBlocker::CargoBuildTargetDirPresentRedacted);
    }
    if evidence.environment.cargo_home.state == CargoEnvironmentPresence::PresentRedacted {
        blockers.push(CargoConfigScopeBlocker::CargoHomePresentRedacted);
    }
    blockers
}

fn sort_and_dedup_blockers(blockers: &mut Vec<CargoConfigScopeBlocker>) {
    blockers.sort();
    blockers.dedup();
}

fn collect_external_blocker(
    blockers: &mut Vec<CargoConfigScopeBlocker>,
    state: &CargoConfigExternalSourceState,
    not_checked: CargoConfigScopeBlocker,
    failed: CargoConfigScopeBlocker,
    present_redacted: CargoConfigScopeBlocker,
) {
    match state {
        CargoConfigExternalSourceState::VerifiedAbsent => {}
        CargoConfigExternalSourceState::PresentRedacted => blockers.push(present_redacted),
        CargoConfigExternalSourceState::NotChecked { .. } => blockers.push(not_checked),
        CargoConfigExternalSourceState::Failed { .. } => blockers.push(failed),
    }
}

fn workspace_config_blocker(reason: CargoEvidenceReason) -> CargoConfigScopeBlocker {
    match reason {
        CargoEvidenceReason::AmbiguousConfig => CargoConfigScopeBlocker::WorkspaceConfigNotChecked,
        CargoEvidenceReason::DuplicateTomlKey => {
            CargoConfigScopeBlocker::WorkspaceConfigDuplicateKey
        }
        CargoEvidenceReason::MalformedToml => CargoConfigScopeBlocker::WorkspaceConfigMalformed,
        CargoEvidenceReason::ResourceLimit => CargoConfigScopeBlocker::WorkspaceConfigResourceLimit,
        CargoEvidenceReason::ConfigReadFailed => CargoConfigScopeBlocker::WorkspaceConfigReadFailed,
        CargoEvidenceReason::InvalidRelativeTargetDir => {
            CargoConfigScopeBlocker::WorkspaceTargetDirInvalid
        }
        CargoEvidenceReason::UnsupportedConfigInclude => {
            CargoConfigScopeBlocker::WorkspaceConfigIncludeUnsupported
        }
        CargoEvidenceReason::UnsupportedManifestShape => {
            CargoConfigScopeBlocker::WorkspaceConfigShapeUnsupported
        }
        _ => CargoConfigScopeBlocker::WorkspaceConfigNotChecked,
    }
}

fn decode_effective_target_dir(
    _inputs: CargoConfigInputs<'_>,
    scope: &CargoConfigScopeEvidenceV1,
) -> CargoEvidence<CargoTargetDirEvidenceV1> {
    if !scope.precedence_complete {
        return CargoEvidence::NotChecked {
            reason: CargoEvidenceReason::ConfigScopeNotChecked,
        };
    }
    match &scope.workspace.target_dir_declaration {
        CargoWorkspaceTargetDirDeclaration::Known { value } => {
            known_target_dir(value.source, &value.relative_path)
        }
        CargoWorkspaceTargetDirDeclaration::VerifiedAbsent => {
            known_target_dir(CargoTargetDirSource::Default, DEFAULT_TARGET_COMPONENT)
        }
        CargoWorkspaceTargetDirDeclaration::NotChecked { .. } => CargoEvidence::NotChecked {
            reason: CargoEvidenceReason::ConfigScopeNotChecked,
        },
        CargoWorkspaceTargetDirDeclaration::Unknown { reason_code } => unknown(*reason_code),
    }
}

fn config_scope_for_input_failure(
    inputs: CargoConfigInputs<'_>,
    reason: CargoEvidenceReason,
) -> CargoConfigScopeEvidenceV1 {
    let mut scope = decode_config_scope(inputs);
    scope.workspace.target_dir_declaration = CargoWorkspaceTargetDirDeclaration::Unknown {
        reason_code: reason,
    };
    normalize_config_scope(&mut scope);
    scope
}

fn config_scope_for_failure(
    reason: CargoEvidenceReason,
    invocation: &CargoInvocationContext,
    invocation_cwd: CargoInvocationCwdInput,
) -> CargoConfigScopeEvidenceV1 {
    config_scope_for_input_failure(
        CargoConfigInputs {
            scope: CargoConfigScopeInputs {
                invocation_cwd,
                ..CargoConfigScopeInputs::production(invocation)
            },
            ..CargoConfigInputs::default()
        },
        reason,
    )
}

fn known_target_dir(
    source: CargoTargetDirSource,
    value: &str,
) -> CargoEvidence<CargoTargetDirEvidenceV1> {
    let components = match validate_relative_target_dir(value) {
        Ok(components) => components,
        Err(reason) => return unknown(reason),
    };
    CargoEvidence::Known {
        value: CargoTargetDirEvidenceV1 {
            schema: CARGO_TARGET_DIR_EVIDENCE_SCHEMA,
            decoder_id: CARGO_CONFIG_DECODER_ID,
            relative_path: components.join("/"),
            relative_components: components,
            source,
        },
    }
}

fn validate_relative_target_dir(value: &str) -> Result<Vec<String>, CargoEvidenceReason> {
    if value.is_empty()
        || value.len() > MAX_TARGET_DIR_BYTES
        || value.starts_with('/')
        || value.starts_with('\\')
        || has_windows_prefix(value)
    {
        return Err(CargoEvidenceReason::InvalidRelativeTargetDir);
    }
    let mut components = Vec::new();
    if value.contains('\\') {
        return Err(CargoEvidenceReason::InvalidRelativeTargetDir);
    }
    for component in value.split('/') {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err(CargoEvidenceReason::InvalidRelativeTargetDir);
        }
        if component.len() > MAX_TARGET_DIR_COMPONENT_BYTES
            || component.bytes().any(|byte| byte == 0 || byte < 0x20)
            || component.ends_with(['.', ' '])
            || component.contains(':')
        {
            return Err(CargoEvidenceReason::InvalidRelativeTargetDir);
        }
        components.push(component.to_string());
        if components.len() > MAX_TARGET_DIR_COMPONENTS {
            return Err(CargoEvidenceReason::ResourceLimit);
        }
    }
    if components.is_empty() {
        return Err(CargoEvidenceReason::InvalidRelativeTargetDir);
    }
    Ok(components)
}

fn has_windows_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn parse_toml(bytes: &[u8]) -> Result<toml::Table, CargoEvidenceReason> {
    let input = std::str::from_utf8(bytes).map_err(|_| CargoEvidenceReason::MalformedToml)?;
    input.parse::<toml::Table>().map_err(|error| {
        if error.message().contains("duplicate key") {
            CargoEvidenceReason::DuplicateTomlKey
        } else {
            CargoEvidenceReason::MalformedToml
        }
    })
}

fn contains_unsupported_include(value: &toml::Value) -> bool {
    match value {
        toml::Value::Table(table) => {
            table.contains_key("include") || table.values().any(contains_unsupported_include)
        }
        toml::Value::Array(values) => values.iter().any(contains_unsupported_include),
        _ => false,
    }
}

fn contains_path_dependency(table: &toml::Table) -> bool {
    const DIRECT_DEPENDENCY_TABLES: &[&str] =
        &["dependencies", "dev-dependencies", "build-dependencies"];
    if DIRECT_DEPENDENCY_TABLES
        .iter()
        .any(|key| table.get(*key).is_some_and(dependency_value_contains_path))
        || table
            .get("workspace")
            .and_then(toml::Value::as_table)
            .and_then(|workspace| workspace.get("dependencies"))
            .is_some_and(dependency_value_contains_path)
        || ["patch", "replace"]
            .iter()
            .any(|key| table.get(*key).is_some_and(dependency_value_contains_path))
    {
        return true;
    }
    table
        .get("target")
        .and_then(toml::Value::as_table)
        .is_some_and(|targets| {
            targets.values().any(|target| {
                target.as_table().is_some_and(|target| {
                    DIRECT_DEPENDENCY_TABLES
                        .iter()
                        .any(|key| target.get(*key).is_some_and(dependency_value_contains_path))
                })
            })
        })
}

fn dependency_value_contains_path(value: &toml::Value) -> bool {
    match value {
        toml::Value::Table(table) => table.iter().any(|(key, value)| {
            (key == "path" && matches!(value, toml::Value::String(_)))
                || dependency_value_contains_path(value)
        }),
        toml::Value::Array(values) => values.iter().any(dependency_value_contains_path),
        _ => false,
    }
}

/// Classifies only the direct children retained by the supplied scan summary. It never opens an
/// object. The allowlist is deliberately conservative and versioned by this module/schema.
fn classify_target_shape(
    summary: &ScanSummary,
    target_entry_id: &ScanEntryId,
) -> CargoEvidence<CargoTargetShapeEvidenceV1> {
    if !summary_identity_graph_is_unique_and_complete(summary) {
        return unknown(CargoEvidenceReason::MissingIdentity);
    }
    if !summary.boundaries.is_empty()
        || summary.progress.iter().any(|event| {
            matches!(
                event,
                ProgressEvent::Error { .. }
                    | ProgressEvent::Cancelled { .. }
                    | ProgressEvent::ResourceLimit { .. }
            )
        })
    {
        return unknown(if summary.boundaries.is_empty() {
            CargoEvidenceReason::IncompleteScan
        } else {
            CargoEvidenceReason::BoundaryPresent
        });
    }

    let targets: Vec<&ScannedEntry> = summary
        .roots
        .iter()
        .chain(summary.entries.iter())
        .filter(|entry| {
            entry
                .identity
                .as_ref()
                .is_some_and(|identity| &identity.entry_id == target_entry_id)
        })
        .collect();
    if targets.is_empty() {
        return unknown(CargoEvidenceReason::TargetEntryMissing);
    }
    if targets.len() != 1 {
        return unknown(CargoEvidenceReason::MultipleTargetEntries);
    }
    let target = targets[0];
    if target.object_type != ObjectType::Directory || !entry_is_complete_live(target) {
        return unknown(CargoEvidenceReason::IncompleteScan);
    }
    let Some(target_identity) = validated_known_identity(target) else {
        return unknown(CargoEvidenceReason::MissingIdentity);
    };
    let Ok(Some(target_locator)) = target.executable_native_locator() else {
        return unknown(CargoEvidenceReason::MissingIdentity);
    };
    if !locator_components_share_scope(target_locator) {
        return unknown(CargoEvidenceReason::MissingIdentity);
    }
    let matching_aggregates: Vec<_> = summary
        .aggregates
        .iter()
        .filter(|aggregate| aggregate.directory_identity == target_entry_id.to_string())
        .collect();
    if matching_aggregates.len() != 1 {
        return unknown(CargoEvidenceReason::MissingTargetAggregate);
    }
    let aggregate = matching_aggregates[0];
    if aggregate.scan_id != target.scan_id
        || aggregate.scan_entry_id().ok().as_ref() != Some(target_entry_id)
        || aggregate.coverage.state != CoverageState::Complete
        || !aggregate.coverage.complete
        || aggregate.coverage.details_lost
        || !aggregate.coverage.incomplete_reasons.is_empty()
        || !matches!(
            aggregate.coverage.provenance,
            FieldProvenance::LiveObservation { .. }
        )
        || aggregate.arithmetic_state != ArithmeticState::Exact
    {
        return unknown(CargoEvidenceReason::IncompleteScan);
    }
    if !matches!(summary.progress.last(), Some(ProgressEvent::Finished))
        || summary
            .progress
            .iter()
            .filter(|event| matches!(event, ProgressEvent::Finished))
            .count()
            != 1
    {
        return unknown(CargoEvidenceReason::IncompleteScan);
    }

    let mut observed = BTreeMap::<String, ObjectType>::new();
    let mut observed_entry_ids = BTreeSet::new();
    for child in &summary.entries {
        let Some(identity) = child.validated_identity().ok().flatten() else {
            return unknown(CargoEvidenceReason::MissingIdentity);
        };
        if identity.parent_id.as_ref() != Some(target_entry_id) {
            continue;
        }
        let Some(identity) = validated_known_identity(child) else {
            return unknown(CargoEvidenceReason::MissingIdentity);
        };
        if !observed_entry_ids.insert(identity.entry_id.clone()) {
            return unknown(CargoEvidenceReason::MissingIdentity);
        }
        let Ok(Some(locator)) = child.executable_native_locator() else {
            return unknown(CargoEvidenceReason::MissingIdentity);
        };
        let mut expected_parent_recipe = target_locator.parent_reopen_recipe.clone();
        expected_parent_recipe.push(target_locator.entry.clone());
        if !entry_is_complete_live(child)
            || identity.scan_root_id != target_identity.scan_root_id
            || identity.filesystem_object_domain_identity
                != target_identity.filesystem_object_domain_identity
            || identity.volume_or_mount_identity != target_identity.volume_or_mount_identity
        {
            return unknown(CargoEvidenceReason::IncompleteScan);
        }
        if locator.scan_root != target_locator.scan_root
            || locator.scan_root_absolute_path != target_locator.scan_root_absolute_path
            || locator.parent_reopen_recipe != expected_parent_recipe
            || !locator_components_share_scope(locator)
        {
            return unknown(CargoEvidenceReason::MissingIdentity);
        }
        let Some(name) = native_name_to_utf8(&child.native_basename) else {
            return unknown(CargoEvidenceReason::UnexpectedTargetComponent);
        };
        if !allowed_top_level_component(&name, &child.object_type) {
            return unknown(match child.object_type {
                ObjectType::Symlink | ObjectType::ReparsePoint | ObjectType::Other => {
                    CargoEvidenceReason::UnknownObjectType
                }
                ObjectType::File | ObjectType::Directory => {
                    CargoEvidenceReason::UnexpectedTargetComponent
                }
            });
        }
        if observed.insert(name, child.object_type.clone()).is_some() {
            return unknown(CargoEvidenceReason::UnexpectedTargetComponent);
        }
    }
    if observed.is_empty() {
        return unknown(CargoEvidenceReason::UnexpectedTargetComponent);
    }
    let direct_child_count = match aggregate.direct_child_count {
        sweepx_model::EvidenceValue::Known { value } => u128::from(value),
        _ => return unknown(CargoEvidenceReason::IncompleteScan),
    };
    if direct_child_count != observed.len() as u128 {
        return unknown(CargoEvidenceReason::IncompleteScan);
    }
    CargoEvidence::Known {
        value: CargoTargetShapeEvidenceV1 {
            schema: CARGO_TARGET_SHAPE_EVIDENCE_SCHEMA,
            target_entry_id: target_entry_id.clone(),
            classification: CargoTargetShape::RecognizedGeneratedStructure,
            observed_top_level_components: observed.into_keys().collect(),
        },
    }
}

fn validated_known_identity(entry: &ScannedEntry) -> Option<&sweepx_model::ScanObjectIdentity> {
    let identity = entry.validated_identity().ok().flatten()?;
    if !matches!(
        identity.platform_file_identity,
        IdentityEvidence::Known { .. }
    ) || !matches!(
        identity.filesystem_object_domain_identity,
        IdentityEvidence::Known { .. }
    ) || !matches!(
        identity.volume_or_mount_identity,
        IdentityEvidence::Known { .. }
    ) {
        return None;
    }
    Some(identity)
}

fn summary_identity_graph_is_unique_and_complete(summary: &ScanSummary) -> bool {
    let Some(scan_id) = summary.roots.first().map(|entry| &entry.scan_id) else {
        return false;
    };
    let mut all_ids = BTreeSet::new();
    let mut root_ids = BTreeSet::new();
    for root in &summary.roots {
        let Some(identity) = validated_known_identity(root) else {
            return false;
        };
        if &root.scan_id != scan_id
            || root.object_type != ObjectType::Directory
            || identity.entry_id != identity.scan_root_id
            || identity.parent_id.is_some()
            || !all_ids.insert(identity.entry_id.clone())
        {
            return false;
        }
        root_ids.insert(identity.entry_id.clone());
    }
    for entry in &summary.entries {
        let Some(identity) = validated_known_identity(entry) else {
            return false;
        };
        if &entry.scan_id != scan_id || !all_ids.insert(identity.entry_id.clone()) {
            return false;
        }
    }
    summary.entries.iter().all(|entry| {
        let identity = entry.identity.as_ref().expect("validated above");
        root_ids.contains(&identity.scan_root_id)
            && identity
                .parent_id
                .as_ref()
                .is_some_and(|parent| all_ids.contains(parent))
    })
}

fn entry_is_complete_live(entry: &ScannedEntry) -> bool {
    entry.coverage.state == CoverageState::Complete
        && entry.coverage.complete
        && !entry.coverage.details_lost
        && entry.coverage.incomplete_reasons.is_empty()
        && matches!(entry.provenance, FieldProvenance::LiveObservation { .. })
        && matches!(
            entry.coverage.provenance,
            FieldProvenance::LiveObservation { .. }
        )
}

fn native_name_to_utf8(name: &NativeName) -> Option<String> {
    match name {
        NativeName::UnixBytes(bytes) => std::str::from_utf8(bytes).ok().map(ToOwned::to_owned),
        NativeName::WindowsUtf16(units) => String::from_utf16(units).ok(),
    }
}

fn native_name_equals(name: &NativeName, expected: &str) -> bool {
    match name {
        NativeName::UnixBytes(bytes) => bytes.as_slice() == expected.as_bytes(),
        NativeName::WindowsUtf16(units) => units.iter().copied().eq(expected.encode_utf16()),
    }
}

fn locator_components_share_scope(locator: &sweepx_model::NativeLocatorEvidence) -> bool {
    let expected_domain = &locator.scan_root.filesystem_object_domain_identity;
    let expected_mount = &locator.scan_root.volume_or_mount_identity;
    std::iter::once(&locator.scan_root)
        .chain(locator.parent_reopen_recipe.iter())
        .chain(std::iter::once(&locator.entry))
        .all(|component| {
            component.filesystem_object_domain_identity == *expected_domain
                && component.volume_or_mount_identity == *expected_mount
        })
}

fn locator_parents_are_backed_by_summary(
    summary: &ScanSummary,
    locator: &sweepx_model::NativeLocatorEvidence,
) -> bool {
    locator
        .parent_reopen_recipe
        .iter()
        .enumerate()
        .skip(1)
        .all(|(index, component)| {
            let matching = summary
                .entries
                .iter()
                .filter(|entry| {
                    entry
                        .identity
                        .as_ref()
                        .is_some_and(|identity| identity.entry_id == component.entry_id)
                })
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return false;
            }
            let entry = matching[0];
            let Ok(Some(entry_locator)) = entry.executable_native_locator() else {
                return false;
            };
            entry_is_complete_live(entry)
                && entry_locator.scan_root == locator.scan_root
                && entry_locator.scan_root_absolute_path == locator.scan_root_absolute_path
                && entry_locator.parent_reopen_recipe == locator.parent_reopen_recipe[..index]
                && entry_locator.entry == *component
        })
}

fn allowed_top_level_component(name: &str, object_type: &ObjectType) -> bool {
    // Cargo's target root contains profile directories plus a small set of Cargo-owned files and
    // directories. Unknown/custom components fail closed.
    const DIRECTORY_NAMES: &[&str] = &["debug", "doc", "package", "release", "tmp"];
    const FILE_NAMES: &[&str] = &[".rustc_info.json", "CACHEDIR.TAG"];
    match object_type {
        ObjectType::Directory => DIRECTORY_NAMES.contains(&name) || cargo_target_triple(name),
        ObjectType::File => FILE_NAMES.contains(&name),
        ObjectType::Symlink | ObjectType::ReparsePoint | ObjectType::Other => false,
    }
}

fn cargo_target_triple(name: &str) -> bool {
    const TESTED_TARGET_TRIPLES: &[&str] = &[
        "aarch64-apple-darwin",
        "aarch64-pc-windows-msvc",
        "aarch64-unknown-linux-gnu",
        "aarch64-unknown-linux-musl",
        "wasm32-unknown-unknown",
        "x86_64-apple-darwin",
        "x86_64-pc-windows-gnu",
        "x86_64-pc-windows-msvc",
        "x86_64-unknown-linux-gnu",
        "x86_64-unknown-linux-musl",
    ];
    TESTED_TARGET_TRIPLES.contains(&name)
}

fn unknown<T>(reason: CargoEvidenceReason) -> CargoEvidence<T> {
    CargoEvidence::Unknown { reason }
}

#[cfg(test)]
pub(crate) fn test_config_scope_projection(
    runtime: CargoConfigScopeRuntime,
) -> CargoConfigScopeProjectionV1 {
    let invocation = CargoInvocationContext {
        runtime,
        cwd: Err(CargoEvidenceReason::MissingIdentity),
        cargo_home_config: CargoHomeConfigCapture::NotChecked,
        cli_overrides_absent: true,
    };
    decode_config_scope(CargoConfigInputs {
        config: CargoConfigFile::VerifiedAbsent,
        config_toml: CargoConfigFile::VerifiedAbsent,
        scope: CargoConfigScopeInputs::production(&invocation),
    })
    .projected()
}

#[cfg(all(test, target_os = "linux"))]
mod linux_real_stack_tests {
    use super::*;

    use std::fs;

    use crate::{HostPlatformScanner, Scanner, ScannerOptions};
    use sweepx_model::ScanId;
    use sweepx_platform::ScanRoot;

    fn scan(root: &std::path::Path, scan_id: &str) -> crate::ScanSummary {
        Scanner::new(
            HostPlatformScanner::new(),
            ScannerOptions {
                scan_id: ScanId::new(scan_id),
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(root.to_path_buf()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap()
    }

    fn reader() -> LocatorReader<HostPlatformScanner> {
        LocatorReader::new(
            HostPlatformScanner::new(),
            cargo_fixed_input_locator_limits(),
        )
    }

    fn assert_unknown<T: std::fmt::Debug>(
        evidence: CargoEvidence<T>,
        expected: CargoEvidenceReason,
    ) {
        assert_eq!(evidence.reason(), Some(expected), "{evidence:?}");
    }

    fn workspace_layout(
        scan_id: &str,
    ) -> (
        tempfile::TempDir,
        crate::ScanSummary,
        ScanEntryId,
        ScanEntryId,
    ) {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("workspace");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("Cargo.toml"), b"[workspace]\nmembers=[]\n").unwrap();
        fs::create_dir(root.join("target")).unwrap();
        fs::create_dir(root.join("target").join("debug")).unwrap();
        let summary = scan(&root, scan_id);
        let manifest_id = summary
            .entries
            .iter()
            .find(|entry| native_name_equals(&entry.native_basename, "Cargo.toml"))
            .and_then(|entry| entry.identity.as_ref())
            .map(|identity| identity.entry_id.clone())
            .expect("manifest entry");
        let target_id = summary
            .entries
            .iter()
            .find(|entry| native_name_equals(&entry.native_basename, "target"))
            .and_then(|entry| entry.identity.as_ref())
            .map(|identity| identity.entry_id.clone())
            .expect("target entry");
        (temp, summary, manifest_id, target_id)
    }

    #[test]
    fn explicit_cargo_home_config_presence_is_redacted_and_observed_once() {
        let (temp, summary, manifest_id, target_id) = workspace_layout("cargo-home-config-present");
        let root_id = summary.roots[0].identity.as_ref().unwrap().entry_id.clone();
        let cargo_home = temp.path().join("secret-explicit-cargo-home");
        fs::create_dir(&cargo_home).unwrap();
        let secret_contents = "secret-cargo-home-config-contents";
        fs::write(
            cargo_home.join("config.toml"),
            format!("[build]\ntarget-dir='{secret_contents}'\n"),
        )
        .unwrap();
        let reader = reader();
        let mut invocation = CargoInvocationContext::capture_for_sweepx_cli(
            CargoConfigScopeRuntime::from_presence(false, false, true),
            Some(cargo_home.as_os_str()),
            &reader,
            &CancellationToken::new(),
        );

        invocation.observe_cargo_home_config(&reader, &CancellationToken::new());
        assert!(matches!(
            invocation.cargo_home_config,
            CargoHomeConfigCapture::PresentRedacted
        ));

        // Observation is invocation-scoped. Once reduced to a redacted aggregate, later calls do
        // not reopen the path or change the result.
        fs::remove_file(cargo_home.join("config.toml")).unwrap();
        invocation.observe_cargo_home_config(&reader, &CancellationToken::new());
        let evidence = collect_and_produce_cargo_typed_evidence(
            &reader,
            &summary,
            &root_id,
            &manifest_id,
            &target_id,
            &invocation,
            &CancellationToken::new(),
        );
        let scope = &evidence.config_scope;

        assert!(matches!(
            scope.cargo_home_config,
            CargoConfigExternalSourceState::PresentRedacted
        ));
        assert!(
            scope
                .blockers
                .contains(&CargoConfigScopeBlocker::CargoHomeConfigPresentRedacted)
        );
        assert!(
            scope
                .blockers
                .contains(&CargoConfigScopeBlocker::CargoHomePresentRedacted)
        );
        assert_eq!(
            scope.environment.cargo_home.state,
            CargoEnvironmentPresence::PresentRedacted
        );
        assert!(matches!(
            scope.cli.target_dir,
            CargoConfigExternalSourceState::VerifiedAbsent
        ));
        assert!(matches!(
            scope.cli.config_overrides,
            CargoConfigExternalSourceState::VerifiedAbsent
        ));
        assert!(!scope.precedence_complete);
        assert!(matches!(
            &evidence.target_dir,
            CargoEvidence::NotChecked {
                reason: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert!(matches!(
            &evidence.target_shape,
            CargoEvidence::Unknown {
                reason: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert!(!evidence.candidate_allowed());
        assert!(!evidence.plan_allowed());

        let serialized = serde_json::to_string(&scope.projected()).unwrap();
        assert!(serialized.contains("\"cargoHomeConfig\":{\"state\":\"present_redacted\"}"));
        assert!(!serialized.contains(&cargo_home.to_string_lossy().to_string()));
        assert!(!serialized.contains(secret_contents));
    }

    #[test]
    fn explicit_cargo_home_non_atomic_absence_stays_not_checked() {
        let temp = tempfile::TempDir::new().unwrap();
        let cargo_home = temp.path().join("empty-explicit-cargo-home");
        fs::create_dir(&cargo_home).unwrap();
        let reader = reader();
        let mut absent = CargoInvocationContext::capture_for_sweepx_cli(
            CargoConfigScopeRuntime::from_presence(false, false, false),
            None,
            &reader,
            &CancellationToken::new(),
        );
        absent.observe_cargo_home_config(&reader, &CancellationToken::new());
        assert!(matches!(
            absent.cargo_home_config,
            CargoHomeConfigCapture::NotChecked
        ));
        let mut invocation = CargoInvocationContext::capture_for_sweepx_cli(
            CargoConfigScopeRuntime::from_presence(false, false, true),
            Some(cargo_home.as_os_str()),
            &reader,
            &CancellationToken::new(),
        );

        invocation.observe_cargo_home_config(&reader, &CancellationToken::new());
        let scope = decode_config_scope(CargoConfigInputs {
            config: CargoConfigFile::VerifiedAbsent,
            config_toml: CargoConfigFile::VerifiedAbsent,
            scope: CargoConfigScopeInputs::production(&invocation),
        });

        assert!(matches!(
            scope.cargo_home_config,
            CargoConfigExternalSourceState::NotChecked {
                reason_code: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert!(
            scope
                .blockers
                .contains(&CargoConfigScopeBlocker::CargoHomeConfigNotChecked)
        );
        assert!(
            !scope
                .blockers
                .contains(&CargoConfigScopeBlocker::CargoHomeConfigPresentRedacted)
        );
        assert!(!scope.precedence_complete);
    }

    #[test]
    fn explicit_cargo_home_invalid_capture_and_cancelled_observation_fail_closed() {
        let reader = reader();
        let invalid = CargoInvocationContext::capture_for_sweepx_cli(
            CargoConfigScopeRuntime::from_presence(false, false, true),
            Some(std::ffi::OsStr::new("relative-cargo-home-must-not-resolve")),
            &reader,
            &CancellationToken::new(),
        );
        assert!(matches!(
            invalid.cargo_home_config,
            CargoHomeConfigCapture::Failed(CargoEvidenceReason::MissingIdentity)
        ));
        let missing_absolute = tempfile::TempDir::new()
            .unwrap()
            .path()
            .join("missing-cargo-home");
        let capture_failed = CargoInvocationContext::capture_for_sweepx_cli(
            CargoConfigScopeRuntime::from_presence(false, false, true),
            Some(missing_absolute.as_os_str()),
            &reader,
            &CancellationToken::new(),
        );
        assert!(matches!(
            capture_failed.cargo_home_config,
            CargoHomeConfigCapture::Failed(CargoEvidenceReason::MissingIdentity)
        ));

        let temp = tempfile::TempDir::new().unwrap();
        let cargo_home = temp.path().join("cancelled-explicit-cargo-home");
        fs::create_dir(&cargo_home).unwrap();
        fs::write(cargo_home.join("config"), b"[build]\ntarget-dir='secret'\n").unwrap();
        let mut cancelled = CargoInvocationContext::capture_for_sweepx_cli(
            CargoConfigScopeRuntime::from_presence(false, false, true),
            Some(cargo_home.as_os_str()),
            &reader,
            &CancellationToken::new(),
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        cancelled.observe_cargo_home_config(&reader, &cancel);
        let scope = decode_config_scope(CargoConfigInputs {
            config: CargoConfigFile::VerifiedAbsent,
            config_toml: CargoConfigFile::VerifiedAbsent,
            scope: CargoConfigScopeInputs::production(&cancelled),
        });

        assert!(matches!(
            scope.cargo_home_config,
            CargoConfigExternalSourceState::Failed {
                reason_code: CargoEvidenceReason::Cancelled
            }
        ));
        assert!(
            scope
                .blockers
                .contains(&CargoConfigScopeBlocker::CargoHomeConfigFailed)
        );
        assert!(!scope.precedence_complete);
    }

    #[test]
    fn explicit_cargo_home_replacement_fails_closed() {
        let temp = tempfile::TempDir::new().unwrap();
        let cargo_home = temp.path().join("replaceable-explicit-cargo-home");
        let moved_home = temp.path().join("captured-explicit-cargo-home");
        fs::create_dir(&cargo_home).unwrap();
        fs::write(cargo_home.join("config"), b"[build]\ntarget-dir='secret'\n").unwrap();
        let reader = reader();
        let mut invocation = CargoInvocationContext::capture_for_unmodeled_caller(
            CargoConfigScopeRuntime::from_presence(false, false, true),
            Some(cargo_home.as_os_str()),
            &reader,
            &CancellationToken::new(),
        );

        fs::rename(&cargo_home, moved_home).unwrap();
        fs::create_dir(&cargo_home).unwrap();
        invocation.observe_cargo_home_config(&reader, &CancellationToken::new());
        let scope = decode_config_scope(CargoConfigInputs {
            config: CargoConfigFile::VerifiedAbsent,
            config_toml: CargoConfigFile::VerifiedAbsent,
            scope: CargoConfigScopeInputs::production(&invocation),
        });

        assert!(matches!(
            scope.cargo_home_config,
            CargoConfigExternalSourceState::Failed {
                reason_code: CargoEvidenceReason::ConfigReadFailed
            }
        ));
        assert!(
            scope
                .blockers
                .contains(&CargoConfigScopeBlocker::CargoHomeConfigFailed)
        );
        assert!(matches!(
            scope.cli.target_dir,
            CargoConfigExternalSourceState::NotChecked { .. }
        ));
        assert!(matches!(
            scope.cli.config_overrides,
            CargoConfigExternalSourceState::NotChecked { .. }
        ));
        assert!(!scope.precedence_complete);
    }

    #[test]
    fn collected_valid_workspace_manifest_is_known_but_target_config_scope_stays_not_checked() {
        let (_temp, mut summary, manifest_id, target_id) = workspace_layout("cargo-fixed-valid");
        summary.roots[0].display_path = "/forged/root".into();
        let root_id = summary.roots[0].identity.as_ref().unwrap().entry_id.clone();
        let evidence = collect_and_produce_cargo_typed_evidence(
            &reader(),
            &summary,
            &root_id,
            &manifest_id,
            &target_id,
            &CargoInvocationContext::unavailable_for_sweepx_cli(
                CargoConfigScopeRuntime::from_presence(false, false, false),
            ),
            &CancellationToken::new(),
        );

        assert!(matches!(evidence.workspace, CargoEvidence::Known { .. }));
        assert!(matches!(
            evidence.target_dir,
            CargoEvidence::NotChecked {
                reason: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert!(matches!(
            evidence.config_scope.workspace.config,
            CargoConfigFileState::NotChecked {
                reason_code: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert!(matches!(
            evidence.config_scope.workspace.config_toml,
            CargoConfigFileState::NotChecked {
                reason_code: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert_eq!(
            evidence.config_scope.workspace.selected,
            CargoWorkspaceConfigSelection::NotChecked
        );
        assert!(matches!(
            evidence.target_shape,
            CargoEvidence::Unknown {
                reason: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
    }

    #[test]
    fn invocation_cwd_records_only_an_exact_revalidated_workspace_path_match() {
        let (temp, summary, manifest_id, target_id) = workspace_layout("cargo-cwd-bound");
        let root_id = summary.roots[0].identity.as_ref().unwrap().entry_id.clone();
        let reader = reader();
        let invocation = CargoInvocationContext::with_cwd_path(
            CargoConfigScopeRuntime::from_presence(false, false, false),
            &temp.path().join("workspace"),
            true,
            &reader,
        );

        let evidence = collect_and_produce_cargo_typed_evidence(
            &reader,
            &summary,
            &root_id,
            &manifest_id,
            &target_id,
            &invocation,
            &CancellationToken::new(),
        );

        assert!(matches!(
            evidence.config_scope.invocation_cwd,
            CargoInvocationCwdBinding::PathMatchesRevalidatedWorkspaceRoot
        ));
        assert!(matches!(
            evidence.config_scope.cli.target_dir,
            CargoConfigExternalSourceState::VerifiedAbsent
        ));
        assert!(matches!(
            evidence.config_scope.cli.config_overrides,
            CargoConfigExternalSourceState::VerifiedAbsent
        ));
        assert!(
            !evidence
                .config_scope
                .blockers
                .contains(&CargoConfigScopeBlocker::InvocationCwdNotBound)
        );
        assert!(
            !evidence
                .config_scope
                .blockers
                .contains(&CargoConfigScopeBlocker::InvocationCwdBindingFailed)
        );
        assert!(
            evidence
                .config_scope
                .blockers
                .contains(&CargoConfigScopeBlocker::InvocationCwdIdentityNotBound)
        );
        assert!(!evidence.config_scope.precedence_complete);
        assert!(matches!(
            evidence.target_dir,
            CargoEvidence::NotChecked {
                reason: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        let serialized = serde_json::to_string(&evidence.config_scope.projected()).unwrap();
        assert!(!serialized.contains(&temp.path().to_string_lossy().to_string()));
    }

    #[test]
    fn invocation_cwd_mismatch_remains_unbound_without_changing_authority() {
        let (temp, summary, manifest_id, target_id) = workspace_layout("cargo-cwd-mismatch");
        let root_id = summary.roots[0].identity.as_ref().unwrap().entry_id.clone();
        let reader = reader();
        let invocation = CargoInvocationContext::with_cwd_path(
            CargoConfigScopeRuntime::from_presence(false, false, false),
            temp.path(),
            true,
            &reader,
        );

        let evidence = collect_and_produce_cargo_typed_evidence(
            &reader,
            &summary,
            &root_id,
            &manifest_id,
            &target_id,
            &invocation,
            &CancellationToken::new(),
        );

        assert!(matches!(
            evidence.config_scope.invocation_cwd,
            CargoInvocationCwdBinding::NotChecked {
                reason_code: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert!(
            evidence
                .config_scope
                .blockers
                .contains(&CargoConfigScopeBlocker::InvocationCwdNotBound)
        );
        assert!(!evidence.config_scope.precedence_complete);
        assert!(matches!(
            evidence.target_shape,
            CargoEvidence::Unknown {
                reason: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
    }

    #[test]
    fn missing_optional_config_files_do_not_claim_global_scope() {
        let (_temp, summary, manifest_id, target_id) =
            workspace_layout("cargo-fixed-optional-missing");
        let root_id = summary.roots[0].identity.as_ref().unwrap().entry_id.clone();

        let evidence = collect_and_produce_cargo_typed_evidence(
            &reader(),
            &summary,
            &root_id,
            &manifest_id,
            &target_id,
            &CargoInvocationContext::unavailable_for_sweepx_cli(
                CargoConfigScopeRuntime::from_presence(false, false, false),
            ),
            &CancellationToken::new(),
        );

        assert!(matches!(evidence.workspace, CargoEvidence::Known { .. }));
        assert!(matches!(
            evidence.target_dir,
            CargoEvidence::NotChecked {
                reason: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert!(matches!(
            evidence.config_scope.workspace.config,
            CargoConfigFileState::NotChecked {
                reason_code: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert!(matches!(
            evidence.config_scope.workspace.config_toml,
            CargoConfigFileState::NotChecked {
                reason_code: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert_eq!(
            evidence.config_scope.workspace.selected,
            CargoWorkspaceConfigSelection::NotChecked
        );
    }

    #[test]
    fn collector_records_workspace_declaration_without_promoting_effective_target() {
        let (temp, summary, manifest_id, target_id) =
            workspace_layout("cargo-fixed-workspace-declaration");
        let root = temp.path().join("workspace");
        fs::create_dir(root.join(".cargo")).unwrap();
        fs::write(
            root.join(".cargo").join("config.toml"),
            b"[build]\ntarget-dir='build/cargo'\n",
        )
        .unwrap();
        let root_id = summary.roots[0].identity.as_ref().unwrap().entry_id.clone();

        let evidence = collect_and_produce_cargo_typed_evidence(
            &reader(),
            &summary,
            &root_id,
            &manifest_id,
            &target_id,
            &CargoInvocationContext::unavailable_for_sweepx_cli(
                CargoConfigScopeRuntime::from_presence(true, true, true),
            ),
            &CancellationToken::new(),
        );

        assert!(matches!(
            evidence.config_scope.workspace.target_dir_declaration,
            CargoWorkspaceTargetDirDeclaration::Known {
                value: CargoWorkspaceTargetDirDeclarationV1 {
                    source: CargoTargetDirSource::ConfigToml,
                    ref relative_path,
                    ..
                }
            } if relative_path == "build/cargo"
        ));
        assert!(!evidence.config_scope.precedence_complete);
        assert!(matches!(
            evidence.target_dir,
            CargoEvidence::NotChecked {
                reason: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert!(matches!(
            evidence.target_shape,
            CargoEvidence::Unknown {
                reason: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
    }

    #[test]
    fn replaced_manifest_fails_closed() {
        let (temp, summary, manifest_id, target_id) =
            workspace_layout("cargo-fixed-replaced-manifest");
        let root = temp.path().join("workspace");
        let manifest_path = root.join("Cargo.toml");
        fs::rename(&manifest_path, root.join("Cargo.old.toml")).unwrap();
        fs::write(&manifest_path, b"[workspace]\nresolver='2'\n").unwrap();
        let root_id = summary.roots[0].identity.as_ref().unwrap().entry_id.clone();

        let evidence = collect_and_produce_cargo_typed_evidence(
            &reader(),
            &summary,
            &root_id,
            &manifest_id,
            &target_id,
            &CargoInvocationContext::unavailable_for_sweepx_cli(
                CargoConfigScopeRuntime::from_presence(false, false, false),
            ),
            &CancellationToken::new(),
        );

        assert_unknown(evidence.workspace, CargoEvidenceReason::MissingManifest);
        assert_unknown(evidence.target_dir, CargoEvidenceReason::MissingManifest);
        assert_unknown(evidence.target_shape, CargoEvidenceReason::MissingManifest);
    }

    #[test]
    fn symlink_config_fails_closed() {
        let (temp, summary, manifest_id, target_id) =
            workspace_layout("cargo-fixed-symlink-config");
        let root = temp.path().join("workspace");
        fs::create_dir(root.join(".cargo")).unwrap();
        fs::write(root.join("real-config"), b"[build]\ntarget-dir='target'\n").unwrap();
        std::os::unix::fs::symlink("../real-config", root.join(".cargo").join("config.toml"))
            .unwrap();
        let root_id = summary.roots[0].identity.as_ref().unwrap().entry_id.clone();

        let evidence = collect_and_produce_cargo_typed_evidence(
            &reader(),
            &summary,
            &root_id,
            &manifest_id,
            &target_id,
            &CargoInvocationContext::unavailable_for_sweepx_cli(
                CargoConfigScopeRuntime::from_presence(false, false, false),
            ),
            &CancellationToken::new(),
        );

        assert!(matches!(evidence.workspace, CargoEvidence::Known { .. }));
        assert_unknown(evidence.target_dir, CargoEvidenceReason::ConfigReadFailed);
        assert_unknown(evidence.target_shape, CargoEvidenceReason::ConfigReadFailed);
    }

    #[test]
    fn alias_collision_maps_to_pair_failed_and_does_not_upgrade_absence() {
        let (temp, summary, manifest_id, target_id) = workspace_layout("cargo-fixed-alias");
        let root = temp.path().join("workspace");
        fs::create_dir(root.join(".cargo")).unwrap();
        fs::write(
            root.join(".cargo").join("CONFIG"),
            b"[build]\ntarget-dir='alias'\n",
        )
        .unwrap();
        let root_id = summary.roots[0].identity.as_ref().unwrap().entry_id.clone();

        let evidence = collect_and_produce_cargo_typed_evidence(
            &reader(),
            &summary,
            &root_id,
            &manifest_id,
            &target_id,
            &CargoInvocationContext::unavailable_for_sweepx_cli(
                CargoConfigScopeRuntime::from_presence(false, false, false),
            ),
            &CancellationToken::new(),
        );

        assert!(matches!(evidence.workspace, CargoEvidence::Known { .. }));
        assert!(matches!(
            evidence.config_scope.workspace.pair_snapshot,
            CargoWorkspacePairState::Failed {
                reason_code: CargoEvidenceReason::AmbiguousConfig
            }
        ));
        assert!(
            evidence
                .config_scope
                .blockers
                .contains(&CargoConfigScopeBlocker::WorkspaceConfigNotChecked)
        );
        assert!(matches!(
            evidence.config_scope.workspace.config,
            CargoConfigFileState::Failed {
                reason_code: CargoEvidenceReason::AmbiguousConfig
            }
        ));
        assert!(matches!(
            evidence.config_scope.workspace.config_toml,
            CargoConfigFileState::Failed {
                reason_code: CargoEvidenceReason::AmbiguousConfig
            }
        ));
        assert_unknown(evidence.target_dir, CargoEvidenceReason::AmbiguousConfig);
        assert_unknown(evidence.target_shape, CargoEvidenceReason::AmbiguousConfig);
    }

    #[test]
    fn oversized_optional_config_fails_closed() {
        let (temp, summary, manifest_id, target_id) =
            workspace_layout("cargo-fixed-oversize-config");
        let root = temp.path().join("workspace");
        fs::create_dir(root.join(".cargo")).unwrap();
        fs::write(
            root.join(".cargo").join("config.toml"),
            vec![b'x'; MAX_CARGO_INPUT_FILE_BYTES + 1],
        )
        .unwrap();
        let root_id = summary.roots[0].identity.as_ref().unwrap().entry_id.clone();

        let evidence = collect_and_produce_cargo_typed_evidence(
            &LocatorReader::new(
                HostPlatformScanner::new(),
                cargo_fixed_input_locator_limits(),
            ),
            &summary,
            &root_id,
            &manifest_id,
            &target_id,
            &CargoInvocationContext::unavailable_for_sweepx_cli(
                CargoConfigScopeRuntime::from_presence(false, false, false),
            ),
            &CancellationToken::new(),
        );

        assert!(matches!(evidence.workspace, CargoEvidence::Known { .. }));
        assert_unknown(evidence.target_dir, CargoEvidenceReason::ResourceLimit);
        assert_unknown(evidence.target_shape, CargoEvidenceReason::ResourceLimit);
    }

    #[test]
    fn cancellation_fails_closed() {
        let (_temp, summary, manifest_id, target_id) = workspace_layout("cargo-fixed-cancelled");
        let root_id = summary.roots[0].identity.as_ref().unwrap().entry_id.clone();
        let cancel = CancellationToken::new();
        cancel.cancel();

        let evidence = collect_and_produce_cargo_typed_evidence(
            &reader(),
            &summary,
            &root_id,
            &manifest_id,
            &target_id,
            &CargoInvocationContext::unavailable_for_sweepx_cli(
                CargoConfigScopeRuntime::from_presence(false, false, false),
            ),
            &cancel,
        );

        assert_unknown(evidence.workspace, CargoEvidenceReason::Cancelled);
        assert_unknown(evidence.target_dir, CargoEvidenceReason::Cancelled);
        assert_unknown(evidence.target_shape, CargoEvidenceReason::Cancelled);
    }

    #[test]
    fn early_collection_failure_does_not_claim_cwd_binding_failure() {
        let (temp, mut summary, manifest_id, target_id) =
            workspace_layout("cargo-fixed-early-failure-cwd");
        let root_id = summary.roots[0].identity.as_ref().unwrap().entry_id.clone();
        summary.entries.retain(|entry| {
            entry.identity.as_ref().map(|identity| &identity.entry_id) != Some(&manifest_id)
        });
        let reader = reader();
        let invocation = CargoInvocationContext::with_cwd_path(
            CargoConfigScopeRuntime::from_presence(false, false, false),
            &temp.path().join("workspace"),
            true,
            &reader,
        );

        let evidence = collect_and_produce_cargo_typed_evidence(
            &reader,
            &summary,
            &root_id,
            &manifest_id,
            &target_id,
            &invocation,
            &CancellationToken::new(),
        );

        assert!(matches!(
            evidence.config_scope.invocation_cwd,
            CargoInvocationCwdBinding::NotChecked {
                reason_code: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert!(
            evidence
                .config_scope
                .blockers
                .contains(&CargoConfigScopeBlocker::InvocationCwdNotBound)
        );
        assert!(
            !evidence
                .config_scope
                .blockers
                .contains(&CargoConfigScopeBlocker::InvocationCwdBindingFailed)
        );
    }

    #[test]
    fn manifest_backend_failures_have_a_manifest_specific_reason() {
        for failure in [
            LocatorReadFailure::ReadFailed,
            LocatorReadFailure::ProviderOrOffline,
            LocatorReadFailure::Unavailable,
        ] {
            assert_eq!(
                map_manifest_read_failure(&failure),
                CargoEvidenceReason::ManifestReadFailed
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use sweepx_model::{
        ByteValue, Coverage, DecimalU128, DirectoryAggregate, EvidenceValue,
        FilesystemObjectDomainIdentity, MethodId, NativeAbsolutePath, NativeLocatorEvidence,
        NativePathComponent, PlatformFileIdentity, ReasonCode, ScanId, ScanObjectIdentity,
        VolumeOrMountIdentity,
    };
    use sweepx_platform::{BoundaryKind, BoundaryRecord};

    #[test]
    fn decodes_virtual_and_workspace_package_manifests() {
        assert_manifest_kind(
            b"[workspace]\nmembers=[]",
            CargoManifestKind::VirtualWorkspace,
        );
        assert_manifest_kind(
            b"[package]\nname='demo'\n[workspace]\nmembers=[]",
            CargoManifestKind::WorkspacePackage,
        );
    }

    #[test]
    fn package_only_or_invalid_package_manifest_is_not_workspace_evidence() {
        assert_unknown(
            decode_workspace_manifest(
                &entry_id_for(1),
                &entry_id_for(2),
                b"[package]\nname='demo'",
            ),
            CargoEvidenceReason::UnsupportedManifestShape,
        );
        for overlapping in [
            b"[workspace]\nmembers=['target/debug']".as_slice(),
            b"[workspace]\n[workspace.dependencies.local]\npath='../local'".as_slice(),
            b"[workspace]\n[patch.crates-io.local]\npath='../local'".as_slice(),
        ] {
            assert_unknown(
                decode_workspace_manifest(&entry_id_for(1), &entry_id_for(2), overlapping),
                CargoEvidenceReason::UnsupportedManifestShape,
            );
        }
        assert!(matches!(
            decode_workspace_manifest(
                &entry_id_for(1),
                &entry_id_for(2),
                b"[workspace]\n[workspace.metadata.tool]\npath='reporting-only'",
            ),
            CargoEvidence::Known { .. }
        ));
        for dependency in [
            b"[workspace]\n[replace]\n'old:1.0.0'={path='../local'}".as_slice(),
            b"[workspace]\n[target.'cfg(unix)'.dev-dependencies.local]\npath='../local'".as_slice(),
            b"[workspace]\n[target.'cfg(unix)'.build-dependencies.local]\npath='../local'"
                .as_slice(),
        ] {
            assert_unknown(
                decode_workspace_manifest(&entry_id_for(1), &entry_id_for(2), dependency),
                CargoEvidenceReason::UnsupportedManifestShape,
            );
        }
        assert_unknown(
            decode_workspace_manifest(&entry_id_for(1), &entry_id_for(2), b"[package]"),
            CargoEvidenceReason::UnsupportedManifestShape,
        );
        for invalid in [
            b"[workspace]\nmembers='crate'".as_slice(),
            b"[workspace]\nexclude=[1]".as_slice(),
            b"[workspace]\ndefault-members=['']".as_slice(),
        ] {
            assert_unknown(
                decode_workspace_manifest(&entry_id_for(1), &entry_id_for(2), invalid),
                CargoEvidenceReason::UnsupportedManifestShape,
            );
        }
        assert_unknown(
            decode_workspace_manifest(&entry_id_for(1), &entry_id_for(2), b"[package]\nname='   '"),
            CargoEvidenceReason::UnsupportedManifestShape,
        );
    }

    #[test]
    fn manifest_parser_fails_closed_for_empty_malformed_duplicate_and_oversized_input() {
        assert_unknown(
            decode_workspace_manifest(&entry_id_for(1), &entry_id_for(2), b""),
            CargoEvidenceReason::MissingManifest,
        );
        assert_unknown(
            decode_workspace_manifest(&entry_id_for(1), &entry_id_for(2), b"[package"),
            CargoEvidenceReason::MalformedToml,
        );
        assert_unknown(
            decode_workspace_manifest(
                &entry_id_for(1),
                &entry_id_for(2),
                b"[package]\nname='one'\nname='two'",
            ),
            CargoEvidenceReason::DuplicateTomlKey,
        );
        assert_unknown(
            decode_workspace_manifest(
                &entry_id_for(1),
                &entry_id_for(2),
                &vec![b' '; MAX_CARGO_INPUT_FILE_BYTES + 1],
            ),
            CargoEvidenceReason::ResourceLimit,
        );
    }

    #[test]
    fn full_test_snapshot_can_decode_default_but_production_scope_never_does() {
        assert_target_dir(
            fully_closed_configs(),
            "target",
            CargoTargetDirSource::Default,
        );
        let production = CargoConfigInputs {
            config: CargoConfigFile::VerifiedAbsent,
            config_toml: CargoConfigFile::VerifiedAbsent,
            scope: CargoConfigScopeInputs::production(&CargoInvocationContext::unavailable(
                CargoConfigScopeRuntime::from_presence(false, false, false),
            )),
        };
        let scope = decode_config_scope(production);
        assert!(!scope.precedence_complete);
        assert!(matches!(
            decode_effective_target_dir(production, &scope),
            CargoEvidence::NotChecked {
                reason: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
    }

    #[test]
    fn workspace_config_precedence_parses_exact_target_dir_declaration() {
        let inputs = CargoConfigInputs {
            config: CargoConfigFile::Present(b"[build]\ntarget-dir='from-config'"),
            config_toml: CargoConfigFile::Present(b"[build]\ntarget-dir='ignored-toml'"),
            scope: fully_closed_scope(),
        };
        let scope = decode_config_scope(inputs);
        assert!(scope.precedence_complete);
        assert_eq!(
            scope.workspace.selected,
            CargoWorkspaceConfigSelection::Config
        );
        assert!(matches!(
            scope.workspace.target_dir_declaration,
            CargoWorkspaceTargetDirDeclaration::Known {
                value: CargoWorkspaceTargetDirDeclarationV1 {
                    source: CargoTargetDirSource::Config,
                    ref relative_path,
                    ..
                }
            } if relative_path == "from-config"
        ));
        assert_target_dir(inputs, "from-config", CargoTargetDirSource::Config);
    }

    #[test]
    fn literal_shell_like_characters_are_valid_relative_config_components() {
        for value in [
            "~cache",
            "dollar$target",
            "brace{target}",
            "percent%target",
            "build target",
        ] {
            let input = format!("[build]\ntarget-dir={value:?}");
            let inputs = CargoConfigInputs {
                config: CargoConfigFile::Present(input.as_bytes()),
                config_toml: CargoConfigFile::VerifiedAbsent,
                scope: fully_closed_scope(),
            };
            assert_target_dir(inputs, value, CargoTargetDirSource::Config);
        }
    }

    #[test]
    fn workspace_config_failures_are_typed_and_block_precedence() {
        for (bytes, reason, blocker) in [
            (
                b"[build]\ntarget-dir='a'\ntarget-dir='b'".as_slice(),
                CargoEvidenceReason::DuplicateTomlKey,
                CargoConfigScopeBlocker::WorkspaceConfigDuplicateKey,
            ),
            (
                b"[build".as_slice(),
                CargoEvidenceReason::MalformedToml,
                CargoConfigScopeBlocker::WorkspaceConfigMalformed,
            ),
            (
                b"include=['override.toml']\n[build]\ntarget-dir='target'".as_slice(),
                CargoEvidenceReason::UnsupportedConfigInclude,
                CargoConfigScopeBlocker::WorkspaceConfigIncludeUnsupported,
            ),
            (
                b"[build]\ntarget-dir='../custom'".as_slice(),
                CargoEvidenceReason::InvalidRelativeTargetDir,
                CargoConfigScopeBlocker::WorkspaceTargetDirInvalid,
            ),
        ] {
            let inputs = CargoConfigInputs {
                config: CargoConfigFile::Present(bytes),
                config_toml: CargoConfigFile::VerifiedAbsent,
                scope: fully_closed_scope(),
            };
            let scope = decode_config_scope(inputs);
            assert!(!scope.precedence_complete);
            assert!(scope.blockers.contains(&blocker));
            assert!(matches!(
                scope.workspace.target_dir_declaration,
                CargoWorkspaceTargetDirDeclaration::Unknown { reason_code } if reason_code == reason
            ));
            let (mut summary, target_id) = shape_summary(&[("debug", ObjectType::Directory)]);
            summary
                .entries
                .push(scan_entry(5, 1, Some(1), "Cargo.toml", ObjectType::File));
            let expected_target_reason = if reason == CargoEvidenceReason::UnsupportedConfigInclude
            {
                CargoEvidenceReason::UnsupportedManifestShape
            } else {
                reason
            };
            assert_unknown(
                produce_cargo_typed_evidence(
                    HandleBoundCargoInputs {
                        root_entry_id: &entry_id_for(1),
                        manifest_entry_id: &entry_id_for(5),
                        manifest_bytes: b"[workspace]",
                        config_inputs: inputs,
                        target_entry_id: &target_id,
                    },
                    &summary,
                )
                .target_dir,
                expected_target_reason,
            );
        }
    }

    #[test]
    fn config_scope_serialization_is_redacted_and_blockers_are_sorted_and_deduplicated() {
        let inputs = CargoConfigInputs {
            config: CargoConfigFile::VerifiedAbsent,
            config_toml: CargoConfigFile::VerifiedAbsent,
            scope: CargoConfigScopeInputs::production(&CargoInvocationContext::unavailable(
                CargoConfigScopeRuntime::from_presence(true, true, true),
            )),
        };
        let mut scope = decode_config_scope(inputs);
        scope
            .blockers
            .push(CargoConfigScopeBlocker::CargoTargetDirPresentRedacted);
        normalize_config_scope(&mut scope);
        assert!(scope.blockers.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            scope
                .blockers
                .iter()
                .filter(|blocker| {
                    **blocker == CargoConfigScopeBlocker::CargoTargetDirPresentRedacted
                })
                .count(),
            1
        );

        let serialized = serde_json::to_string(&scope.projected()).unwrap();
        assert!(serialized.contains("CARGO_TARGET_DIR"));
        assert!(serialized.contains("CARGO_BUILD_TARGET_DIR"));
        assert!(serialized.contains("CARGO_HOME"));
        assert!(serialized.contains("present_redacted"));
        for secret in ["/secret/target", "/secret/cargo-home", "non-unicode"] {
            assert!(!serialized.contains(secret));
        }
    }

    #[test]
    fn external_presence_states_have_source_specific_blockers() {
        let scope = decode_config_scope(CargoConfigInputs {
            config: CargoConfigFile::VerifiedAbsent,
            config_toml: CargoConfigFile::VerifiedAbsent,
            scope: CargoConfigScopeInputs {
                runtime: CargoConfigScopeRuntime::from_presence(false, false, false),
                workspace_pair: CargoWorkspacePairInput::StableSnapshot,
                ancestor_configs: CargoConfigExternalSourceInput::PresentRedacted,
                cargo_home_config: CargoConfigExternalSourceInput::PresentRedacted,
                cli_target_dir: CargoConfigExternalSourceInput::VerifiedAbsent,
                cli_config_overrides: CargoConfigExternalSourceInput::VerifiedAbsent,
                invocation_cwd: CargoInvocationCwdInput::BoundToWorkspaceRoot,
            },
        });

        assert!(matches!(
            scope.ancestor_configs,
            CargoConfigExternalSourceState::PresentRedacted
        ));
        assert!(matches!(
            scope.cargo_home_config,
            CargoConfigExternalSourceState::PresentRedacted
        ));
        assert_eq!(
            scope.blockers,
            vec![
                CargoConfigScopeBlocker::AncestorConfigsPresentRedacted,
                CargoConfigScopeBlocker::CargoHomeConfigPresentRedacted,
            ]
        );
        assert!(!scope.precedence_complete);
    }

    #[test]
    fn absent_cargo_home_and_library_cli_defaults_remain_not_checked() {
        let cli = CargoInvocationContext::unavailable_for_sweepx_cli(
            CargoConfigScopeRuntime::from_presence(false, false, false),
        );
        let library = CargoInvocationContext::unavailable(CargoConfigScopeRuntime::from_presence(
            false, false, false,
        ));

        for invocation in [&cli, &library] {
            let scope = decode_config_scope(CargoConfigInputs {
                config: CargoConfigFile::VerifiedAbsent,
                config_toml: CargoConfigFile::VerifiedAbsent,
                scope: CargoConfigScopeInputs::production(invocation),
            });
            assert!(matches!(
                scope.cargo_home_config,
                CargoConfigExternalSourceState::NotChecked {
                    reason_code: CargoEvidenceReason::ConfigScopeNotChecked
                }
            ));
            assert!(
                scope
                    .blockers
                    .contains(&CargoConfigScopeBlocker::CargoHomeConfigNotChecked)
            );
        }

        let cli_scope = CargoConfigScopeInputs::production(&cli);
        assert_eq!(
            cli_scope.cli_target_dir,
            CargoConfigExternalSourceInput::VerifiedAbsent
        );
        assert_eq!(
            cli_scope.cli_config_overrides,
            CargoConfigExternalSourceInput::VerifiedAbsent
        );
        let library_scope = CargoConfigScopeInputs::production(&library);
        assert_eq!(
            library_scope.cli_target_dir,
            CargoConfigExternalSourceInput::NotChecked
        );
        assert_eq!(
            library_scope.cli_config_overrides,
            CargoConfigExternalSourceInput::NotChecked
        );
    }

    #[test]
    fn unmodeled_library_invocation_keeps_cli_sources_not_checked() {
        let invocation = CargoInvocationContext::unavailable(
            CargoConfigScopeRuntime::from_presence(false, false, false),
        );
        let scope = decode_config_scope(CargoConfigInputs {
            config: CargoConfigFile::VerifiedAbsent,
            config_toml: CargoConfigFile::VerifiedAbsent,
            scope: CargoConfigScopeInputs::production(&invocation),
        });

        assert!(matches!(
            scope.cli.target_dir,
            CargoConfigExternalSourceState::NotChecked {
                reason_code: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert!(matches!(
            scope.cli.config_overrides,
            CargoConfigExternalSourceState::NotChecked {
                reason_code: CargoEvidenceReason::ConfigScopeNotChecked
            }
        ));
        assert!(
            scope
                .blockers
                .contains(&CargoConfigScopeBlocker::CliTargetDirNotChecked)
        );
        assert!(
            scope
                .blockers
                .contains(&CargoConfigScopeBlocker::CliConfigOverridesNotChecked)
        );
        assert!(!scope.precedence_complete);
    }

    #[test]
    fn sealed_source_failures_and_cwd_binding_are_explicit() {
        let inputs = CargoConfigInputs {
            config: CargoConfigFile::VerifiedAbsent,
            config_toml: CargoConfigFile::VerifiedAbsent,
            scope: CargoConfigScopeInputs {
                runtime: CargoConfigScopeRuntime::from_presence(false, false, false),
                workspace_pair: CargoWorkspacePairInput::Failed(
                    CargoEvidenceReason::ConfigReadFailed,
                ),
                ancestor_configs: CargoConfigExternalSourceInput::Failed(
                    CargoEvidenceReason::ConfigReadFailed,
                ),
                cargo_home_config: CargoConfigExternalSourceInput::NotChecked,
                cli_target_dir: CargoConfigExternalSourceInput::VerifiedAbsent,
                cli_config_overrides: CargoConfigExternalSourceInput::Failed(
                    CargoEvidenceReason::ConfigReadFailed,
                ),
                invocation_cwd: CargoInvocationCwdInput::Failed(
                    CargoEvidenceReason::MissingIdentity,
                ),
            },
        };
        let scope = decode_config_scope(inputs);
        assert!(!scope.precedence_complete);
        assert_eq!(
            scope.blockers,
            vec![
                CargoConfigScopeBlocker::AncestorConfigsFailed,
                CargoConfigScopeBlocker::CargoHomeConfigNotChecked,
                CargoConfigScopeBlocker::CliConfigOverridesFailed,
                CargoConfigScopeBlocker::InvocationCwdBindingFailed,
                CargoConfigScopeBlocker::WorkspaceConfigPairFailed,
            ]
        );
    }

    #[test]
    fn aggregate_budget_enforces_per_file_and_total_caps() {
        assert_eq!(
            validate_input_budget([CargoInputFile {
                name: "Cargo.toml",
                bytes: &vec![0; MAX_CARGO_INPUT_FILE_BYTES + 1],
            }]),
            Err(CargoEvidenceReason::ResourceLimit)
        );
        let full = vec![0; MAX_CARGO_INPUT_FILE_BYTES];
        assert_eq!(
            validate_input_budget([
                CargoInputFile {
                    name: "Cargo.toml",
                    bytes: &full
                },
                CargoInputFile {
                    name: "Cargo.lock",
                    bytes: &full
                },
                CargoInputFile {
                    name: ".cargo/config",
                    bytes: &full
                },
                CargoInputFile {
                    name: ".cargo/config.toml",
                    bytes: &full
                },
            ]),
            Ok(())
        );
        assert_eq!(
            validate_input_budget([
                CargoInputFile {
                    name: "Cargo.toml",
                    bytes: &full,
                },
                CargoInputFile {
                    name: "Cargo.lock",
                    bytes: &full,
                },
                CargoInputFile {
                    name: ".cargo/config",
                    bytes: &full,
                },
                CargoInputFile {
                    name: ".cargo/config.toml",
                    bytes: &full,
                },
                CargoInputFile {
                    name: "Cargo.lock",
                    bytes: &[0],
                },
            ]),
            Err(CargoEvidenceReason::ResourceLimit)
        );
    }

    #[test]
    fn shape_classifier_recognizes_only_complete_identity_bound_allowlisted_children() {
        let (summary, target_id) = shape_summary(&[
            ("debug", ObjectType::Directory),
            ("CACHEDIR.TAG", ObjectType::File),
        ]);
        let evidence = classify_target_shape(&summary, &target_id);
        let CargoEvidence::Known { value } = evidence else {
            panic!("expected known evidence: {evidence:?}");
        };
        assert_eq!(
            value.classification,
            CargoTargetShape::RecognizedGeneratedStructure
        );
        assert_eq!(
            value.observed_top_level_components,
            vec!["CACHEDIR.TAG", "debug"]
        );
    }

    #[test]
    fn shape_classifier_rejects_unknown_link_boundary_incomplete_and_missing_identity() {
        let (summary, target_id) = shape_summary(&[("authored.txt", ObjectType::File)]);
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::UnexpectedTargetComponent,
        );

        let (summary, target_id) = shape_summary(&[("debug", ObjectType::Symlink)]);
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::UnknownObjectType,
        );

        let (mut summary, target_id) = shape_summary(&[("debug", ObjectType::Directory)]);
        summary.boundaries.push(BoundaryRecord {
            path: "/display/only".into(),
            kind: BoundaryKind::Symlink,
            reason: ReasonCode::StrictReadOnly,
            detail: "boundary".into(),
        });
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::BoundaryPresent,
        );

        let (mut summary, target_id) = shape_summary(&[("debug", ObjectType::Directory)]);
        summary.entries[1].coverage.complete = false;
        summary.entries[1].coverage.state = CoverageState::Incomplete;
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::IncompleteScan,
        );

        let (mut summary, target_id) = shape_summary(&[("debug", ObjectType::Directory)]);
        summary.entries[1].identity = None;
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::MissingIdentity,
        );

        let (mut summary, target_id) = shape_summary(&[
            ("debug", ObjectType::Directory),
            ("release", ObjectType::Directory),
        ]);
        summary.entries[2].identity.as_mut().unwrap().entry_id = summary.entries[1]
            .identity
            .as_ref()
            .unwrap()
            .entry_id
            .clone();
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::MissingIdentity,
        );

        let (mut summary, target_id) = shape_summary(&[("debug", ObjectType::Directory)]);
        summary.aggregates.clear();
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::MissingTargetAggregate,
        );

        let (mut summary, target_id) = shape_summary(&[("debug", ObjectType::Directory)]);
        summary.progress.clear();
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::IncompleteScan,
        );

        let (mut summary, target_id) = shape_summary(&[("debug", ObjectType::Directory)]);
        summary.progress.push(ProgressEvent::RootAccepted {
            path: "/after-finished".into(),
        });
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::IncompleteScan,
        );

        let (mut summary, target_id) = shape_summary(&[("debug", ObjectType::Directory)]);
        summary.progress.insert(0, ProgressEvent::Finished);
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::IncompleteScan,
        );

        let (mut summary, target_id) = shape_summary(&[("debug", ObjectType::Directory)]);
        summary.entries[1].native_locator = None;
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::MissingIdentity,
        );

        let (summary, target_id) = shape_summary(&[("my-authored-assets", ObjectType::Directory)]);
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::UnexpectedTargetComponent,
        );
    }

    #[test]
    fn bound_workspace_requires_live_direct_child_identity_not_display_paths() {
        let (mut summary, _) = shape_summary(&[("debug", ObjectType::Directory)]);
        summary
            .entries
            .push(scan_entry(5, 1, Some(1), "Cargo.toml", ObjectType::File));
        let known = decode_bound_workspace_manifest(
            &summary,
            &entry_id_for(1),
            &entry_id_for(5),
            b"[workspace]",
        );
        assert!(matches!(known, CargoEvidence::Known { .. }));

        summary
            .entries
            .last_mut()
            .unwrap()
            .identity
            .as_mut()
            .unwrap()
            .parent_id = Some(entry_id_for(2));
        summary.entries.last_mut().unwrap().display_path = "/display/Cargo.toml".into();
        assert_unknown(
            decode_bound_workspace_manifest(
                &summary,
                &entry_id_for(1),
                &entry_id_for(5),
                b"[workspace]",
            ),
            CargoEvidenceReason::MissingIdentity,
        );

        let (mut summary, _) = shape_summary(&[("debug", ObjectType::Directory)]);
        summary
            .entries
            .push(scan_entry(5, 1, Some(1), "Cargo.toml", ObjectType::File));
        summary
            .entries
            .last_mut()
            .unwrap()
            .native_locator
            .as_mut()
            .unwrap()
            .scan_root_absolute_path = Some(other_native_absolute_root());
        assert_unknown(
            decode_bound_workspace_manifest(
                &summary,
                &entry_id_for(1),
                &entry_id_for(5),
                b"[workspace]",
            ),
            CargoEvidenceReason::MissingIdentity,
        );
    }

    #[test]
    fn bound_target_validates_absolute_root_and_every_intermediate_scope() {
        let (mut summary, target_id) = nested_target_summary();
        let workspace = workspace_fact();
        let target_dir = target_dir_fact(&["build", "cargo"]);
        assert!(matches!(
            classify_bound_target_shape(&summary, &workspace, &target_dir, &target_id),
            CargoEvidence::Known { .. }
        ));

        summary.entries[0]
            .native_locator
            .as_mut()
            .unwrap()
            .parent_reopen_recipe[1]
            .filesystem_object_domain_identity =
            IdentityEvidence::known(FilesystemObjectDomainIdentity {
                device: DecimalU128::new(99),
            });
        assert_unknown(
            classify_bound_target_shape(&summary, &workspace, &target_dir, &target_id),
            CargoEvidenceReason::MissingIdentity,
        );

        let (mut summary, target_id) = nested_target_summary();
        summary.entries[0]
            .native_locator
            .as_mut()
            .unwrap()
            .scan_root_absolute_path = Some(other_native_absolute_root());
        assert_unknown(
            classify_bound_target_shape(&summary, &workspace, &target_dir, &target_id),
            CargoEvidenceReason::MissingIdentity,
        );
    }

    #[test]
    fn target_child_requires_exact_executable_parent_locator() {
        let (mut summary, target_id) = shape_summary(&[("debug", ObjectType::Directory)]);
        summary.entries[1]
            .native_locator
            .as_mut()
            .unwrap()
            .scan_root_absolute_path = Some(other_native_absolute_root());
        assert_unknown(
            classify_target_shape(&summary, &target_id),
            CargoEvidenceReason::MissingIdentity,
        );
    }

    #[test]
    fn combined_evidence_keeps_sharing_and_activity_not_checked_and_cannot_authorize() {
        let (mut summary, target_id) = shape_summary(&[("debug", ObjectType::Directory)]);
        summary
            .entries
            .push(scan_entry(5, 1, Some(1), "Cargo.toml", ObjectType::File));
        let input = HandleBoundCargoInputs {
            root_entry_id: &entry_id_for(1),
            manifest_entry_id: &entry_id_for(5),
            manifest_bytes: b"[workspace]",
            config_inputs: fully_closed_configs(),
            target_entry_id: &target_id,
        };
        let evidence = produce_cargo_typed_evidence(input, &summary);
        assert!(matches!(evidence.workspace, CargoEvidence::Known { .. }));
        assert!(matches!(evidence.target_dir, CargoEvidence::Known { .. }));
        assert!(matches!(evidence.target_shape, CargoEvidence::Known { .. }));
        assert_eq!(
            evidence.not_shared.reason(),
            Some(CargoEvidenceReason::SharingNotChecked)
        );
        assert_eq!(
            evidence.activity.reason(),
            Some(CargoEvidenceReason::ActivityNotChecked)
        );
        assert!(!evidence.candidate_allowed());
        assert!(!evidence.plan_allowed());
    }

    fn assert_manifest_kind(bytes: &[u8], expected: CargoManifestKind) {
        let evidence = decode_workspace_manifest(&entry_id_for(1), &entry_id_for(2), bytes);
        let CargoEvidence::Known { value } = evidence else {
            panic!("expected known evidence: {evidence:?}");
        };
        assert_eq!(value.manifest_kind, expected);
        assert_eq!(value.workspace_id, entry_id_for(1).to_string());
    }

    fn assert_target_dir(
        inputs: CargoConfigInputs<'_>,
        expected: &str,
        source: CargoTargetDirSource,
    ) {
        let scope = decode_config_scope(inputs);
        let evidence = decode_effective_target_dir(inputs, &scope);
        let CargoEvidence::Known { value } = evidence else {
            panic!("expected known evidence: {evidence:?}");
        };
        assert_eq!(value.relative_path, expected);
        assert_eq!(value.source, source);
    }

    fn fully_closed_scope() -> CargoConfigScopeInputs {
        CargoConfigScopeInputs {
            runtime: CargoConfigScopeRuntime::from_presence(false, false, false),
            workspace_pair: CargoWorkspacePairInput::StableSnapshot,
            ancestor_configs: CargoConfigExternalSourceInput::VerifiedAbsent,
            cargo_home_config: CargoConfigExternalSourceInput::VerifiedAbsent,
            cli_target_dir: CargoConfigExternalSourceInput::VerifiedAbsent,
            cli_config_overrides: CargoConfigExternalSourceInput::VerifiedAbsent,
            invocation_cwd: CargoInvocationCwdInput::BoundToWorkspaceRoot,
        }
    }

    fn fully_closed_configs() -> CargoConfigInputs<'static> {
        CargoConfigInputs {
            config: CargoConfigFile::VerifiedAbsent,
            config_toml: CargoConfigFile::VerifiedAbsent,
            scope: fully_closed_scope(),
        }
    }

    fn workspace_fact() -> CargoWorkspaceEvidenceV1 {
        CargoWorkspaceEvidenceV1 {
            schema: CARGO_WORKSPACE_EVIDENCE_SCHEMA,
            decoder_id: CARGO_CONFIG_DECODER_ID,
            workspace_id: entry_id_for(1).to_string(),
            root_entry_id: entry_id_for(1),
            manifest_entry_id: entry_id_for(5),
            manifest_kind: CargoManifestKind::VirtualWorkspace,
        }
    }

    fn target_dir_fact(components: &[&str]) -> CargoTargetDirEvidenceV1 {
        CargoTargetDirEvidenceV1 {
            schema: CARGO_TARGET_DIR_EVIDENCE_SCHEMA,
            decoder_id: CARGO_CONFIG_DECODER_ID,
            relative_components: components
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            relative_path: components.join("/"),
            source: CargoTargetDirSource::Default,
        }
    }

    fn assert_unknown<T: std::fmt::Debug>(
        evidence: CargoEvidence<T>,
        expected: CargoEvidenceReason,
    ) {
        assert_eq!(evidence.reason(), Some(expected), "{evidence:?}");
    }

    fn shape_summary(children: &[(&str, ObjectType)]) -> (ScanSummary, ScanEntryId) {
        let root = scan_entry(1, 1, None, "workspace", ObjectType::Directory);
        let target = scan_entry(2, 1, Some(1), "target", ObjectType::Directory);
        let target_id = entry_id_for(2);
        let mut entries = vec![target];
        entries.extend(children.iter().enumerate().map(|(index, (name, kind))| {
            scan_entry(index as u128 + 3, 1, Some(2), name, kind.clone())
        }));
        (
            ScanSummary {
                roots: vec![root],
                entries,
                aggregates: vec![target_aggregate(&target_id, children.len() as u128)],
                boundaries: Vec::new(),
                progress: vec![ProgressEvent::Finished],
            },
            target_id,
        )
    }

    fn nested_target_summary() -> (ScanSummary, ScanEntryId) {
        let (mut summary, target_id) = shape_summary(&[("debug", ObjectType::Directory)]);
        let root_component = summary.roots[0]
            .executable_native_locator()
            .unwrap()
            .unwrap()
            .scan_root
            .clone();
        let build_id = entry_id_for(6);
        let build_component = NativePathComponent {
            entry_id: build_id.clone(),
            parent_id: Some(entry_id_for(1)),
            native_basename: native_name("build"),
            object_type: ObjectType::Directory,
            platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                device: DecimalU128::new(1),
                inode: DecimalU128::new(6),
            }),
            filesystem_object_domain_identity: IdentityEvidence::known(
                FilesystemObjectDomainIdentity {
                    device: DecimalU128::new(1),
                },
            ),
            volume_or_mount_identity: IdentityEvidence::known(VolumeOrMountIdentity {
                value: DecimalU128::new(1),
            }),
            metadata_fingerprint: "fp-6".into(),
        };
        let (target_entries, child_entries) = summary.entries.split_at_mut(1);
        let target = &mut target_entries[0];
        target.identity.as_mut().unwrap().parent_id = Some(build_id.clone());
        target.native_basename = native_name("cargo");
        let target_locator = target.native_locator.as_mut().unwrap();
        target_locator.parent_reopen_recipe = vec![root_component.clone(), build_component.clone()];
        target_locator.entry.parent_id = Some(build_id);
        target_locator.entry.native_basename = native_name("cargo");

        let target_component = target_locator.entry.clone();
        let child_locator = child_entries[0].native_locator.as_mut().unwrap();
        child_locator.parent_reopen_recipe = vec![
            root_component.clone(),
            build_component.clone(),
            target_component,
        ];
        let build_identity = ScanObjectIdentity {
            entry_id: build_component.entry_id.clone(),
            scan_root_id: entry_id_for(1),
            parent_id: build_component.parent_id.clone(),
            platform_file_identity: build_component.platform_file_identity.clone(),
            filesystem_object_domain_identity: build_component
                .filesystem_object_domain_identity
                .clone(),
            volume_or_mount_identity: build_component.volume_or_mount_identity.clone(),
        };
        summary.entries.push(ScannedEntry {
            scan_id: scan_id(),
            identity: Some(build_identity),
            native_locator: Some(NativeLocatorEvidence {
                scan_root: root_component.clone(),
                scan_root_absolute_path: Some(native_absolute_root()),
                parent_reopen_recipe: vec![root_component],
                entry: build_component,
            }),
            display_path: "/display/build".into(),
            native_basename: native_name("build"),
            object_type: ObjectType::Directory,
            logical_bytes: known_bytes(),
            allocated_bytes: known_bytes(),
            reclaimable_estimate: known_bytes(),
            metadata_fingerprint: "fp-6".into(),
            coverage: complete_coverage(),
            provenance: live_provenance(),
        });
        (summary, target_id)
    }

    fn target_aggregate(target_id: &ScanEntryId, direct_child_count: u128) -> DirectoryAggregate {
        DirectoryAggregate {
            scan_id: scan_id(),
            directory_identity: target_id.to_string(),
            revision: DecimalU128::new(1),
            apparent_logical_bytes: known_bytes(),
            unique_logical_bytes: known_bytes(),
            filesystem_reported_allocated_bytes: known_bytes(),
            potentially_reclaimable_bytes: known_bytes(),
            direct_child_count: EvidenceValue::Known {
                value: DecimalU128::new(direct_child_count),
            },
            recursive_entry_count: known_bytes(),
            coverage: complete_coverage(),
            arithmetic_state: ArithmeticState::Exact,
        }
    }

    fn known_bytes() -> ByteValue {
        EvidenceValue::Known {
            value: DecimalU128::ZERO,
        }
    }

    fn scan_entry(
        ordinal: u128,
        root: u128,
        parent: Option<u128>,
        name: &str,
        kind: ObjectType,
    ) -> ScannedEntry {
        let identity = ScanObjectIdentity {
            entry_id: entry_id_for(ordinal),
            scan_root_id: entry_id_for(root),
            parent_id: parent.map(entry_id_for),
            platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                device: DecimalU128::new(1),
                inode: DecimalU128::new(ordinal),
            }),
            filesystem_object_domain_identity: IdentityEvidence::known(
                FilesystemObjectDomainIdentity {
                    device: DecimalU128::new(1),
                },
            ),
            volume_or_mount_identity: IdentityEvidence::known(VolumeOrMountIdentity {
                value: DecimalU128::new(1),
            }),
        };
        ScannedEntry {
            scan_id: scan_id(),
            identity: Some(identity.clone()),
            native_locator: Some(native_locator(&identity, name, kind.clone())),
            display_path: format!("/display/{name}"),
            native_basename: native_name(name),
            object_type: kind,
            logical_bytes: EvidenceValue::Known {
                value: DecimalU128::ZERO,
            },
            allocated_bytes: EvidenceValue::Known {
                value: DecimalU128::ZERO,
            },
            reclaimable_estimate: EvidenceValue::Known {
                value: DecimalU128::ZERO,
            },
            metadata_fingerprint: format!("fp-{ordinal}"),
            coverage: complete_coverage(),
            provenance: live_provenance(),
        }
    }

    fn native_locator(
        identity: &ScanObjectIdentity,
        name: &str,
        kind: ObjectType,
    ) -> NativeLocatorEvidence {
        let root_identity = ScanObjectIdentity {
            entry_id: identity.scan_root_id.clone(),
            scan_root_id: identity.scan_root_id.clone(),
            parent_id: None,
            platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                device: DecimalU128::new(1),
                inode: DecimalU128::new(1),
            }),
            filesystem_object_domain_identity: identity.filesystem_object_domain_identity.clone(),
            volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
        };
        let root_component =
            native_component(&root_identity, "workspace", ObjectType::Directory, "fp-1");
        let parent_reopen_recipe = match &identity.parent_id {
            None => Vec::new(),
            Some(parent_id) if parent_id == &identity.scan_root_id => vec![root_component.clone()],
            Some(parent_id) => vec![
                root_component.clone(),
                NativePathComponent {
                    entry_id: parent_id.clone(),
                    parent_id: Some(identity.scan_root_id.clone()),
                    native_basename: native_name("target"),
                    object_type: ObjectType::Directory,
                    platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                        device: DecimalU128::new(1),
                        inode: DecimalU128::new(2),
                    }),
                    filesystem_object_domain_identity: identity
                        .filesystem_object_domain_identity
                        .clone(),
                    volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
                    metadata_fingerprint: "fp-2".into(),
                },
            ],
        };
        NativeLocatorEvidence {
            scan_root: root_component.clone(),
            scan_root_absolute_path: Some(native_absolute_root()),
            parent_reopen_recipe,
            entry: if identity.parent_id.is_none() {
                root_component
            } else {
                native_component(
                    identity,
                    name,
                    kind,
                    &format!("fp-{}", entry_ordinal(identity)),
                )
            },
        }
    }

    fn native_component(
        identity: &ScanObjectIdentity,
        name: &str,
        kind: ObjectType,
        fingerprint: &str,
    ) -> NativePathComponent {
        NativePathComponent {
            entry_id: identity.entry_id.clone(),
            parent_id: identity.parent_id.clone(),
            native_basename: native_name(name),
            object_type: kind,
            platform_file_identity: identity.platform_file_identity.clone(),
            filesystem_object_domain_identity: identity.filesystem_object_domain_identity.clone(),
            volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
            metadata_fingerprint: fingerprint.into(),
        }
    }

    fn entry_ordinal(identity: &ScanObjectIdentity) -> u128 {
        identity
            .entry_id
            .to_string()
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }

    fn native_absolute_root() -> NativeAbsolutePath {
        #[cfg(unix)]
        {
            NativeAbsolutePath::unix(b"/scan/workspace".to_vec())
        }
        #[cfg(windows)]
        {
            NativeAbsolutePath::windows_utf16(
                r"C:\scan\workspace".encode_utf16().collect::<Vec<_>>(),
            )
        }
        #[cfg(not(any(unix, windows)))]
        {
            NativeAbsolutePath::unix(b"/scan/workspace".to_vec())
        }
    }

    fn other_native_absolute_root() -> NativeAbsolutePath {
        #[cfg(unix)]
        {
            NativeAbsolutePath::unix(b"/other/workspace".to_vec())
        }
        #[cfg(windows)]
        {
            NativeAbsolutePath::windows_utf16(
                r"C:\other\workspace".encode_utf16().collect::<Vec<_>>(),
            )
        }
        #[cfg(not(any(unix, windows)))]
        {
            NativeAbsolutePath::unix(b"/other/workspace".to_vec())
        }
    }

    fn scan_id() -> ScanId {
        ScanId::new("cargo-evidence-tests")
    }

    fn entry_id_for(ordinal: u128) -> ScanEntryId {
        ScanEntryId::for_scan_ordinal(&scan_id(), ordinal).unwrap()
    }

    fn native_name(value: &str) -> NativeName {
        #[cfg(unix)]
        {
            NativeName::unix(value.as_bytes().to_vec())
        }
        #[cfg(windows)]
        {
            NativeName::windows_utf16(value.encode_utf16().collect::<Vec<_>>())
        }
        #[cfg(not(any(unix, windows)))]
        {
            NativeName::unix(value.as_bytes().to_vec())
        }
    }

    fn live_provenance() -> FieldProvenance {
        FieldProvenance::LiveObservation {
            observed_at: "2026-08-28T00:00:00Z".into(),
            method: MethodId::NativeApi,
        }
    }

    fn complete_coverage() -> Coverage {
        Coverage {
            state: CoverageState::Complete,
            complete: true,
            incomplete_reasons: Vec::new(),
            details_lost: false,
            provenance: live_provenance(),
        }
    }
}
