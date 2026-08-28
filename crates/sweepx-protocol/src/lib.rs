use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    str::FromStr,
};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
pub use sweepx_model::CapabilityState;
use sweepx_model::{DecimalU128, OperationId, RequestId};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

pub const OUTPUT_SCHEMA: &str = "sweepx.output/v1";
pub const EVENT_SCHEMA: &str = "sweepx.event/v1";
pub const AUDIT_PROJECTION_SCHEMA: &str = "sweepx.audit-projection/v1";
pub const CAPABILITY_RECORD_SCHEMA: &str = "sweepx.capability-record/v1";
pub const PLAN_REVIEW_SCHEMA: &str = "sweepx.plan-review/v1";
pub const SOURCE_PLAN_SCHEMA: &str = "sweepx.plan/v1";
pub const MAX_CAPABILITY_CELL_BYTES: usize = 128;
pub const MAX_QUALIFICATION_TEXT_BYTES: usize = 512;
pub const MAX_QUALIFICATION_REASON_BYTES: usize = 4096;
pub const MAX_EVIDENCE_LIST_ITEMS: usize = 128;
pub const MAX_EVENT_ID_BYTES: usize = 128;
pub const MAX_EVENT_CURSOR_BYTES: usize = 1024;
pub const MAX_EVENT_TIMESTAMP_BYTES: usize = 64;
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MIN_DURABLE_CURSOR_TOKEN_BYTES: usize = 16;
pub const KNOWN_READ_ONLY_CAPABILITY_CELLS: [&str; 8] = [
    CapabilityCell::SCAN_LOCAL_DIRECTORY,
    CapabilityCell::SCAN_NDJSON_STREAM,
    CapabilityCell::OPERATION_SNAPSHOT_DURABLE,
    CapabilityCell::ANALYSIS_EXPLAIN_SCAN_JSON,
    CapabilityCell::CATALOG_CLEANER_READ,
    CapabilityCell::SCAN_TUI_LIVE,
    CapabilityCell::OPERATION_CANCEL,
    CapabilityCell::OPERATION_EVENT_COMPLETED_REPLAY,
];

/// A stable, bounded capability-cell identifier.
///
/// Capability cells deliberately bind an operation to its object and locality class. A broad
/// name such as `delete` is not a substitute for independent file and directory qualification.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct CapabilityCell(String);

impl CapabilityCell {
    pub const SCAN_LOCAL_DIRECTORY: &'static str = "scan.local.directory";
    pub const SCAN_NDJSON_STREAM: &'static str = "scan.ndjson.stream";
    pub const OPERATION_SNAPSHOT_DURABLE: &'static str = "operation.snapshot.durable";
    pub const ANALYSIS_EXPLAIN_SCAN_JSON: &'static str = "analysis.explain.scan_json";
    pub const CATALOG_CLEANER_READ: &'static str = "catalog.cleaner.read";
    pub const SCAN_TUI_LIVE: &'static str = "scan.tui.live";
    pub const OPERATION_CANCEL: &'static str = "operation.cancel";
    pub const OPERATION_EVENT_COMPLETED_REPLAY: &'static str = "operation.event.completed_replay";
    pub const TRASH_LOCAL_FILE: &'static str = "trash.local.file";
    pub const TRASH_LOCAL_DIRECTORY: &'static str = "trash.local.directory";
    pub const PERMANENT_LOCAL_FILE: &'static str = "permanent.local.file";
    pub const PERMANENT_LOCAL_DIRECTORY: &'static str = "permanent.local.directory";
    pub const PERMANENT_LOCAL_LINK: &'static str = "permanent.local.link";

    pub fn new(value: impl Into<String>) -> Result<Self, CapabilityCellError> {
        let value = value.into();
        validate_capability_cell(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns true unless the cell is an explicitly known read-only capability.
    ///
    /// This is intentionally an allowlist. Future or misspelled cells take the strong
    /// real-OS qualification path until the protocol explicitly classifies them read-only.
    pub fn requires_strong_qualification(&self) -> bool {
        !KNOWN_READ_ONLY_CAPABILITY_CELLS.contains(&self.as_str())
    }

    /// Compatibility name for the strong capability gate. Unknown cells return `true`.
    pub fn is_mutation(&self) -> bool {
        self.requires_strong_qualification()
    }
}

impl AsRef<str> for CapabilityCell {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for CapabilityCell {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CapabilityCell {
    type Err = CapabilityCellError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for CapabilityCell {
    type Error = CapabilityCellError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for CapabilityCell {
    type Error = CapabilityCellError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityCellError {
    Empty,
    TooLong { max_bytes: usize },
    InvalidSyntax,
}

impl fmt::Display for CapabilityCellError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("capability cell is empty"),
            Self::TooLong { max_bytes } => {
                write!(formatter, "capability cell exceeds {max_bytes} bytes")
            }
            Self::InvalidSyntax => formatter
                .write_str("capability cell must contain lowercase dotted identifier segments"),
        }
    }
}

impl Error for CapabilityCellError {}

fn validate_capability_cell(value: &str) -> Result<(), CapabilityCellError> {
    if value.is_empty() {
        return Err(CapabilityCellError::Empty);
    }
    if value.len() > MAX_CAPABILITY_CELL_BYTES {
        return Err(CapabilityCellError::TooLong {
            max_bytes: MAX_CAPABILITY_CELL_BYTES,
        });
    }

    let mut segment_count = 0usize;
    for segment in value.split('.') {
        segment_count += 1;
        let mut bytes = segment.bytes();
        if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(CapabilityCellError::InvalidSyntax);
        }
    }
    if segment_count < 2 {
        return Err(CapabilityCellError::InvalidSyntax);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Windows,
    Macos,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePrivilegeProfile {
    OrdinaryUser,
    Elevated,
    Unknown,
}

/// Selects which exact tuple owns the qualification.
///
/// Platform records cannot carry Cleaner identity. Cleaner records must carry both an exact
/// Cleaner ID and an exact full version. This prevents optional Cleaner metadata from changing
/// the meaning of an otherwise identical key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QualificationScope {
    Platform,
    Cleaner,
}

/// Provenance class for the referenced evidence bundle.
///
/// Only `real_os_qualification` may qualify a mutation cell. The explicitly non-qualifying
/// classes are retained on the wire so test and rejected evidence can be reported honestly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    DevelopmentSnapshot,
    FixtureConformanceOnly,
    RealOsQualification,
    Fake,
    Placeholder,
    Incomplete,
    Stale,
    Mismatched,
}

impl EvidenceClass {
    pub fn may_qualify_non_mutation(self) -> bool {
        matches!(self, Self::DevelopmentSnapshot | Self::RealOsQualification)
    }

    pub fn may_qualify_mutation(self) -> bool {
        self == Self::RealOsQualification
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QualificationValidityStatus {
    Current,
    Stale,
    Revoked,
    Invalidated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationValidity {
    pub status: QualificationValidityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalidation_reason: Option<String>,
}

pub type ValidityMetadata = QualificationValidity;
pub type ValidityStatus = QualificationValidityStatus;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationKey {
    pub scope: QualificationScope,
    pub core_version: String,
    pub scanner_semantics_version: u32,
    pub safety_policy_digest: String,
    pub adapter_id: String,
    pub adapter_digest: String,
    pub os_family: OsFamily,
    pub os_build: String,
    pub arch: String,
    pub filesystem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_version: Option<String>,
    pub volume_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_or_desktop_backend: Option<String>,
    pub runtime_privilege_profile: RuntimePrivilegeProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleaner_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleaner_version: Option<String>,
    pub capability: CapabilityCell,
}

impl QualificationKey {
    pub fn validate(&self) -> Result<(), CapabilityValidationError> {
        validate_bounded_text(&self.core_version, "qualificationKey.coreVersion")?;
        if self.scanner_semantics_version == 0 {
            return Err(CapabilityValidationError::InvalidScannerSemanticsVersion);
        }
        validate_bounded_text(
            &self.safety_policy_digest,
            "qualificationKey.safetyPolicyDigest",
        )?;
        validate_bounded_text(&self.adapter_id, "qualificationKey.adapterId")?;
        validate_bounded_text(&self.adapter_digest, "qualificationKey.adapterDigest")?;
        validate_bounded_text(&self.os_build, "qualificationKey.osBuild")?;
        validate_bounded_text(&self.arch, "qualificationKey.arch")?;
        validate_bounded_text(&self.filesystem, "qualificationKey.filesystem")?;
        validate_optional_bounded_text(
            self.filesystem_version.as_deref(),
            "qualificationKey.filesystemVersion",
        )?;
        validate_bounded_text(&self.volume_class, "qualificationKey.volumeClass")?;
        validate_optional_bounded_text(
            self.provider_or_desktop_backend.as_deref(),
            "qualificationKey.providerOrDesktopBackend",
        )?;
        validate_optional_bounded_text(self.cleaner_id.as_deref(), "qualificationKey.cleanerId")?;
        validate_optional_bounded_text(
            self.cleaner_version.as_deref(),
            "qualificationKey.cleanerVersion",
        )?;
        match self.scope {
            QualificationScope::Platform => {
                if self.cleaner_id.is_some() || self.cleaner_version.is_some() {
                    return Err(CapabilityValidationError::ScopeFieldMismatch {
                        scope: self.scope,
                    });
                }
            }
            QualificationScope::Cleaner => {
                let cleaner_id =
                    self.cleaner_id
                        .as_deref()
                        .ok_or(CapabilityValidationError::MissingField(
                            "qualificationKey.cleanerId",
                        ))?;
                let cleaner_version = self.cleaner_version.as_deref().ok_or(
                    CapabilityValidationError::MissingField("qualificationKey.cleanerVersion"),
                )?;
                validate_exact_value(cleaner_id, "qualificationKey.cleanerId")?;
                validate_exact_value(cleaner_version, "qualificationKey.cleanerVersion")?;
            }
        }
        validate_capability_cell(self.capability.as_str())
            .map_err(CapabilityValidationError::InvalidCapabilityCell)
    }

    pub fn is_mutation(&self) -> bool {
        self.capability.is_mutation()
    }

    fn validate_exact_mutation_tuple(&self) -> Result<(), CapabilityValidationError> {
        for (field, value) in [
            ("qualificationKey.coreVersion", self.core_version.as_str()),
            ("qualificationKey.adapterId", self.adapter_id.as_str()),
            ("qualificationKey.osBuild", self.os_build.as_str()),
            ("qualificationKey.arch", self.arch.as_str()),
            ("qualificationKey.filesystem", self.filesystem.as_str()),
            ("qualificationKey.volumeClass", self.volume_class.as_str()),
        ] {
            validate_exact_value(value, field)?;
        }
        validate_sha256_digest(
            &self.safety_policy_digest,
            "qualificationKey.safetyPolicyDigest",
        )?;
        validate_sha256_digest(&self.adapter_digest, "qualificationKey.adapterDigest")?;
        validate_exact_value(
            required_field(
                self.filesystem_version.as_deref(),
                "qualificationKey.filesystemVersion",
            )?,
            "qualificationKey.filesystemVersion",
        )?;
        validate_exact_value(
            required_field(
                self.provider_or_desktop_backend.as_deref(),
                "qualificationKey.providerOrDesktopBackend",
            )?,
            "qualificationKey.providerOrDesktopBackend",
        )?;
        if let (Some(cleaner_id), Some(cleaner_version)) =
            (self.cleaner_id.as_deref(), self.cleaner_version.as_deref())
        {
            validate_exact_value(cleaner_id, "qualificationKey.cleanerId")?;
            validate_exact_value(cleaner_version, "qualificationKey.cleanerVersion")?;
        }
        if self.volume_class != "local" {
            return Err(CapabilityValidationError::MutationTupleMismatch {
                field: "qualificationKey.volumeClass",
                expected: "local",
            });
        }
        if self.runtime_privilege_profile != RuntimePrivilegeProfile::OrdinaryUser {
            return Err(CapabilityValidationError::MutationTupleMismatch {
                field: "qualificationKey.runtimePrivilegeProfile",
                expected: "ordinary_user",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityEvidence {
    pub bundle_digest: String,
    pub evidence_class: EvidenceClass,
    pub reviewed_by: Vec<String>,
    pub limitations: Vec<String>,
    pub invalidates_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity: Option<QualificationValidity>,
}

pub type QualificationEvidence = CapabilityEvidence;

impl CapabilityEvidence {
    pub fn validate(&self) -> Result<(), CapabilityValidationError> {
        validate_bounded_text(&self.bundle_digest, "evidence.bundleDigest")?;
        validate_non_empty_list(&self.reviewed_by, "evidence.reviewedBy")?;
        validate_list(&self.limitations, "evidence.limitations", true)?;
        validate_non_empty_list(&self.invalidates_on, "evidence.invalidatesOn")?;
        if let Some(validity) = &self.validity {
            validity.validate()?;
        }
        Ok(())
    }
}

impl QualificationValidity {
    pub fn validate(&self) -> Result<(), CapabilityValidationError> {
        for (field, value) in [
            ("evidence.validity.validFrom", self.valid_from.as_deref()),
            ("evidence.validity.expiresAt", self.expires_at.as_deref()),
            (
                "evidence.validity.invalidatedAt",
                self.invalidated_at.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                validate_timestamp(value, field)?;
            }
        }
        validate_optional_reason(
            self.invalidation_reason.as_deref(),
            "evidence.validity.invalidationReason",
        )?;
        if let (Some(valid_from), Some(expires_at)) =
            (self.valid_from.as_deref(), self.expires_at.as_deref())
            && parse_timestamp(valid_from, "evidence.validity.validFrom")?
                >= parse_timestamp(expires_at, "evidence.validity.expiresAt")?
        {
            return Err(CapabilityValidationError::InvalidValidityWindow);
        }

        match self.status {
            QualificationValidityStatus::Current => {
                if self.invalidated_at.is_some() || self.invalidation_reason.is_some() {
                    return Err(CapabilityValidationError::ValidityMetadataMismatch(
                        "current evidence cannot contain invalidation metadata",
                    ));
                }
            }
            QualificationValidityStatus::Stale => {
                if self.invalidation_reason.is_none() {
                    return Err(CapabilityValidationError::MissingField(
                        "evidence.validity.invalidationReason",
                    ));
                }
            }
            QualificationValidityStatus::Revoked | QualificationValidityStatus::Invalidated => {
                if self.invalidated_at.is_none() {
                    return Err(CapabilityValidationError::MissingField(
                        "evidence.validity.invalidatedAt",
                    ));
                }
                if self.invalidation_reason.is_none() {
                    return Err(CapabilityValidationError::MissingField(
                        "evidence.validity.invalidationReason",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityRecordV1 {
    pub schema: String,
    pub recorded_at: String,
    pub qualification_key: QualificationKey,
    pub state: CapabilityState,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub evidence: CapabilityEvidence,
}

pub type CapabilityRecord = CapabilityRecordV1;

impl CapabilityRecordV1 {
    pub fn new(
        recorded_at: impl Into<String>,
        qualification_key: QualificationKey,
        state: CapabilityState,
        reason_code: impl Into<String>,
        evidence: CapabilityEvidence,
    ) -> Self {
        Self {
            schema: CAPABILITY_RECORD_SCHEMA.to_string(),
            recorded_at: recorded_at.into(),
            qualification_key,
            state,
            reason_code: reason_code.into(),
            reason: None,
            evidence,
        }
    }

    /// Validates record structure. A qualified record requires [`Self::validate_at`] so expiry
    /// can never be checked without an explicit trusted evaluation time. JSON Schema validation
    /// is likewise structural only and never grants qualification authority.
    pub fn validate(&self) -> Result<(), CapabilityValidationError> {
        self.validate_shape()?;
        if self.state == CapabilityState::Qualified {
            return Err(CapabilityValidationError::EvaluationTimeRequired);
        }
        Ok(())
    }

    /// Validates the record and evaluates qualification validity at an explicit RFC 3339 time.
    ///
    /// In particular, this method never accepts fixture-only, fake, placeholder, incomplete,
    /// stale, revoked, or mismatched evidence for a `qualified` record.
    pub fn validate_at(&self, evaluation_time: &str) -> Result<(), CapabilityValidationError> {
        self.validate_shape()?;
        let evaluation = parse_timestamp(evaluation_time, "evaluationTime")?;

        if self.state == CapabilityState::Qualified {
            self.validate_qualification_claim(evaluation)?;
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), CapabilityValidationError> {
        if self.schema != CAPABILITY_RECORD_SCHEMA {
            return Err(CapabilityValidationError::SchemaMismatch {
                expected: CAPABILITY_RECORD_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        validate_timestamp(&self.recorded_at, "recordedAt")?;
        self.qualification_key.validate()?;
        validate_bounded_text(&self.reason_code, "reasonCode")?;
        validate_optional_reason(self.reason.as_deref(), "reason")?;
        self.evidence.validate()?;
        Ok(())
    }

    /// This no-clock compatibility method always fails closed. Use [`Self::validate_qualified_at`].
    pub fn validate_qualified(&self) -> Result<(), CapabilityValidationError> {
        if self.state != CapabilityState::Qualified {
            return Err(CapabilityValidationError::NotQualified { state: self.state });
        }
        Err(CapabilityValidationError::EvaluationTimeRequired)
    }

    pub fn validate_qualified_at(
        &self,
        evaluation_time: &str,
    ) -> Result<(), CapabilityValidationError> {
        if self.state != CapabilityState::Qualified {
            return Err(CapabilityValidationError::NotQualified { state: self.state });
        }
        self.validate_at(evaluation_time)
    }

    /// This no-clock compatibility method always returns false.
    pub fn is_qualified_mutation(&self) -> bool {
        false
    }

    pub fn is_qualified_mutation_at(&self, evaluation_time: &str) -> bool {
        self.state == CapabilityState::Qualified
            && self
                .qualification_key
                .capability
                .requires_strong_qualification()
            && self.validate_qualified_at(evaluation_time).is_ok()
    }

    fn validate_qualification_claim(
        &self,
        evaluation: OffsetDateTime,
    ) -> Result<(), CapabilityValidationError> {
        if !self.evidence.evidence_class.may_qualify_non_mutation() {
            return Err(CapabilityValidationError::NonQualifyingEvidenceClass {
                evidence_class: self.evidence.evidence_class,
            });
        }
        validate_sha256_digest(
            &self.qualification_key.safety_policy_digest,
            "qualificationKey.safetyPolicyDigest",
        )?;
        validate_sha256_digest(
            &self.qualification_key.adapter_digest,
            "qualificationKey.adapterDigest",
        )?;
        validate_sha256_digest(&self.evidence.bundle_digest, "evidence.bundleDigest")?;
        let validity = self
            .evidence
            .validity
            .as_ref()
            .ok_or(CapabilityValidationError::MissingField("evidence.validity"))?;
        if validity.status != QualificationValidityStatus::Current {
            return Err(CapabilityValidationError::NonCurrentEvidence {
                status: validity.status,
            });
        }
        let valid_from = parse_timestamp(
            required_field(
                validity.valid_from.as_deref(),
                "evidence.validity.validFrom",
            )?,
            "evidence.validity.validFrom",
        )?;
        let recorded_at = parse_timestamp(&self.recorded_at, "recordedAt")?;
        if recorded_at < valid_from {
            return Err(CapabilityValidationError::RecordPredatesValidity);
        }
        if recorded_at > evaluation {
            return Err(CapabilityValidationError::RecordFromFuture);
        }
        let expires_at = validity
            .expires_at
            .as_deref()
            .map(|value| parse_timestamp(value, "evidence.validity.expiresAt"))
            .transpose()?;
        if let Some(expires_at) = expires_at {
            if valid_from >= expires_at {
                return Err(CapabilityValidationError::InvalidValidityWindow);
            }
            if evaluation >= expires_at {
                return Err(CapabilityValidationError::EvidenceExpired);
            }
        }

        if self
            .qualification_key
            .capability
            .requires_strong_qualification()
        {
            if !self.evidence.evidence_class.may_qualify_mutation() {
                return Err(CapabilityValidationError::MutationRequiresRealOsEvidence);
            }
            required_field(
                validity.expires_at.as_deref(),
                "evidence.validity.expiresAt",
            )?;
            self.qualification_key.validate_exact_mutation_tuple()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityValidationError {
    SchemaMismatch {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    EmptyField(&'static str),
    FieldTooLong {
        field: &'static str,
        max_bytes: usize,
    },
    TooManyItems {
        field: &'static str,
        max_items: usize,
    },
    DuplicateListItem(&'static str),
    InvalidTimestamp(&'static str),
    InvalidDigest(&'static str),
    PlaceholderValue(&'static str),
    InvalidScannerSemanticsVersion,
    InvalidCapabilityCell(CapabilityCellError),
    IncompleteFieldPair {
        first: &'static str,
        second: &'static str,
    },
    ScopeFieldMismatch {
        scope: QualificationScope,
    },
    ValidityMetadataMismatch(&'static str),
    NonQualifyingEvidenceClass {
        evidence_class: EvidenceClass,
    },
    NonCurrentEvidence {
        status: QualificationValidityStatus,
    },
    MutationRequiresRealOsEvidence,
    MutationTupleMismatch {
        field: &'static str,
        expected: &'static str,
    },
    NotQualified {
        state: CapabilityState,
    },
    EvaluationTimeRequired,
    RecordPredatesValidity,
    RecordFromFuture,
    InvalidValidityWindow,
    EvidenceExpired,
}

pub type CapabilityRecordValidationError = CapabilityValidationError;
pub type QualificationValidationError = CapabilityValidationError;

impl fmt::Display for CapabilityValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaMismatch { expected, actual } => {
                write!(
                    formatter,
                    "schema mismatch: expected {expected}, got {actual}"
                )
            }
            Self::MissingField(field) => write!(formatter, "required field is missing: {field}"),
            Self::EmptyField(field) => write!(formatter, "field is empty: {field}"),
            Self::FieldTooLong { field, max_bytes } => {
                write!(formatter, "field exceeds {max_bytes} bytes: {field}")
            }
            Self::TooManyItems { field, max_items } => {
                write!(formatter, "field has more than {max_items} items: {field}")
            }
            Self::DuplicateListItem(field) => {
                write!(formatter, "field contains a duplicate item: {field}")
            }
            Self::InvalidTimestamp(field) => {
                write!(formatter, "invalid RFC 3339 timestamp: {field}")
            }
            Self::InvalidDigest(field) => {
                write!(formatter, "field is not a sha256 digest: {field}")
            }
            Self::PlaceholderValue(field) => {
                write!(formatter, "qualified tuple contains a placeholder: {field}")
            }
            Self::InvalidScannerSemanticsVersion => {
                formatter.write_str("scannerSemanticsVersion must be at least 1")
            }
            Self::InvalidCapabilityCell(error) => error.fmt(formatter),
            Self::IncompleteFieldPair { first, second } => {
                write!(
                    formatter,
                    "fields must be present together: {first}, {second}"
                )
            }
            Self::ScopeFieldMismatch { scope } => {
                write!(
                    formatter,
                    "qualification key fields do not match {scope:?} scope"
                )
            }
            Self::ValidityMetadataMismatch(detail) => formatter.write_str(detail),
            Self::NonQualifyingEvidenceClass { evidence_class } => write!(
                formatter,
                "evidence class {evidence_class:?} cannot validate as qualified"
            ),
            Self::NonCurrentEvidence { status } => {
                write!(formatter, "evidence status {status:?} is not current")
            }
            Self::MutationRequiresRealOsEvidence => {
                formatter.write_str("qualified mutation requires real_os_qualification evidence")
            }
            Self::MutationTupleMismatch { field, expected } => {
                write!(formatter, "qualified mutation requires {field}={expected}")
            }
            Self::NotQualified { state } => {
                write!(
                    formatter,
                    "capability record state is not qualified: {state:?}"
                )
            }
            Self::EvaluationTimeRequired => formatter
                .write_str("qualified records require validation at an explicit evaluation time"),
            Self::RecordPredatesValidity => {
                formatter.write_str("recordedAt precedes evidence.validity.validFrom")
            }
            Self::RecordFromFuture => {
                formatter.write_str("recordedAt is later than the evaluation time")
            }
            Self::InvalidValidityWindow => {
                formatter.write_str("validFrom must be earlier than expiresAt")
            }
            Self::EvidenceExpired => {
                formatter.write_str("qualification evidence is expired at the evaluation time")
            }
        }
    }
}

impl Error for CapabilityValidationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidCapabilityCell(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_bounded_text(
    value: &str,
    field: &'static str,
) -> Result<(), CapabilityValidationError> {
    if value.trim().is_empty() {
        return Err(CapabilityValidationError::EmptyField(field));
    }
    if value.len() > MAX_QUALIFICATION_TEXT_BYTES {
        return Err(CapabilityValidationError::FieldTooLong {
            field,
            max_bytes: MAX_QUALIFICATION_TEXT_BYTES,
        });
    }
    Ok(())
}

fn validate_optional_bounded_text(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), CapabilityValidationError> {
    if let Some(value) = value {
        validate_bounded_text(value, field)?;
    }
    Ok(())
}

fn validate_optional_reason(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), CapabilityValidationError> {
    if let Some(value) = value {
        if value.trim().is_empty() {
            return Err(CapabilityValidationError::EmptyField(field));
        }
        if value.len() > MAX_QUALIFICATION_REASON_BYTES {
            return Err(CapabilityValidationError::FieldTooLong {
                field,
                max_bytes: MAX_QUALIFICATION_REASON_BYTES,
            });
        }
    }
    Ok(())
}

fn validate_list(
    values: &[String],
    field: &'static str,
    may_be_empty: bool,
) -> Result<(), CapabilityValidationError> {
    if !may_be_empty && values.is_empty() {
        return Err(CapabilityValidationError::MissingField(field));
    }
    if values.len() > MAX_EVIDENCE_LIST_ITEMS {
        return Err(CapabilityValidationError::TooManyItems {
            field,
            max_items: MAX_EVIDENCE_LIST_ITEMS,
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        validate_bounded_text(value, field)?;
        if !seen.insert(value) {
            return Err(CapabilityValidationError::DuplicateListItem(field));
        }
    }
    Ok(())
}

fn validate_non_empty_list(
    values: &[String],
    field: &'static str,
) -> Result<(), CapabilityValidationError> {
    validate_list(values, field, false)
}

fn required_field<'a>(
    value: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, CapabilityValidationError> {
    value.ok_or(CapabilityValidationError::MissingField(field))
}

fn validate_exact_value(value: &str, field: &'static str) -> Result<(), CapabilityValidationError> {
    validate_bounded_text(value, field)?;
    if value != value.trim()
        || value.chars().any(char::is_whitespace)
        || value
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'{' | b'}'))
    {
        return Err(CapabilityValidationError::PlaceholderValue(field));
    }
    let normalized = value.to_ascii_lowercase();
    if normalized == "n/a" {
        return Err(CapabilityValidationError::PlaceholderValue(field));
    }
    let placeholder_token = normalized
        .split(|character: char| !character.is_ascii_alphanumeric())
        .any(|token| {
            matches!(
                token,
                "any"
                    | "dev"
                    | "development"
                    | "fake"
                    | "incomplete"
                    | "none"
                    | "placeholder"
                    | "stale"
                    | "tbd"
                    | "unknown"
                    | "unqualified"
                    | "unversioned"
                    | "na"
            )
        });
    if normalized == "*" || placeholder_token {
        return Err(CapabilityValidationError::PlaceholderValue(field));
    }
    Ok(())
}

fn validate_sha256_digest(
    value: &str,
    field: &'static str,
) -> Result<(), CapabilityValidationError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(CapabilityValidationError::InvalidDigest(field));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CapabilityValidationError::InvalidDigest(field));
    }
    if hex
        .bytes()
        .all(|byte| byte.eq_ignore_ascii_case(&hex.as_bytes()[0]))
    {
        return Err(CapabilityValidationError::InvalidDigest(field));
    }
    Ok(())
}

fn validate_timestamp(value: &str, field: &'static str) -> Result<(), CapabilityValidationError> {
    parse_timestamp(value, field).map(|_| ())
}

fn parse_timestamp(
    value: &str,
    field: &'static str,
) -> Result<OffsetDateTime, CapabilityValidationError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| CapabilityValidationError::InvalidTimestamp(field))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum OutputKind {
    #[serde(rename = "scan.result")]
    #[schemars(rename = "scan.result")]
    ScanResult,
    #[serde(rename = "explanation.result")]
    #[schemars(rename = "explanation.result")]
    ExplanationResult,
    #[serde(rename = "plan.result")]
    #[schemars(rename = "plan.result")]
    PlanResult,
    #[serde(rename = "execution.result")]
    #[schemars(rename = "execution.result")]
    ExecutionResult,
    #[serde(rename = "recovery.result")]
    #[schemars(rename = "recovery.result")]
    RecoveryResult,
    #[serde(rename = "cancel.result")]
    #[schemars(rename = "cancel.result")]
    CancelResult,
    #[serde(rename = "status.result")]
    #[schemars(rename = "status.result")]
    StatusResult,
    #[serde(rename = "capabilities.result")]
    #[schemars(rename = "capabilities.result")]
    CapabilitiesResult,
    #[serde(rename = "cleaner.result")]
    #[schemars(rename = "cleaner.result")]
    CleanerResult,
    #[serde(rename = "audit.result")]
    #[schemars(rename = "audit.result")]
    AuditResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutputStatus {
    Ok,
    Partial,
    Blocked,
    AuthorizationRequired,
    Stale,
    Failed,
    NeedsReconciliation,
    Cancelled,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ExitCode {
    Completed = 0,
    UsageError = 2,
    Unsupported = 3,
    Partial = 4,
    SafetyBlocked = 5,
    AuthorizationRequired = 6,
    StaleReplanRequired = 7,
    OperationFailed = 8,
    NeedsReconciliation = 9,
    Cancelled = 10,
    StateIntegrityUnavailable = 11,
    CleanerTrustOrCompat = 12,
    OfficialCommandFailed = 13,
}

impl Serialize for ExitCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for ExitCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            0 => Ok(Self::Completed),
            2 => Ok(Self::UsageError),
            3 => Ok(Self::Unsupported),
            4 => Ok(Self::Partial),
            5 => Ok(Self::SafetyBlocked),
            6 => Ok(Self::AuthorizationRequired),
            7 => Ok(Self::StaleReplanRequired),
            8 => Ok(Self::OperationFailed),
            9 => Ok(Self::NeedsReconciliation),
            10 => Ok(Self::Cancelled),
            11 => Ok(Self::StateIntegrityUnavailable),
            12 => Ok(Self::CleanerTrustOrCompat),
            13 => Ok(Self::OfficialCommandFailed),
            value => Err(serde::de::Error::custom(format!(
                "unknown sweepx exit code: {value}"
            ))),
        }
    }
}

impl JsonSchema for ExitCode {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ExitCode".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        json!({
            "type": "integer",
            "enum": [0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        })
        .try_into()
        .expect("valid exit-code schema")
    }
}

impl ExitCode {
    fn severity_rank(self) -> u8 {
        match self {
            Self::Completed => 0,
            Self::UsageError => 100,
            Self::Partial => 10,
            Self::Unsupported => 20,
            Self::OperationFailed => 30,
            Self::OfficialCommandFailed => 40,
            Self::CleanerTrustOrCompat => 50,
            Self::AuthorizationRequired => 60,
            Self::SafetyBlocked => 70,
            Self::StaleReplanRequired => 80,
            Self::Cancelled => 90,
            Self::NeedsReconciliation => 95,
            Self::StateIntegrityUnavailable => 99,
        }
    }

    pub fn more_conservative(self, other: Self) -> Self {
        if self.severity_rank() >= other.severity_rank() {
            self
        } else {
            other
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CompatSnapshot {
    pub core_version: String,
    pub scanner_semantics_version: u32,
    pub safety_policy_version: u32,
    pub platform_adapter: PlatformAdapterCompat,
    pub cleaner_set_digest: String,
    pub required_features: Vec<String>,
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PlatformAdapterCompat {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OutputEnvelope {
    pub schema: String,
    pub kind: OutputKind,
    pub request_id: RequestId,
    pub operation_id: OperationId,
    pub generated_at: String,
    pub status: OutputStatus,
    pub exit_code: ExitCode,
    pub compat: CompatSnapshot,
    pub summary: Value,
    pub data: Value,
    pub warnings: Vec<ProtocolMessage>,
    pub errors: Vec<ProtocolMessage>,
}

impl OutputEnvelope {
    pub fn new(
        kind: OutputKind,
        request_id: RequestId,
        operation_id: OperationId,
        generated_at: impl Into<String>,
        status: OutputStatus,
        exit_code: ExitCode,
        compat: CompatSnapshot,
    ) -> Self {
        Self {
            schema: OUTPUT_SCHEMA.to_string(),
            kind,
            request_id,
            operation_id,
            generated_at: generated_at.into(),
            status,
            exit_code,
            compat,
            summary: json!({}),
            data: json!({}),
            warnings: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn conservative_exit_code(&self) -> ExitCode {
        self.exit_code.more_conservative(self.status.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolMessage {
    pub code: String,
    pub class: String,
    pub message_key: String,
    pub retryable: bool,
    pub params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventPhase {
    Detect,
    Analyze,
    Plan,
    Authorize,
    Revalidate,
    Execute,
    Reconcile,
    Audit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EventType {
    #[serde(rename = "operation.started")]
    #[schemars(rename = "operation.started")]
    OperationStarted,
    #[serde(rename = "phase.changed")]
    #[schemars(rename = "phase.changed")]
    PhaseChanged,
    #[serde(rename = "scan.root.admitted")]
    #[schemars(rename = "scan.root.admitted")]
    ScanRootAdmitted,
    #[serde(rename = "scan.progress")]
    #[schemars(rename = "scan.progress")]
    ScanProgress,
    #[serde(rename = "scan.aggregate.revised")]
    #[schemars(rename = "scan.aggregate.revised")]
    ScanAggregateRevised,
    #[serde(rename = "scan.boundary.observed")]
    #[schemars(rename = "scan.boundary.observed")]
    ScanBoundaryObserved,
    #[serde(rename = "scan.error.observed")]
    #[schemars(rename = "scan.error.observed")]
    ScanErrorObserved,
    #[serde(rename = "scan.root.completed")]
    #[schemars(rename = "scan.root.completed")]
    ScanRootCompleted,
    #[serde(rename = "candidate.detected")]
    #[schemars(rename = "candidate.detected")]
    CandidateDetected,
    #[serde(rename = "analysis.completed")]
    #[schemars(rename = "analysis.completed")]
    AnalysisCompleted,
    #[serde(rename = "plan.created")]
    #[schemars(rename = "plan.created")]
    PlanCreated,
    #[serde(rename = "plan.rejected")]
    #[schemars(rename = "plan.rejected")]
    PlanRejected,
    #[serde(rename = "approval.requested")]
    #[schemars(rename = "approval.requested")]
    ApprovalRequested,
    #[serde(rename = "approval.granted")]
    #[schemars(rename = "approval.granted")]
    ApprovalGranted,
    #[serde(rename = "approval.rejected")]
    #[schemars(rename = "approval.rejected")]
    ApprovalRejected,
    #[serde(rename = "approval.expired")]
    #[schemars(rename = "approval.expired")]
    ApprovalExpired,
    #[serde(rename = "authorization.explicit_dangerous_delete")]
    #[schemars(rename = "authorization.explicit_dangerous_delete")]
    AuthorizationExplicitDangerousDelete,
    #[serde(rename = "revalidation.started")]
    #[schemars(rename = "revalidation.started")]
    RevalidationStarted,
    #[serde(rename = "revalidation.passed")]
    #[schemars(rename = "revalidation.passed")]
    RevalidationPassed,
    #[serde(rename = "revalidation.stale")]
    #[schemars(rename = "revalidation.stale")]
    RevalidationStale,
    #[serde(rename = "preflight.ready")]
    #[schemars(rename = "preflight.ready")]
    PreflightReady,
    #[serde(rename = "hard_protection.blocked")]
    #[schemars(rename = "hard_protection.blocked")]
    HardProtectionBlocked,
    #[serde(rename = "operation.cancel.requested")]
    #[schemars(rename = "operation.cancel.requested")]
    OperationCancelRequested,
    #[serde(rename = "operation.cancel.accepted")]
    #[schemars(rename = "operation.cancel.accepted")]
    OperationCancelAccepted,
    #[serde(rename = "operation.cancel.already_requested")]
    #[schemars(rename = "operation.cancel.already_requested")]
    OperationCancelAlreadyRequested,
    #[serde(rename = "operation.cancel.already_terminal")]
    #[schemars(rename = "operation.cancel.already_terminal")]
    OperationCancelAlreadyTerminal,
    #[serde(rename = "operation.cancel.too_late")]
    #[schemars(rename = "operation.cancel.too_late")]
    OperationCancelTooLate,
    #[serde(rename = "action.intent.durable")]
    #[schemars(rename = "action.intent.durable")]
    ActionIntentDurable,
    #[serde(rename = "action.platform.completed")]
    #[schemars(rename = "action.platform.completed")]
    ActionPlatformCompleted,
    #[serde(rename = "action.skipped")]
    #[schemars(rename = "action.skipped")]
    ActionSkipped,
    #[serde(rename = "action.failed_before_submit")]
    #[schemars(rename = "action.failed_before_submit")]
    ActionFailedBeforeSubmit,
    #[serde(rename = "action.permit.consumed")]
    #[schemars(rename = "action.permit.consumed")]
    ActionPermitConsumed,
    #[serde(rename = "action.reconciled")]
    #[schemars(rename = "action.reconciled")]
    ActionReconciled,
    #[serde(rename = "action.indeterminate")]
    #[schemars(rename = "action.indeterminate")]
    ActionIndeterminate,
    #[serde(rename = "item.completed")]
    #[schemars(rename = "item.completed")]
    ItemCompleted,
    #[serde(rename = "batch.completed")]
    #[schemars(rename = "batch.completed")]
    BatchCompleted,
    #[serde(rename = "batch.partial")]
    #[schemars(rename = "batch.partial")]
    BatchPartial,
    #[serde(rename = "batch.cancelled")]
    #[schemars(rename = "batch.cancelled")]
    BatchCancelled,
    #[serde(rename = "batch.needs_reconciliation")]
    #[schemars(rename = "batch.needs_reconciliation")]
    BatchNeedsReconciliation,
    #[serde(rename = "recovery.started")]
    #[schemars(rename = "recovery.started")]
    RecoveryStarted,
    #[serde(rename = "recovery.completed")]
    #[schemars(rename = "recovery.completed")]
    RecoveryCompleted,
    #[serde(rename = "audit.started")]
    #[schemars(rename = "audit.started")]
    AuditStarted,
    #[serde(rename = "audit.batch.committed")]
    #[schemars(rename = "audit.batch.committed")]
    AuditBatchCommitted,
    #[serde(rename = "audit.failed")]
    #[schemars(rename = "audit.failed")]
    AuditFailed,
    #[serde(rename = "detail.persistence.failed")]
    #[schemars(rename = "detail.persistence.failed")]
    DetailPersistenceFailed,
    #[serde(rename = "stream.reset_required")]
    #[schemars(rename = "stream.reset_required")]
    StreamResetRequired,
    #[serde(rename = "operation.terminal")]
    #[schemars(rename = "operation.terminal")]
    OperationTerminal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventEnvelope {
    pub schema: String,
    pub stream_id: String,
    pub operation_id: OperationId,
    pub sequence: DecimalU128,
    pub cursor: String,
    pub emitted_at: String,
    pub monotonic_offset_ns: DecimalU128,
    pub r#type: EventType,
    pub phase: EventPhase,
    pub payload: Value,
    pub terminal: bool,
    pub checkpoint: EventCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventCheckpoint {
    pub durable: bool,
    pub last_durable_sequence: DecimalU128,
}

impl EventEnvelope {
    pub fn is_terminal_type(&self) -> bool {
        matches!(self.r#type, EventType::OperationTerminal)
    }

    /// Validates the bounded, context-free invariants of one event.
    ///
    /// This deliberately accepts the legacy in-memory cursor shape still produced by the
    /// disabled NDJSON path. Use [`Self::validate_for_durable_stream`] before admitting an event
    /// to a replayable journal or returning it from a durable stream.
    pub fn validate(&self) -> Result<(), EventValidationError> {
        if self.schema != EVENT_SCHEMA {
            return Err(EventValidationError::SchemaMismatch {
                expected: EVENT_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        validate_event_id(&self.stream_id, "streamId")?;
        validate_event_id(&self.operation_id, "operationId")?;

        let sequence = u128::from(self.sequence);
        if sequence == 0 {
            return Err(EventValidationError::ZeroSequence);
        }
        validate_event_cursor(&self.cursor)?;
        parse_event_timestamp(&self.emitted_at)?;

        if !self.payload.is_object() {
            return Err(EventValidationError::PayloadNotObject);
        }
        let payload_bytes = serde_json::to_vec(&self.payload)
            .expect("serializing an in-memory JSON value cannot fail")
            .len();
        if payload_bytes > MAX_EVENT_PAYLOAD_BYTES {
            return Err(EventValidationError::PayloadTooLarge {
                actual_bytes: payload_bytes,
                max_bytes: MAX_EVENT_PAYLOAD_BYTES,
            });
        }

        if self.terminal != self.is_terminal_type() {
            return Err(EventValidationError::TerminalFlagMismatch);
        }

        let last_durable_sequence = u128::from(self.checkpoint.last_durable_sequence);
        if self.checkpoint.durable {
            if last_durable_sequence != sequence {
                return Err(EventValidationError::DurableCheckpointMismatch {
                    sequence: self.sequence,
                    last_durable_sequence: self.checkpoint.last_durable_sequence,
                });
            }
        } else if last_durable_sequence >= sequence {
            return Err(EventValidationError::NonDurableCheckpointNotBeforeEvent {
                sequence: self.sequence,
                last_durable_sequence: self.checkpoint.last_durable_sequence,
            });
        }

        if self.is_terminal_type() && self.checkpoint.durable {
            self.terminal_payload()?;
        }
        if self.r#type == EventType::StreamResetRequired {
            self.stream_reset_required_payload()?;
        }

        Ok(())
    }

    /// Applies the single-event checks plus the opaque cursor format reserved for durable replay.
    pub fn validate_for_durable_stream(&self) -> Result<(), EventValidationError> {
        self.validate()?;
        if self.r#type == EventType::StreamResetRequired {
            return Err(EventValidationError::DeliveryControlInDurableStream);
        }
        validate_durable_event_cursor(&self.cursor)?;
        if self.is_terminal_type() {
            if !self.checkpoint.durable {
                return Err(EventValidationError::TerminalNotDurable);
            }
            self.terminal_payload()?;
        }
        Ok(())
    }

    /// Returns the typed terminal payload, rejecting missing, unknown, or inconsistent fields.
    pub fn terminal_payload(&self) -> Result<TerminalEventPayload, EventValidationError> {
        if !self.is_terminal_type() {
            return Err(EventValidationError::NotTerminalEvent);
        }
        let payload: TerminalEventPayload = serde_json::from_value(self.payload.clone())
            .map_err(|error| EventValidationError::InvalidTerminalPayload(error.to_string()))?;
        validate_snapshot_digest(&payload.snapshot_digest)?;
        let minimum_exit = ExitCode::from(payload.status);
        if payload.exit_code.more_conservative(minimum_exit) != payload.exit_code {
            return Err(EventValidationError::TerminalExitTooWeak {
                status: payload.status,
                exit_code: payload.exit_code,
            });
        }
        Ok(payload)
    }

    /// Returns the typed payload carried by a replay delivery-control reset event.
    ///
    /// Reset controls are not members of the canonical durable operation stream. They use a
    /// separate control stream and direct the consumer to the terminal snapshot before resuming
    /// from the journal-owned high-water cursor.
    pub fn stream_reset_required_payload(
        &self,
    ) -> Result<StreamResetRequiredPayload, EventValidationError> {
        if self.r#type != EventType::StreamResetRequired {
            return Err(EventValidationError::NotStreamResetRequiredEvent);
        }
        if self.checkpoint.durable {
            return Err(EventValidationError::DeliveryControlMustNotBeDurable);
        }
        let payload: StreamResetRequiredPayload = serde_json::from_value(self.payload.clone())
            .map_err(|error| EventValidationError::InvalidStreamResetPayload(error.to_string()))?;
        validate_durable_event_cursor(&payload.requested_cursor)?;
        validate_event_id(
            &payload.snapshot_ref.operation_id,
            "payload.snapshotRef.operationId",
        )?;
        validate_durable_event_cursor(&payload.resume_after)?;
        if payload.available_from_sequence != DecimalU128::new(1) {
            return Err(EventValidationError::InvalidStreamResetPayload(
                "availableFromSequence must be 1 for completed-stream replay".to_string(),
            ));
        }
        Ok(payload)
    }
}

/// The exact payload carried by `operation.terminal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalEventPayload {
    pub status: OutputStatus,
    pub exit_code: ExitCode,
    pub kind: OutputKind,
    pub snapshot_digest: String,
}

/// Delivery-control payload emitted when a syntactically valid replay cursor is not known by
/// the selected completed journal generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamResetRequiredPayload {
    pub requested_cursor: String,
    pub available_from_sequence: DecimalU128,
    pub snapshot_ref: StreamResetSnapshotRef,
    pub resume_after: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StreamResetSnapshotRef {
    pub operation_id: String,
}

/// Expected terminal facts supplied by the owner of the final durable snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalEventExpectation {
    pub status: OutputStatus,
    pub exit_code: ExitCode,
    pub kind: OutputKind,
    pub snapshot_digest: String,
}

impl TerminalEventExpectation {
    pub fn new(
        status: OutputStatus,
        exit_code: ExitCode,
        kind: OutputKind,
        snapshot_digest: impl Into<String>,
    ) -> Self {
        Self {
            status,
            exit_code,
            kind,
            snapshot_digest: snapshot_digest.into(),
        }
    }
}

/// Validates one complete replayable event stream against its durable terminal snapshot.
///
/// The stream is canonical rather than an at-least-once transport transcript: duplicate
/// deliveries must be deduplicated before this function is called.
pub fn validate_durable_event_stream(
    events: &[EventEnvelope],
    expected_terminal: &TerminalEventExpectation,
) -> Result<(), EventStreamValidationError> {
    let first = events
        .first()
        .ok_or(EventStreamValidationError::EmptyStream)?;

    for (index, event) in events.iter().enumerate() {
        event
            .validate_for_durable_stream()
            .map_err(|source| EventStreamValidationError::InvalidEvent { index, source })?;
    }

    if first.r#type != EventType::OperationStarted {
        return Err(EventStreamValidationError::FirstEventNotStarted);
    }
    if !first.checkpoint.durable {
        return Err(EventStreamValidationError::StartedEventNotDurable);
    }

    let terminal_count = events
        .iter()
        .filter(|event| event.is_terminal_type())
        .count();
    if terminal_count != 1 {
        return Err(EventStreamValidationError::TerminalCount {
            actual: terminal_count,
        });
    }
    if !events.last().is_some_and(EventEnvelope::is_terminal_type) {
        return Err(EventStreamValidationError::TerminalNotLast);
    }

    let mut last_durable_sequence = DecimalU128::ZERO;
    let mut previous_emitted_at = None;
    let mut previous_monotonic_offset = DecimalU128::ZERO;
    let mut cursors = BTreeSet::new();

    for (index, event) in events.iter().enumerate() {
        let expected_sequence = DecimalU128::new(
            u128::try_from(index)
                .expect("usize always fits in u128")
                .checked_add(1)
                .expect("an in-memory event slice cannot exceed u128::MAX entries"),
        );
        if event.sequence != expected_sequence {
            return Err(EventStreamValidationError::SequenceMismatch {
                index,
                expected: expected_sequence,
                actual: event.sequence,
            });
        }
        if event.stream_id != first.stream_id {
            return Err(EventStreamValidationError::StreamIdMismatch { index });
        }
        if event.operation_id != first.operation_id {
            return Err(EventStreamValidationError::OperationIdMismatch { index });
        }
        if index > 0 && event.r#type == EventType::OperationStarted {
            return Err(EventStreamValidationError::StartedEventRepeated { index });
        }
        if !cursors.insert(event.cursor.as_str()) {
            return Err(EventStreamValidationError::DuplicateCursor { index });
        }

        let emitted_at = parse_event_timestamp(&event.emitted_at)
            .map_err(|source| EventStreamValidationError::InvalidEvent { index, source })?;
        if previous_emitted_at.is_some_and(|previous| emitted_at < previous) {
            return Err(EventStreamValidationError::EmittedAtRegression { index });
        }
        if index > 0 && event.monotonic_offset_ns < previous_monotonic_offset {
            return Err(EventStreamValidationError::MonotonicOffsetRegression { index });
        }
        previous_emitted_at = Some(emitted_at);
        previous_monotonic_offset = event.monotonic_offset_ns;

        let expected_last_durable = if event.checkpoint.durable {
            event.sequence
        } else {
            last_durable_sequence
        };
        if event.checkpoint.last_durable_sequence != expected_last_durable {
            return Err(EventStreamValidationError::CheckpointHistoryMismatch {
                index,
                expected: expected_last_durable,
                actual: event.checkpoint.last_durable_sequence,
            });
        }
        if event.checkpoint.durable {
            last_durable_sequence = event.sequence;
        }
    }

    let terminal = events.last().expect("non-empty stream checked above");
    let actual_terminal =
        terminal
            .terminal_payload()
            .map_err(|source| EventStreamValidationError::InvalidEvent {
                index: events.len() - 1,
                source,
            })?;
    if actual_terminal.status != expected_terminal.status {
        return Err(EventStreamValidationError::TerminalExpectationMismatch { field: "status" });
    }
    if actual_terminal.exit_code != expected_terminal.exit_code {
        return Err(EventStreamValidationError::TerminalExpectationMismatch { field: "exitCode" });
    }
    if actual_terminal.kind != expected_terminal.kind {
        return Err(EventStreamValidationError::TerminalExpectationMismatch { field: "kind" });
    }
    if actual_terminal.snapshot_digest != expected_terminal.snapshot_digest {
        return Err(EventStreamValidationError::TerminalExpectationMismatch {
            field: "snapshotDigest",
        });
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventValidationError {
    SchemaMismatch {
        expected: &'static str,
        actual: String,
    },
    EmptyField(&'static str),
    FieldTooLong {
        field: &'static str,
        actual_bytes: usize,
        max_bytes: usize,
    },
    InvalidId(&'static str),
    ZeroSequence,
    InvalidCursor,
    InvalidDurableCursor,
    InvalidTimestamp,
    TimestampNotUtc,
    PayloadNotObject,
    PayloadTooLarge {
        actual_bytes: usize,
        max_bytes: usize,
    },
    TerminalFlagMismatch,
    DurableCheckpointMismatch {
        sequence: DecimalU128,
        last_durable_sequence: DecimalU128,
    },
    NonDurableCheckpointNotBeforeEvent {
        sequence: DecimalU128,
        last_durable_sequence: DecimalU128,
    },
    TerminalNotDurable,
    NotTerminalEvent,
    NotStreamResetRequiredEvent,
    InvalidTerminalPayload(String),
    InvalidStreamResetPayload(String),
    DeliveryControlInDurableStream,
    DeliveryControlMustNotBeDurable,
    InvalidSnapshotDigest,
    TerminalExitTooWeak {
        status: OutputStatus,
        exit_code: ExitCode,
    },
}

impl fmt::Display for EventValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaMismatch { expected, actual } => {
                write!(
                    formatter,
                    "event schema mismatch: expected {expected}, got {actual}"
                )
            }
            Self::EmptyField(field) => write!(formatter, "event field is empty: {field}"),
            Self::FieldTooLong {
                field,
                actual_bytes,
                max_bytes,
            } => write!(
                formatter,
                "event field {field} is {actual_bytes} bytes; maximum is {max_bytes}"
            ),
            Self::InvalidId(field) => write!(formatter, "event field has an invalid ID: {field}"),
            Self::ZeroSequence => formatter.write_str("event sequence must be non-zero"),
            Self::InvalidCursor => formatter.write_str("event cursor has an invalid format"),
            Self::InvalidDurableCursor => {
                formatter.write_str("durable event cursor must use the opaque sxcur1 format")
            }
            Self::InvalidTimestamp => {
                formatter.write_str("event emittedAt must be a valid RFC 3339 timestamp")
            }
            Self::TimestampNotUtc => formatter.write_str("event emittedAt must use UTC (Z)"),
            Self::PayloadNotObject => formatter.write_str("event payload must be an object"),
            Self::PayloadTooLarge {
                actual_bytes,
                max_bytes,
            } => write!(
                formatter,
                "event payload is {actual_bytes} bytes; maximum is {max_bytes}"
            ),
            Self::TerminalFlagMismatch => formatter
                .write_str("event terminal is true if and only if type is operation.terminal"),
            Self::DurableCheckpointMismatch {
                sequence,
                last_durable_sequence,
            } => write!(
                formatter,
                "durable event sequence {sequence} must checkpoint itself, got {last_durable_sequence}"
            ),
            Self::NonDurableCheckpointNotBeforeEvent {
                sequence,
                last_durable_sequence,
            } => write!(
                formatter,
                "non-durable event sequence {sequence} must reference an earlier durable sequence, got {last_durable_sequence}"
            ),
            Self::TerminalNotDurable => formatter.write_str("operation.terminal must be durable"),
            Self::NotTerminalEvent => formatter.write_str("event is not operation.terminal"),
            Self::NotStreamResetRequiredEvent => {
                formatter.write_str("event is not stream.reset_required")
            }
            Self::InvalidTerminalPayload(error) => {
                write!(formatter, "invalid operation.terminal payload: {error}")
            }
            Self::InvalidStreamResetPayload(error) => {
                write!(formatter, "invalid stream.reset_required payload: {error}")
            }
            Self::DeliveryControlInDurableStream => formatter.write_str(
                "stream.reset_required is a delivery control, not a durable stream event",
            ),
            Self::DeliveryControlMustNotBeDurable => {
                formatter.write_str("stream.reset_required must use a non-durable checkpoint")
            }
            Self::InvalidSnapshotDigest => formatter
                .write_str("operation.terminal snapshotDigest must be a lowercase sha256 digest"),
            Self::TerminalExitTooWeak { status, exit_code } => write!(
                formatter,
                "operation.terminal exit code {exit_code:?} is weaker than status {status:?}"
            ),
        }
    }
}

impl Error for EventValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventStreamValidationError {
    EmptyStream,
    InvalidEvent {
        index: usize,
        source: EventValidationError,
    },
    FirstEventNotStarted,
    StartedEventNotDurable,
    StartedEventRepeated {
        index: usize,
    },
    TerminalCount {
        actual: usize,
    },
    TerminalNotLast,
    SequenceMismatch {
        index: usize,
        expected: DecimalU128,
        actual: DecimalU128,
    },
    StreamIdMismatch {
        index: usize,
    },
    OperationIdMismatch {
        index: usize,
    },
    DuplicateCursor {
        index: usize,
    },
    EmittedAtRegression {
        index: usize,
    },
    MonotonicOffsetRegression {
        index: usize,
    },
    CheckpointHistoryMismatch {
        index: usize,
        expected: DecimalU128,
        actual: DecimalU128,
    },
    TerminalExpectationMismatch {
        field: &'static str,
    },
}

impl fmt::Display for EventStreamValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyStream => formatter.write_str("durable event stream is empty"),
            Self::InvalidEvent { index, source } => {
                write!(formatter, "invalid event at index {index}: {source}")
            }
            Self::FirstEventNotStarted => {
                formatter.write_str("durable event stream must start with operation.started")
            }
            Self::StartedEventNotDurable => {
                formatter.write_str("the initial operation.started event must be durable")
            }
            Self::StartedEventRepeated { index } => {
                write!(formatter, "operation.started repeats at index {index}")
            }
            Self::TerminalCount { actual } => write!(
                formatter,
                "durable event stream must contain exactly one operation.terminal, got {actual}"
            ),
            Self::TerminalNotLast => {
                formatter.write_str("operation.terminal must be the final event")
            }
            Self::SequenceMismatch {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "event sequence mismatch at index {index}: expected {expected}, got {actual}"
            ),
            Self::StreamIdMismatch { index } => {
                write!(formatter, "streamId changes at index {index}")
            }
            Self::OperationIdMismatch { index } => {
                write!(formatter, "operationId changes at index {index}")
            }
            Self::DuplicateCursor { index } => {
                write!(formatter, "event cursor repeats at index {index}")
            }
            Self::EmittedAtRegression { index } => {
                write!(formatter, "emittedAt regresses at index {index}")
            }
            Self::MonotonicOffsetRegression { index } => {
                write!(formatter, "monotonicOffsetNs regresses at index {index}")
            }
            Self::CheckpointHistoryMismatch {
                index,
                expected,
                actual,
            } => write!(
                formatter,
                "checkpoint history mismatch at index {index}: expected {expected}, got {actual}"
            ),
            Self::TerminalExpectationMismatch { field } => {
                write!(
                    formatter,
                    "operation.terminal does not match expected {field}"
                )
            }
        }
    }
}

impl Error for EventStreamValidationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEvent { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn validate_event_id(value: &str, field: &'static str) -> Result<(), EventValidationError> {
    if value.is_empty() {
        return Err(EventValidationError::EmptyField(field));
    }
    if value.len() > MAX_EVENT_ID_BYTES {
        return Err(EventValidationError::FieldTooLong {
            field,
            actual_bytes: value.len(),
            max_bytes: MAX_EVENT_ID_BYTES,
        });
    }
    let mut bytes = value.bytes();
    if !bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(EventValidationError::InvalidId(field));
    }
    Ok(())
}

fn validate_event_cursor(value: &str) -> Result<(), EventValidationError> {
    if value.is_empty() {
        return Err(EventValidationError::EmptyField("cursor"));
    }
    if value.len() > MAX_EVENT_CURSOR_BYTES {
        return Err(EventValidationError::FieldTooLong {
            field: "cursor",
            actual_bytes: value.len(),
            max_bytes: MAX_EVENT_CURSOR_BYTES,
        });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(EventValidationError::InvalidCursor);
    }
    Ok(())
}

fn validate_durable_event_cursor(value: &str) -> Result<(), EventValidationError> {
    validate_event_cursor(value)?;
    let Some(token) = value.strip_prefix("sxcur1.") else {
        return Err(EventValidationError::InvalidDurableCursor);
    };
    if token.len() < MIN_DURABLE_CURSOR_TOKEN_BYTES
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(EventValidationError::InvalidDurableCursor);
    }
    Ok(())
}

fn parse_event_timestamp(value: &str) -> Result<OffsetDateTime, EventValidationError> {
    if value.is_empty() {
        return Err(EventValidationError::EmptyField("emittedAt"));
    }
    if value.len() > MAX_EVENT_TIMESTAMP_BYTES {
        return Err(EventValidationError::FieldTooLong {
            field: "emittedAt",
            actual_bytes: value.len(),
            max_bytes: MAX_EVENT_TIMESTAMP_BYTES,
        });
    }
    let timestamp = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| EventValidationError::InvalidTimestamp)?;
    if timestamp.offset() != UtcOffset::UTC || !value.ends_with('Z') {
        return Err(EventValidationError::TimestampNotUtc);
    }
    Ok(timestamp)
}

fn validate_snapshot_digest(value: &str) -> Result<(), EventValidationError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(EventValidationError::InvalidSnapshotDigest);
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EventValidationError::InvalidSnapshotDigest);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditProjectionState {
    Authorized,
    Pending,
    Indeterminate,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditRecoveryDisposition {
    Pending,
    Reserved,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditStableStatus {
    TrashSucceededPlatformReported,
    TrashSucceededLocationReported,
    PermanentDeleteSucceeded,
    FailedPlatformError,
    FailedCancelledByPlatform,
    FailedSourceUnchanged,
    VanishedBeforeAction,
    CancelledBeforeAction,
    IndeterminateAfterCrash,
    IndeterminatePlatformResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcomeRecoveryState {
    PlatformTrashReported,
    TrashLocationReported,
    InapplicablePermanent,
    FailedSourceUnchanged,
    CancelledBeforeAction,
    VanishedBeforeAction,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditTerminalOutcomeProjection {
    pub stable_status: AuditStableStatus,
    pub recovery_state: AuditOutcomeRecoveryState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditActionProjection {
    pub authorization_id: String,
    pub item_id: String,
    pub action_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    pub state: AuditProjectionState,
    pub needs_reconciliation: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_disposition: Option<AuditRecoveryDisposition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_outcome: Option<AuditTerminalOutcomeProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditAuthorizationProjection {
    pub authorization_id: String,
    pub state: AuditProjectionState,
    pub needs_reconciliation: bool,
    pub actions: Vec<AuditActionProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditItemProjection {
    pub item_id: String,
    pub state: AuditProjectionState,
    pub needs_reconciliation: bool,
    pub authorizations: Vec<AuditAuthorizationProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditBatchProjection {
    pub batch_id: String,
    pub state: AuditProjectionState,
    pub needs_reconciliation: bool,
    pub items: Vec<AuditItemProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditProjectionSnapshot {
    pub schema: String,
    pub batches: Vec<AuditBatchProjection>,
}

impl AuditProjectionSnapshot {
    pub fn new(batches: Vec<AuditBatchProjection>) -> Self {
        Self {
            schema: AUDIT_PROJECTION_SCHEMA.to_string(),
            batches,
        }
    }
}

impl From<OutputStatus> for ExitCode {
    fn from(value: OutputStatus) -> Self {
        match value {
            OutputStatus::Ok => ExitCode::Completed,
            OutputStatus::Partial => ExitCode::Partial,
            OutputStatus::Blocked => ExitCode::SafetyBlocked,
            OutputStatus::AuthorizationRequired => ExitCode::AuthorizationRequired,
            OutputStatus::Stale => ExitCode::StaleReplanRequired,
            OutputStatus::Failed => ExitCode::OperationFailed,
            OutputStatus::NeedsReconciliation => ExitCode::NeedsReconciliation,
            OutputStatus::Cancelled => ExitCode::Cancelled,
            OutputStatus::Unsupported => ExitCode::Unsupported,
        }
    }
}

/// A stable, read-only projection of an immutable Core plan for human review.
///
/// This DTO is output-only. Deserializing or editing it never creates a `DeletionPlan`, an
/// approval, an execution authorization, or a preflight permit. Callers may use `planId` only to
/// ask Core to load its independently persisted canonical plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanResultSummaryV1 {
    pub review_only: PlanReviewOnly,
    pub plan_id: String,
    pub item_count: DecimalU128,
    pub action_count: DecimalU128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanResultDataV1 {
    pub schema: String,
    pub source_plan_schema: String,
    pub authority: PlanReviewAuthority,
    pub plan_id: String,
    pub canonical_digest: String,
    pub attention_fingerprint: String,
    pub created_at: String,
    pub expires_at: String,
    pub mode: PlanReviewMode,
    pub item_count: DecimalU128,
    pub action_count: DecimalU128,
    pub aggregate_risk: PlanReviewRiskTier,
    pub potentially_reclaimable_bytes: PlanReviewByteRangeV1,
    pub evidence_quality: PlanReviewEvidenceQualityV1,
    pub boundaries: Vec<PlanReviewNoticeV1>,
    pub blockers: Vec<PlanReviewNoticeV1>,
    pub recovery_expectation: PlanReviewRecoveryExpectationV1,
    pub items: Vec<PlanReviewItemV1>,
}

impl PlanResultDataV1 {
    /// Performs cross-field checks that JSON Schema cannot express.
    ///
    /// Validation establishes only that this is a well-formed review projection. It deliberately
    /// does not verify or grant approval or execution authority.
    pub fn validate(&self) -> Result<(), PlanReviewValidationError> {
        if self.schema != PLAN_REVIEW_SCHEMA {
            return Err(PlanReviewValidationError::SchemaMismatch {
                field: "schema",
                expected: PLAN_REVIEW_SCHEMA,
                actual: self.schema.clone(),
            });
        }
        if self.source_plan_schema != SOURCE_PLAN_SCHEMA {
            return Err(PlanReviewValidationError::SchemaMismatch {
                field: "sourcePlanSchema",
                expected: SOURCE_PLAN_SCHEMA,
                actual: self.source_plan_schema.clone(),
            });
        }
        validate_plan_review_text(&self.plan_id, "planId")?;
        validate_plan_digest(&self.canonical_digest)?;
        validate_attention_fingerprint(&self.attention_fingerprint, &self.canonical_digest)?;
        let created_at = parse_plan_review_timestamp(&self.created_at, "createdAt")?;
        let expires_at = parse_plan_review_timestamp(&self.expires_at, "expiresAt")?;
        if created_at >= expires_at {
            return Err(PlanReviewValidationError::InvalidExpiry);
        }

        let item_count: u128 = self.item_count.into();
        let action_count: u128 = self.action_count.into();
        if item_count == 0 || action_count == 0 {
            return Err(PlanReviewValidationError::EmptyPlan);
        }
        if item_count != self.items.len() as u128 {
            return Err(PlanReviewValidationError::CountMismatch {
                field: "itemCount",
                expected: item_count,
                actual: self.items.len() as u128,
            });
        }

        self.potentially_reclaimable_bytes.validate()?;
        self.evidence_quality.validate()?;
        self.recovery_expectation.validate()?;
        validate_plan_review_notices(&self.boundaries, "boundaries")?;
        validate_plan_review_notices(&self.blockers, "blockers")?;

        let mut item_ids = BTreeSet::new();
        let mut action_ids = BTreeSet::new();
        let mut counted_actions = 0u128;
        let mut maximum_risk = PlanReviewRiskTier::R1;
        for item in &self.items {
            item.validate()?;
            if !item_ids.insert(item.item_id.as_str()) {
                return Err(PlanReviewValidationError::DuplicateIdentifier(
                    "items[].itemId",
                ));
            }
            maximum_risk = maximum_risk.max(item.risk_tier);
            for action in &item.actions {
                counted_actions = counted_actions
                    .checked_add(1)
                    .ok_or(PlanReviewValidationError::CountOverflow)?;
                maximum_risk = maximum_risk.max(action.risk_tier);
                if !action_ids.insert(action.action_id.as_str()) {
                    return Err(PlanReviewValidationError::DuplicateIdentifier(
                        "items[].actions[].actionId",
                    ));
                }
            }
        }
        if action_count != counted_actions {
            return Err(PlanReviewValidationError::CountMismatch {
                field: "actionCount",
                expected: action_count,
                actual: counted_actions,
            });
        }
        if self.aggregate_risk != maximum_risk {
            return Err(PlanReviewValidationError::AggregateRiskMismatch);
        }
        let expected_reclaimable_lower = self.items.iter().try_fold(0u128, |total, item| {
            total
                .checked_add(u128::from(item.potentially_reclaimable_bytes.lower_bound))
                .ok_or(PlanReviewValidationError::CountOverflow)
        })?;
        if u128::from(self.potentially_reclaimable_bytes.lower_bound) != expected_reclaimable_lower
        {
            return Err(PlanReviewValidationError::ReclaimableAggregateMismatch);
        }
        let expected_reclaimable_state = aggregate_reclaimable_state(&self.items);
        if self.potentially_reclaimable_bytes.state != expected_reclaimable_state {
            return Err(PlanReviewValidationError::ReclaimableAggregateMismatch);
        }
        let expected_reclaimable_upper = aggregate_reclaimable_upper_bound(&self.items)?;
        if self.potentially_reclaimable_bytes.upper_bound != expected_reclaimable_upper {
            return Err(PlanReviewValidationError::ReclaimableAggregateMismatch);
        }
        if self.mode == PlanReviewMode::Permanent
            && self
                .items
                .iter()
                .flat_map(|item| &item.actions)
                .any(|action| {
                    !matches!(
                        action.risk_tier,
                        PlanReviewRiskTier::R4 | PlanReviewRiskTier::Blocked
                    )
                })
        {
            return Err(PlanReviewValidationError::PermanentRiskBelowR4);
        }
        if self.mode == PlanReviewMode::Permanent
            && self.recovery_expectation.kind != PlanReviewRecoveryKind::NonePermanent
        {
            return Err(PlanReviewValidationError::PermanentRecoveryMismatch);
        }
        if self.mode == PlanReviewMode::Trash
            && self.recovery_expectation.kind == PlanReviewRecoveryKind::NonePermanent
        {
            return Err(PlanReviewValidationError::TrashRecoveryMismatch);
        }
        for item in &self.items {
            if self.mode == PlanReviewMode::Permanent
                && item.recovery_expectation.kind != PlanReviewRecoveryKind::NonePermanent
            {
                return Err(PlanReviewValidationError::PermanentRecoveryMismatch);
            }
            if self.mode == PlanReviewMode::Trash
                && item.recovery_expectation.kind == PlanReviewRecoveryKind::NonePermanent
            {
                return Err(PlanReviewValidationError::TrashRecoveryMismatch);
            }
        }
        let any_blocked_item = self.items.iter().any(|item| {
            item.risk_tier == PlanReviewRiskTier::Blocked
                || !item.blockers.is_empty()
                || item.actions.iter().any(|action| {
                    action.risk_tier == PlanReviewRiskTier::Blocked || !action.blockers.is_empty()
                })
        });
        let review_is_blocked = self.aggregate_risk == PlanReviewRiskTier::Blocked
            || !self.blockers.is_empty()
            || any_blocked_item;
        if review_is_blocked {
            if self.aggregate_risk != PlanReviewRiskTier::Blocked {
                return Err(PlanReviewValidationError::BlockedAggregateRiskMismatch);
            }
            if self.blockers.is_empty() {
                return Err(PlanReviewValidationError::MissingAggregateBlocker);
            }
            if self.authority.approval_path != PlanReviewApprovalPath::Unavailable {
                return Err(PlanReviewValidationError::BlockedApprovalPathAvailable);
            }
        } else if self.authority.approval_path != PlanReviewApprovalPath::TrustedHumanRequired {
            return Err(PlanReviewValidationError::ReviewableApprovalPathUnavailable);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanReviewMode {
    Trash,
    Permanent,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum PlanReviewRiskTier {
    R1,
    R2,
    R3,
    R4,
    #[serde(rename = "BLOCKED")]
    #[schemars(rename = "BLOCKED")]
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanReviewApprovalPath {
    TrustedHumanRequired,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanReviewEvidenceState {
    Known,
    LowerBound,
    Unknown,
    Unsupported,
    NotChecked,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanReviewRecoveryKind {
    PlatformTrash,
    RebuildOrRedownload,
    NonePermanent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanReviewObjectType {
    File,
    Directory,
    Symlink,
    ReparsePoint,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanReviewAuthority {
    pub review_only: PlanReviewOnly,
    pub approval_state: PlanReviewApprovalState,
    pub execution_state: PlanReviewExecutionState,
    pub approval_path: PlanReviewApprovalPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanReviewOnly;

impl Serialize for PlanReviewOnly {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for PlanReviewOnly {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom("reviewOnly must be true"))
        }
    }
}

impl JsonSchema for PlanReviewOnly {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PlanReviewOnly".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        json!({ "const": true })
            .try_into()
            .expect("valid review-only schema")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanReviewApprovalState {
    NotGranted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanReviewExecutionState {
    NotAuthorized,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanReviewByteRangeV1 {
    pub lower_bound: DecimalU128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upper_bound: Option<DecimalU128>,
    pub state: PlanReviewEvidenceState,
    pub reason_codes: Vec<String>,
}

impl PlanReviewByteRangeV1 {
    fn validate(&self) -> Result<(), PlanReviewValidationError> {
        if let Some(upper_bound) = self.upper_bound
            && u128::from(upper_bound) < u128::from(self.lower_bound)
        {
            return Err(PlanReviewValidationError::InvalidReclaimableRange);
        }
        match self.state {
            PlanReviewEvidenceState::Known => {
                if self.upper_bound.is_some() || !self.reason_codes.is_empty() {
                    return Err(PlanReviewValidationError::InvalidReclaimableState);
                }
            }
            PlanReviewEvidenceState::LowerBound => {
                if self.reason_codes.is_empty() {
                    return Err(PlanReviewValidationError::InvalidReclaimableState);
                }
            }
            PlanReviewEvidenceState::Unknown
            | PlanReviewEvidenceState::Unsupported
            | PlanReviewEvidenceState::NotChecked
            | PlanReviewEvidenceState::Stale => {
                if self.upper_bound.is_some() || self.reason_codes.is_empty() {
                    return Err(PlanReviewValidationError::InvalidReclaimableState);
                }
            }
        }
        validate_plan_review_codes(
            &self.reason_codes,
            "potentiallyReclaimableBytes.reasonCodes",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanReviewEvidenceQualityV1 {
    pub fact_codes: Vec<String>,
    pub manager_fact_codes: Vec<String>,
    pub inference_codes: Vec<String>,
    pub heuristic_codes: Vec<String>,
    pub unknown_codes: Vec<String>,
    pub unsupported_codes: Vec<String>,
    pub not_checked_codes: Vec<String>,
    pub stale_codes: Vec<String>,
    pub incomplete_coverage: bool,
    pub observed_at: Vec<String>,
}

impl PlanReviewEvidenceQualityV1 {
    fn validate(&self) -> Result<(), PlanReviewValidationError> {
        for (values, field) in [
            (&self.fact_codes, "evidenceQuality.factCodes"),
            (&self.manager_fact_codes, "evidenceQuality.managerFactCodes"),
            (&self.inference_codes, "evidenceQuality.inferenceCodes"),
            (&self.heuristic_codes, "evidenceQuality.heuristicCodes"),
            (&self.unknown_codes, "evidenceQuality.unknownCodes"),
            (&self.unsupported_codes, "evidenceQuality.unsupportedCodes"),
            (&self.not_checked_codes, "evidenceQuality.notCheckedCodes"),
            (&self.stale_codes, "evidenceQuality.staleCodes"),
        ] {
            validate_plan_review_codes(values, field)?;
        }
        if self.observed_at.is_empty() {
            return Err(PlanReviewValidationError::MissingObservationTime);
        }
        let mut previous = None;
        for observed_at in &self.observed_at {
            let observed_at =
                parse_plan_review_timestamp(observed_at, "evidenceQuality.observedAt[]")?;
            if previous.is_some_and(|value| value >= observed_at) {
                return Err(PlanReviewValidationError::ObservationTimesNotSorted);
            }
            previous = Some(observed_at);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanReviewNoticeV1 {
    pub code: String,
    pub message_key: String,
    pub params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanReviewRecoveryExpectationV1 {
    pub kind: PlanReviewRecoveryKind,
    pub message_key: String,
    pub location_known: bool,
    pub capacity_release_guaranteed: bool,
    pub application_state_loss_possible: bool,
    pub redownload_or_rebuild_required: bool,
    pub detail_codes: Vec<String>,
}

impl PlanReviewRecoveryExpectationV1 {
    fn validate(&self) -> Result<(), PlanReviewValidationError> {
        if self.capacity_release_guaranteed {
            return Err(PlanReviewValidationError::CapacityReleaseClaim);
        }
        if self.kind == PlanReviewRecoveryKind::NonePermanent
            && (self.location_known || self.redownload_or_rebuild_required)
        {
            return Err(PlanReviewValidationError::PermanentRecoveryMismatch);
        }
        validate_plan_review_code(&self.message_key, "recoveryExpectation.messageKey")?;
        validate_plan_review_codes(&self.detail_codes, "recoveryExpectation.detailCodes")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanReviewItemV1 {
    pub item_id: String,
    pub candidate_id: String,
    pub display_path: String,
    pub object_type: PlanReviewObjectType,
    pub risk_tier: PlanReviewRiskTier,
    pub risk_factors: Vec<String>,
    pub potentially_reclaimable_bytes: PlanReviewByteRangeV1,
    pub evidence_quality: PlanReviewEvidenceQualityV1,
    pub boundaries: Vec<PlanReviewNoticeV1>,
    pub blockers: Vec<PlanReviewNoticeV1>,
    pub recovery_expectation: PlanReviewRecoveryExpectationV1,
    pub actions: Vec<PlanReviewActionV1>,
}

impl PlanReviewItemV1 {
    fn validate(&self) -> Result<(), PlanReviewValidationError> {
        validate_plan_review_text(&self.item_id, "items[].itemId")?;
        validate_plan_review_text(&self.candidate_id, "items[].candidateId")?;
        validate_plan_review_text(&self.display_path, "items[].displayPath")?;
        validate_plan_review_codes(&self.risk_factors, "items[].riskFactors")?;
        if self.actions.is_empty() {
            return Err(PlanReviewValidationError::ItemWithoutActions);
        }
        self.potentially_reclaimable_bytes.validate()?;
        self.evidence_quality.validate()?;
        self.recovery_expectation.validate()?;
        validate_plan_review_notices(&self.boundaries, "items[].boundaries")?;
        validate_plan_review_notices(&self.blockers, "items[].blockers")?;
        let maximum_risk =
            self.actions
                .iter()
                .try_fold(PlanReviewRiskTier::R1, |maximum, action| {
                    action.validate()?;
                    Ok::<_, PlanReviewValidationError>(maximum.max(action.risk_tier))
                })?;
        if self.risk_tier < maximum_risk {
            return Err(PlanReviewValidationError::ItemRiskBelowAction);
        }
        if (self.risk_tier == PlanReviewRiskTier::Blocked || !self.blockers.is_empty())
            && self
                .actions
                .iter()
                .all(|action| action.risk_tier != PlanReviewRiskTier::Blocked)
        {
            return Err(PlanReviewValidationError::BlockedItemWithoutBlockedAction);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanReviewActionV1 {
    pub action_id: String,
    pub risk_tier: PlanReviewRiskTier,
    pub risk_factors: Vec<String>,
    pub blockers: Vec<PlanReviewNoticeV1>,
}

impl PlanReviewActionV1 {
    fn validate(&self) -> Result<(), PlanReviewValidationError> {
        validate_plan_review_text(&self.action_id, "items[].actions[].actionId")?;
        validate_plan_review_codes(&self.risk_factors, "items[].actions[].riskFactors")?;
        validate_plan_review_notices(&self.blockers, "items[].actions[].blockers")?;
        if !self.blockers.is_empty() && self.risk_tier != PlanReviewRiskTier::Blocked {
            return Err(PlanReviewValidationError::BlockedActionRiskMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanReviewValidationError {
    SchemaMismatch {
        field: &'static str,
        expected: &'static str,
        actual: String,
    },
    EmptyField(&'static str),
    InvalidCode(&'static str),
    DuplicateCode(&'static str),
    InvalidTimestamp(&'static str),
    InvalidExpiry,
    InvalidDigest,
    InvalidAttentionFingerprint,
    EmptyPlan,
    CountMismatch {
        field: &'static str,
        expected: u128,
        actual: u128,
    },
    CountOverflow,
    DuplicateIdentifier(&'static str),
    InvalidReclaimableRange,
    InvalidReclaimableState,
    ObservationTimesNotSorted,
    MissingObservationTime,
    CapacityReleaseClaim,
    ItemWithoutActions,
    ItemRiskBelowAction,
    AggregateRiskMismatch,
    ReclaimableAggregateMismatch,
    PermanentRiskBelowR4,
    PermanentRecoveryMismatch,
    TrashRecoveryMismatch,
    BlockedActionRiskMismatch,
    BlockedItemWithoutBlockedAction,
    BlockedAggregateRiskMismatch,
    MissingAggregateBlocker,
    BlockedApprovalPathAvailable,
    ReviewableApprovalPathUnavailable,
}

impl fmt::Display for PlanReviewValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SchemaMismatch {
                field,
                expected,
                actual,
            } => write!(formatter, "{field} must be {expected}, got {actual}"),
            Self::EmptyField(field) => write!(formatter, "field is empty: {field}"),
            Self::InvalidCode(field) => write!(formatter, "field is not a machine code: {field}"),
            Self::DuplicateCode(field) => write!(formatter, "field contains duplicate codes: {field}"),
            Self::InvalidTimestamp(field) => write!(formatter, "invalid RFC 3339 timestamp: {field}"),
            Self::InvalidExpiry => formatter.write_str("expiresAt must be later than createdAt"),
            Self::InvalidDigest => formatter.write_str("canonicalDigest must be 64 lowercase hexadecimal characters"),
            Self::InvalidAttentionFingerprint => formatter.write_str("attentionFingerprint must match the first 12 digest characters and is attention-only"),
            Self::EmptyPlan => formatter.write_str("plan review counts must be non-zero"),
            Self::CountMismatch { field, expected, actual } => write!(formatter, "{field} mismatch: declared {expected}, observed {actual}"),
            Self::CountOverflow => formatter.write_str("plan review action count overflowed"),
            Self::DuplicateIdentifier(field) => write!(formatter, "duplicate identifier: {field}"),
            Self::InvalidReclaimableRange => formatter.write_str("reclaimable upper bound is smaller than its lower bound"),
            Self::InvalidReclaimableState => formatter.write_str("reclaimable range fields do not match its evidence state"),
            Self::ObservationTimesNotSorted => formatter.write_str("observation timestamps must be sorted and unique"),
            Self::MissingObservationTime => formatter.write_str("plan review evidence must include an observation time"),
            Self::CapacityReleaseClaim => formatter.write_str("plan review cannot guarantee capacity release"),
            Self::ItemWithoutActions => formatter.write_str("review item must contain at least one action"),
            Self::ItemRiskBelowAction => formatter.write_str("item risk cannot be below an action risk"),
            Self::AggregateRiskMismatch => formatter.write_str("aggregate risk must equal the maximum item/action risk"),
            Self::ReclaimableAggregateMismatch => formatter.write_str("aggregate reclaimable range must equal the conservative sum of item ranges"),
            Self::PermanentRiskBelowR4 => formatter.write_str("permanent actions must be R4 or BLOCKED"),
            Self::PermanentRecoveryMismatch => formatter.write_str("permanent plans must expose the non-recoverable recovery expectation"),
            Self::TrashRecoveryMismatch => formatter.write_str("trash plans cannot claim the permanent recovery expectation"),
            Self::BlockedActionRiskMismatch => formatter.write_str("an action with blockers must have BLOCKED risk"),
            Self::BlockedItemWithoutBlockedAction => formatter.write_str("a blocked item must contain a blocked action"),
            Self::BlockedAggregateRiskMismatch => formatter.write_str("a review containing blockers must have BLOCKED aggregate risk"),
            Self::MissingAggregateBlocker => formatter.write_str("a blocked review must expose at least one aggregate blocker"),
            Self::BlockedApprovalPathAvailable => formatter.write_str("a blocked review cannot expose an approval path"),
            Self::ReviewableApprovalPathUnavailable => formatter.write_str("a non-blocked review must require the trusted human approval path"),
        }
    }
}

impl Error for PlanReviewValidationError {}

fn aggregate_reclaimable_state(items: &[PlanReviewItemV1]) -> PlanReviewEvidenceState {
    if items.iter().any(|item| {
        matches!(
            item.potentially_reclaimable_bytes.state,
            PlanReviewEvidenceState::Unknown
                | PlanReviewEvidenceState::Unsupported
                | PlanReviewEvidenceState::NotChecked
                | PlanReviewEvidenceState::Stale
        )
    }) {
        PlanReviewEvidenceState::Unknown
    } else if items
        .iter()
        .any(|item| item.potentially_reclaimable_bytes.state == PlanReviewEvidenceState::LowerBound)
    {
        PlanReviewEvidenceState::LowerBound
    } else {
        PlanReviewEvidenceState::Known
    }
}

fn aggregate_reclaimable_upper_bound(
    items: &[PlanReviewItemV1],
) -> Result<Option<DecimalU128>, PlanReviewValidationError> {
    if aggregate_reclaimable_state(items) != PlanReviewEvidenceState::LowerBound
        || items
            .iter()
            .any(|item| item.potentially_reclaimable_bytes.upper_bound.is_none())
    {
        return Ok(None);
    }

    items
        .iter()
        .try_fold(0u128, |total, item| {
            total
                .checked_add(u128::from(
                    item.potentially_reclaimable_bytes
                        .upper_bound
                        .expect("all upper bounds checked"),
                ))
                .ok_or(PlanReviewValidationError::CountOverflow)
        })
        .map(|value| Some(DecimalU128::new(value)))
}

fn validate_plan_review_text(
    value: &str,
    field: &'static str,
) -> Result<(), PlanReviewValidationError> {
    if value.trim().is_empty() {
        return Err(PlanReviewValidationError::EmptyField(field));
    }
    Ok(())
}

fn validate_plan_review_code(
    value: &str,
    field: &'static str,
) -> Result<(), PlanReviewValidationError> {
    validate_plan_review_text(value, field)?;
    if value.len() > 128
        || !value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
    {
        return Err(PlanReviewValidationError::InvalidCode(field));
    }
    Ok(())
}

fn validate_plan_review_codes(
    values: &[String],
    field: &'static str,
) -> Result<(), PlanReviewValidationError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_plan_review_code(value, field)?;
        if !unique.insert(value.as_str()) {
            return Err(PlanReviewValidationError::DuplicateCode(field));
        }
    }
    Ok(())
}

fn validate_plan_review_notices(
    notices: &[PlanReviewNoticeV1],
    field: &'static str,
) -> Result<(), PlanReviewValidationError> {
    let mut codes = BTreeSet::new();
    for notice in notices {
        validate_plan_review_code(&notice.code, field)?;
        validate_plan_review_code(&notice.message_key, field)?;
        for (key, value) in &notice.params {
            validate_plan_review_code(key, field)?;
            validate_plan_review_text(value, field)?;
        }
        if !codes.insert(notice.code.as_str()) {
            return Err(PlanReviewValidationError::DuplicateCode(field));
        }
    }
    Ok(())
}

fn validate_plan_digest(value: &str) -> Result<(), PlanReviewValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PlanReviewValidationError::InvalidDigest);
    }
    Ok(())
}

fn validate_attention_fingerprint(
    fingerprint: &str,
    canonical_digest: &str,
) -> Result<(), PlanReviewValidationError> {
    let expected = format!("SX1-{}", canonical_digest[..12].to_ascii_uppercase());
    if fingerprint != expected {
        return Err(PlanReviewValidationError::InvalidAttentionFingerprint);
    }
    Ok(())
}

fn parse_plan_review_timestamp(
    value: &str,
    field: &'static str,
) -> Result<OffsetDateTime, PlanReviewValidationError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| PlanReviewValidationError::InvalidTimestamp(field))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str =
        "sha256:a4ca63a314f521618213d027be930e4ec1e228b1b08666d915efcd68a7a85654";
    const DIGEST_B: &str =
        "sha256:0830bfa6d9b4b8bd9f1d0a902596135181dc15c820c044c61af45ae30018e6e2";
    const DIGEST_C: &str =
        "sha256:7f5ae547e80fd9244c805b929ca0c13d7517d13807ae2ecaca4bc8bd611dd54d";
    const EVALUATION_TIME: &str = "2026-08-28T00:00:00Z";

    fn qualified_mutation_record() -> CapabilityRecordV1 {
        CapabilityRecordV1 {
            schema: CAPABILITY_RECORD_SCHEMA.to_string(),
            recorded_at: "2026-08-27T12:00:00+08:00".to_string(),
            qualification_key: QualificationKey {
                scope: QualificationScope::Platform,
                core_version: "0.9.0-beta.1".to_string(),
                scanner_semantics_version: 2,
                safety_policy_digest: DIGEST_A.to_string(),
                adapter_id: "linux-gio-trash".to_string(),
                adapter_digest: DIGEST_B.to_string(),
                os_family: OsFamily::Linux,
                os_build: "6.12.10-arch1-1".to_string(),
                arch: "x86_64".to_string(),
                filesystem: "ext4".to_string(),
                filesystem_version: Some("1.0-feature-set".to_string()),
                volume_class: "local".to_string(),
                provider_or_desktop_backend: Some("gio-2.84.1".to_string()),
                runtime_privilege_profile: RuntimePrivilegeProfile::OrdinaryUser,
                cleaner_id: None,
                cleaner_version: None,
                capability: CapabilityCell::new(CapabilityCell::TRASH_LOCAL_FILE).unwrap(),
            },
            state: CapabilityState::Qualified,
            reason_code: "REAL_OS_MATRIX_PASSED".to_string(),
            reason: Some("The exact tuple passed reviewed real-OS tests.".to_string()),
            evidence: CapabilityEvidence {
                bundle_digest: DIGEST_C.to_string(),
                evidence_class: EvidenceClass::RealOsQualification,
                reviewed_by: vec!["reviewer@example.test".to_string()],
                limitations: vec!["local filesystem only".to_string()],
                invalidates_on: vec!["adapter-digest-change".to_string()],
                validity: Some(QualificationValidity {
                    status: QualificationValidityStatus::Current,
                    valid_from: Some("2026-08-27T00:00:00Z".to_string()),
                    expires_at: Some("2026-11-27T00:00:00Z".to_string()),
                    invalidated_at: None,
                    invalidation_reason: None,
                }),
            },
        }
    }

    fn compat() -> CompatSnapshot {
        CompatSnapshot {
            core_version: "0.1.0".to_string(),
            scanner_semantics_version: 1,
            safety_policy_version: 1,
            platform_adapter: PlatformAdapterCompat {
                id: "test".to_string(),
                version: "0.1.0".to_string(),
            },
            cleaner_set_digest: "sha256:test".to_string(),
            required_features: vec![],
            extensions: vec![],
        }
    }

    fn plan_review_example() -> PlanResultDataV1 {
        serde_json::from_str(include_str!(
            "../../../schemas/examples/sweepx.output.plan.result.example.json"
        ))
        .and_then(|envelope: OutputEnvelope| serde_json::from_value(envelope.data))
        .expect("valid plan review example")
    }

    fn plan_review_summary_example() -> PlanResultSummaryV1 {
        serde_json::from_str(include_str!(
            "../../../schemas/examples/sweepx.output.plan.result.example.json"
        ))
        .and_then(|envelope: OutputEnvelope| serde_json::from_value(envelope.summary))
        .expect("valid plan review summary example")
    }

    #[test]
    fn plan_review_example_is_a_valid_read_only_projection() {
        let review = plan_review_example();
        review.validate().unwrap();
        assert_eq!(review.schema, PLAN_REVIEW_SCHEMA);
        assert_eq!(review.source_plan_schema, SOURCE_PLAN_SCHEMA);
        assert_eq!(review.authority.review_only, PlanReviewOnly);
        assert_eq!(
            review.authority.approval_state,
            PlanReviewApprovalState::NotGranted
        );
        assert_eq!(
            review.authority.execution_state,
            PlanReviewExecutionState::NotAuthorized
        );
        assert_eq!(review.item_count.to_string(), "1");
        assert_eq!(review.action_count.to_string(), "2");
        let summary = plan_review_summary_example();
        assert_eq!(summary.review_only, PlanReviewOnly);
        assert_eq!(summary.plan_id, review.plan_id);
        assert_eq!(summary.item_count, review.item_count);
        assert_eq!(summary.action_count, review.action_count);
    }

    #[test]
    fn plan_review_uses_stable_camel_case_and_decimal_strings() {
        let encoded = serde_json::to_value(plan_review_example()).unwrap();
        assert_eq!(encoded["schema"], PLAN_REVIEW_SCHEMA);
        assert_eq!(encoded["authority"]["reviewOnly"], true);
        assert_eq!(encoded["authority"]["approvalState"], "not_granted");
        assert_eq!(encoded["authority"]["executionState"], "not_authorized");
        assert_eq!(encoded["itemCount"], "1");
        assert_eq!(encoded["actionCount"], "2");
        assert_eq!(encoded["potentiallyReclaimableBytes"]["lowerBound"], "4096");
        assert!(encoded.get("item_count").is_none());
        assert!(encoded.get("approvalId").is_none());
        assert!(encoded.get("authorizationId").is_none());
        assert!(encoded.get("nonce").is_none());

        let golden: Value = serde_json::from_str(include_str!(
            "../../../schemas/examples/sweepx.output.plan.result.example.json"
        ))
        .unwrap();
        assert_eq!(encoded, golden["data"]);
    }

    #[test]
    fn plan_review_rejects_unknown_fields() {
        let mut encoded = serde_json::to_value(plan_review_example()).unwrap();
        encoded["approvalId"] = json!("forbidden");
        assert!(serde_json::from_value::<PlanResultDataV1>(encoded).is_err());

        let mut encoded = serde_json::to_value(plan_review_example()).unwrap();
        encoded["items"][0]["actions"][0]["permit"] = json!("forbidden");
        assert!(serde_json::from_value::<PlanResultDataV1>(encoded).is_err());

        let mut encoded = serde_json::to_value(plan_review_example()).unwrap();
        encoded["authority"]["reviewOnly"] = json!(false);
        assert!(serde_json::from_value::<PlanResultDataV1>(encoded).is_err());
    }

    #[test]
    fn plan_review_validation_rejects_authority_and_count_drift() {
        let mut review = plan_review_example();
        review.item_count = DecimalU128::new(2);
        assert!(matches!(
            review.validate(),
            Err(PlanReviewValidationError::CountMismatch {
                field: "itemCount",
                ..
            })
        ));

        let mut review = plan_review_example();
        review.attention_fingerprint = "SX1-FFFFFFFFFFFF".to_string();
        assert!(matches!(
            review.validate(),
            Err(PlanReviewValidationError::InvalidAttentionFingerprint)
        ));

        let mut review = plan_review_example();
        review.recovery_expectation.capacity_release_guaranteed = true;
        assert!(matches!(
            review.validate(),
            Err(PlanReviewValidationError::CapacityReleaseClaim)
        ));

        let mut review = plan_review_example();
        review.potentially_reclaimable_bytes.lower_bound = DecimalU128::new(4097);
        assert!(matches!(
            review.validate(),
            Err(PlanReviewValidationError::ReclaimableAggregateMismatch)
        ));
    }

    #[test]
    fn plan_review_validation_enforces_permanent_and_blocked_gates() {
        let mut permanent = plan_review_example();
        permanent.mode = PlanReviewMode::Permanent;
        assert!(matches!(
            permanent.validate(),
            Err(PlanReviewValidationError::PermanentRiskBelowR4)
        ));

        let mut blocked = plan_review_example();
        blocked.aggregate_risk = PlanReviewRiskTier::Blocked;
        blocked.items[0].risk_tier = PlanReviewRiskTier::Blocked;
        blocked.items[0].actions[0].risk_tier = PlanReviewRiskTier::Blocked;
        blocked.items[0].actions[0]
            .blockers
            .push(PlanReviewNoticeV1 {
                code: "protected_anchor".to_string(),
                message_key: "plan.review.blocker.protected_anchor".to_string(),
                params: BTreeMap::new(),
            });
        blocked.items[0].blockers = blocked.items[0].actions[0].blockers.clone();
        blocked.blockers = blocked.items[0].blockers.clone();
        assert!(matches!(
            blocked.validate(),
            Err(PlanReviewValidationError::BlockedApprovalPathAvailable)
        ));
        blocked.authority.approval_path = PlanReviewApprovalPath::Unavailable;
        blocked.validate().unwrap();
    }

    #[test]
    fn plan_review_validation_rejects_unstable_enums_and_nested_blocker_drift() {
        let mut invalid_action = serde_json::to_value(plan_review_example()).unwrap();
        invalid_action["items"][0]["actions"][0]["actionKind"] = json!("任意动作");
        assert!(serde_json::from_value::<PlanResultDataV1>(invalid_action).is_err());

        let mut hidden_blocker = plan_review_example();
        hidden_blocker.items[0].actions[0].risk_tier = PlanReviewRiskTier::Blocked;
        hidden_blocker.items[0].actions[0]
            .blockers
            .push(PlanReviewNoticeV1 {
                code: "protected_anchor".to_string(),
                message_key: "plan.review.blocker.protected_anchor".to_string(),
                params: BTreeMap::new(),
            });
        hidden_blocker.items[0].risk_tier = PlanReviewRiskTier::Blocked;
        hidden_blocker.aggregate_risk = PlanReviewRiskTier::Blocked;
        assert!(matches!(
            hidden_blocker.validate(),
            Err(PlanReviewValidationError::MissingAggregateBlocker)
        ));
    }

    #[test]
    fn output_status_maps_to_expected_exit_code() {
        assert_eq!(ExitCode::from(OutputStatus::Ok), ExitCode::Completed);
        assert_eq!(
            ExitCode::from(OutputStatus::AuthorizationRequired),
            ExitCode::AuthorizationRequired
        );
        assert_eq!(
            ExitCode::from(OutputStatus::NeedsReconciliation),
            ExitCode::NeedsReconciliation
        );
    }

    #[test]
    fn exit_precedence_prefers_more_conservative_meaning() {
        assert_eq!(
            ExitCode::Cancelled.more_conservative(ExitCode::NeedsReconciliation),
            ExitCode::NeedsReconciliation
        );
        assert_eq!(
            ExitCode::Partial.more_conservative(ExitCode::OperationFailed),
            ExitCode::OperationFailed
        );
        assert_eq!(
            ExitCode::Unsupported.more_conservative(ExitCode::Completed),
            ExitCode::Unsupported
        );
    }

    #[test]
    fn output_envelope_conservative_exit_code_uses_status_when_stronger() {
        let envelope = OutputEnvelope::new(
            OutputKind::ExecutionResult,
            RequestId::new("req-1"),
            OperationId::new("op-1"),
            "2026-08-26T00:00:00Z",
            OutputStatus::NeedsReconciliation,
            ExitCode::Cancelled,
            compat(),
        );
        assert_eq!(
            envelope.conservative_exit_code(),
            ExitCode::NeedsReconciliation
        );
    }

    #[test]
    fn event_envelope_marks_terminal_only_for_terminal_event_type() {
        let terminal = EventEnvelope {
            schema: EVENT_SCHEMA.to_string(),
            stream_id: "stream-1".to_string(),
            operation_id: OperationId::new("op-1"),
            sequence: DecimalU128::new(42),
            cursor: "cursor".to_string(),
            emitted_at: "2026-08-26T00:00:00Z".to_string(),
            monotonic_offset_ns: DecimalU128::new(1234),
            r#type: EventType::OperationTerminal,
            phase: EventPhase::Audit,
            payload: json!({
                "status": "ok",
                "exitCode": 0,
                "kind": "scan.result",
                "snapshotDigest": format!("sha256:{}", "a".repeat(64))
            }),
            terminal: true,
            checkpoint: EventCheckpoint {
                durable: true,
                last_durable_sequence: DecimalU128::new(42),
            },
        };
        assert!(terminal.is_terminal_type());

        let non_terminal = EventEnvelope {
            r#type: EventType::ScanProgress,
            terminal: false,
            ..terminal
        };
        assert!(!non_terminal.is_terminal_type());
    }

    #[test]
    fn stream_reset_payload_is_typed_and_rejects_unknown_fields() {
        let event = EventEnvelope {
            schema: EVENT_SCHEMA.to_string(),
            stream_id: "replay-control-op-1".to_string(),
            operation_id: OperationId::new("op-1"),
            sequence: DecimalU128::new(1),
            cursor: "sxcur1.control-token-0001".to_string(),
            emitted_at: "2026-08-26T00:00:00Z".to_string(),
            monotonic_offset_ns: DecimalU128::ZERO,
            r#type: EventType::StreamResetRequired,
            phase: EventPhase::Audit,
            payload: json!({
                "requestedCursor": "sxcur1.unknown-token-0001",
                "availableFromSequence": "1",
                "snapshotRef": { "operationId": "op-1" },
                "resumeAfter": "sxcur1.terminal-token-001"
            }),
            terminal: false,
            checkpoint: EventCheckpoint {
                durable: false,
                last_durable_sequence: DecimalU128::ZERO,
            },
        };
        event.validate().unwrap();
        let payload = event.stream_reset_required_payload().unwrap();
        assert_eq!(payload.snapshot_ref.operation_id, "op-1");
        assert_eq!(payload.available_from_sequence, DecimalU128::new(1));
        assert!(matches!(
            event.validate_for_durable_stream(),
            Err(EventValidationError::DeliveryControlInDurableStream)
        ));

        let mut durable_control = event.clone();
        durable_control.checkpoint.durable = true;
        durable_control.checkpoint.last_durable_sequence = durable_control.sequence;
        assert!(matches!(
            durable_control.validate(),
            Err(EventValidationError::DeliveryControlMustNotBeDurable)
        ));

        let mut unknown_field = event.clone();
        unknown_field.payload["unexpected"] = json!(true);
        assert!(matches!(
            unknown_field.stream_reset_required_payload(),
            Err(EventValidationError::InvalidStreamResetPayload(_))
        ));

        let mut invalid_available_from = event;
        invalid_available_from.payload["availableFromSequence"] = json!("2");
        assert!(matches!(
            invalid_available_from.stream_reset_required_payload(),
            Err(EventValidationError::InvalidStreamResetPayload(_))
        ));

        let oversized = format!("sxcur1.{}", "a".repeat(MAX_EVENT_CURSOR_BYTES));
        let mut oversized_cursor = invalid_available_from;
        oversized_cursor.payload["requestedCursor"] = json!(oversized);
        assert!(matches!(
            oversized_cursor.stream_reset_required_payload(),
            Err(EventValidationError::FieldTooLong {
                field: "cursor",
                ..
            })
        ));
    }

    fn durable_event_stream_example() -> Vec<EventEnvelope> {
        include_str!("../../../schemas/examples/sweepx.event.durable-stream.golden.ndjson")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("valid event golden line"))
            .collect()
    }

    fn terminal_expectation() -> TerminalEventExpectation {
        TerminalEventExpectation::new(
            OutputStatus::Ok,
            ExitCode::Completed,
            OutputKind::ScanResult,
            "sha256:89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
        )
    }

    #[test]
    fn durable_event_golden_validates_as_single_events_and_stream() {
        let events = durable_event_stream_example();
        assert_eq!(events.len(), 3);
        for event in &events {
            event.validate().unwrap();
            event.validate_for_durable_stream().unwrap();
        }
        validate_durable_event_stream(&events, &terminal_expectation()).unwrap();
    }

    #[test]
    fn single_event_validation_preserves_legacy_in_memory_cursor() {
        let mut event = durable_event_stream_example().remove(1);
        event.cursor = "stream-golden-001:2".to_string();
        event.validate().unwrap();
        assert!(matches!(
            event.validate_for_durable_stream(),
            Err(EventValidationError::InvalidDurableCursor)
        ));
    }

    #[test]
    fn event_validation_enforces_bounds_terminal_equivalence_and_checkpoints() {
        let events = durable_event_stream_example();

        let mut zero = events[0].clone();
        zero.sequence = DecimalU128::ZERO;
        assert!(matches!(
            zero.validate(),
            Err(EventValidationError::ZeroSequence)
        ));

        let mut oversized_id = events[0].clone();
        oversized_id.stream_id = "x".repeat(MAX_EVENT_ID_BYTES + 1);
        assert!(matches!(
            oversized_id.validate(),
            Err(EventValidationError::FieldTooLong {
                field: "streamId",
                ..
            })
        ));

        let mut non_utc = events[0].clone();
        non_utc.emitted_at = "2026-08-28T09:00:00+08:00".to_string();
        assert!(matches!(
            non_utc.validate(),
            Err(EventValidationError::TimestampNotUtc)
        ));

        let mut oversized_payload = events[1].clone();
        oversized_payload.payload = json!({ "value": "x".repeat(MAX_EVENT_PAYLOAD_BYTES) });
        assert!(matches!(
            oversized_payload.validate(),
            Err(EventValidationError::PayloadTooLarge { .. })
        ));

        let mut false_terminal = events[1].clone();
        false_terminal.terminal = true;
        assert!(matches!(
            false_terminal.validate(),
            Err(EventValidationError::TerminalFlagMismatch)
        ));

        let mut durable_drift = events[0].clone();
        durable_drift.checkpoint.last_durable_sequence = DecimalU128::ZERO;
        assert!(matches!(
            durable_drift.validate(),
            Err(EventValidationError::DurableCheckpointMismatch { .. })
        ));

        let mut non_durable_drift = events[1].clone();
        non_durable_drift.checkpoint.last_durable_sequence = non_durable_drift.sequence;
        assert!(matches!(
            non_durable_drift.validate(),
            Err(EventValidationError::NonDurableCheckpointNotBeforeEvent { .. })
        ));
    }

    #[test]
    fn durable_stream_validation_rejects_sequence_identity_and_order_drift() {
        let expectation = terminal_expectation();

        let mut sequence_gap = durable_event_stream_example();
        sequence_gap[1].sequence = DecimalU128::new(3);
        sequence_gap[1].checkpoint.last_durable_sequence = DecimalU128::new(1);
        assert!(matches!(
            validate_durable_event_stream(&sequence_gap, &expectation),
            Err(EventStreamValidationError::SequenceMismatch { index: 1, .. })
        ));

        let mut stream_drift = durable_event_stream_example();
        stream_drift[1].stream_id = "other-stream".to_string();
        assert!(matches!(
            validate_durable_event_stream(&stream_drift, &expectation),
            Err(EventStreamValidationError::StreamIdMismatch { index: 1 })
        ));

        let mut operation_drift = durable_event_stream_example();
        operation_drift[1].operation_id = OperationId::new("other-operation");
        assert!(matches!(
            validate_durable_event_stream(&operation_drift, &expectation),
            Err(EventStreamValidationError::OperationIdMismatch { index: 1 })
        ));

        let mut not_started = durable_event_stream_example();
        not_started[0].r#type = EventType::ScanProgress;
        assert!(matches!(
            validate_durable_event_stream(&not_started, &expectation),
            Err(EventStreamValidationError::FirstEventNotStarted)
        ));

        let mut terminal_not_last = durable_event_stream_example();
        terminal_not_last.swap(1, 2);
        terminal_not_last[1].sequence = DecimalU128::new(2);
        terminal_not_last[1].checkpoint.last_durable_sequence = DecimalU128::new(2);
        terminal_not_last[2].sequence = DecimalU128::new(3);
        terminal_not_last[2].checkpoint.last_durable_sequence = DecimalU128::new(2);
        assert!(matches!(
            validate_durable_event_stream(&terminal_not_last, &expectation),
            Err(EventStreamValidationError::TerminalNotLast)
        ));
    }

    #[test]
    fn durable_stream_validation_rejects_checkpoint_time_and_terminal_drift() {
        let expectation = terminal_expectation();

        let mut checkpoint_drift = durable_event_stream_example();
        checkpoint_drift[1].checkpoint.last_durable_sequence = DecimalU128::ZERO;
        assert!(matches!(
            validate_durable_event_stream(&checkpoint_drift, &expectation),
            Err(EventStreamValidationError::CheckpointHistoryMismatch { index: 1, .. })
        ));

        let mut time_regression = durable_event_stream_example();
        time_regression[1].emitted_at = "2026-08-28T00:59:59Z".to_string();
        assert!(matches!(
            validate_durable_event_stream(&time_regression, &expectation),
            Err(EventStreamValidationError::EmittedAtRegression { index: 1 })
        ));

        let mut monotonic_regression = durable_event_stream_example();
        monotonic_regression[2].monotonic_offset_ns = DecimalU128::new(999);
        assert!(matches!(
            validate_durable_event_stream(&monotonic_regression, &expectation),
            Err(EventStreamValidationError::MonotonicOffsetRegression { index: 2 })
        ));

        let mut payload_drift = durable_event_stream_example();
        payload_drift[2].payload["snapshotDigest"] = json!(format!("sha256:{}", "0".repeat(64)));
        assert!(matches!(
            validate_durable_event_stream(&payload_drift, &expectation),
            Err(EventStreamValidationError::TerminalExpectationMismatch {
                field: "snapshotDigest"
            })
        ));

        let mut weak_exit = durable_event_stream_example();
        weak_exit[2].payload["status"] = json!("failed");
        assert!(matches!(
            validate_durable_event_stream(&weak_exit, &expectation),
            Err(EventStreamValidationError::InvalidEvent {
                index: 2,
                source: EventValidationError::TerminalExitTooWeak { .. }
            })
        ));
    }

    #[test]
    fn protocol_envelopes_serialize_with_stable_schema_names() {
        let envelope = OutputEnvelope::new(
            OutputKind::StatusResult,
            RequestId::new("req-1"),
            OperationId::new("op-1"),
            "2026-08-26T00:00:00Z",
            OutputStatus::Ok,
            ExitCode::Completed,
            compat(),
        );

        let encoded = serde_json::to_value(envelope).unwrap();
        assert_eq!(encoded["schema"], OUTPUT_SCHEMA);
        assert_eq!(encoded["kind"], "status.result");
        assert_eq!(encoded["status"], "ok");
        assert_eq!(encoded["exitCode"], 0);
        assert_eq!(encoded["requestId"], "req-1");
        assert!(encoded.get("request_id").is_none());
    }

    #[test]
    fn event_types_use_the_frozen_dotted_wire_names() {
        assert_eq!(
            serde_json::to_value(EventType::OperationStarted).unwrap(),
            json!("operation.started")
        );
        assert_eq!(
            serde_json::to_value(EventType::OperationTerminal).unwrap(),
            json!("operation.terminal")
        );
    }

    #[test]
    fn legacy_capability_example_deserializes_and_validates() {
        let example = include_str!("../../../schemas/examples/capability-record.example.json");
        let record: CapabilityRecordV1 = serde_json::from_str(example).unwrap();
        record.validate().unwrap();
        assert_eq!(record.schema, CAPABILITY_RECORD_SCHEMA);
        assert_eq!(record.state, CapabilityState::ReportOnly);
        assert_eq!(
            record.qualification_key.capability.as_str(),
            CapabilityCell::TRASH_LOCAL_FILE
        );
    }

    #[test]
    fn capability_record_uses_stable_camel_case_wire_names() {
        let encoded = serde_json::to_value(qualified_mutation_record()).unwrap();
        assert_eq!(encoded["schema"], CAPABILITY_RECORD_SCHEMA);
        assert_eq!(encoded["state"], "qualified");
        assert_eq!(
            encoded["qualificationKey"]["filesystemVersion"],
            "1.0-feature-set"
        );
        assert_eq!(
            encoded["qualificationKey"]["runtimePrivilegeProfile"],
            "ordinary_user"
        );
        assert_eq!(
            encoded["evidence"]["evidenceClass"],
            "real_os_qualification"
        );
        assert_eq!(encoded["evidence"]["validity"]["status"], "current");
        assert!(encoded.get("qualification_key").is_none());
        assert!(encoded["evidence"].get("evidence_class").is_none());
        assert!(encoded["evidence"].get("expiresAt").is_none());
    }

    #[test]
    fn real_os_current_exact_mutation_tuple_qualifies() {
        let record = qualified_mutation_record();
        record.validate_at(EVALUATION_TIME).unwrap();
        record.validate_qualified_at(EVALUATION_TIME).unwrap();
        assert!(record.is_qualified_mutation_at(EVALUATION_TIME));
        assert!(matches!(
            record.validate(),
            Err(CapabilityValidationError::EvaluationTimeRequired)
        ));
        assert!(!record.is_qualified_mutation());
    }

    #[test]
    fn all_explicitly_non_qualifying_evidence_classes_fail_closed() {
        for evidence_class in [
            EvidenceClass::FixtureConformanceOnly,
            EvidenceClass::Fake,
            EvidenceClass::Placeholder,
            EvidenceClass::Incomplete,
            EvidenceClass::Stale,
            EvidenceClass::Mismatched,
        ] {
            let mut record = qualified_mutation_record();
            record.evidence.evidence_class = evidence_class;
            assert!(matches!(
                record.validate_at(EVALUATION_TIME),
                Err(CapabilityValidationError::NonQualifyingEvidenceClass {
                    evidence_class: actual
                }) if actual == evidence_class
            ));
        }
    }

    #[test]
    fn development_evidence_can_qualify_read_only_but_never_mutation() {
        let mut record = qualified_mutation_record();
        record.evidence.evidence_class = EvidenceClass::DevelopmentSnapshot;
        assert!(matches!(
            record.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::MutationRequiresRealOsEvidence)
        ));

        record.qualification_key.capability =
            CapabilityCell::new(CapabilityCell::SCAN_LOCAL_DIRECTORY).unwrap();
        record.validate_qualified_at(EVALUATION_TIME).unwrap();
    }

    #[test]
    fn stream_state_and_completed_replay_cells_are_classified_read_only() {
        for capability in [
            CapabilityCell::SCAN_NDJSON_STREAM,
            CapabilityCell::OPERATION_SNAPSHOT_DURABLE,
            CapabilityCell::OPERATION_EVENT_COMPLETED_REPLAY,
        ] {
            assert!(
                !CapabilityCell::new(capability)
                    .unwrap()
                    .requires_strong_qualification()
            );
        }
    }

    #[test]
    fn unknown_delete_and_erase_cells_take_the_strong_path() {
        for capability in ["delete.local.file", "erase.experimental.object"] {
            let mut record = qualified_mutation_record();
            record.qualification_key.capability = CapabilityCell::new(capability).unwrap();
            record.evidence.evidence_class = EvidenceClass::DevelopmentSnapshot;
            assert!(
                record
                    .qualification_key
                    .capability
                    .requires_strong_qualification()
            );
            assert!(matches!(
                record.validate_at(EVALUATION_TIME),
                Err(CapabilityValidationError::MutationRequiresRealOsEvidence)
            ));
        }
    }

    #[test]
    fn qualified_records_require_explicit_provenance_and_validity() {
        let mut encoded = serde_json::to_value(qualified_mutation_record()).unwrap();
        encoded["evidence"]
            .as_object_mut()
            .unwrap()
            .remove("evidenceClass");
        assert!(serde_json::from_value::<CapabilityRecordV1>(encoded).is_err());

        let mut record = qualified_mutation_record();
        record.evidence.validity = None;
        assert!(matches!(
            record.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::MissingField("evidence.validity"))
        ));
    }

    #[test]
    fn qualification_time_window_is_enforced() {
        let mut future = qualified_mutation_record();
        future.recorded_at = "2026-08-29T00:00:00Z".to_string();
        assert!(matches!(
            future.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::RecordFromFuture)
        ));

        let mut predates = qualified_mutation_record();
        predates.recorded_at = "2026-08-26T23:59:59Z".to_string();
        assert!(matches!(
            predates.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::RecordPredatesValidity)
        ));

        let mut reversed = qualified_mutation_record();
        reversed.evidence.validity.as_mut().unwrap().expires_at =
            Some("2026-08-26T00:00:00Z".to_string());
        assert!(matches!(
            reversed.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::InvalidValidityWindow)
        ));

        let mut expired = qualified_mutation_record();
        expired.evidence.validity.as_mut().unwrap().expires_at = Some(EVALUATION_TIME.to_string());
        assert!(matches!(
            expired.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::EvidenceExpired)
        ));

        let mut missing_expiry = qualified_mutation_record();
        missing_expiry
            .evidence
            .validity
            .as_mut()
            .unwrap()
            .expires_at = None;
        assert!(matches!(
            missing_expiry.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::MissingField(
                "evidence.validity.expiresAt"
            ))
        ));
    }

    #[test]
    fn repeated_digests_never_qualify() {
        for field in ["policy", "adapter", "bundle"] {
            let mut record = qualified_mutation_record();
            let repeated = format!("sha256:{}", "a".repeat(64));
            match field {
                "policy" => record.qualification_key.safety_policy_digest = repeated,
                "adapter" => record.qualification_key.adapter_digest = repeated,
                "bundle" => record.evidence.bundle_digest = repeated,
                _ => unreachable!(),
            }
            assert!(matches!(
                record.validate_at(EVALUATION_TIME),
                Err(CapabilityValidationError::InvalidDigest(_))
            ));
        }
    }

    #[test]
    fn tuple_placeholders_whitespace_and_cleaner_placeholders_are_rejected() {
        for value in [
            " placeholder-v1",
            "placeholder-v1",
            "TBD-unknown",
            "none",
            "n/a",
            "known value",
        ] {
            let mut record = qualified_mutation_record();
            record.qualification_key.provider_or_desktop_backend = Some(value.to_string());
            assert!(matches!(
                record.validate_at(EVALUATION_TIME),
                Err(CapabilityValidationError::PlaceholderValue(
                    "qualificationKey.providerOrDesktopBackend"
                ))
            ));
        }

        let mut cleaner = qualified_mutation_record();
        cleaner.qualification_key.cleaner_id = Some("placeholder-cleaner".to_string());
        cleaner.qualification_key.cleaner_version = Some("TBD-unknown".to_string());
        assert!(matches!(
            cleaner.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::ScopeFieldMismatch {
                scope: QualificationScope::Platform
            })
        ));

        cleaner.qualification_key.scope = QualificationScope::Cleaner;
        assert!(matches!(
            cleaner.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::PlaceholderValue(
                "qualificationKey.cleanerId"
            ))
        ));
    }

    #[test]
    fn exact_tuple_rejects_glob_metacharacters_anywhere() {
        for value in ["linux-*", "ext?", "version[12]", "backend{a,b}"] {
            let mut record = qualified_mutation_record();
            record.qualification_key.provider_or_desktop_backend = Some(value.to_string());
            assert!(matches!(
                record.validate_at(EVALUATION_TIME),
                Err(CapabilityValidationError::PlaceholderValue(
                    "qualificationKey.providerOrDesktopBackend"
                ))
            ));
        }
    }

    #[test]
    fn qualification_scope_makes_cleaner_identity_unambiguous() {
        let mut platform = qualified_mutation_record();
        platform.qualification_key.cleaner_id = Some("org.sweepx.cargo-target".to_string());
        platform.qualification_key.cleaner_version = Some("1.2.3".to_string());
        assert!(matches!(
            platform.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::ScopeFieldMismatch {
                scope: QualificationScope::Platform
            })
        ));

        let mut cleaner = qualified_mutation_record();
        cleaner.qualification_key.scope = QualificationScope::Cleaner;
        cleaner.qualification_key.cleaner_id = Some("org.sweepx.cargo-target".to_string());
        assert!(matches!(
            cleaner.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::MissingField(
                "qualificationKey.cleanerVersion"
            ))
        ));
        cleaner.qualification_key.cleaner_version = Some("1.2.3".to_string());
        cleaner.validate_at(EVALUATION_TIME).unwrap();
    }

    #[test]
    fn stale_revoked_or_invalidated_evidence_never_qualifies() {
        for status in [
            QualificationValidityStatus::Stale,
            QualificationValidityStatus::Revoked,
            QualificationValidityStatus::Invalidated,
        ] {
            let mut record = qualified_mutation_record();
            let validity = record.evidence.validity.as_mut().unwrap();
            validity.status = status;
            validity.invalidation_reason = Some("test invalidation".to_string());
            if status != QualificationValidityStatus::Stale {
                validity.invalidated_at = Some("2026-08-27T01:00:00Z".to_string());
            }
            assert!(matches!(
                record.validate_at(EVALUATION_TIME),
                Err(CapabilityValidationError::NonCurrentEvidence { status: actual })
                    if actual == status
            ));
        }
    }

    #[test]
    fn qualified_mutation_requires_complete_exact_tuple_and_real_digests() {
        let mut missing_provider = qualified_mutation_record();
        missing_provider
            .qualification_key
            .provider_or_desktop_backend = None;
        assert!(matches!(
            missing_provider.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::MissingField(
                "qualificationKey.providerOrDesktopBackend"
            ))
        ));

        let mut placeholder_os = qualified_mutation_record();
        placeholder_os.qualification_key.os_build = "TBD".to_string();
        assert!(matches!(
            placeholder_os.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::PlaceholderValue(
                "qualificationKey.osBuild"
            ))
        ));

        let mut fake_digest = qualified_mutation_record();
        fake_digest.qualification_key.adapter_digest = "sha256:adapter-p4".to_string();
        assert!(matches!(
            fake_digest.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::InvalidDigest(
                "qualificationKey.adapterDigest"
            ))
        ));

        let mut elevated = qualified_mutation_record();
        elevated.qualification_key.runtime_privilege_profile = RuntimePrivilegeProfile::Elevated;
        assert!(matches!(
            elevated.validate_at(EVALUATION_TIME),
            Err(CapabilityValidationError::MutationTupleMismatch {
                field: "qualificationKey.runtimePrivilegeProfile",
                ..
            })
        ));
    }

    #[test]
    fn non_qualified_mutation_record_can_report_incomplete_evidence() {
        let mut record = qualified_mutation_record();
        record.state = CapabilityState::ReportOnly;
        record.evidence.evidence_class = EvidenceClass::FixtureConformanceOnly;
        record.evidence.validity = Some(QualificationValidity {
            status: QualificationValidityStatus::Stale,
            valid_from: None,
            expires_at: None,
            invalidated_at: None,
            invalidation_reason: Some("fixture evidence is non-production".to_string()),
        });
        record.qualification_key.adapter_digest = "sha256:fixture".to_string();
        record.validate().unwrap();
    }

    #[test]
    fn capability_cell_is_bounded_and_structured() {
        for cell in [
            CapabilityCell::SCAN_LOCAL_DIRECTORY,
            CapabilityCell::TRASH_LOCAL_FILE,
            CapabilityCell::TRASH_LOCAL_DIRECTORY,
            CapabilityCell::PERMANENT_LOCAL_FILE,
            CapabilityCell::PERMANENT_LOCAL_DIRECTORY,
            CapabilityCell::PERMANENT_LOCAL_LINK,
        ] {
            assert_eq!(CapabilityCell::new(cell).unwrap().as_str(), cell);
        }
        assert!(CapabilityCell::new("delete").is_err());
        assert!(CapabilityCell::new("Trash.Local.File").is_err());
        assert!(
            CapabilityCell::new(format!("scan.{}", "x".repeat(MAX_CAPABILITY_CELL_BYTES))).is_err()
        );
    }

    #[test]
    fn unknown_capability_record_fields_are_rejected() {
        let mut encoded = serde_json::to_value(qualified_mutation_record()).unwrap();
        encoded["qualificationKey"]["wildcard"] = json!("*");
        assert!(serde_json::from_value::<CapabilityRecordV1>(encoded).is_err());
    }

    #[test]
    fn timestamps_reject_impossible_calendar_values() {
        let mut record = qualified_mutation_record();
        record.recorded_at = "2026-02-30T00:00:00Z".to_string();
        assert!(matches!(
            record.validate(),
            Err(CapabilityValidationError::InvalidTimestamp("recordedAt"))
        ));
    }

    #[test]
    fn exit_precedence_matches_the_normative_order() {
        let order = [
            ExitCode::StateIntegrityUnavailable,
            ExitCode::NeedsReconciliation,
            ExitCode::Cancelled,
            ExitCode::StaleReplanRequired,
            ExitCode::SafetyBlocked,
            ExitCode::AuthorizationRequired,
            ExitCode::CleanerTrustOrCompat,
            ExitCode::OfficialCommandFailed,
            ExitCode::OperationFailed,
            ExitCode::Unsupported,
            ExitCode::Partial,
            ExitCode::Completed,
        ];
        for pair in order.windows(2) {
            assert_eq!(pair[0].more_conservative(pair[1]), pair[0]);
        }
    }
}
