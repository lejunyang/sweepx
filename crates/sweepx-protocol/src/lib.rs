use std::{collections::BTreeMap, error::Error, fmt, str::FromStr};

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
pub use sweepx_model::CapabilityState;
use sweepx_model::{DecimalU128, OperationId, RequestId};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const OUTPUT_SCHEMA: &str = "sweepx.output/v1";
pub const EVENT_SCHEMA: &str = "sweepx.event/v1";
pub const CAPABILITY_RECORD_SCHEMA: &str = "sweepx.capability-record/v1";
pub const MAX_CAPABILITY_CELL_BYTES: usize = 128;
pub const MAX_QUALIFICATION_TEXT_BYTES: usize = 512;
pub const MAX_QUALIFICATION_REASON_BYTES: usize = 4096;
pub const MAX_EVIDENCE_LIST_ITEMS: usize = 128;
pub const KNOWN_READ_ONLY_CAPABILITY_CELLS: [&str; 5] = [
    CapabilityCell::SCAN_LOCAL_DIRECTORY,
    CapabilityCell::ANALYSIS_EXPLAIN_SCAN_JSON,
    CapabilityCell::CATALOG_CLEANER_READ,
    CapabilityCell::SCAN_TUI_LIVE,
    CapabilityCell::OPERATION_CANCEL,
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
    pub const ANALYSIS_EXPLAIN_SCAN_JSON: &'static str = "analysis.explain.scan_json";
    pub const CATALOG_CLEANER_READ: &'static str = "catalog.cleaner.read";
    pub const SCAN_TUI_LIVE: &'static str = "scan.tui.live";
    pub const OPERATION_CANCEL: &'static str = "operation.cancel";
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
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
pub struct EventCheckpoint {
    pub durable: bool,
    pub last_durable_sequence: DecimalU128,
}

impl EventEnvelope {
    pub fn is_terminal_type(&self) -> bool {
        matches!(self.r#type, EventType::OperationTerminal)
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
            payload: json!({ "status": "ok" }),
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
