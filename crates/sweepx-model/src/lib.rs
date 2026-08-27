use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use schemars::JsonSchema;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DecimalU128(pub u128);

impl DecimalU128 {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }
}

impl fmt::Display for DecimalU128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<u128> for DecimalU128 {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<DecimalU128> for u128 {
    fn from(value: DecimalU128) -> Self {
        value.0
    }
}

impl FromStr for DecimalU128 {
    type Err = DecimalU128ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(DecimalU128ParseError::Empty);
        }
        if s.len() > 1 && s.starts_with('0') {
            return Err(DecimalU128ParseError::LeadingZero);
        }
        if !s.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(DecimalU128ParseError::InvalidDigit);
        }
        s.parse::<u128>()
            .map(Self)
            .map_err(|_| DecimalU128ParseError::Overflow)
    }
}

impl Serialize for DecimalU128 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DecimalU128 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(D::Error::custom)
    }
}

impl JsonSchema for DecimalU128 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "DecimalU128".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        json!({
            "type": "string",
            "pattern": "^(0|[1-9][0-9]*)$",
            "description": "Decimal-encoded unsigned 128-bit integer"
        })
        .try_into()
        .expect("valid decimal schema")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecimalU128ParseError {
    #[error("decimal string is empty")]
    Empty,
    #[error("decimal string contains a leading zero")]
    LeadingZero,
    #[error("decimal string contains a non-digit")]
    InvalidDigit,
    #[error("decimal string exceeds u128")]
    Overflow,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EvidenceValue<T> {
    Known { value: T },
    LowerBound { value: T, reason: ReasonCode },
    Unknown { reason: ReasonCode },
    Unsupported { reason: ReasonCode },
    NotChecked { reason: ReasonCode },
}

impl<T> EvidenceValue<T> {
    pub fn state(&self) -> EvidenceState {
        match self {
            Self::Known { .. } => EvidenceState::Known,
            Self::LowerBound { .. } => EvidenceState::LowerBound,
            Self::Unknown { .. } => EvidenceState::Unknown,
            Self::Unsupported { .. } => EvidenceState::Unsupported,
            Self::NotChecked { .. } => EvidenceState::NotChecked,
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Known,
    LowerBound,
    Unknown,
    Unsupported,
    NotChecked,
}

pub type ByteValue = EvidenceValue<DecimalU128>;
pub type CountValue = EvidenceValue<DecimalU128>;

#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    Overflow,
    NotRevalidated,
    IncompleteStreamCoverage,
    AdapterCapabilityAbsent,
    StrictReadOnly,
    IdentityUnstable,
    ResourceLimit,
    UnsupportedPlatform,
    UnsupportedFilesystem,
    InvalidInput,
    UnknownIdentity,
    UnknownLayout,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MethodId {
    MetadataNoFollow,
    NativeApi,
    Calculated,
    ValidatedCacheToken,
    ImportedPreview,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FieldProvenance {
    LiveObservation {
        observed_at: String,
        method: MethodId,
    },
    ValidatedCache {
        observed_at: String,
        validation: MethodId,
        token: String,
    },
    DerivedFromCurrent {
        inputs: Vec<String>,
        algorithm: String,
    },
    StalePreview {
        observed_at: String,
    },
    Unknown {
        reason: ReasonCode,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeNameKind {
    UnixBytesBase64Url,
    WindowsUtf16LeBase64Url,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NativeName {
    UnixBytes(Vec<u8>),
    WindowsUtf16(Vec<u16>),
}

impl NativeName {
    pub fn unix(bytes: impl Into<Vec<u8>>) -> Self {
        Self::UnixBytes(bytes.into())
    }

    pub fn windows_utf16(units: impl Into<Vec<u16>>) -> Self {
        Self::WindowsUtf16(units.into())
    }

    pub fn kind(&self) -> NativeNameKind {
        match self {
            Self::UnixBytes(_) => NativeNameKind::UnixBytesBase64Url,
            Self::WindowsUtf16(_) => NativeNameKind::WindowsUtf16LeBase64Url,
        }
    }

    pub fn encoded_value(&self) -> String {
        match self {
            Self::UnixBytes(bytes) => URL_SAFE_NO_PAD.encode(bytes),
            Self::WindowsUtf16(units) => {
                let mut bytes = Vec::with_capacity(units.len() * 2);
                for unit in units {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                URL_SAFE_NO_PAD.encode(bytes)
            }
        }
    }
}

impl Serialize for NativeName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Wire<'a> {
            kind: NativeNameKind,
            value: &'a str,
        }

        let encoded = self.encoded_value();
        Wire {
            kind: self.kind(),
            value: &encoded,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NativeName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            kind: NativeNameKind,
            value: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&wire.value)
            .map_err(D::Error::custom)?;

        match wire.kind {
            NativeNameKind::UnixBytesBase64Url => Ok(Self::UnixBytes(bytes)),
            NativeNameKind::WindowsUtf16LeBase64Url => {
                let (chunks, remainder) = bytes.as_chunks::<2>();
                if !remainder.is_empty() {
                    return Err(D::Error::custom(
                        "windows utf16 payload must have even length",
                    ));
                }
                let units = chunks
                    .iter()
                    .map(|chunk| u16::from_le_bytes(*chunk))
                    .collect();
                Ok(Self::WindowsUtf16(units))
            }
        }
    }
}

impl JsonSchema for NativeName {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "NativeName".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        json!({
            "type": "object",
            "required": ["kind", "value"],
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": ["unix_bytes_base64_url", "windows_utf16_le_base64_url"]
                },
                "value": {
                    "type": "string",
                    "pattern": "^[A-Za-z0-9_-]*$"
                }
            },
            "additionalProperties": false
        })
        .try_into()
        .expect("valid native name schema")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Id<T> {
    value: String,
    #[serde(skip)]
    marker: PhantomData<T>,
}

impl<T> Id<T> {
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            marker: PhantomData,
        }
    }
}

impl<T> Deref for Id<T> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> fmt::Display for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ScanIdTag;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CandidateIdTag;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct BatchIdTag;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ItemIdTag;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct OperationIdTag;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct RequestIdTag;

pub type ScanId = Id<ScanIdTag>;
pub type CandidateId = Id<CandidateIdTag>;
pub type BatchId = Id<BatchIdTag>;
pub type ItemId = Id<ItemIdTag>;
pub type OperationId = Id<OperationIdTag>;
pub type RequestId = Id<RequestIdTag>;

/// A scanner-issued identity that is unique within one `scan_id` and never derived from a display
/// path. The identifier is intentionally scan-scoped: it binds records and aggregates produced by
/// one traversal, but is not a durable cross-scan filesystem identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScanEntryId(String);

impl ScanEntryId {
    const PREFIX: &'static str = "scan-entry:v1:";

    pub fn for_scan_ordinal(scan_id: &ScanId, ordinal: u128) -> Result<Self, ScanEntryIdError> {
        if scan_id.is_empty() {
            return Err(ScanEntryIdError::EmptyScanId);
        }
        if ordinal == 0 {
            return Err(ScanEntryIdError::ZeroOrdinal);
        }
        let encoded_scan_id = URL_SAFE_NO_PAD.encode(scan_id.as_bytes());
        Ok(Self(format!("{}{encoded_scan_id}:{ordinal}", Self::PREFIX)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn belongs_to(&self, scan_id: &ScanId) -> bool {
        if scan_id.is_empty() {
            return false;
        }
        let encoded_scan_id = URL_SAFE_NO_PAD.encode(scan_id.as_bytes());
        self.0
            .strip_prefix(Self::PREFIX)
            .and_then(|value| value.split_once(':'))
            .is_some_and(|(actual, _)| actual == encoded_scan_id)
    }

    fn validate(value: String) -> Result<Self, ScanEntryIdError> {
        let payload = value
            .strip_prefix(Self::PREFIX)
            .ok_or(ScanEntryIdError::InvalidFormat)?;
        let (encoded_scan_id, ordinal) = payload
            .split_once(':')
            .ok_or(ScanEntryIdError::InvalidFormat)?;
        if encoded_scan_id.is_empty() || ordinal.contains(':') {
            return Err(ScanEntryIdError::InvalidFormat);
        }
        let scan_id = URL_SAFE_NO_PAD
            .decode(encoded_scan_id)
            .map_err(|_| ScanEntryIdError::InvalidScanIdEncoding)?;
        if scan_id.is_empty()
            || std::str::from_utf8(&scan_id).is_err()
            || URL_SAFE_NO_PAD.encode(&scan_id) != encoded_scan_id
        {
            return Err(ScanEntryIdError::InvalidScanIdEncoding);
        }
        let ordinal = ordinal
            .parse::<DecimalU128>()
            .map_err(|_| ScanEntryIdError::InvalidOrdinal)?;
        if ordinal == DecimalU128::ZERO {
            return Err(ScanEntryIdError::ZeroOrdinal);
        }
        Ok(Self(value))
    }
}

impl fmt::Display for ScanEntryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ScanEntryId {
    type Err = ScanEntryIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::validate(value.to_string())
    }
}

impl Serialize for ScanEntryId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ScanEntryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::validate(value).map_err(D::Error::custom)
    }
}

impl JsonSchema for ScanEntryId {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ScanEntryId".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        json!({
            "type": "string",
            "pattern": "^scan-entry:v1:[A-Za-z0-9_-]+:[1-9][0-9]*$",
            "description": "Validated identity unique within one SweepX scan; never path-derived"
        })
        .try_into()
        .expect("valid scan entry id schema")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScanEntryIdError {
    #[error("scan id must not be empty")]
    EmptyScanId,
    #[error("scan entry ordinal must be greater than zero")]
    ZeroOrdinal,
    #[error("scan entry id has an invalid format")]
    InvalidFormat,
    #[error("scan entry id has a non-canonical scan id encoding")]
    InvalidScanIdEncoding,
    #[error("scan entry id has an invalid ordinal")]
    InvalidOrdinal,
    #[error("scan entry id belongs to a different scan")]
    ScanMismatch,
}

/// Identity evidence is never represented by a sentinel value. Missing live platform evidence is
/// an explicit `Unknown(reason)` and cannot be confused with a known zero-valued native identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum IdentityEvidence<T> {
    Known { value: T },
    Unknown { reason: ReasonCode },
}

impl<T> IdentityEvidence<T> {
    pub fn known(value: T) -> Self {
        Self::Known { value }
    }

    pub fn unknown(reason: ReasonCode) -> Self {
        Self::Unknown { reason }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct PlatformFileIdentity {
    pub device: DecimalU128,
    pub inode: DecimalU128,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct FilesystemObjectDomainIdentity {
    pub device: DecimalU128,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct VolumeOrMountIdentity {
    pub value: DecimalU128,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ScanObjectIdentity {
    pub entry_id: ScanEntryId,
    pub scan_root_id: ScanEntryId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<ScanEntryId>,
    pub platform_file_identity: IdentityEvidence<PlatformFileIdentity>,
    pub filesystem_object_domain_identity: IdentityEvidence<FilesystemObjectDomainIdentity>,
    pub volume_or_mount_identity: IdentityEvidence<VolumeOrMountIdentity>,
}

impl ScanObjectIdentity {
    pub fn validate_for_scan(&self, scan_id: &ScanId) -> Result<(), ScanEntryIdError> {
        if !self.entry_id.belongs_to(scan_id)
            || !self.scan_root_id.belongs_to(scan_id)
            || self
                .parent_id
                .as_ref()
                .is_some_and(|identity| !identity.belongs_to(scan_id))
        {
            return Err(ScanEntryIdError::ScanMismatch);
        }
        if (self.entry_id == self.scan_root_id) != self.parent_id.is_none()
            || self.parent_id.as_ref() == Some(&self.entry_id)
        {
            return Err(ScanEntryIdError::InvalidFormat);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct NativePathComponent {
    pub entry_id: ScanEntryId,
    pub native_basename: NativeName,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct NativeLocatorEvidence {
    pub scan_root: NativePathComponent,
    pub parent_reopen_recipe: Vec<NativePathComponent>,
    pub entry: NativePathComponent,
}

impl NativeLocatorEvidence {
    pub fn validate_for_identity(
        &self,
        identity: &ScanObjectIdentity,
        scan_id: &ScanId,
    ) -> Result<(), ScanEntryIdError> {
        identity.validate_for_scan(scan_id)?;
        if !self.scan_root.entry_id.belongs_to(scan_id) || !self.entry.entry_id.belongs_to(scan_id)
        {
            return Err(ScanEntryIdError::ScanMismatch);
        }
        if self.scan_root.entry_id != identity.scan_root_id
            || self.entry.entry_id != identity.entry_id
        {
            return Err(ScanEntryIdError::InvalidFormat);
        }
        for component in &self.parent_reopen_recipe {
            if !component.entry_id.belongs_to(scan_id) {
                return Err(ScanEntryIdError::ScanMismatch);
            }
        }
        if self
            .parent_reopen_recipe
            .first()
            .is_some_and(|component| component.entry_id != self.scan_root.entry_id)
        {
            return Err(ScanEntryIdError::InvalidFormat);
        }
        let mut seen = std::collections::BTreeSet::new();
        for component in &self.parent_reopen_recipe {
            if !seen.insert(component.entry_id.clone())
                || component.entry_id == self.entry.entry_id
            {
                return Err(ScanEntryIdError::InvalidFormat);
            }
        }
        match &identity.parent_id {
            Some(expected_parent)
                if self.parent_reopen_recipe.last().map(|part| &part.entry_id)
                    == Some(expected_parent) => {}
            None if self.parent_reopen_recipe.is_empty() => {}
            _ => return Err(ScanEntryIdError::InvalidFormat),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    Complete,
    Incomplete,
    DetailsLost,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Coverage {
    pub state: CoverageState,
    pub complete: bool,
    pub incomplete_reasons: Vec<ReasonCode>,
    pub details_lost: bool,
    pub provenance: FieldProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObjectType {
    File,
    Directory,
    Symlink,
    ReparsePoint,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ScannedEntry {
    pub scan_id: ScanId,
    /// Absent only on legacy/imported records that predate scan identity. New live scanner output
    /// always supplies this block; consumers must not synthesize one from `display_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<ScanObjectIdentity>,
    /// Absent only on legacy/imported records that predate native lineage capture. New live
    /// scanner output always supplies this block; consumers must not synthesize one from
    /// `display_path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_locator: Option<NativeLocatorEvidence>,
    pub display_path: String,
    pub native_basename: NativeName,
    pub object_type: ObjectType,
    pub logical_bytes: ByteValue,
    pub allocated_bytes: ByteValue,
    pub reclaimable_estimate: ByteValue,
    pub metadata_fingerprint: String,
    pub coverage: Coverage,
    pub provenance: FieldProvenance,
}

impl ScannedEntry {
    /// Returns validated current-format identity, or `Ok(None)` for legacy records.
    pub fn validated_identity(&self) -> Result<Option<&ScanObjectIdentity>, ScanEntryIdError> {
        if let Some(identity) = &self.identity {
            identity.validate_for_scan(&self.scan_id)?;
        }
        Ok(self.identity.as_ref())
    }

    /// Returns validated native locator evidence only when it matches the current validated scan
    /// identity. Legacy/imported records may return `Ok(None)`.
    pub fn validated_native_locator(
        &self,
    ) -> Result<Option<&NativeLocatorEvidence>, ScanEntryIdError> {
        let Some(locator) = &self.native_locator else {
            return Ok(None);
        };
        let Some(identity) = self.validated_identity()? else {
            return Ok(None);
        };
        locator.validate_for_identity(identity, &self.scan_id)?;
        if locator.entry.native_basename != self.native_basename {
            return Err(ScanEntryIdError::InvalidFormat);
        }
        Ok(Some(locator))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArithmeticState {
    Exact,
    LowerBound,
    Overflowed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct DirectoryAggregate {
    pub scan_id: ScanId,
    pub directory_identity: String,
    pub revision: DecimalU128,
    pub apparent_logical_bytes: ByteValue,
    pub unique_logical_bytes: ByteValue,
    pub filesystem_reported_allocated_bytes: ByteValue,
    pub potentially_reclaimable_bytes: ByteValue,
    pub direct_child_count: CountValue,
    pub recursive_entry_count: CountValue,
    pub coverage: Coverage,
    pub arithmetic_state: ArithmeticState,
}

impl DirectoryAggregate {
    /// Parses the identity emitted by current scanners. Legacy aggregates may still deserialize
    /// with a path-valued string for wire compatibility, but that value is not a trusted identity.
    pub fn scan_entry_id(&self) -> Result<ScanEntryId, ScanEntryIdError> {
        let identity: ScanEntryId = self.directory_identity.parse()?;
        if !identity.belongs_to(&self.scan_id) {
            return Err(ScanEntryIdError::ScanMismatch);
        }
        Ok(identity)
    }

    pub fn checked_sum_known(values: &[DecimalU128]) -> ByteValue {
        let mut total = DecimalU128::ZERO;
        for value in values {
            match total.checked_add(*value) {
                Some(next) => total = next,
                None => {
                    return EvidenceValue::Unknown {
                        reason: ReasonCode::Overflow,
                    };
                }
            }
        }
        EvidenceValue::Known { value: total }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskTier {
    R1,
    R2,
    R3,
    R4,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Qualified,
    Degraded,
    ReportOnly,
    Unsupported,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Capability {
    pub id: String,
    pub state: CapabilityState,
    pub reason: Option<ReasonCode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BatchTerminalOutcome {
    Completed,
    Partial,
    Cancelled,
    NeedsReconciliation,
    Rejected,
    HardBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "state",
    content = "terminal_outcome",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum BatchState {
    Discovered,
    Explained,
    Planned,
    AuthorizationPending,
    Authorized,
    Revalidating,
    Ready,
    Executing,
    Completed,
    Partial,
    Cancelled,
    NeedsReconciliation,
    Rejected,
    HardBlocked,
    Audited(BatchTerminalOutcome),
}

impl BatchState {
    pub fn can_transition_to(self, next: Self) -> bool {
        use BatchState as S;

        match (self, next) {
            (S::Discovered, S::Explained)
            | (S::Explained, S::Planned)
            | (S::Planned, S::AuthorizationPending)
            | (S::AuthorizationPending, S::Authorized)
            | (S::Authorized, S::Revalidating)
            | (S::Revalidating, S::Ready)
            | (S::Ready, S::Executing)
            | (S::Executing, S::Completed)
            | (S::Executing, S::Partial)
            | (S::Executing, S::Cancelled)
            | (S::Executing, S::NeedsReconciliation)
            | (S::NeedsReconciliation, S::Completed)
            | (S::NeedsReconciliation, S::Partial)
            | (S::NeedsReconciliation, S::NeedsReconciliation) => true,
            (from, S::Rejected) | (from, S::HardBlocked) if from.is_nonterminal() => true,
            (S::Completed, S::Audited(BatchTerminalOutcome::Completed))
            | (S::Partial, S::Audited(BatchTerminalOutcome::Partial))
            | (S::Cancelled, S::Audited(BatchTerminalOutcome::Cancelled))
            | (S::NeedsReconciliation, S::Audited(BatchTerminalOutcome::NeedsReconciliation))
            | (S::Rejected, S::Audited(BatchTerminalOutcome::Rejected))
            | (S::HardBlocked, S::Audited(BatchTerminalOutcome::HardBlocked)) => true,
            _ => false,
        }
    }

    fn is_nonterminal(self) -> bool {
        matches!(
            self,
            Self::Discovered
                | Self::Explained
                | Self::Planned
                | Self::AuthorizationPending
                | Self::Authorized
                | Self::Revalidating
                | Self::Ready
                | Self::Executing
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ItemTerminalOutcome {
    Succeeded,
    Failed,
    Skipped,
    Stale,
    Cancelled,
    Indeterminate,
    Rejected,
    HardBlocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "state",
    content = "terminal_outcome",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum ItemState {
    Candidate,
    Explained,
    InPlan,
    Authorized,
    Revalidating,
    PreflightReady,
    Trashing,
    PermanentDeleting,
    Succeeded,
    Failed,
    Skipped,
    Stale,
    Cancelled,
    Indeterminate,
    Rejected,
    HardBlocked,
    Audited(ItemTerminalOutcome),
}

impl ItemState {
    pub fn can_transition_to(self, next: Self) -> bool {
        use ItemState as S;

        match (self, next) {
            (S::Candidate, S::Explained)
            | (S::Explained, S::InPlan)
            | (S::InPlan, S::Authorized)
            | (S::Authorized, S::Revalidating)
            | (S::Revalidating, S::PreflightReady)
            | (S::PreflightReady, S::Trashing)
            | (S::PreflightReady, S::PermanentDeleting)
            | (S::Trashing, S::Succeeded)
            | (S::PermanentDeleting, S::Succeeded)
            | (S::Trashing, S::Failed)
            | (S::PermanentDeleting, S::Failed)
            | (S::Trashing, S::Cancelled)
            | (S::PermanentDeleting, S::Cancelled)
            | (S::Trashing, S::Indeterminate)
            | (S::PermanentDeleting, S::Indeterminate)
            | (S::Revalidating, S::Skipped)
            | (S::Revalidating, S::Stale)
            | (S::Revalidating, S::Cancelled)
            | (S::Indeterminate, S::Indeterminate) => true,
            (from, S::Rejected) | (from, S::HardBlocked) if from.is_nonterminal() => true,
            (S::Succeeded, S::Audited(ItemTerminalOutcome::Succeeded))
            | (S::Failed, S::Audited(ItemTerminalOutcome::Failed))
            | (S::Skipped, S::Audited(ItemTerminalOutcome::Skipped))
            | (S::Stale, S::Audited(ItemTerminalOutcome::Stale))
            | (S::Cancelled, S::Audited(ItemTerminalOutcome::Cancelled))
            | (S::Indeterminate, S::Audited(ItemTerminalOutcome::Indeterminate))
            | (S::Rejected, S::Audited(ItemTerminalOutcome::Rejected))
            | (S::HardBlocked, S::Audited(ItemTerminalOutcome::HardBlocked)) => true,
            _ => false,
        }
    }

    fn is_nonterminal(self) -> bool {
        matches!(
            self,
            Self::Candidate
                | Self::Explained
                | Self::InPlan
                | Self::Authorized
                | Self::Revalidating
                | Self::PreflightReady
                | Self::Trashing
                | Self::PermanentDeleting
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_u128_round_trips_as_string() {
        let value = DecimalU128::new(u128::MAX);
        let encoded = serde_json::to_string(&value).unwrap();
        assert_eq!(encoded, format!("\"{}\"", u128::MAX));

        let decoded: DecimalU128 = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn decimal_u128_rejects_invalid_wire_forms() {
        assert!(serde_json::from_str::<DecimalU128>("\"001\"").is_err());
        assert!(serde_json::from_str::<DecimalU128>("\"-1\"").is_err());
        assert!(serde_json::from_str::<DecimalU128>("\"abc\"").is_err());
    }

    #[test]
    fn evidence_value_serializes_with_explicit_state() {
        let value = EvidenceValue::LowerBound {
            value: DecimalU128::new(4096),
            reason: ReasonCode::IncompleteStreamCoverage,
        };

        let encoded = serde_json::to_value(&value).unwrap();
        assert_eq!(
            encoded,
            json!({
                "state": "lower_bound",
                "value": "4096",
                "reason": "incomplete_stream_coverage"
            })
        );
    }

    #[test]
    fn native_name_unix_round_trip_is_lossless() {
        let name = NativeName::unix(vec![0xff, b'a', 0x00, b'/']);
        let encoded = serde_json::to_string(&name).unwrap();
        let decoded: NativeName = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, name);
    }

    #[test]
    fn native_name_windows_round_trip_is_lossless() {
        let name = NativeName::windows_utf16(vec![0x0041, 0xd83d, 0xde80]);
        let encoded = serde_json::to_string(&name).unwrap();
        let decoded: NativeName = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, name);
    }

    #[test]
    fn scan_entry_id_is_canonical_and_scan_scoped() {
        let scan = ScanId::new("scan:/not-a-path");
        let identity = ScanEntryId::for_scan_ordinal(&scan, 42).unwrap();

        assert!(identity.belongs_to(&scan));
        assert!(!identity.belongs_to(&ScanId::new("other")));
        assert!(!identity.as_str().contains("/not-a-path"));
        assert_eq!(identity.as_str().parse::<ScanEntryId>().unwrap(), identity);
        assert!("/tmp/display-only".parse::<ScanEntryId>().is_err());
        assert!("scan-entry:v1:c2Nhbg:0".parse::<ScanEntryId>().is_err());
        assert!("scan-entry:v1:_w:1".parse::<ScanEntryId>().is_err());
    }

    #[test]
    fn legacy_scanned_entry_without_identity_remains_readable_but_unknown() {
        let wire = json!({
            "scan_id": "legacy-scan",
            "display_path": "/legacy/path",
            "native_basename": {"kind": "unix_bytes_base64_url", "value": "cGF0aA"},
            "object_type": "file",
            "logical_bytes": {"state": "known", "value": "1"},
            "allocated_bytes": {"state": "known", "value": "1"},
            "reclaimable_estimate": {"state": "known", "value": "1"},
            "metadata_fingerprint": "legacy",
            "coverage": {
                "state": "complete",
                "complete": true,
                "incomplete_reasons": [],
                "details_lost": false,
                "provenance": {
                    "kind": "unknown",
                    "reason": "not_revalidated"
                }
            },
            "provenance": {
                "kind": "unknown",
                "reason": "not_revalidated"
            }
        });

        let entry: ScannedEntry = serde_json::from_value(wire).unwrap();
        assert_eq!(entry.identity, None);
        assert_eq!(entry.validated_identity().unwrap(), None);
    }

    #[test]
    fn display_path_changes_do_not_change_scan_entry_identity() {
        let scan_id = ScanId::new("same-scan");
        let identity = ScanEntryId::for_scan_ordinal(&scan_id, 9).unwrap();
        let mut first = json!({
            "scan_id": "same-scan",
            "identity": {
                "entry_id": identity,
                "scan_root_id": ScanEntryId::for_scan_ordinal(&scan_id, 1).unwrap(),
                "platform_file_identity": {"state": "unknown", "reason": "unknown_identity"},
                "filesystem_object_domain_identity": {"state": "unknown", "reason": "unknown_identity"},
                "volume_or_mount_identity": {"state": "unknown", "reason": "unknown_identity"}
            },
            "display_path": "/first/display",
            "native_basename": {"kind": "unix_bytes_base64_url", "value": "ZGlzcGxheQ"},
            "object_type": "file",
            "logical_bytes": {"state": "known", "value": "1"},
            "allocated_bytes": {"state": "known", "value": "1"},
            "reclaimable_estimate": {"state": "known", "value": "1"},
            "metadata_fingerprint": "first",
            "coverage": {
                "state": "complete", "complete": true, "incomplete_reasons": [],
                "details_lost": false,
                "provenance": {"kind": "unknown", "reason": "not_revalidated"}
            },
            "provenance": {"kind": "unknown", "reason": "not_revalidated"}
        });
        let mut second = first.clone();
        second["display_path"] = json!("/second/display");
        second["metadata_fingerprint"] = json!("second");

        let first: ScannedEntry = serde_json::from_value(first.take()).unwrap();
        let second: ScannedEntry = serde_json::from_value(second).unwrap();
        assert_eq!(first.identity, second.identity);
    }

    #[test]
    fn directory_aggregate_overflow_becomes_unknown() {
        let sum = DirectoryAggregate::checked_sum_known(&[
            DecimalU128::new(u128::MAX),
            DecimalU128::new(1),
        ]);
        assert_eq!(
            sum,
            EvidenceValue::Unknown {
                reason: ReasonCode::Overflow
            }
        );
    }

    #[test]
    fn batch_state_transitions_follow_contract() {
        assert!(BatchState::Discovered.can_transition_to(BatchState::Explained));
        assert!(BatchState::Ready.can_transition_to(BatchState::Executing));
        assert!(BatchState::Executing.can_transition_to(BatchState::Partial));
        assert!(
            BatchState::Partial
                .can_transition_to(BatchState::Audited(BatchTerminalOutcome::Partial))
        );
        assert!(!BatchState::Planned.can_transition_to(BatchState::Executing));
        assert!(!BatchState::Completed.can_transition_to(BatchState::Partial));
    }

    #[test]
    fn item_state_transitions_follow_contract() {
        assert!(ItemState::Candidate.can_transition_to(ItemState::Explained));
        assert!(ItemState::PreflightReady.can_transition_to(ItemState::Trashing));
        assert!(ItemState::PreflightReady.can_transition_to(ItemState::PermanentDeleting));
        assert!(
            ItemState::Succeeded
                .can_transition_to(ItemState::Audited(ItemTerminalOutcome::Succeeded))
        );
        assert!(!ItemState::Candidate.can_transition_to(ItemState::Succeeded));
        assert!(!ItemState::Trashing.can_transition_to(ItemState::PermanentDeleting));
    }
}
