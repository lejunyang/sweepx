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

/// Unit policy for human-facing byte counts. Machine formats always keep exact decimal bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HumanSizeUnit {
    /// Select the largest binary unit that keeps the value at or above one.
    #[default]
    Auto,
    /// Render the exact integer byte count.
    Bytes,
    /// Render in kibibytes (1024 bytes).
    KiB,
    /// Render in mebibytes (1024 squared bytes).
    MiB,
    /// Render in gibibytes (1024 cubed bytes).
    GiB,
    /// Render in tebibytes (1024 to the fourth power bytes).
    TiB,
}

/// Stable ordering choices shared by the human CLI table and live TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanSort {
    /// Show the largest potentially reclaimable entries first. Unknown values sort last.
    #[default]
    Size,
    /// Sort by the lossily rendered display path. Machine output is never reordered by this.
    Path,
}

impl HumanSizeUnit {
    /// Formats bytes for display without changing the exact values carried by JSON output.
    pub fn format(self, bytes: u128) -> String {
        const UNITS: [(u128, &str); 5] = [
            (1, "B"),
            (1024, "KiB"),
            (1024 * 1024, "MiB"),
            (1024 * 1024 * 1024, "GiB"),
            (1024_u128.pow(4), "TiB"),
        ];
        let selected = match self {
            Self::Auto => UNITS
                .iter()
                .rev()
                .find(|(factor, _)| bytes >= *factor)
                .copied()
                .unwrap_or(UNITS[0]),
            Self::Bytes => UNITS[0],
            Self::KiB => UNITS[1],
            Self::MiB => UNITS[2],
            Self::GiB => UNITS[3],
            Self::TiB => UNITS[4],
        };
        let (factor, label) = selected;
        if factor == 1 {
            format!("{bytes} {label}")
        } else {
            // Integer arithmetic keeps display stable for the full u128 evidence range.
            let mut whole = bytes / factor;
            let mut tenths = ((bytes % factor) * 10 + factor / 2) / factor;
            if tenths == 10 {
                whole += 1;
                tenths = 0;
            }
            format!("{whole}.{tenths} {label}")
        }
    }
}

#[cfg(test)]
mod human_size_tests {
    use super::HumanSizeUnit;

    #[test]
    fn automatic_and_fixed_units_are_stable() {
        assert_eq!(HumanSizeUnit::Auto.format(999), "999 B");
        assert_eq!(HumanSizeUnit::Auto.format(1536), "1.5 KiB");
        assert_eq!(HumanSizeUnit::MiB.format(1_572_864), "1.5 MiB");
        assert_eq!(HumanSizeUnit::Bytes.format(1536), "1536 B");
        assert!(HumanSizeUnit::TiB.format(u128::MAX).ends_with(" TiB"));
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

    /// Validates that this lossless native name is exactly one relative path component.
    ///
    /// `NativeName` is also used by non-executable presentation records, so this invariant is
    /// enforced by locator consumers rather than by the constructors.
    pub fn validate_basename(&self) -> Result<(), NativeNameError> {
        match self {
            Self::UnixBytes(bytes) => {
                if bytes.is_empty() {
                    return Err(NativeNameError::Empty);
                }
                if bytes.contains(&0) {
                    return Err(NativeNameError::ContainsNul);
                }
                if bytes.contains(&b'/') {
                    return Err(NativeNameError::ContainsSeparator);
                }
                if bytes.as_slice() == b"." || bytes.as_slice() == b".." {
                    return Err(NativeNameError::DotComponent);
                }
            }
            Self::WindowsUtf16(units) => {
                if units.is_empty() {
                    return Err(NativeNameError::Empty);
                }
                if units.contains(&0) {
                    return Err(NativeNameError::ContainsNul);
                }
                if units.iter().any(|unit| {
                    matches!(
                        *unit,
                        0..=31
                            | 0x0022
                            | 0x002a
                            | 0x002f
                            | 0x003a
                            | 0x003c
                            | 0x003e
                            | 0x003f
                            | 0x005c
                            | 0x007c
                    )
                }) {
                    return Err(NativeNameError::ContainsSeparator);
                }
                if units.as_slice() == [b'.' as u16]
                    || units.as_slice() == [b'.' as u16, b'.' as u16]
                {
                    return Err(NativeNameError::DotComponent);
                }
                if units
                    .last()
                    .is_some_and(|unit| matches!(*unit, 0x002e | 0x0020))
                    || windows_utf16_is_reserved_device_name(units)
                {
                    return Err(NativeNameError::AmbiguousWindowsName);
                }
            }
        }
        Ok(())
    }

    /// Validates a basename for use by the process's current platform.
    pub fn validate_basename_for_current_platform(&self) -> Result<(), NativeNameError> {
        self.validate_basename()?;
        #[cfg(unix)]
        if !matches!(self, Self::UnixBytes(_)) {
            return Err(NativeNameError::ForeignPlatform);
        }
        #[cfg(windows)]
        if !matches!(self, Self::WindowsUtf16(_)) {
            return Err(NativeNameError::ForeignPlatform);
        }
        #[cfg(not(any(unix, windows)))]
        return Err(NativeNameError::UnsupportedCurrentPlatform);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NativeNameError {
    #[error("native basename is empty")]
    Empty,
    #[error("native basename contains a NUL code unit")]
    ContainsNul,
    #[error("native basename contains a path separator or Windows stream separator")]
    ContainsSeparator,
    #[error("native basename is a dot path component")]
    DotComponent,
    #[error("native basename is ambiguous under Windows path semantics")]
    AmbiguousWindowsName,
    #[error("native basename is for a different platform")]
    ForeignPlatform,
    #[error("the current platform has no supported native basename representation")]
    UnsupportedCurrentPlatform,
}

fn windows_utf16_is_reserved_device_name(component: &[u16]) -> bool {
    let stem_end = component
        .iter()
        .position(|unit| *unit == b'.' as u16)
        .unwrap_or(component.len());
    let stem = &component[..stem_end];
    let stem = &stem[..stem
        .iter()
        .rposition(|unit| *unit != b' ' as u16)
        .map_or(0, |index| index + 1)];

    fn ascii_eq_ignore_case(actual: &[u16], expected: &[u8]) -> bool {
        actual.len() == expected.len()
            && actual.iter().zip(expected).all(|(actual, expected)| {
                u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
            })
    }

    [
        b"CON".as_slice(),
        b"PRN",
        b"AUX",
        b"NUL",
        b"CLOCK$",
        b"CONIN$",
        b"CONOUT$",
    ]
    .iter()
    .any(|reserved| ascii_eq_ignore_case(stem, reserved))
        || (stem.len() == 4
            && (ascii_eq_ignore_case(&stem[..3], b"COM")
                || ascii_eq_ignore_case(&stem[..3], b"LPT"))
            && matches!(
                stem[3],
                value if (value >= b'1' as u16 && value <= b'9' as u16)
                    || matches!(value, 0x00b9 | 0x00b2 | 0x00b3)
            ))
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
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: NativeNameKind,
            value: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&wire.value)
            .map_err(D::Error::custom)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != wire.value {
            return Err(D::Error::custom(
                "native name payload is not canonical unpadded base64url",
            ));
        }

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

/// Maximum lossless storage used for one absolute native path.
///
/// The limit is measured in native encoded bytes: raw bytes on Unix and UTF-16LE bytes on
/// Windows. It matches the scanner's documented 64 KiB native-path representation bound.
pub const MAX_NATIVE_ABSOLUTE_PATH_BYTES: usize = 64 * 1024;
const MAX_NATIVE_ABSOLUTE_PATH_BASE64_LEN: usize = (MAX_NATIVE_ABSOLUTE_PATH_BYTES / 3) * 4
    + match MAX_NATIVE_ABSOLUTE_PATH_BYTES % 3 {
        0 => 0,
        1 => 2,
        _ => 3,
    };

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NativeAbsolutePathKind {
    UnixBytesBase64Url,
    WindowsUtf16LeBase64Url,
}

/// A lossless, platform-tagged absolute path captured at scan-root admission.
///
/// This value deliberately does not normalize path bytes/code units. Cross-platform reports can
/// deserialize either representation, while callers that intend to use it on the local host must
/// additionally call [`Self::validate_for_current_platform`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NativeAbsolutePath {
    UnixBytes(Vec<u8>),
    WindowsUtf16(Vec<u16>),
}

impl NativeAbsolutePath {
    pub fn unix(bytes: impl Into<Vec<u8>>) -> Self {
        Self::UnixBytes(bytes.into())
    }

    pub fn windows_utf16(units: impl Into<Vec<u16>>) -> Self {
        Self::WindowsUtf16(units.into())
    }

    pub fn kind(&self) -> NativeAbsolutePathKind {
        match self {
            Self::UnixBytes(_) => NativeAbsolutePathKind::UnixBytesBase64Url,
            Self::WindowsUtf16(_) => NativeAbsolutePathKind::WindowsUtf16LeBase64Url,
        }
    }

    pub fn encoded_value(&self) -> String {
        match self {
            Self::UnixBytes(bytes) => URL_SAFE_NO_PAD.encode(bytes),
            Self::WindowsUtf16(units) => {
                let mut bytes = Vec::with_capacity(units.len().saturating_mul(2));
                for unit in units {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                URL_SAFE_NO_PAD.encode(bytes)
            }
        }
    }

    pub fn native_byte_len(&self) -> Result<usize, NativeAbsolutePathError> {
        match self {
            Self::UnixBytes(bytes) => Ok(bytes.len()),
            Self::WindowsUtf16(units) => {
                units
                    .len()
                    .checked_mul(2)
                    .ok_or(NativeAbsolutePathError::TooLong {
                        actual_bytes: usize::MAX,
                        max_bytes: MAX_NATIVE_ABSOLUTE_PATH_BYTES,
                    })
            }
        }
    }

    pub fn validate_size(&self) -> Result<(), NativeAbsolutePathError> {
        let actual_bytes = self.native_byte_len()?;
        if actual_bytes > MAX_NATIVE_ABSOLUTE_PATH_BYTES {
            return Err(NativeAbsolutePathError::TooLong {
                actual_bytes,
                max_bytes: MAX_NATIVE_ABSOLUTE_PATH_BYTES,
            });
        }
        Ok(())
    }

    pub fn validate_no_nul(&self) -> Result<(), NativeAbsolutePathError> {
        let contains_nul = match self {
            Self::UnixBytes(bytes) => bytes.contains(&0),
            Self::WindowsUtf16(units) => units.contains(&0),
        };
        if contains_nul {
            return Err(NativeAbsolutePathError::ContainsNul);
        }
        Ok(())
    }

    pub fn validate_absolute(&self) -> Result<(), NativeAbsolutePathError> {
        let absolute = match self {
            Self::UnixBytes(bytes) => bytes.first() == Some(&b'/'),
            Self::WindowsUtf16(units) => windows_utf16_path_is_absolute(units),
        };
        if !absolute {
            return Err(NativeAbsolutePathError::NotAbsolute);
        }
        Ok(())
    }

    /// Validates representation invariants that are meaningful independent of the current host.
    pub fn validate(&self) -> Result<(), NativeAbsolutePathError> {
        self.validate_size()?;
        self.validate_no_nul()?;
        self.validate_absolute()
    }

    /// Validates this absolute path for use on the process's current platform.
    pub fn validate_for_current_platform(&self) -> Result<(), NativeAbsolutePathError> {
        self.validate()?;
        #[cfg(unix)]
        if !matches!(self, Self::UnixBytes(_)) {
            return Err(NativeAbsolutePathError::ForeignPlatform {
                expected: NativeAbsolutePathKind::UnixBytesBase64Url,
                actual: self.kind(),
            });
        }
        #[cfg(windows)]
        if !matches!(self, Self::WindowsUtf16(_)) {
            return Err(NativeAbsolutePathError::ForeignPlatform {
                expected: NativeAbsolutePathKind::WindowsUtf16LeBase64Url,
                actual: self.kind(),
            });
        }
        #[cfg(not(any(unix, windows)))]
        return Err(NativeAbsolutePathError::UnsupportedCurrentPlatform);
        Ok(())
    }

    /// Captures a local path without UTF-8 conversion or normalization.
    pub fn from_path(path: &std::path::Path) -> Result<Self, NativeAbsolutePathError> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let value = Self::unix(path.as_os_str().as_bytes().to_vec());
            value.validate_for_current_platform()?;
            Ok(value)
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let value = Self::windows_utf16(path.as_os_str().encode_wide().collect::<Vec<_>>());
            value.validate_for_current_platform()?;
            Ok(value)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = path;
            Err(NativeAbsolutePathError::UnsupportedCurrentPlatform)
        }
    }

    /// Compares a captured locator with a local path using exact native bytes/code units.
    pub fn equals_path(&self, path: &std::path::Path) -> Result<bool, NativeAbsolutePathError> {
        self.validate_for_current_platform()?;
        Ok(self == &Self::from_path(path)?)
    }
}

fn windows_utf16_path_is_absolute(units: &[u16]) -> bool {
    let separator = |unit: u16| unit == b'\\' as u16 || unit == b'/' as u16;
    let is_namespace_component =
        |component: &[u16]| component == [b'?' as u16] || component == [b'.' as u16];

    // Device and extended-length namespaces (for example `\\?\`, `\\.\`, and
    // `\??\`) do not have ordinary drive/UNC semantics and must be admitted explicitly by a
    // future platform contract rather than slipping through the UNC grammar.
    if (units.len() >= 4
        && separator(units[0])
        && separator(units[1])
        && matches!(units[2], value if value == b'?' as u16 || value == b'.' as u16)
        && separator(units[3]))
        || (units.len() >= 4
            && separator(units[0])
            && units[1] == b'?' as u16
            && units[2] == b'?' as u16
            && separator(units[3]))
    {
        return false;
    }

    let drive_absolute = units.len() >= 3
        && u8::try_from(units[0]).is_ok_and(|drive| drive.is_ascii_alphabetic())
        && units[1] == b':' as u16
        && separator(units[2]);
    if drive_absolute {
        return true;
    }

    if units.len() < 5 || !separator(units[0]) || !separator(units[1]) || separator(units[2]) {
        return false;
    }
    let mut components = units[2..]
        .split(|unit| separator(*unit))
        .filter(|component| !component.is_empty());
    matches!(
        (components.next(), components.next()),
        (Some(server), Some(share))
            if !is_namespace_component(server)
                && !is_namespace_component(share)
                && !server.contains(&(b':' as u16))
                && !share.contains(&(b':' as u16))
    )
}

impl Serialize for NativeAbsolutePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Wire<'a> {
            kind: NativeAbsolutePathKind,
            value: &'a str,
        }

        self.validate().map_err(serde::ser::Error::custom)?;
        let encoded = self.encoded_value();
        Wire {
            kind: self.kind(),
            value: &encoded,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NativeAbsolutePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: NativeAbsolutePathKind,
            value: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.value.len() > MAX_NATIVE_ABSOLUTE_PATH_BASE64_LEN {
            return Err(D::Error::custom(
                "native absolute path payload exceeds 64 KiB",
            ));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&wire.value)
            .map_err(D::Error::custom)?;
        if URL_SAFE_NO_PAD.encode(&bytes) != wire.value {
            return Err(D::Error::custom(
                "native absolute path payload is not canonical unpadded base64url",
            ));
        }

        let value = match wire.kind {
            NativeAbsolutePathKind::UnixBytesBase64Url => Self::UnixBytes(bytes),
            NativeAbsolutePathKind::WindowsUtf16LeBase64Url => {
                let (chunks, remainder) = bytes.as_chunks::<2>();
                if !remainder.is_empty() {
                    return Err(D::Error::custom(
                        "windows utf16 path payload must have even length",
                    ));
                }
                Self::WindowsUtf16(
                    chunks
                        .iter()
                        .map(|chunk| u16::from_le_bytes(*chunk))
                        .collect(),
                )
            }
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

impl JsonSchema for NativeAbsolutePath {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "NativeAbsolutePath".into()
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
                    "pattern": "^[A-Za-z0-9_-]+$",
                    "maxLength": MAX_NATIVE_ABSOLUTE_PATH_BASE64_LEN
                }
            },
            "additionalProperties": false,
            "description": "Canonical unpadded base64url of an absolute native path, bounded to 64 KiB of Unix bytes or Windows UTF-16LE bytes"
        })
        .try_into()
        .expect("valid native absolute path schema")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NativeAbsolutePathError {
    #[error("native absolute path contains a NUL code unit")]
    ContainsNul,
    #[error("native path is not absolute for its tagged platform")]
    NotAbsolute,
    #[error("native absolute path uses {actual:?}, but this host requires {expected:?}")]
    ForeignPlatform {
        expected: NativeAbsolutePathKind,
        actual: NativeAbsolutePathKind,
    },
    #[error("native absolute path is {actual_bytes} bytes; maximum is {max_bytes}")]
    TooLong {
        actual_bytes: usize,
        max_bytes: usize,
    },
    #[error("the current platform has no supported native absolute path representation")]
    UnsupportedCurrentPlatform,
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
#[serde(deny_unknown_fields)]
pub struct NativePathComponent {
    pub entry_id: ScanEntryId,
    /// The scan-scoped identity of the component's direct parent. It is absent only for the scan
    /// root. Legacy components that omit this field remain deserializable, but cannot satisfy a
    /// non-root executable locator chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<ScanEntryId>,
    pub native_basename: NativeName,
    pub object_type: ObjectType,
    pub platform_file_identity: IdentityEvidence<PlatformFileIdentity>,
    pub filesystem_object_domain_identity: IdentityEvidence<FilesystemObjectDomainIdentity>,
    pub volume_or_mount_identity: IdentityEvidence<VolumeOrMountIdentity>,
    pub metadata_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeLocatorEvidence {
    pub scan_root: NativePathComponent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_root_absolute_path: Option<NativeAbsolutePath>,
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
        if let Some(absolute_path) = &self.scan_root_absolute_path {
            absolute_path
                .validate()
                .map_err(|_| ScanEntryIdError::InvalidFormat)?;
        }
        Self::validate_component(&self.scan_root, scan_id, true, false)?;
        Self::validate_component(
            &self.entry,
            scan_id,
            false,
            self.entry.entry_id != self.scan_root.entry_id,
        )?;
        if self.scan_root.entry_id != identity.scan_root_id
            || self.entry.entry_id != identity.entry_id
            || self.scan_root.object_type != ObjectType::Directory
            || self.scan_root.parent_id.is_some()
            || self.entry.parent_id != identity.parent_id
            || self.entry.platform_file_identity != identity.platform_file_identity
            || self.entry.filesystem_object_domain_identity
                != identity.filesystem_object_domain_identity
            || self.entry.volume_or_mount_identity != identity.volume_or_mount_identity
        {
            return Err(ScanEntryIdError::InvalidFormat);
        }
        for component in &self.parent_reopen_recipe {
            Self::validate_component(
                component,
                scan_id,
                true,
                component.entry_id != self.scan_root.entry_id,
            )?;
        }
        if self
            .parent_reopen_recipe
            .first()
            .is_some_and(|component| component != &self.scan_root)
        {
            return Err(ScanEntryIdError::InvalidFormat);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut expected_parent = None;
        for component in &self.parent_reopen_recipe {
            if component.parent_id.as_ref() != expected_parent
                || !seen.insert(component.entry_id.clone())
                || component.entry_id == self.entry.entry_id
            {
                return Err(ScanEntryIdError::InvalidFormat);
            }
            expected_parent = Some(&component.entry_id);
        }
        match &identity.parent_id {
            Some(expected_parent)
                if self.parent_reopen_recipe.last().map(|part| &part.entry_id)
                    == Some(expected_parent)
                    && self.entry.parent_id.as_ref() == Some(expected_parent) => {}
            None if self.parent_reopen_recipe.is_empty() && self.entry == self.scan_root => {}
            _ => return Err(ScanEntryIdError::InvalidFormat),
        }
        Ok(())
    }

    /// Validates locator evidence strongly enough to become local execution input.
    pub fn validate_for_execution(
        &self,
        identity: &ScanObjectIdentity,
        scan_id: &ScanId,
    ) -> Result<(), ScanEntryIdError> {
        self.validate_for_identity(identity, scan_id)?;
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
            return Err(ScanEntryIdError::InvalidFormat);
        }
        self.scan_root_absolute_path
            .as_ref()
            .ok_or(ScanEntryIdError::InvalidFormat)?
            .validate_for_current_platform()
            .map_err(|_| ScanEntryIdError::InvalidFormat)?;

        for component in std::iter::once(&self.scan_root)
            .chain(self.parent_reopen_recipe.iter())
            .chain(std::iter::once(&self.entry))
        {
            if component.entry_id != self.scan_root.entry_id {
                component
                    .native_basename
                    .validate_basename_for_current_platform()
                    .map_err(|_| ScanEntryIdError::InvalidFormat)?;
            }
            if !matches!(
                component.platform_file_identity,
                IdentityEvidence::Known { .. }
            ) || !matches!(
                component.filesystem_object_domain_identity,
                IdentityEvidence::Known { .. }
            ) || !matches!(
                component.volume_or_mount_identity,
                IdentityEvidence::Known { .. }
            ) {
                return Err(ScanEntryIdError::InvalidFormat);
            }
        }
        if self.entry.object_type == ObjectType::Other {
            return Err(ScanEntryIdError::InvalidFormat);
        }
        Ok(())
    }

    fn validate_component(
        component: &NativePathComponent,
        scan_id: &ScanId,
        require_directory: bool,
        require_native_basename: bool,
    ) -> Result<(), ScanEntryIdError> {
        if !component.entry_id.belongs_to(scan_id)
            || component
                .parent_id
                .as_ref()
                .is_some_and(|parent_id| !parent_id.belongs_to(scan_id))
        {
            return Err(ScanEntryIdError::ScanMismatch);
        }
        if component.parent_id.as_ref() == Some(&component.entry_id)
            || (require_directory && component.object_type != ObjectType::Directory)
            || component.metadata_fingerprint.is_empty()
            || (require_native_basename && component.native_basename.validate_basename().is_err())
        {
            return Err(ScanEntryIdError::InvalidFormat);
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
        if locator.entry.native_basename != self.native_basename
            || locator.entry.object_type != self.object_type
            || locator.entry.metadata_fingerprint != self.metadata_fingerprint
        {
            return Err(ScanEntryIdError::InvalidFormat);
        }
        Ok(Some(locator))
    }

    /// Returns locator evidence only when it is structurally valid and usable on this host.
    /// Foreign-platform evidence remains deserializable for reporting but cannot become local
    /// execution authority.
    pub fn executable_native_locator(
        &self,
    ) -> Result<Option<&NativeLocatorEvidence>, ScanEntryIdError> {
        let Some(locator) = self.validated_native_locator()? else {
            return Ok(None);
        };
        let identity = self
            .identity
            .as_ref()
            .ok_or(ScanEntryIdError::InvalidFormat)?;
        locator.validate_for_execution(identity, &self.scan_id)?;
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

    fn known_platform_identity(inode: u128) -> IdentityEvidence<PlatformFileIdentity> {
        IdentityEvidence::known(PlatformFileIdentity {
            device: DecimalU128::new(1),
            inode: DecimalU128::new(inode),
        })
    }

    fn known_domain_identity() -> IdentityEvidence<FilesystemObjectDomainIdentity> {
        IdentityEvidence::known(FilesystemObjectDomainIdentity {
            device: DecimalU128::new(1),
        })
    }

    fn known_mount_identity() -> IdentityEvidence<VolumeOrMountIdentity> {
        IdentityEvidence::known(VolumeOrMountIdentity {
            value: DecimalU128::new(1),
        })
    }

    fn host_native_name(name: &str) -> NativeName {
        #[cfg(unix)]
        {
            NativeName::unix(name.as_bytes().to_vec())
        }
        #[cfg(windows)]
        {
            NativeName::windows_utf16(name.encode_utf16().collect::<Vec<_>>())
        }
        #[cfg(not(any(unix, windows)))]
        {
            NativeName::unix(name.as_bytes().to_vec())
        }
    }

    fn host_native_absolute_root() -> NativeAbsolutePath {
        #[cfg(unix)]
        {
            NativeAbsolutePath::unix(b"/root".to_vec())
        }
        #[cfg(windows)]
        {
            NativeAbsolutePath::windows_utf16(r"C:\root".encode_utf16().collect::<Vec<_>>())
        }
        #[cfg(not(any(unix, windows)))]
        {
            NativeAbsolutePath::unix(b"/root".to_vec())
        }
    }

    fn locator_component(
        scan_id: &ScanId,
        ordinal: u128,
        parent_ordinal: Option<u128>,
        basename: &str,
        object_type: ObjectType,
    ) -> NativePathComponent {
        NativePathComponent {
            entry_id: ScanEntryId::for_scan_ordinal(scan_id, ordinal).unwrap(),
            parent_id: parent_ordinal
                .map(|parent| ScanEntryId::for_scan_ordinal(scan_id, parent).unwrap()),
            native_basename: host_native_name(basename),
            object_type,
            platform_file_identity: known_platform_identity(ordinal),
            filesystem_object_domain_identity: known_domain_identity(),
            volume_or_mount_identity: known_mount_identity(),
            metadata_fingerprint: format!("fp-{ordinal}"),
        }
    }

    fn child_locator_fixture() -> (ScanId, ScanObjectIdentity, NativeLocatorEvidence) {
        let scan_id = ScanId::new("locator-chain");
        let root = locator_component(&scan_id, 1, None, "root", ObjectType::Directory);
        let ancestor = locator_component(&scan_id, 2, Some(1), "ancestor", ObjectType::Directory);
        let parent = locator_component(&scan_id, 3, Some(2), "parent", ObjectType::Directory);
        let entry = locator_component(&scan_id, 4, Some(3), "item", ObjectType::File);
        let identity = ScanObjectIdentity {
            entry_id: entry.entry_id.clone(),
            scan_root_id: root.entry_id.clone(),
            parent_id: entry.parent_id.clone(),
            platform_file_identity: entry.platform_file_identity.clone(),
            filesystem_object_domain_identity: entry.filesystem_object_domain_identity.clone(),
            volume_or_mount_identity: entry.volume_or_mount_identity.clone(),
        };
        let locator = NativeLocatorEvidence {
            scan_root: root.clone(),
            scan_root_absolute_path: Some(host_native_absolute_root()),
            parent_reopen_recipe: vec![root, ancestor, parent],
            entry,
        };
        (scan_id, identity, locator)
    }

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
    fn native_basename_rejects_path_and_dot_components() {
        for invalid in [b"".as_slice(), b".", b"..", b"a/b", b"a\0b"] {
            assert!(
                NativeName::unix(invalid.to_vec())
                    .validate_basename()
                    .is_err()
            );
        }
        for invalid in [
            r".",
            r"..",
            r"a\b",
            r"a/b",
            r"a:b",
            r"NUL.txt",
            r"CLOCK$",
            r"clock$.log",
            r"COM¹",
            r"com².data",
            r"LPT³",
        ] {
            assert!(
                NativeName::windows_utf16(invalid.encode_utf16().collect::<Vec<_>>())
                    .validate_basename()
                    .is_err()
            );
        }
    }

    #[test]
    fn native_locator_accepts_filesystem_root_name_with_absolute_root_authority() {
        let scan_id = ScanId::new("filesystem-root");
        #[allow(unused_mut)]
        let mut root = locator_component(&scan_id, 1, None, "/", ObjectType::Directory);
        let identity = ScanObjectIdentity {
            entry_id: root.entry_id.clone(),
            scan_root_id: root.entry_id.clone(),
            parent_id: None,
            platform_file_identity: root.platform_file_identity.clone(),
            filesystem_object_domain_identity: root.filesystem_object_domain_identity.clone(),
            volume_or_mount_identity: root.volume_or_mount_identity.clone(),
        };
        #[cfg(windows)]
        {
            root.native_basename =
                NativeName::windows_utf16(r"C:\".encode_utf16().collect::<Vec<_>>());
        }
        let absolute_root = {
            #[cfg(unix)]
            {
                NativeAbsolutePath::unix(b"/".to_vec())
            }
            #[cfg(windows)]
            {
                NativeAbsolutePath::windows_utf16(r"C:\".encode_utf16().collect::<Vec<_>>())
            }
            #[cfg(not(any(unix, windows)))]
            {
                NativeAbsolutePath::unix(b"/".to_vec())
            }
        };
        let locator = NativeLocatorEvidence {
            scan_root: root.clone(),
            scan_root_absolute_path: Some(absolute_root),
            parent_reopen_recipe: vec![],
            entry: root,
        };

        assert!(locator.validate_for_execution(&identity, &scan_id).is_ok());
    }

    #[test]
    fn native_locator_requires_a_contiguous_root_to_parent_chain() {
        let (scan_id, identity, locator) = child_locator_fixture();
        assert!(locator.validate_for_identity(&identity, &scan_id).is_ok());

        let mut skipped = locator.clone();
        skipped.parent_reopen_recipe.remove(1);
        assert_eq!(
            skipped.validate_for_identity(&identity, &scan_id),
            Err(ScanEntryIdError::InvalidFormat)
        );

        let mut forged_parent = locator.clone();
        forged_parent.parent_reopen_recipe[2].parent_id =
            Some(ScanEntryId::for_scan_ordinal(&scan_id, 1).unwrap());
        assert_eq!(
            forged_parent.validate_for_identity(&identity, &scan_id),
            Err(ScanEntryIdError::InvalidFormat)
        );

        let mut missing_link = locator;
        missing_link.parent_reopen_recipe[1].parent_id = None;
        assert_eq!(
            missing_link.validate_for_identity(&identity, &scan_id),
            Err(ScanEntryIdError::InvalidFormat)
        );
    }

    #[test]
    fn native_locator_execution_requires_known_identity_and_mount_evidence() {
        let (scan_id, identity, locator) = child_locator_fixture();
        assert!(locator.validate_for_execution(&identity, &scan_id).is_ok());

        let mut unknown_ancestor = locator.clone();
        unknown_ancestor.parent_reopen_recipe[1].platform_file_identity =
            IdentityEvidence::unknown(ReasonCode::UnknownIdentity);
        assert_eq!(
            unknown_ancestor.validate_for_execution(&identity, &scan_id),
            Err(ScanEntryIdError::InvalidFormat)
        );

        let mut unknown_mount = locator.clone();
        unknown_mount.entry.volume_or_mount_identity =
            IdentityEvidence::unknown(ReasonCode::UnknownIdentity);
        let mut matching_identity = identity.clone();
        matching_identity.volume_or_mount_identity =
            IdentityEvidence::unknown(ReasonCode::UnknownIdentity);
        assert_eq!(
            unknown_mount.validate_for_execution(&matching_identity, &scan_id),
            Err(ScanEntryIdError::InvalidFormat)
        );

        let mut unknown_type = locator;
        unknown_type.entry.object_type = ObjectType::Other;
        assert_eq!(
            unknown_type.validate_for_execution(&identity, &scan_id),
            Err(ScanEntryIdError::InvalidFormat)
        );
    }

    #[test]
    fn scanned_entry_rejects_locator_type_and_fingerprint_mismatch() {
        let (scan_id, identity, locator) = child_locator_fixture();
        let mut entry = ScannedEntry {
            scan_id,
            identity: Some(identity),
            native_locator: Some(locator),
            display_path: "/root/ancestor/parent/item".to_string(),
            native_basename: host_native_name("item"),
            object_type: ObjectType::File,
            logical_bytes: EvidenceValue::Known {
                value: DecimalU128::ZERO,
            },
            allocated_bytes: EvidenceValue::Known {
                value: DecimalU128::ZERO,
            },
            reclaimable_estimate: EvidenceValue::Known {
                value: DecimalU128::ZERO,
            },
            metadata_fingerprint: "fp-4".to_string(),
            coverage: Coverage {
                state: CoverageState::Complete,
                complete: true,
                incomplete_reasons: vec![],
                details_lost: false,
                provenance: FieldProvenance::Unknown {
                    reason: ReasonCode::NotRevalidated,
                },
            },
            provenance: FieldProvenance::Unknown {
                reason: ReasonCode::NotRevalidated,
            },
        };
        assert!(entry.validated_native_locator().is_ok());

        entry.object_type = ObjectType::Directory;
        assert_eq!(
            entry.validated_native_locator(),
            Err(ScanEntryIdError::InvalidFormat)
        );
        entry.object_type = ObjectType::File;
        entry.metadata_fingerprint = "forged".to_string();
        assert_eq!(
            entry.validated_native_locator(),
            Err(ScanEntryIdError::InvalidFormat)
        );
    }

    #[test]
    fn native_absolute_paths_round_trip_losslessly_for_both_platforms() {
        let unix = NativeAbsolutePath::unix(vec![b'/', b't', b'm', b'p', b'/', 0xff]);
        let windows = NativeAbsolutePath::windows_utf16(
            r"C:\fixture\rocket-🚀".encode_utf16().collect::<Vec<_>>(),
        );

        for path in [unix, windows] {
            let encoded = serde_json::to_string(&path).unwrap();
            let decoded: NativeAbsolutePath = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, path);
        }
    }

    #[test]
    fn native_absolute_path_rejects_noncanonical_malformed_and_unsafe_wire_forms() {
        for wire in [
            r#"{"kind":"unix_bytes_base64_url","value":"L3RtcA=="}"#,
            r#"{"kind":"unix_bytes_base64_url","value":"dG1w"}"#,
            r#"{"kind":"unix_bytes_base64_url","value":"LwA"}"#,
            r#"{"kind":"windows_utf16_le_base64_url","value":"QwA6AFwAAQ"}"#,
            r#"{"kind":"windows_utf16_le_base64_url","value":"cgBlAGwAYQB0AGkAdgBlAA"}"#,
        ] {
            assert!(
                serde_json::from_str::<NativeAbsolutePath>(wire).is_err(),
                "unexpectedly accepted {wire}"
            );
        }

        let oversized = NativeAbsolutePath::unix(
            std::iter::once(b'/')
                .chain(std::iter::repeat_n(b'a', MAX_NATIVE_ABSOLUTE_PATH_BYTES))
                .collect::<Vec<_>>(),
        );
        assert!(matches!(
            oversized.validate(),
            Err(NativeAbsolutePathError::TooLong { .. })
        ));
        assert!(serde_json::to_string(&oversized).is_err());
    }

    #[test]
    fn native_absolute_path_distinguishes_generic_and_host_validation() {
        let unix = NativeAbsolutePath::unix(b"/tmp/root".to_vec());
        let windows =
            NativeAbsolutePath::windows_utf16(r"C:\root".encode_utf16().collect::<Vec<_>>());
        assert!(unix.validate().is_ok());
        assert!(windows.validate().is_ok());

        #[cfg(unix)]
        {
            assert!(unix.validate_for_current_platform().is_ok());
            assert!(matches!(
                windows.validate_for_current_platform(),
                Err(NativeAbsolutePathError::ForeignPlatform { .. })
            ));
        }
        #[cfg(windows)]
        {
            assert!(windows.validate_for_current_platform().is_ok());
            assert!(matches!(
                unix.validate_for_current_platform(),
                Err(NativeAbsolutePathError::ForeignPlatform { .. })
            ));
        }
    }

    #[test]
    fn windows_native_absolute_path_rejects_namespace_and_relative_forms() {
        for path in [
            r"\\?\C:\root",
            r"\\.\C:\root",
            r"\??\C:\root",
            r"C:relative",
            r"\\server",
        ] {
            let value = NativeAbsolutePath::windows_utf16(path.encode_utf16().collect::<Vec<_>>());
            assert!(
                matches!(value.validate(), Err(NativeAbsolutePathError::NotAbsolute)),
                "unexpectedly accepted {path}"
            );
        }
        assert!(
            NativeAbsolutePath::windows_utf16(
                r"\\server\share\root".encode_utf16().collect::<Vec<_>>()
            )
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn legacy_locator_without_absolute_root_is_readable_but_not_executable() {
        let scan_id = ScanId::new("legacy-locator");
        let root_id = ScanEntryId::for_scan_ordinal(&scan_id, 1).unwrap();
        let component = NativePathComponent {
            entry_id: root_id.clone(),
            parent_id: None,
            native_basename: NativeName::unix(b"root".to_vec()),
            object_type: ObjectType::Directory,
            platform_file_identity: IdentityEvidence::unknown(ReasonCode::UnknownIdentity),
            filesystem_object_domain_identity: IdentityEvidence::unknown(
                ReasonCode::UnknownIdentity,
            ),
            volume_or_mount_identity: IdentityEvidence::unknown(ReasonCode::UnknownIdentity),
            metadata_fingerprint: "root-fingerprint".to_string(),
        };
        let wire = json!({
            "scan_root": component,
            "parent_reopen_recipe": [],
            "entry": component,
        });
        let locator: NativeLocatorEvidence = serde_json::from_value(wire).unwrap();
        assert_eq!(locator.scan_root_absolute_path, None);
        let entry = ScannedEntry {
            scan_id: scan_id.clone(),
            identity: Some(ScanObjectIdentity {
                entry_id: root_id.clone(),
                scan_root_id: root_id,
                parent_id: None,
                platform_file_identity: IdentityEvidence::unknown(ReasonCode::UnknownIdentity),
                filesystem_object_domain_identity: IdentityEvidence::unknown(
                    ReasonCode::UnknownIdentity,
                ),
                volume_or_mount_identity: IdentityEvidence::unknown(ReasonCode::UnknownIdentity),
            }),
            native_locator: Some(locator),
            display_path: "/root".to_string(),
            native_basename: NativeName::unix(b"root".to_vec()),
            object_type: ObjectType::Directory,
            logical_bytes: EvidenceValue::Known {
                value: DecimalU128::ZERO,
            },
            allocated_bytes: EvidenceValue::Known {
                value: DecimalU128::ZERO,
            },
            reclaimable_estimate: EvidenceValue::Known {
                value: DecimalU128::ZERO,
            },
            metadata_fingerprint: "root-fingerprint".to_string(),
            coverage: Coverage {
                state: CoverageState::Complete,
                complete: true,
                incomplete_reasons: vec![],
                details_lost: false,
                provenance: FieldProvenance::Unknown {
                    reason: ReasonCode::NotRevalidated,
                },
            },
            provenance: FieldProvenance::Unknown {
                reason: ReasonCode::NotRevalidated,
            },
        };
        assert!(entry.validated_native_locator().unwrap().is_some());
        assert!(entry.executable_native_locator().is_err());
    }

    #[test]
    fn native_locator_rejects_unknown_fields() {
        let scan_id = ScanId::new("strict-locator");
        let root_id = ScanEntryId::for_scan_ordinal(&scan_id, 1).unwrap();
        let component = NativePathComponent {
            entry_id: root_id,
            parent_id: None,
            native_basename: NativeName::unix(b"root".to_vec()),
            object_type: ObjectType::Directory,
            platform_file_identity: IdentityEvidence::unknown(ReasonCode::UnknownIdentity),
            filesystem_object_domain_identity: IdentityEvidence::unknown(
                ReasonCode::UnknownIdentity,
            ),
            volume_or_mount_identity: IdentityEvidence::unknown(ReasonCode::UnknownIdentity),
            metadata_fingerprint: "root-fingerprint".to_string(),
        };
        let mut wire = json!({
            "scan_root": component,
            "parent_reopen_recipe": [],
            "entry": component,
        });
        wire["unexpected"] = json!(true);
        assert!(serde_json::from_value::<NativeLocatorEvidence>(wire).is_err());
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
