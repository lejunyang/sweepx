use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use sweepx_model::{CountValue, DecimalU128, EvidenceValue, NativeName, ReasonCode};
use thiserror::Error;

pub type ByteValue = EvidenceValue<DecimalU128>;

#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    inner: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.inner.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanRoot {
    pub path: PathBuf,
}

impl ScanRoot {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, RootValidationError> {
        let path = path.into();
        if !path.is_absolute() {
            return Err(RootValidationError::NotAbsolute(path));
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Error)]
pub enum RootValidationError {
    #[error("scan root must be absolute: {0}")]
    NotAbsolute(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    ReparsePoint,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryKind {
    RootSymlink,
    Symlink,
    ReparsePoint,
    Mount,
    ResourceLimit,
    Cancelled,
    OtherFilesystem,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    AccessDenied,
    NotFound,
    Interrupted,
    InvalidInput,
    ResourceLimit,
    Io,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryIdentity {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemIdentity {
    pub device: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountIdentity {
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HardLinkKey {
    pub device: u64,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntryRecord {
    pub path: PathBuf,
    pub file_name: NativeName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMetadata {
    pub path: PathBuf,
    pub file_name: NativeName,
    pub kind: EntryKind,
    pub logical_bytes: ByteValue,
    pub allocated_bytes: ByteValue,
    pub hard_link_count: CountValue,
    pub fingerprint: String,
    pub identity: Option<EntryIdentity>,
    pub filesystem_identity: Option<FilesystemIdentity>,
    pub mount_identity: Option<MountIdentity>,
    pub hard_link_key: Option<HardLinkKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoundaryRecord {
    pub path: PathBuf,
    pub kind: BoundaryKind,
    pub reason: ReasonCode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorRecord {
    pub path: PathBuf,
    pub kind: ErrorKind,
    pub reason: ReasonCode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkEntry {
    Directory(EntryMetadata),
    File(EntryMetadata),
    Link(EntryMetadata),
    Boundary(BoundaryRecord),
    Error(ErrorRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAdmission {
    pub root: ScanRoot,
    pub metadata: EntryMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanResourceLimits {
    pub max_directory_entries: usize,
    pub max_frontier_entries: usize,
    pub max_visited_entries: usize,
    pub max_retained_entries: usize,
    pub max_retained_boundaries: usize,
    pub max_progress_events: usize,
}

impl Default for ScanResourceLimits {
    fn default() -> Self {
        Self {
            max_directory_entries: 131_072,
            max_frontier_entries: 4096,
            max_visited_entries: 131_072,
            max_retained_entries: 16_384,
            max_retained_boundaries: 16_384,
            max_progress_events: 16_384,
        }
    }
}

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("operation cancelled")]
    Cancelled,
    #[error("scan root rejected: {0}")]
    RootRejected(String),
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),
    #[error("io error at {path}: {detail}")]
    Io {
        path: PathBuf,
        detail: String,
        io_kind: Option<std::io::ErrorKind>,
    },
    #[error("unsupported platform operation: {0}")]
    Unsupported(String),
}

impl PlatformError {
    pub fn io(path: impl Into<PathBuf>, error: std::io::Error) -> Self {
        let detail = error.to_string();
        let io_kind = Some(error.kind());
        Self::Io {
            path: path.into(),
            detail,
            io_kind,
        }
    }
}

pub trait PlatformScanner: Send + Sync {
    fn platform_name(&self) -> &'static str;

    fn admit_root(
        &self,
        root: &ScanRoot,
        cancel: &CancellationToken,
    ) -> Result<RootAdmission, PlatformError>;

    fn read_dir_entries(
        &self,
        path: &Path,
        cancel: &CancellationToken,
        max_entries: usize,
    ) -> Result<Vec<DirectoryEntryRecord>, PlatformError>;

    fn stat_entry(
        &self,
        path: &Path,
        file_name: NativeName,
        cancel: &CancellationToken,
    ) -> Result<WalkEntry, PlatformError>;

    fn is_same_mount(
        &self,
        root: &EntryMetadata,
        entry: &EntryMetadata,
    ) -> Result<bool, PlatformError>;
}

pub fn known_u128(value: u128) -> ByteValue {
    EvidenceValue::Known {
        value: DecimalU128::new(value),
    }
}

pub fn known_count(value: u128) -> CountValue {
    EvidenceValue::Known {
        value: DecimalU128::new(value),
    }
}

pub fn lower_bound_u128(value: u128, reason: ReasonCode) -> ByteValue {
    EvidenceValue::LowerBound {
        value: DecimalU128::new(value),
        reason,
    }
}

pub fn unknown_u128(reason: ReasonCode) -> ByteValue {
    EvidenceValue::Unknown { reason }
}

pub fn unsupported_u128(reason: ReasonCode) -> ByteValue {
    EvidenceValue::Unsupported { reason }
}

pub fn error_kind_for_io(error: &std::io::Error) -> ErrorKind {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => ErrorKind::AccessDenied,
        std::io::ErrorKind::NotFound => ErrorKind::NotFound,
        std::io::ErrorKind::Interrupted => ErrorKind::Interrupted,
        _ => ErrorKind::Io,
    }
}

pub fn reason_for_io(error: &std::io::Error) -> ReasonCode {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => ReasonCode::StrictReadOnly,
        std::io::ErrorKind::NotFound => ReasonCode::UnknownIdentity,
        std::io::ErrorKind::Interrupted => ReasonCode::Unknown,
        _ => ReasonCode::Unknown,
    }
}

pub fn fingerprint_for(
    identity: Option<&EntryIdentity>,
    kind: &EntryKind,
    logical_bytes: &ByteValue,
) -> String {
    struct DisplayByteValue<'a>(&'a ByteValue);

    impl fmt::Display for DisplayByteValue<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.0 {
                EvidenceValue::Known { value } => write!(f, "known:{value}"),
                EvidenceValue::LowerBound { value, reason } => {
                    write!(f, "lower:{value}:{reason:?}")
                }
                EvidenceValue::Unknown { reason } => write!(f, "unknown:{reason:?}"),
                EvidenceValue::Unsupported { reason } => write!(f, "unsupported:{reason:?}"),
                EvidenceValue::NotChecked { reason } => write!(f, "not_checked:{reason:?}"),
            }
        }
    }

    match identity {
        Some(identity) => format!(
            "{}:{}:{kind:?}:{}",
            identity.device,
            identity.inode,
            DisplayByteValue(logical_bytes)
        ),
        None => format!("unknown:{kind:?}:{}", DisplayByteValue(logical_bytes)),
    }
}
