use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use serde::{Deserialize, Serialize};
use sweepx_model::{
    CountValue, DecimalU128, EvidenceValue, NativeAbsolutePath, NativeName, ReasonCode,
};
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
    #[error("scan root has no valid bounded native absolute representation: {0}")]
    InvalidNativePath(String),
}

impl ScanRoot {
    pub fn native_absolute_path(&self) -> Result<NativeAbsolutePath, RootValidationError> {
        NativeAbsolutePath::from_path(&self.path)
            .map_err(|error| RootValidationError::InvalidNativePath(error.to_string()))
    }
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
    /// Unix device identifier or Windows volume serial number.
    device: u64,
    /// Unix inode number or a reversible little-endian encoding of Windows `FILE_ID_128`.
    inode: u128,
}

impl EntryIdentity {
    pub const fn from_unix(device: u64, inode: u64) -> Self {
        Self {
            device,
            inode: inode as u128,
        }
    }

    pub const fn from_windows_file_id(device: u64, file_id: [u8; 16]) -> Self {
        Self {
            device,
            inode: u128::from_le_bytes(file_id),
        }
    }

    pub const fn device(&self) -> u64 {
        self.device
    }

    pub const fn inode(&self) -> u128 {
        self.inode
    }

    pub const fn windows_file_id(&self) -> [u8; 16] {
        self.inode.to_le_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemIdentity {
    pub device: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountIdentity {
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HardLinkKey {
    /// Unix device identifier or Windows volume serial number.
    device: u64,
    /// Unix inode number or a reversible little-endian encoding of Windows `FILE_ID_128`.
    inode: u128,
}

impl HardLinkKey {
    pub const fn from_unix(device: u64, inode: u64) -> Self {
        Self {
            device,
            inode: inode as u128,
        }
    }

    pub const fn from_windows_file_id(device: u64, file_id: [u8; 16]) -> Self {
        Self {
            device,
            inode: u128::from_le_bytes(file_id),
        }
    }

    pub const fn device(&self) -> u64 {
        self.device
    }

    pub const fn inode(&self) -> u128 {
        self.inode
    }

    pub const fn windows_file_id(&self) -> [u8; 16] {
        self.inode.to_le_bytes()
    }
}

impl From<EntryIdentity> for HardLinkKey {
    fn from(identity: EntryIdentity) -> Self {
        Self {
            device: identity.device,
            inode: identity.inode,
        }
    }
}

/// An untrusted, displayable child token returned by directory enumeration.
///
/// `file_name` is the native token that a backend resolves relative to the retained parent
/// directory handle. `path` is reporting data and must equal `parent_path.join(file_name)`. The
/// fields remain public for backend compatibility, so constructing or mutating this value does not
/// establish that invariant. Call [`Self::from_parent_and_name`] when creating a record and
/// [`Self::validate_for_parent`] at every trust boundary. In particular, a backend must never use
/// `path` to reopen a child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntryRecord {
    pub path: PathBuf,
    pub file_name: NativeName,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DirectoryEntryInvariantError {
    #[error("native child token encoding does not match the host platform")]
    ForeignNativeName,
    #[error("native child token is not a safe single path component")]
    UnsafeNativeName,
    #[error(
        "directory entry path is not bound to its parent and token: expected {expected:?}, got {actual:?}"
    )]
    PathMismatch { expected: PathBuf, actual: PathBuf },
    #[error(
        "inspected entry path does not match the enumerated child: expected {expected:?}, got {actual:?}"
    )]
    InspectedPathMismatch { expected: PathBuf, actual: PathBuf },
    #[error("inspected entry native name does not match the enumerated child token")]
    InspectedNameMismatch,
    #[error(
        "inspected entry kind does not match its walk variant: expected {expected:?}, got {actual:?}"
    )]
    InspectedKindMismatch {
        expected: EntryKind,
        actual: EntryKind,
    },
    #[error("root admission returned a different root: expected {expected:?}, got {actual:?}")]
    RootMismatch { expected: PathBuf, actual: PathBuf },
    #[error(
        "root metadata path does not match the requested root: expected {expected:?}, got {actual:?}"
    )]
    RootPathMismatch { expected: PathBuf, actual: PathBuf },
    #[error("root metadata is not a directory: got {actual:?}")]
    RootKindMismatch { actual: EntryKind },
    #[error("root admission did not preserve the exact requested native absolute path")]
    RootNativePathMismatch,
}

impl DirectoryEntryRecord {
    /// Constructs a record whose display path is derived from one validated native basename.
    pub fn from_parent_and_name(
        parent_path: &Path,
        file_name: NativeName,
    ) -> Result<Self, DirectoryEntryInvariantError> {
        let component = native_name_component(&file_name)?;
        let record = Self {
            path: parent_path.join(Path::new(&component)),
            file_name,
        };
        record.validate_for_parent(parent_path)?;
        Ok(record)
    }

    /// Verifies that the native token is one safe basename and that `path` is derived from the
    /// supplied parent. This is a lexical/reporting invariant; the backend must additionally bind
    /// the token to the exact retained parent handle and resolve it only with a no-follow,
    /// handle-relative operation.
    pub fn validate_for_parent(
        &self,
        parent_path: &Path,
    ) -> Result<(), DirectoryEntryInvariantError> {
        let component = native_name_component(&self.file_name)?;
        let expected = parent_path.join(Path::new(&component));
        if self.path != expected {
            return Err(DirectoryEntryInvariantError::PathMismatch {
                expected,
                actual: self.path.clone(),
            });
        }
        Ok(())
    }

    /// Conservative retained-memory accounting used for both per-batch and per-directory caps.
    pub fn estimated_retained_bytes(&self) -> Option<usize> {
        let name_bytes = match &self.file_name {
            NativeName::UnixBytes(bytes) => bytes.len(),
            NativeName::WindowsUtf16(units) => units.len().checked_mul(2)?,
        };
        std::mem::size_of::<Self>()
            .checked_add(name_bytes)?
            .checked_add(path_storage_bytes(&self.path)?)
    }
}

fn path_storage_bytes(path: &Path) -> Option<usize> {
    #[cfg(unix)]
    {
        Some(path.as_os_str().as_bytes().len())
    }
    #[cfg(windows)]
    {
        path.as_os_str().encode_wide().count().checked_mul(2)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Some(path.as_os_str().to_string_lossy().len())
    }
}

fn native_name_component(file_name: &NativeName) -> Result<OsString, DirectoryEntryInvariantError> {
    #[cfg(unix)]
    let component = match file_name {
        NativeName::UnixBytes(bytes) if !bytes.contains(&0) => OsString::from_vec(bytes.clone()),
        NativeName::UnixBytes(_) => return Err(DirectoryEntryInvariantError::UnsafeNativeName),
        NativeName::WindowsUtf16(_) => {
            return Err(DirectoryEntryInvariantError::ForeignNativeName);
        }
    };

    #[cfg(windows)]
    let component = match file_name {
        NativeName::WindowsUtf16(units)
            if !units.contains(&0) && !units.contains(&(b':' as u16)) =>
        {
            OsString::from_wide(units)
        }
        NativeName::WindowsUtf16(_) => {
            return Err(DirectoryEntryInvariantError::UnsafeNativeName);
        }
        NativeName::UnixBytes(_) => {
            return Err(DirectoryEntryInvariantError::ForeignNativeName);
        }
    };

    #[cfg(not(any(unix, windows)))]
    let component = {
        let _ = file_name;
        return Err(DirectoryEntryInvariantError::ForeignNativeName);
    };

    let mut components = Path::new(&component).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(DirectoryEntryInvariantError::UnsafeNativeName);
    }
    Ok(component)
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

#[derive(Debug)]
pub struct OpenedDirectory<D> {
    pub metadata: EntryMetadata,
    pub handle: D,
}

#[derive(Debug)]
pub enum WalkEntry<D> {
    Directory(OpenedDirectory<D>),
    File(EntryMetadata),
    Link(EntryMetadata),
    Boundary(BoundaryRecord),
    Error(ErrorRecord),
}

impl<D> WalkEntry<D> {
    /// Validates that an inspection result still describes the enumerated child.
    ///
    /// This catches a buggy or adversarial backend that substitutes reporting metadata after
    /// resolving the child token. It cannot inspect an opaque OS handle, so the backend remains
    /// responsible for proving that any returned directory handle names this same object.
    pub fn validate_for_child(
        &self,
        parent_path: &Path,
        child: &DirectoryEntryRecord,
    ) -> Result<(), DirectoryEntryInvariantError> {
        child.validate_for_parent(parent_path)?;
        match self {
            Self::Directory(opened) => {
                validate_inspected_metadata(child, &opened.metadata, EntryKind::Directory)
            }
            Self::File(metadata) => validate_inspected_metadata(child, metadata, EntryKind::File),
            Self::Link(metadata) => {
                validate_inspected_metadata(child, metadata, EntryKind::Symlink)
            }
            Self::Boundary(boundary) => validate_inspected_path(child, &boundary.path),
            Self::Error(error) => validate_inspected_path(child, &error.path),
        }
    }
}

fn validate_inspected_metadata(
    child: &DirectoryEntryRecord,
    metadata: &EntryMetadata,
    expected_kind: EntryKind,
) -> Result<(), DirectoryEntryInvariantError> {
    validate_inspected_path(child, &metadata.path)?;
    if metadata.file_name != child.file_name {
        return Err(DirectoryEntryInvariantError::InspectedNameMismatch);
    }
    if metadata.kind != expected_kind {
        return Err(DirectoryEntryInvariantError::InspectedKindMismatch {
            expected: expected_kind,
            actual: metadata.kind.clone(),
        });
    }
    Ok(())
}

fn validate_inspected_path(
    child: &DirectoryEntryRecord,
    actual: &Path,
) -> Result<(), DirectoryEntryInvariantError> {
    if actual != child.path {
        return Err(DirectoryEntryInvariantError::InspectedPathMismatch {
            expected: child.path.clone(),
            actual: actual.to_path_buf(),
        });
    }
    Ok(())
}

#[derive(Debug)]
pub struct RootAdmission<D> {
    pub root: ScanRoot,
    pub root_locator: NativeAbsolutePath,
    pub metadata: EntryMetadata,
    pub directory: D,
}

impl<D> RootAdmission<D> {
    pub fn new(
        root: ScanRoot,
        metadata: EntryMetadata,
        directory: D,
        root_locator: NativeAbsolutePath,
    ) -> Self {
        Self {
            root,
            root_locator,
            metadata,
            directory,
        }
    }

    /// Validates the reporting half of root admission. The backend additionally guarantees that
    /// `directory` is the no-follow handle from which `metadata` was read.
    pub fn validate_for_root(
        &self,
        requested: &ScanRoot,
    ) -> Result<(), DirectoryEntryInvariantError> {
        if self.root.path != requested.path {
            return Err(DirectoryEntryInvariantError::RootMismatch {
                expected: requested.path.clone(),
                actual: self.root.path.clone(),
            });
        }
        if self.metadata.path != requested.path {
            return Err(DirectoryEntryInvariantError::RootPathMismatch {
                expected: requested.path.clone(),
                actual: self.metadata.path.clone(),
            });
        }
        if self.metadata.kind != EntryKind::Directory {
            return Err(DirectoryEntryInvariantError::RootKindMismatch {
                actual: self.metadata.kind.clone(),
            });
        }
        if !self
            .root_locator
            .equals_path(requested.path())
            .map_err(|_| DirectoryEntryInvariantError::RootNativePathMismatch)?
        {
            return Err(DirectoryEntryInvariantError::RootNativePathMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryReadLimits {
    /// Maximum records retained in the batch returned by one call.
    pub max_batch_entries: usize,
    /// Maximum estimated retained bytes in the batch returned by one call.
    pub max_batch_bytes: usize,
}

/// One bounded page from a retained directory enumeration cursor.
///
/// Backends retain continuation state inside their opaque directory handle. `end_of_directory` is
/// authoritative: callers must request another batch when it is false. Returning an empty,
/// non-terminal batch violates the scanner contract because it cannot make bounded progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntryBatch {
    pub entries: Vec<DirectoryEntryRecord>,
    pub end_of_directory: bool,
}

impl DirectoryEntryBatch {
    pub fn complete(entries: Vec<DirectoryEntryRecord>) -> Self {
        Self {
            entries,
            end_of_directory: true,
        }
    }

    pub fn continued(entries: Vec<DirectoryEntryRecord>) -> Self {
        Self {
            entries,
            end_of_directory: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanResourceLimits {
    /// Maximum children consumed across all batches for one directory.
    pub max_directory_entries: usize,
    /// Maximum estimated child-record bytes consumed across all batches for one directory.
    pub max_directory_bytes: usize,
    /// Maximum children requested from a backend in one batch.
    pub max_directory_batch_entries: usize,
    /// Maximum estimated child-record bytes requested from a backend in one batch.
    pub max_directory_batch_bytes: usize,
    pub max_frontier_entries: usize,
    pub max_visited_entries: usize,
    /// Maximum in-memory directory aggregation states, including the root.
    pub max_retained_aggregates: usize,
    pub max_retained_entries: usize,
    pub max_retained_boundaries: usize,
    pub max_progress_events: usize,
}

impl Default for ScanResourceLimits {
    fn default() -> Self {
        Self {
            max_directory_entries: 131_072,
            max_directory_bytes: 16 * 1024 * 1024,
            max_directory_batch_entries: 4096,
            max_directory_batch_bytes: 1024 * 1024,
            max_frontier_entries: 4096,
            max_visited_entries: 131_072,
            max_retained_aggregates: 131_072,
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
    #[error("invalid directory entry for parent {parent:?}: {detail}")]
    InvalidDirectoryEntry { parent: PathBuf, detail: String },
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

/// A no-follow scanner whose descendant authority is carried by retained directory handles.
///
/// Implementations must treat every [`DirectoryEntryRecord`] as untrusted, even when it originally
/// came from their own enumeration method: callers can construct or mutate public records. Child
/// inspection must validate the record against the exact parent handle, resolve only its native
/// basename relative to that handle, and verify that a newly opened directory is the object that
/// was inspected. A display path must never be used to regain traversal authority.
pub trait PlatformScanner: Send + Sync {
    /// An owned, scan-scoped traversal capability. It must not be clonable into broader authority
    /// or reconstructed from a display path.
    type DirectoryHandle: Send;

    fn platform_name(&self) -> &'static str;

    fn admit_root(
        &self,
        root: &ScanRoot,
        cancel: &CancellationToken,
    ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError>;

    fn enumerate_children(
        &self,
        directory: &mut Self::DirectoryHandle,
        cancel: &CancellationToken,
        limits: DirectoryReadLimits,
    ) -> Result<DirectoryEntryBatch, PlatformError>;

    /// Performs backend-specific, handle-relative child inspection.
    ///
    /// Implementations must independently enforce the [`DirectoryEntryRecord`] invariant and must
    /// ignore `child.path` for resolution. Scanner code should call [`inspect_bound_child`], which
    /// adds non-overridable contract checks before and after this operation.
    fn inspect_child(
        &self,
        parent: &Self::DirectoryHandle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
    ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError>;

    fn is_same_mount(
        &self,
        root: &EntryMetadata,
        entry: &EntryMetadata,
    ) -> Result<bool, PlatformError>;
}

/// Contract-checking child inspection entry point used by traversal engines.
///
/// `parent_path` is the reporting path paired with `parent` when that handle was admitted. It
/// carries no filesystem authority. Unknown or inconsistent bindings fail closed before the
/// backend can inspect a different token, and substituted result metadata fails closed afterward.
/// This free function cannot be overridden by a [`PlatformScanner`] implementation.
pub fn inspect_bound_child<P: PlatformScanner + ?Sized>(
    platform: &P,
    parent: &P::DirectoryHandle,
    parent_path: &Path,
    child: &DirectoryEntryRecord,
    cancel: &CancellationToken,
) -> Result<WalkEntry<P::DirectoryHandle>, PlatformError> {
    if cancel.is_cancelled() {
        return Err(PlatformError::Cancelled);
    }
    child.validate_for_parent(parent_path).map_err(|error| {
        PlatformError::InvalidDirectoryEntry {
            parent: parent_path.to_path_buf(),
            detail: error.to_string(),
        }
    })?;
    let inspected = platform.inspect_child(parent, child, cancel)?;
    inspected
        .validate_for_child(parent_path, child)
        .map_err(|error| PlatformError::InvalidDirectoryEntry {
            parent: parent_path.to_path_buf(),
            detail: error.to_string(),
        })?;
    Ok(inspected)
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
            identity.device(),
            identity.inode(),
            DisplayByteValue(logical_bytes)
        ),
        None => format!("unknown:{kind:?}:{}", DisplayByteValue(logical_bytes)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn native_name(name: &str) -> NativeName {
        #[cfg(unix)]
        {
            return NativeName::unix(name.as_bytes().to_vec());
        }
        #[cfg(windows)]
        {
            return NativeName::windows_utf16(name.encode_utf16().collect::<Vec<_>>());
        }
        #[allow(unreachable_code)]
        NativeName::unix(name.as_bytes().to_vec())
    }

    #[test]
    fn child_constructor_derives_path_from_parent_and_native_name() {
        let record =
            DirectoryEntryRecord::from_parent_and_name(Path::new("/root"), native_name("safe"))
                .unwrap();

        assert_eq!(record.path, PathBuf::from("/root/safe"));
        assert!(record.validate_for_parent(Path::new("/root")).is_ok());
    }

    #[test]
    fn child_validation_rejects_escape_and_mismatched_path() {
        assert!(matches!(
            DirectoryEntryRecord::from_parent_and_name(
                Path::new("/root"),
                native_name("../outside"),
            ),
            Err(DirectoryEntryInvariantError::UnsafeNativeName)
        ));

        let record = DirectoryEntryRecord {
            path: PathBuf::from("/outside/safe"),
            file_name: native_name("safe"),
        };
        assert!(matches!(
            record.validate_for_parent(Path::new("/root")),
            Err(DirectoryEntryInvariantError::PathMismatch { .. })
        ));
    }

    #[test]
    fn root_admission_validation_rejects_substituted_root_metadata() {
        let requested = ScanRoot::new("/root").unwrap();
        let admission = RootAdmission {
            root: requested.clone(),
            root_locator: requested.native_absolute_path().unwrap(),
            metadata: EntryMetadata {
                path: PathBuf::from("/outside"),
                file_name: native_name("outside"),
                kind: EntryKind::Directory,
                logical_bytes: known_u128(0),
                allocated_bytes: known_u128(0),
                hard_link_count: known_count(1),
                fingerprint: "outside".to_string(),
                identity: None,
                filesystem_identity: None,
                mount_identity: None,
                hard_link_key: None,
            },
            directory: (),
        };

        assert!(matches!(
            admission.validate_for_root(&requested),
            Err(DirectoryEntryInvariantError::RootPathMismatch { .. })
        ));
    }

    #[test]
    fn windows_file_id_round_trip_preserves_high_bits() {
        let file_id = 0x8000_0000_0000_0001_0123_4567_89ab_cdef_u128.to_le_bytes();
        let identity = EntryIdentity::from_windows_file_id(42, file_id);

        assert_eq!(identity.device(), 42);
        assert_eq!(
            identity.inode(),
            0x8000_0000_0000_0001_0123_4567_89ab_cdef_u128
        );
        assert_eq!(identity.windows_file_id(), file_id);

        let hard_link_key = HardLinkKey::from(identity);
        assert_eq!(hard_link_key.device(), 42);
        assert_eq!(hard_link_key.windows_file_id(), file_id);
        assert_eq!(
            hard_link_key,
            HardLinkKey::from_windows_file_id(42, file_id)
        );
    }

    #[test]
    fn windows_file_ids_with_equal_low_bits_do_not_collide() {
        let low_bits = 0x0123_4567_89ab_cdef_u128;
        let low_identity = EntryIdentity::from_windows_file_id(7, low_bits.to_le_bytes());
        let high_identity = EntryIdentity::from_windows_file_id(
            7,
            (low_bits | (0xfedc_ba98_7654_3210_u128 << 64)).to_le_bytes(),
        );

        assert_ne!(low_identity, high_identity);
        assert_ne!(
            fingerprint_for(Some(&low_identity), &EntryKind::File, &known_u128(11)),
            fingerprint_for(Some(&high_identity), &EntryKind::File, &known_u128(11))
        );

        let mut hard_links = HashSet::new();
        assert!(hard_links.insert(HardLinkKey::from(low_identity)));
        assert!(hard_links.insert(HardLinkKey::from(high_identity)));
        assert_eq!(hard_links.len(), 2);
    }
}
