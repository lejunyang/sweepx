//! Invocation-local mount admission and bounded, native-verified firmlink deduplication.
//!
//! Every native scan and reopen uses this policy. A path selects an observation; native
//! identities alone admit the macOS Data volume and establish duplicate firmlink entrances.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use sweepx_model::ReasonCode;
#[cfg(target_os = "macos")]
use sweepx_platform::ScanRoot;
use sweepx_platform::{
    BoundaryKind, BoundaryRecord, CancellationToken, EntryKind, EntryMetadata, PlatformError,
    PlatformScanner, WalkEntry,
};
use thiserror::Error;

/// Failure to establish or preserve an invocation's native volume scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum VolumeScopeError {
    #[error("volume admission cancelled")]
    Cancelled,
    #[error("invalid volume admission request")]
    InvalidRequest,
    #[error("native object identity changed")]
    IdentityMismatch,
    #[error("native volume identity is unavailable")]
    IdentityUnavailable,
    #[error("mount is outside the admitted volume scope")]
    MountChanged,
    #[error("volume admission exceeds its resource budget")]
    ResourceLimit,
    #[error("volume admission is unavailable")]
    Unavailable,
    #[error("volume admission denied")]
    AccessDenied,
}

impl VolumeScopeError {
    /// Keeps structural identity failures fatal. Traversal callers convert only a newly observed
    /// `MountChanged` to a visible exclusion before using this error conversion.
    pub(crate) fn into_platform_error(self, path: &Path) -> PlatformError {
        match self {
            Self::Cancelled => PlatformError::Cancelled,
            Self::ResourceLimit => PlatformError::ResourceLimit(self.to_string()),
            Self::AccessDenied => PlatformError::Io {
                path: path.to_path_buf(),
                detail: self.to_string(),
                io_kind: Some(std::io::ErrorKind::PermissionDenied),
            },
            Self::Unavailable | Self::IdentityUnavailable => {
                PlatformError::Unsupported(self.to_string())
            }
            Self::InvalidRequest | Self::IdentityMismatch | Self::MountChanged => {
                PlatformError::InvalidDirectoryEntry {
                    parent: path.to_path_buf(),
                    detail: self.to_string(),
                }
            }
        }
    }
}

impl From<PlatformError> for VolumeScopeError {
    fn from(error: PlatformError) -> Self {
        match error {
            PlatformError::Cancelled => Self::Cancelled,
            PlatformError::ResourceLimit(_) => Self::ResourceLimit,
            PlatformError::Unsupported(_) | PlatformError::InvalidDirectoryEntry { .. } => {
                Self::Unavailable
            }
            PlatformError::RootRejected(_) => Self::IdentityMismatch,
            PlatformError::Io { io_kind, .. } => match io_kind {
                Some(std::io::ErrorKind::PermissionDenied) => Self::AccessDenied,
                Some(std::io::ErrorKind::NotFound) => Self::IdentityMismatch,
                Some(std::io::ErrorKind::Interrupted) => Self::Cancelled,
                _ => Self::IdentityUnavailable,
            },
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct VolumeScope {
    /// Freshly admitted companion volume for a macOS system-root invocation.
    pub(crate) data: Option<EntryMetadata>,
    /// Physical Data entrances proposed as aliases of preflight-verified logical entrances.
    pub(crate) aliases: std::collections::BTreeMap<PathBuf, EntryMetadata>,
    /// Logical entrances whose identity could not be checked; Data remains the coverage path.
    pub(crate) unverified_logical: BTreeSet<PathBuf>,
}

impl VolumeScope {
    /// Captures a fresh scope for one invocation; no prior Data admission is reused.
    pub(crate) fn prepare<P: PlatformScanner>(
        platform: &P,
        root: &EntryMetadata,
        cancel: &CancellationToken,
    ) -> Result<Self, VolumeScopeError> {
        if cancel.is_cancelled() {
            return Err(VolumeScopeError::Cancelled);
        }
        if root.kind != EntryKind::Directory || !root.path.is_absolute() {
            return Err(VolumeScopeError::InvalidRequest);
        }
        #[cfg(target_os = "macos")]
        if platform.platform_name() == "macos" && root.path == Path::new("/") {
            return Self::macos(platform, root, cancel);
        }
        let _ = (platform, root, cancel);
        Ok(Self::default())
    }

    /// Accepts only the captured root's mount or its independently admitted companion Data
    /// mount. Missing identity is distinct from a confirmed foreign mount and remains a failure.
    pub(crate) fn require_admitted_mount<P: PlatformScanner>(
        &self,
        platform: &P,
        root: &EntryMetadata,
        entry: &EntryMetadata,
    ) -> Result<(), VolumeScopeError> {
        self.verify_entrance(entry)?;
        match require_same_mount(platform, root, entry) {
            Err(VolumeScopeError::MountChanged) => {
                if let Some(data) = &self.data {
                    require_same_mount(platform, data, entry)
                } else {
                    Err(VolumeScopeError::MountChanged)
                }
            }
            result => result,
        }
    }

    /// Whether a path names an entrance whose preflight identity affects volume or alias policy.
    /// Such entrances require a full live observation even on a file-length fast path.
    pub(crate) fn tracks_entrance(&self, path: &Path) -> bool {
        self.data.as_ref().is_some_and(|data| data.path == path)
            || self.aliases.contains_key(path)
            || self.aliases.values().any(|alias| alias.path == path)
    }

    /// Copies complete preflight facts for the one requested entrance. Physical firmlink aliases
    /// keep the logical entrance's native identity but bind reporting fields to this exact child.
    /// The platform helper resolves only relative to the retained parent and checks these facts
    /// both before and after opening; this snapshot alone is never traversal authority.
    pub(crate) fn entrance_expectation(
        &self,
        child: &sweepx_platform::DirectoryEntryRecord,
    ) -> Option<EntryMetadata> {
        let expected = self
            .data
            .as_ref()
            .filter(|data| data.path == child.path)
            .or_else(|| self.aliases.get(&child.path))
            .or_else(|| self.aliases.values().find(|alias| alias.path == child.path))?;
        let mut expected = expected.clone();
        expected.path = child.path.clone();
        expected.file_name = child.file_name.clone();
        Some(expected)
    }

    /// Rechecks every preflight identity used by this entrance, including its directory kind.
    /// Unrelated ordinary files retain their existing platform-qualified observation contract.
    pub(crate) fn verify_entrance(&self, entry: &EntryMetadata) -> Result<(), VolumeScopeError> {
        // Scope preparation is only a proposal until each entrance is observed again by the
        // current walk/reopen. A replaced logical entrance on the same Data mount cannot justify
        // skipping the previously observed physical alias and losing that older object's bytes.
        let expected = self
            .data
            .iter()
            .filter(|data| data.path == entry.path)
            .chain(self.aliases.get(&entry.path))
            .chain(
                self.aliases
                    .values()
                    .filter(|alias| alias.path == entry.path),
            );
        if expected
            .into_iter()
            .any(|expected| !same_object(expected, entry))
        {
            return Err(VolumeScopeError::IdentityMismatch);
        }
        Ok(())
    }

    /// Converts newly observed foreign mounts and unverified logical entrances into exclusions.
    /// Changed entrance identities remain fatal; exclusions never lend authority for descendants.
    pub(crate) fn restrict_child<P: PlatformScanner>(
        &self,
        platform: &P,
        root: &EntryMetadata,
        walked: WalkEntry<P::DirectoryHandle>,
    ) -> Result<WalkEntry<P::DirectoryHandle>, VolumeScopeError> {
        let metadata = match &walked {
            WalkEntry::Directory(opened) => &opened.metadata,
            WalkEntry::File(metadata) | WalkEntry::Link(metadata) => metadata,
            _ => return Ok(walked),
        };
        if self.unverified_logical.contains(&metadata.path) {
            return Ok(WalkEntry::Boundary(BoundaryRecord {
                path: metadata.path.clone(),
                kind: BoundaryKind::OtherFilesystem,
                reason: ReasonCode::UnknownIdentity,
                detail: "unverified firmlink entrance; its Data path is scanned instead".into(),
            }));
        }
        match self.require_admitted_mount(platform, root, metadata) {
            Ok(()) => Ok(walked),
            Err(VolumeScopeError::MountChanged) => Ok(WalkEntry::Boundary(BoundaryRecord {
                path: metadata.path.clone(),
                kind: BoundaryKind::Mount,
                reason: ReasonCode::UnsupportedFilesystem,
                detail: if self.data.is_some() {
                    "mount is outside the admitted system and Data volumes"
                } else {
                    "entry crosses the initial mount boundary"
                }
                .into(),
            })),
            Err(error) => Err(error),
        }
    }

    /// Identifies a proposed physical alias only after its current complete native identity
    /// matches the logical entrance's captured identity. Callers still enforce their query scope.
    pub(crate) fn is_counted_alias(
        &self,
        observed: &EntryMetadata,
    ) -> Result<bool, VolumeScopeError> {
        let Some(expected) = self.aliases.get(&observed.path) else {
            return Ok(false);
        };
        if !same_object(expected, observed) {
            return Err(VolumeScopeError::IdentityMismatch);
        }
        Ok(true)
    }

    /// Suppresses an alias only when this request also covers its verified logical entrance.
    /// A targeted Data-subtree query must measure that subtree's physical contents even when
    /// a whole-system scan would have represented them through another logical entrance.
    pub(crate) fn is_counted_alias_in_subtree(
        &self,
        observed: &EntryMetadata,
        target: &Path,
    ) -> Result<bool, VolumeScopeError> {
        if !self.is_counted_alias(observed)? {
            return Ok(false);
        }
        Ok(self
            .aliases
            .get(&observed.path)
            .is_some_and(|logical| logical.path.starts_with(target)))
    }

    #[cfg(target_os = "macos")]
    fn macos<P: PlatformScanner>(
        platform: &P,
        root: &EntryMetadata,
        cancel: &CancellationToken,
    ) -> Result<Self, VolumeScopeError> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        // Read the sealed system's mapping with no linked final component and bounded storage.
        // Paths select observations; only equal, complete native identities justify an alias.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW_ANY)
            .open("/usr/share/firmlinks")
            .map_err(|_| VolumeScopeError::Unavailable)?;
        let mut bytes = Vec::new();
        file.take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| VolumeScopeError::Unavailable)?;
        if bytes.len() > 65_536 {
            return Err(VolumeScopeError::ResourceLimit);
        }
        let mappings = parse_firmlinks(&bytes)?;
        let data_path = Path::new("/System/Volumes/Data");
        let data_root = ScanRoot::new(data_path).map_err(|_| VolumeScopeError::InvalidRequest)?;
        let data = match platform.admit_root(&data_root, cancel) {
            Ok(admitted) => {
                admitted
                    .validate_for_root(&data_root)
                    .map_err(|_| VolumeScopeError::IdentityMismatch)?;
                admitted.metadata
            }
            // Keep Data and its firmlinks visible as exclusions if the native admission is denied.
            Err(error) if is_skippable_admission(&error) => return Ok(Self::default()),
            Err(error) => return Err(error.into()),
        };
        match require_same_mount(platform, root, &data) {
            Err(VolumeScopeError::MountChanged) => {}
            Ok(()) => return Err(VolumeScopeError::IdentityMismatch),
            Err(error) => return Err(error),
        }
        let mut aliases = std::collections::BTreeMap::new();
        let mut unverified_logical = BTreeSet::new();
        for (logical, relative) in mappings {
            if cancel.is_cancelled() {
                return Err(VolumeScopeError::Cancelled);
            }
            let physical = data_path.join(relative);
            let admit = |path: &Path| -> Result<Option<EntryMetadata>, VolumeScopeError> {
                let scan_root =
                    ScanRoot::new(path).map_err(|_| VolumeScopeError::InvalidRequest)?;
                match platform.admit_root(&scan_root, cancel) {
                    Ok(admitted) => {
                        admitted
                            .validate_for_root(&scan_root)
                            .map_err(|_| VolumeScopeError::IdentityMismatch)?;
                        Ok(Some(admitted.metadata))
                    }
                    Err(PlatformError::RootRejected(_)) => Ok(None),
                    Err(error) if is_skippable_admission(&error) => Ok(None),
                    Err(error) => Err(error.into()),
                }
            };
            match (admit(&logical)?, admit(&physical)?) {
                (Some(logical_metadata), physical_metadata) => {
                    if let Some(physical_metadata) = physical_metadata
                        && !same_object(&logical_metadata, &physical_metadata)
                    {
                        return Err(VolumeScopeError::IdentityMismatch);
                    }
                    require_same_mount(platform, &data, &logical_metadata)?;
                    // A later physical admission must match this logical native identity before
                    // exclusion. If logical admission fails, only the Data entrance contributes.
                    aliases.insert(physical, logical_metadata);
                }
                (None, _) => {
                    unverified_logical.insert(logical);
                }
            }
        }
        Ok(Self {
            data: Some(data),
            aliases,
            unverified_logical,
        })
    }
}

fn require_same_mount<P: PlatformScanner>(
    platform: &P,
    root: &EntryMetadata,
    entry: &EntryMetadata,
) -> Result<(), VolumeScopeError> {
    if root.mount_identity.is_none() || entry.mount_identity.is_none() {
        return Err(VolumeScopeError::IdentityUnavailable);
    }
    match platform.is_same_mount(root, entry) {
        Ok(true) => Ok(()),
        Ok(false) => Err(VolumeScopeError::MountChanged),
        Err(_) => Err(VolumeScopeError::IdentityUnavailable),
    }
}

#[cfg(target_os = "macos")]
fn is_skippable_admission(error: &PlatformError) -> bool {
    matches!(
        error,
        PlatformError::Io {
            io_kind: Some(std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound),
            ..
        }
    )
}

/// Alias suppression requires complete, equal directory/object/filesystem/mount facts.
/// A path match or incomplete identity never establishes that two entrances are one object.
pub(crate) fn same_object(a: &EntryMetadata, b: &EntryMetadata) -> bool {
    a.kind == EntryKind::Directory
        && b.kind == EntryKind::Directory
        && a.identity.is_some()
        && a.identity == b.identity
        && a.filesystem_identity.is_some()
        && a.filesystem_identity == b.filesystem_identity
        && a.mount_identity.is_some()
        && a.mount_identity == b.mount_identity
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn parse_firmlinks(bytes: &[u8]) -> Result<Vec<(PathBuf, PathBuf)>, VolumeScopeError> {
    let text = std::str::from_utf8(bytes).map_err(|_| VolumeScopeError::InvalidRequest)?;
    let mut result = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if result.len() >= 256 {
            return Err(VolumeScopeError::ResourceLimit);
        }
        let (logical, relative) = line
            .split_once('\t')
            .ok_or(VolumeScopeError::InvalidRequest)?;
        let logical = PathBuf::from(logical);
        let relative = PathBuf::from(relative);
        if !logical.is_absolute()
            || logical == Path::new("/")
            || relative.is_absolute()
            || relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            || logical
                .components()
                .skip(1)
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            || logical.starts_with("/System/Volumes/Data")
            || result.iter().any(|(a, b): &(PathBuf, PathBuf)| {
                a.starts_with(&logical)
                    || logical.starts_with(a)
                    || b.starts_with(&relative)
                    || relative.starts_with(b)
            })
        {
            return Err(VolumeScopeError::InvalidRequest);
        }
        result.push((logical, relative));
    }
    if result.is_empty() {
        return Err(VolumeScopeError::InvalidRequest);
    }
    Ok(result)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn mapping_rejects_escape_duplicate_and_unbounded_input() {
        assert_eq!(
            parse_firmlinks(b"/Users\tUsers\n").unwrap(),
            vec![(PathBuf::from("/Users"), PathBuf::from("Users"))]
        );
        for bytes in [
            b"/Users\t../Users\n".as_slice(),
            b"/Users\t/Users\n",
            b"/Users\tUsers\n/Users\telsewhere\n",
            b"/System/Volumes/Data/Users\tUsers\n",
            b"",
        ] {
            assert_eq!(
                parse_firmlinks(bytes),
                Err(VolumeScopeError::InvalidRequest)
            );
        }
        let oversized = (0..257)
            .map(|i| format!("/dir{i}\tdir{i}\n"))
            .collect::<String>();
        assert_eq!(
            parse_firmlinks(oversized.as_bytes()),
            Err(VolumeScopeError::ResourceLimit)
        );
    }
}

#[cfg(all(test, target_os = "macos"))]
#[test]
fn native_mapping_flags_match_ordinary_read() {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    // Darwin rejects combining O_NOFOLLOW with O_NOFOLLOW_ANY. Verify the actual flag using
    // an independent ordinary read of the shipped mapping, not a numeric constant assertion.
    let ordinary = std::fs::read("/usr/share/firmlinks").unwrap();
    let mut native = Vec::new();
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW_ANY)
        .open("/usr/share/firmlinks")
        .unwrap()
        .read_to_end(&mut native)
        .unwrap();
    assert_eq!(native, ordinary);
    assert!(!parse_firmlinks(&native).unwrap().is_empty());
}

#[cfg(all(test, target_os = "macos", feature = "platform-macos"))]
#[test]
fn native_system_and_data_admission_verifies_real_firmlink_identity() {
    let platform = crate::HostPlatformScanner::new();
    let cancel = CancellationToken::new();
    let root = platform
        .admit_root(&ScanRoot::new("/").unwrap(), &cancel)
        .unwrap()
        .metadata;
    let scope = VolumeScope::prepare(&platform, &root, &cancel).unwrap();
    let data = scope.data.as_ref().unwrap();
    assert!(!platform.is_same_mount(&root, data).unwrap());
    scope
        .require_admitted_mount(&platform, &root, data)
        .unwrap();
    let logical = platform
        .admit_root(&ScanRoot::new("/Users").unwrap(), &cancel)
        .unwrap()
        .metadata;
    let physical = platform
        .admit_root(
            &ScanRoot::new("/System/Volumes/Data/Users").unwrap(),
            &cancel,
        )
        .unwrap()
        .metadata;
    // Ordinary metadata independently confirms these native paths identify the same directory.
    use std::os::unix::fs::MetadataExt;
    let a = std::fs::metadata("/Users").unwrap();
    let b = std::fs::metadata("/System/Volumes/Data/Users").unwrap();
    assert_eq!((a.dev(), a.ino()), (b.dev(), b.ino()));
    assert!(scope.is_counted_alias(&physical).unwrap());
    assert!(!scope.is_counted_alias(&logical).unwrap());
    assert_eq!(
        VolumeScope::default().require_admitted_mount(&platform, &root, &logical),
        Err(VolumeScopeError::MountChanged)
    );
}
