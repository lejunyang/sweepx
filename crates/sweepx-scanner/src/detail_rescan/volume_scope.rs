//! Invocation-local mount admission and bounded, native-verified firmlink deduplication.
use super::*;

#[derive(Clone, Default)]
pub(super) struct VolumeScope {
    pub(super) data: Option<EntryMetadata>,
    pub(super) aliases: std::collections::BTreeMap<PathBuf, EntryMetadata>,
    pub(super) unverified_logical: BTreeSet<PathBuf>,
}

impl VolumeScope {
    pub(super) fn prepare<P: PlatformScanner>(
        platform: &P,
        root: &EntryMetadata,
        enabled: bool,
        cancel: &CancellationToken,
    ) -> Result<Self, DetailRescanError> {
        #[cfg(target_os = "macos")]
        if enabled && platform.platform_name() == "macos" && root.path == Path::new("/") {
            return Self::macos(platform, root, cancel);
        }
        let _ = (platform, root, enabled, cancel);
        Ok(Self::default())
    }

    pub(super) fn require_admitted_mount<P: PlatformScanner>(
        &self,
        platform: &P,
        root: &EntryMetadata,
        entry: &EntryMetadata,
    ) -> Result<(), DetailRescanError> {
        match require_same_mount(platform, root, entry) {
            Err(DetailRescanError::MountChanged) => {
                if let Some(data) = &self.data {
                    require_same_mount(platform, data, entry)
                } else {
                    Err(DetailRescanError::MountChanged)
                }
            }
            result => result,
        }
    }

    pub(super) fn restrict_child<P: PlatformScanner>(
        &self,
        platform: &P,
        root: &EntryMetadata,
        walked: WalkEntry<P::DirectoryHandle>,
    ) -> Result<WalkEntry<P::DirectoryHandle>, DetailRescanError> {
        if self.data.is_none() {
            return restrict_detail_child_to_mount(platform, root, walked);
        }
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
            Err(DetailRescanError::MountChanged) => Ok(WalkEntry::Boundary(BoundaryRecord {
                path: metadata.path.clone(),
                kind: BoundaryKind::Mount,
                reason: ReasonCode::UnsupportedFilesystem,
                detail: "mount is outside the admitted system and Data volumes".into(),
            })),
            Err(error) => Err(error),
        }
    }

    pub(super) fn is_counted_alias(
        &self,
        observed: &EntryMetadata,
    ) -> Result<bool, DetailRescanError> {
        let Some(expected) = self.aliases.get(&observed.path) else {
            return Ok(false);
        };
        if !same_object(expected, observed) {
            return Err(DetailRescanError::IdentityMismatch);
        }
        Ok(true)
    }

    #[cfg(target_os = "macos")]
    fn macos<P: PlatformScanner>(
        platform: &P,
        root: &EntryMetadata,
        cancel: &CancellationToken,
    ) -> Result<Self, DetailRescanError> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        // Read the sealed system's mapping with no linked final component and bounded storage.
        // Paths select observations; only equal, complete native identities justify an alias.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW_ANY)
            .open("/usr/share/firmlinks")
            .map_err(|_| DetailRescanError::Unavailable)?;
        let mut bytes = Vec::new();
        file.take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| DetailRescanError::Unavailable)?;
        if bytes.len() > 65_536 {
            return Err(DetailRescanError::ResourceLimit);
        }
        let mappings = parse_firmlinks(&bytes)?;
        let data_path = Path::new("/System/Volumes/Data");
        let data_root = ScanRoot::new(data_path).map_err(|_| DetailRescanError::InvalidRequest)?;
        let data = match platform.admit_root(&data_root, cancel) {
            Ok(admitted) => {
                admitted
                    .validate_for_root(&data_root)
                    .map_err(|_| DetailRescanError::IdentityMismatch)?;
                admitted.metadata
            }
            // Keep Data and its firmlinks visible as exclusions if the native admission is denied.
            Err(error) if skippable_child_io(&error).is_some() => return Ok(Self::default()),
            Err(error) => return Err(map_platform_error(error)),
        };
        match require_same_mount(platform, root, &data) {
            Err(DetailRescanError::MountChanged) => {}
            Ok(()) => return Err(DetailRescanError::IdentityMismatch),
            Err(error) => return Err(error),
        }
        let mut aliases = std::collections::BTreeMap::new();
        let mut unverified_logical = BTreeSet::new();
        for (logical, relative) in mappings {
            if cancel.is_cancelled() {
                return Err(DetailRescanError::Cancelled);
            }
            let physical = data_path.join(relative);
            let admit = |path: &Path| {
                let scan_root =
                    ScanRoot::new(path).map_err(|_| DetailRescanError::InvalidRequest)?;
                match platform.admit_root(&scan_root, cancel) {
                    Ok(admitted) => {
                        admitted
                            .validate_for_root(&scan_root)
                            .map_err(|_| DetailRescanError::IdentityMismatch)?;
                        Ok(Some(admitted.metadata))
                    }
                    Err(PlatformError::RootRejected(_)) => Ok(None),
                    Err(error) if skippable_child_io(&error).is_some() => Ok(None),
                    Err(error) => Err(map_platform_error(error)),
                }
            };
            match (admit(&logical)?, admit(&physical)?) {
                (Some(logical_metadata), physical_metadata) => {
                    if let Some(physical_metadata) = physical_metadata
                        && !same_object(&logical_metadata, &physical_metadata)
                    {
                        return Err(DetailRescanError::IdentityMismatch);
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

fn same_object(a: &EntryMetadata, b: &EntryMetadata) -> bool {
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
fn parse_firmlinks(bytes: &[u8]) -> Result<Vec<(PathBuf, PathBuf)>, DetailRescanError> {
    let text = std::str::from_utf8(bytes).map_err(|_| DetailRescanError::InvalidRequest)?;
    let mut result = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if result.len() >= 256 {
            return Err(DetailRescanError::ResourceLimit);
        }
        let (logical, relative) = line
            .split_once('\t')
            .ok_or(DetailRescanError::InvalidRequest)?;
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
            return Err(DetailRescanError::InvalidRequest);
        }
        result.push((logical, relative));
    }
    if result.is_empty() {
        return Err(DetailRescanError::InvalidRequest);
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
                Err(DetailRescanError::InvalidRequest)
            );
        }
        let oversized = (0..257)
            .map(|i| format!("/dir{i}\tdir{i}\n"))
            .collect::<String>();
        assert_eq!(
            parse_firmlinks(oversized.as_bytes()),
            Err(DetailRescanError::ResourceLimit)
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
    let scope = VolumeScope::prepare(&platform, &root, true, &cancel).unwrap();
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
        Err(DetailRescanError::MountChanged)
    );
}
