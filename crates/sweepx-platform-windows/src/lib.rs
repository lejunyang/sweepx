#[derive(Debug, Default, Clone)]
pub struct WindowsPlatformScanner;

impl WindowsPlatformScanner {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(windows))]
use std::path::Path;
#[cfg(not(windows))]
use sweepx_model::NativeName;
#[cfg(not(windows))]
use sweepx_platform::{
    CancellationToken, DirectoryEntryRecord, EntryMetadata, PlatformError, PlatformScanner,
    RootAdmission, ScanRoot, WalkEntry,
};

#[cfg(not(windows))]
impl PlatformScanner for WindowsPlatformScanner {
    fn platform_name(&self) -> &'static str {
        "windows"
    }

    fn admit_root(
        &self,
        _root: &ScanRoot,
        _cancel: &CancellationToken,
    ) -> Result<RootAdmission, PlatformError> {
        Err(PlatformError::Unsupported(
            "windows scanner backend is unavailable on this host".to_string(),
        ))
    }

    fn read_dir_entries(
        &self,
        _path: &Path,
        _cancel: &CancellationToken,
        _max_entries: usize,
    ) -> Result<Vec<DirectoryEntryRecord>, PlatformError> {
        Err(PlatformError::Unsupported(
            "windows scanner backend is unavailable on this host".to_string(),
        ))
    }

    fn stat_entry(
        &self,
        _path: &Path,
        _file_name: NativeName,
        _cancel: &CancellationToken,
    ) -> Result<WalkEntry, PlatformError> {
        Err(PlatformError::Unsupported(
            "windows scanner backend is unavailable on this host".to_string(),
        ))
    }

    fn is_same_mount(
        &self,
        _root: &EntryMetadata,
        _entry: &EntryMetadata,
    ) -> Result<bool, PlatformError> {
        Err(PlatformError::Unsupported(
            "windows scanner backend is unavailable on this host".to_string(),
        ))
    }
}

#[cfg(windows)]
mod imp {
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use sweepx_model::{NativeName, ReasonCode};
    use sweepx_platform::{
        BoundaryKind, BoundaryRecord, CancellationToken, DirectoryEntryRecord, EntryKind,
        EntryMetadata, ErrorRecord, PlatformError, PlatformScanner, RootAdmission, ScanRoot,
        WalkEntry, error_kind_for_io, fingerprint_for, known_u128, lower_bound_u128, reason_for_io,
        unknown_u128,
    };
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE,
        FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_NO_RECALL,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandle,
        GetFileInformationByHandleEx, OPEN_EXISTING,
    };

    use super::WindowsPlatformScanner;

    #[derive(Debug)]
    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: this type is constructed only from a valid CreateFileW handle and owns it.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObservedMetadata {
        attributes: u32,
        logical_bytes: u64,
        allocation_bytes: Option<u64>,
        volume_serial: u32,
        file_index: u64,
    }

    impl WindowsPlatformScanner {
        fn ensure_not_cancelled(cancel: &CancellationToken) -> Result<(), PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            Ok(())
        }

        fn wide_nul(path: &Path) -> Result<Vec<u16>, io::Error> {
            let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
            if wide.contains(&0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path contains an interior NUL",
                ));
            }
            wide.push(0);
            Ok(wide)
        }

        fn native_name(path: &Path) -> NativeName {
            let name = path.file_name().unwrap_or(path.as_os_str());
            NativeName::windows_utf16(name.encode_wide().collect::<Vec<_>>())
        }

        fn open_metadata_handle(path: &Path) -> Result<OwnedHandle, io::Error> {
            let wide = Self::wide_nul(path)?;
            // SAFETY: `wide` is NUL-terminated and all output ownership is represented by
            // `OwnedHandle`. Zero desired access plus FILE_READ_ATTRIBUTES is metadata-only;
            // OPEN_REPARSE_POINT prevents following the final path component.
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS
                        | FILE_FLAG_OPEN_REPARSE_POINT
                        | FILE_FLAG_OPEN_NO_RECALL,
                    null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(OwnedHandle(handle))
            }
        }

        fn query_metadata(path: &Path) -> Result<ObservedMetadata, io::Error> {
            let handle = Self::open_metadata_handle(path)?;
            // SAFETY: `info` is a valid writable instance for the duration of the call.
            let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
            // SAFETY: `handle` is valid and `info` points to correctly-sized storage.
            if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
                return Err(io::Error::last_os_error());
            }

            let logical_bytes =
                (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
            let file_index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);

            Ok(ObservedMetadata {
                attributes: info.dwFileAttributes,
                logical_bytes,
                allocation_bytes: Self::query_allocation(&handle, info.dwFileAttributes),
                volume_serial: info.dwVolumeSerialNumber,
                file_index,
            })
        }

        fn query_allocation(handle: &OwnedHandle, attributes: u32) -> Option<u64> {
            let unsafe_to_query = attributes
                & (FILE_ATTRIBUTE_DIRECTORY
                    | FILE_ATTRIBUTE_REPARSE_POINT
                    | FILE_ATTRIBUTE_OFFLINE
                    | FILE_ATTRIBUTE_RECALL_ON_OPEN
                    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
                != 0;
            if unsafe_to_query {
                return None;
            }

            let mut standard = FILE_STANDARD_INFO::default();
            // SAFETY: `handle` is the same no-follow handle used for the attribute and identity
            // observation, and `standard` is correctly sized writable output storage.
            if unsafe {
                GetFileInformationByHandleEx(
                    handle.0,
                    FileStandardInfo,
                    (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                    size_of::<FILE_STANDARD_INFO>() as u32,
                )
            } == 0
            {
                return None;
            }
            u64::try_from(standard.AllocationSize).ok()
        }

        fn metadata_to_entry(
            path: &Path,
            file_name: NativeName,
            observed: ObservedMetadata,
        ) -> EntryMetadata {
            let is_reparse = observed.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
            let is_directory = observed.attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
            let kind = if is_reparse {
                EntryKind::ReparsePoint
            } else if is_directory {
                EntryKind::Directory
            } else {
                EntryKind::File
            };

            let logical_bytes = if kind == EntryKind::File {
                known_u128(u128::from(observed.logical_bytes))
            } else {
                known_u128(0)
            };
            let allocated_bytes = if kind == EntryKind::File {
                if observed.attributes
                    & (FILE_ATTRIBUTE_OFFLINE
                        | FILE_ATTRIBUTE_RECALL_ON_OPEN
                        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
                    != 0
                {
                    unknown_u128(ReasonCode::StrictReadOnly)
                } else {
                    observed
                        .allocation_bytes
                        .map(|value| {
                            // FILE_STANDARD_INFO is queried on the already-open no-follow handle.
                            // Alternate-stream coverage is not proven, so keep this a lower bound.
                            lower_bound_u128(
                                u128::from(value),
                                ReasonCode::IncompleteStreamCoverage,
                            )
                        })
                        .unwrap_or_else(|| unknown_u128(ReasonCode::IncompleteStreamCoverage))
                }
            } else if kind == EntryKind::ReparsePoint {
                unknown_u128(ReasonCode::StrictReadOnly)
            } else {
                known_u128(0)
            };

            // BY_HANDLE_FILE_INFORMATION exposes only a weak 64-bit file index and a volume
            // serial whose stability varies by filesystem. The shared model cannot hold the
            // 128-bit FILE_ID_INFO identity plus its capability level, so do not publish these
            // values as authoritative identity, mount, or hard-link evidence. They remain usable
            // only as an intra-call guard around directory enumeration below.
            let identity = None;
            let filesystem_identity = None;
            let mount_identity = None;
            let hard_link_key = None;
            let hard_link_count = sweepx_model::EvidenceValue::Unknown {
                reason: ReasonCode::UnknownIdentity,
            };
            let fingerprint = fingerprint_for(identity.as_ref(), &kind, &logical_bytes);

            EntryMetadata {
                path: path.to_path_buf(),
                file_name,
                kind,
                logical_bytes,
                allocated_bytes,
                hard_link_count,
                fingerprint,
                identity,
                filesystem_identity,
                mount_identity,
                hard_link_key,
            }
        }

        fn entry_error(path: &Path, error: io::Error) -> WalkEntry {
            WalkEntry::Error(ErrorRecord {
                path: path.to_path_buf(),
                kind: error_kind_for_io(&error),
                reason: reason_for_io(&error),
                detail: error.to_string(),
            })
        }
    }

    impl PlatformScanner for WindowsPlatformScanner {
        fn platform_name(&self) -> &'static str {
            "windows"
        }

        fn admit_root(
            &self,
            root: &ScanRoot,
            cancel: &CancellationToken,
        ) -> Result<RootAdmission, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            if !root.path().is_absolute() {
                return Err(PlatformError::RootRejected(format!(
                    "root is not absolute: {}",
                    root.path().display()
                )));
            }
            return Err(PlatformError::Unsupported(
                "safe Windows root admission requires component-wise handle-relative resolution"
                    .to_string(),
            ));

            #[allow(unreachable_code)]
            let observed = Self::query_metadata(root.path())
                .map_err(|error| PlatformError::io(root.path(), error))?;
            Self::ensure_not_cancelled(cancel)?;
            if observed.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(PlatformError::RootRejected(format!(
                    "root is a reparse point and cannot be scanned: {}",
                    root.path().display()
                )));
            }
            if observed.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(PlatformError::RootRejected(format!(
                    "root is not a directory: {}",
                    root.path().display()
                )));
            }

            Ok(RootAdmission {
                root: root.clone(),
                metadata: Self::metadata_to_entry(
                    root.path(),
                    Self::native_name(root.path()),
                    observed,
                ),
            })
        }

        fn read_dir_entries(
            &self,
            path: &Path,
            cancel: &CancellationToken,
            max_entries: usize,
        ) -> Result<Vec<DirectoryEntryRecord>, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            let _ = (path, max_entries);
            Err(PlatformError::Unsupported(
                "safe Windows directory enumeration requires a handle-relative contract"
                    .to_string(),
            ))
        }

        fn stat_entry(
            &self,
            path: &Path,
            file_name: NativeName,
            cancel: &CancellationToken,
        ) -> Result<WalkEntry, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            let _ = file_name;
            return Ok(Self::entry_error(
                path,
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "safe Windows metadata lookup requires component-wise handle-relative resolution",
                ),
            ));

            #[allow(unreachable_code)]
            let observed = match Self::query_metadata(path) {
                Ok(value) => value,
                Err(error) => return Ok(Self::entry_error(path, error)),
            };
            Self::ensure_not_cancelled(cancel)?;
            let entry = Self::metadata_to_entry(path, file_name, observed);

            match entry.kind {
                EntryKind::Directory => Ok(WalkEntry::Directory(entry)),
                EntryKind::File => Ok(WalkEntry::File(entry)),
                EntryKind::ReparsePoint => Ok(WalkEntry::Boundary(BoundaryRecord {
                    path: path.to_path_buf(),
                    kind: BoundaryKind::ReparsePoint,
                    reason: ReasonCode::StrictReadOnly,
                    detail: "reparse point is not followed by the Windows scanner".to_string(),
                })),
                EntryKind::Symlink => Ok(WalkEntry::Link(entry)),
                EntryKind::Other => Ok(WalkEntry::Boundary(BoundaryRecord {
                    path: path.to_path_buf(),
                    kind: BoundaryKind::OtherFilesystem,
                    reason: ReasonCode::UnsupportedFilesystem,
                    detail: "unsupported Windows filesystem object".to_string(),
                })),
            }
        }

        fn is_same_mount(
            &self,
            root: &EntryMetadata,
            entry: &EntryMetadata,
        ) -> Result<bool, PlatformError> {
            match (&root.mount_identity, &entry.mount_identity) {
                (Some(left), Some(right)) => Ok(left == right),
                _ => Err(PlatformError::Unsupported(
                    "volume identity unavailable".to_string(),
                )),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::fs;
        use std::path::PathBuf;

        use super::*;

        fn temp_dir(label: &str) -> PathBuf {
            let path = std::env::temp_dir().join(format!(
                "sweepx-windows-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            path
        }

        #[test]
        fn admit_root_honors_cancellation() {
            let scanner = WindowsPlatformScanner::new();
            let cancel = CancellationToken::new();
            cancel.cancel();
            let root = ScanRoot::new(std::env::temp_dir()).unwrap();
            assert!(matches!(
                scanner.admit_root(&root, &cancel),
                Err(PlatformError::Cancelled)
            ));
        }

        #[test]
        fn root_admission_stays_disabled_without_componentwise_resolution() {
            let scanner = WindowsPlatformScanner::new();
            let root = ScanRoot::new(std::env::temp_dir()).unwrap();
            assert!(matches!(
                scanner.admit_root(&root, &CancellationToken::new()),
                Err(PlatformError::Unsupported(_))
            ));
        }

        #[test]
        fn directory_enumeration_stays_disabled_without_handle_relative_contract() {
            let root = temp_dir("enumeration");
            fs::write(root.join("z.txt"), b"z").unwrap();
            fs::write(root.join("中.txt"), b"wide").unwrap();
            fs::write(root.join("a.txt"), b"a").unwrap();

            let scanner = WindowsPlatformScanner::new();
            assert!(matches!(
                scanner.read_dir_entries(&root, &CancellationToken::new(), 3),
                Err(PlatformError::Unsupported(_))
            ));

            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn metadata_lookup_stays_non_authoritative_without_componentwise_resolution() {
            let root = temp_dir("hard-link");
            let first_path = root.join("first");
            let second_path = root.join("second");
            fs::write(&first_path, b"hello world").unwrap();
            fs::hard_link(&first_path, &second_path).unwrap();

            let scanner = WindowsPlatformScanner::new();
            let first = scanner
                .stat_entry(
                    &first_path,
                    NativeName::windows_utf16("first".encode_utf16().collect::<Vec<_>>()),
                    &CancellationToken::new(),
                )
                .unwrap();
            assert!(matches!(first, WalkEntry::Error(_)));

            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn root_and_child_metadata_remain_conservatively_unavailable() {
            let root = temp_dir("reparse");
            let target = root.join("target");
            let link = root.join("link");
            fs::create_dir(&target).unwrap();
            std::os::windows::fs::symlink_dir(&target, &link).unwrap();

            let scanner = WindowsPlatformScanner::new();
            let error = scanner
                .admit_root(
                    &ScanRoot::new(link.clone()).unwrap(),
                    &CancellationToken::new(),
                )
                .unwrap_err();
            assert!(matches!(error, PlatformError::Unsupported(_)));

            let entry = scanner
                .stat_entry(
                    &link,
                    NativeName::windows_utf16("link".encode_utf16().collect::<Vec<_>>()),
                    &CancellationToken::new(),
                )
                .unwrap();
            assert!(matches!(entry, WalkEntry::Error(_)));

            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn missing_entry_is_an_error_record() {
            let scanner = WindowsPlatformScanner::new();
            let missing = std::env::temp_dir().join("sweepx-definitely-missing-entry");
            let entry = scanner
                .stat_entry(
                    &missing,
                    NativeName::windows_utf16(
                        "sweepx-definitely-missing-entry"
                            .encode_utf16()
                            .collect::<Vec<_>>(),
                    ),
                    &CancellationToken::new(),
                )
                .unwrap();
            assert!(matches!(entry, WalkEntry::Error(_)));
        }
    }
}
