use std::path::Path;

use sweepx_model::NativeName;
use sweepx_platform::{
    CancellationToken, DirectoryEntryRecord, EntryMetadata, PlatformError, PlatformScanner,
    RootAdmission, ScanRoot, WalkEntry,
};

#[derive(Debug, Default, Clone)]
pub struct MacosPlatformScanner;

impl MacosPlatformScanner {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
mod backend {
    use std::ffi::CString;
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    use sweepx_model::ReasonCode;
    use sweepx_platform::{
        EntryIdentity, EntryKind, ErrorRecord, FilesystemIdentity, HardLinkKey, fingerprint_for,
        known_count, known_u128, unknown_u128,
    };

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObjectIdentity {
        device: u64,
        inode: u64,
        kind: EntryKind,
    }

    #[derive(Debug)]
    struct ObservedMetadata {
        stat: libc::stat,
    }

    impl ObservedMetadata {
        fn identity(&self) -> ObjectIdentity {
            ObjectIdentity {
                device: self.stat.st_dev as u64,
                inode: self.stat.st_ino,
                kind: kind_from_mode(self.stat.st_mode),
            }
        }
    }

    #[derive(Debug)]
    struct OpenDirectory {
        stream: *mut libc::DIR,
    }

    impl Drop for OpenDirectory {
        fn drop(&mut self) {
            // SAFETY: `stream` is a non-null `DIR*` returned by fdopendir and owned here.
            unsafe {
                libc::closedir(self.stream);
            }
        }
    }

    fn kind_from_mode(mode: libc::mode_t) -> EntryKind {
        match mode & libc::S_IFMT {
            libc::S_IFDIR => EntryKind::Directory,
            libc::S_IFREG => EntryKind::File,
            libc::S_IFLNK => EntryKind::Symlink,
            _ => EntryKind::Other,
        }
    }

    impl MacosPlatformScanner {
        fn ensure_not_cancelled(cancel: &CancellationToken) -> Result<(), PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            Ok(())
        }

        pub(super) fn native_name(path: &Path) -> NativeName {
            NativeName::unix(
                path.file_name()
                    .unwrap_or(path.as_os_str())
                    .as_bytes()
                    .to_vec(),
            )
        }

        fn path_c_string(path: &Path) -> Result<CString, io::Error> {
            CString::new(path.as_os_str().as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "path contains an interior NUL")
            })
        }

        fn fstat(fd: &OwnedFd) -> Result<ObservedMetadata, io::Error> {
            Self::fstat_raw(fd.as_raw_fd())
        }

        fn fstat_raw(fd: libc::c_int) -> Result<ObservedMetadata, io::Error> {
            let mut stat = MaybeUninit::<libc::stat>::uninit();
            // SAFETY: `stat` points to valid writable storage and fd is live for the call.
            if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful fstat initialized the structure.
            Ok(ObservedMetadata {
                stat: unsafe { stat.assume_init() },
            })
        }

        fn open_directory(path: &Path) -> Result<OpenDirectory, io::Error> {
            let path = Self::path_c_string(path)?;
            // O_NOFOLLOW_ANY rejects a symlink in any path component, while O_DIRECTORY rejects
            // non-directories. This pins the object before enumeration and prevents a swapped
            // root or intermediate component from redirecting traversal.
            let raw_fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW_ANY,
                )
            };
            if raw_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: open returned a fresh owned descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let observed = Self::fstat(&fd)?;
            let identity = observed.identity();
            if identity.kind != EntryKind::Directory {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "opened object is not a directory",
                ));
            }
            let raw_fd = fd.as_raw_fd();
            // SAFETY: fd is a valid directory descriptor. On success fdopendir takes ownership.
            let stream = unsafe { libc::fdopendir(raw_fd) };
            if stream.is_null() {
                return Err(io::Error::last_os_error());
            }
            std::mem::forget(fd);
            Ok(OpenDirectory { stream })
        }

        fn metadata_to_entry(
            path: &Path,
            file_name: NativeName,
            observed: ObservedMetadata,
        ) -> EntryMetadata {
            let kind = kind_from_mode(observed.stat.st_mode);

            let logical_bytes = if matches!(kind, EntryKind::File | EntryKind::Symlink) {
                known_u128(observed.stat.st_size.max(0) as u128)
            } else {
                known_u128(0)
            };
            let allocated_bytes = if matches!(kind, EntryKind::File | EntryKind::Symlink) {
                // APFS clones/snapshots/compression and File Provider objects make exclusive
                // allocation and reclaimability unproved. Keep the value unknown rather than
                // promoting st_blocks attribution into an exact reclaim claim downstream.
                unknown_u128(ReasonCode::UnknownIdentity)
            } else {
                known_u128(0)
            };

            let device = observed.stat.st_dev as u64;
            let inode = observed.stat.st_ino;
            let identity = Some(EntryIdentity { device, inode });
            let filesystem_identity = Some(FilesystemIdentity { device });
            // st_dev is an object-domain identifier, not a stable traversal-mount identifier:
            // same-device mount aliases must not be treated as the admitted mount.
            let mount_identity = None;
            let hard_link_key = (kind == EntryKind::File).then_some(HardLinkKey { device, inode });
            let hard_link_count = known_count(observed.stat.st_nlink as u128);
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
    }

    impl PlatformScanner for MacosPlatformScanner {
        fn platform_name(&self) -> &'static str {
            "macos"
        }

        fn admit_root(
            &self,
            root: &ScanRoot,
            cancel: &CancellationToken,
        ) -> Result<RootAdmission, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;

            // ScanRoot enforces this at construction time. Keep the backend invariant explicit
            // for callers that may deserialize or otherwise construct the public struct.
            if !root.path().is_absolute() {
                return Err(PlatformError::RootRejected(format!(
                    "root is not absolute: {}",
                    root.path().display()
                )));
            }

            let directory = Self::open_directory(root.path()).map_err(|error| {
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ELOOP) | Some(libc::ENOTDIR)
                ) {
                    PlatformError::RootRejected(format!(
                        "root or an intermediate component is not a real directory: {}",
                        root.path().display()
                    ))
                } else {
                    PlatformError::io(root.path(), error)
                }
            })?;
            Self::ensure_not_cancelled(cancel)?;
            let observed = Self::fstat_raw(unsafe { libc::dirfd(directory.stream) })
                .map_err(|error| PlatformError::io(root.path(), error))?;
            let entry =
                Self::metadata_to_entry(root.path(), Self::native_name(root.path()), observed);
            Ok(RootAdmission {
                root: root.clone(),
                metadata: entry,
            })
        }

        fn read_dir_entries(
            &self,
            path: &Path,
            cancel: &CancellationToken,
            max_entries: usize,
        ) -> Result<Vec<DirectoryEntryRecord>, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;

            let _ = (path, cancel, max_entries);
            Err(PlatformError::Unsupported(
                "safe macOS directory enumeration requires per-scan retained descriptors"
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
            Ok(WalkEntry::Error(ErrorRecord {
                path: path.to_path_buf(),
                kind: sweepx_platform::ErrorKind::Unsupported,
                reason: ReasonCode::UnknownIdentity,
                detail: "safe macOS metadata lookup requires a scan-scoped parent handle"
                    .to_string(),
            }))
        }

        fn is_same_mount(
            &self,
            root: &EntryMetadata,
            entry: &EntryMetadata,
        ) -> Result<bool, PlatformError> {
            match (&root.mount_identity, &entry.mount_identity) {
                (Some(left), Some(right)) => Ok(left == right),
                _ => Err(PlatformError::Unsupported(
                    "mount identity unavailable".to_string(),
                )),
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl PlatformScanner for MacosPlatformScanner {
    fn platform_name(&self) -> &'static str {
        "macos"
    }

    fn admit_root(
        &self,
        _root: &ScanRoot,
        _cancel: &CancellationToken,
    ) -> Result<RootAdmission, PlatformError> {
        Err(PlatformError::Unsupported(
            "macOS scanner backend is unavailable on this host".to_string(),
        ))
    }

    fn read_dir_entries(
        &self,
        _path: &Path,
        _cancel: &CancellationToken,
        _max_entries: usize,
    ) -> Result<Vec<DirectoryEntryRecord>, PlatformError> {
        Err(PlatformError::Unsupported(
            "macOS scanner backend is unavailable on this host".to_string(),
        ))
    }

    fn stat_entry(
        &self,
        _path: &Path,
        _file_name: NativeName,
        _cancel: &CancellationToken,
    ) -> Result<WalkEntry, PlatformError> {
        Err(PlatformError::Unsupported(
            "macOS scanner backend is unavailable on this host".to_string(),
        ))
    }

    fn is_same_mount(
        &self,
        _root: &EntryMetadata,
        _entry: &EntryMetadata,
    ) -> Result<bool, PlatformError> {
        Err(PlatformError::Unsupported(
            "macOS scanner backend is unavailable on this host".to_string(),
        ))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    use sweepx_model::{EvidenceValue, ReasonCode};
    use sweepx_platform::{BoundaryKind, BoundaryRecord};

    use super::*;

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sweepx-macos-{test_name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn name(bytes: &[u8]) -> NativeName {
        NativeName::unix(bytes.to_vec())
    }

    #[test]
    fn admits_real_directory_without_claiming_mount_identity() {
        let temp = TempDir::new("admit");
        let scanner = MacosPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();

        assert!(matches!(
            admission.metadata.kind,
            sweepx_platform::EntryKind::Directory
        ));
        assert!(admission.metadata.identity.is_some());
        assert!(admission.metadata.filesystem_identity.is_some());
        assert!(admission.metadata.mount_identity.is_none());
        assert!(matches!(
            scanner.is_same_mount(&admission.metadata, &admission.metadata),
            Err(PlatformError::Unsupported(_))
        ));
    }

    #[test]
    fn rejects_relative_root_even_if_struct_is_constructed_directly() {
        let scanner = MacosPlatformScanner::new();
        let root = ScanRoot {
            path: "relative".into(),
        };
        let error = scanner
            .admit_root(&root, &CancellationToken::new())
            .unwrap_err();
        assert!(matches!(error, PlatformError::RootRejected(_)));
    }

    #[test]
    fn rejects_root_symlink_and_regular_file() {
        let temp = TempDir::new("root-kinds");
        let directory = temp.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let link = temp.path().join("link");
        symlink(&directory, &link).unwrap();
        let file = temp.path().join("file");
        fs::write(&file, b"payload").unwrap();
        let scanner = MacosPlatformScanner::new();

        for path in [link, file] {
            let error = scanner
                .admit_root(&ScanRoot::new(path).unwrap(), &CancellationToken::new())
                .unwrap_err();
            assert!(matches!(error, PlatformError::RootRejected(_)));
        }
    }

    #[test]
    fn directory_enumeration_stays_disabled_without_scan_scoped_handles() {
        let temp = TempDir::new("read-dir");
        for raw in [b"z".as_slice(), b"a".as_slice(), b"m".as_slice()] {
            fs::write(temp.path().join(OsStr::from_bytes(raw)), b"x").unwrap();
        }
        let scanner = MacosPlatformScanner::new();
        let error = scanner
            .read_dir_entries(temp.path(), &CancellationToken::new(), 3)
            .unwrap_err();
        assert!(matches!(error, PlatformError::Unsupported(_)));
    }

    #[test]
    fn native_name_preserves_arbitrary_unix_bytes() {
        let raw = [b'p', 0xff, b'q'];
        let path = Path::new("/tmp").join(OsStr::from_bytes(&raw));
        assert_eq!(MacosPlatformScanner::native_name(&path), name(&raw));
    }

    #[test]
    fn stat_is_no_follow_and_reports_file_identity_sizes_and_links() {
        let temp = TempDir::new("stat");
        let file = temp.path().join("file");
        fs::write(&file, b"hello world").unwrap();
        let second = temp.path().join("second");
        fs::hard_link(&file, &second).unwrap();
        let link = temp.path().join("link");
        symlink(&file, &link).unwrap();
        let scanner = MacosPlatformScanner::new();
        scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();

        let WalkEntry::File(first) = scanner
            .stat_entry(&file, name(b"file"), &CancellationToken::new())
            .unwrap()
        else {
            panic!("expected file entry");
        };
        let WalkEntry::File(second) = scanner
            .stat_entry(&second, name(b"second"), &CancellationToken::new())
            .unwrap()
        else {
            panic!("expected file entry");
        };
        let WalkEntry::Link(link) = scanner
            .stat_entry(&link, name(b"link"), &CancellationToken::new())
            .unwrap()
        else {
            panic!("expected no-follow link entry");
        };

        assert_eq!(first.hard_link_key, second.hard_link_key);
        assert!(matches!(
            first.hard_link_count,
            EvidenceValue::Known { ref value } if value.0 >= 2
        ));
        assert!(matches!(
            first.logical_bytes,
            EvidenceValue::Known { ref value } if value.0 == 11
        ));
        assert!(matches!(
            first.allocated_bytes,
            EvidenceValue::Unknown {
                reason: ReasonCode::UnknownIdentity
            }
        ));
        assert_eq!(link.kind, sweepx_platform::EntryKind::Symlink);
        assert_ne!(link.identity, first.identity);
        assert!(matches!(link.logical_bytes, EvidenceValue::Known { .. }));
        assert!(matches!(
            link.allocated_bytes,
            EvidenceValue::Unknown {
                reason: ReasonCode::UnknownIdentity
            }
        ));
        assert!(link.hard_link_key.is_none());
    }

    #[test]
    fn stat_missing_entry_is_walk_error() {
        let temp = TempDir::new("missing");
        let missing = temp.path().join("missing");
        let scanner = MacosPlatformScanner::new();
        scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let entry = scanner
            .stat_entry(&missing, name(b"missing"), &CancellationToken::new())
            .unwrap();
        assert!(matches!(entry, WalkEntry::Error(_)));
    }

    #[test]
    fn stat_reports_directory_and_special_entry_types() {
        let temp = TempDir::new("entry-types");
        let directory = temp.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let socket = temp.path().join("socket");
        let _listener = UnixListener::bind(&socket).unwrap();
        let scanner = MacosPlatformScanner::new();
        scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();

        assert!(matches!(
            scanner
                .stat_entry(&directory, name(b"directory"), &CancellationToken::new())
                .unwrap(),
            WalkEntry::Directory(_)
        ));
        assert!(matches!(
            scanner
                .stat_entry(&socket, name(b"socket"), &CancellationToken::new())
                .unwrap(),
            WalkEntry::Boundary(BoundaryRecord {
                kind: BoundaryKind::OtherFilesystem,
                ..
            })
        ));
    }

    #[test]
    fn cancellation_prevents_each_operation() {
        let temp = TempDir::new("cancel");
        let file = temp.path().join("file");
        fs::write(&file, b"x").unwrap();
        let scanner = MacosPlatformScanner::new();
        let cancel = CancellationToken::new();
        cancel.cancel();

        assert!(matches!(
            scanner.admit_root(&ScanRoot::new(temp.path()).unwrap(), &cancel),
            Err(PlatformError::Cancelled)
        ));
        assert!(matches!(
            scanner.read_dir_entries(temp.path(), &cancel, 16),
            Err(PlatformError::Cancelled)
        ));
        assert!(matches!(
            scanner.stat_entry(&file, name(b"file"), &cancel),
            Err(PlatformError::Cancelled)
        ));
    }
}
