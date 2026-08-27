#[cfg(target_os = "macos")]
use sweepx_platform::OpenedDirectory;
use sweepx_platform::{
    CancellationToken, DirectoryEntryBatch, DirectoryEntryRecord, DirectoryReadLimits,
    EntryMetadata, PlatformError, PlatformScanner, RootAdmission, ScanRoot, WalkEntry,
};

#[derive(Debug)]
pub struct MacosUnavailableDirectory;

#[derive(Debug, Default, Clone)]
pub struct MacosPlatformScanner;

impl MacosPlatformScanner {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
mod backend {
    use std::ffi::{CStr, CString};
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use sweepx_model::{NativeName, ReasonCode};
    use sweepx_platform::{
        BoundaryKind, BoundaryRecord, EntryIdentity, EntryKind, ErrorRecord, FilesystemIdentity,
        HardLinkKey, fingerprint_for, known_count, known_u128, unknown_u128,
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
    pub struct OpenDirectory {
        stream: *mut libc::DIR,
        path: PathBuf,
        identity: ObjectIdentity,
        pending: Option<DirectoryEntryRecord>,
    }

    // SAFETY: the handle is moved, never shared concurrently, and all directory operations take
    // `&mut self` or derive a transient raw fd from the owned DIR*.
    unsafe impl Send for OpenDirectory {}

    impl Drop for OpenDirectory {
        fn drop(&mut self) {
            // SAFETY: `stream` is a non-null `DIR*` returned by `fdopendir` and owned here.
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

        fn name_c_string(name: &NativeName) -> Result<CString, PlatformError> {
            match name {
                NativeName::UnixBytes(bytes) => CString::new(bytes.as_slice()).map_err(|_| {
                    PlatformError::Unsupported(
                        "directory entry contains an interior NUL".to_string(),
                    )
                }),
                NativeName::WindowsUtf16(_) => Err(PlatformError::Unsupported(
                    "macOS backend only supports unix native names".to_string(),
                )),
            }
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
            // SAFETY: successful `fstat` initialized the structure.
            Ok(ObservedMetadata {
                stat: unsafe { stat.assume_init() },
            })
        }

        fn fstatat_raw(dirfd: libc::c_int, name: &CString) -> Result<ObservedMetadata, io::Error> {
            let mut stat = MaybeUninit::<libc::stat>::uninit();
            // SAFETY: `name` is NUL-terminated, `stat` is writable, and `dirfd` is live.
            if unsafe {
                libc::fstatat(
                    dirfd,
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful `fstatat` initialized the structure.
            Ok(ObservedMetadata {
                stat: unsafe { stat.assume_init() },
            })
        }

        fn dirfd(directory: &OpenDirectory) -> Result<libc::c_int, io::Error> {
            // SAFETY: `directory.stream` is a valid owned DIR* for the lifetime of `directory`.
            let fd = unsafe { libc::dirfd(directory.stream) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(fd)
        }

        fn open_directory_from_fd(fd: OwnedFd, path: PathBuf) -> Result<OpenDirectory, io::Error> {
            let observed = Self::fstat(&fd)?;
            let identity = observed.identity();
            if identity.kind != EntryKind::Directory {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    "opened object is not a directory",
                ));
            }

            let raw_fd = fd.as_raw_fd();
            // SAFETY: `raw_fd` is a valid directory descriptor. On success `fdopendir` takes
            // ownership of the descriptor and will close it via `closedir`.
            let stream = unsafe { libc::fdopendir(raw_fd) };
            if stream.is_null() {
                return Err(io::Error::last_os_error());
            }
            std::mem::forget(fd);
            Ok(OpenDirectory {
                stream,
                path,
                identity,
                pending: None,
            })
        }

        fn open_root_directory(path: &Path) -> Result<OpenDirectory, io::Error> {
            let path_c = Self::path_c_string(path)?;
            // O_NOFOLLOW_ANY rejects symlinks in any path component. Root admission is the only
            // operation allowed to resolve from a path string; descendants are handled via dirfd.
            let raw_fd = unsafe {
                libc::open(
                    path_c.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW_ANY,
                )
            };
            if raw_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `open` returned a fresh owned descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            Self::open_directory_from_fd(fd, path.to_path_buf())
        }

        fn open_child_directory(
            parent: &OpenDirectory,
            child: &DirectoryEntryRecord,
            observed_before: &ObservedMetadata,
        ) -> Result<OpenDirectory, PlatformError> {
            let parent_fd = Self::dirfd(parent)
                .map_err(|error| PlatformError::io(parent.path.clone(), error))?;
            let child_name = Self::name_c_string(&child.file_name)?;

            // SAFETY: `parent_fd` is live, `child_name` is NUL-terminated, and flags refuse
            // following a symlink in the final component while requiring a directory.
            let raw_fd = unsafe {
                libc::openat(
                    parent_fd,
                    child_name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
            };
            if raw_fd < 0 {
                let error = io::Error::last_os_error();
                return ok_error_changed_or_io(parent, child, error);
            }

            // SAFETY: `openat` returned a fresh owned descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let observed_after =
                Self::fstat(&fd).map_err(|error| PlatformError::io(child.path.clone(), error))?;
            if observed_before.identity() != observed_after.identity() {
                return Err(PlatformError::io(
                    child.path.clone(),
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "directory identity changed between fstatat and openat",
                    ),
                ));
            }

            Self::open_directory_from_fd(fd, child.path.clone())
                .map_err(|error| PlatformError::io(child.path.clone(), error))
        }

        fn metadata_to_entry(
            path: &Path,
            file_name: NativeName,
            observed: &ObservedMetadata,
        ) -> EntryMetadata {
            let kind = kind_from_mode(observed.stat.st_mode);

            let logical_bytes = if matches!(kind, EntryKind::File | EntryKind::Symlink) {
                known_u128(observed.stat.st_size.max(0) as u128)
            } else {
                known_u128(0)
            };
            let allocated_bytes = if matches!(kind, EntryKind::File | EntryKind::Symlink) {
                unknown_u128(ReasonCode::UnknownIdentity)
            } else {
                known_u128(0)
            };

            let device = observed.stat.st_dev as u64;
            let inode = observed.stat.st_ino;
            let identity = Some(EntryIdentity { device, inode });
            let filesystem_identity = Some(FilesystemIdentity { device });
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

        fn assert_directory_identity_current(
            directory: &OpenDirectory,
        ) -> Result<(), PlatformError> {
            let fd = Self::dirfd(directory)
                .map_err(|error| PlatformError::io(directory.path.clone(), error))?;
            let observed = Self::fstat_raw(fd)
                .map_err(|error| PlatformError::io(directory.path.clone(), error))?;
            if observed.identity() != directory.identity {
                return Err(PlatformError::io(
                    directory.path.clone(),
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "directory identity changed after admission",
                    ),
                ));
            }
            Ok(())
        }
    }

    fn ok_error_changed_or_io(
        parent: &OpenDirectory,
        child: &DirectoryEntryRecord,
        error: io::Error,
    ) -> Result<OpenDirectory, PlatformError> {
        if matches!(
            error.kind(),
            io::ErrorKind::NotFound
                | io::ErrorKind::NotADirectory
                | io::ErrorKind::PermissionDenied
        ) || matches!(error.raw_os_error(), Some(libc::ELOOP))
        {
            return Err(PlatformError::io(
                child.path.clone(),
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "directory changed between no-follow stat and open under {}: {error}",
                        parent.path.display()
                    ),
                ),
            ));
        }
        Err(PlatformError::io(child.path.clone(), error))
    }

    impl PlatformScanner for MacosPlatformScanner {
        type DirectoryHandle = OpenDirectory;

        fn platform_name(&self) -> &'static str {
            "macos"
        }

        fn admit_root(
            &self,
            root: &ScanRoot,
            cancel: &CancellationToken,
        ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;

            if !root.path().is_absolute() {
                return Err(PlatformError::RootRejected(format!(
                    "root is not absolute: {}",
                    root.path().display()
                )));
            }

            let directory = Self::open_root_directory(root.path()).map_err(|error| {
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ELOOP) | Some(libc::ENOTDIR) | Some(libc::ENOENT)
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
            let entry = Self::metadata_to_entry(
                root.path(),
                Self::native_name(root.path()),
                &ObservedMetadata {
                    stat: {
                        let mut stat = MaybeUninit::<libc::stat>::uninit();
                        // SAFETY: `directory.stream` is valid and `dirfd` + `fstat` use live fd.
                        let fd = unsafe { libc::dirfd(directory.stream) };
                        if fd < 0 || unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
                            return Err(PlatformError::io(root.path(), io::Error::last_os_error()));
                        }
                        // SAFETY: successful fstat initialized the structure.
                        unsafe { stat.assume_init() }
                    },
                },
            );

            Ok(RootAdmission {
                root: root.clone(),
                metadata: entry,
                directory,
            })
        }

        fn enumerate_children(
            &self,
            directory: &mut Self::DirectoryHandle,
            cancel: &CancellationToken,
            limits: DirectoryReadLimits,
        ) -> Result<DirectoryEntryBatch, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            Self::assert_directory_identity_current(directory)?;
            if limits.max_batch_entries == 0 || limits.max_batch_bytes == 0 {
                return Err(PlatformError::ResourceLimit(format!(
                    "directory batch limits must be nonzero at {}",
                    directory.path.display()
                )));
            }

            let mut entries = Vec::new();
            let mut bytes_used = 0usize;

            loop {
                Self::ensure_not_cancelled(cancel)?;

                let child = if let Some(child) = directory.pending.take() {
                    child
                } else {
                    loop {
                        // SAFETY: `__error` returns a valid thread-local errno pointer on macOS.
                        unsafe { *libc::__error() = 0 };
                        // SAFETY: `directory.stream` is valid and owned for the loop duration.
                        let entry = unsafe { libc::readdir(directory.stream) };
                        if entry.is_null() {
                            // SAFETY: `__error` returns a valid thread-local errno pointer.
                            let errno = unsafe { *libc::__error() };
                            if errno == 0 {
                                return Ok(DirectoryEntryBatch::complete(entries));
                            }
                            return Err(PlatformError::io(
                                directory.path.clone(),
                                io::Error::from_raw_os_error(errno),
                            ));
                        }
                        // SAFETY: the returned dirent remains valid until the next call.
                        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                        if name == b"." || name == b".." {
                            continue;
                        }
                        break DirectoryEntryRecord::from_parent_and_name(
                            &directory.path,
                            NativeName::unix(name.to_vec()),
                        )
                        .map_err(|error| {
                            PlatformError::InvalidDirectoryEntry {
                                parent: directory.path.clone(),
                                detail: error.to_string(),
                            }
                        })?;
                    }
                };
                let entry_cost = child.estimated_retained_bytes().ok_or_else(|| {
                    PlatformError::ResourceLimit(format!(
                        "directory byte accounting overflow at {}",
                        directory.path.display()
                    ))
                })?;
                let next_bytes = bytes_used.checked_add(entry_cost).ok_or_else(|| {
                    PlatformError::ResourceLimit(format!(
                        "directory byte accounting overflow at {}",
                        directory.path.display()
                    ))
                })?;
                if entries.is_empty() && entry_cost > limits.max_batch_bytes {
                    return Err(PlatformError::ResourceLimit(format!(
                        "single directory entry exceeds the retained-byte cap at {}",
                        directory.path.display()
                    )));
                }
                if entries.len() >= limits.max_batch_entries || next_bytes > limits.max_batch_bytes
                {
                    directory.pending = Some(child);
                    return Ok(DirectoryEntryBatch::continued(entries));
                }
                bytes_used = next_bytes;
                entries.push(child);
            }
        }

        fn inspect_child(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            child.validate_for_parent(&parent.path).map_err(|error| {
                PlatformError::InvalidDirectoryEntry {
                    parent: parent.path.clone(),
                    detail: error.to_string(),
                }
            })?;
            Self::ensure_not_cancelled(cancel)?;
            Self::assert_directory_identity_current(parent)?;

            let parent_fd = Self::dirfd(parent)
                .map_err(|error| PlatformError::io(parent.path.clone(), error))?;
            let child_name = Self::name_c_string(&child.file_name)?;
            let observed = match Self::fstatat_raw(parent_fd, &child_name) {
                Ok(value) => value,
                Err(error) => {
                    return Ok(WalkEntry::Error(ErrorRecord {
                        path: child.path.clone(),
                        kind: sweepx_platform::error_kind_for_io(&error),
                        reason: sweepx_platform::reason_for_io(&error),
                        detail: error.to_string(),
                    }));
                }
            };

            let metadata = Self::metadata_to_entry(&child.path, child.file_name.clone(), &observed);
            match metadata.kind {
                EntryKind::Directory => {
                    let handle = Self::open_child_directory(parent, child, &observed)?;
                    Ok(WalkEntry::Directory(OpenedDirectory { metadata, handle }))
                }
                EntryKind::File => Ok(WalkEntry::File(metadata)),
                EntryKind::Symlink => Ok(WalkEntry::Link(metadata)),
                EntryKind::ReparsePoint => Ok(WalkEntry::Boundary(BoundaryRecord {
                    path: child.path.clone(),
                    kind: BoundaryKind::ReparsePoint,
                    reason: ReasonCode::UnsupportedFilesystem,
                    detail: "macOS reparse-like entry is unsupported".to_string(),
                })),
                EntryKind::Other => Ok(WalkEntry::Boundary(BoundaryRecord {
                    path: child.path.clone(),
                    kind: BoundaryKind::OtherFilesystem,
                    reason: ReasonCode::UnsupportedFilesystem,
                    detail: "special filesystem entry rejected".to_string(),
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
                    "mount identity unavailable".to_string(),
                )),
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl PlatformScanner for MacosPlatformScanner {
    type DirectoryHandle = MacosUnavailableDirectory;

    fn platform_name(&self) -> &'static str {
        "macos"
    }

    fn admit_root(
        &self,
        _root: &ScanRoot,
        _cancel: &CancellationToken,
    ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
        Err(PlatformError::Unsupported(
            "macOS scanner backend is unavailable on this host".to_string(),
        ))
    }

    fn enumerate_children(
        &self,
        _directory: &mut Self::DirectoryHandle,
        _cancel: &CancellationToken,
        _limits: DirectoryReadLimits,
    ) -> Result<DirectoryEntryBatch, PlatformError> {
        Err(PlatformError::Unsupported(
            "macOS scanner backend is unavailable on this host".to_string(),
        ))
    }

    fn inspect_child(
        &self,
        _parent: &Self::DirectoryHandle,
        _child: &DirectoryEntryRecord,
        _cancel: &CancellationToken,
    ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
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
    use std::path::Path;

    use sweepx_model::{EvidenceValue, NativeName, ReasonCode};
    use sweepx_platform::{BoundaryKind, DirectoryReadLimits};

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

    fn child_record(parent: &Path, bytes: &[u8]) -> DirectoryEntryRecord {
        DirectoryEntryRecord {
            path: parent.join(OsStr::from_bytes(bytes)),
            file_name: name(bytes),
        }
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
    fn enumerate_children_uses_opened_dir_and_enforces_limits() {
        let temp = TempDir::new("enumerate");
        for raw in [b"z".as_slice(), b"a".as_slice(), b"m".as_slice()] {
            fs::write(temp.path().join(OsStr::from_bytes(raw)), b"x").unwrap();
        }

        let scanner = MacosPlatformScanner::new();
        let mut admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let entries = scanner
            .enumerate_children(
                &mut admission.directory,
                &CancellationToken::new(),
                DirectoryReadLimits {
                    max_batch_entries: 8,
                    max_batch_bytes: 1024,
                },
            )
            .unwrap();

        assert_eq!(entries.entries.len(), 3);
        assert_eq!(
            entries
                .entries
                .iter()
                .map(|entry| entry.path.file_name().unwrap().as_bytes().to_vec())
                .collect::<Vec<_>>(),
            vec![b"a".to_vec(), b"m".to_vec(), b"z".to_vec()]
        );

        let error = scanner
            .enumerate_children(
                &mut admission.directory,
                &CancellationToken::new(),
                DirectoryReadLimits {
                    max_batch_entries: 1,
                    max_batch_bytes: 1024,
                },
            )
            .unwrap_err();
        assert!(matches!(error, PlatformError::ResourceLimit(_)));
    }

    #[test]
    fn native_name_preserves_arbitrary_unix_bytes() {
        let raw = [b'p', 0xff, b'q'];
        let path = Path::new("/tmp").join(OsStr::from_bytes(&raw));
        assert_eq!(MacosPlatformScanner::native_name(&path), name(&raw));
    }

    #[test]
    fn inspect_child_is_no_follow_and_reports_file_identity_sizes_and_links() {
        let temp = TempDir::new("inspect");
        let file = temp.path().join("file");
        fs::write(&file, b"hello world").unwrap();
        let second = temp.path().join("second");
        fs::hard_link(&file, &second).unwrap();
        let link = temp.path().join("link");
        symlink(&file, &link).unwrap();
        let scanner = MacosPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();

        let WalkEntry::File(first) = scanner
            .inspect_child(
                &admission.directory,
                &child_record(temp.path(), b"file"),
                &CancellationToken::new(),
            )
            .unwrap()
        else {
            panic!("expected file entry");
        };
        let WalkEntry::File(second) = scanner
            .inspect_child(
                &admission.directory,
                &child_record(temp.path(), b"second"),
                &CancellationToken::new(),
            )
            .unwrap()
        else {
            panic!("expected file entry");
        };
        let WalkEntry::Link(link) = scanner
            .inspect_child(
                &admission.directory,
                &child_record(temp.path(), b"link"),
                &CancellationToken::new(),
            )
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
        assert!(matches!(
            link.logical_bytes,
            EvidenceValue::Known { ref value } if value.0 > 0
        ));
        assert!(matches!(
            link.allocated_bytes,
            EvidenceValue::Unknown {
                reason: ReasonCode::UnknownIdentity
            }
        ));
        assert!(link.hard_link_key.is_none());
    }

    #[test]
    fn inspect_child_missing_entry_is_walk_error() {
        let temp = TempDir::new("missing");
        let scanner = MacosPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let entry = scanner
            .inspect_child(
                &admission.directory,
                &child_record(temp.path(), b"missing"),
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(matches!(entry, WalkEntry::Error(_)));
    }

    #[test]
    fn inspect_child_reports_directory_and_special_entry_types() {
        let temp = TempDir::new("entry-types");
        let directory = temp.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let socket = temp.path().join("socket");
        let _listener = UnixListener::bind(&socket).unwrap();
        let scanner = MacosPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();

        assert!(matches!(
            scanner
                .inspect_child(
                    &admission.directory,
                    &child_record(temp.path(), b"directory"),
                    &CancellationToken::new()
                )
                .unwrap(),
            WalkEntry::Directory(_)
        ));
        assert!(matches!(
            scanner
                .inspect_child(
                    &admission.directory,
                    &child_record(temp.path(), b"socket"),
                    &CancellationToken::new()
                )
                .unwrap(),
            WalkEntry::Boundary(sweepx_platform::BoundaryRecord {
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

        let mut admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(matches!(
            scanner.enumerate_children(
                &mut admission.directory,
                &cancel,
                DirectoryReadLimits {
                    max_batch_entries: 16,
                    max_batch_bytes: 1024,
                }
            ),
            Err(PlatformError::Cancelled)
        ));
        assert!(matches!(
            scanner.inspect_child(
                &admission.directory,
                &child_record(temp.path(), b"file"),
                &cancel
            ),
            Err(PlatformError::Cancelled)
        ));
    }
}
