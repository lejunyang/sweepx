use sweepx_platform::{
    CancellationToken, DirectoryEntryBatch, DirectoryEntryRecord, DirectoryReadLimits,
    EntryMetadata, PlatformError, PlatformScanner, RootAdmission, ScanRoot, WalkEntry,
};
#[cfg(target_os = "macos")]
mod bulk_directory;
#[cfg(target_os = "macos")]
use sweepx_platform::{DirectoryHandleAdmission, OpenedDirectory};

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
    #[cfg(test)]
    use std::fs;
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use sweepx_model::{DecimalU128, NativeName, ReasonCode};
    use sweepx_platform::{
        BoundaryKind, BoundaryRecord, BoundedRegularFileReadError, BoundedRegularFileReadRequest,
        EntryIdentity, EntryKind, ErrorRecord, FilesystemIdentity, HardLinkKey, MountIdentity,
        PresentRegularFileRead, RegularFileChangeStamp, RegularFileIdentityMismatch,
        RegularFileMountMismatch, RegularFileObservation, RegularFileObservationMismatch,
        RegularFileReadExpectation, fingerprint_for, known_count, known_u128, unknown_u128,
    };

    use super::bulk_directory::{BulkDirectoryCursor, unsupported as bulk_unsupported};
    use super::*;

    const REGULAR_FILE_READ_CHUNK_BYTES: usize = 64 * 1024;

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

        fn regular_file_observation(
            &self,
            mount_identity: MountIdentity,
        ) -> RegularFileObservation {
            RegularFileObservation {
                kind: kind_from_mode(self.stat.st_mode),
                identity: EntryIdentity::from_unix(self.stat.st_dev as u64, self.stat.st_ino),
                filesystem_identity: FilesystemIdentity {
                    device: self.stat.st_dev as u64,
                },
                mount_identity,
                logical_bytes: DecimalU128::new(self.stat.st_size.max(0) as u128),
                change_stamp: regular_file_change_stamp(&self.stat),
            }
        }
    }

    #[derive(Debug)]
    pub struct OpenDirectory {
        stream: *mut libc::DIR,
        path: PathBuf,
        identity: ObjectIdentity,
        mount_identity: MountIdentity,
        pending: Option<DirectoryEntryRecord>,
        enumeration: DirectoryEnumeration,
    }

    #[derive(Debug)]
    enum DirectoryEnumeration {
        Bulk(BulkDirectoryCursor),
        Readdir,
        Exhausted,
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

    fn regular_file_change_stamp(stat: &libc::stat) -> RegularFileChangeStamp {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&stat.st_mtime.to_le_bytes());
        bytes.extend_from_slice(&stat.st_mtime_nsec.to_le_bytes());
        bytes.extend_from_slice(&stat.st_ctime.to_le_bytes());
        bytes.extend_from_slice(&stat.st_ctime_nsec.to_le_bytes());
        RegularFileChangeStamp::new(bytes)
    }

    #[cfg(test)]
    #[derive(Debug)]
    enum ReadRegularFileTestHook {
        ReplaceWithSymlinkAfterPreview {
            parent: PathBuf,
            child_name: Vec<u8>,
            link_target: PathBuf,
        },
        CancelAfterFirstChunk {
            parent: PathBuf,
            child_name: Vec<u8>,
            cancel: CancellationToken,
        },
    }

    #[cfg(test)]
    static READ_REGULAR_FILE_TEST_HOOK: std::sync::Mutex<Option<ReadRegularFileTestHook>> =
        std::sync::Mutex::new(None);

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

        fn ensure_not_cancelled_read(
            cancel: &CancellationToken,
        ) -> Result<(), BoundedRegularFileReadError> {
            if cancel.is_cancelled() {
                return Err(BoundedRegularFileReadError::Cancelled);
            }
            Ok(())
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

        fn fstatfs_raw(fd: libc::c_int) -> Result<MountIdentity, io::Error> {
            let mut statfs = MaybeUninit::<libc::statfs>::uninit();
            // SAFETY: `statfs` points to writable storage and fd is live for the call.
            if unsafe { libc::fstatfs(fd, statfs.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful `fstatfs` initialized the structure.
            let statfs = unsafe { statfs.assume_init() };
            let size = std::mem::size_of::<libc::fsid_t>();
            if size < std::mem::size_of::<u64>() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "macOS fsid_t is smaller than u64",
                ));
            }
            let mut bytes = [0u8; 8];
            let source = &statfs.f_fsid as *const libc::fsid_t as *const u8;
            // SAFETY: `source` points to initialized fsid bytes and we copy exactly 8 bytes
            // into a non-overlapping local array after verifying the source size is sufficient.
            unsafe {
                std::ptr::copy_nonoverlapping(source, bytes.as_mut_ptr(), bytes.len());
            }
            Ok(MountIdentity {
                value: u64::from_ne_bytes(bytes),
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

        fn next_directory_record(
            directory: &mut OpenDirectory,
            cancel: &CancellationToken,
        ) -> Result<Option<DirectoryEntryRecord>, PlatformError> {
            loop {
                Self::ensure_not_cancelled(cancel)?;
                let parent = directory.path.clone();
                let fd = Self::dirfd(directory)
                    .map_err(|error| PlatformError::io(parent.clone(), error))?;
                match &mut directory.enumeration {
                    DirectoryEnumeration::Bulk(cursor) => {
                        if let Some(name) = cursor.pop() {
                            return DirectoryEntryRecord::from_parent_and_name(&parent, name)
                                .map(Some)
                                .map_err(|error| PlatformError::InvalidDirectoryEntry {
                                    parent,
                                    detail: error.to_string(),
                                });
                        }
                        match cursor.read_page(fd) {
                            Ok(true) => continue,
                            Ok(false) => {
                                directory.enumeration = DirectoryEnumeration::Exhausted;
                                return Ok(None);
                            }
                            Err(error) if cursor.can_fallback() && bulk_unsupported(&error) => {
                                // Unsupported filesystems may reject getattrlistbulk. Rewind before
                                // falling back so an implementation that touched the cursor cannot
                                // silently omit entries. A failure after any accepted bulk page is
                                // not restartable without duplicate/absence ambiguity and fails.
                                unsafe { libc::rewinddir(directory.stream) };
                                directory.enumeration = DirectoryEnumeration::Readdir;
                            }
                            Err(error) => return Err(PlatformError::io(parent, error)),
                        }
                    }
                    DirectoryEnumeration::Readdir => loop {
                        // SAFETY: `__error` returns a valid thread-local errno pointer on macOS.
                        unsafe { *libc::__error() = 0 };
                        // SAFETY: `directory.stream` is valid and exclusively owned here.
                        let entry = unsafe { libc::readdir(directory.stream) };
                        if entry.is_null() {
                            // SAFETY: `__error` returns a valid thread-local errno pointer.
                            let errno = unsafe { *libc::__error() };
                            if errno == 0 {
                                directory.enumeration = DirectoryEnumeration::Exhausted;
                                return Ok(None);
                            }
                            return Err(PlatformError::io(
                                parent,
                                io::Error::from_raw_os_error(errno),
                            ));
                        }
                        // SAFETY: the returned dirent remains valid until the next readdir call.
                        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                        if name == b"." || name == b".." {
                            continue;
                        }
                        return DirectoryEntryRecord::from_parent_and_name(
                            &parent,
                            NativeName::unix(name.to_vec()),
                        )
                        .map(Some)
                        .map_err(|error| {
                            PlatformError::InvalidDirectoryEntry {
                                parent,
                                detail: error.to_string(),
                            }
                        });
                    },
                    DirectoryEnumeration::Exhausted => return Ok(None),
                }
            }
        }

        fn open_directory_from_fd(fd: OwnedFd, path: PathBuf) -> Result<OpenDirectory, io::Error> {
            let observed = Self::fstat(&fd)?;
            let identity = observed.identity();
            let mount_identity = Self::fstatfs_raw(fd.as_raw_fd())?;
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
                mount_identity,
                pending: None,
                enumeration: DirectoryEnumeration::Bulk(BulkDirectoryCursor::new()),
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
            mount_identity: Option<MountIdentity>,
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
            let identity = EntryIdentity::from_unix(device, inode);
            let filesystem_identity = Some(FilesystemIdentity { device });
            let hard_link_key =
                (kind == EntryKind::File).then(|| HardLinkKey::from(identity.clone()));
            let hard_link_count = known_count(observed.stat.st_nlink as u128);
            let fingerprint = fingerprint_for(Some(&identity), &kind, &logical_bytes);

            EntryMetadata {
                path: path.to_path_buf(),
                file_name,
                kind,
                logical_bytes,
                allocated_bytes,
                hard_link_count,
                fingerprint,
                identity: Some(identity),
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
            let mount_identity = Self::fstatfs_raw(fd)
                .map_err(|error| PlatformError::io(directory.path.clone(), error))?;
            if mount_identity != directory.mount_identity {
                return Err(PlatformError::io(
                    directory.path.clone(),
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "directory mount identity changed after admission",
                    ),
                ));
            }
            Ok(())
        }

        fn validate_regular_file_expectation(
            request: &BoundedRegularFileReadRequest,
            observed_before: &RegularFileObservation,
        ) -> Result<(), BoundedRegularFileReadError> {
            let RegularFileReadExpectation::PreviouslyObserved(expected) = request.expectation()
            else {
                return Ok(());
            };

            if expected.mount_identity() != &observed_before.mount_identity {
                return Err(BoundedRegularFileReadError::MountMismatch(Box::new(
                    RegularFileMountMismatch {
                        expected: Some(expected.clone()),
                        observed_mount_identity: observed_before.mount_identity.clone(),
                    },
                )));
            }
            if expected.identity() != &observed_before.identity
                || expected.filesystem_identity() != &observed_before.filesystem_identity
            {
                return Err(BoundedRegularFileReadError::IdentityMismatch(Box::new(
                    RegularFileIdentityMismatch {
                        expected: Some(expected.clone()),
                        observed_identity: observed_before.identity.clone(),
                        observed_filesystem_identity: observed_before.filesystem_identity.clone(),
                    },
                )));
            }
            Ok(())
        }

        fn validate_regular_file_preview_kind(
            observed: &ObservedMetadata,
        ) -> Result<(), BoundedRegularFileReadError> {
            match kind_from_mode(observed.stat.st_mode) {
                EntryKind::File => Ok(()),
                EntryKind::Symlink | EntryKind::ReparsePoint => {
                    Err(BoundedRegularFileReadError::SymlinkOrReparse {
                        observed_kind: kind_from_mode(observed.stat.st_mode),
                    })
                }
                other => Err(BoundedRegularFileReadError::NotRegular {
                    observed_kind: other,
                }),
            }
        }

        fn compare_regular_file_observations(
            observed_before: &RegularFileObservation,
            observed_after: &RegularFileObservation,
        ) -> Result<(), BoundedRegularFileReadError> {
            if observed_before.mount_identity != observed_after.mount_identity {
                return Err(BoundedRegularFileReadError::MountMismatch(Box::new(
                    RegularFileMountMismatch {
                        expected: None,
                        observed_mount_identity: observed_after.mount_identity.clone(),
                    },
                )));
            }
            if observed_before.identity != observed_after.identity {
                return Err(BoundedRegularFileReadError::IdentityMismatch(Box::new(
                    RegularFileIdentityMismatch {
                        expected: None,
                        observed_identity: observed_after.identity.clone(),
                        observed_filesystem_identity: observed_after.filesystem_identity.clone(),
                    },
                )));
            }
            if observed_before.filesystem_identity != observed_after.filesystem_identity
                || observed_before.logical_bytes != observed_after.logical_bytes
                || observed_before.change_stamp != observed_after.change_stamp
            {
                return Err(BoundedRegularFileReadError::ChangedDuringRead(Box::new(
                    RegularFileObservationMismatch {
                        observed_before: observed_before.clone(),
                        observed_after: observed_after.clone(),
                    },
                )));
            }
            Ok(())
        }

        fn read_regular_file_observation(
            fd: &OwnedFd,
        ) -> Result<RegularFileObservation, io::Error> {
            let observed = Self::fstat(fd)?;
            let mount_identity = Self::fstatfs_raw(fd.as_raw_fd())?;
            Ok(observed.regular_file_observation(mount_identity))
        }

        fn classify_open_failure_after_preview(
            parent: &OpenDirectory,
            child_name: &CString,
            preview: &RegularFileObservation,
            open_error: io::Error,
        ) -> Result<PresentRegularFileRead, BoundedRegularFileReadError> {
            match Self::fstatat_raw(
                Self::dirfd(parent).map_err(BoundedRegularFileReadError::io)?,
                child_name,
            ) {
                Ok(current) => {
                    let current_observed =
                        current.regular_file_observation(parent.mount_identity.clone());
                    match current_observed.kind {
                        EntryKind::Symlink | EntryKind::ReparsePoint => {
                            Err(BoundedRegularFileReadError::SymlinkOrReparse {
                                observed_kind: current_observed.kind,
                            })
                        }
                        EntryKind::File => {
                            if preview.identity != current_observed.identity
                                || preview.filesystem_identity
                                    != current_observed.filesystem_identity
                            {
                                return Err(BoundedRegularFileReadError::IdentityMismatch(
                                    Box::new(RegularFileIdentityMismatch {
                                        expected: None,
                                        observed_identity: current_observed.identity,
                                        observed_filesystem_identity: current_observed
                                            .filesystem_identity,
                                    }),
                                ));
                            }
                            if preview.logical_bytes != current_observed.logical_bytes
                                || preview.change_stamp != current_observed.change_stamp
                            {
                                return Err(BoundedRegularFileReadError::ChangedDuringRead(
                                    Box::new(RegularFileObservationMismatch {
                                        observed_before: preview.clone(),
                                        observed_after: current_observed,
                                    }),
                                ));
                            }
                            Err(BoundedRegularFileReadError::io(open_error))
                        }
                        other => Err(BoundedRegularFileReadError::NotRegular {
                            observed_kind: other,
                        }),
                    }
                }
                Err(reprobe_error) if reprobe_error.kind() == io::ErrorKind::NotFound => {
                    Err(BoundedRegularFileReadError::NotFound)
                }
                Err(_) => Err(BoundedRegularFileReadError::io(open_error)),
            }
        }

        #[cfg(test)]
        fn maybe_run_read_test_hook_after_preview(parent: &OpenDirectory, child_name: &NativeName) {
            let action = {
                let mut guard = READ_REGULAR_FILE_TEST_HOOK.lock().unwrap();
                let matches = guard.as_ref().is_some_and(|hook| match hook {
                    ReadRegularFileTestHook::ReplaceWithSymlinkAfterPreview {
                        parent: expected_parent,
                        child_name: expected_child_name,
                        ..
                    }
                    | ReadRegularFileTestHook::CancelAfterFirstChunk {
                        parent: expected_parent,
                        child_name: expected_child_name,
                        ..
                    } => {
                        expected_parent == &parent.path
                            && matches!(
                                child_name,
                                NativeName::UnixBytes(bytes) if bytes == expected_child_name
                            )
                    }
                });
                if matches { guard.take() } else { None }
            };
            if let Some(ReadRegularFileTestHook::ReplaceWithSymlinkAfterPreview {
                parent,
                child_name,
                link_target,
            }) = action
            {
                let child = parent.join(Path::new(std::ffi::OsStr::from_bytes(&child_name)));
                fs::remove_file(&child).unwrap();
                std::os::unix::fs::symlink(link_target, child).unwrap();
            }
        }

        #[cfg(test)]
        fn maybe_run_read_test_hook_after_first_chunk(
            parent: &OpenDirectory,
            child_name: &NativeName,
        ) {
            let action = {
                let mut guard = READ_REGULAR_FILE_TEST_HOOK.lock().unwrap();
                let matches = guard.as_ref().is_some_and(|hook| match hook {
                    ReadRegularFileTestHook::CancelAfterFirstChunk {
                        parent: expected_parent,
                        child_name: expected_child_name,
                        ..
                    } => {
                        expected_parent == &parent.path
                            && matches!(
                                child_name,
                                NativeName::UnixBytes(bytes) if bytes == expected_child_name
                            )
                    }
                    _ => false,
                });
                if matches { guard.take() } else { None }
            };
            if let Some(ReadRegularFileTestHook::CancelAfterFirstChunk { cancel, .. }) = action {
                cancel.cancel();
            }
        }

        #[cfg(test)]
        pub(crate) fn install_replace_with_symlink_after_preview_hook(
            parent: PathBuf,
            child_name: NativeName,
            link_target: PathBuf,
        ) {
            let NativeName::UnixBytes(child_name) = child_name else {
                panic!("macOS tests require unix native names");
            };
            *READ_REGULAR_FILE_TEST_HOOK.lock().unwrap() =
                Some(ReadRegularFileTestHook::ReplaceWithSymlinkAfterPreview {
                    parent,
                    child_name,
                    link_target,
                });
        }

        #[cfg(test)]
        pub(crate) fn install_cancel_after_first_chunk_hook(
            parent: PathBuf,
            child_name: NativeName,
            cancel: CancellationToken,
        ) {
            let NativeName::UnixBytes(child_name) = child_name else {
                panic!("macOS tests require unix native names");
            };
            *READ_REGULAR_FILE_TEST_HOOK.lock().unwrap() =
                Some(ReadRegularFileTestHook::CancelAfterFirstChunk {
                    parent,
                    child_name,
                    cancel,
                });
        }

        #[cfg(test)]
        pub(crate) fn clear_read_test_hook() {
            *READ_REGULAR_FILE_TEST_HOOK.lock().unwrap() = None;
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
            let root_locator = root
                .native_absolute_path()
                .map_err(|error| PlatformError::RootRejected(error.to_string()))?;

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
                Some(directory.mount_identity.clone()),
            );

            Ok(RootAdmission::new(
                root.clone(),
                entry,
                directory,
                root_locator,
            ))
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
                    let Some(child) = Self::next_directory_record(directory, cancel)? else {
                        return Ok(DirectoryEntryBatch::complete(entries));
                    };
                    child
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
            self.inspect_child_with_directory_admission(
                parent,
                child,
                cancel,
                DirectoryHandleAdmission::Allow,
            )
        }

        fn inspect_child_with_directory_admission(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
            directory_admission: DirectoryHandleAdmission,
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

            match kind_from_mode(observed.stat.st_mode) {
                EntryKind::Directory => {
                    if directory_admission == DirectoryHandleAdmission::Deny {
                        return Ok(WalkEntry::Boundary(BoundaryRecord {
                            path: child.path.clone(),
                            kind: BoundaryKind::ResourceLimit,
                            reason: ReasonCode::ResourceLimit,
                            detail: "frontier limit exceeded".to_string(),
                        }));
                    }
                    let handle = Self::open_child_directory(parent, child, &observed)?;
                    let metadata = Self::metadata_to_entry(
                        &child.path,
                        child.file_name.clone(),
                        &observed,
                        Some(handle.mount_identity.clone()),
                    );
                    Ok(WalkEntry::Directory(OpenedDirectory { metadata, handle }))
                }
                EntryKind::File => Ok(WalkEntry::File(Self::metadata_to_entry(
                    &child.path,
                    child.file_name.clone(),
                    &observed,
                    None,
                ))),
                EntryKind::Symlink => Ok(WalkEntry::Link(Self::metadata_to_entry(
                    &child.path,
                    child.file_name.clone(),
                    &observed,
                    None,
                ))),
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

        fn read_regular_file_relative(
            &self,
            parent: &Self::DirectoryHandle,
            request: &BoundedRegularFileReadRequest,
            cancel: &CancellationToken,
        ) -> Result<PresentRegularFileRead, BoundedRegularFileReadError> {
            Self::ensure_not_cancelled_read(cancel)?;
            Self::assert_directory_identity_current(parent).map_err(|error| {
                BoundedRegularFileReadError::Io {
                    detail: error.to_string(),
                    io_kind: None,
                }
            })?;
            let parent_fd = Self::dirfd(parent).map_err(BoundedRegularFileReadError::io)?;
            let child_name = Self::name_c_string(request.child_name())
                .map_err(|error| BoundedRegularFileReadError::Unsupported(error.to_string()))?;
            let preview = match Self::fstatat_raw(parent_fd, &child_name) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Err(BoundedRegularFileReadError::NotFound);
                }
                Err(error) => return Err(BoundedRegularFileReadError::io(error)),
            };
            Self::validate_regular_file_preview_kind(&preview)?;
            let preview_observed = preview.regular_file_observation(parent.mount_identity.clone());
            Self::ensure_not_cancelled_read(cancel)?;
            #[cfg(test)]
            Self::maybe_run_read_test_hook_after_preview(parent, request.child_name());

            // SAFETY: `parent_fd` is live, `child_name` is NUL-terminated, and the flags force a
            // no-follow open of the final basename while keeping the descriptor nonblocking.
            let raw_fd = unsafe {
                libc::openat(
                    parent_fd,
                    child_name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
            };
            if raw_fd < 0 {
                return Self::classify_open_failure_after_preview(
                    parent,
                    &child_name,
                    &preview_observed,
                    io::Error::last_os_error(),
                );
            }
            // SAFETY: `openat` returned a fresh owned descriptor.
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let observed_before = Self::read_regular_file_observation(&fd)
                .map_err(BoundedRegularFileReadError::io)?;
            Self::validate_regular_file_expectation(request, &observed_before)?;
            Self::compare_regular_file_observations(&preview_observed, &observed_before)?;
            if observed_before.logical_bytes > DecimalU128::new(request.max_bytes() as u128) {
                return Err(BoundedRegularFileReadError::LimitExceeded {
                    max_bytes: request.max_bytes(),
                    observed_logical_bytes: observed_before.logical_bytes,
                });
            }
            Self::ensure_not_cancelled_read(cancel)?;

            let probe_limit = request.max_bytes().saturating_add(1);
            let mut bytes = Vec::with_capacity(probe_limit.min(REGULAR_FILE_READ_CHUNK_BYTES));
            while bytes.len() < probe_limit {
                Self::ensure_not_cancelled_read(cancel)?;
                let remaining = probe_limit - bytes.len();
                let mut chunk = vec![0u8; remaining.min(REGULAR_FILE_READ_CHUNK_BYTES)];
                // SAFETY: `fd` is a live descriptor and `chunk` provides writable storage.
                let read = unsafe {
                    libc::read(
                        fd.as_raw_fd(),
                        chunk.as_mut_ptr().cast::<libc::c_void>(),
                        chunk.len(),
                    )
                };
                if read < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(BoundedRegularFileReadError::io(error));
                }
                let read = read as usize;
                if read == 0 {
                    break;
                }
                chunk.truncate(read);
                bytes.extend_from_slice(&chunk);
                #[cfg(test)]
                if bytes.len() == read {
                    Self::maybe_run_read_test_hook_after_first_chunk(parent, request.child_name());
                }
            }

            Self::ensure_not_cancelled_read(cancel)?;
            let observed_after = Self::read_regular_file_observation(&fd)
                .map_err(BoundedRegularFileReadError::io)?;
            if bytes.len() > request.max_bytes() {
                Self::compare_regular_file_observations(&observed_before, &observed_after)?;
                return Err(BoundedRegularFileReadError::LimitExceeded {
                    max_bytes: request.max_bytes(),
                    observed_logical_bytes: observed_after.logical_bytes,
                });
            }
            Ok(PresentRegularFileRead {
                bytes,
                observed_before,
                observed_after,
            })
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

    fn inspect_child_with_directory_admission(
        &self,
        parent: &Self::DirectoryHandle,
        child: &DirectoryEntryRecord,
        cancel: &CancellationToken,
        _directory_admission: sweepx_platform::DirectoryHandleAdmission,
    ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
        self.inspect_child(parent, child, cancel)
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
    use std::path::{Path, PathBuf};

    use sweepx_model::{DecimalU128, EvidenceValue, NativeName, ReasonCode};
    use sweepx_platform::{
        BoundaryKind, BoundedRegularFileReadError, BoundedRegularFileReadRequest,
        DirectoryReadLimits, read_bound_regular_file,
    };

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
        DirectoryEntryRecord::from_parent_and_name(parent, name(bytes)).unwrap()
    }

    fn read_request(bytes: &[u8], max_bytes: usize) -> BoundedRegularFileReadRequest {
        BoundedRegularFileReadRequest::establish_live(name(bytes), max_bytes).unwrap()
    }

    #[test]
    fn admits_real_directory_with_mount_identity() {
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
        assert!(admission.metadata.mount_identity.is_some());
        assert!(
            scanner
                .is_same_mount(&admission.metadata, &admission.metadata)
                .unwrap()
        );
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
    #[ignore = "requires an explicit native macOS benchmark run"]
    fn native_bulk_enumeration_benchmark_smoke() {
        if std::env::var_os("SWEEPX_RUN_NATIVE_MACOS_BULK_BENCH").as_deref() != Some("1".as_ref()) {
            return;
        }
        let temp = TempDir::new("bulk-benchmark");
        for index in 0..4096 {
            fs::write(temp.path().join(format!("entry-{index:04}")), b"x").unwrap();
        }
        let scanner = MacosPlatformScanner::new();
        let mut admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path().to_path_buf()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let started = std::time::Instant::now();
        let mut count = 0usize;
        loop {
            let page = scanner
                .enumerate_children(
                    &mut admission.directory,
                    &CancellationToken::new(),
                    DirectoryReadLimits {
                        max_batch_entries: 512,
                        max_batch_bytes: 1024 * 1024,
                    },
                )
                .unwrap();
            count += page.entries.len();
            if page.end_of_directory {
                break;
            }
        }
        assert_eq!(count, 4096);
        eprintln!(
            "sweepx_macos_bulk_smoke entries={count} elapsed_ms={}",
            started.elapsed().as_millis()
        );
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
    fn inspect_child_reports_directory_mount_and_special_entry_types() {
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

        let directory_entry = scanner
            .inspect_child(
                &admission.directory,
                &child_record(temp.path(), b"directory"),
                &CancellationToken::new(),
            )
            .unwrap();
        match directory_entry {
            WalkEntry::Directory(OpenedDirectory { metadata, .. }) => {
                assert!(metadata.mount_identity.is_some());
                assert_eq!(metadata.mount_identity, admission.metadata.mount_identity);
                assert!(
                    scanner
                        .is_same_mount(&admission.metadata, &metadata)
                        .unwrap()
                );
            }
            _ => panic!("expected directory entry"),
        }
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

    #[test]
    fn bounded_read_supports_non_utf8_basename() {
        let temp = TempDir::new("bounded-read-nonutf8");
        let raw = [b'p', 0xff, b'q'];
        fs::write(temp.path().join(OsStr::from_bytes(&raw)), b"payload").unwrap();
        let scanner = MacosPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();

        let read = read_bound_regular_file(
            &scanner,
            &admission.directory,
            &read_request(&raw, 64),
            &CancellationToken::new(),
        )
        .unwrap();

        assert_eq!(read.bytes, b"payload");
        assert_eq!(read.observed_before, read.observed_after);
    }

    #[test]
    fn bounded_read_rejects_symlink_without_following_target() {
        let temp = TempDir::new("bounded-read-symlink");
        fs::write(temp.path().join("target"), b"payload").unwrap();
        symlink(temp.path().join("target"), temp.path().join("link")).unwrap();
        let scanner = MacosPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();

        let error = read_bound_regular_file(
            &scanner,
            &admission.directory,
            &read_request(b"link", 64),
            &CancellationToken::new(),
        )
        .unwrap_err();

        assert_eq!(
            error,
            BoundedRegularFileReadError::SymlinkOrReparse {
                observed_kind: sweepx_platform::EntryKind::Symlink,
            }
        );
    }

    #[test]
    fn bounded_read_returns_limit_exceeded_for_oversize_regular_file() {
        let temp = TempDir::new("bounded-read-oversize");
        fs::write(temp.path().join("big"), b"abcdef").unwrap();
        let scanner = MacosPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();

        let error = read_bound_regular_file(
            &scanner,
            &admission.directory,
            &read_request(b"big", 5),
            &CancellationToken::new(),
        )
        .unwrap_err();

        assert_eq!(
            error,
            BoundedRegularFileReadError::LimitExceeded {
                max_bytes: 5,
                observed_logical_bytes: DecimalU128::new(6),
            }
        );
    }

    #[test]
    fn bounded_read_detects_replacement_between_preview_and_open() {
        let temp = TempDir::new("bounded-read-replacement");
        fs::write(temp.path().join("victim"), b"payload").unwrap();
        let scanner = MacosPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        MacosPlatformScanner::install_replace_with_symlink_after_preview_hook(
            temp.path().to_path_buf(),
            name(b"victim"),
            PathBuf::from("replacement-target"),
        );

        let error = read_bound_regular_file(
            &scanner,
            &admission.directory,
            &read_request(b"victim", 64),
            &CancellationToken::new(),
        )
        .unwrap_err();

        MacosPlatformScanner::clear_read_test_hook();
        assert_eq!(
            error,
            BoundedRegularFileReadError::SymlinkOrReparse {
                observed_kind: sweepx_platform::EntryKind::Symlink,
            }
        );
    }

    #[test]
    fn bounded_read_observes_cancellation_between_chunks() {
        let temp = TempDir::new("bounded-read-cancel");
        let large = vec![b'x'; 128 * 1024];
        fs::write(temp.path().join("large"), &large).unwrap();
        let scanner = MacosPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let cancel = CancellationToken::new();
        MacosPlatformScanner::install_cancel_after_first_chunk_hook(
            temp.path().to_path_buf(),
            name(b"large"),
            cancel.clone(),
        );

        let error = read_bound_regular_file(
            &scanner,
            &admission.directory,
            &read_request(b"large", large.len()),
            &cancel,
        )
        .unwrap_err();

        MacosPlatformScanner::clear_read_test_hook();
        assert_eq!(error, BoundedRegularFileReadError::Cancelled);
    }
}
