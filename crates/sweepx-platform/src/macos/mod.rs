use crate::{
    CancellationToken, DirectoryEntryBatch, DirectoryEntryRecord, DirectoryReadLimits,
    EntryMetadata, PlatformError, PlatformScanner, RootAdmission, ScanRoot, WalkEntry,
};
#[cfg(target_os = "macos")]
mod bulk_directory;
#[cfg(target_os = "macos")]
pub mod fsevents;
#[cfg(target_os = "macos")]
use crate::{DirectoryHandleAdmission, OpenedDirectory};

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
    use crate::native_handles::{Admitted, HandleLease};
    use std::ffi::{CStr, CString};
    #[cfg(test)]
    use std::fs;
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use crate::{
        BoundaryKind, BoundaryRecord, BoundedRegularFileReadError, BoundedRegularFileReadRequest,
        EntryIdentity, EntryKind, ErrorRecord, FilesystemIdentity, HardLinkKey, MountIdentity,
        PresentRegularFileRead, RegularFileChangeStamp, RegularFileIdentityMismatch,
        RegularFileMountMismatch, RegularFileObservation, RegularFileObservationMismatch,
        RegularFileReadExpectation, fingerprint_for, known_count, known_u128, unknown_u128,
    };
    use sweepx_model::{CountValue, DecimalU128, NativeName, ReasonCode};

    use super::bulk_directory::{BulkDirectoryCursor, unsupported as bulk_unsupported};
    use super::*;

    // Thin re-exports so external `#[cfg(test)]` helpers can reach the private backend fns.
    #[cfg(test)]
    pub(super) fn dirfd_helper(directory: &OpenDirectory) -> io::Result<libc::c_int> {
        MacosPlatformScanner::dirfd(directory)
    }
    #[cfg(test)]
    pub(super) fn bulk_hints_helper(directory: &OpenDirectory) -> Vec<Vec<u8>> {
        directory.bulk_attributes.keys().cloned().collect()
    }
    #[cfg(test)]
    pub(super) fn fstatat_helper(
        parent_fd: libc::c_int,
        name: &CString,
    ) -> io::Result<ObservedMetadata> {
        MacosPlatformScanner::fstatat_raw(parent_fd, name)
    }
    #[cfg(test)]
    pub(super) fn metadata_helper(
        path: &Path,
        file_name: NativeName,
        observed: &ObservedMetadata,
        mount_identity: Option<MountIdentity>,
        hard_link_count: CountValue,
    ) -> EntryMetadata {
        MacosPlatformScanner::metadata_to_entry(
            path,
            file_name,
            observed,
            mount_identity,
            hard_link_count,
        )
    }
    const REGULAR_FILE_READ_CHUNK_BYTES: usize = 64 * 1024;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ObjectIdentity {
        device: u64,
        inode: u64,
        kind: EntryKind,
    }

    #[derive(Debug)]
    pub struct ObservedMetadata {
        pub stat: libc::stat,
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
        // Drop closes the actual DIR* before this reservation is refunded.
        _lease: HandleLease,
        path: PathBuf,
        identity: ObjectIdentity,
        mount_identity: MountIdentity,
        pending: Option<DirectoryEntryRecord>,
        enumeration: DirectoryEnumeration,
        /// Attributes for the current returned batch and at most one pending lookahead child.
        /// The next enumeration discards older hints; delayed inspection then uses `fstatat`.
        /// The cursor separately retains at most one bounded native page. Neither retains the
        /// whole directory. Exclusive enumerate-and-inspect ownership preserves deferred batches.
        bulk_attributes: std::collections::BTreeMap<Vec<u8>, libc::stat>,
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
                        if let Some(child) = cursor.pop() {
                            // Stash the page-decoded attributes; inspection prefers them over a
                            // per-child fstatat.
                            let NativeName::UnixBytes(name_bytes) = &child.name else {
                                unreachable!("bulk names on this backend are UnixBytes")
                            };
                            directory
                                .bulk_attributes
                                .insert(name_bytes.clone(), child.stat);
                            return DirectoryEntryRecord::from_parent_and_name(&parent, child.name)
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

        fn open_directory_from_fd(
            fd: Admitted<OwnedFd>,
            path: PathBuf,
        ) -> Result<OpenDirectory, io::Error> {
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
            let (fd, lease) = fd.into_parts();
            std::mem::forget(fd);
            Ok(OpenDirectory {
                stream,
                _lease: lease,
                path,
                identity,
                mount_identity,
                pending: None,
                enumeration: DirectoryEnumeration::Bulk(BulkDirectoryCursor::new()),
                bulk_attributes: std::collections::BTreeMap::new(),
            })
        }

        fn open_root_directory(path: &Path) -> Result<OpenDirectory, io::Error> {
            let path_c = Self::path_c_string(path)?;
            // O_NOFOLLOW_ANY rejects symlinks in any path component. Root admission is the only
            // operation allowed to resolve from a path string; descendants are handled via dirfd.
            let lease = HandleLease::acquire_io()?;
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
            let fd = Admitted::new(unsafe { OwnedFd::from_raw_fd(raw_fd) }, lease);
            Self::open_directory_from_fd(fd, path.to_path_buf())
        }

        fn open_child_directory(
            parent: &OpenDirectory,
            child: &DirectoryEntryRecord,
            observed_before: &ObservedMetadata,
        ) -> Result<OpenDirectory, io::Error> {
            let parent_fd = Self::dirfd(parent).map_err(io::Error::other)?;
            let child_name = Self::name_c_string(&child.file_name).map_err(io::Error::other)?;

            // SAFETY: `parent_fd` is live, `child_name` is NUL-terminated, and flags refuse
            // following a symlink in the final component while requiring a directory.
            let lease = HandleLease::acquire_io()?;
            let raw_fd = unsafe {
                libc::openat(
                    parent_fd,
                    child_name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                )
            };
            if raw_fd < 0 {
                // Preserve the original error (TCC EPERM, a vanished child, ...). The caller
                // decides this is a skipped subtree rather than a fatal scan error; do not
                // rewrap it here, or the access-denied kind would be lost.
                return Err(io::Error::last_os_error());
            }

            // SAFETY: `openat` returned a fresh owned descriptor.
            let fd = Admitted::new(unsafe { OwnedFd::from_raw_fd(raw_fd) }, lease);
            let observed_after = Self::fstat(&fd)?;
            if observed_before.identity() != observed_after.identity() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory identity changed between fstatat and openat",
                ));
            }

            Self::open_directory_from_fd(fd, child.path.clone())
        }

        fn metadata_to_entry(
            path: &Path,
            file_name: NativeName,
            observed: &ObservedMetadata,
            mount_identity: Option<MountIdentity>,
            hard_link_count: CountValue,
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

        fn current_bulk_file_length(
            parent: &OpenDirectory,
            child: &DirectoryEntryRecord,
        ) -> Option<u128> {
            child.validate_for_parent(&parent.path).ok()?;
            let NativeName::UnixBytes(bytes) = &child.file_name else {
                return None;
            };
            let stat = parent.bulk_attributes.get(bytes)?;
            (kind_from_mode(stat.st_mode) == EntryKind::File
                && stat.st_dev as u64 == parent.identity.device
                && stat.st_size >= 0)
                .then_some(stat.st_size as u128)
        }

        fn open_bound_regular_file(
            parent: &OpenDirectory,
            request: &BoundedRegularFileReadRequest,
            cancel: &CancellationToken,
        ) -> Result<(Admitted<OwnedFd>, RegularFileObservation), BoundedRegularFileReadError>
        {
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
            let lease = HandleLease::acquire_io().map_err(BoundedRegularFileReadError::io)?;
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
            let fd = Admitted::new(unsafe { OwnedFd::from_raw_fd(raw_fd) }, lease);
            let observed_before = Self::read_regular_file_observation(&fd)
                .map_err(BoundedRegularFileReadError::io)?;
            let native_before = Self::fstat(&fd).map_err(BoundedRegularFileReadError::io)?;
            Self::validate_regular_file_preview_kind(&native_before)?;
            Self::validate_regular_file_expectation(request, &observed_before)?;
            Self::compare_regular_file_observations(&preview_observed, &observed_before)?;
            Ok((fd, observed_before))
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
            // Reject the known provider flag before content, both at the no-follow preview
            // and on the opened descriptor. The calling-thread policy closes the hydration
            // race between these observations; the flag alone would not be sufficient.
            if observed.stat.st_flags & 0x4000_0000 != 0 {
                return Err(BoundedRegularFileReadError::ProviderOrOffline(
                    "file is a dataless object".into(),
                ));
            }
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

        /// Completes detail metadata from one transient no-follow descriptor.
        ///
        /// Ordinary bulk scanning keeps its cheaper observations; only identity-bound details
        /// pay for child fsid evidence. Object replacement or inconsistent observations fail closed.
        pub(super) fn observe_child_mount_metadata(
            parent: &OpenDirectory,
            child: &DirectoryEntryRecord,
            expected: &EntryMetadata,
            cancel: &CancellationToken,
        ) -> Result<EntryMetadata, PlatformError> {
            Self::ensure_not_cancelled(cancel)?;
            child.validate_for_parent(&parent.path).map_err(|error| {
                PlatformError::InvalidDirectoryEntry {
                    parent: parent.path.clone(),
                    detail: error.to_string(),
                }
            })?;
            Self::assert_directory_identity_current(parent)?;
            let parent_fd =
                Self::dirfd(parent).map_err(|error| PlatformError::io(&child.path, error))?;
            let child_name = Self::name_c_string(&child.file_name)?;
            // SAFETY: open only the validated basename relative to the retained parent. O_SYMLINK
            // opens a link itself, never its target; combining it with O_NOFOLLOW rejects links
            // with ELOOP on this host. fstat rejects substituted kinds before accepting evidence.
            // O_EVTONLY requests metadata/event access; no payload read is issued. O_NONBLOCK
            // prevents a substituted FIFO from blocking here. Host access checks still apply.
            let lease =
                HandleLease::acquire_io().map_err(|error| PlatformError::io(&child.path, error))?;
            let raw_fd = unsafe {
                libc::openat(
                    parent_fd,
                    child_name.as_ptr(),
                    libc::O_EVTONLY | libc::O_SYMLINK | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if raw_fd < 0 {
                return Err(PlatformError::io(&child.path, io::Error::last_os_error()));
            }
            // SAFETY: openat returned a fresh fd, released on every success/error/cancel path.
            let fd = Admitted::new(unsafe { OwnedFd::from_raw_fd(raw_fd) }, lease);
            Self::ensure_not_cancelled(cancel)?;
            let observe = || -> io::Result<EntryMetadata> {
                let before = Self::fstat(&fd)?;
                if !matches!(expected.kind, EntryKind::File | EntryKind::Symlink)
                    || expected.kind != before.identity().kind
                    || expected.identity.as_ref()
                        != Some(&EntryIdentity::from_unix(
                            before.stat.st_dev as u64,
                            before.stat.st_ino,
                        ))
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "child identity changed before mount observation",
                    ));
                }
                let mount = Self::fstatfs_raw(fd.as_raw_fd())?;
                let after = Self::fstat(&fd)?;
                let rebound = Self::fstatat_raw(parent_fd, &child_name)?;
                // O_EVTONLY does not pin a mounted volume. Recheck fsid, object metadata and
                // the parent's current no-follow binding; stale open handles cannot license rows.
                if mount != Self::fstatfs_raw(fd.as_raw_fd())?
                    || before.identity() != after.identity()
                    || after.identity() != rebound.identity()
                    || before.stat.st_size != after.stat.st_size
                    || after.stat.st_size != rebound.stat.st_size
                    || regular_file_change_stamp(&before.stat)
                        != regular_file_change_stamp(&after.stat)
                    || regular_file_change_stamp(&after.stat)
                        != regular_file_change_stamp(&rebound.stat)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "child changed during mount observation",
                    ));
                }
                Ok(Self::metadata_to_entry(
                    &child.path,
                    child.file_name.clone(),
                    &after,
                    Some(mount),
                    known_count(after.stat.st_nlink as u128),
                ))
            };
            let observed = observe().map_err(|error| PlatformError::io(&child.path, error))?;
            Self::assert_directory_identity_current(parent)?;
            Self::ensure_not_cancelled(cancel)?;
            Ok(observed)
        }

        fn classify_open_failure_after_preview<T>(
            parent: &OpenDirectory,
            child_name: &CString,
            preview: &RegularFileObservation,
            open_error: io::Error,
        ) -> Result<T, BoundedRegularFileReadError> {
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
                // Independent SDK observation at the actual pre-open failure seam. This
                // catches a bounded reader that forgets the policy used by streaming reads.
                unsafe extern "C" {
                    fn getiopolicy_np(kind: i32, scope: i32) -> i32;
                }
                assert_eq!(unsafe { getiopolicy_np(3, 1) }, 1);
                let child = parent.join(Path::new(std::ffi::OsStr::from_bytes(&child_name)));
                fs::remove_file(&child).unwrap();
                std::os::unix::fs::symlink(link_target, child).unwrap();
            }
        }

        #[cfg(test)]
        pub(in crate::macos) fn install_replace_with_symlink_after_preview_hook(
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
        pub(in crate::macos) fn clear_read_test_hook() {
            *READ_REGULAR_FILE_TEST_HOOK.lock().unwrap() = None;
        }
    }

    impl PlatformScanner for MacosPlatformScanner {
        fn monitor_directory(
            &self,
            _directory: &Self::DirectoryHandle,
            _path: &Path,
            _root: bool,
            _monitor: &crate::change_monitor::ChangeMonitor,
        ) {
            // The one session stream is installed for all roots before traversal starts.
        }
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
            let mut stat_storage = MaybeUninit::<libc::stat>::uninit();
            // SAFETY: `directory.stream` is valid and `dirfd` + `fstat` use the live fd.
            let fd = unsafe { libc::dirfd(directory.stream) };
            if fd < 0 || unsafe { libc::fstat(fd, stat_storage.as_mut_ptr()) } != 0 {
                return Err(PlatformError::io(root.path(), io::Error::last_os_error()));
            }
            // SAFETY: successful fstat initialized the structure.
            let observed_stat = unsafe { stat_storage.assume_init() };
            let entry = Self::metadata_to_entry(
                root.path(),
                Self::native_name(root.path()),
                &ObservedMetadata {
                    stat: observed_stat,
                },
                Some(directory.mount_identity.clone()),
                known_count(observed_stat.st_nlink as u128),
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

            // Keep only the lookahead that belongs to the next batch. Old records remain usable
            // through handle-relative inspection, but must not borrow a previous batch's stat.
            let pending_stat = directory.pending.as_ref().and_then(|child| {
                let NativeName::UnixBytes(bytes) = &child.file_name else {
                    return None;
                };
                directory
                    .bulk_attributes
                    .remove(bytes)
                    .map(|stat| (bytes.clone(), stat))
            });
            directory.bulk_attributes.clear();
            if let Some((name, stat)) = pending_stat {
                directory.bulk_attributes.insert(name, stat);
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

        fn inspect_child_with_mount_identity(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            self.inspect_child_with_mount_identity_and_directory_admission(
                parent,
                child,
                cancel,
                DirectoryHandleAdmission::Allow,
            )
        }

        fn inspect_child_with_mount_identity_and_directory_admission(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
            directory_admission: DirectoryHandleAdmission,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            match self.inspect_child_with_directory_admission(
                parent,
                child,
                cancel,
                directory_admission,
            )? {
                WalkEntry::File(metadata) => Ok(WalkEntry::File(
                    Self::observe_child_mount_metadata(parent, child, &metadata, cancel)?,
                )),
                WalkEntry::Link(metadata) => Ok(WalkEntry::Link(
                    Self::observe_child_mount_metadata(parent, child, &metadata, cancel)?,
                )),
                entry => Ok(entry),
            }
        }

        fn supports_file_length_observation(&self) -> bool {
            true
        }

        fn observe_file_length(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
        ) -> Option<crate::CachedFileEntry> {
            let logical_bytes = Self::current_bulk_file_length(parent, child)?;
            // The exclusively owned parent's current bulk batch already supplied these facts.
            // As with cache confirmation, no per-file syscall or pathname reopen is needed.
            Some(crate::CachedFileEntry {
                path: child.path.clone(),
                file_name: child.file_name.clone(),
                logical_bytes,
            })
        }

        fn confirms_cached_file(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            logical_bytes: u128,
        ) -> bool {
            Self::current_bulk_file_length(parent, child) == Some(logical_bytes)
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

            // A bulk page already supplied this child's attributes; otherwise inspect it
            // directly with fstatat as before.
            let NativeName::UnixBytes(child_bytes) = &child.file_name else {
                unreachable!("this backend only produces UnixBytes child names")
            };
            let (observed, from_bulk) =
                if let Some(stat) = parent.bulk_attributes.get(child_bytes).cloned() {
                    (ObservedMetadata { stat }, true)
                } else {
                    let parent_fd = Self::dirfd(parent)
                        .map_err(|error| PlatformError::io(parent.path.clone(), error))?;
                    let child_name = Self::name_c_string(&child.file_name)?;
                    match Self::fstatat_raw(parent_fd, &child_name) {
                        Ok(value) => (value, false),
                        Err(error) => {
                            return Ok(WalkEntry::Error(ErrorRecord {
                                path: child.path.clone(),
                                kind: crate::error_kind_for_io(&error),
                                reason: crate::reason_for_io(&error),
                                detail: error.to_string(),
                            }));
                        }
                    }
                };
            // getattrlistbulk does not report the hard-link count, so a bulk-decoded row carries
            // an honest unknown instead of a fabricated zero; fstatat rows keep the real count.
            let link_count = if from_bulk {
                CountValue::Unknown {
                    reason: ReasonCode::IncompleteStreamCoverage,
                }
            } else {
                known_count(observed.stat.st_nlink as u128)
            };

            match kind_from_mode(observed.stat.st_mode) {
                EntryKind::Directory => {
                    // Bulk attributes can describe the covered vnode beneath a mount. A
                    // no-follow stat of the name sees the mounted object without activating
                    // it via openat. Keep files on the bulk path; directories need this check.
                    let observed =
                        if from_bulk && observed.stat.st_dev as u64 == parent.identity.device {
                            let parent_fd = Self::dirfd(parent)
                                .map_err(|error| PlatformError::io(parent.path.clone(), error))?;
                            let name = Self::name_c_string(&child.file_name)?;
                            match Self::fstatat_raw(parent_fd, &name) {
                                Ok(current) => current,
                                Err(error) => {
                                    return Ok(WalkEntry::Error(ErrorRecord {
                                        path: child.path.clone(),
                                        kind: crate::error_kind_for_io(&error),
                                        reason: crate::reason_for_io(&error),
                                        detail: error.to_string(),
                                    }));
                                }
                            }
                        } else {
                            observed
                        };
                    // Reject an already observed foreign device before opening its directory:
                    // openat can trigger an automount and block even though traversal would
                    // subsequently refuse that mount. Equality is only a preliminary check;
                    // the opened handle still supplies the authoritative mount identity.
                    if observed.stat.st_dev as u64 != parent.identity.device {
                        return Ok(WalkEntry::Boundary(BoundaryRecord {
                            path: child.path.clone(),
                            kind: BoundaryKind::Mount,
                            reason: ReasonCode::UnsupportedFilesystem,
                            detail: "entry crosses the observed device boundary".to_string(),
                        }));
                    }
                    if kind_from_mode(observed.stat.st_mode) != EntryKind::Directory {
                        return Ok(WalkEntry::Error(ErrorRecord {
                            path: child.path.clone(),
                            kind: crate::ErrorKind::Io,
                            reason: ReasonCode::UnknownIdentity,
                            detail: "directory type changed after bulk observation".to_string(),
                        }));
                    }
                    if directory_admission == DirectoryHandleAdmission::Deny {
                        return Ok(WalkEntry::Boundary(BoundaryRecord {
                            path: child.path.clone(),
                            kind: BoundaryKind::ResourceLimit,
                            reason: ReasonCode::ResourceLimit,
                            detail: "frontier limit exceeded".to_string(),
                        }));
                    }
                    let handle = match Self::open_child_directory(parent, child, &observed) {
                        Ok(handle) => handle,
                        // A directory that cannot be opened (TCC refusal, a child that vanished,
                        // a stat/open race) is a skipped subtree, not a fatal scan error: report
                        // it as an error record so the totals covering it become lower bounds and
                        // an ancestor delete still fails closed on the incomplete coverage.
                        Err(error) => {
                            return Ok(WalkEntry::Error(ErrorRecord {
                                path: child.path.clone(),
                                kind: crate::error_kind_for_io(&error),
                                reason: crate::reason_for_io(&error),
                                detail: error.to_string(),
                            }));
                        }
                    };
                    let metadata = Self::metadata_to_entry(
                        &child.path,
                        child.file_name.clone(),
                        &observed,
                        Some(handle.mount_identity.clone()),
                        link_count,
                    );
                    Ok(WalkEntry::Directory(OpenedDirectory { metadata, handle }))
                }
                EntryKind::File => Ok(WalkEntry::File(Self::metadata_to_entry(
                    &child.path,
                    child.file_name.clone(),
                    &observed,
                    None,
                    link_count,
                ))),
                EntryKind::Symlink => Ok(WalkEntry::Link(Self::metadata_to_entry(
                    &child.path,
                    child.file_name.clone(),
                    &observed,
                    None,
                    link_count,
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

        fn stream_regular_file_relative(
            &self,
            parent: &Self::DirectoryHandle,
            request: &crate::RegularFileStreamRequest,
            cancel: &CancellationToken,
            consume: &mut dyn FnMut(&[u8]) -> Result<(), BoundedRegularFileReadError>,
        ) -> Result<crate::RegularFileStreamResult, BoundedRegularFileReadError> {
            Self::ensure_not_cancelled_read(cancel)?;
            let policy = crate::macos_io_policy::NoMaterialization::enter().map_err(|error| {
                BoundedRegularFileReadError::ProviderOrOffline(error.to_string())
            })?;
            let result = (|| {
                let binding = BoundedRegularFileReadRequest::new(
                    request.child_name().clone(),
                    request.expectation().clone(),
                    0,
                )?;
                let (fd, before) = Self::open_bound_regular_file(parent, &binding, cancel)?;
                crate::content::stream_observed_file(
                    request,
                    cancel,
                    before,
                    |offset, buffer| {
                        // SAFETY: fd is exclusively retained for this range, the offset fits
                        // off_t and writable buffer size bounds the native positional read.
                        loop {
                            Self::ensure_not_cancelled_read(cancel)?;
                            let count = unsafe {
                                libc::pread(
                                    fd.as_raw_fd(),
                                    buffer.as_mut_ptr().cast(),
                                    buffer.len(),
                                    offset as libc::off_t,
                                )
                            };
                            if count >= 0 {
                                return Ok(count as usize);
                            }
                            let error = io::Error::last_os_error();
                            if error.kind() != io::ErrorKind::Interrupted {
                                return Err(BoundedRegularFileReadError::io(error));
                            }
                        }
                    },
                    || {
                        Self::read_regular_file_observation(&fd)
                            .map_err(BoundedRegularFileReadError::io)
                    },
                    consume,
                )
            })();
            // Surface restoration errors on success; preserve the original failure otherwise.
            // RAII also restores after opening, read, consumer, cancellation and panic failures.
            let restored = policy.restore().map_err(BoundedRegularFileReadError::io);
            match result {
                Ok(value) => {
                    restored?;
                    Ok(value)
                }
                Err(error) => Err(error),
            }
        }

        fn read_regular_file_relative(
            &self,
            parent: &Self::DirectoryHandle,
            request: &BoundedRegularFileReadRequest,
            cancel: &CancellationToken,
        ) -> Result<PresentRegularFileRead, BoundedRegularFileReadError> {
            let policy = crate::macos_io_policy::NoMaterialization::enter().map_err(|error| {
                BoundedRegularFileReadError::ProviderOrOffline(error.to_string())
            })?;
            let result = (|| {
                let (fd, observed_before) = Self::open_bound_regular_file(parent, request, cancel)?;
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
            })();
            let restored = policy.restore().map_err(BoundedRegularFileReadError::io);
            match result {
                Ok(value) => {
                    restored?;
                    Ok(value)
                }
                Err(error) => Err(error),
            }
        }
    }

    #[cfg(test)]
    mod device_boundary_tests {
        use super::*;
        use std::os::unix::fs::MetadataExt;

        #[test]
        fn bulk_file_lengths_refuse_foreign_devices_and_invalid_native_lengths() {
            let fixture = tempfile::tempdir().unwrap();
            let path = fixture.path().canonicalize().unwrap();
            fs::write(path.join("file"), b"observed bytes").unwrap();
            let scanner = MacosPlatformScanner::new();
            let cancel = CancellationToken::new();
            let mut admission = scanner
                .admit_root(&ScanRoot::new(&path).unwrap(), &cancel)
                .unwrap();
            let child = DirectoryEntryRecord::from_parent_and_name(
                &path,
                NativeName::UnixBytes(b"file".to_vec()),
            )
            .unwrap();
            let name = MacosPlatformScanner::name_c_string(&child.file_name).unwrap();
            let observed = MacosPlatformScanner::fstatat_raw(
                MacosPlatformScanner::dirfd(&admission.directory).unwrap(),
                &name,
            )
            .unwrap();
            // Inject only the two inadmissible fields into otherwise independently observed
            // metadata. These guards must hold even if a filesystem reports malformed hints.
            for (device, length) in [
                (observed.stat.st_dev.wrapping_add(1), observed.stat.st_size),
                (observed.stat.st_dev, -1),
            ] {
                let mut stat = observed.stat;
                stat.st_dev = device;
                stat.st_size = length;
                admission
                    .directory
                    .bulk_attributes
                    .insert(b"file".to_vec(), stat);
                assert!(
                    scanner
                        .observe_file_length(&admission.directory, &child)
                        .is_none()
                );
            }
        }

        #[test]
        fn foreign_directory_is_rejected_before_attempting_to_open_it() {
            let fixture = tempfile::tempdir().unwrap();
            let path = fixture.path().canonicalize().unwrap();
            let scanner = MacosPlatformScanner::new();
            let cancel = CancellationToken::new();
            let mut admission = scanner
                .admit_root(&ScanRoot::new(&path).unwrap(), &cancel)
                .unwrap();
            let mounted = fs::symlink_metadata("/dev").unwrap();
            assert_ne!(mounted.dev(), fs::symlink_metadata(&path).unwrap().dev());
            let name = b"foreign-not-present".to_vec();
            let child = DirectoryEntryRecord::from_parent_and_name(
                &path,
                NativeName::UnixBytes(name.clone()),
            )
            .unwrap();
            // A controlled bulk observation names a foreign directory that does not exist
            // here. An attempted open would return NotFound, never a mount boundary.
            let mut observed = MacosPlatformScanner::fstat_raw(
                MacosPlatformScanner::dirfd(&admission.directory).unwrap(),
            )
            .unwrap();
            observed.stat.st_dev = mounted.dev() as libc::dev_t;
            admission
                .directory
                .bulk_attributes
                .insert(name, observed.stat);
            assert!(!child.path.exists());
            for directory_admission in [
                DirectoryHandleAdmission::Allow,
                DirectoryHandleAdmission::Deny,
            ] {
                assert!(matches!(
                    scanner
                        .inspect_child_with_directory_admission(
                            &admission.directory,
                            &child,
                            &cancel,
                            directory_admission,
                        )
                        .unwrap(),
                    WalkEntry::Boundary(BoundaryRecord {
                        kind: BoundaryKind::Mount,
                        ..
                    })
                ));
            }
        }

        #[test]
        fn covered_bulk_vnode_does_not_hide_a_current_device_boundary() {
            let scanner = MacosPlatformScanner::new();
            let cancel = CancellationToken::new();
            let mut admission = scanner
                .admit_root(&ScanRoot::new("/").unwrap(), &cancel)
                .unwrap();
            let current = fs::symlink_metadata("/dev").unwrap();
            assert_ne!(current.dev(), fs::symlink_metadata("/").unwrap().dev());
            let child = DirectoryEntryRecord::from_parent_and_name(
                Path::new("/"),
                NativeName::UnixBytes(b"dev".to_vec()),
            )
            .unwrap();
            let underlying = MacosPlatformScanner::fstat_raw(
                MacosPlatformScanner::dirfd(&admission.directory).unwrap(),
            )
            .unwrap();
            admission
                .directory
                .bulk_attributes
                .insert(b"dev".to_vec(), underlying.stat);
            assert!(matches!(
                scanner
                    .inspect_child(&admission.directory, &child, &cancel)
                    .unwrap(),
                WalkEntry::Boundary(BoundaryRecord {
                    kind: BoundaryKind::Mount,
                    ..
                })
            ));
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
        _directory_admission: crate::DirectoryHandleAdmission,
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
use std::path::PathBuf;
#[cfg(all(test, target_os = "macos"))]
use sweepx_model::{CountValue, NativeName};

#[cfg(all(test, target_os = "macos"))]
impl MacosPlatformScanner {
    /// Test access to a live directory's raw fd.
    fn dirfd_for_test(
        &self,
        directory: &backend::OpenDirectory,
    ) -> Result<libc::c_int, std::io::Error> {
        // The private backend fn is reached through a re-exported helper below.
        backend::dirfd_helper(directory)
    }

    /// Test helper: no-follow `fstatat` of one named child.
    fn fstatat_named(
        &self,
        parent_fd: libc::c_int,
        name: &[u8],
    ) -> std::io::Result<backend::ObservedMetadata> {
        let c_name = std::ffi::CString::new(name).expect("test helper name has no interior NUL");
        backend::fstatat_helper(parent_fd, &c_name)
    }

    /// Test access to entry construction with a caller-chosen link count.
    fn metadata_for_test(
        &self,
        path: PathBuf,
        name: NativeName,
        observed: &backend::ObservedMetadata,
        hard_link_count: CountValue,
    ) -> EntryMetadata {
        backend::metadata_helper(&path, name, observed, None, hard_link_count)
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

    use crate::{
        BoundaryKind, BoundedRegularFileReadError, BoundedRegularFileReadRequest,
        DirectoryReadLimits, known_count, read_bound_regular_file,
    };
    use sweepx_model::{DecimalU128, EvidenceValue, NativeName, ReasonCode};

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
            // Resolve the fixture path before handing it to the scanner.
            //
            // `admit_root` opens with `O_NOFOLLOW_ANY`, which refuses a symlink in *any* component
            // — the guard that keeps root admission from being redirected. On macOS `TMPDIR` is
            // `/var/folders/...` and `/var` is a symlink to `/private/var`, so an unresolved
            // fixture path is rejected before any test logic runs. Canonicalizing here keeps the
            // guard intact and gives the test a real directory; asserting on the unresolved path
            // would mean weakening the very check these tests exist to cover.
            let path = path.canonicalize().unwrap_or_else(|error| {
                panic!("fixture {path:?} could not be resolved: {error}");
            });
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

    struct ShortTempDir {
        path: PathBuf,
    }

    impl ShortTempDir {
        fn new(test_name: &str) -> Self {
            let path = PathBuf::from(format!(
                "/tmp/sweepx-macos-{test_name}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&path).unwrap();
            let path = path.canonicalize().unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for ShortTempDir {
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

    fn independently_observed_fsid(path: &Path) -> u64 {
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut attrs = libc::attrlist {
            bitmapcount: libc::ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: libc::ATTR_CMN_FSID,
            volattr: 0,
            dirattr: 0,
            fileattr: 0,
            forkattr: 0,
        };
        // Independent native API: length followed by fsid_t, all packed/aligned to four bytes.
        // No fd or fstatfs from the implementation is used, and a link observes itself.
        let mut result = [0u32; 3];
        // SAFETY: attrlist and the twelve-byte aligned output are initialized and writable;
        // the resolved fixture path is NUL-terminated for the duration of the call.
        let status = unsafe {
            libc::getattrlist(
                path.as_ptr(),
                std::ptr::from_mut(&mut attrs).cast(),
                result.as_mut_ptr().cast(),
                std::mem::size_of_val(&result),
                libc::FSOPT_NOFOLLOW,
            )
        };
        assert_eq!(
            status,
            0,
            "getattrlist: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(result[0], 12);
        u64::from_ne_bytes(
            [result[1].to_ne_bytes(), result[2].to_ne_bytes()]
                .concat()
                .try_into()
                .unwrap(),
        )
    }

    #[test]
    fn bulk_file_id_matches_stat_inode_for_hard_links_and_directories() {
        use std::os::unix::fs::MetadataExt;
        let fixture = TempDir::new("bulk-file-id");
        fs::write(fixture.path().join("file"), b"same-native-object").unwrap();
        fs::hard_link(fixture.path().join("file"), fixture.path().join("alias")).unwrap();
        fs::create_dir(fixture.path().join("directory")).unwrap();
        symlink("file", fixture.path().join("link")).unwrap();
        let scanner = MacosPlatformScanner::new();
        let cancel = CancellationToken::new();
        let mut admission = scanner
            .admit_root(&ScanRoot::new(fixture.path()).unwrap(), &cancel)
            .unwrap();
        let mut observations = std::collections::BTreeMap::new();
        loop {
            let batch = scanner
                .enumerate_children(
                    &mut admission.directory,
                    &cancel,
                    DirectoryReadLimits {
                        max_batch_entries: 8,
                        max_batch_bytes: 8192,
                    },
                )
                .unwrap();
            // Inspect before advancing the batch so the production bulk hint path is exercised.
            for child in batch.entries {
                let expected = fs::symlink_metadata(&child.path).unwrap();
                let metadata = match scanner
                    .inspect_child(&admission.directory, &child, &cancel)
                    .unwrap()
                {
                    WalkEntry::File(metadata) | WalkEntry::Link(metadata) => metadata,
                    WalkEntry::Directory(directory) => directory.metadata,
                    other => panic!("unexpected bulk record: {other:?}"),
                };
                assert_eq!(
                    metadata.identity,
                    Some(crate::EntryIdentity::from_unix(
                        expected.dev(),
                        expected.ino()
                    ))
                );
                let NativeName::UnixBytes(bytes) = child.file_name else {
                    unreachable!()
                };
                observations.insert(bytes, metadata.identity);
            }
            if batch.end_of_directory {
                break;
            }
        }
        assert_eq!(
            observations[b"file".as_slice()],
            observations[b"alias".as_slice()]
        );
        assert_ne!(
            observations[b"file".as_slice()],
            observations[b"link".as_slice()]
        );
        assert!(observations.contains_key(b"directory".as_slice()));
    }

    #[test]
    fn detail_mount_evidence_observes_files_and_dangling_links_without_payload_reads() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let fixture = TempDir::new("detail-mount");
        let file = fixture.path().join("file");
        fs::write(&file, b"1234").unwrap();
        symlink("missing-target", fixture.path().join("link")).unwrap();
        let scanner = MacosPlatformScanner::new();
        let cancel = CancellationToken::new();
        let admission = scanner
            .admit_root(&ScanRoot::new(fixture.path()).unwrap(), &cancel)
            .unwrap();
        for basename in [b"file".as_slice(), b"link".as_slice()] {
            let child = child_record(fixture.path(), basename);
            let fast = scanner
                .inspect_child(&admission.directory, &child, &cancel)
                .unwrap();
            let fast_metadata = match fast {
                WalkEntry::File(metadata) | WalkEntry::Link(metadata) => metadata,
                other => panic!("unexpected fast observation: {other:?}"),
            };
            assert!(fast_metadata.mount_identity.is_none());
            let detailed = crate::inspect_bound_child_with_mount_identity(
                &scanner,
                &admission.directory,
                fixture.path(),
                &child,
                &cancel,
            )
            .unwrap();
            let metadata = match detailed {
                WalkEntry::File(metadata) | WalkEntry::Link(metadata) => metadata,
                other => panic!("unexpected detail observation: {other:?}"),
            };
            let independent = fs::symlink_metadata(&child.path).unwrap();
            assert_eq!(
                metadata.identity,
                Some(crate::EntryIdentity::from_unix(
                    independent.dev(),
                    independent.ino(),
                ))
            );
            assert_eq!(metadata.kind, fast_metadata.kind);
            assert_eq!(
                metadata.logical_bytes,
                crate::known_u128(independent.len() as u128)
            );
            assert_eq!(
                metadata.mount_identity,
                Some(crate::MountIdentity {
                    value: independently_observed_fsid(&child.path),
                })
            );
            assert!(matches!(
                metadata.allocated_bytes,
                EvidenceValue::Unknown { .. }
            ));
        }
        // Metadata-only descriptors still respect host access checks; do not broaden rights.
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::File::open(&file).is_err() {
            assert!(matches!(
                scanner.inspect_child_with_mount_identity(
                    &admission.directory,
                    &child_record(fixture.path(), b"file"),
                    &cancel,
                ),
                Err(PlatformError::Io {
                    io_kind: Some(std::io::ErrorKind::PermissionDenied),
                    ..
                })
            ));
        }
    }

    #[test]
    fn detail_mount_evidence_rejects_replaced_objects_and_preserves_cancellation() {
        let fixture = TempDir::new("detail-mount-race");
        fs::write(fixture.path().join("child"), b"old").unwrap();
        let scanner = MacosPlatformScanner::new();
        let cancel = CancellationToken::new();
        let admission = scanner
            .admit_root(&ScanRoot::new(fixture.path()).unwrap(), &cancel)
            .unwrap();
        let child = child_record(fixture.path(), b"child");
        let WalkEntry::File(before) = scanner
            .inspect_child(&admission.directory, &child, &cancel)
            .unwrap()
        else {
            panic!("expected file");
        };
        // Retain the old inode to make replacement deterministic, rather than relying on inode
        // allocation or a timing race. Both replacements have no right to inherit its evidence.
        fs::rename(&child.path, fixture.path().join("old-inode")).unwrap();
        for replacement_is_link in [false, true] {
            if replacement_is_link {
                fs::remove_file(&child.path).unwrap();
                symlink("missing-target", &child.path).unwrap();
            } else {
                fs::write(&child.path, b"new").unwrap();
            }
            let result = MacosPlatformScanner::observe_child_mount_metadata(
                &admission.directory,
                &child,
                &before,
                &cancel,
            );
            assert!(
                matches!(
                    result,
                    Err(PlatformError::Io {
                        io_kind: Some(std::io::ErrorKind::InvalidData),
                        ..
                    })
                ),
                "replacement_is_link={replacement_is_link}: {result:?}"
            );
        }
        cancel.cancel();
        assert!(matches!(
            scanner.inspect_child_with_mount_identity(&admission.directory, &child, &cancel,),
            Err(PlatformError::Cancelled)
        ));
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
            crate::EntryKind::Directory
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
        // Name the root in each failure. This test failed twice in CI with only a bare `unwrap`
        // location to go on, and the two causes were different — the second could not be told from
        // the first without knowing which path was refused and at which call.
        let root = ScanRoot::new(temp.path())
            .unwrap_or_else(|error| panic!("root {:?} rejected by ScanRoot: {error}", temp.path()));
        let mut admission = scanner
            .admit_root(&root, &CancellationToken::new())
            .unwrap_or_else(|error| {
                panic!("admit_root refused {:?}: {error:?}", temp.path());
            });
        let entries = scanner
            .enumerate_children(
                &mut admission.directory,
                &CancellationToken::new(),
                DirectoryReadLimits {
                    max_batch_entries: 8,
                    max_batch_bytes: 1024,
                },
            )
            .unwrap_or_else(|error| {
                panic!(
                    "enumerate_children failed under {:?}: {error:?}",
                    temp.path()
                );
            });

        // The three fixture names must all be present. Do not assert the total: macOS drops
        // `.DS_Store` and similar metadata into directories at times not under this test's control,
        // and an extra entry would then fail a test that is really about the three names.
        let seen = entries
            .entries
            .iter()
            .map(|entry| entry.path.file_name().unwrap().as_bytes())
            .collect::<std::collections::BTreeSet<_>>();
        for name in [b"a".as_slice(), b"m".as_slice(), b"z".as_slice()] {
            assert!(
                seen.contains(name),
                "child {:?} missing from {:?}",
                String::from_utf8_lossy(name),
                seen.iter()
                    .map(|value| String::from_utf8_lossy(value).to_string())
                    .collect::<Vec<_>>()
            );
        }

        // Provoke the limit on a *fresh* handle, and through the branch that actually raises it.
        //
        // The previous version reused `admission.directory` after the batch above had already
        // returned `complete`, so the handle was exhausted: the loop takes the `next_directory_record
        // -> None` path and returns `Ok(complete)` with an empty batch, and `unwrap_err` panicked on
        // an Ok. Tightening `max_batch_entries` cannot help there, because that check is only reached
        // once a record has been read.
        //
        // The reachable refusal is the retained-byte cap: with `max_batch_bytes` below the cost of a
        // single entry, the first record trips `entry_cost > max_batch_bytes` while `entries` is
        // still empty. That is a genuine backend guarantee rather than an artefact of handle state.
        let mut fresh = scanner
            .admit_root(&root, &CancellationToken::new())
            .unwrap_or_else(|error| {
                panic!(
                    "admit_root refused {:?} on re-admission: {error:?}",
                    temp.path()
                );
            });
        let error = scanner
            .enumerate_children(
                &mut fresh.directory,
                &CancellationToken::new(),
                DirectoryReadLimits {
                    max_batch_entries: 8,
                    max_batch_bytes: 1,
                },
            )
            .unwrap_err();
        assert!(matches!(error, PlatformError::ResourceLimit(_)));

        // A zero limit is refused before any read, so it needs no fixture state at all.
        let zero = scanner
            .enumerate_children(
                &mut fresh.directory,
                &CancellationToken::new(),
                DirectoryReadLimits {
                    max_batch_entries: 0,
                    max_batch_bytes: 1024,
                },
            )
            .unwrap_err();
        assert!(matches!(zero, PlatformError::ResourceLimit(_)));
    }

    #[test]
    fn bulk_hints_are_bounded_by_the_current_batch_and_old_records_fall_back() {
        let temp = TempDir::new("bounded-bulk-hints");
        for index in 0..37 {
            fs::write(temp.path().join(format!("file-{index:03}")), b"hello").unwrap();
        }
        let expected = fs::read_dir(temp.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().as_bytes().to_vec())
            .collect::<std::collections::BTreeSet<_>>();
        let scanner = MacosPlatformScanner::new();
        let cancel = CancellationToken::new();
        let root = ScanRoot::new(temp.path()).unwrap();
        let max_record = expected
            .iter()
            .map(|bytes| {
                child_record(temp.path(), bytes)
                    .estimated_retained_bytes()
                    .unwrap()
            })
            .max()
            .unwrap();
        // Exercise both count-driven and byte-driven batching against an ordinary enumeration.
        for limits in [
            DirectoryReadLimits {
                max_batch_entries: 3,
                max_batch_bytes: 1024 * 1024,
            },
            DirectoryReadLimits {
                max_batch_entries: 512,
                max_batch_bytes: max_record * 2,
            },
        ] {
            let mut admission = scanner.admit_root(&root, &cancel).unwrap();
            let mut seen = std::collections::BTreeSet::new();
            let mut first = None;
            loop {
                let batch = scanner
                    .enumerate_children(&mut admission.directory, &cancel, limits)
                    .unwrap();
                let hints = backend::bulk_hints_helper(&admission.directory);
                assert!(hints.len() <= batch.entries.len() + usize::from(!batch.end_of_directory));
                for child in &batch.entries {
                    let NativeName::UnixBytes(bytes) = &child.file_name else {
                        panic!("Unix child")
                    };
                    assert!(seen.insert(bytes.clone()), "duplicate enumeration");
                    let metadata = fs::symlink_metadata(&child.path).unwrap();
                    let observed = scanner
                        .observe_file_length(&admission.directory, child)
                        .expect("current bulk file facts");
                    assert_eq!(observed.path, child.path);
                    assert_eq!(observed.file_name, child.file_name);
                    assert_eq!(observed.logical_bytes, metadata.len() as u128);
                    assert!(scanner.confirms_cached_file(
                        &admission.directory,
                        child,
                        metadata.len() as u128
                    ));
                    assert!(!scanner.confirms_cached_file(
                        &admission.directory,
                        child,
                        metadata.len() as u128 + 1
                    ));
                    first.get_or_insert_with(|| child.clone());
                }
                if batch.end_of_directory {
                    break;
                }
            }
            assert_eq!(seen, expected);
            let old = first.unwrap();
            let NativeName::UnixBytes(bytes) = &old.file_name else {
                panic!("Unix child")
            };
            assert!(!backend::bulk_hints_helper(&admission.directory).contains(bytes));
            assert!(
                scanner
                    .observe_file_length(&admission.directory, &old)
                    .is_none(),
                "older batches cannot lend current lengths"
            );
            fs::write(&old.path, b"a changed length after enumeration").unwrap();
            let metadata = fs::symlink_metadata(&old.path).unwrap();
            assert!(!scanner.confirms_cached_file(
                &admission.directory,
                &old,
                metadata.len() as u128
            ));
            let WalkEntry::File(observed) = scanner
                .inspect_child(&admission.directory, &old, &cancel)
                .unwrap()
            else {
                panic!("ordinary file")
            };
            assert_eq!(
                observed.logical_bytes,
                crate::known_u128(metadata.len() as u128)
            );
            fs::write(&old.path, b"hello").unwrap();
        }
    }

    #[test]
    fn cached_file_confirmation_requires_current_regular_file_and_valid_binding() {
        let temp = TempDir::new("cached-type-proof");
        fs::write(temp.path().join("file"), b"hello").unwrap();
        fs::create_dir(temp.path().join("directory")).unwrap();
        symlink("file", temp.path().join("link")).unwrap();
        let scanner = MacosPlatformScanner::new();
        assert!(scanner.supports_file_length_observation());
        let cancel = CancellationToken::new();
        let mut admission = scanner
            .admit_root(&ScanRoot::new(temp.path()).unwrap(), &cancel)
            .unwrap();
        let batch = scanner
            .enumerate_children(
                &mut admission.directory,
                &cancel,
                DirectoryReadLimits {
                    max_batch_entries: 32,
                    max_batch_bytes: 1024 * 1024,
                },
            )
            .unwrap();
        for child in &batch.entries {
            let metadata = fs::symlink_metadata(&child.path).unwrap();
            let observed = scanner.observe_file_length(&admission.directory, child);
            assert_eq!(observed.is_some(), metadata.is_file());
            if let Some(observed) = observed {
                assert_eq!(observed.logical_bytes, metadata.len() as u128);
            }
            assert_eq!(
                scanner.confirms_cached_file(&admission.directory, child, metadata.len() as u128),
                metadata.is_file()
            );
            let mut forged = child.clone();
            forged.path = temp.path().join("other");
            assert!(
                scanner
                    .observe_file_length(&admission.directory, &forged)
                    .is_none()
            );
            assert!(!scanner.confirms_cached_file(
                &admission.directory,
                &forged,
                metadata.len() as u128
            ));
        }
        assert!(!scanner.confirms_cached_file(
            &admission.directory,
            &child_record(temp.path(), b"absent"),
            0
        ));
        assert!(
            scanner
                .observe_file_length(&admission.directory, &child_record(temp.path(), b"absent"))
                .is_none()
        );
        let unsupported = DirectoryEntryRecord {
            path: temp.path().join("file"),
            file_name: NativeName::WindowsUtf16("file".encode_utf16().collect()),
        };
        assert!(
            scanner
                .observe_file_length(&admission.directory, &unsupported)
                .is_none()
        );
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

        // First the non-bulk path (explicit fstatat-equivalent), so the real link count is
        // available; the bulk path used by the scan reports an honest unknown instead.
        let parent_fd = scanner
            .dirfd_for_test(&admission.directory)
            .expect("admitted directory has a live dirfd");
        let observed_file = scanner
            .fstatat_named(parent_fd, b"file")
            .expect("file is observable");
        let observed_second = scanner
            .fstatat_named(parent_fd, b"second")
            .expect("second is observable");
        let first = scanner.metadata_for_test(
            temp.path().join("file"),
            NativeName::unix(b"file".to_vec()),
            &observed_file,
            known_count(observed_file.stat.st_nlink as u128),
        );
        let second = scanner.metadata_for_test(
            temp.path().join("second"),
            NativeName::unix(b"second".to_vec()),
            &observed_second,
            known_count(observed_second.stat.st_nlink as u128),
        );

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
        assert_eq!(link.kind, crate::EntryKind::Symlink);
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
    fn unopenable_child_directory_is_skipped_as_walk_error_not_fatal() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new("unopenable-dir");
        // A real directory with no permission to open it, standing in for a TCC refusal. It is
        // writable by root only, and the test runs unprivileged; root's open would succeed, so
        // skip the assertion there rather than pass for the wrong reason.
        let blocked = temp.path().join("blocked");
        fs::create_dir(&blocked).unwrap();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();
        let scanner = MacosPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();

        let inspected = scanner.inspect_child(
            &admission.directory,
            &child_record(temp.path(), b"blocked"),
            &CancellationToken::new(),
        );
        // The scan must not abort; an unwrapped walk entry of the Error kind is the contract.
        match inspected {
            Ok(WalkEntry::Error(record)) => {
                assert!(record.path == blocked);
                assert!(matches!(record.kind, crate::ErrorKind::AccessDenied));
            }
            other => panic!("expected an access-denied walk error, got {other:?}"),
        }
    }

    #[test]
    fn inspect_child_reports_directory_mount_and_special_entry_types() {
        // macOS Unix socket addresses under the long TMPDIR exceed SUN_LEN; use a shorter /tmp root.
        let temp = ShortTempDir::new("entry-types");
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
            WalkEntry::Boundary(crate::BoundaryRecord {
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
    fn bounded_read_preserves_non_utf8_basename_in_request() {
        let raw = [b'p', 0xff, b'q'];
        let request = read_request(&raw, 64);
        assert_eq!(request.child_name(), &NativeName::unix(raw.to_vec()));
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
                observed_kind: crate::EntryKind::Symlink,
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
                observed_kind: crate::EntryKind::Symlink,
            }
        );
    }

    #[test]
    fn bounded_read_cancels_before_chunk_read() {
        let temp = TempDir::new("bounded-read-cancel");
        fs::write(temp.path().join("file"), b"payload").unwrap();
        let scanner = MacosPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = read_bound_regular_file(
            &scanner,
            &admission.directory,
            &read_request(b"file", 64),
            &cancel,
        )
        .unwrap_err();
        assert_eq!(error, BoundedRegularFileReadError::Cancelled);
    }
}
