use std::ffi::{CStr, CString};
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use sweepx_model::{NativeName, ReasonCode};
use sweepx_platform::{
    BoundaryKind, BoundaryRecord, CancellationToken, DirectoryEntryBatch, DirectoryEntryRecord,
    DirectoryHandleAdmission, DirectoryReadLimits, EntryIdentity, EntryKind, EntryMetadata,
    ErrorRecord, FilesystemIdentity, HardLinkKey, MountIdentity, OpenedDirectory, PlatformError,
    PlatformScanner, RootAdmission, ScanRoot, WalkEntry, error_kind_for_io, fingerprint_for,
    known_count, known_u128, reason_for_io,
};

// Native mutation remains a test-only qualification concern. In particular,
// this module is absent from normal and all-features library builds.
#[cfg(all(test, target_os = "linux"))]
mod trash_qualification;

#[derive(Debug, Default, Clone)]
pub struct LinuxPlatformScanner;

/// An owned, scan-scoped capability for one admitted directory.
///
/// The descriptor is intentionally not cloneable: the scanner frontier is the
/// sole owner of traversal authority. `display_path` is reporting data only and
/// is never used to reopen the directory.
#[derive(Debug)]
pub struct LinuxDirectoryHandle {
    fd: OwnedFd,
    display_path: PathBuf,
    cursor: DirectoryCursor,
}

#[derive(Debug)]
enum DirectoryCursor {
    NotStarted,
    Active {
        stream: DirectoryStream,
        pending: Option<DirectoryEntryRecord>,
    },
}

#[derive(Debug)]
struct DirectoryStream(*mut libc::DIR);

// SAFETY: a stream lives in exactly one non-Clone directory handle. The handle
// is movable between threads, but enumeration requires exclusive `&mut` access
// and the DIR* is never used concurrently or exposed outside this module.
unsafe impl Send for DirectoryStream {}

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: the non-null stream was returned by `fdopendir` and ownership
        // was transferred to this guard.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

impl LinuxPlatformScanner {
    pub fn new() -> Self {
        Self
    }

    fn ensure_not_cancelled(cancel: &CancellationToken) -> Result<(), PlatformError> {
        if cancel.is_cancelled() {
            return Err(PlatformError::Cancelled);
        }
        Ok(())
    }

    fn native_name(path: &Path) -> NativeName {
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

    fn child_name_c_string(name: &NativeName) -> Result<CString, io::Error> {
        let NativeName::UnixBytes(bytes) = name else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "linux child name is not encoded as Unix bytes",
            ));
        };
        if bytes.is_empty()
            || bytes == b"."
            || bytes == b".."
            || bytes.contains(&b'/')
            || bytes.contains(&0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "child token is not a single safe basename",
            ));
        }
        CString::new(bytes.as_slice()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "child name contains an interior NUL",
            )
        })
    }

    fn open_root(path: &Path) -> Result<OwnedFd, io::Error> {
        let path = Self::path_c_string(path)?;
        // SAFETY: `open_how` is a plain kernel ABI value initialized to zero,
        // then populated with documented flags.
        let mut how: libc::open_how = unsafe { mem::zeroed() };
        how.flags =
            u64::try_from(libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .expect("open flags fit u64");
        how.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
        // SAFETY: the path and open_how pointers remain valid for the syscall.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how,
                mem::size_of::<libc::open_how>(),
            ) as libc::c_int
        };
        Self::owned_fd(raw)
    }

    fn pin_child(parent: &OwnedFd, name: &CStr) -> Result<OwnedFd, io::Error> {
        // O_PATH | O_NOFOLLOW pins the directory entry itself, including a
        // final symlink, without granting read access or following its target.
        // The token is one validated basename, and RESOLVE_BENEATH keeps the
        // lookup rooted at the retained parent descriptor.
        // SAFETY: `open_how` is a plain kernel ABI value initialized to zero,
        // then populated with documented flags.
        let mut how: libc::open_how = unsafe { mem::zeroed() };
        how.flags = u64::try_from(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .expect("open flags fit u64");
        how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_MAGICLINKS;
        // SAFETY: the basename and open_how pointers remain valid for the
        // syscall, and `parent` is a live directory descriptor.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                parent.as_raw_fd(),
                name.as_ptr(),
                &how,
                mem::size_of::<libc::open_how>(),
            ) as libc::c_int
        };
        Self::owned_fd(raw)
    }

    fn open_child_directory(parent: &OwnedFd, name: &CStr) -> Result<OwnedFd, io::Error> {
        // SAFETY: `open_how` is a plain kernel ABI value initialized to zero,
        // then populated with documented flags.
        let mut how: libc::open_how = unsafe { mem::zeroed() };
        how.flags =
            u64::try_from(libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .expect("open flags fit u64");
        how.resolve = libc::RESOLVE_BENEATH
            | libc::RESOLVE_NO_SYMLINKS
            | libc::RESOLVE_NO_MAGICLINKS
            | libc::RESOLVE_NO_XDEV;
        // SAFETY: the basename and open_how pointers remain valid for the
        // syscall, and `parent` is a live directory descriptor.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                parent.as_raw_fd(),
                name.as_ptr(),
                &how,
                mem::size_of::<libc::open_how>(),
            ) as libc::c_int
        };
        Self::owned_fd(raw)
    }

    fn open_matching_child_directory(
        parent: &OwnedFd,
        name: &CStr,
        pinned_stat: &libc::stat,
        pinned_mount_id: u64,
    ) -> Result<OwnedFd, io::Error> {
        let directory = Self::open_child_directory(parent, name)?;
        let directory_stat = Self::fstat(&directory)?;
        let directory_mount_id = Self::mount_id_for_fd(&directory)?;
        if !Self::same_object(pinned_stat, &directory_stat) || pinned_mount_id != directory_mount_id
        {
            return Err(io::Error::other(
                "directory entry changed between pinning and enumerable open",
            ));
        }
        Ok(directory)
    }

    fn owned_fd(raw: libc::c_int) -> Result<OwnedFd, io::Error> {
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful open-style syscall returns a fresh descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }

    fn duplicate_fd(fd: &OwnedFd) -> Result<OwnedFd, io::Error> {
        // SAFETY: fd is live and F_DUPFD_CLOEXEC returns a fresh descriptor.
        let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        Self::owned_fd(raw)
    }

    fn fstat(fd: &OwnedFd) -> Result<libc::stat, io::Error> {
        let mut output = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: output points to writable storage and fd remains live.
        if unsafe { libc::fstat(fd.as_raw_fd(), output.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstat initialized the output.
        Ok(unsafe { output.assume_init() })
    }

    fn mount_id_for_fd(fd: &OwnedFd) -> Result<u64, io::Error> {
        let mut output = MaybeUninit::<libc::statx>::zeroed();
        let mask = libc::STATX_BASIC_STATS | libc::STATX_MNT_ID;
        // SAFETY: output is writable, fd is live, and AT_EMPTY_PATH requests
        // metadata for that already-pinned descriptor rather than performing a
        // second pathname lookup.
        if unsafe {
            libc::statx(
                fd.as_raw_fd(),
                c"".as_ptr(),
                libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                mask,
                output.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful statx initialized the output.
        let output = unsafe { output.assume_init() };
        if output.stx_mask & libc::STATX_MNT_ID == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "statx did not return a mount identifier",
            ));
        }
        Ok(output.stx_mnt_id)
    }

    fn kind_from_mode(mode: libc::mode_t) -> EntryKind {
        match mode & libc::S_IFMT {
            libc::S_IFDIR => EntryKind::Directory,
            libc::S_IFREG => EntryKind::File,
            libc::S_IFLNK => EntryKind::Symlink,
            _ => EntryKind::Other,
        }
    }

    fn metadata_to_entry(
        path: &Path,
        file_name: NativeName,
        stat: &libc::stat,
        mount_id: u64,
    ) -> EntryMetadata {
        let kind = Self::kind_from_mode(stat.st_mode);
        let logical_bytes = if kind == EntryKind::File {
            known_u128(stat.st_size.max(0) as u128)
        } else {
            known_u128(0)
        };
        let allocated_bytes = if kind == EntryKind::File {
            known_u128(stat.st_blocks.max(0) as u128 * 512)
        } else {
            known_u128(0)
        };
        let device = stat.st_dev;
        let inode = stat.st_ino;
        let identity = EntryIdentity::from_unix(device, inode);
        let filesystem_identity = Some(FilesystemIdentity { device });
        let hard_link_key = (kind == EntryKind::File).then(|| HardLinkKey::from(identity.clone()));
        let fingerprint = fingerprint_for(Some(&identity), &kind, &logical_bytes);

        EntryMetadata {
            path: path.to_path_buf(),
            file_name,
            kind,
            logical_bytes,
            allocated_bytes,
            hard_link_count: known_count(stat.st_nlink as u128),
            fingerprint,
            identity: Some(identity),
            filesystem_identity,
            mount_identity: Some(MountIdentity { value: mount_id }),
            hard_link_key,
        }
    }

    fn error_entry(path: &Path, error: io::Error) -> WalkEntry<LinuxDirectoryHandle> {
        WalkEntry::Error(ErrorRecord {
            path: path.to_path_buf(),
            kind: error_kind_for_io(&error),
            reason: reason_for_io(&error),
            detail: error.to_string(),
        })
    }

    fn same_object(left: &libc::stat, right: &libc::stat) -> bool {
        left.st_dev == right.st_dev
            && left.st_ino == right.st_ino
            && Self::kind_from_mode(left.st_mode) == Self::kind_from_mode(right.st_mode)
    }
}

impl PlatformScanner for LinuxPlatformScanner {
    type DirectoryHandle = LinuxDirectoryHandle;

    fn platform_name(&self) -> &'static str {
        "linux"
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

        let fd = Self::open_root(root.path()).map_err(|error| {
            if matches!(
                error.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::ENOTDIR)
            ) {
                PlatformError::RootRejected(format!(
                    "root or an intermediate component is not a real directory: {}",
                    root.path().display()
                ))
            } else if error.raw_os_error() == Some(libc::ENOSYS) {
                PlatformError::Unsupported(
                    "openat2 is required for safe Linux root admission".to_string(),
                )
            } else {
                PlatformError::io(root.path(), error)
            }
        })?;
        Self::ensure_not_cancelled(cancel)?;
        let stat = Self::fstat(&fd).map_err(|error| PlatformError::io(root.path(), error))?;
        if Self::kind_from_mode(stat.st_mode) != EntryKind::Directory {
            return Err(PlatformError::RootRejected(format!(
                "root is not a directory: {}",
                root.path().display()
            )));
        }
        let mount_id = Self::mount_id_for_fd(&fd).map_err(|error| {
            PlatformError::Unsupported(format!(
                "statx mount identity unavailable for {}: {error}",
                root.path().display()
            ))
        })?;
        let metadata =
            Self::metadata_to_entry(root.path(), Self::native_name(root.path()), &stat, mount_id);
        Ok(RootAdmission::new(
            root.clone(),
            metadata,
            LinuxDirectoryHandle {
                fd,
                display_path: root.path().to_path_buf(),
                cursor: DirectoryCursor::NotStarted,
            },
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
        if limits.max_batch_entries == 0 || limits.max_batch_bytes == 0 {
            return Err(PlatformError::ResourceLimit(format!(
                "directory batch limits must be nonzero at {}",
                directory.display_path.display()
            )));
        }
        if matches!(directory.cursor, DirectoryCursor::NotStarted) {
            let duplicate = Self::duplicate_fd(&directory.fd)
                .map_err(|error| PlatformError::io(&directory.display_path, error))?;
            let raw = duplicate.as_raw_fd();
            // SAFETY: raw is a live directory descriptor. On success fdopendir
            // takes ownership, so the OwnedFd is forgotten immediately afterward.
            let stream = unsafe { libc::fdopendir(raw) };
            if stream.is_null() {
                return Err(PlatformError::io(
                    &directory.display_path,
                    io::Error::last_os_error(),
                ));
            }
            mem::forget(duplicate);
            directory.cursor = DirectoryCursor::Active {
                stream: DirectoryStream(stream),
                pending: None,
            };
        }
        let DirectoryCursor::Active { stream, pending } = &mut directory.cursor else {
            unreachable!("nonterminal directory cursor must be active");
        };
        let mut entries = Vec::new();
        let mut retained_bytes = 0usize;

        loop {
            Self::ensure_not_cancelled(cancel)?;
            let child = if let Some(child) = pending.take() {
                child
            } else {
                loop {
                    // POSIX requires errno to be cleared to distinguish EOF from error.
                    // SAFETY: __errno_location returns the calling thread's errno slot.
                    unsafe {
                        *libc::__errno_location() = 0;
                    }
                    // SAFETY: stream is live and exclusively used by this loop.
                    let raw_entry = unsafe { libc::readdir(stream.0) };
                    if raw_entry.is_null() {
                        let error = io::Error::last_os_error();
                        if error.raw_os_error() == Some(0) {
                            return Ok(DirectoryEntryBatch::complete(entries));
                        }
                        return Err(PlatformError::io(&directory.display_path, error));
                    }
                    // SAFETY: readdir returned a valid dirent whose d_name is NUL terminated.
                    let name = unsafe { CStr::from_ptr((*raw_entry).d_name.as_ptr()) }.to_bytes();
                    if name == b"." || name == b".." {
                        continue;
                    }
                    break DirectoryEntryRecord::from_parent_and_name(
                        &directory.display_path,
                        NativeName::unix(name.to_vec()),
                    )
                    .map_err(|error| PlatformError::InvalidDirectoryEntry {
                        parent: directory.display_path.clone(),
                        detail: error.to_string(),
                    })?;
                }
            };
            let record_bytes = child.estimated_retained_bytes().ok_or_else(|| {
                PlatformError::ResourceLimit(format!(
                    "directory byte accounting overflow at {}",
                    directory.display_path.display()
                ))
            })?;
            let next_bytes = retained_bytes.checked_add(record_bytes).ok_or_else(|| {
                PlatformError::ResourceLimit(format!(
                    "directory byte accounting overflow at {}",
                    directory.display_path.display()
                ))
            })?;
            if entries.is_empty() && record_bytes > limits.max_batch_bytes {
                *pending = Some(child);
                return Err(PlatformError::ResourceLimit(format!(
                    "single directory entry exceeds the retained-byte cap at {}",
                    directory.display_path.display()
                )));
            }
            if entries.len() >= limits.max_batch_entries || next_bytes > limits.max_batch_bytes {
                *pending = Some(child);
                return Ok(DirectoryEntryBatch::continued(entries));
            }
            retained_bytes = next_bytes;
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
        child
            .validate_for_parent(&parent.display_path)
            .map_err(|error| PlatformError::InvalidDirectoryEntry {
                parent: parent.display_path.clone(),
                detail: error.to_string(),
            })?;
        Self::ensure_not_cancelled(cancel)?;
        let name = match Self::child_name_c_string(&child.file_name) {
            Ok(name) => name,
            Err(error) => return Ok(Self::error_entry(&child.path, error)),
        };
        let path = child.path.clone();
        let pinned = match Self::pin_child(&parent.fd, &name) {
            Ok(fd) => fd,
            Err(error) => return Ok(Self::error_entry(&path, error)),
        };
        Self::ensure_not_cancelled(cancel)?;
        let pinned_stat = match Self::fstat(&pinned) {
            Ok(stat) => stat,
            Err(error) => return Ok(Self::error_entry(&path, error)),
        };
        let pinned_mount_id = match Self::mount_id_for_fd(&pinned) {
            Ok(value) => value,
            Err(error) => return Ok(Self::error_entry(&path, error)),
        };

        if Self::kind_from_mode(pinned_stat.st_mode) == EntryKind::Directory {
            if directory_admission == DirectoryHandleAdmission::Deny {
                return Ok(WalkEntry::Boundary(BoundaryRecord {
                    path,
                    kind: BoundaryKind::ResourceLimit,
                    reason: ReasonCode::ResourceLimit,
                    detail: "frontier limit exceeded".to_string(),
                }));
            }
            let directory_fd = match Self::open_matching_child_directory(
                &parent.fd,
                &name,
                &pinned_stat,
                pinned_mount_id,
            ) {
                Ok(fd) => fd,
                Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
                    return Ok(WalkEntry::Boundary(BoundaryRecord {
                        path,
                        kind: BoundaryKind::Mount,
                        reason: ReasonCode::UnsupportedFilesystem,
                        detail: format!(
                            "entry crosses a mount boundary (mount id {})",
                            pinned_mount_id
                        ),
                    }));
                }
                Err(error) => return Ok(Self::error_entry(&path, error)),
            };
            let metadata = Self::metadata_to_entry(
                &path,
                child.file_name.clone(),
                &pinned_stat,
                pinned_mount_id,
            );
            return Ok(WalkEntry::Directory(OpenedDirectory {
                metadata,
                handle: LinuxDirectoryHandle {
                    fd: directory_fd,
                    display_path: path,
                    cursor: DirectoryCursor::NotStarted,
                },
            }));
        }

        let metadata = Self::metadata_to_entry(
            &path,
            child.file_name.clone(),
            &pinned_stat,
            pinned_mount_id,
        );
        match metadata.kind {
            EntryKind::Directory => unreachable!("directories returned above"),
            EntryKind::File => Ok(WalkEntry::File(metadata)),
            EntryKind::Symlink => Ok(WalkEntry::Link(metadata)),
            EntryKind::ReparsePoint => Ok(WalkEntry::Boundary(BoundaryRecord {
                path,
                kind: BoundaryKind::ReparsePoint,
                reason: ReasonCode::UnsupportedFilesystem,
                detail: "directory reparse points are unsupported on linux backend".to_string(),
            })),
            EntryKind::Other => Ok(WalkEntry::Boundary(BoundaryRecord {
                path,
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    use super::*;
    use tempfile::TempDir;

    fn limits(max_entries: usize) -> DirectoryReadLimits {
        DirectoryReadLimits {
            max_batch_entries: max_entries,
            max_batch_bytes: 1024 * 1024,
        }
    }

    fn find_child(
        scanner: &LinuxPlatformScanner,
        admission: &mut RootAdmission<LinuxDirectoryHandle>,
        name: &[u8],
    ) -> DirectoryEntryRecord {
        scanner
            .enumerate_children(
                &mut admission.directory,
                &CancellationToken::new(),
                limits(64),
            )
            .unwrap()
            .entries
            .into_iter()
            .find(|entry| entry.file_name == NativeName::unix(name.to_vec()))
            .unwrap()
    }

    #[test]
    fn reject_root_symlink() {
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let scanner = LinuxPlatformScanner::new();
        let root = ScanRoot::new(link).unwrap();
        let error = scanner
            .admit_root(&root, &CancellationToken::new())
            .unwrap_err();
        assert!(matches!(error, PlatformError::RootRejected(_)));
    }

    #[test]
    fn symlink_child_is_reported_without_following() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("target"), b"payload").unwrap();
        std::os::unix::fs::symlink("target", temp.path().join("link")).unwrap();

        let scanner = LinuxPlatformScanner::new();
        let mut admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path().to_path_buf()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let child = find_child(&scanner, &mut admission, b"link");
        let entry = scanner
            .inspect_child(&admission.directory, &child, &CancellationToken::new())
            .unwrap();

        assert!(matches!(entry, WalkEntry::Link(_)));
    }

    #[test]
    fn denied_directory_admission_classifies_without_opening_a_retained_handle() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("directory")).unwrap();
        fs::write(temp.path().join("file"), b"payload").unwrap();
        std::os::unix::fs::symlink("file", temp.path().join("link")).unwrap();

        let scanner = LinuxPlatformScanner::new();
        let mut admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path().to_path_buf()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let children = scanner
            .enumerate_children(
                &mut admission.directory,
                &CancellationToken::new(),
                limits(64),
            )
            .unwrap()
            .entries;

        for child in children {
            let name = child.file_name.clone();
            let entry = scanner
                .inspect_child_with_directory_admission(
                    &admission.directory,
                    &child,
                    &CancellationToken::new(),
                    DirectoryHandleAdmission::Deny,
                )
                .unwrap();
            if name == NativeName::unix(b"directory".to_vec()) {
                assert!(matches!(
                    entry,
                    WalkEntry::Boundary(BoundaryRecord {
                        kind: BoundaryKind::ResourceLimit,
                        ..
                    })
                ));
            } else if name == NativeName::unix(b"file".to_vec()) {
                assert!(matches!(entry, WalkEntry::File(_)));
            } else if name == NativeName::unix(b"link".to_vec()) {
                assert!(matches!(entry, WalkEntry::Link(_)));
            }
        }
    }

    #[test]
    fn direct_child_inspection_rejects_forged_parent_binding() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("safe"), b"safe").unwrap();
        let scanner = LinuxPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path().to_path_buf()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let forged = DirectoryEntryRecord {
            path: temp.path().join("different"),
            file_name: NativeName::unix(b"safe".to_vec()),
        };

        let error = scanner
            .inspect_child(&admission.directory, &forged, &CancellationToken::new())
            .unwrap_err();

        assert!(matches!(error, PlatformError::InvalidDirectoryEntry { .. }));
    }

    #[test]
    fn pinned_file_identity_and_mount_survive_name_replacement() {
        let temp = TempDir::new().unwrap();
        let child_path = temp.path().join("child");
        let displaced_path = temp.path().join("displaced");
        fs::write(&child_path, b"original").unwrap();

        let scanner = LinuxPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path().to_path_buf()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let name = CString::new("child").unwrap();
        let pinned = LinuxPlatformScanner::pin_child(&admission.directory.fd, &name).unwrap();
        let before = LinuxPlatformScanner::fstat(&pinned).unwrap();
        let before_mount = LinuxPlatformScanner::mount_id_for_fd(&pinned).unwrap();

        fs::rename(&child_path, &displaced_path).unwrap();
        fs::write(&child_path, b"replacement-is-different").unwrap();

        let after = LinuxPlatformScanner::fstat(&pinned).unwrap();
        let after_mount = LinuxPlatformScanner::mount_id_for_fd(&pinned).unwrap();
        let replacement = fs::metadata(&child_path).unwrap();

        assert!(LinuxPlatformScanner::same_object(&before, &after));
        assert_eq!(before_mount, after_mount);
        assert_eq!(after.st_size, 8);
        assert_ne!(after.st_ino, replacement.ino());
    }

    #[test]
    fn directory_reopen_rejects_replacement_after_pin() {
        let temp = TempDir::new().unwrap();
        let child_path = temp.path().join("child");
        let displaced_path = temp.path().join("displaced");
        fs::create_dir(&child_path).unwrap();

        let scanner = LinuxPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path().to_path_buf()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let name = CString::new("child").unwrap();
        let pinned = LinuxPlatformScanner::pin_child(&admission.directory.fd, &name).unwrap();
        let pinned_stat = LinuxPlatformScanner::fstat(&pinned).unwrap();
        let pinned_mount = LinuxPlatformScanner::mount_id_for_fd(&pinned).unwrap();

        fs::rename(&child_path, &displaced_path).unwrap();
        fs::create_dir(&child_path).unwrap();

        let error = LinuxPlatformScanner::open_matching_child_directory(
            &admission.directory.fd,
            &name,
            &pinned_stat,
            pinned_mount,
        )
        .unwrap_err();

        assert!(error.to_string().contains("changed between pinning"));
    }

    #[test]
    fn nested_mount_is_a_boundary_before_enumerable_handle_admission() {
        if !Path::new("/proc").is_dir() {
            return;
        }
        let scanner = LinuxPlatformScanner::new();
        let admission = scanner
            .admit_root(
                &ScanRoot::new(PathBuf::from("/")).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let name = CString::new("proc").unwrap();
        let pinned = LinuxPlatformScanner::pin_child(&admission.directory.fd, &name).unwrap();
        let root_mount = admission.metadata.mount_identity.as_ref().unwrap().value;
        let proc_mount = LinuxPlatformScanner::mount_id_for_fd(&pinned).unwrap();
        if root_mount == proc_mount {
            return;
        }
        let child = DirectoryEntryRecord::from_parent_and_name(
            Path::new("/"),
            NativeName::unix(b"proc".to_vec()),
        )
        .unwrap();

        let entry = scanner
            .inspect_child(&admission.directory, &child, &CancellationToken::new())
            .unwrap();

        assert!(matches!(
            entry,
            WalkEntry::Boundary(BoundaryRecord {
                kind: BoundaryKind::Mount,
                ..
            })
        ));
    }

    #[test]
    fn admitted_descriptor_survives_parent_path_swap() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        let moved = temp.path().join("moved");
        fs::create_dir_all(root.join("child")).unwrap();
        fs::write(root.join("child/safe"), b"safe").unwrap();

        let scanner = LinuxPlatformScanner::new();
        let mut admission = scanner
            .admit_root(
                &ScanRoot::new(root.clone()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        fs::rename(&root, &moved).unwrap();
        fs::create_dir_all(root.join("child")).unwrap();
        fs::write(root.join("child/evil"), b"evil").unwrap();

        let child = find_child(&scanner, &mut admission, b"child");
        let WalkEntry::Directory(mut opened) = scanner
            .inspect_child(&admission.directory, &child, &CancellationToken::new())
            .unwrap()
        else {
            panic!("expected descriptor-relative child directory");
        };
        let names: Vec<_> = scanner
            .enumerate_children(&mut opened.handle, &CancellationToken::new(), limits(64))
            .unwrap()
            .entries
            .into_iter()
            .map(|entry| entry.file_name)
            .collect();

        assert!(names.contains(&NativeName::unix(b"safe".to_vec())));
        assert!(!names.contains(&NativeName::unix(b"evil".to_vec())));
    }

    #[test]
    fn admit_root_honors_cancellation() {
        let temp = TempDir::new().unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = LinuxPlatformScanner::new()
            .admit_root(&ScanRoot::new(temp.path().to_path_buf()).unwrap(), &cancel)
            .unwrap_err();
        assert!(matches!(error, PlatformError::Cancelled));
    }

    #[test]
    fn file_metadata_reports_hard_link_identity() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("file"), b"hello world").unwrap();
        fs::hard_link(temp.path().join("file"), temp.path().join("second")).unwrap();

        let scanner = LinuxPlatformScanner::new();
        let mut admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path().to_path_buf()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let children = scanner
            .enumerate_children(
                &mut admission.directory,
                &CancellationToken::new(),
                limits(64),
            )
            .unwrap();
        let inspect = |name: &[u8]| {
            let child = children
                .entries
                .iter()
                .find(|entry| entry.file_name == NativeName::unix(name.to_vec()))
                .unwrap();
            let WalkEntry::File(metadata) = scanner
                .inspect_child(&admission.directory, child, &CancellationToken::new())
                .unwrap()
            else {
                panic!("expected file");
            };
            metadata
        };
        let first = inspect(b"file");
        let second = inspect(b"second");
        assert_eq!(first.hard_link_key, second.hard_link_key);
        assert_eq!(first.allocated_bytes, second.allocated_bytes);
    }

    #[test]
    fn cancellation_stops_enumeration() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("child")).unwrap();
        let scanner = LinuxPlatformScanner::new();
        let mut admission = scanner
            .admit_root(
                &ScanRoot::new(temp.path().to_path_buf()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = scanner
            .enumerate_children(&mut admission.directory, &cancel, limits(16))
            .unwrap_err();
        assert!(matches!(error, PlatformError::Cancelled));
    }

    #[test]
    fn enumeration_continues_at_entry_cap_and_enforces_unfit_byte_cap() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("a"), b"a").unwrap();
        fs::write(temp.path().join("b"), b"b").unwrap();
        let scanner = LinuxPlatformScanner::new();

        let mut entry_limited = scanner
            .admit_root(
                &ScanRoot::new(temp.path().to_path_buf()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        let first = scanner
            .enumerate_children(
                &mut entry_limited.directory,
                &CancellationToken::new(),
                limits(1),
            )
            .unwrap();
        assert_eq!(first.entries.len(), 1);
        assert!(!first.end_of_directory);
        let second = scanner
            .enumerate_children(
                &mut entry_limited.directory,
                &CancellationToken::new(),
                limits(1),
            )
            .unwrap();
        assert_eq!(second.entries.len(), 1);
        assert!(second.end_of_directory);

        let mut byte_limited = scanner
            .admit_root(
                &ScanRoot::new(temp.path().to_path_buf()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(matches!(
            scanner.enumerate_children(
                &mut byte_limited.directory,
                &CancellationToken::new(),
                DirectoryReadLimits {
                    max_batch_entries: 16,
                    max_batch_bytes: 1,
                },
            ),
            Err(PlatformError::ResourceLimit(_))
        ));
    }

    #[test]
    fn multi_batch_continuation_matches_single_batch_without_loss_or_duplicates() {
        let temp = TempDir::new().unwrap();
        for name in ["alpha", "beta", "gamma", "delta", "epsilon"] {
            fs::write(temp.path().join(name), name.as_bytes()).unwrap();
        }
        let scanner = LinuxPlatformScanner::new();
        let root = ScanRoot::new(temp.path().to_path_buf()).unwrap();

        let mut single = scanner
            .admit_root(&root, &CancellationToken::new())
            .unwrap();
        let single = scanner
            .enumerate_children(&mut single.directory, &CancellationToken::new(), limits(64))
            .unwrap();
        assert!(single.end_of_directory);

        let mut paged = scanner
            .admit_root(&root, &CancellationToken::new())
            .unwrap();
        let mut paged_entries = Vec::new();
        let mut batch_count = 0;
        loop {
            let batch = scanner
                .enumerate_children(&mut paged.directory, &CancellationToken::new(), limits(2))
                .unwrap();
            batch_count += 1;
            assert!(!batch.entries.is_empty() || batch.end_of_directory);
            paged_entries.extend(batch.entries);
            if batch.end_of_directory {
                break;
            }
        }

        assert!(batch_count > 1);
        assert_eq!(paged_entries, single.entries);
    }

    #[test]
    fn root_mount_identity_comes_from_statx() {
        let temp = TempDir::new().unwrap();
        let admission = LinuxPlatformScanner::new()
            .admit_root(
                &ScanRoot::new(temp.path().to_path_buf()).unwrap(),
                &CancellationToken::new(),
            )
            .unwrap();
        assert!(admission.metadata.mount_identity.is_some());
    }
}
