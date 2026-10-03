//! Unix no-follow operations beneath retained cache directory descriptors.

use super::{AccountedFile, EntryMetadata, with_cache_io, write_json};
#[cfg(all(test, target_os = "linux"))]
mod linux_tests;
#[cfg(any(target_os = "linux", test))]
mod mount;
#[cfg(test)]
use super::{Limits, ReadBudget};
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

/// The publishing process owns the critical section. CLOEXEC prevents inheritance after exec,
/// but an in-progress fork/spawn can still hold a duplicate open file description. Closing only
/// our descriptor would leave its flock alive in that child until exec/exit.
/// Releases this invocation's cache publication exclusion when dropped.
pub struct LockGuard {
    file: File,
    owner: libc::pid_t,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // An inherited Rust guard must not unlock its parent's live critical section. Parent
        // release explicitly unlocks before closing; a child merely closes its duplicate.
        // SAFETY: getpid takes no arguments; the guard owns the still-live locked descriptor.
        if unsafe { libc::getpid() } == self.owner {
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

impl LockGuard {
    /// Accounts the held lock without reopening a potentially share-denying lock file.
    pub(crate) fn encoded_bytes(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
}

pub(super) fn same_observation(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

/// A private cache directory retained by native handle; display paths are not reopened.
pub struct Directory {
    fd: OwnedFd,
    // Handle lifetime pins the captured mount; do not persist/recover this from display paths.
    #[cfg(target_os = "linux")]
    mount: mount::Identity,
}

impl Directory {
    fn from_owned(fd: OwnedFd) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        let mount = mount::for_fd(fd.as_raw_fd())?;
        Ok(Self {
            fd,
            #[cfg(target_os = "linux")]
            mount,
        })
    }

    /// Duplicates retained authority without resolving a display pathname again.
    pub(crate) fn retain(&self) -> io::Result<Self> {
        self.private()?;
        Self::from_owned(self.fd.try_clone()?)
    }

    /// Verifies that a retained child still has the same binding beneath this parent.
    pub(crate) fn same_child(&self, name: &str, expected: &Self) -> io::Result<bool> {
        let actual = self.child(name)?.private()?;
        let expected = expected.private()?;
        Ok(actual.dev() == expected.dev() && actual.ino() == expected.ino())
    }

    /// Reads only relative no-follow metadata for complete cache quota accounting.
    pub(crate) fn accounting_metadata(&self, name: &str) -> io::Result<AccountedFile> {
        with_cache_io(|| self.accounting_metadata_guarded(name))
    }

    fn accounting_metadata_guarded(&self, name: &str) -> io::Result<AccountedFile> {
        let parent = self.private()?;
        let name = component(name)?;
        #[cfg(target_os = "linux")]
        {
            let (mount, metadata) = mount::relative(self.fd.as_raw_fd(), &name)?;
            self.mount.require_same(mount)?;
            let device = libc::makedev(metadata.stx_dev_major, metadata.stx_dev_minor);
            let mode = u32::from(metadata.stx_mode);
            // One no-follow statx result supplies the ledger fields and mount admission.
            // It is not an atomic snapshot against concurrent chmod/chown/namespace changes.
            if mode & libc::S_IFMT != libc::S_IFREG
                || metadata.stx_uid != unsafe { libc::geteuid() }
                || mode & 0o077 != 0
                || metadata.stx_nlink != 1
                || device != parent.dev()
            {
                return Err(io::Error::other(
                    "cache accounting requires private single-link regular files on the retained mount",
                ));
            }
            Ok(AccountedFile {
                bytes: metadata.stx_size,
                accessed: (
                    metadata.stx_atime.tv_sec,
                    i64::from(metadata.stx_atime.tv_nsec),
                ),
                identity: [device, metadata.stx_ino, u64::from(metadata.stx_nlink)],
                changed: (
                    metadata.stx_ctime.tv_sec,
                    i64::from(metadata.stx_ctime.tv_nsec),
                ),
            })
        }
        #[cfg(not(target_os = "linux"))]
        self.accounting_metadata_unix(parent, name)
    }

    #[cfg(not(target_os = "linux"))]
    fn accounting_metadata_unix(
        &self,
        parent: Metadata,
        name: CString,
    ) -> io::Result<AccountedFile> {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: validated basename under a retained private directory, initialized on success.
        if unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatat initialized the stat without following a link.
        let metadata = unsafe { metadata.assume_init() };
        // libc stat widths differ between Darwin and Linux; the ledger uses fixed u64 IDs.
        #[allow(clippy::unnecessary_cast)]
        let device = metadata.st_dev as u64;
        #[allow(clippy::unnecessary_cast)]
        let links = metadata.st_nlink as u64;
        // SAFETY: geteuid has no arguments. Unknown/shared/special objects cannot contribute
        // a seemingly complete total or become disposable generation metadata.
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
            || metadata.st_uid != unsafe { libc::geteuid() }
            || metadata.st_mode & 0o077 != 0
            || metadata.st_nlink != 1
            || device != parent.dev()
            || metadata.st_size < 0
        {
            return Err(io::Error::other(
                "cache accounting requires private single-link regular files on the retained device",
            ));
        }
        #[cfg(target_os = "macos")]
        if metadata.st_flags & 0x4000_0000 != 0 {
            // Public SDK sys/stat.h SF_DATALESS (libc omits it). Metadata accounting must
            // refuse this known provider boundary, without opening its data stream.
            return Err(io::Error::other("dataless cache entry"));
        }
        Ok(AccountedFile {
            bytes: metadata.st_size as u64,
            accessed: (metadata.st_atime, metadata.st_atime_nsec),
            identity: [device, metadata.st_ino, links],
            changed: (metadata.st_ctime, metadata.st_ctime_nsec),
        })
    }

    fn private(&self) -> io::Result<Metadata> {
        #[cfg(target_os = "linux")]
        self.mount
            .require_same(mount::for_fd(self.fd.as_raw_fd())?)?;
        let metadata = File::from(self.fd.try_clone()?).metadata()?;
        // SAFETY: geteuid has no pointer arguments. The retained descriptor remains authority.
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(io::Error::other(
                "cache directory is not current-user private",
            ));
        }
        Ok(metadata)
    }

    /// Opens an absolute no-follow cache root, optionally creating private components.
    pub fn open(path: &Path, create: bool) -> io::Result<Self> {
        with_cache_io(|| Self::open_guarded(path, create))
    }

    fn open_guarded(path: &Path, create: bool) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::other("cache path must be absolute"));
        }
        let slash = c"/";
        // SAFETY: slash is NUL terminated; returned descriptor is checked and owned below.
        let fd = unsafe {
            libc::open(
                slash.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        let mut current = Self::from_owned(owned(fd)?)?;
        for part in path.components() {
            let Component::Normal(part) = part else {
                if matches!(part, Component::RootDir | Component::CurDir) {
                    continue;
                }
                return Err(io::Error::other("invalid cache path component"));
            };
            let name = CString::new(part.as_encoded_bytes()).map_err(io::Error::other)?;
            let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
            // SAFETY: retained directory plus one native component; no path authority is reconstructed.
            let mut next = unsafe { libc::openat(current.fd.as_raw_fd(), name.as_ptr(), flags) };
            if next < 0 && create && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                // SAFETY: mkdirat creates only this basename beneath the retained directory.
                let result = unsafe { libc::mkdirat(current.fd.as_raw_fd(), name.as_ptr(), 0o700) };
                if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: same no-follow binding as the initial open; another creator may have raced.
                next = unsafe { libc::openat(current.fd.as_raw_fd(), name.as_ptr(), flags) };
            }
            current = Self::from_owned(owned(next)?)?;
        }
        let metadata = File::from(current.fd.try_clone()?).metadata()?;
        // SAFETY: geteuid has no pointer arguments or side effects.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "cache directory is not current-user private",
            ));
        }
        Ok(current)
    }

    /// Opens a private child directory relative to this retained handle.
    pub fn child(&self, name: &str) -> io::Result<Self> {
        with_cache_io(|| self.child_guarded(name))
    }

    fn child_guarded(&self, name: &str) -> io::Result<Self> {
        self.private()?;
        let name = component(name)?;
        // SAFETY: no-follow basename beneath this retained directory; returned fd is owned.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        let child = Self::from_owned(owned(fd)?)?;
        #[cfg(target_os = "linux")]
        self.mount.require_same(child.mount)?;
        let meta = File::from(child.fd.try_clone()?).metadata()?;
        if meta.dev() != self.private()?.dev() {
            return Err(io::Error::other("cache child crossed a volume boundary"));
        }
        // SAFETY: geteuid has no pointer arguments.
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(io::Error::other("cache child directory is not private"));
        }
        Ok(child)
    }

    /// Creates or admits a private child beneath this retained directory.
    pub fn create_child(&self, name: &str) -> io::Result<Self> {
        with_cache_io(|| self.create_child_guarded(name))
    }

    fn create_child_guarded(&self, name: &str) -> io::Result<Self> {
        self.private()?;
        let native = component(name)?;
        // SAFETY: this is one basename beneath a live parent; mkdir never follows a link.
        if unsafe { libc::mkdirat(self.fd.as_raw_fd(), native.as_ptr(), 0o700) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
        {
            return Err(io::Error::last_os_error());
        }
        self.child(name)
    }

    /// Nonblocking advisory serialization of publication and eviction across invocations.
    /// Contention makes this disposable cache unavailable rather than delaying a scan.
    pub fn lock(&self) -> io::Result<LockGuard> {
        with_cache_io(|| self.lock_guarded())
    }

    fn lock_guarded(&self) -> io::Result<LockGuard> {
        self.private()?;
        // SAFETY: a fixed private basename opened beneath the retained parent, never a link.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c".lock".as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0o600,
            )
        };
        let file = File::from(owned(fd)?);
        #[cfg(target_os = "linux")]
        self.mount.require_same(mount::for_fd(file.as_raw_fd())?)?;
        let meta = file.metadata()?;
        // SAFETY: geteuid has no arguments; flock is applied to the live owned descriptor.
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.nlink() != 1
            || meta.mode() & 0o077 != 0
            || meta.dev() != self.private()?.dev()
        {
            return Err(io::Error::other("invalid cache lock file"));
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(LockGuard {
            file,
            // SAFETY: getpid has no arguments and records the process acquiring this flock.
            owner: unsafe { libc::getpid() },
        })
    }

    pub(super) fn open_file(&self, name: &str) -> io::Result<File> {
        let parent = self.private()?;
        let name = component(name)?;
        // Nonblocking prevents a substituted FIFO from stalling before the type check.
        // SAFETY: validated basename and a live retained parent; the opened fd is checked below.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        let file = File::from(owned(fd)?);
        #[cfg(target_os = "linux")]
        self.mount.require_same(mount::for_fd(file.as_raw_fd())?)?;
        let metadata = file.metadata()?;
        // SAFETY: geteuid has no arguments.
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
            || metadata.dev() != parent.dev()
        {
            return Err(io::Error::other(
                "cache entry is not a private single-link regular file on the retained device",
            ));
        }
        #[cfg(target_os = "macos")]
        {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: live owned descriptor, initialized stat on success; no pathname reopen.
            if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful fstat initialized the complete struct.
            if unsafe { stat.assume_init() }.st_flags & 0x4000_0000 != 0 {
                return Err(io::Error::other("dataless cache entry"));
            }
        }
        Ok(file)
    }

    /// Atomically publishes bounded JSON; this disposable cache write is not crash durable.
    pub fn write_json(
        &self,
        name: &str,
        value: &impl serde::Serialize,
        cap: usize,
    ) -> io::Result<()> {
        self.publish(name, |file| write_json(file, value, cap))
    }

    /// Runs the encoder on an exclusively created private temporary, then publishes it
    /// beneath the same retained parent. Failure removes only this invocation's temporary.
    pub(crate) fn publish(
        &self,
        name: &str,
        encode: impl FnOnce(&mut File) -> io::Result<()>,
    ) -> io::Result<()> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let destination = component(name)?;
        let temp = component(&format!(
            ".sweepx-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))?;
        let mut created = false;
        let prepared = with_cache_io(|| {
            self.private()?;
            match self.open_file(name) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            // SAFETY: exclusive no-follow creation cannot truncate any existing entry.
            let fd = unsafe {
                libc::openat(
                    self.fd.as_raw_fd(),
                    temp.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            let mut file = File::from(owned(fd)?);
            created = true;
            #[cfg(target_os = "linux")]
            self.mount.require_same(mount::for_fd(file.as_raw_fd())?)?;
            encode(&mut file)?;
            Ok(file)
        });
        // A restoration failure must be known before rename, including current.json. A
        // successful encoder alone cannot turn a failed I/O-policy interval into publication.
        let result = prepared.and_then(|_file| {
            // Disposable cache publication is atomic but not crash durable. No data stream
            // access occurs after policy restoration; only the retained-parent name commit.
            self.private()?;
            #[cfg(target_os = "linux")]
            {
                let observed =
                    self.accounting_metadata_guarded(temp.to_str().map_err(io::Error::other)?)?;
                self.mount.require_same(mount::for_fd(_file.as_raw_fd())?)?;
                let expected = _file.metadata()?;
                if observed.identity != [expected.dev(), expected.ino(), expected.nlink()]
                    || observed.bytes != expected.len()
                    || observed.changed != (expected.ctime(), expected.ctime_nsec())
                {
                    return Err(io::Error::other("cache temporary binding changed"));
                }
            }
            // SAFETY: both validated names live beneath the same retained directory.
            if unsafe {
                libc::renameat(
                    self.fd.as_raw_fd(),
                    temp.as_ptr(),
                    self.fd.as_raw_fd(),
                    destination.as_ptr(),
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
        if result.is_err() && created {
            // SAFETY: cleanup only after this invocation's exclusive temporary creation.
            // A pre-existing temp collision must never be removed.
            unsafe {
                libc::unlinkat(self.fd.as_raw_fd(), temp.as_ptr(), 0);
            }
        }
        result
    }

    /// Removes a managed cache basename without following its target.
    pub fn remove(&self, name: &str) -> io::Result<()> {
        with_cache_io(|| self.remove_guarded(name))
    }

    fn remove_guarded(&self, name: &str) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        self.accounting_metadata_guarded(name)?;
        self.private()?;
        let name = component(name)?;
        // SAFETY: unlink only removes this entry beneath the retained parent, never follows it.
        if unsafe { libc::unlinkat(self.fd.as_raw_fd(), name.as_ptr(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Reads native encoded length and LRU time for a managed cache basename.
    pub fn metadata(&self, name: &str) -> io::Result<EntryMetadata> {
        with_cache_io(|| self.metadata_guarded(name))
    }

    fn metadata_guarded(&self, name: &str) -> io::Result<EntryMetadata> {
        #[cfg(target_os = "linux")]
        {
            let metadata = self.accounting_metadata_guarded(name)?;
            Ok(EntryMetadata {
                bytes: metadata.bytes,
                accessed: metadata.accessed,
            })
        }
        #[cfg(not(target_os = "linux"))]
        self.metadata_unix(name)
    }

    #[cfg(not(target_os = "linux"))]
    fn metadata_unix(&self, name: &str) -> io::Result<EntryMetadata> {
        self.private()?;
        let name = component(name)?;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: validated basename and live parent; success initializes the native stat.
        if unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fstatat initialized metadata and did not follow a link.
        let metadata = unsafe { metadata.assume_init() };
        Ok(EntryMetadata {
            bytes: metadata.st_size.max(0) as u64,
            accessed: (metadata.st_atime, metadata.st_atime_nsec),
        })
    }

    /// Visits managed UTF-8 names within a fixed native enumeration budget.
    pub fn entries(&self, mut visit: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        self.entries_all(|name| name.map_or(Ok(()), &mut visit))
    }

    pub(crate) fn entries_all(
        &self,
        visit: impl FnMut(Option<&str>) -> io::Result<()>,
    ) -> io::Result<()> {
        with_cache_io(|| self.entries_all_guarded(visit))
    }

    fn entries_all_guarded(
        &self,
        mut visit: impl FnMut(Option<&str>) -> io::Result<()>,
    ) -> io::Result<()> {
        self.private()?;
        // Opening '.' gives an independent directory offset; dup would share offsets between callers.
        // SAFETY: this is the already retained directory, not a display path.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        let fd = owned(fd)?;
        #[cfg(target_os = "linux")]
        self.mount.require_same(mount::for_fd(fd.as_raw_fd())?)?;
        use std::os::fd::IntoRawFd;
        // SAFETY: fdopendir takes ownership on success; close the raw fd ourselves on failure.
        let raw = fd.into_raw_fd();
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: fdopendir failed and did not take ownership.
            unsafe {
                libc::close(raw);
            }
            return Err(error);
        }
        struct Stream(*mut libc::DIR);
        impl Drop for Stream {
            fn drop(&mut self) {
                // SAFETY: Stream owns the successfully opened directory stream.
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let stream = Stream(stream);
        let mut remaining = super::ENUMERATION_ENTRY_LIMIT;
        loop {
            // SAFETY: stream is live; each d_name is read before the next readdir invalidates it.
            unsafe {
                #[cfg(target_os = "macos")]
                {
                    *libc::__error() = 0;
                }
                #[cfg(target_os = "linux")]
                {
                    *libc::__errno_location() = 0;
                }
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(0) {
                    return Err(error);
                }
                break;
            }
            remaining = remaining
                .checked_sub(1)
                .ok_or_else(|| io::Error::other("cache enumeration budget exceeded"))?;
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            visit(std::str::from_utf8(bytes).ok())?;
        }
        Ok(())
    }
}

fn owned(fd: i32) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn component(name: &str) -> io::Result<CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(io::Error::other("invalid cache basename"));
    }
    CString::new(name).map_err(io::Error::other)
}

pub(super) fn touch_accessed(file: &File) {
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_NOW,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
    ];
    // SAFETY: file is live and times contains two initialized native timespec values.
    unsafe {
        libc::futimens(file.as_raw_fd(), times.as_ptr());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    unsafe extern "C" {
        fn getiopolicy_np(kind: i32, scope: i32) -> i32;
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cache_encoders_readers_and_enumeration_observe_native_off_policy() {
        use std::io::Write;
        let (_guard, path, directory) = directory();
        let previous = unsafe { getiopolicy_np(3, 1) };
        directory
            .publish("data", |file| {
                assert_eq!(unsafe { getiopolicy_np(3, 1) }, 1);
                file.write_all(b"\"independent bytes\"")
            })
            .unwrap();
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
        let read = ReadBudget::new(Limits::default())
            .read::<String>(&directory, "data", Limits::default(), |value| {
                assert_eq!(unsafe { getiopolicy_np(3, 1) }, 1);
                value.capacity()
            })
            .unwrap();
        assert_eq!(read, "independent bytes");
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
        let mut observed = std::collections::BTreeSet::new();
        directory
            .entries_all(|name| {
                assert_eq!(unsafe { getiopolicy_np(3, 1) }, 1);
                observed.insert(name.unwrap().to_owned());
                Ok(())
            })
            .unwrap();
        let ordinary: std::collections::BTreeSet<_> = std::fs::read_dir(&path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(observed, ordinary);
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn restoration_phase_failure_cannot_advance_pointer_or_keep_a_temporary() {
        use std::io::Write;
        let (_guard, path, directory) = directory();
        directory
            .publish("current.json", |file| file.write_all(b"old pointer bytes"))
            .unwrap();
        let before = std::fs::read(path.join("current.json")).unwrap();
        let previous = unsafe { getiopolicy_np(3, 1) };
        let error = directory
            .publish("current.json", |file| {
                file.write_all(b"new pointer bytes")?;
                assert_eq!(unsafe { getiopolicy_np(3, 1) }, 1);
                super::super::FAIL_RESTORE_ONCE.with(|flag| flag.set(true));
                Ok(())
            })
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "injected cache policy restoration failure"
        );
        assert_eq!(std::fs::read(path.join("current.json")).unwrap(), before);
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
        let error = directory
            .publish("current.json", |_| {
                super::super::FAIL_RESTORE_ONCE.with(|flag| flag.set(true));
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "controlled encoder error",
                ))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "controlled encoder error");
        assert_eq!(std::fs::read(path.join("current.json")).unwrap(), before);
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn restoration_phase_failure_discards_both_cache_reader_results() {
        let (_guard, path, directory) = directory();
        directory.write_json("data", &"payload", 64).unwrap();
        let before = std::fs::read(path.join("data")).unwrap();
        let previous = unsafe { getiopolicy_np(3, 1) };
        super::super::FAIL_RESTORE_ONCE.with(|flag| flag.set(true));
        assert!(directory.read_bytes("data", 64).is_err());
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
        let read = ReadBudget::new(Limits::default()).read::<String>(
            &directory,
            "data",
            Limits::default(),
            |value| {
                super::super::FAIL_RESTORE_ONCE.with(|flag| flag.set(true));
                value.capacity()
            },
        );
        assert!(read.is_none());
        assert_eq!(std::fs::read(path.join("data")).unwrap(), before);
        assert_eq!(unsafe { getiopolicy_np(3, 1) }, previous);
    }

    #[test]
    fn parent_lock_release_does_not_wait_for_an_inherited_child_descriptor() {
        let (_fixture, _path, directory) = directory();
        let lock = directory.lock().unwrap();
        let mut pipe = [-1; 2];
        // SAFETY: valid two-int output buffer; both descriptors get RAII owners below.
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        // The child makes only async-signal-safe syscalls until _exit, never touching Rust
        // allocation, assertions or the test framework after a multithreaded-process fork.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(writer.as_raw_fd());
                let mut byte = 0u8;
                libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
                libc::_exit(0);
            }
        }
        drop(reader);
        struct Child {
            pid: libc::pid_t,
            release: Option<OwnedFd>,
        }
        impl Drop for Child {
            fn drop(&mut self) {
                // EOF releases this task-owned child on success or assertion unwinding. Bound
                // shutdown and signal only this known child if the host cannot schedule it.
                self.release.take();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                loop {
                    let waited =
                        unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), libc::WNOHANG) };
                    if waited == self.pid {
                        return;
                    }
                    if waited < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                    {
                        return;
                    }
                    if std::time::Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                unsafe { libc::kill(self.pid, libc::SIGKILL) };
                while unsafe { libc::waitpid(self.pid, std::ptr::null_mut(), 0) } < 0
                    && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                {
                }
            }
        }
        let child = Child {
            pid,
            release: Some(writer),
        };
        assert!(
            directory.lock().is_err(),
            "a live publishing guard must remain exclusive"
        );
        drop(lock);
        let _next = directory
            .lock()
            .expect("the parent finished even though the child keeps its inherited descriptor");
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            0
        );
        drop(child);
    }
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn directory() -> (tempfile::TempDir, std::path::PathBuf, Directory) {
        let guard = tempfile::TempDir::new().unwrap();
        let path = guard.path().canonicalize().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = Directory::open(&path, false).unwrap();
        (guard, path, directory)
    }

    #[test]
    fn input_allowance_is_shared_and_oversize_files_are_not_parsed() {
        let (_guard, path, directory) = directory();
        directory.write_json("a", &"1234", 64).unwrap();
        directory.write_json("b", &"5678", 64).unwrap();
        let limits = Limits {
            entry_bytes: 64,
            input_bytes: 10,
            retained_bytes: 1024,
            ..Limits::default()
        };
        assert_eq!(std::fs::metadata(path.join("a")).unwrap().len(), 6);
        let mut budget = ReadBudget::new(limits);
        assert_eq!(
            budget
                .read::<String>(&directory, "a", limits, |text| text.capacity())
                .unwrap(),
            "1234"
        );
        assert!(
            budget
                .read::<String>(&directory, "b", limits, |_| 0)
                .is_none()
        );
        let file = File::create(path.join("large")).unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        file.set_len(8 * 1024 * 1024).unwrap();
        assert!(
            ReadBudget::new(limits)
                .read::<String>(&directory, "large", limits, |_| panic!(
                    "oversize must not parse"
                ))
                .is_none()
        );
    }

    #[test]
    fn rejected_write_preserves_previous_generation_and_cleans_its_temporary() {
        let (_guard, path, directory) = directory();
        directory.write_json("fact", &"old", 64).unwrap();
        let before = std::fs::read(path.join("fact")).unwrap();
        assert!(directory.write_json("fact", &"a".repeat(1000), 8).is_err());
        assert_eq!(std::fs::read(path.join("fact")).unwrap(), before);
        assert_eq!(std::fs::read_dir(path).unwrap().count(), 1);
    }

    #[test]
    fn linked_aliased_public_and_special_cache_entries_are_refused() {
        let (_guard, path, directory) = directory();
        directory.write_json("original", &"valid", 128).unwrap();
        symlink(path.join("original"), path.join("link")).unwrap();
        std::fs::hard_link(path.join("original"), path.join("alias")).unwrap();
        directory.write_json("public", &"valid", 128).unwrap();
        std::fs::set_permissions(path.join("public"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let fifo = CString::new(path.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: isolated fixture path is NUL terminated and used only for this FIFO.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        for name in ["link", "original", "alias", "public", "fifo"] {
            let limits = Limits::default();
            assert!(
                ReadBudget::new(limits)
                    .read::<String>(&directory, name, limits, |_| 0)
                    .is_none(),
                "{name}"
            );
        }
        let linked = path.join("linked-parent");
        symlink(&path, &linked).unwrap();
        assert!(Directory::open(&linked, false).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Directory::open(&path, false).is_err());
    }

    #[test]
    fn retained_parent_and_nonblocking_lock_survive_path_replacement() {
        let (_guard, path, base) = directory();
        let original = path.join("cache");
        std::fs::create_dir(&original).unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = base.child("cache").unwrap();
        let lock = directory.lock().unwrap();
        assert!(directory.lock().is_err());
        drop(lock);
        assert!(directory.lock().is_ok());
        let retained = path.join("retained");
        std::fs::rename(&original, &retained).unwrap();
        std::fs::create_dir(&original).unwrap();
        directory.write_json("fact", &"old-parent", 128).unwrap();
        assert!(retained.join("fact").exists());
        assert!(!original.join("fact").exists());
    }

    #[test]
    fn enumeration_charges_unknown_names_and_stops_under_a_fixed_allowance() {
        let (_guard, path, directory) = directory();
        // Independent literal workload exceeds the specified 4,096 observations, including
        // unknown entries and native dot entries. No inventory or per-unknown-file stat is kept.
        for index in 0..4097 {
            File::create(path.join(format!("unknown-{index}"))).unwrap();
        }
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 4097);
        let mut visits = 0;
        let error = directory
            .entries(|_| {
                visits += 1;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "cache enumeration budget exceeded");
        assert!(visits <= 4096);
        assert_eq!(std::fs::read_dir(path).unwrap().count(), 4097);
    }
}
