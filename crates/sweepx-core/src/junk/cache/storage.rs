//! Native, bounded I/O for the disposable junk-cache namespace.
//!
//! Directory handles retain authority across path renames. Every path component is opened
//! without following links, and only private regular cache files are read. Publication uses
//! an exclusive temporary file and rename; this cache is not a durable operation journal.

use std::ffi::{CStr, CString};
use std::fs::{File, Metadata};
use std::io::{self, BufWriter, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

/// The publishing process owns the critical section. CLOEXEC prevents inheritance after exec,
/// but an in-progress fork/spawn can still hold a duplicate open file description. Closing only
/// our descriptor would leave its flock alive in that child until exec/exit.
pub(super) struct LockGuard {
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

/// Independent byte units: disk/input are encoded bytes; retained is owned-data estimates.
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    /// Maximum encoded bytes of one file, including temporary publication.
    pub entry_bytes: usize,
    /// Maximum encoded bytes of the root record and index together.
    pub root_bytes: u64,
    /// Maximum managed published bytes after successful eviction.
    pub disk_bytes: u64,
    /// Maximum retained root groups, independently of their sizes.
    pub roots: usize,
    /// Shared encoded input allowance for an invocation.
    pub input_bytes: usize,
    /// Shared owned-data admission estimate; not allocator RSS.
    pub retained_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            entry_bytes: 4 * 1024 * 1024,
            root_bytes: 8 * 1024 * 1024,
            disk_bytes: 64 * 1024 * 1024,
            roots: 256,
            input_bytes: 16 * 1024 * 1024,
            retained_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Shared input/retained allowance for all root records and indexes in one invocation.
pub(crate) struct ReadBudget {
    input: usize,
    retained: usize,
}

impl ReadBudget {
    /// Starts one invocation ledger shared by both cache layers.
    pub fn new(limits: Limits) -> Self {
        Self {
            input: limits.input_bytes,
            retained: limits.retained_bytes,
        }
    }

    /// Allowance still available to the invocation's shared invalidation index.
    pub(super) fn remaining_retained_bytes(&self) -> usize {
        self.retained
    }

    /// Refuses oversized, non-private or unstable observations before returning owned data.
    pub(super) fn read<T: serde::de::DeserializeOwned>(
        &mut self,
        directory: &Directory,
        name: &str,
        limits: Limits,
        estimated: impl FnOnce(&T) -> usize,
    ) -> Option<T> {
        let mut file = directory.open_file(name).ok()?;
        let before = file.metadata().ok()?;
        let size = usize::try_from(before.len()).ok()?;
        if size > limits.entry_bytes || size > self.input {
            return None;
        }
        // The wire cap also bounds transient parsing. Reserve an expansion allowance before
        // deserialization, then charge the actual owned-data estimate for retained results.
        // This is deliberately an admission estimate, not a claim about allocator RSS.
        if size.saturating_mul(16) > self.retained {
            return None;
        }
        self.input -= size;
        let mut bytes = Vec::new();
        (&mut file)
            .take(size as u64 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() != size || !same_observation(&before, &file.metadata().ok()?) {
            return None;
        }
        let value: T = serde_json::from_slice(&bytes).ok()?;
        let retained = estimated(&value);
        if retained > self.retained {
            return None;
        }
        self.retained -= retained;
        // Atime is cache LRU only; it is never a filesystem-fact validity token.
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
        Some(value)
    }
}

fn same_observation(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

pub(super) struct Directory(OwnedFd);

pub(super) struct EntryMetadata {
    pub bytes: u64,
    pub accessed: (i64, i64),
}

impl Directory {
    pub fn open(path: &Path, create: bool) -> io::Result<Self> {
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
        let mut current = Self(owned(fd)?);
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
            let mut next = unsafe { libc::openat(current.0.as_raw_fd(), name.as_ptr(), flags) };
            if next < 0 && create && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                // SAFETY: mkdirat creates only this basename beneath the retained directory.
                let result = unsafe { libc::mkdirat(current.0.as_raw_fd(), name.as_ptr(), 0o700) };
                if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: same no-follow binding as the initial open; another creator may have raced.
                next = unsafe { libc::openat(current.0.as_raw_fd(), name.as_ptr(), flags) };
            }
            current = Self(owned(next)?);
        }
        let metadata = File::from(current.0.try_clone()?).metadata()?;
        // SAFETY: geteuid has no pointer arguments or side effects.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "cache directory is not current-user private",
            ));
        }
        Ok(current)
    }

    pub fn child(&self, name: &str) -> io::Result<Self> {
        let name = component(name)?;
        // SAFETY: no-follow basename beneath this retained directory; returned fd is owned.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        let child = Self(owned(fd)?);
        let meta = File::from(child.0.try_clone()?).metadata()?;
        // SAFETY: geteuid has no pointer arguments.
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(io::Error::other("cache child directory is not private"));
        }
        Ok(child)
    }

    /// Nonblocking advisory serialization of publication and eviction across invocations.
    /// Contention makes this disposable cache unavailable rather than delaying a scan.
    pub fn lock(&self) -> io::Result<LockGuard> {
        // SAFETY: a fixed private basename opened beneath the retained parent, never a link.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
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
        let meta = file.metadata()?;
        // SAFETY: geteuid has no arguments; flock is applied to the live owned descriptor.
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.nlink() != 1
            || meta.mode() & 0o077 != 0
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

    fn open_file(&self, name: &str) -> io::Result<File> {
        let name = component(name)?;
        // Nonblocking prevents a substituted FIFO from stalling before the type check.
        // SAFETY: validated basename and a live retained parent; the opened fd is checked below.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        let file = File::from(owned(fd)?);
        let metadata = file.metadata()?;
        // SAFETY: geteuid has no arguments.
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::other(
                "cache entry is not a private regular file with one link",
            ));
        }
        Ok(file)
    }

    pub fn write_json(
        &self,
        name: &str,
        value: &impl serde::Serialize,
        cap: usize,
    ) -> io::Result<()> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let destination = component(name)?;
        let temp = component(&format!(
            ".sweepx-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))?;
        // SAFETY: exclusive creation cannot truncate a pre-existing file or follow a link.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                temp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        let mut file = File::from(owned(fd)?);
        let result = (|| {
            // Bound buffering while avoiding a filesystem write for every JSON token.
            let mut buffer = BufWriter::with_capacity(64 * 1024, &mut file);
            let mut writer = LimitedWriter {
                file: &mut buffer,
                remaining: cap,
            };
            serde_json::to_writer(&mut writer, value).map_err(io::Error::other)?;
            writer.flush()?;
            // Disposable cache publication is atomic but does not promise crash durability.
            // SAFETY: both names are bound to the same retained cache directory.
            if unsafe {
                libc::renameat(
                    self.0.as_raw_fd(),
                    temp.as_ptr(),
                    self.0.as_raw_fd(),
                    destination.as_ptr(),
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        if result.is_err() {
            // SAFETY: only our exclusively created temporary basename is removed.
            unsafe {
                libc::unlinkat(self.0.as_raw_fd(), temp.as_ptr(), 0);
            }
        }
        result
    }

    pub fn remove(&self, name: &str) -> io::Result<()> {
        let name = component(name)?;
        // SAFETY: unlink only removes this entry beneath the retained parent, never follows it.
        if unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn metadata(&self, name: &str) -> io::Result<EntryMetadata> {
        let name = component(name)?;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: validated basename and live parent; success initializes the native stat.
        if unsafe {
            libc::fstatat(
                self.0.as_raw_fd(),
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

    pub fn entries(
        &self,
        mut visit: impl FnMut(&str, EntryMetadata) -> io::Result<()>,
    ) -> io::Result<()> {
        // Opening '.' gives an independent directory offset; dup would share offsets between callers.
        // SAFETY: this is the already retained directory, not a display path.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        let fd = owned(fd)?;
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
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            let Ok(name) = std::str::from_utf8(bytes) else {
                continue;
            };
            if name == "." || name == ".." {
                continue;
            }
            match self.metadata(name) {
                Ok(metadata) => visit(name, metadata)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
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

struct LimitedWriter<W: Write> {
    file: W,
    remaining: usize,
}
impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("cache entry byte budget exceeded"));
        }
        let count = self.file.write(bytes)?;
        self.remaining -= count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
