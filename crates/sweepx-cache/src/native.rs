//! Native, bounded I/O shared by private cache and operation-state namespaces.
//!
//! Directory handles retain authority across path renames. Native backends refuse linked,
//! shared or non-regular files. Ordinary cache publication is atomic; explicit synced writes
//! request file flushes and Unix parent-directory synchronization, not an operation journal.

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
#[cfg(any(unix, windows))]
mod authority;
#[cfg(all(test, any(unix, windows)))]
mod authority_tests;

/// Identifies exhaustion of the shared 128 retained directory/control-lock owner slots.
/// The quota excludes exported `File` duplicates, SQLite data files and other process handles.
/// Refusal is distinct from unsafe permissions, absence or lock contention.
pub fn authority_handle_limit(error: &io::Error) -> Option<usize> {
    #[cfg(any(unix, windows))]
    {
        authority::limit(error)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = error;
        None
    }
}

#[derive(Debug)]
struct LinkedObject;

impl std::fmt::Display for LinkedObject {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("linked private-state object")
    }
}
impl std::error::Error for LinkedObject {}

fn linked_object() -> io::Error {
    io::Error::other(LinkedObject)
}

/// Identifies a native refusal of a linked object without reopening its display path.
/// Other unsafe or inaccessible observations remain ordinary I/O errors.
pub fn is_link_refusal(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<LinkedObject>())
}
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Directory, LockGuard, StateFileMetadata};
#[cfg(unix)]
use unix::{same_observation, touch_accessed};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{Directory, LockGuard};
#[cfg(windows)]
use windows::{same_observation, touch_accessed};
#[cfg(any(windows, test))]
mod windows_names;

/// Protects the complete synchronous I/O interval on macOS, including opens, mapped access
/// and closing handles. The closure must finish all protected I/O before returning.
/// Success requires restoration; an original operation failure is preserved. Publication
/// must invoke this only for its preparation stage, then commit after restoration succeeds.
#[cfg(target_os = "macos")]
pub fn with_io_policy<T, E>(operation: impl FnOnce() -> Result<T, E>) -> Result<T, E>
where
    E: From<io::Error>,
{
    let policy = sweepx_platform::macos_io_policy::NoMaterialization::enter()?;
    let result = operation();
    {
        #[cfg(test)]
        let restored = if FAIL_RESTORE_ONCE.with(|flag| flag.replace(false)) {
            // Phase failure injection: Drop performs real native restoration; this does not
            // claim a failed kernel setter. The original operation error keeps precedence.
            drop(policy);
            Err(io::Error::other(
                "injected cache policy restoration failure",
            ))
        } else {
            policy.restore()
        };
        #[cfg(not(test))]
        let restored = policy.restore();
        if result.is_ok() {
            restored.map_err(E::from)?;
        }
    }
    result
}

#[cfg(not(target_os = "macos"))]
/// Runs synchronous I/O without a macOS provider policy on this platform.
/// The matching macOS API protects the complete closure and checks policy restoration.
pub fn with_io_policy<T, E>(operation: impl FnOnce() -> Result<T, E>) -> Result<T, E>
where
    E: From<io::Error>,
{
    operation()
}

fn with_cache_io<T>(operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    with_io_policy(operation)
}

#[cfg(all(test, target_os = "macos"))]
std::thread_local! {
    static FAIL_RESTORE_ONCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A post-commit flush failure must not be treated as a pre-commit encoder failure.
pub(super) fn commit_sync(operation: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_COMMIT_SYNC.with(|flag| flag.replace(false)) {
        return Err(io::Error::other("injected post-commit flush failure"));
    }
    operation()
}

#[cfg(test)]
std::thread_local! {
    static FAIL_COMMIT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Maximum native entries examined per disposable cache directory, including unknown names.
const ENUMERATION_ENTRY_LIMIT: usize = 4096;

/// Metadata-only quota observation, including native identity and a change marker for
/// a conservative recheck before removing disposable cache metadata. This does not
/// measure allocation or give authority over any scanned payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AccountedFile {
    pub(crate) bytes: u64,
    /// Retention ranking only; access times do not establish freshness or ownership.
    pub(crate) accessed: (i64, i64),
    /// Unix device/inode/link count, or Windows volume and both halves of the file ID.
    pub(crate) identity: [u64; 3],
    /// Unix ctime with nanoseconds, or Windows ChangeTime in native units.
    pub(crate) changed: (i64, i64),
}

/// Independent byte units: disk/input are encoded bytes; retained is owned-data estimates.
#[derive(Clone, Copy)]
pub struct Limits {
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
pub struct ReadBudget {
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
    pub fn remaining_retained_bytes(&self) -> usize {
        self.retained
    }

    /// Refuses oversized, non-private or unstable observations before returning owned data.
    pub fn read<T: serde::de::DeserializeOwned>(
        &mut self,
        directory: &Directory,
        name: &str,
        limits: Limits,
        estimated: impl FnOnce(&T) -> usize,
    ) -> Option<T> {
        with_cache_io(|| Ok(self.read_guarded(directory, name, limits, estimated)))
            .ok()
            .flatten()
    }

    fn read_guarded<T: serde::de::DeserializeOwned>(
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
        #[cfg(windows)]
        windows::revalidate_file(&file).ok()?;
        let value: T = serde_json::from_slice(&bytes).ok()?;
        let retained = estimated(&value);
        if retained > self.retained {
            return None;
        }
        self.retained -= retained;
        // Atime is cache LRU only; it is never a filesystem-fact validity token.
        touch_accessed(&file);
        Some(value)
    }
}

/// Native encoded length and access-time ordering used only for disposable cache quota/LRU.
pub struct EntryMetadata {
    /// Encoded file length for quota accounting, independent of physical allocation.
    pub bytes: u64,
    /// Native ordering units (Unix seconds/nanoseconds or Windows ticks/zero); LRU only.
    pub accessed: (i64, i64),
}

fn write_json(file: &mut File, value: &impl serde::Serialize, cap: usize) -> io::Result<()> {
    // Both backends share the wire cap and fixed buffer, never materializing the JSON value.
    let mut buffer = BufWriter::with_capacity(64 * 1024, file);
    let mut writer = LimitedWriter {
        file: &mut buffer,
        remaining: cap,
    };
    serde_json::to_writer(&mut writer, value).map_err(io::Error::other)?;
    writer.flush()
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

/// Result of reading a private regular file. Oversize files are observed without reading data.
pub struct BoundedRead {
    /// Observed encoded length; oversize data is not read into memory.
    pub bytes: u64,
    /// Complete, revalidated bytes, or None when the encoded cap refused input.
    pub contents: Option<Vec<u8>>,
}

impl Directory {
    /// Reads one relative private regular file within an encoded cap. Oversize returns
    /// metadata with no contents; missing/unsafe/unstable observations remain errors.
    pub fn read_bytes(&self, name: &str, cap: u64) -> io::Result<BoundedRead> {
        with_cache_io(|| self.read_bytes_guarded(name, cap))
    }

    fn read_bytes_guarded(&self, name: &str, cap: u64) -> io::Result<BoundedRead> {
        let mut file = self.open_file(name)?;
        let before = file.metadata()?;
        let bytes = before.len();
        let contents = if bytes > cap {
            None
        } else {
            // Check length before reserving. A sparse or malformed file cannot grow this
            // allocation beyond the caller's encoded cap, including a racing extra byte.
            let length = usize::try_from(bytes).map_err(io::Error::other)?;
            let mut contents = Vec::new();
            contents
                .try_reserve_exact(length)
                .map_err(io::Error::other)?;
            contents.resize(length, 0);
            file.read_exact(&mut contents)?;
            // The extra-byte probe has a fixed stack buffer, so a racing append cannot
            // double Vec capacity just to discover that the observation changed.
            let mut extra = [0u8; 1];
            if file.read(&mut extra)? != 0 {
                return Err(io::Error::other("cache entry changed during read"));
            }
            Some(contents)
        };
        if !same_observation(&before, &file.metadata()?) {
            return Err(io::Error::other("cache entry changed during read"));
        }
        #[cfg(windows)]
        windows::revalidate_file(&file)?;
        Ok(BoundedRead { bytes, contents })
    }
}

#[cfg(all(test, any(unix, windows)))]
mod synced_tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn exclusive_json_commit_preserves_a_racing_destination_and_discards_refused_temp() {
        let (_fixture, path, root) = fixture();
        assert!(
            root.create_synced_json("oversized", &"too long", 2)
                .is_err()
        );
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
        struct Race<'a>(&'a Directory);
        impl serde::Serialize for Race<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use std::io::Write;
                // Synchronized after preflight and before native commit, without sleeps.
                let mut file = self.0.create_state_file("record").unwrap();
                file.write_all(b"competitor").unwrap();
                serde::Serialize::serialize(&7_u8, serializer)
            }
        }
        let error = root
            .create_synced_json("record", &Race(&root), 32)
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(path.join("record")).unwrap(), b"competitor");
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);
        root.create_synced_json("fresh", &serde_json::json!({"value":[7,9]}), 64)
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(path.join("fresh")).unwrap()
            )
            .unwrap(),
            serde_json::json!({"value":[7,9]})
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn exclusive_json_restoration_phase_refusal_never_publishes_manifest() {
        let (_fixture, path, root) = fixture();
        struct Refuse;
        impl serde::Serialize for Refuse {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                FAIL_RESTORE_ONCE.with(|flag| flag.set(true));
                serde::Serialize::serialize(&7_u8, serializer)
            }
        }
        let error = root
            .create_synced_json("manifest", &Refuse, 64)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "injected cache policy restoration failure"
        );
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
    }

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, Directory) {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let parent = std::fs::canonicalize(temp.path()).unwrap();
        #[cfg(windows)]
        let parent = temp.path().to_path_buf();
        let path = parent.join("state");
        let directory = Directory::open(&path, true).unwrap();
        (temp, path, directory)
    }

    #[test]
    fn synced_bytes_match_independent_read_and_oversize_preserves_old_file() {
        let (_temp, path, directory) = fixture();
        directory
            .write_synced_bytes("snapshot", b"old bytes", 9)
            .unwrap();
        assert_eq!(std::fs::read(path.join("snapshot")).unwrap(), b"old bytes");
        assert!(
            directory
                .write_synced_bytes("snapshot", b"too many bytes", 9)
                .is_err()
        );
        assert_eq!(std::fs::read(path.join("snapshot")).unwrap(), b"old bytes");
        let read = directory.read_bytes("snapshot", 8).unwrap();
        assert_eq!(read.bytes, 9);
        assert!(read.contents.is_none());
        assert_eq!(
            directory
                .read_bytes("snapshot", 9)
                .unwrap()
                .contents
                .unwrap(),
            b"old bytes"
        );
        assert_eq!(std::fs::read_dir(path).unwrap().count(), 1);
    }

    #[test]
    fn post_commit_flush_failure_never_removes_the_published_file() {
        let (_temp, path, directory) = fixture();
        directory
            .write_synced_bytes("snapshot", b"old", 64)
            .unwrap();
        // Inject only this phase's result, not a real kernel flush failure or power loss.
        FAIL_COMMIT_SYNC.with(|flag| flag.set(true));
        let error = directory
            .write_synced_bytes("snapshot", b"new", 64)
            .unwrap_err();
        assert_eq!(error.to_string(), "injected post-commit flush failure");
        assert_eq!(std::fs::read(path.join("snapshot")).unwrap(), b"new");
        assert_eq!(std::fs::read_dir(path).unwrap().count(), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn synced_publication_restoration_failure_preserves_old_file_before_commit() {
        let (_temp, path, directory) = fixture();
        directory
            .write_synced_bytes("snapshot", b"old", 64)
            .unwrap();
        FAIL_RESTORE_ONCE.with(|flag| flag.set(true));
        assert!(
            directory
                .write_synced_bytes("snapshot", b"new", 64)
                .is_err()
        );
        assert_eq!(std::fs::read(path.join("snapshot")).unwrap(), b"old");
        assert_eq!(std::fs::read_dir(path).unwrap().count(), 1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn generic_policy_preserves_operation_error_and_drops_refused_success() {
        #[derive(Debug)]
        enum DomainError {
            Operation,
            Io(io::Error),
        }
        impl From<io::Error> for DomainError {
            fn from(error: io::Error) -> Self {
                Self::Io(error)
            }
        }
        let dropped = std::cell::Cell::new(false);
        struct Owned<'a>(&'a std::cell::Cell<bool>);
        impl Drop for Owned<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let result: Result<Owned<'_>, DomainError> = with_io_policy(|| {
            FAIL_RESTORE_ONCE.with(|flag| flag.set(true));
            Ok(Owned(&dropped))
        });
        assert!(
            matches!(result, Err(DomainError::Io(ref e)) if e.to_string()=="injected cache policy restoration failure")
        );
        assert!(dropped.get());
        let result: Result<(), DomainError> = with_io_policy(|| {
            FAIL_RESTORE_ONCE.with(|flag| flag.set(true));
            Err(DomainError::Operation)
        });
        assert!(matches!(result, Err(DomainError::Operation)));
    }
}
