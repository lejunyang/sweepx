//! Native, bounded I/O shared by disposable cache namespaces.
//!
//! Directory handles retain authority across path renames. Native backends refuse linked,
//! shared or non-regular cache files. Publication is atomic, not a durable operation journal.

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Directory, LockGuard};
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

/// Protects the complete synchronous I/O interval on macOS, including opens and reads.
/// Success requires restoration; an original operation failure is preserved. Publication
/// must invoke this only for its preparation stage, then commit after restoration succeeds.
#[cfg(target_os = "macos")]
fn with_cache_io<T>(operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
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
            restored?;
        }
    }
    result
}

#[cfg(not(target_os = "macos"))]
fn with_cache_io<T>(operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    operation()
}

#[cfg(all(test, target_os = "macos"))]
std::thread_local! {
    static FAIL_RESTORE_ONCE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
pub(crate) struct BoundedRead {
    pub bytes: u64,
    pub contents: Option<Vec<u8>>,
}

impl Directory {
    pub(crate) fn read_bytes(&self, name: &str, cap: u64) -> io::Result<BoundedRead> {
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
