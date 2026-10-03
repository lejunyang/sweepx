//! Native, bounded I/O for the disposable junk-cache namespace.
//!
//! Directory handles retain authority across path renames. Native backends refuse linked,
//! shared or non-regular cache files. Publication is atomic, not a durable operation journal.

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(super) use unix::Directory;
#[cfg(unix)]
use unix::{same_observation, touch_accessed};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(super) use windows::Directory;
#[cfg(windows)]
use windows::{same_observation, touch_accessed};
#[cfg(any(windows, test))]
mod windows_names;

/// Maximum native entries examined per disposable cache directory, including unknown names.
const ENUMERATION_ENTRY_LIMIT: usize = 4096;

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

pub(super) struct EntryMetadata {
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
