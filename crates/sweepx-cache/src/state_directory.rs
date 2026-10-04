//! Aggregate length admission for cooperating SweepX state writers.
//!
//! Lock order is state root, then component lock. Only shipped namespace shapes are walked;
//! unknown files count, unknown directories/unsafe observations refuse admission. No payloads
//! or integrity records are removed. Bounds cover metadata work and logical file lengths,
//! not allocation, RSS, blocking-kernel deadlines or writers that ignore the shared lock.

use crate::{
    STATE_DIRECTORY_BYTE_CAP,
    native::{Directory, LockGuard},
};
use std::{fmt, io, path::Path};

/// Maximum non-dot entries observed across the complete admitted state inventory.
/// Native cursors separately cap each directory at 4096 records, including dot records.
pub const STATE_ENTRY_CAP: usize = 4090;

/// Entries protected from cache growth for one terminal operation's namespace/files.
/// Eight covers the current journal bootstrap's seven names within the total entry bound.
pub const STATE_RECORD_RESERVE_ENTRIES: usize = 8;

/// Complete metadata-only observation under the cooperative state lock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateUsage {
    /// Sum of admitted ordinary file lengths, including unknown files and held locks.
    pub bytes: u64,
    /// Directory and file names charged once each, excluding native dot entries.
    pub entries: usize,
}

/// A typed refusal so callers can distinguish exhausted resources from unsafe permissions.
#[derive(Debug)]
pub struct StateResourceLimit {
    /// Stable diagnostic unit: `state_bytes` or `state_entries`.
    pub resource: &'static str,
    /// Maximum file lengths or entry visits, independent of physical allocation.
    pub limit: u64,
}
impl fmt::Display for StateResourceLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SweepX state exceeds {} limit ({})",
            self.resource, self.limit
        )
    }
}
impl std::error::Error for StateResourceLimit {}

/// Returns the structured quota refusal without interpreting error text.
pub fn resource_limit(error: &io::Error) -> Option<&StateResourceLimit> {
    error.get_ref()?.downcast_ref()
}
fn exhausted(resource: &'static str, limit: u64) -> io::Error {
    io::Error::other(StateResourceLimit { resource, limit })
}

/// Retained global writer exclusion. Keep this alive through publication and SQLite close.
/// Reservations include temporary coexistence, not just the final replacement. A reservation
/// is valid for the caller's next bounded operation while this guard remains held; callers
/// must not start independent writes against the same reservation or reverse lock order.
pub struct StateWriteSession {
    root: Directory,
    lock: LockGuard,
    usage: StateUsage,
    owner_pid: u32,
}
impl StateWriteSession {
    /// Captures private authority, then acquires a nonblocking control lock. Only this zero-
    /// length bootstrap lock may be created before inventory; no component records are created.
    pub fn open(path: &Path, create: bool) -> io::Result<Self> {
        Self::capture(&Directory::open(path, create)?)
    }

    /// Reuses already captured authority, including after its display path is renamed.
    pub fn capture(root: &Directory) -> io::Result<Self> {
        let root = root.retain()?;
        let lock = root.lock()?;
        let mut session = Self {
            root,
            lock,
            usage: StateUsage::default(),
            owner_pid: std::process::id(),
        };
        session.usage = session.observe(None)?;
        Ok(session)
    }

    /// Borrows authority for the bounded operation covered by this session's reservation.
    pub fn root(&self) -> &Directory {
        &self.root
    }

    /// Last complete metadata observation; reservations do not fabricate future file lengths.
    pub fn usage(&self) -> StateUsage {
        self.usage
    }

    /// Revalidates the held control lock's current native binding and process owner.
    /// Long-lived clients must check this before later I/O. This does not renew a length
    /// reservation, enumerate state again or make the following namespace operation atomic.
    pub fn validate_exclusion(&self) -> io::Result<()> {
        if self.owner_pid != std::process::id() {
            return Err(io::Error::other(
                "state reservation belongs to another process",
            ));
        }
        crate::native::with_io_policy(|| self.root.held_lock_bytes(&self.lock).map(|_| ()))
    }

    /// Checks a captured top-level child against this root before using its reservation.
    pub fn contains_child(&self, name: &str, child: &Directory) -> io::Result<bool> {
        self.root.same_child(name, child)
    }

    /// Reobserves and admits additional lengths/entries, including publication temporaries.
    /// An existing destination remains charged until its replacement is actually published.
    pub fn reserve(&mut self, bytes: u64, entries: usize) -> io::Result<()> {
        self.reserve_inner(bytes, entries, None)
    }

    /// Admits disposable cache growth while preserving terminal-record headroom. This reserve
    /// is already included in the 512 MiB total, not additional disk beyond that bound.
    pub fn reserve_disposable(&mut self, bytes: u64, entries: usize) -> io::Result<()> {
        let bytes = bytes
            .checked_add(crate::STATE_RECORD_RESERVE_BYTES)
            .ok_or_else(|| exhausted("state_bytes", STATE_DIRECTORY_BYTE_CAP))?;
        let entries = entries
            .checked_add(STATE_RECORD_RESERVE_ENTRIES)
            .ok_or_else(|| exhausted("state_entries", STATE_ENTRY_CAP as u64))?;
        self.reserve_inner(bytes, entries, None)
    }

    /// Disposable-cache admission with a held component lock, preserving record headroom.
    pub fn reserve_disposable_locked(
        &mut self,
        bytes: u64,
        entries: usize,
        directory: &Directory,
        lock: &LockGuard,
    ) -> io::Result<()> {
        let bytes = bytes
            .checked_add(crate::STATE_RECORD_RESERVE_BYTES)
            .ok_or_else(|| exhausted("state_bytes", STATE_DIRECTORY_BYTE_CAP))?;
        let entries = entries
            .checked_add(STATE_RECORD_RESERVE_ENTRIES)
            .ok_or_else(|| exhausted("state_entries", STATE_ENTRY_CAP as u64))?;
        self.reserve_inner(bytes, entries, Some((directory, lock)))
    }

    /// Reobserves while one component lock is held. Share-denying Windows locks are accounted
    /// through their owned file instead of reopening or weakening their sharing contract.
    pub fn reserve_locked(
        &mut self,
        bytes: u64,
        entries: usize,
        directory: &Directory,
        lock: &LockGuard,
    ) -> io::Result<()> {
        self.reserve_inner(bytes, entries, Some((directory, lock)))
    }

    fn reserve_inner(
        &mut self,
        bytes: u64,
        entries: usize,
        held: Option<(&Directory, &LockGuard)>,
    ) -> io::Result<()> {
        self.validate_exclusion()?;
        self.usage = self.observe(held)?;
        self.validate_exclusion()?;
        if self
            .usage
            .bytes
            .checked_add(bytes)
            .is_none_or(|n| n > STATE_DIRECTORY_BYTE_CAP)
        {
            return Err(exhausted("state_bytes", STATE_DIRECTORY_BYTE_CAP));
        }
        if self
            .usage
            .entries
            .checked_add(entries)
            .is_none_or(|n| n > STATE_ENTRY_CAP)
        {
            return Err(exhausted("state_entries", STATE_ENTRY_CAP as u64));
        }
        Ok(())
    }

    fn observe(&self, held: Option<(&Directory, &LockGuard)>) -> io::Result<StateUsage> {
        let mut usage = StateUsage::default();
        self.walk(&self.root, Layout::Root, held, &mut usage)?;
        Ok(usage)
    }

    fn walk(
        &self,
        directory: &Directory,
        layout: Layout,
        held: Option<(&Directory, &LockGuard)>,
        usage: &mut StateUsage,
    ) -> io::Result<()> {
        // Recursion follows at most root/preview/generations, root/journals/id, or
        // root/junk/subtrees. All cursors/handles and layout state have fixed depth.
        let control = if matches!(layout, Layout::Root) {
            Some(&self.lock)
        } else if let Some((expected, lock)) = held {
            directory.same_retained_directory(expected)?.then_some(lock)
        } else {
            None
        };
        directory.entries_all(|name| {
            if usage.entries == STATE_ENTRY_CAP {
                return Err(exhausted("state_entries", STATE_ENTRY_CAP as u64));
            }
            usage.entries += 1;
            let name = name.ok_or_else(|| io::Error::other("unrepresentable state entry"))?;
            if let Some(child_layout) = layout.child(name) {
                let child = directory.child(name)?;
                self.walk(&child, child_layout, held, usage)?;
                if !directory.same_child(name, &child)? {
                    return Err(io::Error::other(
                        "state child binding changed during accounting",
                    ));
                }
            } else {
                let bytes = if name == ".lock"
                    && let Some(control) = control
                {
                    directory.held_lock_bytes(control)?
                } else {
                    // Native accounting rejects directories, links, public/multi-link files,
                    // provider/volume/mount uncertainty. Never recurse arbitrary unknown trees.
                    directory.accounting_metadata(name)?.bytes
                };
                usage.bytes = usage
                    .bytes
                    .checked_add(bytes)
                    .ok_or_else(|| exhausted("state_bytes", STATE_DIRECTORY_BYTE_CAP))?;
            }
            Ok(())
        })
    }
}

#[derive(Clone, Copy)]
enum Layout {
    Root,
    Preview,
    Junk,
    Journals,
    Flat,
}
impl Layout {
    fn child(self, name: &str) -> Option<Self> {
        match self {
            Self::Root => match name {
                "preview-cache" => Some(Self::Preview),
                "junk-cache" => Some(Self::Junk),
                "event-journals" => Some(Self::Journals),
                "operations"
                | "audit"
                | "permanent-delete-audit"
                | "selection"
                | "manifests"
                | "plans"
                | "cursors"
                | "approval"
                | "recovery"
                | "spill" => Some(Self::Flat),
                _ => None,
            },
            Self::Preview if matches!(name, "generations" | "quarantine") => Some(Self::Flat),
            Self::Junk if name == "subtrees" => Some(Self::Flat),
            Self::Journals
                if name.len() == 64
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
            {
                Some(Self::Flat)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
