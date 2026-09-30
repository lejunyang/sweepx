//! Persistent, per-root cache of classified junk results, validated with FSEvents.
//!
//! # What is stored
//!
//! For every scan root we persist the exact classified candidates it produced together with the
//! FSEvents event id reached *after* the scan. On the next run the root is only reused when
//! FSEvents reports no change at or below it since that id; any event under the root, a
//! dropped/lost-history signal, or a root identity change invalidates it and it is rescanned.
//!
//! # Why this is safe to reuse
//!
//! FSEvents observes file content modifications as well as structure, so an empty history is a
//! stronger statement than a directory-mtime check (which cannot see content writes). The
//! candidates still carry their native locators and identities; the Trash path revalidates each
//! one at execution independently, so a cached report grants no mutation authority on its own.
//!
//! # Failure direction
//!
//! Every error — missing file, unreadable log, timeout, parse failure — is a miss, never a claim
//! of freshness. The cache lives in a user-private directory (`0700`) with `0600` files and
//! rejects symlinks.

#![cfg(target_os = "macos")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use sweepx_core::{FsEventId, current_event_id, events_since};
use sweepx_model::{ByteValue, DirectoryAggregate, ScanEntryId, ScannedEntry};

/// Schema marker for the on-disk root record; bump on an incompatible change.
const STORED_SCHEMA: &str = "sweepx.junk-cache/v1";
/// Bounded wall time for one FSEvents drain; a drain that cannot finish fails the cache.
const FSEVENTS_TIMEOUT: Duration = Duration::from_secs(5);

/// One root's cached result.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredJunkRoot {
    schema: String,
    /// Canonical absolute path of the root at capture; verified before reuse.
    root: String,
    /// Native identity of the root directory at capture.
    root_device: String,
    root_inode: String,
    /// FSEvents id reached after the root was scanned.
    since_event_id: FsEventId,
    candidates: Vec<StoredJunkCandidate>,
}

/// Round-trippable, fully owned copy of the CLI's `JunkCandidate`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredJunkCandidate {
    pub path: String,
    pub rule_id: String,
    pub risk: String,
    pub reclaimable: ByteValue,
    pub evidence: String,
    pub source_reviewed_at: String,
    pub references: Vec<String>,
    pub entry_id: ScanEntryId,
    pub ancestor_ids: BTreeSet<ScanEntryId>,
    pub activity: Option<String>,
    pub stale_formats: Vec<String>,
    pub size_is_logical: bool,
    pub git: Option<StoredGitIgnoreEvidence>,
    pub classification: Option<String>,
    pub confidence: Option<String>,
    pub blockers: Vec<String>,
    /// The source scanned row, restored so a cached candidate can be bulk-trashed with the same
    /// identity revalidation as a fresh one. `None` for records that never carried a row.
    #[serde(default)]
    pub source_entry: Option<sweepx_model::ScannedEntry>,
}

/// Owned form of `GitIgnoreEvidence`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredGitIgnoreEvidence {
    pub status: String,
    pub repository_entry_id: String,
    pub check: String,
}

impl StoredJunkRoot {
    /// Builds a record from freshly scanned candidates for one canonical root.
    pub fn capture(
        canonical_root: &Path,
        candidates: Vec<StoredJunkCandidate>,
    ) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(canonical_root)?;
        Ok(Self {
            schema: STORED_SCHEMA.to_string(),
            root: canonical_root.display().to_string(),
            root_device: metadata.dev().to_string(),
            root_inode: metadata.ino().to_string(),
            // Read after the scan so it can only over-invalidate.
            since_event_id: current_event_id(),
            candidates,
        })
    }

    /// Number of candidates in a stored record, used by tests.
    #[cfg(test)]
    pub fn candidates_len(&self) -> usize {
        self.candidates.len()
    }

    /// Consumes the record, returning its owned candidates.
    pub fn into_candidates(self) -> Vec<StoredJunkCandidate> {
        self.candidates
    }

    /// Whether this record still names an unchanged root the cache may reuse.
    ///
    /// Re-reads the root identity and asks FSEvents for the history since the stored id. A record
    /// is only current when the identity matches, the history drained cleanly, and no event
    /// occurred at or below the root.
    pub fn is_current(&self, canonical_root: &Path) -> bool {
        if self.schema != STORED_SCHEMA || self.root != canonical_root.display().to_string() {
            return false;
        }
        let Ok(metadata) = fs::symlink_metadata(canonical_root) else {
            return false;
        };
        if metadata.dev().to_string() != self.root_device
            || metadata.ino().to_string() != self.root_inode
        {
            return false;
        }
        let Ok(log) = events_since(&[canonical_root], self.since_event_id, FSEVENTS_TIMEOUT) else {
            return false;
        };
        if log.must_rescan {
            return false;
        }
        let root_text = canonical_root.display().to_string();
        let prefix = format!("{root_text}/");
        !log.events.iter().any(|event| {
            let path = event.path.trim_end_matches('/');
            path == root_text || path.starts_with(&prefix)
        })
    }
}

/// Loads a stored record for `canonical_root`, returning `None` on any failure or absence.
pub fn load(cache_dir: &Path, canonical_root: &Path) -> Option<StoredJunkRoot> {
    let path = record_path(cache_dir, canonical_root);
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice::<StoredJunkRoot>(&bytes).ok()
}

/// Atomically writes `record` for its canonical root.
pub fn write(cache_dir: &Path, record: &StoredJunkRoot) -> io::Result<()> {
    prepare_cache_dir(cache_dir)?;
    let canonical_root = PathBuf::from(&record.root);
    let destination = record_path(cache_dir, &canonical_root);

    let bytes =
        serde_json::to_vec_pretty(record).map_err(|error| io::Error::other(error.to_string()))?;
    let temp = temp_path(&destination);
    // Write a private temp file, fsync, then rename; replacing an existing file by rename is atomic.
    fs::write(&temp, bytes)?;
    set_file_private(&temp)?;
    fs::rename(&temp, &destination)
}

/// Removes cached records whose root is no longer in `current_roots`, so the directory does not
/// accumulate entries for stale paths. Missing/unreadable files are simply skipped.
pub fn prune(cache_dir: &Path, current_roots: &[PathBuf]) -> io::Result<()> {
    if !cache_dir.exists() {
        return Ok(());
    }
    let wanted: BTreeSet<String> = current_roots
        .iter()
        .filter_map(|root| record_file_name(root))
        .collect();
    for entry in fs::read_dir(cache_dir)? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.ends_with(".json") && !wanted.contains(name) {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}

fn prepare_cache_dir(cache_dir: &Path) -> io::Result<()> {
    if cache_dir.exists() {
        let metadata = fs::symlink_metadata(cache_dir)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::other("junk cache path is not a real directory"));
        }
        return Ok(());
    }
    fs::create_dir_all(cache_dir)?;
    fs::set_permissions(cache_dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn set_file_private(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn record_path(cache_dir: &Path, canonical_root: &Path) -> PathBuf {
    cache_dir.join(record_file_name(canonical_root).expect("root path hashable"))
}

fn record_file_name(canonical_root: &Path) -> Option<String> {
    let bytes = canonical_root.as_os_str().as_encoded_bytes();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Some(format!("{:x}.json", hasher.finalize()))
}

fn temp_path(destination: &Path) -> PathBuf {
    // Record names are ASCII hex from record_file_name; the non-UTF8 fallback never occurs.
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!(".{name}.tmp"))
        .unwrap_or_else(|| ".tmp".to_string());
    destination.with_file_name(file_name)
}

/// Schema marker for the per-device subtree index.
const SUBTREE_SCHEMA: &str = "sweepx.subtree-index/v1";

/// Per-device index captured after a classified scan.
///
/// It stores the candidate directories (so they re-enter the sink lifecycle when reused) and, for
/// file-level reuse, the captured child listing of every covered directory. The `since_event_id`
/// plus one FSEvents drain lets the provider decide precisely which files changed: unchanged
/// files keep their recorded size with no syscall.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredSubtreeIndex {
    schema: String,
    device: String,
    /// FSEvents id reached after the scan that produced this index.
    since_event_id: FsEventId,
    /// Canonical path → fully covered, for every directory the scan completed.
    ///
    /// This is the record that a non-candidate subtree existed and was scanned completely, which is
    /// what lets it be skipped later even though it has no candidate entry of its own.
    covered: BTreeMap<String, bool>,
    /// Canonical directory path → its captured file/directory children, for file-level reuse.
    #[serde(default)]
    listings: BTreeMap<String, StoredDirListing>,
    directories: Vec<StoredSubtreeDirectory>,
}

/// Persisted child listing of one directory.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct StoredDirListing {
    /// Regular file child name → logical size.
    #[serde(default)]
    pub files: BTreeMap<String, u128>,
    /// Child directory names.
    #[serde(default)]
    pub dirs: BTreeSet<String>,
}

/// One candidate directory in a subtree index.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredSubtreeDirectory {
    pub entry: ScannedEntry,
    pub rule_id: String,
    pub aggregate: DirectoryAggregate,
}

impl StoredSubtreeIndex {
    pub fn new(
        device: String,
        since_event_id: FsEventId,
        covered: BTreeMap<String, bool>,
        listings: BTreeMap<String, StoredDirListing>,
        directories: Vec<StoredSubtreeDirectory>,
    ) -> Self {
        Self {
            schema: SUBTREE_SCHEMA.to_string(),
            device,
            since_event_id,
            covered,
            listings,
            directories,
        }
    }

    pub fn since_event_id(&self) -> FsEventId {
        self.since_event_id
    }

    /// Whether the canonical path was recorded as fully covered during the index's scan.
    pub fn is_covered(&self, path: &str) -> bool {
        self.covered.get(path).copied().unwrap_or(false)
    }

    /// Captured child listing for a directory, if one was stored.
    pub fn listing(&self, path: &str) -> Option<&StoredDirListing> {
        self.listings.get(path)
    }

    pub fn directories(&self) -> &[StoredSubtreeDirectory] {
        &self.directories
    }
}

/// Loads the subtree index for `device`, returning `None` when absent, corrupt, or wrong schema.
pub fn load_subtree_index(cache_dir: &Path, device: &str) -> Option<StoredSubtreeIndex> {
    let path = subtree_index_path(cache_dir, device);
    let bytes = fs::read(path).ok()?;
    let index: StoredSubtreeIndex = serde_json::from_slice(&bytes).ok()?;
    if index.schema != SUBTREE_SCHEMA || index.device != device {
        return None;
    }
    Some(index)
}

/// Atomically writes the subtree index for its device.
pub fn write_subtree_index(cache_dir: &Path, index: &StoredSubtreeIndex) -> io::Result<()> {
    prepare_subtrees_dir(cache_dir)?;
    let destination = subtree_index_path(cache_dir, &index.device);
    let bytes =
        serde_json::to_vec_pretty(index).map_err(|error| io::Error::other(error.to_string()))?;
    let temp = temp_path(&destination);
    fs::write(&temp, bytes)?;
    set_file_private(&temp)?;
    fs::rename(&temp, &destination)
}

fn prepare_subtrees_dir(cache_dir: &Path) -> io::Result<()> {
    prepare_cache_dir(cache_dir)?;
    let path = cache_dir.join("subtrees");
    if path.exists() {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(io::Error::other("subtrees path is not a real directory"));
        }
        return Ok(());
    }
    fs::create_dir_all(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
}

fn subtree_index_path(cache_dir: &Path, device: &str) -> PathBuf {
    // Device names contain only digits/separators; keep a safe file stem via hash anyway.
    let mut hasher = Sha256::new();
    hasher.update(device.as_bytes());
    cache_dir
        .join("subtrees")
        .join(format!("{:x}.json", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn temp_cache() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sweepx-junk-cache-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::canonicalize(&dir).unwrap()
    }

    fn sample_candidate(name: &str) -> StoredJunkCandidate {
        StoredJunkCandidate {
            path: name.to_string(),
            rule_id: "rule:x".to_string(),
            risk: "R2".to_string(),
            reclaimable: ByteValue::Unknown {
                reason: sweepx_model::ReasonCode::UnknownIdentity,
            },
            evidence: String::new(),
            source_reviewed_at: String::new(),
            references: Vec::new(),
            entry_id: ScanEntryId::for_scan_ordinal(&sweepx_model::ScanId::new("test"), 1).unwrap(),
            ancestor_ids: BTreeSet::new(),
            activity: None,
            stale_formats: Vec::new(),
            size_is_logical: true,
            git: None,
            classification: None,
            confidence: None,
            blockers: Vec::new(),
            source_entry: None,
        }
    }

    #[test]
    fn an_untouched_root_round_trips_as_current() {
        let cache = temp_cache();
        let root = cache.join("root");
        fs::create_dir(&root).unwrap();
        let canonical = fs::canonicalize(&root).unwrap();

        let stored = StoredJunkRoot::capture(&canonical, vec![sample_candidate("a")]).unwrap();
        write(&cache, &stored).unwrap();

        let loaded = load(&cache, &canonical).expect("stored");
        assert_eq!(loaded.candidates_len(), 1);
        assert!(
            loaded.is_current(&canonical),
            "nothing changed under the root"
        );

        let _ = fs::remove_dir_all(&cache);
    }

    #[test]
    fn a_change_under_the_root_invalidates_the_record() {
        let cache = temp_cache();
        let root = cache.join("root");
        fs::create_dir(&root).unwrap();
        let canonical = fs::canonicalize(&root).unwrap();

        let stored = StoredJunkRoot::capture(&canonical, vec![]).unwrap();
        write(&cache, &stored).unwrap();

        // A write strictly after capture must invalidate.
        fs::write(canonical.join("new.txt"), b"x").unwrap();
        let loaded = load(&cache, &canonical).expect("stored");
        assert!(
            !loaded.is_current(&canonical),
            "a new file under the root must invalidate"
        );

        let _ = fs::remove_dir_all(&cache);
    }

    #[test]
    fn prune_removes_records_for_roots_no_longer_present() {
        let cache = temp_cache();
        prepare_cache_dir(&cache).unwrap();
        let keep = cache.join("keep");
        let gone = cache.join("gone");
        fs::create_dir(&keep).unwrap();
        fs::create_dir(&gone).unwrap();
        let keep = fs::canonicalize(&keep).unwrap();
        let gone = fs::canonicalize(&gone).unwrap();

        for root in [&keep, &gone] {
            let stored = StoredJunkRoot::capture(root, vec![]).unwrap();
            write(&cache, &stored).unwrap();
        }
        prune(&cache, std::slice::from_ref(&keep)).unwrap();

        assert!(load(&cache, &keep).is_some());
        assert!(load(&cache, &gone).is_none());

        let _ = fs::remove_dir_all(&cache);
    }
}
