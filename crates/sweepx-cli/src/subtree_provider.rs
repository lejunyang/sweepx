//! CLI implementation of [`SubtreeReuse`], backed by the per-device subtree index and FSEvents.
//!
//! # How a subtree is validated
//!
//! At construction the provider groups the roots about to be scanned by device, loads each
//! device's [`StoredSubtreeIndex`], and performs exactly one FSEvents drain per device (from the
//! index's event id) to learn which paths changed. During the walk, `reuse_subtree(path)` answers
//! from that in-memory evidence: a directory is reused only when its device has an index, the
//! drain found no event at or under the path and reported no global rescan. The stored candidate
//! directories under the path are then returned and pushed through the normal sink lifecycle.
//!
//! # Failure direction
//!
//! A missing index, an FSEvents drain error/timeout, a must-rescan flag, or any event touching
//! the path all produce `None`, so the directory is traversed. Nothing is skipped on uncertainty.

#![cfg(target_os = "macos")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sweepx_core::{PlannedEntry, ReusedDirectory, SubtreeReuse, current_event_id, events_since};
use sweepx_platform::CachedFileEntry;

use crate::junk_cache::{self, StoredDirListing, StoredSubtreeDirectory, StoredSubtreeIndex};

/// Bounded wall time for the per-device FSEvents drain.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-device validated state used to answer reuse queries.
struct DeviceState {
    /// Stored index: carries coverage of every scanned directory and the candidate directories.
    index: StoredSubtreeIndex,
    /// Raw absolute paths FSEvents reported since the index event id.
    changed: Vec<String>,
    /// The drain asked for a full rescan (dropped/lost history) or failed; reuse is disabled.
    unusable: bool,
}

/// Reads subtree indexes and FSEvents evidence for the roots being scanned.
pub struct SubtreeCacheProvider {
    cache_dir: PathBuf,
    devices: BTreeMap<String, DeviceState>,
}

impl SubtreeCacheProvider {
    /// Builds the provider for `roots_to_scan` from indexes under `cache_dir`.
    ///
    /// Roots on a device with no usable index are simply absent from the device map, so every
    /// directory under them is traversed. Drain failures mark only that device unusable.
    pub fn prepare(cache_dir: &Path, roots_to_scan: &[PathBuf]) -> Self {
        // Group roots to scan by device id.
        let mut roots_by_device: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
        for root in roots_to_scan {
            if let Some(device) = device_key(root) {
                roots_by_device
                    .entry(device)
                    .or_default()
                    .push(root.clone());
            }
        }

        let mut devices = BTreeMap::new();
        for (device, device_roots) in roots_by_device {
            let Some(index) = junk_cache::load_subtree_index(cache_dir, &device) else {
                // No index: first scan, or never cached for this device. Skip building state.
                continue;
            };

            let paths: Vec<&Path> = device_roots.iter().map(PathBuf::as_path).collect();
            let state = match events_since(&paths, index.since_event_id(), DRAIN_TIMEOUT) {
                Ok(log) => DeviceState {
                    index,
                    changed: log.events.iter().map(|event| event.path.clone()).collect(),
                    unusable: log.must_rescan,
                },
                // A drain error/timeout must not reuse anything on this device.
                Err(_) => DeviceState {
                    index,
                    changed: Vec::new(),
                    unusable: true,
                },
            };
            devices.insert(device, state);
        }

        Self {
            cache_dir: cache_dir.to_path_buf(),
            devices,
        }
    }

    /// Persists a fresh subtree index for the device of `scan_root` from the candidate rows the
    /// scan produced. A write failure is surfaced so the caller can log it; it never fails the run.
    pub fn store_index(
        &self,
        scan_root: &Path,
        covered: BTreeMap<String, bool>,
        listings: BTreeMap<String, StoredDirListing>,
        directories: Vec<StoredSubtreeDirectory>,
    ) -> std::io::Result<()> {
        let device = device_key(scan_root)
            .ok_or_else(|| std::io::Error::other("could not determine device for subtree index"))?;
        let index = StoredSubtreeIndex::new(
            device.clone(),
            current_event_id(),
            covered,
            listings,
            directories,
        );
        junk_cache::write_subtree_index(&self.cache_dir, &index)
    }
}

impl SubtreeReuse for SubtreeCacheProvider {
    fn reuse_subtree(&self, dir_path: &Path) -> Option<Vec<ReusedDirectory>> {
        let device = device_key(dir_path)?;
        let state = self.devices.get(&device)?;
        if state.unusable {
            return None;
        }
        let path_text = dir_path.display().to_string();
        // The index must have recorded this exact directory as fully covered. A directory absent
        // from that record (e.g. created after the prior scan) cannot be skipped.
        if !state.index.is_covered(&path_text) {
            return None;
        }
        let prefix = format!("{path_text}/");
        // Reduce changed paths to their most specific ("leaf") events: an event that has another
        // changed path strictly under it is redundant, because directory-granularity FSEvents
        // repeat every ancestor of the actual change. Only a remaining event at or under this
        // directory invalidates it; events on ancestors/siblings do not. This attributes changes
        // precisely instead of invalidating siblings when their parent changed.
        let leaf_events: Vec<&str> = state
            .changed
            .iter()
            .map(|changed| changed.trim_end_matches('/'))
            .filter(|changed| {
                let ancestor_prefix = format!("{changed}/");
                !state
                    .changed
                    .iter()
                    .any(|other| other.trim_end_matches('/').starts_with(&ancestor_prefix))
            })
            .collect();
        if leaf_events
            .iter()
            .any(|event| *event == path_text || event.starts_with(&prefix))
        {
            return None;
        }

        // Return every stored candidate directory at or under the path. A covered subtree with no
        // candidates returns Some(empty), which is a verified skip.
        let mut reused = Vec::new();
        for stored in state.index.directories() {
            let candidate_path = &stored.entry.display_path;
            if candidate_path == &path_text || candidate_path.starts_with(&prefix) {
                reused.push(ReusedDirectory {
                    entry: stored.entry.clone(),
                    rule_id: stored.rule_id.clone(),
                    aggregate: stored.aggregate.clone(),
                });
            }
        }
        Some(reused)
    }

    fn plan_entries(
        &self,
        dir_path: &Path,
        children: &[sweepx_platform::DirectoryEntryRecord],
    ) -> Option<Vec<PlannedEntry>> {
        let device = device_key(dir_path)?;
        let state = self.devices.get(&device)?;
        if state.unusable {
            return None;
        }
        let path_text = dir_path.display().to_string();
        // The directory must be recorded as fully covered and have a stored child listing; without
        // either we cannot classify children without stating them.
        if !state.index.is_covered(&path_text) {
            return None;
        }
        let listing = state.index.listing(&path_text)?;

        // Exact changed paths. With file-level events these name the changed items themselves.
        let changed: BTreeSet<&str> = state
            .changed
            .iter()
            .map(|changed| changed.trim_end_matches('/'))
            .collect();
        // A changed event on this directory or a strict ancestor (e.g. a directory rename) cannot
        // be attributed to one child, so the whole directory is inspected.
        if changed.contains(path_text.as_str())
            || changed
                .iter()
                .any(|event| path_text.starts_with(&format!("{event}/")))
        {
            return None;
        }

        Some(
            children
                .iter()
                .map(|child| {
                    let Some(name) = name_marker(&child.file_name) else {
                        return PlannedEntry::Inspect(child.clone());
                    };
                    // Reuse only a regular file recorded in the listing whose exact path is
                    // unchanged. Directories, unknown/new children and changed files are inspected.
                    match listing.files.get(&name) {
                        Some(logical_bytes)
                            if !changed.contains(child.path.display().to_string().as_str()) =>
                        {
                            PlannedEntry::ReuseFile(CachedFileEntry {
                                path: child.path.clone(),
                                file_name: child.file_name.clone(),
                                logical_bytes: *logical_bytes,
                            })
                        }
                        _ => PlannedEntry::Inspect(child.clone()),
                    }
                })
                .collect(),
        )
    }
}

/// Converts a native child name to the same marker string the scanner used when building listings.
/// On macOS names are Unix bytes; UTF-8 is required (matches `native_basename_marker`).
fn name_marker(name: &sweepx_model::NativeName) -> Option<String> {
    match name {
        sweepx_model::NativeName::UnixBytes(bytes) => String::from_utf8(bytes.clone()).ok(),
        sweepx_model::NativeName::WindowsUtf16(_) => None,
    }
}

fn device_key(path: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    Some(metadata.dev().to_string())
}
