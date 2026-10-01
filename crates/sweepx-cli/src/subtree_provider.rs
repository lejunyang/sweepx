//! CLI implementation of [`SubtreeReuse`], backed by the per-root file index and FSEvents.
//!
//! One shared event-history drain indexes invalidations for cached file lengths. Directories
//! are always traversed so current identities, rule markers and ancestor accounting are rebuilt.
//! Missing history or uncertain coverage falls back to live metadata inspection.

#![cfg(target_os = "macos")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sweepx_core::{FsEventId, PlannedEntry, SubtreeReuse, events_since};
use sweepx_platform::CachedFileEntry;

use crate::junk_cache::{self, StoredJunkRoot, StoredSubtreeIndex};
use sweepx_scanner::ChangeLog;

/// Bounded wall time for the shared FSEvents drain.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-root validated state used to answer reuse queries.
struct RootState {
    /// Stored index: carries directory coverage and cached file lengths.
    index: StoredSubtreeIndex,
    /// Raw absolute paths FSEvents reported since the index event id.
    changed: BTreeSet<PathBuf>,
    /// The drain asked for a full rescan (dropped/lost history) or failed; reuse is disabled.
    unusable: bool,
}

/// Reads subtree indexes and FSEvents evidence for the roots being scanned.
pub struct SubtreeCacheProvider {
    cache_dir: PathBuf,
    roots: BTreeMap<PathBuf, RootState>,
}

impl SubtreeCacheProvider {
    /// Loads both cache layers and validates them with one complete history drain.
    ///
    /// The query covers every requested root from the oldest root/index cursor. Each consumer
    /// filters events by its own cursor, so older index events cannot invalidate newer root
    /// records. Both caches are loaded before querying: a subsequently loaded older index
    /// could otherwise require history that the shared observation did not cover.
    pub fn prepare(cache_dir: &Path, roots: &[PathBuf]) -> (Self, Vec<Option<StoredJunkRoot>>) {
        Self::prepare_with_query(cache_dir, roots, |paths, since| {
            events_since(paths, since, DRAIN_TIMEOUT)
        })
    }

    fn prepare_with_query(
        cache_dir: &Path,
        roots: &[PathBuf],
        query: impl FnOnce(&[&Path], FsEventId) -> std::io::Result<ChangeLog>,
    ) -> (Self, Vec<Option<StoredJunkRoot>>) {
        let mut reader = junk_cache::CacheReader::new(cache_dir);
        let records = reader.roots(roots);
        let bindings: BTreeMap<_, _> = roots
            .iter()
            .filter_map(|root| {
                let metadata = fs::symlink_metadata(root).ok()?;
                Some((root, (metadata.dev(), metadata.ino())))
            })
            .collect();
        let indexes: BTreeMap<_, _> = roots
            .iter()
            .take(junk_cache::Limits::default().roots)
            .filter_map(|root| Some((root.clone(), reader.index(root)?)))
            .collect();
        let since = records
            .iter()
            .flatten()
            .map(StoredJunkRoot::since_event_id)
            .chain(indexes.values().map(StoredSubtreeIndex::since_event_id))
            .min();
        let paths: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
        let log = since.and_then(|since| query(&paths, since).ok());
        let records = junk_cache::validate_records_with_log(roots, records, log.as_ref());
        // A root replaced while history was draining cannot lend its old listing to the
        // replacement tree, even if that change is delivered only in the next event batch.
        let rebound: BTreeSet<_> = roots
            .iter()
            .filter(|root| {
                let current = fs::symlink_metadata(root)
                    .ok()
                    .map(|meta| (meta.dev(), meta.ino()));
                current.is_none() || current.as_ref() != bindings.get(root)
            })
            .cloned()
            .collect();
        let root_states = indexes
            .into_iter()
            .map(|(root, index)| {
                let usable = log.as_ref().filter(|log| !log.must_rescan);
                let mut changed: BTreeSet<PathBuf> = usable
                    .map(|log| {
                        log.events
                            .iter()
                            .filter(|event| {
                                event.id > index.since_event_id()
                                    && (Path::new(&event.path).starts_with(&root)
                                        || root.starts_with(&event.path))
                            })
                            .map(|event| PathBuf::from(&event.path))
                            .collect()
                    })
                    .unwrap_or_default();
                changed.extend(
                    rebound
                        .iter()
                        .filter(|changed| changed.starts_with(&root) || root.starts_with(changed))
                        .cloned(),
                );
                (
                    root.clone(),
                    RootState {
                        index,
                        changed,
                        unusable: usable.is_none() || rebound.contains(&root),
                    },
                )
            })
            .collect();
        (
            Self {
                cache_dir: cache_dir.to_path_buf(),
                roots: root_states,
            },
            records,
        )
    }

    /// Persists a bounded optional index for this root without copying other roots' listings.
    /// Write failures are surfaced for logging and never fail the report.
    pub fn store_index(
        &self,
        scan_root: &Path,
        all_roots: &[PathBuf],
        since_event_id: FsEventId,
        covered: &BTreeMap<String, bool>,
        listings: &BTreeMap<String, sweepx_scanner::DirListing>,
    ) -> std::io::Result<()> {
        let index =
            StoredSubtreeIndex::capture(scan_root, all_roots, since_event_id, covered, listings)?;
        junk_cache::write_subtree_index(&self.cache_dir, &index)
    }
}

impl SubtreeReuse for SubtreeCacheProvider {
    fn plan_entries(
        &self,
        dir_path: &Path,
        children: &[sweepx_platform::DirectoryEntryRecord],
    ) -> Option<Vec<PlannedEntry>> {
        let (_, state) = self
            .roots
            .iter()
            .filter(|(root, _)| dir_path.starts_with(root))
            .max_by_key(|(root, _)| root.components().count())?;
        if state.unusable {
            return None;
        }
        let path_text = dir_path.to_str()?;
        // The directory must be recorded as fully covered and have a stored child listing; without
        // either we cannot classify children without stating them.
        if !state.index.is_covered(path_text) {
            return None;
        }
        let listing = state.index.listing(path_text)?;

        // The set is built once during preparation, not once per visited directory. Ancestor
        // events invalidate the entire listing; descendant events invalidate their own children.
        if dir_path
            .ancestors()
            .any(|ancestor| state.changed.contains(ancestor))
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
                        Some(logical_bytes) if !overlaps_changes(&state.changed, &child.path) => {
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

// Path ordering keeps descendants contiguous; query costs depth + log(events), without
// allocating a second copy of the event history for every directory or child.
fn overlaps_changes(changed: &BTreeSet<PathBuf>, path: &Path) -> bool {
    path.ancestors().any(|ancestor| changed.contains(ancestor))
        || changed
            .range(path.to_path_buf()..)
            .next()
            .is_some_and(|event| event.starts_with(path))
}

/// Converts a native child name to the same marker string the scanner used when building listings.
/// On macOS names are Unix bytes; UTF-8 is required (matches `native_basename_marker`).
fn name_marker(name: &sweepx_model::NativeName) -> Option<String> {
    match name {
        sweepx_model::NativeName::UnixBytes(bytes) => String::from_utf8(bytes.clone()).ok(),
        sweepx_model::NativeName::WindowsUtf16(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::junk_cache::StoredDirListing;

    fn seeded_cache() -> (tempfile::TempDir, PathBuf, Vec<PathBuf>) {
        let fixture = tempfile::TempDir::new().unwrap();
        let base = fixture.path().canonicalize().unwrap();
        let cache = base.join("cache");
        let roots: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|name| {
                let root = base.join(name);
                fs::create_dir(&root).unwrap();
                fs::write(root.join("file"), b"payload").unwrap();
                let record = StoredJunkRoot::capture(&root, vec![], 80).unwrap();
                junk_cache::write(&cache, &record).unwrap();
                root
            })
            .collect();
        for root in &roots {
            let path = root.to_str().unwrap().to_string();
            let covered = [(path.clone(), true)].into_iter().collect();
            let listings = [(
                path,
                StoredDirListing {
                    files: [("file".to_string(), 7)].into_iter().collect(),
                    dirs: BTreeSet::new(),
                },
            )]
            .into_iter()
            .collect();
            let index = StoredSubtreeIndex::new(root, 40, covered, listings).unwrap();
            junk_cache::write_subtree_index(&cache, &index).unwrap();
        }
        (fixture, cache, roots)
    }

    #[test]
    fn shared_drain_uses_oldest_cursor_and_preserves_each_consumers_cursor() {
        let (_fixture, cache, roots) = seeded_cache();
        let calls = std::cell::Cell::new(0);
        let (provider, records) =
            SubtreeCacheProvider::prepare_with_query(&cache, &roots, |paths, since| {
                calls.set(calls.get() + 1);
                assert_eq!(since, 40, "older file-index history must be included");
                assert_eq!(
                    paths.iter().copied().collect::<BTreeSet<_>>(),
                    roots.iter().map(PathBuf::as_path).collect()
                );
                Ok(ChangeLog {
                    must_rescan: false,
                    events: vec![
                        sweepx_scanner::ChangeEvent {
                            path: roots[0].join("file").display().to_string(),
                            id: 60,
                            flags: 0,
                        },
                        sweepx_scanner::ChangeEvent {
                            path: roots[1].join("file").display().to_string(),
                            id: 90,
                            flags: 0,
                        },
                    ],
                })
            });
        assert_eq!(calls.get(), 1);
        assert!(
            records[0].is_some(),
            "old event must not invalidate newer root record"
        );
        assert!(records[1].is_none(), "new event must invalidate its root");
        let device = &provider.roots[&roots[0]];
        assert!(!device.unusable);
        assert!(overlaps_changes(&device.changed, &roots[0].join("file")));
        assert!(overlaps_changes(
            &provider.roots[&roots[1]].changed,
            &roots[1].join("file")
        ));
        assert!(!overlaps_changes(&device.changed, &roots[0].join("other")));
    }

    #[test]
    fn incomplete_or_failed_shared_history_disables_both_cache_layers() {
        let (_fixture, cache, roots) = seeded_cache();
        for failed in [false, true] {
            let (provider, records) =
                SubtreeCacheProvider::prepare_with_query(&cache, &roots, |_, _| {
                    if failed {
                        Err(std::io::Error::other("history unavailable"))
                    } else {
                        Ok(ChangeLog {
                            events: vec![],
                            must_rescan: true,
                        })
                    }
                });
            assert!(records.iter().all(Option::is_none));
            assert!(provider.roots.values().all(|device| device.unusable));
        }
    }

    #[test]
    fn root_binding_is_rechecked_after_the_shared_observation() {
        let (_fixture, cache, roots) = seeded_cache();
        let (provider, records) =
            SubtreeCacheProvider::prepare_with_query(&cache, &roots, |_, _| {
                // Keep the original inode alive so the replacement cannot accidentally reuse it.
                fs::rename(&roots[0], roots[0].with_extension("old")).unwrap();
                fs::create_dir(&roots[0]).unwrap();
                Ok(ChangeLog {
                    events: vec![],
                    must_rescan: false,
                })
            });
        assert!(records[0].is_none());
        assert!(records[1].is_some());
        let state = &provider.roots[&roots[0]];
        assert!(overlaps_changes(&state.changed, &roots[0].join("file")));
        assert!(!overlaps_changes(&state.changed, &roots[1].join("file")));
    }

    #[test]
    fn cache_absence_does_not_query_native_history() {
        let fixture = tempfile::TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let (provider, records) = SubtreeCacheProvider::prepare_with_query(
            &root.join("absent-cache"),
            std::slice::from_ref(&root),
            |_, _| panic!("no cursor to validate"),
        );
        assert!(records[0].is_none());
        assert!(provider.roots.is_empty());
    }

    #[test]
    fn history_preserves_ancestors_and_component_boundaries() {
        let changed = ["/root/a", "/root/a/child", "/root/b/file"]
            .into_iter()
            .map(PathBuf::from)
            .collect();
        for path in ["/", "/root", "/root/a/sibling", "/root/b", "/root/b/file"] {
            assert!(overlaps_changes(&changed, Path::new(path)), "{path}");
        }
        for path in ["/root/ab", "/root/b/other", "/other"] {
            assert!(!overlaps_changes(&changed, Path::new(path)), "{path}");
        }
    }
    #[test]
    fn alternating_roots_keep_independent_indexes_and_missing_children_are_inspected() {
        let (_fixture, cache, roots) = seeded_cache();
        // Only A changes. B must survive the next generation even on the same device.
        let changed = &roots[0];
        fs::write(changed.join("file"), b"longer-payload").unwrap();
        let path = changed.to_str().unwrap().to_string();
        let covered = [(path.clone(), true)].into_iter().collect();
        let listings = [(
            path.clone(),
            sweepx_scanner::DirListing {
                files: [("file".into(), 14)].into_iter().collect(),
                dirs: BTreeSet::new(),
            },
        )]
        .into_iter()
        .collect();
        let (provider, _) = SubtreeCacheProvider::prepare_with_query(&cache, &roots, |_, _| {
            Ok(ChangeLog {
                events: vec![],
                must_rescan: false,
            })
        });
        provider
            .store_index(changed, &roots, 100, &covered, &listings)
            .unwrap();
        let (provider, _) = SubtreeCacheProvider::prepare_with_query(&cache, &roots, |_, since| {
            assert_eq!(since, 40, "B still needs its older cursor");
            Ok(ChangeLog {
                events: vec![],
                must_rescan: false,
            })
        });
        for (root, expected) in [(&roots[0], 14), (&roots[1], 7)] {
            let children: Vec<_> = ["file", "uncached"]
                .into_iter()
                .map(|name| sweepx_platform::DirectoryEntryRecord {
                    path: root.join(name),
                    file_name: sweepx_model::NativeName::UnixBytes(name.as_bytes().to_vec()),
                })
                .collect();
            let plan = provider.plan_entries(root, &children).unwrap();
            assert!(
                matches!(&plan[0], PlannedEntry::ReuseFile(file) if file.logical_bytes == expected)
            );
            assert!(matches!(&plan[1], PlannedEntry::Inspect(_)));
            assert_eq!(
                fs::metadata(root.join("file")).unwrap().len() as u128,
                expected
            );
        }
    }
}
