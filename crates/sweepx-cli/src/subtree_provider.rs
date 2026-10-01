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

const MAX_CHANGE_PATHS: usize = 65_536;
const MAX_CHANGE_BYTES: usize = 16 * 1024 * 1024;

/// Per-root validated state used to answer reuse queries.
struct RootState {
    /// Stored index: carries directory coverage and cached file lengths.
    index: StoredSubtreeIndex,
    /// The drain asked for a full rescan (dropped/lost history) or failed; reuse is disabled.
    unusable: bool,
}

/// Reads subtree indexes and FSEvents evidence for the roots being scanned.
pub struct SubtreeCacheProvider {
    cache_dir: PathBuf,
    roots: BTreeMap<PathBuf, RootState>,
    /// One bounded path/cursor map, shared by every root rather than copied per consumer.
    changes: Option<ChangeIndex>,
}

impl SubtreeCacheProvider {
    /// Loads both cache layers and validates them with one complete history drain.
    ///
    /// The query covers every cached consumer from the oldest root/index cursor. Each consumer
    /// filters events by its own cursor, so older index events cannot invalidate newer root
    /// records. Both caches are loaded before querying: a subsequently loaded older index
    /// could otherwise require history that the shared observation did not cover.
    /// Candidate records additionally require the current classification context. A changed or
    /// unknown context does not invalidate file facts or require a second history query.
    pub fn prepare(
        cache_dir: &Path,
        roots: &[PathBuf],
        context: Option<&[u8; 32]>,
    ) -> (Self, Vec<Option<StoredJunkRoot>>) {
        Self::prepare_with_query(cache_dir, roots, context, |paths, since| {
            events_since(paths, since, DRAIN_TIMEOUT)
        })
    }

    fn prepare_with_query(
        cache_dir: &Path,
        roots: &[PathBuf],
        context: Option<&[u8; 32]>,
        query: impl FnOnce(&[&Path], FsEventId) -> std::io::Result<ChangeLog>,
    ) -> (Self, Vec<Option<StoredJunkRoot>>) {
        Self::prepare_with_query_and_limits(
            cache_dir,
            roots,
            context,
            query,
            MAX_CHANGE_PATHS,
            MAX_CHANGE_BYTES,
        )
    }

    fn prepare_with_query_and_limits(
        cache_dir: &Path,
        roots: &[PathBuf],
        context: Option<&[u8; 32]>,
        query: impl FnOnce(&[&Path], FsEventId) -> std::io::Result<ChangeLog>,
        change_count: usize,
        change_bytes: usize,
    ) -> (Self, Vec<Option<StoredJunkRoot>>) {
        let mut reader = junk_cache::CacheReader::new(cache_dir);
        let records = reader.roots(roots, context);
        let max_roots = junk_cache::Limits::default().roots;
        let bindings: BTreeMap<_, _> = roots
            .iter()
            .take(max_roots)
            .map(|root| {
                let identity = fs::symlink_metadata(root)
                    .ok()
                    .map(|metadata| (metadata.dev(), metadata.ino()));
                (root, identity)
            })
            .collect();
        let indexes: BTreeMap<_, _> = roots
            .iter()
            .take(max_roots)
            .filter_map(|root| Some((root.clone(), reader.index(root)?)))
            .collect();
        let since = records
            .iter()
            .flatten()
            .map(StoredJunkRoot::since_event_id)
            .chain(indexes.values().map(StoredSubtreeIndex::since_event_id))
            .min();
        let paths: Vec<&Path> = roots
            .iter()
            .take(max_roots)
            .enumerate()
            .filter(|(ordinal, root)| {
                records[*ordinal].is_some() || indexes.contains_key(root.as_path())
            })
            .map(|(_, root)| root.as_path())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let log = since.and_then(|since| query(&paths, since).ok());
        let mut records = junk_cache::validate_records_with_log(roots, records, log.as_ref());
        // A root replaced while history was draining cannot lend its old listing to the
        // replacement tree, even if that change is delivered only in the next event batch.
        let rebound: BTreeSet<_> = roots
            .iter()
            .take(max_roots)
            .filter(|root| {
                let current = fs::symlink_metadata(root)
                    .ok()
                    .map(|meta| (meta.dev(), meta.ino()));
                bindings.get(root).is_some_and(|before| before != &current)
            })
            .cloned()
            .collect();
        // Binding observations are newer than the history validation above. They may expose a
        // replacement before its event is delivered; complete root facts must also be rejected.
        for (root, record) in roots.iter().zip(&mut records) {
            if rebound
                .iter()
                .any(|changed| changed.starts_with(root) || root.starts_with(changed))
            {
                *record = None;
            }
        }
        // Charge provider root keys/nodes before admitting the shared change map. Root count
        // is bounded independently; this estimate is conservative rather than allocator RSS.
        let auxiliary = roots.iter().take(max_roots).fold(0usize, |bytes, root| {
            bytes.saturating_add(root.as_os_str().len().saturating_mul(2).saturating_add(256))
        });
        let remaining = reader
            .remaining_retained_bytes()
            .saturating_sub(auxiliary)
            .min(change_bytes);
        let changes = if auxiliary <= reader.remaining_retained_bytes() {
            log.and_then(|log| ChangeIndex::capture(log, rebound, change_count, remaining))
        } else {
            None
        };
        if changes.is_none() {
            records.fill(None);
        }
        let root_states = if changes.is_some() {
            indexes
                .into_iter()
                .map(|(root, index)| {
                    let current = fs::symlink_metadata(&root)
                        .ok()
                        .map(|meta| (meta.dev(), meta.ino()));
                    let unchanged = current.is_some() && bindings.get(&root) == Some(&current);
                    // Untracked extra requested roots cannot borrow an ancestor's index if their
                    // binding was outside our bounded validation set.
                    let untracked_overlap = roots
                        .iter()
                        .skip(max_roots)
                        .any(|other| other.starts_with(&root) || root.starts_with(other));
                    (
                        root,
                        RootState {
                            index,
                            unusable: !unchanged || untracked_overlap,
                        },
                    )
                })
                .collect()
        } else {
            BTreeMap::new()
        };
        (
            Self {
                cache_dir: cache_dir.to_path_buf(),
                roots: root_states,
                changes,
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
        let changes = self.changes.as_ref()?;
        let since = state.index.since_event_id();
        let path_text = dir_path.to_str()?;
        // The directory must be recorded as fully covered and have a stored child listing; without
        // either we cannot classify children without stating them.
        if !state.index.is_covered(path_text) {
            return None;
        }
        let listing = state.index.listing(path_text)?;

        // The set is built once during preparation, not once per visited directory. Ancestor
        // events invalidate the entire listing; descendant events invalidate their own children.
        if dir_path.ancestors().any(|ancestor| {
            changes
                .paths
                .get(ancestor)
                .is_some_and(|cursor| cursor.is_after(since))
        }) {
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
                    match listing.files.get(name) {
                        Some(logical_bytes) if !changes.overlaps(&child.path, since) => {
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

/// A native root replacement is unconditional; using MAX as a synthetic event id would
/// incorrectly permit an index whose cursor already equals MAX.
#[derive(Clone, Copy)]
enum ChangeCursor {
    Event(FsEventId),
    Rebound,
}
impl ChangeCursor {
    fn is_after(self, since: FsEventId) -> bool {
        match self {
            Self::Event(id) => id > since,
            Self::Rebound => true,
        }
    }
}

/// Last event per path is sufficient: a change is relevant exactly when its largest cursor
/// exceeds the consumer's cursor. Keeping one map avoids multiplying event retention by roots.
struct ChangeIndex {
    paths: BTreeMap<PathBuf, ChangeCursor>,
    retained: usize,
}

impl ChangeIndex {
    fn capture(
        log: ChangeLog,
        rebound: BTreeSet<PathBuf>,
        event_limit: usize,
        byte_limit: usize,
    ) -> Option<Self> {
        if log.must_rescan {
            return None;
        }
        let mut index = Self {
            paths: BTreeMap::new(),
            retained: 0,
        };
        // Strings move into native paths without a second payload copy. The historical Vec is
        // dropped here and only one bounded invalidation map remains throughout traversal.
        for event in log.events {
            index.insert(
                PathBuf::from(event.path),
                ChangeCursor::Event(event.id),
                event_limit,
                byte_limit,
            )?;
        }
        for root in rebound {
            // Native rebinding invalidates every consumer cursor, even before its event arrives.
            index.insert(root, ChangeCursor::Rebound, event_limit, byte_limit)?;
        }
        Some(index)
    }

    fn insert(
        &mut self,
        path: PathBuf,
        cursor: ChangeCursor,
        event_limit: usize,
        byte_limit: usize,
    ) -> Option<()> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return None;
        }
        if let Some(previous) = self.paths.get_mut(&path) {
            *previous = match (*previous, cursor) {
                (ChangeCursor::Event(old), ChangeCursor::Event(new)) => {
                    ChangeCursor::Event(old.max(new))
                }
                _ => ChangeCursor::Rebound,
            };
            return Some(());
        }
        // Fixed node allowance includes the key/cursor and tree structure; path capacity is
        // separate. Failure invalidates the entire map instead of losing a relevant change.
        let retained = self
            .retained
            .checked_add(128)?
            .checked_add(path.capacity())?;
        if self.paths.len() >= event_limit || retained > byte_limit {
            return None;
        }
        self.paths.insert(path, cursor);
        self.retained = retained;
        Some(())
    }

    fn overlaps(&self, path: &Path, since: FsEventId) -> bool {
        path.ancestors().any(|ancestor| {
            self.paths
                .get(ancestor)
                .is_some_and(|cursor| cursor.is_after(since))
        }) || self
            .paths
            .range::<Path, _>((std::ops::Bound::Included(path), std::ops::Bound::Unbounded))
            .take_while(|(changed, _)| changed.starts_with(path))
            .any(|(_, cursor)| cursor.is_after(since))
    }
}

/// Converts a native child name to the same marker string the scanner used when building listings.
/// On macOS names are Unix bytes; UTF-8 is required (matches `native_basename_marker`).
fn name_marker(name: &sweepx_model::NativeName) -> Option<&str> {
    match name {
        sweepx_model::NativeName::UnixBytes(bytes) => std::str::from_utf8(bytes).ok(),
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
                let record = StoredJunkRoot::capture(&root, vec![], 80, [0; 32]).unwrap();
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
    fn new_platform_context_rescans_empty_candidates_and_keeps_file_facts() {
        use sweepx_core::junk::{
            JunkService,
            platform::{PlatformJunkEvidence, load_platform_junk_rules},
        };
        let (_fixture, cache, roots) = seeded_cache();
        let root = &roots[0];
        fs::create_dir(root.join("user-data-child")).unwrap();
        let project = JunkService::built_in().unwrap();
        let empty_evidence = PlatformJunkEvidence::default();
        let project_classifier = project.with_platform(&[], &empty_evidence);
        let old_context = project_classifier.classification_context_digest().unwrap();
        let context = sweepx_core::CoreContext::new(sweepx_i18n::LocaleResolution::new(
            sweepx_i18n::Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let request = sweepx_core::ScanRequest {
            roots: vec![root.clone()],
            state_dir: None,
        };
        let old = sweepx_core::scan_junk_with_store::<sweepx_core::MemorySnapshotStore>(
            &context,
            &request,
            None,
            &project_classifier,
            None,
        )
        .unwrap();
        assert!(old.decisions.is_empty());
        junk_cache::write(
            &cache,
            &StoredJunkRoot::capture(root, vec![], 80, old_context).unwrap(),
        )
        .unwrap();
        let rules = load_platform_junk_rules()
            .unwrap()
            .into_iter()
            .filter(|rule| rule.id == "macos.user-caches")
            .collect::<Vec<_>>();
        assert_eq!(rules.len(), 1);
        let classifier = project.with_platform(&rules, &empty_evidence);
        let new_context = classifier.classification_context_digest().unwrap();
        let empty_log = |_: &[&Path], _: FsEventId| {
            Ok(ChangeLog {
                events: vec![],
                must_rescan: false,
            })
        };
        let (_, old_records) = SubtreeCacheProvider::prepare_with_query(
            &cache,
            std::slice::from_ref(root),
            Some(&old_context),
            empty_log,
        );
        assert!(
            old_records[0].is_some(),
            "unchanged context admits the warm empty report"
        );
        for current in [Some(&new_context), None] {
            let (provider, records) = SubtreeCacheProvider::prepare_with_query(
                &cache,
                std::slice::from_ref(root),
                current,
                empty_log,
            );
            assert!(
                records[0].is_none(),
                "new or unknown scope cannot replay an empty report"
            );
            let child = sweepx_platform::DirectoryEntryRecord::from_parent_and_name(
                root,
                sweepx_model::NativeName::unix(b"file".to_vec()),
            )
            .unwrap();
            let plan = provider.plan_entries(root, &[child]).unwrap();
            assert!(matches!(&plan[0], PlannedEntry::ReuseFile(file)
                if file.logical_bytes == u128::from(fs::symlink_metadata(root.join("file")).unwrap().len())));
            let fresh = sweepx_core::scan_junk_with_store::<sweepx_core::MemorySnapshotStore>(
                &context,
                &request,
                None,
                &classifier,
                Some(&provider),
            )
            .unwrap();
            assert_eq!(
                fresh.decisions.len(),
                1,
                "live traversal introduces the new candidate"
            );
            let candidate = fresh
                .scan
                .summary
                .entries
                .iter()
                .find(|entry| {
                    entry
                        .identity
                        .as_ref()
                        .is_some_and(|id| fresh.decisions.contains_key(&id.entry_id))
                })
                .unwrap();
            assert_eq!(
                candidate.display_path,
                root.join("user-data-child").display().to_string()
            );
        }
        let after = fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            after,
            ["file", "user-data-child"]
                .into_iter()
                .map(std::ffi::OsString::from)
                .collect()
        );
    }

    #[test]
    fn shared_drain_uses_oldest_cursor_and_preserves_each_consumers_cursor() {
        let (_fixture, cache, roots) = seeded_cache();
        let calls = std::cell::Cell::new(0);
        let (provider, records) = SubtreeCacheProvider::prepare_with_query(
            &cache,
            &roots,
            Some(&[0; 32]),
            |paths, since| {
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
            },
        );
        assert_eq!(calls.get(), 1);
        assert!(
            records[0].is_some(),
            "old event must not invalidate newer root record"
        );
        assert!(records[1].is_none(), "new event must invalidate its root");
        let device = &provider.roots[&roots[0]];
        assert!(!device.unusable);
        assert!(
            provider
                .changes
                .as_ref()
                .unwrap()
                .overlaps(&roots[0].join("file"), device.index.since_event_id())
        );
        assert!(
            provider
                .changes
                .as_ref()
                .unwrap()
                .overlaps(&roots[1].join("file"), 40)
        );
        assert!(
            !provider
                .changes
                .as_ref()
                .unwrap()
                .overlaps(&roots[0].join("other"), 40)
        );
    }

    #[test]
    fn incomplete_or_failed_shared_history_disables_both_cache_layers() {
        let (_fixture, cache, roots) = seeded_cache();
        for failed in [false, true] {
            let (provider, records) =
                SubtreeCacheProvider::prepare_with_query(&cache, &roots, Some(&[0; 32]), |_, _| {
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
            assert!(provider.roots.is_empty());
            assert!(provider.changes.is_none());
        }
    }

    #[test]
    fn root_binding_is_rechecked_after_the_shared_observation() {
        let (_fixture, cache, roots) = seeded_cache();
        let (provider, records) =
            SubtreeCacheProvider::prepare_with_query(&cache, &roots, Some(&[0; 32]), |_, _| {
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
        assert!(state.unusable);
        assert!(
            provider
                .changes
                .as_ref()
                .unwrap()
                .overlaps(&roots[0].join("file"), 40)
        );
        assert!(
            !provider
                .changes
                .as_ref()
                .unwrap()
                .overlaps(&roots[1].join("file"), 40)
        );
    }

    #[test]
    fn cache_absence_does_not_query_native_history() {
        let fixture = tempfile::TempDir::new().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        let (provider, records) = SubtreeCacheProvider::prepare_with_query(
            &root.join("absent-cache"),
            std::slice::from_ref(&root),
            Some(&[0; 32]),
            |_, _| panic!("no cursor to validate"),
        );
        assert!(records[0].is_none());
        assert!(provider.roots.is_empty());
    }

    #[test]
    fn history_preserves_ancestors_and_component_boundaries() {
        let changed = ChangeIndex {
            paths: ["/root/a", "/root/a/child", "/root/b/file"]
                .into_iter()
                .map(|path| (PathBuf::from(path), ChangeCursor::Event(1)))
                .collect(),
            retained: 0,
        };
        for path in ["/", "/root", "/root/a/sibling", "/root/b", "/root/b/file"] {
            assert!(changed.overlaps(Path::new(path), 0), "{path}");
        }
        for path in ["/root/ab", "/root/b/other", "/other"] {
            assert!(!changed.overlaps(Path::new(path), 0), "{path}");
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
        let (provider, _) =
            SubtreeCacheProvider::prepare_with_query(&cache, &roots, Some(&[0; 32]), |_, _| {
                Ok(ChangeLog {
                    events: vec![],
                    must_rescan: false,
                })
            });
        provider
            .store_index(changed, &roots, 100, &covered, &listings)
            .unwrap();
        let (provider, _) =
            SubtreeCacheProvider::prepare_with_query(&cache, &roots, Some(&[0; 32]), |_, since| {
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
    fn log_of(events: &[(&str, u64)]) -> ChangeLog {
        ChangeLog {
            must_rescan: false,
            events: events
                .iter()
                .map(|(path, id)| sweepx_scanner::ChangeEvent {
                    path: (*path).into(),
                    id: *id,
                    flags: 0,
                })
                .collect(),
        }
    }

    #[test]
    fn shared_map_deduplicates_paths_and_matches_a_brute_force_cursor_oracle() {
        let observations = [
            ("/root/a/aaa", 10),
            ("/root/a/file", 30),
            ("/root/a/file", 20),
            ("/root/a/zzz", 100),
            ("/root/b", 5),
        ];
        let index = ChangeIndex::capture(log_of(&observations), BTreeSet::new(), 10, 4096).unwrap();
        assert_eq!(index.paths.len(), 4);
        for path in [
            "/",
            "/root",
            "/root/a",
            "/root/a/file",
            "/root/a/aaa",
            "/root/ab",
            "/root/a/other",
            "/root/b/child",
            "/other",
        ] {
            for since in [0, 10, 20, 30, 50, 100, u64::MAX] {
                let expected = observations.iter().any(|(changed, id)| {
                    *id > since
                        && (Path::new(changed).starts_with(path)
                            || Path::new(path).starts_with(changed))
                });
                assert_eq!(
                    index.overlaps(Path::new(path), since),
                    expected,
                    "{path} cursor={since}"
                );
            }
        }
    }

    #[test]
    fn distinct_path_and_byte_limits_refuse_whole_index_but_duplicates_fit() {
        let repeated = vec![("/root/file", 12); 100];
        let index = ChangeIndex::capture(log_of(&repeated), BTreeSet::new(), 1, 512).unwrap();
        assert_eq!(index.paths.len(), 1);
        assert!(
            ChangeIndex::capture(
                log_of(&[("/root/a", 1), ("/root/b", 2)]),
                BTreeSet::new(),
                1,
                4096
            )
            .is_none()
        );
        let long = format!("/root/{}", "x".repeat(700));
        assert!(ChangeIndex::capture(log_of(&[(&long, 1)]), BTreeSet::new(), 10, 512).is_none());
        assert!(
            ChangeIndex::capture(log_of(&[("/root/../else", 1)]), BTreeSet::new(), 10, 4096)
                .is_none()
        );
    }

    #[test]
    fn native_rebinding_is_unconditional_even_for_the_largest_event_cursor() {
        let rebound = [PathBuf::from("/root/a")].into_iter().collect();
        let index = ChangeIndex::capture(log_of(&[("/root/a", 0)]), rebound, 10, 4096).unwrap();
        for path in ["/root", "/root/a", "/root/a/file"] {
            assert!(index.overlaps(Path::new(path), u64::MAX));
        }
        assert!(!index.overlaps(Path::new("/root/ab"), u64::MAX));
    }

    #[test]
    fn change_budget_failure_cannot_leave_either_cache_layer_enabled() {
        let (_fixture, cache, roots) = seeded_cache();
        for (count, bytes) in [(0, 4096), (10, 64)] {
            let (provider, records) = SubtreeCacheProvider::prepare_with_query_and_limits(
                &cache,
                &roots,
                Some(&[0; 32]),
                |_, _| {
                    // The event predates both complete root records but is relevant to the older
                    // file index. Root records cannot mask a truncated invalidation map.
                    Ok(log_of(&[(roots[0].join("file").to_str().unwrap(), 60)]))
                },
                count,
                bytes,
            );
            assert!(records.iter().all(Option::is_none));
            assert!(provider.changes.is_none());
            for root in &roots {
                let child = sweepx_platform::DirectoryEntryRecord {
                    path: root.join("file"),
                    file_name: sweepx_model::NativeName::UnixBytes(b"file".to_vec()),
                };
                assert!(provider.plan_entries(root, &[child]).is_none());
            }
        }
    }
    #[test]
    fn uncached_extra_roots_do_not_expand_the_native_history_query() {
        let (_fixture, cache, mut roots) = seeded_cache();
        let cached = roots.clone();
        let base = roots[0].parent().unwrap().to_path_buf();
        roots.extend((0..300).map(|ordinal| base.join(format!("uncached-{ordinal}"))));
        let (provider, records) = SubtreeCacheProvider::prepare_with_query(
            &cache,
            &roots,
            Some(&[0; 32]),
            |paths, since| {
                assert_eq!(since, 40);
                assert_eq!(
                    paths.iter().copied().collect::<BTreeSet<_>>(),
                    cached.iter().map(PathBuf::as_path).collect()
                );
                Ok(log_of(&[]))
            },
        );
        assert!(records[0].is_some() && records[1].is_some());
        assert!(records[2..].iter().all(Option::is_none));
        assert_eq!(provider.roots.len(), 2);
        assert!(provider.changes.unwrap().paths.is_empty());
    }
    #[test]
    fn a_nested_root_outside_the_binding_budget_cannot_borrow_an_ancestor_index() {
        let (_fixture, cache, mut roots) = seeded_cache();
        let parent = roots[0].clone();
        let base = parent.parent().unwrap().to_path_buf();
        roots.extend((0..254).map(|ordinal| base.join(format!("unrelated-{ordinal}"))));
        let nested = parent.join("unvalidated");
        fs::create_dir(&nested).unwrap();
        roots.push(nested);
        let (provider, _) =
            SubtreeCacheProvider::prepare_with_query(&cache, &roots, Some(&[0; 32]), |_, _| {
                Ok(log_of(&[]))
            });
        let child = sweepx_platform::DirectoryEntryRecord {
            path: parent.join("file"),
            file_name: sweepx_model::NativeName::UnixBytes(b"file".to_vec()),
        };
        assert!(provider.plan_entries(&parent, &[child]).is_none());
    }
}
