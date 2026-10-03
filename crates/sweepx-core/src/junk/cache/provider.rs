//! Shared implementation of [`SubtreeReuse`], backed by the per-root file index and FSEvents.
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

use crate::{FsEventId, PlannedEntry, SubtreeReuse, events_since};
use sweepx_platform::CachedFileEntry;

use super::grouping::{
    DEFAULT_GROUPING_BYTES, GroupingBudget, RootScope, group_listings, group_sources,
};
use super::{self as junk_cache, StoredJunkRoot, StoredSubtreeIndex};
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
    /// Optional original candidate snapshot; local merges publish this only as historical.
    preview: Option<StoredJunkRoot>,
}

/// Reads subtree indexes and FSEvents evidence for the roots being scanned.
pub struct SubtreeCacheProvider {
    cache_dir: PathBuf,
    roots: BTreeMap<PathBuf, RootState>,
    /// One bounded path/cursor map, shared by every root rather than copied per consumer.
    changes: Option<ChangeIndex>,
}

impl SubtreeCacheProvider {
    /// Compatibility entry point for file-index preparation. Candidate slots always miss.
    ///
    /// A one-shot event history cannot qualify current whole-root facts: recently completed
    /// writes can arrive after HistoryDone. Callers must freshly traverse roots, while cached
    /// file lengths still require live type/length confirmation in the scanner. The context
    /// argument and aligned slots remain for callers migrating from whole-root replay.
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
        let _ = context;
        let reader = junk_cache::CacheReader::new(cache_dir);
        (
            Self::prepare_loaded(cache_dir, roots, reader, query, change_count, change_bytes),
            vec![None; roots.len()],
        )
    }

    /// Validates file indexes using the budget already spent on historical preview reads.
    /// No whole-root report is replayed as current; directories remain freshly observed.
    pub fn prepare_files(
        cache_dir: &Path,
        roots: &[PathBuf],
        reader: junk_cache::CacheReader,
    ) -> Self {
        Self::prepare_loaded(
            cache_dir,
            roots,
            reader,
            |paths, since| events_since(paths, since, DRAIN_TIMEOUT),
            MAX_CHANGE_PATHS,
            MAX_CHANGE_BYTES,
        )
    }

    /// Loads original-scope historical candidates and file indexes under the same shared read
    /// budget before one history query. Used only for local fragment publication, never replay.
    pub(crate) fn prepare_fragments(
        cache_dir: &Path,
        roots: &[PathBuf],
        scope: &[PathBuf],
        reader: junk_cache::CacheReader,
    ) -> Self {
        Self::prepare_fragments_with_query(cache_dir, roots, scope, reader, |paths, since| {
            events_since(paths, since, DRAIN_TIMEOUT)
        })
    }

    fn prepare_fragments_with_query(
        cache_dir: &Path,
        roots: &[PathBuf],
        scope: &[PathBuf],
        mut reader: junk_cache::CacheReader,
        query: impl FnOnce(&[&Path], FsEventId) -> std::io::Result<ChangeLog>,
    ) -> Self {
        let previews = reader.historical_roots_scoped(roots, scope);
        let mut provider = Self::prepare_loaded(
            cache_dir,
            roots,
            reader,
            query,
            MAX_CHANGE_PATHS,
            MAX_CHANGE_BYTES,
        );
        for (root, preview) in roots.iter().zip(previews) {
            if let Some(state) = provider.roots.get_mut(root) {
                state.preview = preview;
            }
        }
        provider
    }

    fn prepare_loaded(
        cache_dir: &Path,
        roots: &[PathBuf],
        mut reader: junk_cache::CacheReader,
        query: impl FnOnce(&[&Path], FsEventId) -> std::io::Result<ChangeLog>,
        change_count: usize,
        change_bytes: usize,
    ) -> Self {
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
        let since = indexes
            .values()
            .map(StoredSubtreeIndex::since_event_id)
            .min();
        let paths: Vec<&Path> = roots
            .iter()
            .take(max_roots)
            .filter(|root| indexes.contains_key(root.as_path()))
            .map(|root| root.as_path())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let log = since.and_then(|since| query(&paths, since).ok());
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
                            preview: None,
                        },
                    )
                })
                .collect()
        } else {
            BTreeMap::new()
        };
        Self {
            cache_dir: cache_dir.to_path_buf(),
            roots: root_states,
            changes,
        }
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

    /// Publishes file facts only if capture still matches the traversal's observed native root.
    /// A root replaced before capture must never bind the old listing to the new directory.
    pub fn store_observed_index(
        &self,
        source: &sweepx_model::ScannedEntry,
        all_roots: &[PathBuf],
        since_event_id: FsEventId,
        covered: &BTreeMap<String, bool>,
        listings: &BTreeMap<String, sweepx_scanner::DirListing>,
    ) -> std::io::Result<()> {
        let root = crate::junk::git::native_path(source)
            .ok_or_else(|| std::io::Error::other("observed cache root path unavailable"))?;
        let index =
            StoredSubtreeIndex::capture(&root, all_roots, since_event_id, covered, listings)?;
        self.publish_observed_index(source, index)
    }

    /// Publishes a root's borrowed partition; coverage and ownership were checked once by the
    /// caller's shared grouping pass, while capture still rechecks the current native root.
    pub(crate) fn store_observed_index_owned<'a>(
        &self,
        source: &sweepx_model::ScannedEntry,
        since_event_id: FsEventId,
        listings: impl IntoIterator<Item = (&'a String, &'a sweepx_scanner::DirListing)>,
    ) -> std::io::Result<()> {
        let root = crate::junk::git::native_path(source)
            .ok_or_else(|| std::io::Error::other("observed cache root path unavailable"))?;
        let index = StoredSubtreeIndex::capture_owned(&root, since_event_id, listings)?;
        self.publish_observed_index(source, index)
    }

    fn publish_observed_index(
        &self,
        source: &sweepx_model::ScannedEntry,
        index: StoredSubtreeIndex,
    ) -> std::io::Result<()> {
        if !index.matches_observed_root(source) {
            return Err(std::io::Error::other("cache root changed after traversal"));
        }
        junk_cache::write_subtree_index(&self.cache_dir, &index)
    }

    /// Publishes observed roots using direct single-root projection or bounded shared grouping.
    ///
    /// The original request scope owns nested facts using its deepest matching root; duplicate
    /// root spellings publish only their final ordinal. Every publication rechecks the observed
    /// native root, and each root retains its independent 4 MiB optional projection allowance.
    /// Auxiliary views share an 8 MiB capacity estimate. Exhaustion/allocation failure reports
    /// one omission through `on_error`; other write failures report their root individually.
    /// Cancellation omits remaining cache work. Neither omission nor cache errors change current
    /// scan facts or classification completeness. This method performs worker-side filesystem I/O.
    #[allow(clippy::too_many_arguments)]
    pub fn store_observed_indexes(
        &self,
        sources: &[sweepx_model::ScannedEntry],
        all_roots: &[PathBuf],
        since_event_id: FsEventId,
        covered: &BTreeMap<String, bool>,
        listings: &BTreeMap<String, sweepx_scanner::DirListing>,
        cancel: &sweepx_platform::CancellationToken,
        on_error: impl FnMut(&Path, std::io::Error),
    ) {
        self.store_observed_indexes_with_budget(
            sources,
            all_roots,
            since_event_id,
            covered,
            listings,
            cancel,
            DEFAULT_GROUPING_BYTES,
            on_error,
        );
    }

    /// Injectable auxiliary allowance for deterministic omission tests of the shipped batch path.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_observed_indexes_with_budget(
        &self,
        sources: &[sweepx_model::ScannedEntry],
        all_roots: &[PathBuf],
        since_event_id: FsEventId,
        covered: &BTreeMap<String, bool>,
        listings: &BTreeMap<String, sweepx_scanner::DirListing>,
        cancel: &sweepx_platform::CancellationToken,
        auxiliary_bytes: usize,
        mut on_error: impl FnMut(&Path, std::io::Error),
    ) {
        if sources.is_empty() || cancel.is_cancelled() {
            return;
        }
        let mut budget = GroupingBudget::new(auxiliary_bytes);
        let prepared = (|| {
            let scope = RootScope::new(all_roots, &mut budget)?;
            let sources = group_sources(&scope, sources, &mut budget, cancel)?;
            Some((scope, sources))
        })();
        let Some((scope, sources)) = prepared else {
            if !cancel.is_cancelled() {
                on_error(
                    &self.cache_dir,
                    std::io::Error::other("optional cache index grouping budget unavailable"),
                );
            }
            return;
        };
        if sources.is_empty() || cancel.is_cancelled() {
            return;
        }
        if scope.len() == 1 {
            // Preserve capture's early tail omission: partitioning the entire listing table
            // cannot help a single root, whose independent wire allowance may fill early.
            let root = &all_roots[0];
            let Some(source) = sources.get(0).first() else {
                return;
            };
            if root.to_str().is_some_and(|root| covered.contains_key(root))
                && let Err(error) =
                    self.store_observed_index(source, all_roots, since_event_id, covered, listings)
            {
                on_error(root, error);
            }
            return;
        }
        let Some(listings) = group_listings(&scope, covered, listings, &mut budget, cancel) else {
            if !cancel.is_cancelled() {
                on_error(
                    &self.cache_dir,
                    std::io::Error::other("optional cache index grouping budget unavailable"),
                );
            }
            return;
        };
        for (ordinal, root) in all_roots.iter().enumerate() {
            if cancel.is_cancelled() {
                break;
            }
            let Some(source) = sources.get(ordinal).first() else {
                continue;
            };
            if root.to_str().is_none_or(|root| !covered.contains_key(root)) {
                continue;
            }
            if let Err(error) = self.store_observed_index_owned(
                source,
                since_event_id,
                listings.get(ordinal).iter().copied(),
            ) {
                on_error(root, error);
            }
        }
    }

    /// Consumes one validated generation after traversal. Current selected listings take
    /// priority; only unaffected, independently covered siblings carry forward. Strict
    /// ancestors are omitted rather than granting recursive coverage to shallow observations.
    /// A missing/unusable history retains the old generation and returns false. The cursor
    /// must have been captured before this provider's history query and the new traversal.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_observed_fragment(
        &mut self,
        source: &sweepx_model::ScannedEntry,
        all_roots: &[PathBuf],
        cursor: FsEventId,
        selected: &[PathBuf],
        covered: &BTreeMap<String, bool>,
        listings: &BTreeMap<String, sweepx_scanner::DirListing>,
        candidates: Vec<junk_cache::StoredJunkCandidate>,
    ) -> std::io::Result<bool> {
        let root = crate::junk::git::native_path(source)
            .ok_or_else(|| std::io::Error::other("observed fragment root unavailable"))?;
        self.store_observed_fragment_owned(
            source,
            all_roots,
            cursor,
            selected,
            covered,
            listings.iter().filter(|(path, _)| {
                covered.get(*path) == Some(&true)
                    && owner(Path::new(path), all_roots) == Some(root.as_path())
            }),
            candidates,
        )
    }

    /// Same fragment contract as `store_observed_fragment`, using a shared fresh-fact partition.
    /// The original scope, selected coverage and both old/new native bindings remain mandatory.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn store_observed_fragment_owned<'a>(
        &mut self,
        source: &sweepx_model::ScannedEntry,
        all_roots: &[PathBuf],
        cursor: FsEventId,
        selected: &[PathBuf],
        covered: &BTreeMap<String, bool>,
        listings: impl IntoIterator<Item = (&'a String, &'a sweepx_scanner::DirListing)>,
        candidates: Vec<junk_cache::StoredJunkCandidate>,
    ) -> std::io::Result<bool> {
        let root = crate::junk::git::native_path(source)
            .ok_or_else(|| std::io::Error::other("observed fragment root unavailable"))?;
        let paths: Vec<_> = selected
            .iter()
            .filter(|path| {
                path.starts_with(&root) && owner(path, all_roots) == Some(root.as_path())
            })
            .cloned()
            .collect();
        if paths.is_empty()
            || paths.iter().any(|path| {
                path.to_str()
                    .is_none_or(|path| covered.get(path) != Some(&true))
            })
        {
            return Err(std::io::Error::other(
                "selected fragment coverage unavailable",
            ));
        }
        let Some(changes) = &self.changes else {
            return Ok(false);
        };
        let Some(state) = self.roots.remove(&root) else {
            return Ok(false);
        };
        if state.unusable {
            return Ok(false);
        }
        if !state.index.matches_observed_root(source) {
            return Err(std::io::Error::other(
                "fragment original root binding changed",
            ));
        }
        let mut merged = StoredSubtreeIndex::capture_owned(&root, cursor, listings)?;
        if !merged.matches_observed_root(source) {
            return Err(std::io::Error::other(
                "fragment root changed after traversal",
            ));
        }
        merged.listings.retain(|path, _| {
            paths
                .iter()
                .any(|selected| Path::new(path).starts_with(selected))
        });
        merged
            .covered
            .retain(|path, _| merged.listings.contains_key(path));
        // Same conservative JSON allowances as capture, charged before copies. Fresh facts
        // win optional retention; index omission never permits skipping directories or files.
        let used = merged.listings.iter().fold(
            1024usize.saturating_add(root.as_os_str().len().saturating_mul(6)),
            |used, (path, listing)| {
                listing.files.keys().fold(
                    used.saturating_add(path.len().saturating_mul(12).saturating_add(128)),
                    |used, name| {
                        used.saturating_add(name.len().saturating_mul(6).saturating_add(64))
                    },
                )
            },
        );
        let mut remaining = junk_cache::Limits::default()
            .entry_bytes
            .saturating_sub(used);
        let since = state.index.since_event_id;
        for (path, listing) in state.index.listings {
            let native = Path::new(&path);
            if state.index.covered.get(&path) != Some(&true)
                || owner(native, all_roots) != Some(root.as_path())
                || paths
                    .iter()
                    .any(|selected| native.starts_with(selected) || selected.starts_with(native))
                || changes.overlaps(native, since)
            {
                continue;
            }
            let cost = path.len().saturating_mul(12).saturating_add(128);
            if cost > remaining {
                break;
            }
            remaining -= cost;
            let mut saved = junk_cache::StoredDirListing::default();
            for (name, bytes) in listing.files {
                let cost = name.len().saturating_mul(6).saturating_add(64);
                if cost > remaining {
                    break;
                }
                remaining -= cost;
                saved.files.insert(name, bytes);
            }
            merged.covered.insert(path.clone(), true);
            merged.listings.insert(path, saved);
        }
        junk_cache::write_subtree_index(&self.cache_dir, &merged)?;
        if let Some(preview) = state.preview {
            let preview = preview.merge_preview(&paths, candidates, Some(cursor));
            if !preview.matches_observed_root(source) {
                return Err(std::io::Error::other(
                    "fragment preview root binding changed",
                ));
            }
            junk_cache::write(&self.cache_dir, &preview)?;
        }
        Ok(true)
    }
}

fn owner<'a>(path: &Path, roots: &'a [PathBuf]) -> Option<&'a Path> {
    roots
        .iter()
        .filter(|root| path.starts_with(root))
        .max_by_key(|root| root.components().count())
        .map(PathBuf::as_path)
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
    use super::super::StoredDirListing;
    use super::*;

    fn scan_root(root: &Path) -> sweepx_scanner::ClassifiedScan {
        sweepx_scanner::Scanner::new(
            sweepx_scanner::HostPlatformScanner::new(),
            sweepx_scanner::ScannerOptions::default(),
        )
        .scan_classified(
            &[sweepx_platform::ScanRoot::new(root.to_path_buf()).unwrap()],
            &sweepx_platform::CancellationToken::new(),
            &crate::junk::JunkService::built_in().unwrap(),
            None,
        )
        .unwrap()
    }

    fn fragment_provider(
        cache: &Path,
        roots: &[PathBuf],
        log: std::io::Result<ChangeLog>,
    ) -> SubtreeCacheProvider {
        SubtreeCacheProvider::prepare_fragments_with_query(
            cache,
            roots,
            roots,
            junk_cache::CacheReader::new(cache),
            |_, _| log,
        )
    }

    fn empty_history() -> ChangeLog {
        ChangeLog {
            events: vec![],
            must_rescan: false,
        }
    }

    #[test]
    fn fragment_merges_fresh_files_and_only_validated_siblings_across_generations() {
        let (_fixture, cache, roots) = seeded_cache();
        let root = &roots[0];
        let selected = root.join("selected");
        let sibling = root.join("sibling");
        let changed = root.join("changed");
        for path in [&selected, &sibling, &changed] {
            fs::create_dir(path).unwrap();
            fs::write(path.join("payload"), b"original").unwrap();
        }
        let removed = selected.join("removed");
        fs::create_dir(&removed).unwrap();
        let old = scan_root(root);
        SubtreeCacheProvider::prepare_files(&cache, &[], junk_cache::CacheReader::new(&cache))
            .store_observed_index(
                &old.observed_roots[0],
                &roots,
                40,
                &old.covered_paths,
                &old.dir_listings,
            )
            .unwrap();
        let other_index = fs::read(cache.join(junk_cache::index_file_name(&roots[1]))).unwrap();
        fs::write(selected.join("payload"), b"larger new selected bytes").unwrap();
        fs::write(changed.join("payload"), b"outside mutation").unwrap();
        fs::remove_dir(&removed).unwrap();
        let mut provider = fragment_provider(
            &cache,
            &roots,
            Ok(ChangeLog {
                events: [&selected, &changed]
                    .iter()
                    .map(|path| sweepx_scanner::ChangeEvent {
                        path: path.join("payload").to_str().unwrap().into(),
                        id: 60,
                        flags: 0,
                    })
                    .collect(),
                must_rescan: false,
            }),
        );
        let fresh = scan_root(root);
        assert!(
            provider
                .store_observed_fragment(
                    &fresh.observed_roots[0],
                    &roots,
                    100,
                    std::slice::from_ref(&selected),
                    &fresh.covered_paths,
                    &fresh.dir_listings,
                    vec![]
                )
                .unwrap()
        );
        let index = junk_cache::CacheReader::new(&cache).index(root).unwrap();
        assert_eq!(index.since_event_id(), 100);
        assert!(
            !index.is_covered(root.to_str().unwrap()),
            "shallow ancestors cannot become recursively covered"
        );
        assert!(index.listing(removed.to_str().unwrap()).is_none());
        assert!(
            index.listing(changed.to_str().unwrap()).is_none(),
            "changed outside facts cannot advance their cursor"
        );
        for path in [&selected, &sibling] {
            assert!(index.is_covered(path.to_str().unwrap()));
            assert_eq!(
                index.listing(path.to_str().unwrap()).unwrap().files["payload"],
                u128::from(fs::symlink_metadata(path.join("payload")).unwrap().len())
            );
        }
        assert_eq!(
            fs::read(cache.join(junk_cache::index_file_name(&roots[1]))).unwrap(),
            other_index
        );
        assert!(junk_cache::CacheReader::new(&cache).historical_roots(&roots)[0].is_some());
        let (next, reports) = SubtreeCacheProvider::prepare_with_query(
            &cache,
            &roots[..1],
            Some(&[0; 32]),
            |_, since| {
                assert_eq!(since, 100);
                Ok(empty_history())
            },
        );
        assert!(
            reports[0].is_none(),
            "mixed candidate namespaces remain historical even with empty history"
        );
        let child = sweepx_platform::DirectoryEntryRecord {
            path: sibling.join("payload"),
            file_name: sweepx_model::NativeName::UnixBytes(b"payload".to_vec()),
        };
        assert!(
            matches!(&next.plan_entries(&sibling, std::slice::from_ref(&child)).unwrap()[0],
            PlannedEntry::ReuseFile(file) if file.logical_bytes == u128::from(fs::metadata(&child.path).unwrap().len()))
        );
        // A second local generation must retain the first generation's fresh selected facts.
        let mut next = fragment_provider(&cache, &roots[..1], Ok(empty_history()));
        fs::write(sibling.join("payload"), b"second local generation").unwrap();
        let fresh = scan_root(root);
        assert!(
            next.store_observed_fragment(
                &fresh.observed_roots[0],
                &roots,
                200,
                std::slice::from_ref(&sibling),
                &fresh.covered_paths,
                &fresh.dir_listings,
                vec![]
            )
            .unwrap()
        );
        let index = junk_cache::CacheReader::new(&cache).index(root).unwrap();
        for path in [&selected, &sibling] {
            assert_eq!(
                index.listing(path.to_str().unwrap()).unwrap().files["payload"],
                u128::from(fs::metadata(path.join("payload")).unwrap().len())
            );
        }
        let (racing, _) = SubtreeCacheProvider::prepare_with_query(
            &cache,
            &roots[..1],
            Some(&[0; 32]),
            |_, since| {
                assert_eq!(since, 200);
                Ok(ChangeLog {
                    events: vec![sweepx_scanner::ChangeEvent {
                        path: child.path.to_str().unwrap().into(),
                        id: 210,
                        flags: 0,
                    }],
                    must_rescan: false,
                })
            },
        );
        assert!(matches!(
            &racing.plan_entries(&sibling, &[child]).unwrap()[0],
            PlannedEntry::Inspect(_)
        ));
    }

    #[test]
    fn fragment_history_failure_never_advances_published_facts() {
        let (_fixture, cache, roots) = seeded_cache();
        let fresh = scan_root(&roots[0]);
        let before_index = fs::read(cache.join(junk_cache::index_file_name(&roots[0]))).unwrap();
        let before_report = fs::read(cache.join(junk_cache::record_file_name(&roots[0]))).unwrap();
        for log in [
            Err(std::io::Error::other("missing history")),
            Ok(ChangeLog {
                events: vec![],
                must_rescan: true,
            }),
            Ok(ChangeLog {
                events: vec![sweepx_scanner::ChangeEvent {
                    path: "relative".into(),
                    id: 50,
                    flags: 0,
                }],
                must_rescan: false,
            }),
        ] {
            let mut provider = fragment_provider(&cache, &roots, log);
            assert!(
                !provider
                    .store_observed_fragment(
                        &fresh.observed_roots[0],
                        &roots,
                        100,
                        &roots[..1],
                        &fresh.covered_paths,
                        &fresh.dir_listings,
                        vec![]
                    )
                    .unwrap()
            );
            assert_eq!(
                fs::read(cache.join(junk_cache::index_file_name(&roots[0]))).unwrap(),
                before_index
            );
            assert_eq!(
                fs::read(cache.join(junk_cache::record_file_name(&roots[0]))).unwrap(),
                before_report
            );
        }
    }

    #[test]
    fn fragment_incomplete_coverage_and_replaced_native_root_refuse_publication() {
        let (_fixture, cache, roots) = seeded_cache();
        let mut provider = fragment_provider(&cache, &roots, Ok(empty_history()));
        let fresh = scan_root(&roots[0]);
        let before = fs::read(cache.join(junk_cache::index_file_name(&roots[0]))).unwrap();
        let mut covered = fresh.covered_paths.clone();
        covered.insert(roots[0].to_str().unwrap().into(), false);
        assert!(
            provider
                .store_observed_fragment(
                    &fresh.observed_roots[0],
                    &roots,
                    100,
                    &roots[..1],
                    &covered,
                    &fresh.dir_listings,
                    vec![]
                )
                .is_err()
        );
        assert_eq!(
            fs::read(cache.join(junk_cache::index_file_name(&roots[0]))).unwrap(),
            before
        );
        fs::rename(&roots[0], roots[0].with_extension("old")).unwrap();
        fs::create_dir(&roots[0]).unwrap();
        assert!(
            provider
                .store_observed_fragment(
                    &fresh.observed_roots[0],
                    &roots,
                    100,
                    &roots[..1],
                    &fresh.covered_paths,
                    &fresh.dir_listings,
                    vec![]
                )
                .is_err()
        );
        assert_eq!(
            fs::read(cache.join(junk_cache::index_file_name(&roots[0]))).unwrap(),
            before
        );
    }

    #[test]
    fn fragment_merge_drops_newly_nested_root_facts_from_ancestor_index() {
        let (_fixture, cache, roots) = seeded_cache();
        let root = &roots[0];
        let selected = root.join("selected");
        let nested = root.join("nested");
        for path in [&selected, &nested] {
            fs::create_dir(path).unwrap();
            fs::write(path.join("payload"), b"independent owner").unwrap();
        }
        let old = scan_root(root);
        let old_index =
            StoredSubtreeIndex::capture(root, &roots, 40, &old.covered_paths, &old.dir_listings)
                .unwrap();
        junk_cache::write_subtree_index(&cache, &old_index).unwrap();
        assert!(old_index.listing(nested.to_str().unwrap()).is_some());
        let scope = [root.clone(), nested.clone()];
        let mut provider = SubtreeCacheProvider::prepare_fragments_with_query(
            &cache,
            &roots[..1],
            &scope,
            junk_cache::CacheReader::new(&cache),
            |_, _| Ok(empty_history()),
        );
        // The old candidate report has a different attribution scope and cannot be merged.
        assert!(provider.roots[root].preview.is_none());
        assert!(
            provider
                .store_observed_fragment(
                    &old.observed_roots[0],
                    &scope,
                    100,
                    &[selected],
                    &old.covered_paths,
                    &old.dir_listings,
                    vec![]
                )
                .unwrap()
        );
        let merged = junk_cache::CacheReader::new(&cache).index(root).unwrap();
        assert!(merged.listing(nested.to_str().unwrap()).is_none());
        assert!(!merged.is_covered(nested.to_str().unwrap()));
    }

    #[test]
    fn fragment_preview_and_index_reads_share_the_invocation_budget() {
        let (_fixture, cache, roots) = seeded_cache();
        let roots = &roots[..1];
        let limits = junk_cache::Limits {
            input_bytes: fs::metadata(cache.join(junk_cache::record_file_name(&roots[0])))
                .unwrap()
                .len() as usize,
            ..junk_cache::Limits::default()
        };
        let mut reader = junk_cache::CacheReader::new(&cache);
        reader.limits = limits;
        reader.budget = junk_cache::ReadBudget::new(limits);
        let provider = SubtreeCacheProvider::prepare_fragments_with_query(
            &cache,
            roots,
            roots,
            reader,
            |_, _| panic!("the preview consumed the input allowance; index not admitted"),
        );
        assert!(provider.roots.is_empty());
        assert!(provider.changes.is_none());
    }

    #[test]
    fn historical_preview_and_file_index_share_the_encoded_input_allowance() {
        let (_fixture, cache, roots) = seeded_cache();
        let roots = [roots[0].clone()];
        let root_bytes = fs::metadata(cache.join(junk_cache::record_file_name(&roots[0])))
            .unwrap()
            .len() as usize;
        let limits = junk_cache::Limits {
            input_bytes: root_bytes,
            ..junk_cache::Limits::default()
        };
        let mut reader = junk_cache::CacheReader::new(&cache);
        reader.limits = limits;
        reader.budget = junk_cache::ReadBudget::new(limits);
        assert!(reader.historical_roots(&roots)[0].is_some());
        let provider = SubtreeCacheProvider::prepare_loaded(
            &cache,
            &roots,
            reader,
            |_, _| panic!("no index was admitted, so history is unnecessary"),
            MAX_CHANGE_PATHS,
            MAX_CHANGE_BYTES,
        );
        assert!(
            provider.roots.is_empty(),
            "preview reads must not reset the index read budget"
        );
    }

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
        use crate::junk::{
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
        let context = crate::CoreContext::new(sweepx_i18n::LocaleResolution::new(
            sweepx_i18n::Locale::EnUs,
            sweepx_i18n::LocaleSource::Explicit,
        ));
        let request = crate::ScanRequest {
            roots: vec![root.clone()],
            state_dir: None,
        };
        let old = crate::scan_junk_with_store::<crate::MemorySnapshotStore>(
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
            old_records[0].is_none(),
            "even unchanged context cannot prove current tree coverage"
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
            let fresh = crate::scan_junk_with_store::<crate::MemorySnapshotStore>(
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
            records[0].is_none(),
            "an event cursor cannot qualify whole-root replay"
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
        assert!(records[1].is_none());
        assert!(
            !provider.roots[&roots[1]].unusable,
            "unchanged native binding keeps independent file facts"
        );
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
        assert!(records.iter().all(Option::is_none));
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

#[cfg(test)]
#[path = "freshness_tests.rs"]
mod freshness_tests;
