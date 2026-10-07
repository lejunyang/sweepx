mod acceleration;
mod detail_rescan;
mod locator_reader;

pub use acceleration::{
    AcceleratedPreview, AccelerationDecision, AccelerationRefusal, qualify_acceleration,
    read_accelerated_preview,
};
pub use detail_rescan::{
    DETAIL_SCAN_MIN_ORDINAL, DetailEntryIdAllocator, DetailRescanError, DetailRescanRequest,
    DetailRescanResult, DetailRescanner, FileContentError, FileContentRequest,
};
pub use locator_reader::{
    CargoConfigMemberObservation, CargoConfigMemberPresenceObservation, CargoConfigPairConsistency,
    CargoConfigPairObservation, CargoConfigPairPresenceObservation, CargoManifestObservation,
    DirectoryPathAbsence, DirectoryPathObservation, LocatorBatchReadRequest,
    LocatorBatchReadResult, LocatorDirectoryComparison, LocatorDirectoryComparisonFailure,
    LocatorDirectoryIdentity, LocatorDirectoryLookupFailure, LocatorFileRead, LocatorFileRequest,
    LocatorReadError, LocatorReadFailure, LocatorReadLimits, LocatorReader,
};

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};

use sweepx_model::{
    ArithmeticState, Coverage, CoverageState, DecimalU128, DirectoryAggregate, EvidenceValue,
    FieldProvenance, FilesystemObjectDomainIdentity, IdentityEvidence, NativeAbsolutePath,
    NativeLocatorEvidence, NativeName, NativePathComponent, ObjectType, PlatformFileIdentity,
    ReasonCode, ScanEntryId, ScanId, ScanObjectIdentity, ScannedEntry, VolumeOrMountIdentity,
};
use sweepx_platform::{
    BoundaryKind, BoundaryRecord, CancellationToken, DirectoryHandleAdmission, DirectoryReadLimits,
    EntryKind, EntryMetadata, HardLinkKey, PlatformError, PlatformScanner, RootAdmission,
    ScanResourceLimits, ScanRoot, WalkEntry, inspect_bound_child_with_directory_admission,
    known_count, known_u128, lower_bound_u128, unknown_u128,
};
use thiserror::Error;

#[cfg(all(target_os = "linux", feature = "platform-linux"))]
pub use sweepx_platform::linux::LinuxPlatformScanner as HostPlatformScanner;
#[cfg(all(target_os = "macos", feature = "platform-macos"))]
pub use sweepx_platform::macos::MacosPlatformScanner as HostPlatformScanner;
#[cfg(all(target_os = "windows", feature = "platform-windows"))]
pub use sweepx_platform::windows::WindowsPlatformScanner as HostPlatformScanner;
/// Volume change detection, re-exported so consumers reach it through the same edge as the
/// scanner rather than taking a second dependency on the platform crate.
#[cfg(all(target_os = "windows", feature = "platform-windows"))]
pub use sweepx_platform::windows::{
    ChangeVerdict, VolumeChangeToken, compare_to_current, read_volume_change_token,
    read_volume_journal_bounds,
};

/// FSEvents change-log query, re-exported through the scanner edge so consumers (the junk cache)
/// do not take a second dependency on the macOS platform crate.
#[cfg(all(target_os = "macos", feature = "platform-macos"))]
pub use sweepx_platform::macos::fsevents::{
    ChangeEvent, ChangeLog, EventId as FsEventId, current_event_id, events_since,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerOptions {
    pub scan_id: ScanId,
    pub resource_limits: ScanResourceLimits,
    /// Requested number of directory workers. Values above 32 are capped at 32.
    pub max_workers: usize,
    /// Retains optional ordinary-file names and lengths for a later file-cache generation.
    /// Directory coverage, native root observations and required classification markers remain
    /// available when disabled. Callers with current native length observations can avoid building
    /// an unused per-file index; the default preserves cache publication for existing consumers.
    pub retain_file_index: bool,
}

impl Default for ScannerOptions {
    fn default() -> Self {
        Self {
            scan_id: ScanId::new("scan-p1"),
            resource_limits: ScanResourceLimits::default(),
            max_workers: 4,
            retain_file_index: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressEvent {
    RootAccepted {
        path: PathBuf,
    },
    EntryObserved {
        path: PathBuf,
        kind: ObjectType,
    },
    Boundary {
        path: PathBuf,
        kind: BoundaryKind,
    },
    Error {
        path: PathBuf,
        reason: ReasonCode,
    },
    Cancelled {
        path: PathBuf,
    },
    ResourceLimit {
        path: PathBuf,
    },
    /// The accelerated scan path was not used for this root.
    ///
    /// Purely informational: the portable traversal produces complete, exact results, so this is
    /// neither an error nor a boundary. It exists so a user can tell *why* a scan took the slow
    /// path -- most often because the process is not elevated, which is the normal case.
    ///
    /// `reason` is a stable machine code from [`AccelerationRefusal::code`] and must not be
    /// localized. `elevation_might_help` is carried separately so a caller can decide whether
    /// mentioning `--elevate` is honest, without re-deriving that from the code string.
    AccelerationUnavailable {
        path: PathBuf,
        reason: &'static str,
        elevation_might_help: bool,
    },
    /// A fast, non-authoritative preview of a root read from NTFS metadata.
    ///
    /// Emitted before the traversal so a caller can show a provisional total in about a second
    /// on a tree that takes minutes to walk. It carries **no execution authority**: there is no
    /// reopen recipe behind these numbers, so nothing may be deleted on the strength of a
    /// preview, and a caller must replace them with the traversal's results when those arrive.
    ///
    /// `complete` is false when some records under the root could not be resolved, in which case
    /// `logical_bytes` is a lower bound and must never be rendered as an exact size.
    AcceleratedPreview {
        path: PathBuf,
        entry_count: u64,
        logical_bytes: u128,
        complete: bool,
        elapsed_micros: u128,
    },
    Finished,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSummary {
    pub roots: Vec<ScannedEntry>,
    pub entries: Vec<ScannedEntry>,
    pub aggregates: Vec<DirectoryAggregate>,
    pub boundaries: Vec<BoundaryRecord>,
    pub progress: Vec<ProgressEvent>,
    /// Constant-size facts retained even when the optional progress log is truncated.
    pub progress_retention: ProgressRetention,
}

/// Progress-log omissions and terminal observations, independent of filesystem coverage.
///
/// Dropping an observation does not drop a file, candidate or boundary. Errors and cancellation
/// remain visible through these facts; live observers receive every event before retention.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgressRetention {
    /// Number of observed progress records absent from the retained log.
    pub omitted_events: u128,
    /// Error observations absent from the log, included in [`ScanSummary::error_count`].
    pub omitted_errors: u128,
    /// Whether traversal observed cancellation, regardless of log capacity.
    pub cancelled: bool,
    /// Whether a traversal or result-retention resource limit was observed.
    /// A limit on the optional progress log itself never sets this flag.
    pub resource_limited: bool,
    /// Whether the traversal sequencer ended; this does not imply complete coverage or success.
    pub finished: bool,
}

impl ScanSummary {
    /// Counts all observed errors, including errors displaced or omitted by log retention.
    pub fn error_count(&self) -> u128 {
        self.progress_retention.omitted_errors.saturating_add(
            self.progress
                .iter()
                .filter(|event| matches!(event, ProgressEvent::Error { .. }))
                .count() as u128,
        )
    }

    fn retain_progress(&mut self, event: ProgressEvent, cap: usize) {
        self.progress_retention.cancelled |= matches!(event, ProgressEvent::Cancelled { .. });
        self.progress_retention.resource_limited |=
            matches!(event, ProgressEvent::ResourceLimit { .. });
        self.progress_retention.finished |= matches!(event, ProgressEvent::Finished);
        if self.progress.len() < cap {
            self.progress.push(event);
            return;
        }
        // Preserve the latest failure/terminal detail when a slot exists. Earlier displaced
        // errors still contribute to the authoritative count. Routine observations never
        // overwrite diagnostic detail, and no log omission manufactures a coverage boundary.
        let omitted = if matches!(
            event,
            ProgressEvent::Error { .. } | ProgressEvent::Cancelled { .. } | ProgressEvent::Finished
        ) && let Some(last) = self.progress.last_mut()
        {
            std::mem::replace(last, event)
        } else {
            event
        };
        self.progress_retention.omitted_events =
            self.progress_retention.omitted_events.saturating_add(1);
        if matches!(omitted, ProgressEvent::Error { .. }) {
            self.progress_retention.omitted_errors =
                self.progress_retention.omitted_errors.saturating_add(1);
        }
    }
}

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("platform error: {0}")]
    Platform(#[from] PlatformError),
    #[error("root validation error: {0}")]
    RootValidation(String),
}

pub trait ScanSink {
    fn push_root(&mut self, root: &Path, entry: ScannedEntry) -> Result<(), ScanError>;
    fn push_entry(&mut self, root: &Path, entry: ScannedEntry) -> Result<(), ScanError>;
    fn push_boundary(&mut self, root: &Path, boundary: BoundaryRecord) -> Result<(), ScanError>;
    fn push_progress(&mut self, root: &Path, event: ProgressEvent) -> Result<(), ScanError>;
    fn push_aggregate(
        &mut self,
        root: &Path,
        aggregate: DirectoryAggregate,
    ) -> Result<(), ScanError>;

    /// Requires full current file observations instead of length-only bulk or cache shortcuts.
    /// Consumers needing allocation or native file facts must opt in; logical lengths alone
    /// cannot supply those fields. Directory traversal and its boundaries stay unchanged.
    fn wants_file_observations(&self) -> bool {
        false
    }

    /// Accepts current ordinary-file lengths without allocating file rows or native recipes.
    /// This shortcut still requires live, handle-relative backend observations; absent or
    /// malformed observations fall back to normal inspection. Consumers needing file identity,
    /// allocation or hard-link facts must leave this disabled. Full-file observers override it.
    fn accepts_file_lengths(&self) -> bool {
        false
    }

    /// Whether the consumer needs lower-bound directory statistics between committed batches.
    /// Disabled by default so ordinary scans do not build transient aggregate snapshots.
    fn wants_directory_progress(&self) -> bool {
        false
    }

    /// Whether final aggregates may arrive when a subtree closes, before the root finishes.
    /// The subtree and its parent must have finished enumeration. Consumers opting in must
    /// not require marker observations from other directories; aggregate ordering may change.
    fn accepts_closed_subtrees(&self) -> bool {
        false
    }

    /// Reports statistics from a committed directory batch, before recursive coverage is known.
    /// This is a provisional observation, never a replacement for the final aggregate.
    fn note_directory_progress(&mut self, _path: &Path, _aggregate: &DirectoryAggregate) {}

    /// Notes complete enumeration of the rule-relevant names under this current directory ID.
    /// Separate from recursive coverage: scoped ancestors enumerate markers without walking
    /// unrelated subtrees. Failure, truncation and cancellation never call this hook.
    fn note_directory_enumerated(&mut self, _id: &ScanEntryId) {}

    /// Optional scheduling preference, sampled at the next directory round.
    /// This path changes ordering only; it cannot admit or reopen an object.
    fn preferred_directory(&self) -> Option<PathBuf> {
        None
    }

    /// Notes the canonical path of a directory the walk completed, with its coverage.
    ///
    /// Called for every directory, candidate or not, just before the aggregate may be dropped. A
    /// classified sink uses it to record that a subtree existed and was fully scanned, which is the
    /// precondition for reusing that subtree later. Default no-op for sinks that do not cache.
    fn note_directory_coverage(&mut self, _path: &Path, _coverage: &Coverage) {}

    /// Reports native traversal coverage before retention losses weaken stored aggregates.
    /// Live analyses receive every boundary themselves and can distinguish an omitted log from
    /// an unvisited subtree. This hook does not establish reusable cache or clean authority;
    /// consumers needing retained evidence must use `note_directory_coverage` instead.
    fn note_native_directory_coverage(&mut self, _path: &Path, _coverage: &Coverage) {}

    /// Records a length-only ordinary file under its current parent and optional next-generation listing.
    ///
    /// The classified sink uses it to keep the parent's file-marker set complete for marker-based
    /// rules; no row is buffered. Default no-op for sinks that do not classify.
    fn note_cached_file(
        &mut self,
        _parent_id: &ScanEntryId,
        _file: &sweepx_platform::CachedFileEntry,
    ) {
    }

    /// Number of times evidence was lost because a retention cap was reached.
    ///
    /// "Evidence" means data a total or a coverage claim is computed from: aggregates and
    /// boundary records. Losing one of those makes the affected results genuinely incomplete.
    fn overflow_count(&self) -> usize {
        0
    }

    /// Number of times *detail* was truncated because a retention cap was reached.
    ///
    /// Detail means per-entry rows. These are dropped after their bytes
    /// have already been folded into the directory aggregate, so truncating them does not make
    /// a total wrong -- it only makes the listing partial. Kept separate from
    /// [`Self::overflow_count`] so a large scan is not reported as having inexact totals
    /// merely because it produced more rows than the result buffer holds.
    fn detail_overflow_count(&self) -> usize {
        0
    }

    /// Number of aggregates retained across the scan so far. Streaming sinks that retain none may
    /// leave this at zero.
    fn retained_aggregate_count(&self) -> usize {
        0
    }
}

/// The children of one directory captured during a scan, for file-level reuse.
///
/// Known lengths may be proposed for reuse; current backend facts must still establish ordinary
/// file type and length. The legacy `dirs` slot is empty in new scans.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct DirListing {
    /// Observed regular file basenames with known logical lengths, subject to the optional index budget.
    pub files: BTreeMap<String, u128>,
    /// Legacy directory-name slot; new scans keep directory lineage in `directory_markers` only.
    /// Reuse always enumerates current children and does not need a second copy of directory names.
    pub dirs: BTreeSet<String>,
}

/// One enumerated child about to be inspected, resolved against the cache before any syscall.
#[derive(Debug)]
pub enum PlannedEntry {
    /// A proposed unchanged regular file. Current backend facts must confirm its type and length;
    /// otherwise the scanner inspects it normally, regardless of the persisted cache claim.
    ReuseFile(sweepx_platform::CachedFileEntry),
    /// The child must be inspected normally (a directory, a changed/new file, or unknown type).
    Inspect(sweepx_platform::DirectoryEntryRecord),
}

/// Supplies validated file metadata while directories remain live-enumerated.
///
/// Whole-subtree skipping cannot use candidate rows alone: it would lose ancestor accounting,
/// current scan identities and parent markers needed by classification.
pub trait SubtreeReuse: Sync {
    /// Plans the inspection of a directory's enumerated children before any are stated.
    ///
    /// Returns a vector aligned entry-for-entry with `children`: each is reused from cache (only
    /// unchanged regular files) or inspected. `None` means no plan is available for this
    /// directory, so the scanner states every child — the safe fallback. Implementors must not
    /// reuse a file unless the directory was recorded as fully covered and file-level evidence
    /// proves that exact file unchanged. The scanner also requires current backend confirmation
    /// of the ordinary-file type and logical length before accepting a proposed reuse.
    fn plan_entries(
        &self,
        _dir_path: &Path,
        _children: &[sweepx_platform::DirectoryEntryRecord],
    ) -> Option<Vec<PlannedEntry>> {
        None
    }
}
/// Classifies observed directories using one loaded rule service.
///
/// The collecting sink evaluates directories after the marker observations they depend on.
/// Only matching rows and aggregates are retained.
/// Provisional live statistics cannot establish marker absence or a final rule decision.
pub trait JunkClassifier {
    /// Whether decisions depend only on this entry and its own/parent file-marker sets.
    ///
    /// Opting in permits classification after complete subtree and parent enumeration, using
    /// the same `classify` implementation. All decisions, including rule precedence and
    /// negative predicates, must be final with these facts. The default waits for the entire
    /// root's markers so existing custom evaluators can inspect the full index safely.
    fn uses_only_local_markers(&self) -> bool {
        false
    }

    /// Whether a file basename is needed as a classification marker.
    /// Defaults to retaining every name for custom evaluators. Built-in rule services can
    /// restrict this to their admitted marker set without changing rule semantics.
    fn needs_file_marker(&self, _name: &NativeName) -> bool {
        true
    }

    /// Returns the stable id of the rule that makes this directory a junk candidate, or
    /// `None` when no rule matches.
    ///
    /// `markers` maps a directory entry id to the native basenames of file entries observed
    /// directly under it. Rules may need the directory's own markers or its parent's, so the
    /// whole index is passed rather than one set. The classifier must base its decision on
    /// captured identity, locator and these markers, never on the display path.
    fn classify(
        &self,
        entry: &ScannedEntry,
        markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
    ) -> Option<String>;
}

/// Borrowed live observations from the existing classified traversal.
///
/// Callbacks run synchronously on the scan sequencer, not the directory workers. Consumers must
/// keep them short and bound any owned copies or event queues. Local-marker classifiers may
/// emit completed subtrees before the root finishes; other classifiers wait for root markers.
/// A candidate callback is emitted only after its final aggregate
/// and rule decision have been admitted. This interface does not provide Git enrichment, a UI
/// queue or execution authority. Cancellation uses the scan's existing token.
pub trait ClassifiedScanObserver {
    /// Observes each current entry before optional row retention or directory classification.
    /// A borrowed fact is not execution authorization; expensive work belongs off the UI thread.
    fn on_entry(&mut self, _entry: &ScannedEntry) {}

    /// Requests current file metadata rather than logical-length-only cache reuse.
    /// Required for analyses consuming `on_entry` for every regular file, including backends
    /// that can otherwise report live logical lengths without building full file rows.
    fn wants_file_observations(&self) -> bool {
        false
    }

    /// Whether provisional directory aggregates are useful to this observer.
    /// Defaults to true for existing interactive consumers; file-only analyses can avoid them.
    fn wants_directory_progress(&self) -> bool {
        true
    }

    /// Reports progress even when the retained progress log is full.
    fn on_progress(&mut self, _root: &Path, _event: &ProgressEvent) {}

    /// Reports a boundary even when the retained boundary log is full.
    fn on_boundary(&mut self, _boundary: &BoundaryRecord) {}

    /// Receives native recursive coverage before optional row, boundary-log or aggregate retention
    /// losses weaken stored coverage. Combine with live boundaries/errors for the analysis scope;
    /// this does not upgrade retained summaries, classifications or cache reuse authority.
    fn on_directory_coverage(&mut self, _path: &Path, _coverage: &Coverage) {}

    /// Reports a committed directory batch as lower-bound statistics.
    /// Final statistics for classified directories arrive with `on_candidate`.
    fn on_directory_progress(&mut self, _path: &Path, _aggregate: &DirectoryAggregate) {}

    /// Reports one retained base rule candidate; interpretation remains the caller's job.
    fn on_candidate(
        &mut self,
        _entry: &ScannedEntry,
        _rule_id: &str,
        _aggregate: &DirectoryAggregate,
    ) {
    }

    /// Selects a directory preference for the next bounded scheduling round.
    /// The scanner prioritizes an already admitted path or its admitted ancestor/descendants.
    /// Arbitrary or stale paths cannot add work, bypass boundaries or authorize execution.
    fn preferred_directory(&self) -> Option<PathBuf> {
        None
    }
}

/// Result of a classified scan: the pruned summary plus the rule id chosen per entry.
pub struct ClassifiedScan {
    /// Present only for selected-subtree scans. True requires every requested directory to
    /// reach coverage reporting and all observations below it to be complete. Shallow
    /// ancestors are excluded; classification/resource diagnostics remain separate.
    pub subtree_coverage_complete: Option<bool>,
    /// Optional native root observations for cache publication, including non-candidate roots.
    /// Charged to the shared metadata budget and evictable; absent evidence forbids publication.
    /// These rows do not enter the candidate summary or machine output.
    pub observed_roots: Vec<ScannedEntry>,
    /// Summary whose directory rows contain only classified candidates, with sparse `.git` file
    /// rows retained as worktree/submodule boundary facts.
    pub summary: ScanSummary,
    /// Entry id to the rule id returned by the classifier, keyed for candidate assembly.
    pub decisions: BTreeMap<ScanEntryId, String>,
    /// Native names of directory children observed under each parent mapped to the child
    /// entry id, even when the child directory itself was not classified and its row dropped.
    pub directory_markers: BTreeMap<ScanEntryId, BTreeMap<String, ScanEntryId>>,
    /// Coverage of *every* directory the walk completed, not just classified candidates.
    ///
    /// The retained aggregates only cover candidate directories now, but post-scan checks (the
    /// Git repository evidence) still must know whether a non-candidate parent was scanned
    /// completely. Keeping just the small Coverage, rather than the whole aggregate, preserves
    /// that distinction without re-retaining the aggregate.
    pub coverages: BTreeMap<ScanEntryId, Coverage>,
    /// Canonical path → whether the directory was fully covered, for every directory scanned.
    pub covered_paths: BTreeMap<String, bool>,
    /// Canonical directory path → its captured file/directory children, for file-level reuse.
    pub dir_listings: BTreeMap<String, DirListing>,
}

// Manual `Debug`: the classifier trait object intentionally carries no Debug bound.
impl std::fmt::Debug for CollectingScanSink<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CollectingScanSink")
            .field("summary", &self.summary)
            .field("limits", &self.limits)
            .field("overflow_count", &self.overflow_count)
            .field("detail_overflow_count", &self.detail_overflow_count)
            .field("classified", &self.classifier.is_some())
            .finish_non_exhaustive()
    }
}
struct CollectingScanSink<'a> {
    summary: ScanSummary,
    observed_roots: Vec<ScannedEntry>,
    limits: ScanResourceLimits,
    overflowed_roots: BTreeSet<PathBuf>,
    overflow_count: usize,
    detail_overflowed_roots: BTreeSet<PathBuf>,
    detail_overflow_count: usize,
    /// Number of retained rows that are directories. Directory rows carry classification
    /// evidence (junk rules match directories), so they are admitted against their own count
    /// rather than sharing a pool that file rows could exhaust.
    retained_directories: usize,
    /// Ordinary detail rows share a byte allowance because native ancestor recipes make a
    /// deep entry much larger than a shallow one. Counts alone do not bound that storage.
    retained_entry_bytes: usize,
    /// When present, the sink runs in junk mode: non-directory rows feed only the marker index,
    /// and directory rows are classified when their aggregate is pushed.
    classifier: Option<&'a dyn JunkClassifier>,
    observer: Option<&'a mut dyn ClassifiedScanObserver>,
    /// Directory rows observed but not yet classified (the aggregate arrives after the subtree
    /// walk completes). Keyed by the row's entry id.
    pending_directories: BTreeMap<ScanEntryId, ScannedEntry>,
    /// Ids of rows that entered through `push_root`, so a classified root is routed back to
    /// `summary.roots` rather than `summary.entries`.
    pending_root_ids: BTreeSet<ScanEntryId>,
    /// Native basenames of file rows observed directly under a directory, keyed by the
    /// parent's entry id. Cheap names only -- rows themselves are dropped.
    file_markers: BTreeMap<ScanEntryId, BTreeSet<String>>,
    /// Native names of *directory* rows directly under a directory, mapped to the child's own
    /// entry id. Non-junk directory rows are dropped too, but post-scan checks need both to
    /// know the name existed (e.g. `.git`) and to reconstruct the parent chain.
    directory_markers: BTreeMap<ScanEntryId, BTreeMap<String, ScanEntryId>>,
    /// Coverage per completed directory, retained for every directory and returned with the scan.
    coverages: BTreeMap<ScanEntryId, Coverage>,
    /// Canonical path of every fully covered directory, even non-candidates, for the reuse index.
    covered_paths: BTreeMap<String, bool>,
    /// Captured file/directory children keyed by canonical directory path, for file-level reuse.
    dir_listings: BTreeMap<String, DirListing>,
    /// Optional file-index retention is independent of required marker and directory evidence.
    retain_file_index: bool,
    /// Rule id chosen per classified directory, returned with the finished scan.
    decisions: BTreeMap<ScanEntryId, String>,
    // One budget spans required facts and optional reuse indexes. Per-root counters reset only
    // when sequential root admission begins; global retained storage remains charged.
    metadata_bytes: usize,
    root_metadata_bytes: usize,
    reuse_bytes: usize,
    root_reuse_bytes: usize,
    active_root: PathBuf,
    metadata_lost: bool,
    scoped: bool,
    enumerated_directories: BTreeSet<ScanEntryId>,
    selected_paths: Option<&'a [PathBuf]>,
    selected_seen: Vec<bool>,
    selected_coverage_complete: bool,
}

impl<'a> CollectingScanSink<'a> {
    fn new(limits: ScanResourceLimits) -> Self {
        Self {
            summary: ScanSummary {
                progress_retention: Default::default(),
                roots: Vec::new(),
                entries: Vec::new(),
                aggregates: Vec::new(),
                boundaries: Vec::new(),
                progress: Vec::new(),
            },
            limits,
            observed_roots: Vec::new(),
            overflowed_roots: BTreeSet::new(),
            overflow_count: 0,
            detail_overflowed_roots: BTreeSet::new(),
            detail_overflow_count: 0,
            retained_directories: 0,
            retained_entry_bytes: 0,
            classifier: None,
            observer: None,
            pending_directories: BTreeMap::new(),
            pending_root_ids: BTreeSet::new(),
            file_markers: BTreeMap::new(),
            directory_markers: BTreeMap::new(),
            coverages: BTreeMap::new(),
            covered_paths: BTreeMap::new(),
            dir_listings: BTreeMap::new(),
            retain_file_index: true,
            decisions: BTreeMap::new(),
            metadata_bytes: 0,
            root_metadata_bytes: 0,
            reuse_bytes: 0,
            root_reuse_bytes: 0,
            active_root: PathBuf::new(),
            metadata_lost: false,
            scoped: false,
            enumerated_directories: BTreeSet::new(),
            selected_paths: None,
            selected_seen: Vec::new(),
            selected_coverage_complete: true,
        }
    }

    /// Constructs a sink in junk classification mode driven by `classifier`.
    fn new_classified(limits: ScanResourceLimits, classifier: &'a dyn JunkClassifier) -> Self {
        let mut sink = Self::new(limits);
        sink.classifier = Some(classifier);
        sink
    }

    fn finish(self) -> ScanSummary {
        self.summary
    }

    /// Finishes a classified scan.
    ///
    /// Rows left pending are directories whose aggregate never arrived (mount/refused
    /// boundaries already recorded elsewhere); dropping them is consistent with their
    /// subtree not having been traversed.
    fn finish_classified(self) -> ClassifiedScan {
        ClassifiedScan {
            subtree_coverage_complete: self.selected_paths.map(|_| {
                self.selected_coverage_complete && self.selected_seen.iter().all(|seen| *seen)
            }),
            observed_roots: self.observed_roots,
            summary: self.summary,
            decisions: self.decisions,
            directory_markers: self.directory_markers,
            coverages: self.coverages,
            covered_paths: self.covered_paths,
            dir_listings: self.dir_listings,
        }
    }

    /// Admits retained metadata, evicting optional indexes before losing classification facts.
    /// These estimates include owned strings and fixed container allowances; they do
    /// not claim to measure allocator RSS. Optional index omissions only force fresh metadata.
    fn admit_metadata(&mut self, bytes: usize, required: bool) -> bool {
        let fits = |global: usize, root: usize| {
            global
                .checked_add(bytes)
                .is_some_and(|next| next <= self.limits.max_classified_metadata_bytes)
                && root
                    .checked_add(bytes)
                    .is_some_and(|next| next <= self.limits.max_classified_root_metadata_bytes)
        };
        if required && !fits(self.metadata_bytes, self.root_metadata_bytes) {
            self.dir_listings.clear();
            self.covered_paths.clear();
            self.observed_roots = Vec::new();
            self.metadata_bytes -= self.reuse_bytes;
            self.root_metadata_bytes -= self.root_reuse_bytes;
            self.reuse_bytes = 0;
            self.root_reuse_bytes = 0;
        }
        if !fits(self.metadata_bytes, self.root_metadata_bytes) {
            if required {
                self.metadata_lost = true;
                let root = self.active_root.clone();
                self.mark_detail_overflow(
                    &root,
                    &root,
                    "classified metadata byte budget exhausted",
                );
            }
            return false;
        }
        self.metadata_bytes += bytes;
        self.root_metadata_bytes += bytes;
        if !required {
            self.reuse_bytes += bytes;
            self.root_reuse_bytes += bytes;
        }
        true
    }

    fn row_cost(entry: &ScannedEntry) -> usize {
        entry
            .estimated_retained_bytes()
            .saturating_add(512)
            .saturating_add(
                entry
                    .identity
                    .as_ref()
                    .map_or(0, |id| id.entry_id.as_str().len()),
            )
    }

    fn record_file(
        &mut self,
        parent_id: &ScanEntryId,
        name: &NativeName,
        path: &Path,
        size: Option<u128>,
    ) {
        let needs_marker = self
            .classifier
            .is_some_and(|classifier| classifier.needs_file_marker(name));
        if !self.retain_file_index && !needs_marker {
            return;
        }
        let Some(marker) = native_basename_marker(name) else {
            return;
        };
        if needs_marker
            && !self
                .file_markers
                .get(parent_id)
                .is_some_and(|markers| markers.contains(&marker))
            && self.admit_metadata(
                256usize
                    .saturating_add(marker.capacity())
                    .saturating_add(parent_id.as_str().len()),
                true,
            )
        {
            self.file_markers
                .entry(parent_id.clone())
                .or_default()
                .insert(marker.clone());
        }
        if self.retain_file_index
            && let Some(parent) = path.parent().and_then(Path::to_str)
            && let Some(size) = size
        {
            let parent = parent.to_string();
            if !self
                .dir_listings
                .get(&parent)
                .is_some_and(|listing| listing.files.contains_key(&marker))
                && self.admit_metadata(
                    256usize
                        .saturating_add(parent.capacity())
                        .saturating_add(marker.capacity()),
                    false,
                )
            {
                self.dir_listings
                    .entry(parent)
                    .or_default()
                    .files
                    .insert(marker, size);
            }
        }
    }

    /// A missing required marker can make a negative predicate spuriously match. Once facts
    /// were lost, skip remaining classification for this root and report partial coverage of
    /// classification, while the ordinary traversal still computes its filesystem totals.
    fn classify_pending(&mut self, id: &ScanEntryId) -> Option<bool> {
        let entry = self.pending_directories.remove(id)?;
        let is_root = self.pending_root_ids.remove(id);
        let cost = Self::row_cost(&entry);
        let complete_markers = !self.scoped
            || (self.enumerated_directories.contains(id)
                && entry
                    .identity
                    .as_ref()
                    .and_then(|identity| identity.parent_id.as_ref())
                    .is_none_or(|parent| self.enumerated_directories.contains(parent)));
        let decision = if self.metadata_lost || !complete_markers {
            None
        } else {
            self.classifier
                .expect("classified sink carries a classifier")
                .classify(&entry, &self.file_markers)
        };
        let Some(rule_id) = decision
            .filter(|rule| self.admit_metadata(128usize.saturating_add(rule.capacity()), true))
        else {
            self.metadata_bytes -= cost;
            self.root_metadata_bytes -= cost;
            return None;
        };
        self.decisions.insert(id.clone(), rule_id);
        if is_root {
            self.summary.roots.push(entry);
        } else {
            self.summary.entries.push(entry);
        }
        Some(is_root)
    }

    /// Records loss of evidence a total or coverage claim depends on.
    ///
    /// Callers must use this only when the dropped record would have changed a total or a
    /// boundary claim; truncated detail belongs in [`Self::mark_detail_overflow`], because
    /// this one causes every open aggregate to be reported as a lower bound.
    fn mark_overflow(&mut self, root: &Path, path: &Path, detail: &str) {
        if self.overflowed_roots.insert(root.to_path_buf()) {
            self.overflow_count += 1;
            self.push_boundary_marker(BoundaryRecord {
                path: path.to_path_buf(),
                kind: BoundaryKind::ResourceLimit,
                reason: ReasonCode::ResourceLimit,
                detail: detail.to_string(),
            });
            self.push_progress_marker(ProgressEvent::ResourceLimit {
                path: path.to_path_buf(),
            });
        }
    }

    /// Records truncation of per-entry detail.
    ///
    /// Still surfaced as a boundary so the truncation is visible and the caller can report the
    /// listing as partial -- silence would let a truncated listing look complete. It
    /// deliberately does not touch aggregate coverage: the bytes were already accumulated
    /// before the row was dropped, so the totals remain exact.
    fn mark_detail_overflow(&mut self, root: &Path, path: &Path, detail: &str) {
        if self.detail_overflowed_roots.insert(root.to_path_buf()) {
            self.detail_overflow_count += 1;
            self.push_boundary_marker(BoundaryRecord {
                path: path.to_path_buf(),
                kind: BoundaryKind::ResourceLimit,
                reason: ReasonCode::ResourceLimit,
                detail: detail.to_string(),
            });
            self.push_progress_marker(ProgressEvent::ResourceLimit {
                path: path.to_path_buf(),
            });
        }
    }

    fn push_boundary_marker(&mut self, boundary: BoundaryRecord) {
        if let Some(observer) = self.observer.as_deref_mut() {
            observer.on_boundary(&boundary);
        }
        Self::push_capped_replace_last(
            &mut self.summary.boundaries,
            boundary,
            self.limits.max_retained_boundaries,
        );
    }

    fn push_progress_marker(&mut self, event: ProgressEvent) {
        if let Some(observer) = self.observer.as_deref_mut() {
            observer.on_progress(&self.active_root, &event);
        }
        self.summary
            .retain_progress(event, self.limits.max_progress_events);
    }

    fn push_capped_replace_last<T>(items: &mut Vec<T>, item: T, cap: usize) {
        if cap == 0 {
            return;
        }
        if items.len() < cap {
            items.push(item);
        } else if let Some(last) = items.last_mut() {
            *last = item;
        }
    }
}

impl ScanSink for CollectingScanSink<'_> {
    fn push_root(&mut self, root: &Path, entry: ScannedEntry) -> Result<(), ScanError> {
        if self.classifier.is_some() {
            // Hold the root until its aggregate arrives; it is classified there like every
            // directory, then routed to `summary.roots`.
            let Some(identity) = entry.identity.as_ref() else {
                return Ok(());
            };
            self.active_root = root.to_path_buf();
            self.root_metadata_bytes = 0;
            self.root_reuse_bytes = 0;
            self.metadata_lost = false;
            if !self.admit_metadata(Self::row_cost(&entry), true) {
                return Ok(());
            }
            let id = identity.entry_id.clone();
            if self.observed_roots.len() < self.limits.max_retained_entries
                && self.admit_metadata(Self::row_cost(&entry).saturating_mul(2), false)
            {
                // Optional copies cannot displace required classification facts. Double the
                // estimate to cover spare Vec capacity; pressure evicts them with file indexes.
                self.observed_roots.push(entry.clone());
            }
            self.pending_root_ids.insert(id.clone());
            self.pending_directories.insert(id, entry);
            return Ok(());
        }
        if self.summary.roots.len() >= self.limits.max_retained_entries {
            self.mark_overflow(root, root, "retained root cap exceeded");
            return Ok(());
        }
        self.summary.roots.push(entry);
        Ok(())
    }

    fn push_entry(&mut self, root: &Path, entry: ScannedEntry) -> Result<(), ScanError> {
        if let Some(observer) = self.observer.as_deref_mut() {
            observer.on_entry(&entry);
        }
        if self.classifier.is_some() {
            match entry.object_type {
                ObjectType::Directory => {
                    let Some(identity) = entry.identity.as_ref() else {
                        return Ok(());
                    };
                    if let Some(parent_id) = identity.parent_id.as_ref()
                        && let Some(name) = native_basename_marker(&entry.native_basename)
                        && self.admit_metadata(
                            384usize
                                .saturating_add(name.capacity())
                                .saturating_add(identity.entry_id.as_str().len())
                                .saturating_add(parent_id.as_str().len()),
                            true,
                        )
                    {
                        self.directory_markers
                            .entry(parent_id.clone())
                            .or_default()
                            .insert(name, identity.entry_id.clone());
                    }
                    if self.admit_metadata(Self::row_cost(&entry), true) {
                        self.pending_directories
                            .insert(identity.entry_id.clone(), entry);
                    }
                }
                ObjectType::File => {
                    let Some(parent_id) =
                        entry.identity.as_ref().and_then(|id| id.parent_id.as_ref())
                    else {
                        return Ok(());
                    };
                    self.record_file(
                        parent_id,
                        &entry.native_basename,
                        Path::new(&entry.display_path),
                        extract_known_u128(&entry.logical_bytes),
                    );
                    // A gitfile is a repository boundary (worktree/submodule), not an ordinary
                    // project marker. Preserve its native parent lineage without retaining every
                    // file row; loss consumes the same required-evidence budget as directories.
                    if native_basename_marker(&entry.native_basename).as_deref() == Some(".git")
                        && self.admit_metadata(Self::row_cost(&entry), true)
                    {
                        self.summary.entries.push(entry);
                    }
                }
                // Symlinks and reparse/other rows feed no junk rule; symlinks are already
                // recorded as boundaries.
                ObjectType::Symlink | ObjectType::ReparsePoint | ObjectType::Other => {}
            }
            return Ok(());
        }
        // Directory rows are classified against junk rules, so they must not be crowded out by
        // file rows: measured on a real machine, ~/Library/Caches held 81,459 directories and
        // 579,576 files, and a single shared 16,384 cap retained only 425 directory rows --
        // every later cache directory silently stopped being a candidate. Directories are
        // therefore admitted against their own count; files and other non-directory rows use
        // the overall length and never evict a directory. Dropped rows in either pool stay
        // detail overflows: the bytes were already folded into the exact directory aggregate.
        let is_directory = entry.object_type == ObjectType::Directory;
        let pool_full = if is_directory {
            self.retained_directories >= self.limits.max_retained_entries
        } else {
            self.summary.entries.len() >= self.limits.max_retained_entries
        };
        if pool_full {
            self.mark_detail_overflow(
                root,
                Path::new(&entry.display_path),
                if is_directory {
                    "retained directory entry cap exceeded"
                } else {
                    "retained entry cap exceeded"
                },
            );
            return Ok(());
        }
        // File analyses already received the live observation and recursive totals already
        // counted it. Reserve twice the owned estimate for Vec growth and allocator overhead;
        // refusing detail must not manufacture incomplete filesystem accounting.
        let bytes = Self::row_cost(&entry).saturating_mul(2);
        let Some(next_bytes) = self
            .retained_entry_bytes
            .checked_add(bytes)
            .filter(|next| *next <= self.limits.max_retained_entry_bytes)
        else {
            self.mark_detail_overflow(
                root,
                Path::new(&entry.display_path),
                "retained entry byte budget exceeded",
            );
            return Ok(());
        };
        self.retained_entry_bytes = next_bytes;
        if is_directory {
            self.retained_directories += 1;
        }
        self.summary.entries.push(entry);
        Ok(())
    }

    fn push_boundary(&mut self, root: &Path, boundary: BoundaryRecord) -> Result<(), ScanError> {
        if let Some(observer) = self.observer.as_deref_mut() {
            observer.on_boundary(&boundary);
        }
        if self.summary.boundaries.len() >= self.limits.max_retained_boundaries {
            // Losing a boundary record loses the evidence that something was skipped, so the
            // affected totals must be reported as lower bounds rather than exact.
            self.mark_overflow(root, &boundary.path, "retained boundary cap exceeded");
            return Ok(());
        }
        self.summary.boundaries.push(boundary);
        Ok(())
    }

    fn push_progress(&mut self, root: &Path, event: ProgressEvent) -> Result<(), ScanError> {
        if let Some(observer) = self.observer.as_deref_mut() {
            observer.on_progress(root, &event);
        }
        self.summary
            .retain_progress(event, self.limits.max_progress_events);
        Ok(())
    }

    fn push_aggregate(
        &mut self,
        root: &Path,
        aggregate: DirectoryAggregate,
    ) -> Result<(), ScanError> {
        if self.classifier.is_some() {
            // The aggregate id names the now-complete directory: classify its pending row first,
            // and retain the aggregate only when this directory is itself a junk candidate.
            let id = ScanEntryId::from_loaded(aggregate.directory_identity.clone());
            // Retain coverage for every completed directory, candidate or not, before the aggregate
            // is dropped or kept; downstream evidence checks read this rather than the aggregate.
            if self.admit_metadata(
                256usize.saturating_add(id.as_str().len()).saturating_add(
                    aggregate
                        .coverage
                        .incomplete_reasons
                        .len()
                        .saturating_mul(std::mem::size_of::<ReasonCode>()),
                ),
                true,
            ) {
                self.coverages
                    .insert(id.clone(), aggregate.coverage.clone());
            }
            let classified_root = self.classify_pending(&id);
            if !self.decisions.contains_key(&id) {
                // A non-candidate directory's bytes are not needed for any total: file entries are
                // folded into every ancestor's state as they are visited (`propagate_file_entry`
                // walks the full ancestor chain), so parent totals never read a child's retained
                // aggregate. Discarding here is what keeps retained aggregates proportional to
                // the classified set instead of the whole tree. Keeping them previously made a
                // large walk overflow `max_retained_aggregates`, dropping evidence for real
                // candidates, which then reported `unknown` sizes intermittently.
                return Ok(());
            }
            if self.summary.aggregates.len() >= self.limits.max_retained_aggregates {
                // The classified set itself exceeded the cap: this is real evidence loss, so it
                // stays an overflow rather than silently shrinking the result.
                self.decisions.remove(&id);
                self.mark_overflow(
                    root,
                    root,
                    "retained aggregate cap exceeded across classified candidates",
                );
                return Ok(());
            }
            if let Some(is_root) = classified_root
                && let Some(observer) = self.observer.as_deref_mut()
            {
                let entry = if is_root {
                    self.summary.roots.last()
                } else {
                    self.summary.entries.last()
                }
                .expect("classified row was retained");
                let rule = self
                    .decisions
                    .get(&id)
                    .expect("classified rule was retained");
                observer.on_candidate(entry, rule, &aggregate);
            }
            self.summary.aggregates.push(aggregate);
            return Ok(());
        }
        if self.summary.aggregates.len() >= self.limits.max_retained_aggregates {
            self.mark_overflow(
                root,
                root,
                "retained aggregate cap exceeded across scan roots",
            );
            return Ok(());
        }
        self.summary.aggregates.push(aggregate);
        Ok(())
    }

    fn overflow_count(&self) -> usize {
        self.overflow_count
    }

    fn detail_overflow_count(&self) -> usize {
        self.detail_overflow_count
    }

    fn retained_aggregate_count(&self) -> usize {
        self.summary.aggregates.len()
    }

    fn wants_directory_progress(&self) -> bool {
        self.observer
            .as_ref()
            .is_some_and(|observer| observer.wants_directory_progress())
    }

    fn wants_file_observations(&self) -> bool {
        self.observer
            .as_ref()
            .is_some_and(|observer| observer.wants_file_observations())
    }

    fn accepts_file_lengths(&self) -> bool {
        self.classifier.is_some() && !self.wants_file_observations()
    }

    fn accepts_closed_subtrees(&self) -> bool {
        self.classifier
            .is_some_and(JunkClassifier::uses_only_local_markers)
    }

    fn note_directory_enumerated(&mut self, id: &ScanEntryId) {
        if self.scoped && self.admit_metadata(128usize.saturating_add(id.as_str().len()), true) {
            self.enumerated_directories.insert(id.clone());
        }
    }

    fn note_directory_progress(&mut self, path: &Path, aggregate: &DirectoryAggregate) {
        if let Some(observer) = self.observer.as_deref_mut() {
            observer.on_directory_progress(path, aggregate);
        }
    }

    fn preferred_directory(&self) -> Option<PathBuf> {
        self.observer
            .as_deref()
            .and_then(ClassifiedScanObserver::preferred_directory)
    }

    fn note_native_directory_coverage(&mut self, path: &Path, coverage: &Coverage) {
        if let Some(observer) = self.observer.as_deref_mut() {
            observer.on_directory_coverage(path, coverage);
        }
    }

    fn note_directory_coverage(&mut self, path: &Path, coverage: &Coverage) {
        if let Some(paths) = self.selected_paths {
            for (index, selected) in paths.iter().enumerate() {
                if path == selected {
                    self.selected_seen[index] = true;
                }
                if path.starts_with(selected) {
                    self.selected_coverage_complete &= coverage.complete && !coverage.details_lost;
                }
            }
        }
        if self.classifier.is_some()
            && !self.metadata_lost
            && let Some(path) = path.to_str()
        {
            let path = path.to_string();
            if self.admit_metadata(256usize.saturating_add(path.capacity()), false) {
                self.covered_paths.insert(path, coverage.complete);
            }
        }
    }

    fn note_cached_file(
        &mut self,
        parent_id: &ScanEntryId,
        file: &sweepx_platform::CachedFileEntry,
    ) {
        if self.classifier.is_some() {
            // Validated lengths are carried into the next generation under the same optional
            // budget as fresh files. Missing listings force inspection on subsequent scans.
            self.record_file(
                parent_id,
                &file.file_name,
                &file.path,
                Some(file.logical_bytes),
            );
        }
    }
}

pub struct Scanner<P> {
    platform: P,
    options: ScannerOptions,
    monitor: Option<Arc<sweepx_platform::change_monitor::ChangeMonitor>>,
}

#[derive(Debug)]
struct FrontierDirectory<D> {
    path: PathBuf,
    handle: D,
    identity: ScanObjectIdentity,
    native_component: NativePathComponent,
    parent_reopen_recipe: Vec<NativePathComponent>,
    started: bool,
    consumed_entries: usize,
    consumed_bytes: usize,
    /// Children that were enumerated but not yet inspected, because the handle permits for
    /// this pass ran out.
    ///
    /// Deferring instead of refusing is what keeps a wide directory's totals exact. A
    /// directory can have far more children than the whole permit pool -- npm's
    /// `content-v2/sha512` has 256 -- and refusing the remainder turned every ancestor
    /// aggregate into a lower bound. These records were already produced by an enumeration of
    /// this exact handle, so re-inspecting them later needs no re-enumeration and no
    /// pathname reopen; the handle stays alive because the directory is returned to the
    /// frontier while this list is non-empty.
    ///
    /// Bounded by one enumeration batch, so retained memory stays proportional to
    /// `max_directory_batch_entries` times the number of open directories.
    pending_children: Vec<sweepx_platform::DirectoryEntryRecord>,
}

const MAX_SCANNER_WORKERS: usize = 32;
/// How many directories one scheduling round may expand at once.
///
/// The traversal is depth-first, so a round takes the most recently discovered
/// directories. Capping the round bounds how far the frontier can grow in one step: the
/// live handle set stays proportional to the tree's *depth* rather than its *breadth*.
///
/// This is a constant rather than the configured worker count on purpose. Permits are
/// divided across the round, so deriving the round size from worker count would make
/// *which* entries get admitted depend on how many threads the caller asked for. Worker
/// count may change throughput; it must never change results.
const DEPTH_FIRST_ROUND_DIRECTORIES: usize = MAX_SCANNER_WORKERS;
/// Highest ordinal reserved for the ordinary breadth-first scan. Detail rescans allocate only
/// above this value so retained and refreshed rows cannot collide within one scan id.
pub const ORDINARY_SCAN_MAX_ORDINAL: u128 = u128::MAX / 2;

struct DirectoryTask<D> {
    ticket: u128,
    current: FrontierDirectory<D>,
    child_directory_permits: usize,
}

struct ScheduledDirectory<D> {
    current: FrontierDirectory<D>,
    child_directory_permits: usize,
}

/// Selects only from admitted capabilities. Unrelated preferences preserve depth-first order.
/// A pending ancestor can advance discovery toward the requested directory, while deeper
/// descendants retain the reserve strategy that bounds handles on wide trees.
fn take_frontier_directory<D>(
    frontier: &mut VecDeque<FrontierDirectory<D>>,
    preferred: Option<&Path>,
) -> FrontierDirectory<D> {
    let selected = preferred.and_then(|preferred| {
        frontier
            .iter()
            .enumerate()
            .filter_map(|(index, current)| {
                let relation = if current.path.starts_with(preferred) {
                    2
                } else if preferred.starts_with(&current.path) {
                    1
                } else {
                    return None;
                };
                Some(((relation, current.path.components().count(), index), index))
            })
            .max_by_key(|(score, _)| *score)
            .map(|(_, index)| index)
    });
    match selected {
        Some(index) => frontier.remove(index),
        // A resumed ancestor is pushed after its children. Merely popping the back would
        // expand that ancestor again, filling the pool with siblings before descent.
        None => frontier
            .iter()
            .enumerate()
            .max_by_key(|(index, current)| (current.path.components().count(), *index))
            .map(|(index, _)| index)
            .and_then(|index| frontier.remove(index)),
    }
    .expect("frontier round length was captured")
}

struct DirectoryTaskResult<D> {
    ticket: u128,
    child_directory_permits: usize,
    outcome: DirectoryTaskOutcome<D>,
}

enum DirectoryTaskOutcome<D> {
    Batch(Box<PreparedDirectoryBatch<D>>),
    VisitedLimit { path: PathBuf },
    Cancelled { path: PathBuf },
    EnumerationIo { path: PathBuf },
    EnumerationResourceLimit { path: PathBuf, detail: String },
    Fatal(PlatformError),
    Panicked { path: PathBuf },
}

struct PreparedDirectoryBatch<D> {
    current: FrontierDirectory<D>,
    inspected: Vec<WalkEntry<D>>,
    opened_child_permits: usize,
    end_of_directory: bool,
    directory_limit_blocks_continuation: bool,
    terminal: Option<InspectionTerminal>,
}

// Scope controls observation work, never filesystem authority. Ancestors enumerate fully for
// needed marker absence, but only selected subtrees recurse. Borrowing this bounded selection
// avoids duplicating native paths into a depth-sized route index on every scan.
#[derive(Clone, Copy)]
struct SubtreeScope<'a> {
    paths: &'a [PathBuf],
    classifier: &'a (dyn JunkClassifier + Sync),
}
impl SubtreeScope<'_> {
    fn selected(&self, path: &Path) -> bool {
        self.paths.iter().any(|selected| path.starts_with(selected))
    }
    fn related(&self, path: &Path) -> bool {
        self.selected(path) || self.paths.iter().any(|selected| selected.starts_with(path))
    }
    fn inspect(&self, child: &sweepx_platform::DirectoryEntryRecord) -> bool {
        self.related(&child.path)
            || self.classifier.needs_file_marker(&child.file_name)
            || native_basename_marker(&child.file_name).as_deref() == Some(".git")
    }
}

enum InspectionTerminal {
    Cancelled { path: PathBuf },
    Fatal(PlatformError),
}

impl<D> FrontierDirectory<D> {
    fn parent_recipe_with_self(&self) -> Vec<NativePathComponent> {
        let mut recipe = self.parent_reopen_recipe.clone();
        recipe.push(self.native_component.clone());
        recipe
    }
}

fn prepare_directory_task<P: PlatformScanner + ?Sized>(
    platform: &P,
    task: DirectoryTask<P::DirectoryHandle>,
    cancel: &CancellationToken,
    limits: ScanResourceLimits,
    reuse: Option<&dyn SubtreeReuse>,
    allow_file_lengths: bool,
    subtree_scope: Option<SubtreeScope<'_>>,
) -> DirectoryTaskResult<P::DirectoryHandle> {
    let DirectoryTask {
        ticket,
        mut current,
        child_directory_permits,
    } = task;
    let path = current.path.clone();
    if cancel.is_cancelled() {
        return DirectoryTaskResult {
            ticket,
            child_directory_permits,
            outcome: DirectoryTaskOutcome::Cancelled { path },
        };
    }

    let remaining_entries = limits
        .max_directory_entries
        .saturating_sub(current.consumed_entries);
    let remaining_bytes = limits
        .max_directory_bytes
        .saturating_sub(current.consumed_bytes);
    let requested_batch_limits = DirectoryReadLimits {
        max_batch_entries: limits.max_directory_batch_entries.min(remaining_entries),
        max_batch_bytes: limits.max_directory_batch_bytes.min(remaining_bytes),
    };

    // Children left over from an earlier pass are inspected before any new enumeration, so a
    // wide directory drains its backlog rather than reading further ahead and growing it.
    // `replaying_backlog` is recorded here rather than inferred from the batch afterwards: a
    // freshly enumerated mid-stream batch is indistinguishable from a replayed one by shape
    // alone, and mistaking one for the other would corrupt the cumulative entry accounting.
    let replaying_backlog = !current.pending_children.is_empty();
    let batch = if replaying_backlog {
        // The cursor is still mid-stream, so `continued` keeps the continuation slot reserved
        // and the handle owned.
        let backlog = std::mem::take(&mut current.pending_children);
        sweepx_platform::DirectoryEntryBatch::continued(backlog)
    } else {
        match platform.enumerate_children(&mut current.handle, cancel, requested_batch_limits) {
            Ok(batch) => batch,
            Err(PlatformError::Cancelled) => {
                return DirectoryTaskResult {
                    ticket,
                    child_directory_permits,
                    outcome: DirectoryTaskOutcome::Cancelled { path },
                };
            }
            Err(PlatformError::Io { .. }) => {
                return DirectoryTaskResult {
                    ticket,
                    child_directory_permits,
                    outcome: DirectoryTaskOutcome::EnumerationIo { path },
                };
            }
            Err(PlatformError::ResourceLimit(detail)) => {
                return DirectoryTaskResult {
                    ticket,
                    child_directory_permits,
                    outcome: DirectoryTaskOutcome::EnumerationResourceLimit { path, detail },
                };
            }
            Err(error) => {
                return DirectoryTaskResult {
                    ticket,
                    child_directory_permits,
                    outcome: DirectoryTaskOutcome::Fatal(error),
                };
            }
        }
    };
    if batch.entries.is_empty() && !batch.end_of_directory {
        return DirectoryTaskResult {
            ticket,
            child_directory_permits,
            outcome: DirectoryTaskOutcome::Fatal(PlatformError::InvalidDirectoryEntry {
                parent: path,
                detail: "backend returned an empty non-terminal directory batch".to_string(),
            }),
        };
    }
    let batch_entries = batch.entries.len();
    let batch_bytes = batch.entries.iter().try_fold(0usize, |total, entry| {
        entry
            .estimated_retained_bytes()
            .and_then(|bytes| total.checked_add(bytes))
    });
    if batch_entries > requested_batch_limits.max_batch_entries
        || batch_bytes.is_none_or(|bytes| bytes > requested_batch_limits.max_batch_bytes)
    {
        return DirectoryTaskResult {
            ticket,
            child_directory_permits,
            outcome: DirectoryTaskOutcome::Fatal(PlatformError::InvalidDirectoryEntry {
                parent: path,
                detail: "backend exceeded the requested directory batch limit".to_string(),
            }),
        };
    }
    // Replayed records were already counted when first enumerated; counting them again would
    // drive the per-directory cumulative limit toward a false positive.
    if !replaying_backlog {
        current.consumed_entries = match current.consumed_entries.checked_add(batch_entries) {
            Some(value) => value,
            None => {
                return DirectoryTaskResult {
                    ticket,
                    child_directory_permits,
                    outcome: DirectoryTaskOutcome::Fatal(PlatformError::ResourceLimit(
                        "directory entry accounting overflow".to_string(),
                    )),
                };
            }
        };
        current.consumed_bytes = match current
            .consumed_bytes
            .checked_add(batch_bytes.expect("batch byte accounting checked above"))
        {
            Some(value) => value,
            None => {
                return DirectoryTaskResult {
                    ticket,
                    child_directory_permits,
                    outcome: DirectoryTaskOutcome::Fatal(PlatformError::ResourceLimit(
                        "directory byte accounting overflow".to_string(),
                    )),
                };
            }
        };
    }
    current.started = true;
    // File-level reuse plan, obtained before any child is stated and aligned to batch entries.
    // `None` for the directory (no cache/coverage) means every child is inspected.
    let plan: Option<Vec<PlannedEntry>> =
        reuse.and_then(|provider| provider.plan_entries(&path, &batch.entries));
    let end_of_directory = batch.end_of_directory;
    let directory_limit_blocks_continuation = !end_of_directory
        && (current.consumed_entries >= limits.max_directory_entries
            || current.consumed_bytes >= limits.max_directory_bytes);
    let mut inspected = Vec::with_capacity(batch_entries);
    let mut terminal = None;
    let mut opened_child_permits = 0usize;
    let mut deferred = Vec::new();
    // Deferring is only safe while this pass can still make progress. A directory granted at
    // least one permit inspects at least one child per pass, so its backlog strictly shrinks
    // and the traversal terminates. A directory granted zero permits would defer its entire
    // batch unchanged and be rescheduled forever, so it must fall back to refusing its child
    // directories -- reporting the boundary honestly rather than hanging.
    let may_defer = child_directory_permits > 0;
    for (index, directory_entry) in batch.entries.into_iter().enumerate() {
        if cancel.is_cancelled() {
            terminal = Some(InspectionTerminal::Cancelled {
                path: directory_entry.path,
            });
            break;
        }
        // Validate even omitted records against the retained parent capability. Skipping an
        // unrelated name must not conceal a backend path substitution or escape the root.
        if let Err(error) = directory_entry.validate_for_parent(&path) {
            terminal = Some(InspectionTerminal::Fatal(
                PlatformError::InvalidDirectoryEntry {
                    parent: path.clone(),
                    detail: error.to_string(),
                },
            ));
            break;
        }
        if subtree_scope
            .is_some_and(|scope| !scope.selected(&path) && !scope.inspect(&directory_entry))
        {
            continue;
        }
        let permit_available = opened_child_permits < child_directory_permits;
        // Once the permits are spent, keep the rest for a later pass instead of refusing them.
        // A record cannot be classified as file-or-directory without inspecting it, so
        // refusing here would discard a real subtree and turn every ancestor total into a
        // lower bound; deferring keeps both the handle budget and the totals intact.
        if !permit_available && may_defer {
            deferred.reserve(batch_entries - index);
            deferred.push(directory_entry);
            continue;
        }
        // Junk-only consumers need the current logical length and marker, not a full file row
        // with a cloned native ancestor recipe. The backend's current native observation supplies
        // those facts independently of an on-disk cache or delayed change-history delivery.
        if allow_file_lengths
            && native_basename_marker(&directory_entry.file_name).as_deref() != Some(".git")
            && let Some(observed) = platform.observe_file_length(&current.handle, &directory_entry)
            && observed.path == directory_entry.path
            && observed.file_name == directory_entry.file_name
        {
            inspected.push(WalkEntry::CachedFile(observed));
            continue;
        }
        // History validates old facts, but cannot replace current type evidence. A stale or
        // misaligned plan must not suppress directory traversal or turn a link into a file.
        if let Some(PlannedEntry::ReuseFile(cached)) =
            plan.as_ref().and_then(|entries| entries.get(index))
            && cached.path == directory_entry.path
            && cached.file_name == directory_entry.file_name
            // Keep gitfile native lineage available to post-scan boundary interpretation.
            && native_basename_marker(&directory_entry.file_name).as_deref() != Some(".git")
            && platform.confirms_cached_file(
                &current.handle,
                &directory_entry,
                cached.logical_bytes,
            )
        {
            inspected.push(WalkEntry::CachedFile(cached.clone()));
            continue;
        }
        match inspect_directory_entry(
            platform,
            &current.handle,
            &path,
            &directory_entry,
            cancel,
            permit_available,
        ) {
            Ok(WalkEntry::Directory(opened)) => {
                opened_child_permits += 1;
                inspected.push(WalkEntry::Directory(opened));
            }
            Ok(walk) => inspected.push(walk),
            Err(PlatformError::Cancelled) => {
                terminal = Some(InspectionTerminal::Cancelled {
                    path: directory_entry.path,
                });
                break;
            }
            Err(error) => {
                terminal = Some(InspectionTerminal::Fatal(error));
                break;
            }
        }
    }
    current.pending_children = deferred;

    DirectoryTaskResult {
        ticket,
        child_directory_permits,
        outcome: DirectoryTaskOutcome::Batch(Box::new(PreparedDirectoryBatch {
            current,
            inspected,
            opened_child_permits,
            end_of_directory,
            directory_limit_blocks_continuation,
            terminal,
        })),
    }
}

fn inspect_directory_entry<P: PlatformScanner + ?Sized>(
    platform: &P,
    parent: &P::DirectoryHandle,
    parent_path: &Path,
    directory_entry: &sweepx_platform::DirectoryEntryRecord,
    cancel: &CancellationToken,
    child_directory_permit: bool,
) -> Result<WalkEntry<P::DirectoryHandle>, PlatformError> {
    inspect_bound_child_with_directory_admission(
        platform,
        parent,
        parent_path,
        directory_entry,
        cancel,
        if child_directory_permit {
            DirectoryHandleAdmission::Allow
        } else {
            DirectoryHandleAdmission::Deny
        },
    )
}

impl<P> Scanner<P>
where
    P: PlatformScanner,
{
    pub fn new(platform: P, options: ScannerOptions) -> Self {
        Self {
            platform,
            options,
            monitor: None,
        }
    }

    /// Attaches a session's advisory listener. Directories are registered from retained native
    /// handles before enumeration; listener failure never weakens ordinary scan boundaries.
    pub fn with_change_monitor(
        mut self,
        monitor: Arc<sweepx_platform::change_monitor::ChangeMonitor>,
    ) -> Self {
        self.monitor = Some(monitor);
        self
    }

    pub fn scan(
        &self,
        roots: &[ScanRoot],
        cancel: &CancellationToken,
    ) -> Result<ScanSummary, ScanError> {
        let mut sink = CollectingScanSink::new(self.options.resource_limits);
        self.scan_with_sink(roots, cancel, None, &mut sink)?;
        Ok(sink.finish())
    }

    /// Runs the ordinary metadata walk with borrowed observations before row retention.
    /// Independent analyses can consume every current file without buffering the full listing.
    /// Cancellation and filesystem/resource boundaries use the same traversal as `scan`.
    pub fn scan_with_observer(
        &self,
        roots: &[ScanRoot],
        cancel: &CancellationToken,
        observer: &mut dyn ClassifiedScanObserver,
    ) -> Result<ScanSummary, ScanError> {
        let mut sink = CollectingScanSink::new(self.options.resource_limits);
        sink.observer = Some(observer);
        self.scan_with_sink(roots, cancel, None, &mut sink)?;
        Ok(sink.summary)
    }

    /// Runs the walk in junk classification mode.
    ///
    /// Only directories the `classifier` returns a rule id for are retained as rows, so the
    /// caller can build a small result even when the scanned trees contain hundreds of
    /// thousands of entries. Aggregates and boundaries are retained as in [`Self::scan`].
    pub fn scan_classified(
        &self,
        roots: &[ScanRoot],
        cancel: &CancellationToken,
        classifier: &dyn JunkClassifier,
        reuse: Option<&dyn SubtreeReuse>,
    ) -> Result<ClassifiedScan, ScanError> {
        let mut sink = CollectingScanSink::new_classified(self.options.resource_limits, classifier);
        sink.retain_file_index = self.options.retain_file_index;
        self.scan_with_sink(roots, cancel, reuse, &mut sink)?;
        Ok(sink.finish_classified())
    }

    /// Runs the same classified walk while exposing borrowed live observations.
    ///
    /// The observer cannot change admission, resource accounting or rule decisions. It may
    /// request an ordering preference for already admitted directories and cancel via the
    /// supplied token. Final candidates are delivered before the traversal's `Finished` event;
    /// an error return can occur without `Finished` and must be handled by the caller.
    pub fn scan_classified_with_observer(
        &self,
        roots: &[ScanRoot],
        cancel: &CancellationToken,
        classifier: &dyn JunkClassifier,
        reuse: Option<&dyn SubtreeReuse>,
        observer: &mut dyn ClassifiedScanObserver,
    ) -> Result<ClassifiedScan, ScanError> {
        let mut sink = CollectingScanSink::new_classified(self.options.resource_limits, classifier);
        sink.retain_file_index = self.options.retain_file_index;
        sink.observer = Some(observer);
        self.scan_with_sink(roots, cancel, reuse, &mut sink)?;
        Ok(sink.finish_classified())
    }

    /// Observes selected subtrees and the shallow ancestor context required by local rules.
    ///
    /// Selections must be bounded absolute paths inside the admitted roots. They filter work,
    /// not identity or execution authority: native roots, lineage, no-follow and mount checks
    /// stay unchanged. Ancestor totals/coverage are incomplete; selected subtree facts may be
    /// complete. All required ancestor file markers and `.git` facts are freshly observed.
    /// Root-wide custom evaluators are refused rather than given a silently incomplete index.
    /// The classifier is shared by bounded workers for its read-only marker-name predicate.
    pub fn scan_classified_subtrees_with_observer(
        &self,
        roots: &[ScanRoot],
        cancel: &CancellationToken,
        classifier: &(dyn JunkClassifier + Sync),
        reuse: Option<&dyn SubtreeReuse>,
        subtrees: &[PathBuf],
        observer: &mut dyn ClassifiedScanObserver,
    ) -> Result<ClassifiedScan, ScanError> {
        if !classifier.uses_only_local_markers()
            || subtrees.is_empty()
            || subtrees.len() > 256
            || subtrees.iter().any(|path| {
                !path.is_absolute()
                    || path.as_os_str().len() > 64 * 1024
                    || !roots.iter().any(|root| path.starts_with(root.path()))
            })
        {
            return Err(ScanError::RootValidation(
                "invalid local classification scope".into(),
            ));
        }
        let mut sink = CollectingScanSink::new_classified(self.options.resource_limits, classifier);
        sink.retain_file_index = self.options.retain_file_index;
        sink.scoped = true;
        sink.selected_paths = Some(subtrees);
        sink.selected_seen = vec![false; subtrees.len()];
        sink.observer = Some(observer);
        self.scan_with_sink_scoped(
            roots,
            cancel,
            reuse,
            Some(SubtreeScope {
                paths: subtrees,
                classifier,
            }),
            &mut sink,
        )?;
        Ok(sink.finish_classified())
    }

    /// Admits only the requested roots. This is the fast first frame for progressive TUI mode;
    /// no child directory is traversed until the browser requests a bounded detail rescan.
    pub fn scan_roots_only(
        &self,
        roots: &[ScanRoot],
        cancel: &CancellationToken,
    ) -> Result<ScanSummary, ScanError> {
        let mut summary = ScanSummary {
            progress_retention: Default::default(),
            roots: Vec::with_capacity(roots.len()),
            entries: Vec::new(),
            aggregates: Vec::new(),
            boundaries: Vec::new(),
            progress: Vec::new(),
        };
        let mut next_entry_ordinal = Some(1u128);
        for root in roots {
            let admission = match self.platform.admit_root(root, cancel) {
                Ok(admission) => admission,
                Err(error) if error.is_access_denied() => {
                    // First frame mirrors the full walk: a denied root is an incomplete root
                    // rather than a reason to refuse the whole root set. Its detail rescan later
                    // re-reports the same boundary.
                    let root_entry_id =
                        allocate_scan_entry_id(&self.options.scan_id, &mut next_entry_ordinal)?;
                    summary.retain_progress(
                        ProgressEvent::Error {
                            path: root.path().to_path_buf(),
                            reason: ReasonCode::StrictReadOnly,
                        },
                        self.options.resource_limits.max_progress_events,
                    );
                    summary.boundaries.push(BoundaryRecord {
                        path: root.path().to_path_buf(),
                        kind: BoundaryKind::AccessDenied,
                        reason: ReasonCode::StrictReadOnly,
                        detail: error.to_string(),
                    });
                    summary.aggregates.push(access_denied_root_aggregate(
                        &self.options.scan_id,
                        root_entry_id,
                    ));
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            admission.validate_for_root(root).map_err(|error| {
                PlatformError::InvalidDirectoryEntry {
                    parent: root.path().to_path_buf(),
                    detail: error.to_string(),
                }
            })?;
            let root_entry_id =
                allocate_scan_entry_id(&self.options.scan_id, &mut next_entry_ordinal)?;
            let root_identity = scan_object_identity(
                root_entry_id.clone(),
                root_entry_id,
                None,
                &admission.metadata,
            );
            summary.roots.push(scanned_entry_from_metadata(
                &self.options.scan_id,
                &admission.metadata,
                root_identity.clone(),
                native_locator_evidence(
                    &admission.root_locator,
                    &native_path_component(&root_identity, &admission.metadata),
                    &[],
                    &native_path_component(&root_identity, &admission.metadata),
                ),
                complete_coverage(),
            ));
            summary.retain_progress(
                ProgressEvent::RootAccepted {
                    path: root.path().to_path_buf(),
                },
                self.options.resource_limits.max_progress_events,
            );
        }
        summary.retain_progress(
            ProgressEvent::Finished,
            self.options.resource_limits.max_progress_events,
        );
        Ok(summary)
    }

    pub fn scan_with_sink<S: ScanSink>(
        &self,
        roots: &[ScanRoot],
        cancel: &CancellationToken,
        reuse: Option<&dyn SubtreeReuse>,
        sink: &mut S,
    ) -> Result<(), ScanError> {
        self.scan_with_sink_scoped(roots, cancel, reuse, None, sink)
    }

    fn scan_with_sink_scoped<S: ScanSink>(
        &self,
        roots: &[ScanRoot],
        cancel: &CancellationToken,
        reuse: Option<&dyn SubtreeReuse>,
        subtree_scope: Option<SubtreeScope<'_>>,
        sink: &mut S,
    ) -> Result<(), ScanError> {
        if self.options.max_workers == 0 {
            return Err(ScanError::RootValidation(
                "max_workers must be greater than zero".to_string(),
            ));
        }
        if self.options.resource_limits.max_frontier_entries == 0 {
            return Err(ScanError::RootValidation(
                "max_frontier_entries must be greater than zero".to_string(),
            ));
        }
        let mut next_entry_ordinal = Some(1u128);

        for root in roots {
            if subtree_scope.is_some_and(|scope| !scope.related(root.path())) {
                continue;
            }
            if cancel.is_cancelled() {
                let root_entry_id =
                    allocate_scan_entry_id(&self.options.scan_id, &mut next_entry_ordinal)?;
                sink.push_progress(
                    root.path(),
                    ProgressEvent::Cancelled {
                        path: root.path.clone(),
                    },
                )?;
                sink.push_aggregate(
                    root.path(),
                    cancelled_root_aggregate(&self.options.scan_id, root_entry_id),
                )?;
                break;
            }
            if sink.retained_aggregate_count()
                >= self.options.resource_limits.max_retained_aggregates
            {
                sink.push_progress(
                    root.path(),
                    ProgressEvent::ResourceLimit {
                        path: root.path().to_path_buf(),
                    },
                )?;
                sink.push_boundary(
                    root.path(),
                    BoundaryRecord {
                        path: root.path().to_path_buf(),
                        kind: BoundaryKind::ResourceLimit,
                        reason: ReasonCode::ResourceLimit,
                        detail: "retained aggregate cap exceeded across scan roots".to_string(),
                    },
                )?;
                continue;
            }
            let admission = match self.platform.admit_root(root, cancel) {
                Ok(admission) => admission,
                Err(PlatformError::Cancelled) => {
                    let root_entry_id =
                        allocate_scan_entry_id(&self.options.scan_id, &mut next_entry_ordinal)?;
                    sink.push_progress(
                        root.path(),
                        ProgressEvent::Cancelled {
                            path: root.path.clone(),
                        },
                    )?;
                    sink.push_aggregate(
                        root.path(),
                        cancelled_root_aggregate(&self.options.scan_id, root_entry_id),
                    )?;
                    if cancel.is_cancelled() {
                        break;
                    }
                    continue;
                }
                Err(error) if error.is_access_denied() => {
                    // A root the host refuses to open (TCC) is skipped and marked incomplete,
                    // exactly like an unopenable child: emit an error record, an access-denied
                    // boundary and a zero lower-bound aggregate, then scan the remaining roots.
                    // Other I/O failures below still abort; swallowing e.g. EIO would hide a
                    // real volume fault.
                    let root_entry_id =
                        allocate_scan_entry_id(&self.options.scan_id, &mut next_entry_ordinal)?;
                    sink.push_progress(
                        root.path(),
                        ProgressEvent::Error {
                            path: root.path().to_path_buf(),
                            reason: ReasonCode::StrictReadOnly,
                        },
                    )?;
                    sink.push_boundary(
                        root.path(),
                        BoundaryRecord {
                            path: root.path().to_path_buf(),
                            kind: BoundaryKind::AccessDenied,
                            reason: ReasonCode::StrictReadOnly,
                            detail: error.to_string(),
                        },
                    )?;
                    sink.push_aggregate(
                        root.path(),
                        access_denied_root_aggregate(&self.options.scan_id, root_entry_id),
                    )?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            admission.validate_for_root(root).map_err(|error| {
                PlatformError::InvalidDirectoryEntry {
                    parent: root.path().to_path_buf(),
                    detail: error.to_string(),
                }
            })?;
            let root_entry_id =
                allocate_scan_entry_id(&self.options.scan_id, &mut next_entry_ordinal)?;
            let root_identity = scan_object_identity(
                root_entry_id.clone(),
                root_entry_id,
                None,
                &admission.metadata,
            );
            let overflow_count_before = sink.overflow_count();
            sink.push_progress(
                root.path(),
                ProgressEvent::RootAccepted {
                    path: root.path.clone(),
                },
            )?;
            sink.push_root(
                root.path(),
                scanned_entry_from_metadata(
                    &self.options.scan_id,
                    &admission.metadata,
                    root_identity.clone(),
                    native_locator_evidence(
                        &admission.root_locator,
                        &native_path_component(&root_identity, &admission.metadata),
                        &[],
                        &native_path_component(&root_identity, &admission.metadata),
                    ),
                    complete_coverage(),
                ),
            )?;

            self.scan_root(
                admission,
                root_identity,
                &mut next_entry_ordinal,
                cancel,
                overflow_count_before,
                reuse,
                subtree_scope,
                sink,
            )?;
            if cancel.is_cancelled() {
                break;
            }
        }

        sink.push_progress(Path::new("/"), ProgressEvent::Finished)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_root<S: ScanSink>(
        &self,
        admission: RootAdmission<P::DirectoryHandle>,
        root_identity: ScanObjectIdentity,
        next_entry_ordinal: &mut Option<u128>,
        cancel: &CancellationToken,
        overflow_count_before: usize,
        reuse: Option<&dyn SubtreeReuse>,
        subtree_scope: Option<SubtreeScope<'_>>,
        sink: &mut S,
    ) -> Result<(), ScanError> {
        let RootAdmission {
            root,
            root_locator,
            metadata: root_metadata,
            directory,
        } = admission;
        let root_path = root.path().to_path_buf();

        if let Some(monitor) = &self.monitor
            && monitor.is_available()
        {
            self.platform
                .monitor_directory(&directory, &root_path, true, monitor);
        }

        // Logical-length reuse has no current allocation or file identity observation to
        // deliver. File analyses request the ordinary backend inspection, never fabricated
        // entry facts. Existing junk-only/cache paths keep their original fast behavior.
        let reuse = if sink.wants_file_observations() {
            None
        } else {
            reuse
        };
        let allow_file_lengths = sink.accepts_file_lengths()
            && !sink.wants_file_observations()
            && self.platform.supports_file_length_observation();

        // Qualify the accelerated path before traversing.
        //
        // When it qualifies, a bulk NTFS read produces a *preview* of the root: totals in about a
        // second where the handle-relative walk needs minutes. The walk still runs and still
        // produces every authoritative record, because only a live handle yields the reopen
        // recipe that a delete is allowed to act on. The preview is emitted first so a caller can
        // show a provisional size immediately and replace it when the walk finishes.
        let acceleration = qualify_acceleration(&root_path, cancel);
        if let Some(refusal) = acceleration.refusal() {
            // Reported as progress, not a boundary. A boundary means filesystem coverage was lost;
            // declining an optimization loses nothing, and recording it as a boundary would make
            // every ordinary unelevated scan look partial.
            sink.push_progress(
                &root_path,
                ProgressEvent::AccelerationUnavailable {
                    path: root_path.clone(),
                    reason: refusal.code(),
                    elevation_might_help: refusal.elevation_might_help(),
                },
            )?;
        } else {
            match read_accelerated_preview(&root_path, cancel) {
                Ok(preview) => sink.push_progress(
                    &root_path,
                    ProgressEvent::AcceleratedPreview {
                        path: root_path.clone(),
                        entry_count: preview.entry_count,
                        logical_bytes: preview.logical_bytes,
                        complete: preview.complete,
                        elapsed_micros: preview.elapsed.as_micros(),
                    },
                )?,
                // A preview failure is never fatal: the authoritative walk below is unaffected,
                // so this degrades to exactly the unaccelerated experience.
                Err(refusal) => sink.push_progress(
                    &root_path,
                    ProgressEvent::AccelerationUnavailable {
                        path: root_path.clone(),
                        reason: refusal.code(),
                        elevation_might_help: refusal.elevation_might_help(),
                    },
                )?,
            }
        }

        let mut frontier = VecDeque::from([FrontierDirectory {
            path: root_metadata.path.clone(),
            handle: directory,
            identity: root_identity.clone(),
            native_component: native_path_component(&root_identity, &root_metadata),
            parent_reopen_recipe: Vec::new(),
            started: false,
            consumed_entries: 0,
            consumed_bytes: 0,
            pending_children: Vec::new(),
        }]);
        let mut active_frontier_entries = 1usize;
        let mut visited_directories = 0usize;
        let mut directory_states = BTreeMap::<PathBuf, DirectoryState>::new();
        directory_states.insert(
            root_metadata.path.clone(),
            DirectoryState::new(root_identity.entry_id.clone()),
        );
        if subtree_scope.is_some_and(|scope| !scope.selected(&root_metadata.path)) {
            directory_states
                .get_mut(&root_metadata.path)
                .expect("root state retained")
                .incomplete_reasons
                .insert(ReasonCode::IncompleteStreamCoverage);
        }

        let worker_count = self.options.max_workers.min(MAX_SCANNER_WORKERS);
        // A worker owns one retained handle for the whole enumerate-and-inspect batch. It cannot
        // allocate ids, update aggregates, or call the sink. The scoped caller below is the sole
        // sequencer and commits results by monotonically increasing ticket.
        std::thread::scope(|scope| -> Result<(), ScanError> {
            let (task_tx, task_rx) =
                sync_channel::<DirectoryTask<P::DirectoryHandle>>(worker_count);
            let task_rx = Arc::new(Mutex::new(task_rx));
            let (result_tx, result_rx) =
                sync_channel::<DirectoryTaskResult<P::DirectoryHandle>>(worker_count);

            for _ in 0..worker_count {
                let task_rx = Arc::clone(&task_rx);
                let result_tx = result_tx.clone();
                let platform = &self.platform;
                let limits = self.options.resource_limits;
                // `reuse` is `Copy` (an optional shared reference) and is captured per worker.
                scope.spawn(move || {
                    loop {
                        let task = {
                            let receiver = task_rx
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            receiver.recv()
                        };
                        let Ok(task) = task else {
                            break;
                        };
                        let ticket = task.ticket;
                        let path = task.current.path.clone();
                        let child_directory_permits = task.child_directory_permits;
                        let result = catch_unwind(AssertUnwindSafe(|| {
                            prepare_directory_task(
                                platform,
                                task,
                                cancel,
                                limits,
                                reuse,
                                allow_file_lengths,
                                subtree_scope,
                            )
                        }))
                        .unwrap_or(DirectoryTaskResult {
                            ticket,
                            child_directory_permits,
                            outcome: DirectoryTaskOutcome::Panicked { path },
                        });
                        if result_tx.send(result).is_err() {
                            break;
                        }
                    }
                });
            }
            drop(result_tx);

            let traversal = (|| -> Result<(), ScanError> {
                let mut next_dispatch_ticket = 0u128;
                let mut next_commit_ticket = 0u128;
                // At most `worker_count` tickets are in flight, so this reorder buffer and both
                // sync channels have a common, explicit bound.
                let mut ready = BTreeMap::<u128, DirectoryTaskResult<P::DirectoryHandle>>::new();
                let mut ticket_paths = BTreeMap::<u128, PathBuf>::new();
                let mut scheduled = VecDeque::<ScheduledDirectory<P::DirectoryHandle>>::new();

                loop {
                    if cancel.is_cancelled() && next_commit_ticket == next_dispatch_ticket {
                        let path = ticket_paths
                            .get(&next_commit_ticket)
                            .cloned()
                            .or_else(|| frontier.front().map(|current| current.path.clone()))
                            .unwrap_or_else(|| root_path.clone());
                        mark_all_open_incomplete(
                            &mut directory_states,
                            ReasonCode::IncompleteStreamCoverage,
                        );
                        sink.push_progress(&root_path, ProgressEvent::Cancelled { path })?;
                        break;
                    }
                    if next_commit_ticket == next_dispatch_ticket
                        && scheduled.is_empty()
                        && frontier.is_empty()
                    {
                        break;
                    }
                    if next_commit_ticket == next_dispatch_ticket
                        && scheduled.is_empty()
                        && !frontier.is_empty()
                    {
                        // Depth-first, with a reserve kept back for descending.
                        //
                        // A breadth-first round expanded *every* directory at the current level
                        // and split the whole permit pool across them, so a wide directory
                        // (npm's `content-v2/sha512` has 256 subdirectories, 24453 in total)
                        // exhausted the pool at that level. Every unadmitted child became a
                        // `frontier limit exceeded` boundary, which makes the *aggregates*
                        // incomplete -- the totals users read became lower bounds, and no amount
                        // of result-side merging can recover a subtree that was never walked.
                        //
                        // Two rules make that bounded rather than lossy. First, the newest
                        // directories are expanded first, so permits are spent descending.
                        // Second, only part of the free pool is granted; the reserve is what
                        // lets the next level down open a handle, so peak usage tracks the
                        // tree's *depth* instead of its widest level.
                        let available = self
                            .options
                            .resource_limits
                            .max_frontier_entries
                            .saturating_sub(active_frontier_entries);
                        let grantable = available - available / 2;
                        // Deriving the round size from what can actually be granted keeps every
                        // scheduled directory at one permit or more. A directory granted zero
                        // must fall back to refusing its child directories, so handing out
                        // zeroes here would reintroduce the very boundaries this avoids.
                        let directory_count = frontier
                            .len()
                            .min(DEPTH_FIRST_ROUND_DIRECTORIES)
                            .min(grantable.max(1));
                        let quotient = grantable / directory_count;
                        let remainder = grantable % directory_count;
                        let preferred = sink.preferred_directory();
                        for index in 0..directory_count {
                            let current =
                                take_frontier_directory(&mut frontier, preferred.as_deref());
                            let child_directory_permits = quotient
                                .saturating_add(usize::from(index < remainder))
                                .min(self.options.resource_limits.max_directory_batch_entries);
                            active_frontier_entries = active_frontier_entries
                                .checked_add(child_directory_permits)
                                .ok_or_else(|| {
                                    PlatformError::ResourceLimit(
                                        "frontier permit accounting overflow".to_string(),
                                    )
                                })?;
                            scheduled.push_back(ScheduledDirectory {
                                current,
                                child_directory_permits,
                            });
                        }
                    }

                    while !cancel.is_cancelled()
                        && next_dispatch_ticket
                            .checked_sub(next_commit_ticket)
                            .and_then(|count| usize::try_from(count).ok())
                            .is_some_and(|count| count < worker_count)
                    {
                        if cancel.is_cancelled() {
                            break;
                        }
                        let Some(ScheduledDirectory {
                            current,
                            child_directory_permits,
                        }) = scheduled.pop_front()
                        else {
                            break;
                        };
                        let ticket = next_dispatch_ticket;
                        next_dispatch_ticket =
                            next_dispatch_ticket.checked_add(1).ok_or_else(|| {
                                PlatformError::ResourceLimit(
                                    "directory scheduler ticket space exhausted".to_string(),
                                )
                            })?;
                        ticket_paths.insert(ticket, current.path.clone());

                        if !current.started {
                            visited_directories =
                                visited_directories.checked_add(1).ok_or_else(|| {
                                    PlatformError::ResourceLimit(
                                        "visited directory accounting overflow".to_string(),
                                    )
                                })?;
                        }
                        if !current.started
                            && visited_directories
                                > self.options.resource_limits.max_visited_entries
                        {
                            ready.insert(
                                ticket,
                                DirectoryTaskResult {
                                    ticket,
                                    child_directory_permits,
                                    outcome: DirectoryTaskOutcome::VisitedLimit {
                                        path: current.path.clone(),
                                    },
                                },
                            );
                            continue;
                        }

                        task_tx
                            .send(DirectoryTask {
                                ticket,
                                current,
                                child_directory_permits,
                            })
                            .map_err(|_| {
                                PlatformError::Unsupported(
                                    "directory scheduler stopped unexpectedly".to_string(),
                                )
                            })?;
                    }

                    if next_commit_ticket == next_dispatch_ticket {
                        continue;
                    }

                    while !ready.contains_key(&next_commit_ticket) {
                        let result = result_rx.recv().map_err(|_| {
                            PlatformError::Unsupported(
                                "directory scheduler stopped unexpectedly".to_string(),
                            )
                        })?;
                        if ready.insert(result.ticket, result).is_some() {
                            return Err(PlatformError::Unsupported(
                                "directory scheduler returned a duplicate ticket".to_string(),
                            )
                            .into());
                        }
                    }
                    let result = ready
                        .remove(&next_commit_ticket)
                        .expect("next stable directory ticket is ready");
                    let DirectoryTaskResult {
                        child_directory_permits,
                        outcome,
                        ..
                    } = result;
                    ticket_paths.remove(&next_commit_ticket);
                    next_commit_ticket = next_commit_ticket.checked_add(1).ok_or_else(|| {
                        PlatformError::ResourceLimit(
                            "directory scheduler ticket space exhausted".to_string(),
                        )
                    })?;
                    active_frontier_entries = active_frontier_entries.saturating_sub(1);
                    active_frontier_entries =
                        active_frontier_entries.saturating_sub(child_directory_permits);

                    let PreparedDirectoryBatch {
                        current,
                        inspected,
                        mut opened_child_permits,
                        end_of_directory,
                        directory_limit_blocks_continuation,
                        terminal,
                    } = match outcome {
                        DirectoryTaskOutcome::Batch(batch) => *batch,
                        DirectoryTaskOutcome::VisitedLimit { path } => {
                            let boundary = BoundaryRecord {
                                path: path.clone(),
                                kind: BoundaryKind::ResourceLimit,
                                reason: ReasonCode::ResourceLimit,
                                detail: "visited directory limit exceeded".to_string(),
                            };
                            note_boundary(
                                &mut directory_states,
                                &boundary.path,
                                boundary.reason.clone(),
                            );
                            sink.push_progress(&root_path, ProgressEvent::ResourceLimit { path })?;
                            sink.push_boundary(&root_path, boundary)?;
                            continue;
                        }
                        DirectoryTaskOutcome::Cancelled { path } => {
                            mark_all_open_incomplete(
                                &mut directory_states,
                                ReasonCode::IncompleteStreamCoverage,
                            );
                            sink.push_progress(&root_path, ProgressEvent::Cancelled { path })?;
                            break;
                        }
                        DirectoryTaskOutcome::EnumerationIo { path } => {
                            note_boundary(
                                &mut directory_states,
                                &path,
                                ReasonCode::IncompleteStreamCoverage,
                            );
                            sink.push_progress(
                                &root_path,
                                ProgressEvent::Error {
                                    path,
                                    reason: ReasonCode::IncompleteStreamCoverage,
                                },
                            )?;
                            continue;
                        }
                        DirectoryTaskOutcome::EnumerationResourceLimit { path, detail } => {
                            note_boundary(&mut directory_states, &path, ReasonCode::ResourceLimit);
                            sink.push_progress(
                                &root_path,
                                ProgressEvent::ResourceLimit { path: path.clone() },
                            )?;
                            sink.push_boundary(
                                &root_path,
                                BoundaryRecord {
                                    path,
                                    kind: BoundaryKind::ResourceLimit,
                                    reason: ReasonCode::ResourceLimit,
                                    detail,
                                },
                            )?;
                            continue;
                        }
                        DirectoryTaskOutcome::Fatal(error) => return Err(error.into()),
                        DirectoryTaskOutcome::Panicked { path } => {
                            return Err(PlatformError::Unsupported(format!(
                                "platform scanner panicked while scanning {}",
                                path.display()
                            ))
                            .into());
                        }
                    };
                    let path = current.path.clone();
                    // A directory stays owned while it still has unconsumed stream *or* an
                    // uninspected backlog. Dropping it with a non-empty backlog would silently
                    // discard children that were already enumerated, which is exactly the
                    // lower-bound outcome this scheduling is meant to prevent.
                    let continuation_reserved = (!end_of_directory
                        || !current.pending_children.is_empty())
                        && !directory_limit_blocks_continuation;
                    if continuation_reserved {
                        // Keep the continuation slot reserved while this stable ticket commits,
                        // exactly as in the single-worker traversal.
                        active_frontier_entries += 1;
                    }

                    for walk in inspected {
                        let entry_id =
                            allocate_scan_entry_id(&self.options.scan_id, next_entry_ordinal)?;
                        match walk {
                            WalkEntry::Directory(opened) => {
                                if opened_child_permits == 0 {
                                    return Err(PlatformError::Unsupported(
                                        "directory worker returned an unpermitted child handle"
                                            .to_string(),
                                    )
                                    .into());
                                }
                                opened_child_permits -= 1;
                                let metadata = opened.metadata;
                                let same_mount = if root_metadata.mount_identity.is_none()
                                    || metadata.mount_identity.is_none()
                                {
                                    Err(PlatformError::Unsupported(
                                        "mount identity unavailable".to_string(),
                                    ))
                                } else {
                                    self.platform.is_same_mount(&root_metadata, &metadata)
                                };
                                match same_mount {
                                    Ok(true) => {}
                                    Ok(false) => {
                                        let boundary = BoundaryRecord {
                                            path: metadata.path.clone(),
                                            kind: BoundaryKind::Mount,
                                            reason: ReasonCode::UnsupportedFilesystem,
                                            detail: "entry crosses the initial mount boundary"
                                                .to_string(),
                                        };
                                        note_boundary(
                                            &mut directory_states,
                                            &metadata.path,
                                            boundary.reason.clone(),
                                        );
                                        sink.push_progress(
                                            &root_path,
                                            ProgressEvent::Boundary {
                                                path: metadata.path.clone(),
                                                kind: boundary.kind.clone(),
                                            },
                                        )?;
                                        sink.push_boundary(&root_path, boundary)?;
                                        continue;
                                    }
                                    Err(_) => {
                                        let boundary = BoundaryRecord {
                                    path: metadata.path.clone(),
                                    kind: BoundaryKind::Mount,
                                    reason: ReasonCode::UnknownIdentity,
                                    detail: "mount identity unavailable; refusing to cross uncertain boundary".to_string(),
                                };
                                        note_boundary(
                                            &mut directory_states,
                                            &metadata.path,
                                            boundary.reason.clone(),
                                        );
                                        sink.push_progress(
                                            &root_path,
                                            ProgressEvent::Boundary {
                                                path: metadata.path.clone(),
                                                kind: boundary.kind.clone(),
                                            },
                                        )?;
                                        sink.push_boundary(&root_path, boundary)?;
                                        continue;
                                    }
                                }

                                let descend =
                                    subtree_scope.is_none_or(|scope| scope.related(&metadata.path));
                                if descend
                                    && sink
                                        .retained_aggregate_count()
                                        .checked_add(directory_states.len())
                                        .is_none_or(|count| {
                                            count
                                                >= self
                                                    .options
                                                    .resource_limits
                                                    .max_retained_aggregates
                                        })
                                {
                                    let boundary = BoundaryRecord {
                                        path: metadata.path.clone(),
                                        kind: BoundaryKind::ResourceLimit,
                                        reason: ReasonCode::ResourceLimit,
                                        detail: "retained aggregate limit exceeded".to_string(),
                                    };
                                    note_boundary(
                                        &mut directory_states,
                                        &metadata.path,
                                        boundary.reason.clone(),
                                    );
                                    sink.push_progress(
                                        &root_path,
                                        ProgressEvent::Boundary {
                                            path: metadata.path.clone(),
                                            kind: boundary.kind.clone(),
                                        },
                                    )?;
                                    sink.push_boundary(&root_path, boundary)?;
                                    continue;
                                }

                                let identity = scan_object_identity(
                                    entry_id.clone(),
                                    root_identity.entry_id.clone(),
                                    Some(current.identity.entry_id.clone()),
                                    &metadata,
                                );
                                let native_component = native_path_component(&identity, &metadata);
                                let scanned = scanned_entry_from_metadata(
                                    &self.options.scan_id,
                                    &metadata,
                                    identity.clone(),
                                    native_locator_evidence(
                                        &root_locator,
                                        &native_path_component(&root_identity, &root_metadata),
                                        &current.parent_recipe_with_self(),
                                        &native_component,
                                    ),
                                    complete_coverage(),
                                );
                                sink.push_progress(
                                    &root_path,
                                    ProgressEvent::EntryObserved {
                                        path: metadata.path.clone(),
                                        kind: ObjectType::Directory,
                                    },
                                )?;
                                propagate_directory_entry(&mut directory_states, &metadata.path);
                                sink.push_entry(&root_path, scanned)?;
                                if !descend {
                                    continue;
                                }
                                if let Some(monitor) = &self.monitor
                                    && monitor.is_available()
                                {
                                    self.platform.monitor_directory(
                                        &opened.handle,
                                        &metadata.path,
                                        false,
                                        monitor,
                                    );
                                }
                                directory_states
                                    .entry(metadata.path.clone())
                                    .or_insert_with(|| DirectoryState::new(entry_id.clone()));
                                if subtree_scope
                                    .is_some_and(|scope| !scope.selected(&metadata.path))
                                {
                                    directory_states
                                        .get_mut(&metadata.path)
                                        .expect("child state retained")
                                        .incomplete_reasons
                                        .insert(ReasonCode::IncompleteStreamCoverage);
                                }
                                if sink.accepts_closed_subtrees() {
                                    directory_states
                                        .get_mut(&path)
                                        .expect("parent state retained")
                                        .open_subtrees += 1;
                                }
                                frontier.push_back(FrontierDirectory {
                                    path: metadata.path.clone(),
                                    handle: opened.handle,
                                    identity,
                                    native_component,
                                    parent_reopen_recipe: current.parent_recipe_with_self(),
                                    started: false,
                                    consumed_entries: 0,
                                    consumed_bytes: 0,
                                    pending_children: Vec::new(),
                                });
                                active_frontier_entries += 1;
                            }
                            WalkEntry::CachedFile(cached) => {
                                // Fold a current bulk or validated cached length and its marker.
                                // Neither observation has full file facts, so no row is retained.
                                sink.push_progress(
                                    &root_path,
                                    ProgressEvent::EntryObserved {
                                        path: cached.path.clone(),
                                        kind: ObjectType::File,
                                    },
                                )?;
                                propagate_cached_file(
                                    &mut directory_states,
                                    &cached.path,
                                    cached.logical_bytes,
                                );
                                sink.note_cached_file(&current.identity.entry_id, &cached);
                            }
                            WalkEntry::File(metadata) => {
                                let identity = scan_object_identity(
                                    entry_id,
                                    root_identity.entry_id.clone(),
                                    Some(current.identity.entry_id.clone()),
                                    &metadata,
                                );
                                let native_component = native_path_component(&identity, &metadata);
                                let scanned = scanned_entry_from_metadata(
                                    &self.options.scan_id,
                                    &metadata,
                                    identity.clone(),
                                    native_locator_evidence(
                                        &root_locator,
                                        &native_path_component(&root_identity, &root_metadata),
                                        &current.parent_recipe_with_self(),
                                        &native_component,
                                    ),
                                    complete_coverage(),
                                );
                                sink.push_progress(
                                    &root_path,
                                    ProgressEvent::EntryObserved {
                                        path: metadata.path.clone(),
                                        kind: ObjectType::File,
                                    },
                                )?;
                                propagate_file_entry(
                                    &mut directory_states,
                                    &metadata.path,
                                    &metadata,
                                );
                                sink.push_entry(&root_path, scanned)?;
                            }
                            WalkEntry::Link(metadata) => {
                                let identity = scan_object_identity(
                                    entry_id,
                                    root_identity.entry_id.clone(),
                                    Some(current.identity.entry_id.clone()),
                                    &metadata,
                                );
                                let native_component = native_path_component(&identity, &metadata);
                                let coverage = Coverage {
                                    state: CoverageState::Complete,
                                    complete: true,
                                    incomplete_reasons: vec![],
                                    details_lost: false,
                                    provenance: live_provenance(),
                                };
                                sink.push_progress(
                                    &root_path,
                                    ProgressEvent::Boundary {
                                        path: metadata.path.clone(),
                                        kind: BoundaryKind::Symlink,
                                    },
                                )?;
                                sink.push_boundary(
                                    &root_path,
                                    BoundaryRecord {
                                        path: metadata.path.clone(),
                                        kind: BoundaryKind::Symlink,
                                        reason: ReasonCode::StrictReadOnly,
                                        detail: "symlink recorded and not followed".to_string(),
                                    },
                                )?;
                                sink.push_entry(
                                    &root_path,
                                    scanned_entry_from_metadata(
                                        &self.options.scan_id,
                                        &metadata,
                                        identity.clone(),
                                        native_locator_evidence(
                                            &root_locator,
                                            &native_path_component(&root_identity, &root_metadata),
                                            &current.parent_recipe_with_self(),
                                            &native_component,
                                        ),
                                        coverage,
                                    ),
                                )?;
                            }
                            WalkEntry::Boundary(boundary) => {
                                note_boundary(
                                    &mut directory_states,
                                    &boundary.path,
                                    boundary.reason.clone(),
                                );
                                sink.push_progress(
                                    &root_path,
                                    ProgressEvent::Boundary {
                                        path: boundary.path.clone(),
                                        kind: boundary.kind.clone(),
                                    },
                                )?;
                                sink.push_boundary(&root_path, boundary)?;
                            }
                            WalkEntry::Error(error) => {
                                note_boundary(
                                    &mut directory_states,
                                    &error.path,
                                    error.reason.clone(),
                                );
                                sink.push_progress(
                                    &root_path,
                                    ProgressEvent::Error {
                                        path: error.path.clone(),
                                        reason: error.reason.clone(),
                                    },
                                )?;
                                sink.push_entry(
                                    &root_path,
                                    ScannedEntry {
                                        scan_id: self.options.scan_id.clone(),
                                        identity: Some(ScanObjectIdentity {
                                            entry_id,
                                            scan_root_id: root_identity.entry_id.clone(),
                                            parent_id: Some(current.identity.entry_id.clone()),
                                            platform_file_identity: IdentityEvidence::unknown(
                                                ReasonCode::UnknownIdentity,
                                            ),
                                            filesystem_object_domain_identity:
                                                IdentityEvidence::unknown(
                                                    ReasonCode::UnknownIdentity,
                                                ),
                                            volume_or_mount_identity: IdentityEvidence::unknown(
                                                ReasonCode::UnknownIdentity,
                                            ),
                                        }),
                                        native_locator: None,
                                        display_path: error.path.display().to_string(),
                                        native_basename: native_basename_for_path(&error.path),
                                        object_type: ObjectType::Other,
                                        logical_bytes: unknown_u128(error.reason.clone()),
                                        allocated_bytes: unknown_u128(error.reason.clone()),
                                        hard_link_count: None,
                                        reclaimable_estimate: unknown_u128(error.reason.clone()),
                                        metadata_fingerprint: format!("error:{}", error.detail),
                                        coverage: Coverage {
                                            state: CoverageState::Incomplete,
                                            complete: false,
                                            incomplete_reasons: vec![error.reason.clone()],
                                            details_lost: false,
                                            provenance: live_provenance(),
                                        },
                                        provenance: live_provenance(),
                                    },
                                )?;
                            }
                        }
                    }
                    let cancelled_during_inspection = match terminal {
                        Some(InspectionTerminal::Cancelled {
                            path: cancelled_path,
                        }) => {
                            mark_all_open_incomplete(
                                &mut directory_states,
                                ReasonCode::IncompleteStreamCoverage,
                            );
                            sink.push_progress(
                                &root_path,
                                ProgressEvent::Cancelled {
                                    path: cancelled_path,
                                },
                            )?;
                            true
                        }
                        Some(InspectionTerminal::Fatal(error)) => return Err(error.into()),
                        None => false,
                    };
                    if opened_child_permits != 0 {
                        return Err(PlatformError::Unsupported(
                            "directory worker did not account for its frontier permit".to_string(),
                        )
                        .into());
                    }
                    if cancelled_during_inspection {
                        break;
                    }
                    if directory_limit_blocks_continuation {
                        note_boundary(&mut directory_states, &path, ReasonCode::ResourceLimit);
                        sink.push_progress(
                            &root_path,
                            ProgressEvent::ResourceLimit { path: path.clone() },
                        )?;
                        sink.push_boundary(
                            &root_path,
                            BoundaryRecord {
                                path: path.clone(),
                                kind: BoundaryKind::ResourceLimit,
                                reason: ReasonCode::ResourceLimit,
                                detail: "per-directory cumulative enumeration limit exceeded"
                                    .to_string(),
                            },
                        )?;
                    }
                    if continuation_reserved {
                        frontier.push_back(current);
                    }
                    if sink.wants_directory_progress()
                        && let Some(state) = directory_states.get(&path)
                    {
                        // Only committed batches reach consumers. Outstanding worker results
                        // and unvisited descendants make every interim total a lower bound.
                        sink.note_directory_progress(
                            &path,
                            &state.aggregate(&self.options.scan_id, false),
                        );
                    }
                    if sink.accepts_closed_subtrees()
                        && !continuation_reserved
                        && end_of_directory
                        && !directory_limit_blocks_continuation
                        && !cancel.is_cancelled()
                    {
                        sink.note_directory_enumerated(
                            &directory_states
                                .get(&path)
                                .expect("enumerated state retained")
                                .entry_id,
                        );
                        finish_subtree_batch(
                            &root_path,
                            &path,
                            &self.options.scan_id,
                            &mut directory_states,
                            sink,
                        )?;
                    }
                }
                Ok(())
            })();

            drop(task_tx);
            traversal
        })?;

        // Only lost *evidence* invalidates the totals. A dropped aggregate or boundary means a
        // subtree's contribution is unaccounted for, so every still-open directory must be
        // reported as a lower bound.
        //
        // Truncated detail is deliberately not escalated here. `propagate_file_entry` folds an
        // entry's bytes into its ancestors' aggregates before the row reaches the sink, so a row
        // dropped by the retention cap has already been counted. Escalating it would have
        // reported exact totals as incomplete -- observed on a wide tree where all 12001
        // aggregates were flagged `resource_limit` purely because the scan produced more rows
        // than the result buffer holds. The truncation is still visible as a boundary record, so
        // the *listing* is honestly reported as partial while the *totals* stay exact.
        let retention_overflow = sink.overflow_count() > overflow_count_before;
        if retention_overflow {
            // Live consumers already received each boundary. Preserve the native walk's coverage
            // separately while keeping stored summaries and reuse indexes conservative. Normal
            // scans reuse the final aggregate below, avoiding a second aggregate computation.
            for (path, state) in &directory_states {
                sink.note_native_directory_coverage(
                    path,
                    &state.aggregate(&self.options.scan_id, true).coverage,
                );
            }
            mark_all_open_incomplete(&mut directory_states, ReasonCode::ResourceLimit);
        }

        let mut aggregates: Vec<(PathBuf, DirectoryAggregate)> = directory_states
            .into_iter()
            .map(|(path, state)| (path, state.into_aggregate(&self.options.scan_id)))
            .collect();
        aggregates.sort_by(|(_, left), (_, right)| {
            left.directory_identity.cmp(&right.directory_identity)
        });
        for (path, aggregate) in aggregates {
            if !retention_overflow {
                sink.note_native_directory_coverage(&path, &aggregate.coverage);
            }
            // Report the directory path and its coverage before the sink possibly drops the
            // aggregate; used to record full subtree coverage for the reuse index.
            sink.note_directory_coverage(&path, &aggregate.coverage);
            sink.push_aggregate(&root_path, aggregate)?;
        }
        Ok(())
    }
}

/// Closes admitted subtrees on the sequencer after their final committed batch. File bytes
/// have already been folded into every open ancestor, so removing a closed state loses no
/// accounting. A finished child waits if its parent still has unconsumed markers. Errors and
/// cancelled streams never set enumeration_finished; their ancestors fall back to root-end
/// lower bounds. The short-lived waiting-path list is bounded by the admitted state count.
fn finish_subtree_batch(
    root: &Path,
    path: &Path,
    scan_id: &ScanId,
    states: &mut BTreeMap<PathBuf, DirectoryState>,
    sink: &mut dyn ScanSink,
) -> Result<(), ScanError> {
    states
        .get_mut(path)
        .expect("enumerated state retained")
        .enumeration_finished = true;
    let waiting: Vec<_> = states
        .range(path.to_path_buf()..)
        .take_while(|(child, _)| child.starts_with(path))
        .filter(|(child, state)| {
            child.parent() == Some(path)
                && state.subtree_closed
                && state.incomplete_reasons.is_empty()
        })
        .map(|(child, _)| child.clone())
        .collect();
    for child in waiting {
        emit_closed_subtree(root, &child, scan_id, states, sink)?;
    }
    let mut current = path.to_path_buf();
    while let Some(state) = states.get_mut(&current) {
        if state.subtree_closed || !state.enumeration_finished || state.open_subtrees != 0 {
            break;
        }
        state.subtree_closed = true;
        let complete = state.incomplete_reasons.is_empty();
        let parent = current
            .parent()
            .filter(|parent| states.contains_key(*parent))
            .map(Path::to_path_buf);
        let parent_enumerated = if let Some(parent) = &parent {
            let state = states.get_mut(parent).expect("parent retained");
            state.open_subtrees = state.open_subtrees.checked_sub(1).ok_or_else(|| {
                PlatformError::Unsupported("closed subtree accounting underflow".into())
            })?;
            state.enumeration_finished
        } else {
            true
        };
        if complete && parent_enumerated {
            emit_closed_subtree(root, &current, scan_id, states, sink)?;
        }
        let Some(parent) = parent else {
            break;
        };
        current = parent;
    }
    Ok(())
}

fn emit_closed_subtree(
    root: &Path,
    path: &Path,
    scan_id: &ScanId,
    states: &mut BTreeMap<PathBuf, DirectoryState>,
    sink: &mut dyn ScanSink,
) -> Result<(), ScanError> {
    let state = states.remove(path).expect("closed subtree retained");
    let aggregate = state.into_aggregate(scan_id);
    sink.note_native_directory_coverage(path, &aggregate.coverage);
    sink.note_directory_coverage(path, &aggregate.coverage);
    sink.push_aggregate(root, aggregate)
}

#[derive(Debug, Clone)]
struct DirectoryState {
    entry_id: ScanEntryId,
    direct_child_count: u128,
    recursive_entry_count: u128,
    apparent_logical_bytes: u128,
    unique_logical_bytes: Option<u128>,
    allocated_bytes: EvidenceAccumulator,
    reclaimable_bytes: EvidenceAccumulator,
    incomplete_reasons: BTreeSet<ReasonCode>,
    counted_hard_links: BTreeSet<HardLinkKey>,
    // Only used by sinks accepting completed subtrees. No child paths or hard-link sets are
    // copied into the closure tracker. A parent closes after all admitted children close.
    enumeration_finished: bool,
    open_subtrees: usize,
    subtree_closed: bool,
}

impl DirectoryState {
    fn new(entry_id: ScanEntryId) -> Self {
        Self {
            entry_id,
            direct_child_count: 0,
            recursive_entry_count: 0,
            apparent_logical_bytes: 0,
            unique_logical_bytes: Some(0),
            allocated_bytes: EvidenceAccumulator::known_zero(),
            reclaimable_bytes: EvidenceAccumulator::known_zero(),
            incomplete_reasons: BTreeSet::new(),
            counted_hard_links: BTreeSet::new(),
            enumeration_finished: false,
            open_subtrees: 0,
            subtree_closed: false,
        }
    }

    fn note_direct_child(&mut self) {
        self.direct_child_count += 1;
    }

    fn note_recursive_entry(&mut self) {
        self.recursive_entry_count += 1;
    }

    fn into_aggregate(self, scan_id: &ScanId) -> DirectoryAggregate {
        self.aggregate(scan_id, true)
    }

    /// Borrows the small scalar state without cloning the retained hard-link identity set.
    /// A progress snapshot deliberately leaves recursive coverage incomplete.
    fn aggregate(&self, scan_id: &ScanId, final_observation: bool) -> DirectoryAggregate {
        let complete = final_observation && self.incomplete_reasons.is_empty();
        let mut reasons: Vec<_> = self.incomplete_reasons.iter().cloned().collect();
        if !final_observation && !reasons.contains(&ReasonCode::IncompleteStreamCoverage) {
            reasons.push(ReasonCode::IncompleteStreamCoverage);
        }
        let apparent = if complete {
            known_u128(self.apparent_logical_bytes)
        } else {
            lower_bound_u128(
                self.apparent_logical_bytes,
                ReasonCode::IncompleteStreamCoverage,
            )
        };
        let unique = match self.unique_logical_bytes {
            Some(value) if complete => known_u128(value),
            Some(value) => lower_bound_u128(value, ReasonCode::IncompleteStreamCoverage),
            None => unknown_u128(ReasonCode::UnknownIdentity),
        };
        let allocated = self.allocated_bytes.clone().into_value(complete);
        let reclaimable = self.reclaimable_bytes.clone().into_value(complete);

        DirectoryAggregate {
            scan_id: scan_id.clone(),
            directory_identity: self.entry_id.to_string(),
            revision: DecimalU128::new(1),
            apparent_logical_bytes: apparent,
            unique_logical_bytes: unique,
            filesystem_reported_allocated_bytes: allocated.clone(),
            potentially_reclaimable_bytes: reclaimable,
            direct_child_count: if final_observation {
                known_count(self.direct_child_count)
            } else {
                lower_bound_u128(
                    self.direct_child_count,
                    ReasonCode::IncompleteStreamCoverage,
                )
            },
            recursive_entry_count: if final_observation {
                known_count(self.recursive_entry_count)
            } else {
                lower_bound_u128(
                    self.recursive_entry_count,
                    ReasonCode::IncompleteStreamCoverage,
                )
            },
            coverage: Coverage {
                state: if complete {
                    CoverageState::Complete
                } else {
                    CoverageState::Incomplete
                },
                complete,
                incomplete_reasons: reasons,
                details_lost: false,
                provenance: live_provenance(),
            },
            arithmetic_state: if complete {
                ArithmeticState::Exact
            } else {
                ArithmeticState::LowerBound
            },
        }
    }
}

fn allocate_scan_entry_id(
    scan_id: &ScanId,
    next_ordinal: &mut Option<u128>,
) -> Result<ScanEntryId, ScanError> {
    let ordinal = next_ordinal.take().ok_or_else(|| {
        ScanError::Platform(PlatformError::ResourceLimit(
            "scan entry identity space exhausted".to_string(),
        ))
    })?;
    if ordinal > ORDINARY_SCAN_MAX_ORDINAL {
        return Err(ScanError::Platform(PlatformError::ResourceLimit(
            "ordinary scan entry identity space exhausted".to_string(),
        )));
    }
    *next_ordinal = if ordinal == ORDINARY_SCAN_MAX_ORDINAL {
        None
    } else {
        Some(ordinal + 1)
    };
    ScanEntryId::for_scan_ordinal(scan_id, ordinal)
        .map_err(|error| ScanError::RootValidation(error.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EvidenceAccumulator {
    Known(u128),
    LowerBound { value: u128, reason: ReasonCode },
    Unknown { reason: ReasonCode },
}

impl EvidenceAccumulator {
    fn known_zero() -> Self {
        Self::Known(0)
    }

    fn add(&mut self, value: &sweepx_platform::ByteValue) {
        let incoming = Self::from_value(value);
        *self = match (&*self, incoming) {
            (Self::Unknown { reason }, _) => Self::Unknown {
                reason: reason.clone(),
            },
            (_, Self::Unknown { reason }) => Self::Unknown { reason },
            (Self::Known(current), Self::Known(next)) => match current.checked_add(next) {
                Some(value) => Self::Known(value),
                None => Self::Unknown {
                    reason: ReasonCode::Overflow,
                },
            },
            (Self::Known(current), Self::LowerBound { value, reason }) => Self::LowerBound {
                value: match current.checked_add(value) {
                    Some(value) => value,
                    None => {
                        return *self = Self::Unknown {
                            reason: ReasonCode::Overflow,
                        };
                    }
                },
                reason,
            },
            (Self::LowerBound { value, reason }, Self::Known(current)) => Self::LowerBound {
                value: match value.checked_add(current) {
                    Some(value) => value,
                    None => {
                        return *self = Self::Unknown {
                            reason: ReasonCode::Overflow,
                        };
                    }
                },
                reason: reason.clone(),
            },
            (
                Self::LowerBound {
                    value: left_value,
                    reason: left_reason,
                },
                Self::LowerBound {
                    value: right_value,
                    reason,
                },
            ) => Self::LowerBound {
                value: match left_value.checked_add(right_value) {
                    Some(value) => value,
                    None => {
                        return *self = Self::Unknown {
                            reason: ReasonCode::Overflow,
                        };
                    }
                },
                reason: combine_reasons(left_reason, &reason),
            },
        };
    }

    fn into_value(self, complete: bool) -> sweepx_platform::ByteValue {
        match self {
            Self::Known(value) if complete => known_u128(value),
            Self::Known(value) => lower_bound_u128(value, ReasonCode::IncompleteStreamCoverage),
            Self::LowerBound { value, reason } => lower_bound_u128(value, reason),
            Self::Unknown { reason } => unknown_u128(reason),
        }
    }

    fn from_value(value: &sweepx_platform::ByteValue) -> Self {
        match value {
            EvidenceValue::Known { value } => Self::Known(value.0),
            EvidenceValue::LowerBound { value, reason } => Self::LowerBound {
                value: value.0,
                reason: reason.clone(),
            },
            EvidenceValue::Unknown { reason }
            | EvidenceValue::Unsupported { reason }
            | EvidenceValue::NotChecked { reason } => Self::Unknown {
                reason: reason.clone(),
            },
        }
    }
}

fn combine_reasons(left: &ReasonCode, right: &ReasonCode) -> ReasonCode {
    if left == right {
        left.clone()
    } else {
        ReasonCode::UnknownIdentity
    }
}

fn propagate_directory_entry(states: &mut BTreeMap<PathBuf, DirectoryState>, path: &Path) {
    for ancestor in path.ancestors().skip(1) {
        if let Some(state) = states.get_mut(ancestor) {
            state.note_recursive_entry();
            if path.parent() == Some(ancestor) {
                state.note_direct_child();
            }
        }
    }
}

fn propagate_file_entry(
    states: &mut BTreeMap<PathBuf, DirectoryState>,
    path: &Path,
    metadata: &EntryMetadata,
) {
    let logical = extract_known_u128(&metadata.logical_bytes).unwrap_or(0);
    let has_multiple_links = matches!(
        &metadata.hard_link_count,
        sweepx_model::EvidenceValue::Known { value } if value.0 > 1
    );

    for ancestor in path.ancestors().skip(1) {
        if let Some(state) = states.get_mut(ancestor) {
            state.note_recursive_entry();
            state.apparent_logical_bytes += logical;
            if path.parent() == Some(ancestor) {
                state.note_direct_child();
            }

            match metadata.hard_link_key.as_ref() {
                Some(key) => {
                    if state.counted_hard_links.insert(key.clone()) {
                        add_option_u128(&mut state.unique_logical_bytes, logical);
                        state.allocated_bytes.add(&metadata.allocated_bytes);
                    }
                    if has_multiple_links {
                        state.reclaimable_bytes = EvidenceAccumulator::Unknown {
                            reason: ReasonCode::UnknownIdentity,
                        };
                    } else if state.counted_hard_links.contains(key) {
                        state.reclaimable_bytes.add(&metadata.allocated_bytes);
                    }
                }
                None => {
                    state.unique_logical_bytes = None;
                    state.allocated_bytes = EvidenceAccumulator::Unknown {
                        reason: ReasonCode::UnknownIdentity,
                    };
                    state.reclaimable_bytes = EvidenceAccumulator::Unknown {
                        reason: ReasonCode::UnknownIdentity,
                    };
                }
            }
        }
    }
}

/// Folds a regular file's length-only observation into every ancestor state.
///
/// Bulk and cached shortcuts carry logical length only, not allocation or hard-link identity.
/// Propagate those missing fields as unknown; logical length is never a reclaimable estimate.
fn propagate_cached_file(
    states: &mut BTreeMap<PathBuf, DirectoryState>,
    path: &Path,
    logical: u128,
) {
    for ancestor in path.ancestors().skip(1) {
        if let Some(state) = states.get_mut(ancestor) {
            state.note_recursive_entry();
            state.apparent_logical_bytes += logical;
            state.unique_logical_bytes = None;
            state.allocated_bytes = EvidenceAccumulator::Unknown {
                reason: ReasonCode::UnknownIdentity,
            };
            state.reclaimable_bytes = EvidenceAccumulator::Unknown {
                reason: ReasonCode::UnknownIdentity,
            };
            if path.parent() == Some(ancestor) {
                state.note_direct_child();
            }
        }
    }
}

fn add_option_u128(slot: &mut Option<u128>, value: u128) {
    if let Some(current) = slot.as_mut() {
        *current += value;
    }
}

fn note_boundary(states: &mut BTreeMap<PathBuf, DirectoryState>, path: &Path, reason: ReasonCode) {
    for ancestor in path.ancestors() {
        if let Some(state) = states.get_mut(ancestor) {
            state.incomplete_reasons.insert(reason.clone());
            if path.parent() == Some(ancestor) {
                state.note_direct_child();
            }
        }
    }
}

fn mark_all_open_incomplete(states: &mut BTreeMap<PathBuf, DirectoryState>, reason: ReasonCode) {
    for state in states.values_mut() {
        state.incomplete_reasons.insert(reason.clone());
    }
}

fn scanned_entry_from_metadata(
    scan_id: &ScanId,
    metadata: &EntryMetadata,
    identity: ScanObjectIdentity,
    native_locator: NativeLocatorEvidence,
    coverage: Coverage,
) -> ScannedEntry {
    ScannedEntry {
        scan_id: scan_id.clone(),
        identity: Some(identity),
        native_locator: Some(native_locator),
        display_path: metadata.path.display().to_string(),
        native_basename: metadata.file_name.clone(),
        object_type: match metadata.kind {
            EntryKind::File => ObjectType::File,
            EntryKind::Directory => ObjectType::Directory,
            EntryKind::Symlink => ObjectType::Symlink,
            EntryKind::ReparsePoint => ObjectType::ReparsePoint,
            EntryKind::Other => ObjectType::Other,
        },
        logical_bytes: metadata.logical_bytes.clone(),
        allocated_bytes: metadata.allocated_bytes.clone(),
        hard_link_count: Some(metadata.hard_link_count.clone()),
        reclaimable_estimate: match metadata.kind {
            EntryKind::File => {
                if matches!(
                    &metadata.hard_link_count,
                    sweepx_model::EvidenceValue::Known { value } if value.0 > 1
                ) {
                    unknown_u128(ReasonCode::UnknownIdentity)
                } else {
                    metadata.allocated_bytes.clone()
                }
            }
            EntryKind::Directory
            | EntryKind::Symlink
            | EntryKind::ReparsePoint
            | EntryKind::Other => known_u128(0),
        },
        metadata_fingerprint: metadata.fingerprint.clone(),
        coverage,
        provenance: live_provenance(),
    }
}

fn native_path_component(
    identity: &ScanObjectIdentity,
    metadata: &EntryMetadata,
) -> NativePathComponent {
    NativePathComponent {
        entry_id: identity.entry_id.clone(),
        parent_id: identity.parent_id.clone(),
        native_basename: metadata.file_name.clone(),
        object_type: match metadata.kind {
            EntryKind::File => ObjectType::File,
            EntryKind::Directory => ObjectType::Directory,
            EntryKind::Symlink => ObjectType::Symlink,
            EntryKind::ReparsePoint => ObjectType::ReparsePoint,
            EntryKind::Other => ObjectType::Other,
        },
        platform_file_identity: identity.platform_file_identity.clone(),
        filesystem_object_domain_identity: identity.filesystem_object_domain_identity.clone(),
        volume_or_mount_identity: identity.volume_or_mount_identity.clone(),
        metadata_fingerprint: metadata.fingerprint.clone(),
    }
}

fn scan_object_identity(
    entry_id: ScanEntryId,
    scan_root_id: ScanEntryId,
    parent_id: Option<ScanEntryId>,
    metadata: &EntryMetadata,
) -> ScanObjectIdentity {
    let platform_file_identity = match &metadata.identity {
        Some(identity) => IdentityEvidence::known(PlatformFileIdentity {
            device: DecimalU128::new(identity.device().into()),
            inode: DecimalU128::new(identity.inode()),
        }),
        None => IdentityEvidence::unknown(ReasonCode::UnknownIdentity),
    };
    let filesystem_object_domain_identity = match &metadata.filesystem_identity {
        Some(identity) => IdentityEvidence::known(FilesystemObjectDomainIdentity {
            device: DecimalU128::new(identity.device.into()),
        }),
        None => IdentityEvidence::unknown(ReasonCode::UnknownIdentity),
    };
    let volume_or_mount_identity = match &metadata.mount_identity {
        Some(identity) => IdentityEvidence::known(VolumeOrMountIdentity {
            value: DecimalU128::new(identity.value.into()),
        }),
        None => IdentityEvidence::unknown(ReasonCode::UnknownIdentity),
    };

    ScanObjectIdentity {
        entry_id,
        scan_root_id,
        parent_id,
        platform_file_identity,
        filesystem_object_domain_identity,
        volume_or_mount_identity,
    }
}

fn native_locator_evidence(
    root_absolute_path: &NativeAbsolutePath,
    root_component: &NativePathComponent,
    parent_reopen_recipe: &[NativePathComponent],
    entry_component: &NativePathComponent,
) -> NativeLocatorEvidence {
    NativeLocatorEvidence {
        scan_root: root_component.clone(),
        scan_root_absolute_path: Some(root_absolute_path.clone()),
        parent_reopen_recipe: parent_reopen_recipe.to_vec(),
        entry: entry_component.clone(),
    }
}

fn complete_coverage() -> Coverage {
    Coverage {
        state: CoverageState::Complete,
        complete: true,
        incomplete_reasons: Vec::new(),
        details_lost: false,
        provenance: live_provenance(),
    }
}

fn cancelled_root_aggregate(scan_id: &ScanId, entry_id: ScanEntryId) -> DirectoryAggregate {
    incomplete_root_aggregate(scan_id, entry_id, ReasonCode::IncompleteStreamCoverage)
}

/// Aggregate for a root whose admission failed because the host refused to read it (a TCC
/// denial). Every quantity is a zero lower bound: no object under the root was observed, so
/// even a direct child count would be invented rather than measured. The `reason` records why
/// coverage is absent so an ancestor total and any delete decision stay fail-closed.
fn access_denied_root_aggregate(scan_id: &ScanId, entry_id: ScanEntryId) -> DirectoryAggregate {
    incomplete_root_aggregate(scan_id, entry_id, ReasonCode::StrictReadOnly)
}

fn incomplete_root_aggregate(
    scan_id: &ScanId,
    entry_id: ScanEntryId,
    reason: ReasonCode,
) -> DirectoryAggregate {
    DirectoryAggregate {
        scan_id: scan_id.clone(),
        directory_identity: entry_id.to_string(),
        revision: DecimalU128::new(1),
        apparent_logical_bytes: lower_bound_u128(0, reason.clone()),
        unique_logical_bytes: lower_bound_u128(0, reason.clone()),
        filesystem_reported_allocated_bytes: lower_bound_u128(0, reason.clone()),
        potentially_reclaimable_bytes: lower_bound_u128(0, reason.clone()),
        direct_child_count: known_count(0),
        recursive_entry_count: known_count(0),
        coverage: Coverage {
            state: CoverageState::Incomplete,
            complete: false,
            incomplete_reasons: vec![reason],
            details_lost: false,
            provenance: live_provenance(),
        },
        arithmetic_state: ArithmeticState::LowerBound,
    }
}

fn live_provenance() -> FieldProvenance {
    FieldProvenance::LiveObservation {
        observed_at: "1970-01-01T00:00:00Z".to_string(),
        method: sweepx_model::MethodId::MetadataNoFollow,
    }
}

fn extract_known_u128(value: &sweepx_platform::ByteValue) -> Option<u128> {
    match value {
        sweepx_model::EvidenceValue::Known { value } => Some(value.0),
        _ => None,
    }
}

fn native_basename_for_path(path: &Path) -> NativeName {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        return NativeName::unix(
            path.file_name()
                .unwrap_or(path.as_os_str())
                .as_bytes()
                .to_vec(),
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        return NativeName::windows_utf16(
            path.file_name()
                .unwrap_or(path.as_os_str())
                .encode_wide()
                .collect::<Vec<_>>(),
        );
    }
    #[allow(unreachable_code)]
    NativeName::unix(path.display().to_string().into_bytes())
}

/// Converts a retained native basename into the marker string rules compare against.
///
/// Matches the CLI's `native_name_for_rule`: UTF-8 on Unix, lowercased UTF-16 on Windows.
/// A non-UTF-8 Unix name returns `None` -- no marker is recorded rather than a lossy guess.
fn native_basename_marker(name: &NativeName) -> Option<String> {
    match name {
        NativeName::UnixBytes(bytes) => String::from_utf8(bytes.clone()).ok(),
        NativeName::WindowsUtf16(units) => String::from_utf16(units)
            .ok()
            .map(|name| name.to_ascii_lowercase()),
    }
}

#[cfg(test)]
mod tests {
    mod early_candidates;
    use std::collections::BTreeMap;
    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    use super::*;

    /// Builds a synthetic absolute path that the host accepts as absolute.
    ///
    /// These scanner tests drive a fake backend, so the paths never touch a real
    /// filesystem, but `ScanRoot` still validates absoluteness -- and that is
    /// platform-defined. `/root` is absolute on Unix yet relative on Windows, where a
    /// path needs a volume prefix, so a hardcoded Unix literal would make every test
    /// here fail on Windows for a reason unrelated to what it asserts.
    fn test_path(relative: &str) -> PathBuf {
        #[cfg(windows)]
        {
            PathBuf::from(format!("C:\\{}", relative.replace('/', "\\")))
        }
        #[cfg(not(windows))]
        {
            PathBuf::from(format!("/{relative}"))
        }
    }
    use sweepx_platform::{
        DirectoryEntryBatch, DirectoryEntryRecord, EntryIdentity, FilesystemIdentity, MountIdentity,
    };

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    fn linux_scanner(options: ScannerOptions) -> Scanner<HostPlatformScanner> {
        Scanner::new(HostPlatformScanner::new(), options)
    }

    fn test_native_name(name: &str) -> NativeName {
        #[cfg(unix)]
        {
            return NativeName::unix(name.as_bytes().to_vec());
        }
        #[cfg(windows)]
        {
            return NativeName::windows_utf16(name.encode_utf16().collect::<Vec<_>>());
        }
        #[allow(unreachable_code)]
        NativeName::unix(name.as_bytes().to_vec())
    }

    fn test_entry(parent: &Path, name: &str) -> DirectoryEntryRecord {
        DirectoryEntryRecord::from_parent_and_name(parent, test_native_name(name)).unwrap()
    }

    #[test]
    fn ordinary_entry_allocator_stops_before_detail_ordinal_namespace() {
        let scan_id = ScanId::new("ordinal-partition");
        let mut next = Some(ORDINARY_SCAN_MAX_ORDINAL);

        let last = allocate_scan_entry_id(&scan_id, &mut next).expect("last ordinary ordinal");
        assert_eq!(
            last,
            ScanEntryId::for_scan_ordinal(&scan_id, ORDINARY_SCAN_MAX_ORDINAL).unwrap()
        );
        assert_eq!(next, None);
        assert!(matches!(
            allocate_scan_entry_id(&scan_id, &mut next),
            Err(ScanError::Platform(PlatformError::ResourceLimit(detail)))
                if detail == "scan entry identity space exhausted"
        ));

        let mut already_in_detail_namespace = Some(ORDINARY_SCAN_MAX_ORDINAL + 1);
        assert!(matches!(
            allocate_scan_entry_id(&scan_id, &mut already_in_detail_namespace),
            Err(ScanError::Platform(PlatformError::ResourceLimit(detail)))
                if detail == "ordinary scan entry identity space exhausted"
        ));
    }

    #[test]
    fn bounded_scheduler_honors_worker_count_and_caps_it_at_32() {
        let serial_probe = Arc::new(SchedulerProbe::new(1));
        let serial = SchedulingPlatform::new(4, Arc::clone(&serial_probe));
        let serial_root = serial.root.clone();
        Scanner::new(
            serial,
            ScannerOptions {
                max_workers: 1,
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(serial_root).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(serial_probe.max_active.load(Ordering::SeqCst), 1);
        assert!(!serial_probe.same_handle_overlap.load(Ordering::SeqCst));

        let parallel_probe = Arc::new(SchedulerProbe::new(4));
        let parallel = SchedulingPlatform::new(4, Arc::clone(&parallel_probe));
        let parallel_root = parallel.root.clone();
        Scanner::new(
            parallel,
            ScannerOptions {
                max_workers: 4,
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(parallel_root).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(parallel_probe.max_active.load(Ordering::SeqCst), 4);
        assert!(!parallel_probe.same_handle_overlap.load(Ordering::SeqCst));

        let capped_probe = Arc::new(SchedulerProbe::new(MAX_SCANNER_WORKERS));
        let capped = SchedulingPlatform::new(MAX_SCANNER_WORKERS + 8, Arc::clone(&capped_probe));
        let capped_root = capped.root.clone();
        Scanner::new(
            capped,
            ScannerOptions {
                max_workers: usize::MAX,
                // The barrier checks all 32 workers with a deliberately larger synthetic
                // frontier. The native default must leave room in the shared I/O pool.
                resource_limits: ScanResourceLimits {
                    max_frontier_entries: 256,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(capped_root).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(
            capped_probe.max_active.load(Ordering::SeqCst),
            MAX_SCANNER_WORKERS
        );
        assert!(!capped_probe.same_handle_overlap.load(Ordering::SeqCst));
    }

    #[test]
    fn frontier_admission_is_independent_of_worker_count() {
        fn scan_with_workers(max_workers: usize) -> Vec<(String, ObjectType)> {
            let probe = Arc::new(SchedulerProbe::new(0));
            let platform = SchedulingPlatform::new(4, probe);
            let root = platform.root.clone();
            let summary = Scanner::new(
                platform,
                ScannerOptions {
                    scan_id: ScanId::new(format!("worker-parity-{max_workers}")),
                    max_workers,
                    resource_limits: ScanResourceLimits {
                        max_frontier_entries: 3,
                        ..ScanResourceLimits::default()
                    },
                    ..ScannerOptions::default()
                },
            )
            .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
            .unwrap();
            summary
                .entries
                .into_iter()
                .map(|entry| (entry.display_path, entry.object_type))
                .collect()
        }

        assert_eq!(scan_with_workers(1), scan_with_workers(4));
    }

    #[test]
    fn sequencer_commits_worker_results_in_stable_ticket_order() {
        let root = test_path("scheduler-root");
        // Traversal is depth-first, so the *last* enumerated child is dispatched first and
        // therefore holds the earlier ticket. Making that one the slow worker is what gives
        // this test its teeth: the earlier ticket must still commit first even though it
        // finishes last. Pinning the slow role to `dir-000` instead would hand the earlier
        // ticket to the worker that also finishes first, and the assertion below would pass
        // without the sequencer reordering anything.
        let first_dispatched_and_slow = root.join("dir-001");
        let second_dispatched_but_fast = root.join("dir-000");
        let probe = Arc::new(SchedulerProbe::new(2).with_out_of_order(
            first_dispatched_and_slow.clone(),
            second_dispatched_but_fast.clone(),
        ));
        let platform = SchedulingPlatform::new(2, Arc::clone(&probe));

        let summary = Scanner::new(
            platform,
            ScannerOptions {
                scan_id: ScanId::new("stable-scheduler"),
                max_workers: 2,
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();

        // Wall-clock completion really was the reverse of dispatch order...
        let completion_order = probe.completion_order();
        assert_eq!(
            &completion_order[..2],
            [
                second_dispatched_but_fast.clone(),
                first_dispatched_and_slow.clone()
            ],
            "the probe failed to invert completion order, so this test would prove nothing"
        );
        // ...yet the committed leaves follow dispatch order, not completion order. The two
        // directories themselves are committed by the root's ticket, so they appear in
        // enumeration order.
        assert_eq!(
            summary
                .entries
                .iter()
                .map(|entry| PathBuf::from(&entry.display_path))
                .collect::<Vec<_>>(),
            [
                second_dispatched_but_fast.clone(),
                first_dispatched_and_slow.clone(),
                first_dispatched_and_slow.join("leaf"),
                second_dispatched_but_fast.join("leaf"),
            ]
        );
        assert_eq!(
            summary
                .entries
                .iter()
                .map(|entry| entry.identity.as_ref().unwrap().entry_id.clone())
                .collect::<Vec<_>>(),
            (2..=5)
                .map(|ordinal| {
                    ScanEntryId::for_scan_ordinal(&ScanId::new("stable-scheduler"), ordinal)
                        .unwrap()
                })
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn platform_panic_completes_its_ticket_without_hanging_the_scheduler() {
        let probe = Arc::new(SchedulerProbe::new(0));
        let platform = SchedulingPlatform::new(8, Arc::clone(&probe))
            .with_panic_path(test_path("scheduler-root/dir-000"));
        let root = platform.root.clone();
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);

        let scan = std::thread::spawn(move || {
            let result = Scanner::new(
                platform,
                ScannerOptions {
                    max_workers: 4,
                    ..ScannerOptions::default()
                },
            )
            .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new());
            done_tx.send(result).unwrap();
        });

        let result = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("scheduler hung after a platform worker panicked");
        scan.join().unwrap();
        assert!(matches!(
            result,
            Err(ScanError::Platform(PlatformError::Unsupported(detail)))
                if detail.contains("platform scanner panicked")
                    && detail.contains("dir-000")
        ));
    }

    #[test]
    fn cancellation_stops_new_directory_dispatch_with_bounded_overshoot() {
        let probe = Arc::new(SchedulerProbe::new(0));
        let child_count = 8;
        let platform = SchedulingPlatform::new(child_count, Arc::clone(&probe));
        let root = platform.root.clone();
        // Depth-first dispatch takes the newest directory first, so the round that carries the
        // cancel trigger begins with the last enumerated child.
        let first_dispatched = root.join("dir-007");
        probe.set_cancel_path(first_dispatched.clone());
        let cancel = CancellationToken::new();
        let max_workers = 2;

        let summary = Scanner::new(
            platform,
            ScannerOptions {
                max_workers,
                ..ScannerOptions::default()
            },
        )
        .scan(&[ScanRoot::new(root.clone()).unwrap()], &cancel)
        .unwrap();

        // Only the directories already dispatched into the bounded in-flight window may start.
        // Which of them records itself first is a race between the workers, so asserting an
        // order here would assert a race outcome; the meaningful claims are the window's size
        // and *which* directories it drew from.
        let started = probe.started_paths();
        assert!(
            started.len() <= max_workers,
            "cancel dispatched beyond the bounded in-flight window: {started:?}"
        );
        assert!(
            started.contains(&first_dispatched),
            "the directory that triggers cancellation must have run: {started:?}"
        );
        // Depth-first order is observable here: the window must be drawn from the *last*
        // enumerated children. Under the old breadth-first scheduling this set would have been
        // `dir-000`/`dir-001` instead, so this also guards the traversal order.
        let newest_children: BTreeSet<PathBuf> = (child_count - max_workers..child_count)
            .map(|index| root.join(format!("dir-{index:03}")))
            .collect();
        assert!(
            started.iter().all(|path| newest_children.contains(path)),
            "depth-first dispatch must draw from the newest children, got {started:?}"
        );
        // Nothing from a deeper level may start: cancellation is observed before this round's
        // children are ever enumerated, so every started path is a direct child of the root.
        assert!(
            started
                .iter()
                .all(|path| path.parent() == Some(root.as_path())),
            "a directory from a deeper level started after cancellation: {started:?}"
        );
        assert!(
            summary
                .progress
                .iter()
                .any(|event| { matches!(event, ProgressEvent::Cancelled { .. }) })
        );
        assert!(
            summary
                .aggregates
                .iter()
                .all(|aggregate| !aggregate.coverage.complete)
        );
    }

    /// A wide, deep tree must scan completely instead of degrading to lower bounds.
    ///
    /// This is the npm `_cacache` shape in miniature: a directory whose fan-out exceeds the
    /// frontier permit pool, with content nested underneath it. Under breadth-first
    /// scheduling the pool was divided across the whole level, so most children became
    /// `frontier limit exceeded` boundaries and every ancestor aggregate turned into a
    /// lower bound -- the totals users read were wrong no matter how results were merged
    /// afterwards. The assertions below are about *evidence quality*, which is what that
    /// bug actually damaged.
    #[test]
    fn a_wide_fan_out_tree_is_scanned_completely_within_a_small_frontier() {
        let fan_out = 64;
        let frontier_permits = 8;
        assert!(
            fan_out > frontier_permits,
            "the fan-out must exceed the permit pool or this proves nothing"
        );

        let platform = NestedFanOutPlatform::new(fan_out);
        let root = platform.root.clone();
        let summary = Scanner::new(
            platform,
            ScannerOptions {
                scan_id: ScanId::new("wide-fan-out"),
                max_workers: 4,
                resource_limits: ScanResourceLimits {
                    max_frontier_entries: frontier_permits,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();

        assert!(
            !summary
                .boundaries
                .iter()
                .any(|boundary| boundary.detail == "frontier limit exceeded"),
            "a bounded depth-first traversal must not shed directories at a wide level"
        );
        // Every directory in the tree: the root, its children, and one leaf directory under
        // each child.
        assert_eq!(summary.aggregates.len(), 1 + fan_out * 2);
        assert!(
            summary
                .aggregates
                .iter()
                .all(|aggregate| aggregate.coverage.complete),
            "totals must be exact, not lower bounds, when nothing was actually skipped"
        );
        assert!(
            summary
                .aggregates
                .iter()
                .all(|aggregate| aggregate.arithmetic_state == ArithmeticState::Exact)
        );
        // Each leaf directory holds one file, and the payload must reach the root total.
        let root_aggregate = aggregate_for_path(&summary, &root);
        assert_eq!(
            root_aggregate.apparent_logical_bytes,
            known_u128((fan_out as u128) * NestedFanOutPlatform::FILE_BYTES)
        );
        assert_eq!(
            root_aggregate.recursive_entry_count,
            known_count((fan_out as u128) * 3)
        );
    }

    /// Truncating the entry listing must not be reported as inexact totals.
    ///
    /// Observed on a real wide tree: 12001 directories were all walked and the byte total was
    /// provably exact, yet every aggregate came back `resource_limit` and the run reported
    /// `partial`, purely because the scan produced more rows than the result buffer holds.
    /// Users read the totals; telling them a complete total is a lower bound is a correctness
    /// bug in the opposite direction from the one the cap exists to prevent.
    #[test]
    fn truncating_the_entry_listing_keeps_directory_totals_exact() {
        let fan_out = 16;
        let platform = NestedFanOutPlatform::new(fan_out);
        let root = platform.root.clone();
        // Well below the number of entries this tree produces, so the cap is certain to bite.
        let retained_entries = 4;

        let summary = Scanner::new(
            platform,
            ScannerOptions {
                scan_id: ScanId::new("detail-truncation"),
                max_workers: 4,
                resource_limits: ScanResourceLimits {
                    max_retained_entries: retained_entries,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();

        assert_eq!(
            summary.entries.len(),
            retained_entries,
            "the cap must actually have truncated the listing"
        );
        // Directory rows now have their own admission pool, so the overflow that fires first is
        // named by whichever pool the depth-first traversal filled. Either message proves the
        // truncation stayed visible; the ordering between pools is not a contract.
        assert!(
            summary.boundaries.iter().any(|boundary| {
                boundary.kind == BoundaryKind::ResourceLimit
                    && matches!(
                        boundary.detail.as_str(),
                        "retained entry cap exceeded" | "retained directory entry cap exceeded"
                    )
            }),
            "truncation must stay visible so the listing is not mistaken for complete"
        );

        // Nothing was skipped, so every total must still be exact.
        assert_eq!(summary.aggregates.len(), 1 + fan_out * 2);
        assert!(
            summary
                .aggregates
                .iter()
                .all(|aggregate| aggregate.coverage.complete),
            "detail truncation must not turn exact totals into lower bounds"
        );
        assert!(
            summary
                .aggregates
                .iter()
                .all(|aggregate| aggregate.arithmetic_state == ArithmeticState::Exact)
        );
        // The root total is joined through the retained root row, which is never truncated.
        let root_aggregate = aggregate_for_path(&summary, &root);
        assert_eq!(
            root_aggregate.apparent_logical_bytes,
            known_u128((fan_out as u128) * NestedFanOutPlatform::FILE_BYTES)
        );
        assert_eq!(
            root_aggregate.recursive_entry_count,
            known_count((fan_out as u128) * 3)
        );
    }

    /// File rows must not consume the cap directory classification needs.
    ///
    /// The fixture holds 32 directory rows and 16 file rows. With a 40-row cap the old single
    /// pool could retain as few as 24 directory rows once files were admitted, silently
    /// removing cache directories from junk classification. Directory rows now carry their
    /// own count, so every directory row is retained even when the overall cap is spent on
    /// files; only surplus file rows are dropped as detail overflow.
    #[test]
    fn directory_rows_are_retained_even_when_file_rows_fill_the_cap() {
        let fan_out = 16;
        let platform = NestedFanOutPlatform::new(fan_out);
        let root = platform.root.clone();
        let retained_entries = 40;

        let summary = Scanner::new(
            platform,
            ScannerOptions {
                scan_id: ScanId::new("directory-pool"),
                max_workers: 4,
                resource_limits: ScanResourceLimits {
                    max_retained_entries: retained_entries,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        )
        .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
        .unwrap();

        let retained_directory_rows = summary
            .entries
            .iter()
            .filter(|entry| entry.object_type == ObjectType::Directory)
            .count();
        assert_eq!(
            retained_directory_rows,
            fan_out * 2,
            "file rows must not crowd directory rows out of the listing"
        );
        assert_eq!(summary.entries.len(), retained_entries);
        assert!(summary.boundaries.iter().any(|boundary| {
            boundary.kind == BoundaryKind::ResourceLimit
                && boundary.detail == "retained entry cap exceeded"
        }));
    }

    /// A classified scan retains only rows the classifier accepts and records their rule ids;
    /// aggregates are likewise retained only for the classified directories.
    #[test]
    fn classified_scan_keeps_only_matching_directory_rows() {
        let fan_out = 8;
        let platform = NestedFanOutPlatform::new(fan_out);
        let root = platform.root.clone();

        /// Matches branch directories only (`dir-NNN`), rejecting leaf directories.
        struct BranchOnly;
        impl JunkClassifier for BranchOnly {
            fn classify(
                &self,
                entry: &ScannedEntry,
                _markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
            ) -> Option<String> {
                match &entry.native_basename {
                    NativeName::UnixBytes(bytes) if bytes.starts_with(b"dir-") => {
                        Some("rule:branch".to_string())
                    }
                    _ => None,
                }
            }
        }

        let result = Scanner::new(
            platform,
            ScannerOptions {
                scan_id: ScanId::new("classified"),
                max_workers: 4,
                ..ScannerOptions::default()
            },
        )
        .scan_classified(
            &[ScanRoot::new(root).unwrap()],
            &CancellationToken::new(),
            &BranchOnly,
            None,
        )
        .unwrap();

        // Only the fan classified branches retain aggregates: non-candidate directories (the
        // root and the leaves) drop theirs because no total reads them. Each branch's retained
        // aggregate still carries that whole subtree's measured size.
        assert_eq!(result.summary.aggregates.len(), fan_out);
        // Exactly the fan branch rows, each with one decision carrying the rule id.
        assert_eq!(result.decisions.len(), fan_out);
        assert!(
            result
                .decisions
                .values()
                .all(|rule_id| rule_id == "rule:branch")
        );
        assert_eq!(result.summary.entries.len(), fan_out);
        assert!(result.summary.entries.iter().all(|entry| {
            matches!(&entry.native_basename,
                NativeName::UnixBytes(bytes) if bytes.starts_with(b"dir-"))
        }));
        // Leaf directories must not have been retained as rows.
        assert!(
            !result
                .summary
                .entries
                .iter()
                .any(|entry| matches!(&entry.native_basename,
                NativeName::UnixBytes(bytes) if bytes.as_slice() == b"leaf"))
        );
    }

    struct ObservedBranches;
    impl JunkClassifier for ObservedBranches {
        fn classify(
            &self,
            entry: &ScannedEntry,
            _: &BTreeMap<ScanEntryId, BTreeSet<String>>,
        ) -> Option<String> {
            native_basename_marker(&entry.native_basename)
                .is_some_and(|name| name.starts_with("dir-"))
                .then(|| "rule:branch".to_string())
        }
    }

    #[derive(Default)]
    struct ObservationLog {
        candidates: Vec<(ScannedEntry, String, DirectoryAggregate)>,
        statistics: Vec<(PathBuf, DirectoryAggregate)>,
        boundaries: Vec<BoundaryRecord>,
        progress: Vec<ProgressEvent>,
        finished: bool,
        cancel_on_batch: Option<CancellationToken>,
        preference_after_batch: Option<PathBuf>,
    }

    impl ClassifiedScanObserver for ObservationLog {
        fn on_progress(&mut self, _: &Path, event: &ProgressEvent) {
            self.finished |= matches!(event, ProgressEvent::Finished);
            self.progress.push(event.clone());
        }

        fn on_boundary(&mut self, boundary: &BoundaryRecord) {
            self.boundaries.push(boundary.clone());
        }

        fn on_directory_progress(&mut self, path: &Path, aggregate: &DirectoryAggregate) {
            assert!(!self.finished, "batch statistics must precede Finished");
            assert!(!aggregate.coverage.complete);
            assert_eq!(aggregate.arithmetic_state, ArithmeticState::LowerBound);
            assert!(matches!(
                aggregate.apparent_logical_bytes,
                EvidenceValue::LowerBound { .. }
            ));
            assert!(matches!(
                aggregate.recursive_entry_count,
                EvidenceValue::LowerBound { .. }
            ));
            self.statistics
                .push((path.to_path_buf(), aggregate.clone()));
            if let Some(cancel) = &self.cancel_on_batch {
                cancel.cancel();
            }
        }

        fn on_candidate(
            &mut self,
            entry: &ScannedEntry,
            rule: &str,
            aggregate: &DirectoryAggregate,
        ) {
            assert!(!self.finished, "final candidate must precede Finished");
            self.candidates
                .push((entry.clone(), rule.to_string(), aggregate.clone()));
        }

        fn preferred_directory(&self) -> Option<PathBuf> {
            (!self.statistics.is_empty())
                .then(|| self.preference_after_batch.clone())
                .flatten()
        }
    }

    #[test]
    fn live_traversal_coverage_does_not_upgrade_retention_limited_cache_evidence() {
        #[derive(Default)]
        struct CoverageObserver {
            coverage: BTreeMap<PathBuf, Coverage>,
        }
        impl ClassifiedScanObserver for CoverageObserver {
            fn on_directory_coverage(&mut self, path: &Path, coverage: &Coverage) {
                assert!(
                    self.coverage
                        .insert(path.to_path_buf(), coverage.clone())
                        .is_none()
                );
            }
        }
        struct RootCandidate;
        impl JunkClassifier for RootCandidate {
            fn classify(
                &self,
                _: &ScannedEntry,
                _: &BTreeMap<ScanEntryId, BTreeSet<String>>,
            ) -> Option<String> {
                Some("fixture:root".into())
            }
        }
        for directory_limit in [usize::MAX, 1] {
            let root = test_path("root");
            let file = root.join("file");
            let link = root.join("link");
            // Classified scans do not retain ordinary file rows, so a row cap alone cannot
            // create this loss. A real link boundary with zero log capacity exercises it.
            let platform = FakePlatform::new(
                root.clone(),
                vec![test_entry(&root, "file"), test_entry(&root, "link")],
                BTreeMap::from([
                    (
                        file.clone(),
                        WalkEntry::File(test_metadata(file, "file", EntryKind::File, Some(1))),
                    ),
                    (
                        link.clone(),
                        WalkEntry::Link(test_metadata(link, "link", EntryKind::Symlink, Some(1))),
                    ),
                ]),
            )
            .with_batch_size(1);
            let mut observer = CoverageObserver::default();
            let result = Scanner::new(
                platform,
                ScannerOptions {
                    resource_limits: ScanResourceLimits {
                        max_retained_entries: 1,
                        max_retained_boundaries: 0,
                        max_directory_entries: directory_limit,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .scan_classified_with_observer(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
                &RootCandidate,
                None,
                &mut observer,
            )
            .unwrap();
            assert!(result.summary.boundaries.is_empty());
            assert!(!result.covered_paths.is_empty());
            assert!(
                result.covered_paths.values().all(|complete| !complete),
                "retained cache evidence remains conservative"
            );
            assert!(
                result
                    .summary
                    .aggregates
                    .iter()
                    .all(|aggregate| !aggregate.coverage.complete)
            );
            if directory_limit == usize::MAX {
                assert_eq!(
                    observer.coverage.len(),
                    1,
                    "controlled root has only a file and link"
                );
                assert!(observer.coverage.values().all(|coverage| coverage.complete));
                assert!(observer.coverage[&root].complete);
            } else {
                assert!(
                    !observer.coverage[&root].complete,
                    "real traversal truncation remains a gap"
                );
            }
        }
    }

    #[test]
    fn live_classified_observations_preserve_results_and_final_candidates() {
        let platform = NestedFanOutPlatform::new(8);
        let roots = [ScanRoot::new(platform.root.clone()).unwrap()];
        let scanner = Scanner::new(platform, ScannerOptions::default());
        let ordinary = scanner
            .scan_classified(&roots, &CancellationToken::new(), &ObservedBranches, None)
            .unwrap();
        let mut observed = ObservationLog::default();
        let live = scanner
            .scan_classified_with_observer(
                &roots,
                &CancellationToken::new(),
                &ObservedBranches,
                None,
                &mut observed,
            )
            .unwrap();
        assert_eq!(ordinary.summary, live.summary);
        assert_eq!(ordinary.decisions, live.decisions);
        assert_eq!(ordinary.directory_markers, live.directory_markers);
        assert_eq!(ordinary.coverages, live.coverages);
        assert_eq!(ordinary.covered_paths, live.covered_paths);
        assert_eq!(ordinary.dir_listings, live.dir_listings);
        assert_eq!(ordinary.observed_roots, live.observed_roots);
        assert_eq!(live.observed_roots.len(), 1);
        assert!(
            live.summary.roots.is_empty(),
            "a non-candidate root is not junk"
        );
        assert!(observed.finished);
        assert_eq!(observed.progress, live.summary.progress);
        assert_eq!(observed.boundaries, live.summary.boundaries);
        assert!(!observed.statistics.is_empty());
        assert_eq!(observed.candidates.len(), 8);
        for (entry, rule, aggregate) in observed.candidates {
            let id = entry.identity.as_ref().unwrap().entry_id.clone();
            assert_eq!(live.decisions.get(&id), Some(&rule));
            assert!(live.summary.entries.contains(&entry));
            assert!(live.summary.aggregates.contains(&aggregate));
            assert!(aggregate.coverage.complete);
            // The controlled fixture contains exactly one ordinary payload per branch.
            assert_eq!(aggregate.recursive_entry_count, known_count(2));
        }
    }

    #[test]
    fn observer_cancels_between_batches_without_claiming_complete_statistics() {
        let platform = NestedFanOutPlatform::new(8);
        let roots = [ScanRoot::new(platform.root.clone()).unwrap()];
        let cancel = CancellationToken::new();
        let mut observed = ObservationLog {
            cancel_on_batch: Some(cancel.clone()),
            ..ObservationLog::default()
        };
        let result = Scanner::new(
            platform,
            ScannerOptions {
                max_workers: 1,
                ..ScannerOptions::default()
            },
        )
        .scan_classified_with_observer(&roots, &cancel, &ObservedBranches, None, &mut observed)
        .unwrap();
        assert!(cancel.is_cancelled());
        assert_eq!(observed.statistics.len(), 1);
        assert!(observed.finished);
        assert!(
            observed
                .progress
                .iter()
                .any(|event| matches!(event, ProgressEvent::Cancelled { .. }))
        );
        assert!(
            result
                .summary
                .aggregates
                .iter()
                .all(|aggregate| !aggregate.coverage.complete)
        );
        assert!(
            observed
                .candidates
                .iter()
                .all(|(_, _, aggregate)| !aggregate.coverage.complete)
        );
    }

    #[test]
    fn progress_log_omissions_preserve_classified_results_and_live_observations() {
        let platform = NestedFanOutPlatform::new(8);
        let roots = [ScanRoot::new(platform.root.clone()).unwrap()];
        let ordinary = Scanner::new(platform, ScannerOptions::default())
            .scan_classified(&roots, &CancellationToken::new(), &ObservedBranches, None)
            .unwrap();
        for cap in [0, 1, 4] {
            let mut observed = ObservationLog::default();
            let result = Scanner::new(
                NestedFanOutPlatform::new(8),
                ScannerOptions {
                    resource_limits: ScanResourceLimits {
                        max_progress_events: cap,
                        ..ScanResourceLimits::default()
                    },
                    ..ScannerOptions::default()
                },
            )
            .scan_classified_with_observer(
                &roots,
                &CancellationToken::new(),
                &ObservedBranches,
                None,
                &mut observed,
            )
            .unwrap();
            assert!(result.summary.progress.len() <= cap);
            assert!(result.summary.progress_retention.omitted_events > 0);
            assert!(result.summary.progress_retention.finished && observed.finished);
            assert!(!result.summary.progress_retention.cancelled);
            assert!(!result.summary.progress_retention.resource_limited);
            assert_eq!(result.summary.error_count(), 0);
            assert_eq!(result.summary.roots, ordinary.summary.roots);
            assert_eq!(result.summary.entries, ordinary.summary.entries);
            assert_eq!(result.summary.aggregates, ordinary.summary.aggregates);
            assert_eq!(result.summary.boundaries, ordinary.summary.boundaries);
            assert_eq!(result.decisions, ordinary.decisions);
            assert_eq!(result.coverages, ordinary.coverages);
            assert_eq!(observed.candidates.len(), ordinary.decisions.len());
            assert_eq!(observed.progress, ordinary.summary.progress);
        }
    }

    #[test]
    fn progress_log_cap_cannot_hide_errors_cancellation_or_traversal_end() {
        let root = test_path("progress-root");
        for cap in [0, 1, 4] {
            let mut sink = CollectingScanSink::new(ScanResourceLimits {
                max_progress_events: cap,
                ..ScanResourceLimits::default()
            });
            for index in 0..10 {
                sink.push_progress(
                    &root,
                    ProgressEvent::Error {
                        path: root.join(format!("failed-{index}")),
                        reason: ReasonCode::IncompleteStreamCoverage,
                    },
                )
                .unwrap();
                sink.push_progress(
                    &root,
                    ProgressEvent::EntryObserved {
                        path: root.join(format!("ordinary-{index}")),
                        kind: ObjectType::File,
                    },
                )
                .unwrap();
            }
            sink.push_progress(&root, ProgressEvent::Cancelled { path: root.clone() })
                .unwrap();
            sink.push_progress(&root, ProgressEvent::Finished).unwrap();
            assert_eq!(sink.detail_overflow_count(), 0);
            assert_eq!(sink.overflow_count(), 0);
            let result = sink.finish();
            assert_eq!(result.error_count(), 10);
            assert_eq!(
                result.progress_retention.omitted_events + result.progress.len() as u128,
                22
            );
            assert!(result.progress_retention.cancelled && result.progress_retention.finished);
            assert!(result.boundaries.is_empty());
            assert!(result.progress.len() <= cap);
            if cap > 0 {
                assert_eq!(result.progress.last(), Some(&ProgressEvent::Finished));
            }
        }
    }

    #[test]
    fn enumeration_error_remains_counted_without_a_progress_log() {
        let root = test_path("error-root");
        let platform = FakePlatform::new(root.clone(), Vec::new(), BTreeMap::new())
            .with_enumeration_failure(PlatformError::Io {
                path: root.clone(),
                detail: "controlled I/O failure".into(),
                io_kind: Some(std::io::ErrorKind::PermissionDenied),
            });
        let result = Scanner::new(
            platform,
            ScannerOptions {
                resource_limits: ScanResourceLimits {
                    max_progress_events: 0,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(result.progress.is_empty());
        assert_eq!(result.error_count(), 1);
        assert!(result.progress_retention.finished);
        assert!(!aggregate_for_path(&result, &root).coverage.complete);
    }

    #[test]
    fn observer_delivers_boundaries_and_finish_outside_retained_log_caps() {
        let root = test_path("observer-root");
        let platform = FakePlatform::new(root.clone(), Vec::new(), BTreeMap::new())
            .with_enumeration_failure(PlatformError::ResourceLimit(
                "controlled enumeration limit".into(),
            ));
        let mut observed = ObservationLog::default();
        let result = Scanner::new(
            platform,
            ScannerOptions {
                resource_limits: ScanResourceLimits {
                    max_progress_events: 0,
                    max_retained_boundaries: 0,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        )
        .scan_classified_with_observer(
            &[ScanRoot::new(root).unwrap()],
            &CancellationToken::new(),
            &ObservedBranches,
            None,
            &mut observed,
        )
        .unwrap();
        assert!(result.summary.progress.is_empty());
        assert!(result.summary.boundaries.is_empty());
        assert!(result.summary.progress_retention.resource_limited);
        assert!(result.summary.progress_retention.finished);
        assert!(observed.finished);
        assert!(
            observed
                .boundaries
                .iter()
                .any(|boundary| boundary.detail == "controlled enumeration limit")
        );
        assert!(
            observed
                .progress
                .iter()
                .any(|event| matches!(event, ProgressEvent::ResourceLimit { .. }))
        );
    }

    #[test]
    fn a_live_preference_changes_admitted_dispatch_order_without_changing_coverage() {
        let probe = Arc::new(SchedulerProbe::new(0));
        let platform = SchedulingPlatform::new(4, Arc::clone(&probe));
        let root = platform.root.clone();
        let preferred = root.join("dir-000");
        let mut observed = ObservationLog {
            preference_after_batch: Some(preferred.clone()),
            ..ObservationLog::default()
        };
        let result = Scanner::new(
            platform,
            ScannerOptions {
                max_workers: 1,
                ..ScannerOptions::default()
            },
        )
        .scan_classified_with_observer(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
            &ObservedBranches,
            None,
            &mut observed,
        )
        .unwrap();
        let started = &probe.state.lock().unwrap().started_paths;
        assert_eq!(started.first(), Some(&preferred));
        let expected: BTreeSet<_> = (0..4)
            .map(|index| root.join(format!("dir-{index:03}")))
            .collect();
        assert_eq!(started.iter().cloned().collect::<BTreeSet<_>>(), expected);
        assert_eq!(result.decisions.len(), 4);
        assert!(
            result
                .summary
                .aggregates
                .iter()
                .all(|aggregate| aggregate.coverage.complete
                    && aggregate.recursive_entry_count == known_count(1))
        );
        assert!(result.summary.boundaries.is_empty());
        assert!(!probe.same_handle_overlap.load(Ordering::SeqCst));
    }

    #[test]
    fn metadata_budget_exhaustion_never_turns_missing_markers_into_a_match() {
        struct NegativePredicate(std::cell::Cell<usize>);
        impl JunkClassifier for NegativePredicate {
            fn classify(
                &self,
                _: &ScannedEntry,
                markers: &BTreeMap<ScanEntryId, BTreeSet<String>>,
            ) -> Option<String> {
                self.0.set(self.0.get() + 1);
                markers
                    .is_empty()
                    .then(|| "absence-is-not-proof".to_string())
            }
        }
        let platform = NestedFanOutPlatform::new(2);
        let root = platform.root.clone();
        let classifier = NegativePredicate(std::cell::Cell::new(0));
        let result = Scanner::new(
            platform,
            ScannerOptions {
                resource_limits: ScanResourceLimits {
                    max_classified_metadata_bytes: 0,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        )
        .scan_classified(
            &[ScanRoot::new(root).unwrap()],
            &CancellationToken::new(),
            &classifier,
            None,
        )
        .unwrap();
        assert_eq!(
            classifier.0.get(),
            0,
            "no evaluator may see falsely complete missing facts"
        );
        assert!(result.decisions.is_empty());
        assert!(result.covered_paths.is_empty());
        assert!(
            result
                .summary
                .boundaries
                .iter()
                .any(|boundary| boundary.kind == BoundaryKind::ResourceLimit)
        );
        assert!(
            result
                .summary
                .progress
                .iter()
                .any(|event| matches!(event, ProgressEvent::EntryObserved { .. })),
            "metadata retention must not stop the filesystem walk"
        );
    }

    #[test]
    fn required_evidence_evicts_optional_root_observations_and_releases_their_vector() {
        let platform = NestedFanOutPlatform::new(0);
        let root = platform.root.clone();
        let source = Scanner::new(platform, ScannerOptions::default())
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap()
            .roots
            .remove(0);
        let mut sink =
            CollectingScanSink::new_classified(ScanResourceLimits::default(), &ObservedBranches);
        sink.push_root(&root, source).unwrap();
        assert_eq!(sink.observed_roots.len(), 1);
        sink.limits.max_classified_metadata_bytes = sink.metadata_bytes;
        // Fill the current admission budget, then request one required evidence byte. Optional
        // publication facts must be discarded before required classification becomes partial.
        assert!(sink.admit_metadata(1, true));
        assert!(sink.observed_roots.is_empty());
        assert_eq!(sink.observed_roots.capacity(), 0);
        assert!(!sink.metadata_lost);
    }

    #[test]
    fn required_marker_evicts_optional_file_indexes_within_the_shared_budget() {
        struct MarkerOnly;
        impl JunkClassifier for MarkerOnly {
            fn needs_file_marker(&self, name: &NativeName) -> bool {
                name == &test_native_name("Cargo.toml")
            }
            fn classify(
                &self,
                _: &ScannedEntry,
                _: &BTreeMap<ScanEntryId, BTreeSet<String>>,
            ) -> Option<String> {
                None
            }
        }
        let mut sink = CollectingScanSink::new_classified(
            ScanResourceLimits {
                max_classified_metadata_bytes: 1024,
                max_classified_root_metadata_bytes: 1024,
                ..ScanResourceLimits::default()
            },
            &MarkerOnly,
        );
        let parent = ScanEntryId::from_loaded("parent".into());
        let root = test_path("root");
        for index in 0..20 {
            let name = format!("payload-{index:03}");
            sink.note_cached_file(
                &parent,
                &sweepx_platform::CachedFileEntry {
                    path: root.join(&name),
                    file_name: test_native_name(&name),
                    logical_bytes: 7,
                },
            );
            assert!(sink.metadata_bytes <= 1024);
            assert!(sink.root_metadata_bytes <= 1024);
        }
        assert!(sink.reuse_bytes > 0);
        assert!(sink.file_markers.is_empty());
        sink.note_cached_file(
            &parent,
            &sweepx_platform::CachedFileEntry {
                path: root.join("Cargo.toml"),
                file_name: test_native_name("Cargo.toml"),
                logical_bytes: 123,
            },
        );
        assert!(sink.file_markers[&parent].contains("Cargo.toml"));
        assert!(
            !sink.metadata_lost,
            "optional cache pressure must not lose required evidence"
        );
        assert_eq!(sink.detail_overflow_count(), 0);
        assert!(sink.metadata_bytes <= 1024);
        assert!(
            sink.dir_listings
                .values()
                .flat_map(|listing| listing.files.keys())
                .all(|name| name == "Cargo.toml")
        );
    }

    /// Losing a *boundary* record is different in kind, and must still degrade the totals.
    ///
    /// A boundary is the evidence that a subtree was skipped. Once it is dropped there is no
    /// record that anything is missing, so the affected totals genuinely are lower bounds and
    /// must say so. This is the property the detail-truncation fix above must not weaken.
    #[test]
    fn losing_boundary_evidence_still_reports_totals_as_incomplete() {
        let live_handles = Arc::new(AtomicUsize::new(0));
        let max_live_handles = Arc::new(AtomicUsize::new(0));
        let child_inspections = Arc::new(AtomicUsize::new(0));
        let platform = HandleCountingPlatform::new(
            16,
            Arc::clone(&live_handles),
            Arc::clone(&max_live_handles),
            Arc::clone(&child_inspections),
        );
        let root = platform.root.clone();

        let summary = Scanner::new(
            platform,
            ScannerOptions {
                scan_id: ScanId::new("boundary-loss"),
                max_workers: 4,
                resource_limits: ScanResourceLimits {
                    // One permit forces refusals; a tiny boundary buffer then loses the
                    // records describing them.
                    max_frontier_entries: 1,
                    max_retained_boundaries: 2,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();

        assert!(summary.boundaries.iter().any(|boundary| {
            boundary.kind == BoundaryKind::ResourceLimit
                && boundary.detail == "retained boundary cap exceeded"
        }));
        let root_aggregate = aggregate_for_path(&summary, &root);
        assert!(
            !root_aggregate.coverage.complete,
            "dropping the record of a skipped subtree must leave the total a lower bound"
        );
        assert!(
            root_aggregate
                .coverage
                .incomplete_reasons
                .contains(&ReasonCode::ResourceLimit)
        );
    }

    fn test_metadata(
        path: PathBuf,
        name: &str,
        kind: EntryKind,
        mount_identity: Option<u64>,
    ) -> EntryMetadata {
        EntryMetadata {
            path,
            file_name: test_native_name(name),
            kind,
            logical_bytes: known_u128(0),
            allocated_bytes: known_u128(0),
            hard_link_count: known_count(1),
            fingerprint: format!("fake:{name}"),
            identity: Some(EntryIdentity::from_unix(
                1,
                match name {
                    "root" => 1,
                    "child" => 2,
                    "safe" => 3,
                    "evil" => 4,
                    _ => 5,
                },
            )),
            filesystem_identity: Some(FilesystemIdentity { device: 1 }),
            mount_identity: mount_identity.map(|value| MountIdentity { value }),
            hard_link_key: None,
        }
    }

    fn aggregate_for_path<'a>(summary: &'a ScanSummary, path: &Path) -> &'a DirectoryAggregate {
        let entry = summary
            .roots
            .iter()
            .chain(summary.entries.iter())
            .find(|entry| entry.display_path == path.display().to_string())
            .expect("scanned entry for aggregate path");
        let entry_id = &entry
            .identity
            .as_ref()
            .expect("live scanner entry identity")
            .entry_id;
        summary
            .aggregates
            .iter()
            .find(|aggregate| aggregate.directory_identity == entry_id.as_str())
            .expect("aggregate joined by stable scan identity")
    }

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    #[test]
    fn scan_collects_files_symlinks_and_hard_links_deterministically() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let alpha = root.join("alpha.txt");
        fs::write(&alpha, b"1234").unwrap();
        let hard = root.join("alpha-hard.txt");
        fs::hard_link(&alpha, &hard).unwrap();
        let sub = root.join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("beta.txt"), b"123456").unwrap();
        std::os::unix::fs::symlink(&alpha, root.join("alpha-link")).unwrap();

        let scanner = linux_scanner(ScannerOptions::default());
        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        let root_aggregate = aggregate_for_path(&result, &root);
        assert_eq!(root_aggregate.apparent_logical_bytes, known_u128(14));
        assert_eq!(root_aggregate.unique_logical_bytes, known_u128(10));
        assert_eq!(
            root_aggregate.potentially_reclaimable_bytes,
            unknown_u128(ReasonCode::UnknownIdentity)
        );
        assert!(root_aggregate.coverage.complete);
        let root_identity = result.roots[0].identity.as_ref().unwrap();
        assert_eq!(
            root_aggregate.directory_identity,
            root_identity.entry_id.as_str()
        );
        assert!(root_identity.entry_id.belongs_to(&result.roots[0].scan_id));
        assert_eq!(root_identity.entry_id, root_identity.scan_root_id);
        assert_eq!(root_identity.parent_id, None);
        assert!(matches!(
            root_identity.platform_file_identity,
            IdentityEvidence::Known { .. }
        ));
        assert!(matches!(
            root_identity.filesystem_object_domain_identity,
            IdentityEvidence::Known { .. }
        ));
        assert!(matches!(
            root_identity.volume_or_mount_identity,
            IdentityEvidence::Known { .. }
        ));
        let root_locator = result.roots[0].validated_native_locator().unwrap().unwrap();
        assert_eq!(root_locator.scan_root.entry_id, root_identity.entry_id);
        assert_eq!(
            root_locator.scan_root_absolute_path.clone().unwrap(),
            NativeAbsolutePath::from_path(&root).unwrap()
        );
        assert!(root_locator.parent_reopen_recipe.is_empty());
        assert_eq!(root_locator.entry.entry_id, root_identity.entry_id);
        assert_eq!(root_locator.entry.native_basename, test_native_name("root"));
        let sub_entry = result
            .entries
            .iter()
            .find(|entry| entry.display_path == sub.display().to_string())
            .unwrap();
        let sub_identity = sub_entry.identity.as_ref().unwrap();
        assert_eq!(sub_identity.scan_root_id, root_identity.entry_id);
        assert_eq!(
            sub_identity.parent_id.as_ref(),
            Some(&root_identity.entry_id)
        );
        assert_eq!(
            aggregate_for_path(&result, &sub).directory_identity,
            sub_identity.entry_id.as_str()
        );
        let sub_locator = sub_entry.validated_native_locator().unwrap().unwrap();
        assert_eq!(sub_locator.scan_root.entry_id, root_identity.entry_id);
        assert_eq!(
            sub_locator.scan_root_absolute_path.clone().unwrap(),
            NativeAbsolutePath::from_path(&root).unwrap()
        );
        assert_eq!(
            sub_locator
                .parent_reopen_recipe
                .iter()
                .map(|component| &component.entry_id)
                .collect::<Vec<_>>(),
            [&root_identity.entry_id]
        );
        assert_eq!(sub_locator.scan_root.parent_id, None);
        assert_eq!(sub_locator.parent_reopen_recipe[0].parent_id, None);
        assert_eq!(
            sub_locator.entry.parent_id.as_ref(),
            Some(&root_identity.entry_id)
        );
        assert_eq!(
            sub_locator
                .parent_reopen_recipe
                .iter()
                .map(|component| component.native_basename.clone())
                .collect::<Vec<_>>(),
            [test_native_name("root")]
        );
        assert_eq!(sub_locator.entry.entry_id, sub_identity.entry_id);
        assert_eq!(sub_locator.entry.native_basename, test_native_name("sub"));
        let beta = sub.join("beta.txt");
        let beta_entry = result
            .entries
            .iter()
            .find(|entry| entry.display_path == beta.display().to_string())
            .unwrap();
        let beta_identity = beta_entry.identity.as_ref().unwrap();
        let beta_locator = beta_entry.validated_native_locator().unwrap().unwrap();
        assert_eq!(beta_locator.scan_root.entry_id, root_identity.entry_id);
        assert_eq!(
            beta_locator.scan_root_absolute_path.clone().unwrap(),
            NativeAbsolutePath::from_path(&root).unwrap()
        );
        assert_eq!(
            beta_locator
                .parent_reopen_recipe
                .iter()
                .map(|component| &component.entry_id)
                .collect::<Vec<_>>(),
            [&root_identity.entry_id, &sub_identity.entry_id]
        );
        assert_eq!(beta_locator.parent_reopen_recipe[0].parent_id, None);
        assert_eq!(
            beta_locator.parent_reopen_recipe[1].parent_id.as_ref(),
            Some(&root_identity.entry_id)
        );
        assert_eq!(
            beta_locator.entry.parent_id.as_ref(),
            Some(&sub_identity.entry_id)
        );
        assert_eq!(
            beta_locator
                .parent_reopen_recipe
                .iter()
                .map(|component| component.native_basename.clone())
                .collect::<Vec<_>>(),
            [test_native_name("root"), test_native_name("sub")]
        );
        assert_eq!(beta_locator.entry.entry_id, beta_identity.entry_id);
        assert_eq!(
            beta_locator.entry.native_basename,
            test_native_name("beta.txt")
        );
        assert!(
            result
                .boundaries
                .iter()
                .any(|boundary| boundary.kind == BoundaryKind::Symlink)
        );
    }

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    #[test]
    fn cancellation_marks_scan_incomplete() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("child")).unwrap();

        let scanner = linux_scanner(ScannerOptions::default());
        let cancel = CancellationToken::new();
        cancel.cancel();
        let result = scanner
            .scan(&[ScanRoot::new(root.clone()).unwrap()], &cancel)
            .unwrap();

        assert!(
            result
                .progress
                .iter()
                .any(|event| matches!(event, ProgressEvent::Cancelled { .. }))
        );
        let root_aggregate = result.aggregates.first().unwrap();
        let cancelled_identity = root_aggregate.scan_entry_id().unwrap();
        assert!(cancelled_identity.belongs_to(&ScannerOptions::default().scan_id));
        assert_ne!(
            root_aggregate.directory_identity,
            root.display().to_string()
        );
        assert!(!root_aggregate.coverage.complete);
        assert!(result.roots.is_empty());
        assert!(result.entries.is_empty());
    }

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    #[test]
    fn cancelled_scan_does_not_admit_later_roots() {
        let temp = tempfile::TempDir::new().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();

        let result = linux_scanner(ScannerOptions::default())
            .scan(
                &[
                    ScanRoot::new(first.clone()).unwrap(),
                    ScanRoot::new(second.clone()).unwrap(),
                ],
                &cancel,
            )
            .unwrap();

        assert_eq!(result.aggregates.len(), 1);
        assert!(result.roots.is_empty());
        assert!(result.entries.is_empty());
        assert!(
            result
                .progress
                .iter()
                .any(|event| matches!(event, ProgressEvent::Cancelled { path } if path == &first))
        );
        assert!(
            !result
                .progress
                .iter()
                .any(|event| matches!(event, ProgressEvent::Cancelled { path } if path == &second))
        );
    }

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    #[test]
    fn roots_only_scan_admits_roots_without_retaining_children() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("child"), b"payload").unwrap();

        let result = linux_scanner(ScannerOptions::default())
            .scan_roots_only(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        assert_eq!(result.roots.len(), 1);
        assert_eq!(result.roots[0].display_path, root.display().to_string());
        assert!(result.entries.is_empty());
        assert!(result.aggregates.is_empty());
        assert!(result.boundaries.is_empty());
        assert!(matches!(
            result.progress.last(),
            Some(ProgressEvent::Finished)
        ));
    }

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    #[test]
    fn frontier_limit_records_boundary() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        for index in 0..3 {
            fs::create_dir(root.join(format!("dir-{index}"))).unwrap();
        }

        let scanner = linux_scanner(ScannerOptions {
            resource_limits: ScanResourceLimits {
                max_directory_entries: 32,
                max_directory_bytes: 1024 * 1024,
                max_directory_batch_entries: 8,
                max_directory_batch_bytes: 256 * 1024,
                max_frontier_entries: 1,
                max_visited_entries: 32,
                max_retained_aggregates: 32,
                max_retained_entries: 16_384,
                max_retained_boundaries: 16_384,
                max_progress_events: 16_384,
                ..ScanResourceLimits::default()
            },
            ..ScannerOptions::default()
        });
        let result = scanner
            .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
            .unwrap();

        assert!(
            result
                .boundaries
                .iter()
                .any(|boundary| boundary.kind == BoundaryKind::ResourceLimit)
        );
    }

    #[test]
    fn frontier_permits_bound_live_directory_handles_before_inspection() {
        let live_handles = Arc::new(AtomicUsize::new(0));
        let max_live_handles = Arc::new(AtomicUsize::new(0));
        let child_inspections = Arc::new(AtomicUsize::new(0));
        let platform = HandleCountingPlatform::new(
            16,
            Arc::clone(&live_handles),
            Arc::clone(&max_live_handles),
            Arc::clone(&child_inspections),
        );
        let root = platform.root.clone();
        let max_frontier_entries = 3;

        let result = Scanner::new(
            platform,
            ScannerOptions {
                max_workers: 8,
                resource_limits: ScanResourceLimits {
                    max_frontier_entries,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();

        assert!(
            max_live_handles.load(Ordering::SeqCst) <= max_frontier_entries,
            "live directory handle high-water exceeded the frontier permit cap"
        );
        assert_eq!(live_handles.load(Ordering::SeqCst), 0);
        // Deferred siblings are still inspected, while completed children release their
        // handles before the next sibling. A shallow wide tree needs no coverage loss.
        assert_eq!(child_inspections.load(Ordering::SeqCst), 16);
        assert_eq!(
            result
                .boundaries
                .iter()
                .filter(|boundary| boundary.detail == "frontier limit exceeded")
                .count(),
            0
        );
        assert_eq!(result.entries.len(), 16);
        assert!(
            result
                .aggregates
                .iter()
                .all(|aggregate| aggregate.coverage.complete)
        );
    }

    #[test]
    fn root_uses_the_only_frontier_permit_before_any_child_inspection() {
        let live_handles = Arc::new(AtomicUsize::new(0));
        let max_live_handles = Arc::new(AtomicUsize::new(0));
        let child_inspections = Arc::new(AtomicUsize::new(0));
        let platform = HandleCountingPlatform::new(
            4,
            Arc::clone(&live_handles),
            Arc::clone(&max_live_handles),
            Arc::clone(&child_inspections),
        );
        let root = platform.root.clone();

        let result = Scanner::new(
            platform,
            ScannerOptions {
                max_workers: 4,
                resource_limits: ScanResourceLimits {
                    max_frontier_entries: 1,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        )
        .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
        .unwrap();

        assert_eq!(max_live_handles.load(Ordering::SeqCst), 1);
        assert_eq!(live_handles.load(Ordering::SeqCst), 0);
        // Metadata-only inspection classifies every token while denying every
        // child directory before a second retained handle is constructed.
        assert_eq!(child_inspections.load(Ordering::SeqCst), 4);
        assert_eq!(
            result
                .boundaries
                .iter()
                .filter(|boundary| boundary.detail == "frontier limit exceeded")
                .count(),
            4
        );
    }

    #[test]
    fn zero_frontier_limit_fails_before_root_admission() {
        let live_handles = Arc::new(AtomicUsize::new(0));
        let max_live_handles = Arc::new(AtomicUsize::new(0));
        let child_inspections = Arc::new(AtomicUsize::new(0));
        let platform = HandleCountingPlatform::new(
            1,
            Arc::clone(&live_handles),
            Arc::clone(&max_live_handles),
            Arc::clone(&child_inspections),
        );
        let root = platform.root.clone();

        let result = Scanner::new(
            platform,
            ScannerOptions {
                resource_limits: ScanResourceLimits {
                    max_frontier_entries: 0,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        )
        .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new());

        assert!(matches!(
            result,
            Err(ScanError::RootValidation(message))
                if message == "max_frontier_entries must be greater than zero"
        ));
        assert_eq!(live_handles.load(Ordering::SeqCst), 0);
        assert_eq!(max_live_handles.load(Ordering::SeqCst), 0);
        assert_eq!(child_inspections.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn full_frontier_still_observes_files_and_links() {
        let root = test_path("root");
        let directory = root.join("dir");
        let file = root.join("file.bin");
        let link = root.join("link");
        let scanner = Scanner::new(
            FakePlatform::new(
                root.clone(),
                vec![
                    test_entry(&root, "dir"),
                    test_entry(&root, "file.bin"),
                    test_entry(&root, "link"),
                ],
                BTreeMap::from([
                    (
                        directory.clone(),
                        WalkEntry::Directory(sweepx_platform::OpenedDirectory {
                            metadata: test_metadata(
                                directory.clone(),
                                "dir",
                                EntryKind::Directory,
                                Some(1),
                            ),
                            handle: FakeDirectoryHandle {
                                path: directory.clone(),
                                capability_id: 2,
                                cursor: 0,
                            },
                        }),
                    ),
                    (
                        file.clone(),
                        WalkEntry::File(test_metadata(
                            file.clone(),
                            "file.bin",
                            EntryKind::File,
                            Some(1),
                        )),
                    ),
                    (
                        link.clone(),
                        WalkEntry::Link(test_metadata(
                            link.clone(),
                            "link",
                            EntryKind::Symlink,
                            Some(1),
                        )),
                    ),
                ]),
            ),
            ScannerOptions {
                resource_limits: ScanResourceLimits {
                    max_frontier_entries: 1,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        );

        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        assert!(result.entries.iter().any(|entry| {
            entry.display_path == file.display().to_string()
                && entry.object_type == ObjectType::File
        }));
        assert!(result.entries.iter().any(|entry| {
            entry.display_path == link.display().to_string()
                && entry.object_type == ObjectType::Symlink
        }));
        assert!(result.boundaries.iter().any(|boundary| {
            boundary.path == directory
                && boundary.kind == BoundaryKind::ResourceLimit
                && boundary.detail == "frontier limit exceeded"
        }));
        assert!(
            result.boundaries.iter().any(|boundary| {
                boundary.path == link && boundary.kind == BoundaryKind::Symlink
            })
        );
    }

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    #[test]
    fn hardlink_unique_accounting_is_per_subtree() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        let left = root.join("left");
        let right = root.join("right");
        fs::create_dir_all(&left).unwrap();
        fs::create_dir_all(&right).unwrap();

        let original = left.join("shared.txt");
        fs::write(&original, b"1234").unwrap();
        fs::hard_link(&original, right.join("shared.txt")).unwrap();

        let scanner = linux_scanner(ScannerOptions::default());
        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        let root_aggregate = aggregate_for_path(&result, &root);
        let left_aggregate = aggregate_for_path(&result, &left);
        let right_aggregate = aggregate_for_path(&result, &right);

        assert_eq!(root_aggregate.apparent_logical_bytes, known_u128(8));
        assert_eq!(root_aggregate.unique_logical_bytes, known_u128(4));
        assert_eq!(left_aggregate.unique_logical_bytes, known_u128(4));
        assert_eq!(right_aggregate.unique_logical_bytes, known_u128(4));
    }

    #[test]
    fn hardlink_dedup_uses_all_windows_file_id_bits() {
        let root = test_path("root");
        let first = root.join("first.bin");
        let first_hard_link = root.join("first-hard.bin");
        let second = root.join("second.bin");
        let shared_low_bits = 0x0123_4567_89ab_cdef_u128;
        let first_identity = EntryIdentity::from_windows_file_id(9, shared_low_bits.to_le_bytes());
        let second_identity = EntryIdentity::from_windows_file_id(
            9,
            (shared_low_bits | (0xfedc_ba98_7654_3210_u128 << 64)).to_le_bytes(),
        );
        let file_metadata =
            |path: PathBuf, name: &str, identity: EntryIdentity, link_count: u128| {
                let logical_bytes = known_u128(if name == "second.bin" { 7 } else { 5 });
                EntryMetadata {
                    path,
                    file_name: test_native_name(name),
                    kind: EntryKind::File,
                    logical_bytes: logical_bytes.clone(),
                    allocated_bytes: logical_bytes.clone(),
                    hard_link_count: known_count(link_count),
                    fingerprint: sweepx_platform::fingerprint_for(
                        Some(&identity),
                        &EntryKind::File,
                        &logical_bytes,
                    ),
                    filesystem_identity: Some(FilesystemIdentity {
                        device: identity.device(),
                    }),
                    mount_identity: Some(MountIdentity { value: 9 }),
                    hard_link_key: Some(HardLinkKey::from(identity.clone())),
                    identity: Some(identity),
                }
            };
        let scanner = Scanner::new(
            FakePlatform::new(
                root.clone(),
                vec![
                    test_entry(&root, "first.bin"),
                    test_entry(&root, "first-hard.bin"),
                    test_entry(&root, "second.bin"),
                ],
                BTreeMap::from([
                    (
                        first.clone(),
                        WalkEntry::File(file_metadata(
                            first,
                            "first.bin",
                            first_identity.clone(),
                            2,
                        )),
                    ),
                    (
                        first_hard_link.clone(),
                        WalkEntry::File(file_metadata(
                            first_hard_link,
                            "first-hard.bin",
                            first_identity,
                            2,
                        )),
                    ),
                    (
                        second.clone(),
                        WalkEntry::File(file_metadata(
                            second.clone(),
                            "second.bin",
                            second_identity,
                            1,
                        )),
                    ),
                ]),
            ),
            ScannerOptions::default(),
        );

        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        let aggregate = aggregate_for_path(&result, &root);
        assert_eq!(aggregate.apparent_logical_bytes, known_u128(17));
        assert_eq!(aggregate.unique_logical_bytes, known_u128(12));
        let second_entry = result
            .entries
            .iter()
            .find(|entry| entry.display_path == second.display().to_string())
            .unwrap();
        assert_eq!(
            second_entry
                .identity
                .as_ref()
                .unwrap()
                .platform_file_identity,
            IdentityEvidence::known(PlatformFileIdentity {
                device: DecimalU128::new(9),
                inode: DecimalU128::new(shared_low_bits | (0xfedc_ba98_7654_3210_u128 << 64)),
            })
        );
    }

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    #[test]
    fn visited_limit_records_boundary() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("child")).unwrap();
        fs::create_dir(root.join("child").join("nested")).unwrap();

        let scanner = linux_scanner(ScannerOptions {
            resource_limits: ScanResourceLimits {
                max_directory_entries: 32,
                max_directory_bytes: 1024 * 1024,
                max_directory_batch_entries: 8,
                max_directory_batch_bytes: 256 * 1024,
                max_frontier_entries: 32,
                max_visited_entries: 1,
                max_retained_aggregates: 32,
                max_retained_entries: 16_384,
                max_retained_boundaries: 16_384,
                max_progress_events: 16_384,
                ..ScanResourceLimits::default()
            },
            ..ScannerOptions::default()
        });
        let result = scanner
            .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
            .unwrap();

        assert!(
            result
                .boundaries
                .iter()
                .any(|boundary| boundary.kind == BoundaryKind::ResourceLimit)
        );
    }

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    #[test]
    fn retained_entry_cap_truncates_detail_without_making_totals_inexact() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("a.txt"), b"a").unwrap();
        fs::write(root.join("b.txt"), b"b").unwrap();

        let scanner = linux_scanner(ScannerOptions {
            resource_limits: ScanResourceLimits {
                max_directory_entries: 32,
                max_directory_bytes: 1024 * 1024,
                max_directory_batch_entries: 8,
                max_directory_batch_bytes: 256 * 1024,
                max_frontier_entries: 32,
                max_visited_entries: 32,
                max_retained_aggregates: 32,
                max_retained_entries: 1,
                max_retained_boundaries: 4,
                max_progress_events: 8,
                ..ScanResourceLimits::default()
            },
            ..ScannerOptions::default()
        });
        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        // The listing is truncated, and that truncation stays visible.
        assert_eq!(result.entries.len(), 1);
        assert!(result.boundaries.iter().any(|boundary| {
            boundary.kind == BoundaryKind::ResourceLimit
                && boundary.detail == "retained entry cap exceeded"
        }));
        assert!(
            result
                .progress
                .iter()
                .any(|event| matches!(event, ProgressEvent::ResourceLimit { .. }))
        );

        // The totals must survive it. Each entry's bytes are folded into its ancestors before
        // the row reaches the sink, so dropping the row loses detail and nothing else.
        let root_aggregate = aggregate_for_path(&result, &root);
        assert_eq!(root_aggregate.apparent_logical_bytes, known_u128(2));
        assert_eq!(root_aggregate.direct_child_count, known_count(2));
        assert!(
            root_aggregate.coverage.complete,
            "truncating the entry listing must not report the byte totals as a lower bound"
        );
        assert!(
            !root_aggregate
                .coverage
                .incomplete_reasons
                .contains(&ReasonCode::ResourceLimit)
        );
    }

    #[test]
    fn aggregate_preserves_lower_bound_allocated_and_reclaimable() {
        let root = test_path("root");
        let file = root.join("file.bin");
        let scanner = Scanner::new(
            FakePlatform::new(
                root.clone(),
                vec![test_entry(&root, "file.bin")],
                BTreeMap::from([(
                    file.clone(),
                    WalkEntry::File(EntryMetadata {
                        path: file.clone(),
                        file_name: test_native_name("file.bin"),
                        kind: EntryKind::File,
                        logical_bytes: known_u128(7),
                        allocated_bytes: lower_bound_u128(11, ReasonCode::UnknownLayout),
                        hard_link_count: known_count(1),
                        fingerprint: "fp".to_string(),
                        identity: Some(EntryIdentity::from_unix(1, 2)),
                        filesystem_identity: Some(FilesystemIdentity { device: 1 }),
                        mount_identity: Some(MountIdentity { value: 1 }),
                        hard_link_key: Some(HardLinkKey::from_unix(1, 2)),
                    }),
                )]),
            ),
            ScannerOptions::default(),
        );

        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        let aggregate = aggregate_for_path(&result, &root);
        assert_eq!(
            aggregate.filesystem_reported_allocated_bytes,
            lower_bound_u128(11, ReasonCode::UnknownLayout)
        );
        assert_eq!(
            aggregate.potentially_reclaimable_bytes,
            lower_bound_u128(11, ReasonCode::UnknownLayout)
        );
    }

    #[test]
    fn cached_plan_without_current_backend_evidence_is_inspected() {
        struct StalePlan;
        impl SubtreeReuse for StalePlan {
            fn plan_entries(
                &self,
                _: &Path,
                children: &[DirectoryEntryRecord],
            ) -> Option<Vec<PlannedEntry>> {
                Some(
                    children
                        .iter()
                        .map(|child| {
                            PlannedEntry::ReuseFile(sweepx_platform::CachedFileEntry {
                                path: child.path.clone(),
                                file_name: child.file_name.clone(),
                                logical_bytes: 999,
                            })
                        })
                        .collect(),
                )
            }
        }
        let root = test_path("root");
        let file = root.join("file");
        let mut metadata = test_metadata(file.clone(), "file", EntryKind::File, Some(1));
        metadata.logical_bytes = known_u128(7);
        let scanner = Scanner::new(
            FakePlatform::new(
                root.clone(),
                vec![test_entry(&root, "file")],
                BTreeMap::from([(file, WalkEntry::File(metadata))]),
            ),
            ScannerOptions::default(),
        );
        let mut sink = CollectingScanSink::new(ScanResourceLimits::default());
        scanner
            .scan_with_sink(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
                Some(&StalePlan),
                &mut sink,
            )
            .unwrap();
        let result = sink.finish();
        assert_eq!(
            aggregate_for_path(&result, &root).apparent_logical_bytes,
            known_u128(7)
        );
        assert_eq!(result.entries.len(), 1);
    }

    #[cfg(all(target_os = "macos", feature = "platform-macos"))]
    #[test]
    fn cached_plans_cannot_hide_current_directories_links_lengths_or_child_bindings() {
        use std::fs;
        struct StalePlan;
        impl SubtreeReuse for StalePlan {
            fn plan_entries(
                &self,
                dir: &Path,
                children: &[DirectoryEntryRecord],
            ) -> Option<Vec<PlannedEntry>> {
                Some(
                    children
                        .iter()
                        .map(|child| {
                            let path = if child.path.file_name().unwrap() == "misaligned" {
                                dir.join("same")
                            } else {
                                child.path.clone()
                            };
                            PlannedEntry::ReuseFile(sweepx_platform::CachedFileEntry {
                                path,
                                file_name: child.file_name.clone(),
                                logical_bytes: 7,
                            })
                        })
                        .collect(),
                )
            }
        }
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::write(root.join("same"), b"1234567").unwrap();
        fs::write(root.join("misaligned"), b"1234567").unwrap();
        fs::write(root.join("resized"), b"123456789").unwrap();
        fs::create_dir(root.join("directory")).unwrap();
        fs::write(root.join("directory/payload"), b"12345").unwrap();
        std::os::unix::fs::symlink("same", root.join("link")).unwrap();
        fn ordinary_file_total(path: &Path) -> u128 {
            std::fs::read_dir(path)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    let metadata = std::fs::symlink_metadata(entry.path()).unwrap();
                    if metadata.is_dir() {
                        ordinary_file_total(&entry.path())
                    } else if metadata.is_file() {
                        metadata.len() as u128
                    } else {
                        0
                    }
                })
                .sum()
        }
        let expected = ordinary_file_total(&root);
        let scanner = Scanner::new(
            HostPlatformScanner::new(),
            ScannerOptions {
                resource_limits: ScanResourceLimits {
                    max_directory_batch_entries: 2,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        );
        let mut sink = CollectingScanSink::new(ScanResourceLimits::default());
        scanner
            .scan_with_sink(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
                Some(&StalePlan),
                &mut sink,
            )
            .unwrap();
        let result = sink.finish();
        let aggregate = aggregate_for_path(&result, &root);
        assert_eq!(aggregate.apparent_logical_bytes, known_u128(expected));
        assert!(aggregate.coverage.complete);
        let row = |name: &str| {
            result
                .entries
                .iter()
                .find(|entry| entry.display_path == root.join(name).display().to_string())
        };
        // A genuinely confirmed unchanged file uses the shortcut; rejected proposals retain live rows.
        assert!(row("same").is_none());
        assert!(row("misaligned").is_some());
        assert!(row("resized").is_some());
        assert!(row("directory/payload").is_some());
        assert_eq!(row("directory").unwrap().object_type, ObjectType::Directory);
        assert_eq!(row("link").unwrap().object_type, ObjectType::Symlink);
    }

    #[test]
    fn cached_files_keep_markers_and_survive_the_next_generation() {
        struct NoCandidates;
        impl JunkClassifier for NoCandidates {
            fn classify(
                &self,
                _: &ScannedEntry,
                _: &BTreeMap<ScanEntryId, BTreeSet<String>>,
            ) -> Option<String> {
                None
            }
        }
        let mut sink =
            CollectingScanSink::new_classified(ScanResourceLimits::default(), &NoCandidates);
        let parent = ScanEntryId::from_loaded("current-parent".into());
        let root = test_path("root");
        let file = sweepx_platform::CachedFileEntry {
            path: root.join("Cargo.toml"),
            file_name: test_native_name("Cargo.toml"),
            logical_bytes: 123,
        };
        sink.note_cached_file(&parent, &file);
        assert!(sink.file_markers[&parent].contains("Cargo.toml"));
        assert_eq!(
            sink.finish_classified().dir_listings[&root.display().to_string()].files["Cargo.toml"],
            123
        );
    }

    #[cfg(unix)]
    #[test]
    fn ambiguous_display_paths_are_not_file_cache_keys() {
        use std::os::unix::ffi::OsStringExt;
        struct NoCandidates;
        impl JunkClassifier for NoCandidates {
            fn classify(
                &self,
                _: &ScannedEntry,
                _: &BTreeMap<ScanEntryId, BTreeSet<String>>,
            ) -> Option<String> {
                None
            }
        }
        let mut sink =
            CollectingScanSink::new_classified(ScanResourceLimits::default(), &NoCandidates);
        let left = PathBuf::from(std::ffi::OsString::from_vec(b"/root/a\xff".to_vec()));
        let right = PathBuf::from(std::ffi::OsString::from_vec(b"/root/a\xfe".to_vec()));
        assert_ne!(left, right);
        assert_eq!(
            left.display().to_string(),
            right.display().to_string(),
            "independent lossy-path collision"
        );
        let coverage = complete_coverage();
        for (path, parent) in [(left, "left"), (right, "right")] {
            let parent = ScanEntryId::from_loaded(parent.into());
            sink.note_cached_file(
                &parent,
                &sweepx_platform::CachedFileEntry {
                    path: path.join("Cargo.toml"),
                    file_name: test_native_name("Cargo.toml"),
                    logical_bytes: 7,
                },
            );
            sink.note_directory_coverage(&path, &coverage);
            assert!(
                sink.file_markers[&parent].contains("Cargo.toml"),
                "native marker evidence remains available"
            );
        }
        assert!(sink.dir_listings.is_empty());
        assert!(sink.covered_paths.is_empty());
    }

    #[test]
    fn cached_logical_size_never_claims_unique_allocated_or_reclaimable_bytes() {
        let root = test_path("root");
        let child = root.join("nested");
        let mut states = BTreeMap::from([
            (
                root.clone(),
                DirectoryState::new(ScanEntryId::from_loaded("root".into())),
            ),
            (
                child.clone(),
                DirectoryState::new(ScanEntryId::from_loaded("child".into())),
            ),
        ]);
        propagate_cached_file(&mut states, &child.join("sparse-or-linked"), 123);
        for (path, state) in states {
            let aggregate = state.into_aggregate(&ScanId::new("test"));
            assert_eq!(aggregate.apparent_logical_bytes, known_u128(123));
            assert_eq!(aggregate.recursive_entry_count, known_count(1));
            assert_eq!(
                aggregate.direct_child_count,
                known_count(u128::from(path == child))
            );
            assert_eq!(
                aggregate.unique_logical_bytes,
                unknown_u128(ReasonCode::UnknownIdentity)
            );
            assert_eq!(
                aggregate.filesystem_reported_allocated_bytes,
                unknown_u128(ReasonCode::UnknownIdentity)
            );
            assert_eq!(
                aggregate.potentially_reclaimable_bytes,
                unknown_u128(ReasonCode::UnknownIdentity)
            );
        }
    }

    #[test]
    fn aggregate_propagates_unknown_allocated_and_reclaimable_reason() {
        let root = test_path("root");
        let file = root.join("file.bin");
        let scanner = Scanner::new(
            FakePlatform::new(
                root.clone(),
                vec![test_entry(&root, "file.bin")],
                BTreeMap::from([(
                    file.clone(),
                    WalkEntry::File(EntryMetadata {
                        path: file.clone(),
                        file_name: test_native_name("file.bin"),
                        kind: EntryKind::File,
                        logical_bytes: known_u128(7),
                        allocated_bytes: unknown_u128(ReasonCode::UnknownLayout),
                        hard_link_count: known_count(1),
                        fingerprint: "fp".to_string(),
                        identity: Some(EntryIdentity::from_unix(1, 2)),
                        filesystem_identity: Some(FilesystemIdentity { device: 1 }),
                        mount_identity: Some(MountIdentity { value: 1 }),
                        hard_link_key: Some(HardLinkKey::from_unix(1, 2)),
                    }),
                )]),
            ),
            ScannerOptions::default(),
        );

        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        let aggregate = aggregate_for_path(&result, &root);
        assert_eq!(
            aggregate.filesystem_reported_allocated_bytes,
            unknown_u128(ReasonCode::UnknownLayout)
        );
        assert_eq!(
            aggregate.potentially_reclaimable_bytes,
            unknown_u128(ReasonCode::UnknownLayout)
        );
    }

    #[test]
    fn aggregate_overflow_becomes_unknown_instead_of_wrapping() {
        let mut accumulator = EvidenceAccumulator::Known(u128::MAX);
        accumulator.add(&known_u128(1));
        assert_eq!(
            accumulator.into_value(true),
            unknown_u128(ReasonCode::Overflow)
        );

        let mut lower = EvidenceAccumulator::LowerBound {
            value: u128::MAX,
            reason: ReasonCode::UnknownLayout,
        };
        lower.add(&known_u128(1));
        assert_eq!(lower.into_value(true), unknown_u128(ReasonCode::Overflow));
    }

    #[test]
    fn live_identity_uses_typed_metadata_and_aggregate_joins_directory_entry_id() {
        let root = test_path("root");
        let child = root.join("child");
        let scanner = Scanner::new(
            FakePlatform::tree(
                root.clone(),
                BTreeMap::from([
                    (root.clone(), vec![test_entry(&root, "child")]),
                    (child.clone(), Vec::new()),
                ]),
                BTreeMap::from([(
                    child.clone(),
                    WalkEntry::Directory(sweepx_platform::OpenedDirectory {
                        metadata: test_metadata(
                            child.clone(),
                            "child",
                            EntryKind::Directory,
                            Some(7),
                        ),
                        handle: FakeDirectoryHandle {
                            path: child.clone(),
                            capability_id: 2,
                            cursor: 0,
                        },
                    }),
                )]),
            ),
            ScannerOptions {
                scan_id: ScanId::new("identity-test"),
                ..ScannerOptions::default()
            },
        );

        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();
        let root_entry = result.roots.first().unwrap();
        let child_entry = result
            .entries
            .iter()
            .find(|entry| entry.display_path == child.display().to_string())
            .unwrap();
        let root_identity = root_entry.identity.as_ref().unwrap();
        let child_identity = child_entry.identity.as_ref().unwrap();

        assert_eq!(root_identity.entry_id, root_identity.scan_root_id);
        assert_eq!(root_identity.parent_id, None);
        assert_eq!(child_identity.scan_root_id, root_identity.entry_id);
        assert_eq!(
            child_identity.parent_id.as_ref(),
            Some(&root_identity.entry_id)
        );
        assert_eq!(
            child_identity.platform_file_identity,
            IdentityEvidence::known(PlatformFileIdentity {
                device: DecimalU128::new(1),
                inode: DecimalU128::new(2),
            })
        );
        assert_eq!(
            child_identity.filesystem_object_domain_identity,
            IdentityEvidence::known(FilesystemObjectDomainIdentity {
                device: DecimalU128::new(1),
            })
        );
        assert_eq!(
            child_identity.volume_or_mount_identity,
            IdentityEvidence::known(VolumeOrMountIdentity {
                value: DecimalU128::new(7),
            })
        );
        let aggregate = aggregate_for_path(&result, &child);
        assert_eq!(
            aggregate.directory_identity,
            child_identity.entry_id.as_str()
        );
        assert_ne!(aggregate.directory_identity, child.display().to_string());
    }

    #[test]
    fn unknown_platform_identity_stays_explicitly_unknown() {
        let root = test_path("root");
        let child = root.join("file");
        let mut metadata = test_metadata(child.clone(), "file", EntryKind::File, Some(1));
        metadata.identity = None;
        metadata.filesystem_identity = None;
        metadata.mount_identity = None;
        let scanner = Scanner::new(
            FakePlatform::new(
                root.clone(),
                vec![test_entry(&root, "file")],
                BTreeMap::from([(child.clone(), WalkEntry::File(metadata))]),
            ),
            ScannerOptions::default(),
        );

        let result = scanner
            .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
            .unwrap();
        let identity = result.entries[0].identity.as_ref().unwrap();

        assert_eq!(
            identity.platform_file_identity,
            IdentityEvidence::unknown(ReasonCode::UnknownIdentity)
        );
        assert_eq!(
            identity.filesystem_object_domain_identity,
            IdentityEvidence::unknown(ReasonCode::UnknownIdentity)
        );
        assert_eq!(
            identity.volume_or_mount_identity,
            IdentityEvidence::unknown(ReasonCode::UnknownIdentity)
        );
    }

    #[test]
    fn entry_ids_are_unique_across_multiple_roots_and_cancelled_admission() {
        let first = test_path("first");
        let cancelled = test_path("cancelled");
        let third = test_path("third");
        let scanner = Scanner::new(
            MultiRootIdentityPlatform {
                cancelled_root: cancelled.clone(),
                // No root is denied in this test.
                denied_root: test_path("not-denied"),
            },
            ScannerOptions {
                scan_id: ScanId::new("multi-root"),
                ..ScannerOptions::default()
            },
        );

        let result = scanner
            .scan(
                &[
                    ScanRoot::new(first.clone()).unwrap(),
                    ScanRoot::new(cancelled).unwrap(),
                    ScanRoot::new(third.clone()).unwrap(),
                ],
                &CancellationToken::new(),
            )
            .unwrap();
        let entry_ids: BTreeSet<_> = result
            .roots
            .iter()
            .map(|entry| entry.identity.as_ref().unwrap().entry_id.clone())
            .collect();
        let aggregate_ids: BTreeSet<_> = result
            .aggregates
            .iter()
            .map(|aggregate| aggregate.scan_entry_id().unwrap())
            .collect();

        assert_eq!(result.roots.len(), 2);
        assert_eq!(entry_ids.len(), 2);
        assert_eq!(result.aggregates.len(), 3);
        assert_eq!(aggregate_ids.len(), 3);
        assert!(entry_ids.is_subset(&aggregate_ids));
        assert!(
            aggregate_ids
                .iter()
                .all(|identity| identity.belongs_to(&ScanId::new("multi-root")))
        );
        assert!(result.roots.iter().all(|entry| {
            entry.display_path == first.display().to_string()
                || entry.display_path == third.display().to_string()
        }));
    }

    #[test]
    fn access_denied_root_is_skipped_and_remaining_roots_still_scan() {
        let first = test_path("first");
        let denied = test_path("denied");
        let third = test_path("third");
        let scanner = Scanner::new(
            MultiRootIdentityPlatform {
                cancelled_root: test_path("not-cancelled"),
                denied_root: denied.clone(),
            },
            ScannerOptions {
                scan_id: ScanId::new("denied-root"),
                ..ScannerOptions::default()
            },
        );
        let roots = [
            ScanRoot::new(first.clone()).unwrap(),
            ScanRoot::new(denied.clone()).unwrap(),
            ScanRoot::new(third.clone()).unwrap(),
        ];

        // Full walk: the denial must not be fatal, the sibling roots must scan.
        let result = scanner.scan(&roots, &CancellationToken::new()).unwrap();
        assert_eq!(result.roots.len(), 2);
        assert!(result.roots.iter().all(|entry| {
            entry.display_path == first.display().to_string()
                || entry.display_path == third.display().to_string()
        }));
        assert!(result.boundaries.iter().any(|boundary| {
            boundary.path == denied
                && boundary.kind == BoundaryKind::AccessDenied
                && boundary.reason == ReasonCode::StrictReadOnly
        }));
        assert!(result.progress.iter().any(|event| {
            matches!(event, ProgressEvent::Error { path, reason }
                if path == denied.as_path() && reason == &ReasonCode::StrictReadOnly)
        }));
        // The denied root keeps an incomplete, lower-bound aggregate so its totals can never be
        // read as "zero junk"; the two admitted roots stay complete. Its StrictReadOnly reason
        // uniquely identifies it among the three aggregates.
        let denied_aggregate = result
            .aggregates
            .iter()
            .find(|aggregate| {
                aggregate
                    .coverage
                    .incomplete_reasons
                    .contains(&ReasonCode::StrictReadOnly)
            })
            .expect("an incomplete aggregate for the denied root");
        assert!(!denied_aggregate.coverage.complete);
        assert_eq!(
            denied_aggregate.arithmetic_state,
            ArithmeticState::LowerBound
        );
        assert_eq!(result.aggregates.len(), 3);

        // The root-only first frame applies the same skip rather than failing the root set.
        let frame = scanner
            .scan_roots_only(&roots, &CancellationToken::new())
            .unwrap();
        assert_eq!(frame.roots.len(), 2);
        assert!(frame.boundaries.iter().any(|boundary| {
            boundary.path == denied && boundary.kind == BoundaryKind::AccessDenied
        }));
        assert!(frame.progress.iter().any(
            |event| matches!(event, ProgressEvent::Error { path, .. } if path == denied.as_path())
        ));
    }

    #[test]
    fn forged_child_path_is_rejected_before_backend_inspection() {
        let root = test_path("root");
        let outside = test_path("outside/evil");
        let inspect_calls = Arc::new(AtomicUsize::new(0));
        let scanner = Scanner::new(
            FakePlatform::new(
                root.clone(),
                vec![DirectoryEntryRecord {
                    path: outside.clone(),
                    file_name: test_native_name("safe"),
                }],
                BTreeMap::from([(
                    outside.clone(),
                    WalkEntry::File(test_metadata(
                        outside.clone(),
                        "safe",
                        EntryKind::File,
                        Some(1),
                    )),
                )]),
            )
            .with_inspect_calls(inspect_calls.clone()),
            ScannerOptions::default(),
        );

        let error = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            ScanError::Platform(PlatformError::InvalidDirectoryEntry { parent, .. })
                if parent == root
        ));
        assert_eq!(inspect_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn forged_child_name_is_rejected_before_backend_inspection() {
        let root = test_path("root");
        let child_path = root.join("safe");
        let outside = test_path("outside/evil");
        let inspect_calls = Arc::new(AtomicUsize::new(0));
        let scanner = Scanner::new(
            FakePlatform::new(
                root.clone(),
                vec![DirectoryEntryRecord {
                    path: child_path,
                    file_name: test_native_name("../outside/evil"),
                }],
                BTreeMap::from([(
                    outside.clone(),
                    WalkEntry::File(test_metadata(outside, "evil", EntryKind::File, Some(1))),
                )]),
            )
            .with_inspect_calls(inspect_calls.clone()),
            ScannerOptions::default(),
        );

        let error = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            ScanError::Platform(PlatformError::InvalidDirectoryEntry { parent, .. })
                if parent == root
        ));
        assert_eq!(inspect_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn substituted_inspection_metadata_cannot_redirect_accounting() {
        let root = test_path("root");
        let safe = root.join("safe");
        let outside = test_path("outside/evil");
        let scanner = Scanner::new(
            FakePlatform::new(
                root.clone(),
                vec![test_entry(&root, "safe")],
                BTreeMap::from([(
                    safe,
                    WalkEntry::File(test_metadata(outside, "evil", EntryKind::File, Some(1))),
                )]),
            ),
            ScannerOptions::default(),
        );

        let error = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            ScanError::Platform(PlatformError::InvalidDirectoryEntry { parent, .. })
                if parent == root
        ));
    }

    #[test]
    fn retained_child_handle_prevents_ancestor_replacement_redirect() {
        let root = test_path("root");
        let child = root.join("child");
        let safe = child.join("safe");
        let replacement = child.join("evil");
        let platform = FakePlatform::tree(
            root.clone(),
            BTreeMap::from([
                (root.clone(), vec![test_entry(&root, "child")]),
                (child.clone(), vec![test_entry(&child, "safe")]),
            ]),
            BTreeMap::from([
                (
                    child.clone(),
                    WalkEntry::Directory(sweepx_platform::OpenedDirectory {
                        metadata: test_metadata(
                            child.clone(),
                            "child",
                            EntryKind::Directory,
                            Some(1),
                        ),
                        handle: FakeDirectoryHandle {
                            path: child.clone(),
                            capability_id: 2,
                            cursor: 0,
                        },
                    }),
                ),
                (
                    safe.clone(),
                    WalkEntry::File(test_metadata(
                        safe.clone(),
                        "safe",
                        EntryKind::File,
                        Some(1),
                    )),
                ),
                (
                    replacement.clone(),
                    WalkEntry::File(test_metadata(
                        replacement.clone(),
                        "evil",
                        EntryKind::File,
                        Some(1),
                    )),
                ),
            ]),
        );
        let replacement_flag = platform.replace_child_path_after_open.clone();
        replacement_flag.store(true, Ordering::SeqCst);
        let scanner = Scanner::new(platform, ScannerOptions::default());

        let result = scanner
            .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
            .unwrap();

        let paths: Vec<_> = result
            .entries
            .iter()
            .map(|entry| entry.display_path.as_str())
            .collect();
        assert!(paths.contains(&child.to_str().unwrap()));
        assert!(paths.contains(&safe.to_str().unwrap()));
        assert!(!paths.contains(&replacement.to_str().unwrap()));
    }

    #[test]
    fn unknown_mount_identity_fails_closed_even_if_backend_claims_same_mount() {
        let root = test_path("root");
        let child = root.join("child");
        let nested = child.join("safe");
        let scanner = Scanner::new(
            FakePlatform::tree(
                root.clone(),
                BTreeMap::from([
                    (root.clone(), vec![test_entry(&root, "child")]),
                    (child.clone(), vec![test_entry(&child, "safe")]),
                ]),
                BTreeMap::from([(
                    child.clone(),
                    WalkEntry::Directory(sweepx_platform::OpenedDirectory {
                        metadata: test_metadata(child.clone(), "child", EntryKind::Directory, None),
                        handle: FakeDirectoryHandle {
                            path: child.clone(),
                            capability_id: 2,
                            cursor: 0,
                        },
                    }),
                )]),
            ),
            ScannerOptions::default(),
        );

        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        assert!(result.entries.is_empty());
        assert!(result.boundaries.iter().any(|boundary| {
            boundary.path == child
                && boundary.kind == BoundaryKind::Mount
                && boundary.reason == ReasonCode::UnknownIdentity
        }));
        assert!(
            !result
                .entries
                .iter()
                .any(|entry| entry.display_path == nested.display().to_string())
        );
        let aggregate = aggregate_for_path(&result, &root);
        assert!(!aggregate.coverage.complete);
        assert!(
            aggregate
                .coverage
                .incomplete_reasons
                .contains(&ReasonCode::UnknownIdentity)
        );
    }

    #[test]
    fn fake_resource_limit_keeps_aggregate_incomplete() {
        let root = test_path("root");
        let scanner = Scanner::new(
            FakePlatform::new(root.clone(), Vec::new(), BTreeMap::new()).with_enumeration_failure(
                PlatformError::ResourceLimit("adversarial byte budget".to_string()),
            ),
            ScannerOptions::default(),
        );

        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();
        let aggregate = aggregate_for_path(&result, &root);

        assert!(!aggregate.coverage.complete);
        assert!(
            aggregate
                .coverage
                .incomplete_reasons
                .contains(&ReasonCode::ResourceLimit)
        );
    }

    #[test]
    fn enumeration_io_error_does_not_duplicate_directory_identity() {
        let root = test_path("root");
        let scanner = Scanner::new(
            FakePlatform::new(root.clone(), Vec::new(), BTreeMap::new()).with_enumeration_failure(
                PlatformError::Io {
                    path: root.clone(),
                    detail: "injected enumeration failure".to_string(),
                    io_kind: Some(std::io::ErrorKind::PermissionDenied),
                },
            ),
            ScannerOptions::default(),
        );

        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        assert_eq!(result.roots.len(), 1);
        assert!(result.entries.is_empty());
        assert_eq!(
            result
                .roots
                .iter()
                .chain(result.entries.iter())
                .filter_map(|entry| entry.identity.as_ref())
                .map(|identity| identity.entry_id.clone())
                .collect::<BTreeSet<_>>()
                .len(),
            1
        );
        assert!(result.progress.iter().any(|event| matches!(
            event,
            ProgressEvent::Error { path, reason }
                if path == &root && reason == &ReasonCode::IncompleteStreamCoverage
        )));
        let aggregate = aggregate_for_path(&result, &root);
        assert!(!aggregate.coverage.complete);
        assert!(
            aggregate
                .coverage
                .incomplete_reasons
                .contains(&ReasonCode::IncompleteStreamCoverage)
        );
    }

    #[test]
    fn cancellation_during_fake_inspection_keeps_aggregate_incomplete() {
        let root = test_path("root");
        let scanner = Scanner::new(
            FakePlatform::new(
                root.clone(),
                vec![test_entry(&root, "safe")],
                BTreeMap::new(),
            )
            .with_cancel_on_inspect(),
            ScannerOptions::default(),
        );

        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();
        let aggregate = aggregate_for_path(&result, &root);

        assert!(!aggregate.coverage.complete);
        assert!(
            aggregate
                .coverage
                .incomplete_reasons
                .contains(&ReasonCode::IncompleteStreamCoverage)
        );
        assert!(result.progress.iter().any(
            |event| matches!(event, ProgressEvent::Cancelled { path } if path == &root.join("safe"))
        ));
    }

    #[test]
    fn scanner_consumes_bounded_batches_until_end_of_directory() {
        let root = test_path("root");
        let paths: Vec<_> = ["one", "two", "three"]
            .into_iter()
            .map(|name| root.join(name))
            .collect();
        let entries = ["one", "two", "three"]
            .into_iter()
            .map(|name| test_entry(&root, name))
            .collect();
        let walk_entries = ["one", "two", "three"]
            .into_iter()
            .map(|name| {
                let path = root.join(name);
                (
                    path.clone(),
                    WalkEntry::File(test_metadata(path, name, EntryKind::File, Some(1))),
                )
            })
            .collect();
        let scanner = Scanner::new(
            FakePlatform::new(root.clone(), entries, walk_entries).with_batch_size(1),
            ScannerOptions::default(),
        );

        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        assert_eq!(result.entries.len(), 3);
        for path in paths {
            assert!(
                result
                    .entries
                    .iter()
                    .any(|entry| entry.display_path == path.display().to_string())
            );
        }
        let aggregate = aggregate_for_path(&result, &root);
        assert_eq!(aggregate.direct_child_count, known_count(3));
        assert!(aggregate.coverage.complete);
    }

    #[test]
    fn retained_aggregate_cap_blocks_new_subtrees_and_marks_root_incomplete() {
        let root = test_path("root");
        let first = root.join("first");
        let second = root.join("second");
        let nested = first.join("nested");
        let scanner = Scanner::new(
            FakePlatform::tree(
                root.clone(),
                BTreeMap::from([
                    (
                        root.clone(),
                        vec![test_entry(&root, "first"), test_entry(&root, "second")],
                    ),
                    (first.clone(), vec![test_entry(&first, "nested")]),
                ]),
                BTreeMap::from([
                    (
                        first.clone(),
                        WalkEntry::Directory(sweepx_platform::OpenedDirectory {
                            metadata: test_metadata(
                                first.clone(),
                                "first",
                                EntryKind::Directory,
                                Some(1),
                            ),
                            handle: FakeDirectoryHandle {
                                path: first.clone(),
                                capability_id: 2,
                                cursor: 0,
                            },
                        }),
                    ),
                    (
                        second.clone(),
                        WalkEntry::Directory(sweepx_platform::OpenedDirectory {
                            metadata: test_metadata(
                                second.clone(),
                                "second",
                                EntryKind::Directory,
                                Some(1),
                            ),
                            handle: FakeDirectoryHandle {
                                path: second.clone(),
                                capability_id: 3,
                                cursor: 0,
                            },
                        }),
                    ),
                    (
                        nested.clone(),
                        WalkEntry::File(test_metadata(
                            nested.clone(),
                            "nested",
                            EntryKind::File,
                            Some(1),
                        )),
                    ),
                ]),
            ),
            ScannerOptions {
                resource_limits: ScanResourceLimits {
                    max_retained_aggregates: 2,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        );

        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        assert!(result.aggregates.len() <= 2);
        assert!(result.boundaries.iter().any(|boundary| {
            boundary.path == second
                && boundary.kind == BoundaryKind::ResourceLimit
                && boundary.detail == "retained aggregate limit exceeded"
        }));
        let root_aggregate = aggregate_for_path(&result, &root);
        assert!(!root_aggregate.coverage.complete);
        assert!(
            root_aggregate
                .coverage
                .incomplete_reasons
                .contains(&ReasonCode::ResourceLimit)
        );
    }

    #[test]
    fn cumulative_directory_cap_stops_continuation_and_marks_incomplete() {
        let root = test_path("root");
        let entries: Vec<_> = ["one", "two", "three"]
            .into_iter()
            .map(|name| test_entry(&root, name))
            .collect();
        let walk_entries = ["one", "two", "three"]
            .into_iter()
            .map(|name| {
                let path = root.join(name);
                (
                    path.clone(),
                    WalkEntry::File(test_metadata(path, name, EntryKind::File, Some(1))),
                )
            })
            .collect();
        let scanner = Scanner::new(
            FakePlatform::new(root.clone(), entries, walk_entries).with_batch_size(1),
            ScannerOptions {
                resource_limits: ScanResourceLimits {
                    max_directory_entries: 2,
                    max_directory_batch_entries: 1,
                    ..ScanResourceLimits::default()
                },
                ..ScannerOptions::default()
            },
        );

        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        assert_eq!(result.entries.len(), 2);
        assert!(result.boundaries.iter().any(|boundary| {
            boundary.path == root
                && boundary.kind == BoundaryKind::ResourceLimit
                && boundary.detail == "per-directory cumulative enumeration limit exceeded"
        }));
        let aggregate = aggregate_for_path(&result, &root);
        assert!(!aggregate.coverage.complete);
        assert!(
            aggregate
                .coverage
                .incomplete_reasons
                .contains(&ReasonCode::ResourceLimit)
        );
    }

    #[test]
    fn collecting_sink_caps_aggregates_across_multiple_roots() {
        let limits = ScanResourceLimits {
            max_retained_aggregates: 1,
            ..ScanResourceLimits::default()
        };
        let mut sink = CollectingScanSink::new(limits);
        let scan_id = ScanId::new("scan");
        let first = DirectoryState::new(ScanEntryId::for_scan_ordinal(&scan_id, 1).unwrap())
            .into_aggregate(&scan_id);
        let second = DirectoryState::new(ScanEntryId::for_scan_ordinal(&scan_id, 2).unwrap())
            .into_aggregate(&scan_id);

        sink.push_aggregate(test_path("first").as_path(), first)
            .unwrap();
        sink.push_aggregate(test_path("second").as_path(), second)
            .unwrap();
        let summary = sink.finish();

        assert_eq!(summary.aggregates.len(), 1);
        assert!(summary.boundaries.iter().any(|boundary| {
            boundary.path == test_path("second").as_path()
                && boundary.kind == BoundaryKind::ResourceLimit
                && boundary.detail == "retained aggregate cap exceeded across scan roots"
        }));
        assert!(summary.progress.iter().any(|event| {
            matches!(event, ProgressEvent::ResourceLimit { path } if path == test_path("second").as_path())
        }));
    }

    #[derive(Debug)]
    struct MultiRootIdentityPlatform {
        cancelled_root: PathBuf,
        denied_root: PathBuf,
    }

    impl PlatformScanner for MultiRootIdentityPlatform {
        type DirectoryHandle = FakeDirectoryHandle;

        fn platform_name(&self) -> &'static str {
            "multi-root-fake"
        }

        fn admit_root(
            &self,
            root: &ScanRoot,
            _cancel: &CancellationToken,
        ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
            if root.path == self.cancelled_root {
                return Err(PlatformError::Cancelled);
            }
            if root.path == self.denied_root {
                // A TCC-style refusal: an existing root the host will not open. The retained
                // PermissionDenied kind is what marks it as skippable rather than a fatal I/O
                // fault.
                return Err(PlatformError::io(
                    root.path.clone(),
                    std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "Operation not permitted",
                    ),
                ));
            }
            let root_locator = root
                .native_absolute_path()
                .map_err(|error| PlatformError::RootRejected(error.to_string()))?;
            Ok(RootAdmission::new(
                root.clone(),
                test_metadata(
                    root.path.clone(),
                    root.path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("root"),
                    EntryKind::Directory,
                    Some(1),
                ),
                FakeDirectoryHandle {
                    path: root.path.clone(),
                    capability_id: 1,
                    cursor: 0,
                },
                root_locator,
            ))
        }

        fn enumerate_children(
            &self,
            _directory: &mut Self::DirectoryHandle,
            _cancel: &CancellationToken,
            _limits: DirectoryReadLimits,
        ) -> Result<DirectoryEntryBatch, PlatformError> {
            Ok(DirectoryEntryBatch::complete(Vec::new()))
        }

        fn inspect_child(
            &self,
            _parent: &Self::DirectoryHandle,
            _child: &DirectoryEntryRecord,
            _cancel: &CancellationToken,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            unreachable!("empty roots have no children")
        }

        fn inspect_child_with_directory_admission(
            &self,
            _parent: &Self::DirectoryHandle,
            _child: &DirectoryEntryRecord,
            _cancel: &CancellationToken,
            _directory_admission: DirectoryHandleAdmission,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            unreachable!("empty roots have no children")
        }

        fn is_same_mount(
            &self,
            _root: &EntryMetadata,
            _entry: &EntryMetadata,
        ) -> Result<bool, PlatformError> {
            Ok(true)
        }
    }

    #[derive(Debug)]
    struct FakePlatform {
        root_metadata: EntryMetadata,
        entries_by_capability: BTreeMap<u64, Vec<DirectoryEntryRecord>>,
        walk_entries: BTreeMap<PathBuf, WalkEntry<FakeDirectoryHandle>>,
        inspect_calls: Arc<AtomicUsize>,
        enumeration_failure: Option<FakeEnumerationFailure>,
        cancel_on_inspect: bool,
        replace_child_path_after_open: Arc<AtomicBool>,
        batch_size: Option<usize>,
        file_length_proposals: Option<BTreeMap<PathBuf, sweepx_platform::CachedFileEntry>>,
        file_length_calls: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    enum FakeEnumerationFailure {
        ResourceLimit(String),
        Io {
            path: PathBuf,
            detail: String,
            io_kind: Option<std::io::ErrorKind>,
        },
    }

    #[derive(Debug)]
    struct FakeDirectoryHandle {
        path: PathBuf,
        capability_id: u64,
        cursor: usize,
    }

    #[derive(Debug)]
    struct CountingDirectoryHandle {
        path: PathBuf,
        capability_id: u64,
        cursor: usize,
        live_handles: Arc<AtomicUsize>,
    }

    impl CountingDirectoryHandle {
        fn new(
            path: PathBuf,
            capability_id: u64,
            live_handles: Arc<AtomicUsize>,
            max_live_handles: &AtomicUsize,
        ) -> Self {
            let live = live_handles.fetch_add(1, Ordering::SeqCst) + 1;
            max_live_handles.fetch_max(live, Ordering::SeqCst);
            Self {
                path,
                capability_id,
                cursor: 0,
                live_handles,
            }
        }
    }

    impl Drop for CountingDirectoryHandle {
        fn drop(&mut self) {
            self.live_handles.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    /// A two-level wide tree: `root/dir-NNN/leaf/payload.bin`.
    ///
    /// Models the shape that defeated breadth-first permit allocation -- a very wide level
    /// with content *below* it, so shedding children at the wide level silently loses real
    /// bytes rather than just directory rows.
    struct NestedFanOutPlatform {
        root: PathBuf,
        fan_out: usize,
    }

    /// Distinguishes the three directory roles without consulting a display path.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FanOutRole {
        Root,
        Branch,
        Leaf,
    }

    /// Handle for [`NestedFanOutPlatform`], carrying its own role and identity.
    ///
    /// The branch index travels in the handle rather than being re-parsed from the path:
    /// only the branch level is named `dir-NNN`, so deriving it from a leaf's own path would
    /// fail. Carrying it also mirrors the real contract, where a display path is never the
    /// source of traversal state.
    #[derive(Debug)]
    struct FanOutHandle {
        path: PathBuf,
        role: FanOutRole,
        branch_index: u64,
        cursor: usize,
    }

    impl NestedFanOutPlatform {
        /// Bytes in each leaf's single file; distinct per leaf would obscure the total.
        const FILE_BYTES: u128 = 1024;

        fn new(fan_out: usize) -> Self {
            Self {
                root: test_path("fan-out-root"),
                fan_out,
            }
        }

        fn directory_metadata(&self, path: PathBuf, inode: u64) -> EntryMetadata {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("fan-out-root")
                .to_string();
            let mut metadata = test_metadata(path, &name, EntryKind::Directory, Some(1));
            metadata.identity = Some(EntryIdentity::from_unix(1, inode));
            metadata
        }

        fn file_metadata(&self, path: PathBuf, inode: u64) -> EntryMetadata {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("payload.bin")
                .to_string();
            let mut metadata = test_metadata(path, &name, EntryKind::File, Some(1));
            let identity = EntryIdentity::from_unix(1, inode);
            metadata.logical_bytes = known_u128(Self::FILE_BYTES);
            metadata.allocated_bytes = known_u128(Self::FILE_BYTES);
            metadata.hard_link_key = Some(HardLinkKey::from(identity.clone()));
            metadata.identity = Some(identity);
            metadata
        }

        /// Parses a branch directory's index from its own generated name.
        ///
        /// Only valid for a `dir-NNN` path; every other level receives its index through
        /// [`FanOutHandle::branch_index`].
        fn branch_index(path: &Path) -> u64 {
            path.file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("dir-"))
                .and_then(|index| index.parse::<u64>().ok())
                .expect("generated fan-out branch name")
        }
    }

    impl PlatformScanner for NestedFanOutPlatform {
        type DirectoryHandle = FanOutHandle;

        fn platform_name(&self) -> &'static str {
            "nested-fan-out-fake"
        }

        fn admit_root(
            &self,
            root: &ScanRoot,
            cancel: &CancellationToken,
        ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            Ok(RootAdmission::new(
                root.clone(),
                self.directory_metadata(self.root.clone(), 1),
                FanOutHandle {
                    path: self.root.clone(),
                    role: FanOutRole::Root,
                    branch_index: 0,
                    cursor: 0,
                },
                root.native_absolute_path()
                    .map_err(|error| PlatformError::RootRejected(error.to_string()))?,
            ))
        }

        fn enumerate_children(
            &self,
            directory: &mut Self::DirectoryHandle,
            cancel: &CancellationToken,
            _limits: DirectoryReadLimits,
        ) -> Result<DirectoryEntryBatch, PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            if directory.cursor > 0 {
                return Ok(DirectoryEntryBatch::complete(Vec::new()));
            }
            directory.cursor = 1;
            let entries = match directory.role {
                FanOutRole::Root => (0..self.fan_out)
                    .map(|index| test_entry(&directory.path, &format!("dir-{index:03}")))
                    .collect(),
                FanOutRole::Branch => vec![test_entry(&directory.path, "leaf")],
                FanOutRole::Leaf => vec![test_entry(&directory.path, "payload.bin")],
            };
            Ok(DirectoryEntryBatch::complete(entries))
        }

        fn inspect_child(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            self.inspect_child_with_directory_admission(
                parent,
                child,
                cancel,
                DirectoryHandleAdmission::Allow,
            )
        }

        fn inspect_child_with_directory_admission(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
            directory_admission: DirectoryHandleAdmission,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            child.validate_for_parent(&parent.path).map_err(|error| {
                PlatformError::InvalidDirectoryEntry {
                    parent: parent.path.clone(),
                    detail: error.to_string(),
                }
            })?;

            // Files terminate the tree, so no permit is involved. Distinct identities matter:
            // hard-link dedup keys off file identity, so reusing one inode across leaves
            // would silently collapse `unique_logical_bytes` and hide a real regression.
            if parent.role == FanOutRole::Leaf {
                // Offset keeps file inodes disjoint from directory inodes.
                let inode = 1_000_000 + parent.branch_index;
                return Ok(WalkEntry::File(
                    self.file_metadata(child.path.clone(), inode),
                ));
            }

            // Report the same boundary the real backends report, so a regression shows up as
            // the exact evidence the traversal fix is supposed to eliminate.
            if directory_admission == DirectoryHandleAdmission::Deny {
                return Ok(WalkEntry::Boundary(BoundaryRecord {
                    path: child.path.clone(),
                    kind: BoundaryKind::ResourceLimit,
                    reason: ReasonCode::ResourceLimit,
                    detail: "frontier limit exceeded".to_string(),
                }));
            }

            let (role, branch_index, inode) = match parent.role {
                FanOutRole::Root => {
                    let index = Self::branch_index(&child.path);
                    (FanOutRole::Branch, index, 100 + index)
                }
                FanOutRole::Branch => (
                    FanOutRole::Leaf,
                    parent.branch_index,
                    100_000 + parent.branch_index,
                ),
                FanOutRole::Leaf => unreachable!("leaf children are handled above"),
            };
            Ok(WalkEntry::Directory(sweepx_platform::OpenedDirectory {
                metadata: self.directory_metadata(child.path.clone(), inode),
                handle: FanOutHandle {
                    path: child.path.clone(),
                    role,
                    branch_index,
                    cursor: 0,
                },
            }))
        }

        fn is_same_mount(
            &self,
            _root: &EntryMetadata,
            _entry: &EntryMetadata,
        ) -> Result<bool, PlatformError> {
            Ok(true)
        }
    }

    struct HandleCountingPlatform {
        root: PathBuf,
        child_count: usize,
        live_handles: Arc<AtomicUsize>,
        max_live_handles: Arc<AtomicUsize>,
        child_inspections: Arc<AtomicUsize>,
    }

    impl HandleCountingPlatform {
        fn new(
            child_count: usize,
            live_handles: Arc<AtomicUsize>,
            max_live_handles: Arc<AtomicUsize>,
            child_inspections: Arc<AtomicUsize>,
        ) -> Self {
            Self {
                root: test_path("handle-root"),
                child_count,
                live_handles,
                max_live_handles,
                child_inspections,
            }
        }

        fn metadata(&self, path: PathBuf, inode: u64) -> EntryMetadata {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("handle-root")
                .to_string();
            let mut metadata = test_metadata(path, &name, EntryKind::Directory, Some(1));
            metadata.identity = Some(EntryIdentity::from_unix(1, inode));
            metadata
        }
    }

    impl PlatformScanner for HandleCountingPlatform {
        type DirectoryHandle = CountingDirectoryHandle;

        fn platform_name(&self) -> &'static str {
            "handle-counting-fake"
        }

        fn admit_root(
            &self,
            root: &ScanRoot,
            cancel: &CancellationToken,
        ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            Ok(RootAdmission::new(
                root.clone(),
                self.metadata(self.root.clone(), 1),
                CountingDirectoryHandle::new(
                    self.root.clone(),
                    1,
                    Arc::clone(&self.live_handles),
                    &self.max_live_handles,
                ),
                root.native_absolute_path()
                    .map_err(|error| PlatformError::RootRejected(error.to_string()))?,
            ))
        }

        fn enumerate_children(
            &self,
            directory: &mut Self::DirectoryHandle,
            _cancel: &CancellationToken,
            _limits: DirectoryReadLimits,
        ) -> Result<DirectoryEntryBatch, PlatformError> {
            if directory.cursor > 0 || directory.capability_id != 1 {
                return Ok(DirectoryEntryBatch::complete(Vec::new()));
            }
            directory.cursor = 1;
            Ok(DirectoryEntryBatch::complete(
                (0..self.child_count)
                    .map(|index| test_entry(&self.root, &format!("dir-{index:03}")))
                    .collect(),
            ))
        }

        fn inspect_child(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            _cancel: &CancellationToken,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            self.inspect_child_with_directory_admission(
                parent,
                child,
                _cancel,
                DirectoryHandleAdmission::Allow,
            )
        }

        fn inspect_child_with_directory_admission(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            _cancel: &CancellationToken,
            directory_admission: DirectoryHandleAdmission,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            self.child_inspections.fetch_add(1, Ordering::SeqCst);
            child.validate_for_parent(&parent.path).map_err(|error| {
                PlatformError::InvalidDirectoryEntry {
                    parent: parent.path.clone(),
                    detail: error.to_string(),
                }
            })?;
            let capability_id = child
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("dir-"))
                .and_then(|index| index.parse::<u64>().ok())
                .expect("generated handle-counting directory name")
                + 2;
            if directory_admission == DirectoryHandleAdmission::Deny {
                return Ok(WalkEntry::Boundary(BoundaryRecord {
                    path: child.path.clone(),
                    kind: BoundaryKind::ResourceLimit,
                    reason: ReasonCode::ResourceLimit,
                    detail: "frontier limit exceeded".to_string(),
                }));
            }
            Ok(WalkEntry::Directory(sweepx_platform::OpenedDirectory {
                metadata: self.metadata(child.path.clone(), capability_id),
                handle: CountingDirectoryHandle::new(
                    child.path.clone(),
                    capability_id,
                    Arc::clone(&self.live_handles),
                    &self.max_live_handles,
                ),
            }))
        }

        fn is_same_mount(
            &self,
            _root: &EntryMetadata,
            _entry: &EntryMetadata,
        ) -> Result<bool, PlatformError> {
            Ok(true)
        }
    }

    #[derive(Debug)]
    struct SchedulerProbe {
        target_active: usize,
        active: AtomicUsize,
        max_active: AtomicUsize,
        same_handle_overlap: AtomicBool,
        state: Mutex<SchedulerProbeState>,
        wake: Condvar,
    }

    #[derive(Debug, Default)]
    struct SchedulerProbeState {
        released: bool,
        active_handles: BTreeMap<u64, usize>,
        started_paths: Vec<PathBuf>,
        completion_order: Vec<PathBuf>,
        slow_path: Option<PathBuf>,
        fast_path: Option<PathBuf>,
        fast_finished: bool,
        cancel_path: Option<PathBuf>,
    }

    impl SchedulerProbe {
        fn new(target_active: usize) -> Self {
            Self {
                target_active,
                active: AtomicUsize::new(0),
                max_active: AtomicUsize::new(0),
                same_handle_overlap: AtomicBool::new(false),
                state: Mutex::new(SchedulerProbeState {
                    released: target_active == 0,
                    ..SchedulerProbeState::default()
                }),
                wake: Condvar::new(),
            }
        }

        fn with_out_of_order(mut self, slow_path: PathBuf, fast_path: PathBuf) -> Self {
            let state = self.state.get_mut().unwrap();
            state.slow_path = Some(slow_path);
            state.fast_path = Some(fast_path);
            self
        }

        fn set_cancel_path(&self, path: PathBuf) {
            self.state.lock().unwrap().cancel_path = Some(path);
        }

        fn started_paths(&self) -> Vec<PathBuf> {
            self.state.lock().unwrap().started_paths.clone()
        }

        fn completion_order(&self) -> Vec<PathBuf> {
            self.state.lock().unwrap().completion_order.clone()
        }

        fn begin(&self, handle_id: u64, path: &Path, cancel: &CancellationToken) -> bool {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut state = self.state.lock().unwrap();
            let handle_active = state.active_handles.entry(handle_id).or_default();
            *handle_active += 1;
            if *handle_active > 1 {
                self.same_handle_overlap.store(true, Ordering::SeqCst);
            }
            state.started_paths.push(path.to_path_buf());
            if state.cancel_path.as_deref() == Some(path) {
                cancel.cancel();
                return true;
            }
            if self.target_active > 0 && active >= self.target_active {
                state.released = true;
                self.wake.notify_all();
            }
            while !state.released {
                let now = std::time::Instant::now();
                assert!(
                    now < deadline,
                    "scheduler did not reach expected concurrency"
                );
                let remaining = deadline.saturating_duration_since(now);
                (state, _) = self.wake.wait_timeout(state, remaining).unwrap();
            }
            while state.slow_path.as_deref() == Some(path) && !state.fast_finished {
                let now = std::time::Instant::now();
                assert!(now < deadline, "faster ticket never completed");
                let remaining = deadline.saturating_duration_since(now);
                (state, _) = self.wake.wait_timeout(state, remaining).unwrap();
            }
            false
        }

        fn finish(&self, handle_id: u64, path: &Path) {
            let mut state = self.state.lock().unwrap();
            let handle_active = state
                .active_handles
                .get_mut(&handle_id)
                .expect("started handle is tracked");
            *handle_active -= 1;
            state.completion_order.push(path.to_path_buf());
            if state.fast_path.as_deref() == Some(path) {
                state.fast_finished = true;
                self.wake.notify_all();
            }
            drop(state);
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct SchedulingPlatform {
        root: PathBuf,
        child_count: usize,
        probe: Arc<SchedulerProbe>,
        panic_path: Option<PathBuf>,
    }

    impl SchedulingPlatform {
        fn new(child_count: usize, probe: Arc<SchedulerProbe>) -> Self {
            Self {
                root: test_path("scheduler-root"),
                child_count,
                probe,
                panic_path: None,
            }
        }

        fn with_panic_path(mut self, path: PathBuf) -> Self {
            self.panic_path = Some(path);
            self
        }

        fn metadata(&self, path: PathBuf, kind: EntryKind, inode: u64) -> EntryMetadata {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("scheduler-root")
                .to_string();
            let mut metadata = test_metadata(path, &name, kind, Some(1));
            metadata.identity = Some(EntryIdentity::from_unix(1, inode));
            metadata
        }
    }

    impl PlatformScanner for SchedulingPlatform {
        type DirectoryHandle = FakeDirectoryHandle;

        fn platform_name(&self) -> &'static str {
            "scheduling-fake"
        }

        fn admit_root(
            &self,
            root: &ScanRoot,
            cancel: &CancellationToken,
        ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            Ok(RootAdmission::new(
                root.clone(),
                self.metadata(self.root.clone(), EntryKind::Directory, 1),
                FakeDirectoryHandle {
                    path: self.root.clone(),
                    capability_id: 1,
                    cursor: 0,
                },
                root.native_absolute_path()
                    .map_err(|error| PlatformError::RootRejected(error.to_string()))?,
            ))
        }

        fn enumerate_children(
            &self,
            directory: &mut Self::DirectoryHandle,
            cancel: &CancellationToken,
            _limits: DirectoryReadLimits,
        ) -> Result<DirectoryEntryBatch, PlatformError> {
            if self.panic_path.as_deref() == Some(&directory.path) {
                panic!("injected platform scanner panic");
            }
            if directory.cursor > 0 {
                return Ok(DirectoryEntryBatch::complete(Vec::new()));
            }
            directory.cursor = 1;
            if directory.capability_id == 1 {
                return Ok(DirectoryEntryBatch::complete(
                    (0..self.child_count)
                        .map(|index| test_entry(&self.root, &format!("dir-{index:03}")))
                        .collect(),
                ));
            }

            if self
                .probe
                .begin(directory.capability_id, &directory.path, cancel)
            {
                self.probe.finish(directory.capability_id, &directory.path);
                return Err(PlatformError::Cancelled);
            }
            let entry = test_entry(&directory.path, "leaf");
            self.probe.finish(directory.capability_id, &directory.path);
            // Force a continuation ticket so the probe also verifies that one retained handle is
            // never enumerated concurrently with itself.
            Ok(DirectoryEntryBatch::continued(vec![entry]))
        }

        fn inspect_child(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            self.inspect_child_with_directory_admission(
                parent,
                child,
                cancel,
                DirectoryHandleAdmission::Allow,
            )
        }

        fn inspect_child_with_directory_admission(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
            directory_admission: DirectoryHandleAdmission,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            child.validate_for_parent(&parent.path).map_err(|error| {
                PlatformError::InvalidDirectoryEntry {
                    parent: parent.path.clone(),
                    detail: error.to_string(),
                }
            })?;
            if parent.capability_id == 1 {
                let index = child
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_prefix("dir-"))
                    .and_then(|index| index.parse::<u64>().ok())
                    .expect("generated scheduler directory name");
                let capability_id = index + 2;
                if directory_admission == DirectoryHandleAdmission::Deny {
                    return Ok(WalkEntry::Boundary(BoundaryRecord {
                        path: child.path.clone(),
                        kind: BoundaryKind::ResourceLimit,
                        reason: ReasonCode::ResourceLimit,
                        detail: "frontier limit exceeded".to_string(),
                    }));
                }
                Ok(WalkEntry::Directory(sweepx_platform::OpenedDirectory {
                    metadata: self.metadata(
                        child.path.clone(),
                        EntryKind::Directory,
                        capability_id,
                    ),
                    handle: FakeDirectoryHandle {
                        path: child.path.clone(),
                        capability_id,
                        cursor: 0,
                    },
                }))
            } else {
                Ok(WalkEntry::File(self.metadata(
                    child.path.clone(),
                    EntryKind::File,
                    10_000 + parent.capability_id,
                )))
            }
        }

        fn is_same_mount(
            &self,
            _root: &EntryMetadata,
            _entry: &EntryMetadata,
        ) -> Result<bool, PlatformError> {
            Ok(true)
        }
    }

    impl FakePlatform {
        fn new(
            root: PathBuf,
            entries: Vec<DirectoryEntryRecord>,
            walk_entries: BTreeMap<PathBuf, WalkEntry<FakeDirectoryHandle>>,
        ) -> Self {
            Self {
                root_metadata: EntryMetadata {
                    path: root.clone(),
                    file_name: test_native_name("root"),
                    kind: EntryKind::Directory,
                    logical_bytes: known_u128(0),
                    allocated_bytes: known_u128(0),
                    hard_link_count: known_count(1),
                    fingerprint: "root".to_string(),
                    identity: Some(EntryIdentity::from_unix(1, 1)),
                    filesystem_identity: Some(FilesystemIdentity { device: 1 }),
                    mount_identity: Some(MountIdentity { value: 1 }),
                    hard_link_key: None,
                },
                entries_by_capability: BTreeMap::from([(1, entries)]),
                walk_entries,
                inspect_calls: Arc::new(AtomicUsize::new(0)),
                enumeration_failure: None,
                cancel_on_inspect: false,
                replace_child_path_after_open: Arc::new(AtomicBool::new(false)),
                batch_size: None,
                file_length_proposals: None,
                file_length_calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn tree(
            root: PathBuf,
            entries_by_path: BTreeMap<PathBuf, Vec<DirectoryEntryRecord>>,
            walk_entries: BTreeMap<PathBuf, WalkEntry<FakeDirectoryHandle>>,
        ) -> Self {
            let mut platform = Self::new(root.clone(), Vec::new(), walk_entries);
            platform.entries_by_capability = entries_by_path
                .into_iter()
                .map(|(path, entries)| {
                    let capability_id = if path == root { 1 } else { 2 };
                    (capability_id, entries)
                })
                .collect();
            platform
        }

        fn with_inspect_calls(mut self, inspect_calls: Arc<AtomicUsize>) -> Self {
            self.inspect_calls = inspect_calls;
            self
        }

        fn with_enumeration_failure(mut self, failure: PlatformError) -> Self {
            self.enumeration_failure = Some(match failure {
                PlatformError::ResourceLimit(detail) => {
                    FakeEnumerationFailure::ResourceLimit(detail)
                }
                PlatformError::Io {
                    path,
                    detail,
                    io_kind,
                } => FakeEnumerationFailure::Io {
                    path,
                    detail,
                    io_kind,
                },
                _ => panic!("fake supports resource-limit and I/O enumeration failures only"),
            });
            self
        }

        fn with_cancel_on_inspect(mut self) -> Self {
            self.cancel_on_inspect = true;
            self
        }

        fn with_batch_size(mut self, batch_size: usize) -> Self {
            assert!(batch_size > 0);
            self.batch_size = Some(batch_size);
            self
        }
    }

    impl PlatformScanner for FakePlatform {
        type DirectoryHandle = FakeDirectoryHandle;

        fn platform_name(&self) -> &'static str {
            "fake"
        }

        fn supports_file_length_observation(&self) -> bool {
            self.file_length_proposals.is_some()
        }

        fn observe_file_length(
            &self,
            _: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
        ) -> Option<sweepx_platform::CachedFileEntry> {
            self.file_length_calls.fetch_add(1, Ordering::SeqCst);
            self.file_length_proposals
                .as_ref()?
                .get(&child.path)
                .cloned()
        }

        fn admit_root(
            &self,
            root: &ScanRoot,
            cancel: &CancellationToken,
        ) -> Result<RootAdmission<Self::DirectoryHandle>, PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            let root_locator = root
                .native_absolute_path()
                .map_err(|error| PlatformError::RootRejected(error.to_string()))?;
            Ok(RootAdmission::new(
                root.clone(),
                self.root_metadata.clone(),
                FakeDirectoryHandle {
                    path: self.root_metadata.path.clone(),
                    capability_id: 1,
                    cursor: 0,
                },
                root_locator,
            ))
        }

        fn enumerate_children(
            &self,
            directory: &mut Self::DirectoryHandle,
            cancel: &CancellationToken,
            limits: DirectoryReadLimits,
        ) -> Result<DirectoryEntryBatch, PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            if let Some(failure) = &self.enumeration_failure {
                return match failure {
                    FakeEnumerationFailure::ResourceLimit(detail) => {
                        Err(PlatformError::ResourceLimit(detail.clone()))
                    }
                    FakeEnumerationFailure::Io {
                        path,
                        detail,
                        io_kind,
                    } => Err(PlatformError::Io {
                        path: path.clone(),
                        detail: detail.clone(),
                        io_kind: *io_kind,
                    }),
                };
            }
            let entries = self
                .entries_by_capability
                .get(&directory.capability_id)
                .cloned()
                .unwrap_or_default();
            if directory.capability_id == 2
                && self.replace_child_path_after_open.load(Ordering::SeqCst)
            {
                assert_eq!(directory.path, test_path("root/child"));
                // A path-reopening implementation would observe `evil`; the retained capability
                // continues to enumerate the directory admitted as capability 2.
                let entries: Vec<_> = entries
                    .into_iter()
                    .filter(|entry| entry.file_name == test_native_name("safe"))
                    .collect();
                let start = directory.cursor.min(entries.len());
                let end = self.batch_size.map_or(entries.len(), |size| {
                    start
                        .saturating_add(size.min(limits.max_batch_entries))
                        .min(entries.len())
                });
                directory.cursor = end;
                return Ok(DirectoryEntryBatch {
                    entries: entries[start..end].to_vec(),
                    end_of_directory: end == entries.len(),
                });
            }
            let start = directory.cursor.min(entries.len());
            let end = self.batch_size.map_or(entries.len(), |size| {
                start
                    .saturating_add(size.min(limits.max_batch_entries))
                    .min(entries.len())
            });
            directory.cursor = end;
            Ok(DirectoryEntryBatch {
                entries: entries[start..end].to_vec(),
                end_of_directory: end == entries.len(),
            })
        }

        fn inspect_child(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            self.inspect_child_with_directory_admission(
                parent,
                child,
                cancel,
                DirectoryHandleAdmission::Allow,
            )
        }

        fn inspect_child_with_directory_admission(
            &self,
            parent: &Self::DirectoryHandle,
            child: &DirectoryEntryRecord,
            cancel: &CancellationToken,
            directory_admission: DirectoryHandleAdmission,
        ) -> Result<WalkEntry<Self::DirectoryHandle>, PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            self.inspect_calls.fetch_add(1, Ordering::SeqCst);
            if self.cancel_on_inspect {
                return Err(PlatformError::Cancelled);
            }
            child.validate_for_parent(&parent.path).map_err(|error| {
                PlatformError::InvalidDirectoryEntry {
                    parent: parent.path.clone(),
                    detail: error.to_string(),
                }
            })?;
            match self.walk_entries.get(&child.path) {
                Some(WalkEntry::Directory(opened)) => {
                    if directory_admission == DirectoryHandleAdmission::Deny {
                        return Ok(WalkEntry::Boundary(BoundaryRecord {
                            path: child.path.clone(),
                            kind: BoundaryKind::ResourceLimit,
                            reason: ReasonCode::ResourceLimit,
                            detail: "frontier limit exceeded".to_string(),
                        }));
                    }
                    Ok(WalkEntry::Directory(sweepx_platform::OpenedDirectory {
                        metadata: opened.metadata.clone(),
                        handle: FakeDirectoryHandle {
                            path: opened.metadata.path.clone(),
                            capability_id: opened.handle.capability_id,
                            cursor: 0,
                        },
                    }))
                }
                Some(WalkEntry::File(metadata)) => Ok(WalkEntry::File(metadata.clone())),
                Some(WalkEntry::Link(metadata)) => Ok(WalkEntry::Link(metadata.clone())),
                Some(WalkEntry::Boundary(boundary)) => Ok(WalkEntry::Boundary(boundary.clone())),
                Some(WalkEntry::Error(error)) => Ok(WalkEntry::Error(error.clone())),
                // The fake scanner never produces a cache entry in these tests; pass it through.
                Some(WalkEntry::CachedFile(cached)) => Ok(WalkEntry::CachedFile(cached.clone())),
                None => Err(PlatformError::Unsupported("missing fake entry".to_string())),
            }
        }

        fn is_same_mount(
            &self,
            _root: &EntryMetadata,
            _entry: &EntryMetadata,
        ) -> Result<bool, PlatformError> {
            Ok(true)
        }
    }
}
