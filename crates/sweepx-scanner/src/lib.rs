use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use sweepx_model::{
    ArithmeticState, Coverage, CoverageState, DecimalU128, DirectoryAggregate, EvidenceValue,
    FieldProvenance, NativeName, ObjectType, ReasonCode, ScanId, ScannedEntry,
};
use sweepx_platform::{
    BoundaryKind, BoundaryRecord, CancellationToken, EntryKind, EntryMetadata, HardLinkKey,
    PlatformError, PlatformScanner, RootAdmission, ScanResourceLimits, ScanRoot, WalkEntry,
    known_count, known_u128, lower_bound_u128, unknown_u128,
};
use thiserror::Error;

#[cfg(all(target_os = "linux", feature = "platform-linux"))]
pub use sweepx_platform_linux::LinuxPlatformScanner as HostPlatformScanner;
#[cfg(all(target_os = "macos", feature = "platform-macos"))]
pub use sweepx_platform_macos::MacosPlatformScanner as HostPlatformScanner;
#[cfg(all(target_os = "windows", feature = "platform-windows"))]
pub use sweepx_platform_windows::WindowsPlatformScanner as HostPlatformScanner;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerOptions {
    pub scan_id: ScanId,
    pub resource_limits: ScanResourceLimits,
    pub max_workers: usize,
}

impl Default for ScannerOptions {
    fn default() -> Self {
        Self {
            scan_id: ScanId::new("scan-p1"),
            resource_limits: ScanResourceLimits::default(),
            max_workers: 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressEvent {
    RootAccepted { path: PathBuf },
    EntryObserved { path: PathBuf, kind: ObjectType },
    Boundary { path: PathBuf, kind: BoundaryKind },
    Error { path: PathBuf, reason: ReasonCode },
    Cancelled { path: PathBuf },
    ResourceLimit { path: PathBuf },
    Finished,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSummary {
    pub roots: Vec<ScannedEntry>,
    pub entries: Vec<ScannedEntry>,
    pub aggregates: Vec<DirectoryAggregate>,
    pub boundaries: Vec<BoundaryRecord>,
    pub progress: Vec<ProgressEvent>,
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
    fn push_aggregate(&mut self, aggregate: DirectoryAggregate) -> Result<(), ScanError>;

    fn overflow_count(&self) -> usize {
        0
    }
}

#[derive(Debug)]
struct CollectingScanSink {
    summary: ScanSummary,
    limits: ScanResourceLimits,
    overflowed_roots: BTreeSet<PathBuf>,
    overflow_count: usize,
}

impl CollectingScanSink {
    fn new(limits: ScanResourceLimits) -> Self {
        Self {
            summary: ScanSummary {
                roots: Vec::new(),
                entries: Vec::new(),
                aggregates: Vec::new(),
                boundaries: Vec::new(),
                progress: Vec::new(),
            },
            limits,
            overflowed_roots: BTreeSet::new(),
            overflow_count: 0,
        }
    }

    fn finish(self) -> ScanSummary {
        self.summary
    }

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

    fn push_boundary_marker(&mut self, boundary: BoundaryRecord) {
        Self::push_capped_replace_last(
            &mut self.summary.boundaries,
            boundary,
            self.limits.max_retained_boundaries,
        );
    }

    fn push_progress_marker(&mut self, event: ProgressEvent) {
        Self::push_capped_replace_last(
            &mut self.summary.progress,
            event,
            self.limits.max_progress_events,
        );
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

impl ScanSink for CollectingScanSink {
    fn push_root(&mut self, root: &Path, entry: ScannedEntry) -> Result<(), ScanError> {
        if self.summary.roots.len() >= self.limits.max_retained_entries {
            self.mark_overflow(root, root, "retained root cap exceeded");
            return Ok(());
        }
        self.summary.roots.push(entry);
        Ok(())
    }

    fn push_entry(&mut self, root: &Path, entry: ScannedEntry) -> Result<(), ScanError> {
        if self.summary.entries.len() >= self.limits.max_retained_entries {
            self.mark_overflow(
                root,
                Path::new(&entry.display_path),
                "retained entry cap exceeded",
            );
            return Ok(());
        }
        self.summary.entries.push(entry);
        Ok(())
    }

    fn push_boundary(&mut self, root: &Path, boundary: BoundaryRecord) -> Result<(), ScanError> {
        if self.summary.boundaries.len() >= self.limits.max_retained_boundaries {
            self.mark_overflow(root, &boundary.path, "retained boundary cap exceeded");
            return Ok(());
        }
        self.summary.boundaries.push(boundary);
        Ok(())
    }

    fn push_progress(&mut self, root: &Path, event: ProgressEvent) -> Result<(), ScanError> {
        if self.summary.progress.len() >= self.limits.max_progress_events {
            let overflow_path = match &event {
                ProgressEvent::RootAccepted { path }
                | ProgressEvent::Boundary { path, .. }
                | ProgressEvent::Error { path, .. }
                | ProgressEvent::Cancelled { path }
                | ProgressEvent::ResourceLimit { path }
                | ProgressEvent::EntryObserved { path, .. } => path.as_path(),
                ProgressEvent::Finished => root,
            };
            self.mark_overflow(root, overflow_path, "retained progress cap exceeded");
            return Ok(());
        }
        self.summary.progress.push(event);
        Ok(())
    }

    fn push_aggregate(&mut self, aggregate: DirectoryAggregate) -> Result<(), ScanError> {
        self.summary.aggregates.push(aggregate);
        Ok(())
    }

    fn overflow_count(&self) -> usize {
        self.overflow_count
    }
}

pub struct Scanner<P> {
    platform: P,
    options: ScannerOptions,
}

impl<P> Scanner<P>
where
    P: PlatformScanner,
{
    pub fn new(platform: P, options: ScannerOptions) -> Self {
        Self { platform, options }
    }

    pub fn scan(
        &self,
        roots: &[ScanRoot],
        cancel: &CancellationToken,
    ) -> Result<ScanSummary, ScanError> {
        let mut sink = CollectingScanSink::new(self.options.resource_limits);
        self.scan_with_sink(roots, cancel, &mut sink)?;
        Ok(sink.finish())
    }

    pub fn scan_with_sink<S: ScanSink>(
        &self,
        roots: &[ScanRoot],
        cancel: &CancellationToken,
        sink: &mut S,
    ) -> Result<(), ScanError> {
        if self.options.max_workers == 0 {
            return Err(ScanError::RootValidation(
                "max_workers must be greater than zero".to_string(),
            ));
        }

        for root in roots {
            let admission = match self.platform.admit_root(root, cancel) {
                Ok(admission) => admission,
                Err(PlatformError::Cancelled) => {
                    sink.push_progress(
                        root.path(),
                        ProgressEvent::Cancelled {
                            path: root.path.clone(),
                        },
                    )?;
                    sink.push_aggregate(cancelled_root_aggregate(
                        &self.options.scan_id,
                        root.path(),
                    ))?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
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
                    complete_coverage(),
                ),
            )?;

            self.scan_root(&admission, cancel, overflow_count_before, sink)?;
        }

        sink.push_progress(Path::new("/"), ProgressEvent::Finished)?;
        Ok(())
    }

    fn scan_root<S: ScanSink>(
        &self,
        admission: &RootAdmission,
        cancel: &CancellationToken,
        overflow_count_before: usize,
        sink: &mut S,
    ) -> Result<(), ScanError> {
        let mut frontier = VecDeque::from([admission.metadata.path.clone()]);
        let mut active_frontier_entries = 1usize;
        let mut visited_directories = 0usize;
        let mut directory_states = BTreeMap::<PathBuf, DirectoryState>::new();
        directory_states.insert(
            admission.metadata.path.clone(),
            DirectoryState::new(admission.metadata.path.clone()),
        );

        while let Some(path) = frontier.pop_front() {
            active_frontier_entries = active_frontier_entries.saturating_sub(1);
            if cancel.is_cancelled() {
                mark_all_open_incomplete(
                    &mut directory_states,
                    ReasonCode::IncompleteStreamCoverage,
                );
                sink.push_progress(admission.root.path(), ProgressEvent::Cancelled { path })?;
                break;
            }

            visited_directories += 1;
            if visited_directories > self.options.resource_limits.max_visited_entries {
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
                sink.push_progress(
                    admission.root.path(),
                    ProgressEvent::ResourceLimit { path: path.clone() },
                )?;
                sink.push_boundary(admission.root.path(), boundary)?;
                continue;
            }

            let entries = match self.platform.read_dir_entries(
                &path,
                cancel,
                self.options.resource_limits.max_directory_entries,
            ) {
                Ok(entries) => entries,
                Err(PlatformError::Cancelled) => {
                    mark_all_open_incomplete(
                        &mut directory_states,
                        ReasonCode::IncompleteStreamCoverage,
                    );
                    sink.push_progress(
                        admission.root.path(),
                        ProgressEvent::Cancelled { path: path.clone() },
                    )?;
                    break;
                }
                Err(PlatformError::Io { detail, .. }) => {
                    note_boundary(
                        &mut directory_states,
                        &path,
                        ReasonCode::IncompleteStreamCoverage,
                    );
                    sink.push_progress(
                        admission.root.path(),
                        ProgressEvent::Error {
                            path: path.clone(),
                            reason: ReasonCode::IncompleteStreamCoverage,
                        },
                    )?;
                    sink.push_entry(
                        admission.root.path(),
                        ScannedEntry {
                            scan_id: self.options.scan_id.clone(),
                            display_path: path.display().to_string(),
                            native_basename: native_basename_for_path(&path),
                            object_type: ObjectType::Directory,
                            logical_bytes: lower_bound_u128(
                                0,
                                ReasonCode::IncompleteStreamCoverage,
                            ),
                            allocated_bytes: lower_bound_u128(
                                0,
                                ReasonCode::IncompleteStreamCoverage,
                            ),
                            reclaimable_estimate: lower_bound_u128(
                                0,
                                ReasonCode::IncompleteStreamCoverage,
                            ),
                            metadata_fingerprint: format!("read_dir_error:{detail}"),
                            coverage: Coverage {
                                state: CoverageState::Incomplete,
                                complete: false,
                                incomplete_reasons: vec![ReasonCode::IncompleteStreamCoverage],
                                details_lost: false,
                                provenance: live_provenance(),
                            },
                            provenance: live_provenance(),
                        },
                    )?;
                    continue;
                }
                Err(PlatformError::ResourceLimit(detail)) => {
                    note_boundary(&mut directory_states, &path, ReasonCode::ResourceLimit);
                    sink.push_progress(
                        admission.root.path(),
                        ProgressEvent::ResourceLimit { path: path.clone() },
                    )?;
                    sink.push_boundary(
                        admission.root.path(),
                        BoundaryRecord {
                            path: path.clone(),
                            kind: BoundaryKind::ResourceLimit,
                            reason: ReasonCode::ResourceLimit,
                            detail,
                        },
                    )?;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            for directory_entry in entries {
                if cancel.is_cancelled() {
                    mark_all_open_incomplete(
                        &mut directory_states,
                        ReasonCode::IncompleteStreamCoverage,
                    );
                    sink.push_progress(
                        admission.root.path(),
                        ProgressEvent::Cancelled {
                            path: directory_entry.path,
                        },
                    )?;
                    break;
                }

                let walk = match self.platform.stat_entry(
                    &directory_entry.path,
                    directory_entry.file_name.clone(),
                    cancel,
                ) {
                    Ok(entry) => entry,
                    Err(PlatformError::Cancelled) => {
                        mark_all_open_incomplete(
                            &mut directory_states,
                            ReasonCode::IncompleteStreamCoverage,
                        );
                        sink.push_progress(
                            admission.root.path(),
                            ProgressEvent::Cancelled {
                                path: directory_entry.path.clone(),
                            },
                        )?;
                        break;
                    }
                    Err(error) => return Err(error.into()),
                };
                match walk {
                    WalkEntry::Directory(metadata) => {
                        let same_mount =
                            self.platform.is_same_mount(&admission.metadata, &metadata);
                        match same_mount {
                            Ok(true) => {}
                            Ok(false) => {
                                let boundary = BoundaryRecord {
                                    path: metadata.path.clone(),
                                    kind: BoundaryKind::Mount,
                                    reason: ReasonCode::UnsupportedFilesystem,
                                    detail: "entry crosses the initial mount boundary".to_string(),
                                };
                                note_boundary(
                                    &mut directory_states,
                                    &metadata.path,
                                    boundary.reason.clone(),
                                );
                                sink.push_progress(
                                    admission.root.path(),
                                    ProgressEvent::Boundary {
                                        path: metadata.path.clone(),
                                        kind: boundary.kind.clone(),
                                    },
                                )?;
                                sink.push_boundary(admission.root.path(), boundary)?;
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
                                    admission.root.path(),
                                    ProgressEvent::Boundary {
                                        path: metadata.path.clone(),
                                        kind: boundary.kind.clone(),
                                    },
                                )?;
                                sink.push_boundary(admission.root.path(), boundary)?;
                                continue;
                            }
                        }

                        if active_frontier_entries
                            >= self.options.resource_limits.max_frontier_entries
                        {
                            let boundary = BoundaryRecord {
                                path: metadata.path.clone(),
                                kind: BoundaryKind::ResourceLimit,
                                reason: ReasonCode::ResourceLimit,
                                detail: "frontier limit exceeded".to_string(),
                            };
                            note_boundary(
                                &mut directory_states,
                                &metadata.path,
                                boundary.reason.clone(),
                            );
                            sink.push_progress(
                                admission.root.path(),
                                ProgressEvent::Boundary {
                                    path: metadata.path.clone(),
                                    kind: boundary.kind.clone(),
                                },
                            )?;
                            sink.push_boundary(admission.root.path(), boundary)?;
                            continue;
                        }

                        let scanned = scanned_entry_from_metadata(
                            &self.options.scan_id,
                            &metadata,
                            complete_coverage(),
                        );
                        sink.push_progress(
                            admission.root.path(),
                            ProgressEvent::EntryObserved {
                                path: metadata.path.clone(),
                                kind: ObjectType::Directory,
                            },
                        )?;
                        propagate_directory_entry(&mut directory_states, &metadata.path);
                        directory_states
                            .entry(metadata.path.clone())
                            .or_insert_with(|| DirectoryState::new(metadata.path.clone()));
                        sink.push_entry(admission.root.path(), scanned)?;
                        frontier.push_back(metadata.path.clone());
                        active_frontier_entries += 1;
                    }
                    WalkEntry::File(metadata) => {
                        let scanned = scanned_entry_from_metadata(
                            &self.options.scan_id,
                            &metadata,
                            complete_coverage(),
                        );
                        sink.push_progress(
                            admission.root.path(),
                            ProgressEvent::EntryObserved {
                                path: metadata.path.clone(),
                                kind: ObjectType::File,
                            },
                        )?;
                        propagate_file_entry(&mut directory_states, &metadata.path, &metadata);
                        sink.push_entry(admission.root.path(), scanned)?;
                    }
                    WalkEntry::Link(metadata) => {
                        let coverage = Coverage {
                            state: CoverageState::Complete,
                            complete: true,
                            incomplete_reasons: vec![],
                            details_lost: false,
                            provenance: live_provenance(),
                        };
                        sink.push_progress(
                            admission.root.path(),
                            ProgressEvent::Boundary {
                                path: metadata.path.clone(),
                                kind: BoundaryKind::Symlink,
                            },
                        )?;
                        sink.push_boundary(
                            admission.root.path(),
                            BoundaryRecord {
                                path: metadata.path.clone(),
                                kind: BoundaryKind::Symlink,
                                reason: ReasonCode::StrictReadOnly,
                                detail: "symlink recorded and not followed".to_string(),
                            },
                        )?;
                        sink.push_entry(
                            admission.root.path(),
                            scanned_entry_from_metadata(&self.options.scan_id, &metadata, coverage),
                        )?;
                    }
                    WalkEntry::Boundary(boundary) => {
                        note_boundary(
                            &mut directory_states,
                            &boundary.path,
                            boundary.reason.clone(),
                        );
                        sink.push_progress(
                            admission.root.path(),
                            ProgressEvent::Boundary {
                                path: boundary.path.clone(),
                                kind: boundary.kind.clone(),
                            },
                        )?;
                        sink.push_boundary(admission.root.path(), boundary)?;
                    }
                    WalkEntry::Error(error) => {
                        note_boundary(&mut directory_states, &error.path, error.reason.clone());
                        sink.push_progress(
                            admission.root.path(),
                            ProgressEvent::Error {
                                path: error.path.clone(),
                                reason: error.reason.clone(),
                            },
                        )?;
                        sink.push_entry(
                            admission.root.path(),
                            ScannedEntry {
                                scan_id: self.options.scan_id.clone(),
                                display_path: error.path.display().to_string(),
                                native_basename: native_basename_for_path(&error.path),
                                object_type: ObjectType::Other,
                                logical_bytes: unknown_u128(error.reason.clone()),
                                allocated_bytes: unknown_u128(error.reason.clone()),
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
        }

        if sink.overflow_count() > overflow_count_before {
            mark_all_open_incomplete(&mut directory_states, ReasonCode::ResourceLimit);
        }

        let mut aggregates: Vec<_> = directory_states
            .into_values()
            .map(|state| state.into_aggregate(&self.options.scan_id))
            .collect();
        aggregates.sort_by(|left, right| left.directory_identity.cmp(&right.directory_identity));
        for aggregate in aggregates {
            sink.push_aggregate(aggregate)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct DirectoryState {
    path: PathBuf,
    direct_child_count: u128,
    recursive_entry_count: u128,
    apparent_logical_bytes: u128,
    unique_logical_bytes: Option<u128>,
    allocated_bytes: EvidenceAccumulator,
    reclaimable_bytes: EvidenceAccumulator,
    incomplete_reasons: BTreeSet<ReasonCode>,
    counted_hard_links: BTreeSet<HardLinkKey>,
}

impl DirectoryState {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            direct_child_count: 0,
            recursive_entry_count: 0,
            apparent_logical_bytes: 0,
            unique_logical_bytes: Some(0),
            allocated_bytes: EvidenceAccumulator::known_zero(),
            reclaimable_bytes: EvidenceAccumulator::known_zero(),
            incomplete_reasons: BTreeSet::new(),
            counted_hard_links: BTreeSet::new(),
        }
    }

    fn note_direct_child(&mut self) {
        self.direct_child_count += 1;
    }

    fn note_recursive_entry(&mut self) {
        self.recursive_entry_count += 1;
    }

    fn into_aggregate(self, scan_id: &ScanId) -> DirectoryAggregate {
        let complete = self.incomplete_reasons.is_empty();
        let reasons: Vec<_> = self.incomplete_reasons.into_iter().collect();
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
        let allocated = self.allocated_bytes.into_value(complete);
        let reclaimable = self.reclaimable_bytes.into_value(complete);

        DirectoryAggregate {
            scan_id: scan_id.clone(),
            directory_identity: self.path.display().to_string(),
            revision: DecimalU128::new(1),
            apparent_logical_bytes: apparent,
            unique_logical_bytes: unique,
            filesystem_reported_allocated_bytes: allocated.clone(),
            potentially_reclaimable_bytes: reclaimable,
            direct_child_count: known_count(self.direct_child_count),
            recursive_entry_count: known_count(self.recursive_entry_count),
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
    for ancestor in ancestors_for_entry(path) {
        if let Some(state) = states.get_mut(&ancestor) {
            state.note_recursive_entry();
            if path.parent() == Some(ancestor.as_path()) {
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

    for ancestor in ancestors_for_entry(path) {
        if let Some(state) = states.get_mut(&ancestor) {
            state.note_recursive_entry();
            state.apparent_logical_bytes += logical;
            if path.parent() == Some(ancestor.as_path()) {
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

fn add_option_u128(slot: &mut Option<u128>, value: u128) {
    if let Some(current) = slot.as_mut() {
        *current += value;
    }
}

fn note_boundary(states: &mut BTreeMap<PathBuf, DirectoryState>, path: &Path, reason: ReasonCode) {
    for ancestor in state_and_ancestors(path) {
        if let Some(state) = states.get_mut(&ancestor) {
            state.incomplete_reasons.insert(reason.clone());
            if path.parent() == Some(ancestor.as_path()) {
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

fn ancestors_for_entry(path: &Path) -> Vec<PathBuf> {
    let mut ancestors = Vec::new();
    let mut current = path.parent();
    while let Some(path) = current {
        ancestors.push(path.to_path_buf());
        current = path.parent();
    }
    ancestors
}

fn state_and_ancestors(path: &Path) -> Vec<PathBuf> {
    let mut all = vec![path.to_path_buf()];
    all.extend(ancestors_for_entry(path));
    all
}

fn scanned_entry_from_metadata(
    scan_id: &ScanId,
    metadata: &EntryMetadata,
    coverage: Coverage,
) -> ScannedEntry {
    ScannedEntry {
        scan_id: scan_id.clone(),
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

fn complete_coverage() -> Coverage {
    Coverage {
        state: CoverageState::Complete,
        complete: true,
        incomplete_reasons: Vec::new(),
        details_lost: false,
        provenance: live_provenance(),
    }
}

fn cancelled_root_aggregate(scan_id: &ScanId, path: &Path) -> DirectoryAggregate {
    DirectoryAggregate {
        scan_id: scan_id.clone(),
        directory_identity: path.display().to_string(),
        revision: DecimalU128::new(1),
        apparent_logical_bytes: lower_bound_u128(0, ReasonCode::IncompleteStreamCoverage),
        unique_logical_bytes: lower_bound_u128(0, ReasonCode::IncompleteStreamCoverage),
        filesystem_reported_allocated_bytes: lower_bound_u128(
            0,
            ReasonCode::IncompleteStreamCoverage,
        ),
        potentially_reclaimable_bytes: lower_bound_u128(0, ReasonCode::IncompleteStreamCoverage),
        direct_child_count: known_count(0),
        recursive_entry_count: known_count(0),
        coverage: Coverage {
            state: CoverageState::Incomplete,
            complete: false,
            incomplete_reasons: vec![ReasonCode::IncompleteStreamCoverage],
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
                .unwrap_or_else(|| path.as_os_str())
                .encode_wide()
                .collect::<Vec<_>>(),
        );
    }
    #[allow(unreachable_code)]
    NativeName::unix(path.display().to_string().into_bytes())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::*;
    use sweepx_platform::{DirectoryEntryRecord, EntryIdentity, FilesystemIdentity, MountIdentity};

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    fn linux_scanner(options: ScannerOptions) -> Scanner<HostPlatformScanner> {
        Scanner::new(HostPlatformScanner::new(), options)
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

        let root_aggregate = result
            .aggregates
            .iter()
            .find(|entry| entry.directory_identity == root.display().to_string())
            .unwrap();
        assert_eq!(root_aggregate.apparent_logical_bytes, known_u128(14));
        assert_eq!(root_aggregate.unique_logical_bytes, known_u128(10));
        assert_eq!(
            root_aggregate.potentially_reclaimable_bytes,
            unknown_u128(ReasonCode::UnknownIdentity)
        );
        assert!(root_aggregate.coverage.complete);
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
        let root_aggregate = result
            .aggregates
            .iter()
            .find(|entry| entry.directory_identity == root.display().to_string())
            .unwrap();
        assert!(!root_aggregate.coverage.complete);
        assert!(result.roots.is_empty());
        assert!(result.entries.is_empty());
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
                max_frontier_entries: 1,
                max_visited_entries: 32,
                max_retained_entries: 16_384,
                max_retained_boundaries: 16_384,
                max_progress_events: 16_384,
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

        let root_aggregate = result
            .aggregates
            .iter()
            .find(|entry| entry.directory_identity == root.display().to_string())
            .unwrap();
        let left_aggregate = result
            .aggregates
            .iter()
            .find(|entry| entry.directory_identity == left.display().to_string())
            .unwrap();
        let right_aggregate = result
            .aggregates
            .iter()
            .find(|entry| entry.directory_identity == right.display().to_string())
            .unwrap();

        assert_eq!(root_aggregate.apparent_logical_bytes, known_u128(8));
        assert_eq!(root_aggregate.unique_logical_bytes, known_u128(4));
        assert_eq!(left_aggregate.unique_logical_bytes, known_u128(4));
        assert_eq!(right_aggregate.unique_logical_bytes, known_u128(4));
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
                max_frontier_entries: 32,
                max_visited_entries: 1,
                max_retained_entries: 16_384,
                max_retained_boundaries: 16_384,
                max_progress_events: 16_384,
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
    fn retained_entry_cap_marks_root_incomplete_and_records_resource_limit() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("a.txt"), b"a").unwrap();
        fs::write(root.join("b.txt"), b"b").unwrap();

        let scanner = linux_scanner(ScannerOptions {
            resource_limits: ScanResourceLimits {
                max_directory_entries: 32,
                max_frontier_entries: 32,
                max_visited_entries: 32,
                max_retained_entries: 1,
                max_retained_boundaries: 4,
                max_progress_events: 8,
            },
            ..ScannerOptions::default()
        });
        let result = scanner
            .scan(
                &[ScanRoot::new(root.clone()).unwrap()],
                &CancellationToken::new(),
            )
            .unwrap();

        assert_eq!(result.entries.len(), 1);
        assert!(
            result
                .boundaries
                .iter()
                .any(|boundary| boundary.kind == BoundaryKind::ResourceLimit)
        );
        assert!(
            result
                .progress
                .iter()
                .any(|event| matches!(event, ProgressEvent::ResourceLimit { .. }))
        );
        let root_aggregate = result
            .aggregates
            .iter()
            .find(|entry| entry.directory_identity == root.display().to_string())
            .unwrap();
        assert!(!root_aggregate.coverage.complete);
        assert!(
            root_aggregate
                .coverage
                .incomplete_reasons
                .contains(&ReasonCode::ResourceLimit)
        );
    }

    #[test]
    fn aggregate_preserves_lower_bound_allocated_and_reclaimable() {
        let root = PathBuf::from("/root");
        let file = root.join("file.bin");
        let scanner = Scanner::new(
            FakePlatform::new(
                root.clone(),
                vec![DirectoryEntryRecord {
                    path: file.clone(),
                    file_name: NativeName::windows_utf16(
                        "file.bin".encode_utf16().collect::<Vec<_>>(),
                    ),
                }],
                BTreeMap::from([(
                    file.clone(),
                    WalkEntry::File(EntryMetadata {
                        path: file.clone(),
                        file_name: NativeName::windows_utf16(
                            "file.bin".encode_utf16().collect::<Vec<_>>(),
                        ),
                        kind: EntryKind::File,
                        logical_bytes: known_u128(7),
                        allocated_bytes: lower_bound_u128(11, ReasonCode::UnknownLayout),
                        hard_link_count: known_count(1),
                        fingerprint: "fp".to_string(),
                        identity: Some(EntryIdentity {
                            device: 1,
                            inode: 2,
                        }),
                        filesystem_identity: Some(FilesystemIdentity { device: 1 }),
                        mount_identity: Some(MountIdentity { value: 1 }),
                        hard_link_key: Some(HardLinkKey {
                            device: 1,
                            inode: 2,
                        }),
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

        let aggregate = result
            .aggregates
            .iter()
            .find(|entry| entry.directory_identity == root.display().to_string())
            .unwrap();
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
    fn aggregate_propagates_unknown_allocated_and_reclaimable_reason() {
        let root = PathBuf::from("/root");
        let file = root.join("file.bin");
        let scanner = Scanner::new(
            FakePlatform::new(
                root.clone(),
                vec![DirectoryEntryRecord {
                    path: file.clone(),
                    file_name: NativeName::windows_utf16(
                        "file.bin".encode_utf16().collect::<Vec<_>>(),
                    ),
                }],
                BTreeMap::from([(
                    file.clone(),
                    WalkEntry::File(EntryMetadata {
                        path: file.clone(),
                        file_name: NativeName::windows_utf16(
                            "file.bin".encode_utf16().collect::<Vec<_>>(),
                        ),
                        kind: EntryKind::File,
                        logical_bytes: known_u128(7),
                        allocated_bytes: unknown_u128(ReasonCode::UnknownLayout),
                        hard_link_count: known_count(1),
                        fingerprint: "fp".to_string(),
                        identity: Some(EntryIdentity {
                            device: 1,
                            inode: 2,
                        }),
                        filesystem_identity: Some(FilesystemIdentity { device: 1 }),
                        mount_identity: Some(MountIdentity { value: 1 }),
                        hard_link_key: Some(HardLinkKey {
                            device: 1,
                            inode: 2,
                        }),
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

        let aggregate = result
            .aggregates
            .iter()
            .find(|entry| entry.directory_identity == root.display().to_string())
            .unwrap();
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

    #[derive(Debug)]
    struct FakePlatform {
        root_metadata: EntryMetadata,
        entries: Vec<DirectoryEntryRecord>,
        walk_entries: BTreeMap<PathBuf, WalkEntry>,
    }

    impl FakePlatform {
        fn new(
            root: PathBuf,
            entries: Vec<DirectoryEntryRecord>,
            walk_entries: BTreeMap<PathBuf, WalkEntry>,
        ) -> Self {
            Self {
                root_metadata: EntryMetadata {
                    path: root.clone(),
                    file_name: NativeName::windows_utf16("root".encode_utf16().collect::<Vec<_>>()),
                    kind: EntryKind::Directory,
                    logical_bytes: known_u128(0),
                    allocated_bytes: known_u128(0),
                    hard_link_count: known_count(1),
                    fingerprint: "root".to_string(),
                    identity: Some(EntryIdentity {
                        device: 1,
                        inode: 1,
                    }),
                    filesystem_identity: Some(FilesystemIdentity { device: 1 }),
                    mount_identity: Some(MountIdentity { value: 1 }),
                    hard_link_key: None,
                },
                entries,
                walk_entries,
            }
        }
    }

    impl PlatformScanner for FakePlatform {
        fn platform_name(&self) -> &'static str {
            "fake"
        }

        fn admit_root(
            &self,
            root: &ScanRoot,
            cancel: &CancellationToken,
        ) -> Result<RootAdmission, PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            Ok(RootAdmission {
                root: root.clone(),
                metadata: self.root_metadata.clone(),
            })
        }

        fn read_dir_entries(
            &self,
            _path: &Path,
            cancel: &CancellationToken,
            _max_entries: usize,
        ) -> Result<Vec<DirectoryEntryRecord>, PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            Ok(self.entries.clone())
        }

        fn stat_entry(
            &self,
            path: &Path,
            _file_name: NativeName,
            cancel: &CancellationToken,
        ) -> Result<WalkEntry, PlatformError> {
            if cancel.is_cancelled() {
                return Err(PlatformError::Cancelled);
            }
            self.walk_entries
                .get(path)
                .cloned()
                .ok_or_else(|| PlatformError::Unsupported("missing fake entry".to_string()))
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
