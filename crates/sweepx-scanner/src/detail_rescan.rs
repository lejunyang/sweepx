use std::collections::{BTreeSet, VecDeque};
use std::ffi::OsString;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;

use sweepx_model::{
    ArithmeticState, Coverage, CoverageState, DecimalU128, DirectoryAggregate, EvidenceValue,
    IdentityEvidence, NativeAbsolutePath, NativeLocatorEvidence, NativePathComponent, ObjectType,
    ReasonCode, ScanEntryId, ScanId, ScanObjectIdentity, ScannedEntry,
};
use sweepx_platform::{
    BoundaryKind, CancellationToken, DirectoryEntryRecord, DirectoryReadLimits, EntryKind,
    EntryMetadata, ErrorKind, HardLinkKey, PlatformError, PlatformScanner, RootAdmission,
    ScanResourceLimits, ScanRoot, WalkEntry, inspect_bound_child, known_count,
};
use thiserror::Error;

use super::{
    EvidenceAccumulator, ORDINARY_SCAN_MAX_ORDINAL, complete_coverage, native_locator_evidence,
    native_path_component, scan_object_identity, scanned_entry_from_metadata,
};

pub const DETAIL_SCAN_MIN_ORDINAL: u128 = ORDINARY_SCAN_MAX_ORDINAL + 1;

/// A source-scan allocator used by repeated detail rescans.
///
/// The allocator starts after the greatest already-observed ordinal and never rewinds, including
/// after a failed rescan. This preserves scan-scoped identity uniqueness without retaining a
/// second copy of every entry id in the browser.
#[derive(Debug, Clone)]
pub struct DetailEntryIdAllocator {
    scan_id: ScanId,
    next_ordinal: Option<u128>,
}

impl DetailEntryIdAllocator {
    pub fn new(scan_id: ScanId) -> Result<Self, DetailRescanError> {
        ScanEntryId::for_scan_ordinal(&scan_id, 1)
            .map_err(|_| DetailRescanError::InvalidRequest)?;
        Ok(Self {
            scan_id,
            // Ordinary Scanner ids grow upward from one. Detail ids grow downward from the top
            // half, giving targeted rescans a disjoint namespace even when ordinary rows were
            // evicted before the provider was constructed.
            next_ordinal: Some(u128::MAX),
        })
    }

    pub fn scan_id(&self) -> &ScanId {
        &self.scan_id
    }

    pub fn reserve(&mut self, entry_id: &ScanEntryId) -> Result<(), DetailRescanError> {
        if !entry_id.belongs_to(&self.scan_id) {
            return Err(DetailRescanError::InvalidRequest);
        }
        let ordinal = entry_id
            .as_str()
            .rsplit_once(':')
            .and_then(|(_, ordinal)| ordinal.parse::<u128>().ok())
            .filter(|ordinal| *ordinal != 0)
            .ok_or(DetailRescanError::InvalidRequest)?;
        if ordinal >= DETAIL_SCAN_MIN_ORDINAL
            && self.next_ordinal.is_some_and(|next| ordinal <= next)
        {
            self.next_ordinal = ordinal.checked_sub(1);
        }
        Ok(())
    }

    fn allocate(&mut self) -> Result<ScanEntryId, DetailRescanError> {
        let ordinal = self
            .next_ordinal
            .take()
            .ok_or(DetailRescanError::ResourceLimit)?;
        if ordinal < DETAIL_SCAN_MIN_ORDINAL {
            return Err(DetailRescanError::ResourceLimit);
        }
        self.next_ordinal = ordinal.checked_sub(1);
        ScanEntryId::for_scan_ordinal(&self.scan_id, ordinal)
            .map_err(|_| DetailRescanError::ResourceLimit)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DetailRescanRequest<'a> {
    pub source_scan_id: &'a ScanId,
    pub source_root_identity: &'a ScanObjectIdentity,
    pub source_directory_identity: &'a ScanObjectIdentity,
    pub directory_locator: &'a NativeLocatorEvidence,
    pub revision: DecimalU128,
    pub max_rows: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailRescanResult {
    pub observed_root: ScannedEntry,
    pub observed_directory: ScannedEntry,
    pub rows: Vec<ScannedEntry>,
    pub aggregate: DirectoryAggregate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DetailRescanError {
    #[error("detail rescan request is internally inconsistent")]
    InvalidRequest,
    #[error("required native identity evidence is unavailable")]
    IdentityUnavailable,
    #[error("a reopened filesystem object no longer matches its recorded identity")]
    IdentityMismatch,
    #[error("the reopened target crossed or changed its recorded mount")]
    MountChanged,
    #[error("a required directory is now a symlink or reparse point")]
    SymlinkOrReparse,
    #[error("detail rescan was cancelled")]
    Cancelled,
    #[error("detail rescan resource limit was exceeded")]
    ResourceLimit,
    #[error("the platform cannot safely perform this detail rescan")]
    Unavailable,
}

/// Scanner-owned, read-only targeted rescans.
///
/// Only the lossless native root in `NativeLocatorEvidence` is admitted as a root. Every
/// descendant component is then reopened relative to the retained parent handle with
/// `inspect_bound_child`; no display path is accepted as input or used to regain authority.
pub struct DetailRescanner<P> {
    platform: P,
    limits: ScanResourceLimits,
}

impl<P> DetailRescanner<P>
where
    P: PlatformScanner,
{
    pub fn new(platform: P, limits: ScanResourceLimits) -> Self {
        Self { platform, limits }
    }

    pub fn rescan(
        &self,
        request: DetailRescanRequest<'_>,
        ids: &mut DetailEntryIdAllocator,
        cancel: &CancellationToken,
    ) -> Result<DetailRescanResult, DetailRescanError> {
        self.validate_request(&request, ids)?;
        if cancel.is_cancelled() {
            return Err(DetailRescanError::Cancelled);
        }

        let reopened = self.reopen_target(&request, cancel)?;
        let observed_root = reopened.observed_root.clone();
        let observed_directory = reopened.observed_directory.clone();
        let (rows, aggregate) = self.scan_target_directory(&request, reopened, ids, cancel)?;

        Ok(DetailRescanResult {
            observed_root,
            observed_directory,
            rows,
            aggregate,
        })
    }

    fn validate_request(
        &self,
        request: &DetailRescanRequest<'_>,
        ids: &DetailEntryIdAllocator,
    ) -> Result<(), DetailRescanError> {
        if ids.scan_id() != request.source_scan_id
            || request.directory_locator.parent_reopen_recipe.len()
                > self.limits.max_visited_entries
            || request.source_root_identity.entry_id != request.source_root_identity.scan_root_id
            || request.source_root_identity.parent_id.is_some()
            || request.source_directory_identity.scan_root_id
                != request.source_root_identity.entry_id
            || request.directory_locator.scan_root.object_type != ObjectType::Directory
            || request.directory_locator.entry.object_type != ObjectType::Directory
        {
            return Err(DetailRescanError::InvalidRequest);
        }
        request
            .source_root_identity
            .validate_for_scan(request.source_scan_id)
            .map_err(|_| DetailRescanError::InvalidRequest)?;
        request
            .directory_locator
            .validate_for_execution(request.source_directory_identity, request.source_scan_id)
            .map_err(|_| DetailRescanError::InvalidRequest)?;
        if !component_matches_identity(
            &request.directory_locator.scan_root,
            request.source_root_identity,
        ) || !component_matches_identity(
            &request.directory_locator.entry,
            request.source_directory_identity,
        ) {
            return Err(DetailRescanError::InvalidRequest);
        }
        Ok(())
    }

    fn reopen_target(
        &self,
        request: &DetailRescanRequest<'_>,
        cancel: &CancellationToken,
    ) -> Result<ReopenedTarget<P::DirectoryHandle>, DetailRescanError> {
        let native_root = request
            .directory_locator
            .scan_root_absolute_path
            .as_ref()
            .ok_or(DetailRescanError::InvalidRequest)?;
        let root_path = native_absolute_path_buf(native_root)?;
        let root = ScanRoot::new(root_path).map_err(|_| DetailRescanError::InvalidRequest)?;
        let admission = self
            .platform
            .admit_root(&root, cancel)
            .map_err(map_platform_error)?;
        admission
            .validate_for_root(&root)
            .map_err(|_| DetailRescanError::Unavailable)?;
        if &admission.root_locator != native_root {
            return Err(DetailRescanError::IdentityMismatch);
        }

        let RootAdmission {
            root_locator,
            metadata: root_metadata,
            directory: root_handle,
            ..
        } = admission;
        validate_expected_directory(
            &request.directory_locator.scan_root,
            &root_metadata,
            request.source_root_identity,
        )?;
        let observed_root_component =
            native_path_component(request.source_root_identity, &root_metadata);
        let observed_root_locator = NativeLocatorEvidence {
            scan_root: observed_root_component.clone(),
            scan_root_absolute_path: Some(root_locator.clone()),
            parent_reopen_recipe: Vec::new(),
            entry: observed_root_component.clone(),
        };
        let observed_root = scanned_entry_from_metadata(
            request.source_scan_id,
            &root_metadata,
            request.source_root_identity.clone(),
            observed_root_locator,
            complete_coverage(),
        );

        if request.source_directory_identity.entry_id == request.source_root_identity.entry_id {
            return Ok(ReopenedTarget {
                root_metadata: root_metadata.clone(),
                target_metadata: root_metadata,
                target_handle: root_handle,
                observed_root: observed_root.clone(),
                observed_directory: observed_root,
                observed_locator: NativeLocatorEvidence {
                    scan_root: observed_root_component.clone(),
                    scan_root_absolute_path: Some(root_locator),
                    parent_reopen_recipe: Vec::new(),
                    entry: observed_root_component,
                },
            });
        }

        let mut current_handle = root_handle;
        let mut current_path = root_metadata.path.clone();
        let mut observed_parent_recipe = vec![observed_root_component.clone()];
        let mut target_metadata = None;
        let mut target_component = None;

        let lineage = request
            .directory_locator
            .parent_reopen_recipe
            .iter()
            .skip(1)
            .map(|component| (component, false))
            .chain(std::iter::once((&request.directory_locator.entry, true)));
        for (expected, is_target) in lineage {
            let child = DirectoryEntryRecord::from_parent_and_name(
                &current_path,
                expected.native_basename.clone(),
            )
            .map_err(|_| DetailRescanError::InvalidRequest)?;
            let walked = inspect_bound_child(
                &self.platform,
                &current_handle,
                &current_path,
                &child,
                cancel,
            )
            .map_err(map_platform_error)?;
            let opened = match walked {
                WalkEntry::Directory(opened) => opened,
                WalkEntry::Link(_) => return Err(DetailRescanError::SymlinkOrReparse),
                WalkEntry::Boundary(boundary) => return Err(map_boundary(&boundary.kind)),
                WalkEntry::Error(error) => return Err(map_walk_error(error.kind)),
                WalkEntry::File(_) => return Err(DetailRescanError::IdentityMismatch),
            };
            let expected_identity = if is_target {
                request.source_directory_identity.clone()
            } else {
                identity_from_component(expected, request.source_root_identity)
            };
            validate_expected_directory(expected, &opened.metadata, &expected_identity)?;
            require_same_mount(&self.platform, &root_metadata, &opened.metadata)?;
            let observed_identity = expected_identity;
            let observed_component = native_path_component(&observed_identity, &opened.metadata);
            current_path = opened.metadata.path.clone();
            current_handle = opened.handle;
            if is_target {
                target_metadata = Some(opened.metadata);
                target_component = Some(observed_component);
            } else {
                observed_parent_recipe.push(observed_component);
            }
        }

        let target_metadata = target_metadata.ok_or(DetailRescanError::InvalidRequest)?;
        let target_component = target_component.ok_or(DetailRescanError::InvalidRequest)?;
        let observed_locator = NativeLocatorEvidence {
            scan_root: observed_root_component,
            scan_root_absolute_path: Some(root_locator),
            parent_reopen_recipe: observed_parent_recipe,
            entry: target_component,
        };
        let observed_directory = scanned_entry_from_metadata(
            request.source_scan_id,
            &target_metadata,
            request.source_directory_identity.clone(),
            observed_locator.clone(),
            complete_coverage(),
        );
        Ok(ReopenedTarget {
            root_metadata,
            target_metadata,
            target_handle: current_handle,
            observed_root,
            observed_directory,
            observed_locator,
        })
    }

    fn scan_target_directory(
        &self,
        request: &DetailRescanRequest<'_>,
        reopened: ReopenedTarget<P::DirectoryHandle>,
        ids: &mut DetailEntryIdAllocator,
        cancel: &CancellationToken,
    ) -> Result<(Vec<ScannedEntry>, DirectoryAggregate), DetailRescanError> {
        let ReopenedTarget {
            root_metadata,
            target_metadata,
            target_handle,
            observed_locator,
            ..
        } = reopened;
        let mut rows = Vec::new();
        let mut aggregate = TargetAggregateState::new();
        let mut current = TargetDirectory {
            path: target_metadata.path,
            handle: target_handle,
            identity: request.source_directory_identity.clone(),
            parent_reopen_recipe: observed_locator.parent_reopen_recipe,
            native_component: observed_locator.entry,
        };
        let mut nested_directories = Vec::new();

        {
            if cancel.is_cancelled() {
                return Err(DetailRescanError::Cancelled);
            }
            let mut consumed_entries = 0usize;
            let mut consumed_bytes = 0usize;
            loop {
                let remaining_entries = self
                    .limits
                    .max_directory_entries
                    .saturating_sub(consumed_entries);
                let remaining_bytes = self
                    .limits
                    .max_directory_bytes
                    .saturating_sub(consumed_bytes);
                if remaining_entries == 0 || remaining_bytes == 0 {
                    return Err(DetailRescanError::ResourceLimit);
                }
                let batch_limits = DirectoryReadLimits {
                    max_batch_entries: self
                        .limits
                        .max_directory_batch_entries
                        .min(remaining_entries),
                    max_batch_bytes: self.limits.max_directory_batch_bytes.min(remaining_bytes),
                };
                if batch_limits.max_batch_entries == 0 || batch_limits.max_batch_bytes == 0 {
                    return Err(DetailRescanError::ResourceLimit);
                }
                let batch = self
                    .platform
                    .enumerate_children(&mut current.handle, cancel, batch_limits)
                    .map_err(map_platform_error)?;
                if batch.entries.is_empty() && !batch.end_of_directory {
                    return Err(DetailRescanError::Unavailable);
                }
                let batch_bytes = batch.entries.iter().try_fold(0usize, |total, child| {
                    child
                        .estimated_retained_bytes()
                        .and_then(|bytes| total.checked_add(bytes))
                });
                if batch.entries.len() > batch_limits.max_batch_entries
                    || batch_bytes.is_none_or(|bytes| bytes > batch_limits.max_batch_bytes)
                {
                    return Err(DetailRescanError::Unavailable);
                }
                consumed_entries = consumed_entries
                    .checked_add(batch.entries.len())
                    .ok_or(DetailRescanError::ResourceLimit)?;
                consumed_bytes = consumed_bytes
                    .checked_add(batch_bytes.expect("batch bytes checked above"))
                    .ok_or(DetailRescanError::ResourceLimit)?;

                for child in batch.entries {
                    let walked = inspect_bound_child(
                        &self.platform,
                        &current.handle,
                        &current.path,
                        &child,
                        cancel,
                    )
                    .map_err(map_platform_error)?;
                    let entry_id = ids.allocate()?;
                    aggregate.note_entry()?;
                    if aggregate.recursive_entry_count > self.limits.max_visited_entries as u128 {
                        return Err(DetailRescanError::ResourceLimit);
                    }
                    aggregate.note_direct_child()?;
                    if rows.len() >= request.max_rows
                        || rows.len() >= self.limits.max_retained_entries
                    {
                        return Err(DetailRescanError::ResourceLimit);
                    }

                    match walked {
                        WalkEntry::Directory(opened) => {
                            require_same_mount(&self.platform, &root_metadata, &opened.metadata)?;
                            let identity = scan_object_identity(
                                entry_id,
                                request.source_root_identity.entry_id.clone(),
                                Some(current.identity.entry_id.clone()),
                                &opened.metadata,
                            );
                            if !identity_is_known(&identity) {
                                return Err(DetailRescanError::IdentityUnavailable);
                            }
                            let native_component =
                                native_path_component(&identity, &opened.metadata);
                            let parent_reopen_recipe = current.parent_recipe_with_self();
                            rows.push(scanned_entry_from_metadata(
                                request.source_scan_id,
                                &opened.metadata,
                                identity.clone(),
                                native_locator_evidence(
                                    request
                                        .directory_locator
                                        .scan_root_absolute_path
                                        .as_ref()
                                        .ok_or(DetailRescanError::InvalidRequest)?,
                                    &request.directory_locator.scan_root,
                                    &parent_reopen_recipe,
                                    &native_component,
                                ),
                                complete_coverage(),
                            ));
                            if nested_directories.len() >= self.limits.max_frontier_entries {
                                return Err(DetailRescanError::ResourceLimit);
                            }
                            nested_directories.push(NestedDirectory {
                                path: opened.metadata.path,
                                handle: opened.handle,
                                identity,
                            });
                        }
                        WalkEntry::File(metadata) => {
                            require_same_mount(&self.platform, &root_metadata, &metadata)?;
                            aggregate.note_file(&metadata);
                            let identity = scan_object_identity(
                                entry_id,
                                request.source_root_identity.entry_id.clone(),
                                Some(current.identity.entry_id.clone()),
                                &metadata,
                            );
                            if !identity_is_known(&identity) {
                                return Err(DetailRescanError::IdentityUnavailable);
                            }
                            let component = native_path_component(&identity, &metadata);
                            rows.push(scanned_entry_from_metadata(
                                request.source_scan_id,
                                &metadata,
                                identity,
                                native_locator_evidence(
                                    request
                                        .directory_locator
                                        .scan_root_absolute_path
                                        .as_ref()
                                        .ok_or(DetailRescanError::InvalidRequest)?,
                                    &request.directory_locator.scan_root,
                                    &current.parent_recipe_with_self(),
                                    &component,
                                ),
                                complete_coverage(),
                            ));
                        }
                        WalkEntry::Link(metadata) => {
                            require_same_mount(&self.platform, &root_metadata, &metadata)?;
                            let identity = scan_object_identity(
                                entry_id,
                                request.source_root_identity.entry_id.clone(),
                                Some(current.identity.entry_id.clone()),
                                &metadata,
                            );
                            if !identity_is_known(&identity) {
                                return Err(DetailRescanError::IdentityUnavailable);
                            }
                            let component = native_path_component(&identity, &metadata);
                            rows.push(scanned_entry_from_metadata(
                                request.source_scan_id,
                                &metadata,
                                identity,
                                native_locator_evidence(
                                    request
                                        .directory_locator
                                        .scan_root_absolute_path
                                        .as_ref()
                                        .ok_or(DetailRescanError::InvalidRequest)?,
                                    &request.directory_locator.scan_root,
                                    &current.parent_recipe_with_self(),
                                    &component,
                                ),
                                complete_coverage(),
                            ));
                        }
                        WalkEntry::Boundary(boundary) => {
                            return Err(map_boundary(&boundary.kind));
                        }
                        WalkEntry::Error(error) => {
                            return Err(map_walk_error(error.kind));
                        }
                    }
                }
                if batch.end_of_directory {
                    break;
                }
            }
        }

        // Descendants are consumed only to prove and compute the target's complete recursive
        // aggregate. They never become detail rows.
        self.scan_nested_directories(
            &root_metadata,
            &mut nested_directories,
            &mut aggregate,
            ids,
            cancel,
        )?;

        Ok((
            rows,
            aggregate.finish(
                request.source_scan_id,
                &request.source_directory_identity.entry_id,
                request.revision,
            ),
        ))
    }

    fn scan_nested_directories(
        &self,
        root_metadata: &EntryMetadata,
        initial: &mut Vec<NestedDirectory<P::DirectoryHandle>>,
        aggregate: &mut TargetAggregateState,
        ids: &mut DetailEntryIdAllocator,
        cancel: &CancellationToken,
    ) -> Result<(), DetailRescanError> {
        let mut frontier: VecDeque<_> = initial.drain(..).collect();
        let mut visited = 0usize;
        while let Some(mut current) = frontier.pop_front() {
            visited = visited
                .checked_add(1)
                .ok_or(DetailRescanError::ResourceLimit)?;
            if visited > self.limits.max_visited_entries || cancel.is_cancelled() {
                return Err(if cancel.is_cancelled() {
                    DetailRescanError::Cancelled
                } else {
                    DetailRescanError::ResourceLimit
                });
            }
            let mut consumed_entries = 0usize;
            let mut consumed_bytes = 0usize;
            loop {
                let batch_limits = DirectoryReadLimits {
                    max_batch_entries: self.limits.max_directory_batch_entries.min(
                        self.limits
                            .max_directory_entries
                            .saturating_sub(consumed_entries),
                    ),
                    max_batch_bytes: self.limits.max_directory_batch_bytes.min(
                        self.limits
                            .max_directory_bytes
                            .saturating_sub(consumed_bytes),
                    ),
                };
                if batch_limits.max_batch_entries == 0 || batch_limits.max_batch_bytes == 0 {
                    return Err(DetailRescanError::ResourceLimit);
                }
                let batch = self
                    .platform
                    .enumerate_children(&mut current.handle, cancel, batch_limits)
                    .map_err(map_platform_error)?;
                if batch.entries.is_empty() && !batch.end_of_directory {
                    return Err(DetailRescanError::Unavailable);
                }
                let batch_bytes = batch.entries.iter().try_fold(0usize, |total, child| {
                    child
                        .estimated_retained_bytes()
                        .and_then(|bytes| total.checked_add(bytes))
                });
                if batch.entries.len() > batch_limits.max_batch_entries
                    || batch_bytes.is_none_or(|bytes| bytes > batch_limits.max_batch_bytes)
                {
                    return Err(DetailRescanError::Unavailable);
                }
                consumed_entries = consumed_entries
                    .checked_add(batch.entries.len())
                    .ok_or(DetailRescanError::ResourceLimit)?;
                consumed_bytes = consumed_bytes
                    .checked_add(batch_bytes.expect("batch bytes checked"))
                    .ok_or(DetailRescanError::ResourceLimit)?;
                for child in batch.entries {
                    let walked = inspect_bound_child(
                        &self.platform,
                        &current.handle,
                        &current.path,
                        &child,
                        cancel,
                    )
                    .map_err(map_platform_error)?;
                    let entry_id = ids.allocate()?;
                    aggregate.note_entry()?;
                    if aggregate.recursive_entry_count > self.limits.max_visited_entries as u128 {
                        return Err(DetailRescanError::ResourceLimit);
                    }
                    match walked {
                        WalkEntry::Directory(opened) => {
                            require_same_mount(&self.platform, root_metadata, &opened.metadata)?;
                            if frontier.len() >= self.limits.max_frontier_entries {
                                return Err(DetailRescanError::ResourceLimit);
                            }
                            let identity = scan_object_identity(
                                entry_id,
                                current.identity.scan_root_id.clone(),
                                Some(current.identity.entry_id.clone()),
                                &opened.metadata,
                            );
                            if !identity_is_known(&identity) {
                                return Err(DetailRescanError::IdentityUnavailable);
                            }
                            frontier.push_back(NestedDirectory {
                                path: opened.metadata.path,
                                handle: opened.handle,
                                identity,
                            });
                        }
                        WalkEntry::File(metadata) => {
                            require_same_mount(&self.platform, root_metadata, &metadata)?;
                            aggregate.note_file(&metadata);
                        }
                        WalkEntry::Link(metadata) => {
                            require_same_mount(&self.platform, root_metadata, &metadata)?;
                        }
                        WalkEntry::Boundary(boundary) => {
                            return Err(map_boundary(&boundary.kind));
                        }
                        WalkEntry::Error(error) => return Err(map_walk_error(error.kind)),
                    }
                }
                if batch.end_of_directory {
                    break;
                }
            }
        }
        Ok(())
    }
}

struct TargetDirectory<D> {
    path: PathBuf,
    handle: D,
    identity: ScanObjectIdentity,
    parent_reopen_recipe: Vec<NativePathComponent>,
    native_component: NativePathComponent,
}

struct NestedDirectory<D> {
    path: PathBuf,
    handle: D,
    identity: ScanObjectIdentity,
}

impl<D> TargetDirectory<D> {
    fn parent_recipe_with_self(&self) -> Vec<NativePathComponent> {
        let mut recipe = self.parent_reopen_recipe.clone();
        recipe.push(self.native_component.clone());
        recipe
    }
}

struct TargetAggregateState {
    direct_child_count: u128,
    recursive_entry_count: u128,
    apparent_logical_bytes: EvidenceAccumulator,
    unique_logical_bytes: EvidenceAccumulator,
    allocated_bytes: EvidenceAccumulator,
    reclaimable_bytes: EvidenceAccumulator,
    counted_hard_links: BTreeSet<HardLinkKey>,
}

impl TargetAggregateState {
    fn new() -> Self {
        Self {
            direct_child_count: 0,
            recursive_entry_count: 0,
            apparent_logical_bytes: EvidenceAccumulator::known_zero(),
            unique_logical_bytes: EvidenceAccumulator::known_zero(),
            allocated_bytes: EvidenceAccumulator::known_zero(),
            reclaimable_bytes: EvidenceAccumulator::known_zero(),
            counted_hard_links: BTreeSet::new(),
        }
    }

    fn note_entry(&mut self) -> Result<(), DetailRescanError> {
        self.recursive_entry_count = self
            .recursive_entry_count
            .checked_add(1)
            .ok_or(DetailRescanError::ResourceLimit)?;
        Ok(())
    }

    fn note_direct_child(&mut self) -> Result<(), DetailRescanError> {
        self.direct_child_count = self
            .direct_child_count
            .checked_add(1)
            .ok_or(DetailRescanError::ResourceLimit)?;
        Ok(())
    }

    fn note_file(&mut self, metadata: &EntryMetadata) {
        self.apparent_logical_bytes.add(&metadata.logical_bytes);
        let multiple_links = matches!(
            metadata.hard_link_count,
            EvidenceValue::Known { value } if value.0 > 1
        );
        match metadata.hard_link_key.as_ref() {
            Some(key) => {
                let first = self.counted_hard_links.insert(key.clone());
                if first {
                    self.unique_logical_bytes.add(&metadata.logical_bytes);
                    self.allocated_bytes.add(&metadata.allocated_bytes);
                }
                if multiple_links {
                    self.reclaimable_bytes = EvidenceAccumulator::Unknown {
                        reason: ReasonCode::UnknownIdentity,
                    };
                } else if first {
                    self.reclaimable_bytes.add(&metadata.allocated_bytes);
                }
            }
            None => {
                self.unique_logical_bytes = EvidenceAccumulator::Unknown {
                    reason: ReasonCode::UnknownIdentity,
                };
                self.allocated_bytes = EvidenceAccumulator::Unknown {
                    reason: ReasonCode::UnknownIdentity,
                };
                self.reclaimable_bytes = EvidenceAccumulator::Unknown {
                    reason: ReasonCode::UnknownIdentity,
                };
            }
        }
    }

    fn finish(
        self,
        scan_id: &ScanId,
        directory_id: &ScanEntryId,
        revision: DecimalU128,
    ) -> DirectoryAggregate {
        DirectoryAggregate {
            scan_id: scan_id.clone(),
            directory_identity: directory_id.to_string(),
            revision,
            apparent_logical_bytes: self.apparent_logical_bytes.into_value(true),
            unique_logical_bytes: self.unique_logical_bytes.into_value(true),
            filesystem_reported_allocated_bytes: self.allocated_bytes.into_value(true),
            potentially_reclaimable_bytes: self.reclaimable_bytes.into_value(true),
            direct_child_count: known_count(self.direct_child_count),
            recursive_entry_count: known_count(self.recursive_entry_count),
            coverage: Coverage {
                state: CoverageState::Complete,
                complete: true,
                incomplete_reasons: Vec::new(),
                details_lost: false,
                provenance: super::live_provenance(),
            },
            arithmetic_state: ArithmeticState::Exact,
        }
    }
}

struct ReopenedTarget<D> {
    root_metadata: EntryMetadata,
    target_metadata: EntryMetadata,
    target_handle: D,
    observed_root: ScannedEntry,
    observed_directory: ScannedEntry,
    observed_locator: NativeLocatorEvidence,
}

fn component_matches_identity(
    component: &NativePathComponent,
    identity: &ScanObjectIdentity,
) -> bool {
    component.entry_id == identity.entry_id
        && component.parent_id == identity.parent_id
        && component.platform_file_identity == identity.platform_file_identity
        && component.filesystem_object_domain_identity == identity.filesystem_object_domain_identity
        && component.volume_or_mount_identity == identity.volume_or_mount_identity
}

fn identity_from_component(
    component: &NativePathComponent,
    root: &ScanObjectIdentity,
) -> ScanObjectIdentity {
    ScanObjectIdentity {
        entry_id: component.entry_id.clone(),
        scan_root_id: root.entry_id.clone(),
        parent_id: component.parent_id.clone(),
        platform_file_identity: component.platform_file_identity.clone(),
        filesystem_object_domain_identity: component.filesystem_object_domain_identity.clone(),
        volume_or_mount_identity: component.volume_or_mount_identity.clone(),
    }
}

fn validate_expected_directory(
    expected: &NativePathComponent,
    metadata: &EntryMetadata,
    expected_identity: &ScanObjectIdentity,
) -> Result<(), DetailRescanError> {
    if metadata.kind == EntryKind::Symlink || metadata.kind == EntryKind::ReparsePoint {
        return Err(DetailRescanError::SymlinkOrReparse);
    }
    if metadata.kind != EntryKind::Directory || expected.object_type != ObjectType::Directory {
        return Err(DetailRescanError::IdentityMismatch);
    }
    let observed = scan_object_identity(
        expected_identity.entry_id.clone(),
        expected_identity.scan_root_id.clone(),
        expected_identity.parent_id.clone(),
        metadata,
    );
    if !identity_is_known(&observed) {
        return Err(DetailRescanError::IdentityUnavailable);
    }
    if observed.volume_or_mount_identity != expected_identity.volume_or_mount_identity {
        return Err(DetailRescanError::MountChanged);
    }
    if metadata.file_name != expected.native_basename
        || observed.platform_file_identity != expected_identity.platform_file_identity
        || observed.filesystem_object_domain_identity
            != expected_identity.filesystem_object_domain_identity
    {
        return Err(DetailRescanError::IdentityMismatch);
    }
    Ok(())
}

fn identity_is_known(identity: &ScanObjectIdentity) -> bool {
    matches!(
        identity.platform_file_identity,
        IdentityEvidence::Known { .. }
    ) && matches!(
        identity.filesystem_object_domain_identity,
        IdentityEvidence::Known { .. }
    ) && matches!(
        identity.volume_or_mount_identity,
        IdentityEvidence::Known { .. }
    )
}

fn require_same_mount<P: PlatformScanner>(
    platform: &P,
    root: &EntryMetadata,
    entry: &EntryMetadata,
) -> Result<(), DetailRescanError> {
    if root.mount_identity.is_none() || entry.mount_identity.is_none() {
        return Err(DetailRescanError::IdentityUnavailable);
    }
    match platform.is_same_mount(root, entry) {
        Ok(true) => Ok(()),
        Ok(false) => Err(DetailRescanError::MountChanged),
        Err(_) => Err(DetailRescanError::IdentityUnavailable),
    }
}

fn native_absolute_path_buf(path: &NativeAbsolutePath) -> Result<PathBuf, DetailRescanError> {
    path.validate_for_current_platform()
        .map_err(|_| DetailRescanError::InvalidRequest)?;
    #[cfg(unix)]
    if let NativeAbsolutePath::UnixBytes(bytes) = path {
        return Ok(PathBuf::from(OsString::from_vec(bytes.clone())));
    }
    #[cfg(windows)]
    if let NativeAbsolutePath::WindowsUtf16(units) = path {
        return Ok(PathBuf::from(OsString::from_wide(units)));
    }
    Err(DetailRescanError::InvalidRequest)
}

fn map_platform_error(error: PlatformError) -> DetailRescanError {
    match error {
        PlatformError::Cancelled => DetailRescanError::Cancelled,
        PlatformError::ResourceLimit(_) => DetailRescanError::ResourceLimit,
        PlatformError::Unsupported(_) | PlatformError::InvalidDirectoryEntry { .. } => {
            DetailRescanError::Unavailable
        }
        PlatformError::RootRejected(_) => DetailRescanError::IdentityMismatch,
        PlatformError::Io { io_kind, .. } => match io_kind {
            Some(std::io::ErrorKind::NotFound) => DetailRescanError::IdentityMismatch,
            Some(std::io::ErrorKind::Interrupted) => DetailRescanError::Cancelled,
            _ => DetailRescanError::IdentityUnavailable,
        },
    }
}

fn map_boundary(kind: &BoundaryKind) -> DetailRescanError {
    match kind {
        BoundaryKind::RootSymlink | BoundaryKind::Symlink | BoundaryKind::ReparsePoint => {
            DetailRescanError::SymlinkOrReparse
        }
        BoundaryKind::Mount => DetailRescanError::MountChanged,
        BoundaryKind::ResourceLimit => DetailRescanError::ResourceLimit,
        BoundaryKind::Cancelled => DetailRescanError::Cancelled,
        BoundaryKind::OtherFilesystem => DetailRescanError::Unavailable,
    }
}

fn map_walk_error(kind: ErrorKind) -> DetailRescanError {
    match kind {
        ErrorKind::NotFound => DetailRescanError::IdentityMismatch,
        ErrorKind::Interrupted => DetailRescanError::Cancelled,
        ErrorKind::ResourceLimit => DetailRescanError::ResourceLimit,
        ErrorKind::Unsupported => DetailRescanError::Unavailable,
        ErrorKind::AccessDenied | ErrorKind::InvalidInput | ErrorKind::Io => {
            DetailRescanError::IdentityUnavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_ids_descend_in_the_disjoint_upper_half() {
        let scan_id = ScanId::new("detail-id-test");
        let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();

        assert_eq!(
            ids.allocate().unwrap(),
            ScanEntryId::for_scan_ordinal(&scan_id, u128::MAX).unwrap()
        );
        assert_eq!(
            ids.allocate().unwrap(),
            ScanEntryId::for_scan_ordinal(&scan_id, u128::MAX - 1).unwrap()
        );
    }

    #[test]
    fn reserving_existing_detail_ids_never_reuses_them() {
        let scan_id = ScanId::new("detail-reserve-test");
        let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();
        ids.reserve(&ScanEntryId::for_scan_ordinal(&scan_id, u128::MAX - 7).unwrap())
            .unwrap();

        assert_eq!(
            ids.allocate().unwrap(),
            ScanEntryId::for_scan_ordinal(&scan_id, u128::MAX - 8).unwrap()
        );
    }

    #[test]
    fn lower_half_reservations_do_not_move_the_detail_cursor() {
        let scan_id = ScanId::new("detail-half-test");
        let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();
        ids.reserve(&ScanEntryId::for_scan_ordinal(&scan_id, DETAIL_SCAN_MIN_ORDINAL - 1).unwrap())
            .unwrap();

        assert_eq!(
            ids.allocate().unwrap(),
            ScanEntryId::for_scan_ordinal(&scan_id, u128::MAX).unwrap()
        );
    }

    #[test]
    fn detail_id_allocator_stops_at_the_upper_half_boundary() {
        let scan_id = ScanId::new("detail-exhaustion-test");
        let mut ids = DetailEntryIdAllocator {
            scan_id: scan_id.clone(),
            next_ordinal: Some(DETAIL_SCAN_MIN_ORDINAL),
        };

        assert_eq!(
            ids.allocate().unwrap(),
            ScanEntryId::for_scan_ordinal(&scan_id, DETAIL_SCAN_MIN_ORDINAL).unwrap()
        );
        assert_eq!(ids.allocate(), Err(DetailRescanError::ResourceLimit));
    }

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    #[test]
    fn live_detail_rescan_returns_only_direct_rows_and_complete_recursive_aggregate() {
        use std::fs;

        use crate::{HostPlatformScanner, Scanner, ScannerOptions};
        use sweepx_platform::{CancellationToken, ScanResourceLimits, ScanRoot, known_u128};

        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        let target = root.join("target");
        let nested = target.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(target.join("direct.txt"), b"1234").unwrap();
        fs::write(nested.join("deep.txt"), b"123456").unwrap();

        let scan_id = ScanId::new("detail-live-test");
        let summary = Scanner::new(
            HostPlatformScanner::new(),
            ScannerOptions {
                scan_id: scan_id.clone(),
                ..ScannerOptions::default()
            },
        )
        .scan(
            &[ScanRoot::new(root.clone()).unwrap()],
            &CancellationToken::new(),
        )
        .unwrap();
        let root_entry = &summary.roots[0];
        let target_entry = summary
            .entries
            .iter()
            .find(|entry| entry.display_path == target.display().to_string())
            .unwrap();
        let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();
        for entry in summary.roots.iter().chain(summary.entries.iter()) {
            ids.reserve(&entry.identity.as_ref().unwrap().entry_id)
                .unwrap();
        }
        let result =
            DetailRescanner::new(HostPlatformScanner::new(), ScanResourceLimits::default())
                .rescan(
                    DetailRescanRequest {
                        source_scan_id: &scan_id,
                        source_root_identity: root_entry.identity.as_ref().unwrap(),
                        source_directory_identity: target_entry.identity.as_ref().unwrap(),
                        directory_locator: target_entry
                            .executable_native_locator()
                            .unwrap()
                            .unwrap(),
                        revision: DecimalU128::new(7),
                        max_rows: 8,
                    },
                    &mut ids,
                    &CancellationToken::new(),
                )
                .unwrap();

        assert_eq!(result.rows.len(), 2);
        assert!(result.rows.iter().any(|entry| {
            entry.native_basename == test_native_name("direct.txt")
                && entry.object_type == ObjectType::File
        }));
        assert!(result.rows.iter().any(|entry| {
            entry.native_basename == test_native_name("nested")
                && entry.object_type == ObjectType::Directory
        }));
        assert!(
            result
                .rows
                .iter()
                .all(|entry| entry.native_basename != test_native_name("deep.txt"))
        );
        assert_eq!(result.aggregate.revision, DecimalU128::new(7));
        assert_eq!(result.aggregate.direct_child_count, known_count(2));
        assert_eq!(result.aggregate.recursive_entry_count, known_count(3));
        assert_eq!(result.aggregate.apparent_logical_bytes, known_u128(10));
        assert!(result.aggregate.coverage.complete);
        assert_eq!(result.aggregate.arithmetic_state, ArithmeticState::Exact);
    }

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    #[test]
    fn live_detail_rescan_rejects_more_direct_rows_than_requested() {
        use std::fs;

        use crate::{HostPlatformScanner, Scanner, ScannerOptions};
        use sweepx_platform::{CancellationToken, ScanResourceLimits, ScanRoot};

        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("one"), b"1").unwrap();
        fs::write(root.join("two"), b"2").unwrap();
        let scan_id = ScanId::new("detail-limit-test");
        let summary = Scanner::new(
            HostPlatformScanner::new(),
            ScannerOptions {
                scan_id: scan_id.clone(),
                ..ScannerOptions::default()
            },
        )
        .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
        .unwrap();
        let root_entry = &summary.roots[0];
        let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();

        let error = DetailRescanner::new(HostPlatformScanner::new(), ScanResourceLimits::default())
            .rescan(
                DetailRescanRequest {
                    source_scan_id: &scan_id,
                    source_root_identity: root_entry.identity.as_ref().unwrap(),
                    source_directory_identity: root_entry.identity.as_ref().unwrap(),
                    directory_locator: root_entry.executable_native_locator().unwrap().unwrap(),
                    revision: DecimalU128::new(2),
                    max_rows: 1,
                },
                &mut ids,
                &CancellationToken::new(),
            )
            .unwrap_err();

        assert_eq!(error, DetailRescanError::ResourceLimit);
    }

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    #[test]
    fn live_detail_rescan_rejects_a_replaced_directory_identity() {
        use std::fs;

        use crate::{HostPlatformScanner, Scanner, ScannerOptions};
        use sweepx_platform::{CancellationToken, ScanResourceLimits, ScanRoot};

        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        let target = root.join("target");
        fs::create_dir_all(&target).unwrap();
        let scan_id = ScanId::new("detail-replacement-test");
        let summary = Scanner::new(
            HostPlatformScanner::new(),
            ScannerOptions {
                scan_id: scan_id.clone(),
                ..ScannerOptions::default()
            },
        )
        .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
        .unwrap();
        let root_entry = &summary.roots[0];
        let target_entry = summary
            .entries
            .iter()
            .find(|entry| entry.native_basename == test_native_name("target"))
            .unwrap();
        let locator = target_entry
            .executable_native_locator()
            .unwrap()
            .unwrap()
            .clone();
        let target_identity = target_entry.identity.as_ref().unwrap().clone();
        fs::rename(&target, target.with_extension("old")).unwrap();
        fs::create_dir(&target).unwrap();
        let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();

        let error = DetailRescanner::new(HostPlatformScanner::new(), ScanResourceLimits::default())
            .rescan(
                DetailRescanRequest {
                    source_scan_id: &scan_id,
                    source_root_identity: root_entry.identity.as_ref().unwrap(),
                    source_directory_identity: &target_identity,
                    directory_locator: &locator,
                    revision: DecimalU128::new(2),
                    max_rows: 8,
                },
                &mut ids,
                &CancellationToken::new(),
            )
            .unwrap_err();

        assert_eq!(error, DetailRescanError::IdentityMismatch);
    }

    #[cfg(all(target_os = "linux", feature = "platform-linux"))]
    #[test]
    fn live_detail_rescan_ignores_a_forged_display_path() {
        use std::fs;

        use crate::{HostPlatformScanner, Scanner, ScannerOptions};
        use sweepx_platform::{CancellationToken, ScanResourceLimits, ScanRoot};

        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("inside"), b"x").unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("outside-only"), b"x").unwrap();
        let scan_id = ScanId::new("detail-display-test");
        let summary = Scanner::new(
            HostPlatformScanner::new(),
            ScannerOptions {
                scan_id: scan_id.clone(),
                ..ScannerOptions::default()
            },
        )
        .scan(&[ScanRoot::new(root).unwrap()], &CancellationToken::new())
        .unwrap();
        let mut forged_root = summary.roots[0].clone();
        forged_root.display_path = outside.display().to_string();
        let mut ids = DetailEntryIdAllocator::new(scan_id.clone()).unwrap();

        let result =
            DetailRescanner::new(HostPlatformScanner::new(), ScanResourceLimits::default())
                .rescan(
                    DetailRescanRequest {
                        source_scan_id: &scan_id,
                        source_root_identity: forged_root.identity.as_ref().unwrap(),
                        source_directory_identity: forged_root.identity.as_ref().unwrap(),
                        directory_locator: forged_root
                            .executable_native_locator()
                            .unwrap()
                            .unwrap(),
                        revision: DecimalU128::new(2),
                        max_rows: 8,
                    },
                    &mut ids,
                    &CancellationToken::new(),
                )
                .unwrap();

        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].native_basename, test_native_name("inside"));
    }

    #[cfg(unix)]
    fn test_native_name(name: &str) -> sweepx_model::NativeName {
        sweepx_model::NativeName::unix(name.as_bytes().to_vec())
    }
}
