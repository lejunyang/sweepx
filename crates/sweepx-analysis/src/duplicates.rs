//! Explicit content analysis. A matching hash is an observation, never a deletion decision.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
use sweepx_model::{DecimalU128, EvidenceValue, IdentityEvidence, ObjectType, ScannedEntry};
use sweepx_platform::{
    BoundedRegularFileReadError, CancellationToken, PlatformScanner, RegularFileObservation,
    RegularFileStreamResult,
};
use sweepx_scanner::{DetailRescanError, DetailRescanner, FileContentError, FileContentRequest};

/// Finite bounds for one explicit content analysis across all scan roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateOptions {
    /// Inclusive logical-size threshold. Zero-byte files are analyzed only when this is zero.
    pub minimum_logical_bytes: DecimalU128,
    /// Maximum distinct retained objects, in 1..=100,000.
    pub max_files: usize,
    /// Owned-data admission estimate in 1..=64 MiB, including stage indexes; not exact RSS.
    pub max_retained_bytes: usize,
    /// Payload-range budget charged before every attempted read, including failed reads.
    pub max_read_bytes: u64,
    /// Largest admitted logical file, including full hashing, at most signed 64-bit length.
    pub max_file_bytes: u64,
    /// Maximum requested content-stage ranges, including zero-byte final revalidation.
    /// Backends may also perform bounded metadata probes when opening these ranges.
    pub max_read_operations: usize,
    /// Prefix/suffix sample bound, in 1..=64 KiB; samples cannot prove duplicate contents.
    pub sample_bytes: u64,
    /// Cooperative content-phase deadline in milliseconds, checked between native calls/chunks.
    pub max_duration_ms: u64,
}
impl Default for DuplicateOptions {
    fn default() -> Self {
        Self {
            minimum_logical_bytes: 1024.into(),
            max_files: 20_000,
            max_retained_bytes: 64 * 1024 * 1024,
            max_read_bytes: 8 * 1024 * 1024 * 1024,
            max_file_bytes: 8 * 1024 * 1024 * 1024,
            max_read_operations: 80_000,
            sample_bytes: 4096,
            max_duration_ms: 30_000,
        }
    }
}
/// Invalid bounds are rejected before collecting metadata or accessing content.
#[derive(Debug, thiserror::Error)]
#[error(
    "duplicate analysis limits must be finite: files 1..=100000, retained bytes 1..=64 MiB, samples 1..=64 KiB, operations 1..=400000, duration 1..=300000 ms, positive signed-64-bit read limits"
)]
pub struct DuplicateOptionsError;

/// Why an explicit content analysis cannot cover all eligible ordinary files.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateIncompleteReason {
    /// Metadata traversal omitted part of the selected no-follow scope.
    TraversalIncomplete,
    /// Ordinary-file length or native object identity was missing.
    MetadataUnavailable,
    /// Files or stage metadata did not fit the retention budget.
    RetentionLimit,
    /// A file, range, operation count or cumulative IO limit was exhausted.
    ReadLimit,
    /// Cooperative content deadline elapsed; an individual native call is not preempted.
    Deadline,
    /// Caller cancellation stops new reads and preserves only already completed groups.
    Cancelled,
    /// File identity, mount, length or change stamp changed/refused validation.
    ChangedOrUnbound,
    /// A cloud/provider/offline boundary prevented safe local content access.
    ProviderOrOffline,
    /// Other native read refusal or error; no partial hash is accepted.
    ReadFailed,
}
/// Distinct ordinary-file objects with the same logical length and complete SHA-256.
/// No preferred keeper, automatic deletion, allocation sum or reclaimable-space claim is made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateGroup {
    /// Raw full-content SHA-256 in lowercase hexadecimal; samples are not reported as proof.
    pub sha256: String,
    /// Shared exact logical length.
    pub logical_bytes: DecimalU128,
    /// Source observations of distinct native objects, with allocation/coverage evidence intact.
    pub files: Vec<ScannedEntry>,
}
/// Read-only duplicate observations, separate from junk candidates and large-file rankings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateReport {
    /// Exact thresholds and limits used.
    pub options: DuplicateOptions,
    /// Only groups with at least two complete, revalidated hashes.
    pub groups: Vec<DuplicateGroup>,
    /// Ordinary-file path observations, before threshold or alias exclusion.
    pub observed_files: DecimalU128,
    /// Distinct native objects admitted to the bounded metadata index.
    pub retained_files: DecimalU128,
    /// Same-object aliases/repeated root observations excluded from duplicate comparisons.
    pub hard_link_aliases_excluded: DecimalU128,
    /// Requested payload bytes charged before reads. Failed/short reads do not refund this bound.
    pub read_budget_charged_bytes: DecimalU128,
    /// Bytes delivered to stage hashers, including provisional data discarded after failures.
    pub delivered_bytes: DecimalU128,
    /// Attempted stage ranges, including failures and metadata-only final checks.
    /// Additional backend metadata opens/probes are not payload reads or counted stage requests.
    pub read_operations: DecimalU128,
    /// True only if traversal and all admitted content comparisons have no gaps.
    pub complete: bool,
    /// Explicit gaps; an intentionally empty threshold-selected result can be complete.
    pub incomplete_reasons: Vec<DuplicateIncompleteReason>,
}
/// Injectable retained-lineage reader. Successful stages must return exact range bytes and
/// stable native observations; provisional bytes on an error never establish a hash.
pub trait DuplicateContentSource {
    /// Reads one bounded range on the caller's worker, preserving cancellation and prior stamps.
    fn read(
        &mut self,
        request: FileContentRequest<'_>,
        cancel: &CancellationToken,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), BoundedRegularFileReadError>,
    ) -> Result<RegularFileStreamResult, FileContentError>;
}
impl<P: PlatformScanner> DuplicateContentSource for DetailRescanner<P> {
    fn read(
        &mut self,
        request: FileContentRequest<'_>,
        cancel: &CancellationToken,
        consume: &mut dyn FnMut(&[u8]) -> Result<(), BoundedRegularFileReadError>,
    ) -> Result<RegularFileStreamResult, FileContentError> {
        self.stream_file(request, cancel, consume)
    }
}

/// Bounded metadata collector fed before optional scan-listing retention. Analysis is opt-in:
/// collect does no content IO, while `analyze` runs size/sample/full-hash stages synchronously.
pub struct DuplicateCollector {
    options: DuplicateOptions,
    files: Vec<ScannedEntry>,
    objects: BTreeMap<(u128, u128, u128), usize>,
    retained_bytes: usize,
    observed: u128,
    aliases: u128,
    gaps: BTreeSet<DuplicateIncompleteReason>,
}
impl DuplicateCollector {
    /// Validates all finite bounds before observing a file.
    pub fn new(options: DuplicateOptions) -> Result<Self, DuplicateOptionsError> {
        if !(1..=100_000).contains(&options.max_files)
            || !(1..=64 * 1024 * 1024).contains(&options.max_retained_bytes)
            || !(1..=400_000).contains(&options.max_read_operations)
            || !(1..=65536).contains(&options.sample_bytes)
            || !(1..=300_000).contains(&options.max_duration_ms)
            || options.max_read_bytes == 0
            || options.max_read_bytes > i64::MAX as u64
            || options.max_file_bytes == 0
            || options.max_file_bytes > i64::MAX as u64
        {
            return Err(DuplicateOptionsError);
        }
        Ok(Self {
            options,
            files: Vec::new(),
            objects: BTreeMap::new(),
            retained_bytes: 0,
            observed: 0,
            aliases: 0,
            gaps: BTreeSet::new(),
        })
    }
    /// Observes ordinary files without reading payloads; aliases cannot create a duplicate group.
    pub fn observe(&mut self, entry: &ScannedEntry) {
        if entry.object_type != ObjectType::File {
            return;
        }
        self.observed = self.observed.saturating_add(1);
        let EvidenceValue::Known { value: size } = entry.logical_bytes else {
            self.gaps
                .insert(DuplicateIncompleteReason::MetadataUnavailable);
            return;
        };
        if size < self.options.minimum_logical_bytes {
            return;
        }
        let Some(identity) = &entry.identity else {
            self.gaps
                .insert(DuplicateIncompleteReason::MetadataUnavailable);
            return;
        };
        let (IdentityEvidence::Known { value: object }, IdentityEvidence::Known { value: domain }) = (
            &identity.platform_file_identity,
            &identity.filesystem_object_domain_identity,
        ) else {
            self.gaps
                .insert(DuplicateIncompleteReason::MetadataUnavailable);
            return;
        };
        let key = (domain.device.0, object.device.0, object.inode.0);
        if let Some(index) = self.objects.get(&key) {
            self.aliases = self.aliases.saturating_add(1);
            if self.files[*index].logical_bytes != entry.logical_bytes {
                self.gaps
                    .insert(DuplicateIncompleteReason::ChangedOrUnbound);
            }
            return;
        }
        if size.0 > u128::from(self.options.max_file_bytes) {
            self.gaps.insert(DuplicateIncompleteReason::ReadLimit);
            return;
        }
        // Covers entries, observation stamps, stage indexes, digest strings and output transfer.
        // This is an owned-data estimate, deliberately separate from allocator RSS.
        let cost = entry
            .estimated_retained_bytes()
            .saturating_mul(3)
            .saturating_add(1024);
        if self.files.len() >= self.options.max_files
            || self.retained_bytes.saturating_add(cost) > self.options.max_retained_bytes
        {
            self.gaps.insert(DuplicateIncompleteReason::RetentionLimit);
            return;
        }
        self.retained_bytes += cost;
        self.objects.insert(key, self.files.len());
        self.files.push(entry.clone());
    }

    /// Runs staged content reads, preserving gaps rather than treating skipped files as unique.
    /// Cancellation/deadline/limits stop or refuse work; only complete hashes form groups.
    pub fn analyze(
        mut self,
        source: &mut dyn DuplicateContentSource,
        traversal_complete: bool,
        cancel: &CancellationToken,
    ) -> DuplicateReport {
        if !traversal_complete {
            self.gaps
                .insert(DuplicateIncompleteReason::TraversalIncomplete);
        }
        let mut budget = ReadBudget {
            options: &self.options,
            started: Instant::now(),
            charged: 0,
            delivered: 0,
            operations: 0,
        };
        let mut sizes = BTreeMap::<u64, Vec<usize>>::new();
        for (index, file) in self.files.iter().enumerate() {
            if let EvidenceValue::Known { value } = file.logical_bytes {
                sizes.entry(value.0 as u64).or_default().push(index);
            }
        }
        let mut previous = vec![None; self.files.len()];
        let mut selected = Vec::new();
        // A stopped stage discards provisional hashes. Already finalized groups survive, while
        // cancellation/deadline avoids walking all remaining stage indexes and opening more files.
        'content: {
            let mut full = BTreeMap::<(u64, [u8; 32]), Vec<usize>>::new();
            for (size, indices) in sizes.into_iter().filter(|(_, files)| files.len() > 1) {
                let mut samples = BTreeMap::<[u8; 32], Vec<usize>>::new();
                for index in indices {
                    let mut hasher = Sha256::new();
                    hasher.update(b"sweepx.duplicate.sample/v1\0");
                    hasher.update(size.to_le_bytes());
                    let prefix = size.min(self.options.sample_bytes);
                    let suffix = (size - prefix).min(self.options.sample_bytes);
                    let mut good = true;
                    for (offset, count) in [(0, prefix), (size - suffix, suffix)] {
                        if count == 0 && offset > 0 {
                            continue;
                        }
                        hasher.update(offset.to_le_bytes());
                        hasher.update(count.to_le_bytes());
                        match budget.read(
                            source,
                            &self.files[index],
                            offset,
                            count,
                            previous[index].as_ref(),
                            cancel,
                            &mut hasher,
                        ) {
                            Ok(observation) => previous[index] = Some(observation),
                            Err(reason) => {
                                let stop = reason.stops_content();
                                self.gaps.insert(reason);
                                if stop {
                                    break 'content;
                                }
                                good = false;
                                break;
                            }
                        }
                    }
                    if good {
                        samples
                            .entry(hasher.finalize().into())
                            .or_default()
                            .push(index);
                    }
                }
                for indices in samples.into_values().filter(|files| files.len() > 1) {
                    for index in indices {
                        let mut hasher = Sha256::new();
                        match budget.read(
                            source,
                            &self.files[index],
                            0,
                            size,
                            previous[index].as_ref(),
                            cancel,
                            &mut hasher,
                        ) {
                            Ok(observation) => {
                                previous[index] = Some(observation);
                                full.entry((size, hasher.finalize().into()))
                                    .or_default()
                                    .push(index);
                            }
                            Err(reason) => {
                                let stop = reason.stops_content();
                                self.gaps.insert(reason);
                                if stop {
                                    break 'content;
                                }
                            }
                        }
                    }
                }
            }
            for ((size, digest), indices) in full.into_iter().filter(|(_, files)| files.len() > 1) {
                let mut valid = Vec::new();
                for index in indices {
                    // Revalidate earlier hashes after the other files' IO, without reading content.
                    match budget.read(
                        source,
                        &self.files[index],
                        0,
                        0,
                        previous[index].as_ref(),
                        cancel,
                        &mut Sha256::new(),
                    ) {
                        Ok(_) => valid.push(index),
                        Err(reason) => {
                            let stop = reason.stops_content();
                            self.gaps.insert(reason);
                            if stop {
                                break 'content;
                            }
                        }
                    }
                }
                if valid.len() > 1 {
                    selected.push((size, digest, valid));
                }
            }
        }
        if cancel.is_cancelled() {
            self.gaps.insert(DuplicateIncompleteReason::Cancelled);
        }
        let retained = self.files.len();
        let mut slots: Vec<_> = self.files.into_iter().map(Some).collect();
        let groups = selected
            .into_iter()
            .map(|(size, digest, indices)| DuplicateGroup {
                logical_bytes: u128::from(size).into(),
                sha256: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
                files: indices
                    .into_iter()
                    .map(|index| {
                        slots[index]
                            .take()
                            .expect("one content group per distinct object")
                    })
                    .collect(),
            })
            .collect();
        DuplicateReport {
            options: self.options.clone(),
            groups,
            observed_files: self.observed.into(),
            retained_files: (retained as u128).into(),
            hard_link_aliases_excluded: self.aliases.into(),
            read_budget_charged_bytes: u128::from(budget.charged).into(),
            delivered_bytes: u128::from(budget.delivered).into(),
            read_operations: (budget.operations as u128).into(),
            complete: self.gaps.is_empty(),
            incomplete_reasons: self.gaps.into_iter().collect(),
        }
    }
}

struct ReadBudget<'a> {
    options: &'a DuplicateOptions,
    started: Instant,
    charged: u64,
    delivered: u64,
    operations: usize,
}
impl ReadBudget<'_> {
    #[allow(clippy::too_many_arguments)]
    fn read(
        &mut self,
        source: &mut dyn DuplicateContentSource,
        entry: &ScannedEntry,
        offset: u64,
        count: u64,
        previous: Option<&RegularFileObservation>,
        cancel: &CancellationToken,
        hash: &mut Sha256,
    ) -> Result<RegularFileObservation, DuplicateIncompleteReason> {
        if cancel.is_cancelled() {
            return Err(DuplicateIncompleteReason::Cancelled);
        }
        let deadline = Duration::from_millis(self.options.max_duration_ms);
        if self.started.elapsed() >= deadline {
            return Err(DuplicateIncompleteReason::Deadline);
        }
        if self.operations >= self.options.max_read_operations
            || count > self.options.max_read_bytes - self.charged
        {
            return Err(DuplicateIncompleteReason::ReadLimit);
        }
        self.operations += 1;
        self.charged += count;
        let mut delivered = 0u64;
        let mut timed_out = false;
        let mut exceeded = false;
        let result = source.read(
            FileContentRequest {
                entry,
                offset,
                max_bytes: count,
                previous,
            },
            cancel,
            &mut |chunk| {
                if cancel.is_cancelled() {
                    return Err(BoundedRegularFileReadError::Cancelled);
                }
                if self.started.elapsed() >= deadline {
                    timed_out = true;
                    return Err(BoundedRegularFileReadError::Cancelled);
                }
                delivered = delivered.saturating_add(chunk.len() as u64);
                if delivered > count {
                    exceeded = true;
                    return Err(BoundedRegularFileReadError::io(std::io::Error::other(
                        "content source exceeded reserved range",
                    )));
                }
                self.delivered += chunk.len() as u64;
                hash.update(chunk);
                Ok(())
            },
        );
        if timed_out || self.started.elapsed() >= deadline {
            return Err(DuplicateIncompleteReason::Deadline);
        }
        if cancel.is_cancelled() {
            return Err(DuplicateIncompleteReason::Cancelled);
        }
        let result = result.map_err(read_reason)?;
        if exceeded
            || delivered != count
            || result.bytes_read != count
            || result.observed_before != result.observed_after
            || previous.is_some_and(|before| before != &result.observed_before)
            || !observation_matches_entry(entry, &result.observed_before)
        {
            return Err(DuplicateIncompleteReason::ChangedOrUnbound);
        }
        Ok(result.observed_after)
    }
}
impl DuplicateIncompleteReason {
    fn stops_content(&self) -> bool {
        matches!(self, Self::Cancelled | Self::Deadline)
    }
}

fn observation_matches_entry(entry: &ScannedEntry, observed: &RegularFileObservation) -> bool {
    let Some(identity) = &entry.identity else {
        return false;
    };
    let IdentityEvidence::Known { value: object } = &identity.platform_file_identity else {
        return false;
    };
    let IdentityEvidence::Known { value: domain } = &identity.filesystem_object_domain_identity
    else {
        return false;
    };
    // Even injectable readers must bind full 128-bit object IDs and the original exact length;
    // same-length stable reads of another object, or a grown file's prefix, cannot form a group.
    observed.kind == sweepx_platform::EntryKind::File
        && object.device.0 == u128::from(observed.identity.device())
        && object.inode.0 == observed.identity.inode()
        && domain.device.0 == u128::from(observed.filesystem_identity.device)
        && entry.logical_bytes
            == (EvidenceValue::Known {
                value: observed.logical_bytes,
            })
        && match &identity.volume_or_mount_identity {
            IdentityEvidence::Known { value } => {
                value.value.0 == u128::from(observed.mount_identity.value)
            }
            _ => true,
        }
}
fn read_reason(error: FileContentError) -> DuplicateIncompleteReason {
    use DuplicateIncompleteReason as R;
    match error {
        FileContentError::Binding(DetailRescanError::Cancelled)
        | FileContentError::Read(BoundedRegularFileReadError::Cancelled) => R::Cancelled,
        FileContentError::Binding(DetailRescanError::ResourceLimit)
        | FileContentError::Read(BoundedRegularFileReadError::LimitExceeded { .. }) => R::ReadLimit,
        FileContentError::Read(BoundedRegularFileReadError::ProviderOrOffline(_)) => {
            R::ProviderOrOffline
        }
        FileContentError::Binding(_)
        | FileContentError::Read(
            BoundedRegularFileReadError::IdentityMismatch(_)
            | BoundedRegularFileReadError::MountMismatch(_)
            | BoundedRegularFileReadError::ChangedDuringRead(_)
            | BoundedRegularFileReadError::SymlinkOrReparse { .. }
            | BoundedRegularFileReadError::NotFound,
        ) => R::ChangedOrUnbound,
        _ => R::ReadFailed,
    }
}

#[cfg(test)]
mod tests;
