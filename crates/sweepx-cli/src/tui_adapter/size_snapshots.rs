//! Bounded, invocation-local display snapshots. These are observations from the completed scan,
//! not fresh subtree facts, classification evidence or permission to execute cleanup.

use std::collections::{BTreeMap, HashMap};

use sweepx_model::{
    DirectoryAggregate, FilesystemObjectDomainIdentity, IdentityEvidence, ObjectType,
    PlatformFileIdentity, ScanEntryId, ScanObjectIdentity, VolumeOrMountIdentity,
};
use sweepx_scanner::{DetailRescanResult, DirectorySizeObservation};

const MAX_DIRECTORIES: usize = 16_384;
const MAX_BYTES: usize = 16 * 1024 * 1024;

struct LiveValue {
    bytes: sweepx_model::ByteValue,
    sequence: u128,
    cost: usize,
}

/// Separate, bounded advisory progress. Eviction admits newly scanned directories after the
/// capacity is reached; these provisional values never enter the completed-snapshot cache.
#[derive(Default)]
pub(super) struct LiveSizeSnapshots {
    values: HashMap<Key, LiveValue>,
    order: BTreeMap<u128, Key>,
    sequence: u128,
    bytes: usize,
}

impl LiveSizeSnapshots {
    pub(super) fn insert(&mut self, observation: &DirectorySizeObservation) {
        let Some(key) = Key::from_identity(&observation.identity) else {
            return;
        };
        let value = match observation.aggregate.apparent_logical_bytes {
            sweepx_model::EvidenceValue::Known { value }
            | sweepx_model::EvidenceValue::LowerBound { value, .. } => value,
            _ => return,
        };
        if self.values.get(&key).is_some_and(|old| {
            matches!(old.bytes, sweepx_model::EvidenceValue::LowerBound { value: previous, .. } if previous.0 > value.0)
        }) {
            return;
        }
        // Include both owned key copies, root strings, both indexes and their allocation overhead.
        let cost = (std::mem::size_of::<(Key, LiveValue)>() + std::mem::size_of::<(u128, Key)>())
            * 2
            + key.root.as_str().len() * 2;
        if cost > MAX_BYTES {
            return;
        }
        let Some(sequence) = self.sequence.checked_add(1) else {
            return;
        };
        self.sequence = sequence;
        if let Some(old) = self.values.remove(&key) {
            self.order.remove(&old.sequence);
            self.bytes -= old.cost;
        }
        while self.values.len() >= MAX_DIRECTORIES || self.bytes.saturating_add(cost) > MAX_BYTES {
            let Some((_, evicted)) = self.order.pop_first() else {
                return;
            };
            if let Some(old) = self.values.remove(&evicted) {
                self.bytes -= old.cost;
            }
        }
        self.order.insert(sequence, key.clone());
        self.values.insert(
            key,
            LiveValue {
                bytes: sweepx_model::EvidenceValue::LowerBound {
                    value,
                    reason: sweepx_model::ReasonCode::IncompleteStreamCoverage,
                },
                sequence,
                cost,
            },
        );
        self.bytes += cost;
    }

    pub(super) fn sample(
        &self,
        identities: &[ScanObjectIdentity],
    ) -> Vec<sweepx_tui::LiveDirectorySize> {
        identities
            .iter()
            .take(MAX_DIRECTORIES)
            .filter_map(|identity| {
                let key = Key::from_identity(identity)?;
                let value = self.values.get(&key)?;
                Some(sweepx_tui::LiveDirectorySize {
                    identity: identity.clone(),
                    bytes: value.bytes.clone(),
                })
            })
            .collect()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    root: ScanEntryId,
    file: PlatformFileIdentity,
    domain: FilesystemObjectDomainIdentity,
    mount: VolumeOrMountIdentity,
}

impl Key {
    fn from_identity(identity: &ScanObjectIdentity) -> Option<Self> {
        let IdentityEvidence::Known { value: file } = &identity.platform_file_identity else {
            return None;
        };
        let IdentityEvidence::Known { value: domain } = &identity.filesystem_object_domain_identity
        else {
            return None;
        };
        let IdentityEvidence::Known { value: mount } = &identity.volume_or_mount_identity else {
            return None;
        };
        Some(Self {
            root: identity.scan_root_id.clone(),
            file: file.clone(),
            domain: domain.clone(),
            mount: mount.clone(),
        })
    }
}

#[derive(Default)]
/// One bounded generation of historical directory sizes for ordinary TUI navigation.
pub(super) struct SizeSnapshots {
    values: HashMap<Key, DirectoryAggregate>,
    bytes: usize,
}

impl SizeSnapshots {
    /// Retains a completed observation only with known native keys and available capacity.
    pub(super) fn insert(&mut self, observation: DirectorySizeObservation) {
        let Some(key) = Key::from_identity(&observation.identity) else {
            return;
        };
        self.insert_value(key, observation.aggregate);
    }

    fn insert_value(&mut self, key: Key, aggregate: DirectoryAggregate) {
        // Include owned strings, reason vectors, map overhead and both key/value storage. The
        // second cap prevents unusually long scan IDs from defeating the directory-count cap.
        let cost = std::mem::size_of::<(Key, DirectoryAggregate)>() * 2
            + key.root.to_string().len()
            + aggregate.scan_id.len()
            + aggregate.directory_identity.len()
            + aggregate.coverage.incomplete_reasons.len()
                * std::mem::size_of::<sweepx_model::ReasonCode>()
            + match &aggregate.coverage.provenance {
                sweepx_model::FieldProvenance::LiveObservation { observed_at, .. }
                | sweepx_model::FieldProvenance::StalePreview { observed_at } => observed_at.len(),
                sweepx_model::FieldProvenance::ValidatedCache {
                    observed_at, token, ..
                } => observed_at.len().saturating_add(token.len()),
                sweepx_model::FieldProvenance::DerivedFromCurrent { inputs, algorithm } => {
                    inputs.iter().fold(
                        algorithm.len() + inputs.len() * std::mem::size_of::<String>(),
                        |cost, input| cost.saturating_add(input.len()),
                    )
                }
                sweepx_model::FieldProvenance::Unknown { .. } => 0,
            };
        if self.values.contains_key(&key)
            || self.values.len() >= MAX_DIRECTORIES
            || self.bytes.saturating_add(cost) > MAX_BYTES
        {
            return;
        }
        self.bytes += cost;
        self.values.insert(key, aggregate);
    }

    /// Publishes a successful traversal's staged sizes; existing scan-time observations survive.
    pub(super) fn merge(&mut self, staged: Self) {
        for (key, aggregate) in staged.values {
            self.insert_value(key, aggregate);
        }
    }

    /// Projects historical sizes onto a current direct listing, rebinding the target ID/revision.
    /// Returns whether the target's recursive size was retained with the same direct-child count.
    pub(super) fn apply(&self, detail: &mut DetailRescanResult) -> bool {
        for row in &mut detail.rows {
            if row.object_type != ObjectType::Directory {
                continue;
            }
            if let Some(size) = row
                .identity
                .as_ref()
                .and_then(Key::from_identity)
                .and_then(|key| self.values.get(&key))
            {
                row.logical_bytes = size.apparent_logical_bytes.clone();
                row.coverage = size.coverage.clone();
            }
        }
        let Some(size) = detail
            .observed_directory
            .identity
            .as_ref()
            .and_then(Key::from_identity)
            .and_then(|key| self.values.get(&key))
        else {
            return false;
        };
        // A changed immediate inventory is an observable invalidation. Deep mutations remain
        // intentionally scan-time snapshots until the user refreshes; never claim freshness.
        if size.direct_child_count != detail.aggregate.direct_child_count {
            return false;
        }
        let mut aggregate = size.clone();
        aggregate.scan_id = detail.aggregate.scan_id.clone();
        aggregate.directory_identity = detail.aggregate.directory_identity.clone();
        aggregate.revision = detail.aggregate.revision;
        detail.aggregate = aggregate;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sweepx_model::{
        ArithmeticState, Coverage, CoverageState, DecimalU128, EvidenceValue, ReasonCode, ScanId,
    };

    fn observation(ordinal: u128) -> DirectorySizeObservation {
        let scan = ScanId::new("display-snapshot");
        let root = ScanEntryId::for_scan_ordinal(&scan, 1).unwrap();
        let entry_id = ScanEntryId::for_scan_ordinal(&scan, ordinal).unwrap();
        let known = EvidenceValue::Known {
            value: DecimalU128::new(23),
        };
        DirectorySizeObservation {
            identity: ScanObjectIdentity {
                entry_id: entry_id.clone(),
                scan_root_id: root.clone(),
                parent_id: Some(root),
                platform_file_identity: IdentityEvidence::known(PlatformFileIdentity {
                    device: DecimalU128::new(1),
                    inode: DecimalU128::new(ordinal),
                }),
                filesystem_object_domain_identity: IdentityEvidence::known(
                    FilesystemObjectDomainIdentity {
                        device: DecimalU128::new(1),
                    },
                ),
                volume_or_mount_identity: IdentityEvidence::known(VolumeOrMountIdentity {
                    value: DecimalU128::new(1),
                }),
            },
            aggregate: DirectoryAggregate {
                scan_id: scan,
                directory_identity: entry_id.to_string(),
                revision: DecimalU128::new(1),
                apparent_logical_bytes: known.clone(),
                unique_logical_bytes: EvidenceValue::Unknown {
                    reason: ReasonCode::UnknownIdentity,
                },
                filesystem_reported_allocated_bytes: known.clone(),
                potentially_reclaimable_bytes: known.clone(),
                direct_child_count: known.clone(),
                recursive_entry_count: known,
                coverage: Coverage {
                    state: CoverageState::Complete,
                    complete: true,
                    details_lost: false,
                    incomplete_reasons: Vec::new(),
                    provenance: sweepx_model::FieldProvenance::LiveObservation {
                        observed_at: "fixture".into(),
                        method: sweepx_model::MethodId::MetadataNoFollow,
                    },
                },
                arithmetic_state: ArithmeticState::Exact,
            },
        }
    }

    #[test]
    fn native_snapshot_keys_require_known_scope_domain_and_mount() {
        let source = observation(2);
        let key = Key::from_identity(&source.identity).unwrap();
        let mut changed = source.identity.clone();
        changed.entry_id = ScanEntryId::for_scan_ordinal(&source.aggregate.scan_id, 99).unwrap();
        assert!(
            Key::from_identity(&changed).unwrap() == key,
            "new listing IDs may rebind the same native directory"
        );
        changed.scan_root_id = ScanEntryId::for_scan_ordinal(&source.aggregate.scan_id, 9).unwrap();
        assert!(Key::from_identity(&changed).unwrap() != key);
        changed = source.identity.clone();
        changed.volume_or_mount_identity = IdentityEvidence::known(VolumeOrMountIdentity {
            value: DecimalU128::new(2),
        });
        assert!(Key::from_identity(&changed).unwrap() != key);
        changed = source.identity.clone();
        changed.platform_file_identity = IdentityEvidence::unknown(ReasonCode::UnknownIdentity);
        assert!(Key::from_identity(&changed).is_none());
    }

    #[test]
    fn oversized_generations_do_not_exceed_either_retention_cap() {
        let mut snapshots = SizeSnapshots::default();
        for ordinal in 2..40_002 {
            snapshots.insert(observation(ordinal));
        }
        assert!(!snapshots.values.is_empty());
        assert!(snapshots.values.len() <= MAX_DIRECTORIES);
        assert!(snapshots.bytes <= MAX_BYTES);
        let before = (snapshots.values.len(), snapshots.bytes);
        let mut staged = SizeSnapshots::default();
        staged.insert(observation(40_003));
        snapshots.merge(staged);
        assert_eq!((snapshots.values.len(), snapshots.bytes), before);
    }

    #[test]
    fn live_samples_rebind_native_ids_and_never_publish_exact_or_regress() {
        let mut live = LiveSizeSnapshots::default();
        let mut source = observation(2);
        live.insert(&source);
        let mut queried = source.identity.clone();
        queried.entry_id = ScanEntryId::for_scan_ordinal(&source.aggregate.scan_id, 99).unwrap();
        let samples = live.sample(&[queried.clone()]);
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].identity, queried);
        assert_eq!(
            samples[0].bytes,
            EvidenceValue::LowerBound {
                value: DecimalU128::new(23),
                reason: ReasonCode::IncompleteStreamCoverage,
            }
        );
        source.aggregate.apparent_logical_bytes = EvidenceValue::Known {
            value: DecimalU128::new(7),
        };
        live.insert(&source);
        assert_eq!(live.sample(&[queried.clone()]), samples);
        source.aggregate.apparent_logical_bytes = EvidenceValue::Known {
            value: DecimalU128::new(47),
        };
        live.insert(&source);
        assert!(
            matches!(live.sample(&[queried.clone()])[0].bytes, EvidenceValue::LowerBound {value, ..} if value.0 == 47)
        );
        queried.volume_or_mount_identity = IdentityEvidence::unknown(ReasonCode::UnknownIdentity);
        assert!(live.sample(&[queried]).is_empty());
    }

    #[test]
    fn live_retention_admits_new_progress_after_eviction_and_replaces_without_growth() {
        let mut live = LiveSizeSnapshots::default();
        for ordinal in 2..40_002 {
            live.insert(&observation(ordinal));
        }
        assert!(live.values.len() <= MAX_DIRECTORIES);
        assert_eq!(live.values.len(), live.order.len());
        assert!(live.bytes <= MAX_BYTES);
        assert!(live.sample(&[observation(2).identity]).is_empty());
        assert_eq!(live.sample(&[observation(40_001).identity]).len(), 1);
        let before = (live.values.len(), live.order.len(), live.bytes);
        for _ in 0..100 {
            live.insert(&observation(40_001));
        }
        assert_eq!(before, (live.values.len(), live.order.len(), live.bytes));
    }
}
